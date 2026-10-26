package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const agentCapability = "wg-relay-v1,wg-reality-ss-v2"

func validAgentToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// Credential URLs must use authenticated TLS, never TOFU or URL credentials.
func secureAgentURL(raw, scheme string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != scheme || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("agent credentials require a secure URL without userinfo, query or fragment")
	}
	return u, nil
}

func validateAgentTransport(cfg *Config) error {
	if !validAgentToken(cfg.AgentToken) {
		return errors.New("invalid permanent agent credential")
	}
	panel, err := secureAgentURL(cfg.PanelURL, "https")
	if err != nil {
		return err
	}
	ws, err := secureAgentURL(cfg.WSURL, "wss")
	if err != nil {
		return err
	}
	if !strings.EqualFold(panel.Host, ws.Host) {
		return errors.New("authenticated WebSocket must use the enrollment panel host")
	}
	return nil
}

// EnrollAgent redeems a short-lived, one-use token and atomically persists the
// permanent credential. The enrollment token is never saved or logged.
func EnrollAgent(ctx context.Context, configPath, token string) error {
	return enrollAgent(ctx, configPath, token, &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	})
}

func enrollAgent(ctx context.Context, configPath, token string, client *http.Client) error {
	if !validAgentToken(token) {
		return errors.New("invalid enrollment token")
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	u, err := secureAgentURL(cfg.PanelURL, "https")
	if err != nil {
		return err
	}
	ws, err := secureAgentURL(cfg.WSURL, "wss")
	if err != nil {
		return err
	}
	if !strings.EqualFold(u.Host, ws.Host) {
		return errors.New("WebSocket and enrollment panel hosts must match")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/agent/enroll"
	u.RawPath = ""
	body, err := json.Marshal(struct {
		InstallID string `json:"install_id"`
		Token     string `json:"token"`
	}{cfg.InstallID, token})
	if err != nil {
		return errors.New("cannot encode enrollment request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot create enrollment request")
	}
	req.Header.Set("Content-Type", "application/json")
	// Clone the client so even callers supplying a CA-aware transport cannot
	// accidentally forward the enrollment token through a redirect.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("enrollment request failed; verify TLS trust and connectivity")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("enrollment rejected")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return errors.New("invalid enrollment response")
	}
	var result struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &result) != nil || !validAgentToken(result.Token) {
		return errors.New("invalid enrollment response")
	}
	cfg.AgentToken = result.Token
	if err := SaveConfig(configPath, cfg); err != nil {
		return errors.New("enrollment succeeded but credential storage failed; rotate enrollment and retry")
	}
	return nil
}
