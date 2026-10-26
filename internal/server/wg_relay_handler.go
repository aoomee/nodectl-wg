package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/wgrelay"

	"gorm.io/gorm"
)

var wgManager *wgrelay.Manager
var wgImportMu sync.Mutex

// All routes use the existing panel authentication. A custom header plus JSON
// content type prevents cross-site form submissions with the admin cookie.
func registerWGRoutes(mux *http.ServeMux, manager *wgrelay.Manager) {
	mux.HandleFunc("/api/wg-relay/", withAuthAndSecure(wgHandler(manager)))
}
func wgJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func wgError(w http.ResponseWriter, status int, err error) {
	wgJSON(w, status, map[string]any{"error": err.Error()})
}
func wgDecode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("请求格式不正确或内容过大")
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return errors.New("请求必须是单个 JSON 对象")
	}
	return nil
}
func wgHandler(m *wgrelay.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			wgError(w, 503, errors.New("WG 任务存储未初始化，请检查服务日志"))
			return
		}
		action := strings.TrimPrefix(r.URL.Path, "/api/wg-relay/")
		if r.Method == http.MethodGet {
			switch action {
			case "jobs":
				wgJSON(w, 200, map[string]any{"jobs": m.List()})
			case "job":
				j, err := m.Get(r.URL.Query().Get("id"))
				if err != nil {
					wgError(w, 404, err)
					return
				}
				wgJSON(w, 200, j)
			default:
				http.NotFound(w, r)
			}
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			wgError(w, 405, errors.New("请求方法不支持"))
			return
		}
		media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if r.Header.Get("X-NodeCtl-WG") != "1" || media != "application/json" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			wgError(w, 403, errors.New("请求来源校验失败，请从面板操作"))
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
				wgError(w, 403, errors.New("请求来源不匹配"))
				return
			}
		}
		switch action {
		case "start":
			var req wgrelay.Request
			if err := wgDecode(w, r, &req); err != nil {
				wgError(w, 400, err)
				return
			}
			if err := req.Validate(); err != nil {
				wgError(w, 400, err)
				return
			}
			if err := wgrelay.CheckRuntime(); err != nil {
				wgError(w, 503, err)
				return
			}
			j, err := m.Start(req)
			if err != nil {
				status := 400
				if errors.Is(err, wgrelay.ErrBusy) {
					status = 409
				}
				wgError(w, status, err)
				return
			}
			wgJSON(w, 202, j)
		case "cancel", "import":
			var req struct {
				ID string `json:"id"`
			}
			if err := wgDecode(w, r, &req); err != nil {
				wgError(w, 400, err)
				return
			}
			if action == "cancel" {
				if err := m.Cancel(req.ID); err != nil {
					wgError(w, 404, err)
					return
				}
				wgJSON(w, 200, map[string]any{"ok": true})
				return
			}
			j, err := m.Get(req.ID)
			if err != nil {
				wgError(w, 404, err)
				return
			}
			if j.Status != "succeeded" || j.Spec.Mode != "deploy" || j.Result == nil || j.Result.Kind != "deploy" || !strings.HasPrefix(j.Result.Link, "vless://") {
				wgError(w, 409, errors.New("只有部署及业务验证成功的任务才能导入"))
				return
			}
			node, err := importWGNode(j.Result.Link)
			if err != nil {
				wgError(w, 500, errors.New("节点保存失败，请检查数据库后重试"))
				return
			}
			wgJSON(w, 200, map[string]any{"node": node, "message": "已加入自定义节点与订阅"})
		default:
			http.NotFound(w, r)
		}
	}
}

// Serialize imports and check the link inside a transaction so retries are idempotent.
func importWGNode(link string) (database.CustomNode, error) {
	wgImportMu.Lock()
	defer wgImportMu.Unlock()
	var node database.CustomNode
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		err := tx.Where("link = ?", link).First(&node).Error
		if err == nil {
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		node = database.CustomNode{Link: link, Name: "WG 中转", Protocol: "vless", RoutingType: 1}
		if strings.Contains(link, "#VLESS-WG-SS") {
			node.Name = "WG 中转 · VLESS → SS"
		} else {
			node.Name = "WG 中转 · Realm → VLESS"
		}
		if u, err := url.Parse(link); err == nil {
			node.Name += " · " + u.Host
		}
		return tx.Create(&node).Error
	})
	return node, err
}

func StopWGRelay() {
	if wgManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		wgManager.Close(ctx)
	}
}
