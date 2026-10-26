package wgrelay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validRequest() Request {
	return Request{Mode: "deploy", Architecture: "realm", AIP: "8.8.8.8", BIP: "1.1.1.1", ASSH: 22, BSSH: 22, APort: 443, BPort: 443, AUsername: "root", BUsername: "ubuntu", APassword: "a-secret-123", BPassword: "b-secret-456", SNI: "addons.mozilla.org", MTU: 1280}
}
func awaitJob(t *testing.T, m *Manager, id string) Job {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		j, err := m.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != "running" && j.Status != "cancelling" {
			return j
		}
		select {
		case <-deadline:
			t.Fatal("job did not finish")
		case <-time.After(time.Millisecond):
		}
	}
}
func TestValidation(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1", "240.0.0.1", "::1", "8.8.8.8;id", "localhost"} {
		r := validRequest()
		r.AIP = ip
		if r.Validate() == nil {
			t.Errorf("accepted %q", ip)
		}
	}
	for _, change := range []func(*Request){func(r *Request) { r.BIP = r.AIP }, func(r *Request) { r.ASSH = 0 }, func(r *Request) { r.APort = r.ASSH }, func(r *Request) { r.BPort = 65536 }, func(r *Request) { r.SNI = "example.com;id" }, func(r *Request) { r.AUsername = "root;id" }, func(r *Request) { r.APassword = "" }, func(r *Request) { r.MTU = 9000 }, func(r *Request) { r.Architecture = "evil" }, func(r *Request) { r.Mode = "evil" }} {
		r := validRequest()
		change(&r)
		if r.Validate() == nil {
			t.Fatal("accepted invalid request", r.Public())
		}
	}
	for _, mode := range []string{"realm", "vless_ss"} {
		r := validRequest()
		r.Architecture = mode
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
func TestJobPersistenceRedactionAndIsolation(t *testing.T) {
	root := t.TempDir()
	r := validRequest()
	entered := make(chan struct{})
	release := make(chan struct{})
	m, err := New(root, func(ctx context.Context, r Request, folder string, w io.Writer) (Result, error) {
		fmt.Fprint(w, "checking "+r.APassword[:4])
		close(entered)
		<-release
		fmt.Fprintln(w, r.APassword[4:]+" and "+r.BPassword)
		os.WriteFile(filepath.Join(folder, "temporary-key"), []byte("private"), 0600)
		return Result{Kind: "deploy", Link: "vless://verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	j, err := m.Start(r)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if _, err := m.Start(r); !errors.Is(err, ErrBusy) {
		t.Fatalf("second job: %v", err)
	}
	before, _ := m.Get(j.ID)
	if strings.Contains(before.Log, r.APassword[:4]) {
		t.Fatal("partial password leaked")
	}
	if before.Spec.APassword != "" {
		t.Fatal("password in API")
	}
	close(release)
	j = awaitJob(t, m, j.ID)
	if j.Status != "succeeded" || j.Result == nil {
		t.Fatal(j)
	}
	b, _ := os.ReadFile(filepath.Join(root, "jobs", j.ID+".json"))
	for _, secret := range []string{r.APassword, r.BPassword} {
		if strings.Contains(string(b), secret) {
			t.Fatal("password on disk")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "jobs", j.ID)); !os.IsNotExist(err) {
		t.Fatal("job workspace not removed")
	}
	stat, _ := os.Stat(filepath.Join(root, "jobs", j.ID+".json"))
	if stat.Mode().Perm() != 0600 {
		t.Fatal("job permissions")
	}
	restored, err := New(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := restored.Get(j.ID)
	if saved.Result.Link != "vless://verified" {
		t.Fatal("result did not survive restart")
	}
	saved.Result.Link = "changed"
	original, _ := restored.Get(j.ID)
	if original.Result.Link == "changed" {
		t.Fatal("mutable snapshot")
	}
}
func TestFailedCancelledAndTimedOutNeverExport(t *testing.T) {
	for _, kind := range []string{"failed", "cancelled", "timed_out"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := New(t.TempDir(), func(ctx context.Context, r Request, _ string, w io.Writer) (Result, error) {
				if kind != "failed" {
					<-ctx.Done()
				}
				return Result{Kind: "deploy", Link: "vless://must-not-export"}, errors.New(r.BPassword)
			})
			if kind == "timed_out" {
				m.timeout = 10 * time.Millisecond
			}
			j, err := m.Start(validRequest())
			if err != nil {
				t.Fatal(err)
			}
			if kind == "cancelled" {
				m.Cancel(j.ID)
			}
			j = awaitJob(t, m, j.ID)
			if j.Status != kind || j.Result != nil {
				t.Fatal(j)
			}
			if strings.Contains(j.Log, validRequest().BPassword) {
				t.Fatal("error leaked password")
			}
		})
	}
}
func TestInterruptedRecovery(t *testing.T) {
	root := t.TempDir()
	m, _ := New(root, nil)
	j := Job{ID: "cb3d58d2-840f-4e3d-a27c-638f5ac83c4d", Status: "running", Spec: validRequest().Public(), Created: time.Now()}
	if err := m.save(&j); err != nil {
		t.Fatal(err)
	}
	m, err := New(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(j.ID)
	if got.Status != "interrupted" || got.Result != nil {
		t.Fatal(got)
	}
}
func TestBoundedLogsAndRetention(t *testing.T) {
	m, _ := New(t.TempDir(), func(_ context.Context, r Request, _ string, w io.Writer) (Result, error) {
		fmt.Fprint(w, strings.Repeat("x", maxLog*2)+r.APassword)
		return Result{Kind: "deploy", Link: "vless://ok"}, nil
	})
	for i := 0; i < maxJobs+2; i++ {
		j, err := m.Start(validRequest())
		if err != nil {
			t.Fatal(err)
		}
		got := awaitJob(t, m, j.ID)
		if len(got.Log) > maxLog || strings.Contains(got.Log, validRequest().APassword) {
			t.Fatal("log limit/redaction")
		}
	}
	if len(m.List()) != maxJobs {
		t.Fatal("retention limit")
	}
	files, _ := filepath.Glob(filepath.Join(m.root, "jobs", "*.json"))
	if len(files) != maxJobs {
		t.Fatal("disk retention limit")
	}
}
func TestEngineIntegrity(t *testing.T) {
	script, _ := engineFS.ReadFile("engine/vendor/wg-multi-relay.sh")
	h := sha256.Sum256(script)
	expected := hex.EncodeToString(h[:])
	for _, name := range []string{"engine/deploy.py", "engine/remote_worker.py"} {
		b, _ := engineFS.ReadFile(name)
		if !strings.Contains(string(b), "WG_SHA = '"+expected+"'") {
			t.Fatalf("%s checksum mismatch", name)
		}
	}
}
func TestPublicRequestJSON(t *testing.T) {
	b, _ := json.Marshal(validRequest().Public())
	if strings.Contains(string(b), "password") {
		t.Fatal(string(b))
	}
}

func TestSplitAndOverlappingPasswordRedaction(t *testing.T) {
	m := &Manager{jobs: map[string]*Job{"test": {}}}
	w := &logWriter{m: m, id: "test", secrets: []string{"abc-long-secret", "abc"}}
	w.Write([]byte("prefix abc"))
	if strings.Contains(m.jobs["test"].Log, "abc") {
		t.Fatal("partial password exposed")
	}
	w.Write([]byte("-long-secret suffix\n"))
	if strings.Contains(m.jobs["test"].Log, "long-secret") {
		t.Fatal("overlapping password leaked")
	}
	if m.jobs["test"].Log != "prefix [密码已隐藏] suffix\n" {
		t.Fatal(m.jobs["test"].Log)
	}
}
