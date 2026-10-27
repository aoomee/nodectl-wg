package webassets

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type assetRecord struct {
	File, SHA256, Integrity, License string
}

func manifest(t *testing.T) []assetRecord {
	t.Helper()
	b, err := os.ReadFile("vendor/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var records []assetRecord
	if err := json.Unmarshal(b, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatal("expected both browser dependencies")
	}
	return records
}

func TestAssetsIntegrityAndTemplates(t *testing.T) {
	var templates strings.Builder
	err := filepath.WalkDir("../../templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".html") {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			templates.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	remoteScript := regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["'](?:https?:)?//`)
	if remoteScript.MatchString(templates.String()) {
		t.Fatal("template loads a remote executable script")
	}
	for _, record := range manifest(t) {
		b, err := files.ReadFile("vendor/" + record.File)
		if err != nil {
			t.Fatal(err)
		}
		sha := sha256.Sum256(b)
		if hex.EncodeToString(sha[:]) != record.SHA256 || !strings.Contains(record.File, record.SHA256[:12]) {
			t.Fatal("script content/name mismatch", record.File)
		}
		sri := sha512.Sum384(b)
		if "sha384-"+base64.StdEncoding.EncodeToString(sri[:]) != record.Integrity {
			t.Fatal("SRI mismatch", record.File)
		}
		if !strings.Contains(templates.String(), `src="`+Prefix+record.File+`" integrity="`+record.Integrity+`"`) {
			t.Fatal("template missing local asset with matching SRI", record.File)
		}
		license, err := files.ReadFile("vendor/" + record.License)
		if err != nil || !strings.Contains(string(license), "Copyright") {
			t.Fatal("embedded license missing", record.License, err)
		}
	}
}

func TestAssetsHTTP(t *testing.T) {
	for _, record := range manifest(t) {
		url := Prefix + record.File
		get := httptest.NewRecorder()
		Handler(get, httptest.NewRequest(http.MethodGet, url, nil))
		if get.Code != 200 || get.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || get.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal(get.Code, get.Header())
		}
		sha := sha256.Sum256(get.Body.Bytes())
		if hex.EncodeToString(sha[:]) != record.SHA256 {
			t.Fatal("served wrong asset")
		}
		if !strings.Contains(get.Header().Get("Cache-Control"), "immutable") {
			t.Fatal("missing versioned asset cache")
		}
		head := httptest.NewRecorder()
		Handler(head, httptest.NewRequest(http.MethodHead, url, nil))
		if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(get.Body.Len()) {
			t.Fatal("invalid HEAD", head)
		}
		conditional := httptest.NewRequest(http.MethodGet, url, nil)
		conditional.Header.Set("If-None-Match", get.Header().Get("ETag"))
		cached := httptest.NewRecorder()
		Handler(cached, conditional)
		if cached.Code != 304 || cached.Body.Len() != 0 {
			t.Fatal("invalid cache revalidation")
		}
		license := httptest.NewRecorder()
		Handler(license, httptest.NewRequest(http.MethodGet, Prefix+record.License, nil))
		if license.Code != 200 || !strings.HasPrefix(license.Header().Get("Content-Type"), "text/plain") {
			t.Fatal("license not available")
		}
	}
	for _, path := range []string{Prefix, Prefix + "missing.js", Prefix + "manifest.json", Prefix + "../assets.go", Prefix + "nested/file.js", "/data/database.db"} {
		w := httptest.NewRecorder()
		Handler(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 404 || w.Header().Get("Cache-Control") != "" {
			t.Fatal(path, w.Code, w.Header())
		}
	}
	w := httptest.NewRecorder()
	Handler(w, httptest.NewRequest(http.MethodPost, Prefix+manifest(t)[0].File, nil))
	if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("unexpected write method accepted")
	}
}
