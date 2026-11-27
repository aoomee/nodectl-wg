// Package webassets serves the reviewed browser dependencies embedded in the panel.
package webassets

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Only scripts and their licenses are public; no working-directory files are served.
//
//go:embed vendor/*.js vendor/*.txt
var files embed.FS

const Prefix = "/assets/vendor/"

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, Prefix)
	if name == r.URL.Path || name == "" || strings.ContainsAny(name, "/\\") || !(strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".txt")) {
		http.NotFound(w, r)
		return
	}
	data, err := files.ReadFile("vendor/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := "text/javascript; charset=utf-8"
	if strings.HasSuffix(name, ".txt") {
		contentType = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", fmt.Sprintf("\"%x\"", sha256.Sum256(data)))
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}
