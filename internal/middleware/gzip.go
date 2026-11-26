package middleware

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

var gzipWriterPool = sync.Pool{
	New: func() any {
		w, err := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		if err != nil {
			return gzip.NewWriter(io.Discard)
		}
		return w
	},
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
	bypass      bool
}

func shouldCompressContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return true
	}
	if semi := strings.IndexByte(ct, ';'); semi >= 0 {
		ct = strings.TrimSpace(ct[:semi])
	}
	// Never buffer/compress SSE streams or already-compressed/binary payloads.
	if ct == "text/event-stream" {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json",
		"application/javascript",
		"application/x-javascript",
		"application/xml",
		"application/xhtml+xml",
		"application/yaml",
		"application/x-yaml",
		"image/svg+xml":
		return true
	default:
		return false
	}
}

func (w *gzipResponseWriter) decideCompression(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	h := w.Header()
	if statusCode == http.StatusNoContent ||
		statusCode == http.StatusNotModified ||
		(statusCode >= 100 && statusCode < 200) ||
		h.Get("Content-Encoding") != "" ||
		!shouldCompressContentType(h.Get("Content-Type")) {
		w.bypass = true
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}

	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	h.Add("Vary", "Accept-Encoding")

	gz := gzipWriterPool.Get().(*gzip.Writer)
	gz.Reset(w.ResponseWriter)
	w.gz = gz
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *gzipResponseWriter) WriteHeader(statusCode int) {
	w.decideCompression(statusCode)
}

func (w *gzipResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", http.DetectContentType(p))
		}
		w.decideCompression(http.StatusOK)
	}
	if w.bypass || w.gz == nil {
		return w.ResponseWriter.Write(p)
	}
	return w.gz.Write(p)
}

func (w *gzipResponseWriter) Flush() {
	if w.gz != nil {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *gzipResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}

func (w *gzipResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *gzipResponseWriter) close() {
	if w.gz != nil {
		_ = w.gz.Close()
		w.gz.Reset(io.Discard)
		gzipWriterPool.Put(w.gz)
		w.gz = nil
	}
}

// Gzip 对支持 gzip 的客户端自动压缩 HTML/CSS/JS/JSON/SVG 响应，
// 自动跳过 WebSocket 升级与 SSE 事件流，大幅降低首页与接口传输体积。
func Gzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead ||
			r.Header.Get("Upgrade") != "" ||
			!strings.Contains(strings.ToLower(r.Header.Get("Accept-Encoding")), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		gzw := &gzipResponseWriter{ResponseWriter: w}
		defer gzw.close()
		next.ServeHTTP(gzw, r)
	})
}
