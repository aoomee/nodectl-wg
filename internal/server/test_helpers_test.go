package server

import (
	"html/template"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"wirearc/internal/database"
	"wirearc/internal/logger"
)

func wgTestDB(t *testing.T) {
	t.Helper()
	old := database.DB
	oldLog := logger.Log
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "test.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&database.CustomNode{}, &database.NodePool{}, &database.AirportNode{}, &database.SysConfig{}); err != nil {
		t.Fatal(err)
	}
	database.DB = db
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { sql, _ := db.DB(); sql.Close(); database.DB = old; logger.Log = oldLog })
}

func TestIndexTemplatesRender(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err = tmpl.ParseGlob("../../templates/components/*.html")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "index.html", map[string]any{
		"Title":   "WireArc 控制台",
		"Version": "v1.1.0",
		"Stats":   map[string]int{"Total": 0, "Direct": 0, "Landing": 0, "Blocked": 0},
	}); err != nil {
		t.Fatal(err)
	}
	rendered := b.String()
	if !strings.Contains(rendered, "WireArc") || !strings.Contains(rendered, "nodeWGEditor") {
		t.Fatal("WireArc or Agent WG UI missing from rendered index.html")
	}
	if strings.Contains(rendered, "wgRelayModal") {
		t.Fatal("removed legacy SSH WG modal still present in index.html")
	}
}
