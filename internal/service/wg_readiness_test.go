package service

import (
	"encoding/json"
	"nodectl/internal/database"
	"strings"
	"testing"
)

func TestWGReadinessReasons(t *testing.T) {
	for _, kind := range []string{"ready", "protocol", "identity", "offline", "unauthenticated", "unsupported", "blocked", "traffic", "tunnel", "ipv4", "occupied", "same-machine"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := newWGTest(t)
			c.agentStatus = func(string) string { return "ready" }
			var err error
			code := kind
			switch kind {
			case "protocol":
				err = c.db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("disabled_links", `["ss"]`).Error
			case "identity":
				err = c.db.Model(&database.AgentIdentity{}).Where("node_uuid = ?", "landing").Update("secret_hash", "").Error
			case "offline", "unauthenticated", "unsupported":
				c.agentStatus = func(id string) string {
					if id == "bbbbbbbbbbbb" {
						return kind
					}
					return "ready"
				}
				code = "agent"
			case "blocked":
				err = c.db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("is_blocked", true).Error
				code = "node"
			case "traffic":
				err = c.db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("traffic_threshold_reached", true).Error
				code = "node"
			case "tunnel":
				err = c.db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("tunnel_enabled", true).Error
				code = "node"
			case "ipv4":
				err = c.db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("ipv4", "127.0.0.1").Error
				code = "node"
			case "occupied":
				err = c.db.Create(&database.WGPairNode{NodeUUID: "landing", PairID: "another-pair"}).Error
				code = "available"
			case "same-machine":
				err = c.db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("ipv4", "198.51.100.1").Error
				code = "distinct"
			}
			if err != nil {
				t.Fatal(err)
			}
			options, err := c.options("entry")
			if err != nil {
				t.Fatal(err)
			}
			if !options.Ready || !options.Readiness.Ready || options.Readiness.Role != "entry" || len(options.Readiness.Checks) != 4 {
				t.Fatalf("entry checks: %+v", options.Readiness)
			}
			if len(options.Peers) != 1 {
				t.Fatal("unavailable landing disappeared")
			}
			peer := options.Peers[0]
			if kind == "identity" && peer.Readiness.EnrollmentMode != "rotate" {
				t.Fatal("revoked identity needs explicit re-enrollment")
			}
			if options.Readiness.EnrollmentMode != "none" {
				t.Fatal("bound identity must not prompt initial enrollment")
			}
			if kind == "ready" {
				if !peer.Ready || !peer.Readiness.Ready {
					t.Fatal("ready peer rejected")
				}
			} else {
				if peer.Ready || peer.Readiness.Ready {
					t.Fatal("unavailable peer accepted")
				}
				found := false
				for _, check := range peer.Readiness.Checks {
					if check.Code == code && !check.Ready && check.Detail != "" {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing reason %s: %+v", code, peer.Readiness)
				}
			}
			data, _ := json.Marshal(options)
			for _, secret := range []string{"PUBLIC_LINK_NOT_CANONICAL_SECRET", strings.Repeat("b", 64), "ss://", "vless://"} {
				if strings.Contains(string(data), secret) {
					t.Fatal("readiness leaked credentials")
				}
			}
		})
	}
}

func TestWGReadinessLandingAndDatabaseFailure(t *testing.T) {
	c, _ := newWGTest(t)
	options, err := c.options("landing")
	if err != nil || options.Ready || !options.Readiness.Ready || options.Readiness.Role != "landing" || options.Readiness.Checks[1].Label != "SS 部署" {
		t.Fatalf("landing checks %+v: %v", options, err)
	}
	if err := c.db.Migrator().DropTable(&database.AgentIdentity{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.options("entry"); err == nil {
		t.Fatal("database failure shown as unbound")
	}
}
