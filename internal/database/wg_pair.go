package database

import (
	"errors"
	"time"
)

// WGPair is durable desired state, not proof that an entry listener is running.
// REALITY credentials are private persistence only; never serialize them.
// WireGuard private keys remain exclusively on the agents.
type WGPair struct {
	ID                string `gorm:"primaryKey;size:32"`
	EntryUUID         string `gorm:"uniqueIndex;size:36;not null"`
	PeerUUID          string `gorm:"index;size:36;not null"`
	EntryInstallID    string
	PeerInstallID     string
	EntryIP           string
	PeerIP            string
	EntryPort         int
	EntryWGPort       int
	PeerWGPort        int
	EntryAddress      string `gorm:"uniqueIndex;not null"`
	PeerAddress       string `gorm:"uniqueIndex;not null"`
	TargetPort        int
	LinkHash          string `json:"-"`
	RealityLink       string `json:"-" gorm:"type:text"`
	EntryIdentityHash string `json:"-"`
	PeerIdentityHash  string `json:"-"`
	RetryCount        uint
	NextRetryAt       time.Time
	HealthCheckedAt   time.Time
	EntryPublicKey    string
	PeerPublicKey     string
	DesiredRevision   uint64
	AppliedRevision   uint64
	Enabled           bool
	Phase             string
	Status            string `gorm:"index"`
	Error             string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// WGPairNode reserves a node in either role, including during pending cleanup.
// The primary key prevents cross-role conflicts in concurrent transactions.
type WGPairNode struct {
	NodeUUID string `gorm:"primaryKey;size:36"`
	PairID   string `gorm:"index;size:32;not null"`
}

// MigrateWGPairs must run after database initialization and database switching.
func MigrateWGPairs() error {
	if DB == nil {
		return errors.New("database unavailable")
	}
	return DB.AutoMigrate(&WGPair{}, &WGPairNode{})
}
