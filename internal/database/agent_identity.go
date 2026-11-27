package database

import "time"

// AgentIdentity is a durable binding/tombstone. Revocation MUST NOT delete it:
// Bound prevents a previously enrolled install ID falling back to legacy auth.
// Only hashes are stored; none of these fields belong in public node responses.
type AgentIdentity struct {
	NodeUUID            string    `gorm:"primaryKey;type:varchar(36)" json:"-"`
	InstallID           string    `gorm:"uniqueIndex;type:varchar(12);not null" json:"-"`
	Bound               bool      `gorm:"not null;default:false" json:"-"`
	SecretHash          string    `gorm:"type:varchar(64);index" json:"-"`
	EnrollmentHash      string    `gorm:"type:varchar(64);index" json:"-"`
	EnrollmentExpiresAt time.Time `json:"-"`
	CreatedAt           time.Time `json:"-"`
	UpdatedAt           time.Time `json:"-"`
}
