// Package verificationview is the read model of per-tenant verification
// sessions (ADR-0033 #3 and #9). It is shared by the HTTP and PostgreSQL
// adapters so neither imports the other. It has no field that could carry the
// JWS, claims, vp_token, nonce or state (VER-FR08).
package verificationview

import (
	"errors"
	"time"
)

// ErrNotFound means the session does not exist for the authorized tenant. A
// session of another tenant is reported the same way.
var ErrNotFound = errors.New("verification session not found")

// Session is what a tenant operator may read about a verification session.
// Status is pending, completed or expired; expired is derived from ExpiresAt.
type Session struct {
	SessionID    string     `json:"sessionId"`
	Status       string     `json:"status"`
	Result       string     `json:"result,omitempty"`
	Codes        []string   `json:"codes,omitempty"`
	ReportDigest string     `json:"reportDigest,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	CompletedAt  *time.Time `json:"completedAt,omitempty"`
}

// Position is the keyset position of the last row of a page.
type Position struct {
	CreatedAt time.Time
	SessionID string
}
