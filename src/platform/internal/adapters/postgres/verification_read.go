package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/verificationview"
)

// VerificationReadStore serves the read-only session views (ADR-0033 #3 and #9,
// VER-T11-e). Pool must belong to hukid_verification_runtime: row security
// limits every query to the tenant set by WithTenant, so a session of another
// tenant is indistinguishable from one that does not exist. The caller must
// have authorized the actor and the verification:read capability first.
type VerificationReadStore struct{ Pool *pgxpool.Pool }

// The projection is shared by Get and List. expired is derived from expires_at
// with the database clock, as the stored status is only pending or completed.
const verificationColumns = `session_id::text,
 CASE WHEN status='pending' AND expires_at<=clock_timestamp() THEN 'expired' ELSE status END,
 result,codes,report_digest,created_at,expires_at,completed_at`

func scanVerificationSession(row pgx.Row) (verificationview.Session, error) {
	var (
		session verificationview.Session
		result  *string
		digest  []byte
	)
	if err := row.Scan(&session.SessionID, &session.Status, &result, &session.Codes, &digest, &session.CreatedAt, &session.ExpiresAt, &session.CompletedAt); err != nil {
		return verificationview.Session{}, err
	}
	if result != nil {
		session.Result = *result
	}
	if len(digest) > 0 {
		session.ReportDigest = "sha256:" + hex.EncodeToString(digest)
	}
	session.CreatedAt, session.ExpiresAt = session.CreatedAt.UTC(), session.ExpiresAt.UTC()
	if session.CompletedAt != nil {
		completed := session.CompletedAt.UTC()
		session.CompletedAt = &completed
	}
	if len(session.Codes) == 0 {
		session.Codes = nil
	}
	return session, nil
}

// Get returns one session of the authorized tenant, or
// verificationview.ErrNotFound.
func (s *VerificationReadStore) Get(ctx context.Context, actor, tenant, sessionID string) (verificationview.Session, error) {
	if s == nil || s.Pool == nil {
		return verificationview.Session{}, errors.New("verification reader unavailable")
	}
	var session verificationview.Session
	err := WithTenant(ctx, s.Pool, actor, tenant, func(tx pgx.Tx) error {
		var e error
		session, e = scanVerificationSession(tx.QueryRow(ctx, `SELECT `+verificationColumns+`
FROM verification.sessions WHERE tenant_id=$1 AND session_id=$2::uuid`, tenant, sessionID))
		if errors.Is(e, pgx.ErrNoRows) {
			return verificationview.ErrNotFound
		}
		return e
	})
	if err != nil {
		return verificationview.Session{}, err
	}
	return session, nil
}

// List returns at most limit sessions of the authorized tenant, newest first,
// strictly after the keyset position. It never reads another tenant: the
// predicate and the row-level policy both bind tenant_id.
func (s *VerificationReadStore) List(ctx context.Context, actor, tenant, status string, limit int, after *verificationview.Position) ([]verificationview.Session, error) {
	if s == nil || s.Pool == nil || limit < 1 || limit > 101 {
		return nil, errors.New("verification reader unavailable")
	}
	var (
		afterCreated *time.Time
		afterID      *string
	)
	if after != nil {
		afterCreated, afterID = &after.CreatedAt, &after.SessionID
	}
	sessions := []verificationview.Session{}
	err := WithTenant(ctx, s.Pool, actor, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+verificationColumns+`
FROM verification.sessions
WHERE tenant_id=$1
 AND ($2='' OR ($2='completed' AND status='completed')
  OR ($2='pending' AND status='pending' AND expires_at>clock_timestamp())
  OR ($2='expired' AND status='pending' AND expires_at<=clock_timestamp()))
 AND ($3::timestamptz IS NULL OR (created_at,session_id)<($3::timestamptz,$4::uuid))
ORDER BY created_at DESC,session_id DESC
LIMIT $5`, tenant, status, afterCreated, afterID, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			session, e := scanVerificationSession(rows)
			if e != nil {
				return e
			}
			sessions = append(sessions, session)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}
