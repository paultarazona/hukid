//go:build integration

package postgres

import (
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/verificationview"
)

func TestVerificationReadStoreIsolatesTenantsAndDerivesExpired(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	pool := db.pool(t, "hukid_verification_runtime")
	store := &VerificationReadStore{Pool: pool}

	pendingID, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	doneID, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	expiredID, err := startSession(t, db, vsTenantA, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	foreignID, err := startSession(t, db, vsTenantB, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	digest := []byte(strings.Repeat("\xab", 32))
	var ok bool
	if err := pool.QueryRow(testContext, `SELECT verification.complete_session($1::uuid,'fail',$2,$3)`, doneID, []string{"format.header.alg"}, digest).Scan(&ok); err != nil || !ok {
		t.Fatalf("complete: %v %v", ok, err)
	}
	time.Sleep(1300 * time.Millisecond)

	got, err := store.Get(testContext, vsOperator, vsTenantA, doneID)
	if err != nil || got.Status != "completed" || got.Result != "fail" || len(got.Codes) != 1 || got.CompletedAt == nil || got.ReportDigest != "sha256:"+strings.Repeat("ab", 32) {
		t.Fatalf("completed session: %+v (%v)", got, err)
	}
	got, err = store.Get(testContext, vsOperator, vsTenantA, pendingID)
	if err != nil || got.Status != "pending" || got.Result != "" || got.Codes != nil || got.ReportDigest != "" || got.CompletedAt != nil {
		t.Fatalf("pending session: %+v (%v)", got, err)
	}
	if got, err = store.Get(testContext, vsOperator, vsTenantA, expiredID); err != nil || got.Status != "expired" {
		t.Fatalf("expired session: %+v (%v)", got, err)
	}
	// A session of another tenant is indistinguishable from one that does not exist.
	for _, id := range []string{foreignID, "55555555-5555-4555-8555-555555555555"} {
		if _, err := store.Get(testContext, vsOperator, vsTenantA, id); err != verificationview.ErrNotFound {
			t.Fatalf("%s: got %v, want ErrNotFound", id, err)
		}
	}

	rows, err := store.List(testContext, vsOperator, vsTenantA, "", 100, nil)
	if err != nil || len(rows) != 3 {
		t.Fatalf("tenant A list: %d rows (%v)", len(rows), err)
	}
	for _, row := range rows {
		if row.SessionID == foreignID {
			t.Fatal("tenant A listed tenant B's session")
		}
	}
	for status, want := range map[string]string{"pending": pendingID, "completed": doneID, "expired": expiredID} {
		rows, err := store.List(testContext, vsOperator, vsTenantA, status, 100, nil)
		if err != nil || len(rows) != 1 || rows[0].SessionID != want || rows[0].Status != status {
			t.Fatalf("filter %s: %+v (%v)", status, rows, err)
		}
	}
}

func TestVerificationReadStorePagesByKeysetWithoutGapsOrRepeats(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	store := &VerificationReadStore{Pool: db.pool(t, "hukid_verification_runtime")}
	want := map[string]bool{}
	for range 5 {
		id, err := startSession(t, db, vsTenantA, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		want[id] = true
	}
	var after *verificationview.Position
	var previous time.Time
	seen := 0
	for page := 0; page < 5; page++ {
		rows, err := store.List(testContext, vsOperator, vsTenantA, "", 2, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if !want[row.SessionID] {
				t.Fatalf("unexpected or repeated session %s", row.SessionID)
			}
			delete(want, row.SessionID)
			if !previous.IsZero() && row.CreatedAt.After(previous) {
				t.Fatalf("not newest first: %s after %s", row.CreatedAt, previous)
			}
			previous = row.CreatedAt
			seen++
		}
		last := rows[len(rows)-1]
		after = &verificationview.Position{CreatedAt: last.CreatedAt, SessionID: last.SessionID}
	}
	if seen != 5 || len(want) != 0 {
		t.Fatalf("seen %d sessions, %d missing", seen, len(want))
	}
}
