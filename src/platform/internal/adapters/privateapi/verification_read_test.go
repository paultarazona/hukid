package privateapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/verificationview"
)

const (
	vrSessionA = "7a7f8c3e-5b0e-4a6b-9a39-0d6c1f3c9a11"
	vrSessionB = "7a7f8c3e-5b0e-4a6b-9a39-0d6c1f3c9a12"
	vrSessionC = "7a7f8c3e-5b0e-4a6b-9a39-0d6c1f3c9a13"
)

type vrOperators struct{}

func (vrOperators) VerifyOperator(_ context.Context, raw string) (a.Operator, error) {
	if raw == "valid" {
		return a.Operator{Issuer: "configured", Subject: "self"}, nil
	}
	return a.Operator{}, a.ErrCredential
}

type vrReader struct {
	rows       []verificationview.Session
	err        error
	listCalls  int
	getCalls   int
	lastTenant string
	lastStatus string
	lastLimit  int
	lastAfter  *verificationview.Position
}

func (r *vrReader) Get(_ context.Context, _, tenant, id string) (verificationview.Session, error) {
	r.getCalls++
	r.lastTenant = tenant
	if r.err != nil {
		return verificationview.Session{}, r.err
	}
	for _, row := range r.rows {
		if row.SessionID == id {
			return row, nil
		}
	}
	return verificationview.Session{}, verificationview.ErrNotFound
}

func (r *vrReader) List(_ context.Context, _, tenant, status string, limit int, after *verificationview.Position) ([]verificationview.Session, error) {
	r.listCalls++
	r.lastTenant, r.lastStatus, r.lastLimit, r.lastAfter = tenant, status, limit, after
	if r.err != nil {
		return nil, r.err
	}
	rows := r.rows
	if after != nil {
		var rest []verificationview.Session
		for _, row := range rows {
			if row.CreatedAt.Before(after.CreatedAt) {
				rest = append(rest, row)
			}
		}
		rows = rest
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func vrRows() []verificationview.Session {
	base := time.Date(2026, 11, 16, 12, 0, 0, 123456000, time.UTC)
	completed := base.Add(-time.Minute)
	return []verificationview.Session{
		{SessionID: vrSessionA, Status: "pending", CreatedAt: base, ExpiresAt: base.Add(5 * time.Minute)},
		{SessionID: vrSessionB, Status: "completed", Result: "fail", Codes: []string{"issuer_untrusted"}, ReportDigest: "sha256:" + strings.Repeat("ab", 32),
			CreatedAt: base.Add(-2 * time.Minute), ExpiresAt: base.Add(3 * time.Minute), CompletedAt: &completed},
		{SessionID: vrSessionC, Status: "expired", CreatedAt: base.Add(-time.Hour), ExpiresAt: base.Add(-55 * time.Minute)},
	}
}

func vrRig(t *testing.T) (*VerificationHandler, *vrReader, *http.ServeMux) {
	t.Helper()
	h, _, _, _ := vsRig(t, 4)
	h.Operators.Verifier = vrOperators{}
	reader := &vrReader{rows: vrRows()}
	h.Reader = reader
	h.CursorKey = []byte("0123456789abcdef0123456789abcdef")
	mux := http.NewServeMux()
	h.Register(mux)
	return h, reader, mux
}

func vrGet(mux *http.ServeMux, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func vrList(t *testing.T, mux *http.ServeMux, tenant, query string) (int, VerificationPage) {
	t.Helper()
	rec := vrGet(mux, "/v1/operator/tenants/"+tenant+"/verification-sessions"+query, "valid")
	var page VerificationPage
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code, page
}

func TestListVerificationSessionsForAuthorizedRoles(t *testing.T) {
	for _, tenant := range []string{"admin", "security"} {
		_, reader, mux := vrRig(t)
		rec := vrGet(mux, "/v1/operator/tenants/"+tenant+"/verification-sessions", "valid")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d body %s", tenant, rec.Code, rec.Body)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: response must not be cacheable", tenant)
		}
		body := rec.Body.String()
		for _, forbidden := range []string{"nonce", "state", "jws", "claims", "vp_token", "launchUri"} {
			if strings.Contains(strings.ToLower(body), forbidden) {
				t.Fatalf("%s: response leaks %q: %s", tenant, forbidden, body)
			}
		}
		var page VerificationPage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 3 || page.NextCursor != nil || reader.lastTenant != tenant || reader.lastLimit != defaultVerificationPage+1 {
			t.Fatalf("%s: items=%d cursor=%v tenant=%q limit=%d", tenant, len(page.Items), page.NextCursor, reader.lastTenant, reader.lastLimit)
		}
		if !strings.Contains(body, `"nextCursor":null`) || !strings.Contains(body, `"reportDigest":"sha256:`) {
			t.Fatalf("%s: unexpected body %s", tenant, body)
		}
	}
}

func TestListVerificationSessionsRejectsWithoutCapabilityOrTenant(t *testing.T) {
	_, reader, mux := vrRig(t)
	for tenant, want := range map[string]int{"operator": 403, "support": 403, "foreign": 404} {
		if code, _ := vrList(t, mux, tenant, ""); code != want {
			t.Fatalf("%s: status %d, want %d", tenant, code, want)
		}
	}
	if code := vrGet(mux, "/v1/operator/tenants/admin/verification-sessions", "").Code; code != 401 {
		t.Fatalf("no bearer: status %d", code)
	}
	if code := vrGet(mux, "/v1/operator/tenants/admin/verification-sessions", "forged").Code; code != 401 {
		t.Fatalf("forged bearer: status %d", code)
	}
	if reader.listCalls != 0 || reader.getCalls != 0 {
		t.Fatalf("data read before authorization: list=%d get=%d", reader.listCalls, reader.getCalls)
	}
}

func TestListVerificationSessionsPaginatesWithABoundCursor(t *testing.T) {
	_, reader, mux := vrRig(t)
	code, first := vrList(t, mux, "admin", "?limit=2")
	if code != 200 || len(first.Items) != 2 || first.NextCursor == nil || reader.lastLimit != 3 {
		t.Fatalf("first page: status %d items %d cursor %v limit %d", code, len(first.Items), first.NextCursor, reader.lastLimit)
	}
	cursor := *first.NextCursor
	if len(cursor) < 32 || len(cursor) > 2048 || strings.ContainsAny(cursor, "+/=.") {
		t.Fatalf("cursor outside the contract: %q", cursor)
	}
	code, second := vrList(t, mux, "admin", "?limit=2&cursor="+cursor)
	if code != 200 || len(second.Items) != 1 || second.NextCursor != nil || second.Items[0].SessionID != vrSessionC {
		t.Fatalf("second page: status %d items %+v cursor %v", code, second.Items, second.NextCursor)
	}
	if reader.lastAfter == nil || reader.lastAfter.SessionID != vrSessionB || !reader.lastAfter.CreatedAt.Equal(first.Items[1].CreatedAt) {
		t.Fatalf("keyset position not the last row of the page: %+v", reader.lastAfter)
	}
	// The same cursor is useless for another tenant, another filter, or once altered.
	reader.listCalls = 0
	// Flip a character inside the payload, where every bit is meaningful.
	swap := "A"
	if cursor[10] == 'A' {
		swap = "B"
	}
	flipped := cursor[:10] + swap + cursor[11:]
	for name, query := range map[string]string{
		"other filter": "?status=completed&cursor=" + cursor,
		"tampered":     "?cursor=" + flipped,
		"garbage":      "?cursor=" + strings.Repeat("A", 40),
		"short":        "?cursor=abc",
		"bad charset":  "?cursor=" + strings.Repeat("!", 40),
	} {
		if code, _ := vrList(t, mux, "admin", query); code != 422 {
			t.Fatalf("%s: status %d, want 422", name, code)
		}
	}
	if code, _ := vrList(t, mux, "security", "?cursor="+cursor); code != 422 {
		t.Fatalf("cursor replayed on another tenant: status %d", code)
	}
	if reader.listCalls != 0 {
		t.Fatalf("a rejected cursor reached the reader %d times", reader.listCalls)
	}
}

func TestListVerificationSessionsValidatesTheQuery(t *testing.T) {
	_, reader, mux := vrRig(t)
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=abc", "?limit=1&limit=2", "?status=failed", "?status=", "?status=pending&status=completed", "?tenant=other", "?sort=asc"} {
		want := 422
		if query == "?status=" {
			want = 200 // an empty filter means no filter
		}
		if code, _ := vrList(t, mux, "admin", query); code != want {
			t.Fatalf("%s: status %d, want %d", query, code, want)
		}
	}
	reader.listCalls = 0
	for _, status := range []string{"pending", "completed", "expired"} {
		if code, _ := vrList(t, mux, "admin", "?status="+status); code != 200 || reader.lastStatus != status {
			t.Fatalf("%s: status %d passed %q", status, code, reader.lastStatus)
		}
	}
	if code, _ := vrList(t, mux, "admin", "?limit=100"); code != 200 || reader.lastLimit != 101 {
		t.Fatalf("limit 100 must ask for 101 rows, got %d", reader.lastLimit)
	}
}

func TestGetVerificationSession(t *testing.T) {
	_, reader, mux := vrRig(t)
	rec := vrGet(mux, "/v1/operator/tenants/admin/verification-sessions/"+vrSessionB, "valid")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	var session verificationview.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.Status != "completed" || session.Result != "fail" || len(session.Codes) != 1 || session.CompletedAt == nil || reader.lastTenant != "admin" {
		t.Fatalf("unexpected session %+v", session)
	}
	pending := vrGet(mux, "/v1/operator/tenants/admin/verification-sessions/"+vrSessionA, "valid").Body.String()
	for _, absent := range []string{`"result"`, `"codes"`, `"reportDigest"`, `"completedAt"`} {
		if strings.Contains(pending, absent) {
			t.Fatalf("a pending session must not carry %s: %s", absent, pending)
		}
	}
}

func TestGetVerificationSessionHidesMissingAndMalformedIdentifiers(t *testing.T) {
	_, reader, mux := vrRig(t)
	for _, id := range []string{"7a7f8c3e-5b0e-4a6b-9a39-0d6c1f3c9aff", "not-a-uuid", "7A7F8C3E-5B0E-4A6B-9A39-0D6C1F3C9A11"} {
		rec := vrGet(mux, "/v1/operator/tenants/admin/verification-sessions/"+id, "valid")
		if rec.Code != 404 || !strings.Contains(rec.Body.String(), "resource_not_found") {
			t.Fatalf("%q: status %d body %s", id, rec.Code, rec.Body)
		}
	}
	if reader.getCalls != 1 {
		t.Fatalf("malformed identifiers must not reach the reader, calls=%d", reader.getCalls)
	}
	for tenant, want := range map[string]int{"operator": 403, "support": 403, "foreign": 404} {
		if code := vrGet(mux, "/v1/operator/tenants/"+tenant+"/verification-sessions/"+vrSessionA, "valid").Code; code != want {
			t.Fatalf("%s: status %d, want %d", tenant, code, want)
		}
	}
	if code := vrGet(mux, "/v1/operator/tenants/admin/verification-sessions/"+vrSessionA, "").Code; code != 401 {
		t.Fatalf("no bearer: status %d", code)
	}
	if reader.getCalls != 1 {
		t.Fatalf("data read before authorization, calls=%d", reader.getCalls)
	}
}

func TestReadVerificationSessionsFailClosed(t *testing.T) {
	h, reader, mux := vrRig(t)
	reader.err = errors.New("pq: connection refused host=db")
	for _, path := range []string{"/v1/operator/tenants/admin/verification-sessions", "/v1/operator/tenants/admin/verification-sessions/" + vrSessionA} {
		if rec := vrGet(mux, path, "valid"); rec.Code != 503 || strings.Contains(rec.Body.String(), "refused") {
			t.Fatalf("%s: status %d body %s", path, rec.Code, rec.Body)
		}
	}
	reader.err = nil
	for name, mutate := range map[string]func(){
		"no reader":     func() { h.Reader = nil },
		"short key":     func() { h.Reader, h.CursorKey = reader, []byte("short") },
		"no key":        func() { h.CursorKey = nil },
		"no tenancy":    func() { h.CursorKey = []byte("0123456789abcdef0123456789abcdef"); h.Operators.Tenancy = nil },
		"no authorizer": func() { h.Operators.Verifier = nil },
	} {
		mutate()
		rec := vrGet(mux, "/v1/operator/tenants/admin/verification-sessions", "valid")
		if rec.Code != 503 {
			t.Fatalf("%s: status %d, want 503", name, rec.Code)
		}
		h2, _, _ := vrRig(t)
		*h = *h2
		mux = http.NewServeMux()
		h.Register(mux)
	}
}

func TestReadVerificationSessionsRequireGET(t *testing.T) {
	_, reader, mux := vrRig(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/operator/tenants/admin/verification-sessions/"+vrSessionA, nil)
	req.Header.Set("Authorization", "Bearer valid")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 405 || reader.getCalls != 0 {
		t.Fatalf("POST on a session: status %d calls %d", rec.Code, reader.getCalls)
	}
}
