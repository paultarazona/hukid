package privateapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/verificationview"
)

// VerificationCapabilityRead is granted by the local membership (ADR-0033 #5).
// Reading needs no step-up: it never creates or changes anything.
const VerificationCapabilityRead = "verification:read"

const (
	defaultVerificationPage = 25
	maxVerificationPage     = 100
	// Keep the cursor inside the contract's 32..2048 character window.
	maxVerificationCursor = 2048
)

var (
	sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	cursorPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// VerificationReader reads sessions for an already authorized tenant. Status
// is "", "pending", "completed" or "expired"; "expired" is derived from
// expires_at by the reader, as stored statuses are only pending and completed.
type VerificationReader interface {
	Get(ctx context.Context, actor, tenant, sessionID string) (verificationview.Session, error)
	// List returns at most limit rows, newest first, strictly after after.
	List(ctx context.Context, actor, tenant, status string, limit int, after *verificationview.Position) ([]verificationview.Session, error)
}

// VerificationPage is the list response body.
type VerificationPage struct {
	Items      []verificationview.Session `json:"items"`
	NextCursor *string                    `json:"nextCursor"`
}

type cursorBody struct {
	Tenant    string `json:"t"`
	Actor     string `json:"a"`
	Status    string `json:"s"`
	CreatedAt string `json:"c"`
	SessionID string `json:"i"`
}

func cursorMAC(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("hukid.verification.cursor.v1\x00"))
	mac.Write(payload)
	return mac.Sum(nil)
}

// sealCursor authenticates the position and binds it to tenant, actor and
// filter, so a cursor cannot be replayed for another tenant, operator or status.
func sealCursor(key []byte, tenant, actor, status string, pos verificationview.Position) string {
	payload, _ := json.Marshal(cursorBody{tenant, actor, status, pos.CreatedAt.UTC().Format(time.RFC3339Nano), pos.SessionID})
	return base64.RawURLEncoding.EncodeToString(append(payload, cursorMAC(key, payload)...))
}

func openCursor(key []byte, raw, tenant, actor, status string) (verificationview.Position, error) {
	if len(raw) < 32 || len(raw) > maxVerificationCursor || !cursorPattern.MatchString(raw) {
		return verificationview.Position{}, a.ErrRequest
	}
	blob, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(blob) <= sha256.Size {
		return verificationview.Position{}, a.ErrRequest
	}
	payload, tag := blob[:len(blob)-sha256.Size], blob[len(blob)-sha256.Size:]
	if !hmac.Equal(tag, cursorMAC(key, payload)) {
		return verificationview.Position{}, a.ErrRequest
	}
	var body cursorBody
	if json.Unmarshal(payload, &body) != nil || body.Tenant != tenant || body.Actor != actor || body.Status != status || !sessionIDPattern.MatchString(body.SessionID) {
		return verificationview.Position{}, a.ErrRequest
	}
	created, err := time.Parse(time.RFC3339Nano, body.CreatedAt)
	if err != nil {
		return verificationview.Position{}, a.ErrRequest
	}
	return verificationview.Position{CreatedAt: created, SessionID: body.SessionID}, nil
}

func (h *VerificationHandler) readReady() bool {
	return h != nil && h.Operators != nil && h.Operators.Tenancy != nil && h.Operators.Verifier != nil && h.Reader != nil && len(h.CursorKey) >= 32
}

// bearerActor verifies the operator token and resolves the local identity. No
// tenant data is read before it succeeds.
func (h *VerificationHandler) bearerActor(ctx context.Context, r *http.Request) (string, error) {
	raw, err := Bearer(r)
	if err != nil {
		return "", err
	}
	operator, err := h.Operators.Verifier.VerifyOperator(ctx, raw)
	if err != nil {
		return "", err
	}
	identity, err := h.Operators.Tenancy.Me(ctx, operator)
	if err != nil {
		return "", err
	}
	return identity.ActorID, nil
}

// requireRead checks the live membership and the verification:read capability.
func (h *VerificationHandler) requireRead(ctx context.Context, actor, tenant string) error {
	member, err := h.Operators.Tenancy.Context(ctx, actor, tenant)
	if err != nil {
		return err
	}
	if !slices.Contains(member.Capabilities, VerificationCapabilityRead) {
		return errVerificationForbidden
	}
	return nil
}

func (h *VerificationHandler) list(w http.ResponseWriter, r *http.Request) {
	h.bearerRead(w, r, "list")
}

func (h *VerificationHandler) get(w http.ResponseWriter, r *http.Request) {
	h.bearerRead(w, r, "get")
}

func (h *VerificationHandler) bearerRead(w http.ResponseWriter, r *http.Request, kind string) {
	ok := PrepareMethod(w, r, http.MethodGet)
	if !h.readReady() {
		if ok {
			VerificationProblem(w, a.ErrDependency)
		}
		return
	}
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	actor, err := h.bearerActor(ctx, r)
	if err != nil {
		VerificationProblem(w, err)
		return
	}
	h.ServeRead(w, r.WithContext(ctx), actor, kind, true)
}

// ServeRead serves the list (kind "list") or one session (kind "get") for an
// actor the caller already authenticated, after re-checking membership and the
// verification:read capability. The caller must have run PrepareMethod. The
// browser mount reuses it with the session cookie instead of a Bearer token.
func (h *VerificationHandler) ServeRead(w http.ResponseWriter, r *http.Request, actor, kind string, bearer bool) {
	fail := func(err error) { VerificationProblemFor(w, err, bearer) }
	if !h.readReady() {
		fail(a.ErrDependency)
		return
	}
	tenant := r.PathValue("tenantId")
	if err := h.requireRead(r.Context(), actor, tenant); err != nil {
		fail(err)
		return
	}
	if kind == "get" {
		h.serveGet(w, r, actor, tenant, fail)
		return
	}
	h.serveList(w, r, actor, tenant, fail)
}

func (h *VerificationHandler) serveList(w http.ResponseWriter, r *http.Request, actor, tenant string, fail func(error)) {
	status, limit, rawCursor, err := parseListQuery(r)
	if err != nil {
		fail(err)
		return
	}
	var after *verificationview.Position
	if rawCursor != "" {
		position, err := openCursor(h.CursorKey, rawCursor, tenant, actor, status)
		if err != nil {
			fail(err)
			return
		}
		after = &position
	}
	// One extra row tells whether another page exists without a count query.
	rows, err := h.Reader.List(r.Context(), actor, tenant, status, limit+1, after)
	if err != nil {
		fail(err)
		return
	}
	page := VerificationPage{Items: []verificationview.Session{}}
	if len(rows) > limit {
		last := rows[limit-1]
		cursor := sealCursor(h.CursorKey, tenant, actor, status, verificationview.Position{CreatedAt: last.CreatedAt, SessionID: last.SessionID})
		page.NextCursor = &cursor
		rows = rows[:limit]
	}
	page.Items = append(page.Items, rows...)
	writeJSON(w, http.StatusOK, page)
}

func (h *VerificationHandler) serveGet(w http.ResponseWriter, r *http.Request, actor, tenant string, fail func(error)) {
	sessionID := r.PathValue("sessionId")
	if !sessionIDPattern.MatchString(sessionID) {
		fail(verificationview.ErrNotFound)
		return
	}
	session, err := h.Reader.Get(r.Context(), actor, tenant, sessionID)
	if err != nil {
		fail(err)
		return
	}
	writeJSON(w, http.StatusOK, session)
}

func parseListQuery(r *http.Request) (status string, limit int, cursor string, err error) {
	query := r.URL.Query()
	for key, values := range query {
		if (key != "status" && key != "limit" && key != "cursor") || len(values) != 1 {
			return "", 0, "", a.ErrRequest
		}
	}
	status = query.Get("status")
	if status != "" && status != "pending" && status != "completed" && status != "expired" {
		return "", 0, "", a.ErrRequest
	}
	limit = defaultVerificationPage
	if raw := query.Get("limit"); raw != "" {
		parsed, convErr := strconv.Atoi(raw)
		if convErr != nil || parsed < 1 || parsed > maxVerificationPage {
			return "", 0, "", a.ErrRequest
		}
		limit = parsed
	}
	return status, limit, query.Get("cursor"), nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
