package console

import (
	"context"
	"net/http"
	"time"

	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/authentication"
)

// VerificationHandler is the browser mount of the verification module. It
// authenticates the console session cookie and delegates to the same handlers
// as the Bearer API. Reads re-check the live membership and verification:read
// (VER-T11-e). Starting a session (ADR-0037) additionally requires the exact
// console Origin and the CSRF proof; the start handler then re-checks fresh
// MFA, the membership and verification:start.
type VerificationHandler struct {
	Auth       *MeHandler
	Management *privateapi.VerificationHandler
}

func (h *VerificationHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/console/api/tenants/{tenantId}/verification-sessions", func(w http.ResponseWriter, r *http.Request) { h.serve(w, r, "list") })
	mux.HandleFunc("/console/api/tenants/{tenantId}/verification-sessions/{sessionId}", func(w http.ResponseWriter, r *http.Request) { h.serve(w, r, "get") })
}

func (h *VerificationHandler) serve(w http.ResponseWriter, r *http.Request, kind string) {
	start := kind == "list" && r.Method == http.MethodPost
	method := http.MethodGet
	if start {
		method = http.MethodPost
	}
	if !privateapi.PrepareMethod(w, r, method) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	fail := func(err error) { privateapi.VerificationProblemFor(w, err, false) }
	if h == nil || h.Auth == nil || h.Management == nil {
		fail(authentication.ErrDependency)
		return
	}
	cookie := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == h.Auth.Sessions.Policy.CookieName {
			cookie = c.Value
			count++
		}
	}
	if count != 1 {
		fail(authentication.ErrSession)
		return
	}
	var session authentication.SessionView
	var err error
	if start {
		origins, proofs := r.Header.Values("Origin"), r.Header.Values("X-CSRF-Token")
		if len(origins) != 1 || origins[0] != h.Auth.Sessions.Policy.ConsoleOrigin {
			fail(authentication.ErrOrigin)
			return
		}
		if len(proofs) != 1 {
			fail(authentication.ErrCSRF)
			return
		}
		session, err = h.Auth.Sessions.CheckCommand(ctx, cookie, proofs[0])
	} else {
		session, err = h.Auth.Sessions.Read(ctx, cookie)
	}
	if err != nil {
		fail(err)
		return
	}
	operator, err := h.Auth.Verifier.VerifyOperator(ctx, session.AccessToken)
	if err != nil {
		fail(err)
		return
	}
	identity, err := h.Auth.Tenancy.Me(ctx, operator)
	if err != nil {
		fail(err)
		return
	}
	if identity.ActorID != session.ActorID {
		fail(authentication.ErrSession)
		return
	}
	// Browser reads must use the explicitly selected context, not a URL switch.
	if session.ActiveTenantID == "" || session.ActiveTenantID != r.PathValue("tenantId") {
		fail(authentication.ErrTenant)
		return
	}
	if err = h.Auth.Sessions.Touch(ctx, cookie); err != nil {
		fail(err)
		return
	}
	if start {
		command := r.Clone(ctx)
		command.Header.Del("Cookie")
		command.Header.Del("Origin")
		command.Header.Del("X-CSRF-Token")
		command.Header.Set("Authorization", "Bearer "+session.AccessToken)
		h.Management.ServeStart(w, command)
		return
	}
	h.Management.ServeRead(w, r.WithContext(ctx), identity.ActorID, kind, false)
}
