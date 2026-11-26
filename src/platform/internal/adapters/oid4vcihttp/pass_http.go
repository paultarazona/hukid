package oid4vcihttp

// Check-in pass endpoints (ADR-0038). The two wallet endpoints are public: the
// signed holder presentation is the credential. Redeeming a pass belongs to the
// Integration API and needs pass:verify. Codes and presentations are never logged.

import (
	"errors"
	"net/http"

	"hukid.local/platform/internal/issuance"
)

func (h *IssuanceHandler) passNonce(w http.ResponseWriter, _ *http.Request) {
	if !h.ready() {
		problem(w, http.StatusServiceUnavailable, "server_error", "Service unavailable", nil)
		return
	}
	nonce, err := h.Service.NewPassNonce()
	if err != nil {
		problem(w, http.StatusInternalServerError, "server_error", "Internal error", nil)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", nonce)
}

func (h *IssuanceHandler) createPass(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		problem(w, http.StatusServiceUnavailable, "server_error", "Service unavailable", nil)
		return
	}
	var in struct {
		Presentation string `json:"presentation"`
	}
	if !isJSON(r) || decodeBody(w, r, maxPassBody, &in, true) != nil || in.Presentation == "" {
		problem(w, http.StatusBadRequest, "malformed_request", "The request body is not valid", nil)
		return
	}
	pass, err := h.Service.CreatePass(in.Presentation)
	switch {
	case errors.Is(err, issuance.ErrPassUnsupported):
		problem(w, http.StatusUnprocessableEntity, "pass_not_supported", "The credential does not support check-in", nil)
	case errors.Is(err, issuance.ErrPassBusy):
		w.Header().Set("Retry-After", "5")
		problem(w, http.StatusTooManyRequests, "too_many_passes", "Try again shortly", nil)
	case err != nil:
		problem(w, http.StatusForbidden, "pass_rejected", "The presentation was not accepted", nil)
	default:
		writeJSON(w, http.StatusCreated, "application/json", pass)
	}
}

func (h *IssuanceHandler) verifyPass(w http.ResponseWriter, r *http.Request) {
	token, ok := h.authenticateIntegration(w, r)
	if !ok {
		return
	}
	var in struct {
		Code    string `json:"code"`
		EventID string `json:"eventId"`
	}
	if !isJSON(r) || decodeBody(w, r, maxTokenBody, &in, true) != nil {
		problem(w, http.StatusBadRequest, "malformed_request", "The request body is not valid", nil)
		return
	}
	result, err := h.Service.VerifyPass(token, in.Code, in.EventID)
	if err != nil {
		writeIntegrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", result)
}
