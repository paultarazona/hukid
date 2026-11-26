package issuance

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSetIssuerPrefixAndValidation(t *testing.T) {
	defer func() {
		if err := SetIssuerPrefix(DefaultIssuerPrefix); err != nil {
			t.Fatalf("restore default prefix: %v", err)
		}
	}()

	if err := SetIssuerPrefix("https://tunnel.trycloudflare.com"); err != nil {
		t.Fatalf("SetIssuerPrefix valid tunnel failed: %v", err)
	}
	if IssuerPrefix != "https://tunnel.trycloudflare.com/" {
		t.Fatalf("unexpected IssuerPrefix: %q", IssuerPrefix)
	}

	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	rec, err := NewIssuerRecord("tenant-unas", "iss_tunnel", "unas", "UNAS Tunnel", now)
	if err != nil {
		t.Fatalf("NewIssuerRecord failed: %v", err)
	}
	if rec.IssuerURI != "https://tunnel.trycloudflare.com/unas" {
		t.Fatalf("unexpected IssuerURI: %q", rec.IssuerURI)
	}
	if err := ValidateIssuerIdentifier(rec.IssuerURI); err != nil {
		t.Fatalf("ValidateIssuerIdentifier failed for custom prefix: %v", err)
	}

	if err := SetIssuerPrefix("https://issuer.hukid.pe/public/"); err != nil {
		t.Fatalf("SetIssuerPrefix subpath failed: %v", err)
	}
	subRec, err := NewIssuerRecord("tenant-unas", "iss_sub", "fiis", "FIIS", now)
	if err != nil || subRec.IssuerURI != "https://issuer.hukid.pe/public/fiis" {
		t.Fatalf("unexpected subpath IssuerURI: %+v err=%v", subRec, err)
	}

	for _, invalid := range []string{
		"ftp://remote.example.com/",
		"https://issuer.example.com?bad=1",
		"https://issuer.example.com#frag",
		"https://user:pass@issuer.example.com/",
		"/relative/path",
	} {
		if err := SetIssuerPrefix(invalid); err == nil {
			t.Fatalf("expected SetIssuerPrefix(%q) to fail", invalid)
		}
	}
	if err := SetIssuerPrefix("   "); err != nil || IssuerPrefix != DefaultIssuerPrefix {
		t.Fatalf("expected empty SetIssuerPrefix to reset default, got prefix=%q err=%v", IssuerPrefix, err)
	}
}

func TestOperatorChangeCredentialStatus(t *testing.T) {
	h := newServiceHarness(t)
	def := sampleCertificateDefinition("tenant-unas", "iss_unas")
	def.Version = "2.0.0"
	def.ConfigurationID = "unas_certificate_susp_v2"
	def.StatusPurposes = []string{PurposeRevocation, PurposeSuspension}
	if err := h.defs.CreateDraft(def, "admin-1", "cor-susp-1", h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.defs.Publish("tenant-unas", "iss_unas", def.ID, def.Version, "admin-1", "cor-susp-2", h.clock.Now()); err != nil {
		t.Fatal(err)
	}

	tokResp, err := h.svc.ClientCredentialsToken("cli_events", "events-secret-0123456789abcdef", []string{ScopeIssuanceCreate, ScopeIssuanceRead})
	if err != nil {
		t.Fatal(err)
	}
	intTok, err := h.svc.AuthenticateIntegration(tokResp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := h.svc.CreateIssuanceRequest(intTok, "op-status-req-0001", IssuanceRequestInput{
		IssuerID:             "iss_unas",
		CredentialDefinition: "unas-certificate@2.0.0",
		Claims: map[string]any{
			"participantName": "Luis Torres",
			"eventName":       "Simposio IA",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := h.svc.ResolveOffer("unas", created.CredentialOfferURI[strings.LastIndex(created.CredentialOfferURI, "ofr_"):])
	if err != nil {
		t.Fatal(err)
	}
	vciTok, err := h.svc.PreAuthorizedToken(offer.Grants[PreAuthorizedGrantType].PreAuthorizedCode)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := h.svc.IssueNonce("unas")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := BuildHolderProof(mustGenerateKey(t), h.issuer.IssuerURI, nonce, h.clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.RequestCredential("unas", vciTok.AccessToken, CredentialRequest{
		CredentialIdentifier: vciTok.AuthorizationDetails[0].CredentialIdentifiers[0],
		Proofs: struct {
			JWT []string `json:"jwt"`
		}{JWT: []string{proof}},
	}); err != nil {
		t.Fatal(err)
	}
	polled, err := h.svc.GetRequest(intTok, created.ID)
	if err != nil || polled.CredentialID == "" {
		t.Fatalf("GetRequest failed: %+v err=%v", polled, err)
	}

	if _, err := h.svc.OperatorChangeCredentialStatus("tenant-unas", polled.CredentialID, "suspend", "actor-admin", "cor-bad", StatusChangeInput{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest without reasonCode on suspend, got %v", err)
	}
	if _, err := h.svc.OperatorChangeCredentialStatus("other-tenant", polled.CredentialID, "suspend", "actor-admin", "cor-x", StatusChangeInput{ReasonCode: "operator_request"}); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound cross-tenant, got %v", err)
	}

	susp, err := h.svc.OperatorChangeCredentialStatus("tenant-unas", polled.CredentialID, "suspend", "actor-admin", "cor-op-1", StatusChangeInput{ReasonCode: "operator_request"})
	if err != nil || susp.DesiredStatus != CredentialStatusSuspended || susp.PublishedStatus != CredentialStatusSuspended {
		t.Fatalf("unexpected suspend result: %+v err=%v", susp, err)
	}
	react, err := h.svc.OperatorChangeCredentialStatus("tenant-unas", polled.CredentialID, "reactivate", "actor-admin", "cor-op-2", StatusChangeInput{})
	if err != nil || react.DesiredStatus != CredentialStatusActive || react.PublishedStatus != CredentialStatusActive {
		t.Fatalf("unexpected reactivate result: %+v err=%v", react, err)
	}
	rev, err := h.svc.OperatorChangeCredentialStatus("tenant-unas", polled.CredentialID, "revoke", "actor-admin", "cor-op-3", StatusChangeInput{ReasonCode: "security_response"})
	if err != nil || rev.DesiredStatus != CredentialStatusRevoked || rev.PublishedStatus != CredentialStatusRevoked {
		t.Fatalf("unexpected revoke result: %+v err=%v", rev, err)
	}
	if _, err := h.svc.OperatorChangeCredentialStatus("tenant-unas", polled.CredentialID, "reactivate", "actor-admin", "cor-op-4", StatusChangeInput{}); !errors.Is(err, ErrInvalidStatusTransition) {
		t.Fatalf("expected ErrInvalidStatusTransition reactivating revoked credential, got %v", err)
	}
	events, err := h.svc.ListAuditEvents("tenant-unas", "credential.revoked")
	if err != nil || len(events) != 1 || events[0].ActorID != "actor-admin" {
		t.Fatalf("expected operator actor in revocation audit: %+v err=%v", events, err)
	}
}

func TestRetentionMetricsAndReplayDLQ(t *testing.T) {
	h := newServiceHarness(t)
	tokResp, err := h.svc.ClientCredentialsToken("cli_events", "events-secret-0123456789abcdef", []string{ScopeIssuanceCreate, ScopeIssuanceRead})
	if err != nil {
		t.Fatal(err)
	}
	intTok, err := h.svc.AuthenticateIntegration(tokResp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Stale offer request (will expire and later be crypto-shredded).
	staleReq, _, err := h.svc.CreateIssuanceRequest(intTok, "stale-offer-req-001", IssuanceRequestInput{
		IssuerID:             "iss_unas",
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims:               map[string]any{"participantName": "Expirado", "eventName": "Evento"},
		Source:               &SourceInput{System: "events", Reference: "stale-ref"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Deferred request -> redeemed -> failed (DLQ) -> replayed -> fulfilled -> retrieved.
	defReq, _, err := h.svc.CreateIssuanceRequest(intTok, "dlq-replay-req-0001", IssuanceRequestInput{
		IssuerID:             "iss_unas",
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims:               map[string]any{"participantName": "Carla Vela", "eventName": "Workshop"},
		Delivery:             &DeliveryInput{Deferred: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := h.svc.ResolveOffer("unas", defReq.CredentialOfferURI[strings.LastIndex(defReq.CredentialOfferURI, "ofr_"):])
	if err != nil {
		t.Fatal(err)
	}
	vciTok, err := h.svc.PreAuthorizedToken(offer.Grants[PreAuthorizedGrantType].PreAuthorizedCode)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := h.svc.IssueNonce("unas")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := BuildHolderProof(mustGenerateKey(t), h.issuer.IssuerURI, nonce, h.clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := h.svc.RequestCredential("unas", vciTok.AccessToken, CredentialRequest{
		CredentialIdentifier: vciTok.AuthorizationDetails[0].CredentialIdentifiers[0],
		Proofs: struct {
			JWT []string `json:"jwt"`
		}{JWT: []string{proof}},
	})
	if err != nil || outcome.TransactionID == "" {
		t.Fatalf("deferred request failed: %+v err=%v", outcome, err)
	}

	if err := h.svc.FailDeferredRequest("tenant-unas", defReq.ID, "kms_timeout"); err != nil {
		t.Fatal(err)
	}
	metrics, err := h.svc.OperationalMetrics("tenant-unas")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.ActiveIssuers != 1 || metrics.PublishedDefinitions != 1 || metrics.PreparedRequests != 1 || metrics.DeferredFailedDLQ != 1 {
		t.Fatalf("unexpected metrics with DLQ item: %+v", metrics)
	}

	if err := h.svc.ReplayFailedDeferredRequest("tenant-unas", defReq.ID, "actor-admin", "cor-dlq-1"); err != nil {
		t.Fatalf("ReplayFailedDeferredRequest failed: %v", err)
	}
	if err := h.svc.ReplayFailedDeferredRequest("tenant-unas", defReq.ID, "actor-admin", "cor-dlq-2"); !errors.Is(err, ErrInvalidStatusTransition) {
		t.Fatalf("expected ErrInvalidStatusTransition replaying non-failed request, got %v", err)
	}
	fulfilled, err := h.svc.FulfillPendingDeferredRequests("tenant-unas", 10)
	if err != nil || fulfilled != 1 {
		t.Fatalf("FulfillPendingDeferredRequests after replay = %d err=%v", fulfilled, err)
	}
	if vcJWT, _, err := h.svc.DeferredCredential("unas", vciTok.AccessToken, outcome.TransactionID); err != nil || vcJWT == "" {
		t.Fatalf("DeferredCredential after replay failed: err=%v", err)
	}

	// 3. Uncollected fulfilled deferred VC (wallet never picked it up -> retention shreds VCCipher).
	uncollectedReq, _, err := h.svc.CreateIssuanceRequest(intTok, "uncollected-def-req-1", IssuanceRequestInput{
		IssuerID:             "iss_unas",
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims:               map[string]any{"participantName": "Uncollected", "eventName": "Workshop"},
		Delivery:             &DeliveryInput{Deferred: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	uncollectedOffer, _ := h.svc.ResolveOffer("unas", uncollectedReq.CredentialOfferURI[strings.LastIndex(uncollectedReq.CredentialOfferURI, "ofr_"):])
	uncollectedVCI, _ := h.svc.PreAuthorizedToken(uncollectedOffer.Grants[PreAuthorizedGrantType].PreAuthorizedCode)
	uncollectedNonce, _ := h.svc.IssueNonce("unas")
	uncollectedProof, _ := BuildHolderProof(mustGenerateKey(t), h.issuer.IssuerURI, uncollectedNonce, h.clock.Now(), nil)
	if _, err := h.svc.RequestCredential("unas", uncollectedVCI.AccessToken, CredentialRequest{
		CredentialIdentifier: uncollectedVCI.AuthorizationDetails[0].CredentialIdentifiers[0],
		Proofs: struct {
			JWT []string `json:"jwt"`
		}{JWT: []string{uncollectedProof}},
	}); err != nil {
		t.Fatal(err)
	}
	if fulfilled2, err := h.svc.FulfillPendingDeferredRequests("tenant-unas", 10); err != nil || fulfilled2 != 1 {
		t.Fatalf("fulfill uncollected deferred failed: fulfilled=%d err=%v", fulfilled2, err)
	}

	metrics, err = h.svc.OperationalMetrics("tenant-unas")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.DeferredPending != 0 || metrics.DeferredFailedDLQ != 0 || metrics.IssuedCredentials != 2 {
		t.Fatalf("unexpected post-fulfill metrics: %+v", metrics)
	}

	// Expire stale offer first (+35m), then cancel it so both become terminal before retention cutoff.
	h.clock.Advance(35 * time.Minute)
	summary1, err := h.svc.PurgeExpiredMaterial("tenant-unas", 7*24*time.Hour, 100, "system:retention", "cor-ret-1")
	if err != nil {
		t.Fatal(err)
	}
	if summary1.ExpiredOffers != 1 || summary1.ShreddedRequests != 0 || summary1.ShreddedDeferredVCs != 0 {
		t.Fatalf("unexpected first retention pass summary: %+v", summary1)
	}
	tokResp2, err := h.svc.ClientCredentialsToken("cli_events", "events-secret-0123456789abcdef", []string{ScopeIssuanceCreate, ScopeIssuanceRead})
	if err != nil {
		t.Fatal(err)
	}
	intTok2, err := h.svc.AuthenticateIntegration(tokResp2.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.CancelRequest(intTok2, staleReq.ID); err != nil {
		t.Fatalf("cancel stale request failed: %v", err)
	}

	// Advance past 7-day retention window -> crypto-shreds stale cancelled + 2 issued requests and 1 uncollected deferred VC envelope.
	h.clock.Advance(8 * 24 * time.Hour)
	summary2, err := h.svc.PurgeExpiredMaterial("tenant-unas", 7*24*time.Hour, 100, "system:retention", "cor-ret-2")
	if err != nil {
		t.Fatal(err)
	}
	if summary2.ShreddedRequests != 3 || summary2.ShreddedDeferredVCs != 1 {
		t.Fatalf("expected 3 shredded requests and 1 shredded deferred VC, got %+v", summary2)
	}
	summary3, err := h.svc.PurgeExpiredMaterial("tenant-unas", 7*24*time.Hour, 100, "system:retention", "cor-ret-3")
	if err != nil {
		t.Fatal(err)
	}
	if summary3.ExpiredOffers != 0 || summary3.ShreddedRequests != 0 || summary3.ShreddedDeferredVCs != 0 {
		t.Fatalf("expected idempotent third retention pass to be zero, got %+v", summary3)
	}
	retAudit, err := h.svc.ListAuditEvents("tenant-unas", "issuance.retention_purged")
	if err != nil || len(retAudit) != 2 {
		t.Fatalf("expected 2 retention audit events, got %+v err=%v", retAudit, err)
	}
}
