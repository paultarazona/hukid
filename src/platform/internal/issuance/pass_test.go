package issuance

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const passSecret = "events-secret-0123456789abcdef"

func b64json(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// holderPresentation builds the vp+jwt the wallet sends.
func holderPresentation(t *testing.T, key *ecdsa.PrivateKey, vc, audience, nonce string) string {
	t.Helper()
	raw, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"alg": "ES256", "typ": "vp+jwt", "jwk": map[string]any{"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(raw[1:33]), "y": base64.RawURLEncoding.EncodeToString(raw[33:])}}
	payload := map[string]any{
		"@context": []string{"https://www.w3.org/ns/credentials/v2", "https://schemas.hukid.pe/contexts/presentation/v1"},
		"type":     []string{"VerifiablePresentation"}, "aud": audience, "nonce": nonce,
		"verifiableCredential": []any{map[string]any{"type": "EnvelopedVerifiableCredential", "id": "data:application/vc+jwt," + vc}},
	}
	input := b64json(t, header) + "." + b64json(t, payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type passFixture struct {
	h        *serviceHarness
	holder   *ecdsa.PrivateKey
	vc       string
	issued   IntegrationToken
	door     IntegrationToken
	audience string
}

func newPassFixture(t *testing.T) *passFixture {
	t.Helper()
	h := newServiceHarness(t)
	def := sampleCertificateDefinition("tenant-unas", "iss_unas")
	def.ID = "event-participation"
	def.ConfigurationID = "event-participation-v1"
	def.Fields = map[string]FieldSpec{
		"recipient": {Type: "object", Required: true, Fields: map[string]FieldSpec{"registrationId": {Type: "string", Required: true}}},
		"event":     {Type: "object", Required: true, Fields: map[string]FieldSpec{"id": {Type: "string", Required: true}}},
	}
	if _, err := h.svc.CreateDraftDefinition(def, "admin-1", "cor-a"); err != nil {
		t.Fatalf("draft: %v", err)
	}
	if _, err := h.svc.PublishDefinition("tenant-unas", "iss_unas", def.ID, def.Version, "admin-1", "cor-b"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	token := func(client, secret string, scope string) IntegrationToken {
		resp, err := h.svc.ClientCredentialsToken(client, secret, []string{scope})
		if err != nil {
			t.Fatalf("token %s: %v", scope, err)
		}
		out, err := h.svc.AuthenticateIntegration(resp.AccessToken)
		if err != nil {
			t.Fatalf("auth %s: %v", scope, err)
		}
		return out
	}
	if _, _, err := h.svc.RegisterIntegrationClient("tenant-unas", "cli_door", "Puerta", passSecret, []string{"iss_unas"}, []string{ScopePassVerify}, nil, "admin-1", "cor-c"); err != nil {
		t.Fatalf("door client: %v", err)
	}
	f := &passFixture{h: h, holder: mustGenerateKey(t), audience: PassAudience(h.issuer.IssuerURI)}
	f.issued = token("cli_events", passSecret, ScopeIssuanceCreate)
	f.door = token("cli_door", passSecret, ScopePassVerify)

	res, _, err := h.svc.CreateIssuanceRequest(f.issued, "pass-fixture-key-0001", IssuanceRequestInput{
		IssuerID: "iss_unas", CredentialDefinition: "event-participation@1.0.0",
		Claims: map[string]any{"recipient": map[string]any{"registrationId": "reg-1"}, "event": map[string]any{"id": "event-1"}},
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	offer, err := h.svc.ResolveOffer("unas", res.CredentialOfferURI[strings.LastIndex(res.CredentialOfferURI, "ofr_"):])
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	access, err := h.svc.PreAuthorizedToken(offer.Grants[PreAuthorizedGrantType].PreAuthorizedCode)
	if err != nil {
		t.Fatalf("pre-authorized: %v", err)
	}
	nonce, err := h.svc.IssueNonce("unas")
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	proof, err := BuildHolderProof(f.holder, h.issuer.IssuerURI, nonce, h.clock.Now(), nil)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	req := CredentialRequest{CredentialIdentifier: access.AuthorizationDetails[0].CredentialIdentifiers[0]}
	req.Proofs.JWT = []string{proof}
	if f.vc, err = h.svc.IssueCredential("unas", access.AccessToken, req); err != nil {
		t.Fatalf("issue: %v", err)
	}
	return f
}

func (f *passFixture) pass(t *testing.T) Pass {
	t.Helper()
	nonce, err := f.h.svc.NewPassNonce()
	if err != nil {
		t.Fatal(err)
	}
	pass, err := f.h.svc.CreatePass(holderPresentation(t, f.holder, f.vc, f.audience, nonce.Nonce))
	if err != nil {
		t.Fatalf("create pass: %v", err)
	}
	return pass
}

func (f *passFixture) verify(t *testing.T, code, event string) PassVerification {
	t.Helper()
	out, err := f.h.svc.VerifyPass(f.door, code, event)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return out
}

func TestPassIsSingleUseAndBoundToTheEvent(t *testing.T) {
	f := newPassFixture(t)
	pass := f.pass(t)
	if got := f.verify(t, pass.Code, "otro-evento"); got.Result != PassResultFail || got.Code != PassCodeEventMismatch || got.RegistrationID != "" {
		t.Fatalf("wrong event: %+v", got)
	}
	got := f.verify(t, pass.Code, "event-1")
	if got.Result != PassResultPass || got.RegistrationID != "reg-1" || got.EventID != "event-1" ||
		got.CredentialDefinition != "event-participation@1.0.0" || !strings.HasPrefix(got.CredentialID, "vc_") {
		t.Fatalf("pass: %+v", got)
	}
	if again := f.verify(t, pass.Code, "event-1"); again.Result != PassResultFail || again.Code != PassCodeInvalid {
		t.Fatalf("reuse: %+v", again)
	}
}

func TestPassUsesCurrentAuthoritativeStatusAfterPublishedListExpires(t *testing.T) {
	f := newPassFixture(t)
	f.h.clock.Advance(f.h.svc.cfg.StatusListTTL + time.Minute)

	pass := f.pass(t)
	if pass.Code == "" {
		t.Fatal("expected an active credential to produce a pass after the cached status list expires")
	}
}

func TestPassExpiresAndANewOneReplacesTheOld(t *testing.T) {
	f := newPassFixture(t)
	first := f.pass(t)
	second := f.pass(t)
	if got := f.verify(t, first.Code, "event-1"); got.Code != PassCodeInvalid {
		t.Fatalf("replaced pass: %+v", got)
	}
	f.h.clock.Advance(PassTTL + time.Second)
	if got := f.verify(t, second.Code, "event-1"); got.Code != PassCodeInvalid {
		t.Fatalf("expired pass: %+v", got)
	}
}

func TestPassRequiresTheHolderKeyAudienceAndFreshNonce(t *testing.T) {
	f := newPassFixture(t)
	nonce, err := f.h.svc.NewPassNonce()
	if err != nil {
		t.Fatal(err)
	}
	good := holderPresentation(t, f.holder, f.vc, f.audience, nonce.Nonce)
	for name, vp := range map[string]string{
		"other holder key": holderPresentation(t, mustGenerateKey(t), f.vc, f.audience, nonce.Nonce),
		"other audience":   holderPresentation(t, f.holder, f.vc, "https://evil.example/v1/passes", nonce.Nonce),
		"forged nonce":     holderPresentation(t, f.holder, f.vc, f.audience, strings.Repeat("A", len(nonce.Nonce))),
		"tampered vc":      holderPresentation(t, f.holder, f.vc[:len(f.vc)-4]+"AAAA", f.audience, nonce.Nonce),
		"garbage":          "a.b.c",
	} {
		if _, err := f.h.svc.CreatePass(vp); !errors.Is(err, ErrPassRejected) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A correctly addressed, signed attempt consumes its nonce even if it fails
	// later (holder binding): the wallet asks for a new one.
	if _, err := f.h.svc.CreatePass(good); !errors.Is(err, ErrPassRejected) {
		t.Fatalf("consumed nonce: %v", err)
	}
	if nonce, err = f.h.svc.NewPassNonce(); err != nil {
		t.Fatal(err)
	}
	good = holderPresentation(t, f.holder, f.vc, f.audience, nonce.Nonce)
	if _, err := f.h.svc.CreatePass(good); err != nil {
		t.Fatalf("fresh nonce: %v", err)
	}
	if _, err := f.h.svc.CreatePass(good); !errors.Is(err, ErrPassRejected) {
		t.Fatalf("replayed presentation: %v", err)
	}
	stale, err := f.h.svc.NewPassNonce()
	if err != nil {
		t.Fatal(err)
	}
	f.h.clock.Advance(passNonceTTL + time.Second)
	if _, err := f.h.svc.CreatePass(holderPresentation(t, f.holder, f.vc, f.audience, stale.Nonce)); !errors.Is(err, ErrPassRejected) {
		t.Fatalf("stale nonce: %v", err)
	}
}

func TestPassNeedsScopeIssuerGrantAndActiveCredential(t *testing.T) {
	f := newPassFixture(t)
	pass := f.pass(t)
	if _, err := f.h.svc.VerifyPass(f.issued, pass.Code, "event-1"); !errors.Is(err, ErrClientUnauthorized) {
		t.Fatalf("issuance token must not redeem passes: %v", err)
	}
	foreign := f.door
	foreign.AllowedIssuers = []string{"iss_other"}
	if got, err := f.h.svc.VerifyPass(foreign, pass.Code, "event-1"); err != nil || got.Code != PassCodeInvalid {
		t.Fatalf("issuer not granted: %+v %v", got, err)
	}
	foreign = f.door
	foreign.TenantID = "tenant-other"
	if got, err := f.h.svc.VerifyPass(foreign, pass.Code, "event-1"); err != nil || got.Code != PassCodeInvalid {
		t.Fatalf("other tenant: %+v %v", got, err)
	}
	for _, record := range f.h.svc.mem.issuedCreds {
		record.DesiredStatus = "revoked"
	}
	if got := f.verify(t, pass.Code, "event-1"); got.Result != PassResultFail || got.Code != PassCodeNotActive {
		t.Fatalf("revoked after the pass: %+v", got)
	}
	nonce, err := f.h.svc.NewPassNonce()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.svc.CreatePass(holderPresentation(t, f.holder, f.vc, f.audience, nonce.Nonce)); !errors.Is(err, ErrPassRejected) {
		t.Fatalf("revoked credential must not get a pass: %v", err)
	}
}
