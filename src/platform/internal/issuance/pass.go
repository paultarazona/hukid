package issuance

// Check-in passes (ADR-0038). The holder proves possession of the key bound to a
// credential this HukID issued and receives a random, short-lived, single-use
// code that the wallet shows as a QR. The integration client of the door system
// exchanges that code, once, for the minimum data it needs. This is a HukID
// protocol, not OpenID4VP.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"hukid.local/platform/internal/verification"
)

const (
	// PassTTL is how long a pass code can be redeemed.
	PassTTL      = 60 * time.Second
	passNonceTTL = 60 * time.Second
	// maxPasses bounds the live passes and consumed nonces held in memory.
	maxPasses = 10000
	// PassPath is the path of the wallet endpoint; its URL on the issuer origin
	// is the audience of the holder presentation.
	PassPath = "/v1/passes"

	PassResultPass = "pass"
	PassResultFail = "fail"

	PassCodeInvalid       = "code_invalid"
	PassCodeEventMismatch = "event_mismatch"
	PassCodeNotActive     = "credential_not_active"
)

var (
	// ErrPassRejected hides why a presentation did not obtain a pass.
	ErrPassRejected = errors.New("pass presentation rejected")
	// ErrPassUnsupported means the credential lacks the check-in data.
	ErrPassUnsupported = errors.New("credential does not support check-in passes")
	// ErrPassBusy means the bounded in-memory store is full.
	ErrPassBusy = errors.New("too many live passes")
)

type passRecord struct {
	tenantID, issuerID, digest string
	credentialID, definition   string
	registrationID, eventID    string
	expiresAt                  time.Time
}

// passStore lives in process memory: passes last one minute, so a restart only
// forces the holder to show a new one. It does not support several API replicas.
type passStore struct {
	mu     sync.Mutex
	key    []byte
	passes map[[32]byte]passRecord
	used   map[string]time.Time
}

func (p *passStore) sweep(now time.Time) {
	for hash, rec := range p.passes {
		if !now.Before(rec.expiresAt) {
			delete(p.passes, hash)
		}
	}
	for key, until := range p.used {
		if !now.Before(until) {
			delete(p.used, key)
		}
	}
}

// nonceKey returns the per-process HMAC key. Callers hold p.mu.
func (p *passStore) nonceKey(random io.Reader) ([]byte, error) {
	if p.key == nil {
		key := make([]byte, 32)
		if _, err := io.ReadFull(random, key); err != nil {
			return nil, err
		}
		p.key = key
		p.passes = map[[32]byte]passRecord{}
		p.used = map[string]time.Time{}
	}
	return p.key, nil
}

// passReplay consumes a presentation once. Callers hold p.mu.
type passReplay struct {
	store *passStore
	until time.Time
}

func (r passReplay) Consume(key string) (bool, error) {
	if _, seen := r.store.used[key]; seen {
		return false, nil
	}
	if len(r.store.used) >= maxPasses {
		return false, ErrPassBusy
	}
	r.store.used[key] = r.until
	return true, nil
}

// PassNonce is the challenge the holder signs.
type PassNonce struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Pass is the single-use code shown by the wallet.
type Pass struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// PassVerification is what the door system learns about a pass.
type PassVerification struct {
	Result               string `json:"result"`
	Code                 string `json:"code,omitempty"`
	RegistrationID       string `json:"registrationId,omitempty"`
	EventID              string `json:"eventId,omitempty"`
	CredentialID         string `json:"credentialId,omitempty"`
	CredentialDefinition string `json:"credentialDefinition,omitempty"`
}

// NewPassNonce returns a stateless, authenticated challenge: nothing is stored
// until a validly signed presentation uses it.
func (s *Service) NewPassNonce() (PassNonce, error) {
	s.passes.mu.Lock()
	defer s.passes.mu.Unlock()
	key, err := s.passes.nonceKey(s.cfg.Random)
	if err != nil {
		return PassNonce{}, ErrInvalidRequest
	}
	expires := s.now().Add(passNonceTTL).Truncate(time.Second)
	body := make([]byte, 24)
	if _, err := io.ReadFull(s.cfg.Random, body[:16]); err != nil {
		return PassNonce{}, ErrInvalidRequest
	}
	binary.BigEndian.PutUint64(body[16:], uint64(expires.Unix()))
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return PassNonce{Nonce: base64.RawURLEncoding.EncodeToString(mac.Sum(body)), ExpiresAt: expires}, nil
}

func (p *passStore) validNonce(nonce string, now time.Time) (time.Time, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(raw) != 24+sha256.Size || p.key == nil {
		return time.Time{}, false
	}
	mac := hmac.New(sha256.New, p.key)
	mac.Write(raw[:24])
	if !hmac.Equal(mac.Sum(nil), raw[24:]) {
		return time.Time{}, false
	}
	expires := time.Unix(int64(binary.BigEndian.Uint64(raw[16:24])), 0).UTC()
	return expires, now.Before(expires)
}

// PassAudience is the audience a holder presentation must name for an issuer.
func PassAudience(issuerURI string) string {
	u, err := url.Parse(issuerURI)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + PassPath
}

func jwtPayload(compact string) map[string]any {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// routingHints reads, without trusting them, the nonce and the first enveloped
// credential. They only select the tenant and keys; everything is verified after.
func routingHints(vp string) (nonce, credential string) {
	payload := jwtPayload(vp)
	nonce, _ = payload["nonce"].(string)
	entries, _ := payload["verifiableCredential"].([]any)
	if len(entries) != 1 {
		return nonce, ""
	}
	entry, _ := entries[0].(map[string]any)
	id, _ := entry["id"].(string)
	credential, found := strings.CutPrefix(id, "data:application/vc+jwt,")
	if !found {
		return nonce, ""
	}
	return nonce, credential
}

func credentialContexts(credential string) []string {
	contexts := []string{VCDMBaseContext}
	raw, _ := jwtPayload(credential)["@context"].([]any)
	for _, c := range raw {
		if text, ok := c.(string); ok && text != VCDMBaseContext {
			contexts = append(contexts, text)
		}
	}
	return contexts
}

type issuerKeyList struct {
	issuer string
	keys   []PublicJWK
}

func (l issuerKeyList) ResolveKey(issuer, kid string) (verification.ResolvedKey, error) {
	for _, jwk := range l.keys {
		if jwk.Kid == kid && issuer == l.issuer {
			key, err := DecodePublicJWK(jwk)
			if err != nil {
				return verification.ResolvedKey{}, err
			}
			return verification.ResolvedKey{Key: key, Issuer: l.issuer}, nil
		}
	}
	return verification.ResolvedKey{}, verification.ErrKeyNotFound
}

type passClock func() time.Time

func (c passClock) Now() time.Time { return c() }

func nested(claims map[string]any, object, field string) string {
	inner, _ := claims[object].(map[string]any)
	value, _ := inner[field].(string)
	if len(value) > 128 {
		return ""
	}
	return strings.TrimSpace(value)
}

// CreatePass verifies the holder presentation and returns a pass code. A new
// pass replaces the previous one of the same credential.
func (s *Service) CreatePass(presentation string) (Pass, error) {
	nonce, credential := routingHints(presentation)
	// Contexts of the issued definition are accepted: the digest lookup below
	// only admits the exact bytes this HukID signed, and none is ever fetched.
	contexts := credentialContexts(credential)
	limits := verification.DefaultLimits
	limits.Contexts = contexts
	parsed, check := verification.ParseCredential(credential, limits)
	if credential == "" || check.Result != verification.Pass {
		return Pass{}, ErrPassRejected
	}
	slug, found := strings.CutPrefix(parsed.Issuer, IssuerPrefix)
	if !found || !isValidSlug(slug) {
		return Pass{}, ErrPassRejected
	}
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return Pass{}, ErrPassRejected
	}

	s.passes.mu.Lock()
	defer s.passes.mu.Unlock()
	now := s.now()
	nonceExpiry, valid := s.passes.validNonce(nonce, now)
	if !valid {
		return Pass{}, ErrPassRejected
	}
	s.passes.sweep(now)

	digest := verification.Digest([]byte(credential))
	var record passRecord
	var keys issuerKeyList
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil {
			return err
		}
		if !found || issuerRec.IssuerURI != parsed.Issuer || issuerRec.State != IssuerActive {
			return ErrPassRejected
		}
		list, err := tx.ListPublicKeys(issuerRec.IssuerID)
		if err != nil {
			return err
		}
		keys = issuerKeyList{issuer: issuerRec.IssuerURI, keys: list}
		record = passRecord{tenantID: tenantID, issuerID: issuerRec.IssuerID, digest: digest}
		return nil
	})
	if err != nil {
		return Pass{}, passError(err)
	}

	verifier, err := verification.NewVerifier(keys, passClock(s.now), verification.DefaultLimits, verification.DefaultClockSkew)
	if err != nil {
		return Pass{}, ErrPassRejected
	}
	verifier = verifier.WithCredentialContexts(contexts[1:]...)
	// The nonce doubles as state; consuming it makes the presentation single use.
	report, err := verifier.WithReplayStore(passReplay{store: &s.passes, until: nonceExpiry}).VerifyPresentation(
		verification.Response{VP: presentation, State: nonce},
		verification.Request{Audience: PassAudience(parsed.Issuer), Nonce: nonce, State: nonce})
	if err != nil {
		return Pass{}, passError(err)
	}
	if report.TechnicalResult != verification.Valid || len(report.Credentials) != 1 {
		return Pass{}, ErrPassRejected
	}

	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issued, found, err := tx.FindIssuedCredentialByDigest(digest)
		if err != nil {
			return err
		}
		if !found || issued.IssuerID != record.issuerID || issued.DesiredStatus != CredentialStatusActive {
			return ErrPassRejected
		}
		request, found, err := tx.GetRequestForClient(issued.RequestID, issued.ClientID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPassRejected
		}
		record.credentialID = issued.CredentialID
		record.definition = request.DefID + "@" + request.DefVersion
		return nil
	})
	if err != nil {
		return Pass{}, passError(err)
	}
	subject, _ := jwtPayload(credential)["credentialSubject"].(map[string]any)
	record.registrationID = nested(subject, "recipient", "registrationId")
	record.eventID = nested(subject, "event", "id")
	if record.registrationID == "" || record.eventID == "" {
		return Pass{}, ErrPassUnsupported
	}

	for hash, other := range s.passes.passes {
		if other.digest == digest {
			delete(s.passes.passes, hash)
		}
	}
	if len(s.passes.passes) >= maxPasses {
		return Pass{}, ErrPassBusy
	}
	code, err := generateOpaqueToken(s.cfg.Random)
	if err != nil {
		return Pass{}, ErrInvalidRequest
	}
	record.expiresAt = now.Add(PassTTL)
	s.passes.passes[sha256.Sum256([]byte(code))] = record
	return Pass{Code: code, ExpiresAt: record.expiresAt}, nil
}

func passError(err error) error {
	if errors.Is(err, ErrPassBusy) {
		return ErrPassBusy
	}
	return ErrPassRejected
}

// VerifyPass redeems a pass for the door system of eventID. Only a passing
// result consumes the code, so a scan at the wrong event does not burn it.
func (s *Service) VerifyPass(token IntegrationToken, code, eventID string) (PassVerification, error) {
	if !slices.Contains(token.Scopes, ScopePassVerify) {
		return PassVerification{}, ErrClientUnauthorized
	}
	if code == "" || len(code) > 256 || strings.TrimSpace(eventID) == "" || len(eventID) > 128 {
		return PassVerification{}, ErrInvalidRequest
	}
	failed := func(reason string) PassVerification { return PassVerification{Result: PassResultFail, Code: reason} }

	s.passes.mu.Lock()
	defer s.passes.mu.Unlock()
	now := s.now()
	hash := sha256.Sum256([]byte(code))
	record, found := s.passes.passes[hash]
	// A pass of another tenant or of a non granted issuer looks like no pass.
	if !found || !now.Before(record.expiresAt) || record.tenantID != token.TenantID || !slices.Contains(token.AllowedIssuers, record.issuerID) {
		return failed(PassCodeInvalid), nil
	}
	var result PassVerification
	err := s.backend.WithTenantTx(record.tenantID, func(tx Tx) error {
		client, ok, err := tx.GetClient(token.ClientID)
		if err != nil {
			return err
		}
		var clientPtr *StoredClient
		if ok {
			clientPtr = &client
		}
		if err := AuthorizeStoredIssuerAccess(clientPtr, token, record.tenantID, record.issuerID, ScopePassVerify, now); err != nil {
			return err
		}
		issued, ok, err := tx.FindIssuedCredentialByDigest(record.digest)
		if err != nil {
			return err
		}
		outcome := "succeeded"
		switch {
		case !ok || issued.DesiredStatus != CredentialStatusActive:
			result, outcome = failed(PassCodeNotActive), "denied"
		case eventID != record.eventID:
			result, outcome = failed(PassCodeEventMismatch), "denied"
		default:
			result = PassVerification{Result: PassResultPass, RegistrationID: record.registrationID, EventID: record.eventID,
				CredentialID: record.credentialID, CredentialDefinition: record.definition}
		}
		return tx.AppendAudit(s.newAudit(record.tenantID, token.ClientID, "pass.verified", record.credentialID, outcome, "", now))
	})
	if err != nil {
		return PassVerification{}, err
	}
	if result.Result == PassResultPass {
		delete(s.passes.passes, hash)
	}
	return result, nil
}
