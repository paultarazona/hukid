package issuance

import (
	"strings"
	"time"
)

// RetentionSummary reports counts purged or crypto-shredded in one retention pass (HK-053).
type RetentionSummary struct {
	ExpiredOffers       int `json:"expiredOffers"`
	ShreddedRequests    int `json:"shreddedRequests"`
	ShreddedDeferredVCs int `json:"shreddedDeferredVcs"`
}

// OperationalMetrics summarizes live queue/DLQ/issuance counts for one tenant (HK-054).
type OperationalMetrics struct {
	TenantID             string `json:"tenantId"`
	ActiveIssuers        int    `json:"activeIssuers"`
	PublishedDefinitions int    `json:"publishedDefinitions"`
	PreparedRequests     int    `json:"preparedRequests"`
	DeferredPending      int    `json:"deferredPending"`
	DeferredFailedDLQ    int    `json:"deferredFailedDlq"`
	IssuedCredentials    int    `json:"issuedCredentials"`
	SuspendedCredentials int    `json:"suspendedCredentials"`
	RevokedCredentials   int    `json:"revokedCredentials"`
}

// PurgeExpiredMaterial expires stale offers and crypto-shreds claims/VC envelopes
// for terminal records older than retentionWindow within tenantID (HK-053).
func (s *Service) PurgeExpiredMaterial(tenantID string, retentionWindow time.Duration, limit int, actorID, correlationID string) (RetentionSummary, error) {
	if strings.TrimSpace(tenantID) == "" || retentionWindow < 0 || limit < 1 || limit > 5000 {
		return RetentionSummary{}, ErrInvalidRequest
	}
	now := s.now()
	cutoff := now.Add(-retentionWindow)
	var out RetentionSummary
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		summary, err := tx.PurgeExpiredIssuanceMaterial(now, cutoff, limit)
		if err != nil {
			return err
		}
		out = summary
		if summary.ExpiredOffers > 0 || summary.ShreddedRequests > 0 || summary.ShreddedDeferredVCs > 0 {
			return tx.AppendAudit(s.newAudit(tenantID, actorID, "issuance.retention_purged", tenantID, "succeeded", correlationID, now))
		}
		return nil
	})
	if err != nil {
		return RetentionSummary{}, err
	}
	return out, nil
}

// OperationalMetrics returns tenant-scoped counters for issuance queues, DLQ and credentials (HK-054).
func (s *Service) OperationalMetrics(tenantID string) (OperationalMetrics, error) {
	if strings.TrimSpace(tenantID) == "" {
		return OperationalMetrics{}, ErrInvalidRequest
	}
	var out OperationalMetrics
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		metrics, err := tx.ReadOperationalMetrics()
		if err != nil {
			return err
		}
		metrics.TenantID = tenantID
		out = metrics
		return nil
	})
	if err != nil {
		return OperationalMetrics{}, err
	}
	return out, nil
}

// ReplayFailedDeferredRequest moves a failed deferred issuance transaction back to pending
// so the deferred worker (HK-025) can re-attempt fulfillment (HK-054 DLQ replay).
func (s *Service) ReplayFailedDeferredRequest(tenantID, requestID, actorID, correlationID string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(requestID) == "" || strings.TrimSpace(actorID) == "" {
		return ErrInvalidRequest
	}
	now := s.now()
	return s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		ok, err := tx.RequeueFailedDeferredRequest(requestID, now.Add(24*time.Hour))
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidStatusTransition
		}
		return tx.AppendAudit(s.newAudit(tenantID, actorID, "issuance.deferred_replayed", requestID, "succeeded", correlationID, now))
	})
}
