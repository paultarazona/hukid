-- Check-in passes (ADR-0038): new integration scope and lookup of an issued
-- credential by the digest of its signed bytes. Pass codes are not persisted.
ALTER TABLE tenancy.integration_clients
  DROP CONSTRAINT integration_clients_scopes_allowed;
ALTER TABLE tenancy.integration_clients
  ADD CONSTRAINT integration_clients_scopes_allowed
  CHECK (cardinality(scopes) BETWEEN 1 AND 8 AND scopes <@ ARRAY['issuance:create', 'issuance:read', 'status:write', 'pass:verify']::text[]);

CREATE INDEX issued_credentials_digest_idx ON status.issued_credentials(tenant_id, jws_digest);
