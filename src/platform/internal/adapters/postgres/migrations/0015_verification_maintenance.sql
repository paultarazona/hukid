-- Least-privilege maintenance role for the verification retention purge (ADR-0033, ADR-0034).
-- It can run the two bounded purge functions and nothing else: it cannot read or write sessions,
-- keys or configurations directly, and it is not a runtime role the API opens pools for.
DO $$
BEGIN
 IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_verification_maintenance') THEN
  CREATE ROLE hukid_verification_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_verification_maintenance'
  AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
  RAISE EXCEPTION 'Unsafe pre-existing verification maintenance role';
 END IF;
END $$;
SET LOCAL ROLE hukid_owner;

GRANT USAGE ON SCHEMA verification TO hukid_verification_maintenance;
GRANT EXECUTE ON FUNCTION verification.purge_sessions(integer,integer) TO hukid_verification_maintenance;
GRANT EXECUTE ON FUNCTION verification.purge_retired_keys(integer) TO hukid_verification_maintenance;
