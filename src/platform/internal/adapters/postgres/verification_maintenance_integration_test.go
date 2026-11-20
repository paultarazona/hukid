//go:build integration

package postgres

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// maintenanceConn opens a connection as a fresh login that is a member of the
// maintenance group role only, the shape stagingdb runtime-logins gives the
// purge login.
func maintenanceConn(t *testing.T, db *testDatabase) *pgx.Conn {
	t.Helper()
	name := "hukid_test_login_" + randomHex(t, 8)
	password := randomHex(t, 32)
	// Both strings are generated hex, never user input. Identifier is quoted.
	mustExec(t, db.admin, fmt.Sprintf("CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s'", pgx.Identifier{name}.Sanitize(), password))
	db.roles = append(db.roles, name)
	mustExec(t, db.admin, "GRANT hukid_verification_maintenance TO "+pgx.Identifier{name}.Sanitize())
	u, err := url.Parse(db.dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(name, password)
	conn, err := pgx.Connect(testContext, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(testContext) })
	return conn
}

func TestVerificationMaintenanceRoleOnlyRunsThePurges(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	var unsafe bool
	if err := db.admin.QueryRow(testContext, `SELECT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname='hukid_verification_maintenance'`).Scan(&unsafe); err != nil || unsafe {
		t.Fatalf("maintenance group role must exist without privileges (%v)", err)
	}
	old, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.admin, `UPDATE verification.sessions SET created_at=now()-interval '40 days',expires_at=now()-interval '40 days'+interval '5 minutes' WHERE session_id=$1`, old)
	conn := maintenanceConn(t, db)

	sessions, keys, err := PurgeVerification(testContext, conn, 30, 10)
	if err != nil || sessions != 1 || keys != 0 {
		t.Fatalf("purge as the maintenance login removed %d sessions and %d keys (%v)", sessions, keys, err)
	}
	var left int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM verification.sessions WHERE session_id=$1`, fresh).Scan(&left); err != nil || left != 1 {
		t.Fatalf("recent session purged: %d (%v)", left, err)
	}

	for _, statement := range []string{
		`SELECT count(*) FROM verification.sessions`,
		`SELECT count(*) FROM verification.verifier_keys`,
		`SELECT count(*) FROM verification.verifier_configs`,
		`UPDATE verification.sessions SET status='completed'`,
		`DELETE FROM verification.sessions`,
		`SELECT verification.complete_session('` + fresh + `','pass','{}','\x` + fmt.Sprintf("%064x", 1) + `')`,
		`SELECT verification.session_signing_key('` + fresh + `')`,
	} {
		_, err := conn.Exec(testContext, statement)
		expectCode(t, err, "42501")
	}
}
