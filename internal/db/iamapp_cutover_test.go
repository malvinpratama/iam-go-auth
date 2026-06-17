//go:build integration

// Integration tests for the Phase 3c (T4) least-privilege cutover. They open a
// SECOND connection as the prepared non-superuser role `iam_app` and prove that,
// once the app connects as it, Postgres RLS enforces tenant isolation on the
// Kept-strict tables by default — the whole point of moving off the superuser
// `app`. Run with: go test -tags=integration ./...
package db_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultTenant is the fixed default-tenant UUID seeded by migration 000010 (kept
// in sync with handler.defaultTenantID).
const defaultTenant = "00000000-0000-0000-0000-000000000001"

// iamAppDSN rewrites a superuser DSN to connect as iam_app with the given password.
func iamAppDSN(t *testing.T, superDSN, pw string) string {
	t.Helper()
	u, err := url.Parse(superDSN)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.User = url.UserPassword("iam_app", pw)
	return u.String()
}

// enableIamApp turns the prepared (NOLOGIN) iam_app role into a usable login and
// returns a pool connected as it.
func enableIamApp(t *testing.T, ctx context.Context, admin *pgxpool.Pool, dsn string) *pgxpool.Pool {
	t.Helper()
	if _, err := admin.Exec(ctx, "ALTER ROLE iam_app WITH LOGIN PASSWORD 'iamapp_test'"); err != nil {
		t.Fatalf("enable iam_app login: %v", err)
	}
	app, err := pgxpool.New(ctx, iamAppDSN(t, dsn, "iamapp_test"))
	if err != nil {
		t.Fatalf("iam_app pool: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

// TestIamAppCutover_classSplit proves the 000016 reclass under a REAL non-superuser
// connection: as iam_app the Kept-strict tables (projects, user_roles) are
// fail-closed — zero rows without app.tenant_id — while the relaxed Kelas-B tables
// (memberships) stay readable. Setting app.tenant_id then reveals that tenant's
// strict rows. This is what makes the connection-role cutover safe.
func TestIamAppCutover_classSplit(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgres(t)

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()

	// Seed a user with a membership + a user_role, both in the default tenant.
	var uid uuid.UUID
	if err := admin.QueryRow(ctx,
		"INSERT INTO users (email, password_hash) VALUES ('m@x.test','x') RETURNING id").Scan(&uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := admin.Exec(ctx,
		"INSERT INTO memberships (user_id, tenant_id) VALUES ($1, $2)", uid, defaultTenant); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	var roleID int64
	if err := admin.QueryRow(ctx, "SELECT id FROM roles WHERE name='admin' LIMIT 1").Scan(&roleID); err != nil {
		t.Fatalf("lookup admin role: %v", err)
	}
	if _, err := admin.Exec(ctx,
		"INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES ($1, $2, $3)", uid, roleID, defaultTenant); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}

	app := enableIamApp(t, ctx, admin, dsn)

	// 1. The connection role really is the non-superuser iam_app.
	var who string
	var super bool
	if err := app.QueryRow(ctx,
		"SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&who, &super); err != nil {
		t.Fatalf("current_user: %v", err)
	}
	if who != "iam_app" || super {
		t.Fatalf("want non-superuser iam_app, got user=%q super=%v", who, super)
	}

	// 2. Kept-strict + no app.tenant_id → fail-closed. projects has a seeded default
	//    project and user_roles has the seeded row; both must be hidden.
	for _, tbl := range []string{"projects", "user_roles"} {
		var n int
		if err := app.QueryRow(ctx, "SELECT count(*) FROM "+tbl).Scan(&n); err != nil {
			t.Fatalf("count %s as iam_app: %v", tbl, err)
		}
		if n != 0 {
			t.Fatalf("Kept-strict %s must be 0 without app.tenant_id, saw %d", tbl, n)
		}
	}

	// 3. Relaxed Kelas-B table stays readable without any tenant context.
	var members int
	if err := app.QueryRow(ctx, "SELECT count(*) FROM memberships").Scan(&members); err != nil {
		t.Fatalf("count memberships as iam_app: %v", err)
	}
	if members == 0 {
		t.Fatal("relaxed memberships must be readable by iam_app without app.tenant_id")
	}

	// 4. With app.tenant_id set, the Kept-strict rows of that tenant become visible.
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", defaultTenant); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	var ur int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM user_roles").Scan(&ur); err != nil {
		t.Fatalf("scoped user_roles: %v", err)
	}
	if ur == 0 {
		t.Fatal("with app.tenant_id=default, iam_app must see the default tenant's user_roles")
	}
}

// TestIamAppCutover_writeWithCheck proves that, as iam_app, a Kept-strict write is
// pinned to app.tenant_id by the RLS WITH CHECK: a same-tenant INSERT passes and a
// cross-tenant INSERT is rejected — without relying on SET ROLE, because the
// connection role itself is the non-superuser iam_app.
func TestIamAppCutover_writeWithCheck(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgres(t)

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()

	var tenantB uuid.UUID
	if err := admin.QueryRow(ctx,
		"INSERT INTO tenants (slug, name) VALUES ('beta','Beta') RETURNING id").Scan(&tenantB); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}

	app := enableIamApp(t, ctx, admin, dsn)

	// insertProject writes a projects row owned by rowTenant while app.tenant_id is
	// pinned to the default tenant.
	insertProject := func(rowTenant uuid.UUID, slug string) error {
		tx, err := app.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", defaultTenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO projects (tenant_id, slug, name) VALUES ($1, $2, 'p')", rowTenant, slug); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// Same-tenant write (row tenant == app.tenant_id) passes WITH CHECK.
	if err := insertProject(uuid.MustParse(defaultTenant), "ok"); err != nil {
		t.Fatalf("same-tenant write under iam_app should pass: %v", err)
	}
	// Cross-tenant write (row tenant = B while app.tenant_id = default) is rejected.
	if err := insertProject(tenantB, "evil"); err == nil {
		t.Fatal("cross-tenant write under iam_app must be rejected by RLS WITH CHECK")
	}
}
