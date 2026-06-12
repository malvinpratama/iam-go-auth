//go:build integration

// Integration tests for the auth repository against a real Postgres
// (testcontainers). Run with: go test -tags=integration ./...
// They exercise the actual SQL + embedded migrations, not mocks.
package db_test

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	auth "github.com/malvinpratama/iam-go-auth"
	"github.com/malvinpratama/iam-go-auth/internal/db"
	"github.com/malvinpratama/iam-go-libs/migrate"
)

// newDB starts a throwaway Postgres, applies the embedded migrations, and
// returns a ready *db.Queries. The container is torn down at test end.
func newDB(t *testing.T) *db.Queries {
	q, _ := newDBPool(t)
	return q
}

// newDBPool is newDB but also returns the underlying pool, for tests that need
// to drive raw transactions (e.g. exercising RLS as the iam_rls role).
func newDBPool(t *testing.T) (*db.Queries, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("auth"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		// Postgres briefly opens the port during init before restarting, so wait
		// for the "ready" log to appear twice (the robust readiness signal) — a
		// plain port check races and yields "connection reset by peer".
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	sub, err := fs.Sub(auth.MigrationsFS, "db/migrations")
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	if err := migrate.Run(ctx, dsn, sub); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return db.New(pool), pool
}

func TestUserLifecycle_softDeleteRestore(t *testing.T) {
	q := newDB(t)
	ctx := context.Background()

	u, err := q.CreateUser(ctx, db.CreateUserParams{Email: "alice@test.local", PasswordHash: "argon2$x"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := q.GetUserByEmail(ctx, "alice@test.local")
	if err != nil || got.ID != u.ID {
		t.Fatalf("get by email: %v", err)
	}
	if active, _ := q.IsUserActive(ctx, u.ID); !active {
		t.Fatal("new user should be active")
	}
	if err := q.SoftDeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if active, _ := q.IsUserActive(ctx, u.ID); active {
		t.Fatal("soft-deleted user should be inactive")
	}
	if err := q.RestoreUser(ctx, u.ID); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if active, _ := q.IsUserActive(ctx, u.ID); !active {
		t.Fatal("restored user should be active again")
	}
}

func TestListRolesWithPermissions_singleQuery(t *testing.T) {
	q := newDB(t)
	ctx := context.Background()

	// The seed migration creates the admin role (a built-in template, tenant_id
	// NULL) with the full permission set — visible from any tenant context.
	roles, err := q.ListRolesWithPermissions(ctx, pgtype.UUID{})
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	var adminPerms int
	for _, r := range roles {
		if r.Name == "admin" {
			adminPerms = len(r.Permissions)
		}
	}
	if adminPerms == 0 {
		t.Fatal("admin should carry permissions via the single aggregated query")
	}
}

func TestApiKey_createValidateRevoke(t *testing.T) {
	q := newDB(t)
	ctx := context.Background()

	u, err := q.CreateUser(ctx, db.CreateUserParams{Email: "key@test.local", PasswordHash: "x"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	// tenant_id is a NOT-NULL FK to the seeded default tenant (M6 backfill).
	defaultTenant := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	if err := q.CreateApiKey(ctx, db.CreateApiKeyParams{
		ID: "k1", UserID: u.ID, KeyHash: "hash1", Name: "ci", Scopes: []string{"user:read"}, TenantID: defaultTenant,
	}); err != nil {
		t.Fatalf("create key: %v", err)
	}
	row, err := q.GetApiKeyByHash(ctx, "hash1")
	if err != nil || row.UserID != u.ID {
		t.Fatalf("get key by hash: %v", err)
	}
	if len(row.Scopes) != 1 || row.Scopes[0] != "user:read" {
		t.Fatalf("unexpected scopes: %v", row.Scopes)
	}
	if err := q.RevokeApiKey(ctx, db.RevokeApiKeyParams{ID: "k1", UserID: u.ID}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	row2, err := q.GetApiKeyByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("get after revoke: %v", err)
	}
	if !row2.RevokedAt.Valid {
		t.Fatal("key should be revoked")
	}
}

func TestRecoveryCode_singleUse(t *testing.T) {
	q := newDB(t)
	ctx := context.Background()

	u, err := q.CreateUser(ctx, db.CreateUserParams{Email: "rec@test.local", PasswordHash: "x"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := q.InsertRecoveryCode(ctx, db.InsertRecoveryCodeParams{UserID: u.ID, CodeHash: "rc-hash"}); err != nil {
		t.Fatalf("insert recovery: %v", err)
	}
	if _, err := q.ConsumeRecoveryCode(ctx, db.ConsumeRecoveryCodeParams{UserID: u.ID, CodeHash: "rc-hash"}); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	if _, err := q.ConsumeRecoveryCode(ctx, db.ConsumeRecoveryCodeParams{UserID: u.ID, CodeHash: "rc-hash"}); err == nil {
		t.Fatal("second consume of the same recovery code must fail (one-time)")
	}
}

// TestRLS_withCheckRejectsCrossTenantWrite proves the M6 defense-in-depth: a
// tenant-scoped write run inside an iam_rls transaction (SET LOCAL ROLE iam_rls +
// app.tenant_id) is rejected by the RLS WITH CHECK policy if it targets another
// tenant — even though the app connects as a superuser elsewhere. This is what
// makes routing writes through withTenant (Phase 3b) meaningful.
func TestRLS_withCheckRejectsCrossTenantWrite(t *testing.T) {
	q, pool := newDBPool(t)
	ctx := context.Background()

	tenantA := uuid.MustParse("00000000-0000-0000-0000-000000000001") // seeded default
	var tenantB uuid.UUID
	if err := pool.QueryRow(ctx, "INSERT INTO tenants (slug, name) VALUES ('beta', 'Beta') RETURNING id").Scan(&tenantB); err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	// inTenant mirrors the handler's withTenant: an iam_rls tx scoped to `tenant`.
	inTenant := func(tenant uuid.UUID, fn func(*db.Queries) error) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE iam_rls"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenant.String()); err != nil {
			return err
		}
		if err := fn(q.WithTx(tx)); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// A write for the active tenant passes WITH CHECK.
	if err := inTenant(tenantA, func(qq *db.Queries) error {
		_, e := qq.CreateProject(ctx, db.CreateProjectParams{TenantID: tenantA, Slug: "ok", Name: "OK"})
		return e
	}); err != nil {
		t.Fatalf("same-tenant write should pass RLS WITH CHECK: %v", err)
	}

	// A write that targets another tenant while scoped to A must be rejected.
	if err := inTenant(tenantA, func(qq *db.Queries) error {
		_, e := qq.CreateProject(ctx, db.CreateProjectParams{TenantID: tenantB, Slug: "evil", Name: "Evil"})
		return e
	}); err == nil {
		t.Fatal("cross-tenant write (tenant_id=B while app.tenant_id=A) must be rejected by RLS WITH CHECK")
	}
}
