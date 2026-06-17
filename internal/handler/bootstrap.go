package handler

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/malvinpratama/iam-go-auth/internal/db"
	"github.com/malvinpratama/iam-go-auth/internal/password"
)

// BootstrapAdmin ensures an admin account exists. It is idempotent: if the email
// is already registered it does nothing. Credentials come from the environment so
// each stack hashes them with its own algorithm (no shared password hash in SQL).
func BootstrapAdmin(ctx context.Context, pool *pgxpool.Pool, email, plainPassword string) error {
	if email == "" || plainPassword == "" {
		return nil
	}
	q := db.New(pool)
	if _, err := q.GetUserByEmail(ctx, email); err == nil {
		return nil // already exists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	hash, err := password.Hash(plainPassword)
	if err != nil {
		return err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := q.WithTx(tx)

	// AssignRoleToUser writes user_roles (Kept-strict RLS, Phase 3c) — set the GUC to
	// the default tenant so the write passes once the app connects as iam_app.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", defaultTenantUUID.String()); err != nil {
		return err
	}

	user, err := qtx.CreateUser(ctx, db.CreateUserParams{Email: email, PasswordHash: hash})
	if err != nil {
		return err
	}
	if err := qtx.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: user.ID, Name: "admin", TenantID: defaultTenantUUID}); err != nil {
		return err
	}
	// M6: the admin joins the default tenant so it can log in.
	if err := qtx.CreateMembership(ctx, db.CreateMembershipParams{UserID: user.ID, TenantID: defaultTenantUUID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// BootstrapDemo ensures a read-only demo account exists so anyone visiting the
// public demo can sign in and look around without being able to change anything.
// It is assigned the built-in "viewer" role (every *:read permission, no writes,
// seeded by migration 000015). Idempotent; credentials come from the environment.
func BootstrapDemo(ctx context.Context, pool *pgxpool.Pool, email, plainPassword string) error {
	if email == "" || plainPassword == "" {
		return nil
	}
	q := db.New(pool)
	if _, err := q.GetUserByEmail(ctx, email); err == nil {
		return nil // already exists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	hash, err := password.Hash(plainPassword)
	if err != nil {
		return err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := q.WithTx(tx)

	// AssignRoleToUser writes user_roles (Kept-strict RLS, Phase 3c) — set the GUC to
	// the default tenant so the write passes once the app connects as iam_app.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", defaultTenantUUID.String()); err != nil {
		return err
	}

	user, err := qtx.CreateUser(ctx, db.CreateUserParams{Email: email, PasswordHash: hash})
	if err != nil {
		return err
	}
	if err := qtx.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: user.ID, Name: "viewer", TenantID: defaultTenantUUID}); err != nil {
		return err
	}
	if err := qtx.CreateMembership(ctx, db.CreateMembershipParams{UserID: user.ID, TenantID: defaultTenantUUID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
