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
