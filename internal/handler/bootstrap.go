package handler

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/malvinpratama/iam-go-auth/internal/password"
	"github.com/malvinpratama/iam-go-auth/internal/db"
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
	if err := qtx.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: user.ID, Name: "admin"}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
