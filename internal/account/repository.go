package account

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

const accountColumns = `id, name, slug, status, created_at, updated_at`

func scanAccount(row pgx.Row) (*Account, error) {
	var a Account
	err := row.Scan(&a.ID, &a.Name, &a.Slug, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateWithOwner inserts an account and the creating user's OWNER membership
// atomically.
func (r *Repository) CreateWithOwner(ctx context.Context, name, slug, userID string) (*Account, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	acc, err := scanAccount(tx.QueryRow(ctx, `
		INSERT INTO accounts (name, slug)
		VALUES ($1, $2)
		RETURNING `+accountColumns, name, slug))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrSlugTaken
		}
		return nil, fmt.Errorf("insert account: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO account_members (account_id, user_id, role, status)
		VALUES ($1, $2, 'OWNER', 'ACTIVE')`, acc.ID, userID); err != nil {
		return nil, fmt.Errorf("insert owner membership: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return acc, nil
}

// ListForUser returns every non-deleted account the user is a member of,
// together with their membership role and status.
func (r *Repository) ListForUser(ctx context.Context, userID string) ([]Membership, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.id, a.name, a.slug, a.status, a.created_at, a.updated_at,
		       m.role, m.status, m.created_at
		FROM accounts a
		JOIN account_members m ON m.account_id = a.id
		WHERE m.user_id = $1 AND a.status <> 'DELETED'
		ORDER BY a.created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	memberships := make([]Membership, 0)
	for rows.Next() {
		var m Membership
		if err := rows.Scan(
			&m.ID, &m.Name, &m.Slug, &m.Status, &m.CreatedAt, &m.UpdatedAt,
			&m.Role, &m.MemberStatus, &m.MemberSince,
		); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		memberships = append(memberships, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate accounts: %w", err)
	}
	return memberships, nil
}

// SlugExists reports whether an account already uses the given slug.
func (r *Repository) SlugExists(ctx context.Context, slug string) (bool, error) {
	var exists bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM accounts WHERE slug = $1)`, slug,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("check slug: %w", err)
	}
	return exists, nil
}
