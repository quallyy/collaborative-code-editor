package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quallyy/auth-service/internal/domain"
	"github.com/quallyy/auth-service/internal/repository"
)

type sessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) repository.SessionRepository {
	return &sessionRepository{pool: pool}
}

func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	query := `
        INSERT INTO sessions (id, user_id, refresh_token, user_agent, ip_address, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `
	now := time.Now().UTC()
	_, err := r.pool.Exec(ctx, query,
		session.ID, session.UserID, session.RefreshToken, session.UserAgent,
		session.IPAddress, session.ExpiresAt, now,
	)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

func (r *sessionRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (*domain.Session, error) {
	query := `
        SELECT id, user_id, refresh_token, user_agent, ip_address, expires_at, created_at, revoked_at
        FROM sessions WHERE refresh_token = $1
    `
	var session domain.Session
	var revokedAt *time.Time
	err := r.pool.QueryRow(ctx, query, refreshToken).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshToken,
		&session.UserAgent,
		&session.IPAddress,
		&session.ExpiresAt,
		&session.CreatedAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session by refresh token: %w", err)
	}
	session.RevokedAt = revokedAt
	return &session, nil
}

func (r *sessionRepository) GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	query := `
        SELECT id, user_id, refresh_token, user_agent, ip_address, expires_at, created_at, revoked_at
        FROM sessions
        WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
        ORDER BY created_at DESC
    `
	rows, err := r.pool.Query(ctx, query, userID, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("failed to query active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*domain.Session
	for rows.Next() {
		var session domain.Session
		var revokedAt *time.Time
		if err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.RefreshToken,
			&session.UserAgent,
			&session.IPAddress,
			&session.ExpiresAt,
			&session.CreatedAt,
			&revokedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}
		session.RevokedAt = revokedAt
		sessions = append(sessions, &session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating session rows: %w", err)
	}
	return sessions, nil
}

func (r *sessionRepository) Revoke(ctx context.Context, refreshToken string) error {
	query := `
        UPDATE sessions SET revoked_at = $1
        WHERE refresh_token = $2 AND revoked_at IS NULL
    `
	tag, err := r.pool.Exec(ctx, query, time.Now().UTC(), refreshToken)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrSessionNotFound
	}
	return nil
}

func (r *sessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	query := `
        UPDATE sessions SET revoked_at = $1
        WHERE user_id = $2 AND revoked_at IS NULL
    `
	_, err := r.pool.Exec(ctx, query, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all sessions for user: %w", err)
	}
	return nil
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at < $1`
	tag, err := r.pool.Exec(ctx, query, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *sessionRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	query := `
        SELECT COUNT(*) FROM sessions
        WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
    `
	var count int
	err := r.pool.QueryRow(ctx, query, userID, time.Now().UTC()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}
	return count, nil
}