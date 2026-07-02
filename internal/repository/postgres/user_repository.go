package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quallyy/auth-service/internal/domain"
	"github.com/quallyy/auth-service/internal/repository"
)

type userRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) repository.UserRepository {
	return &userRepository{pool: pool}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
        INSERT INTO users (id, email, username, password_hash, display_name, avatar_url, is_active, is_verified, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `
	now := time.Now().UTC()
	_, err := r.pool.Exec(ctx, query,
		user.ID, user.Email, user.Username, user.PasswordHash, user.DisplayName,
		user.AvatarURL, user.IsActive, user.IsVerified, now, now,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return domain.ErrUserExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
        SELECT id, email, username, password_hash, display_name, avatar_url, is_active, is_verified, created_at, updated_at
        FROM users WHERE id = $1
    `
	var user domain.User
	var avatarURL *string
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.DisplayName,
		&avatarURL,
		&user.IsActive,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	user.AvatarURL = avatarURL
	return &user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
        SELECT id, email, username, password_hash, display_name, avatar_url, is_active, is_verified, created_at, updated_at
        FROM users WHERE email = $1
    `
	var user domain.User
	var avatarURL *string
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.DisplayName,
		&avatarURL,
		&user.IsActive,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	user.AvatarURL = avatarURL
	return &user, nil
}

func (r *userRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	query := `
        SELECT id, email, username, password_hash, display_name, avatar_url, is_active, is_verified, created_at, updated_at
        FROM users WHERE username = $1
    `
	var user domain.User
	var avatarURL *string
	err := r.pool.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.DisplayName,
		&avatarURL,
		&user.IsActive,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	user.AvatarURL = avatarURL
	return &user, nil
}

func (r *userRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
	var exists bool
	if err := r.pool.QueryRow(ctx, query, email).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}
	return exists, nil
}

func (r *userRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`
	var exists bool
	if err := r.pool.QueryRow(ctx, query, username).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check username existence: %w", err)
	}
	return exists, nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err := r.pool.Exec(ctx, query, hashedPassword, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

func (r *userRepository) UpdateVerificationStatus(ctx context.Context, userID uuid.UUID, verified bool) error {
	query := `UPDATE users SET is_verified = $1, updated_at = $2 WHERE id = $3`
	_, err := r.pool.Exec(ctx, query, verified, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("failed to update verification status: %w", err)
	}
	return nil
}

func (r *userRepository) UpdateProfile(ctx context.Context, userID uuid.UUID, displayName string, avatarURL *string) error {
	query := `UPDATE users SET display_name = $1, avatar_url = $2, updated_at = $3 WHERE id = $4`
	_, err := r.pool.Exec(ctx, query, displayName, avatarURL, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("failed to update profile: %w", err)
	}
	return nil
}

func (r *userRepository) Deactivate(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE users SET is_active = false, updated_at = $1 WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}
	return nil
}