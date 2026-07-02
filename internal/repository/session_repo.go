package repository

import (
    "context"

    "github.com/google/uuid"
    "github.com/quallyy/auth-service/internal/domain"
)

// SessionRepository defines all operations for session data access.
type SessionRepository interface {
    // Create stores a new session (created after login/register).
    Create(ctx context.Context, session *domain.Session) error

    // GetByRefreshToken finds a session by its refresh token.
    // Used when user tries to refresh their access token.
    // Returns domain.ErrSessionNotFound if token doesn't exist.
    GetByRefreshToken(ctx context.Context, refreshToken string) (*domain.Session, error)

    // GetActiveByUserID returns all active (non-revoked, non-expired) sessions for a user.
    // Used to show "active devices" to the user.
    GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)

    // Revoke marks a single session as revoked (logout).
    // Returns domain.ErrSessionNotFound if session doesn't exist or already revoked.
    Revoke(ctx context.Context, refreshToken string) error

    // RevokeAllForUser revokes ALL active sessions for a user.
    // Used for "logout from all devices" or security incidents.
    RevokeAllForUser(ctx context.Context, userID uuid.UUID) error

    // DeleteExpired removes all expired sessions from the database.
    // Run periodically as cleanup.
    DeleteExpired(ctx context.Context) (int64, error)

    // CountActiveByUserID counts active sessions for a user.
    // Could be used to enforce "max 5 devices" limit.
    CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error)
}