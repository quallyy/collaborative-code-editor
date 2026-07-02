package repository

import (
    "context"

    "github.com/google/uuid"
    "github.com/quallyy/auth-service/internal/domain"
)

// UserRepository defines all operations for user data access.
// Any implementation (PostgreSQL, MySQL, in-memory) must satisfy this.
type UserRepository interface {
    // Create inserts a new user into the database.
    // Returns error if email/username already exists (handled at DB level).
    Create(ctx context.Context, user *domain.User) error

    // GetByID fetches a user by their unique ID.
    // Returns domain.ErrUserNotFound if user doesn't exist.
    GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)

    // GetByEmail fetches a user by their email address.
    // Used during login.
    // Returns domain.ErrUserNotFound if user doesn't exist.
    GetByEmail(ctx context.Context, email string) (*domain.User, error)

    // GetByUsername fetches a user by their username.
    // Used for profile lookups.
    // Returns domain.ErrUserNotFound if user doesn't exist.
    GetByUsername(ctx context.Context, username string) (*domain.User, error)

    // ExistsByEmail checks if a user with this email already exists.
    // Used during registration to prevent duplicates.
    // Returns (true, nil) if exists, (false, nil) if not.
    ExistsByEmail(ctx context.Context, email string) (bool, error)

    // ExistsByUsername checks if a username is already taken.
    // Used during registration to prevent duplicates.
    ExistsByUsername(ctx context.Context, username string) (bool, error)

    // UpdatePassword updates the user's password hash.
    // Used for password reset functionality.
    UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error

    // UpdateVerificationStatus marks a user's email as verified.
    // Used after email verification link is clicked.
    UpdateVerificationStatus(ctx context.Context, userID uuid.UUID, verified bool) error

    // UpdateProfile updates display name and/or avatar.
    // Used when user edits their profile.
    UpdateProfile(ctx context.Context, userID uuid.UUID, displayName string, avatarURL *string) error

    // Deactivate disables a user account.
    // Used by admins or when user deletes account.
    Deactivate(ctx context.Context, userID uuid.UUID) error
}