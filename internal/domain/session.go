package domain

import (
    "time"

    "github.com/google/uuid"
)

type Session struct {
    ID           uuid.UUID  `json:"id"`
    UserID       uuid.UUID  `json:"user_id"`
    RefreshToken string     `json:"-"` // Never expose in JSON
    UserAgent    string     `json:"user_agent"`
    IPAddress    string     `json:"ip_address"`
    ExpiresAt    time.Time  `json:"expires_at"`
    CreatedAt    time.Time  `json:"created_at"`
    RevokedAt    *time.Time `json:"revoked_at,omitempty"` // nil = active
}

// SessionCreate is what we pass to the repository when creating a session.
type SessionCreate struct {
    UserID       uuid.UUID
    RefreshToken string
    UserAgent    string
    IPAddress    string
    ExpiresAt    time.Time
}

// IsRevoked returns true if the session was explicitly revoked (logout).
func (s *Session) IsRevoked() bool {
    return s.RevokedAt != nil
}

// IsExpired returns true if the session has passed its expiration time.
func (s *Session) IsExpired() bool {
    return time.Now().After(s.ExpiresAt)
}

// IsValid returns true if session is active and not expired.
func (s *Session) IsValid() bool {
    return !s.IsRevoked() && !s.IsExpired()
}