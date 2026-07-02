package domain

import "errors"

var (
    ErrUserNotFound       = errors.New("user not found")
    ErrUserExists         = errors.New("user already exists")
    ErrInvalidCredentials = errors.New("invalid email or password")
    ErrInvalidToken       = errors.New("invalid token")
    ErrTokenExpired       = errors.New("token expired")
    ErrSessionNotFound    = errors.New("session not found")
    ErrSessionRevoked     = errors.New("session has been revoked")
    ErrAccountDisabled    = errors.New("account is disabled")
    ErrEmailNotVerified   = errors.New("email not verified")
)