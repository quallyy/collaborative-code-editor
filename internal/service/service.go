package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/quallyy/auth-service/internal/domain"
	"github.com/quallyy/auth-service/internal/repository"
	"github.com/quallyy/auth-service/pkg/hash"
	"github.com/quallyy/auth-service/pkg/helpers"
	"github.com/quallyy/auth-service/pkg/token"
)

type AuthService struct {
	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
	jwtManager  *token.JWTManager
}

func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	jwtManager *token.JWTManager,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		jwtManager:  jwtManager,
	}
}

func (s *AuthService) Register(ctx context.Context, input domain.UserCreate) (*domain.UserResponse, error) {
	exists, err := s.userRepo.ExistsByEmail(ctx, input.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrUserExists
	}

	hashed, err := hash.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	user := &domain.User{
		ID:           uuid.New(),
		Email:        input.Email,
		Username:     input.Username,
		PasswordHash: hashed,
		DisplayName:  input.DisplayName,
		IsActive:     true,
		IsVerified:   false,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}
	return user.ToResponse(), nil
}

func (s *AuthService) Login(ctx context.Context, input domain.UserLogin, userAgent, ip string) (accessToken, refreshToken string, err error) {
	user, err := s.userRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", "", domain.ErrInvalidCredentials
		}
		return "", "", err
	}

	if !hash.CheckPasswordHash(input.Password, user.PasswordHash) {
		return "", "", domain.ErrInvalidCredentials
	}

	if !user.IsActive {
		return "", "", domain.ErrAccountDisabled
	}

	accessToken, err = s.jwtManager.GenerateAccessToken(user.ID, 15*time.Minute)
	if err != nil {
		return "", "", err
	}

	refreshToken = helpers.GenerateRefreshToken()

	session := &domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		RefreshToken: helpers.HashRefreshToken(refreshToken),
		UserAgent:    userAgent,
		IPAddress:    ip,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (newAccessToken, newRefreshToken string, err error) {
	hashedToken := helpers.HashRefreshToken(refreshToken)

	session, err := s.sessionRepo.GetByRefreshToken(ctx, hashedToken)
	if err != nil {
		return "", "", err
	}

	if !session.IsValid() {
		return "", "", domain.ErrSessionRevoked
	}

	user, err := s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		return "", "", err
	}
	if !user.IsActive {
		return "", "", domain.ErrAccountDisabled
	}

	if err := s.sessionRepo.Revoke(ctx, hashedToken); err != nil {
		return "", "", err
	}

	newAccessToken, err = s.jwtManager.GenerateAccessToken(user.ID, 15*time.Minute)
	if err != nil {
		return "", "", err
	}

	newRefreshToken = helpers.GenerateRefreshToken()
	newSession := &domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		RefreshToken: helpers.HashRefreshToken(newRefreshToken),
		UserAgent:    session.UserAgent,
		IPAddress:    session.IPAddress,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}
	if err := s.sessionRepo.Create(ctx, newSession); err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.sessionRepo.Revoke(ctx, helpers.HashRefreshToken(refreshToken))
}

func (s *AuthService) LogoutAllDevices(ctx context.Context, userID uuid.UUID) error {
	return s.sessionRepo.RevokeAllForUser(ctx, userID)
}

func (s *AuthService) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.UserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.ToResponse(), nil
}