package token

import (
    "errors"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

var ErrInvalidToken = errors.New("invalid token")

type JWTManager struct {
    secretKey string
}

func NewJWTManager(secretKey string) *JWTManager {
    return &JWTManager{secretKey: secretKey}
}

// GenerateAccessToken creates a signed JWT for a user that lasts for a specific duration.
func (m *JWTManager) GenerateAccessToken(userID uuid.UUID, duration time.Duration) (string, error) {
    claims := jwt.MapClaims{
        "sub": userID.String(),                 // Subject (User ID)
        "exp": time.Now().Add(duration).Unix(), // Expiration time
        "iat": time.Now().Unix(),               // Issued at
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(m.secretKey))
}

// VerifyAccessToken validates the token and returns the user ID.
func (m *JWTManager) VerifyAccessToken(tokenString string) (uuid.UUID, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, ErrInvalidToken
        }
        return []byte(m.secretKey), nil
    })
    if err != nil || !token.Valid {
        return uuid.Nil, ErrInvalidToken
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return uuid.Nil, ErrInvalidToken
    }

    userIDStr, ok := claims["sub"].(string)
    if !ok {
        return uuid.Nil, ErrInvalidToken
    }

    return uuid.Parse(userIDStr)
}