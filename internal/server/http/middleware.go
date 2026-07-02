package http

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/quallyy/auth-service/pkg/token"
)

const userIDContextKey = "userID"

// AuthMiddleware verifies the Bearer access token on protected routes
// and injects the authenticated user's ID into the gin context.
func AuthMiddleware(jwtManager *token.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			return
		}

		tokenString := parts[1]
		userID, err := jwtManager.VerifyAccessToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired access token"})
			return
		}

		c.Set(userIDContextKey, userID)
		c.Next()
	}
}

// userIDFromContext extracts the authenticated user's ID set by AuthMiddleware.
func userIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(userIDContextKey)
	if !exists {
		return uuid.Nil, false
	}
	userID, ok := val.(uuid.UUID)
	if !ok {
		return uuid.Nil, false
	}
	return userID, true
}