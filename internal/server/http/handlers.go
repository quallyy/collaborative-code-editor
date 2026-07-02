package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/quallyy/auth-service/internal/domain"
	"github.com/quallyy/auth-service/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
	validate    *validator.Validate
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validate:    validator.New(),
	}
}

// ErrorResponse is the shape returned for all error cases.
type ErrorResponse struct {
	Error interface{} `json:"error"`
}

// TokenResponse is returned by Login and Refresh.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

const refreshTokenCookieName = "refresh_token"

// Register godoc
//
//	@Summary      Register a new user
//	@Tags         auth
//	@Accept       json
//	@Produce      json
//	@Param        body  body      domain.UserCreate  true  "Registration payload"
//	@Success      201   {object}  domain.UserResponse
//	@Failure      400   {object}  ErrorResponse
//	@Failure      409   {object}  ErrorResponse
//	@Failure      500   {object}  ErrorResponse
//	@Router       /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var input domain.UserCreate
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.validate.Struct(input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": formatValidationErrors(err)})
		return
	}

	user, err := h.authService.Register(c.Request.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserExists):
			c.JSON(http.StatusConflict, gin.H{"error": "email or username already taken"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register user"})
		}
		return
	}

	c.JSON(http.StatusCreated, user)
}

// Login godoc
//
//	@Summary      Login
//	@Description  Authenticates the user and sets an HTTP-only refresh_token cookie.
//	@Tags         auth
//	@Accept       json
//	@Produce      json
//	@Param        body  body      domain.UserLogin  true  "Login credentials"
//	@Success      200   {object}  TokenResponse
//	@Failure      400   {object}  ErrorResponse
//	@Failure      401   {object}  ErrorResponse
//	@Failure      403   {object}  ErrorResponse
//	@Failure      500   {object}  ErrorResponse
//	@Router       /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var input domain.UserLogin
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.validate.Struct(input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": formatValidationErrors(err)})
		return
	}

	userAgent := c.Request.UserAgent()
	ip := c.ClientIP()

	accessToken, refreshToken, err := h.authService.Login(c.Request.Context(), input, userAgent, ip)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		case errors.Is(err, domain.ErrAccountDisabled):
			c.JSON(http.StatusForbidden, gin.H{"error": "account is disabled"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to login"})
		}
		return
	}

	setRefreshTokenCookie(c, refreshToken)
	c.JSON(http.StatusOK, gin.H{"access_token": accessToken})
}

// Refresh godoc
//
//	@Summary      Refresh tokens
//	@Description  Reads the HTTP-only `refresh_token` cookie, rotates it, and returns a new access token.
//	@Tags         auth
//	@Produce      json
//	@Success      200  {object}  TokenResponse
//	@Failure      401  {object}  ErrorResponse
//	@Failure      403  {object}  ErrorResponse
//	@Failure      500  {object}  ErrorResponse
//	@Router       /auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie(refreshTokenCookieName)
	if err != nil || refreshToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing refresh token"})
		return
	}

	newAccessToken, newRefreshToken, err := h.authService.RefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrSessionNotFound), errors.Is(err, domain.ErrSessionRevoked):
			clearRefreshTokenCookie(c)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid, please login again"})
		case errors.Is(err, domain.ErrAccountDisabled):
			clearRefreshTokenCookie(c)
			c.JSON(http.StatusForbidden, gin.H{"error": "account is disabled"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		}
		return
	}

	setRefreshTokenCookie(c, newRefreshToken)
	c.JSON(http.StatusOK, gin.H{"access_token": newAccessToken})
}

// Logout godoc
//
//	@Summary      Logout current session
//	@Description  Revokes the current session using the HTTP-only `refresh_token` cookie and clears it.
//	@Tags         auth
//	@Success      204
//	@Router       /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie(refreshTokenCookieName)
	if err != nil || refreshToken == "" {
		clearRefreshTokenCookie(c)
		c.Status(http.StatusNoContent)
		return
	}

	if err := h.authService.Logout(c.Request.Context(), refreshToken); err != nil {
		clearRefreshTokenCookie(c)
		c.Status(http.StatusNoContent)
		return
	}

	clearRefreshTokenCookie(c)
	c.Status(http.StatusNoContent)
}

// LogoutAllDevices godoc
//
//	@Summary      Logout from all devices
//	@Tags         auth
//	@Security     BearerAuth
//	@Success      204
//	@Failure      401  {object}  ErrorResponse
//	@Failure      500  {object}  ErrorResponse
//	@Router       /auth/logout-all [post]
func (h *AuthHandler) LogoutAllDevices(c *gin.Context) {
	userID, ok := userIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.authService.LogoutAllDevices(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout from all devices"})
		return
	}

	clearRefreshTokenCookie(c)
	c.Status(http.StatusNoContent)
}

// Me godoc
//
//	@Summary      Get current user profile
//	@Tags         auth
//	@Security     BearerAuth
//	@Produce      json
//	@Success      200  {object}  domain.UserResponse
//	@Failure      401  {object}  ErrorResponse
//	@Failure      404  {object}  ErrorResponse
//	@Router       /auth/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := userIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	user, err := h.authService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func setRefreshTokenCookie(c *gin.Context, refreshToken string) {
	c.SetCookie(
		refreshTokenCookieName,
		refreshToken,
		int((30 * 24 * time.Hour).Seconds()),
		"/",
		"",   // domain — set explicitly in prod (e.g. ".yourapp.com")
		true, // secure — HTTPS only; will silently fail to set over plain HTTP in local dev
		true, // httpOnly — not accessible to JS, mitigates XSS token theft
	)
}

func clearRefreshTokenCookie(c *gin.Context) {
	c.SetCookie(refreshTokenCookieName, "", -1, "/", "", true, true)
}

func formatValidationErrors(err error) map[string]string {
	out := make(map[string]string)
	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		for _, fe := range validationErrs {
			out[fe.Field()] = fe.Tag()
		}
	}
	return out
}