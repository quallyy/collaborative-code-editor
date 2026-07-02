package http

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/quallyy/auth-service/pkg/token"
)

func RegisterRoutes(router *gin.Engine, authHandler *AuthHandler, jwtManager *token.JWTManager) {
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	auth := router.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout)
	}

	protected := router.Group("/auth")
	protected.Use(AuthMiddleware(jwtManager))
	{
		protected.GET("/me", authHandler.Me)
		protected.POST("/logout-all", authHandler.LogoutAllDevices)
	}
}