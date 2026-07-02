package main

import (
	"context"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	_ "github.com/quallyy/auth-service/docs"
	httptransport "github.com/quallyy/auth-service/internal/server/http"
	"github.com/quallyy/auth-service/internal/repository/postgres"
	"github.com/quallyy/auth-service/internal/service"
	"github.com/quallyy/auth-service/pkg/token"
)

// @title           Auth Service API
// @version         1.0
// @description     JWT-based authentication service with refresh token rotation.
// @host            localhost:8080
// @BasePath        /
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization

func main() {
	_ = godotenv.Load()

	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}

	userRepo := postgres.NewUserRepository(pool)
	sessionRepo := postgres.NewSessionRepository(pool) // requires this to exist — see note below

	jwtManager := token.NewJWTManager(jwtSecret)

	authService := service.NewAuthService(userRepo, sessionRepo, jwtManager)
	authHandler := httptransport.NewAuthHandler(authService)

	router := gin.Default()
	httptransport.RegisterRoutes(router, authHandler, jwtManager)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("auth-service listening on :%s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}