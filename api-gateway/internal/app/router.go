package app

import (
	"api-gateway/internal/client"
	"api-gateway/internal/health"
	"api-gateway/internal/middleware"
	"api-gateway/internal/routes"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRouter(authClient *client.AuthClient, authServiceAddr, databaseURL string) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Swagger documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Comprehensive health check
	healthChecker := health.NewHealthChecker(authServiceAddr, databaseURL)
	router.GET("/health", func(c *gin.Context) {
		status := healthChecker.CheckAllServices()
		// Set appropriate HTTP status code
		httpStatus := 200
		if !status.Overall {
			httpStatus = 503
		}
		c.JSON(httpStatus, status)
	})

	// Auth routes
	authRoutes := routes.NewAuthRoutes(authClient)
	api := router.Group("/api/v1")
	{
		// Public routes (no authentication required)
		api.POST("/register", authRoutes.Register)
		api.POST("/login", authRoutes.Login)
		api.POST("/forgot-password", authRoutes.ForgotPassword)
		api.POST("/reset-password", authRoutes.ResetPassword)

		// Protected routes (JWT authentication required)
		protected := api.Group("/")
		protected.Use(middleware.RequireAuth(authClient))
		{
			// Profile route - get current user info from JWT
			protected.GET("/users/me", authRoutes.GetProfile)
			// User management routes
			protected.GET("/users/:id", authRoutes.GetUser)
			protected.PUT("/users/:id", authRoutes.UpdateUser)
			protected.PUT("/users/:id/password", authRoutes.ChangePassword)
			protected.DELETE("/users/:id", authRoutes.DeleteUser)
			protected.POST("/users/:id/verify", authRoutes.VerifyUser)

			// Login history routes
			protected.GET("/users/:id/login-history", authRoutes.GetUserLoginHistory)
			protected.GET("/users/:id/recent-logins", authRoutes.GetRecentLoginHistory)
			protected.GET("/users/:id/failed-attempts", authRoutes.GetFailedLoginAttempts)
		}
	}

	return router
}
