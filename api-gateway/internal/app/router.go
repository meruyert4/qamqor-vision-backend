package app

import (
	"api-gateway/internal/client"
	"api-gateway/internal/routes"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRouter(authClient *client.AuthClient) *gin.Engine {
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

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Auth routes
	authRoutes := routes.NewAuthRoutes(authClient)
	api := router.Group("/api/v1")
	{
		api.POST("/register", authRoutes.Register)
		api.POST("/login", authRoutes.Login)
		api.GET("/users/:id", authRoutes.GetUser)
		api.PUT("/users/:id", authRoutes.UpdateUser)
		api.PUT("/users/:id/password", authRoutes.ChangePassword)
		api.DELETE("/users/:id", authRoutes.DeleteUser)
		api.POST("/users/:id/verify", authRoutes.VerifyUser)
		api.POST("/forgot-password", authRoutes.ForgotPassword)
		api.POST("/reset-password", authRoutes.ResetPassword)

		// Login history routes
		api.GET("/users/:id/login-history", authRoutes.GetUserLoginHistory)
		api.GET("/users/:id/recent-logins", authRoutes.GetRecentLoginHistory)
		api.GET("/users/:id/failed-attempts", authRoutes.GetFailedLoginAttempts)
	}

	return router
}
