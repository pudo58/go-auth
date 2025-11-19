package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	InitDB()
	LoadJWTSecretFromEnv() // optional

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := r.Group("/api/v1")

	auth := api.Group("/auth")
	{
		auth.POST("/register", RegisterHandler)
		auth.POST("/login", LoginHandler)
	}

	api.GET("/profile", AuthMiddleware(), ProfileHandler)

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Không thể start server: ", err)
	}
}
