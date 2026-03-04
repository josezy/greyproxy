package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func HealthHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := s.DB.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"error":  err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}
