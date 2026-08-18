package httpapi

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oklog/ulid/v2"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
)

func requestID(c *gin.Context) {
	rid := ulid.Make().String()
	c.Header("X-Request-ID", rid)
	c.Next()
}

func recoverer(log outbound.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Error("panic recovered", "error", err, "path", c.Request.URL.Path)
				c.AbortWithStatus(500)
			}
		}()
		c.Next()
	}
}

func requestLogger(log outbound.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Info("request", "method", c.Request.Method, "path", c.Request.URL.Path, "duration_ms", time.Since(start).Milliseconds())
	}
}
