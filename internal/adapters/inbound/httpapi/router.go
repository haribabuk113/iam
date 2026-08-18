package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
)

// NewRouter wires the IAM's public HTTP surface (architecture plan §12):
// login/callback/token/signup/signin for the auth flow, JWKS for token
// verification, and a liveness probe.
func NewRouter(auth *AuthHandler, tokens outbound.TokenSigner, log outbound.Logger) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(requestID, recoverer(log), requestLogger(log))

	r.GET("/login", auth.Login)
	r.GET("/callback", auth.Callback)
	r.POST("/token", auth.Token)
	r.POST("/signup", auth.SignUp)
	r.POST("/signin", auth.SignIn)
	r.GET("/.well-known/jwks.json", jwksHandler(tokens))
	r.GET("/healthz", healthHandler)

	return r
}

func jwksHandler(tokens outbound.TokenSigner) gin.HandlerFunc {
	return func(c *gin.Context) {
		jwks, err := tokens.JWKS()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "jwks_unavailable"})
			return
		}
		c.Data(http.StatusOK, "application/json", jwks)
	}
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
