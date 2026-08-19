package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
)

// RouterConfig carries the tunables NewRouter needs beyond its handlers —
// kept as a struct rather than positional params since most of these are
// operational knobs (rate limits, CORS allow-list) set from env, not
// application logic.
type RouterConfig struct {
	// AllowedOrigins is the flattened set of every app's configured
	// return_to origins (IAM_ALLOWED_APPS) — reused as the CORS allow-list
	// for /signup and /signin.
	AllowedOrigins map[string]bool
	// RateLimitRPS / RateLimitBurst configure the per-IP token bucket
	// guarding /login, /signup, /signin.
	RateLimitRPS   float64
	RateLimitBurst int
}

// NewRouter wires the IAM's public HTTP surface (architecture plan §12):
// login/callback/token/signup/signin for the auth flow, JWKS for token
// verification, /metrics for scraping, and a liveness probe.
func NewRouter(auth *AuthHandler, tokens outbound.TokenSigner, log outbound.Logger, cfg RouterConfig) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(requestID, recoverer(log), requestLogger(log), metrics, cors(cfg.AllowedOrigins))

	limit := newLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)

	r.GET("/login", rateLimit(limit), auth.Login)
	r.GET("/callback", auth.Callback)
	r.POST("/token", auth.Token)
	r.POST("/signup", rateLimit(limit), auth.SignUp)
	r.POST("/signin", rateLimit(limit), auth.SignIn)
	r.GET("/.well-known/jwks.json", jwksHandler(tokens))
	r.GET("/healthz", healthHandler)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

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
