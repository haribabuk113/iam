package httpapi

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oklog/ulid/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

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

// ---------- rate limiting ----------

// limiter is a per-key token bucket (no external dependency) — protects
// the password/OAuth-start endpoints from credential stuffing and login
// enumeration, which neither this service nor a fronting gateway
// otherwise throttles (see finding: no rate limiting anywhere).
type limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens added per second
	burst    float64 // bucket capacity
	lastSeen map[string]time.Time
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

func newLimiter(ratePerSecond float64, burst int) *limiter {
	l := &limiter{
		buckets:  make(map[string]*bucket),
		lastSeen: make(map[string]time.Time),
		rate:     ratePerSecond,
		burst:    float64(burst),
	}
	go l.sweep()
	return l
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.lastSeen[key] = now

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, lastFill: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops idle buckets so a distributed flood of one-off IPs can't
// grow this map without bound.
func (l *limiter) sweep() {
	for range time.Tick(10 * time.Minute) {
		l.mu.Lock()
		cutoff := time.Now().Add(-30 * time.Minute)
		for key, seen := range l.lastSeen {
			if seen.Before(cutoff) {
				delete(l.buckets, key)
				delete(l.lastSeen, key)
			}
		}
		l.mu.Unlock()
	}
}

// rateLimit throttles by client IP. Applied only to the endpoints an
// attacker can drive directly at volume (login start, password
// signup/signin) — see router.go.
func rateLimit(l *limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.allow(c.ClientIP()) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ---------- CORS ----------

// cors allows cross-origin requests only from the origins configured as
// return_to destinations for at least one app (IAM_ALLOWED_APPS). /signup
// and /signin are the only endpoints this matters for today — /login is a
// top-level browser navigation, and /token is documented as
// server-to-server — but it's applied globally since it's a no-op for any
// request without a matching Origin header.
func cors(allowedOrigins map[string]bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && allowedOrigins[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// ---------- metrics ----------

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "iam_http_requests_total",
		Help: "Total HTTP requests handled, by method, route, and status code.",
	}, []string{"method", "route", "status"})

	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "iam_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds, by method and route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})
)

func metrics(c *gin.Context) {
	start := time.Now()
	c.Next()

	route := c.FullPath()
	if route == "" {
		route = "unmatched"
	}
	status := strconv.Itoa(c.Writer.Status())
	httpRequestsTotal.WithLabelValues(c.Request.Method, route, status).Inc()
	httpRequestDuration.WithLabelValues(c.Request.Method, route).Observe(time.Since(start).Seconds())
}
