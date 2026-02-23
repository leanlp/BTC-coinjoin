package api

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// ──────────────────────────────────────────────────────────────────
// Bearer Token Authentication Middleware
//
// Reads API_AUTH_TOKEN from environment. If set, all protected routes
// require: Authorization: Bearer <token>
//
// Public endpoints (WebSocket stream, scan progress) are excluded.
// ──────────────────────────────────────────────────────────────────

// AuthMiddleware returns a Gin middleware that validates bearer tokens.
// If API_AUTH_TOKEN is not set, all requests are allowed (dev mode).
// WARNING: In GIN_MODE=release, leaving API_AUTH_TOKEN unset exposes all
// protected routes to the public internet. Always set a strong token in prod.
func AuthMiddleware() gin.HandlerFunc {
	token := os.Getenv("API_AUTH_TOKEN")

	// Fail loudly in production if auth is not configured.
	if token == "" && os.Getenv("GIN_MODE") == "release" {
		log.Println("[SECURITY WARNING] API_AUTH_TOKEN is not set in release mode. " +
			"All protected endpoints are publicly accessible. " +
			"Set API_AUTH_TOKEN in your environment to enforce authentication.")
	}

	return func(c *gin.Context) {
		// If no token is configured, skip auth (development mode)
		if token == "" {
			c.Next()
			return
		}

		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Missing Authorization header",
				"hint":  "Use: Authorization: Bearer <API_AUTH_TOKEN>",
			})
			c.Abort()
			return
		}

		// Parse "Bearer <token>"
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid Authorization header format"})
			c.Abort()
			return
		}

		// Use constant-time comparison to prevent timing-based token enumeration.
		if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(token)) != 1 {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// IsSyntheticEnabled returns true if ENABLE_SYNTHETIC=true is set.
// Synthetic transaction modes (/analyze/whirlpool, /analyze/mix)
// are disabled by default in production to prevent data poisoning.
func IsSyntheticEnabled() bool {
	return os.Getenv("ENABLE_SYNTHETIC") == "true"
}
