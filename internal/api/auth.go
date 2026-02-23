package api

import (
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
func AuthMiddleware() gin.HandlerFunc {
	token := os.Getenv("API_AUTH_TOKEN")

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
		if len(parts) != 2 || parts[0] != "Bearer" || parts[1] != token {
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
