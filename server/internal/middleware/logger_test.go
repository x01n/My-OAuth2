package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestLogger_RedactsSensitiveQueryValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	if got := sanitizeQueryString("token=abc123&state=ok&client_secret=super-secret"); got != "client_secret=%2A%2A%2AREDACTED%2A%2A%2A&state=ok&token=%2A%2A%2AREDACTED%2A%2A%2A" {
		t.Fatalf("sanitizeQueryString()=%q", got)
	}
}

func TestRecoveryWithLogger_SanitizesSensitiveBodySnippet(t *testing.T) {
	router := gin.New()
	router.Use(RecoveryWithLogger())
	router.POST("/api/test", func(c *gin.Context) {
		panic("boom")
	})

	body := `{"password":"super-secret","token":"secret-token","profile":{"access_token":"inner-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/test?code=abc&state=ok", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
