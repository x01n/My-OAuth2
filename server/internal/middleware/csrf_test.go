package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"server/internal/model"
	"server/internal/repository"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func init() {
	gin.SetMode(gin.TestMode)
}

/* 辅助函数：创建带 CSRF 中间件的 Gin 引擎 */
func setupCSRFRouter() *gin.Engine {
	r := gin.New()
	r.Use(CSRFProtection())
	r.POST("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	return r
}

func setupCSRFRouterWithRiskEvents(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gin.New()
	r.Use(CSRFProtectionWithRiskEventRepository(repository.NewRiskEventRepository(db)))
	r.POST("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	return r, db
}

func TestCSRF_GET_Bypass(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("GET should bypass CSRF, got %d", w.Code)
	}
}

func TestCSRF_POST_WithAuthHeader_Bypass(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("POST with Authorization header should bypass CSRF, got %d", w.Code)
	}
}

func TestCSRF_POST_MissingCookie(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("POST without CSRF cookie should be 403, got %d", w.Code)
	}
}

func TestCSRF_POST_MissingCookie_RecordsRiskEvent(t *testing.T) {
	r, db := setupCSRFRouterWithRiskEvents(t)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Host = "localhost"
	req.RemoteAddr = "203.0.113.50:12345"
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set("User-Agent", "csrf-risk-test")
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("POST without CSRF cookie should be 403, got %d", w.Code)
	}

	var event model.RiskEvent
	if err := db.Where("user_id IS NULL AND risk_score = ? AND decision = ?", 50, model.RiskDecisionChallenge).
		First(&event).Error; err != nil {
		t.Fatalf("find risk event: %v", err)
	}
	if event.IPAddress != "203.0.113.50" {
		t.Fatalf("ip_address=%q want 203.0.113.50", event.IPAddress)
	}
	if event.UserAgent != "csrf-risk-test" {
		t.Fatalf("user_agent=%q want csrf-risk-test", event.UserAgent)
	}
	if event.Reason != model.RiskEventReasonCSRFTokenMissing {
		t.Fatalf("reason=%q want %q", event.Reason, model.RiskEventReasonCSRFTokenMissing)
	}
}

func TestCSRF_POST_WithAuthHeader_DoesNotRecordRiskEvent(t *testing.T) {
	r, db := setupCSRFRouterWithRiskEvents(t)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer token")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("POST with Authorization header should bypass CSRF, got %d", w.Code)
	}

	var count int64
	db.Model(&model.RiskEvent{}).Count(&count)
	if count != 0 {
		t.Fatalf("risk event count=%d want 0", count)
	}
}

func TestCSRF_POST_MissingHeader(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.AddCookie(&http.Cookie{Name: CSRFTokenCookie, Value: "test-token"})
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("POST without CSRF header should be 403, got %d", w.Code)
	}
}

func TestCSRF_POST_TokenMismatch(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.AddCookie(&http.Cookie{Name: CSRFTokenCookie, Value: "token-a"})
	req.Header.Set(CSRFTokenHeader, "token-b")
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("POST with mismatched CSRF tokens should be 403, got %d", w.Code)
	}
}

func TestCSRF_POST_ValidToken(t *testing.T) {
	r := setupCSRFRouter()
	token := GenerateCSRFToken()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.AddCookie(&http.Cookie{Name: CSRFTokenCookie, Value: token})
	req.Header.Set(CSRFTokenHeader, token)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("POST with valid CSRF token should be 200, got %d", w.Code)
	}
}

func TestCSRF_POST_CrossOrigin_Blocked(t *testing.T) {
	r := setupCSRFRouter()
	token := GenerateCSRFToken()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://evil.com")
	req.AddCookie(&http.Cookie{Name: CSRFTokenCookie, Value: token})
	req.Header.Set(CSRFTokenHeader, token)
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("POST from cross-origin should be 403, got %d", w.Code)
	}
}

func TestGenerateCSRFToken_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token := GenerateCSRFToken()
		if len(token) != csrfTokenLength*2 {
			t.Errorf("CSRF token length = %d, want %d", len(token), csrfTokenLength*2)
		}
		if seen[token] {
			t.Fatal("GenerateCSRFToken() produced duplicate")
		}
		seen[token] = true
	}
}
