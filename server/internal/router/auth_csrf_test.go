package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"server/internal/config"
	"server/internal/database"
	"server/internal/middleware"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/cache"
	"server/pkg/jwt"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAuthCSRFRouter(t *testing.T) (func(req *http.Request) *httptest.ResponseRecorder, *gorm.DB) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(
		&model.User{},
		&model.Application{},
		&model.AuthorizationCode{},
		&model.AccessToken{},
		&model.RefreshToken{},
		&model.SystemConfig{},
		&model.UserAuthorization{},
		&model.LoginLog{},
		&model.RiskEvent{},
		&model.Webhook{},
		&model.WebhookDelivery{},
		&model.FederatedProvider{},
		&model.FederatedIdentity{},
		&model.TrustedApp{},
		&model.PasswordReset{},
		&model.DeviceCode{},
		&model.EmailVerification{},
		&model.EmailTask{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	previousDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previousDB })

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:              "127.0.0.1",
			Port:              8080,
			Mode:              "test",
			AllowRegistration: true,
		},
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{
			FrontendURL: "http://localhost:3000",
			IDTokenTTL:  15 * time.Minute,
		},
	}
	cacheInstance := cache.NewMemoryCache(5 * time.Minute)
	engine, _, cleanup := Setup(cfg, cacheInstance)
	t.Cleanup(cleanup)

	send := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec
	}
	return send, db
}

func createAccessTokenForRouterTest(t *testing.T, db *gorm.DB) string {
	t.Helper()
	user := &model.User{
		ID:           uuid.New(),
		Email:        "csrf-router@example.com",
		Username:     "csrfrouter",
		PasswordHash: "hashed-password",
		Role:         model.RoleUser,
		Status:       "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, err := jwt.NewManager("test-secret-with-enough-length", "test").GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	if err := repository.NewOAuthRepository(db).CreateAccessToken(&model.AccessToken{
		Token:     token,
		ClientID:  "",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("store access token: %v", err)
	}
	return token
}

func createAccessTokenWithUserIDForRouterTest(t *testing.T, db *gorm.DB) (string, uuid.UUID) {
	t.Helper()
	user := &model.User{
		ID:           uuid.New(),
		Email:        "csrf-router-risk-user@example.com",
		Username:     "csrfrouterriskuser",
		PasswordHash: "hashed-password",
		Role:         model.RoleUser,
		Status:       "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, err := jwt.NewManager("test-secret-with-enough-length", "test").GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	if err := repository.NewOAuthRepository(db).CreateAccessToken(&model.AccessToken{
		Token:     token,
		ClientID:  "",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("store access token: %v", err)
	}
	return token, user.ID
}

func createUserMismatchAccessTokenForRouterTest(t *testing.T, db *gorm.DB) string {
	t.Helper()
	claimsUser := &model.User{
		ID:           uuid.New(),
		Email:        "csrf-router-claims@example.com",
		Username:     "csrfrouterclaims",
		PasswordHash: "hashed-password",
		Role:         model.RoleUser,
		Status:       "active",
	}
	storedUser := &model.User{
		ID:           uuid.New(),
		Email:        "csrf-router-stored@example.com",
		Username:     "csrfrouterstored",
		PasswordHash: "hashed-password",
		Role:         model.RoleUser,
		Status:       "active",
	}
	if err := db.Create(claimsUser).Error; err != nil {
		t.Fatalf("create claims user: %v", err)
	}
	if err := db.Create(storedUser).Error; err != nil {
		t.Fatalf("create stored user: %v", err)
	}

	token, err := jwt.NewManager("test-secret-with-enough-length", "test").GenerateToken(
		claimsUser.ID,
		claimsUser.Email,
		claimsUser.Username,
		string(claimsUser.Role),
		jwt.TokenTypeAccess,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	if err := repository.NewOAuthRepository(db).CreateAccessToken(&model.AccessToken{
		Token:     token,
		ClientID:  "",
		UserID:    &storedUser.ID,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("store mismatched access token: %v", err)
	}
	return token
}

func createClientMismatchAccessTokenForRouterTest(t *testing.T, db *gorm.DB) string {
	t.Helper()
	user := &model.User{
		ID:           uuid.New(),
		Email:        "csrf-router-client-claims@example.com",
		Username:     "csrfrouterclientclaims",
		PasswordHash: "hashed-password",
		Role:         model.RoleUser,
		Status:       "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, err := jwt.NewManager("test-secret-with-enough-length", "test").GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	if err := repository.NewOAuthRepository(db).CreateAccessToken(&model.AccessToken{
		Token:     token,
		ClientID:  "router-client-mismatch",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("store client mismatched access token: %v", err)
	}
	return token
}

func createNoEndUserAccessTokenForRouterTest(t *testing.T, db *gorm.DB) string {
	t.Helper()
	user := &model.User{
		ID:           uuid.New(),
		Email:        "csrf-router-no-end-user@example.com",
		Username:     "csrfrouternoenduser",
		PasswordHash: "hashed-password",
		Role:         model.RoleUser,
		Status:       "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, err := jwt.NewManager("test-secret-with-enough-length", "test").GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	if err := repository.NewOAuthRepository(db).CreateAccessToken(&model.AccessToken{
		Token:     token,
		ClientID:  "",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("store no end user access token: %v", err)
	}
	return token
}

func TestAuthRefreshRequiresCSRFHeaderWhenUsingCookie(t *testing.T) {
	send, db := setupAuthCSRFRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.AddCookie(&http.Cookie{Name: middleware.RefreshTokenCookie, Value: "refresh-token"})
	req.AddCookie(&http.Cookie{Name: middleware.CSRFTokenCookie, Value: "csrf-token"})

	rec := send(req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var count int64
	db.Model(&model.RiskEvent{}).
		Where("user_id IS NULL AND risk_score = ? AND decision = ?", 50, model.RiskDecisionChallenge).
		Count(&count)
	if count != 1 {
		t.Fatalf("risk event count=%d want 1", count)
	}
}

func TestAuthLogoutRequiresCSRFHeaderWhenUsingCookie(t *testing.T) {
	send, db := setupAuthCSRFRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.AddCookie(&http.Cookie{Name: middleware.AccessTokenCookie, Value: "access-token"})
	req.AddCookie(&http.Cookie{Name: middleware.CSRFTokenCookie, Value: "csrf-token"})

	rec := send(req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var count int64
	db.Model(&model.RiskEvent{}).
		Where("user_id IS NULL AND risk_score = ? AND decision = ?", 50, model.RiskDecisionChallenge).
		Count(&count)
	if count != 1 {
		t.Fatalf("risk event count=%d want 1", count)
	}
}

func TestAuthCheckPasswordDoesNotRequireCSRF(t *testing.T) {
	send, _ := setupAuthCSRFRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/check-password", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")

	rec := send(req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("check-password should not be blocked by CSRF middleware: body=%s", rec.Body.String())
	}
}

func TestOAuthTokenEndpointDoesNotRequireCSRF(t *testing.T) {
	send, _ := setupAuthCSRFRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")

	rec := send(req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("oauth token endpoint should not be blocked by CSRF middleware: body=%s", rec.Body.String())
	}
}

func TestProtectedBearerPostBypassesCSRF(t *testing.T) {
	send, _ := setupAuthCSRFRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/user/profile", nil)
	req.Header.Set("Authorization", "Bearer invalid")

	rec := send(req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("bearer request should not be blocked by CSRF middleware: body=%s", rec.Body.String())
	}
}

func TestProtectedBearerPostRejectsRevokedStoredAccessToken(t *testing.T) {
	send, db := setupAuthCSRFRouter(t)
	token := createAccessTokenForRouterTest(t, db)
	if err := repository.NewOAuthRepository(db).RevokeAccessToken(token); err != nil {
		t.Fatalf("revoke access token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := send(req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked stored access token status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestProtectedBearerPostRejectsStoredAccessTokenUserMismatch(t *testing.T) {
	send, db := setupAuthCSRFRouter(t)
	token := createUserMismatchAccessTokenForRouterTest(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := send(req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stored access token user mismatch status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestProtectedBearerPostRejectsStoredAccessTokenClientMismatch(t *testing.T) {
	send, db := setupAuthCSRFRouter(t)
	token := createClientMismatchAccessTokenForRouterTest(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := send(req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stored access token client mismatch status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestProtectedBearerPostRejectsStoredAccessTokenWithoutEndUser(t *testing.T) {
	send, db := setupAuthCSRFRouter(t)
	token := createNoEndUserAccessTokenForRouterTest(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := send(req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stored access token without end user status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestProtectedBearerPostRejectsUnstoredCentralAccessToken(t *testing.T) {
	send, db := setupAuthCSRFRouter(t)
	user := &model.User{
		ID:           uuid.New(),
		Email:        "unstored-central-reject@example.com",
		Username:     "unstoredcentralreject",
		PasswordHash: "hashed-password",
		Role:         model.RoleUser,
		Status:       "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, err := jwt.NewManager("test-secret-with-enough-length", "test").GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := send(req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unstored central access token status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestProtectedCookiePostRequiresCSRFHeader(t *testing.T) {
	send, db := setupAuthCSRFRouter(t)
	accessToken, userID := createAccessTokenWithUserIDForRouterTest(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/user/profile", nil)
	req.Host = "localhost"
	req.RemoteAddr = "203.0.113.51:23456"
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set("User-Agent", "csrf-router-risk-test")
	req.AddCookie(&http.Cookie{Name: middleware.AccessTokenCookie, Value: accessToken})
	req.AddCookie(&http.Cookie{Name: middleware.CSRFTokenCookie, Value: "csrf-token"})

	rec := send(req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var event model.RiskEvent
	if err := db.Where("user_id = ? AND risk_score = ? AND decision = ?", userID, 50, model.RiskDecisionChallenge).
		First(&event).Error; err != nil {
		t.Fatalf("find risk event: %v", err)
	}
	if event.UserID == nil || *event.UserID != userID {
		t.Fatalf("user_id=%v want %s", event.UserID, userID)
	}
	if event.IPAddress != "203.0.113.51" {
		t.Fatalf("ip_address=%q want 203.0.113.51", event.IPAddress)
	}
	if event.UserAgent != "csrf-router-risk-test" {
		t.Fatalf("user_agent=%q want csrf-router-risk-test", event.UserAgent)
	}
	if event.Reason != model.RiskEventReasonCSRFTokenHeaderMissing {
		t.Fatalf("reason=%q want %q", event.Reason, model.RiskEventReasonCSRFTokenHeaderMissing)
	}
}

func TestAuthRefreshWithCSRFHeaderReachesHandler(t *testing.T) {
	send, _ := setupAuthCSRFRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set(middleware.CSRFTokenHeader, "csrf-token")
	req.AddCookie(&http.Cookie{Name: middleware.RefreshTokenCookie, Value: uuid.NewString()})
	req.AddCookie(&http.Cookie{Name: middleware.CSRFTokenCookie, Value: "csrf-token"})

	rec := send(req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("refresh with matching CSRF token should reach handler: body=%s", rec.Body.String())
	}
}
