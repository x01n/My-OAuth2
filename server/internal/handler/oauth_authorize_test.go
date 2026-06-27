package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"server/internal/config"
	gctx "server/internal/context"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type oauthAuthorizeHandlerFixture struct {
	router       *gin.Engine
	db           *gorm.DB
	app          *model.Application
	user         *model.User
	userAuthRepo *repository.UserAuthorizationRepository
	authTime     *int64
}

func setupOAuthAuthorizeHandlerFixture(t *testing.T) oauthAuthorizeHandlerFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.AuthorizationCode{}, &model.AccessToken{}, &model.RefreshToken{}, &model.UserAuthorization{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	appRepo := repository.NewApplicationRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	userRepo := repository.NewUserRepository(db)
	userAuthRepo := repository.NewUserAuthorizationRepository(db)

	cfg := &config.Config{
		OAuth: config.OAuthConfig{
			AuthCodeTTL:     10 * time.Minute,
			AccessTokenTTL:  time.Hour,
			RefreshTokenTTL: 24 * time.Hour,
			IDTokenTTL:      time.Hour,
		},
		JWT: config.JWTConfig{
			Secret: "test-secret-with-enough-length",
			Issuer: "test",
		},
	}
	oauthService := service.NewOAuthService(appRepo, oauthRepo, userRepo, userAuthRepo, cfg)
	oauthService.SetJWTManager(jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer))

	user := &model.User{
		Email:        "oauth-authorize-handler@example.com",
		Username:     "oauthauthorizehandler",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:                "oauth-authorize-handler-client",
		ClientSecret:            "oauth-authorize-handler-secret",
		Name:                    "OAuth Authorize Handler Client",
		UserID:                  user.ID,
		RedirectURIs:            `["http://localhost/callback"]`,
		AppType:                 model.AppTypeConfidential,
		TokenEndpointAuthMethod: model.AuthMethodClientSecretBasic,
		GrantTypes:              `["authorization_code"]`,
		Scopes:                  `["read","openid","profile"]`,
		AllowedScopes:           `["read","openid","profile"]`,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	authTime := time.Now().Unix()
	setUserContext := func(c *gin.Context) {
		gctx.SetUser(c, user.ID, user.Email, user.Username, string(user.Role))
		gctx.SetAuthTime(c, authTime)
		gctx.SetAuthMethods(c, []string{jwt.AuthenticationMethodPassword})
	}
	router.GET("/api/oauth/authorize/pending", func(c *gin.Context) {
		setUserContext(c)
		NewOAuthHandler(oauthService, nil, "", "").GetAuthorizePending(c)
	})
	router.POST("/api/oauth/authorize", func(c *gin.Context) {
		setUserContext(c)
		NewOAuthHandler(oauthService, nil, "", "").AuthorizeSubmit(c)
	})

	return oauthAuthorizeHandlerFixture{
		router:       router,
		db:           db,
		app:          app,
		user:         user,
		userAuthRepo: userAuthRepo,
		authTime:     &authTime,
	}
}

func getAuthorizePending(t *testing.T, router *gin.Engine, params map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	q := make([]string, 0, len(params))
	for key, value := range params {
		q = append(q, key+"="+url.QueryEscape(value))
	}
	sort.Strings(q)
	req := httptest.NewRequest(http.MethodGet, "/api/oauth/authorize/pending?"+strings.Join(q, "&"), nil)
	req.RemoteAddr = "192.0.2.1:1234"

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func postAuthorizeSubmitJSON(t *testing.T, router *gin.Engine, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/oauth/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.1:1234"

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestOAuthHandler_AuthorizeSubmitDenyRejectsInvalidRedirectURI(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)

	rec := postAuthorizeSubmitJSON(t, f.router, map[string]any{
		"client_id":     f.app.ClientID,
		"redirect_uri":  "https://evil.example/callback",
		"response_type": "code",
		"scope":         "read",
		"state":         "state-value",
		"consent":       "deny",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "evil.example") {
		t.Fatalf("response should not contain invalid redirect URI body=%s", rec.Body.String())
	}

	var body Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Success {
		t.Fatalf("success=true want false body=%s", rec.Body.String())
	}
	if body.Error == nil {
		t.Fatalf("error is nil body=%s", rec.Body.String())
	}
	if body.Error.Code != "BAD_REQUEST" {
		t.Fatalf("error.code=%q want BAD_REQUEST", body.Error.Code)
	}
}

func TestOAuthHandler_AuthorizeSubmitDenyAllowsRegisteredRedirectURI(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)

	rec := postAuthorizeSubmitJSON(t, f.router, map[string]any{
		"client_id":     f.app.ClientID,
		"redirect_uri":  "http://localhost/callback",
		"response_type": "code",
		"scope":         "read",
		"state":         "state-value",
		"consent":       "deny",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			RedirectURL string `json:"redirect_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success {
		t.Fatalf("success=false want true body=%s", rec.Body.String())
	}
	if !strings.HasPrefix(body.Data.RedirectURL, "http://localhost/callback?") {
		t.Fatalf("redirect_url=%q want localhost callback", body.Data.RedirectURL)
	}
	if !strings.Contains(body.Data.RedirectURL, "error=access_denied") {
		t.Fatalf("redirect_url=%q want access_denied error", body.Data.RedirectURL)
	}
}

func TestOAuthHandler_AuthorizeSubmitStoresNonceOnAuthorizationCode(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)

	rec := postAuthorizeSubmitJSON(t, f.router, map[string]any{
		"client_id":     f.app.ClientID,
		"redirect_uri":  "http://localhost/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "state-value",
		"nonce":         "nonce-123",
		"consent":       "allow",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success || body.Data.Code == "" {
		t.Fatalf("response missing authorization code body=%s", rec.Body.String())
	}

	var authCode model.AuthorizationCode
	if err := f.db.First(&authCode, "code = ?", body.Data.Code).Error; err != nil {
		t.Fatalf("find authorization code: %v", err)
	}
	if authCode.Nonce != "nonce-123" {
		t.Fatalf("Nonce=%q want nonce-123", authCode.Nonce)
	}
}

func TestOAuthHandler_AuthorizeSubmitStoresAuthTimeAndMaxAge(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)
	authTime := time.Now().Add(-60 * time.Second).Unix()
	*f.authTime = authTime

	rec := postAuthorizeSubmitJSON(t, f.router, map[string]any{
		"client_id":     f.app.ClientID,
		"redirect_uri":  "http://localhost/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "state-value",
		"max_age":       "300",
		"consent":       "allow",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success || body.Data.Code == "" {
		t.Fatalf("response missing authorization code body=%s", rec.Body.String())
	}

	var authCode model.AuthorizationCode
	if err := f.db.First(&authCode, "code = ?", body.Data.Code).Error; err != nil {
		t.Fatalf("find authorization code: %v", err)
	}
	if authCode.AuthTime != authTime {
		t.Fatalf("AuthTime=%d want %d", authCode.AuthTime, authTime)
	}
	if authCode.MaxAge != 300 {
		t.Fatalf("MaxAge=%d want 300", authCode.MaxAge)
	}
	if authCode.AMR != jwt.AuthenticationMethodPassword {
		t.Fatalf("AMR=%q want %q", authCode.AMR, jwt.AuthenticationMethodPassword)
	}
}

func TestOAuthHandler_AuthorizeSubmitMaxAgeRequiresFreshLogin(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)
	*f.authTime = time.Now().Add(-10 * time.Minute).Unix()

	rec := postAuthorizeSubmitJSON(t, f.router, map[string]any{
		"client_id":     f.app.ClientID,
		"redirect_uri":  "http://localhost/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "state-value",
		"max_age":       "60",
		"consent":       "allow",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			LoginRequired bool `json:"login_required"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success || !body.Data.LoginRequired {
		t.Fatalf("login_required response missing body=%s", rec.Body.String())
	}

	var authCodeCount int64
	if err := f.db.Model(&model.AuthorizationCode{}).Count(&authCodeCount).Error; err != nil {
		t.Fatalf("count authorization codes: %v", err)
	}
	if authCodeCount != 0 {
		t.Fatalf("authorization code count=%d want 0", authCodeCount)
	}
}

func TestOAuthHandler_AuthorizePendingPromptNoneIssuesCodeWhenConsentExists(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)
	if _, err := f.userAuthRepo.CreateOrUpdate(f.user.ID, f.app.ID, "openid profile email", "authorization_code"); err != nil {
		t.Fatalf("create user authorization: %v", err)
	}

	rec := getAuthorizePending(t, f.router, map[string]string{
		"client_id":    f.app.ClientID,
		"redirect_uri": "http://localhost/callback",
		"scope":        "openid profile",
		"state":        "state-value",
		"prompt":       "none",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Pending     bool   `json:"pending"`
			RedirectURL string `json:"redirect_url"`
			Reused      bool   `json:"reused"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success || !body.Data.Pending || body.Data.RedirectURL == "" {
		t.Fatalf("prompt=none should return redirect_url body=%s", rec.Body.String())
	}
	if !strings.Contains(body.Data.RedirectURL, "code=") {
		t.Fatalf("redirect_url=%q should contain authorization code", body.Data.RedirectURL)
	}
	if !strings.Contains(body.Data.RedirectURL, "state=state-value") {
		t.Fatalf("redirect_url=%q should preserve state", body.Data.RedirectURL)
	}
}

func TestOAuthHandler_AuthorizePendingSkipsConsentWhenPriorAuthorizationExists(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)
	if _, err := f.userAuthRepo.CreateOrUpdate(f.user.ID, f.app.ID, "openid profile email", "authorization_code"); err != nil {
		t.Fatalf("create user authorization: %v", err)
	}

	rec := getAuthorizePending(t, f.router, map[string]string{
		"client_id":      f.app.ClientID,
		"redirect_uri":   "http://localhost/callback",
		"scope":          "openid profile",
		"state":          "state-value",
		"code_challenge": "fresh-pkce-challenge",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Pending     bool   `json:"pending"`
			RedirectURL string `json:"redirect_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success || !body.Data.Pending || body.Data.RedirectURL == "" {
		t.Fatalf("prior authorization should auto-issue code body=%s", rec.Body.String())
	}
	if !strings.Contains(body.Data.RedirectURL, "code=") {
		t.Fatalf("redirect_url=%q should contain authorization code", body.Data.RedirectURL)
	}
}

func TestOAuthHandler_AuthorizePendingPromptConsentRequiresManualConsent(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)
	if _, err := f.userAuthRepo.CreateOrUpdate(f.user.ID, f.app.ID, "openid profile email", "authorization_code"); err != nil {
		t.Fatalf("create user authorization: %v", err)
	}

	rec := getAuthorizePending(t, f.router, map[string]string{
		"client_id":    f.app.ClientID,
		"redirect_uri": "http://localhost/callback",
		"scope":        "openid profile",
		"state":        "state-value",
		"prompt":       "consent",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Pending     bool   `json:"pending"`
			RedirectURL string `json:"redirect_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success || body.Data.Pending || body.Data.RedirectURL != "" {
		t.Fatalf("prompt=consent should not auto-issue code body=%s", rec.Body.String())
	}
}

func TestOAuthHandler_AuthorizePendingPromptNoneReturnsConsentRequired(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)

	rec := getAuthorizePending(t, f.router, map[string]string{
		"client_id":    f.app.ClientID,
		"redirect_uri": "http://localhost/callback",
		"scope":        "openid profile",
		"state":        "state-value",
		"prompt":       "none",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			RedirectURL string `json:"redirect_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success || body.Data.RedirectURL == "" {
		t.Fatalf("prompt=none should return error redirect body=%s", rec.Body.String())
	}
	if !strings.Contains(body.Data.RedirectURL, "error=consent_required") {
		t.Fatalf("redirect_url=%q should contain consent_required", body.Data.RedirectURL)
	}
	if !strings.Contains(body.Data.RedirectURL, "state=state-value") {
		t.Fatalf("redirect_url=%q should preserve state", body.Data.RedirectURL)
	}
}

func TestOAuthHandler_AuthorizeSubmitPromptLoginRequiresFreshLogin(t *testing.T) {
	f := setupOAuthAuthorizeHandlerFixture(t)

	rec := postAuthorizeSubmitJSON(t, f.router, map[string]any{
		"client_id":     f.app.ClientID,
		"redirect_uri":  "http://localhost/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "state-value",
		"prompt":        "login",
		"consent":       "allow",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			LoginRequired bool `json:"login_required"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Success || !body.Data.LoginRequired {
		t.Fatalf("prompt=login should require login body=%s", rec.Body.String())
	}
}
