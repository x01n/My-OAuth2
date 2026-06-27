package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type oauthIntrospectHandlerFixture struct {
	router       *gin.Engine
	app          *model.Application
	refreshToken *model.RefreshToken
}

func setupOAuthIntrospectHandlerFixture(t *testing.T) oauthIntrospectHandlerFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.AccessToken{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	appRepo := repository.NewApplicationRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	userRepo := repository.NewUserRepository(db)
	cfg := &config.Config{
		OAuth: config.OAuthConfig{
			AccessTokenTTL:  time.Hour,
			RefreshTokenTTL: 24 * time.Hour,
			IDTokenTTL:      time.Hour,
		},
		JWT: config.JWTConfig{
			Secret: "test-secret-with-enough-length",
			Issuer: "test",
		},
	}
	oauthService := service.NewOAuthService(appRepo, oauthRepo, userRepo, nil, cfg)
	oauthService.SetJWTManager(jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer))

	user := &model.User{
		Email:        "oauth-introspect-handler@example.com",
		Username:     "oauthintrospecthandler",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:      "oauth-introspect-handler-client",
		ClientSecret:  "oauth-introspect-handler-secret",
		Name:          "OAuth Introspect Handler Client",
		UserID:        user.ID,
		AppType:       model.AppTypeConfidential,
		GrantTypes:    `["authorization_code","refresh_token"]`,
		Scopes:        `["openid","profile","email"]`,
		AllowedScopes: `["openid","profile","email"]`,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	accessToken := &model.AccessToken{
		ClientID:  app.ClientID,
		UserID:    &user.ID,
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := oauthRepo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}
	refreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		UserID:        &user.ID,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	if err := oauthRepo.CreateRefreshToken(refreshToken); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/oauth/introspect", NewOAuthHandler(oauthService, nil, "", "").Introspect)

	return oauthIntrospectHandlerFixture{
		router:       router,
		app:          app,
		refreshToken: refreshToken,
	}
}

func postIntrospectForm(t *testing.T, router *gin.Engine, values url.Values) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func postIntrospectFormWithBasicAuth(t *testing.T, router *gin.Engine, values url.Values, username, password string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(username, password)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestOAuthHandler_IntrospectRejectsMissingClientAuthentication(t *testing.T) {
	f := setupOAuthIntrospectHandlerFixture(t)

	rec := postIntrospectForm(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Error != "invalid_client" {
		t.Fatalf("error=%q want invalid_client", body.Error)
	}
}

func TestOAuthHandler_IntrospectRejectsMultipleClientAuthenticationMethods(t *testing.T) {
	f := setupOAuthIntrospectHandlerFixture(t)

	rec := postIntrospectFormWithBasicAuth(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
		"client_id":       {f.app.ClientID},
		"client_secret":   {f.app.ClientSecret},
	}, f.app.ClientID, f.app.ClientSecret)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Error != "invalid_request" {
		t.Fatalf("error=%q want invalid_request", body.Error)
	}
}

func TestOAuthHandler_IntrospectInvalidBasicAuthReturnsChallenge(t *testing.T) {
	f := setupOAuthIntrospectHandlerFixture(t)

	rec := postIntrospectFormWithBasicAuth(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
	}, f.app.ClientID, "wrong-secret")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Basic" {
		t.Fatalf("WWW-Authenticate=%q want Basic", got)
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Error != "invalid_client" {
		t.Fatalf("error=%q want invalid_client", body.Error)
	}
}

func TestOAuthHandler_IntrospectReturnsInactiveForInvalidTokenWithValidClient(t *testing.T) {
	f := setupOAuthIntrospectHandlerFixture(t)

	rec := postIntrospectForm(t, f.router, url.Values{
		"token":           {"not-a-token"},
		"token_type_hint": {"refresh_token"},
		"client_id":       {f.app.ClientID},
		"client_secret":   {f.app.ClientSecret},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Active {
		t.Fatalf("active=true want false")
	}
}

func TestOAuthHandler_IntrospectIgnoresIncorrectTokenTypeHint(t *testing.T) {
	f := setupOAuthIntrospectHandlerFixture(t)

	rec := postIntrospectForm(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"access_token"},
		"client_id":       {f.app.ClientID},
		"client_secret":   {f.app.ClientSecret},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Active    bool   `json:"active"`
		ClientID  string `json:"client_id"`
		TokenType string `json:"token_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !body.Active {
		t.Fatalf("active=false want true body=%s", rec.Body.String())
	}
	if body.ClientID != f.app.ClientID {
		t.Fatalf("client_id=%s want %s body=%s", body.ClientID, f.app.ClientID, rec.Body.String())
	}
	if body.TokenType != "refresh_token" {
		t.Fatalf("token_type=%s want refresh_token body=%s", body.TokenType, rec.Body.String())
	}
}
