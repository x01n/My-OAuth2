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

type oauthRevokeHandlerFixture struct {
	router       *gin.Engine
	oauthRepo    *repository.OAuthRepository
	appRepo      *repository.ApplicationRepository
	app          *model.Application
	refreshToken *model.RefreshToken
}

func setupOAuthRevokeHandlerFixture(t *testing.T) oauthRevokeHandlerFixture {
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
		Email:        "oauth-revoke-handler@example.com",
		Username:     "oauthrevokehandler",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:      "oauth-revoke-handler-client",
		ClientSecret:  "oauth-revoke-handler-secret",
		Name:          "OAuth Revoke Handler Client",
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
	router.POST("/oauth/revoke", NewOAuthHandler(oauthService, nil, "", "").Revoke)

	return oauthRevokeHandlerFixture{
		router:       router,
		oauthRepo:    oauthRepo,
		appRepo:      appRepo,
		app:          app,
		refreshToken: refreshToken,
	}
}

func postRevokeForm(t *testing.T, router *gin.Engine, values url.Values) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func postRevokeFormWithBasicAuth(t *testing.T, router *gin.Engine, values url.Values, username, password string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(username, password)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func requireOAuthError(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, rec.Body.String())
	}
	if body.Error != want {
		t.Fatalf("error=%q want %q body=%s", body.Error, want, rec.Body.String())
	}
}

func createRefreshTokenForApp(t *testing.T, f oauthRevokeHandlerFixture, app *model.Application) *model.RefreshToken {
	t.Helper()

	accessToken := &model.AccessToken{
		ClientID:  app.ClientID,
		UserID:    &app.UserID,
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}
	refreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		UserID:        &app.UserID,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	if err := f.oauthRepo.CreateRefreshToken(refreshToken); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	return refreshToken
}

func TestOAuthHandler_RevokeRejectsMissingClientAuthentication(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	rec := postRevokeForm(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if storedRefreshToken.Revoked {
		t.Fatalf("refresh token should not be revoked without client authentication")
	}
}

func TestOAuthHandler_RevokeRejectsMultipleClientAuthenticationMethods(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	rec := postRevokeFormWithBasicAuth(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
		"client_id":       {f.app.ClientID},
		"client_secret":   {f.app.ClientSecret},
	}, f.app.ClientID, f.app.ClientSecret)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	requireOAuthError(t, rec, "invalid_request")

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if storedRefreshToken.Revoked {
		t.Fatalf("refresh token should not be revoked with multiple client authentication methods")
	}
}

func TestOAuthHandler_RevokeInvalidBasicAuthReturnsChallenge(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	rec := postRevokeFormWithBasicAuth(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
	}, f.app.ClientID, "wrong-secret")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Basic" {
		t.Fatalf("WWW-Authenticate=%q want Basic", got)
	}
	requireOAuthError(t, rec, "invalid_client")

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if storedRefreshToken.Revoked {
		t.Fatalf("refresh token should not be revoked with invalid Basic client authentication")
	}
}

func TestOAuthHandler_RevokeAcceptsBasicAuthClientAuthentication(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	values := url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.app.ClientID, f.app.ClientSecret)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("refresh token should be revoked")
	}
}

func TestOAuthHandler_RevokeAcceptsPostClientAuthentication(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	rec := postRevokeForm(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
		"client_id":       {f.app.ClientID},
		"client_secret":   {f.app.ClientSecret},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("refresh token should be revoked")
	}
}

func TestOAuthHandler_RevokeDifferentClientKeepsTokenActive(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	otherApp := &model.Application{
		ClientID:      "oauth-revoke-handler-other-client",
		ClientSecret:  "oauth-revoke-handler-other-secret",
		Name:          "OAuth Revoke Handler Other Client",
		UserID:        f.app.UserID,
		AppType:       model.AppTypeConfidential,
		GrantTypes:    `["authorization_code","refresh_token"]`,
		Scopes:        `["openid","profile","email"]`,
		AllowedScopes: `["openid","profile","email"]`,
	}
	if err := f.appRepo.Create(otherApp); err != nil {
		t.Fatalf("create other app: %v", err)
	}

	values := url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"refresh_token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(otherApp.ClientID, otherApp.ClientSecret)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if storedRefreshToken.Revoked {
		t.Fatalf("refresh token should stay active when revoked by a different client")
	}
}

func TestOAuthHandler_RevokeUnknownTokenReturnsOK(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	rec := postRevokeForm(t, f.router, url.Values{
		"token":           {"unknown-refresh-token"},
		"token_type_hint": {"refresh_token"},
		"client_id":       {f.app.ClientID},
		"client_secret":   {f.app.ClientSecret},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if storedRefreshToken.Revoked {
		t.Fatalf("existing refresh token should not be revoked by unknown token request")
	}
}

func TestOAuthHandler_RevokeIgnoresIncorrectTokenTypeHint(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	rec := postRevokeForm(t, f.router, url.Values{
		"token":           {f.refreshToken.Token},
		"token_type_hint": {"access_token"},
		"client_id":       {f.app.ClientID},
		"client_secret":   {f.app.ClientSecret},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("refresh token should be revoked when token_type_hint is incorrect")
	}
}

func TestOAuthHandler_RevokePublicClientOwnTokenWithoutSecret(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	publicApp := &model.Application{
		ClientID:                "oauth-revoke-handler-public-client",
		ClientSecret:            "oauth-revoke-handler-public-secret",
		Name:                    "OAuth Revoke Handler Public Client",
		UserID:                  f.app.UserID,
		AppType:                 model.AppTypePublic,
		TokenEndpointAuthMethod: model.AuthMethodNone,
		GrantTypes:              `["authorization_code","refresh_token"]`,
		Scopes:                  `["openid","profile","email"]`,
		AllowedScopes:           `["openid","profile","email"]`,
	}
	if err := f.appRepo.Create(publicApp); err != nil {
		t.Fatalf("create public app: %v", err)
	}
	refreshToken := createRefreshTokenForApp(t, f, publicApp)

	rec := postRevokeForm(t, f.router, url.Values{
		"token":           {refreshToken.Token},
		"token_type_hint": {"refresh_token"},
		"client_id":       {publicApp.ClientID},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("public client refresh token should be revoked without client_secret")
	}
}

func TestOAuthHandler_RevokePublicClientWrongSecretRejectsRequest(t *testing.T) {
	f := setupOAuthRevokeHandlerFixture(t)

	publicApp := &model.Application{
		ClientID:                "oauth-revoke-handler-public-wrong-secret-client",
		ClientSecret:            "oauth-revoke-handler-public-wrong-secret",
		Name:                    "OAuth Revoke Handler Public Wrong Secret Client",
		UserID:                  f.app.UserID,
		AppType:                 model.AppTypePublic,
		TokenEndpointAuthMethod: model.AuthMethodNone,
		GrantTypes:              `["authorization_code","refresh_token"]`,
		Scopes:                  `["openid","profile","email"]`,
		AllowedScopes:           `["openid","profile","email"]`,
	}
	if err := f.appRepo.Create(publicApp); err != nil {
		t.Fatalf("create public app: %v", err)
	}
	refreshToken := createRefreshTokenForApp(t, f, publicApp)

	rec := postRevokeForm(t, f.router, url.Values{
		"token":           {refreshToken.Token},
		"token_type_hint": {"refresh_token"},
		"client_id":       {publicApp.ClientID},
		"client_secret":   {"wrong-public-secret"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if storedRefreshToken.Revoked {
		t.Fatalf("public client refresh token should not be revoked with wrong client_secret")
	}
}
