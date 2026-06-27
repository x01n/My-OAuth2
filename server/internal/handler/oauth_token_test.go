package handler

import (
	"encoding/base64"
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

type oauthTokenHandlerFixture struct {
	db        *gorm.DB
	router    *gin.Engine
	oauthRepo *repository.OAuthRepository
	manager   *jwt.Manager
	app       *model.Application
	user      *model.User
}

func setupOAuthTokenHandlerFixture(t *testing.T) oauthTokenHandlerFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.AuthorizationCode{}, &model.AccessToken{}, &model.RefreshToken{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	appRepo := repository.NewApplicationRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	userRepo := repository.NewUserRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)

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
	manager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer)
	oauthService := service.NewOAuthService(appRepo, oauthRepo, userRepo, nil, cfg)
	oauthService.SetJWTManager(manager)
	oauthService.SetRiskEventRepository(riskEventRepo)

	user := &model.User{
		Email:        "oauth-token-handler@example.com",
		Username:     "oauthtokenhandler",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:                "oauth-token-handler-client",
		ClientSecret:            "oauth-token-handler-secret",
		Name:                    "OAuth Token Handler Client",
		UserID:                  user.ID,
		AppType:                 model.AppTypeMachine,
		TokenEndpointAuthMethod: model.AuthMethodClientSecretBasic,
		GrantTypes:              `["client_credentials"]`,
		Scopes:                  `["read"]`,
		AllowedScopes:           `["read"]`,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/oauth/token", NewOAuthHandler(oauthService, nil, "", "").Token)

	return oauthTokenHandlerFixture{
		db:        db,
		router:    router,
		oauthRepo: oauthRepo,
		manager:   manager,
		app:       app,
		user:      user,
	}
}

func postTokenForm(t *testing.T, router *gin.Engine, values url.Values, basicClientID, basicClientSecret string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(values.Encode()))
	req.Host = "oauth.example.test"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "oauth-token-handler-test")
	req.RemoteAddr = "192.0.2.1:1234"
	if basicClientID != "" || basicClientSecret != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(basicClientID + ":" + basicClientSecret))
		req.Header.Set("Authorization", "Basic "+credentials)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestOAuthHandler_TokenInvalidBasicClientAuthenticationIncludesChallenge(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)

	rec := postTokenForm(t, f.router, url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"read"},
	}, f.app.ClientID, "wrong-secret")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="oauth"` {
		t.Fatalf("WWW-Authenticate=%q want %q", got, `Basic realm="oauth"`)
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

func TestOAuthHandler_TokenRejectsMultipleClientAuthenticationMethods(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)

	rec := postTokenForm(t, f.router, url.Values{
		"grant_type":    {"client_credentials"},
		"scope":         {"read"},
		"client_id":     {f.app.ClientID},
		"client_secret": {f.app.ClientSecret},
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

func TestOAuthHandler_TokenUnsupportedGrantType(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)

	rec := postTokenForm(t, f.router, url.Values{
		"grant_type":    {"password"},
		"client_id":     {f.app.ClientID},
		"client_secret": {f.app.ClientSecret},
	}, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Error != "unsupported_grant_type" {
		t.Fatalf("error=%q want unsupported_grant_type", body.Error)
	}
}

func TestOAuthHandler_TokenMissingGrantType(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)

	rec := postTokenForm(t, f.router, url.Values{
		"client_id":     {f.app.ClientID},
		"client_secret": {f.app.ClientSecret},
	}, "", "")
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

func TestOAuthHandler_TokenAuthorizationCodeRedirectMismatch(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)

	authCode := &model.AuthorizationCode{
		ClientID:            f.app.ClientID,
		UserID:              f.app.UserID,
		RedirectURI:         "http://localhost/callback",
		Scope:               "read",
		CodeChallenge:       "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	if err := f.oauthRepo.CreateAuthorizationCode(authCode); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}

	rec := postTokenForm(t, f.router, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode.Code},
		"redirect_uri":  {"http://localhost/other-callback"},
		"client_id":     {f.app.ClientID},
		"client_secret": {f.app.ClientSecret},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Error != "invalid_grant" {
		t.Fatalf("error=%q want invalid_grant", body.Error)
	}
}

func TestOAuthHandler_TokenErrorResponseIncludesNoStoreHeaders(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)

	rec := postTokenForm(t, f.router, url.Values{
		"grant_type":    {"password"},
		"client_id":     {f.app.ClientID},
		"client_secret": {f.app.ClientSecret},
	}, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma=%q want no-cache", got)
	}
}

func TestOAuthHandler_TokenRefreshReplayRecordsRequestContext(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)
	f.app.GrantTypes = `["client_credentials","refresh_token"]`
	if err := f.db.Save(f.app).Error; err != nil {
		t.Fatalf("update app grant types: %v", err)
	}

	accessToken := &model.AccessToken{
		ClientID:  f.app.ClientID,
		UserID:    &f.user.ID,
		Scope:     "read",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}
	refreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		UserID:        &f.user.ID,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	if err := f.oauthRepo.CreateRefreshToken(refreshToken); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	values := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken.Token},
	}
	first := postTokenForm(t, f.router, values, f.app.ClientID, f.app.ClientSecret)
	if first.Code != http.StatusOK {
		t.Fatalf("first refresh status=%d body=%s", first.Code, first.Body.String())
	}
	var firstBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(first.Body).Decode(&firstBody); err != nil {
		t.Fatalf("decode first refresh: %v", err)
	}
	if firstBody.AccessToken == "" || firstBody.RefreshToken == "" {
		t.Fatalf("first refresh returned incomplete tokens: %+v", firstBody)
	}

	replay := postTokenForm(t, f.router, values, f.app.ClientID, f.app.ClientSecret)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d want %d body=%s", replay.Code, http.StatusBadRequest, replay.Body.String())
	}

	var riskEvent model.RiskEvent
	if err := f.db.Where("user_id = ? AND risk_score = ? AND decision = ?", f.user.ID, 80, model.RiskDecisionBlock).
		First(&riskEvent).Error; err != nil {
		t.Fatalf("find risk event: %v", err)
	}
	if riskEvent.IPAddress != "192.0.2.1" {
		t.Fatalf("risk event ip_address=%q want %q", riskEvent.IPAddress, "192.0.2.1")
	}
	if riskEvent.UserAgent != "oauth-token-handler-test" {
		t.Fatalf("risk event user_agent=%q want %q", riskEvent.UserAgent, "oauth-token-handler-test")
	}
	if riskEvent.Reason != model.RiskEventReasonRefreshTokenReplay {
		t.Fatalf("risk event reason=%q want %q", riskEvent.Reason, model.RiskEventReasonRefreshTokenReplay)
	}
}

func TestOAuthHandler_TokenAuthorizationCodeIDTokenIncludesNonce(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)
	f.app.AppType = model.AppTypeConfidential
	f.app.RedirectURIs = `["http://localhost/callback"]`
	f.app.GrantTypes = `["client_credentials","authorization_code","refresh_token"]`
	f.app.Scopes = `["read","openid","profile"]`
	f.app.AllowedScopes = `["read","openid","profile"]`
	if err := f.db.Save(f.app).Error; err != nil {
		t.Fatalf("update app: %v", err)
	}

	authCode := &model.AuthorizationCode{
		ClientID:    f.app.ClientID,
		UserID:      f.user.ID,
		RedirectURI: "http://localhost/callback",
		Scope:       "openid profile",
		Nonce:       "nonce-123",
		AuthTime:    time.Now().Add(-5 * time.Minute).Unix(),
		AMR:         jwt.AuthenticationMethodPassword,
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	if err := f.oauthRepo.CreateAuthorizationCode(authCode); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}

	rec := postTokenForm(t, f.router, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode.Code},
		"redirect_uri":  {authCode.RedirectURI},
		"client_id":     {f.app.ClientID},
		"client_secret": {f.app.ClientSecret},
	}, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.AccessToken == "" {
		t.Fatalf("access_token is empty body=%s", rec.Body.String())
	}
	if body.RefreshToken == "" {
		t.Fatalf("refresh_token is empty body=%s", rec.Body.String())
	}
	if body.IDToken == "" {
		t.Fatalf("id_token is empty body=%s", rec.Body.String())
	}
	if body.TokenType != "Bearer" {
		t.Fatalf("token_type=%q want Bearer", body.TokenType)
	}
	if body.ExpiresIn != int64(time.Hour.Seconds()) {
		t.Fatalf("expires_in=%d want %d", body.ExpiresIn, int64(time.Hour.Seconds()))
	}
	if body.Scope != authCode.Scope {
		t.Fatalf("scope=%q want %q", body.Scope, authCode.Scope)
	}
	if jwt.IsEncryptedToken(body.IDToken) {
		t.Fatalf("id_token should be client-verifiable JWS, got encrypted token")
	}
	claims, err := f.manager.ValidateClientIDTokenWithIssuer(body.IDToken, f.app.ClientID, f.app.ClientSecret, "https://oauth.example.test")
	if err != nil {
		t.Fatalf("validate id_token: %v", err)
	}
	if claims.Nonce != "nonce-123" {
		t.Fatalf("Nonce=%q want nonce-123", claims.Nonce)
	}
	if claims.AuthTime != authCode.AuthTime {
		t.Fatalf("AuthTime=%d want %d", claims.AuthTime, authCode.AuthTime)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("AMR=%#v want [%q]", claims.AMR, jwt.AuthenticationMethodPassword)
	}
	if claims.ATHash != jwt.AccessTokenHash(body.AccessToken) {
		t.Fatalf("ATHash=%q want %q", claims.ATHash, jwt.AccessTokenHash(body.AccessToken))
	}
}

func TestOAuthHandler_TokenRefreshIDTokenPreservesAuthTime(t *testing.T) {
	f := setupOAuthTokenHandlerFixture(t)
	f.app.AppType = model.AppTypeConfidential
	f.app.RedirectURIs = `["http://localhost/callback"]`
	f.app.GrantTypes = `["client_credentials","authorization_code","refresh_token"]`
	f.app.Scopes = `["read","openid","profile"]`
	f.app.AllowedScopes = `["read","openid","profile"]`
	if err := f.db.Save(f.app).Error; err != nil {
		t.Fatalf("update app: %v", err)
	}

	authTime := time.Now().Add(-5 * time.Minute).Unix()
	accessToken := &model.AccessToken{
		ClientID:  f.app.ClientID,
		UserID:    &f.user.ID,
		Scope:     "openid profile",
		AuthTime:  authTime,
		AMR:       jwt.AuthenticationMethodPassword,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}
	refreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		UserID:        &f.user.ID,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	if err := f.oauthRepo.CreateRefreshToken(refreshToken); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	rec := postTokenForm(t, f.router, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken.Token},
	}, f.app.ClientID, f.app.ClientSecret)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.AccessToken == "" {
		t.Fatalf("access_token is empty body=%s", rec.Body.String())
	}
	if body.RefreshToken == "" {
		t.Fatalf("refresh_token is empty body=%s", rec.Body.String())
	}
	if body.IDToken == "" {
		t.Fatalf("id_token is empty body=%s", rec.Body.String())
	}
	if body.TokenType != "Bearer" {
		t.Fatalf("token_type=%q want Bearer", body.TokenType)
	}
	if body.ExpiresIn != int64(time.Hour.Seconds()) {
		t.Fatalf("expires_in=%d want %d", body.ExpiresIn, int64(time.Hour.Seconds()))
	}
	if body.Scope != accessToken.Scope {
		t.Fatalf("scope=%q want %q", body.Scope, accessToken.Scope)
	}
	if jwt.IsEncryptedToken(body.IDToken) {
		t.Fatalf("id_token should be client-verifiable JWS, got encrypted token")
	}
	claims, err := f.manager.ValidateClientIDTokenWithIssuer(body.IDToken, f.app.ClientID, f.app.ClientSecret, "https://oauth.example.test")
	if err != nil {
		t.Fatalf("validate id_token: %v", err)
	}
	if claims.AuthTime != authTime {
		t.Fatalf("AuthTime=%d want %d", claims.AuthTime, authTime)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("AMR=%#v want [%q]", claims.AMR, jwt.AuthenticationMethodPassword)
	}
	if claims.ATHash != jwt.AccessTokenHash(body.AccessToken) {
		t.Fatalf("ATHash=%q want %q", claims.ATHash, jwt.AccessTokenHash(body.AccessToken))
	}
}
