package service

import (
	"errors"
	"testing"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type introspectionTestFixture struct {
	service      *OAuthService
	userRepo     *repository.UserRepository
	oauthRepo    *repository.OAuthRepository
	user         *model.User
	app          *model.Application
	refreshToken *model.RefreshToken
}

func setupIntrospectionTestFixture(t *testing.T) introspectionTestFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.AuthorizationCode{}, &model.AccessToken{}, &model.RefreshToken{}); err != nil {
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
	svc := NewOAuthService(appRepo, oauthRepo, userRepo, nil, cfg)
	svc.SetJWTManager(jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer))

	user := &model.User{
		Email:        "introspect-user@example.com",
		Username:     "introspectuser",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:      "client-introspect",
		ClientSecret:  "secret-introspect",
		Name:          "Client Introspect",
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

	return introspectionTestFixture{
		service:      svc,
		userRepo:     userRepo,
		oauthRepo:    oauthRepo,
		user:         user,
		app:          app,
		refreshToken: refreshToken,
	}
}

func TestOAuthService_IntrospectToken_ReturnsInactiveForSuspendedRefreshTokenUser(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	f.user.Status = "suspended"
	if err := f.userRepo.Update(f.user); err != nil {
		t.Fatalf("update user: %v", err)
	}

	result, err := f.service.IntrospectToken(f.refreshToken.Token, f.app.ClientID, f.app.ClientSecret, "refresh_token")
	if err != nil {
		t.Fatalf("introspect refresh token: %v", err)
	}

	active, ok := result["active"].(bool)
	if !ok {
		t.Fatalf("active type=%T want bool", result["active"])
	}
	if active {
		t.Fatalf("active=true want false for suspended user")
	}
	if _, ok := result["sub"]; ok {
		t.Fatalf("inactive response should not include sub")
	}
	if _, ok := result["username"]; ok {
		t.Fatalf("inactive response should not include username")
	}
}

func TestOAuthService_IntrospectToken_ReturnsRefreshTokenClaimsForActiveUser(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	result, err := f.service.IntrospectToken(f.refreshToken.Token, f.app.ClientID, f.app.ClientSecret, "refresh_token")
	if err != nil {
		t.Fatalf("introspect refresh token: %v", err)
	}

	if active, ok := result["active"].(bool); !ok || !active {
		t.Fatalf("active=%v want true", result["active"])
	}
	if got := result["client_id"]; got != f.app.ClientID {
		t.Fatalf("client_id=%v want %s", got, f.app.ClientID)
	}
	if got := result["token_type"]; got != "refresh_token" {
		t.Fatalf("token_type=%v want refresh_token", got)
	}
	if got := result["sub"]; got != f.user.ID.String() {
		t.Fatalf("sub=%v want %s", got, f.user.ID.String())
	}
}

func TestOAuthService_IntrospectToken_IgnoresIncorrectTokenTypeHint(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	result, err := f.service.IntrospectToken(f.refreshToken.Token, f.app.ClientID, f.app.ClientSecret, "access_token")
	if err != nil {
		t.Fatalf("introspect refresh token with incorrect hint: %v", err)
	}

	if active, ok := result["active"].(bool); !ok || !active {
		t.Fatalf("active=%v want true", result["active"])
	}
	if got := result["client_id"]; got != f.app.ClientID {
		t.Fatalf("client_id=%v want %s", got, f.app.ClientID)
	}
	if got := result["token_type"]; got != "refresh_token" {
		t.Fatalf("token_type=%v want refresh_token", got)
	}
	if got := result["sub"]; got != f.user.ID.String() {
		t.Fatalf("sub=%v want %s", got, f.user.ID.String())
	}
}

func TestOAuthService_IntrospectToken_ReturnsInactiveForDifferentClient(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	otherApp := &model.Application{
		ClientID:      "client-introspect-other",
		ClientSecret:  "secret-introspect-other",
		Name:          "Other Introspect Client",
		UserID:        f.user.ID,
		AppType:       model.AppTypeConfidential,
		GrantTypes:    `["authorization_code","refresh_token"]`,
		Scopes:        `["openid","profile","email"]`,
		AllowedScopes: `["openid","profile","email"]`,
	}
	if err := f.service.appRepo.Create(otherApp); err != nil {
		t.Fatalf("create other app: %v", err)
	}

	result, err := f.service.IntrospectToken(f.refreshToken.Token, otherApp.ClientID, otherApp.ClientSecret, "refresh_token")
	if err != nil {
		t.Fatalf("introspect refresh token with other client: %v", err)
	}

	active, ok := result["active"].(bool)
	if !ok {
		t.Fatalf("active type=%T want bool", result["active"])
	}
	if active {
		t.Fatalf("active=true want false for different client")
	}
	if _, ok := result["exp"]; ok {
		t.Fatalf("inactive response should not include exp")
	}
	if _, ok := result["sub"]; ok {
		t.Fatalf("inactive response should not include sub")
	}
}

func TestOAuthService_TokenRejectsPublicAuthorizationCodeWithoutPKCE(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	publicApp := &model.Application{
		ClientID:                "public-auth-code-client",
		ClientSecret:            "public-auth-code-secret",
		Name:                    "Public Auth Code Client",
		UserID:                  f.user.ID,
		AppType:                 model.AppTypePublic,
		TokenEndpointAuthMethod: model.AuthMethodNone,
		RedirectURIs:            `["http://localhost/callback"]`,
		GrantTypes:              `["authorization_code","refresh_token"]`,
		Scopes:                  `["openid","profile"]`,
		AllowedScopes:           `["openid","profile"]`,
	}
	if err := f.service.appRepo.Create(publicApp); err != nil {
		t.Fatalf("create public app: %v", err)
	}

	authCode := &model.AuthorizationCode{
		ClientID:    publicApp.ClientID,
		UserID:      f.user.ID,
		RedirectURI: "http://localhost/callback",
		Scope:       "openid profile",
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	if err := f.oauthRepo.CreateAuthorizationCode(authCode); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}

	result, err := f.service.Token(&TokenInput{
		GrantType:    "authorization_code",
		Code:         authCode.Code,
		RedirectURI:  authCode.RedirectURI,
		ClientID:     publicApp.ClientID,
		CodeVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
	})
	if !errors.Is(err, ErrInvalidCodeVerifier) {
		t.Fatalf("err=%v want ErrInvalidCodeVerifier", err)
	}
	if result != nil {
		t.Fatalf("result should be nil")
	}
}

func TestOAuthService_TokenRejectsAuthorizationCodeRedirectMismatch(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	authCode := &model.AuthorizationCode{
		ClientID:            f.app.ClientID,
		UserID:              f.user.ID,
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid profile",
		CodeChallenge:       "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	if err := f.oauthRepo.CreateAuthorizationCode(authCode); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}

	result, err := f.service.Token(&TokenInput{
		GrantType:    "authorization_code",
		Code:         authCode.Code,
		RedirectURI:  "http://localhost/other-callback",
		ClientID:     f.app.ClientID,
		ClientSecret: f.app.ClientSecret,
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
	if !errors.Is(err, ErrInvalidRedirectURI) {
		t.Fatalf("err=%v want ErrInvalidRedirectURI", err)
	}
	if result != nil {
		t.Fatalf("result should be nil")
	}
}

func TestOAuthService_GetUserInfoWithScopeRequiresOpenIDScope(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	accessToken := &model.AccessToken{
		Token:     "userinfo-no-openid-token",
		ClientID:  f.app.ClientID,
		UserID:    &f.user.ID,
		Scope:     "profile email",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}

	user, scope, err := f.service.GetUserInfoWithScope(accessToken.Token)
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("err=%v want ErrInvalidScope", err)
	}
	if user != nil {
		t.Fatalf("user should be nil")
	}
	if scope != "" {
		t.Fatalf("scope=%q want empty", scope)
	}
}

func TestOAuthService_GetUserInfoWithScopeAllowsOpenIDScope(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	accessToken := &model.AccessToken{
		Token:     "userinfo-openid-token",
		ClientID:  f.app.ClientID,
		UserID:    &f.user.ID,
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}

	user, scope, err := f.service.GetUserInfoWithScope(accessToken.Token)
	if err != nil {
		t.Fatalf("GetUserInfoWithScope: %v", err)
	}
	if user == nil || user.ID != f.user.ID {
		t.Fatalf("user=%v want fixture user", user)
	}
	if scope != "openid profile" {
		t.Fatalf("scope=%q want openid profile", scope)
	}
}

func TestOAuthService_RevokeTokenForClientRequiresClientAuthentication(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	if err := f.service.RevokeTokenForClient(f.refreshToken.Token, "refresh_token", f.app.ClientID, ""); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("revoke error=%v want %v", err, ErrInvalidClient)
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if storedRefreshToken.Revoked {
		t.Fatalf("refresh token should not be revoked after invalid client authentication")
	}
}

func TestOAuthService_RevokeTokenForClientDoesNotRevokeDifferentClientToken(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	otherApp := &model.Application{
		ClientID:      "client-introspect-other",
		ClientSecret:  "secret-introspect-other",
		Name:          "Other Introspect Client",
		UserID:        f.user.ID,
		AppType:       model.AppTypeConfidential,
		GrantTypes:    `["authorization_code","refresh_token"]`,
		Scopes:        `["openid","profile","email"]`,
		AllowedScopes: `["openid","profile","email"]`,
	}
	if err := f.service.appRepo.Create(otherApp); err != nil {
		t.Fatalf("create other app: %v", err)
	}

	if err := f.service.RevokeTokenForClient(f.refreshToken.Token, "refresh_token", otherApp.ClientID, otherApp.ClientSecret); err != nil {
		t.Fatalf("revoke with different client: %v", err)
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if storedRefreshToken.Revoked {
		t.Fatalf("refresh token should not be revoked by a different client")
	}
}

func TestOAuthService_RevokeTokenForClientRevokesOwnedRefreshAndAccessToken(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	if err := f.service.RevokeTokenForClient(f.refreshToken.Token, "refresh_token", f.app.ClientID, f.app.ClientSecret); err != nil {
		t.Fatalf("revoke refresh token: %v", err)
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("refresh token should be revoked")
	}
	if f.refreshToken.AccessTokenID == nil {
		t.Fatalf("refresh token access_token_id is nil")
	}
	storedAccessToken, err := f.oauthRepo.FindAccessTokenByID(*f.refreshToken.AccessTokenID)
	if err != nil {
		t.Fatalf("find access token: %v", err)
	}
	if !storedAccessToken.Revoked {
		t.Fatalf("access token should be revoked")
	}
}

func TestOAuthService_RevokeTokenForClientIgnoresIncorrectTokenTypeHint(t *testing.T) {
	f := setupIntrospectionTestFixture(t)

	if err := f.service.RevokeTokenForClient(f.refreshToken.Token, "access_token", f.app.ClientID, f.app.ClientSecret); err != nil {
		t.Fatalf("revoke refresh token with incorrect hint: %v", err)
	}

	storedRefreshToken, err := f.oauthRepo.FindRefreshToken(f.refreshToken.Token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("refresh token should be revoked when token_type_hint is incorrect")
	}
	if f.refreshToken.AccessTokenID == nil {
		t.Fatalf("refresh token access_token_id is nil")
	}
	storedAccessToken, err := f.oauthRepo.FindAccessTokenByID(*f.refreshToken.AccessTokenID)
	if err != nil {
		t.Fatalf("find access token: %v", err)
	}
	if !storedAccessToken.Revoked {
		t.Fatalf("access token should be revoked when token_type_hint is incorrect")
	}
}
