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

type tokenExchangeTestFixture struct {
	service      *OAuthService
	db           *gorm.DB
	oauthRepo    *repository.OAuthRepository
	user         *model.User
	app          *model.Application
	subjectToken *model.AccessToken
}

func setupTokenExchangeTestFixture(t *testing.T) tokenExchangeTestFixture {
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
	svc := NewOAuthService(appRepo, oauthRepo, userRepo, nil, cfg)
	svc.SetJWTManager(jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer))

	user := &model.User{
		Email:        "exchange-user@example.com",
		Username:     "exchangeuser",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:      "client-a",
		ClientSecret:  "secret-a",
		Name:          "Client A",
		UserID:        user.ID,
		AppType:       model.AppTypeConfidential,
		GrantTypes:    `["authorization_code","refresh_token","token_exchange"]`,
		Scopes:        `["openid","profile","email"]`,
		AllowedScopes: `["openid","profile","email"]`,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	subjectToken := &model.AccessToken{
		ClientID:  app.ClientID,
		UserID:    &user.ID,
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := oauthRepo.CreateAccessToken(subjectToken); err != nil {
		t.Fatalf("create subject token: %v", err)
	}

	return tokenExchangeTestFixture{
		service:      svc,
		db:           db,
		oauthRepo:    oauthRepo,
		user:         user,
		app:          app,
		subjectToken: subjectToken,
	}
}

func (f tokenExchangeTestFixture) validTokenExchangeInput() *TokenInput {
	return &TokenInput{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         f.app.ClientID,
		ClientSecret:     f.app.ClientSecret,
		SubjectToken:     f.subjectToken.Token,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            "openid",
	}
}

func TestOAuthService_TokenExchangeRejectsInvalidRequestShapes(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	tests := []struct {
		name  string
		patch func(*TokenInput)
	}{
		{
			name: "missing subject_token_type",
			patch: func(input *TokenInput) {
				input.SubjectTokenType = ""
			},
		},
		{
			name: "actor_token without actor_token_type",
			patch: func(input *TokenInput) {
				input.ActorToken = f.subjectToken.Token
			},
		},
		{
			name: "actor_token_type without actor_token",
			patch: func(input *TokenInput) {
				input.ActorTokenType = TokenTypeAccessToken
			},
		},
		{
			name: "unsupported requested_token_type",
			patch: func(input *TokenInput) {
				input.RequestedTokenType = TokenTypeIDToken
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := f.validTokenExchangeInput()
			tt.patch(input)

			result, err := f.service.Token(input)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("err=%v want ErrInvalidRequest", err)
			}
			if result != nil {
				t.Fatalf("result should be nil")
			}
		})
	}
}

func TestOAuthService_TokenRejectsUnsupportedGrantType(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	result, err := f.service.Token(&TokenInput{
		GrantType:    "password",
		ClientID:     f.app.ClientID,
		ClientSecret: f.app.ClientSecret,
	})
	if !errors.Is(err, ErrUnsupportedGrantType) {
		t.Fatalf("err=%v want ErrUnsupportedGrantType", err)
	}
	if result != nil {
		t.Fatalf("result should be nil")
	}
}

func TestOAuthService_TokenRejectsMissingGrantType(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	result, err := f.service.Token(&TokenInput{
		ClientID:     f.app.ClientID,
		ClientSecret: f.app.ClientSecret,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err=%v want ErrInvalidRequest", err)
	}
	if result != nil {
		t.Fatalf("result should be nil")
	}
}

func TestOAuthService_TokenExchangeRejectsUnsupportedTarget(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	tests := []struct {
		name  string
		patch func(*TokenInput)
	}{
		{
			name: "audience",
			patch: func(input *TokenInput) {
				input.Audience = "api://orders"
			},
		},
		{
			name: "resource",
			patch: func(input *TokenInput) {
				input.Resource = "https://api.example.com/orders"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := f.validTokenExchangeInput()
			tt.patch(input)

			result, err := f.service.Token(input)
			if !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("err=%v want ErrInvalidTarget", err)
			}
			if result != nil {
				t.Fatalf("result should be nil")
			}
		})
	}
}

func TestOAuthService_TokenExchangeRejectsCrossClientSubjectToken(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	crossClientToken := &model.AccessToken{
		ClientID:  "client-b",
		UserID:    &f.user.ID,
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(crossClientToken); err != nil {
		t.Fatalf("create cross client token: %v", err)
	}

	input := f.validTokenExchangeInput()
	input.SubjectToken = crossClientToken.Token

	result, err := f.service.Token(input)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("err=%v want ErrInvalidGrant", err)
	}
	if result != nil {
		t.Fatalf("result should be nil")
	}
}

func TestOAuthService_TokenExchangeRejectsCrossClientActorToken(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	crossClientActorToken := &model.AccessToken{
		ClientID:  "client-b",
		UserID:    &f.user.ID,
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(crossClientActorToken); err != nil {
		t.Fatalf("create cross client actor token: %v", err)
	}

	input := f.validTokenExchangeInput()
	input.ActorToken = crossClientActorToken.Token
	input.ActorTokenType = TokenTypeAccessToken

	result, err := f.service.Token(input)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("err=%v want ErrInvalidGrant", err)
	}
	if result != nil {
		t.Fatalf("result should be nil")
	}
}

func TestOAuthService_TokenExchangeRejectsScopeOutsideSubjectToken(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	input := f.validTokenExchangeInput()
	input.Scope = "email"

	result, err := f.service.Token(input)
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("err=%v want ErrInvalidScope", err)
	}
	if result != nil {
		t.Fatalf("result should be nil")
	}
}

func TestOAuthService_TokenExchangeIssuesAccessTokenWithIssuedTokenType(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	result, err := f.service.Token(f.validTokenExchangeInput())
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if result == nil {
		t.Fatalf("result should not be nil")
	}
	if result.AccessToken == "" {
		t.Fatalf("access token should not be empty")
	}
	if result.RefreshToken != "" {
		t.Fatalf("refresh token should be empty")
	}
	if result.IssuedTokenType != TokenTypeAccessToken {
		t.Fatalf("issued_token_type=%q want %q", result.IssuedTokenType, TokenTypeAccessToken)
	}
	if result.Scope != "openid" {
		t.Fatalf("scope=%q want openid", result.Scope)
	}
}

func TestOAuthService_TokenExchangeIssuesRefreshTokenWithIssuedTokenType(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	input := f.validTokenExchangeInput()
	input.RequestedTokenType = TokenTypeRefreshToken

	result, err := f.service.Token(input)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if result == nil {
		t.Fatalf("result should not be nil")
	}
	if result.AccessToken == "" {
		t.Fatalf("access token should not be empty")
	}
	if result.RefreshToken == "" {
		t.Fatalf("refresh token should not be empty")
	}
	if result.IssuedTokenType != TokenTypeRefreshToken {
		t.Fatalf("issued_token_type=%q want %q", result.IssuedTokenType, TokenTypeRefreshToken)
	}
}

func TestOAuthService_TokenExchangeRejectsRefreshTokenWhenGrantDisabled(t *testing.T) {
	f := setupTokenExchangeTestFixture(t)

	f.app.GrantTypes = `["token_exchange"]`
	if err := f.service.appRepo.Update(f.app); err != nil {
		t.Fatalf("update app grant types: %v", err)
	}

	input := f.validTokenExchangeInput()
	input.RequestedTokenType = TokenTypeRefreshToken

	result, err := f.service.Token(input)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("token exchange error=%v want %v", err, ErrInvalidGrant)
	}
	if result != nil {
		t.Fatalf("result should be nil when refresh_token grant is disabled")
	}

	var accessTokenCount int64
	if err := f.db.Model(&model.AccessToken{}).
		Where("client_id = ? AND token <> ?", f.app.ClientID, f.subjectToken.Token).
		Count(&accessTokenCount).Error; err != nil {
		t.Fatalf("count issued access tokens: %v", err)
	}
	if accessTokenCount != 0 {
		t.Fatalf("issued access token count=%d want 0", accessTokenCount)
	}

	var refreshTokenCount int64
	if err := f.db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked = ?", f.user.ID, false).
		Count(&refreshTokenCount).Error; err != nil {
		t.Fatalf("count issued refresh tokens: %v", err)
	}
	if refreshTokenCount != 0 {
		t.Fatalf("issued refresh token count=%d want 0", refreshTokenCount)
	}
}
