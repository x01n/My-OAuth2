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

func setupOAuthRefreshRiskEventTest(t *testing.T) (*OAuthService, *gorm.DB, *model.User, *model.Application, *model.RefreshToken) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.AccessToken{}, &model.RefreshToken{}, &model.RiskEvent{}); err != nil {
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
	service := NewOAuthService(appRepo, oauthRepo, userRepo, nil, cfg)
	service.SetJWTManager(jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer))
	service.SetRiskEventRepository(riskEventRepo)

	user := &model.User{
		Email:        "oauth-refresh-risk@example.com",
		Username:     "oauthrefreshrisk",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:      "oauth-refresh-risk-client",
		ClientSecret:  "oauth-refresh-risk-secret",
		Name:          "OAuth Refresh Risk Client",
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

	return service, db, user, app, refreshToken
}

func TestOAuthService_RefreshTokenReplayRecordsRiskEvent(t *testing.T) {
	service, db, user, app, refreshToken := setupOAuthRefreshRiskEventTest(t)

	sameClientAccessToken := &model.AccessToken{
		ClientID:  app.ClientID,
		UserID:    &user.ID,
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := service.oauthRepo.CreateAccessToken(sameClientAccessToken); err != nil {
		t.Fatalf("create same-client access token: %v", err)
	}
	sameClientRefreshToken := &model.RefreshToken{
		AccessTokenID: &sameClientAccessToken.ID,
		UserID:        &user.ID,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	if err := service.oauthRepo.CreateRefreshToken(sameClientRefreshToken); err != nil {
		t.Fatalf("create same-client refresh token: %v", err)
	}

	input := &TokenInput{
		GrantType:    "refresh_token",
		ClientID:     app.ClientID,
		RefreshToken: refreshToken.Token,
		IPAddress:    "203.0.113.71",
		UserAgent:    "oauth-refresh-replay-test",
	}
	result, err := service.Token(input)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if result == nil || result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatalf("first refresh returned incomplete tokens: %+v", result)
	}

	if _, err := service.Token(input); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("replayed refresh error=%v want %v", err, ErrTokenRevoked)
	}

	var riskEvent model.RiskEvent
	if err := db.Where("user_id = ? AND risk_score = ? AND decision = ?", user.ID, 80, model.RiskDecisionBlock).
		First(&riskEvent).Error; err != nil {
		t.Fatalf("find risk event: %v", err)
	}
	if riskEvent.IPAddress != "203.0.113.71" {
		t.Fatalf("risk event ip_address=%q want %q", riskEvent.IPAddress, "203.0.113.71")
	}
	if riskEvent.UserAgent != "oauth-refresh-replay-test" {
		t.Fatalf("risk event user_agent=%q want %q", riskEvent.UserAgent, "oauth-refresh-replay-test")
	}
	if riskEvent.Reason != model.RiskEventReasonRefreshTokenReplay {
		t.Fatalf("risk event reason=%q want %q", riskEvent.Reason, model.RiskEventReasonRefreshTokenReplay)
	}

	storedRefreshToken, err := service.oauthRepo.FindRefreshToken(result.RefreshToken)
	if err != nil {
		t.Fatalf("find rotated refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("rotated refresh token should be revoked after replay detection")
	}

	storedAccessToken, err := service.oauthRepo.FindAccessToken(result.AccessToken)
	if err != nil {
		t.Fatalf("find rotated access token: %v", err)
	}
	if !storedAccessToken.Revoked {
		t.Fatalf("rotated access token should be revoked after replay detection")
	}

	var storedSameClientAccessToken model.AccessToken
	if err := db.First(&storedSameClientAccessToken, "id = ?", sameClientAccessToken.ID).Error; err != nil {
		t.Fatalf("find same-client access token: %v", err)
	}
	if !storedSameClientAccessToken.Revoked {
		t.Fatalf("same-client access token should be revoked after replay detection")
	}

	var storedSameClientRefreshToken model.RefreshToken
	if err := db.First(&storedSameClientRefreshToken, "id = ?", sameClientRefreshToken.ID).Error; err != nil {
		t.Fatalf("find same-client refresh token: %v", err)
	}
	if !storedSameClientRefreshToken.Revoked {
		t.Fatalf("same-client refresh token should be revoked after replay detection")
	}
}
