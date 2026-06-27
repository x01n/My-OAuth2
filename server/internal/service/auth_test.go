package service

import (
	"errors"
	"testing"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
	"server/pkg/password"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAuthServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.LoginLog{}, &model.AccessToken{}, &model.RefreshToken{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testAuthServiceConfig() *config.Config {
	return &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
}

func TestAuthService_LoginStoresCentralAccessToken(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	hash, err := password.Hash("LoginPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "login-store@example.com",
		Username:     "loginstore",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := testAuthServiceConfig()
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetOAuthRepo(oauthRepo)

	_, tokens, err := authService.Login(&LoginInput{
		Email:    user.Email,
		Password: "LoginPass123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	storedAccessToken, err := oauthRepo.FindAccessToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("find stored access token: %v", err)
	}
	if storedAccessToken.ClientID != "" {
		t.Fatalf("client_id=%q want empty central token client_id", storedAccessToken.ClientID)
	}
	if storedAccessToken.UserID == nil || *storedAccessToken.UserID != user.ID {
		t.Fatalf("stored access token user_id=%v want %s", storedAccessToken.UserID, user.ID)
	}
	if !storedAccessToken.IsValid() {
		t.Fatalf("stored access token should be valid")
	}
}

func TestAuthService_RefreshTokensStoresRotatedCentralAccessToken(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	hash, err := password.Hash("RefreshPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "refresh-store@example.com",
		Username:     "refreshstore",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := testAuthServiceConfig()
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetOAuthRepo(oauthRepo)

	_, initialTokens, err := authService.Login(&LoginInput{
		Email:    user.Email,
		Password: "RefreshPass123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	refreshedTokens, err := authService.RefreshTokens(initialTokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh tokens: %v", err)
	}

	storedAccessToken, err := oauthRepo.FindAccessToken(refreshedTokens.AccessToken)
	if err != nil {
		t.Fatalf("find refreshed access token: %v", err)
	}
	if storedAccessToken.ClientID != "" {
		t.Fatalf("client_id=%q want empty central token client_id", storedAccessToken.ClientID)
	}
	if storedAccessToken.UserID == nil || *storedAccessToken.UserID != user.ID {
		t.Fatalf("stored refreshed access token user_id=%v want %s", storedAccessToken.UserID, user.ID)
	}
	if !storedAccessToken.IsValid() {
		t.Fatalf("stored refreshed access token should be valid")
	}
}

func TestAuthService_RefreshTokensPreservesAuthTime(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	hash, err := password.Hash("RefreshAuthTime123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "refresh-auth-time@example.com",
		Username:     "refreshauthtime",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := testAuthServiceConfig()
	manager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer)
	authService := NewAuthService(userRepo, loginLogRepo, manager, cfg)
	authService.SetOAuthRepo(oauthRepo)

	authTime := time.Now().Add(-10 * time.Minute).Unix()
	initialTokens, err := authService.generateTokens(user, authTime)
	if err != nil {
		t.Fatalf("generate initial tokens: %v", err)
	}

	refreshedTokens, err := authService.RefreshTokens(initialTokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh tokens: %v", err)
	}

	accessClaims, err := manager.ValidateAccessToken(refreshedTokens.AccessToken)
	if err != nil {
		t.Fatalf("validate refreshed access token: %v", err)
	}
	if accessClaims.AuthTime != authTime {
		t.Fatalf("refreshed access auth_time=%d want %d", accessClaims.AuthTime, authTime)
	}
	if len(accessClaims.AMR) != 1 || accessClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("refreshed access amr=%#v want [%q]", accessClaims.AMR, jwt.AuthenticationMethodPassword)
	}

	refreshClaims, err := manager.ValidateRefreshToken(refreshedTokens.RefreshToken)
	if err != nil {
		t.Fatalf("validate refreshed refresh token: %v", err)
	}
	if refreshClaims.AuthTime != authTime {
		t.Fatalf("refreshed refresh auth_time=%d want %d", refreshClaims.AuthTime, authTime)
	}
	if len(refreshClaims.AMR) != 1 || refreshClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("refreshed refresh amr=%#v want [%q]", refreshClaims.AMR, jwt.AuthenticationMethodPassword)
	}

	idClaims, err := manager.ValidateToken(refreshedTokens.IDToken)
	if err != nil {
		t.Fatalf("validate refreshed id_token: %v", err)
	}
	if idClaims.AuthTime != authTime {
		t.Fatalf("refreshed id_token auth_time=%d want %d", idClaims.AuthTime, authTime)
	}
	if len(idClaims.AMR) != 1 || idClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("refreshed id_token amr=%#v want [%q]", idClaims.AMR, jwt.AuthenticationMethodPassword)
	}
	if idClaims.ATHash != jwt.AccessTokenHash(refreshedTokens.AccessToken) {
		t.Fatalf("refreshed id_token at_hash=%q want %q", idClaims.ATHash, jwt.AccessTokenHash(refreshedTokens.AccessToken))
	}
}

func TestAuthService_Login_blocksHighRiskAnomalyBeforeIssuingTokens(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "risk@example.com",
		Username:     "riskuser",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now().Add(-30 * time.Minute)
	logs := []model.LoginLog{
		{UserID: &user.ID, LoginType: model.LoginTypeDirect, IPAddress: "10.0.0.8", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: true, Email: user.Email, CreatedAt: now},
		{UserID: &user.ID, LoginType: model.LoginTypeDirect, IPAddress: "10.0.0.9", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: now.Add(5 * time.Minute)},
		{UserID: &user.ID, LoginType: model.LoginTypeDirect, IPAddress: "10.0.0.10", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: now.Add(10 * time.Minute)},
		{UserID: &user.ID, LoginType: model.LoginTypeDirect, IPAddress: "10.0.0.11", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: now.Add(15 * time.Minute)},
	}
	if err := db.Create(&logs).Error; err != nil {
		t.Fatalf("create logs: %v", err)
	}

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetAnomalyDetectionService(NewAnomalyDetectionService(loginLogRepo, userRepo))
	authService.SetRiskEventRepository(riskEventRepo)

	_, tokens, err := authService.Login(&LoginInput{
		Email:     user.Email,
		Password:  "StrongPass123!",
		IPAddress: "203.0.113.44",
		UserAgent: "curl/8.0",
	})
	if !errors.Is(err, ErrSuspiciousLogin) {
		t.Fatalf("err=%v want ErrSuspiciousLogin", err)
	}
	if tokens != nil {
		t.Fatalf("tokens should be nil when login is blocked")
	}

	var successCount int64
	db.Model(&model.LoginLog{}).Where("user_id = ? AND success = true AND ip_address = ?", user.ID, "203.0.113.44").Count(&successCount)
	if successCount != 0 {
		t.Fatalf("blocked login wrote success log count=%d", successCount)
	}

	var riskEvent model.RiskEvent
	if err := db.Where("user_id = ? AND risk_score = ? AND decision = ?", user.ID, 100, model.RiskDecisionBlock).
		First(&riskEvent).Error; err != nil {
		t.Fatalf("find risk event: %v", err)
	}
	if riskEvent.IPAddress != "203.0.113.44" {
		t.Fatalf("risk event ip address=%q want 203.0.113.44", riskEvent.IPAddress)
	}
	if riskEvent.UserAgent != "curl/8.0" {
		t.Fatalf("risk event user agent=%q want curl/8.0", riskEvent.UserAgent)
	}
	if riskEvent.Reason != model.RiskEventReasonSuspiciousLogin {
		t.Fatalf("risk event reason=%q want %q", riskEvent.Reason, model.RiskEventReasonSuspiciousLogin)
	}
}

func TestAuthService_Login_recordsRiskEventWhenMFARequired(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "risk-mfa@example.com",
		Username:     "riskmfa",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	logs := []model.LoginLog{
		{UserID: &user.ID, LoginType: model.LoginTypeDirect, IPAddress: "10.0.0.8", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: true, Email: user.Email, CreatedAt: time.Now().Add(-2 * time.Hour)},
		{UserID: &user.ID, LoginType: model.LoginTypeDirect, IPAddress: "10.0.0.9", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: time.Now().Add(-30 * time.Minute)},
		{UserID: &user.ID, LoginType: model.LoginTypeDirect, IPAddress: "10.0.0.10", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: time.Now().Add(-20 * time.Minute)},
		{UserID: &user.ID, LoginType: model.LoginTypeDirect, IPAddress: "10.0.0.11", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: time.Now().Add(-10 * time.Minute)},
	}
	if err := db.Create(&logs).Error; err != nil {
		t.Fatalf("create logs: %v", err)
	}

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetAnomalyDetectionService(NewAnomalyDetectionService(loginLogRepo, userRepo))
	authService.SetRiskEventRepository(riskEventRepo)

	_, tokens, err := authService.Login(&LoginInput{
		Email:     user.Email,
		Password:  "StrongPass123!",
		IPAddress: "203.0.113.44",
		UserAgent: "Mozilla/5.0 Firefox/121.0 Linux",
	})
	if err != nil {
		t.Fatalf("login with mfa-risk anomaly: %v", err)
	}
	if tokens == nil {
		t.Fatalf("tokens should be issued for mfa-risk login")
	}

	var riskEvent model.RiskEvent
	if err := db.Where("user_id = ? AND risk_score = ? AND decision = ?", user.ID, 75, model.RiskDecisionMFA).
		First(&riskEvent).Error; err != nil {
		t.Fatalf("find risk event: %v", err)
	}
	if riskEvent.IPAddress != "203.0.113.44" {
		t.Fatalf("risk event ip address=%q want 203.0.113.44", riskEvent.IPAddress)
	}
	if riskEvent.UserAgent != "Mozilla/5.0 Firefox/121.0 Linux" {
		t.Fatalf("risk event user agent=%q want Mozilla/5.0 Firefox/121.0 Linux", riskEvent.UserAgent)
	}
	if riskEvent.Reason != model.RiskEventReasonAdditionalVerificationRequired {
		t.Fatalf("risk event reason=%q want %q", riskEvent.Reason, model.RiskEventReasonAdditionalVerificationRequired)
	}
}

func TestAuthService_Login_recordsRiskEventWhenFailedAttemptsLockAccount(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "lock-risk@example.com",
		Username:     "lockriskuser",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetRiskEventRepository(riskEventRepo)

	for i := 0; i < MaxFailedLogins; i++ {
		_, err := authService.AuthenticateLogin(&LoginInput{
			Email:     user.Email,
			Password:  "WrongPass123!",
			IPAddress: "203.0.113.80",
			UserAgent: "lock-risk-test",
		})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d err=%v want ErrInvalidCredentials", i+1, err)
		}
	}

	storedUser, err := userRepo.FindByEmail(user.Email)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if storedUser.LockedUntil == nil {
		t.Fatalf("locked_until is nil")
	}
	if storedUser.FailedLogins != MaxFailedLogins {
		t.Fatalf("failed_logins=%d want %d", storedUser.FailedLogins, MaxFailedLogins)
	}

	var riskEvent model.RiskEvent
	if err := db.Where("user_id = ? AND decision = ? AND reason = ?", user.ID, model.RiskDecisionBlock, model.RiskEventReasonAccountLockedAfterFailedLogins).
		First(&riskEvent).Error; err != nil {
		t.Fatalf("find account lock risk event: %v", err)
	}
	if riskEvent.RiskScore != 80 {
		t.Fatalf("risk_score=%d want 80", riskEvent.RiskScore)
	}
	if riskEvent.IPAddress != "203.0.113.80" {
		t.Fatalf("ip_address=%q want 203.0.113.80", riskEvent.IPAddress)
	}
	if riskEvent.UserAgent != "lock-risk-test" {
		t.Fatalf("user_agent=%q want lock-risk-test", riskEvent.UserAgent)
	}
}

func TestAuthService_RefreshTokens_recordsRiskEventOnReplayAfterGracePeriod(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "refresh-replay@example.com",
		Username:     "refreshreplay",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetOAuthRepo(oauthRepo)
	authService.SetRiskEventRepository(riskEventRepo)

	initialTokens, err := authService.generateTokens(user, time.Now().Unix())
	if err != nil {
		t.Fatalf("generate initial tokens: %v", err)
	}
	replayAccessToken := &model.AccessToken{
		Token:     "refresh-replay-access-token",
		ClientID:  "refresh-replay-client",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := oauthRepo.CreateAccessToken(replayAccessToken); err != nil {
		t.Fatalf("create replay access token: %v", err)
	}
	refreshedTokens, err := authService.RefreshTokens(initialTokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh tokens: %v", err)
	}
	if refreshedTokens == nil || refreshedTokens.RefreshToken == "" {
		t.Fatalf("refresh tokens returned empty refresh token")
	}

	initialClaims, err := authService.jwtManager.ValidateRefreshToken(initialTokens.RefreshToken)
	if err != nil {
		t.Fatalf("validate initial refresh token: %v", err)
	}
	oldRevokedAt := time.Now().Add(-time.Minute)
	if err := db.Model(&model.RefreshToken{}).
		Where("token = ?", initialClaims.ID).
		Update("revoked_at", oldRevokedAt).Error; err != nil {
		t.Fatalf("age revoked refresh token: %v", err)
	}

	if _, err := authService.RefreshTokensWithRequestContext(initialTokens.RefreshToken, "203.0.113.70", "refresh-replay-test"); err == nil {
		t.Fatalf("replayed refresh token should fail")
	}

	var riskEvent model.RiskEvent
	if err := db.Where("user_id = ? AND risk_score = ? AND decision = ?", user.ID, 80, model.RiskDecisionBlock).
		First(&riskEvent).Error; err != nil {
		t.Fatalf("find risk event: %v", err)
	}
	if riskEvent.IPAddress != "203.0.113.70" {
		t.Fatalf("risk event ip_address=%q want %q", riskEvent.IPAddress, "203.0.113.70")
	}
	if riskEvent.UserAgent != "refresh-replay-test" {
		t.Fatalf("risk event user_agent=%q want %q", riskEvent.UserAgent, "refresh-replay-test")
	}
	if riskEvent.Reason != model.RiskEventReasonRefreshTokenReplay {
		t.Fatalf("risk event reason=%q want %q", riskEvent.Reason, model.RiskEventReasonRefreshTokenReplay)
	}

	var activeRefreshCount int64
	db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked = ?", user.ID, false).
		Count(&activeRefreshCount)
	if activeRefreshCount != 0 {
		t.Fatalf("active refresh token count=%d want 0", activeRefreshCount)
	}

	var activeAccessCount int64
	db.Model(&model.AccessToken{}).
		Where("user_id = ? AND revoked = ?", user.ID, false).
		Count(&activeAccessCount)
	if activeAccessCount != 0 {
		t.Fatalf("active access token count=%d want 0", activeAccessCount)
	}
}

func TestAuthService_RefreshTokens_doesNotRecordRiskEventDuringGracePeriod(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "refresh-grace@example.com",
		Username:     "refreshgrace",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetOAuthRepo(oauthRepo)
	authService.SetRiskEventRepository(riskEventRepo)

	initialTokens, err := authService.generateTokens(user, time.Now().Unix())
	if err != nil {
		t.Fatalf("generate initial tokens: %v", err)
	}
	if _, err := authService.RefreshTokens(initialTokens.RefreshToken); err != nil {
		t.Fatalf("refresh tokens: %v", err)
	}

	if _, err := authService.RefreshTokens(initialTokens.RefreshToken); err == nil {
		t.Fatalf("grace-period replay should fail")
	}

	var eventCount int64
	db.Model(&model.RiskEvent{}).Where("user_id = ?", user.ID).Count(&eventCount)
	if eventCount != 0 {
		t.Fatalf("risk event count=%d want 0", eventCount)
	}
}

func TestAuthService_RefreshTokens_RevokesStoredAccessTokensForDisabledUser(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "disabled-refresh@example.com",
		Username:     "disabledrefresh",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetOAuthRepo(oauthRepo)

	tokens, err := authService.generateTokens(user, time.Now().Unix())
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}
	storedAccessToken := &model.AccessToken{
		Token:     "disabled-refresh-access-token",
		ClientID:  "disabled-refresh-client",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := oauthRepo.CreateAccessToken(storedAccessToken); err != nil {
		t.Fatalf("create stored access token: %v", err)
	}

	user.Status = "disabled"
	if err := userRepo.Update(user); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	if _, err := authService.RefreshTokens(tokens.RefreshToken); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("refresh disabled user error=%v want %v", err, ErrUserDisabled)
	}

	var activeAccessCount int64
	db.Model(&model.AccessToken{}).
		Where("user_id = ? AND revoked = ?", user.ID, false).
		Count(&activeAccessCount)
	if activeAccessCount != 0 {
		t.Fatalf("active access token count=%d want 0", activeAccessCount)
	}
}

func TestAuthService_ChangePassword_RevokesStoredAccessTokens(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	hash, err := password.Hash("OldPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "change-password@example.com",
		Username:     "changepassword",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	storedAccessToken := &model.AccessToken{
		Token:     "change-password-access-token",
		ClientID:  "change-password-client",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := oauthRepo.CreateAccessToken(storedAccessToken); err != nil {
		t.Fatalf("create stored access token: %v", err)
	}

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret-with-enough-length",
			Issuer:          "test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetOAuthRepo(oauthRepo)

	tokens, err := authService.generateTokens(user, time.Now().Unix())
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}
	refreshClaims, err := authService.jwtManager.ValidateRefreshToken(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("validate refresh token: %v", err)
	}

	if err := authService.ChangePassword(user.ID, "OldPass123!", "NewPass123!"); err != nil {
		t.Fatalf("change password: %v", err)
	}

	var activeAccessCount int64
	db.Model(&model.AccessToken{}).
		Where("user_id = ? AND revoked = ?", user.ID, false).
		Count(&activeAccessCount)
	if activeAccessCount != 0 {
		t.Fatalf("active access token count=%d want 0", activeAccessCount)
	}

	storedRefreshToken, err := oauthRepo.FindAuthRefreshToken(refreshClaims.ID)
	if err != nil {
		t.Fatalf("find auth refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("auth refresh token should be revoked after password change")
	}
	if _, err := authService.RefreshTokens(tokens.RefreshToken); err == nil {
		t.Fatalf("old refresh token should not refresh after password change")
	}
}

func TestAuthService_DeleteAccountDeletesSDKExternalIdentities(t *testing.T) {
	db := setupAuthServiceTestDB(t)
	if err := db.AutoMigrate(&model.SDKExternalIdentity{}); err != nil {
		t.Fatalf("migrate sdk external identity: %v", err)
	}
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	sdkExternalRepo := repository.NewSDKExternalIdentityRepository(db)

	hash, err := password.Hash("DeletePass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "delete-sdk-external@example.com",
		Username:     "deletesdkexternal",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := sdkExternalRepo.Create(&model.SDKExternalIdentity{
		UserID:         user.ID,
		ExternalSource: "platform-delete-alpha",
		ExternalID:     "external-delete-alpha-001",
	}); err != nil {
		t.Fatalf("create alpha identity: %v", err)
	}
	if err := sdkExternalRepo.Create(&model.SDKExternalIdentity{
		UserID:         user.ID,
		ExternalSource: "platform-delete-beta",
		ExternalID:     "external-delete-beta-001",
	}); err != nil {
		t.Fatalf("create beta identity: %v", err)
	}

	cfg := testAuthServiceConfig()
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetCleanupRepos(nil, nil, nil, sdkExternalRepo, nil, nil, nil)

	if err := authService.DeleteAccount(user.ID, "DeletePass123!"); err != nil {
		t.Fatalf("delete account: %v", err)
	}

	var identityCount int64
	if err := db.Model(&model.SDKExternalIdentity{}).Where("user_id = ?", user.ID).Count(&identityCount).Error; err != nil {
		t.Fatalf("count sdk external identities: %v", err)
	}
	if identityCount != 0 {
		t.Fatalf("sdk external identity count=%d want 0", identityCount)
	}
	if _, err := userRepo.FindByID(user.ID); !errors.Is(err, repository.ErrUserNotFound) {
		t.Fatalf("deleted user error=%v want %v", err, repository.ErrUserNotFound)
	}
}
