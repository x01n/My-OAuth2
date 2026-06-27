package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"server/internal/config"
	"server/internal/middleware"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"
	"server/pkg/password"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTokenVerifyTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.AccessToken{}, &model.RefreshToken{}, &model.FederatedProvider{}, &model.FederatedIdentity{}, &model.TrustedApp{}, &model.LoginLog{}, &model.RiskEvent{}, &model.SDKExternalIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testAuthConfig() *config.Config {
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

func postJSON(t *testing.T, router *gin.Engine, path string, payload map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeSuccessData(t *testing.T, rec *httptest.ResponseRecorder, target interface{}) {
	t.Helper()

	var envelope struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !envelope.Success {
		t.Fatalf("response success=false body=%s", rec.Body.String())
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		t.Fatalf("decode data: %v body=%s", err, rec.Body.String())
	}
}

func decodeErrorInfo(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()

	var envelope struct {
		Success bool `json:"success"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, rec.Body.String())
	}
	if envelope.Success {
		t.Fatalf("response success=true body=%s", rec.Body.String())
	}
	return envelope.Error.Code, envelope.Error.Message
}

func TestSDKHandler_RefreshTokenStoresRotatedRefreshToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")
	authService := service.NewAuthService(userRepo, loginLogRepo, jwtManager, testAuthConfig())
	authService.SetOAuthRepo(oauthRepo)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		Email:        "sdk-refresh@example.com",
		Username:     "sdkrefresh",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-refresh-client",
		ClientSecret: "sdk-refresh-secret",
		Name:         "SDK Refresh Client",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	sdkHandler := NewSDKHandler(authService, appRepo, jwtManager)
	sdkHandler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/sdk/login", sdkHandler.Login)
	router.POST("/api/sdk/refresh", sdkHandler.RefreshToken)
	router.POST("/api/sdk/verify", sdkHandler.VerifyToken)

	loginRec := postJSON(t, router, "/api/sdk/login", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"email":         user.Email,
		"password":      "StrongPass123!",
	})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var loginTokens SDKTokenResponse
	decodeSuccessData(t, loginRec, &loginTokens)
	if loginTokens.AccessToken == "" {
		t.Fatalf("login access token should not be empty")
	}
	if loginTokens.IDToken == "" {
		t.Fatalf("login id token should not be empty")
	}
	if jwt.IsEncryptedToken(loginTokens.IDToken) {
		t.Fatalf("login id_token should be client-verifiable JWS, got encrypted token")
	}
	loginIDClaims, err := jwtManager.ValidateClientIDToken(loginTokens.IDToken, app.ClientID, app.ClientSecret)
	if err != nil {
		t.Fatalf("validate login id token: %v", err)
	}
	if loginIDClaims.TokenType != jwt.TokenTypeIDToken {
		t.Fatalf("login id_token token_type=%q want %q", loginIDClaims.TokenType, jwt.TokenTypeIDToken)
	}
	if loginIDClaims.ClientID != app.ClientID {
		t.Fatalf("login id_token client_id=%q want %q", loginIDClaims.ClientID, app.ClientID)
	}
	if loginIDClaims.AuthTime <= 0 {
		t.Fatalf("login id_token auth_time=%d want positive", loginIDClaims.AuthTime)
	}
	if len(loginIDClaims.AMR) != 1 || loginIDClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("login id_token amr=%#v want [%q]", loginIDClaims.AMR, jwt.AuthenticationMethodPassword)
	}
	if loginIDClaims.ATHash != jwt.AccessTokenHash(loginTokens.AccessToken) {
		t.Fatalf("login id_token at_hash=%q want %q", loginIDClaims.ATHash, jwt.AccessTokenHash(loginTokens.AccessToken))
	}
	if storedLoginAccessToken, err := oauthRepo.FindAccessToken(loginTokens.AccessToken); err != nil {
		t.Fatalf("login access token should be stored: %v", err)
	} else if storedLoginAccessToken.ClientID != app.ClientID || storedLoginAccessToken.UserID == nil || *storedLoginAccessToken.UserID != user.ID {
		t.Fatalf("stored login access token mismatch: %#v", storedLoginAccessToken)
	}
	loginVerifyRec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  loginTokens.AccessToken,
	})
	if loginVerifyRec.Code != http.StatusOK {
		t.Fatalf("login access token verify status=%d body=%s", loginVerifyRec.Code, loginVerifyRec.Body.String())
	}
	if err := oauthRepo.RevokeAccessToken(loginTokens.AccessToken); err != nil {
		t.Fatalf("revoke login access token: %v", err)
	}
	revokedLoginVerifyRec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  loginTokens.AccessToken,
	})
	if revokedLoginVerifyRec.Code == http.StatusOK {
		t.Fatalf("revoked login access token should not verify: status=%d body=%s", revokedLoginVerifyRec.Code, revokedLoginVerifyRec.Body.String())
	}

	firstRefreshRec := postJSON(t, router, "/api/sdk/refresh", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"refresh_token": loginTokens.RefreshToken,
	})
	if firstRefreshRec.Code != http.StatusOK {
		t.Fatalf("first refresh status=%d body=%s", firstRefreshRec.Code, firstRefreshRec.Body.String())
	}
	var firstRefresh struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	decodeSuccessData(t, firstRefreshRec, &firstRefresh)
	if firstRefresh.AccessToken == "" {
		t.Fatalf("first refresh access token should not be empty")
	}
	if firstRefresh.RefreshToken == "" {
		t.Fatalf("first refresh token should not be empty")
	}
	if firstRefresh.IDToken == "" {
		t.Fatalf("first refresh id token should not be empty")
	}
	if jwt.IsEncryptedToken(firstRefresh.IDToken) {
		t.Fatalf("first refresh id_token should be client-verifiable JWS, got encrypted token")
	}
	firstRefreshIDClaims, err := jwtManager.ValidateClientIDToken(firstRefresh.IDToken, app.ClientID, app.ClientSecret)
	if err != nil {
		t.Fatalf("validate first refresh id token: %v", err)
	}
	if firstRefreshIDClaims.TokenType != jwt.TokenTypeIDToken {
		t.Fatalf("first refresh id_token token_type=%q want %q", firstRefreshIDClaims.TokenType, jwt.TokenTypeIDToken)
	}
	if firstRefreshIDClaims.ClientID != app.ClientID {
		t.Fatalf("first refresh id_token client_id=%q want %q", firstRefreshIDClaims.ClientID, app.ClientID)
	}
	if firstRefreshIDClaims.AuthTime != loginIDClaims.AuthTime {
		t.Fatalf("first refresh id_token auth_time=%d want %d", firstRefreshIDClaims.AuthTime, loginIDClaims.AuthTime)
	}
	if len(firstRefreshIDClaims.AMR) != 1 || firstRefreshIDClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("first refresh id_token amr=%#v want [%q]", firstRefreshIDClaims.AMR, jwt.AuthenticationMethodPassword)
	}
	if firstRefreshIDClaims.ATHash != jwt.AccessTokenHash(firstRefresh.AccessToken) {
		t.Fatalf("first refresh id_token at_hash=%q want %q", firstRefreshIDClaims.ATHash, jwt.AccessTokenHash(firstRefresh.AccessToken))
	}
	if storedRefreshAccessToken, err := oauthRepo.FindAccessToken(firstRefresh.AccessToken); err != nil {
		t.Fatalf("refreshed access token should be stored: %v", err)
	} else if storedRefreshAccessToken.ClientID != app.ClientID || storedRefreshAccessToken.UserID == nil || *storedRefreshAccessToken.UserID != user.ID {
		t.Fatalf("stored refreshed access token mismatch: %#v", storedRefreshAccessToken)
	}
	refreshVerifyRec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  firstRefresh.AccessToken,
	})
	if refreshVerifyRec.Code != http.StatusOK {
		t.Fatalf("refreshed access token verify status=%d body=%s", refreshVerifyRec.Code, refreshVerifyRec.Body.String())
	}
	if err := oauthRepo.RevokeAccessToken(firstRefresh.AccessToken); err != nil {
		t.Fatalf("revoke refreshed access token: %v", err)
	}
	revokedRefreshVerifyRec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  firstRefresh.AccessToken,
	})
	if revokedRefreshVerifyRec.Code == http.StatusOK {
		t.Fatalf("revoked refreshed access token should not verify: status=%d body=%s", revokedRefreshVerifyRec.Code, revokedRefreshVerifyRec.Body.String())
	}

	secondRefreshRec := postJSON(t, router, "/api/sdk/refresh", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"refresh_token": firstRefresh.RefreshToken,
	})
	if secondRefreshRec.Code != http.StatusOK {
		t.Fatalf("second refresh status=%d body=%s", secondRefreshRec.Code, secondRefreshRec.Body.String())
	}
	var activeRefreshCount int64
	db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked = ? AND expires_at > ?", user.ID, false, time.Now()).
		Count(&activeRefreshCount)
	if activeRefreshCount != 1 {
		t.Fatalf("active refresh token count=%d want 1", activeRefreshCount)
	}

	replayRec := postJSON(t, router, "/api/sdk/refresh", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"refresh_token": loginTokens.RefreshToken,
	})
	if replayRec.Code == http.StatusOK {
		t.Fatalf("replayed original refresh token should fail: status=%d body=%s", replayRec.Code, replayRec.Body.String())
	}
}

func TestSDKHandler_LoginRecordsSDKContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")
	authService := service.NewAuthService(userRepo, loginLogRepo, jwtManager, testAuthConfig())
	authService.SetOAuthRepo(oauthRepo)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		Email:        "sdk-context@example.com",
		Username:     "sdkcontext",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-context-client",
		ClientSecret: "sdk-context-secret",
		Name:         "SDK Context Client",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	sdkHandler := NewSDKHandler(authService, appRepo, jwtManager)
	sdkHandler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/sdk/login", sdkHandler.Login)

	payload := map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"email":         user.Email,
		"password":      "StrongPass123!",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SDK-Test/1.0")
	req.RemoteAddr = "203.0.113.77:54321"
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
	}

	logs, err := loginLogRepo.FindRecentByUserID(user.ID, 1)
	if err != nil {
		t.Fatalf("find login logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("login log count=%d want 1", len(logs))
	}
	log := logs[0]
	if log.LoginType != model.LoginTypeSDK {
		t.Fatalf("login type=%q want %q", log.LoginType, model.LoginTypeSDK)
	}
	if log.AppID == nil || *log.AppID != app.ID {
		t.Fatalf("app id=%v want %s", log.AppID, app.ID)
	}
	if log.IPAddress != "203.0.113.77" {
		t.Fatalf("ip address=%q want 203.0.113.77", log.IPAddress)
	}
	if log.UserAgent != "SDK-Test/1.0" {
		t.Fatalf("user agent=%q want SDK-Test/1.0", log.UserAgent)
	}
	if !log.Success {
		t.Fatalf("login log success=false want true")
	}

	storedUser, err := userRepo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if storedUser.LastLoginIP != "203.0.113.77" {
		t.Fatalf("last login ip=%q want 203.0.113.77", storedUser.LastLoginIP)
	}
	if storedUser.LastLoginAt == nil {
		t.Fatalf("last login at is nil")
	}
}

func TestSDKHandler_LoginBlocksSuspiciousLoginWithoutIssuingTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")
	authService := service.NewAuthService(userRepo, loginLogRepo, jwtManager, testAuthConfig())
	authService.SetOAuthRepo(oauthRepo)
	authService.SetAnomalyDetectionService(service.NewAnomalyDetectionService(loginLogRepo, userRepo))
	authService.SetRiskEventRepository(riskEventRepo)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		Email:        "sdk-risk@example.com",
		Username:     "sdkrisk",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-risk-client",
		ClientSecret: "sdk-risk-secret",
		Name:         "SDK Risk Client",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	now := time.Now().Add(-30 * time.Minute)
	historicalLogs := []model.LoginLog{
		{UserID: &user.ID, AppID: &app.ID, LoginType: model.LoginTypeSDK, IPAddress: "10.0.0.8", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: true, Email: user.Email, CreatedAt: now},
		{UserID: &user.ID, AppID: &app.ID, LoginType: model.LoginTypeSDK, IPAddress: "10.0.0.9", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: now.Add(5 * time.Minute)},
		{UserID: &user.ID, AppID: &app.ID, LoginType: model.LoginTypeSDK, IPAddress: "10.0.0.10", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: now.Add(10 * time.Minute)},
		{UserID: &user.ID, AppID: &app.ID, LoginType: model.LoginTypeSDK, IPAddress: "10.0.0.11", UserAgent: "Mozilla/5.0 Chrome/120.0 Windows NT 10.0", Success: false, Email: user.Email, CreatedAt: now.Add(15 * time.Minute)},
	}
	if err := db.Create(&historicalLogs).Error; err != nil {
		t.Fatalf("create login logs: %v", err)
	}

	sdkHandler := NewSDKHandler(authService, appRepo, jwtManager)
	sdkHandler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/sdk/login", sdkHandler.Login)

	payload := map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"email":         user.Email,
		"password":      "StrongPass123!",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "curl/8.0")
	req.RemoteAddr = "203.0.113.88:54321"
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	var resp struct {
		Success bool       `json:"success"`
		Error   *ErrorInfo `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if resp.Success {
		t.Fatalf("success=true body=%s", rec.Body.String())
	}
	if resp.Error == nil {
		t.Fatalf("error is nil body=%s", rec.Body.String())
	}
	if resp.Error.Code != ErrCodeSuspiciousLogin {
		t.Fatalf("error code=%q want %s", resp.Error.Code, ErrCodeSuspiciousLogin)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("access_token")) || bytes.Contains(rec.Body.Bytes(), []byte("refresh_token")) {
		t.Fatalf("response body contains token field body=%s", rec.Body.String())
	}

	var accessTokenCount int64
	db.Model(&model.AccessToken{}).Count(&accessTokenCount)
	if accessTokenCount != 0 {
		t.Fatalf("access token count=%d want 0", accessTokenCount)
	}
	var refreshTokenCount int64
	db.Model(&model.RefreshToken{}).Count(&refreshTokenCount)
	if refreshTokenCount != 0 {
		t.Fatalf("refresh token count=%d want 0", refreshTokenCount)
	}
	var riskEventCount int64
	db.Model(&model.RiskEvent{}).
		Where("user_id = ? AND risk_score = ? AND decision = ?", user.ID, 100, model.RiskDecisionBlock).
		Count(&riskEventCount)
	if riskEventCount != 1 {
		t.Fatalf("risk event count=%d want 1", riskEventCount)
	}
}

func TestSDKHandler_LoginReturnsAccountLocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")
	authService := service.NewAuthService(userRepo, loginLogRepo, jwtManager, testAuthConfig())
	authService.SetOAuthRepo(oauthRepo)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	lockedUntil := time.Now().Add(time.Hour)
	user := &model.User{
		Email:        "sdk-locked@example.com",
		Username:     "sdklocked",
		PasswordHash: hash,
		Status:       "active",
		LockedUntil:  &lockedUntil,
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-locked-client",
		ClientSecret: "sdk-locked-secret",
		Name:         "SDK Locked Client",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	sdkHandler := NewSDKHandler(authService, appRepo, jwtManager)
	sdkHandler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/sdk/login", sdkHandler.Login)

	payload := map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"email":         user.Email,
		"password":      "StrongPass123!",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SDK-Test/1.0")
	req.RemoteAddr = "203.0.113.89:54321"
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	var resp struct {
		Success bool       `json:"success"`
		Error   *ErrorInfo `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if resp.Success {
		t.Fatalf("success=true body=%s", rec.Body.String())
	}
	if resp.Error == nil {
		t.Fatalf("error is nil body=%s", rec.Body.String())
	}
	if resp.Error.Code != "ACCOUNT_LOCKED" {
		t.Fatalf("error code=%q want ACCOUNT_LOCKED", resp.Error.Code)
	}

	logs, err := loginLogRepo.FindRecentByUserID(user.ID, 1)
	if err != nil {
		t.Fatalf("find login logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("login log count=%d want 1", len(logs))
	}
	if logs[0].LoginType != model.LoginTypeSDK {
		t.Fatalf("login type=%q want %q", logs[0].LoginType, model.LoginTypeSDK)
	}
	if logs[0].AppID == nil || *logs[0].AppID != app.ID {
		t.Fatalf("app id=%v want %s", logs[0].AppID, app.ID)
	}
	if logs[0].IPAddress != "203.0.113.89" {
		t.Fatalf("ip address=%q want 203.0.113.89", logs[0].IPAddress)
	}
}

func TestSDKHandler_RegisterStoresIssuedTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")
	authService := service.NewAuthService(userRepo, loginLogRepo, jwtManager, testAuthConfig())
	authService.SetOAuthRepo(oauthRepo)

	owner := &model.User{
		Email:        "sdk-register-owner@example.com",
		Username:     "sdkregisterowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-register-client",
		ClientSecret: "sdk-register-secret",
		Name:         "SDK Register Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	sdkHandler := NewSDKHandler(authService, appRepo, jwtManager)
	sdkHandler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/sdk/register", sdkHandler.Register)
	router.POST("/api/sdk/refresh", sdkHandler.RefreshToken)
	router.POST("/api/sdk/verify", sdkHandler.VerifyToken)

	registerPayload := map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"email":         "sdk-register-user@example.com",
		"username":      "sdkregisteruser",
		"password":      "StrongPass123!",
	}
	registerBody, err := json.Marshal(registerPayload)
	if err != nil {
		t.Fatalf("marshal register payload: %v", err)
	}
	registerReq := httptest.NewRequest(http.MethodPost, "/api/sdk/register", bytes.NewReader(registerBody))
	registerReq.Header.Set("Content-Type", "application/json")
	registerReq.Header.Set("User-Agent", "SDK-Register/1.0")
	registerReq.RemoteAddr = "203.0.113.90:54321"
	registerRec := httptest.NewRecorder()
	router.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", registerRec.Code, registerRec.Body.String())
	}
	var registerTokens SDKTokenResponse
	decodeSuccessData(t, registerRec, &registerTokens)
	if registerTokens.AccessToken == "" {
		t.Fatalf("register access token should not be empty")
	}
	if registerTokens.RefreshToken == "" {
		t.Fatalf("register refresh token should not be empty")
	}
	if registerTokens.IDToken == "" {
		t.Fatalf("register id token should not be empty")
	}

	registeredUser, err := userRepo.FindByEmail("sdk-register-user@example.com")
	if err != nil {
		t.Fatalf("find registered user: %v", err)
	}
	if jwt.IsEncryptedToken(registerTokens.IDToken) {
		t.Fatalf("register id_token should be client-verifiable JWS, got encrypted token")
	}
	registerIDClaims, err := jwtManager.ValidateClientIDToken(registerTokens.IDToken, app.ClientID, app.ClientSecret)
	if err != nil {
		t.Fatalf("validate register id token: %v", err)
	}
	if registerIDClaims.TokenType != jwt.TokenTypeIDToken {
		t.Fatalf("register id_token token_type=%q want %q", registerIDClaims.TokenType, jwt.TokenTypeIDToken)
	}
	if registerIDClaims.ClientID != app.ClientID {
		t.Fatalf("register id_token client_id=%q want %q", registerIDClaims.ClientID, app.ClientID)
	}
	if registerIDClaims.UserID != registeredUser.ID {
		t.Fatalf("register id_token user_id=%s want %s", registerIDClaims.UserID, registeredUser.ID)
	}
	if registerIDClaims.AuthTime <= 0 {
		t.Fatalf("register id_token auth_time=%d want positive", registerIDClaims.AuthTime)
	}
	if len(registerIDClaims.AMR) != 1 || registerIDClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("register id_token amr=%#v want [%q]", registerIDClaims.AMR, jwt.AuthenticationMethodPassword)
	}
	if registerIDClaims.ATHash != jwt.AccessTokenHash(registerTokens.AccessToken) {
		t.Fatalf("register id_token at_hash=%q want %q", registerIDClaims.ATHash, jwt.AccessTokenHash(registerTokens.AccessToken))
	}
	if registeredUser.LastLoginIP != "203.0.113.90" {
		t.Fatalf("registered user last login ip=%q want 203.0.113.90", registeredUser.LastLoginIP)
	}
	if registeredUser.LastLoginAt == nil {
		t.Fatalf("registered user last login at is nil")
	}

	logs, err := loginLogRepo.FindRecentByUserID(registeredUser.ID, 1)
	if err != nil {
		t.Fatalf("find login logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("login log count=%d want 1", len(logs))
	}
	log := logs[0]
	if log.LoginType != model.LoginTypeSDK {
		t.Fatalf("login type=%q want %q", log.LoginType, model.LoginTypeSDK)
	}
	if log.AppID == nil || *log.AppID != app.ID {
		t.Fatalf("app id=%v want %s", log.AppID, app.ID)
	}
	if log.IPAddress != "203.0.113.90" {
		t.Fatalf("ip address=%q want 203.0.113.90", log.IPAddress)
	}
	if log.UserAgent != "SDK-Register/1.0" {
		t.Fatalf("user agent=%q want SDK-Register/1.0", log.UserAgent)
	}
	if !log.Success {
		t.Fatalf("login log success=false want true")
	}

	if storedAccessToken, err := oauthRepo.FindAccessToken(registerTokens.AccessToken); err != nil {
		t.Fatalf("register access token should be stored: %v", err)
	} else if storedAccessToken.ClientID != app.ClientID || storedAccessToken.UserID == nil || *storedAccessToken.UserID != registeredUser.ID {
		t.Fatalf("stored register access token mismatch: %#v", storedAccessToken)
	}

	verifyRec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  registerTokens.AccessToken,
	})
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("register access token verify status=%d body=%s", verifyRec.Code, verifyRec.Body.String())
	}

	refreshRec := postJSON(t, router, "/api/sdk/refresh", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"refresh_token": registerTokens.RefreshToken,
	})
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("register refresh token status=%d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshTokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	decodeSuccessData(t, refreshRec, &refreshTokens)
	if refreshTokens.IDToken == "" {
		t.Fatalf("register refresh id token should not be empty")
	}
	refreshIDClaims, err := jwtManager.ValidateClientIDToken(refreshTokens.IDToken, app.ClientID, app.ClientSecret)
	if err != nil {
		t.Fatalf("validate register refresh id token: %v", err)
	}
	if refreshIDClaims.AuthTime != registerIDClaims.AuthTime {
		t.Fatalf("register refresh id_token auth_time=%d want %d", refreshIDClaims.AuthTime, registerIDClaims.AuthTime)
	}
	if len(refreshIDClaims.AMR) != 1 || refreshIDClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("register refresh id_token amr=%#v want [%q]", refreshIDClaims.AMR, jwt.AuthenticationMethodPassword)
	}
	if refreshIDClaims.ATHash != jwt.AccessTokenHash(refreshTokens.AccessToken) {
		t.Fatalf("register refresh id_token at_hash=%q want %q", refreshIDClaims.ATHash, jwt.AccessTokenHash(refreshTokens.AccessToken))
	}
}

func TestSDKHandler_SignTokenStoresServiceToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")
	authService := service.NewAuthService(userRepo, nil, jwtManager, testAuthConfig())
	authService.SetOAuthRepo(oauthRepo)

	owner := &model.User{
		Email:        "sdk-sign-owner@example.com",
		Username:     "sdksignowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-sign-client",
		ClientSecret: "sdk-sign-secret",
		Name:         "SDK Sign Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeMachine,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	sdkHandler := NewSDKHandler(authService, appRepo, jwtManager)
	sdkHandler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/token/sign", sdkHandler.SignToken)
	router.POST("/api/sdk/verify", sdkHandler.VerifyToken)

	signRec := postJSON(t, router, "/token/sign", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
	})
	if signRec.Code != http.StatusOK {
		t.Fatalf("sign token status=%d body=%s", signRec.Code, signRec.Body.String())
	}
	var signResponse struct {
		Token     string `json:"token"`
		TokenType string `json:"token_type"`
		ExpiresIn int64  `json:"expires_in"`
		ClientID  string `json:"client_id"`
		Scope     string `json:"scope"`
	}
	decodeSuccessData(t, signRec, &signResponse)
	if signResponse.Token == "" {
		t.Fatalf("service token should not be empty")
	}

	if storedAccessToken, err := oauthRepo.FindAccessToken(signResponse.Token); err != nil {
		t.Fatalf("service token should be stored: %v", err)
	} else if storedAccessToken.ClientID != app.ClientID || storedAccessToken.UserID == nil || *storedAccessToken.UserID != owner.ID {
		t.Fatalf("stored service token mismatch: %#v", storedAccessToken)
	}

	verifyRec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  signResponse.Token,
	})
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("service token verify status=%d body=%s", verifyRec.Code, verifyRec.Body.String())
	}

	if err := oauthRepo.RevokeAccessToken(signResponse.Token); err != nil {
		t.Fatalf("revoke service token: %v", err)
	}
	revokedVerifyRec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  signResponse.Token,
	})
	if revokedVerifyRec.Code == http.StatusOK {
		t.Fatalf("revoked service token should not verify: status=%d body=%s", revokedVerifyRec.Code, revokedVerifyRec.Body.String())
	}
}

func TestSDKHandler_VerifyTokenRejectsRefreshToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, nil, nil, nil)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "sdk-verify@example.com",
		Username:     "sdkverify",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-client",
		ClientSecret: "sdk-secret",
		Name:         "SDK Client",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	refreshToken, err := jwtManager.GenerateClientToken(user.ID, user.Email, user.Username, string(user.Role), app.ClientID, jwt.TokenTypeRefresh, time.Hour)
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/verify", NewSDKHandler(authService, appRepo, jwtManager).VerifyToken)

	rec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  refreshToken,
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("refresh token should not verify as access token: status=%d body=%s", rec.Code, rec.Body.String())
	}
	code, message := decodeErrorInfo(t, rec)
	if code != ErrCodeTokenInvalid {
		t.Fatalf("error code=%q want %s body=%s", code, ErrCodeTokenInvalid, rec.Body.String())
	}
	if message != "Invalid or expired access token" {
		t.Fatalf("error message=%q want Invalid or expired access token", message)
	}
}

func TestSDKHandler_VerifyTokenReturnsInvalidClientCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, nil, nil, nil)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "sdk-invalid-client@example.com",
		Username:     "sdkinvalidclient",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-invalid-client",
		ClientSecret: "sdk-valid-secret",
		Name:         "SDK Invalid Client",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/verify", NewSDKHandler(authService, appRepo, jwtManager).VerifyToken)

	rec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": "wrong-secret",
		"access_token":  "access-token",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	code, message := decodeErrorInfo(t, rec)
	if code != ErrCodeInvalidClient {
		t.Fatalf("error code=%q want %s body=%s", code, ErrCodeInvalidClient, rec.Body.String())
	}
	if message != "Invalid client credentials" {
		t.Fatalf("error message=%q want Invalid client credentials", message)
	}
}

func TestSDKHandler_VerifyTokenReturnsExpiredTokenCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, nil, nil, nil)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "sdk-expired@example.com",
		Username:     "sdkexpired",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-expired-client",
		ClientSecret: "sdk-expired-secret",
		Name:         "SDK Expired Client",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	accessToken, err := jwtManager.GenerateClientToken(user.ID, user.Email, user.Username, string(user.Role), app.ClientID, jwt.TokenTypeAccess, -time.Second)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/verify", NewSDKHandler(authService, appRepo, jwtManager).VerifyToken)

	rec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  accessToken,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	code, message := decodeErrorInfo(t, rec)
	if code != ErrCodeTokenExpired {
		t.Fatalf("error code=%q want %s body=%s", code, ErrCodeTokenExpired, rec.Body.String())
	}
	if message != "Invalid or expired access token" {
		t.Fatalf("error message=%q want Invalid or expired access token", message)
	}
}

func TestSDKHandler_VerifyTokenRejectsDifferentClientAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, nil, nil, nil)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "sdk-client-scope@example.com",
		Username:     "sdkclientscope",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-client-a",
		ClientSecret: "sdk-secret-a",
		Name:         "SDK Client A",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	accessToken, err := jwtManager.GenerateClientToken(user.ID, user.Email, user.Username, string(user.Role), "sdk-client-b", jwt.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/verify", NewSDKHandler(authService, appRepo, jwtManager).VerifyToken)

	rec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  accessToken,
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("different client access token should not verify: status=%d body=%s", rec.Code, rec.Body.String())
	}
	code, message := decodeErrorInfo(t, rec)
	if code != ErrCodeTokenInvalid {
		t.Fatalf("error code=%q want %s body=%s", code, ErrCodeTokenInvalid, rec.Body.String())
	}
	if message != "Invalid or expired access token" {
		t.Fatalf("error message=%q want Invalid or expired access token", message)
	}
}

func TestSDKHandler_VerifyTokenRejectsSuspendedUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	authService := service.NewAuthService(userRepo, nil, nil, nil)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "sdk-disabled@example.com",
		Username:     "sdkdisabled",
		PasswordHash: "hashed-password",
		Status:       "suspended",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-disabled-client",
		ClientSecret: "sdk-disabled-secret",
		Name:         "SDK Disabled Client",
		UserID:       user.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	accessToken, err := jwtManager.GenerateClientToken(user.ID, user.Email, user.Username, string(user.Role), app.ClientID, jwt.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	if err := oauthRepo.CreateAccessToken(&model.AccessToken{
		Token:     accessToken,
		ClientID:  app.ClientID,
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("store access token: %v", err)
	}

	handler := NewSDKHandler(authService, appRepo, jwtManager)
	handler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/sdk/verify", handler.VerifyToken)

	rec := postJSON(t, router, "/api/sdk/verify", map[string]string{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"access_token":  accessToken,
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("suspended user access token should not verify: status=%d body=%s", rec.Code, rec.Body.String())
	}
	code, message := decodeErrorInfo(t, rec)
	if code != ErrCodeUserDisabled {
		t.Fatalf("error code=%q want %s body=%s", code, ErrCodeUserDisabled, rec.Body.String())
	}
	if message != "User account is disabled" {
		t.Fatalf("error message=%q want User account is disabled", message)
	}

	var activeAccessCount int64
	db.Model(&model.AccessToken{}).
		Where("user_id = ? AND revoked = ? AND expires_at > ?", user.ID, false, time.Now()).
		Count(&activeAccessCount)
	if activeAccessCount != 0 {
		t.Fatalf("active access token count=%d want 0", activeAccessCount)
	}
}

func TestFederationHandler_VerifyTokenRejectsRefreshToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	federationRepo := repository.NewFederationRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "federation-verify@example.com",
		Username:     "federationverify",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	trustedApp := &model.TrustedApp{
		Name:            "Verifier",
		APIKey:          "api-key",
		APISecret:       "api-secret",
		CanVerifyTokens: true,
		Enabled:         true,
	}
	if err := federationRepo.CreateTrustedApp(trustedApp); err != nil {
		t.Fatalf("create trusted app: %v", err)
	}

	refreshToken, err := jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeRefresh, time.Hour)
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}

	router := gin.New()
	router.POST("/api/federation/verify", NewFederationHandler(federationRepo, userRepo, jwtManager, "http://localhost:8080").VerifyToken)

	rec := postJSON(t, router, "/api/federation/verify", map[string]string{
		"token":      refreshToken,
		"api_key":    trustedApp.APIKey,
		"api_secret": trustedApp.APISecret,
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("refresh token should not verify as access token: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFederationHandler_VerifyTokenRejectsSuspendedUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	federationRepo := repository.NewFederationRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "federation-disabled@example.com",
		Username:     "federationdisabled",
		PasswordHash: "hashed-password",
		Status:       "disabled",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	trustedApp := &model.TrustedApp{
		Name:            "Disabled Verifier",
		APIKey:          "disabled-api-key",
		APISecret:       "disabled-api-secret",
		CanVerifyTokens: true,
		Enabled:         true,
	}
	if err := federationRepo.CreateTrustedApp(trustedApp); err != nil {
		t.Fatalf("create trusted app: %v", err)
	}

	accessToken, err := jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	if err := oauthRepo.CreateAccessToken(&model.AccessToken{
		Token:     accessToken,
		ClientID:  "federation-disabled-client",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("store access token: %v", err)
	}

	handler := NewFederationHandler(federationRepo, userRepo, jwtManager, "http://localhost:8080")
	handler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/federation/verify", handler.VerifyToken)

	rec := postJSON(t, router, "/api/federation/verify", map[string]string{
		"token":      accessToken,
		"api_key":    trustedApp.APIKey,
		"api_secret": trustedApp.APISecret,
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("disabled user access token should not verify: status=%d body=%s", rec.Code, rec.Body.String())
	}

	var activeAccessCount int64
	db.Model(&model.AccessToken{}).
		Where("user_id = ? AND revoked = ? AND expires_at > ?", user.ID, false, time.Now()).
		Count(&activeAccessCount)
	if activeAccessCount != 0 {
		t.Fatalf("active access token count=%d want 0", activeAccessCount)
	}
}

func TestFederationHandler_VerifyTokenRejectsStoredRevokedAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	federationRepo := repository.NewFederationRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "federation-revoked@example.com",
		Username:     "federationrevoked",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	trustedApp := &model.TrustedApp{
		Name:            "Revoked Verifier",
		APIKey:          "revoked-api-key",
		APISecret:       "revoked-api-secret",
		CanVerifyTokens: true,
		Enabled:         true,
	}
	if err := federationRepo.CreateTrustedApp(trustedApp); err != nil {
		t.Fatalf("create trusted app: %v", err)
	}

	accessToken, err := jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	if err := oauthRepo.CreateAccessToken(&model.AccessToken{
		Token:     accessToken,
		ClientID:  "federation-revoked-client",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("store access token: %v", err)
	}
	if err := oauthRepo.RevokeAccessToken(accessToken); err != nil {
		t.Fatalf("revoke access token: %v", err)
	}

	handler := NewFederationHandler(federationRepo, userRepo, jwtManager, "http://localhost:8080")
	handler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/federation/verify", handler.VerifyToken)

	rec := postJSON(t, router, "/api/federation/verify", map[string]string{
		"token":      accessToken,
		"api_key":    trustedApp.APIKey,
		"api_secret": trustedApp.APISecret,
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("stored revoked access token should not verify: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFederationHandler_VerifyTokenRejectsUnstoredAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	federationRepo := repository.NewFederationRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	user := &model.User{
		Email:        "federation-unstored@example.com",
		Username:     "federationunstored",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	trustedApp := &model.TrustedApp{
		Name:            "Unstored Verifier",
		APIKey:          "unstored-api-key",
		APISecret:       "unstored-api-secret",
		CanVerifyTokens: true,
		Enabled:         true,
	}
	if err := federationRepo.CreateTrustedApp(trustedApp); err != nil {
		t.Fatalf("create trusted app: %v", err)
	}

	accessToken, err := jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	handler := NewFederationHandler(federationRepo, userRepo, jwtManager, "http://localhost:8080")
	handler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/federation/verify", handler.VerifyToken)

	rec := postJSON(t, router, "/api/federation/verify", map[string]string{
		"token":      accessToken,
		"api_key":    trustedApp.APIKey,
		"api_secret": trustedApp.APISecret,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unstored access token status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestFederationHandler_CallbackStoresAccessTokenForRevocationAwareVerify(t *testing.T) {
	gin.SetMode(gin.TestMode)

	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"provider-access-token","refresh_token":"provider-refresh-token","token_type":"Bearer","expires_in":3600}`))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"sub":"federation-callback-user","email":"federation-callback@example.com","name":"Federation Callback","email_verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer providerServer.Close()

	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	federationRepo := repository.NewFederationRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	provider := &model.FederatedProvider{
		Name:               "Federation Callback Provider",
		Slug:               "federation-callback",
		AuthURL:            providerServer.URL + "/auth",
		TokenURL:           providerServer.URL + "/token",
		UserInfoURL:        providerServer.URL + "/userinfo",
		ClientID:           "federation-callback-client",
		ClientSecret:       "federation-callback-secret",
		Scopes:             "openid profile email",
		Enabled:            true,
		AutoCreateUser:     true,
		TrustEmailVerified: true,
	}
	if err := federationRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	trustedApp := &model.TrustedApp{
		Name:            "Callback Verifier",
		APIKey:          "callback-api-key",
		APISecret:       "callback-api-secret",
		CanVerifyTokens: true,
		Enabled:         true,
	}
	if err := federationRepo.CreateTrustedApp(trustedApp); err != nil {
		t.Fatalf("create trusted app: %v", err)
	}

	handler := NewFederationHandler(federationRepo, userRepo, jwtManager, "http://oauth.example.test")
	handler.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.GET("/api/federation/callback/:slug", handler.Callback)
	router.POST("/api/federation/verify", handler.VerifyToken)

	callbackReq := httptest.NewRequest(http.MethodGet, "/api/federation/callback/federation-callback?code=auth-code&state=fed-state", nil)
	callbackReq.AddCookie(&http.Cookie{Name: "fed_state", Value: "fed-state"})
	callbackReq.AddCookie(&http.Cookie{Name: "fed_return", Value: "/dashboard"})
	callbackRec := httptest.NewRecorder()
	router.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback status=%d body=%s", callbackRec.Code, callbackRec.Body.String())
	}

	var accessToken string
	for _, cookie := range callbackRec.Result().Cookies() {
		if cookie.Name == middleware.AccessTokenCookie {
			accessToken = cookie.Value
			break
		}
	}
	if accessToken == "" {
		t.Fatalf("callback should set access token cookie")
	}
	accessClaims, err := jwtManager.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("validate callback access token: %v", err)
	}
	if accessClaims.ClientID != "" {
		t.Fatalf("callback access token client_id=%q want empty central token client_id", accessClaims.ClientID)
	}
	if accessClaims.AuthTime <= 0 {
		t.Fatalf("callback access token auth_time=%d want positive", accessClaims.AuthTime)
	}

	createdUser, err := userRepo.FindByEmail("federation-callback@example.com")
	if err != nil {
		t.Fatalf("find callback user: %v", err)
	}
	localTokens, err := handler.issueFederationLocalTokens(createdUser)
	if err != nil {
		t.Fatalf("issue federation local tokens: %v", err)
	}
	if localTokens.AccessToken == "" || localTokens.RefreshToken == "" || localTokens.IDToken == "" {
		t.Fatalf("federation local tokens should include access_token, refresh_token and id_token: %#v", localTokens)
	}
	if localTokens.TokenType != "Bearer" {
		t.Fatalf("federation token_type=%q want Bearer", localTokens.TokenType)
	}
	if localTokens.ExpiresIn != int64(time.Hour.Seconds()) {
		t.Fatalf("federation expires_in=%d want %d", localTokens.ExpiresIn, int64(time.Hour.Seconds()))
	}
	idClaims, err := jwtManager.ValidateToken(localTokens.IDToken)
	if err != nil {
		t.Fatalf("validate federation id_token: %v", err)
	}
	if idClaims.TokenType != jwt.TokenTypeIDToken {
		t.Fatalf("federation id_token token_type=%q want %q", idClaims.TokenType, jwt.TokenTypeIDToken)
	}
	if idClaims.ClientID != "" {
		t.Fatalf("federation id_token client_id=%q want empty central token client_id", idClaims.ClientID)
	}
	if idClaims.AuthTime <= 0 {
		t.Fatalf("federation id_token auth_time=%d want positive", idClaims.AuthTime)
	}

	storedAccessToken, err := oauthRepo.FindAccessToken(accessToken)
	if err != nil {
		t.Fatalf("callback access token should be stored: %v", err)
	}
	if storedAccessToken.ClientID != "" {
		t.Fatalf("stored access token client_id=%q want empty central token client_id", storedAccessToken.ClientID)
	}
	if storedAccessToken.UserID == nil {
		t.Fatalf("stored access token should have user_id")
	}

	verifyRec := postJSON(t, router, "/api/federation/verify", map[string]string{
		"token":      accessToken,
		"api_key":    trustedApp.APIKey,
		"api_secret": trustedApp.APISecret,
	})
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("stored callback access token should verify: status=%d body=%s", verifyRec.Code, verifyRec.Body.String())
	}

	if err := oauthRepo.RevokeAccessToken(accessToken); err != nil {
		t.Fatalf("revoke callback access token: %v", err)
	}
	revokedVerifyRec := postJSON(t, router, "/api/federation/verify", map[string]string{
		"token":      accessToken,
		"api_key":    trustedApp.APIKey,
		"api_secret": trustedApp.APISecret,
	})
	if revokedVerifyRec.Code == http.StatusOK {
		t.Fatalf("revoked callback access token should not verify: status=%d body=%s", revokedVerifyRec.Code, revokedVerifyRec.Body.String())
	}
}
