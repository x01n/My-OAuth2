package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"server/internal/config"
	gctx "server/internal/context"
	"server/internal/middleware"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"
	"server/pkg/password"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAuthHandlerTestDB(t *testing.T) *gorm.DB {
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

func testAuthHandlerConfig() *config.Config {
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

func TestAuthHandler_LoginReturnsOAuthTokenFieldsAndLegacyTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupAuthHandlerTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "handler-login@example.com",
		Username:     "handlerlogin",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := testAuthHandlerConfig()
	manager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer)
	authService := service.NewAuthService(userRepo, loginLogRepo, manager, cfg)
	authService.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.POST("/api/auth/login", NewAuthHandler(authService, cfg).Login)

	body := bytes.NewBufferString(`{"email":"handler-login@example.com","password":"StrongPass123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			User         UserResponse `json:"user"`
			AccessToken  string       `json:"access_token"`
			RefreshToken string       `json:"refresh_token"`
			IDToken      string       `json:"id_token"`
			TokenType    string       `json:"token_type"`
			ExpiresIn    int64        `json:"expires_in"`
			Tokens       struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				IDToken      string `json:"id_token"`
				TokenType    string `json:"token_type"`
				ExpiresIn    int64  `json:"expires_in"`
			} `json:"tokens"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success=false body=%s", rec.Body.String())
	}
	if resp.Data.User.ID != user.ID.String() {
		t.Fatalf("user.id=%q want %q", resp.Data.User.ID, user.ID.String())
	}
	if resp.Data.AccessToken == "" || resp.Data.RefreshToken == "" || resp.Data.IDToken == "" {
		t.Fatalf("top-level token fields are incomplete body=%s", rec.Body.String())
	}
	if resp.Data.TokenType != "Bearer" {
		t.Fatalf("token_type=%q want Bearer", resp.Data.TokenType)
	}
	if resp.Data.ExpiresIn != int64(cfg.JWT.AccessTokenTTL.Seconds()) {
		t.Fatalf("expires_in=%d want %d", resp.Data.ExpiresIn, int64(cfg.JWT.AccessTokenTTL.Seconds()))
	}
	if resp.Data.Tokens.AccessToken != resp.Data.AccessToken {
		t.Fatalf("tokens.access_token does not match top-level access_token")
	}
	if resp.Data.Tokens.RefreshToken != resp.Data.RefreshToken {
		t.Fatalf("tokens.refresh_token does not match top-level refresh_token")
	}
	if resp.Data.Tokens.IDToken != resp.Data.IDToken {
		t.Fatalf("tokens.id_token does not match top-level id_token")
	}
	if resp.Data.Tokens.TokenType != resp.Data.TokenType {
		t.Fatalf("tokens.token_type does not match top-level token_type")
	}
	if resp.Data.Tokens.ExpiresIn != resp.Data.ExpiresIn {
		t.Fatalf("tokens.expires_in does not match top-level expires_in")
	}

	idClaims, err := manager.ValidateToken(resp.Data.IDToken)
	if err != nil {
		t.Fatalf("validate id_token: %v", err)
	}
	if idClaims.TokenType != jwt.TokenTypeIDToken {
		t.Fatalf("id_token token_type=%q want %q", idClaims.TokenType, jwt.TokenTypeIDToken)
	}
	if idClaims.AuthTime <= 0 {
		t.Fatalf("id_token auth_time=%d want positive", idClaims.AuthTime)
	}
	if len(idClaims.AMR) != 1 || idClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("id_token amr=%#v want [%q]", idClaims.AMR, jwt.AuthenticationMethodPassword)
	}
	if idClaims.ATHash != jwt.AccessTokenHash(resp.Data.AccessToken) {
		t.Fatalf("id_token at_hash=%q want %q", idClaims.ATHash, jwt.AccessTokenHash(resp.Data.AccessToken))
	}
}

func TestAuthHandler_LoginAccessTokenAuthenticatesProtectedRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupAuthHandlerTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "handler-bearer-login@example.com",
		Username:     "handlerbearerlogin",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := testAuthHandlerConfig()
	manager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer)
	authService := service.NewAuthService(userRepo, loginLogRepo, manager, cfg)
	authService.SetOAuthRepo(oauthRepo)

	router := gin.New()
	router.Use(middleware.WithUserRepo(userRepo))
	authHandler := NewAuthHandler(authService, cfg)
	router.POST("/api/auth/login", authHandler.Login)
	router.GET("/protected", middleware.AuthWithOAuthRepo(manager, oauthRepo), func(c *gin.Context) {
		userID, ok := gctx.GetUserID(c)
		if !ok {
			t.Fatalf("missing user_id in context")
		}
		authTime, ok := gctx.GetAuthTime(c)
		if !ok {
			t.Fatalf("missing auth_time in context")
		}
		amr, ok := gctx.GetAuthMethods(c)
		if !ok {
			t.Fatalf("missing auth_methods in context")
		}
		c.JSON(http.StatusOK, gin.H{
			"user_id":        userID.String(),
			"user_email":     c.GetString(gctx.UserEmailKey),
			"user_username":  c.GetString(gctx.UserUsernameKey),
			"user_role":      c.GetString(gctx.UserRoleKey),
			"auth_client_id": gctx.GetClientID(c),
			"auth_time":      authTime,
			"amr":            amr,
		})
	})

	loginBody := bytes.NewBufferString(`{"email":"handler-bearer-login@example.com","password":"StrongPass123!"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	router.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status=%d want %d body=%s", loginRec.Code, http.StatusOK, loginRec.Body.String())
	}

	var loginResp struct {
		Success bool `json:"success"`
		Data    struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("decode login response: %v body=%s", err, loginRec.Body.String())
	}
	if !loginResp.Success || loginResp.Data.AccessToken == "" {
		t.Fatalf("login response missing access_token body=%s", loginRec.Body.String())
	}

	protectedReq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	protectedReq.Header.Set("Authorization", "Bearer "+loginResp.Data.AccessToken)
	protectedRec := httptest.NewRecorder()
	router.ServeHTTP(protectedRec, protectedReq)
	if protectedRec.Code != http.StatusOK {
		t.Fatalf("protected status=%d want %d body=%s", protectedRec.Code, http.StatusOK, protectedRec.Body.String())
	}

	var protectedResp struct {
		UserID       string   `json:"user_id"`
		UserEmail    string   `json:"user_email"`
		UserUsername string   `json:"user_username"`
		UserRole     string   `json:"user_role"`
		ClientID     string   `json:"auth_client_id"`
		AuthTime     int64    `json:"auth_time"`
		AMR          []string `json:"amr"`
	}
	if err := json.Unmarshal(protectedRec.Body.Bytes(), &protectedResp); err != nil {
		t.Fatalf("decode protected response: %v body=%s", err, protectedRec.Body.String())
	}
	if protectedResp.UserID != user.ID.String() {
		t.Fatalf("user_id=%q want %q", protectedResp.UserID, user.ID.String())
	}
	if protectedResp.UserEmail != user.Email {
		t.Fatalf("user_email=%q want %q", protectedResp.UserEmail, user.Email)
	}
	if protectedResp.UserUsername != user.Username {
		t.Fatalf("user_username=%q want %q", protectedResp.UserUsername, user.Username)
	}
	if protectedResp.UserRole != string(user.Role) {
		t.Fatalf("user_role=%q want %q", protectedResp.UserRole, string(user.Role))
	}
	if protectedResp.ClientID != "" {
		t.Fatalf("auth_client_id=%q want empty central token client_id", protectedResp.ClientID)
	}
	if protectedResp.AuthTime <= 0 {
		t.Fatalf("auth_time=%d want positive", protectedResp.AuthTime)
	}
	if len(protectedResp.AMR) != 1 || protectedResp.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("amr=%#v want [%q]", protectedResp.AMR, jwt.AuthenticationMethodPassword)
	}

	var accessCookie *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == middleware.AccessTokenCookie {
			accessCookie = cookie
			break
		}
	}
	if accessCookie == nil || accessCookie.Value == "" {
		t.Fatalf("login response missing %s cookie", middleware.AccessTokenCookie)
	}

	cookieReq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	cookieReq.AddCookie(accessCookie)
	cookieRec := httptest.NewRecorder()
	router.ServeHTTP(cookieRec, cookieReq)
	if cookieRec.Code != http.StatusOK {
		t.Fatalf("cookie protected status=%d want %d body=%s", cookieRec.Code, http.StatusOK, cookieRec.Body.String())
	}

	var cookieResp struct {
		UserID   string   `json:"user_id"`
		ClientID string   `json:"auth_client_id"`
		AMR      []string `json:"amr"`
	}
	if err := json.Unmarshal(cookieRec.Body.Bytes(), &cookieResp); err != nil {
		t.Fatalf("decode cookie protected response: %v body=%s", err, cookieRec.Body.String())
	}
	if cookieResp.UserID != user.ID.String() {
		t.Fatalf("cookie user_id=%q want %q", cookieResp.UserID, user.ID.String())
	}
	if cookieResp.ClientID != "" {
		t.Fatalf("cookie auth_client_id=%q want empty central token client_id", cookieResp.ClientID)
	}
	if len(cookieResp.AMR) != 1 || cookieResp.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("cookie amr=%#v want [%q]", cookieResp.AMR, jwt.AuthenticationMethodPassword)
	}
}

func TestAuthHandler_RefreshReturnsOAuthTokenFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupAuthHandlerTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "handler-refresh@example.com",
		Username:     "handlerrefresh",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := testAuthHandlerConfig()
	manager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer)
	authService := service.NewAuthService(userRepo, loginLogRepo, manager, cfg)
	authService.SetOAuthRepo(oauthRepo)

	_, tokens, err := authService.Login(&service.LoginInput{
		Email:    user.Email,
		Password: "StrongPass123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	router := gin.New()
	router.POST("/api/auth/refresh", NewAuthHandler(authService, cfg).Refresh)

	body := bytes.NewBufferString(`{"refresh_token":"` + tokens.RefreshToken + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			IDToken      string `json:"id_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int64  `json:"expires_in"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success=false body=%s", rec.Body.String())
	}
	if resp.Data.AccessToken == "" || resp.Data.RefreshToken == "" || resp.Data.IDToken == "" {
		t.Fatalf("refresh token fields are incomplete body=%s", rec.Body.String())
	}
	if resp.Data.TokenType != "Bearer" {
		t.Fatalf("token_type=%q want Bearer", resp.Data.TokenType)
	}
	if resp.Data.ExpiresIn != int64(cfg.JWT.AccessTokenTTL.Seconds()) {
		t.Fatalf("expires_in=%d want %d", resp.Data.ExpiresIn, int64(cfg.JWT.AccessTokenTTL.Seconds()))
	}

	idClaims, err := manager.ValidateToken(resp.Data.IDToken)
	if err != nil {
		t.Fatalf("validate id_token: %v", err)
	}
	if idClaims.TokenType != jwt.TokenTypeIDToken {
		t.Fatalf("id_token token_type=%q want %q", idClaims.TokenType, jwt.TokenTypeIDToken)
	}
	if len(idClaims.AMR) != 1 || idClaims.AMR[0] != jwt.AuthenticationMethodPassword {
		t.Fatalf("id_token amr=%#v want [%q]", idClaims.AMR, jwt.AuthenticationMethodPassword)
	}
	if idClaims.ATHash != jwt.AccessTokenHash(resp.Data.AccessToken) {
		t.Fatalf("id_token at_hash=%q want %q", idClaims.ATHash, jwt.AccessTokenHash(resp.Data.AccessToken))
	}
}

func TestAuthHandler_Login_blocksSuspiciousLoginWithoutIssuingTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupAuthHandlerTestDB(t)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "handler-risk@example.com",
		Username:     "handlerrisk",
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

	cfg := testAuthHandlerConfig()
	authService := service.NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetAnomalyDetectionService(service.NewAnomalyDetectionService(loginLogRepo, userRepo))
	authService.SetRiskEventRepository(riskEventRepo)

	router := gin.New()
	router.POST("/api/auth/login", NewAuthHandler(authService, cfg).Login)

	body := bytes.NewBufferString(`{"email":"handler-risk@example.com","password":"StrongPass123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "curl/8.0")
	req.RemoteAddr = "203.0.113.44:12345"
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
		t.Fatalf("error.code=%q want %q", resp.Error.Code, ErrCodeSuspiciousLogin)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("access_token")) || bytes.Contains(rec.Body.Bytes(), []byte("refresh_token")) {
		t.Fatalf("response body contains token field body=%s", rec.Body.String())
	}

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == middleware.AccessTokenCookie || cookie.Name == middleware.RefreshTokenCookie {
			t.Fatalf("unexpected auth cookie %q", cookie.Name)
		}
	}

	var accessTokenCount int64
	if err := db.Model(&model.AccessToken{}).Count(&accessTokenCount).Error; err != nil {
		t.Fatalf("count access tokens: %v", err)
	}
	if accessTokenCount != 0 {
		t.Fatalf("access token count=%d want 0", accessTokenCount)
	}

	var refreshTokenCount int64
	if err := db.Model(&model.RefreshToken{}).Count(&refreshTokenCount).Error; err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	if refreshTokenCount != 0 {
		t.Fatalf("refresh token count=%d want 0", refreshTokenCount)
	}

	var riskEventCount int64
	if err := db.Model(&model.RiskEvent{}).
		Where("user_id = ? AND risk_score = ? AND decision = ?", user.ID, 100, model.RiskDecisionBlock).
		Count(&riskEventCount).Error; err != nil {
		t.Fatalf("count risk events: %v", err)
	}
	if riskEventCount != 1 {
		t.Fatalf("risk event count=%d want 1", riskEventCount)
	}
}
