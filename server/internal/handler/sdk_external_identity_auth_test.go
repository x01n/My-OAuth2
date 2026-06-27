package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"
	"server/pkg/password"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type sdkAuthExternalIdentityFixture struct {
	router          *gin.Engine
	db              *gorm.DB
	userRepo        *repository.UserRepository
	app             *model.Application
	sdkExternalRepo *repository.SDKExternalIdentityRepository
	riskEventRepo   *repository.RiskEventRepository
}

func setupSDKAuthExternalIdentityFixture(t *testing.T) sdkAuthExternalIdentityFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	sdkExternalRepo := repository.NewSDKExternalIdentityRepository(db)
	riskEventRepo := repository.NewRiskEventRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")
	authService := service.NewAuthService(userRepo, loginLogRepo, jwtManager, testAuthConfig())
	authService.SetOAuthRepo(oauthRepo)

	owner := &model.User{
		Email:        "sdk-auth-external-owner@example.com",
		Username:     "sdkauthexternalowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-auth-external-client",
		ClientSecret: "sdk-auth-external-secret",
		Name:         "SDK Auth External Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	sdkHandler := NewSDKHandler(authService, appRepo, jwtManager)
	sdkHandler.SetOAuthRepo(oauthRepo)
	sdkHandler.SetSDKExternalIdentityRepo(sdkExternalRepo)
	sdkHandler.SetRiskEventRepository(riskEventRepo)

	router := gin.New()
	router.POST("/api/sdk/register", sdkHandler.Register)
	router.POST("/api/sdk/login", sdkHandler.Login)

	return sdkAuthExternalIdentityFixture{
		router:          router,
		db:              db,
		userRepo:        userRepo,
		app:             app,
		sdkExternalRepo: sdkExternalRepo,
		riskEventRepo:   riskEventRepo,
	}
}

func TestSDKHandler_RegisterLinksExternalIdentity(t *testing.T) {
	f := setupSDKAuthExternalIdentityFixture(t)

	rec := postJSON(t, f.router, "/api/sdk/register", map[string]string{
		"client_id":       f.app.ClientID,
		"client_secret":   f.app.ClientSecret,
		"email":           "sdk-register-external@example.com",
		"username":        "sdkregisterexternal",
		"password":        "StrongPass123!",
		"external_id":     "external-register-001",
		"external_source": "platform-register",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", rec.Code, rec.Body.String())
	}

	var tokens SDKTokenResponse
	decodeSuccessData(t, rec, &tokens)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" {
		t.Fatalf("register response missing token fields: %#v", tokens)
	}

	user, err := f.userRepo.FindByEmail("sdk-register-external@example.com")
	if err != nil {
		t.Fatalf("find registered user: %v", err)
	}
	identity, err := f.sdkExternalRepo.FindByExternalIdentity("platform-register", "external-register-001")
	if err != nil {
		t.Fatalf("find external identity: %v", err)
	}
	if identity.UserID != user.ID {
		t.Fatalf("external identity user_id=%s want %s", identity.UserID, user.ID)
	}
}

func TestSDKHandler_LoginLinksExternalIdentity(t *testing.T) {
	f := setupSDKAuthExternalIdentityFixture(t)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		Email:        "sdk-login-external@example.com",
		Username:     "sdkloginexternal",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := f.userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	rec := postJSON(t, f.router, "/api/sdk/login", map[string]string{
		"client_id":       f.app.ClientID,
		"client_secret":   f.app.ClientSecret,
		"email":           user.Email,
		"password":        "StrongPass123!",
		"external_id":     "external-login-001",
		"external_source": "platform-login",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
	}

	var tokens SDKTokenResponse
	decodeSuccessData(t, rec, &tokens)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" {
		t.Fatalf("login response missing token fields: %#v", tokens)
	}

	identity, err := f.sdkExternalRepo.FindByExternalIdentity("platform-login", "external-login-001")
	if err != nil {
		t.Fatalf("find external identity: %v", err)
	}
	if identity.UserID != user.ID {
		t.Fatalf("external identity user_id=%s want %s", identity.UserID, user.ID)
	}
}

func TestSDKHandler_LoginRejectsExternalIdentityConflict(t *testing.T) {
	f := setupSDKAuthExternalIdentityFixture(t)

	hash, err := password.Hash("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	linkedUser := &model.User{
		Email:        "sdk-linked-external@example.com",
		Username:     "sdklinkedexternal",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := f.userRepo.Create(linkedUser); err != nil {
		t.Fatalf("create linked user: %v", err)
	}
	loginUser := &model.User{
		Email:        "sdk-conflict-external@example.com",
		Username:     "sdkconflictexternal",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := f.userRepo.Create(loginUser); err != nil {
		t.Fatalf("create login user: %v", err)
	}
	if err := f.sdkExternalRepo.Create(&model.SDKExternalIdentity{
		UserID:         linkedUser.ID,
		ExternalSource: "platform-conflict",
		ExternalID:     "external-conflict-001",
	}); err != nil {
		t.Fatalf("create external identity: %v", err)
	}

	bodyBytes, err := json.Marshal(map[string]string{
		"client_id":       f.app.ClientID,
		"client_secret":   f.app.ClientSecret,
		"email":           loginUser.Email,
		"password":        "StrongPass123!",
		"external_id":     "external-conflict-001",
		"external_source": "platform-conflict",
	})
	if err != nil {
		t.Fatalf("marshal login payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SDK-External-Conflict/1.0")
	req.RemoteAddr = "203.0.113.88:54321"
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("login status=%d want %d body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	code, message := decodeErrorInfo(t, rec)
	if code != ErrCodeConflict {
		t.Fatalf("error code=%q want %q", code, ErrCodeConflict)
	}
	if message != "External identity belongs to another user" {
		t.Fatalf("error message=%q", message)
	}
	body := rec.Body.String()
	if strings.Contains(body, "access_token") || strings.Contains(body, "refresh_token") || strings.Contains(body, "id_token") {
		t.Fatalf("conflict response should not include token fields: %s", body)
	}

	var riskEvent model.RiskEvent
	if err := f.db.Where("user_id = ? AND risk_score = ? AND decision = ? AND reason = ?", loginUser.ID, 80, model.RiskDecisionBlock, model.RiskEventReasonSDKExternalIdentityConflict).
		First(&riskEvent).Error; err != nil {
		t.Fatalf("find risk event: %v", err)
	}
	if riskEvent.IPAddress != "203.0.113.88" {
		t.Fatalf("risk event ip_address=%q want 203.0.113.88", riskEvent.IPAddress)
	}
	if riskEvent.UserAgent != "SDK-External-Conflict/1.0" {
		t.Fatalf("risk event user_agent=%q want SDK-External-Conflict/1.0", riskEvent.UserAgent)
	}
}
