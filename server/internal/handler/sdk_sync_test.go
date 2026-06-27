package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"

	"gorm.io/gorm"
)

type sdkSyncHandlerFixture struct {
	db              *gorm.DB
	router          *gin.Engine
	userRepo        *repository.UserRepository
	appRepo         *repository.ApplicationRepository
	sdkExternalRepo *repository.SDKExternalIdentityRepository
	app             *model.Application
	owner           *model.User
}

func setupSDKSyncHandlerFixture(t *testing.T, clientID, clientSecret, ownerEmail, ownerUsername string) sdkSyncHandlerFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	sdkExternalRepo := repository.NewSDKExternalIdentityRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        ownerEmail,
		Username:     ownerUsername,
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Name:         "SDK Sync Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	handler := NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test"))
	handler.SetSDKExternalIdentityRepo(sdkExternalRepo)

	router := gin.New()
	router.POST("/api/sdk/sync/user", handler.SyncUser)
	router.POST("/api/sdk/sync/batch", handler.BatchSync)

	return sdkSyncHandlerFixture{
		db:              db,
		router:          router,
		userRepo:        userRepo,
		appRepo:         appRepo,
		sdkExternalRepo: sdkExternalRepo,
		app:             app,
		owner:           owner,
	}
}

func TestSDKHandler_SyncUserPersistsExternalIDOnCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        "sdk-sync-owner@example.com",
		Username:     "sdksyncowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-sync-client",
		ClientSecret: "sdk-sync-secret",
		Name:         "SDK Sync Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/sync/user", NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test")).SyncUser)

	rec := postJSON(t, router, "/api/sdk/sync/user", map[string]string{
		"client_id":       app.ClientID,
		"client_secret":   app.ClientSecret,
		"email":           "sdk-sync-user@example.com",
		"username":        "sdksyncuser",
		"external_id":     "external-sync-001",
		"external_source": "platform-alpha",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("sync create status=%d want %d body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	user, err := userRepo.FindByEmail("sdk-sync-user@example.com")
	if err != nil {
		t.Fatalf("find synced user: %v", err)
	}
	if user.ExternalID != "external-sync-001" {
		t.Fatalf("external_id=%q want external-sync-001", user.ExternalID)
	}
	if user.ExternalSource != "platform-alpha" {
		t.Fatalf("external_source=%q want platform-alpha", user.ExternalSource)
	}
}

func TestSDKHandler_BatchSyncPersistsExternalIDOnCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        "sdk-batch-sync-owner@example.com",
		Username:     "sdkbatchsyncowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-batch-sync-client",
		ClientSecret: "sdk-batch-sync-secret",
		Name:         "SDK Batch Sync Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/sync/batch", NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test")).BatchSync)

	payload := map[string]interface{}{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"users": []map[string]string{
			{
				"email":           "sdk-batch-sync-user@example.com",
				"username":        "sdkbatchsyncuser",
				"external_id":     "external-batch-sync-001",
				"external_source": "platform-beta",
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/sync/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch sync status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	user, err := userRepo.FindByEmail("sdk-batch-sync-user@example.com")
	if err != nil {
		t.Fatalf("find batch synced user: %v", err)
	}
	if user.ExternalID != "external-batch-sync-001" {
		t.Fatalf("external_id=%q want external-batch-sync-001", user.ExternalID)
	}
	if user.ExternalSource != "platform-beta" {
		t.Fatalf("external_source=%q want platform-beta", user.ExternalSource)
	}
}

func TestSDKHandler_SyncUserPersistsExternalIDOnUpdate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        "sdk-sync-update-owner@example.com",
		Username:     "sdksyncupdateowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-sync-update-client",
		ClientSecret: "sdk-sync-update-secret",
		Name:         "SDK Sync Update Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	existingUser := &model.User{
		Email:        "sdk-sync-existing@example.com",
		Username:     "sdksyncexisting",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(existingUser); err != nil {
		t.Fatalf("create existing user: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/sync/user", NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test")).SyncUser)

	rec := postJSON(t, router, "/api/sdk/sync/user", map[string]string{
		"client_id":       app.ClientID,
		"client_secret":   app.ClientSecret,
		"email":           existingUser.Email,
		"username":        existingUser.Username,
		"external_id":     "external-sync-update-001",
		"external_source": "platform-gamma",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("sync update status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	user, err := userRepo.FindByEmail(existingUser.Email)
	if err != nil {
		t.Fatalf("find updated user: %v", err)
	}
	if user.ExternalID != "external-sync-update-001" {
		t.Fatalf("external_id=%q want external-sync-update-001", user.ExternalID)
	}
	if user.ExternalSource != "platform-gamma" {
		t.Fatalf("external_source=%q want platform-gamma", user.ExternalSource)
	}
}

func TestSDKHandler_SyncUserUpdatesExistingUserByExternalIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        "sdk-sync-external-owner@example.com",
		Username:     "sdksyncexternalowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-sync-external-client",
		ClientSecret: "sdk-sync-external-secret",
		Name:         "SDK Sync External Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	existingUser := &model.User{
		Email:          "sdk-sync-old-email@example.com",
		Username:       "sdksyncexternal",
		PasswordHash:   "hashed-password",
		Status:         "active",
		ExternalID:     "external-sync-existing-001",
		ExternalSource: "platform-zeta",
	}
	if err := userRepo.Create(existingUser); err != nil {
		t.Fatalf("create existing user: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/sync/user", NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test")).SyncUser)

	rec := postJSON(t, router, "/api/sdk/sync/user", map[string]string{
		"client_id":       app.ClientID,
		"client_secret":   app.ClientSecret,
		"email":           "sdk-sync-new-email@example.com",
		"username":        existingUser.Username,
		"external_id":     existingUser.ExternalID,
		"external_source": existingUser.ExternalSource,
		"nickname":        "External Match",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("sync external update status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	updatedUser, err := userRepo.FindByID(existingUser.ID)
	if err != nil {
		t.Fatalf("find existing user: %v", err)
	}
	if updatedUser.Email != existingUser.Email {
		t.Fatalf("email=%q want unchanged %q", updatedUser.Email, existingUser.Email)
	}
	if updatedUser.Nickname != "External Match" {
		t.Fatalf("nickname=%q want External Match", updatedUser.Nickname)
	}

	var count int64
	if err := db.Model(&model.User{}).Where("external_source = ? AND external_id = ?", existingUser.ExternalSource, existingUser.ExternalID).Count(&count).Error; err != nil {
		t.Fatalf("count external identity users: %v", err)
	}
	if count != 1 {
		t.Fatalf("external identity user count=%d want 1", count)
	}
}

func TestSDKHandler_SyncUserLinksMultipleSDKExternalIdentitiesToOneUser(t *testing.T) {
	f := setupSDKSyncHandlerFixture(
		t,
		"sdk-sync-multi-client",
		"sdk-sync-multi-secret",
		"sdk-sync-multi-owner@example.com",
		"sdksyncmultiowner",
	)

	firstRec := postJSON(t, f.router, "/api/sdk/sync/user", map[string]string{
		"client_id":       f.app.ClientID,
		"client_secret":   f.app.ClientSecret,
		"email":           "sdk-sync-multi-user@example.com",
		"username":        "sdksyncmultiuser",
		"external_id":     "external-alpha-001",
		"external_source": "platform-alpha",
	})
	if firstRec.Code != http.StatusCreated {
		t.Fatalf("first sync status=%d want %d body=%s", firstRec.Code, http.StatusCreated, firstRec.Body.String())
	}

	secondRec := postJSON(t, f.router, "/api/sdk/sync/user", map[string]string{
		"client_id":       f.app.ClientID,
		"client_secret":   f.app.ClientSecret,
		"email":           "sdk-sync-multi-user@example.com",
		"username":        "sdksyncmultiuser",
		"external_id":     "external-beta-001",
		"external_source": "platform-beta",
	})
	if secondRec.Code != http.StatusOK {
		t.Fatalf("second sync status=%d want %d body=%s", secondRec.Code, http.StatusOK, secondRec.Body.String())
	}

	user, err := f.userRepo.FindByEmail("sdk-sync-multi-user@example.com")
	if err != nil {
		t.Fatalf("find synced user: %v", err)
	}

	alphaIdentity, err := f.sdkExternalRepo.FindByExternalIdentity("platform-alpha", "external-alpha-001")
	if err != nil {
		t.Fatalf("find alpha identity: %v", err)
	}
	if alphaIdentity.UserID != user.ID {
		t.Fatalf("alpha identity user_id=%s want %s", alphaIdentity.UserID, user.ID)
	}

	betaIdentity, err := f.sdkExternalRepo.FindByExternalIdentity("platform-beta", "external-beta-001")
	if err != nil {
		t.Fatalf("find beta identity: %v", err)
	}
	if betaIdentity.UserID != user.ID {
		t.Fatalf("beta identity user_id=%s want %s", betaIdentity.UserID, user.ID)
	}

	var userCount int64
	if err := f.db.Model(&model.User{}).Where("email = ?", user.Email).Count(&userCount).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("user count=%d want 1", userCount)
	}
}

func TestSDKHandler_SyncUserMatchesExistingUserBySDKExternalIdentityTable(t *testing.T) {
	f := setupSDKSyncHandlerFixture(
		t,
		"sdk-sync-table-client",
		"sdk-sync-table-secret",
		"sdk-sync-table-owner@example.com",
		"sdksynctableowner",
	)

	existingUser := &model.User{
		Email:        "sdk-sync-table-old@example.com",
		Username:     "sdksynctableuser",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := f.userRepo.Create(existingUser); err != nil {
		t.Fatalf("create existing user: %v", err)
	}
	if err := f.sdkExternalRepo.Create(&model.SDKExternalIdentity{
		UserID:         existingUser.ID,
		ExternalSource: "platform-table",
		ExternalID:     "external-table-001",
	}); err != nil {
		t.Fatalf("create external identity: %v", err)
	}

	rec := postJSON(t, f.router, "/api/sdk/sync/user", map[string]string{
		"client_id":       f.app.ClientID,
		"client_secret":   f.app.ClientSecret,
		"email":           "sdk-sync-table-new@example.com",
		"username":        existingUser.Username,
		"external_id":     "external-table-001",
		"external_source": "platform-table",
		"nickname":        "SDK External Table Match",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("sync status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	updatedUser, err := f.userRepo.FindByID(existingUser.ID)
	if err != nil {
		t.Fatalf("find updated user: %v", err)
	}
	if updatedUser.Email != existingUser.Email {
		t.Fatalf("email=%q want unchanged %q", updatedUser.Email, existingUser.Email)
	}
	if updatedUser.Nickname != "SDK External Table Match" {
		t.Fatalf("nickname=%q want SDK External Table Match", updatedUser.Nickname)
	}
}

func TestSDKHandler_SyncUserRejectsExternalIdentityConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        "sdk-sync-conflict-owner@example.com",
		Username:     "sdksyncconflictowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-sync-conflict-client",
		ClientSecret: "sdk-sync-conflict-secret",
		Name:         "SDK Sync Conflict Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	emailUser := &model.User{
		Email:        "sdk-sync-conflict-email@example.com",
		Username:     "sdksyncconflictemail",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(emailUser); err != nil {
		t.Fatalf("create email user: %v", err)
	}

	externalUser := &model.User{
		Email:          "sdk-sync-conflict-external@example.com",
		Username:       "sdksyncconflictexternal",
		PasswordHash:   "hashed-password",
		Status:         "active",
		ExternalID:     "external-conflict-001",
		ExternalSource: "platform-conflict",
	}
	if err := userRepo.Create(externalUser); err != nil {
		t.Fatalf("create external user: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/sync/user", NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test")).SyncUser)

	rec := postJSON(t, router, "/api/sdk/sync/user", map[string]string{
		"client_id":       app.ClientID,
		"client_secret":   app.ClientSecret,
		"email":           emailUser.Email,
		"username":        emailUser.Username,
		"external_id":     externalUser.ExternalID,
		"external_source": externalUser.ExternalSource,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("sync conflict status=%d want %d body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestSDKHandler_SyncUserWithPasswordPersistsExternalIDOnCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        "sdk-sync-password-owner@example.com",
		Username:     "sdksyncpasswordowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-sync-password-client",
		ClientSecret: "sdk-sync-password-secret",
		Name:         "SDK Sync Password Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/sync/user", NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test")).SyncUser)

	rec := postJSON(t, router, "/api/sdk/sync/user", map[string]string{
		"client_id":       app.ClientID,
		"client_secret":   app.ClientSecret,
		"email":           "sdk-sync-password-user@example.com",
		"username":        "sdksyncpassworduser",
		"external_id":     "external-sync-password-001",
		"external_source": "platform-delta",
		"password":        "StrongPass123!",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("sync password create status=%d want %d body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	user, err := userRepo.FindByEmail("sdk-sync-password-user@example.com")
	if err != nil {
		t.Fatalf("find password synced user: %v", err)
	}
	if user.ExternalID != "external-sync-password-001" {
		t.Fatalf("external_id=%q want external-sync-password-001", user.ExternalID)
	}
	if user.ExternalSource != "platform-delta" {
		t.Fatalf("external_source=%q want platform-delta", user.ExternalSource)
	}
}

func TestSDKHandler_BatchSyncPersistsExternalIDOnUpdate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        "sdk-batch-sync-update-owner@example.com",
		Username:     "sdkbatchsyncupdateowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-batch-sync-update-client",
		ClientSecret: "sdk-batch-sync-update-secret",
		Name:         "SDK Batch Sync Update Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	existingUser := &model.User{
		Email:        "sdk-batch-sync-existing@example.com",
		Username:     "sdkbatchsyncexisting",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(existingUser); err != nil {
		t.Fatalf("create existing user: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/sync/batch", NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test")).BatchSync)

	payload := map[string]interface{}{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"users": []map[string]string{
			{
				"email":           existingUser.Email,
				"username":        existingUser.Username,
				"external_id":     "external-batch-sync-update-001",
				"external_source": "platform-epsilon",
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/sync/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch sync update status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	user, err := userRepo.FindByEmail(existingUser.Email)
	if err != nil {
		t.Fatalf("find batch synced existing user: %v", err)
	}
	if user.ExternalID != "external-batch-sync-update-001" {
		t.Fatalf("external_id=%q want external-batch-sync-update-001", user.ExternalID)
	}
	if user.ExternalSource != "platform-epsilon" {
		t.Fatalf("external_source=%q want platform-epsilon", user.ExternalSource)
	}
}

func TestSDKHandler_BatchSyncReportsExternalIdentityConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	authService := service.NewAuthService(userRepo, repository.NewLoginLogRepository(db), jwt.NewManager("test-secret-with-enough-length", "test"), testAuthConfig())

	owner := &model.User{
		Email:        "sdk-batch-conflict-owner@example.com",
		Username:     "sdkbatchconflictowner",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	app := &model.Application{
		ClientID:     "sdk-batch-conflict-client",
		ClientSecret: "sdk-batch-conflict-secret",
		Name:         "SDK Batch Conflict Client",
		UserID:       owner.ID,
		AppType:      model.AppTypeConfidential,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	emailUser := &model.User{
		Email:        "sdk-batch-conflict-email@example.com",
		Username:     "sdkbatchconflictemail",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(emailUser); err != nil {
		t.Fatalf("create email user: %v", err)
	}

	externalUser := &model.User{
		Email:          "sdk-batch-conflict-external@example.com",
		Username:       "sdkbatchconflictexternal",
		PasswordHash:   "hashed-password",
		Status:         "active",
		ExternalID:     "external-batch-conflict-001",
		ExternalSource: "platform-batch-conflict",
	}
	if err := userRepo.Create(externalUser); err != nil {
		t.Fatalf("create external user: %v", err)
	}

	router := gin.New()
	router.POST("/api/sdk/sync/batch", NewSDKHandler(authService, appRepo, jwt.NewManager("test-secret-with-enough-length", "test")).BatchSync)

	payload := map[string]interface{}{
		"client_id":     app.ClientID,
		"client_secret": app.ClientSecret,
		"users": []map[string]string{
			{
				"email":           emailUser.Email,
				"username":        emailUser.Username,
				"external_id":     externalUser.ExternalID,
				"external_source": externalUser.ExternalSource,
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sdk/sync/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch sync conflict status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("response data=%T want map[string]any", resp.Data)
	}
	if data["failed"] != float64(1) {
		t.Fatalf("failed=%v want 1", data["failed"])
	}
}
