package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
)

func TestFederationHandler_AdminUpdateProviderPreservesExistingSecretWhenOmitted(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupTokenVerifyTestDB(t)
	federationRepo := repository.NewFederationRepository(db)
	userRepo := repository.NewUserRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	provider := &model.FederatedProvider{
		Name:               "Legacy Federation",
		Slug:               "legacy-fed",
		Description:        "before update",
		AuthURL:            "https://idp.example.com/oauth/authorize",
		TokenURL:           "https://idp.example.com/oauth/token",
		UserInfoURL:        "https://idp.example.com/oauth/userinfo",
		ClientID:           "legacy-client-id",
		ClientSecret:       "stored-secret",
		Scopes:             "openid profile email",
		Enabled:            true,
		AutoCreateUser:     true,
		TrustEmailVerified: true,
		SyncProfile:        true,
	}
	if err := federationRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	handler := NewFederationHandler(federationRepo, userRepo, jwtManager, "http://localhost:8080")
	router := gin.New()
	router.POST("/api/admin/federation/providers/:id", handler.AdminUpdateProvider)

	payload := map[string]any{
		"name":                 "Legacy Federation Updated",
		"slug":                 "legacy-fed",
		"description":          "after update",
		"auth_url":             "https://idp.example.com/oauth/authorize",
		"token_url":            "https://idp.example.com/oauth/token",
		"userinfo_url":         "https://idp.example.com/oauth/userinfo",
		"client_id":            "legacy-client-id-updated",
		"scopes":               "openid profile email offline_access",
		"enabled":              true,
		"auto_create_user":     false,
		"trust_email_verified": false,
		"sync_profile":         false,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	path := "/api/admin/federation/providers/" + provider.ID.String()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	stored, err := federationRepo.FindByID(provider.ID)
	if err != nil {
		t.Fatalf("find provider: %v", err)
	}
	if stored.ClientSecret != "stored-secret" {
		t.Fatalf("client_secret=%q want stored-secret", stored.ClientSecret)
	}
	if stored.Name != "Legacy Federation Updated" {
		t.Fatalf("name=%q want updated", stored.Name)
	}
	if stored.ClientID != "legacy-client-id-updated" {
		t.Fatalf("client_id=%q want updated", stored.ClientID)
	}
	if stored.AutoCreateUser {
		t.Fatalf("auto_create_user=%v want false", stored.AutoCreateUser)
	}
	if stored.TrustEmailVerified {
		t.Fatalf("trust_email_verified=%v want false", stored.TrustEmailVerified)
	}
	if stored.SyncProfile {
		t.Fatalf("sync_profile=%v want false", stored.SyncProfile)
	}
}

func TestFederationHandler_AdminUpdateProviderRejectsMissingStoredSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupTokenVerifyTestDB(t)
	federationRepo := repository.NewFederationRepository(db)
	userRepo := repository.NewUserRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	provider := &model.FederatedProvider{
		Name:               "Broken Federation",
		Slug:               "broken-fed",
		Description:        "no secret stored",
		AuthURL:            "https://idp.example.com/oauth/authorize",
		TokenURL:           "https://idp.example.com/oauth/token",
		UserInfoURL:        "https://idp.example.com/oauth/userinfo",
		ClientID:           "broken-client-id",
		ClientSecret:       "",
		Scopes:             "openid profile email",
		Enabled:            true,
		AutoCreateUser:     true,
		TrustEmailVerified: true,
		SyncProfile:        true,
	}
	if err := federationRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	handler := NewFederationHandler(federationRepo, userRepo, jwtManager, "http://localhost:8080")
	router := gin.New()
	router.POST("/api/admin/federation/providers/:id", handler.AdminUpdateProvider)

	payload := map[string]any{
		"name":         "Broken Federation Updated",
		"slug":         "broken-fed",
		"auth_url":     "https://idp.example.com/oauth/authorize",
		"token_url":    "https://idp.example.com/oauth/token",
		"userinfo_url": "https://idp.example.com/oauth/userinfo",
		"client_id":    "broken-client-id",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	path := "/api/admin/federation/providers/" + provider.ID.String()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	code, message := decodeErrorInfo(t, rec)
	if code != "BAD_REQUEST" {
		t.Fatalf("error code=%q want BAD_REQUEST", code)
	}
	if message != "Name, slug, client_id and client_secret are required" {
		t.Fatalf("error message=%q", message)
	}
}
