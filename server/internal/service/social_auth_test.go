package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type socialLinkTestFixture struct {
	service        *SocialAuthService
	federationRepo *repository.FederationRepository
	user           *model.User
	providerServer *httptest.Server
}

func setupSocialLinkTest(t *testing.T) socialLinkTestFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true, TranslateError: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.FederatedProvider{}, &model.FederatedIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	userRepo := repository.NewUserRepository(db)
	federationRepo := repository.NewFederationRepository(db)
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "social-link-test-secret",
			Issuer: "social-link-test",
		},
	}
	service := NewSocialAuthService(userRepo, federationRepo, nil, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)

	user := &model.User{
		Email:        "social-link@example.com",
		Username:     "sociallink",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "provider-access-" + r.FormValue("code"),
				"refresh_token": "provider-refresh-" + r.FormValue("code"),
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/userinfo":
			auth := r.Header.Get("Authorization")
			externalID := "external-one"
			if auth == "Bearer provider-access-code-two" {
				externalID = "external-two"
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":             externalID,
				"email":          fmt.Sprintf("%s@example.com", externalID),
				"name":           externalID,
				"email_verified": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(providerServer.Close)

	return socialLinkTestFixture{
		service:        service,
		federationRepo: federationRepo,
		user:           user,
		providerServer: providerServer,
	}
}

func createSocialLinkProvider(t *testing.T, f socialLinkTestFixture, slug string) *model.FederatedProvider {
	t.Helper()

	provider := &model.FederatedProvider{
		Name:               slug,
		Slug:               slug,
		AuthURL:            f.providerServer.URL + "/auth",
		TokenURL:           f.providerServer.URL + "/token",
		UserInfoURL:        f.providerServer.URL + "/userinfo",
		ClientID:           slug + "-client",
		ClientSecret:       slug + "-secret",
		Scopes:             `["openid","email","profile"]`,
		Enabled:            true,
		AutoCreateUser:     true,
		TrustEmailVerified: true,
	}
	if err := f.federationRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}
	return provider
}

func TestSocialAuthService_LinkAccountRejectsSecondIdentityForSameProvider(t *testing.T) {
	f := setupSocialLinkTest(t)
	provider := createSocialLinkProvider(t, f, "same-provider")

	err := f.service.LinkAccount(context.Background(), f.user.ID, provider.Slug, "code-one", "http://app.example/callback")
	if err != nil {
		t.Fatalf("first link: %v", err)
	}

	err = f.service.LinkAccount(context.Background(), f.user.ID, provider.Slug, "code-two", "http://app.example/callback")
	if err != ErrProviderAlreadyLinked {
		t.Fatalf("second same-provider link error=%v want %v", err, ErrProviderAlreadyLinked)
	}

	identities, err := f.federationRepo.FindIdentitiesByUserID(f.user.ID)
	if err != nil {
		t.Fatalf("find identities: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("identity count=%d want 1", len(identities))
	}
	if identities[0].ProviderID != provider.ID || identities[0].ExternalID != "external-one" {
		t.Fatalf("identity=%+v want provider=%s external_id=external-one", identities[0], provider.ID)
	}
}

func TestSocialAuthService_LinkAccountMapsDuplicateCreateToProviderAlreadyLinked(t *testing.T) {
	f := setupSocialLinkTest(t)
	provider := createSocialLinkProvider(t, f, "duplicate-provider")

	existingIdentity := &model.FederatedIdentity{
		UserID:        f.user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "existing-external",
		ExternalEmail: "existing-external@example.com",
	}
	if err := f.federationRepo.CreateIdentity(existingIdentity); err != nil {
		t.Fatalf("create existing identity: %v", err)
	}

	err := f.service.LinkAccount(context.Background(), f.user.ID, provider.Slug, "code-two", "http://app.example/callback")
	if !errors.Is(err, ErrProviderAlreadyLinked) {
		t.Fatalf("duplicate create link error=%v want %v", err, ErrProviderAlreadyLinked)
	}
}

func TestSocialAuthService_LinkAccountAllowsDifferentProvidersForSameUser(t *testing.T) {
	f := setupSocialLinkTest(t)
	firstProvider := createSocialLinkProvider(t, f, "first-provider")
	secondProvider := createSocialLinkProvider(t, f, "second-provider")

	if err := f.service.LinkAccount(context.Background(), f.user.ID, firstProvider.Slug, "code-one", "http://app.example/callback"); err != nil {
		t.Fatalf("first provider link: %v", err)
	}
	if err := f.service.LinkAccount(context.Background(), f.user.ID, secondProvider.Slug, "code-two", "http://app.example/callback"); err != nil {
		t.Fatalf("second provider link: %v", err)
	}

	identities, err := f.federationRepo.FindIdentitiesByUserID(f.user.ID)
	if err != nil {
		t.Fatalf("find identities: %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("identity count=%d want 2", len(identities))
	}
}

func TestSocialAuthService_ExchangeCodeForTokenRejectsDisabledProvider(t *testing.T) {
	f := setupSocialLinkTest(t)
	provider := createSocialLinkProvider(t, f, "disabled-token-provider")
	provider.Enabled = false
	if err := f.federationRepo.UpdateProvider(provider); err != nil {
		t.Fatalf("disable provider: %v", err)
	}

	tokenResp, err := f.service.ExchangeCodeForToken(context.Background(), provider.Slug, "code-one", "http://app.example/callback")
	if !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("exchange disabled provider error=%v want %v", err, ErrProviderDisabled)
	}
	if tokenResp != nil {
		t.Fatalf("token response=%+v want nil", tokenResp)
	}
}

func TestSocialAuthService_GetUserInfoRejectsDisabledProvider(t *testing.T) {
	f := setupSocialLinkTest(t)
	provider := createSocialLinkProvider(t, f, "disabled-userinfo-provider")
	provider.Enabled = false
	if err := f.federationRepo.UpdateProvider(provider); err != nil {
		t.Fatalf("disable provider: %v", err)
	}

	userInfo, err := f.service.GetUserInfo(context.Background(), provider.Slug, "provider-access-code-one")
	if !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("userinfo disabled provider error=%v want %v", err, ErrProviderDisabled)
	}
	if userInfo != nil {
		t.Fatalf("user info=%+v want nil", userInfo)
	}
}

func TestSocialAuthService_LoginOrCreateUserRejectsDisabledProvider(t *testing.T) {
	f := setupSocialLinkTest(t)
	provider := createSocialLinkProvider(t, f, "disabled-login-provider")
	provider.Enabled = false
	if err := f.federationRepo.UpdateProvider(provider); err != nil {
		t.Fatalf("disable provider: %v", err)
	}

	user, tokens, err := f.service.LoginOrCreateUser(
		context.Background(),
		provider.Slug,
		&SocialUserInfo{
			ID:            "disabled-login-external",
			Email:         "disabled-login@example.com",
			Username:      "disabledlogin",
			EmailVerified: true,
		},
		&OAuthTokenResponse{
			AccessToken:  "disabled-access",
			RefreshToken: "disabled-refresh",
			ExpiresIn:    3600,
		},
		"203.0.113.10",
		"disabled-login-test",
	)
	if !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("login disabled provider error=%v want %v", err, ErrProviderDisabled)
	}
	if user != nil {
		t.Fatalf("user=%+v want nil", user)
	}
	if tokens != nil {
		t.Fatalf("tokens=%+v want nil", tokens)
	}
}

func TestFederationRepository_FindIdentityByUserAndProvider(t *testing.T) {
	f := setupSocialLinkTest(t)
	provider := createSocialLinkProvider(t, f, "lookup-provider")
	identity := &model.FederatedIdentity{
		UserID:        f.user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "lookup-external",
		ExternalEmail: "lookup-external@example.com",
		TokenExpiry:   time.Now().Add(time.Hour),
	}
	if err := f.federationRepo.CreateIdentity(identity); err != nil {
		t.Fatalf("create identity: %v", err)
	}

	found, err := f.federationRepo.FindIdentityByUserAndProvider(f.user.ID, provider.ID)
	if err != nil {
		t.Fatalf("find identity by user and provider: %v", err)
	}
	if found.ID != identity.ID || found.ExternalID != identity.ExternalID {
		t.Fatalf("found identity=%+v want id=%s external_id=%s", found, identity.ID, identity.ExternalID)
	}
}

func TestFederatedIdentityUniqueConstraints(t *testing.T) {
	f := setupSocialLinkTest(t)
	firstProvider := createSocialLinkProvider(t, f, "constraint-first")
	secondProvider := createSocialLinkProvider(t, f, "constraint-second")

	firstIdentity := &model.FederatedIdentity{
		UserID:        f.user.ID,
		ProviderID:    firstProvider.ID,
		ExternalID:    "constraint-external-one",
		ExternalEmail: "constraint-external-one@example.com",
	}
	if err := f.federationRepo.CreateIdentity(firstIdentity); err != nil {
		t.Fatalf("create first identity: %v", err)
	}

	sameUserProvider := &model.FederatedIdentity{
		UserID:        f.user.ID,
		ProviderID:    firstProvider.ID,
		ExternalID:    "constraint-external-two",
		ExternalEmail: "constraint-external-two@example.com",
	}
	if err := f.federationRepo.CreateIdentity(sameUserProvider); !errors.Is(err, repository.ErrFederatedIdentityAlreadyExists) {
		t.Fatalf("duplicate user/provider identity error=%v want %v", err, repository.ErrFederatedIdentityAlreadyExists)
	}

	otherUser := &model.User{
		Email:        "social-link-other@example.com",
		Username:     "sociallinkother",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := f.service.userRepo.Create(otherUser); err != nil {
		t.Fatalf("create other user: %v", err)
	}
	sameProviderExternal := &model.FederatedIdentity{
		UserID:        otherUser.ID,
		ProviderID:    firstProvider.ID,
		ExternalID:    firstIdentity.ExternalID,
		ExternalEmail: "duplicate-external@example.com",
	}
	if err := f.federationRepo.CreateIdentity(sameProviderExternal); !errors.Is(err, repository.ErrFederatedIdentityAlreadyExists) {
		t.Fatalf("duplicate provider/external identity error=%v want %v", err, repository.ErrFederatedIdentityAlreadyExists)
	}

	differentProvider := &model.FederatedIdentity{
		UserID:        f.user.ID,
		ProviderID:    secondProvider.ID,
		ExternalID:    firstIdentity.ExternalID,
		ExternalEmail: "same-external-different-provider@example.com",
	}
	if err := f.federationRepo.CreateIdentity(differentProvider); err != nil {
		t.Fatalf("same external_id under different provider should be allowed: %v", err)
	}
}
