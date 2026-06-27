package service

import (
	"testing"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"

	"github.com/crewjam/saml"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupSAMLAuthServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true, TranslateError: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.SAMLProvider{}, &model.SAMLIdentity{}, &model.LoginLog{}, &model.AccessToken{}, &model.RefreshToken{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func setupSAMLAuthService(t *testing.T) (*SAMLAuthService, *repository.UserRepository, *repository.SAMLProviderRepository, *repository.SAMLIdentityRepository, *repository.OAuthRepository) {
	t.Helper()
	db := setupSAMLAuthServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	providerRepo := repository.NewSAMLProviderRepository(db)
	identityRepo := repository.NewSAMLIdentityRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "saml-test-secret-with-enough-length",
			Issuer:          "saml-test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{IDTokenTTL: 15 * time.Minute},
	}
	authService := NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetOAuthRepo(oauthRepo)
	svc := NewSAMLAuthService(providerRepo, identityRepo, userRepo, loginLogRepo, authService)
	return svc, userRepo, providerRepo, identityRepo, oauthRepo
}

func TestSAMLAuthService_ProfileFromAssertionFallsBackToNameIDEmail(t *testing.T) {
	svc, _, _, _, _ := setupSAMLAuthService(t)
	provider := &model.SAMLProvider{
		EmailAttribute:       "mail",
		UsernameAttribute:    "uid",
		EmployeeIDAttribute:  "employeeNumber",
		DisplayNameAttribute: "displayName",
		GivenNameAttribute:   "givenName",
		FamilyNameAttribute:  "sn",
		GroupAttribute:       "memberOf",
	}
	assertion := &saml.Assertion{
		Issuer: saml.Issuer{Value: "https://idp.example.com"},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value:  "person@example.com",
				Format: string(saml.EmailAddressNameIDFormat),
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{Name: "uid", Values: []saml.AttributeValue{{Value: "person"}}},
					{Name: "memberOf", Values: []saml.AttributeValue{{Value: "admins"}, {Value: "users"}}},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{{SessionIndex: "session-1"}},
	}

	profile, err := svc.ProfileFromAssertion(provider, assertion)
	if err != nil {
		t.Fatalf("profile from assertion: %v", err)
	}
	if profile.Email != "person@example.com" {
		t.Fatalf("email=%q want person@example.com", profile.Email)
	}
	if profile.Username != "person" {
		t.Fatalf("username=%q want person", profile.Username)
	}
	if profile.SessionIndex != "session-1" {
		t.Fatalf("session_index=%q want session-1", profile.SessionIndex)
	}
	if len(profile.Groups) != 2 || profile.Groups[0] != "admins" || profile.Groups[1] != "users" {
		t.Fatalf("groups=%v", profile.Groups)
	}
}

func TestSAMLAuthService_LoginRejectsNilDisabledOrInvalidProviderProfile(t *testing.T) {
	svc, _, _, _, _ := setupSAMLAuthService(t)
	disabledProvider := &model.SAMLProvider{
		Name:               "Disabled SAML",
		Slug:               "disabled-saml",
		Enabled:            false,
		AutoCreateUser:     true,
		TrustEmailVerified: true,
		DefaultRole:        model.RoleUser,
	}
	cases := []struct {
		name  string
		input SAMLLoginInput
		want  error
	}{
		{
			name: "nil provider",
			input: SAMLLoginInput{
				Provider: nil,
				Profile:  SAMLUserProfile{ExternalID: "ext-1", Email: "user@example.com"},
			},
			want: ErrEnterpriseProviderNotFound,
		},
		{
			name: "disabled provider",
			input: SAMLLoginInput{
				Provider: disabledProvider,
				Profile:  SAMLUserProfile{ExternalID: "ext-2", Email: "user@example.com"},
			},
			want: ErrEnterpriseProviderDisabled,
		},
		{
			name: "missing external id",
			input: SAMLLoginInput{
				Provider: &model.SAMLProvider{Enabled: true},
				Profile:  SAMLUserProfile{Email: "user@example.com"},
			},
			want: ErrSAMLAssertionInvalid,
		},
		{
			name: "missing email",
			input: SAMLLoginInput{
				Provider: &model.SAMLProvider{Enabled: true},
				Profile:  SAMLUserProfile{ExternalID: "ext-3"},
			},
			want: ErrSAMLAssertionInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.Login(tc.input)
			if err != tc.want {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}
}

func TestSAMLAuthService_LoginRejectsUntrustedEmailConflict(t *testing.T) {
	svc, userRepo, providerRepo, _, _ := setupSAMLAuthService(t)
	provider := &model.SAMLProvider{
		Name:               "Corp SAML",
		Slug:               "corp-saml",
		Enabled:            true,
		AutoCreateUser:     true,
		TrustEmailVerified: false,
		DefaultRole:        model.RoleUser,
	}
	if err := providerRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}
	user := &model.User{
		Email:        "existing@example.com",
		Username:     "existing",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, _, err := svc.Login(SAMLLoginInput{
		Provider: provider,
		Profile: SAMLUserProfile{
			ExternalID:   "external-user-1",
			Email:        "existing@example.com",
			Username:     "external-existing",
			DisplayName:  "Existing User",
			GivenName:    "Existing",
			FamilyName:   "User",
			Groups:       []string{"users"},
			SessionIndex: "session-1",
		},
		IPAddress: "127.0.0.1",
		UserAgent: "unit-test",
	})
	if err != ErrExternalEmailConflict {
		t.Fatalf("err=%v want ErrExternalEmailConflict", err)
	}
}

func TestSAMLAuthService_LoginCreatesIdentityAndStoresFederatedAMR(t *testing.T) {
	svc, userRepo, providerRepo, identityRepo, oauthRepo := setupSAMLAuthService(t)
	provider := &model.SAMLProvider{
		Name:               "Corp SAML",
		Slug:               "corp-saml",
		Enabled:            true,
		AutoCreateUser:     true,
		TrustEmailVerified: true,
		DefaultRole:        model.RoleUser,
	}
	provider.SetRoleMappings(model.RoleMappingMap{"admins": model.RoleAdmin})
	if err := providerRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	createdUser, tokens, err := svc.Login(SAMLLoginInput{
		Provider: provider,
		Profile: SAMLUserProfile{
			ExternalID:   "external-user-2",
			Email:        "saml-created@example.com",
			Username:     "samlcreated",
			DisplayName:  "SAML Created",
			GivenName:    "SAML",
			FamilyName:   "Created",
			Groups:       []string{"admins"},
			SessionIndex: "session-2",
		},
		IPAddress: "127.0.0.1",
		UserAgent: "unit-test",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if tokens == nil || tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" {
		t.Fatalf("tokens=%#v want full token set", tokens)
	}
	if createdUser.Role != model.RoleAdmin {
		t.Fatalf("role=%q want admin", createdUser.Role)
	}
	storedUser, err := userRepo.FindByEmail("saml-created@example.com")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if storedUser.ExternalSource != "saml:corp-saml" {
		t.Fatalf("external_source=%q want saml:corp-saml", storedUser.ExternalSource)
	}
	identity, err := identityRepo.FindByExternalID(provider.ID, "external-user-2")
	if err != nil {
		t.Fatalf("find identity: %v", err)
	}
	if identity.SessionIndex != "session-2" {
		t.Fatalf("session_index=%q want session-2", identity.SessionIndex)
	}
	accessToken, err := oauthRepo.FindAccessToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("find access token: %v", err)
	}
	if accessToken.AMR != jwt.AuthenticationMethodFederated {
		t.Fatalf("amr=%q want %q", accessToken.AMR, jwt.AuthenticationMethodFederated)
	}
}
