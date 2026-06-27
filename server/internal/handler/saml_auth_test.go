package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
)

var errSAMLTestUnknown = errors.New("saml test unknown")

func setupSAMLHandlerTest(t *testing.T) (*gin.Engine, *repository.SAMLProviderRepository) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := setupTokenVerifyTestDB(t)
	if err := db.AutoMigrate(&model.SAMLProvider{}, &model.SAMLIdentity{}); err != nil {
		t.Fatalf("migrate saml tables: %v", err)
	}
	providerRepo := repository.NewSAMLProviderRepository(db)
	identityRepo := repository.NewSAMLIdentityRepository(db)
	userRepo := repository.NewUserRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "saml-handler-test-secret-with-enough-length",
			Issuer:          "saml-handler-test",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth: config.OAuthConfig{
			FrontendURL: "http://localhost:3000",
			IDTokenTTL:  15 * time.Minute,
		},
	}
	authService := service.NewAuthService(userRepo, loginLogRepo, jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer), cfg)
	authService.SetOAuthRepo(oauthRepo)
	samlAuthService := service.NewSAMLAuthService(providerRepo, identityRepo, userRepo, loginLogRepo, authService)
	handler := NewSAMLAuthHandler(providerRepo, samlAuthService, cfg, "http://localhost:8080", "http://localhost:3000")
	router := gin.New()
	router.GET("/api/federation/saml/:slug/metadata", handler.Metadata)
	router.GET("/api/federation/saml/:slug/login", handler.StartLogin)
	return router, providerRepo
}

func TestSAMLAuthHandler_RedirectSAMLServiceErrorMapsKnownErrors(t *testing.T) {
	h := &SAMLAuthHandler{}
	router := gin.New()
	router.GET("/redirect", func(c *gin.Context) {
		name := c.Query("name")
		var err error
		switch name {
		case "provider-disabled":
			err = service.ErrEnterpriseProviderDisabled
		case "email-conflict":
			err = service.ErrExternalEmailConflict
		case "user-not-found":
			err = service.ErrEnterpriseUserNotFound
		case "invalid-credentials":
			err = service.ErrInvalidCredentials
		default:
			err = errSAMLTestUnknown
		}
		h.redirectSAMLServiceError(c, err)
	})

	cases := []struct {
		name     string
		query    string
		location string
	}{
		{name: "provider disabled", query: "provider-disabled", location: "/login?error=SAML+provider+is+disabled"},
		{name: "external email conflict", query: "email-conflict", location: "/login?error=Email+already+registered%3B+please+sign+in+first+and+link+the+provider+manually"},
		{name: "enterprise user not found", query: "user-not-found", location: "/login?error=SAML+user+is+not+allowed"},
		{name: "invalid credentials", query: "invalid-credentials", location: "/login?error=SAML+user+is+disabled"},
		{name: "default branch", query: "unknown", location: "/login?error=Failed+to+process+SAML+login"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/redirect?name="+tc.query, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusFound {
				t.Fatalf("status=%d want %d", rec.Code, http.StatusFound)
			}
			if got := rec.Header().Get("Location"); got != tc.location {
				t.Fatalf("location=%q want %q", got, tc.location)
			}
		})
	}
}

func TestParseRSAPrivateKeyPEM_AcceptsPKCS1AndPKCS8(t *testing.T) {
	pkcs1CertPEM, pkcs1KeyPEM, err := generateSAMLKeyPair("pkcs1-test")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	_ = pkcs1CertPEM
	_, err = parseRSAPrivateKeyPEM(pkcs1KeyPEM)
	if err != nil {
		t.Fatalf("parse pkcs1 pem: %v", err)
	}

	_, generatedPKCS1, err := generateSAMLKeyPair("pkcs8-test")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	pkcs1Parsed, err := parseRSAPrivateKeyPEM(generatedPKCS1)
	if err != nil {
		t.Fatalf("parse generated pkcs1: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(pkcs1Parsed)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})
	_, err = parseRSAPrivateKeyPEM(string(pkcs8PEM))
	if err != nil {
		t.Fatalf("parse pkcs8 pem: %v", err)
	}

	if _, err := parseRSAPrivateKeyPEM("not-a-pem"); err == nil {
		t.Fatalf("expected invalid pem error")
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal ecdsa key: %v", err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	if _, err := parseRSAPrivateKeyPEM(string(ecPEM)); err == nil {
		t.Fatalf("expected non-rsa key error")
	}
}

func TestSAMLAuthHandler_MetadataReturnsNotFoundForMissingProvider(t *testing.T) {
	router, _ := setupSAMLHandlerTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/federation/saml/missing/metadata", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	code, message := decodeErrorInfo(t, rec)
	if code != "NOT_FOUND" {
		t.Fatalf("code=%q want NOT_FOUND", code)
	}
	if message != "SAML provider not found" {
		t.Fatalf("message=%q", message)
	}
}

func TestSAMLAuthHandler_StartLoginRedirectsWhenProviderDisabled(t *testing.T) {
	router, providerRepo := setupSAMLHandlerTest(t)
	certPEM, keyPEM, err := generateSAMLKeyPair("disabled-saml-test")
	if err != nil {
		t.Fatalf("generate saml key pair: %v", err)
	}
	provider := &model.SAMLProvider{
		Name:           "Disabled SAML",
		Slug:           "disabled-saml",
		Enabled:        false,
		MetadataXML:    `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}
	if err := providerRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/federation/saml/disabled-saml/login?return_to=%2Fdashboard", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if location != "/login?error=SAML+provider+is+disabled" {
		t.Fatalf("location=%q", location)
	}
}

func TestSAMLAuthHandler_MetadataReturnsXMLForConfiguredProvider(t *testing.T) {
	router, providerRepo := setupSAMLHandlerTest(t)
	certPEM, keyPEM, err := generateSAMLKeyPair("metadata-saml-test")
	if err != nil {
		t.Fatalf("generate saml key pair: %v", err)
	}
	provider := &model.SAMLProvider{
		Name:                "Metadata SAML",
		Slug:                "metadata-saml",
		Enabled:             true,
		AllowIDPInitiated:   true,
		MetadataXML:         `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		CertificatePEM:      certPEM,
		PrivateKeyPEM:       keyPEM,
		DefaultRedirectPath: "/dashboard",
	}
	if err := providerRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/federation/saml/metadata-saml/metadata", nil)
	req.Host = "localhost:8080"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "application/samlmetadata+xml; charset=utf-8" {
		t.Fatalf("content-type=%q", contentType)
	}
	if body := rec.Body.String(); body == "" || body[0] != '<' {
		t.Fatalf("metadata body=%q", body)
	}
}
