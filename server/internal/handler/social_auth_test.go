package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"server/internal/middleware"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
)

func TestSocialAuthHandler_CallbackUsesCookiesWithoutTokenQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"provider-access-token","refresh_token":"provider-refresh-token","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"external-user-1","email":"social-cookie@example.com","name":"Social Cookie","email_verified":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer providerServer.Close()

	db := setupTokenVerifyTestDB(t)
	userRepo := repository.NewUserRepository(db)
	federationRepo := repository.NewFederationRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")
	socialService := service.NewSocialAuthService(userRepo, federationRepo, loginLogRepo, jwtManager, testAuthConfig())
	socialService.SetOAuthRepo(oauthRepo)

	provider := &model.FederatedProvider{
		Name:               "Social Cookie Provider",
		Slug:               "social-cookie",
		AuthURL:            providerServer.URL + "/auth",
		TokenURL:           providerServer.URL + "/token",
		UserInfoURL:        providerServer.URL + "/userinfo",
		ClientID:           "social-client",
		ClientSecret:       "social-secret",
		Scopes:             "openid profile email",
		Enabled:            true,
		AutoCreateUser:     true,
		TrustEmailVerified: true,
	}
	if err := federationRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	router := gin.New()
	router.GET("/api/auth/social/:provider/callback", NewSocialAuthHandler(socialService).Callback)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/social-cookie/callback?code=auth-code&state=test-state", nil)
	req.Host = "app.example.test"
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "test-state"})
	req.AddCookie(&http.Cookie{Name: "oauth_return_to", Value: "/dashboard"})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatalf("redirect location should not be empty")
	}
	if strings.Contains(location, "access_token=") || strings.Contains(location, "refresh_token=") {
		t.Fatalf("redirect location should not contain tokens: %s", location)
	}
	if strings.Contains(location, "id_token=") {
		t.Fatalf("redirect location should not contain id_token: %s", location)
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if redirectURL.Scheme != "http" || redirectURL.Host != "app.example.test" || redirectURL.Path != "/auth/callback" {
		t.Fatalf("unexpected redirect location: %s", location)
	}
	if got := redirectURL.Query().Get("return_to"); got != "/dashboard" {
		t.Fatalf("return_to=%q want /dashboard", got)
	}
	if got, want := redirectURL.Query().Get("user_id"), findSocialCookieUserID(t, userRepo); got != want {
		t.Fatalf("user_id=%q want %q", got, want)
	}

	cookies := rec.Result().Cookies()
	assertClearedCookie(t, cookies, "oauth_state", "/")
	assertClearedCookie(t, cookies, "oauth_return_to", "/")
	accessToken := assertCookie(t, cookies, middleware.AccessTokenCookie, true, "/")
	refreshToken := assertCookie(t, cookies, middleware.RefreshTokenCookie, true, "/api/auth")
	assertCookie(t, cookies, middleware.CSRFTokenCookie, false, "/")

	accessClaims, err := jwtManager.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("validate social callback access token: %v", err)
	}
	if accessClaims.ClientID != "" {
		t.Fatalf("access token client_id=%q want empty central token client_id", accessClaims.ClientID)
	}
	if accessClaims.AuthTime <= 0 {
		t.Fatalf("access token auth_time=%d want positive", accessClaims.AuthTime)
	}
	refreshClaims, err := jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("validate social callback refresh token: %v", err)
	}
	if refreshClaims.ClientID != "" {
		t.Fatalf("refresh token client_id=%q want empty central token client_id", refreshClaims.ClientID)
	}
	if refreshClaims.AuthTime != accessClaims.AuthTime {
		t.Fatalf("refresh token auth_time=%d want %d", refreshClaims.AuthTime, accessClaims.AuthTime)
	}

	storedAccessToken, err := oauthRepo.FindAccessToken(accessToken)
	if err != nil {
		t.Fatalf("social callback access token should be stored: %v", err)
	}
	if storedAccessToken.ClientID != "" {
		t.Fatalf("stored access token client_id=%q want empty central token client_id", storedAccessToken.ClientID)
	}
	if storedAccessToken.UserID == nil {
		t.Fatalf("stored access token should have user_id")
	}
	protected := gin.New()
	protected.Use(middleware.WithUserRepo(userRepo))
	protected.GET("/api/protected", middleware.AuthWithOAuthRepo(jwtManager, oauthRepo), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	protectedReq := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	protectedReq.AddCookie(&http.Cookie{Name: middleware.AccessTokenCookie, Value: accessToken})
	protectedRec := httptest.NewRecorder()
	protected.ServeHTTP(protectedRec, protectedReq)
	if protectedRec.Code != http.StatusNoContent {
		t.Fatalf("social callback access token should authenticate protected route: status=%d body=%s", protectedRec.Code, protectedRec.Body.String())
	}
	if err := oauthRepo.RevokeAccessToken(accessToken); err != nil {
		t.Fatalf("revoke social callback access token: %v", err)
	}
	revokedAccessToken, err := oauthRepo.FindAccessToken(accessToken)
	if err != nil {
		t.Fatalf("find revoked social callback access token: %v", err)
	}
	if revokedAccessToken.IsValid() {
		t.Fatalf("revoked social callback access token should not be valid")
	}
}

func findSocialCookieUserID(t *testing.T, userRepo *repository.UserRepository) string {
	t.Helper()

	user, err := userRepo.FindByEmail("social-cookie@example.com")
	if err != nil {
		t.Fatalf("find created user: %v", err)
	}
	return user.ID.String()
}

func assertClearedCookie(t *testing.T, cookies []*http.Cookie, name string, path string) {
	t.Helper()

	for _, cookie := range cookies {
		if cookie.Name != name {
			continue
		}
		if cookie.Path != path {
			t.Fatalf("%s clear path=%q want %q", name, cookie.Path, path)
		}
		if cookie.MaxAge >= 0 {
			t.Fatalf("%s MaxAge=%d want negative for clearing", name, cookie.MaxAge)
		}
		return
	}
	t.Fatalf("cleared %s cookie not found", name)
}

func assertCookie(t *testing.T, cookies []*http.Cookie, name string, httpOnly bool, path string) string {
	t.Helper()

	for _, cookie := range cookies {
		if cookie.Name != name {
			continue
		}
		if cookie.Value == "" {
			t.Fatalf("%s cookie value should not be empty", name)
		}
		if cookie.HttpOnly != httpOnly {
			t.Fatalf("%s HttpOnly=%v want %v", name, cookie.HttpOnly, httpOnly)
		}
		if cookie.Path != path {
			t.Fatalf("%s path=%q want %q", name, cookie.Path, path)
		}
		return cookie.Value
	}
	t.Fatalf("%s cookie not found", name)
	return ""
}
