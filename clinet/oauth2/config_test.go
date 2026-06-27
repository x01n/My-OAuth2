package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

/* ========== Config.Validate ========== */

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig("client-id", "secret", "http://localhost:9000/callback")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestConfig_Validate_MissingClientID(t *testing.T) {
	cfg := DefaultConfig("", "secret", "http://localhost:9000/callback")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client_id") {
		t.Errorf("Validate() should require client_id, got: %v", err)
	}
}

func TestConfig_Validate_MissingAuthURL(t *testing.T) {
	cfg := DefaultConfig("cid", "secret", "http://localhost:9000/callback")
	cfg.AuthURL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "auth_url") {
		t.Errorf("Validate() should require auth_url, got: %v", err)
	}
}

func TestConfig_Validate_MissingTokenURL(t *testing.T) {
	cfg := DefaultConfig("cid", "secret", "http://localhost:9000/callback")
	cfg.TokenURL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "token_url") {
		t.Errorf("Validate() should require token_url, got: %v", err)
	}
}

func TestConfig_Validate_MissingRedirectURL(t *testing.T) {
	cfg := DefaultConfig("cid", "secret", "")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "redirect_url") {
		t.Errorf("Validate() should require redirect_url, got: %v", err)
	}
}

func TestConfig_Validate_InvalidScheme(t *testing.T) {
	cfg := DefaultConfig("cid", "secret", "ftp://localhost/callback")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "http") {
		t.Errorf("Validate() should reject non-http scheme, got: %v", err)
	}
}

/* ========== DefaultConfig ========== */

func TestDefaultConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig("my-id", "my-secret", "http://localhost:9000/cb")
	if cfg.ClientID != "my-id" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "my-id")
	}
	if !cfg.UsePKCE {
		t.Error("UsePKCE should default to true")
	}
	if cfg.Issuer != "http://localhost:8080" {
		t.Fatalf("Issuer=%q want http://localhost:8080", cfg.Issuer)
	}
	if len(cfg.Scopes) == 0 {
		t.Error("Scopes should have defaults")
	}
}

func TestSSOConfig_DerivesEndpointsFromIssuerURL(t *testing.T) {
	cfg := SSOConfig("sso-client", "sso-secret", "http://localhost:8080/", "http://app.example.test/callback")

	if cfg.AuthURL != "http://localhost:8080/oauth/authorize" {
		t.Fatalf("AuthURL=%q want http://localhost:8080/oauth/authorize", cfg.AuthURL)
	}
	if cfg.TokenURL != "http://localhost:8080/oauth/token" {
		t.Fatalf("TokenURL=%q want http://localhost:8080/oauth/token", cfg.TokenURL)
	}
	if cfg.UserInfoURL != "http://localhost:8080/oauth/userinfo" {
		t.Fatalf("UserInfoURL=%q want http://localhost:8080/oauth/userinfo", cfg.UserInfoURL)
	}
	if cfg.Issuer != "http://localhost:8080" {
		t.Fatalf("Issuer=%q want http://localhost:8080", cfg.Issuer)
	}
	if cfg.RedirectURL != "http://app.example.test/callback" {
		t.Fatalf("RedirectURL=%q want http://app.example.test/callback", cfg.RedirectURL)
	}
	if !cfg.UsePKCE {
		t.Fatal("UsePKCE should default to true")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestDiscoverSSOConfig_DiscoversEndpointsFromOpenIDConfiguration(t *testing.T) {
	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                           serverURL(t, r),
			"authorization_endpoint":           serverURL(t, r) + "/oauth/authorize",
			"token_endpoint":                   serverURL(t, r) + "/oauth/token",
			"userinfo_endpoint":                serverURL(t, r) + "/oauth/userinfo",
			"code_challenge_methods_supported": []string{"S256"},
		})
	}))
	defer server.Close()

	cfg, err := DiscoverSSOConfig(context.Background(), "client-id", "client-secret", server.URL+"/", "http://app.example.test/callback")
	if err != nil {
		t.Fatalf("DiscoverSSOConfig() unexpected error: %v", err)
	}
	if requestedPath != "/.well-known/openid-configuration" {
		t.Fatalf("requested path=%q want /.well-known/openid-configuration", requestedPath)
	}
	if cfg.AuthURL != server.URL+"/oauth/authorize" {
		t.Fatalf("AuthURL=%q want %s/oauth/authorize", cfg.AuthURL, server.URL)
	}
	if cfg.TokenURL != server.URL+"/oauth/token" {
		t.Fatalf("TokenURL=%q want %s/oauth/token", cfg.TokenURL, server.URL)
	}
	if cfg.UserInfoURL != server.URL+"/oauth/userinfo" {
		t.Fatalf("UserInfoURL=%q want %s/oauth/userinfo", cfg.UserInfoURL, server.URL)
	}
	if cfg.Issuer != server.URL {
		t.Fatalf("Issuer=%q want %s", cfg.Issuer, server.URL)
	}
	if !cfg.UsePKCE {
		t.Fatal("UsePKCE should be true when discovery advertises S256")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestDiscoverSSOConfig_UsesIssuerPathForOpenIDConfiguration(t *testing.T) {
	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		if r.URL.Path != "/tenant/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		issuer := serverURL(t, r) + "/tenant"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/oauth/authorize",
			"token_endpoint":         issuer + "/oauth/token",
			"userinfo_endpoint":      issuer + "/oauth/userinfo",
		})
	}))
	defer server.Close()

	cfg, err := DiscoverSSOConfig(context.Background(), "client-id", "client-secret", server.URL+"/tenant/", "http://app.example.test/callback")
	if err != nil {
		t.Fatalf("DiscoverSSOConfig() unexpected error: %v", err)
	}
	if requestedPath != "/tenant/.well-known/openid-configuration" {
		t.Fatalf("requested path=%q want /tenant/.well-known/openid-configuration", requestedPath)
	}
	if cfg.AuthURL != server.URL+"/tenant/oauth/authorize" {
		t.Fatalf("AuthURL=%q want %s/tenant/oauth/authorize", cfg.AuthURL, server.URL)
	}
	if cfg.Issuer != server.URL+"/tenant" {
		t.Fatalf("Issuer=%q want %s/tenant", cfg.Issuer, server.URL)
	}
}

func TestDiscoverSSOConfig_RejectsIssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 serverURL(t, r) + "/other",
			"authorization_endpoint": serverURL(t, r) + "/oauth/authorize",
			"token_endpoint":         serverURL(t, r) + "/oauth/token",
			"userinfo_endpoint":      serverURL(t, r) + "/oauth/userinfo",
		})
	}))
	defer server.Close()

	_, err := DiscoverSSOConfig(context.Background(), "client-id", "client-secret", server.URL, "http://app.example.test/callback")
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("DiscoverSSOConfig() error=%v want issuer mismatch", err)
	}
}

func TestDiscoverSSOConfig_RejectsMissingUserInfoEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 serverURL(t, r),
			"authorization_endpoint": serverURL(t, r) + "/oauth/authorize",
			"token_endpoint":         serverURL(t, r) + "/oauth/token",
		})
	}))
	defer server.Close()

	_, err := DiscoverSSOConfig(context.Background(), "client-id", "client-secret", server.URL, "http://app.example.test/callback")
	if err == nil || !strings.Contains(err.Error(), "userinfo_endpoint") {
		t.Fatalf("DiscoverSSOConfig() error=%v want missing userinfo_endpoint", err)
	}
}

func serverURL(t *testing.T, r *http.Request) string {
	t.Helper()

	return "http://" + r.Host
}

/* ========== MemoryTokenStore ========== */

func TestMemoryTokenStore_SetGetDelete(t *testing.T) {
	store := NewMemoryTokenStore()

	/* 初始状态无 token */
	token, err := store.GetToken()
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != nil {
		t.Error("initial GetToken() should return nil")
	}

	/* 存储 token */
	tk := &Token{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		TokenType:    "Bearer",
	}
	if err := store.SetToken(tk); err != nil {
		t.Fatalf("SetToken() error: %v", err)
	}

	/* 读取 token */
	got, err := store.GetToken()
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if got == nil || got.AccessToken != "access-123" {
		t.Errorf("GetToken().AccessToken = %v, want %q", got, "access-123")
	}

	/* 删除 token */
	if err := store.DeleteToken(); err != nil {
		t.Fatalf("DeleteToken() error: %v", err)
	}
	got2, _ := store.GetToken()
	if got2 != nil {
		t.Error("GetToken() after DeleteToken() should return nil")
	}
}
