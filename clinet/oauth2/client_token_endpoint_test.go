package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_RevokeAndIntrospectDeriveEndpointFromTokenPath(t *testing.T) {
	var revokePath string
	var introspectPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gateway/token-service/oauth/revoke":
			revokePath = r.URL.Path
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse revoke form: %v", err)
			}
			if got := r.Form.Get("token"); got != "refresh-token" {
				t.Fatalf("revoke token=%q want refresh-token", got)
			}
			w.WriteHeader(http.StatusOK)
		case "/gateway/token-service/oauth/introspect":
			introspectPath = r.URL.Path
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse introspect form: %v", err)
			}
			if got := r.Form.Get("token"); got != "access-token" {
				t.Fatalf("introspect token=%q want access-token", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": true})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := DefaultConfig("client-id", "client-secret", server.URL+"/callback")
	cfg.TokenURL = server.URL + "/gateway/token-service/oauth/token"
	cfg.AuthURL = server.URL + "/oauth/authorize"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	tokenStore := NewMemoryTokenStore()
	if err := tokenStore.SetToken(&Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
	}); err != nil {
		t.Fatalf("set token: %v", err)
	}
	client.SetTokenStore(tokenStore)

	if err := client.RevokeToken(context.Background(), "refresh_token"); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	if revokePath != "/gateway/token-service/oauth/revoke" {
		t.Fatalf("revoke path=%q want /gateway/token-service/oauth/revoke", revokePath)
	}

	result, err := client.IntrospectToken(context.Background(), "access-token", "access_token")
	if err != nil {
		t.Fatalf("introspect token: %v", err)
	}
	if active, ok := result["active"].(bool); !ok || !active {
		t.Fatalf("active=%v want true", result["active"])
	}
	if introspectPath != "/gateway/token-service/oauth/introspect" {
		t.Fatalf("introspect path=%q want /gateway/token-service/oauth/introspect", introspectPath)
	}
}

func TestClient_RevokeTokenReturnsOAuthErrorOnInvalidClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			t.Fatalf("path=%q want /oauth/revoke", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
	}))
	defer server.Close()

	cfg := DefaultConfig("client-id", "client-secret", server.URL+"/callback")
	cfg.TokenURL = server.URL + "/oauth/token"
	cfg.AuthURL = server.URL + "/oauth/authorize"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	tokenStore := NewMemoryTokenStore()
	if err := tokenStore.SetToken(&Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
	}); err != nil {
		t.Fatalf("set token: %v", err)
	}
	client.SetTokenStore(tokenStore)

	err = client.RevokeToken(context.Background(), "refresh_token")
	if err == nil {
		t.Fatal("revoke token error is nil")
	}
	oauthErr, ok := IsOAuthError(err)
	if !ok {
		t.Fatalf("error type=%T want OAuthError", err)
	}
	if oauthErr.Code != "invalid_client" {
		t.Fatalf("oauth error code=%q want invalid_client", oauthErr.Code)
	}
	if oauthErr.Description != "Invalid client credentials" {
		t.Fatalf("oauth error description=%q want Invalid client credentials", oauthErr.Description)
	}
	if oauthErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("oauth error status=%d want %d", oauthErr.StatusCode, http.StatusUnauthorized)
	}

	storedToken, err := tokenStore.GetToken()
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if storedToken == nil {
		t.Fatal("stored token is nil after failed revoke")
	}
	if storedToken.RefreshToken != "refresh-token" {
		t.Fatalf("stored refresh token=%q want refresh-token", storedToken.RefreshToken)
	}
}

func TestClient_IntrospectTokenReturnsOAuthErrorOnInvalidClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/introspect" {
			t.Fatalf("path=%q want /oauth/introspect", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
	}))
	defer server.Close()

	cfg := DefaultConfig("client-id", "client-secret", server.URL+"/callback")
	cfg.TokenURL = server.URL + "/oauth/token"
	cfg.AuthURL = server.URL + "/oauth/authorize"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	result, err := client.IntrospectToken(context.Background(), "access-token", "access_token")
	if err == nil {
		t.Fatal("introspect token error is nil")
	}
	if result != nil {
		t.Fatalf("result=%v want nil", result)
	}
	oauthErr, ok := IsOAuthError(err)
	if !ok {
		t.Fatalf("error type=%T want OAuthError", err)
	}
	if oauthErr.Code != "invalid_client" {
		t.Fatalf("oauth error code=%q want invalid_client", oauthErr.Code)
	}
	if oauthErr.Description != "Invalid client credentials" {
		t.Fatalf("oauth error description=%q want Invalid client credentials", oauthErr.Description)
	}
	if oauthErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("oauth error status=%d want %d", oauthErr.StatusCode, http.StatusUnauthorized)
	}
}
