package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClient_HandleCallbackExchangesTokenAndFetchesUserInfo(t *testing.T) {
	var tokenRequestCodeVerifier string
	var userInfoAuthorization string
	var tokenIssuer string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "authorization_code" {
				t.Fatalf("grant_type=%q want authorization_code", got)
			}
			if got := r.Form.Get("code"); got != "auth-code" {
				t.Fatalf("code=%q want auth-code", got)
			}
			if got := r.Form.Get("redirect_uri"); got != "http://app.example.test/callback" {
				t.Fatalf("redirect_uri=%q want http://app.example.test/callback", got)
			}
			if got := r.Form.Get("client_id"); got != "client-id" {
				t.Fatalf("client_id=%q want client-id", got)
			}
			tokenRequestCodeVerifier = r.Form.Get("code_verifier")
			if tokenRequestCodeVerifier == "" {
				t.Fatal("code_verifier should not be empty")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "access-token",
				"refresh_token": "refresh-token",
				"id_token":      signTestIDToken(t, "client-id", "client-secret", tokenIssuer, nil),
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "openid profile email",
			})
		case "/oauth/userinfo":
			userInfoAuthorization = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":                "user-1",
				"email":              "user@example.test",
				"email_verified":     true,
				"name":               "Example User",
				"preferred_username": "exampleuser",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	tokenIssuer = server.URL

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	staleStore := &staleReadTokenStore{
		readToken: &Token{AccessToken: "stale-access-token", TokenType: "Bearer"},
	}
	client.SetTokenStore(staleStore)

	authURL, err := client.AuthCodeURL()
	if err != nil {
		t.Fatalf("auth code url: %v", err)
	}
	state := queryValue(t, authURL, "state")
	if queryValue(t, authURL, "code_challenge") == "" {
		t.Fatal("code_challenge should not be empty")
	}
	if got := queryValue(t, authURL, "code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method=%q want S256", got)
	}

	result, err := client.HandleCallback(context.Background(), &CallbackRequest{
		Code:  "auth-code",
		State: state,
	})
	if err != nil {
		t.Fatalf("handle callback: %v", err)
	}
	if result.Token == nil || result.Token.AccessToken != "access-token" {
		t.Fatalf("access token=%v want access-token", result.Token)
	}
	if result.Token.RefreshToken != "refresh-token" {
		t.Fatalf("refresh token=%q want refresh-token", result.Token.RefreshToken)
	}
	if result.Token.IDToken == "" {
		t.Fatal("id_token should not be empty")
	}
	if result.UserInfo == nil {
		t.Fatal("userinfo should not be nil")
	}
	if result.UserInfo.Sub != "user-1" {
		t.Fatalf("userinfo sub=%q want user-1", result.UserInfo.Sub)
	}
	if result.UserInfo.Email != "user@example.test" {
		t.Fatalf("userinfo email=%q want user@example.test", result.UserInfo.Email)
	}
	if userInfoAuthorization != "Bearer access-token" {
		t.Fatalf("userinfo authorization=%q want Bearer access-token", userInfoAuthorization)
	}

	if staleStore.writtenToken == nil || staleStore.writtenToken.AccessToken != "access-token" {
		t.Fatalf("written token=%v want access-token", staleStore.writtenToken)
	}
}

func TestClient_HandleCallbackRejectsIDTokenATHashMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "different-access-token",
			"refresh_token": "refresh-token",
			"id_token":      signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", nil),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "openid profile email",
		})
	}))
	defer server.Close()

	cfg := SSOConfig("client-id", "client-secret", "http://oauth.example.test", "http://app.example.test/callback")
	cfg.TokenURL = server.URL + "/oauth/token"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	authURL, err := client.AuthCodeURL()
	if err != nil {
		t.Fatalf("auth code url: %v", err)
	}
	state := queryValue(t, authURL, "state")

	_, err = client.HandleCallback(context.Background(), &CallbackRequest{
		Code:  "auth-code",
		State: state,
	})
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}

func TestClient_HandleCallbackRejectsInvalidIDToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "access-token",
			"refresh_token": "refresh-token",
			"id_token":      "invalid-id-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "openid profile email",
		})
	}))
	defer server.Close()

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	authURL, err := client.AuthCodeURL()
	if err != nil {
		t.Fatalf("auth code url: %v", err)
	}
	state := queryValue(t, authURL, "state")

	_, err = client.HandleCallback(context.Background(), &CallbackRequest{
		Code:  "auth-code",
		State: state,
	})
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}

func TestClient_HandleCallbackReturnsOAuthError(t *testing.T) {
	cfg := SSOConfig("client-id", "client-secret", "http://oauth.example.test", "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	_, err = client.HandleCallback(context.Background(), &CallbackRequest{
		Error:            "access_denied",
		ErrorDescription: "user denied access",
	})
	if err == nil {
		t.Fatal("expected callback error")
	}
	oauthErr, ok := IsOAuthError(err)
	if !ok {
		t.Fatalf("error type=%T want OAuthError", err)
	}
	if oauthErr.Code != "access_denied" {
		t.Fatalf("oauth error code=%q want access_denied", oauthErr.Code)
	}
	if oauthErr.Description != "user denied access" {
		t.Fatalf("oauth error description=%q want user denied access", oauthErr.Description)
	}
	if got := err.Error(); got != "oauth2: access_denied - user denied access" {
		t.Fatalf("error string=%q want oauth2: access_denied - user denied access", got)
	}
}

func TestClient_HandleCallbackRejectsMissingCode(t *testing.T) {
	cfg := SSOConfig("client-id", "client-secret", "http://oauth.example.test", "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	_, err = client.HandleCallback(context.Background(), &CallbackRequest{State: "state"})
	if err == nil || !strings.Contains(err.Error(), "callback code") {
		t.Fatalf("error=%v want missing callback code", err)
	}
}

func TestClient_HandleCallbackRejectsInvalidState(t *testing.T) {
	cfg := SSOConfig("client-id", "client-secret", "http://oauth.example.test", "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if _, err := client.AuthCodeURL(); err != nil {
		t.Fatalf("auth code url: %v", err)
	}
	_, err = client.HandleCallback(context.Background(), &CallbackRequest{
		Code:  "auth-code",
		State: "wrong-state",
	})
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("error=%v want ErrInvalidState", err)
	}
}

func TestCallbackRequestFromHTTPRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=state&error=&error_description=", nil)

	callbackReq := CallbackRequestFromHTTPRequest(req)
	if callbackReq.Code != "auth-code" {
		t.Fatalf("code=%q want auth-code", callbackReq.Code)
	}
	if callbackReq.State != "state" {
		t.Fatalf("state=%q want state", callbackReq.State)
	}
}

func queryValue(t *testing.T, rawURL string, key string) string {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return parsed.Query().Get(key)
}

type staleReadTokenStore struct {
	readToken    *Token
	writtenToken *Token
}

func (s *staleReadTokenStore) GetToken() (*Token, error) {
	return s.readToken, nil
}

func (s *staleReadTokenStore) SetToken(token *Token) error {
	s.writtenToken = token
	return nil
}

func (s *staleReadTokenStore) DeleteToken() error {
	s.readToken = nil
	s.writtenToken = nil
	return nil
}
