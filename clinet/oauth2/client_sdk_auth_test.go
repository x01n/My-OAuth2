package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func signSDKIDToken(t *testing.T, issuer, accessToken string) string {
	t.Helper()
	return signTestIDToken(t, "client-id", "client-secret", issuer, map[string]interface{}{
		"at_hash": accessTokenHash(accessToken),
	})
}

func TestClient_LoginUserStoresIDToken(t *testing.T) {
	var loginPayload map[string]string
	var loginIDToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sdk/login" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&loginPayload); err != nil {
			t.Fatalf("decode login payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"access_token":  "sdk-access-token",
				"refresh_token": "sdk-refresh-token",
				"id_token":      loginIDToken,
				"token_type":    "Bearer",
				"expires_in":    86400,
				"user": map[string]string{
					"id":       "user-1",
					"email":    "user@example.test",
					"username": "userone",
					"role":     "user",
				},
			},
		})
	}))
	defer server.Close()
	loginIDToken = signSDKIDToken(t, server.URL, "sdk-access-token")

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	store := NewMemoryTokenStore()
	client.SetTokenStore(store)

	resp, err := client.LoginUser(context.Background(), &SDKLoginRequest{
		Email:    "user@example.test",
		Password: "StrongPass123!",
	})
	if err != nil {
		t.Fatalf("login user: %v", err)
	}
	if loginPayload["client_id"] != "client-id" {
		t.Fatalf("client_id=%q want client-id", loginPayload["client_id"])
	}
	if resp.IDToken != loginIDToken {
		t.Fatalf("response id_token=%q want signed id_token", resp.IDToken)
	}

	stored, err := store.GetToken()
	if err != nil {
		t.Fatalf("get stored token: %v", err)
	}
	if stored == nil {
		t.Fatalf("stored token is nil")
	}
	if stored.IDToken != loginIDToken {
		t.Fatalf("stored id_token=%q want signed id_token", stored.IDToken)
	}
}

func TestClient_LoginUserRejectsIDTokenATHashMismatch(t *testing.T) {
	var loginIDToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sdk/login" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"access_token":  "sdk-access-token",
				"refresh_token": "sdk-refresh-token",
				"id_token":      loginIDToken,
				"token_type":    "Bearer",
				"expires_in":    86400,
				"user": map[string]string{
					"id":       "user-1",
					"email":    "user@example.test",
					"username": "userone",
					"role":     "user",
				},
			},
		})
	}))
	defer server.Close()
	loginIDToken = signSDKIDToken(t, server.URL, "other-sdk-access-token")

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	store := NewMemoryTokenStore()
	client.SetTokenStore(store)

	resp, err := client.LoginUser(context.Background(), &SDKLoginRequest{
		Email:    "user@example.test",
		Password: "StrongPass123!",
	})
	if resp != nil {
		t.Fatalf("response=%v want nil", resp)
	}
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want %v", err, ErrInvalidIDToken)
	}

	stored, err := store.GetToken()
	if err != nil {
		t.Fatalf("get stored token: %v", err)
	}
	if stored != nil {
		t.Fatalf("stored token=%v want nil", stored)
	}
}

func TestClient_LegacySyncUserLoginReturnsAllTokens(t *testing.T) {
	var loginPayload map[string]string
	var loginIDToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/sdk/login":
			if err := json.NewDecoder(r.Body).Decode(&loginPayload); err != nil {
				t.Fatalf("decode login payload: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"access_token":  "legacy-login-access-token",
					"refresh_token": "legacy-login-refresh-token",
					"id_token":      loginIDToken,
					"token_type":    "Bearer",
					"expires_in":    86400,
					"user": map[string]string{
						"id":       "legacy-user-1",
						"email":    "legacy-login@example.test",
						"username": "legacylogin",
						"role":     "user",
					},
				},
			})
		case "/api/sdk/register":
			t.Fatalf("unexpected register request")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	loginIDToken = signSDKIDToken(t, server.URL, "legacy-login-access-token")

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	resp, err := client.LegacySyncUser(context.Background(), &LegacySyncUserRequest{
		Email:    "legacy-login@example.test",
		Username: "legacylogin",
		Password: "StrongPass123!",
	})
	if err != nil {
		t.Fatalf("legacy sync user: %v", err)
	}
	if loginPayload["client_id"] != "client-id" {
		t.Fatalf("client_id=%q want client-id", loginPayload["client_id"])
	}
	if resp.Created {
		t.Fatalf("created=%v want false", resp.Created)
	}
	if resp.AccessToken != "legacy-login-access-token" {
		t.Fatalf("access_token=%q want legacy-login-access-token", resp.AccessToken)
	}
	if resp.RefreshToken != "legacy-login-refresh-token" {
		t.Fatalf("refresh_token=%q want legacy-login-refresh-token", resp.RefreshToken)
	}
	if resp.IDToken != loginIDToken {
		t.Fatalf("id_token=%q want signed id_token", resp.IDToken)
	}
}

func TestClient_LegacySyncUserRegisterReturnsAllTokens(t *testing.T) {
	var registerPayload map[string]string
	var registerIDToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/sdk/login":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error": map[string]string{
					"code":    "UNAUTHORIZED",
					"message": "Invalid email or password",
				},
			})
		case "/api/sdk/register":
			if err := json.NewDecoder(r.Body).Decode(&registerPayload); err != nil {
				t.Fatalf("decode register payload: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"access_token":  "legacy-register-access-token",
					"refresh_token": "legacy-register-refresh-token",
					"id_token":      registerIDToken,
					"token_type":    "Bearer",
					"expires_in":    86400,
					"user": map[string]string{
						"id":       "legacy-user-2",
						"email":    "legacy-register@example.test",
						"username": "legacyregister",
						"role":     "user",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	registerIDToken = signSDKIDToken(t, server.URL, "legacy-register-access-token")

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	resp, err := client.LegacySyncUser(context.Background(), &LegacySyncUserRequest{
		Email:    "legacy-register@example.test",
		Username: "legacyregister",
		Password: "StrongPass123!",
	})
	if err != nil {
		t.Fatalf("legacy sync user: %v", err)
	}
	if registerPayload["client_id"] != "client-id" {
		t.Fatalf("client_id=%q want client-id", registerPayload["client_id"])
	}
	if !resp.Created {
		t.Fatalf("created=%v want true", resp.Created)
	}
	if resp.AccessToken != "legacy-register-access-token" {
		t.Fatalf("access_token=%q want legacy-register-access-token", resp.AccessToken)
	}
	if resp.RefreshToken != "legacy-register-refresh-token" {
		t.Fatalf("refresh_token=%q want legacy-register-refresh-token", resp.RefreshToken)
	}
	if resp.IDToken != registerIDToken {
		t.Fatalf("id_token=%q want signed id_token", resp.IDToken)
	}
}

func TestClient_RefreshSDKUserTokenStoresIDToken(t *testing.T) {
	var refreshPayload map[string]string
	var refreshIDToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sdk/refresh" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&refreshPayload); err != nil {
			t.Fatalf("decode refresh payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"access_token":  "refreshed-sdk-access-token",
				"refresh_token": "refreshed-sdk-refresh-token",
				"id_token":      refreshIDToken,
				"token_type":    "Bearer",
				"expires_in":    86400,
			},
		})
	}))
	defer server.Close()
	refreshIDToken = signSDKIDToken(t, server.URL, "refreshed-sdk-access-token")

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	store := NewMemoryTokenStore()
	client.SetTokenStore(store)
	if err := store.SetToken(&Token{
		AccessToken:  "old-sdk-access-token",
		RefreshToken: "old-sdk-refresh-token",
		IDToken:      "old-sdk-id-token",
		TokenType:    "Bearer",
	}); err != nil {
		t.Fatalf("set stored token: %v", err)
	}

	resp, err := client.RefreshSDKUserToken(context.Background())
	if err != nil {
		t.Fatalf("refresh SDK user token: %v", err)
	}
	if refreshPayload["client_id"] != "client-id" {
		t.Fatalf("client_id=%q want client-id", refreshPayload["client_id"])
	}
	if refreshPayload["client_secret"] != "client-secret" {
		t.Fatalf("client_secret=%q want client-secret", refreshPayload["client_secret"])
	}
	if refreshPayload["refresh_token"] != "old-sdk-refresh-token" {
		t.Fatalf("refresh_token=%q want old-sdk-refresh-token", refreshPayload["refresh_token"])
	}
	if resp.AccessToken != "refreshed-sdk-access-token" {
		t.Fatalf("response access_token=%q want refreshed-sdk-access-token", resp.AccessToken)
	}
	if resp.RefreshToken != "refreshed-sdk-refresh-token" {
		t.Fatalf("response refresh_token=%q want refreshed-sdk-refresh-token", resp.RefreshToken)
	}
	if resp.IDToken != refreshIDToken {
		t.Fatalf("response id_token=%q want signed id_token", resp.IDToken)
	}

	stored, err := store.GetToken()
	if err != nil {
		t.Fatalf("get stored token: %v", err)
	}
	if stored == nil {
		t.Fatalf("stored token is nil")
	}
	if stored.AccessToken != "refreshed-sdk-access-token" {
		t.Fatalf("stored access_token=%q want refreshed-sdk-access-token", stored.AccessToken)
	}
	if stored.RefreshToken != "refreshed-sdk-refresh-token" {
		t.Fatalf("stored refresh_token=%q want refreshed-sdk-refresh-token", stored.RefreshToken)
	}
	if stored.IDToken != refreshIDToken {
		t.Fatalf("stored id_token=%q want signed id_token", stored.IDToken)
	}
}

func TestClient_RefreshSDKUserTokenMapsErrors(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		message string
		wantErr error
	}{
		{
			name:    "invalid client",
			code:    "UNAUTHORIZED",
			message: "Invalid client credentials",
			wantErr: ErrInvalidClient,
		},
		{
			name:    "invalid refresh token",
			code:    "UNAUTHORIZED",
			message: "Invalid or expired refresh token",
			wantErr: ErrTokenExpired,
		},
		{
			name:    "user disabled",
			code:    "USER_DISABLED",
			message: "User account is disabled",
			wantErr: ErrAccessDenied,
		},
		{
			name:    "forbidden",
			code:    "FORBIDDEN",
			message: "Refresh token was not issued to this client",
			wantErr: ErrAccessDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/sdk/refresh" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				statusCode := http.StatusUnauthorized
				if tt.code == "FORBIDDEN" {
					statusCode = http.StatusForbidden
				}
				w.WriteHeader(statusCode)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    tt.code,
						"message": tt.message,
					},
				})
			}))
			defer server.Close()

			cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			defer client.Close()
			store := NewMemoryTokenStore()
			client.SetTokenStore(store)
			if err := store.SetToken(&Token{RefreshToken: "sdk-refresh-token"}); err != nil {
				t.Fatalf("set stored token: %v", err)
			}

			resp, err := client.RefreshSDKUserToken(context.Background())
			if resp != nil {
				t.Fatalf("response=%v want nil", resp)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error=%v want %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_EnsureSDKUserTokenReturnsStoredValidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request path=%s", r.URL.Path)
	}))
	defer server.Close()

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	store := NewMemoryTokenStore()
	client.SetTokenStore(store)
	if err := store.SetToken(&Token{
		AccessToken:  "valid-sdk-access-token",
		RefreshToken: "valid-sdk-refresh-token",
		IDToken:      "valid-sdk-id-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("set stored token: %v", err)
	}

	token, err := client.EnsureSDKUserToken(context.Background())
	if err != nil {
		t.Fatalf("ensure SDK user token: %v", err)
	}
	if token.AccessToken != "valid-sdk-access-token" {
		t.Fatalf("access_token=%q want valid-sdk-access-token", token.AccessToken)
	}
	if token.IDToken != "valid-sdk-id-token" {
		t.Fatalf("id_token=%q want valid-sdk-id-token", token.IDToken)
	}
}

func TestClient_EnsureSDKUserTokenRefreshesExpiredToken(t *testing.T) {
	var refreshPayload map[string]string
	var refreshIDToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sdk/refresh" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&refreshPayload); err != nil {
			t.Fatalf("decode refresh payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"access_token":  "ensured-sdk-access-token",
				"refresh_token": "ensured-sdk-refresh-token",
				"id_token":      refreshIDToken,
				"token_type":    "Bearer",
				"expires_in":    86400,
			},
		})
	}))
	defer server.Close()
	refreshIDToken = signSDKIDToken(t, server.URL, "ensured-sdk-access-token")

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	store := NewMemoryTokenStore()
	client.SetTokenStore(store)
	if err := store.SetToken(&Token{
		AccessToken:  "expired-sdk-access-token",
		RefreshToken: "expired-sdk-refresh-token",
		IDToken:      "expired-sdk-id-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("set stored token: %v", err)
	}

	token, err := client.EnsureSDKUserToken(context.Background())
	if err != nil {
		t.Fatalf("ensure SDK user token: %v", err)
	}
	if refreshPayload["refresh_token"] != "expired-sdk-refresh-token" {
		t.Fatalf("refresh_token=%q want expired-sdk-refresh-token", refreshPayload["refresh_token"])
	}
	if token.AccessToken != "ensured-sdk-access-token" {
		t.Fatalf("access_token=%q want ensured-sdk-access-token", token.AccessToken)
	}
	if token.RefreshToken != "ensured-sdk-refresh-token" {
		t.Fatalf("refresh_token=%q want ensured-sdk-refresh-token", token.RefreshToken)
	}
	if token.IDToken != refreshIDToken {
		t.Fatalf("id_token=%q want signed id_token", token.IDToken)
	}

	stored, err := store.GetToken()
	if err != nil {
		t.Fatalf("get stored token: %v", err)
	}
	if stored == nil {
		t.Fatalf("stored token is nil")
	}
	if stored.AccessToken != "ensured-sdk-access-token" {
		t.Fatalf("stored access_token=%q want ensured-sdk-access-token", stored.AccessToken)
	}
	if stored.IDToken != refreshIDToken {
		t.Fatalf("stored id_token=%q want signed id_token", stored.IDToken)
	}
}
