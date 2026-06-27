package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_SignTokenOmitsUserID(t *testing.T) {
	var requestPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token/sign" {
			t.Fatalf("path=%q want /token/sign", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestPayload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"token":"service-token","token_type":"Bearer","expires_in":3600}}`))
	}))
	defer server.Close()

	cfg := DefaultConfig("sign-client", "sign-secret", server.URL+"/callback")
	cfg.AuthURL = server.URL + "/oauth/authorize"
	cfg.TokenURL = server.URL + "/oauth/token"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := client.SignToken(context.Background(), &SignTokenRequest{
		Claims:    map[string]interface{}{"purpose": "service"},
		ExpiresIn: 3600,
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	if resp.Token != "service-token" {
		t.Fatalf("token=%q want service-token", resp.Token)
	}

	if got := requestPayload["client_id"]; got != "sign-client" {
		t.Fatalf("client_id=%v want sign-client", got)
	}
	if got := requestPayload["client_secret"]; got != "sign-secret" {
		t.Fatalf("client_secret=%v want sign-secret", got)
	}
	if got := requestPayload["expires_in"]; got != float64(3600) {
		t.Fatalf("expires_in=%v want 3600", got)
	}
	if _, ok := requestPayload["claims"].(map[string]interface{}); !ok {
		t.Fatalf("claims=%#v want object", requestPayload["claims"])
	}
	if _, ok := requestPayload["user_id"]; ok {
		t.Fatalf("request must not include removed user_id field: %#v", requestPayload)
	}
}

func TestClient_ValidateUserTokenUsesSDKVerify(t *testing.T) {
	var requestPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sdk/verify" {
			t.Fatalf("path=%q want /api/sdk/verify", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("authorization header should not be used for SDK verify")
		}
		if err := json.NewDecoder(r.Body).Decode(&requestPayload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"valid":true,"user":{"id":"user-123","email":"sdk-user@example.com","username":"sdkuser","role":"user","email_verified":true},"claims":{"sub":"user-123","email":"sdk-user@example.com","role":"user","client_id":"sdk-client"}}}`))
	}))
	defer server.Close()

	cfg := DefaultConfig("sdk-client", "sdk-secret", server.URL+"/callback")
	cfg.AuthURL = server.URL + "/oauth/authorize"
	cfg.TokenURL = server.URL + "/oauth/token"
	cfg.UserInfoURL = server.URL + "/oauth/userinfo"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	userInfo, err := client.ValidateUserToken(context.Background(), "sdk-access-token")
	if err != nil {
		t.Fatalf("validate user token: %v", err)
	}
	if userInfo.Sub != "user-123" {
		t.Fatalf("sub=%q want user-123", userInfo.Sub)
	}
	if userInfo.Email != "sdk-user@example.com" {
		t.Fatalf("email=%q want sdk-user@example.com", userInfo.Email)
	}
	if userInfo.PreferredUsername != "sdkuser" {
		t.Fatalf("preferred_username=%q want sdkuser", userInfo.PreferredUsername)
	}
	if !userInfo.EmailVerified {
		t.Fatalf("email_verified=false want true")
	}

	if got := requestPayload["client_id"]; got != "sdk-client" {
		t.Fatalf("client_id=%v want sdk-client", got)
	}
	if got := requestPayload["client_secret"]; got != "sdk-secret" {
		t.Fatalf("client_secret=%v want sdk-secret", got)
	}
	if got := requestPayload["access_token"]; got != "sdk-access-token" {
		t.Fatalf("access_token=%v want sdk-access-token", got)
	}
}

func TestClient_ValidateUserTokenMapsSDKVerifyErrors(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		message string
		wantErr error
	}{
		{
			name:    "invalid client",
			code:    "INVALID_CLIENT",
			message: "Invalid client credentials",
			wantErr: ErrInvalidClient,
		},
		{
			name:    "token expired",
			code:    "TOKEN_EXPIRED",
			message: "Invalid or expired access token",
			wantErr: ErrTokenExpired,
		},
		{
			name:    "token invalid",
			code:    "TOKEN_INVALID",
			message: "Invalid or expired access token",
			wantErr: ErrTokenExpired,
		},
		{
			name:    "user disabled",
			code:    "USER_DISABLED",
			message: "User account is disabled",
			wantErr: ErrAccessDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/sdk/verify" {
					t.Fatalf("path=%q want /api/sdk/verify", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    tt.code,
						"message": tt.message,
					},
				})
			}))
			defer server.Close()

			cfg := DefaultConfig("sdk-client", "sdk-secret", server.URL+"/callback")
			cfg.AuthURL = server.URL + "/oauth/authorize"
			cfg.TokenURL = server.URL + "/oauth/token"

			client, err := NewClient(cfg)
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			userInfo, err := client.ValidateUserToken(context.Background(), "sdk-access-token")
			if userInfo != nil {
				t.Fatalf("user info=%v want nil", userInfo)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error=%v want %v", err, tt.wantErr)
			}
		})
	}
}
