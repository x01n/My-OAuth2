package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_RegisterUserSendsExternalIdentity(t *testing.T) {
	var registerPayload map[string]string
	var registerIDToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sdk/register" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&registerPayload); err != nil {
			t.Fatalf("decode register payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"access_token":  "sdk-register-access-token",
				"refresh_token": "sdk-register-refresh-token",
				"id_token":      registerIDToken,
				"token_type":    "Bearer",
				"expires_in":    86400,
				"user": map[string]string{
					"id":       "user-1",
					"email":    "register@example.test",
					"username": "registeruser",
					"role":     "user",
				},
			},
		})
	}))
	defer server.Close()
	registerIDToken = signSDKIDToken(t, server.URL, "sdk-register-access-token")

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	resp, err := client.RegisterUser(context.Background(), &SDKRegisterRequest{
		Email:          "register@example.test",
		Username:       "registeruser",
		Password:       "StrongPass123!",
		ExternalID:     "external-register-001",
		ExternalSource: "platform-register",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	if resp.IDToken != registerIDToken {
		t.Fatalf("response id_token=%q want signed id_token", resp.IDToken)
	}
	if registerPayload["external_id"] != "external-register-001" {
		t.Fatalf("external_id=%q want external-register-001", registerPayload["external_id"])
	}
	if registerPayload["external_source"] != "platform-register" {
		t.Fatalf("external_source=%q want platform-register", registerPayload["external_source"])
	}
}

func TestClient_LoginUserSendsExternalIdentity(t *testing.T) {
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
				"access_token":  "sdk-login-access-token",
				"refresh_token": "sdk-login-refresh-token",
				"id_token":      loginIDToken,
				"token_type":    "Bearer",
				"expires_in":    86400,
				"user": map[string]string{
					"id":       "user-1",
					"email":    "login@example.test",
					"username": "loginuser",
					"role":     "user",
				},
			},
		})
	}))
	defer server.Close()
	loginIDToken = signSDKIDToken(t, server.URL, "sdk-login-access-token")

	cfg := SSOConfig("client-id", "client-secret", server.URL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	resp, err := client.LoginUser(context.Background(), &SDKLoginRequest{
		Email:          "login@example.test",
		Password:       "StrongPass123!",
		ExternalID:     "external-login-001",
		ExternalSource: "platform-login",
	})
	if err != nil {
		t.Fatalf("login user: %v", err)
	}
	if resp.IDToken != loginIDToken {
		t.Fatalf("response id_token=%q want signed id_token", resp.IDToken)
	}
	if loginPayload["external_id"] != "external-login-001" {
		t.Fatalf("external_id=%q want external-login-001", loginPayload["external_id"])
	}
	if loginPayload["external_source"] != "platform-login" {
		t.Fatalf("external_source=%q want platform-login", loginPayload["external_source"])
	}
}

func TestClient_LoginUserMapsExternalIdentityConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sdk/login" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error": map[string]string{
				"code":    "CONFLICT",
				"message": "External identity belongs to another user",
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

	resp, err := client.LoginUser(context.Background(), &SDKLoginRequest{
		Email:          "login@example.test",
		Password:       "StrongPass123!",
		ExternalID:     "external-conflict-001",
		ExternalSource: "platform-conflict",
	})
	if resp != nil {
		t.Fatalf("response=%v want nil", resp)
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error=%v want %v", err, ErrConflict)
	}
}
