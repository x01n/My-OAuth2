package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_SyncUserSendsExternalSource(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sdk/sync/user" {
			t.Fatalf("path=%s want /api/sdk/sync/user", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"action":"created","user":{"id":"user-1","email":"sdk@example.com","username":"sdkuser"}}}`))
	}))
	defer server.Close()

	client, err := NewClient(&Config{
		ClientID:     "sdk-client",
		ClientSecret: "sdk-secret",
		AuthURL:      server.URL + "/oauth/authorize",
		TokenURL:     server.URL + "/oauth/token",
		RedirectURL:  server.URL + "/callback",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	resp, err := client.SyncUser(context.Background(), &SyncUserRequest{
		Email:          "sdk@example.com",
		Username:       "sdkuser",
		ExternalID:     "external-client-001",
		ExternalSource: "platform-client",
	})
	if err != nil {
		t.Fatalf("sync user: %v", err)
	}
	if resp.Action != "created" {
		t.Fatalf("action=%q want created", resp.Action)
	}
	if payload["external_id"] != "external-client-001" {
		t.Fatalf("external_id=%v want external-client-001", payload["external_id"])
	}
	if payload["external_source"] != "platform-client" {
		t.Fatalf("external_source=%v want platform-client", payload["external_source"])
	}
}
