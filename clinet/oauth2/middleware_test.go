package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func TestClient_GetUserInfoUsesStoredToken(t *testing.T) {
	var userInfoAuthorization string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/userinfo" {
			t.Fatalf("path=%q want /oauth/userinfo", r.URL.Path)
		}
		userInfoAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":   "stored-user",
			"email": "stored@example.test",
			"name":  "Stored User",
		})
	}))
	defer server.Close()

	client := newMiddlewareTestClient(t, server.URL)
	store := NewMemoryTokenStore()
	if err := store.SetToken(&Token{AccessToken: "stored-access-token", TokenType: "Bearer"}); err != nil {
		t.Fatalf("set token: %v", err)
	}
	client.SetTokenStore(store)

	userInfo, err := client.GetUserInfo(context.Background())
	if err != nil {
		t.Fatalf("get userinfo: %v", err)
	}
	if userInfo.Sub != "stored-user" {
		t.Fatalf("userinfo sub=%q want stored-user", userInfo.Sub)
	}
	if userInfoAuthorization != "Bearer stored-access-token" {
		t.Fatalf("userinfo authorization=%q want Bearer stored-access-token", userInfoAuthorization)
	}
}

func TestClient_MiddlewareFetchesUserInfoWithoutMutatingTokenStore(t *testing.T) {
	var userInfoAuthorization string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/userinfo" {
			t.Fatalf("path=%q want /oauth/userinfo", r.URL.Path)
		}
		userInfoAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":                "request-user",
			"email":              "request@example.test",
			"name":               "Request User",
			"preferred_username": "requestuser",
		})
	}))
	defer server.Close()

	client := newMiddlewareTestClient(t, server.URL)
	store := NewMemoryTokenStore()
	if err := store.SetToken(&Token{AccessToken: "stored-access-token", TokenType: "Bearer"}); err != nil {
		t.Fatalf("set token: %v", err)
	}
	client.SetTokenStore(store)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := TokenFromContext(r.Context())
		if token == nil {
			t.Fatal("token from context is nil")
		}
		if token.AccessToken != "request-access-token" {
			t.Fatalf("context token=%q want request-access-token", token.AccessToken)
		}

		userInfo := UserInfoFromContext(r.Context())
		if userInfo == nil {
			t.Fatal("userinfo from context is nil")
		}
		if userInfo.Sub != "request-user" {
			t.Fatalf("context userinfo sub=%q want request-user", userInfo.Sub)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer request-access-token")
	rec := httptest.NewRecorder()

	client.Middleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if userInfoAuthorization != "Bearer request-access-token" {
		t.Fatalf("userinfo authorization=%q want Bearer request-access-token", userInfoAuthorization)
	}

	storedToken, err := store.GetToken()
	if err != nil {
		t.Fatalf("get stored token: %v", err)
	}
	if storedToken == nil || storedToken.AccessToken != "stored-access-token" {
		t.Fatalf("stored token=%v want stored-access-token", storedToken)
	}
}

func TestClient_GinMiddlewareFetchesUserInfoWithoutMutatingTokenStore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var userInfoAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfoAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":   "gin-user",
			"email": "gin@example.test",
			"name":  "Gin User",
		})
	}))
	defer server.Close()

	client := newMiddlewareTestClient(t, server.URL)
	store := NewMemoryTokenStore()
	if err := store.SetToken(&Token{AccessToken: "stored-access-token", TokenType: "Bearer"}); err != nil {
		t.Fatalf("set token: %v", err)
	}
	client.SetTokenStore(store)

	router := gin.New()
	router.Use(client.GinMiddleware())
	router.GET("/resource", func(ctx *gin.Context) {
		token := GinToken(ctx)
		if token == nil {
			t.Fatal("gin token is nil")
		}
		if token.AccessToken != "gin-request-token" {
			t.Fatalf("gin token=%q want gin-request-token", token.AccessToken)
		}
		userInfo := GinUserInfo(ctx)
		if userInfo == nil {
			t.Fatal("gin userinfo is nil")
		}
		if userInfo.Sub != "gin-user" {
			t.Fatalf("gin userinfo sub=%q want gin-user", userInfo.Sub)
		}
		ctx.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer gin-request-token")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if userInfoAuthorization != "Bearer gin-request-token" {
		t.Fatalf("userinfo authorization=%q want Bearer gin-request-token", userInfoAuthorization)
	}
	assertStoredToken(t, store, "stored-access-token")
}

func TestClient_EchoMiddlewareFetchesUserInfoWithoutMutatingTokenStore(t *testing.T) {
	var userInfoAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfoAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":   "echo-user",
			"email": "echo@example.test",
			"name":  "Echo User",
		})
	}))
	defer server.Close()

	client := newMiddlewareTestClient(t, server.URL)
	store := NewMemoryTokenStore()
	if err := store.SetToken(&Token{AccessToken: "stored-access-token", TokenType: "Bearer"}); err != nil {
		t.Fatalf("set token: %v", err)
	}
	client.SetTokenStore(store)

	app := echo.New()
	app.Use(client.EchoMiddleware())
	app.GET("/resource", func(ctx echo.Context) error {
		userInfo := EchoGetUserInfo(ctx)
		if userInfo == nil {
			t.Fatal("echo userinfo is nil")
		}
		if userInfo.Sub != "echo-user" {
			t.Fatalf("echo userinfo sub=%q want echo-user", userInfo.Sub)
		}
		if got := EchoGetUserID(ctx); got != "echo-user" {
			t.Fatalf("echo user id=%q want echo-user", got)
		}
		return ctx.NoContent(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer echo-request-token")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if userInfoAuthorization != "Bearer echo-request-token" {
		t.Fatalf("userinfo authorization=%q want Bearer echo-request-token", userInfoAuthorization)
	}
	assertStoredToken(t, store, "stored-access-token")
}

func newMiddlewareTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()

	cfg := SSOConfig("client-id", "client-secret", serverURL, "http://app.example.test/callback")
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func assertStoredToken(t *testing.T, store TokenStore, wantAccessToken string) {
	t.Helper()

	storedToken, err := store.GetToken()
	if err != nil {
		t.Fatalf("get stored token: %v", err)
	}
	if storedToken == nil {
		t.Fatal("stored token is nil")
	}
	if storedToken.AccessToken != wantAccessToken {
		t.Fatalf("stored token=%q want %s", storedToken.AccessToken, wantAccessToken)
	}
}
