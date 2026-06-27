package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func getOIDCDiscovery(t *testing.T) map[string]interface{} {
	t.Helper()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/.well-known/openid-configuration", NewOIDCHandler("test-issuer").Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "auth.example.test"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode discovery: %v body=%s", err, rec.Body.String())
	}
	return body
}

func getOIDCJWKS(t *testing.T) map[string]interface{} {
	t.Helper()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/.well-known/jwks.json", NewOIDCHandler("test-issuer").JWKS)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	req.Host = "auth.example.test"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode jwks: %v body=%s", err, rec.Body.String())
	}
	return body
}

func requireDiscoveryStringSlice(t *testing.T, body map[string]interface{}, key string, want []string) {
	t.Helper()

	raw, ok := body[key]
	if !ok {
		t.Fatalf("%s missing", key)
	}
	values, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("%s=%#v want array", key, raw)
	}
	if len(values) != len(want) {
		t.Fatalf("%s length=%d want %d values=%#v", key, len(values), len(want), values)
	}
	for i, expected := range want {
		got, ok := values[i].(string)
		if !ok {
			t.Fatalf("%s[%d]=%#v want string", key, i, values[i])
		}
		if got != expected {
			t.Fatalf("%s[%d]=%q want %q values=%#v", key, i, got, expected, values)
		}
	}
}

func requireDiscoveryBool(t *testing.T, body map[string]interface{}, key string, want bool) {
	t.Helper()

	raw, ok := body[key]
	if !ok {
		t.Fatalf("%s missing", key)
	}
	got, ok := raw.(bool)
	if !ok {
		t.Fatalf("%s=%#v want bool", key, raw)
	}
	if got != want {
		t.Fatalf("%s=%t want %t", key, got, want)
	}
}

func TestOIDCHandler_DiscoveryAdvertisesImplementedAuthorizeCapabilities(t *testing.T) {
	body := getOIDCDiscovery(t)

	requireDiscoveryStringSlice(t, body, "response_types_supported", []string{"code"})
	requireDiscoveryStringSlice(t, body, "response_modes_supported", []string{"query"})
	requireDiscoveryStringSlice(t, body, "prompt_values_supported", []string{"none", "login", "consent"})
	requireDiscoveryBool(t, body, "claims_parameter_supported", false)
	requireDiscoveryBool(t, body, "request_parameter_supported", false)
	requireDiscoveryBool(t, body, "request_uri_parameter_supported", false)
}

func TestOIDCHandler_DiscoveryAdvertisesImplementedIDTokenSigningAlgorithm(t *testing.T) {
	body := getOIDCDiscovery(t)

	requireDiscoveryStringSlice(t, body, "id_token_signing_alg_values_supported", []string{"HS256"})
}

func TestOIDCHandler_DiscoveryAdvertisesImplementedClaims(t *testing.T) {
	body := getOIDCDiscovery(t)

	requireDiscoveryStringSlice(t, body, "claims_supported", []string{
		"sub",
		"iss",
		"aud",
		"exp",
		"iat",
		"nonce",
		"auth_time",
		"amr",
		"at_hash",
		"azp",
		"name",
		"family_name",
		"given_name",
		"nickname",
		"preferred_username",
		"picture",
		"website",
		"gender",
		"birthdate",
		"zoneinfo",
		"locale",
		"updated_at",
		"email",
		"email_verified",
		"phone_number",
		"phone_number_verified",
		"address",
	})
}

func TestOIDCHandler_DiscoveryDoesNotAdvertiseAdminAppManagementAsDynamicRegistration(t *testing.T) {
	body := getOIDCDiscovery(t)

	if got, ok := body["registration_endpoint"]; ok {
		t.Fatalf("registration_endpoint=%#v must be omitted when dynamic client registration is not implemented", got)
	}
}

func TestOIDCHandler_DiscoveryDoesNotAdvertiseUnsupportedImplicitGrant(t *testing.T) {
	body := getOIDCDiscovery(t)

	raw, ok := body["grant_types_supported"]
	if !ok {
		t.Fatal("grant_types_supported missing")
	}
	values, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("grant_types_supported=%#v want array", raw)
	}
	for _, value := range values {
		if value == "implicit" {
			t.Fatalf("grant_types_supported must not include implicit: %#v", values)
		}
	}
}

func TestOIDCHandler_DiscoveryAdvertisesSSOIntegrationEndpoints(t *testing.T) {
	body := getOIDCDiscovery(t)

	want := map[string]string{
		"issuer":                 "https://auth.example.test",
		"authorization_endpoint": "https://auth.example.test/oauth/authorize",
		"token_endpoint":         "https://auth.example.test/oauth/token",
		"userinfo_endpoint":      "https://auth.example.test/oauth/userinfo",
		"end_session_endpoint":   "https://auth.example.test/oauth/logout",
	}
	for key, expected := range want {
		raw, ok := body[key]
		if !ok {
			t.Fatalf("%s missing", key)
		}
		got, ok := raw.(string)
		if !ok {
			t.Fatalf("%s=%#v want string", key, raw)
		}
		if got != expected {
			t.Fatalf("%s=%q want %q", key, got, expected)
		}
	}
}

func TestOIDCHandler_JWKSDoesNotPublishUnusedRS256Key(t *testing.T) {
	body := getOIDCJWKS(t)

	raw, ok := body["keys"]
	if !ok {
		t.Fatal("keys missing")
	}
	keys, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("keys=%#v want array", raw)
	}
	if len(keys) != 0 {
		t.Fatalf("keys length=%d want 0 keys=%#v", len(keys), keys)
	}
}
