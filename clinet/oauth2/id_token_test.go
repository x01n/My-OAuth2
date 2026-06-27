package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func signTestIDToken(t *testing.T, clientID, clientSecret, issuer string, overrides map[string]interface{}) string {
	t.Helper()

	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	now := time.Now()
	claims := map[string]interface{}{
		"iss":        issuer,
		"sub":        "user-1",
		"aud":        []string{clientID},
		"exp":        now.Add(time.Hour).Unix(),
		"nbf":        now.Add(-time.Minute).Unix(),
		"iat":        now.Unix(),
		"jti":        "test-jti",
		"user_id":    "user-1",
		"email":      "user@example.test",
		"username":   "userone",
		"role":       "user",
		"token_type": "id_token",
		"client_id":  clientID,
		"scope":      "openid profile email",
		"nonce":      "nonce-123",
		"auth_time":  now.Add(-5 * time.Minute).Unix(),
		"amr":        []string{"pwd"},
		"at_hash":    "Pxa-1wifRlPl7yG_0oJNfw",
		"azp":        clientID,
	}
	for key, value := range overrides {
		claims[key] = value
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	mac := hmac.New(sha256.New, []byte(clientSecret))
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestValidateIDTokenAcceptsHS256ClientSecretToken(t *testing.T) {
	idToken := signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", nil)

	claims, err := ValidateIDToken(idToken, "client-id", "client-secret", "http://oauth.example.test")
	if err != nil {
		t.Fatalf("ValidateIDToken() error: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("sub=%q want user-1", claims.Subject)
	}
	if claims.ClientID != "client-id" {
		t.Fatalf("client_id=%q want client-id", claims.ClientID)
	}
	if claims.Nonce != "nonce-123" {
		t.Fatalf("nonce=%q want nonce-123", claims.Nonce)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != "pwd" {
		t.Fatalf("amr=%#v want [\"pwd\"]", claims.AMR)
	}
	if claims.ATHash != "Pxa-1wifRlPl7yG_0oJNfw" {
		t.Fatalf("at_hash=%q want Pxa-1wifRlPl7yG_0oJNfw", claims.ATHash)
	}
	if claims.AZP != "client-id" {
		t.Fatalf("azp=%q want client-id", claims.AZP)
	}
}

func TestValidateIDTokenWithAccessTokenChecksATHash(t *testing.T) {
	idToken := signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", nil)

	if _, err := ValidateIDTokenWithAccessToken(idToken, "client-id", "client-secret", "http://oauth.example.test", "access-token"); err != nil {
		t.Fatalf("ValidateIDTokenWithAccessToken() error: %v", err)
	}
	if _, err := ValidateIDTokenWithAccessToken(idToken, "client-id", "client-secret", "http://oauth.example.test", "other-access-token"); !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("wrong access token error=%v want ErrInvalidIDToken", err)
	}
}

func TestValidateIDTokenRejectsWrongClientSecret(t *testing.T) {
	idToken := signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", nil)

	_, err := ValidateIDToken(idToken, "client-id", "wrong-secret", "http://oauth.example.test")
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}

func TestValidateIDTokenRejectsIssuerMismatch(t *testing.T) {
	idToken := signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", nil)

	_, err := ValidateIDToken(idToken, "client-id", "client-secret", "http://other.example.test")
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}

func TestValidateIDTokenRejectsEncryptedInternalToken(t *testing.T) {
	_, err := ValidateIDToken("o2e1.internal-token", "client-id", "client-secret", "http://oauth.example.test")
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}

func TestValidateIDTokenRejectsExpiredToken(t *testing.T) {
	idToken := signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", map[string]interface{}{
		"exp": time.Now().Add(-time.Minute).Unix(),
	})

	_, err := ValidateIDToken(idToken, "client-id", "client-secret", "http://oauth.example.test")
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}

func TestValidateIDTokenRejectsAudienceMismatch(t *testing.T) {
	idToken := signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", map[string]interface{}{
		"aud": []string{"other-client"},
	})

	_, err := ValidateIDToken(idToken, "client-id", "client-secret", "http://oauth.example.test")
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}

func TestValidateIDTokenRejectsAuthorizedPartyMismatch(t *testing.T) {
	idToken := signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", map[string]interface{}{
		"azp": "other-client",
	})

	_, err := ValidateIDToken(idToken, "client-id", "client-secret", "http://oauth.example.test")
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}

func TestValidateIDTokenRejectsNonHS256(t *testing.T) {
	idToken := signTestIDToken(t, "client-id", "client-secret", "http://oauth.example.test", nil)
	parts := strings.Split(idToken, ".")
	headerBytes, err := json.Marshal(map[string]interface{}{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(headerBytes)
	idToken = strings.Join(parts, ".")

	_, err = ValidateIDToken(idToken, "client-id", "client-secret", "http://oauth.example.test")
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("error=%v want ErrInvalidIDToken", err)
	}
}
