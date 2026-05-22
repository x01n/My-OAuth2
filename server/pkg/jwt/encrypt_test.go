package jwt

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEncryptedToken_NotPlainJWT(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()
	token, err := m.GenerateToken(uid, "a@b.com", "user", "user", TokenTypeAccess, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedToken(token) {
		t.Fatalf("expected encrypted prefix, got %q", token[:min(12, len(token))])
	}
	if strings.HasPrefix(token, "eyJ") {
		t.Fatal("token must not expose JWT header to clients")
	}
	claims, err := m.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.UserID != uid {
		t.Fatalf("user id mismatch")
	}
}

func TestEncryptedIDToken_RoundTrip(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()
	token, err := m.GenerateIDToken(uid, "a@b.com", "user", "user", "client-1", "openid profile", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedToken(token) {
		t.Fatal("id_token should be encrypted")
	}
	claims, err := m.ValidateToken(token)
	if err != nil || claims.TokenType != TokenTypeIDToken {
		t.Fatalf("validate id_token: %v type=%s", err, claims.TokenType)
	}
}
