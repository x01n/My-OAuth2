package repository

import (
	"strings"
	"testing"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupOAuthRepositoryTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.AuthorizationCode{}, &model.AccessToken{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestOAuthRepository_AccessTokenLongTokenUsesStableLookupValue(t *testing.T) {
	db := setupOAuthRepositoryTestDB(t)
	repo := NewOAuthRepository(db)

	rawToken := strings.Repeat("a", 700)
	accessToken := &model.AccessToken{
		Token:     rawToken,
		ClientID:  "long-token-client",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := repo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}
	if accessToken.Token != rawToken {
		t.Fatalf("returned token should remain raw token")
	}

	var stored model.AccessToken
	if err := db.First(&stored, "id = ?", accessToken.ID).Error; err != nil {
		t.Fatalf("find stored token: %v", err)
	}
	if stored.Token == rawToken {
		t.Fatalf("long access token should not be stored as raw token")
	}
	if len(stored.Token) != 71 || !strings.HasPrefix(stored.Token, "sha256:") {
		t.Fatalf("stored token should be sha256 lookup value, got %q", stored.Token)
	}

	found, err := repo.FindAccessToken(rawToken)
	if err != nil {
		t.Fatalf("find access token by raw token: %v", err)
	}
	if found.Token != rawToken {
		t.Fatalf("found token should expose raw token")
	}

	if err := repo.RevokeAccessToken(rawToken); err != nil {
		t.Fatalf("revoke access token by raw token: %v", err)
	}
	found, err = repo.FindAccessToken(rawToken)
	if err != nil {
		t.Fatalf("find revoked access token by raw token: %v", err)
	}
	if !found.Revoked {
		t.Fatalf("access token should be revoked")
	}
}

func TestOAuthRepository_AccessTokenLookupSupportsLegacyRawLongToken(t *testing.T) {
	db := setupOAuthRepositoryTestDB(t)
	repo := NewOAuthRepository(db)

	rawToken := strings.Repeat("b", 700)
	legacyAccessToken := &model.AccessToken{
		Token:     rawToken,
		ClientID:  "legacy-long-token-client",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := db.Create(legacyAccessToken).Error; err != nil {
		t.Fatalf("create legacy access token: %v", err)
	}

	found, err := repo.FindAccessToken(rawToken)
	if err != nil {
		t.Fatalf("find legacy access token by raw token: %v", err)
	}
	if found.ID != legacyAccessToken.ID {
		t.Fatalf("found legacy access token id=%s want %s", found.ID, legacyAccessToken.ID)
	}

	if err := repo.RevokeAccessToken(rawToken); err != nil {
		t.Fatalf("revoke legacy access token by raw token: %v", err)
	}
	found, err = repo.FindAccessToken(rawToken)
	if err != nil {
		t.Fatalf("find revoked legacy access token by raw token: %v", err)
	}
	if !found.Revoked {
		t.Fatalf("legacy access token should be revoked")
	}
}

func TestOAuthRepository_FindReusableAuthorizationCodeRequiresSameNonce(t *testing.T) {
	db := setupOAuthRepositoryTestDB(t)
	repo := NewOAuthRepository(db)
	userID := uuid.New()

	authCode := &model.AuthorizationCode{
		ClientID:    "nonce-client",
		UserID:      userID,
		RedirectURI: "http://localhost/callback",
		Scope:       "openid profile",
		Nonce:       "nonce-one",
		MaxAge:      -1,
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	if err := repo.CreateAuthorizationCode(authCode); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}

	if _, err := repo.FindReusableAuthorizationCode(userID, authCode.ClientID, authCode.RedirectURI, authCode.Scope, "", "nonce-two", -1); err != ErrAuthCodeNotFound {
		t.Fatalf("FindReusableAuthorizationCode with different nonce err=%v want ErrAuthCodeNotFound", err)
	}

	found, err := repo.FindReusableAuthorizationCode(userID, authCode.ClientID, authCode.RedirectURI, authCode.Scope, "", "nonce-one", -1)
	if err != nil {
		t.Fatalf("FindReusableAuthorizationCode with same nonce: %v", err)
	}
	if found.ID != authCode.ID {
		t.Fatalf("found id=%s want %s", found.ID, authCode.ID)
	}
}

func TestOAuthRepository_FindReusableAuthorizationCodeRequiresSameMaxAge(t *testing.T) {
	db := setupOAuthRepositoryTestDB(t)
	repo := NewOAuthRepository(db)
	userID := uuid.New()

	authCode := &model.AuthorizationCode{
		ClientID:    "max-age-client",
		UserID:      userID,
		RedirectURI: "http://localhost/callback",
		Scope:       "openid profile",
		MaxAge:      300,
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	if err := repo.CreateAuthorizationCode(authCode); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}

	if _, err := repo.FindReusableAuthorizationCode(userID, authCode.ClientID, authCode.RedirectURI, authCode.Scope, "", "", 60); err != ErrAuthCodeNotFound {
		t.Fatalf("FindReusableAuthorizationCode with different max_age err=%v want ErrAuthCodeNotFound", err)
	}

	found, err := repo.FindReusableAuthorizationCode(userID, authCode.ClientID, authCode.RedirectURI, authCode.Scope, "", "", 300)
	if err != nil {
		t.Fatalf("FindReusableAuthorizationCode with same max_age: %v", err)
	}
	if found.ID != authCode.ID {
		t.Fatalf("found id=%s want %s", found.ID, authCode.ID)
	}
}
