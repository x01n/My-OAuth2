package service

import (
	"testing"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
	"server/pkg/password"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupPasswordResetServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.PasswordReset{}, &model.AccessToken{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestPasswordResetService_ResetPasswordRevokesTokensAndResetLinks(t *testing.T) {
	db := setupPasswordResetServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	resetRepo := repository.NewPasswordResetRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	jwtManager := jwt.NewManager("test-secret-with-enough-length", "test")

	hash, err := password.Hash("OldPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.New(),
		Email:        "reset-security@example.com",
		Username:     "resetsecurity",
		PasswordHash: hash,
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	service := NewPasswordResetService(userRepo, resetRepo)
	service.SetOAuthRepo(oauthRepo)

	resetToken, err := service.RequestPasswordReset(user.Email, "192.0.2.10", "reset-test")
	if err != nil {
		t.Fatalf("request reset token: %v", err)
	}
	otherResetToken, err := service.RequestPasswordReset(user.Email, "192.0.2.11", "reset-test")
	if err != nil {
		t.Fatalf("request other reset token: %v", err)
	}

	accessToken := &model.AccessToken{
		Token:     "reset-security-access-token",
		ClientID:  "reset-security-client",
		UserID:    &user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := oauthRepo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}

	authRefreshToken, err := jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeRefresh, time.Hour)
	if err != nil {
		t.Fatalf("generate auth refresh token: %v", err)
	}
	refreshClaims, err := jwtManager.ValidateRefreshToken(authRefreshToken)
	if err != nil {
		t.Fatalf("validate auth refresh token: %v", err)
	}
	if err := oauthRepo.StoreAuthRefreshToken(refreshClaims.ID, user.ID, refreshClaims.ExpiresAt.Time); err != nil {
		t.Fatalf("store auth refresh token: %v", err)
	}

	if err := service.ResetPassword(resetToken, "NewPass123!"); err != nil {
		t.Fatalf("reset password: %v", err)
	}

	if _, err := service.ValidateResetToken(resetToken); err == nil {
		t.Fatalf("used reset token should be invalid")
	}
	if _, err := service.ValidateResetToken(otherResetToken); err == nil {
		t.Fatalf("other reset token should be invalid")
	}

	var activeAccessCount int64
	db.Model(&model.AccessToken{}).
		Where("user_id = ? AND revoked = ?", user.ID, false).
		Count(&activeAccessCount)
	if activeAccessCount != 0 {
		t.Fatalf("active access token count=%d want 0", activeAccessCount)
	}

	storedRefreshToken, err := oauthRepo.FindAuthRefreshToken(refreshClaims.ID)
	if err != nil {
		t.Fatalf("find auth refresh token: %v", err)
	}
	if !storedRefreshToken.Revoked {
		t.Fatalf("auth refresh token should be revoked after password reset")
	}
}
