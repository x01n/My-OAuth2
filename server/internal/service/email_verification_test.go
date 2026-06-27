package service

import (
	"testing"
	"time"

	"server/internal/model"
	"server/internal/repository"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupEmailVerificationServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.EmailVerification{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestEmailVerificationService_VerifyEmailChangesEmailAndInvalidatesTokens(t *testing.T) {
	db := setupEmailVerificationServiceTestDB(t)
	userRepo := repository.NewUserRepository(db)
	verifyRepo := repository.NewEmailVerificationRepository(db)

	user := &model.User{
		ID:            uuid.New(),
		Email:         "old-email@example.com",
		Username:      "emailchange",
		PasswordHash:  "hashed-password",
		Status:        "active",
		EmailVerified: false,
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	emailChange := &model.EmailVerification{
		UserID:    user.ID,
		Email:     "new-email@example.com",
		Token:     "email-change-token",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := verifyRepo.Create(emailChange); err != nil {
		t.Fatalf("create email change token: %v", err)
	}
	otherVerification := &model.EmailVerification{
		UserID:    user.ID,
		Email:     user.Email,
		Token:     "other-email-token",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := verifyRepo.Create(otherVerification); err != nil {
		t.Fatalf("create other verification token: %v", err)
	}

	service := NewEmailVerificationService(userRepo, verifyRepo)
	if err := service.VerifyEmail(emailChange.Token); err != nil {
		t.Fatalf("verify email: %v", err)
	}

	updatedUser, err := userRepo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("find updated user: %v", err)
	}
	if updatedUser.Email != "new-email@example.com" {
		t.Fatalf("email=%q want %q", updatedUser.Email, "new-email@example.com")
	}
	if !updatedUser.EmailVerified {
		t.Fatalf("email should be verified")
	}

	if err := service.VerifyEmail(emailChange.Token); err == nil {
		t.Fatalf("used email change token should be invalid")
	}
	if _, err := verifyRepo.FindValidByToken(otherVerification.Token); err == nil {
		t.Fatalf("other email verification token should be invalid")
	}
}
