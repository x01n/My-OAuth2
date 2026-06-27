package repository

import (
	"errors"
	"testing"

	"server/internal/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupSDKExternalIdentityTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.SDKExternalIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestSDKExternalIdentityModel_CreatesSourceIDCompositeUniqueIndex(t *testing.T) {
	db := setupSDKExternalIdentityTestDB(t)

	if !db.Migrator().HasIndex(&model.SDKExternalIdentity{}, "idx_sdk_external_identity_source_id") {
		t.Fatalf("missing idx_sdk_external_identity_source_id")
	}
	columns := sqliteIndexColumns(t, db, "idx_sdk_external_identity_source_id")
	if len(columns) != 2 {
		t.Fatalf("index columns=%v want [external_source external_id]", columns)
	}
	if columns[0] != "external_source" || columns[1] != "external_id" {
		t.Fatalf("index columns=%v want [external_source external_id]", columns)
	}
}

func TestSDKExternalIdentityRepository_FindByExternalIdentityMatchesSourceAndID(t *testing.T) {
	db := setupSDKExternalIdentityTestDB(t)
	userRepo := NewUserRepository(db)
	repo := NewSDKExternalIdentityRepository(db)

	user := &model.User{
		Email:        "sdk-external-identity@example.com",
		Username:     "sdkexternalidentity",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	alphaIdentity := &model.SDKExternalIdentity{
		UserID:         user.ID,
		ExternalSource: "platform-alpha",
		ExternalID:     "shared-external-001",
	}
	if err := repo.Create(alphaIdentity); err != nil {
		t.Fatalf("create alpha identity: %v", err)
	}
	betaIdentity := &model.SDKExternalIdentity{
		UserID:         user.ID,
		ExternalSource: "platform-beta",
		ExternalID:     "shared-external-001",
	}
	if err := repo.Create(betaIdentity); err != nil {
		t.Fatalf("create beta identity: %v", err)
	}

	foundAlpha, err := repo.FindByExternalIdentity("platform-alpha", "shared-external-001")
	if err != nil {
		t.Fatalf("find alpha identity: %v", err)
	}
	if foundAlpha.ID != alphaIdentity.ID || foundAlpha.UserID != user.ID {
		t.Fatalf("found alpha identity=%+v want id=%s user_id=%s", foundAlpha, alphaIdentity.ID, user.ID)
	}

	foundBeta, err := repo.FindByExternalIdentity("platform-beta", "shared-external-001")
	if err != nil {
		t.Fatalf("find beta identity: %v", err)
	}
	if foundBeta.ID != betaIdentity.ID || foundBeta.UserID != user.ID {
		t.Fatalf("found beta identity=%+v want id=%s user_id=%s", foundBeta, betaIdentity.ID, user.ID)
	}

	if _, err := repo.FindByExternalIdentity("platform-gamma", "shared-external-001"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing source error=%v want %v", err, ErrUserNotFound)
	}
	if _, err := repo.FindByExternalIdentity("", "shared-external-001"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("empty source error=%v want %v", err, ErrUserNotFound)
	}
	if _, err := repo.FindByExternalIdentity("platform-alpha", ""); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("empty external id error=%v want %v", err, ErrUserNotFound)
	}
}

func TestSDKExternalIdentityRepository_RejectsDuplicateSourceAndID(t *testing.T) {
	db := setupSDKExternalIdentityTestDB(t)
	userRepo := NewUserRepository(db)
	repo := NewSDKExternalIdentityRepository(db)

	firstUser := &model.User{
		Email:        "sdk-external-first@example.com",
		Username:     "sdkexternalfirst",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(firstUser); err != nil {
		t.Fatalf("create first user: %v", err)
	}
	secondUser := &model.User{
		Email:        "sdk-external-second@example.com",
		Username:     "sdkexternalsecond",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(secondUser); err != nil {
		t.Fatalf("create second user: %v", err)
	}

	firstIdentity := &model.SDKExternalIdentity{
		UserID:         firstUser.ID,
		ExternalSource: "platform-duplicate",
		ExternalID:     "external-duplicate-001",
	}
	if err := repo.Create(firstIdentity); err != nil {
		t.Fatalf("create first identity: %v", err)
	}

	duplicateIdentity := &model.SDKExternalIdentity{
		UserID:         secondUser.ID,
		ExternalSource: firstIdentity.ExternalSource,
		ExternalID:     firstIdentity.ExternalID,
	}
	if err := repo.Create(duplicateIdentity); !errors.Is(err, ErrSDKExternalIdentityAlreadyExists) {
		t.Fatalf("duplicate identity error=%v want %v", err, ErrSDKExternalIdentityAlreadyExists)
	}
}
