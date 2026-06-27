package repository

import (
	"errors"
	"testing"

	"server/internal/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupUserModelTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestUserModel_CreatesExternalSourceIDCompositeIndex(t *testing.T) {
	db := setupUserModelTestDB(t)

	if !db.Migrator().HasIndex(&model.User{}, "idx_users_external_source_id") {
		t.Fatalf("missing idx_users_external_source_id")
	}
	columns := sqliteIndexColumns(t, db, "idx_users_external_source_id")
	if len(columns) != 2 {
		t.Fatalf("index columns=%v want [external_source external_id]", columns)
	}
	if columns[0] != "external_source" || columns[1] != "external_id" {
		t.Fatalf("index columns=%v want [external_source external_id]", columns)
	}
}

func TestUserRepository_FindByExternalIdentityMatchesSourceAndID(t *testing.T) {
	db := setupUserModelTestDB(t)
	repo := NewUserRepository(db)

	alphaUser := &model.User{
		Email:          "external-alpha@example.com",
		Username:       "externalalpha",
		PasswordHash:   "hashed-password",
		Status:         "active",
		ExternalSource: "platform-alpha",
		ExternalID:     "shared-external-001",
	}
	if err := repo.Create(alphaUser); err != nil {
		t.Fatalf("create alpha user: %v", err)
	}

	betaUser := &model.User{
		Email:          "external-beta@example.com",
		Username:       "externalbeta",
		PasswordHash:   "hashed-password",
		Status:         "active",
		ExternalSource: "platform-beta",
		ExternalID:     "shared-external-001",
	}
	if err := repo.Create(betaUser); err != nil {
		t.Fatalf("create beta user: %v", err)
	}

	foundAlpha, err := repo.FindByExternalIdentity("platform-alpha", "shared-external-001")
	if err != nil {
		t.Fatalf("find alpha external identity: %v", err)
	}
	if foundAlpha.ID != alphaUser.ID {
		t.Fatalf("found alpha id=%s want %s", foundAlpha.ID, alphaUser.ID)
	}

	foundBeta, err := repo.FindByExternalIdentity("platform-beta", "shared-external-001")
	if err != nil {
		t.Fatalf("find beta external identity: %v", err)
	}
	if foundBeta.ID != betaUser.ID {
		t.Fatalf("found beta id=%s want %s", foundBeta.ID, betaUser.ID)
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
