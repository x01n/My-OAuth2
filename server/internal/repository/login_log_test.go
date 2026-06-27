package repository

import (
	"testing"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupLoginLogTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.LoginLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestLoginLogRepository_GetTrend_groupsByDayAndFillsMissingDays(t *testing.T) {
	db := setupLoginLogTestDB(t)
	repo := NewLoginLogRepository(db)

	startDate := time.Now().AddDate(0, 0, -2).Truncate(24 * time.Hour)
	userID := uuid.New()
	logs := []model.LoginLog{
		{UserID: &userID, LoginType: model.LoginTypeDirect, Success: true, CreatedAt: startDate.Add(2 * time.Hour)},
		{UserID: &userID, LoginType: model.LoginTypeDirect, Success: false, CreatedAt: startDate.Add(3 * time.Hour)},
		{UserID: &userID, LoginType: model.LoginTypeDirect, Success: true, CreatedAt: startDate.AddDate(0, 0, 2).Add(4 * time.Hour)},
	}
	if err := db.Create(&logs).Error; err != nil {
		t.Fatalf("create logs: %v", err)
	}

	trends, err := repo.GetTrend(2)
	if err != nil {
		t.Fatalf("GetTrend: %v", err)
	}
	if len(trends) != 3 {
		t.Fatalf("len=%d want 3: %#v", len(trends), trends)
	}

	assertTrend := func(index int, date time.Time, total, success, failed int64) {
		t.Helper()
		got := trends[index]
		if got.Date != date.Format("2006-01-02") {
			t.Fatalf("index %d date=%q want %q", index, got.Date, date.Format("2006-01-02"))
		}
		if got.TotalCount != total || got.Success != success || got.Failed != failed {
			t.Fatalf("index %d got total/success/failed=%d/%d/%d want %d/%d/%d",
				index, got.TotalCount, got.Success, got.Failed, total, success, failed)
		}
	}

	assertTrend(0, startDate, 2, 1, 1)
	assertTrend(1, startDate.AddDate(0, 0, 1), 0, 0, 0)
	assertTrend(2, startDate.AddDate(0, 0, 2), 1, 1, 0)
}

func TestLoginLogRepository_FindRecent_preloadsRelationSummariesOnly(t *testing.T) {
	db := setupLoginLogTestDB(t)
	repo := NewLoginLogRepository(db)

	user := &model.User{
		ID:           uuid.New(),
		Email:        "login-summary@example.com",
		Username:     "loginsummary",
		PasswordHash: "hashed-password",
		PhoneNumber:  "+15551234567",
		Address:      `{"formatted":"1 Sensitive Way"}`,
		Metadata:     `{"secret_note":"internal"}`,
		Tags:         "vip,security-review",
		LastLoginIP:  "198.51.100.10",
		FailedLogins: 3,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ID:            uuid.New(),
		ClientID:      "login-summary-client",
		ClientSecret:  "login-summary-secret",
		Name:          "Login Summary App",
		Description:   "description should not be preloaded",
		RedirectURIs:  `["https://client.example/callback"]`,
		Scopes:        `["openid","profile","email"]`,
		UserID:        user.ID,
		GrantTypes:    `["authorization_code","refresh_token"]`,
		AllowedScopes: `["openid","profile","email"]`,
		JWKSURI:       "https://client.example/.well-known/jwks.json",
		JWKS:          `{"keys":[{"kid":"test"}]}`,
	}
	if err := db.Create(app).Error; err != nil {
		t.Fatalf("create app: %v", err)
	}

	log := model.LoginLog{
		UserID:    &user.ID,
		AppID:     &app.ID,
		LoginType: model.LoginTypeOAuth,
		IPAddress: "203.0.113.20",
		UserAgent: "login-summary-test",
		Email:     user.Email,
		Success:   true,
		CreatedAt: time.Now(),
	}
	if err := db.Create(&log).Error; err != nil {
		t.Fatalf("create login log: %v", err)
	}

	logs, total, err := repo.FindRecent(0, 10)
	if err != nil {
		t.Fatalf("find recent: %v", err)
	}
	if total != 1 {
		t.Fatalf("total=%d want 1", total)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs)=%d want 1", len(logs))
	}

	gotUser := logs[0].User
	if gotUser == nil {
		t.Fatalf("preloaded user is nil")
	}
	if gotUser.ID != user.ID || gotUser.Email != user.Email || gotUser.Username != user.Username {
		t.Fatalf("preloaded summary user mismatch: %#v", gotUser)
	}
	if gotUser.PasswordHash != "" || gotUser.PhoneNumber != "" || gotUser.Address != "" || gotUser.Metadata != "" || gotUser.Tags != "" || gotUser.LastLoginIP != "" || gotUser.FailedLogins != 0 {
		t.Fatalf("login log user preload included non-summary fields: %#v", gotUser)
	}

	gotApp := logs[0].App
	if gotApp == nil {
		t.Fatalf("preloaded app is nil")
	}
	if gotApp.ID != app.ID || gotApp.Name != app.Name {
		t.Fatalf("preloaded summary app mismatch: %#v", gotApp)
	}
	if gotApp.ClientID != "" || gotApp.ClientSecret != "" || gotApp.Description != "" || gotApp.RedirectURIs != "" || gotApp.Scopes != "" || gotApp.GrantTypes != "" || gotApp.AllowedScopes != "" || gotApp.JWKSURI != "" || gotApp.JWKS != "" {
		t.Fatalf("login log app preload included non-summary fields: %#v", gotApp)
	}
}
