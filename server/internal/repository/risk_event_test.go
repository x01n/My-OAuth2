package repository

import (
	"testing"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupRiskEventTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

type sqliteIndexColumn struct {
	Seqno int    `gorm:"column:seqno"`
	Name  string `gorm:"column:name"`
}

func sqliteIndexColumns(t *testing.T, db *gorm.DB, indexName string) []string {
	t.Helper()

	var rows []sqliteIndexColumn
	if err := db.Raw("PRAGMA index_info(" + indexName + ")").Scan(&rows).Error; err != nil {
		t.Fatalf("read index info %s: %v", indexName, err)
	}
	columns := make([]string, len(rows))
	for _, row := range rows {
		if row.Seqno < 0 || row.Seqno >= len(rows) {
			t.Fatalf("index %s seqno=%d out of range", indexName, row.Seqno)
		}
		columns[row.Seqno] = row.Name
	}
	return columns
}

func TestRiskEventModel_CreatesDecisionCreatedAtCompositeIndex(t *testing.T) {
	db := setupRiskEventTestDB(t)

	if !db.Migrator().HasIndex(&model.RiskEvent{}, "idx_risk_events_decision_created_at") {
		t.Fatalf("missing idx_risk_events_decision_created_at")
	}
	columns := sqliteIndexColumns(t, db, "idx_risk_events_decision_created_at")
	if len(columns) != 2 {
		t.Fatalf("index columns=%v want [decision created_at]", columns)
	}
	if columns[0] != "decision" || columns[1] != "created_at" {
		t.Fatalf("index columns=%v want [decision created_at]", columns)
	}
}

func TestRiskEventModel_CreatesReasonCreatedAtCompositeIndex(t *testing.T) {
	db := setupRiskEventTestDB(t)

	if !db.Migrator().HasIndex(&model.RiskEvent{}, "idx_risk_events_reason_created_at") {
		t.Fatalf("missing idx_risk_events_reason_created_at")
	}
	columns := sqliteIndexColumns(t, db, "idx_risk_events_reason_created_at")
	if len(columns) != 2 {
		t.Fatalf("index columns=%v want [reason created_at]", columns)
	}
	if columns[0] != "reason" || columns[1] != "created_at" {
		t.Fatalf("index columns=%v want [reason created_at]", columns)
	}
}

func TestRiskEventRepository_FindRecent_ordersByCreatedAtAndPreloadsUser(t *testing.T) {
	db := setupRiskEventTestDB(t)
	repo := NewRiskEventRepository(db)

	user := &model.User{
		ID:       uuid.New(),
		Email:    "risk-list@example.com",
		Username: "risklist",
		Status:   "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	older := model.RiskEvent{
		UserID:    &user.ID,
		RiskScore: 50,
		Decision:  model.RiskDecisionChallenge,
		CreatedAt: time.Now().Add(-time.Hour),
	}
	newer := model.RiskEvent{
		UserID:    &user.ID,
		RiskScore: 80,
		Decision:  model.RiskDecisionBlock,
		CreatedAt: time.Now(),
	}
	if err := db.Create(&older).Error; err != nil {
		t.Fatalf("create older event: %v", err)
	}
	if err := db.Create(&newer).Error; err != nil {
		t.Fatalf("create newer event: %v", err)
	}

	events, total, err := repo.FindRecent(0, 1)
	if err != nil {
		t.Fatalf("find recent: %v", err)
	}
	if total != 2 {
		t.Fatalf("total=%d want 2", total)
	}
	if len(events) != 1 {
		t.Fatalf("len(events)=%d want 1", len(events))
	}
	if events[0].ID != newer.ID {
		t.Fatalf("first event id=%s want %s", events[0].ID, newer.ID)
	}
	if events[0].User == nil || events[0].User.Email != user.Email {
		t.Fatalf("expected preloaded user email %q, got %#v", user.Email, events[0].User)
	}
}

func TestRiskEventRepository_FindRecent_preloadsUserSummaryOnly(t *testing.T) {
	db := setupRiskEventTestDB(t)
	repo := NewRiskEventRepository(db)

	user := &model.User{
		ID:           uuid.New(),
		Email:        "risk-summary@example.com",
		Username:     "risksummary",
		Avatar:       "https://cdn.example/avatar.png",
		Status:       "active",
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

	event := model.RiskEvent{
		UserID:    &user.ID,
		RiskScore: 80,
		Decision:  model.RiskDecisionBlock,
		CreatedAt: time.Now(),
	}
	if err := db.Create(&event).Error; err != nil {
		t.Fatalf("create risk event: %v", err)
	}

	events, total, err := repo.FindRecent(0, 10)
	if err != nil {
		t.Fatalf("find recent: %v", err)
	}
	if total != 1 {
		t.Fatalf("total=%d want 1", total)
	}
	if len(events) != 1 {
		t.Fatalf("len(events)=%d want 1", len(events))
	}
	got := events[0].User
	if got == nil {
		t.Fatalf("preloaded user is nil")
	}
	if got.ID != user.ID || got.Email != user.Email || got.Username != user.Username || got.Avatar != user.Avatar || got.Status != user.Status {
		t.Fatalf("preloaded summary user mismatch: %#v", got)
	}
	if got.PasswordHash != "" || got.PhoneNumber != "" || got.Address != "" || got.Metadata != "" || got.Tags != "" || got.LastLoginIP != "" || got.FailedLogins != 0 {
		t.Fatalf("risk event user preload included non-summary fields: %#v", got)
	}
}

func TestRiskEventRepository_FindRecentByDecision_filtersAndCounts(t *testing.T) {
	db := setupRiskEventTestDB(t)
	repo := NewRiskEventRepository(db)

	user := &model.User{
		ID:       uuid.New(),
		Email:    "risk-filter@example.com",
		Username: "riskfilter",
		Status:   "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	eventsToCreate := []model.RiskEvent{
		{UserID: &user.ID, RiskScore: 50, Decision: model.RiskDecisionChallenge, CreatedAt: time.Now().Add(-2 * time.Hour)},
		{UserID: &user.ID, RiskScore: 80, Decision: model.RiskDecisionBlock, CreatedAt: time.Now().Add(-time.Hour)},
		{UserID: &user.ID, RiskScore: 90, Decision: model.RiskDecisionBlock, CreatedAt: time.Now()},
	}
	for i := range eventsToCreate {
		if err := db.Create(&eventsToCreate[i]).Error; err != nil {
			t.Fatalf("create event %d: %v", i, err)
		}
	}

	events, total, err := repo.FindRecentByDecision(model.RiskDecisionBlock, 0, 10)
	if err != nil {
		t.Fatalf("find recent by decision: %v", err)
	}
	if total != 2 {
		t.Fatalf("total=%d want 2", total)
	}
	if len(events) != 2 {
		t.Fatalf("len(events)=%d want 2", len(events))
	}
	for _, event := range events {
		if event.Decision != model.RiskDecisionBlock {
			t.Fatalf("decision=%s want %s", event.Decision, model.RiskDecisionBlock)
		}
	}
	if events[0].CreatedAt.Before(events[1].CreatedAt) {
		t.Fatalf("events are not ordered by created_at desc")
	}
}

func TestRiskEventRepository_FindRecentByDecision_appliesPaginationAfterFilter(t *testing.T) {
	db := setupRiskEventTestDB(t)
	repo := NewRiskEventRepository(db)

	user := &model.User{
		ID:       uuid.New(),
		Email:    "risk-filter-page@example.com",
		Username: "riskfilterpage",
		Status:   "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now()
	eventsToCreate := []model.RiskEvent{
		{UserID: &user.ID, RiskScore: 50, Decision: model.RiskDecisionChallenge, CreatedAt: now.Add(time.Hour)},
		{UserID: &user.ID, RiskScore: 70, Decision: model.RiskDecisionBlock, CreatedAt: now.Add(30 * time.Minute)},
		{UserID: &user.ID, RiskScore: 80, Decision: model.RiskDecisionBlock, CreatedAt: now.Add(20 * time.Minute)},
		{UserID: &user.ID, RiskScore: 90, Decision: model.RiskDecisionBlock, CreatedAt: now.Add(10 * time.Minute)},
	}
	for i := range eventsToCreate {
		if err := db.Create(&eventsToCreate[i]).Error; err != nil {
			t.Fatalf("create event %d: %v", i, err)
		}
	}

	events, total, err := repo.FindRecentByDecision(model.RiskDecisionBlock, 1, 1)
	if err != nil {
		t.Fatalf("find recent by decision: %v", err)
	}
	if total != 3 {
		t.Fatalf("total=%d want 3", total)
	}
	if len(events) != 1 {
		t.Fatalf("len(events)=%d want 1", len(events))
	}
	if events[0].RiskScore != 80 || events[0].Decision != model.RiskDecisionBlock {
		t.Fatalf("unexpected paged event: %#v", events[0])
	}
	if events[0].User == nil || events[0].User.Email != user.Email {
		t.Fatalf("expected preloaded user email %q, got %#v", user.Email, events[0].User)
	}
}

func TestRiskEventRepository_FindRecentFiltered_filtersByReasonAndDecision(t *testing.T) {
	db := setupRiskEventTestDB(t)
	repo := NewRiskEventRepository(db)

	user := &model.User{
		ID:       uuid.New(),
		Email:    "risk-reason-filter@example.com",
		Username: "riskreasonfilter",
		Status:   "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now()
	eventsToCreate := []model.RiskEvent{
		{UserID: &user.ID, RiskScore: 50, Decision: model.RiskDecisionChallenge, Reason: model.RiskEventReasonCSRFTokenMissing, CreatedAt: now.Add(-3 * time.Hour)},
		{UserID: &user.ID, RiskScore: 80, Decision: model.RiskDecisionBlock, Reason: model.RiskEventReasonRefreshTokenReplay, CreatedAt: now.Add(-2 * time.Hour)},
		{UserID: &user.ID, RiskScore: 90, Decision: model.RiskDecisionBlock, Reason: model.RiskEventReasonSDKExternalIdentityConflict, CreatedAt: now.Add(-time.Hour)},
		{UserID: &user.ID, RiskScore: 95, Decision: model.RiskDecisionBlock, Reason: model.RiskEventReasonRefreshTokenReplay, CreatedAt: now},
	}
	for i := range eventsToCreate {
		if err := db.Create(&eventsToCreate[i]).Error; err != nil {
			t.Fatalf("create event %d: %v", i, err)
		}
	}

	decision := model.RiskDecisionBlock
	events, total, err := repo.FindRecentFiltered(RiskEventFilter{
		Decision: &decision,
		Reason:   model.RiskEventReasonRefreshTokenReplay,
	}, 0, 10)
	if err != nil {
		t.Fatalf("find recent filtered: %v", err)
	}
	if total != 2 {
		t.Fatalf("total=%d want 2", total)
	}
	if len(events) != 2 {
		t.Fatalf("len(events)=%d want 2", len(events))
	}
	for _, event := range events {
		if event.Decision != model.RiskDecisionBlock {
			t.Fatalf("decision=%s want %s", event.Decision, model.RiskDecisionBlock)
		}
		if event.Reason != model.RiskEventReasonRefreshTokenReplay {
			t.Fatalf("reason=%q want %q", event.Reason, model.RiskEventReasonRefreshTokenReplay)
		}
	}
	if events[0].CreatedAt.Before(events[1].CreatedAt) {
		t.Fatalf("events are not ordered by created_at desc")
	}
	if events[0].RiskScore != 95 {
		t.Fatalf("first risk_score=%d want 95", events[0].RiskScore)
	}
}
