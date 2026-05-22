package repository

import (
	"testing"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupWebhookTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.Webhook{}, &model.WebhookDelivery{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestWebhookRepository_Delete_cascadesDeliveries(t *testing.T) {
	db := setupWebhookTestDB(t)
	repo := NewWebhookRepository(db)

	appID := uuid.New()
	wh := &model.Webhook{AppID: appID, URL: "https://example.com/hook", Events: "*", Active: true}
	if err := repo.Create(wh); err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	for i := 0; i < 3; i++ {
		d := &model.WebhookDelivery{
			WebhookID: wh.ID,
			Event:     model.WebhookEventUserLogin,
			Payload:   `{"ok":true}`,
		}
		if err := repo.CreateDelivery(d); err != nil {
			t.Fatalf("create delivery: %v", err)
		}
	}

	if err := repo.Delete(wh.ID); err != nil {
		t.Fatalf("delete webhook: %v", err)
	}

	var deliveryCount int64
	db.Model(&model.WebhookDelivery{}).Where("webhook_id = ?", wh.ID).Count(&deliveryCount)
	if deliveryCount != 0 {
		t.Fatalf("expected 0 deliveries, got %d", deliveryCount)
	}

	var webhookCount int64
	db.Model(&model.Webhook{}).Where("id = ?", wh.ID).Count(&webhookCount)
	if webhookCount != 0 {
		t.Fatalf("expected webhook deleted")
	}
}

func TestWebhookRepository_DeleteByAppID_cascadesDeliveries(t *testing.T) {
	db := setupWebhookTestDB(t)
	repo := NewWebhookRepository(db)

	appID := uuid.New()
	wh := &model.Webhook{AppID: appID, URL: "https://example.com/hook", Events: "*", Active: true}
	if err := repo.Create(wh); err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	if err := repo.CreateDelivery(&model.WebhookDelivery{
		WebhookID: wh.ID,
		Event:     model.WebhookEventTokenIssued,
		Payload:   `{}`,
	}); err != nil {
		t.Fatalf("create delivery: %v", err)
	}

	if err := repo.DeleteByAppID(appID); err != nil {
		t.Fatalf("delete by app: %v", err)
	}

	var n int64
	db.Model(&model.WebhookDelivery{}).Count(&n)
	if n != 0 {
		t.Fatalf("expected no deliveries left, got %d", n)
	}
}
