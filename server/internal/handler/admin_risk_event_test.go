package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"server/internal/model"
	"server/internal/repository"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAdminHandler_GetRiskEvents_returnsPagedEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := &model.User{
		ID:       uuid.New(),
		Email:    "admin-risk@example.com",
		Username: "adminrisk",
		Status:   "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	event := &model.RiskEvent{
		UserID:    &user.ID,
		RiskScore: 80,
		Decision:  model.RiskDecisionBlock,
	}
	if err := db.Create(event).Error; err != nil {
		t.Fatalf("create risk event: %v", err)
	}

	handler := NewAdminHandler(nil, nil, nil, repository.NewRiskEventRepository(db), nil)
	router := gin.New()
	router.GET("/risk-events", handler.GetRiskEvents)

	req := httptest.NewRequest(http.MethodGet, "/risk-events?page=1&limit=20", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Events []model.RiskEvent `json:"events"`
			Total  int64             `json:"total"`
			Page   int               `json:"page"`
			Limit  int               `json:"limit"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Success {
		t.Fatalf("success=false body=%s", rec.Body.String())
	}
	if body.Data.Total != 1 || body.Data.Page != 1 || body.Data.Limit != 20 {
		t.Fatalf("unexpected pagination: total=%d page=%d limit=%d", body.Data.Total, body.Data.Page, body.Data.Limit)
	}
	if len(body.Data.Events) != 1 {
		t.Fatalf("len(events)=%d want 1", len(body.Data.Events))
	}
	if body.Data.Events[0].RiskScore != 80 || body.Data.Events[0].Decision != model.RiskDecisionBlock {
		t.Fatalf("unexpected event: %#v", body.Data.Events[0])
	}
	if body.Data.Events[0].User == nil || body.Data.Events[0].User.Email != user.Email {
		t.Fatalf("expected preloaded user email %q, got %#v", user.Email, body.Data.Events[0].User)
	}
}

func TestAdminHandler_GetRiskEvents_returnsUserSummaryOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := &model.User{
		ID:           uuid.New(),
		Email:        "admin-risk-summary@example.com",
		Username:     "adminrisksummary",
		PhoneNumber:  "+15551234567",
		Address:      `{"formatted":"1 Sensitive Way"}`,
		Metadata:     `{"secret_note":"internal"}`,
		Tags:         "vip,security-review",
		Status:       "active",
		PasswordHash: "hashed-password",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	event := &model.RiskEvent{
		UserID:    &user.ID,
		RiskScore: 90,
		Decision:  model.RiskDecisionBlock,
		IPAddress: "203.0.113.44",
		UserAgent: "curl/8.0",
		Reason:    model.RiskEventReasonSuspiciousLogin,
	}
	if err := db.Create(event).Error; err != nil {
		t.Fatalf("create risk event: %v", err)
	}

	handler := NewAdminHandler(nil, nil, nil, repository.NewRiskEventRepository(db), nil)
	router := gin.New()
	router.GET("/risk-events", handler.GetRiskEvents)

	req := httptest.NewRequest(http.MethodGet, "/risk-events", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Events []map[string]any `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if len(body.Data.Events) != 1 {
		t.Fatalf("len(events)=%d want 1", len(body.Data.Events))
	}
	riskUser, ok := body.Data.Events[0]["user"].(map[string]any)
	if !ok {
		t.Fatalf("risk event user missing or wrong type: %#v", body.Data.Events[0]["user"])
	}
	for _, forbidden := range []string{"phone_number", "address", "metadata", "tags", "password_hash", "last_login_ip", "failed_logins", "locked_until"} {
		if _, exists := riskUser[forbidden]; exists {
			t.Fatalf("risk event user should not expose %q: %#v", forbidden, riskUser)
		}
	}
	if riskUser["id"] != user.ID.String() || riskUser["email"] != user.Email || riskUser["username"] != user.Username {
		t.Fatalf("unexpected risk event user summary: %#v", riskUser)
	}
}

func TestAdminHandler_GetLoginLogs_returnsRelationSummariesOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.LoginLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := &model.User{
		ID:           uuid.New(),
		Email:        "admin-login-log@example.com",
		Username:     "adminloginlog",
		PhoneNumber:  "+15557654321",
		Address:      `{"formatted":"2 Sensitive Way"}`,
		Metadata:     `{"secret_note":"internal"}`,
		Tags:         "vip,security-review",
		Status:       "active",
		PasswordHash: "hashed-password",
		LastLoginIP:  "198.51.100.12",
		FailedLogins: 3,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	app := &model.Application{
		ID:                      uuid.New(),
		ClientID:                "login-log-client",
		ClientSecret:            "stored-client-secret",
		Name:                    "Login Log App",
		Description:             "internal description",
		RedirectURIs:            `["https://client.example/callback"]`,
		Scopes:                  `["openid","profile"]`,
		UserID:                  user.ID,
		AppType:                 model.AppTypeConfidential,
		TokenEndpointAuthMethod: model.AuthMethodClientSecretBasic,
		GrantTypes:              `["authorization_code"]`,
		AllowedScopes:           `["openid","profile"]`,
		JWKSURI:                 "https://client.example/jwks.json",
		JWKS:                    `{"keys":[]}`,
	}
	if err := db.Create(app).Error; err != nil {
		t.Fatalf("create app: %v", err)
	}
	log := &model.LoginLog{
		UserID:    &user.ID,
		AppID:     &app.ID,
		LoginType: model.LoginTypeOAuth,
		IPAddress: "203.0.113.77",
		UserAgent: "Mozilla/5.0",
		Success:   true,
		Email:     user.Email,
	}
	if err := db.Create(log).Error; err != nil {
		t.Fatalf("create login log: %v", err)
	}

	handler := NewAdminHandler(nil, nil, repository.NewLoginLogRepository(db), nil, nil)
	router := gin.New()
	router.GET("/login-logs", handler.GetLoginLogs)

	req := httptest.NewRequest(http.MethodGet, "/login-logs", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Logs []map[string]any `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if len(body.Data.Logs) != 1 {
		t.Fatalf("len(logs)=%d want 1", len(body.Data.Logs))
	}
	loginUser, ok := body.Data.Logs[0]["user"].(map[string]any)
	if !ok {
		t.Fatalf("login log user missing or wrong type: %#v", body.Data.Logs[0]["user"])
	}
	for _, forbidden := range []string{"phone_number", "address", "metadata", "tags", "password_hash", "last_login_ip", "failed_logins", "locked_until", "applications"} {
		if _, exists := loginUser[forbidden]; exists {
			t.Fatalf("login log user should not expose %q: %#v", forbidden, loginUser)
		}
	}
	if loginUser["id"] != user.ID.String() || loginUser["email"] != user.Email || loginUser["username"] != user.Username {
		t.Fatalf("unexpected login log user summary: %#v", loginUser)
	}

	loginApp, ok := body.Data.Logs[0]["app"].(map[string]any)
	if !ok {
		t.Fatalf("login log app missing or wrong type: %#v", body.Data.Logs[0]["app"])
	}
	for _, forbidden := range []string{"client_id", "client_secret", "description", "redirect_uris", "scopes", "grant_types", "allowed_scopes", "jwks_uri", "user"} {
		if _, exists := loginApp[forbidden]; exists {
			t.Fatalf("login log app should not expose %q: %#v", forbidden, loginApp)
		}
	}
	if loginApp["id"] != app.ID.String() || loginApp["name"] != app.Name {
		t.Fatalf("unexpected login log app summary: %#v", loginApp)
	}
}

func TestAdminHandler_GetRiskEvents_clampsPaginationLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := &model.User{
		ID:       uuid.New(),
		Email:    "admin-risk-limit@example.com",
		Username: "adminrisklimit",
		Status:   "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	for i := 0; i < 25; i++ {
		event := &model.RiskEvent{
			UserID:    &user.ID,
			RiskScore: 50,
			Decision:  model.RiskDecisionChallenge,
		}
		if err := db.Create(event).Error; err != nil {
			t.Fatalf("create risk event %d: %v", i, err)
		}
	}

	handler := NewAdminHandler(nil, nil, nil, repository.NewRiskEventRepository(db), nil)
	router := gin.New()
	router.GET("/risk-events", handler.GetRiskEvents)

	req := httptest.NewRequest(http.MethodGet, "/risk-events?page=-2&limit=500", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Events []model.RiskEvent `json:"events"`
			Total  int64             `json:"total"`
			Page   int               `json:"page"`
			Limit  int               `json:"limit"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Success {
		t.Fatalf("success=false body=%s", rec.Body.String())
	}
	if body.Data.Total != 25 || body.Data.Page != 1 || body.Data.Limit != 20 {
		t.Fatalf("unexpected pagination: total=%d page=%d limit=%d", body.Data.Total, body.Data.Page, body.Data.Limit)
	}
	if len(body.Data.Events) != 20 {
		t.Fatalf("len(events)=%d want 20", len(body.Data.Events))
	}
}

func TestAdminHandler_GetRiskEvents_filtersByDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := &model.User{
		ID:       uuid.New(),
		Email:    "admin-risk-filter@example.com",
		Username: "adminriskfilter",
		Status:   "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	eventsToCreate := []model.RiskEvent{
		{UserID: &user.ID, RiskScore: 50, Decision: model.RiskDecisionChallenge},
		{UserID: &user.ID, RiskScore: 80, Decision: model.RiskDecisionBlock},
		{UserID: &user.ID, RiskScore: 90, Decision: model.RiskDecisionBlock},
	}
	for i := range eventsToCreate {
		if err := db.Create(&eventsToCreate[i]).Error; err != nil {
			t.Fatalf("create risk event %d: %v", i, err)
		}
	}

	handler := NewAdminHandler(nil, nil, nil, repository.NewRiskEventRepository(db), nil)
	router := gin.New()
	router.GET("/risk-events", handler.GetRiskEvents)

	req := httptest.NewRequest(http.MethodGet, "/risk-events?page=1&limit=20&decision=block", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Events   []model.RiskEvent `json:"events"`
			Total    int64             `json:"total"`
			Page     int               `json:"page"`
			Limit    int               `json:"limit"`
			Decision string            `json:"decision"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Success {
		t.Fatalf("success=false body=%s", rec.Body.String())
	}
	if body.Data.Total != 2 || body.Data.Page != 1 || body.Data.Limit != 20 || body.Data.Decision != "block" {
		t.Fatalf("unexpected response metadata: total=%d page=%d limit=%d decision=%q", body.Data.Total, body.Data.Page, body.Data.Limit, body.Data.Decision)
	}
	if len(body.Data.Events) != 2 {
		t.Fatalf("len(events)=%d want 2", len(body.Data.Events))
	}
	for _, event := range body.Data.Events {
		if event.Decision != model.RiskDecisionBlock {
			t.Fatalf("decision=%s want %s", event.Decision, model.RiskDecisionBlock)
		}
	}
}

func TestAdminHandler_GetRiskEvents_paginatesFilteredDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := &model.User{
		ID:       uuid.New(),
		Email:    "admin-risk-filter-page@example.com",
		Username: "adminriskfilterpage",
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
			t.Fatalf("create risk event %d: %v", i, err)
		}
	}

	handler := NewAdminHandler(nil, nil, nil, repository.NewRiskEventRepository(db), nil)
	router := gin.New()
	router.GET("/risk-events", handler.GetRiskEvents)

	req := httptest.NewRequest(http.MethodGet, "/risk-events?page=2&limit=1&decision=block", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Events   []model.RiskEvent `json:"events"`
			Total    int64             `json:"total"`
			Page     int               `json:"page"`
			Limit    int               `json:"limit"`
			Decision string            `json:"decision"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Success {
		t.Fatalf("success=false body=%s", rec.Body.String())
	}
	if body.Data.Total != 3 || body.Data.Page != 2 || body.Data.Limit != 1 || body.Data.Decision != "block" {
		t.Fatalf("unexpected response metadata: total=%d page=%d limit=%d decision=%q", body.Data.Total, body.Data.Page, body.Data.Limit, body.Data.Decision)
	}
	if len(body.Data.Events) != 1 {
		t.Fatalf("len(events)=%d want 1", len(body.Data.Events))
	}
	if body.Data.Events[0].RiskScore != 80 || body.Data.Events[0].Decision != model.RiskDecisionBlock {
		t.Fatalf("unexpected paged event: %#v", body.Data.Events[0])
	}
}

func TestAdminHandler_GetRiskEvents_filtersByReasonAndDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := &model.User{
		ID:       uuid.New(),
		Email:    "admin-risk-reason-filter@example.com",
		Username: "adminriskreasonfilter",
		Status:   "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	eventsToCreate := []model.RiskEvent{
		{UserID: &user.ID, RiskScore: 50, Decision: model.RiskDecisionChallenge, Reason: model.RiskEventReasonCSRFTokenMissing},
		{UserID: &user.ID, RiskScore: 80, Decision: model.RiskDecisionBlock, Reason: model.RiskEventReasonRefreshTokenReplay},
		{UserID: &user.ID, RiskScore: 90, Decision: model.RiskDecisionBlock, Reason: model.RiskEventReasonSDKExternalIdentityConflict},
	}
	for i := range eventsToCreate {
		if err := db.Create(&eventsToCreate[i]).Error; err != nil {
			t.Fatalf("create risk event %d: %v", i, err)
		}
	}

	handler := NewAdminHandler(nil, nil, nil, repository.NewRiskEventRepository(db), nil)
	router := gin.New()
	router.GET("/risk-events", handler.GetRiskEvents)

	req := httptest.NewRequest(http.MethodGet, "/risk-events?page=1&limit=20&decision=block&reason=refresh+token+replay", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Events   []model.RiskEvent `json:"events"`
			Total    int64             `json:"total"`
			Page     int               `json:"page"`
			Limit    int               `json:"limit"`
			Decision string            `json:"decision"`
			Reason   string            `json:"reason"`
			Reasons  []string          `json:"reasons"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Success {
		t.Fatalf("success=false body=%s", rec.Body.String())
	}
	if body.Data.Total != 1 || body.Data.Page != 1 || body.Data.Limit != 20 || body.Data.Decision != "block" || body.Data.Reason != model.RiskEventReasonRefreshTokenReplay {
		t.Fatalf("unexpected response metadata: total=%d page=%d limit=%d decision=%q reason=%q", body.Data.Total, body.Data.Page, body.Data.Limit, body.Data.Decision, body.Data.Reason)
	}
	if len(body.Data.Reasons) == 0 {
		t.Fatalf("reasons should not be empty")
	}
	if len(body.Data.Events) != 1 {
		t.Fatalf("len(events)=%d want 1", len(body.Data.Events))
	}
	if body.Data.Events[0].Decision != model.RiskDecisionBlock || body.Data.Events[0].Reason != model.RiskEventReasonRefreshTokenReplay {
		t.Fatalf("unexpected event: %#v", body.Data.Events[0])
	}
}

func TestAdminHandler_GetRiskEvents_rejectsInvalidDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	handler := NewAdminHandler(nil, nil, nil, repository.NewRiskEventRepository(db), nil)
	router := gin.New()
	router.GET("/risk-events", handler.GetRiskEvents)

	req := httptest.NewRequest(http.MethodGet, "/risk-events?decision=invalid", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestAdminHandler_GetRiskEvents_rejectsInvalidReason(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RiskEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	handler := NewAdminHandler(nil, nil, nil, repository.NewRiskEventRepository(db), nil)
	router := gin.New()
	router.GET("/risk-events", handler.GetRiskEvents)

	req := httptest.NewRequest(http.MethodGet, "/risk-events?reason=unknown", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
