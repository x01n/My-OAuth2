package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type LDAPAuthHandler struct {
	ldapAuthService *service.LDAPAuthService
	cfg             *config.Config
	webhookService  *service.WebhookService
}

type LDAPLoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

func NewLDAPAuthHandler(ldapAuthService *service.LDAPAuthService, cfg *config.Config) *LDAPAuthHandler {
	return &LDAPAuthHandler{ldapAuthService: ldapAuthService, cfg: cfg}
}

func (h *LDAPAuthHandler) SetWebhookService(ws *service.WebhookService) {
	h.webhookService = ws
}

func (h *LDAPAuthHandler) Login(c *gin.Context) {
	var req LDAPLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, ErrCodeBadRequest, err.Error())
		return
	}

	user, tokens, err := h.ldapAuthService.Login(c.Request.Context(), service.LDAPLoginInput{
		ProviderSlug: c.Param("slug"),
		Identifier:   req.Identifier,
		Password:     req.Password,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			Error(c, http.StatusUnauthorized, ErrCodeInvalidCredentials, "Invalid enterprise credentials")
		case errors.Is(err, service.ErrEnterpriseProviderNotFound):
			Error(c, http.StatusNotFound, ErrCodeNotFound, "Enterprise directory provider not found")
		case errors.Is(err, service.ErrEnterpriseProviderDisabled):
			Error(c, http.StatusForbidden, ErrCodeForbidden, "Enterprise directory provider is disabled")
		case errors.Is(err, service.ErrEnterpriseUserNotFound):
			Error(c, http.StatusUnauthorized, ErrCodeInvalidCredentials, "Invalid enterprise credentials")
		case errors.Is(err, service.ErrExternalEmailConflict):
			Error(c, http.StatusConflict, ErrCodeConflict, "Email already registered; please sign in first and link the provider manually")
		default:
			Error(c, http.StatusInternalServerError, ErrCodeInternalError, "Failed to login with enterprise directory")
		}
		return
	}

	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), uuid.Nil, model.WebhookEventUserLogin, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"source":   "ldap",
		})
	}

	EmitAuthEvent(AuthEvent{
		Type:      "user_login",
		AppID:     "",
		AppName:   "System",
		UserID:    user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		Timestamp: time.Now(),
	})

	refreshMaxAge := 30 * 24 * 3600
	if h.cfg != nil {
		refreshMaxAge = h.cfg.JWT.RefreshTokenTTLDays * 24 * 3600
	}
	setAuthTokenCookies(c, tokens, refreshMaxAge)

	response := authTokenData(tokens)
	response["user"] = UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		Username:      user.Username,
		Role:          string(user.Role),
		Avatar:        user.Avatar,
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
	response["tokens"] = tokens

	Success(c, response)
}
