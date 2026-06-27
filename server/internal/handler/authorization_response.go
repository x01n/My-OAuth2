package handler

import (
	"strings"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
)

/* AuthUserSummary 授权记录中的用户摘要（不含密码等敏感字段） */
type AuthUserSummary struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	Username      string  `json:"username"`
	DisplayName   string  `json:"display_name"`
	Avatar        string  `json:"avatar,omitempty"`
	Role          string  `json:"role"`
	Status        string  `json:"status"`
	EmailVerified bool    `json:"email_verified"`
	LastLoginAt   *string `json:"last_login_at,omitempty"`
}

/* AuthAppSummary 授权记录中的应用摘要 */
type AuthAppSummary struct {
	ID          string   `json:"id"`
	ClientID    string   `json:"client_id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	GrantTypes  []string `json:"grant_types,omitempty"`
}

/* AuthorizationResponse 用户授权记录 API 响应 */
type AuthorizationResponse struct {
	ID           string           `json:"id"`
	UserID       string           `json:"user_id"`
	AppID        string           `json:"app_id"`
	Scope        string           `json:"scope"`
	Scopes       []string         `json:"scopes"`
	GrantType    string           `json:"grant_type"`
	AuthorizedAt string           `json:"authorized_at"`
	ExpiresAt    *string          `json:"expires_at,omitempty"`
	Revoked      bool             `json:"revoked"`
	RevokedAt    *string          `json:"revoked_at,omitempty"`
	IsActive     bool             `json:"is_active"`
	User         *AuthUserSummary `json:"user,omitempty"`
	App          *AuthAppSummary  `json:"app,omitempty"`
}

func toAuthUserSummary(u *model.User) *AuthUserSummary {
	if u == nil || u.ID == uuid.Nil {
		return nil
	}
	summary := &AuthUserSummary{
		ID:            u.ID.String(),
		Email:         u.Email,
		Username:      u.Username,
		DisplayName:   u.GetFullName(),
		Avatar:        u.Avatar,
		Role:          string(u.Role),
		Status:        u.Status,
		EmailVerified: u.EmailVerified,
	}
	if u.LastLoginAt != nil {
		t := u.LastLoginAt.Format(time.RFC3339)
		summary.LastLoginAt = &t
	}
	return summary
}

func toAuthAppSummary(app *model.Application) *AuthAppSummary {
	if app == nil || app.ID == uuid.Nil {
		return nil
	}
	return &AuthAppSummary{
		ID:          app.ID.String(),
		ClientID:    app.ClientID,
		Name:        app.Name,
		Description: app.Description,
		Scopes:      app.GetOIDCScopes(),
		GrantTypes:  app.GetGrantTypes(),
	}
}

func toAuthorizationResponse(auth model.UserAuthorization) AuthorizationResponse {
	resp := AuthorizationResponse{
		ID:           auth.ID.String(),
		UserID:       auth.UserID.String(),
		AppID:        auth.AppID.String(),
		Scope:        auth.Scope,
		Scopes:       strings.Fields(auth.Scope),
		GrantType:    auth.GrantType,
		AuthorizedAt: auth.AuthorizedAt.Format(time.RFC3339),
		Revoked:      auth.Revoked,
		IsActive:     auth.IsValid(),
		User:         toAuthUserSummary(auth.User),
		App:          toAuthAppSummary(auth.App),
	}
	if auth.ExpiresAt != nil {
		t := auth.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &t
	}
	if auth.RevokedAt != nil {
		t := auth.RevokedAt.Format(time.RFC3339)
		resp.RevokedAt = &t
	}
	return resp
}

func toAuthorizationResponses(auths []model.UserAuthorization) []AuthorizationResponse {
	out := make([]AuthorizationResponse, len(auths))
	for i, a := range auths {
		out[i] = toAuthorizationResponse(a)
	}
	return out
}
