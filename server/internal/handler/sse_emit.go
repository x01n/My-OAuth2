package handler

import (
	"time"

	"server/internal/model"
	"server/internal/service"
)

/*
 * emitOAuthTokenSSE 令牌签发/刷新时推送完整 SSE 事件（含用户信息）
 */
func emitOAuthTokenSSE(oauthSvc *service.OAuthService, app *model.Application, grantType, accessToken, scope string) {
	if app == nil {
		return
	}
	eventType := "token_issued"
	if grantType == "refresh_token" {
		eventType = "token_refreshed"
	}
	ev := AuthEvent{
		Type:      eventType,
		AppID:     app.ID.String(),
		AppName:   app.Name,
		Scope:     scope,
		GrantType: grantType,
		Timestamp: time.Now(),
	}
	if oauthSvc != nil && accessToken != "" {
		if user, _, err := oauthSvc.ValidateAccessToken(accessToken); err == nil && user != nil {
			ev.UserID = user.ID.String()
			ev.Username = user.Username
			ev.Email = user.Email
		}
	}
	EmitAuthEvent(ev)
}

/* emitOAuthAuthorizedSSE 用户同意 OAuth 授权 */
func emitOAuthAuthorizedSSE(app *model.Application, userID, username, email, scope string) {
	if app == nil {
		return
	}
	EmitAuthEvent(AuthEvent{
		Type:      "oauth_authorized",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    userID,
		Username:  username,
		Email:     email,
		Scope:     scope,
		Timestamp: time.Now(),
	})
}

/* emitDeviceAuthorizedSSE 设备流授权成功 */
func emitDeviceAuthorizedSSE(app *model.Application, userID, username, email, scope string) {
	if app == nil {
		return
	}
	EmitAuthEvent(AuthEvent{
		Type:      "device_authorized",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    userID,
		Username:  username,
		Email:     email,
		Scope:     scope,
		Timestamp: time.Now(),
	})
}
