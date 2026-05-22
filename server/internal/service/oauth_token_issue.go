package service

import (
	"time"

	"server/internal/model"
	"server/pkg/jwt"
)

/*
 * persistUserAccessToken 持久化用户委托 access_token（优先签发加密 JWT，机器令牌仍用不透明串）
 */
func (s *OAuthService) persistUserAccessToken(at *model.AccessToken, user *model.User) error {
	if at.Token == "" && user != nil && s.jwtManager != nil {
		ttl := time.Until(at.ExpiresAt)
		if ttl <= 0 {
			ttl = s.config.OAuth.AccessTokenTTL
		}
		tok, err := s.jwtManager.GenerateClientTokenWithScope(
			user.ID, user.Email, user.Username, string(user.Role),
			at.ClientID, at.Scope, jwt.TokenTypeAccess, ttl,
		)
		if err != nil {
			return err
		}
		at.Token = tok
	}
	return s.oauthRepo.CreateAccessToken(at)
}

/*
 * persistUserRefreshToken 持久化用户委托 refresh_token（优先签发加密 JWT）
 */
func (s *OAuthService) persistUserRefreshToken(rt *model.RefreshToken, user *model.User, clientID, scope string) error {
	if rt.Token == "" && user != nil && s.jwtManager != nil {
		ttl := time.Until(rt.ExpiresAt)
		if ttl <= 0 {
			ttl = s.config.OAuth.RefreshTokenTTL
		}
		tok, err := s.jwtManager.GenerateClientTokenWithScope(
			user.ID, user.Email, user.Username, string(user.Role),
			clientID, scope, jwt.TokenTypeRefresh, ttl,
		)
		if err != nil {
			return err
		}
		rt.Token = tok
	}
	return s.oauthRepo.CreateRefreshToken(rt)
}
