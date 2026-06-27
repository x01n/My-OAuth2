package service

import (
	"server/internal/model"
	"server/pkg/jwt"
)

/* SetJWTManager 注入 JWT 管理器（签发 OIDC id_token） */
func (s *OAuthService) SetJWTManager(m *jwt.Manager) {
	s.jwtManager = m
}

/*
 * enrichTokenResultWithIDToken 在 scope 含 openid 时附加 id_token
 */
func (s *OAuthService) enrichTokenResultWithIDToken(result *TokenResult, user *model.User, clientID, issuer, scope, nonce string, authTime int64, amr []string) error {
	if result == nil || user == nil || s.jwtManager == nil || !model.ScopeContainsOpenID(scope) {
		return nil
	}
	app, err := s.appRepo.FindByClientID(clientID)
	if err != nil {
		return ErrInvalidClient
	}
	ttl := s.config.OAuth.IDTokenTTL
	if ttl <= 0 {
		ttl = s.config.OAuth.AccessTokenTTL
	}
	idt, err := s.jwtManager.GenerateClientIDTokenWithIssuerAndNonceAndAuthTimeAndAMRAndATHash(
		user.ID, user.Email, user.Username, string(user.Role), clientID, app.ClientSecret, issuer, scope, nonce, authTime, amr, jwt.AccessTokenHash(result.AccessToken), ttl,
	)
	if err != nil {
		return err
	}
	result.IDToken = idt
	return nil
}
