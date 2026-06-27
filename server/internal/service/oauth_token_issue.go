package service

import (
	"strings"
	"time"

	"server/internal/model"
	"server/pkg/jwt"
)

/*
 * persistUserAccessToken 持久化用户委托 access_token（优先签发加密 JWT，机器令牌仍用不透明串）
 */
func (s *OAuthService) persistUserAccessToken(at *model.AccessToken, user *model.User, authTime int64, amr []string) error {
	if authTime <= 0 {
		authTime = time.Now().Unix()
	}
	at.AuthTime = authTime
	at.AMR = encodeAMR(amr)
	if at.Token == "" && user != nil && s.jwtManager != nil {
		ttl := time.Until(at.ExpiresAt)
		if ttl <= 0 {
			ttl = s.config.OAuth.AccessTokenTTL
		}
		tok, err := s.jwtManager.GenerateClientTokenWithScopeAndAuthTimeAndAMR(
			user.ID, user.Email, user.Username, string(user.Role),
			at.ClientID, at.Scope, jwt.TokenTypeAccess, authTime, amr, ttl,
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
func (s *OAuthService) persistUserRefreshToken(rt *model.RefreshToken, user *model.User, clientID, scope string, authTime int64, amr []string) error {
	if authTime <= 0 {
		authTime = time.Now().Unix()
	}
	if rt.Token == "" && user != nil && s.jwtManager != nil {
		ttl := time.Until(rt.ExpiresAt)
		if ttl <= 0 {
			ttl = s.config.OAuth.RefreshTokenTTL
		}
		tok, err := s.jwtManager.GenerateClientTokenWithScopeAndAuthTimeAndAMR(
			user.ID, user.Email, user.Username, string(user.Role),
			clientID, scope, jwt.TokenTypeRefresh, authTime, amr, ttl,
		)
		if err != nil {
			return err
		}
		rt.Token = tok
	}
	return s.oauthRepo.CreateRefreshToken(rt)
}

func encodeAMR(amr []string) string {
	return strings.Join(normalizeAMRValues(amr), " ")
}

func decodeAMR(value string) []string {
	if value == "" {
		return nil
	}
	return normalizeAMRValues(strings.Fields(value))
}

func normalizeAMRValues(amr []string) []string {
	if len(amr) == 0 {
		return nil
	}
	out := make([]string, 0, len(amr))
	for _, value := range amr {
		if value == "" {
			continue
		}
		exists := false
		for _, item := range out {
			if item == value {
				exists = true
				break
			}
		}
		if !exists {
			out = append(out, value)
		}
	}
	return out
}
