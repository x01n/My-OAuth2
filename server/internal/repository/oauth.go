package repository

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* OAuth 仓储层错误定义 */
var (
	ErrAuthCodeNotFound = errors.New("authorization code not found")
	ErrTokenNotFound    = errors.New("token not found")
)

/*
 * OAuthRepository OAuth2 令牌数据仓储
 * 功能：封装授权码、access_token、refresh_token 的全部 CRUD 操作
 *       同时支持 Auth 认证系统的 Refresh Token Rotation
 */
type OAuthRepository struct {
	db *gorm.DB
}

/*
 * NewOAuthRepository 创建 OAuth 仓储实例
 * @param db - GORM 数据库连接
 */
func NewOAuthRepository(db *gorm.DB) *OAuthRepository {
	return &OAuthRepository{db: db}
}

/*
 * CreateAuthorizationCode 创建新的授权码
 * 功能：自动生成随机授权码（如未设置）
 * @param code - 授权码实体
 */
func (r *OAuthRepository) CreateAuthorizationCode(code *model.AuthorizationCode) error {
	if code.Code == "" {
		code.Code = generateAuthCode()
	}
	return r.db.Create(code).Error
}

/*
 * FindAuthorizationCode 查找授权码
 * @param code - 授权码字符串
 * @return *model.AuthorizationCode - 授权码实体，未找到时返回 ErrAuthCodeNotFound
 */
func (r *OAuthRepository) FindAuthorizationCode(code string) (*model.AuthorizationCode, error) {
	var authCode model.AuthorizationCode
	result := r.db.First(&authCode, "code = ?", code)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAuthCodeNotFound
		}
		return nil, result.Error
	}
	return &authCode, nil
}

/*
 * FindReusableAuthorizationCode 查找同一授权请求下仍可用的授权码（防重复提交）
 */
func (r *OAuthRepository) FindReusableAuthorizationCode(
	userID uuid.UUID,
	clientID, redirectURI, scope, codeChallenge, nonce string,
	maxAge int64,
) (*model.AuthorizationCode, error) {
	var authCode model.AuthorizationCode
	q := r.db.Where(
		"user_id = ? AND client_id = ? AND redirect_uri = ? AND scope = ? AND used = ? AND expires_at > ?",
		userID, clientID, redirectURI, scope, false, time.Now(),
	)
	if codeChallenge != "" {
		q = q.Where("code_challenge = ?", codeChallenge)
	} else {
		q = q.Where("(code_challenge = '' OR code_challenge IS NULL)")
	}
	if nonce != "" {
		q = q.Where("nonce = ?", nonce)
	} else {
		q = q.Where("(nonce = '' OR nonce IS NULL)")
	}
	q = q.Where("max_age = ?", maxAge)
	err := q.Order("created_at DESC").First(&authCode).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAuthCodeNotFound
		}
		return nil, err
	}
	if !authCode.IsValid() {
		return nil, ErrAuthCodeNotFound
	}
	return &authCode, nil
}

/**
 * MarkAuthorizationCodeUsed 原子地把授权码标记为已使用
 *
 * @description
 *   RFC 6749 §4.1.2 要求 code 单次使用。使用条件 UPDATE：
 *   `UPDATE ... SET used=true WHERE code=? AND used=false`，
 *   仅当 RowsAffected==1 时调用方拿到所有权可继续签发 token，
 *   否则代表本次请求并发输给了另一个兑换请求，必须拒绝。
 *
 * @param  {string} code - 授权码
 * @returns {(bool, error)} (claimed, err) — claimed=true 表示本次抢占成功
 * @security L-4 修复：单条原子 SQL 防止并发兑换签发多对 token
 */
func (r *OAuthRepository) MarkAuthorizationCodeUsed(code string) (bool, error) {
	res := r.db.Model(&model.AuthorizationCode{}).
		Where("code = ? AND used = ?", code, false).
		Update("used", true)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

/* DeleteExpiredAuthorizationCodes 清理已过期的授权码 */
func (r *OAuthRepository) DeleteExpiredAuthorizationCodes() error {
	return r.db.Delete(&model.AuthorizationCode{}, "expires_at < ?", time.Now()).Error
}

/*
 * CreateAccessToken 创建新的访问令牌
 * 功能：自动生成随机 token（如未设置）
 * @param token - 访问令牌实体
 */
func (r *OAuthRepository) CreateAccessToken(token *model.AccessToken) error {
	if token.Token == "" {
		token.Token = generateToken()
		return r.db.Create(token).Error
	}

	issuedToken := token.Token
	token.Token = accessTokenLookupValue(issuedToken)
	if err := r.db.Create(token).Error; err != nil {
		token.Token = issuedToken
		return err
	}
	token.Token = issuedToken
	return nil
}

/*
 * FindAccessToken 查找访问令牌（预加载关联用户）
 * @param token - 令牌字符串
 * @return *model.AccessToken - 令牌实体，未找到时返回 ErrTokenNotFound
 */
func (r *OAuthRepository) FindAccessToken(token string) (*model.AccessToken, error) {
	var accessToken model.AccessToken
	lookupToken := accessTokenLookupValue(token)
	lookupValues := []string{lookupToken}
	if lookupToken != token {
		lookupValues = append(lookupValues, token)
	}
	result := r.db.Preload("User").First(&accessToken, "token IN ?", lookupValues)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	accessToken.Token = token
	return &accessToken, nil
}

/*
 * FindAccessTokenByID 根据 UUID 查找访问令牌
 * @param id - 令牌 UUID
 */
func (r *OAuthRepository) FindAccessTokenByID(id uuid.UUID) (*model.AccessToken, error) {
	var accessToken model.AccessToken
	result := r.db.First(&accessToken, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &accessToken, nil
}

/* RevokeAccessToken 撤销访问令牌 */
func (r *OAuthRepository) RevokeAccessToken(token string) error {
	lookupToken := accessTokenLookupValue(token)
	lookupValues := []string{lookupToken}
	if lookupToken != token {
		lookupValues = append(lookupValues, token)
	}
	return r.db.Model(&model.AccessToken{}).Where("token IN ?", lookupValues).Update("revoked", true).Error
}

/*
 * CreateRefreshToken 创建新的刷新令牌
 * 功能：自动生成随机 token（如未设置）
 * @param token - 刷新令牌实体
 */
func (r *OAuthRepository) CreateRefreshToken(token *model.RefreshToken) error {
	if token.Token == "" {
		token.Token = generateToken()
	}
	return r.db.Create(token).Error
}

/*
 * FindRefreshToken 查找刷新令牌（预加载关联 AccessToken）
 * @param token - 令牌字符串
 * @return *model.RefreshToken - 令牌实体，未找到时返回 ErrTokenNotFound
 */
func (r *OAuthRepository) FindRefreshToken(token string) (*model.RefreshToken, error) {
	var refreshToken model.RefreshToken
	result := r.db.Preload("AccessToken").First(&refreshToken, "token = ?", token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &refreshToken, nil
}

/**
 * RevokeRefreshToken 原子撤销刷新令牌
 *
 * @description
 *   条件 UPDATE 抢占语义：`UPDATE ... SET revoked=true WHERE token=? AND revoked=false`，
 *   RowsAffected==1 才代表本次撤销由本调用产生。OAuth2 流程的 refresh token rotation
 *   需根据该返回值决定是否签发新 token（L-9 修复并发问题）。
 *
 * @param  {string} token - refresh_token 字符串
 * @returns {(bool, error)} (claimed, err) — claimed=true 表示本次抢占成功
 * @security L-9 修复：并发刷新只允许一个成功
 */
func (r *OAuthRepository) RevokeRefreshToken(token string) (bool, error) {
	res := r.db.Model(&model.RefreshToken{}).
		Where("token = ? AND revoked = ?", token, false).
		Update("revoked", true)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

/* RevokeRefreshTokenByAccessTokenID 根据关联的 access_token_id 撤销刷新令牌 */
func (r *OAuthRepository) RevokeRefreshTokenByAccessTokenID(accessTokenID uuid.UUID) error {
	return r.db.Model(&model.RefreshToken{}).Where("access_token_id = ?", accessTokenID).Update("revoked", true).Error
}

/*
 * RevokeTokensByClientAndUser 撤销指定应用+用户的所有 OAuth 令牌
 * 功能：用户撤销对某个应用的授权时，同时撤销该应用签发给该用户的所有 token
 * @param clientID - 应用的 client_id
 * @param userID   - 用户 UUID
 */
func (r *OAuthRepository) RevokeTokensByClientAndUser(clientID string, userID uuid.UUID) error {
	/* 撤销该用户在该应用的所有 access_token */
	if err := r.db.Model(&model.AccessToken{}).
		Where("client_id = ? AND user_id = ? AND revoked = ?", clientID, userID, false).
		Update("revoked", true).Error; err != nil {
		return err
	}
	/* 撤销关联的所有 refresh_token（通过子查询找到 access_token_id） */
	return r.db.Exec(`
		UPDATE refresh_tokens SET revoked = true
		WHERE revoked = false AND access_token_id IN (
			SELECT id FROM access_tokens WHERE client_id = ? AND user_id = ?
		)`, clientID, userID).Error
}

/* DeleteExpiredTokens 清理已过期的访问令牌和刷新令牌 */
func (r *OAuthRepository) DeleteExpiredTokens() error {
	now := time.Now()
	if err := r.db.Delete(&model.AccessToken{}, "expires_at < ?", now).Error; err != nil {
		return err
	}
	return r.db.Delete(&model.RefreshToken{}, "expires_at < ?", now).Error
}

/**
 * DeleteTokensByClientID 删除指定 client_id 的 OAuth 凭证数据
 *
 * @description
 *   删除顺序：authorization_codes → refresh_tokens → access_tokens，
 *   其中 refresh_tokens 通过 access_tokens 子查询关联删除，避免应用删除后残留授权数据。
 *
 * @param  {string} clientID - OAuth 应用 client_id
 * @returns {error}
 */
func (r *OAuthRepository) DeleteTokensByClientID(clientID string) error {
	if err := r.db.Delete(&model.AuthorizationCode{}, "client_id = ?", clientID).Error; err != nil {
		return err
	}
	if err := r.db.Exec(`
		DELETE FROM refresh_tokens
		WHERE access_token_id IN (
			SELECT id FROM access_tokens WHERE client_id = ?
		)`, clientID).Error; err != nil {
		return err
	}
	return r.db.Delete(&model.AccessToken{}, "client_id = ?", clientID).Error
}

/*
 * RevokeTokensByUserID 撤销用户的所有令牌（用于登出）
 * @param userID - 用户 UUID
 */
func (r *OAuthRepository) RevokeTokensByUserID(userID uuid.UUID) error {
	var accessIDs []uuid.UUID
	if err := r.db.Model(&model.AccessToken{}).Where("user_id = ?", userID).Pluck("id", &accessIDs).Error; err != nil {
		return err
	}
	if err := r.db.Model(&model.AccessToken{}).Where("user_id = ?", userID).Update("revoked", true).Error; err != nil {
		return err
	}
	if len(accessIDs) > 0 {
		if err := r.db.Model(&model.RefreshToken{}).Where("access_token_id IN ?", accessIDs).Update("revoked", true).Error; err != nil {
			return err
		}
	}
	return r.db.Model(&model.RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true).Error
}

/*
 * 以下方法用于用户认证系统的 refresh token 轮换（单次使用）
 * 使用 JWT 的 jti（Token 字段）作为唯一标识
 */

/*
 * StoreAuthRefreshToken 存储 Auth Refresh Token 记录
 * 功能：用于 Token Rotation 轮换追踪，以 JWT 的 jti 作为唯一标识
 * @param jti       - JWT Token ID
 * @param userID    - 用户 UUID
 * @param expiresAt - 过期时间
 */
func (r *OAuthRepository) StoreAuthRefreshToken(jti string, userID uuid.UUID, expiresAt time.Time) error {
	record := &model.RefreshToken{
		Token:     jti,
		UserID:    &userID,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}
	return r.db.Create(record).Error
}

/*
 * FindAuthRefreshToken 按 JTI 查找未撤销的 Auth Refresh Token
 * @param jti - JWT Token ID
 * @return *model.RefreshToken - 令牌实体，未找到时返回 ErrTokenNotFound
 */
func (r *OAuthRepository) FindAuthRefreshToken(jti string) (*model.RefreshToken, error) {
	var token model.RefreshToken
	result := r.db.Where("token = ? AND user_id IS NOT NULL", jti).First(&token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &token, nil
}

/* RevokeAuthRefreshToken 按 JTI 撤销 Auth Refresh Token（单次使用后失效，同时记录撤销时间） */
func (r *OAuthRepository) RevokeAuthRefreshToken(jti string) error {
	now := time.Now()
	return r.db.Model(&model.RefreshToken{}).
		Where("token = ? AND user_id IS NOT NULL", jti).
		Updates(map[string]interface{}{"revoked": true, "revoked_at": now}).Error
}

/*
 * RevokeUserAuthRefreshTokens 撤销用户所有 Auth Refresh Token（用于登出）
 * @param userID - 用户 UUID
 */
func (r *OAuthRepository) RevokeUserAuthRefreshTokens(userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Updates(map[string]interface{}{"revoked": true, "revoked_at": now}).Error
}

/* CleanExpiredAuthRefreshTokens 清理过期的 Auth Refresh Token */
func (r *OAuthRepository) CleanExpiredAuthRefreshTokens() error {
	return r.db.Where("user_id IS NOT NULL AND expires_at < ?", time.Now()).Delete(&model.RefreshToken{}).Error
}

/* generateAuthCode 生成随机授权码（32 字节 Base64 URL 编码） */
func generateAuthCode() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

/* generateToken 生成随机令牌（48 字节 Base64 URL 编码） */
func generateToken() string {
	bytes := make([]byte, 48)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func accessTokenLookupValue(token string) string {
	if token == "" || len(token) <= 500 || isAccessTokenHash(token) {
		return token
	}
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isAccessTokenHash(token string) bool {
	const prefix = "sha256:"
	if len(token) != 71 || len(token) < len(prefix) || token[:len(prefix)] != prefix {
		return false
	}
	for _, ch := range token[len(prefix):] {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}
