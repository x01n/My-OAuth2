/**
 * @file        jwt.go
 * @package     jwt
 * @description JWT 令牌管理：生成、验证、Claims 解析；支持 access/refresh 区分与 client audience 隔离
 */
package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

/**
 * TokenType 令牌类型枚举
 * @enum {string}
 */
type TokenType string

const (
	/** 访问令牌 — 短期有效，用于 API 鉴权 */
	TokenTypeAccess TokenType = "access"

	/** 刷新令牌 — 长期有效，用于换取新的 access token */
	TokenTypeRefresh TokenType = "refresh"

	/** OpenID Connect ID Token（JWT，仅用于 OIDC 身份声明） */
	TokenTypeIDToken TokenType = "id_token"
)

var (
	/** token 解析失败或签名不合法 */
	ErrInvalidToken = errors.New("invalid token")

	/** token 已过期 */
	ErrExpiredToken = errors.New("token has expired")

	/** access 与 refresh 类型不匹配（如把 refresh 当 access 使用） */
	ErrTokenTypeMismatch = errors.New("token type mismatch")
)

/**
 * Claims JWT 自定义声明
 *
 * @description
 *   包含用户身份、角色、令牌类型与可选的 client 归属。
 *   ClientID 用于区分"中央 token"（=""）与"外部 SDK token"（=client_id），
 *   中央 AdminOnly 中间件会拒绝 ClientID!="" 的 token 防止 SDK 越权进控制台。
 *
 * @field {uuid.UUID}  UserID    - 用户唯一标识
 * @field {string}     Email     - 用户邮箱
 * @field {string}     Username  - 用户名
 * @field {string}     Role      - 角色（admin/user/service）
 * @field {TokenType}  TokenType - access 或 refresh
 * @field {string}     ClientID  - 颁发方 client_id；""=中央颁发；非空=外部应用 scoped token
 * @security ClientID!="" 的 token 不能进入 /api/admin/*
 */
type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	TokenType TokenType `json:"token_type"`
	ClientID  string    `json:"client_id,omitempty"`
	Scope     string    `json:"scope,omitempty"` /* OIDC id_token 授权 scope */
	jwt.RegisteredClaims
}

/**
 * Manager JWT 管理器（HMAC-SHA256）
 *
 * @description 共享 secret 签发与校验 JWT；强制 alg=HS256 防止算法混淆攻击。
 */
type Manager struct {
	secretKey []byte
	encKey    []byte
	issuer    string
}

/**
 * NewManager 创建 JWT 管理器实例
 *
 * @param  {string} secretKey - HMAC 签名密钥（至少 32 字节）
 * @param  {string} issuer    - JWT iss 字段
 * @returns {*Manager}
 */
func NewManager(secretKey, issuer string) *Manager {
	return &Manager{
		secretKey: []byte(secretKey),
		encKey:    deriveEncryptionKey(secretKey),
		issuer:    issuer,
	}
}

/**
 * GenerateToken 生成"中央 token"（aud=issuer，ClientID=""）
 *
 * @description
 *   适用于 /api/auth/login、密码刷新等中央认证流程颁发的 token。
 *   这类 token 通过 AdminOnly 中间件后可访问 /api/admin/*。
 *
 * @param  {uuid.UUID}     userID    - 用户 UUID
 * @param  {string}        email     - 用户邮箱
 * @param  {string}        username  - 用户名
 * @param  {string}        role      - 角色（admin/user）
 * @param  {TokenType}     tokenType - access 或 refresh
 * @param  {time.Duration} ttl       - token 有效期
 * @returns {string, error} 签名后的 JWT 字符串
 */
func (m *Manager) GenerateToken(userID uuid.UUID, email, username, role string, tokenType TokenType, ttl time.Duration) (string, error) {
	return m.generate(userID, email, username, role, "", tokenType, "", ttl)
}

/**
 * GenerateClientToken 生成"外部 client scoped token"（aud=client_id，ClientID=client_id）
 *
 * @description
 *   适用于 SDK 端点（/api/sdk/login 等）、/token/sign 颁发给外部 client 的 token。
 *   这类 token 携带 ClientID 标识颁发方，中央 AdminOnly 中间件会拒绝其访问 /api/admin/*。
 *
 * @param  {uuid.UUID}     userID    - 用户 UUID（=app 所有者或登录用户）
 * @param  {string}        email     - 用户邮箱
 * @param  {string}        username  - 用户名
 * @param  {string}        role      - 角色（中央颁发时透传；/token/sign 应强制 "service"）
 * @param  {string}        clientID  - 颁发方 client_id（非空）
 * @param  {TokenType}     tokenType - access 或 refresh
 * @param  {time.Duration} ttl       - token 有效期
 * @returns {string, error} 签名后的 JWT 字符串
 * @security ClientID!="" 在 AdminOnly 中间件会被拒绝
 */
func (m *Manager) GenerateClientToken(userID uuid.UUID, email, username, role, clientID string, tokenType TokenType, ttl time.Duration) (string, error) {
	return m.GenerateClientTokenWithScope(userID, email, username, role, clientID, "", tokenType, ttl)
}

/* GenerateClientTokenWithScope 签发带 scope 的外部 client JWT（OAuth access/refresh） */
func (m *Manager) GenerateClientTokenWithScope(userID uuid.UUID, email, username, role, clientID, scope string, tokenType TokenType, ttl time.Duration) (string, error) {
	return m.generate(userID, email, username, role, clientID, tokenType, scope, ttl)
}

/*
 * GenerateIDToken 签发 OpenID Connect id_token（JWT）
 * @param scope - 授权 scope 字符串（含 openid 时由调用方保证）
 */
func (m *Manager) GenerateIDToken(userID uuid.UUID, email, username, role, clientID, scope string, ttl time.Duration) (string, error) {
	return m.generate(userID, email, username, role, clientID, TokenTypeIDToken, scope, ttl)
}

/**
 * generate 内部统一签发逻辑
 *
 * @param  {string} clientID - 空字符串=中央 token；非空=client scoped
 * @returns {string, error}
 */
func (m *Manager) generate(userID uuid.UUID, email, username, role, clientID string, tokenType TokenType, scope string, ttl time.Duration) (string, error) {
	now := time.Now()

	/* audience：中央 token 用 issuer；client token 用 client_id，便于资源服务器按 aud 路由 */
	aud := jwt.ClaimStrings{m.issuer}
	if clientID != "" {
		aud = jwt.ClaimStrings{clientID}
	}

	claims := &Claims{
		UserID:    userID,
		Email:     email,
		Username:  username,
		Role:      role,
		TokenType: tokenType,
		ClientID:  clientID,
		Scope:     scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        generateSecureJTI(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", err
	}
	return encryptSignedJWT(m.encKey, signed)
}

/**
 * ValidateToken 验证 token 并返回 claims（不校验 token 类型）
 *
 * @description
 *   强制校验 alg=HS256 防止 alg:none / RS256 混淆攻击；强制校验 issuer 防止跨服务 token 混用。
 *   注意：本方法不校验 audience（既允许中央 token 也允许 client token），调用方自行处理。
 *
 * @param  {string} tokenString - JWT 字符串
 * @returns {*Claims, error}
 * @throws {ErrExpiredToken} token 已过期
 * @throws {ErrInvalidToken} 签名/算法/issuer 不合法
 */
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	signed, err := decryptTokenIfNeeded(m.encKey, tokenString)
	if err != nil {
		return nil, ErrInvalidToken
	}
	token, err := jwt.ParseWithClaims(signed, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		/* 强制 HMAC 签名算法，阻止 alg:none / alg:RS256 混淆攻击 */
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.secretKey, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

/**
 * ValidateAccessToken 验证 token 且确保是 access 类型
 *
 * @param  {string} tokenString
 * @returns {*Claims, error}
 * @throws {ErrTokenTypeMismatch} 当传入 refresh token
 */
func (m *Manager) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenType == TokenTypeRefresh {
		return nil, ErrTokenTypeMismatch
	}
	return claims, nil
}

/**
 * ValidateRefreshToken 验证 token 且确保是 refresh 类型
 *
 * @param  {string} tokenString
 * @returns {*Claims, error}
 * @throws {ErrTokenTypeMismatch} 当传入 access token
 */
func (m *Manager) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != TokenTypeRefresh {
		return nil, ErrTokenTypeMismatch
	}
	return claims, nil
}

/**
 * generateSecureJTI 使用 crypto/rand 生成 32 字符 hex JTI
 *
 * @description 比 uuid.New()（基于 math/rand）更适合安全场景。
 * @returns {string} 32 字符十六进制串
 */
func generateSecureJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()
	}
	return hex.EncodeToString(b)
}
