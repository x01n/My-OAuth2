package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
	"server/pkg/logger"

	"github.com/google/uuid"
)

/**
 * OAuth2 服务层错误定义
 * @enum {error}
 */
var (
	/** 客户端凭据无效 */
	ErrInvalidClient = errors.New("invalid client")

	/** redirect_uri 不在白名单 */
	ErrInvalidRedirectURI = errors.New("invalid redirect uri")

	/** 授权信息无效（code/refresh_token/subject_token 等） */
	ErrInvalidGrant = errors.New("invalid grant")

	/** scope 超出允许范围 */
	ErrInvalidScope = errors.New("invalid scope")

	/** OAuth grant_type 不受支持 */
	ErrUnsupportedGrantType = errors.New("unsupported grant type")

	/** OAuth 请求参数缺失或不合法 */
	ErrInvalidRequest = errors.New("invalid request")

	/** 请求的 audience/resource 目标不可签发 */
	ErrInvalidTarget = errors.New("invalid target")

	/** 授权码已过期 */
	ErrAuthCodeExpired = errors.New("authorization code expired")

	/** 授权码已被使用 */
	ErrAuthCodeUsed = errors.New("authorization code already used")

	/** PKCE code_verifier 不匹配 */
	ErrInvalidCodeVerifier = errors.New("invalid code verifier")

	/** OIDC max_age 要求重新认证 */
	ErrLoginRequired = errors.New("login required")

	/** OIDC prompt=none 无法静默完成授权同意 */
	ErrConsentRequired = errors.New("consent required")

	/** access token 已过期 */
	ErrTokenExpired = errors.New("token expired")

	/** access token 已被撤销 */
	ErrTokenRevoked = errors.New("token revoked")

	/** 令牌无用户上下文（如 client_credentials），不能用于 UserInfo 等终端用户 API */
	ErrNoUserInToken = errors.New("token has no associated user")
)

/**
 * splitScopeSet 将空格分隔 scope 串转换为 set
 *
 * @param  {string} scope - 空格分隔的 scope 字符串
 * @returns {map[string]bool} key 为 scope 名的 set
 */
func splitScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		if s != "" {
			set[s] = true
		}
	}
	return set
}

func parseOIDCMaxAge(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return -1, nil
	}
	maxAge, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || maxAge < 0 {
		return 0, ErrInvalidRequest
	}
	return maxAge, nil
}

func isFreshOIDCSession(authTime int64, maxAge int64) bool {
	if maxAge < 0 {
		return true
	}
	if authTime <= 0 {
		return false
	}
	return time.Since(time.Unix(authTime, 0)) <= time.Duration(maxAge)*time.Second
}

type oidcPrompt struct {
	None    bool
	Login   bool
	Consent bool
}

func parseOIDCPrompt(raw string) (oidcPrompt, error) {
	var prompt oidcPrompt
	seen := make(map[string]bool)
	for _, value := range strings.Fields(raw) {
		if seen[value] {
			return prompt, ErrInvalidRequest
		}
		seen[value] = true
		switch value {
		case "none":
			prompt.None = true
		case "login":
			prompt.Login = true
		case "consent":
			prompt.Consent = true
		case "select_account":
			return prompt, ErrInvalidRequest
		default:
			return prompt, ErrInvalidRequest
		}
	}
	if prompt.None && len(seen) > 1 {
		return prompt, ErrInvalidRequest
	}
	return prompt, nil
}

func scopeCovers(grantedScope, requestedScope string) bool {
	granted := splitScopeSet(grantedScope)
	for _, scope := range strings.Fields(requestedScope) {
		if !granted[scope] {
			return false
		}
	}
	return true
}

func (s *OAuthService) hasReusableUserAuthorization(userID, appID uuid.UUID, requestedScope string) bool {
	if s.userAuthRepo == nil {
		return false
	}
	auth, err := s.userAuthRepo.FindByUserAndApp(userID, appID)
	if err != nil || auth == nil || !auth.IsValid() {
		return false
	}
	return scopeCovers(auth.Scope, requestedScope)
}

/*
 * OAuthService OAuth2 核心服务
 * 功能：实现 OAuth2 授权码流程、Token 签发/刷新/撤销、PKCE 校验、
 *       Client Credentials 授权、Device Flow、Token Introspection 等
 */
type OAuthService struct {
	appRepo       *repository.ApplicationRepository
	oauthRepo     *repository.OAuthRepository
	userRepo      *repository.UserRepository
	userAuthRepo  *repository.UserAuthorizationRepository
	riskEventRepo *repository.RiskEventRepository
	deviceRepo    *repository.DeviceCodeRepository
	jwtManager    *jwt.Manager
	config        *config.Config
}

/*
 * NewOAuthService 创建 OAuth2 服务实例
 * @param appRepo      - 应用仓储
 * @param oauthRepo    - OAuth 令牌仓储
 * @param userRepo     - 用户仓储
 * @param userAuthRepo - 用户授权仓储
 * @param cfg          - 系统配置
 */
func NewOAuthService(
	appRepo *repository.ApplicationRepository,
	oauthRepo *repository.OAuthRepository,
	userRepo *repository.UserRepository,
	userAuthRepo *repository.UserAuthorizationRepository,
	cfg *config.Config,
) *OAuthService {
	return &OAuthService{
		appRepo:      appRepo,
		oauthRepo:    oauthRepo,
		userRepo:     userRepo,
		userAuthRepo: userAuthRepo,
		config:       cfg,
	}
}

/* SetDeviceCodeRepository 注入设备码仓储（可选依赖，启用 Device Flow） */
func (s *OAuthService) SetDeviceCodeRepository(repo *repository.DeviceCodeRepository) {
	s.deviceRepo = repo
}

/* SetRiskEventRepository 注入风控事件仓储（可选依赖） */
func (s *OAuthService) SetRiskEventRepository(repo *repository.RiskEventRepository) {
	s.riskEventRepo = repo
}

func (s *OAuthService) recordRiskEvent(userID *uuid.UUID, riskScore int, decision model.RiskDecision, ipAddress, userAgent, reason string) {
	if s.riskEventRepo == nil {
		return
	}
	if err := s.riskEventRepo.Create(&model.RiskEvent{
		UserID:    userID,
		RiskScore: riskScore,
		Decision:  decision,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Reason:    reason,
	}); err != nil {
		logger.Warn("Failed to record OAuth risk event", "user_id", userID, "risk_score", riskScore, "decision", decision, "reason", reason, "error", err)
	}
}

/* AuthorizeInput OAuth2 授权请求参数，支持 PKCE */
type AuthorizeInput struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	MaxAge              string
	Prompt              string
	AuthTime            int64
	AMR                 []string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              uuid.UUID
}

/* AuthorizeResult OAuth2 授权结果，包含授权码和重定向信息 */
type AuthorizeResult struct {
	Code        string
	RedirectURI string
	State       string
	Reused      bool // 复用未兑换的授权码（重复提交）
}

/*
 * Authorize 创建授权码
 * 功能：校验客户端、回调地址、scope，生成授权码，记录用户授权
 *       支持 PKCE (code_challenge / code_challenge_method)
 * @param input - 授权请求参数
 * @return *AuthorizeResult - 授权码和重定向信息
 */
func (s *OAuthService) Authorize(input *AuthorizeInput) (*AuthorizeResult, error) {
	// Validate client
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if !app.SupportsGrantType("authorization_code") {
		return nil, ErrInvalidGrant
	}

	if !app.ValidateUserAuthorizationScope(input.Scope) {
		return nil, ErrInvalidScope
	}

	user, err := s.userRepo.FindByID(input.UserID)
	if err != nil || user.IsSuspended() {
		return nil, ErrAccessDenied
	}

	// Validate redirect URI
	if !app.ValidateRedirectURI(input.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	/*
	 * PKCE 强制策略 (RFC 7636)：
	 *   - 公开客户端（SPA/移动端）必须使用 PKCE
	 *   - 机密客户端推荐但不强制
	 *   - code_challenge_method 仅接受 S256（禁用 plain）
	 */
	if app.AppType == model.AppTypePublic {
		if input.CodeChallenge == "" {
			return nil, errors.New("PKCE code_challenge is required for public clients")
		}
	}
	if input.CodeChallenge != "" {
		if input.CodeChallengeMethod == "" {
			input.CodeChallengeMethod = "S256"
		}
		if input.CodeChallengeMethod != "S256" {
			return nil, errors.New("only S256 code_challenge_method is supported")
		}
	}

	prompt, err := parseOIDCPrompt(input.Prompt)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if prompt.Login {
		return nil, ErrLoginRequired
	}
	if prompt.Consent && prompt.None {
		return nil, ErrInvalidRequest
	}
	if prompt.None && !s.hasReusableUserAuthorization(input.UserID, app.ID, input.Scope) {
		return nil, ErrConsentRequired
	}

	maxAge, err := parseOIDCMaxAge(input.MaxAge)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if maxAge >= 0 && !isFreshOIDCSession(input.AuthTime, maxAge) {
		return nil, ErrLoginRequired
	}
	authTime := input.AuthTime
	if authTime <= 0 {
		authTime = time.Now().Unix()
	}

	if existing, err := s.oauthRepo.FindReusableAuthorizationCode(
		input.UserID, input.ClientID, input.RedirectURI, input.Scope, input.CodeChallenge, input.Nonce, maxAge,
	); err == nil && existing != nil {
		return &AuthorizeResult{
			Code:        existing.Code,
			RedirectURI: input.RedirectURI,
			State:       input.State,
			Reused:      true,
		}, nil
	}

	authCode := &model.AuthorizationCode{
		ClientID:            input.ClientID,
		UserID:              input.UserID,
		RedirectURI:         input.RedirectURI,
		Scope:               input.Scope,
		Nonce:               input.Nonce,
		AuthTime:            authTime,
		AMR:                 encodeAMR(input.AMR),
		MaxAge:              maxAge,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(s.config.OAuth.AuthCodeTTL),
	}

	if err := s.oauthRepo.CreateAuthorizationCode(authCode); err != nil {
		return nil, err
	}

	if s.userAuthRepo != nil && !prompt.None {
		s.userAuthRepo.CreateOrUpdate(input.UserID, app.ID, input.Scope, "authorization_code")
	}

	return &AuthorizeResult{
		Code:        authCode.Code,
		RedirectURI: input.RedirectURI,
		State:       input.State,
		Reused:      false,
	}, nil
}

/*
 * FindPendingAuthorization 查找可复用的授权码（授权页加载时用于自动跳转）
 */
func (s *OAuthService) FindPendingAuthorization(input *AuthorizeInput) (*AuthorizeResult, error) {
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	prompt, err := parseOIDCPrompt(input.Prompt)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if prompt.Login {
		return nil, ErrLoginRequired
	}
	maxAge, err := parseOIDCMaxAge(input.MaxAge)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if maxAge >= 0 && !isFreshOIDCSession(input.AuthTime, maxAge) {
		return nil, ErrLoginRequired
	}
	if prompt.None && !s.hasReusableUserAuthorization(input.UserID, app.ID, input.Scope) {
		return nil, ErrConsentRequired
	}
	existing, err := s.oauthRepo.FindReusableAuthorizationCode(
		input.UserID, input.ClientID, input.RedirectURI, input.Scope, input.CodeChallenge, input.Nonce, maxAge,
	)
	if err == nil {
		return &AuthorizeResult{
			Code:        existing.Code,
			RedirectURI: input.RedirectURI,
			State:       input.State,
			Reused:      true,
		}, nil
	}
	if !prompt.Consent && s.hasReusableUserAuthorization(input.UserID, app.ID, input.Scope) {
		return s.Authorize(input)
	}
	if prompt.None {
		return s.Authorize(input)
	}
	return nil, err
}

/*
 * TokenInput OAuth2 Token 请求参数
 * 功能：统一封装所有 grant_type 的请求参数
 *       支持 authorization_code、refresh_token、client_credentials、device_code、token-exchange
 */
type TokenInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Issuer       string
	IPAddress    string
	UserAgent    string
	CodeVerifier string
	Scope        string // For client_credentials grant
	DeviceCode   string // For device_code grant
	// Token Exchange (RFC 8693)
	SubjectToken       string // The token to exchange
	SubjectTokenType   string // urn:ietf:params:oauth:token-type:access_token, etc.
	ActorToken         string // Optional actor token for delegation
	ActorTokenType     string // Type of actor token
	RequestedTokenType string // Requested token type
	Audience           string // Target audience for the new token
	Resource           string // Target resource
}

/* TokenResult OAuth2/OIDC Token 响应结构（RFC 6749 + OIDC） */
type TokenResult struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

/*
 * Token 根据 grant_type 签发或刷新令牌
 * 功能：路由到对应的 grant 处理函数
 *       支持: authorization_code, refresh_token, client_credentials, device_code, token-exchange
 * @param input - Token 请求参数
 * @return *TokenResult - 令牌响应
 */
func (s *OAuthService) Token(input *TokenInput) (*TokenResult, error) {
	if input.GrantType == "" {
		return nil, ErrInvalidRequest
	}

	switch input.GrantType {
	case "authorization_code":
		return s.exchangeAuthorizationCode(input)
	case "refresh_token":
		return s.refreshAccessToken(input)
	case "client_credentials":
		return s.clientCredentials(input)
	case "urn:ietf:params:oauth:grant-type:device_code", "device_code":
		return s.deviceCodeGrant(input)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		return s.tokenExchange(input)
	default:
		return nil, ErrUnsupportedGrantType
	}
}

/*
 * exchangeAuthorizationCode 授权码换取令牌
 * 功能：校验授权码、客户端、回调地址、PKCE，签发 access_token + refresh_token
 * @param input - Token 请求参数
 */
func (s *OAuthService) exchangeAuthorizationCode(input *TokenInput) (*TokenResult, error) {
	// Find authorization code
	authCode, err := s.oauthRepo.FindAuthorizationCode(input.Code)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	// Check if code is expired
	if authCode.IsExpired() {
		return nil, ErrAuthCodeExpired
	}

	// Check if code is already used
	if authCode.Used {
		return nil, ErrAuthCodeUsed
	}

	// Validate client
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if authCode.ClientID != input.ClientID {
		return nil, ErrInvalidGrant
	}

	/*
	 * 客户端认证策略：
	 *   - 机密客户端（confidential/machine）必须提供有效的 client_secret
	 *   - 公开客户端（public）不需要 client_secret，但必须使用 PKCE
	 */
	if app.AppType == model.AppTypeConfidential || app.AppType == model.AppTypeMachine {
		if input.ClientSecret == "" || subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
			return nil, ErrInvalidClient
		}
	} else if input.ClientSecret != "" {
		/* 公开客户端也提供了 secret，仍然校验 */
		if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
			return nil, ErrInvalidClient
		}
	}

	// Validate redirect URI
	if authCode.RedirectURI != input.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	if app.AppType == model.AppTypePublic && authCode.CodeChallenge == "" {
		return nil, ErrInvalidCodeVerifier
	}

	// Validate PKCE code verifier
	if authCode.CodeChallenge != "" {
		if !s.validateCodeVerifier(input.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, ErrInvalidCodeVerifier
		}
	}

	/*
	 * Mark authorization code as used — 原子抢占
	 * L-4 修复：仅当本调用拿到 RowsAffected==1 才继续签发 token，
	 * 否则代表已有并发请求消费过该 code → RFC 6749 §4.1.2 要求拒绝重复兑换。
	 */
	claimed, err := s.oauthRepo.MarkAuthorizationCodeUsed(input.Code)
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, ErrAuthCodeUsed
	}

	user, err := s.userRepo.FindByID(authCode.UserID)
	if err != nil || user.IsSuspended() {
		return nil, ErrAccessDenied
	}

	if !app.SupportsGrantType("authorization_code") {
		return nil, ErrInvalidGrant
	}

	// Create access token
	accessToken := &model.AccessToken{
		ClientID:  input.ClientID,
		UserID:    &authCode.UserID,
		Scope:     authCode.Scope,
		AuthTime:  authCode.AuthTime,
		AMR:       authCode.AMR,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}

	if err := s.persistUserAccessToken(accessToken, user, authCode.AuthTime, decodeAMR(authCode.AMR)); err != nil {
		return nil, err
	}

	uid := authCode.UserID
	refreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		UserID:        &uid,
		ExpiresAt:     time.Now().Add(s.config.OAuth.RefreshTokenTTL),
	}

	if err := s.persistUserRefreshToken(refreshToken, user, input.ClientID, authCode.Scope, authCode.AuthTime, decodeAMR(authCode.AMR)); err != nil {
		return nil, err
	}

	result := &TokenResult{
		AccessToken:  accessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken.Token,
		Scope:        authCode.Scope,
	}
	if err := s.enrichTokenResultWithIDToken(result, user, input.ClientID, input.Issuer, authCode.Scope, authCode.Nonce, authCode.AuthTime, decodeAMR(authCode.AMR)); err != nil {
		return nil, err
	}
	return result, nil
}

/*
 * refreshAccessToken 使用 refresh_token 刷新令牌
 * 功能：撤销旧令牌对，签发新的 access_token + refresh_token
 * @param input - Token 请求参数
 */
func (s *OAuthService) refreshAccessToken(input *TokenInput) (*TokenResult, error) {
	// Find refresh token
	refreshToken, err := s.oauthRepo.FindRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	/*
	 * Refresh Token 重放检测 (Token Rotation Security)
	 * 如果一个已被撤销的 refresh_token 再次被使用，说明可能发生了令牌泄露：
	 *   - 攻击者和合法用户都持有同一个 refresh_token
	 *   - 合法用户先刷新（旧 token 被撤销），攻击者再使用旧 token
	 * 安全措施：撤销该 refresh_token 关联的所有令牌（整个 token family）
	 */
	if refreshToken.Revoked {
		s.recordRiskEvent(refreshToken.UserID, 80, model.RiskDecisionBlock, input.IPAddress, input.UserAgent, model.RiskEventReasonRefreshTokenReplay)
		if refreshToken.AccessTokenID != nil {
			if at, atErr := s.oauthRepo.FindAccessTokenByID(*refreshToken.AccessTokenID); atErr == nil {
				if at.UserID != nil {
					_ = s.oauthRepo.RevokeTokensByClientAndUser(at.ClientID, *at.UserID)
				} else {
					_ = s.oauthRepo.RevokeAccessToken(at.Token)
					_ = s.oauthRepo.RevokeRefreshTokenByAccessTokenID(at.ID)
				}
			}
		}
		return nil, ErrTokenRevoked
	}

	// Check if token is valid (expired check)
	if !refreshToken.IsValid() {
		return nil, ErrTokenRevoked
	}

	// Get the old access token to get user info
	if refreshToken.AccessTokenID == nil {
		return nil, ErrInvalidGrant
	}
	oldAccessToken, err := s.oauthRepo.FindAccessTokenByID(*refreshToken.AccessTokenID)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if !oldAccessToken.IsValid() {
		return nil, ErrTokenRevoked
	}

	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if oldAccessToken.ClientID != input.ClientID {
		return nil, ErrInvalidGrant
	}
	if !app.SupportsGrantType("refresh_token") {
		return nil, ErrInvalidGrant
	}

	var user *model.User
	if oldAccessToken.UserID != nil {
		var uErr error
		user, uErr = s.userRepo.FindByID(*oldAccessToken.UserID)
		if uErr != nil || user.IsSuspended() {
			return nil, ErrAccessDenied
		}
	}

	/* 检查用户对该应用的授权是否已被撤销 */
	if oldAccessToken.UserID != nil && s.userAuthRepo != nil {
		auth, authErr := s.userAuthRepo.FindByUserAndApp(*oldAccessToken.UserID, app.ID)
		if authErr != nil || !auth.IsValid() {
			_, _ = s.oauthRepo.RevokeRefreshToken(input.RefreshToken)
			return nil, ErrAccessDenied
		}
	}

	/*
	 * L-9 修复：原子抢占 refresh token 撤销
	 * 并发场景：两个 client 同时用同一个 refresh_token 调 /oauth/token，
	 * 旧代码两个都通过 Revoked=false 校验并签出 token。
	 * 新代码用 RowsAffected==1 抢占，只有一个能继续签发。
	 */
	claimed, err := s.oauthRepo.RevokeRefreshToken(input.RefreshToken)
	if err != nil || !claimed {
		return nil, ErrInvalidGrant
	}
	s.oauthRepo.RevokeAccessToken(oldAccessToken.Token)

	authTime := oldAccessToken.AuthTime
	if authTime <= 0 {
		authTime = time.Now().Unix()
	}
	amr := decodeAMR(oldAccessToken.AMR)

	// Create new access token
	accessToken := &model.AccessToken{
		ClientID:  oldAccessToken.ClientID,
		UserID:    oldAccessToken.UserID,
		Scope:     oldAccessToken.Scope,
		AuthTime:  authTime,
		AMR:       oldAccessToken.AMR,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}

	if err := s.persistUserAccessToken(accessToken, user, authTime, amr); err != nil {
		return nil, err
	}

	newRefreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		UserID:        oldAccessToken.UserID,
		ExpiresAt:     time.Now().Add(s.config.OAuth.RefreshTokenTTL),
	}

	if err := s.persistUserRefreshToken(newRefreshToken, user, oldAccessToken.ClientID, oldAccessToken.Scope, authTime, amr); err != nil {
		return nil, err
	}

	result := &TokenResult{
		AccessToken:  accessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		RefreshToken: newRefreshToken.Token,
		Scope:        oldAccessToken.Scope,
	}
	if user != nil {
		if err := s.enrichTokenResultWithIDToken(result, user, input.ClientID, input.Issuer, oldAccessToken.Scope, "", authTime, amr); err != nil {
			return nil, err
		}
	}
	return result, nil
}

/*
 * clientCredentials 客户端凭证授权 (RFC 6749 Section 4.4)
 * 功能：机器对机器认证，无用户上下文，验证 client_id/secret 后直接签发 access_token
 *       不签发 refresh_token（客户端可随时重新认证）
 * @param input - Token 请求参数
 */
func (s *OAuthService) clientCredentials(input *TokenInput) (*TokenResult, error) {
	// Validate client credentials
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	/* 常量时间比较 client_secret，防止时序攻击 */
	if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
		return nil, ErrInvalidClient
	}

	/* 仅 machine / confidential 类型应用允许 client_credentials 授权 */
	if app.AppType != model.AppTypeMachine && app.AppType != model.AppTypeConfidential {
		return nil, ErrInvalidGrant
	}

	if !app.SupportsGrantType("client_credentials") {
		return nil, ErrInvalidGrant
	}

	scope, ok := app.ResolveClientCredentialsScope(input.Scope)
	if !ok {
		return nil, ErrInvalidScope
	}

	// Create access token (no end-user — UserID stays nil)
	accessToken := &model.AccessToken{
		ClientID:  input.ClientID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}

	if err := s.oauthRepo.CreateAccessToken(accessToken); err != nil {
		return nil, err
	}

	// Client credentials grant typically does not issue refresh tokens
	// as the client can always re-authenticate with its credentials
	return &TokenResult{
		AccessToken: accessToken.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		Scope:       scope,
	}, nil
}

/* Device Flow 错误定义 (RFC 8628) */
var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
)

/*
 * deviceCodeGrant 设备码授权 (RFC 8628)
 * 功能：设备轮询此端点直到用户在浏览器完成授权
 *       返回 authorization_pending / slow_down / access_denied / expired_token
 *       授权成功后签发 access_token + refresh_token 并删除设备码
 * @param input - Token 请求参数（需包含 DeviceCode）
 */
func (s *OAuthService) deviceCodeGrant(input *TokenInput) (*TokenResult, error) {
	if s.deviceRepo == nil {
		return nil, ErrInvalidGrant
	}

	if input.DeviceCode == "" {
		return nil, ErrInvalidGrant
	}

	// Find device code
	dc, err := s.deviceRepo.FindByDeviceCode(input.DeviceCode)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	// Validate client
	if dc.ClientID != input.ClientID {
		return nil, ErrInvalidClient
	}

	/* RFC 8628 Section 3.5: 强制执行轮询间隔，客户端过快轮询返回 slow_down */
	now := time.Now()
	if dc.LastPolledAt != nil {
		interval := time.Duration(dc.Interval) * time.Second
		if now.Sub(*dc.LastPolledAt) < interval {
			/* 记录本次轮询时间并增加 interval（slow_down 语义） */
			_ = s.deviceRepo.UpdateLastPolledAt(input.DeviceCode, now)
			return nil, ErrSlowDown
		}
	}
	_ = s.deviceRepo.UpdateLastPolledAt(input.DeviceCode, now)

	// Check if expired
	if dc.IsExpired() {
		return nil, ErrExpiredToken
	}

	// Check status
	switch dc.Status {
	case "pending":
		return nil, ErrAuthorizationPending
	case "denied":
		return nil, ErrAccessDenied
	case "authorized":
		/* 继续尝试原子消费 */
	case "consumed":
		return nil, ErrInvalidGrant
	default:
		return nil, ErrInvalidGrant
	}

	/*
	 * L-5 修复：原子消费 device_code，防止并发轮询重复签发 token。
	 * 只有第一个把 authorized -> consumed 的请求可以继续；其余并发请求直接失败。
	 */
	claimedDC, claimed, err := s.deviceRepo.ConsumeAuthorizedDeviceCode(input.DeviceCode)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if !claimed {
		return nil, ErrInvalidGrant
	}
	dc = claimedDC

	// Get user
	if dc.UserID == nil {
		return nil, ErrInvalidGrant
	}
	user, err := s.userRepo.FindByID(*dc.UserID)
	if err != nil || user.IsSuspended() {
		return nil, ErrAccessDenied
	}

	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if !app.SupportsGrantType("device_code") {
		return nil, ErrInvalidGrant
	}
	if !app.ValidateUserAuthorizationScope(dc.Scope) {
		return nil, ErrInvalidScope
	}

	authTime := time.Now().Unix()

	// Create access token
	accessToken := &model.AccessToken{
		ClientID:  input.ClientID,
		UserID:    &user.ID,
		Scope:     dc.Scope,
		AuthTime:  authTime,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}

	if err := s.persistUserAccessToken(accessToken, user, authTime, nil); err != nil {
		return nil, err
	}

	refreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		UserID:        dc.UserID,
		ExpiresAt:     time.Now().Add(s.config.OAuth.RefreshTokenTTL),
	}

	if err := s.persistUserRefreshToken(refreshToken, user, input.ClientID, dc.Scope, authTime, nil); err != nil {
		return nil, err
	}

	// Record user authorization
	if s.userAuthRepo != nil {
		app, _ := s.appRepo.FindByClientID(input.ClientID)
		if app != nil {
			s.userAuthRepo.CreateOrUpdate(user.ID, app.ID, dc.Scope, "device_code")
		}
	}

	result := &TokenResult{
		AccessToken:  accessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken.Token,
		Scope:        dc.Scope,
	}
	if err := s.enrichTokenResultWithIDToken(result, user, input.ClientID, input.Issuer, dc.Scope, "", authTime, nil); err != nil {
		return nil, err
	}
	return result, nil
}

/* Token 类型 URI 常量 (RFC 8693 Token Exchange) */
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

/* TokenExchangeResult Token Exchange 扩展响应结构 (RFC 8693) */
type TokenExchangeResult struct {
	TokenResult
	IssuedTokenType string `json:"issued_token_type"`
}

/*
 * tokenExchange Token 交换授权 (RFC 8693)
 * 功能：使用已有令牌换取新令牌，支持 access_token 和 refresh_token 类型交换
 *       可用于跨服务委托、令牌降权等场景
 * @param input - Token 请求参数（需包含 SubjectToken 和 SubjectTokenType）
 */
func (s *OAuthService) tokenExchange(input *TokenInput) (*TokenResult, error) {
	if input.SubjectToken == "" || input.SubjectTokenType == "" {
		return nil, ErrInvalidRequest
	}
	if input.ActorToken == "" && input.ActorTokenType != "" {
		return nil, ErrInvalidRequest
	}
	if input.ActorToken != "" && input.ActorTokenType == "" {
		return nil, ErrInvalidRequest
	}

	requestedType := input.RequestedTokenType
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}
	switch requestedType {
	case TokenTypeAccessToken, "access_token":
		requestedType = TokenTypeAccessToken
	case TokenTypeRefreshToken, "refresh_token":
		requestedType = TokenTypeRefreshToken
	default:
		return nil, ErrInvalidRequest
	}

	/*
	 * 强制要求客户端认证（RFC 8693 安全要求）
	 * 安全加固（M-4）：禁止 public 应用使用 token-exchange；公开客户端无法安全持有 secret，
	 * 不应被赋予委托/降权能力，否则会被前端 XSS / 移动端逆向直接利用。
	 */
	if input.ClientID == "" {
		return nil, ErrInvalidClient
	}
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	/* 仅 confidential / machine 允许 token-exchange */
	if app.AppType != model.AppTypeConfidential && app.AppType != model.AppTypeMachine {
		return nil, ErrInvalidClient
	}

	/* 机密客户端 / 机器客户端必须提供有效 secret */
	if input.ClientSecret == "" || subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
		return nil, ErrInvalidClient
	}

	if !app.SupportsGrantType("token_exchange") {
		return nil, ErrInvalidGrant
	}
	if requestedType == TokenTypeRefreshToken && !app.SupportsGrantType("refresh_token") {
		return nil, ErrInvalidGrant
	}

	if input.Audience != "" || input.Resource != "" {
		return nil, ErrInvalidTarget
	}

	var user *model.User
	var originalScope string
	var subjectClientID string /* 持有 subject_token 的原 client_id（用于 C-3 跨 client 校验） */
	var authTime int64
	var amr []string

	switch input.SubjectTokenType {
	case TokenTypeAccessToken, "access_token":
		u, accessToken, err := s.ValidateAccessToken(input.SubjectToken)
		if err != nil {
			return nil, ErrInvalidGrant
		}
		/* client_credentials 签发的 access_token 无用户上下文，禁止作为 subject_token 交换 */
		if u == nil || !accessToken.HasEndUser() {
			return nil, ErrInvalidGrant
		}
		user = u
		originalScope = accessToken.Scope
		subjectClientID = accessToken.ClientID
		authTime = accessToken.AuthTime
		amr = decodeAMR(accessToken.AMR)

	case TokenTypeRefreshToken, "refresh_token":
		refreshToken, err := s.oauthRepo.FindRefreshToken(input.SubjectToken)
		if err != nil || !refreshToken.IsValid() {
			return nil, ErrInvalidGrant
		}
		if refreshToken.AccessTokenID == nil {
			return nil, ErrInvalidGrant
		}
		accessToken, err := s.oauthRepo.FindAccessTokenByID(*refreshToken.AccessTokenID)
		if err != nil {
			return nil, ErrInvalidGrant
		}
		if !accessToken.HasEndUser() {
			return nil, ErrInvalidGrant
		}
		user, err = s.userRepo.FindByID(*accessToken.UserID)
		if err != nil {
			return nil, ErrInvalidGrant
		}
		originalScope = accessToken.Scope
		subjectClientID = accessToken.ClientID
		authTime = accessToken.AuthTime
		amr = decodeAMR(accessToken.AMR)

	default:
		return nil, ErrInvalidRequest
	}

	/*
	 * C-3 修复：subject_token 必须来自调用方自己的 client；禁止跨 client 委派
	 * （否则 app B 持有 secret 后用 app A 的 token 作为 subject_token 即可签出指向 app A 用户的 token）
	 */
	if subjectClientID == "" || subjectClientID != input.ClientID {
		return nil, ErrInvalidGrant
	}

	if user.IsSuspended() {
		return nil, ErrAccessDenied
	}
	if authTime <= 0 {
		authTime = time.Now().Unix()
	}

	if input.ActorToken != "" {
		switch input.ActorTokenType {
		case TokenTypeAccessToken, "access_token":
			_, actorAccessToken, err := s.ValidateAccessToken(input.ActorToken)
			if err != nil {
				return nil, ErrInvalidGrant
			}
			if actorAccessToken == nil || !actorAccessToken.HasEndUser() || actorAccessToken.ClientID != input.ClientID {
				return nil, ErrInvalidGrant
			}
		default:
			return nil, ErrInvalidRequest
		}
	}

	/*
	 * C-2 修复：scope 严格子集校验
	 * 规则：结果 scope ⊆ originalScope 且 ⊆ 应用 Scopes/AllowedScopes 白名单
	 */
	scope := input.Scope
	if scope == "" {
		scope = originalScope
	}
	if model.ScopeContainsWildcard(scope) {
		return nil, ErrInvalidScope
	}
	appAllowedSet := splitScopeSet(strings.Join(append(app.GetAllowedScopes(), app.GetScopes()...), " "))
	if len(appAllowedSet) == 0 {
		return nil, ErrInvalidScope
	}
	originalSet := splitScopeSet(originalScope)
	for _, s := range strings.Fields(scope) {
		if s == "" {
			continue
		}
		if !originalSet[s] || !appAllowedSet[s] {
			return nil, ErrInvalidScope
		}
	}

	newAccessToken := &model.AccessToken{
		ClientID:  input.ClientID,
		Scope:     scope,
		AuthTime:  authTime,
		AMR:       encodeAMR(amr),
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}
	if user != nil {
		newAccessToken.UserID = &user.ID
	}

	if err := s.persistUserAccessToken(newAccessToken, user, authTime, amr); err != nil {
		return nil, err
	}

	var newRefreshToken *model.RefreshToken
	if requestedType == TokenTypeRefreshToken {
		newRefreshToken = &model.RefreshToken{
			AccessTokenID: &newAccessToken.ID,
			UserID:        newAccessToken.UserID,
			ExpiresAt:     time.Now().Add(s.config.OAuth.RefreshTokenTTL),
		}
		if err := s.persistUserRefreshToken(newRefreshToken, user, input.ClientID, scope, authTime, amr); err != nil {
			return nil, err
		}
	}

	result := &TokenResult{
		AccessToken:     newAccessToken.Token,
		TokenType:       "Bearer",
		ExpiresIn:       int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		Scope:           scope,
		IssuedTokenType: requestedType,
	}

	if newRefreshToken != nil {
		result.RefreshToken = newRefreshToken.Token
	}

	if user != nil {
		if err := s.enrichTokenResultWithIDToken(result, user, input.ClientID, input.Issuer, scope, "", authTime, amr); err != nil {
			return nil, err
		}
	}

	return result, nil
}

/**
 * ValidateAccessToken 校验访问令牌并返回关联的用户与令牌实体
 *
 * @description
 *   完整校验链：DB 查 token → 校验未过期未撤销 → 拉取关联用户 →
 *   **校验用户状态**（active）— 禁用用户的 token 立即失效（L-3 修复）。
 *
 * @param  {string} token - 访问令牌字符串
 * @returns {(*model.User, *model.AccessToken, error)}
 *   user 在 client_credentials 模式下为 nil
 * @throws {ErrTokenExpired}  token 在 DB 中找不到
 * @throws {ErrTokenRevoked}  token 已撤销 / 过期
 * @throws {ErrAccessDenied}  关联用户已禁用
 * @security 用户从 active → disabled/suspended 后，其现有 token 立即在 API 鉴权层失效
 */
func (s *OAuthService) ValidateAccessToken(token string) (*model.User, *model.AccessToken, error) {
	accessToken, err := s.oauthRepo.FindAccessToken(token)
	if err != nil {
		return nil, nil, ErrTokenExpired
	}

	if !accessToken.IsValid() {
		return nil, nil, ErrTokenRevoked
	}

	if !accessToken.HasEndUser() {
		/* Client credentials token — no user associated */
		return nil, accessToken, nil
	}

	user, err := s.userRepo.FindByID(*accessToken.UserID)
	if err != nil {
		return nil, nil, err
	}

	/* L-3 修复：禁用 / 停用用户的 token 立即失效 */
	if user.IsSuspended() || user.Status == "disabled" {
		return nil, nil, ErrAccessDenied
	}

	return user, accessToken, nil
}

/*
 * RevokeToken 撤销令牌
 * 功能：根据 tokenTypeHint 撤销指定类型的令牌，未指定时两者都尝试
 * @param token         - 令牌字符串
 * @param tokenTypeHint - 令牌类型提示 (access_token / refresh_token)
 */
func (s *OAuthService) RevokeToken(token, tokenTypeHint string) error {
	return s.revokeToken(token, tokenTypeHint, "")
}

func (s *OAuthService) RevokeTokenForClient(token, tokenTypeHint, clientID, clientSecret string) error {
	app, err := s.appRepo.FindByClientID(clientID)
	if err != nil {
		return ErrInvalidClient
	}
	if app.AppType == model.AppTypeConfidential || app.AppType == model.AppTypeMachine {
		if clientSecret == "" || subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(clientSecret)) != 1 {
			return ErrInvalidClient
		}
	} else if clientSecret != "" {
		if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(clientSecret)) != 1 {
			return ErrInvalidClient
		}
	}

	ownerClientID, err := s.tokenOwnerClientID(token, tokenTypeHint)
	if err != nil {
		return err
	}
	if ownerClientID != clientID {
		return nil
	}
	return s.revokeToken(token, tokenTypeHint, clientID)
}

func (s *OAuthService) tokenOwnerClientID(token, tokenTypeHint string) (string, error) {
	findAccessTokenOwner := func() (string, bool) {
		at, err := s.oauthRepo.FindAccessToken(token)
		if err != nil {
			return "", false
		}
		return at.ClientID, true
	}

	findRefreshTokenOwner := func() (string, bool) {
		rt, err := s.oauthRepo.FindRefreshToken(token)
		if err != nil || rt.AccessTokenID == nil {
			return "", false
		}
		at, err := s.oauthRepo.FindAccessTokenByID(*rt.AccessTokenID)
		if err != nil {
			return "", false
		}
		return at.ClientID, true
	}

	switch tokenTypeHint {
	case "access_token":
		if clientID, ok := findAccessTokenOwner(); ok {
			return clientID, nil
		}
		if clientID, ok := findRefreshTokenOwner(); ok {
			return clientID, nil
		}
	case "refresh_token":
		if clientID, ok := findRefreshTokenOwner(); ok {
			return clientID, nil
		}
		if clientID, ok := findAccessTokenOwner(); ok {
			return clientID, nil
		}
	default:
		if clientID, ok := findAccessTokenOwner(); ok {
			return clientID, nil
		}
		if clientID, ok := findRefreshTokenOwner(); ok {
			return clientID, nil
		}
	}
	return "", ErrTokenExpired
}

func (s *OAuthService) revokeToken(token, tokenTypeHint, clientID string) error {
	revokeAccessToken := func() bool {
		at, err := s.oauthRepo.FindAccessToken(token)
		if err != nil {
			return false
		}
		if clientID != "" && at.ClientID != clientID {
			return true
		}
		_ = s.oauthRepo.RevokeAccessToken(token)
		_ = s.oauthRepo.RevokeRefreshTokenByAccessTokenID(at.ID)
		return true
	}

	revokeRefreshToken := func() bool {
		rt, err := s.oauthRepo.FindRefreshToken(token)
		if err != nil {
			return false
		}
		if rt.AccessTokenID != nil {
			if at, atErr := s.oauthRepo.FindAccessTokenByID(*rt.AccessTokenID); atErr == nil {
				if clientID != "" && at.ClientID != clientID {
					return true
				}
				_ = s.oauthRepo.RevokeAccessToken(at.Token)
			}
		}
		_, _ = s.oauthRepo.RevokeRefreshToken(token)
		return true
	}

	switch tokenTypeHint {
	case "access_token":
		if revokeAccessToken() || revokeRefreshToken() {
			return nil
		}
	case "refresh_token":
		if revokeRefreshToken() || revokeAccessToken() {
			return nil
		}
	default:
		if revokeAccessToken() || revokeRefreshToken() {
			return nil
		}
	}
	return ErrTokenExpired
}

/*
 * GetUserInfoWithScope 获取访问令牌关联的用户信息及授权 scope (OIDC UserInfo 端点)
 * @param token - 访问令牌字符串
 * @return *model.User  - 用户实体
 * @return string       - 令牌授权的 scope
 */
func (s *OAuthService) GetUserInfoWithScope(token string) (*model.User, string, error) {
	user, accessToken, err := s.ValidateAccessToken(token)
	if err != nil {
		return nil, "", err
	}
	if user == nil {
		return nil, "", ErrNoUserInToken
	}
	scope := ""
	if accessToken != nil {
		scope = accessToken.Scope
	}
	if !model.ScopeContainsOpenID(scope) {
		return nil, "", ErrInvalidScope
	}
	return user, scope, nil
}

/*
 * GetUserInfo 获取访问令牌关联的用户信息 (OIDC UserInfo 端点，向后兼容)
 * @param token - 访问令牌字符串
 * @return *model.User - 用户实体
 */
func (s *OAuthService) GetUserInfo(token string) (*model.User, error) {
	user, _, err := s.GetUserInfoWithScope(token)
	return user, err
}

/*
 * validateCodeVerifier PKCE code_verifier 校验 (RFC 7636)
 * @param verifier  - 客户端提供的 code_verifier
 * @param challenge - 授权请求时的 code_challenge
 * @param method    - 校验方法 (S256 / plain)
 * @return bool     - 校验通过返回 true
 */
func (s *OAuthService) validateCodeVerifier(verifier, challenge, method string) bool {
	if verifier == "" {
		return false
	}

	/*
	 * RFC 7636 §4.1: code_verifier 长度必须在 43-128 字符之间
	 * 过短的 verifier 安全熵不足，过长的超出规范
	 */
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}

	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		/* 使用常量时间比较防止时序攻击 */
		return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
	default:
		/* 仅支持 S256，拒绝 plain 和其他方法（符合 OAuth 2.1 草案要求） */
		return false
	}
}

/*
 * GetApplication 根据 client_id 获取应用
 * @param clientID - OAuth2 客户端 ID
 */
func (s *OAuthService) GetApplication(clientID string) (*model.Application, error) {
	return s.appRepo.FindByClientID(clientID)
}

/*
 * ParseScope 解析空格分隔的 scope 字符串
 * @param scope  - 空格分隔的 scope 字符串
 * @return []string - scope 切片
 */
func ParseScope(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Split(scope, " ")
}

/**
 * IntrospectToken Token 内省 (RFC 7662)
 *
 * @description
 *   校验令牌有效性并返回其元数据，支持 access_token 和 refresh_token。
 *
 *   安全加固：
 *   - L-24：secret 比较改用 ConstantTimeCompare 防止时序侧信道
 *   - H-3：public 客户端不再无凭据通过；至少要求 token 必须归属调用方 client_id
 *          （防止任意 public app 探测他人 token 元数据）
 *   - 当调用方不是 token 所属 client 时，返回 minimal info（active+exp），不暴露 user 字段
 *
 * @param  {string} token         - 待内省的令牌
 * @param  {string} clientID      - 请求客户端 ID（必填）
 * @param  {string} clientSecret  - 请求客户端密钥（confidential/machine 必填）
 * @param  {string} tokenTypeHint - "access_token" 或 "refresh_token"
 * @returns {(map[string]interface{}, error)} 令牌元数据
 * @throws  {ErrInvalidClient} 客户端鉴权失败
 * @security 跨 client 探测仅返回最少信息
 */
func (s *OAuthService) IntrospectToken(token, clientID, clientSecret, tokenTypeHint string) (map[string]interface{}, error) {
	/*
	 * RFC 7662 安全增强：强制要求客户端认证
	 * introspection 端点返回敏感信息（用户 ID、scope 等），必须验证调用者身份
	 * 拒绝无认证的请求，防止未授权方探测 token 状态
	 */
	if clientID == "" {
		return nil, ErrInvalidClient
	}
	app, err := s.appRepo.FindByClientID(clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	/*
	 * L-24 修复：所有 secret 比较改用 ConstantTimeCompare 防时序侧信道
	 * H-3 修复：public 应用即便不提供 secret 也通过 — 改为：
	 *   - confidential/machine：必须 secret
	 *   - public：必须 secret 或 token 归属本 client（下方再校验）
	 */
	if app.AppType == model.AppTypeConfidential || app.AppType == model.AppTypeMachine {
		if clientSecret == "" || subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(clientSecret)) != 1 {
			return nil, ErrInvalidClient
		}
	} else if clientSecret != "" {
		if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(clientSecret)) != 1 {
			return nil, ErrInvalidClient
		}
	}

	inactive := func() map[string]interface{} {
		return map[string]interface{}{"active": false}
	}

	introspectAccessToken := func() (map[string]interface{}, bool) {
		user, accessToken, err := s.ValidateAccessToken(token)
		if err != nil || accessToken == nil {
			return nil, false
		}
		/* RFC 7662 active=false：调用方不被允许内省该 token 时不泄露活跃状态 */
		if accessToken.ClientID != clientID {
			return inactive(), true
		}
		result := map[string]interface{}{
			"active":     true,
			"scope":      accessToken.Scope,
			"client_id":  accessToken.ClientID,
			"token_type": "Bearer",
			"exp":        accessToken.ExpiresAt.Unix(),
			"iat":        accessToken.CreatedAt.Unix(),
			"aud":        accessToken.ClientID,
			"iss":        s.config.JWT.Issuer,
		}
		/* 有用户关联时补充用户字段（client_credentials 模式无用户） */
		if user != nil {
			result["sub"] = user.ID.String()
			result["username"] = user.Username
			result["email"] = user.Email
			result["email_verified"] = user.EmailVerified
		}
		return result, true
	}

	introspectRefreshToken := func() (map[string]interface{}, bool) {
		refreshToken, err := s.oauthRepo.FindRefreshToken(token)
		if err != nil || refreshToken == nil || !refreshToken.ExpiresAt.After(time.Now()) || refreshToken.Revoked {
			return nil, false
		}
		var accessToken *model.AccessToken
		if refreshToken.AccessTokenID != nil {
			accessToken, _ = s.oauthRepo.FindAccessTokenByID(*refreshToken.AccessTokenID)
		}
		if accessToken == nil || !accessToken.HasEndUser() {
			return nil, false
		}
		/* H-3 跨 client 保护 */
		if accessToken.ClientID != clientID {
			return inactive(), true
		}
		user, err := s.userRepo.FindByID(*accessToken.UserID)
		if err != nil || user.IsSuspended() {
			return inactive(), true
		}
		return map[string]interface{}{
			"active":     true,
			"scope":      accessToken.Scope,
			"client_id":  accessToken.ClientID,
			"username":   user.Username,
			"token_type": "refresh_token",
			"exp":        refreshToken.ExpiresAt.Unix(),
			"iat":        refreshToken.CreatedAt.Unix(),
			"sub":        user.ID.String(),
		}, true
	}

	switch tokenTypeHint {
	case "access_token":
		if result, ok := introspectAccessToken(); ok {
			return result, nil
		}
		if result, ok := introspectRefreshToken(); ok {
			return result, nil
		}
	case "refresh_token":
		if result, ok := introspectRefreshToken(); ok {
			return result, nil
		}
		if result, ok := introspectAccessToken(); ok {
			return result, nil
		}
	default:
		if result, ok := introspectAccessToken(); ok {
			return result, nil
		}
		if result, ok := introspectRefreshToken(); ok {
			return result, nil
		}
	}

	/* 未找到或无效：RFC 7662 §2.2 要求返回 active=false 而非 4xx */
	return inactive(), nil
}
