package handler

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/audit"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/* federationHTTPClient 优化的 HTTP 客户端，配置合理的超时和连接池 */
var federationHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	},
}

/*
 * FederationHandler 联邦认证请求处理器
 * 功能：处理联邦提供者管理、联邦登录回调、身份关联、受信任应用等 HTTP 请求
 */
type FederationHandler struct {
	providerRepo *repository.FederationRepository
	userRepo     *repository.UserRepository
	oauthRepo    *repository.OAuthRepository
	jwtManager   *jwt.Manager
	baseURL      string
	httpClient   *http.Client
	cfg          *config.Config
}

/* SetOAuthRepo 注入 OAuthRepository（启用 Refresh Token Rotation） */
func (h *FederationHandler) SetOAuthRepo(repo *repository.OAuthRepository) {
	h.oauthRepo = repo
}

func (h *FederationHandler) isStoredAccessTokenUsable(token string, userID uuid.UUID) bool {
	if h.oauthRepo == nil {
		return true
	}
	accessToken, err := h.oauthRepo.FindAccessToken(token)
	if err != nil {
		return false
	}
	if !accessToken.IsValid() {
		return false
	}
	if !accessToken.HasEndUser() || accessToken.UserID == nil {
		return false
	}
	return *accessToken.UserID == userID
}

func (h *FederationHandler) storeFederationAccessToken(token string, userID uuid.UUID, ttl time.Duration) error {
	if h.oauthRepo == nil {
		return nil
	}
	return h.oauthRepo.CreateAccessToken(&model.AccessToken{
		Token:     token,
		ClientID:  "",
		UserID:    &userID,
		Scope:     federationLoginScope,
		ExpiresAt: time.Now().Add(ttl),
	})
}

func NewFederationHandler(
	providerRepo *repository.FederationRepository,
	userRepo *repository.UserRepository,
	jwtManager *jwt.Manager,
	baseURL string,
	cfg ...*config.Config,
) *FederationHandler {
	h := &FederationHandler{
		providerRepo: providerRepo,
		userRepo:     userRepo,
		jwtManager:   jwtManager,
		baseURL:      baseURL,
		httpClient:   federationHTTPClient,
	}
	if len(cfg) > 0 {
		h.cfg = cfg[0]
	}
	return h
}

// ListProviders returns all enabled federated providers (public)
// GET /api/federation/providers
func (h *FederationHandler) ListProviders(c *gin.Context) {
	providers, err := h.providerRepo.FindAllEnabled()
	if err != nil {
		InternalError(c, "Failed to fetch providers")
		return
	}

	// 只返回公开信息
	type PublicProvider struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Slug       string `json:"slug"`
		IconURL    string `json:"icon_url,omitempty"`
		ButtonText string `json:"button_text,omitempty"`
	}

	result := make([]PublicProvider, len(providers))
	for i, p := range providers {
		result[i] = PublicProvider{
			ID:         p.ID.String(),
			Name:       p.Name,
			Slug:       p.Slug,
			IconURL:    p.IconURL,
			ButtonText: p.ButtonText,
		}
	}

	Success(c, gin.H{"providers": result})
}

// InitiateLogin starts the federated login flow
// GET /api/federation/login/:slug
func (h *FederationHandler) InitiateLogin(c *gin.Context) {
	slug := c.Param("slug")
	returnTo := safeReturnPath(c.Query("return_to"))

	provider, err := h.providerRepo.FindBySlug(slug)
	if err != nil || !provider.Enabled {
		BadRequest(c, "Provider not found or disabled")
		return
	}

	// 生成state
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		InternalError(c, "Failed to generate security state")
		return
	}
	state := hex.EncodeToString(stateBytes)

	// 存储state和return_to（SameSite=Lax 允许同站顶级导航时携带）
	secure := isRequestSecure(c)
	setCookie(c, "fed_state", state, 600, "/", secure, true, http.SameSiteLaxMode)
	setCookie(c, "fed_return", returnTo, 600, "/", secure, true, http.SameSiteLaxMode)

	// 构建授权URL
	authURL, _ := url.Parse(provider.AuthURL)
	q := authURL.Query()
	q.Set("client_id", provider.ClientID)
	q.Set("redirect_uri", h.baseURL+"/api/federation/callback/"+slug)
	q.Set("response_type", "code")
	q.Set("scope", provider.Scopes)
	q.Set("state", state)
	authURL.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, authURL.String())
}

// Callback handles the OAuth2 callback from federated provider
// GET /api/federation/callback/:slug
func (h *FederationHandler) Callback(c *gin.Context) {
	slug := c.Param("slug")
	code := c.Query("code")
	state := c.Query("state")
	errorMsg := c.Query("error")

	if errorMsg != "" {
		h.redirectWithError(c, "Federation login denied: "+errorMsg)
		return
	}

	/* 验证 state（常量时间比较，防止时序攻击） */
	savedState, _ := c.Cookie("fed_state")
	if !hmac.Equal([]byte(state), []byte(savedState)) {
		h.redirectWithError(c, "Invalid state parameter")
		return
	}

	provider, err := h.providerRepo.FindBySlug(slug)
	if err != nil || !provider.Enabled {
		h.redirectWithError(c, "Provider not found")
		return
	}

	// 交换token
	tokenResp, err := h.exchangeToken(provider, code)
	if err != nil {
		h.redirectWithError(c, "Failed to exchange token: "+err.Error())
		return
	}

	// 获取用户信息
	userInfo, err := h.fetchUserInfo(provider, tokenResp.AccessToken)
	if err != nil {
		h.redirectWithError(c, "Failed to fetch user info: "+err.Error())
		return
	}

	// 查找或创建用户
	user, err := h.findOrCreateUser(provider, userInfo, tokenResp)
	if err != nil {
		h.redirectWithError(c, "Failed to process user: "+err.Error())
		return
	}

	tokens, err := h.issueFederationLocalTokens(user)
	if err != nil {
		h.redirectWithError(c, "Failed to generate login session")
		return
	}
	if err := h.persistFederationLocalTokens(tokens, user.ID); err != nil {
		h.redirectWithError(c, "Failed to persist login session")
		return
	}

	// 获取return_to
	returnTo, _ := c.Cookie("fed_return")
	returnTo = safeReturnPath(returnTo)

	// 清除cookies
	fedSecure := isRequestSecure(c)
	setCookie(c, "fed_state", "", -1, "/", fedSecure, true, http.SameSiteLaxMode)
	setCookie(c, "fed_return", "", -1, "/", fedSecure, true, http.SameSiteLaxMode)

	setAuthTokenCookies(c, tokens, int(h.federationRefreshTokenTTL().Seconds()))

	c.Redirect(http.StatusFound, returnTo)
}

const federationLoginScope = "openid profile email"

func (h *FederationHandler) federationAccessTokenTTL() time.Duration {
	if h.cfg != nil && h.cfg.JWT.AccessTokenTTL > 0 {
		return h.cfg.JWT.AccessTokenTTL
	}
	return time.Hour
}

func (h *FederationHandler) federationRefreshTokenTTL() time.Duration {
	if h.cfg != nil && h.cfg.JWT.RefreshTokenTTL > 0 {
		return h.cfg.JWT.RefreshTokenTTL
	}
	return 30 * 24 * time.Hour
}

func (h *FederationHandler) federationIDTokenTTL() time.Duration {
	if h.cfg != nil && h.cfg.OAuth.IDTokenTTL > 0 {
		return h.cfg.OAuth.IDTokenTTL
	}
	return h.federationAccessTokenTTL()
}

func (h *FederationHandler) issueFederationLocalTokens(user *model.User) (*service.AuthTokens, error) {
	authTime := time.Now().Unix()
	accessTTL := h.federationAccessTokenTTL()
	refreshTTL := h.federationRefreshTokenTTL()

	accessToken, err := h.jwtManager.GenerateTokenWithAuthTime(
		user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeAccess, authTime, accessTTL,
	)
	if err != nil {
		return nil, err
	}
	refreshToken, err := h.jwtManager.GenerateTokenWithAuthTime(
		user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeRefresh, authTime, refreshTTL,
	)
	if err != nil {
		return nil, err
	}
	idToken, err := h.jwtManager.GenerateIDTokenWithNonceAndAuthTime(
		user.ID, user.Email, user.Username, string(user.Role), "", federationLoginScope, "", authTime, h.federationIDTokenTTL(),
	)
	if err != nil {
		return nil, err
	}

	return &service.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTTL.Seconds()),
	}, nil
}

func (h *FederationHandler) persistFederationLocalTokens(tokens *service.AuthTokens, userID uuid.UUID) error {
	if h.oauthRepo == nil {
		return nil
	}
	if err := h.storeFederationAccessToken(tokens.AccessToken, userID, h.federationAccessTokenTTL()); err != nil {
		return err
	}
	refreshClaims, err := h.jwtManager.ValidateRefreshToken(tokens.RefreshToken)
	if err != nil {
		return err
	}
	return h.oauthRepo.StoreAuthRefreshToken(refreshClaims.ID, userID, refreshClaims.ExpiresAt.Time)
}

// VerifyToken verifies a token from a trusted app (for multi-system SSO)
// POST /api/federation/verify
func (h *FederationHandler) VerifyToken(c *gin.Context) {
	var req struct {
		Token     string `json:"token" binding:"required"`
		APIKey    string `json:"api_key" binding:"required"`
		APISecret string `json:"api_secret" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "Invalid request")
		return
	}

	/* 验证 API 凭据（使用常量时间比较 API_Secret，防止时序攻击） */
	trustedApp, err := h.providerRepo.FindTrustedAppByAPIKey(req.APIKey)
	if err != nil || !trustedApp.Enabled {
		Unauthorized(c, "Invalid API credentials")
		return
	}
	if !hmac.Equal([]byte(trustedApp.APISecret), []byte(req.APISecret)) {
		Unauthorized(c, "Invalid API credentials")
		return
	}

	if !trustedApp.CanVerifyTokens {
		Forbidden(c, "Not authorized to verify tokens")
		return
	}

	// 验证 access token，禁止 refresh token 被当作 access token 使用
	claims, err := h.jwtManager.ValidateAccessToken(req.Token)
	if err != nil {
		Unauthorized(c, "Invalid or expired token")
		return
	}

	if !h.isStoredAccessTokenUsable(req.Token, claims.UserID) {
		Unauthorized(c, "Invalid or expired token")
		return
	}

	// 获取用户信息
	user, err := h.userRepo.FindByID(claims.UserID)
	if err != nil {
		Unauthorized(c, "User not found")
		return
	}
	if user.IsSuspended() {
		if h.oauthRepo != nil {
			_ = h.oauthRepo.RevokeTokensByUserID(user.ID)
		}
		Unauthorized(c, "User account is disabled")
		return
	}

	// 返回用户信息
	Success(c, gin.H{
		"valid": true,
		"user": gin.H{
			"id":             user.ID.String(),
			"email":          user.Email,
			"username":       user.Username,
			"email_verified": user.EmailVerified,
			"role":           user.Role,
		},
		"expires_at": claims.ExpiresAt.Unix(),
	})
}

// --- Admin endpoints ---

// AdminListProviders returns all providers (admin only)
// GET /api/admin/federation/providers
func (h *FederationHandler) AdminListProviders(c *gin.Context) {
	providers, err := h.providerRepo.FindAll()
	if err != nil {
		InternalError(c, "Failed to fetch providers")
		return
	}
	Success(c, gin.H{"providers": providers})
}

/*
 * AdminCreateProvider 创建联邦提供者（管理员专用）
 * 安全：校验必填字段、URL 格式和 slug 合法性
 * @route POST /api/admin/federation/providers
 */
func (h *FederationHandler) AdminCreateProvider(c *gin.Context) {
	var req model.FederatedProvider
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	/* 必填字段校验 */
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(req.Slug)
	req.AuthURL = strings.TrimSpace(req.AuthURL)
	req.TokenURL = strings.TrimSpace(req.TokenURL)
	req.UserInfoURL = strings.TrimSpace(req.UserInfoURL)
	req.ClientID = strings.TrimSpace(req.ClientID)

	if req.Name == "" || req.Slug == "" || req.ClientID == "" || req.ClientSecret == "" {
		BadRequest(c, "Name, slug, client_id and client_secret are required")
		return
	}

	/* URL 格式校验：必须是 https:// 开头（生产环境安全要求） */
	for _, u := range []string{req.AuthURL, req.TokenURL, req.UserInfoURL} {
		if u == "" {
			BadRequest(c, "auth_url, token_url, and userinfo_url are required")
			return
		}
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			BadRequest(c, "URLs must start with http:// or https://")
			return
		}
	}

	if err := h.providerRepo.CreateProvider(&req); err != nil {
		InternalError(c, "Failed to create provider: "+err.Error())
		return
	}

	audit.Log(audit.ActionProviderCreate, audit.ResultSuccess, getActorID(c), req.ID.String(), c.ClientIP(), "provider", req.Slug)
	Success(c, req)
}

type federatedProviderUpdateRequest struct {
	Name               *string `json:"name,omitempty"`
	Slug               *string `json:"slug,omitempty"`
	Description        *string `json:"description,omitempty"`
	AuthURL            *string `json:"auth_url,omitempty"`
	TokenURL           *string `json:"token_url,omitempty"`
	UserInfoURL        *string `json:"userinfo_url,omitempty"`
	ClientID           *string `json:"client_id,omitempty"`
	ClientSecret       *string `json:"client_secret,omitempty"`
	Scopes             *string `json:"scopes,omitempty"`
	Enabled            *bool   `json:"enabled,omitempty"`
	AutoCreateUser     *bool   `json:"auto_create_user,omitempty"`
	TrustEmailVerified *bool   `json:"trust_email_verified,omitempty"`
	SyncProfile        *bool   `json:"sync_profile,omitempty"`
	IconURL            *string `json:"icon_url,omitempty"`
	ButtonText         *string `json:"button_text,omitempty"`
}

// AdminUpdateProvider updates a provider
// PUT /api/admin/federation/providers/:id
func (h *FederationHandler) AdminUpdateProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid provider ID")
		return
	}

	provider, err := h.providerRepo.FindByID(id)
	if err != nil {
		NotFound(c, "Provider not found")
		return
	}

	var req federatedProviderUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	if req.Name != nil {
		provider.Name = strings.TrimSpace(*req.Name)
	}
	if req.Slug != nil {
		provider.Slug = strings.TrimSpace(*req.Slug)
	}
	if req.Description != nil {
		provider.Description = strings.TrimSpace(*req.Description)
	}
	if req.AuthURL != nil {
		provider.AuthURL = strings.TrimSpace(*req.AuthURL)
	}
	if req.TokenURL != nil {
		provider.TokenURL = strings.TrimSpace(*req.TokenURL)
	}
	if req.UserInfoURL != nil {
		provider.UserInfoURL = strings.TrimSpace(*req.UserInfoURL)
	}
	if req.ClientID != nil {
		provider.ClientID = strings.TrimSpace(*req.ClientID)
	}
	if req.ClientSecret != nil && strings.TrimSpace(*req.ClientSecret) != "" {
		provider.ClientSecret = *req.ClientSecret
	}
	if req.Scopes != nil {
		provider.Scopes = strings.TrimSpace(*req.Scopes)
	}
	if req.Enabled != nil {
		provider.Enabled = *req.Enabled
	}
	if req.AutoCreateUser != nil {
		provider.AutoCreateUser = *req.AutoCreateUser
	}
	if req.TrustEmailVerified != nil {
		provider.TrustEmailVerified = *req.TrustEmailVerified
	}
	if req.SyncProfile != nil {
		provider.SyncProfile = *req.SyncProfile
	}
	if req.IconURL != nil {
		provider.IconURL = strings.TrimSpace(*req.IconURL)
	}
	if req.ButtonText != nil {
		provider.ButtonText = strings.TrimSpace(*req.ButtonText)
	}

	if provider.Name == "" || provider.Slug == "" || provider.ClientID == "" || provider.ClientSecret == "" {
		BadRequest(c, "Name, slug, client_id and client_secret are required")
		return
	}

	for _, u := range []string{provider.AuthURL, provider.TokenURL, provider.UserInfoURL} {
		if u == "" {
			BadRequest(c, "auth_url, token_url, and userinfo_url are required")
			return
		}
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			BadRequest(c, "URLs must start with http:// or https://")
			return
		}
	}

	if err = h.providerRepo.UpdateProvider(provider); err != nil {
		InternalError(c, "Failed to update provider")
		return
	}

	Success(c, provider)
}

// AdminDeleteProvider deletes a provider
// DELETE /api/admin/federation/providers/:id
func (h *FederationHandler) AdminDeleteProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid provider ID")
		return
	}

	if err := h.providerRepo.DeleteProvider(id); err != nil {
		InternalError(c, "Failed to delete provider")
		return
	}

	audit.Log(audit.ActionProviderDelete, audit.ResultSuccess, getActorID(c), id.String(), c.ClientIP())
	Success(c, gin.H{"message": "Provider deleted"})
}

// --- Helper functions ---

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func (h *FederationHandler) exchangeToken(provider *model.FederatedProvider, code string) (*tokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", h.baseURL+"/api/federation/callback/"+provider.Slug)
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "POST", provider.TokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	/* 限制响应体大小（1MB），防止恶意提供者返回超大响应导致 OOM */
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

type userInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Nickname      string `json:"nickname"`
	Picture       string `json:"picture"`
}

func (h *FederationHandler) fetchUserInfo(provider *model.FederatedProvider, accessToken string) (*userInfoResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", provider.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	/* 限制响应体大小（1MB），防止恶意提供者返回超大响应 */
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo failed: %s", string(body))
	}

	var userInfo userInfoResponse
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

/**
 * findOrCreateUser 根据联邦身份查找或创建本地用户
 *
 * @description
 *   流程：
 *   1. 已有 FederatedIdentity → 复用关联用户（更新 token + 同步 profile）
 *   2. 该 sub 没有绑定 → 按 email 查本地用户：
 *      - C-4 安全修复：**只有当 provider.TrustEmailVerified==true 且 userInfo.EmailVerified==true
 *        时才允许自动合并**。否则拒绝自动合并（防止恶意 IdP 注册 admin@victim 接管管理员）。
 *   3. 无现有用户 → 按 provider.AutoCreateUser 决定是否新建
 *
 * @param  {*model.FederatedProvider} provider
 * @param  {*userInfoResponse}        userInfo
 * @param  {*tokenResponse}           tokenResp
 * @returns {(*model.User, error)}
 * @throws  {error} 当邮箱已存在但未通过双向验证 → 阻止自动合并
 * @security C-4 修复：未验证邮箱不允许自动合并已有账户
 */
func (h *FederationHandler) findOrCreateUser(provider *model.FederatedProvider, userInfo *userInfoResponse, tokenResp *tokenResponse) (*model.User, error) {
	// 先查找已关联的身份
	identity, err := h.providerRepo.FindIdentityByExternalID(provider.ID, userInfo.Sub)
	if err == nil && identity != nil {
		// 已有关联，更新token并返回用户
		identity.AccessToken = tokenResp.AccessToken
		identity.RefreshToken = tokenResp.RefreshToken
		identity.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		h.providerRepo.UpdateIdentity(identity)

		user, _ := h.userRepo.FindByID(identity.UserID)
		if user != nil && provider.SyncProfile {
			// 同步资料
			h.syncUserProfile(user, userInfo)
		}
		return user, nil
	}

	// 查找邮箱是否已存在
	user, err := h.userRepo.FindByEmail(userInfo.Email)
	if err != nil {
		if !provider.AutoCreateUser {
			return nil, fmt.Errorf("user not found and auto-create is disabled")
		}
		// 创建新用户
		user = &model.User{
			Email:         userInfo.Email,
			Username:      h.generateUsername(userInfo),
			PasswordHash:  "", // 无密码
			EmailVerified: provider.TrustEmailVerified && userInfo.EmailVerified,
			GivenName:     userInfo.GivenName,
			FamilyName:    userInfo.FamilyName,
			Nickname:      userInfo.Nickname,
			Avatar:        userInfo.Picture,
		}
		if err := h.userRepo.Create(user); err != nil {
			return nil, err
		}
	} else {
		/*
		 * C-4 修复（关键安全分支）：
		 * 本地已存在该邮箱用户 → 必须双向验证后才能自动合并。
		 *
		 * 拒绝合并条件（任一）：
		 *   - provider 未被管理员标记为可信邮箱来源（TrustEmailVerified=false）
		 *   - 远端 userInfo 没有标记邮箱已验证（防止恶意 IdP 伪造）
		 *
		 * 拒绝时不抛具体原因（防止用户枚举），让用户先登录本地账号再手动绑定。
		 */
		if !(provider.TrustEmailVerified && userInfo.EmailVerified) {
			return nil, fmt.Errorf("email already registered; please sign in first and link the provider manually")
		}
	}

	// 创建联邦身份关联
	identity = &model.FederatedIdentity{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    userInfo.Sub,
		ExternalEmail: userInfo.Email,
		AccessToken:   tokenResp.AccessToken,
		RefreshToken:  tokenResp.RefreshToken,
		TokenExpiry:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}
	h.providerRepo.CreateIdentity(identity)

	return user, nil
}

func (h *FederationHandler) syncUserProfile(user *model.User, userInfo *userInfoResponse) {
	updated := false
	if userInfo.GivenName != "" && user.GivenName == "" {
		user.GivenName = userInfo.GivenName
		updated = true
	}
	if userInfo.FamilyName != "" && user.FamilyName == "" {
		user.FamilyName = userInfo.FamilyName
		updated = true
	}
	if userInfo.Nickname != "" && user.Nickname == "" {
		user.Nickname = userInfo.Nickname
		updated = true
	}
	if userInfo.Picture != "" && user.Avatar == "" {
		user.Avatar = userInfo.Picture
		updated = true
	}
	if updated {
		h.userRepo.Update(user)
	}
}

func (h *FederationHandler) generateUsername(userInfo *userInfoResponse) string {
	if userInfo.Nickname != "" {
		return userInfo.Nickname
	}
	if userInfo.Name != "" {
		return strings.ReplaceAll(userInfo.Name, " ", "")
	}
	// 从邮箱生成
	parts := strings.Split(userInfo.Email, "@")
	return parts[0]
}

func (h *FederationHandler) redirectWithError(c *gin.Context, msg string) {
	c.Redirect(http.StatusFound, "/login?error="+url.QueryEscape(msg))
}
