package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"
	"server/pkg/logger"
	"server/pkg/sanitize"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * SDKHandler SDK 接入请求处理器
 * 功能：处理第三方应用通过 SDK 进行的用户注册、登录、Token 刷新/验证、用户同步等 HTTP 请求
 *       所有请求需携带 client_id + client_secret 进行客户端认证
 */
type SDKHandler struct {
	authService     *service.AuthService
	appRepo         *repository.ApplicationRepository
	oauthRepo       *repository.OAuthRepository
	sdkExternalRepo *repository.SDKExternalIdentityRepository
	riskEventRepo   *repository.RiskEventRepository
	jwtManager      *jwt.Manager
	webhookService  *service.WebhookService
}

/*
 * NewSDKHandler 创建 SDK 处理器实例
 * @param authService - 认证服务
 * @param appRepo     - 应用仓储
 * @param jwtManager  - JWT 管理器
 */
func NewSDKHandler(authService *service.AuthService, appRepo *repository.ApplicationRepository, jwtManager *jwt.Manager) *SDKHandler {
	return &SDKHandler{
		authService: authService,
		appRepo:     appRepo,
		jwtManager:  jwtManager,
	}
}

/* SetWebhookService 注入 Webhook 服务（用于触发用户注册/登录事件） */
func (h *SDKHandler) SetWebhookService(ws *service.WebhookService) {
	h.webhookService = ws
}

func (h *SDKHandler) SetOAuthRepo(repo *repository.OAuthRepository) {
	h.oauthRepo = repo
}

/* SetSDKExternalIdentityRepo 注入 SDK 外部身份仓储（用于多平台单用户关联） */
func (h *SDKHandler) SetSDKExternalIdentityRepo(repo *repository.SDKExternalIdentityRepository) {
	h.sdkExternalRepo = repo
}

/* SetRiskEventRepository 注入风控事件仓储（用于记录 SDK 外部身份绑定冲突） */
func (h *SDKHandler) SetRiskEventRepository(repo *repository.RiskEventRepository) {
	h.riskEventRepo = repo
}

/* SDKRegisterRequest SDK 用户注册请求体 */
type SDKRegisterRequest struct {
	ClientID       string `json:"client_id" binding:"required"`
	ClientSecret   string `json:"client_secret" binding:"required"`
	Email          string `json:"email" binding:"required,email"`
	Username       string `json:"username" binding:"required,min=3,max=50"`
	Password       string `json:"password" binding:"required,min=8"`
	ExternalID     string `json:"external_id,omitempty"`
	ExternalSource string `json:"external_source,omitempty"`
}

/* SDKLoginRequest SDK 用户登录请求体 */
type SDKLoginRequest struct {
	ClientID       string `json:"client_id" binding:"required"`
	ClientSecret   string `json:"client_secret" binding:"required"`
	Email          string `json:"email" binding:"required,email"`
	Password       string `json:"password" binding:"required"`
	ExternalID     string `json:"external_id,omitempty"`
	ExternalSource string `json:"external_source,omitempty"`
}

// SDKTokenResponse represents token response for SDK
type SDKTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	User         struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
}

const (
	sdkAccessTokenTTL  = 24 * time.Hour
	sdkRefreshTokenTTL = 7 * 24 * time.Hour
	sdkUserScope       = "openid profile email"
)

type sdkIssuedTokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int64
}

func (h *SDKHandler) issueSDKUserTokens(user *model.User, clientID, clientSecret string, authTime int64) (*sdkIssuedTokens, error) {
	if authTime <= 0 {
		authTime = time.Now().Unix()
	}
	amr := []string{jwt.AuthenticationMethodPassword}
	accessToken, err := h.jwtManager.GenerateClientTokenWithScopeAndAuthTimeAndAMR(
		user.ID, user.Email, user.Username, string(user.Role),
		clientID, sdkUserScope, jwt.TokenTypeAccess, authTime, amr, sdkAccessTokenTTL,
	)
	if err != nil {
		return nil, err
	}
	refreshToken, err := h.jwtManager.GenerateClientTokenWithScopeAndAuthTimeAndAMR(
		user.ID, user.Email, user.Username, string(user.Role),
		clientID, sdkUserScope, jwt.TokenTypeRefresh, authTime, amr, sdkRefreshTokenTTL,
	)
	if err != nil {
		return nil, err
	}
	idToken, err := h.jwtManager.GenerateClientIDTokenWithNonceAndAuthTimeAndAMRAndATHash(
		user.ID, user.Email, user.Username, string(user.Role),
		clientID, clientSecret, sdkUserScope, "", authTime, amr, jwt.AccessTokenHash(accessToken), sdkAccessTokenTTL,
	)
	if err != nil {
		return nil, err
	}
	return &sdkIssuedTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ExpiresIn:    int64(sdkAccessTokenTTL.Seconds()),
	}, nil
}

func (h *SDKHandler) persistSDKUserTokens(tokens *sdkIssuedTokens, clientID string, userID uuid.UUID) error {
	if h.oauthRepo == nil {
		return nil
	}
	if err := h.storeSDKAccessToken(tokens.AccessToken, clientID, userID, sdkAccessTokenTTL); err != nil {
		return err
	}
	refreshClaims, err := h.jwtManager.ValidateRefreshToken(tokens.RefreshToken)
	if err != nil {
		return err
	}
	return h.oauthRepo.StoreAuthRefreshToken(refreshClaims.ID, userID, refreshClaims.ExpiresAt.Time)
}

func sdkTokenResponse(user *model.User, tokens *sdkIssuedTokens) SDKTokenResponse {
	resp := SDKTokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokens.ExpiresIn,
	}
	resp.User.ID = user.ID.String()
	resp.User.Email = user.Email
	resp.User.Username = user.Username
	resp.User.Role = string(user.Role)
	return resp
}

// Register handles user registration via SDK
// POST /api/sdk/register
func (h *SDKHandler) Register(c *gin.Context) {
	var req SDKRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Validate client credentials
	app, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	/* 输入清洗 */
	req.Email = sanitize.Email(req.Email)
	if u, ok := sanitize.Username(req.Username); ok {
		req.Username = u
	} else {
		BadRequest(c, "Invalid username format")
		return
	}

	if err := h.ensureSDKExternalIdentityAvailable(uuid.Nil, req.ExternalSource, req.ExternalID); err != nil {
		if errors.Is(err, repository.ErrSDKExternalIdentityAlreadyExists) {
			h.recordSDKExternalIdentityConflict(c, nil)
			Conflict(c, "External identity belongs to another user")
			return
		}
		InternalError(c, "Failed to link external identity")
		return
	}

	// Register user
	user, err := h.authService.Register(&service.RegisterInput{
		Email:    req.Email,
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrEmailExists) {
			Conflict(c, "Email already exists")
			return
		}
		if errors.Is(err, service.ErrUsernameExists) {
			Conflict(c, "Username already exists")
			return
		}
		InternalError(c, "Failed to create user")
		return
	}
	if err := h.ensureSDKExternalIdentity(user.ID, req.ExternalSource, req.ExternalID); err != nil {
		if errors.Is(err, repository.ErrSDKExternalIdentityAlreadyExists) {
			h.recordSDKExternalIdentityConflict(c, &user.ID)
			Conflict(c, "External identity belongs to another user")
			return
		}
		InternalError(c, "Failed to link external identity")
		return
	}

	/*
	 * 生成 client-scoped token（H-2 修复）：
	 * SDK 颁发的 token 携带 ClientID claim，aud=client_id；中央 AdminOnly 中间件
	 * 会拒绝此类 token，防止外部应用通过 SDK 获取 admin role token 进入控制台。
	 */
	tokens, err := h.issueSDKUserTokens(user, app.ClientID, app.ClientSecret, time.Now().Unix())
	if err != nil {
		InternalError(c, "Failed to generate registration session")
		return
	}
	if err := h.persistSDKUserTokens(tokens, app.ClientID, user.ID); err != nil {
		InternalError(c, "Failed to persist registration session")
		return
	}
	if sessionErr := h.authService.RecordAuthenticatedSession(user, &service.LoginInput{
		Email:     user.Email,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		LoginType: model.LoginTypeSDK,
		AppID:     &app.ID,
	}); sessionErr != nil {
		InternalError(c, "Failed to persist registration session")
		return
	}

	// Emit SSE event
	EmitAuthEvent(AuthEvent{
		Type:      "user_registered",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		Timestamp: time.Now(),
	})

	// Trigger webhook
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), app.ID, model.WebhookEventUserRegistered, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"source":   "sdk",
		})
	}

	Created(c, sdkTokenResponse(user, tokens))
}

// Login handles user login via SDK
// POST /api/sdk/login
func (h *SDKHandler) Login(c *gin.Context) {
	var req SDKLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Validate client credentials
	app, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	// Login user
	user, err := h.authService.AuthenticateLogin(&service.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		LoginType: model.LoginTypeSDK,
		AppID:     &app.ID,
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			Unauthorized(c, "Invalid email or password")
			return
		}
		if errors.Is(err, service.ErrAccountLocked) {
			Error(c, http.StatusTooManyRequests, "ACCOUNT_LOCKED", "Account temporarily locked due to too many failed attempts. Please try again later.")
			return
		}
		if errors.Is(err, service.ErrSuspiciousLogin) {
			Error(c, http.StatusForbidden, ErrCodeSuspiciousLogin, "Login blocked due to suspicious activity")
			return
		}
		InternalError(c, "Failed to login")
		return
	}

	if err := h.ensureSDKExternalIdentity(user.ID, req.ExternalSource, req.ExternalID); err != nil {
		if errors.Is(err, repository.ErrSDKExternalIdentityAlreadyExists) {
			h.recordSDKExternalIdentityConflict(c, &user.ID)
			Conflict(c, "External identity belongs to another user")
			return
		}
		InternalError(c, "Failed to link external identity")
		return
	}

	/* SDK 颁发 client-scoped token：aud=client_id + ClientID claim，AdminOnly 中间件会拒绝（H-2） */
	tokens, err := h.issueSDKUserTokens(user, app.ClientID, app.ClientSecret, time.Now().Unix())
	if err != nil {
		InternalError(c, "Failed to generate login session")
		return
	}
	if err := h.persistSDKUserTokens(tokens, app.ClientID, user.ID); err != nil {
		InternalError(c, "Failed to persist login session")
		return
	}

	// Emit SSE event
	EmitAuthEvent(AuthEvent{
		Type:      "user_login",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		Timestamp: time.Now(),
	})

	// Trigger webhook
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), app.ID, model.WebhookEventUserLogin, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"source":   "sdk",
		})
	}

	Success(c, sdkTokenResponse(user, tokens))
}

/**
 * SignTokenRequest 自定义 token 签发请求
 *
 * @description
 *   重要安全变更（修复 0day C-1）：
 *   - **移除** UserID 任意指定字段；服务 token 的 subject 自动绑定为 app.UserID（应用所有者）
 *   - **限制** 仅 confidential / machine 类型应用允许使用
 *   - **role 强制为 "service"**，不透传用户真实角色，防止越权获得 admin token
 *   - 颁发的 token 带 audience=client_id + ClientID 字段，AdminOnly 中间件会拒绝
 */
type SignTokenRequest struct {
	/** 应用 client_id */
	ClientID string `json:"client_id" binding:"required"`

	/** 应用 client_secret */
	ClientSecret string `json:"client_secret" binding:"required"`

	/** 自定义 claims（可选，仅 metadata 用途，不影响鉴权） */
	Claims map[string]interface{} `json:"claims"`

	/** 有效期（秒），默认 3600，最大 86400 */
	ExpiresIn int64 `json:"expires_in"`
}

/**
 * SignToken 为应用签发服务级 access token（M2M 场景）
 *
 * @route   POST /token/sign
 * @middleware AuthRateLimiter
 *
 * @description
 *   仅供应用以自己的身份获取服务级 token，用于调用受 OAuth 保护的资源 API。
 *   不再允许任意指定 user_id（修复 C-1：任意应用 client_secret 可签发 admin token）。
 *
 *   颁发的 token 特征：
 *   - Subject = app.UserID（应用所有者）
 *   - Role    = "service"（固定，不携带 admin/user）
 *   - aud     = client_id
 *   - ClientID claim = client_id（AdminOnly 中间件会因此拒绝该 token）
 *
 *   适用条件（任一不满足直接 403）：
 *   - app_type 必须是 confidential 或 machine
 *   - client_secret 校验通过（ConstantTimeCompare）
 *
 * @security 移除 user_id 任意指定 + role 强制 service + audience 隔离
 */
func (h *SDKHandler) SignToken(c *gin.Context) {
	var req SignTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	/* 验证 client 凭据 */
	app, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	/* 安全要求：仅 confidential / machine 类型应用允许签发服务 token，public/SPA 不允许 */
	if app.AppType != model.AppTypeConfidential && app.AppType != model.AppTypeMachine {
		Forbidden(c, "Token signing is restricted to confidential or machine clients")
		return
	}

	/* 默认/最大有效期 */
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	if expiresIn > 86400 { /* 最大 1 天，比原来的 30 天大幅收紧 */
		expiresIn = 86400
	}

	/*
	 * 安全约束：
	 * - subject 强制为 app 所有者，不接受外部传入的 user_id
	 * - role 强制 "service"
	 * - audience = client_id，并写入 ClientID claim
	 *   → 中央 AdminOnly 中间件会拒绝该 token，防止任意签发 admin token 提权
	 */
	owner, err := h.authService.GetUserByID(app.UserID)
	if err != nil {
		InternalError(c, "App owner not found")
		return
	}

	token, err := h.jwtManager.GenerateClientToken(
		owner.ID,
		owner.Email,
		owner.Username,
		"service", /* 强制 role */
		app.ClientID,
		jwt.TokenTypeAccess,
		time.Duration(expiresIn)*time.Second,
	)
	if err != nil {
		InternalError(c, "Failed to generate token")
		return
	}
	if storeErr := h.storeSDKAccessToken(token, app.ClientID, owner.ID, time.Duration(expiresIn)*time.Second); storeErr != nil {
		InternalError(c, "Failed to persist service token")
		return
	}

	Success(c, gin.H{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": expiresIn,
		"scope":      "service",
		"client_id":  app.ClientID,
	})
}

// ========== 用户同步 API ==========

// SyncUserRequest 用户同步请求（接入应用注册的用户同步到OAuth系统）
type SyncUserRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`

	// 必填字段
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required,min=2,max=50"`

	// 外部系统ID（用于关联）
	ExternalID     string `json:"external_id"`
	ExternalSource string `json:"external_source"`

	// 可选：设置密码（如果用户需要直接登录OAuth系统）
	Password string `json:"password,omitempty"`

	// OIDC标准字段
	GivenName   string `json:"given_name,omitempty"`
	FamilyName  string `json:"family_name,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	Gender      string `json:"gender,omitempty"`
	Birthdate   string `json:"birthdate,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Avatar      string `json:"avatar,omitempty"`

	// 元数据
	EmailVerified bool `json:"email_verified"`
}

// SyncUser 同步用户到OAuth系统
// POST /api/sdk/sync/user
func (h *SDKHandler) SyncUser(c *gin.Context) {
	var req SyncUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	app, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	// 查找是否已存在用户
	existingUser, conflict := h.findSDKSyncUser(&req)
	if conflict {
		h.recordSDKExternalIdentityConflict(c, nil)
		Conflict(c, "External identity belongs to another user")
		return
	}

	if existingUser != nil {
		// 用户已存在，更新资料
		h.updateUserProfile(existingUser, &req)
		if err := h.ensureSDKExternalIdentity(existingUser.ID, req.ExternalSource, req.ExternalID); err != nil {
			if errors.Is(err, repository.ErrSDKExternalIdentityAlreadyExists) {
				h.recordSDKExternalIdentityConflict(c, &existingUser.ID)
				Conflict(c, "External identity belongs to another user")
				return
			}
			InternalError(c, "Failed to link external identity")
			return
		}

		Success(c, gin.H{
			"action": "updated",
			"user": gin.H{
				"id":       existingUser.ID.String(),
				"email":    existingUser.Email,
				"username": existingUser.Username,
			},
		})
		return
	}

	// 创建新用户
	passwordHash := ""
	if req.Password != "" {
		// 如果提供了密码，则哈希存储
		user, err := h.authService.Register(&service.RegisterInput{
			Email:    req.Email,
			Username: req.Username,
			Password: req.Password,
		})
		if err != nil {
			if errors.Is(err, service.ErrUsernameExists) {
				// 用户名已存在，尝试添加后缀
				suffix := req.ExternalID
				if len(suffix) > 6 {
					suffix = suffix[:6]
				}
				req.Username = req.Username + "_" + suffix
				user, err = h.authService.Register(&service.RegisterInput{
					Email:    req.Email,
					Username: req.Username,
					Password: req.Password,
				})
			}
			if err != nil {
				InternalError(c, "Failed to create user: "+err.Error())
				return
			}
		}
		h.updateUserProfile(user, &req)
		if err := h.ensureSDKExternalIdentity(user.ID, req.ExternalSource, req.ExternalID); err != nil {
			if errors.Is(err, repository.ErrSDKExternalIdentityAlreadyExists) {
				h.recordSDKExternalIdentityConflict(c, &user.ID)
				Conflict(c, "External identity belongs to another user")
				return
			}
			InternalError(c, "Failed to link external identity")
			return
		}

		EmitAuthEvent(AuthEvent{
			Type:      "user_registered",
			AppID:     app.ID.String(),
			AppName:   app.Name,
			UserID:    user.ID.String(),
			Username:  user.Username,
			Email:     user.Email,
			Timestamp: time.Now(),
		})

		Created(c, gin.H{
			"action": "created",
			"user": gin.H{
				"id":       user.ID.String(),
				"email":    user.Email,
				"username": user.Username,
			},
		})
		return
	}

	// 无密码用户（只能通过OAuth登录）
	newUser := &model.User{
		Email:          req.Email,
		Username:       req.Username,
		PasswordHash:   passwordHash,
		EmailVerified:  req.EmailVerified,
		ExternalID:     req.ExternalID,
		ExternalSource: req.ExternalSource,
		GivenName:      req.GivenName,
		FamilyName:     req.FamilyName,
		Nickname:       req.Nickname,
		Gender:         req.Gender,
		PhoneNumber:    req.PhoneNumber,
		Avatar:         req.Avatar,
	}

	if req.Birthdate != "" {
		if t, err := time.Parse("2006-01-02", req.Birthdate); err == nil {
			newUser.Birthdate = &t
		}
	}

	if err := h.authService.CreateUser(newUser); err != nil {
		// 用户名冲突处理
		if errors.Is(err, service.ErrUsernameExists) && req.ExternalID != "" {
			suffix := req.ExternalID
			if len(suffix) > 6 {
				suffix = suffix[:6]
			}
			newUser.Username = req.Username + "_" + suffix
			err = h.authService.CreateUser(newUser)
		}
		if err != nil {
			InternalError(c, "Failed to create user: "+err.Error())
			return
		}
	}
	if err := h.ensureSDKExternalIdentity(newUser.ID, req.ExternalSource, req.ExternalID); err != nil {
		if errors.Is(err, repository.ErrSDKExternalIdentityAlreadyExists) {
			h.recordSDKExternalIdentityConflict(c, &newUser.ID)
			Conflict(c, "External identity belongs to another user")
			return
		}
		InternalError(c, "Failed to link external identity")
		return
	}

	EmitAuthEvent(AuthEvent{
		Type:      "user_registered",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    newUser.ID.String(),
		Username:  newUser.Username,
		Email:     newUser.Email,
		Timestamp: time.Now(),
	})

	Created(c, gin.H{
		"action": "created",
		"user": gin.H{
			"id":       newUser.ID.String(),
			"email":    newUser.Email,
			"username": newUser.Username,
		},
	})
}

func (h *SDKHandler) findSDKSyncUser(req *SyncUserRequest) (*model.User, bool) {
	emailUser, _ := h.authService.GetUserByEmail(req.Email)
	externalUser, _ := h.authService.GetUserByExternalIdentity(req.ExternalSource, req.ExternalID)
	if externalUser == nil && h.sdkExternalRepo != nil && req.ExternalSource != "" && req.ExternalID != "" {
		if identity, err := h.sdkExternalRepo.FindByExternalIdentity(req.ExternalSource, req.ExternalID); err == nil {
			externalUser, _ = h.authService.GetUserByID(identity.UserID)
		}
	}

	if emailUser != nil && externalUser != nil && emailUser.ID != externalUser.ID {
		return nil, true
	}
	if emailUser != nil {
		return emailUser, false
	}
	return externalUser, false
}

func (h *SDKHandler) ensureSDKExternalIdentityAvailable(userID uuid.UUID, externalSource, externalID string) error {
	if h.sdkExternalRepo == nil || externalSource == "" || externalID == "" {
		return nil
	}
	identity, err := h.sdkExternalRepo.FindByExternalIdentity(externalSource, externalID)
	if err == nil {
		if userID != uuid.Nil && identity.UserID == userID {
			return nil
		}
		return repository.ErrSDKExternalIdentityAlreadyExists
	}
	if !errors.Is(err, repository.ErrUserNotFound) {
		return err
	}
	return nil
}

func (h *SDKHandler) ensureSDKExternalIdentity(userID uuid.UUID, externalSource, externalID string) error {
	if h.sdkExternalRepo == nil || externalSource == "" || externalID == "" {
		return nil
	}
	identity, err := h.sdkExternalRepo.FindByExternalIdentity(externalSource, externalID)
	if err == nil {
		if identity.UserID == userID {
			return nil
		}
		return repository.ErrSDKExternalIdentityAlreadyExists
	}
	if !errors.Is(err, repository.ErrUserNotFound) {
		return err
	}
	return h.sdkExternalRepo.Create(&model.SDKExternalIdentity{
		UserID:         userID,
		ExternalSource: externalSource,
		ExternalID:     externalID,
	})
}

func (h *SDKHandler) recordSDKExternalIdentityConflict(c *gin.Context, userID *uuid.UUID) {
	if h.riskEventRepo == nil {
		return
	}
	if err := h.riskEventRepo.Create(&model.RiskEvent{
		UserID:    userID,
		RiskScore: 80,
		Decision:  model.RiskDecisionBlock,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Reason:    model.RiskEventReasonSDKExternalIdentityConflict,
	}); err != nil {
		logger.Warn("Failed to record SDK external identity risk event", "user_id", userID, "reason", model.RiskEventReasonSDKExternalIdentityConflict, "error", err)
	}
}

// updateUserProfile 更新用户资料
func (h *SDKHandler) updateUserProfile(user *model.User, req *SyncUserRequest) {
	updated := false

	if req.GivenName != "" && user.GivenName == "" {
		user.GivenName = req.GivenName
		updated = true
	}
	if req.FamilyName != "" && user.FamilyName == "" {
		user.FamilyName = req.FamilyName
		updated = true
	}
	if req.Nickname != "" && user.Nickname == "" {
		user.Nickname = req.Nickname
		updated = true
	}
	if req.Gender != "" && user.Gender == "" {
		user.Gender = req.Gender
		updated = true
	}
	if req.PhoneNumber != "" && user.PhoneNumber == "" {
		user.PhoneNumber = req.PhoneNumber
		updated = true
	}
	if req.Avatar != "" && user.Avatar == "" {
		user.Avatar = req.Avatar
		updated = true
	}
	if req.EmailVerified && !user.EmailVerified {
		user.EmailVerified = true
		updated = true
	}
	if req.ExternalID != "" && user.ExternalID == "" {
		user.ExternalID = req.ExternalID
		updated = true
	}
	if req.ExternalSource != "" && user.ExternalSource == "" {
		user.ExternalSource = req.ExternalSource
		updated = true
	}
	if req.Birthdate != "" && user.Birthdate == nil {
		if t, err := time.Parse("2006-01-02", req.Birthdate); err == nil {
			user.Birthdate = &t
			updated = true
		}
	}

	if updated {
		h.authService.UpdateUser(user)
	}
}

// GetUserRequest 获取用户请求
type GetUserRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	Email        string `json:"email,omitempty"`
	UserID       string `json:"user_id,omitempty"`
}

// GetUser 获取用户信息
// POST /api/sdk/user
func (h *SDKHandler) GetUser(c *gin.Context) {
	var req GetUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	_, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	var user *model.User

	if req.UserID != "" {
		userID, err := model.ParseUUID(req.UserID)
		if err != nil {
			BadRequest(c, "Invalid user ID")
			return
		}
		user, err = h.authService.GetUserByID(userID)
	} else if req.Email != "" {
		user, err = h.authService.GetUserByEmail(req.Email)
	} else {
		BadRequest(c, "email or user_id is required")
		return
	}

	if err != nil || user == nil {
		NotFound(c, "User not found")
		return
	}

	Success(c, gin.H{
		"user": buildUserResponse(user),
	})
}

// BatchSyncRequest 批量同步请求
type BatchSyncRequest struct {
	ClientID     string            `json:"client_id" binding:"required"`
	ClientSecret string            `json:"client_secret" binding:"required"`
	Users        []SyncUserRequest `json:"users" binding:"required,min=1,max=100"`
}

// BatchSync 批量同步用户
// POST /api/sdk/sync/batch
func (h *SDKHandler) BatchSync(c *gin.Context) {
	var req BatchSyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	_, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	results := make([]gin.H, 0, len(req.Users))
	created := 0
	updated := 0
	failed := 0

	for _, userReq := range req.Users {
		userReq.ClientID = req.ClientID
		userReq.ClientSecret = req.ClientSecret

		existingUser, conflict := h.findSDKSyncUser(&userReq)

		if conflict {
			h.recordSDKExternalIdentityConflict(c, nil)
			results = append(results, gin.H{
				"email":  userReq.Email,
				"action": "failed",
				"error":  "external identity belongs to another user",
			})
			failed++
		} else if existingUser != nil {
			h.updateUserProfile(existingUser, &userReq)
			if err := h.ensureSDKExternalIdentity(existingUser.ID, userReq.ExternalSource, userReq.ExternalID); err != nil {
				if errors.Is(err, repository.ErrSDKExternalIdentityAlreadyExists) {
					h.recordSDKExternalIdentityConflict(c, &existingUser.ID)
				}
				results = append(results, gin.H{
					"email":  userReq.Email,
					"action": "failed",
					"error":  "external identity belongs to another user",
				})
				failed++
				continue
			}
			results = append(results, gin.H{
				"email":  userReq.Email,
				"action": "updated",
				"id":     existingUser.ID.String(),
			})
			updated++
		} else {
			newUser := &model.User{
				Email:          userReq.Email,
				Username:       userReq.Username,
				EmailVerified:  userReq.EmailVerified,
				ExternalID:     userReq.ExternalID,
				ExternalSource: userReq.ExternalSource,
				GivenName:      userReq.GivenName,
				FamilyName:     userReq.FamilyName,
				Nickname:       userReq.Nickname,
				Avatar:         userReq.Avatar,
			}

			if err := h.authService.CreateUser(newUser); err != nil {
				results = append(results, gin.H{
					"email":  userReq.Email,
					"action": "failed",
					"error":  err.Error(),
				})
				failed++
			} else if err := h.ensureSDKExternalIdentity(newUser.ID, userReq.ExternalSource, userReq.ExternalID); err != nil {
				if errors.Is(err, repository.ErrSDKExternalIdentityAlreadyExists) {
					h.recordSDKExternalIdentityConflict(c, &newUser.ID)
				}
				results = append(results, gin.H{
					"email":  userReq.Email,
					"action": "failed",
					"error":  "external identity belongs to another user",
				})
				failed++
			} else {
				results = append(results, gin.H{
					"email":  userReq.Email,
					"action": "created",
					"id":     newUser.ID.String(),
				})
				created++
			}
		}
	}

	Success(c, gin.H{
		"total":   len(req.Users),
		"created": created,
		"updated": updated,
		"failed":  failed,
		"results": results,
	})
}

// ========== SDK Token Refresh ==========

// SDKRefreshRequest SDK token 刷新请求
func (h *SDKHandler) storeSDKAccessToken(token string, clientID string, userID uuid.UUID, ttl time.Duration) error {
	if h.oauthRepo == nil {
		return nil
	}
	return h.oauthRepo.CreateAccessToken(&model.AccessToken{
		Token:     token,
		ClientID:  clientID,
		UserID:    &userID,
		ExpiresAt: time.Now().Add(ttl),
	})
}

func (h *SDKHandler) isSDKAccessTokenUsable(token string, clientID string, userID uuid.UUID) bool {
	if h.oauthRepo == nil {
		return true
	}

	accessToken, err := h.oauthRepo.FindAccessToken(token)
	if err != nil {
		return false
	}
	if !accessToken.IsValid() || accessToken.ClientID != clientID {
		return false
	}
	if !accessToken.HasEndUser() || accessToken.UserID == nil {
		return false
	}
	return *accessToken.UserID == userID
}

type SDKRefreshRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	RefreshToken string `json:"refresh_token" binding:"required"`
}

/**
 * RefreshToken 使用 refresh token 换取新的 token 对
 *
 * @route   POST /api/sdk/refresh
 *
 * @description
 *   SDK 专用 refresh 端点。安全检查：
 *   1. 验证 client_id + client_secret
 *   2. **H-1 修复**：解析旧 refresh token 的 ClientID claim，必须与请求的 client_id 一致
 *      — 防止 App A 使用 App B 签发的 refresh token 跨客户端刷新
 *   3. 通过 AuthService.ConsumeRefreshTokenWithRequestContext() 执行 Token Rotation（单次使用 + 重放检测）
 *   4. 新 token 使用 GenerateClientToken 签发，保持 audience 隔离
 *
 * @security H-1 修复：跨客户端 refresh token 检查 + 新 token 保持 client-scoped
 */
func (h *SDKHandler) RefreshToken(c *gin.Context) {
	var req SDKRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	app, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	/*
	 * H-1 修复：跨客户端 refresh token 检查
	 * 解析旧 refresh token 中的 ClientID claim，确认与当前请求的 client_id 一致。
	 * 不一致则拒绝（可能是 App A 窃取了 App B 的 refresh token）。
	 */
	oldClaims, parseErr := h.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if parseErr != nil {
		Unauthorized(c, "Invalid or expired refresh token")
		return
	}
	if oldClaims.ClientID != req.ClientID {
		Forbidden(c, "Refresh token was not issued to this client")
		return
	}

	consumedClaims, user, err := h.authService.ConsumeRefreshTokenWithRequestContext(req.RefreshToken, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		if errors.Is(err, service.ErrUserDisabled) {
			Error(c, http.StatusUnauthorized, ErrCodeUserDisabled, "User account is disabled")
			return
		}
		Unauthorized(c, "Invalid or expired refresh token")
		return
	}

	/* 重新签发 client-scoped token，保持 SDK audience 与 client_id 隔离。 */
	authTime := consumedClaims.AuthTime
	if authTime <= 0 && consumedClaims.IssuedAt != nil {
		authTime = consumedClaims.IssuedAt.Time.Unix()
	}
	tokens, err := h.issueSDKUserTokens(user, app.ClientID, app.ClientSecret, authTime)
	if err != nil {
		InternalError(c, "Failed to generate refresh token")
		return
	}
	if err := h.persistSDKUserTokens(tokens, app.ClientID, user.ID); err != nil {
		InternalError(c, "Failed to persist refresh token")
		return
	}

	Success(c, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"id_token":      tokens.IDToken,
		"token_type":    "Bearer",
		"expires_in":    tokens.ExpiresIn,
	})
}

// ========== SDK Token Verify ==========

// SDKVerifyRequest SDK token 验证请求
type SDKVerifyRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	AccessToken  string `json:"access_token" binding:"required"`
}

// VerifyToken 验证 access token 有效性并返回用户信息
// POST /api/sdk/verify
func (h *SDKHandler) VerifyToken(c *gin.Context) {
	var req SDKVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	_, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Error(c, http.StatusUnauthorized, ErrCodeInvalidClient, "Invalid client credentials")
		return
	}

	// 验证 access token，禁止 refresh token 被当作 access token 使用
	claims, err := h.jwtManager.ValidateAccessToken(req.AccessToken)
	if err != nil {
		if errors.Is(err, jwt.ErrExpiredToken) {
			Error(c, http.StatusUnauthorized, ErrCodeTokenExpired, "Invalid or expired access token")
			return
		}
		Error(c, http.StatusUnauthorized, ErrCodeTokenInvalid, "Invalid or expired access token")
		return
	}
	if claims.ClientID != req.ClientID {
		Error(c, http.StatusUnauthorized, ErrCodeTokenInvalid, "Invalid or expired access token")
		return
	}
	if !h.isSDKAccessTokenUsable(req.AccessToken, req.ClientID, claims.UserID) {
		Error(c, http.StatusUnauthorized, ErrCodeTokenInvalid, "Invalid or expired access token")
		return
	}

	// 获取用户完整信息
	user, err := h.authService.GetUserByID(claims.UserID)
	if err != nil {
		NotFound(c, "User not found")
		return
	}
	if user.IsSuspended() {
		if h.oauthRepo != nil {
			_ = h.oauthRepo.RevokeTokensByUserID(user.ID)
		}
		Error(c, http.StatusUnauthorized, ErrCodeUserDisabled, "User account is disabled")
		return
	}

	Success(c, gin.H{
		"valid": true,
		"user":  buildUserResponse(user),
		"claims": gin.H{
			"sub":       claims.UserID.String(),
			"email":     claims.Email,
			"role":      claims.Role,
			"client_id": claims.ClientID,
			"exp":       claims.ExpiresAt.Unix(),
			"iat":       claims.IssuedAt.Unix(),
		},
	})
}

// buildUserResponse 构建用户响应
func buildUserResponse(user *model.User) gin.H {
	resp := gin.H{
		"id":             user.ID.String(),
		"email":          user.Email,
		"username":       user.Username,
		"email_verified": user.EmailVerified,
		"role":           string(user.Role),
		"created_at":     user.CreatedAt,
	}

	if user.GivenName != "" {
		resp["given_name"] = user.GivenName
	}
	if user.FamilyName != "" {
		resp["family_name"] = user.FamilyName
	}
	if user.Nickname != "" {
		resp["nickname"] = user.Nickname
	}
	if user.Avatar != "" {
		resp["avatar"] = user.Avatar
	}
	if user.PhoneNumber != "" {
		resp["phone_number"] = user.PhoneNumber
	}

	return resp
}
