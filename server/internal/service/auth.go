package service

import (
	"errors"
	"fmt"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
	"server/pkg/logger"
	"server/pkg/password"

	"github.com/google/uuid"
)

/**
 * 认证服务层错误定义
 * @enum {error}
 */
var (
	/** 邮箱或密码错误 / 用户被禁用 */
	ErrInvalidCredentials = errors.New("invalid credentials")

	/** 邮箱已被注册 */
	ErrEmailExists = errors.New("email already exists")

	/** 用户名已被占用 */
	ErrUsernameExists = errors.New("username already exists")

	/** 密码不满足强度要求 */
	ErrPasswordTooWeak = errors.New("password does not meet strength requirements")

	/** 账户因连续失败被临时锁定 */
	ErrAccountLocked = errors.New("account temporarily locked due to too many failed attempts")

	/** 用户被管理员禁用（disabled/suspended） */
	ErrUserDisabled = errors.New("user account is disabled")
)

/*
 * AuthService 用户认证服务
 * 功能：用户注册、登录、Token 签发与刷新、登出、用户查询
 *       支持 Refresh Token Rotation 安全机制
 */
type AuthService struct {
	userRepo               *repository.UserRepository
	loginLogRepo           *repository.LoginLogRepository
	oauthRepo              *repository.OAuthRepository
	jwtManager             *jwt.Manager
	config                 *config.Config
	tokenBlacklist         *jwt.Blacklist
	appRepo                *repository.ApplicationRepository
	userAuthRepo           *repository.UserAuthorizationRepository
	federationRepo         *repository.FederationRepository
	deviceCodeRepo         *repository.DeviceCodeRepository
	passwordResetRepo      *repository.PasswordResetRepository
	emailVerificationRepo  *repository.EmailVerificationRepository
}

/*
 * NewAuthService 创建认证服务实例
 * @param userRepo     - 用户数据仓储
 * @param loginLogRepo - 登录日志仓储
 * @param jwtManager   - JWT 管理器
 * @param cfg          - 系统配置
 */
func NewAuthService(userRepo *repository.UserRepository, loginLogRepo *repository.LoginLogRepository, jwtManager *jwt.Manager, cfg *config.Config) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		loginLogRepo: loginLogRepo,
		jwtManager:   jwtManager,
		config:       cfg,
	}
}

/* SetOAuthRepo 注入 OAuthRepository（启用 Refresh Token Rotation） */
func (s *AuthService) SetOAuthRepo(repo *repository.OAuthRepository) {
	s.oauthRepo = repo
}

/* SetTokenBlacklist 注入 JWT 黑名单（启用 access token 即时吊销） */
func (s *AuthService) SetTokenBlacklist(bl *jwt.Blacklist) {
	s.tokenBlacklist = bl
}

/* SetCleanupRepos 注入账号删除所需的级联清理仓储 */
func (s *AuthService) SetCleanupRepos(
	appRepo *repository.ApplicationRepository,
	userAuthRepo *repository.UserAuthorizationRepository,
	federationRepo *repository.FederationRepository,
	deviceCodeRepo *repository.DeviceCodeRepository,
	passwordResetRepo *repository.PasswordResetRepository,
	emailVerificationRepo *repository.EmailVerificationRepository,
) {
	s.appRepo = appRepo
	s.userAuthRepo = userAuthRepo
	s.federationRepo = federationRepo
	s.deviceCodeRepo = deviceCodeRepo
	s.passwordResetRepo = passwordResetRepo
	s.emailVerificationRepo = emailVerificationRepo
}

/* GetJWTManager 返回 JWT 管理器（用于 Logout 等场景解析 token） */
func (s *AuthService) GetJWTManager() *jwt.Manager {
	return s.jwtManager
}

/* RegisterInput 用户注册输入参数 */
type RegisterInput struct {
	Email    string
	Username string
	Password string
}

/* LoginInput 用户登录输入参数 */
type LoginInput struct {
	Email     string
	Password  string
	IPAddress string
	UserAgent string
}

/* AuthTokens 登录/OAuth 用户委托令牌（access + refresh + id_token，均为加密 JWT） */
type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

/*
 * Register 创建新用户账号
 * 功能：校验邮箱/用户名唯一性，哈希密码，第一个用户自动成为管理员
 * @param input - 注册参数
 * @return *model.User - 创建后的用户实体
 */
func (s *AuthService) Register(input *RegisterInput) (*model.User, error) {
	/* 校验密码强度（长度、bcrypt 72 字节限制） */
	if err := password.ValidateStrength(input.Password); err != nil {
		return nil, ErrPasswordTooWeak
	}

	// Check if email exists
	exists, err := s.userRepo.ExistsByEmail(input.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrEmailExists
	}

	// Check if username exists
	exists, err = s.userRepo.ExistsByUsername(input.Username)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrUsernameExists
	}

	// Hash password
	hashedPassword, err := password.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	// Check if this is the first user (make them admin)
	userCount, err := s.userRepo.Count()
	if err != nil {
		return nil, err
	}

	role := model.RoleUser
	if userCount == 0 {
		role = model.RoleAdmin
	}

	// Create user
	user := &model.User{
		Email:        input.Email,
		Username:     input.Username,
		PasswordHash: hashedPassword,
		Role:         role,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	return user, nil
}

/*
 * Login 用户登录认证
 * 功能：校验邮箱密码，记录登录日志，签发 JWT 令牌对
 * @param input - 登录参数（邮箱、密码、IP、UA）
 * @return *model.User   - 用户实体
 * @return *AuthTokens   - JWT 令牌对
 */
/*
 * 账户锁定策略常量
 * MaxFailedLogins: 连续失败次数阈值
 * LockDuration:    锁定持续时间
 */
const (
	MaxFailedLogins = 5
	LockDuration    = 15 * time.Minute
)

func (s *AuthService) Login(input *LoginInput) (*model.User, *AuthTokens, error) {
	// Find user by email
	user, err := s.userRepo.FindByEmail(input.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			// Log failed login attempt (user not found)
			if s.loginLogRepo != nil {
				s.loginLogRepo.CreateLoginLog(nil, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, false, "user not found")
			}
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}

	/* 用户状态检查：suspended/disabled 用户拒绝登录 */
	if user.Status != "" && user.Status != "active" {
		if s.loginLogRepo != nil {
			s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, false, "user "+user.Status)
		}
		return nil, nil, ErrInvalidCredentials
	}

	/* 账户锁定检查：连续失败超过阈值后临时锁定 */
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		if s.loginLogRepo != nil {
			s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, false, "account locked")
		}
		return nil, nil, ErrAccountLocked
	}

	// Verify password
	if !password.Verify(input.Password, user.PasswordHash) {
		/* 递增失败计数，达到阈值时锁定账户 */
		user.FailedLogins++
		if user.FailedLogins >= MaxFailedLogins {
			lockUntil := time.Now().Add(LockDuration)
			user.LockedUntil = &lockUntil
		}
		s.userRepo.Update(user)

		// Log failed login attempt (wrong password)
		if s.loginLogRepo != nil {
			s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, false, "invalid password")
		}
		return nil, nil, ErrInvalidCredentials
	}

	/* 登录成功：重置失败计数和锁定状态 */
	needsUpdate := user.FailedLogins > 0 || user.LockedUntil != nil
	if user.FailedLogins > 0 || user.LockedUntil != nil {
		user.FailedLogins = 0
		user.LockedUntil = nil
		needsUpdate = true
	}

	/*
	 * L-8 修复：写入最后登录时间与 IP，供个人中心 / 管理后台展示
	 * 用 UTC 时间避免跨时区比较毛刺（L-13）
	 */
	now := time.Now().UTC()
	user.LastLoginAt = &now
	if input.IPAddress != "" {
		user.LastLoginIP = input.IPAddress
	}
	needsUpdate = true

	/* bcrypt cost 自适应升级：旧哈希使用较低 cost 时透明重哈希 */
	if password.NeedsRehash(user.PasswordHash) {
		if newHash, hashErr := password.Hash(input.Password); hashErr == nil {
			user.PasswordHash = newHash
			needsUpdate = true
			logger.Info("Password rehashed with updated cost", "user_id", user.ID)
		}
	}

	if needsUpdate {
		s.userRepo.Update(user)
	}

	// Log successful login
	if s.loginLogRepo != nil {
		s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, true, "")
	}

	// Generate tokens
	tokens, err := s.generateTokens(user)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

/**
 * RefreshTokens 使用 refresh token 生成新的 token 对（Rotation 模式）
 *
 * @description
 *   单次使用语义 — 旧 refresh token 立即作废；超过宽限期重复使用视为重放，
 *   撤销该用户全部 refresh token。**禁用用户的刷新请求会被直接拒绝，
 *   并主动撤销其所有现存 token**（修复"禁用用户能继续刷新"漏洞）。
 *
 * @param  {string} refreshToken - 旧 refresh token
 * @returns {*AuthTokens, error}  新 token 对；失败返回错误
 * @throws  {ErrUserDisabled}    用户已被管理员禁用
 * @security 禁用用户：拒绝刷新 + 黑名单全部已签发 access token
 */
func (s *AuthService) RefreshTokens(refreshToken string) (*AuthTokens, error) {
	/* 验证 refresh token 且确保类型正确 */
	claims, err := s.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	/* Token Rotation: 检查 DB 中该 token 是否已被使用/撤销 */
	if s.oauthRepo != nil {
		record, findErr := s.oauthRepo.FindAuthRefreshToken(claims.ID)
		if findErr != nil {
			/* token 不在 DB 中（可能是旧 token 或伪造的） */
			return nil, errors.New("refresh token not recognized")
		}
		if record.Revoked {
			/*
			 * 宽限期机制：Token Rotation 存在竞态条件
			 * 前端可能因 Cookie 更新延迟 / 多标签页并发等原因，在短时间内重复使用同一个旧 token
			 * 如果在 30 秒宽限期内，不触发"撤销全部 token"的核弹操作，只拒绝本次请求
			 * 超过宽限期则视为真正的重放攻击，撤销该用户全部 refresh token
			 */
			const rotationGracePeriod = 30 * time.Second
			if record.RevokedAt != nil && time.Since(*record.RevokedAt) < rotationGracePeriod {
				return nil, errors.New("refresh token already used (grace period)")
			}
			/* 超过宽限期：检测到重放攻击，撤销该用户所有 refresh token */
			if record.UserID != nil {
				_ = s.oauthRepo.RevokeUserAuthRefreshTokens(*record.UserID)
			}
			return nil, errors.New("refresh token already used")
		}
		/* 标记旧 token 已使用 */
		_ = s.oauthRepo.RevokeAuthRefreshToken(claims.ID)
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return nil, err
	}

	/*
	 * 用户状态实时校验：禁用用户拒绝刷新（C-1 相关 + 用户禁用需求）
	 * 安全策略：检测到禁用用户的刷新请求时，主动撤销其所有现存 token，
	 * 防止已在客户端持有的 access token 继续被使用至过期。
	 */
	if user.IsSuspended() || user.Status == "disabled" {
		if s.oauthRepo != nil {
			_ = s.oauthRepo.RevokeUserAuthRefreshTokens(user.ID)
		}
		if s.tokenBlacklist != nil {
			_ = s.tokenBlacklist.RevokeAllForUser(user.ID.String(), s.config.JWT.AccessTokenTTL)
		}
		return nil, ErrUserDisabled
	}

	return s.generateTokens(user)
}

/*
 * LogoutUser 用户登出时撤销该用户所有令牌
 * 功能：Auth refresh（Dashboard JWT）+ OAuth 不透明令牌（授权码/设备流/令牌交换）一并失效
 * @param userID - 用户 UUID
 */
func (s *AuthService) LogoutUser(userID uuid.UUID) {
	if s.oauthRepo != nil {
		_ = s.oauthRepo.RevokeUserAuthRefreshTokens(userID)
		_ = s.oauthRepo.RevokeTokensByUserID(userID)
	}
	if s.tokenBlacklist != nil {
		_ = s.tokenBlacklist.RevokeAllForUser(userID.String(), s.config.JWT.AccessTokenTTL)
	}
}

/*
 * GetUserByID 根据 UUID 获取用户
 * @param id - 用户 UUID
 * @return *model.User - 用户实体
 */
func (s *AuthService) GetUserByID(id uuid.UUID) (*model.User, error) {
	return s.userRepo.FindByID(id)
}

/*
 * generateTokens 为用户生成 JWT 令牌对（access + refresh）
 * 功能：签发 access_token 和 refresh_token，并将 refresh_token 的 JTI 存入 DB 用于 Rotation 追踪
 * @param user - 用户实体
 * @return *AuthTokens - 令牌对
 */
func (s *AuthService) generateTokens(user *model.User) (*AuthTokens, error) {
	accessToken, err := s.jwtManager.GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		s.config.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwtManager.GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeRefresh,
		s.config.JWT.RefreshTokenTTL,
	)
	if err != nil {
		return nil, err
	}

	/* 将 refresh token 的 JTI 存入 DB，用于 Token Rotation 追踪 */
	if s.oauthRepo != nil {
		if refreshClaims, parseErr := s.jwtManager.ValidateRefreshToken(refreshToken); parseErr == nil {
			if storeErr := s.oauthRepo.StoreAuthRefreshToken(
				refreshClaims.ID,
				user.ID,
				refreshClaims.ExpiresAt.Time,
			); storeErr != nil {
				logger.Error("Failed to store auth refresh token",
					"user_id", user.ID,
					"error", storeErr,
				)
				/* 存储失败会导致下次刷新时 token “不被识别”，必须返回错误 */
				return nil, fmt.Errorf("failed to persist refresh token: %w", storeErr)
			}
		}
	}

	loginScope := "openid profile email"
	idTTL := s.config.OAuth.IDTokenTTL
	if idTTL <= 0 {
		idTTL = s.config.JWT.AccessTokenTTL
	}
	idToken, err := s.jwtManager.GenerateIDToken(
		user.ID, user.Email, user.Username, string(user.Role), "", loginScope, idTTL,
	)
	if err != nil {
		return nil, err
	}

	return &AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
	}, nil
}

/*
 * GetUserByEmail 根据邮箱获取用户
 * @param email - 用户邮箱
 */
func (s *AuthService) GetUserByEmail(email string) (*model.User, error) {
	return s.userRepo.FindByEmail(email)
}

/*
 * CreateUser 创建新用户（无密码校验，用于社交登录等场景）
 * 功能：校验邮箱/用户名唯一性后直接创建
 * @param user - 用户实体
 */
func (s *AuthService) CreateUser(user *model.User) error {
	// Check if email exists
	exists, err := s.userRepo.ExistsByEmail(user.Email)
	if err != nil {
		return err
	}
	if exists {
		return ErrEmailExists
	}

	// Check if username exists
	exists, err = s.userRepo.ExistsByUsername(user.Username)
	if err != nil {
		return err
	}
	if exists {
		return ErrUsernameExists
	}

	return s.userRepo.Create(user)
}

/*
 * ChangePassword 修改用户密码
 * 功能：验证旧密码后设置新密码（社交登录用户无旧密码时允许直接设置）
 * @param userID      - 用户 UUID
 * @param oldPassword - 旧密码
 * @param newPassword - 新密码
 */
func (s *AuthService) ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	/* 验证旧密码是否正确（社交登录用户可能没有密码，允许直接设置） */
	if user.PasswordHash != "" {
		if !password.Verify(oldPassword, user.PasswordHash) {
			return ErrInvalidCredentials
		}
	}

	/* 校验新密码强度 */
	if err := password.ValidateStrength(newPassword); err != nil {
		return ErrPasswordTooWeak
	}

	/* 生成新密码哈希 */
	hashedPassword, err := password.Hash(newPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = hashedPassword
	if err := s.userRepo.Update(user); err != nil {
		return err
	}

	/* 密码修改后使历史 password reset token 失效，防止旧邮件链接继续可用 */
	if s.passwordResetRepo != nil {
		_ = s.passwordResetRepo.InvalidateUserTokens(userID)
	}

	/* 密码修改后撤销该用户所有 auth refresh token，强制其他会话重新登录 */
	if s.oauthRepo != nil {
		_ = s.oauthRepo.RevokeUserAuthRefreshTokens(userID)
	}
	/* 同时吊销所有已签发的 access token（基于用户级别时间戳） */
	if s.tokenBlacklist != nil {
		_ = s.tokenBlacklist.RevokeAllForUser(userID.String(), s.config.JWT.AccessTokenTTL)
	}
	return nil
}

/*
 * DeleteAccount 用户自助删除账号 (GDPR 合规)
 * 功能：验证密码后永久删除用户数据，撤销所有 token、授权、联邦身份和归属应用
 * @param userID   - 用户 UUID
 * @param password - 当前密码（社交登录用户可为空）
 */
func (s *AuthService) DeleteAccount(userID uuid.UUID, pwd string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	/* 密码校验：有密码的用户必须验证（社交登录用户无密码可跳过） */
	if user.PasswordHash != "" {
		if pwd == "" {
			return ErrInvalidCredentials
		}
		if !password.Verify(pwd, user.PasswordHash) {
			return ErrInvalidCredentials
		}
	}

	/* 撤销所有 refresh token */
	if s.oauthRepo != nil {
		_ = s.oauthRepo.RevokeUserAuthRefreshTokens(userID)
		_ = s.oauthRepo.RevokeTokensByUserID(userID)
	}

	/* 吊销所有 access token（JWT 黑名单） */
	if s.tokenBlacklist != nil {
		_ = s.tokenBlacklist.RevokeAllForUser(userID.String(), s.config.JWT.AccessTokenTTL)
	}

	/* 删除用户作为 owner 创建的所有应用（连带清理 app 相关授权、token、webhook） */
	if s.appRepo != nil {
		if apps, appErr := s.appRepo.FindByUserID(userID); appErr == nil {
			for _, app := range apps {
				if s.userAuthRepo != nil {
					_, _ = s.userAuthRepo.DeleteByApp(app.ID)
				}
				if s.oauthRepo != nil {
					_ = s.oauthRepo.DeleteTokensByClientID(app.ClientID)
				}
				_ = s.appRepo.Delete(app.ID)
			}
		}
	}

	if s.userAuthRepo != nil {
		_, _ = s.userAuthRepo.DeleteByUser(userID)
	}
	if s.federationRepo != nil {
		_ = s.federationRepo.DeleteIdentitiesByUserID(userID)
	}
	if s.deviceCodeRepo != nil {
		_ = s.deviceCodeRepo.DeleteByUserID(userID)
	}
	if s.passwordResetRepo != nil {
		_ = s.passwordResetRepo.DeleteByUserID(userID)
	}
	if s.emailVerificationRepo != nil {
		_ = s.emailVerificationRepo.DeleteByUserID(userID)
	}
	if s.loginLogRepo != nil {
		_ = s.loginLogRepo.DeleteByUserID(userID)
	}

	/* 永久删除用户记录 */
	return s.userRepo.Delete(userID)
}

/*
 * UpdateUser 更新用户信息
 * @param user - 包含更新字段的用户实体
 */
func (s *AuthService) UpdateUser(user *model.User) error {
	return s.userRepo.Update(user)
}
