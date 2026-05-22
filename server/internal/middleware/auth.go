/**
 * @file        auth.go
 * @package     middleware
 * @description JWT 鉴权中间件、可选鉴权、AdminOnly 守卫；含用户状态实时校验
 */
package middleware

import (
	"net/http"
	"strings"

	ctx "server/internal/context"
	"server/internal/repository"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
)

const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
	AccessTokenCookie   = "access_token"
	RefreshTokenCookie  = "refresh_token"
)

/**
 * extractToken 从请求中提取 Bearer token
 *
 * @description 优先级：Authorization Header > httpOnly Cookie。不支持查询字符串避免日志泄露。
 *
 * @param  {*gin.Context} c
 * @returns {string} token 字符串；未找到时返回 ""
 */
func extractToken(c *gin.Context) string {
	/* 1. 优先从 Authorization header 提取 */
	authHeader := c.GetHeader(AuthorizationHeader)
	if authHeader != "" && strings.HasPrefix(authHeader, BearerPrefix) {
		return strings.TrimPrefix(authHeader, BearerPrefix)
	}

	/* 2. 回退到 httpOnly Cookie */
	if token, err := c.Cookie(AccessTokenCookie); err == nil && token != "" {
		return token
	}

	return ""
}

/**
 * authError 返回统一格式的鉴权错误
 *
 * @param  {*gin.Context} c
 * @param  {string} code    - 错误代码
 * @param  {string} message - 错误描述
 */
func authError(c *gin.Context, code, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"success": false,
		"error":   gin.H{"code": code, "message": message},
	})
}

/**
 * Auth 创建 JWT 鉴权中间件
 *
 * @description
 *   流程：提取 token → ValidateAccessToken（含 alg/issuer/typ 校验）→ 黑名单检查 →
 *   用户状态实时校验（disabled/suspended 拒绝）→ 写入 ctx（含 ClientID）。
 *
 *   支持 Authorization Header 和 httpOnly Cookie 两种通道。
 *
 * @param  {*jwt.Manager}             jwtManager - JWT 管理器
 * @param  {*jwt.Blacklist}           blacklist  - 可选，传入启用 JTI 级 + 用户级吊销
 * @returns {gin.HandlerFunc}
 *
 * @security 用户状态为 disabled/suspended 时即时拒绝（不依赖 token 黑名单的最终一致性）
 */
func Auth(jwtManager *jwt.Manager, blacklist ...*jwt.Blacklist) gin.HandlerFunc {
	var bl *jwt.Blacklist
	if len(blacklist) > 0 {
		bl = blacklist[0]
	}

	return func(c *gin.Context) {
		tokenString := extractToken(c)
		if tokenString == "" {
			authError(c, "UNAUTHORIZED", "Authorization required")
			return
		}

		claims, err := jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			switch err {
			case jwt.ErrExpiredToken:
				authError(c, "TOKEN_EXPIRED", "Token has expired")
			case jwt.ErrTokenTypeMismatch:
				authError(c, "TOKEN_INVALID", "Invalid token type")
			default:
				authError(c, "TOKEN_INVALID", "Invalid token")
			}
			return
		}

		/* JWT 黑名单检查：JTI 级别吊销 + 用户级别全局吊销 */
		if bl != nil {
			if bl.IsRevoked(claims.ID) {
				authError(c, "TOKEN_REVOKED", "Token has been revoked")
				return
			}
			if claims.IssuedAt != nil && bl.IsUserTokenRevoked(claims.UserID.String(), claims.IssuedAt.Time) {
				authError(c, "TOKEN_REVOKED", "Token has been revoked")
				return
			}
		}

		/* 用户状态实时校验：disabled/suspended 用户即时拒绝（即使 token 未过期） */
		if userRepo := getUserRepo(c); userRepo != nil {
			user, err := userRepo.FindByID(claims.UserID)
			if err == nil && user != nil && !isUserActive(user.Status) {
				authError(c, "USER_DISABLED", "User account is disabled")
				return
			}
		}

		ctx.SetUser(c, claims.UserID, claims.Email, claims.Username, claims.Role)
		ctx.SetClientID(c, claims.ClientID)
		c.Next()
	}
}

/**
 * OptionalAuth 可选鉴权中间件
 *
 * @description token 有效时设置用户信息；无 token 或无效时不拦截。
 *
 * @param  {*jwt.Manager}   jwtManager
 * @param  {*jwt.Blacklist} blacklist  - 可选
 * @returns {gin.HandlerFunc}
 */
func OptionalAuth(jwtManager *jwt.Manager, blacklist ...*jwt.Blacklist) gin.HandlerFunc {
	var bl *jwt.Blacklist
	if len(blacklist) > 0 {
		bl = blacklist[0]
	}

	return func(c *gin.Context) {
		tokenString := extractToken(c)
		if tokenString == "" {
			c.Next()
			return
		}

		claims, err := jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			c.Next()
			return
		}

		/* 黑名单检查（可选） */
		if bl != nil {
			if bl.IsRevoked(claims.ID) || (claims.IssuedAt != nil && bl.IsUserTokenRevoked(claims.UserID.String(), claims.IssuedAt.Time)) {
				c.Next()
				return
			}
		}

		ctx.SetUser(c, claims.UserID, claims.Email, claims.Username, claims.Role)
		ctx.SetClientID(c, claims.ClientID)
		c.Next()
	}
}

/**
 * AdminOnly 管理员权限守卫
 *
 * @description
 *   仅允许 role=admin **且** ClientID="" 的请求通过。
 *   外部 SDK 颁发的 admin token 会被拒绝（H-2 修复）。
 *
 * @returns {gin.HandlerFunc}
 * @security 拒绝 ClientID!="" 的 token，无论 role
 */
func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ctx.IsAdmin(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   gin.H{"code": "ADMIN_REQUIRED", "message": "Admin access required"},
			})
			return
		}
		c.Next()
	}
}

/* ========== 用户状态校验辅助 ========== */

const userRepoCtxKey = "_user_repo_for_auth"

/**
 * WithUserRepo 在 Gin engine 启动时注入 UserRepository，
 * 让 Auth 中间件能在每个请求实时校验用户状态。
 *
 * @description
 *   通过中间件链注入而非全局变量，避免 import cycle。
 *   router.Setup 应当在所有 Auth 中间件之前 use 此中间件。
 *
 * @param  {*repository.UserRepository} repo
 * @returns {gin.HandlerFunc}
 */
func WithUserRepo(repo *repository.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(userRepoCtxKey, repo)
		c.Next()
	}
}

/**
 * getUserRepo 从上下文取出 UserRepository（注入失败时返回 nil 不拦截）
 */
func getUserRepo(c *gin.Context) *repository.UserRepository {
	v, exists := c.Get(userRepoCtxKey)
	if !exists {
		return nil
	}
	r, _ := v.(*repository.UserRepository)
	return r
}

/**
 * isUserActive 判断用户是否处于可用状态
 *
 * @param  {string} status - User.Status 字段（"" / active / disabled / suspended / locked）
 * @returns {bool} 仅 "" 与 "active" 视为可用
 */
func isUserActive(status string) bool {
	return status == "" || status == "active"
}

/* CORS 已迁移到 cors.go */
