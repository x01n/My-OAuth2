/**
 * @file        context.go
 * @package     context
 * @description 在 Gin 上下文中存取当前用户信息（UserID/Email/Username/Role/ClientID）
 */
package context

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/**
 * 上下文键名常量
 * @enum {string}
 */
const (
	/** 用户 UUID */
	UserIDKey = "user_id"

	/** 用户邮箱 */
	UserEmailKey = "user_email"

	/** 用户名 */
	UserUsernameKey = "user_username"

	/** 角色（admin/user/service） */
	UserRoleKey = "user_role"

	/** 颁发方 client_id；""=中央 token；非空=外部 SDK token */
	ClientIDKey = "auth_client_id"

	/** 终端用户最近一次完成认证的 Unix 秒级时间 */
	AuthTimeKey = "auth_time"

	/** OIDC Authentication Methods References */
	AuthMethodsKey = "auth_methods"
)

/**
 * SetUser 将用户信息写入 Gin 上下文
 *
 * @param  {*gin.Context} c        - Gin 上下文
 * @param  {uuid.UUID}    userID   - 用户 UUID
 * @param  {string}       email    - 邮箱
 * @param  {string}       username - 用户名
 * @param  {string}       role     - 角色
 */
func SetUser(c *gin.Context, userID uuid.UUID, email, username, role string) {
	c.Set(UserIDKey, userID)
	c.Set(UserEmailKey, email)
	c.Set(UserUsernameKey, username)
	c.Set(UserRoleKey, role)
}

/**
 * SetClientID 写入 JWT 携带的 client_id
 *
 * @param  {*gin.Context} c        - Gin 上下文
 * @param  {string}       clientID - 颁发方 client_id（中央 token 传 ""）
 */
func SetClientID(c *gin.Context, clientID string) {
	c.Set(ClientIDKey, clientID)
}

/**
 * SetAuthTime 写入 JWT 携带的 auth_time
 *
 * @param  {*gin.Context} c
 * @param  {int64}        authTime - Unix 秒级时间；0 表示未知
 */
func SetAuthTime(c *gin.Context, authTime int64) {
	c.Set(AuthTimeKey, authTime)
}

/**
 * SetAuthMethods 写入 OIDC amr 认证方法列表
 *
 * @param  {*gin.Context} c
 * @param  {[]string}     methods - RFC 8176 amr 值，如 "pwd"
 */
func SetAuthMethods(c *gin.Context, methods []string) {
	c.Set(AuthMethodsKey, append([]string(nil), methods...))
}

/**
 * GetUserID 从上下文提取用户 UUID
 *
 * @param  {*gin.Context} c
 * @returns {(uuid.UUID, bool)} (UUID, 是否存在)
 */
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := userID.(uuid.UUID)
	return id, ok
}

/**
 * GetUserEmail 从上下文提取用户邮箱
 *
 * @param  {*gin.Context} c
 * @returns {(string, bool)}
 */
func GetUserEmail(c *gin.Context) (string, bool) {
	email, exists := c.Get(UserEmailKey)
	if !exists {
		return "", false
	}
	e, ok := email.(string)
	return e, ok
}

/**
 * GetUserUsername 从上下文提取用户名
 *
 * @param  {*gin.Context} c
 * @returns {(string, bool)}
 */
func GetUserUsername(c *gin.Context) (string, bool) {
	username, exists := c.Get(UserUsernameKey)
	if !exists {
		return "", false
	}
	u, ok := username.(string)
	return u, ok
}

/**
 * GetUserRole 从上下文提取用户角色
 *
 * @param  {*gin.Context} c
 * @returns {(string, bool)}
 */
func GetUserRole(c *gin.Context) (string, bool) {
	role, exists := c.Get(UserRoleKey)
	if !exists {
		return "", false
	}
	r, ok := role.(string)
	return r, ok
}

/**
 * GetClientID 从上下文提取颁发方 client_id
 *
 * @param  {*gin.Context} c
 * @returns {string} 中央 token 返回 ""；外部 SDK token 返回 client_id
 */
func GetClientID(c *gin.Context) string {
	v, exists := c.Get(ClientIDKey)
	if !exists {
		return ""
	}
	s, _ := v.(string)
	return s
}

/**
 * GetAuthTime 从上下文提取 auth_time
 *
 * @param  {*gin.Context} c
 * @returns {(int64, bool)}
 */
func GetAuthTime(c *gin.Context) (int64, bool) {
	v, exists := c.Get(AuthTimeKey)
	if !exists {
		return 0, false
	}
	authTime, ok := v.(int64)
	return authTime, ok
}

/**
 * GetAuthMethods 从上下文提取 OIDC amr 认证方法列表
 *
 * @param  {*gin.Context} c
 * @returns {([]string, bool)}
 */
func GetAuthMethods(c *gin.Context) ([]string, bool) {
	v, exists := c.Get(AuthMethodsKey)
	if !exists {
		return nil, false
	}
	methods, ok := v.([]string)
	if !ok {
		return nil, false
	}
	return append([]string(nil), methods...), true
}

/**
 * IsAdmin 检查当前用户是否为管理员
 *
 * @description
 *   仅当 role=admin **且** 来自中央 token（ClientID="")时返回 true。
 *   外部 SDK 颁发的 admin token 会被拒绝，防止 SDK 越权进控制台（H-2 修复）。
 *
 * @param  {*gin.Context} c
 * @returns {bool}
 * @security 拒绝 ClientID!="" 的 admin token
 */
func IsAdmin(c *gin.Context) bool {
	role, ok := GetUserRole(c)
	if !ok || role != "admin" {
		return false
	}
	/* 外部 SDK 颁发的 admin token 不能进入中央控制台 */
	if GetClientID(c) != "" {
		return false
	}
	return true
}
