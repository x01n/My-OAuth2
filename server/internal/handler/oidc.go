package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/url"
	"sync"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/cache"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * OIDCHandler OIDC 发现端点处理器
 * 功能：处理 OpenID Connect Discovery、JWKS、WebFinger、OIDC Logout 等端点
 */
type OIDCHandler struct {
	issuer     string
	privateKey *rsa.PrivateKey
	keyID      string
	mu         sync.RWMutex
	oauthRepo  *repository.OAuthRepository
	appRepo    *repository.ApplicationRepository
	jwtManager *jwt.Manager
	cache      cache.Cache
}

/*
 * NewOIDCHandler 创建 OIDC 处理器实例
 * @param issuer - JWT 签发者标识（iss）
 */
func NewOIDCHandler(issuer string) *OIDCHandler {
	h := &OIDCHandler{
		issuer: issuer,
		keyID:  "oauth2-key-1",
	}
	/* RSA 密钥延迟生成：首次访问 JWKS 端点时触发，不阻塞服务启动 */
	go h.generateKey()
	return h
}

/* SetOAuthRepo 注入 OAuth 仓储和 JWT 管理器（用于 Token 撤销和 OIDC Logout） */
func (h *OIDCHandler) SetOAuthRepo(oauthRepo *repository.OAuthRepository, jwtManager *jwt.Manager) {
	h.oauthRepo = oauthRepo
	h.jwtManager = jwtManager
}

/* SetApplicationRepo 注入应用仓储（用于校验 OIDC logout 回跳地址） */
func (h *OIDCHandler) SetApplicationRepo(appRepo *repository.ApplicationRepository) {
	h.appRepo = appRepo
}

/* SetCache 注入统一缓存实例（用于 discovery/JWKS 热读缓存） */
func (h *OIDCHandler) SetCache(c cache.Cache) {
	h.cache = c
}

/*
 * generateKey 生成 RSA 密钥对用于 JWT/OIDC 签名
 * 使用 2048 位（NIST 推荐安全等级，生成速度比 4096 位快约 8 倍）
 */
func (h *OIDCHandler) generateKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.privateKey = key
	h.mu.Unlock()
}

/* ensureKey 确保 RSA 密钥已生成，未就绪时同步生成 */
func (h *OIDCHandler) ensureKey() {
	h.mu.RLock()
	hasKey := h.privateKey != nil
	h.mu.RUnlock()
	if !hasKey {
		h.generateKey()
	}
}

// Discovery returns the OIDC discovery document
// GET /.well-known/openid-configuration
func (h *OIDCHandler) Discovery(c *gin.Context) {
	// 动态获取issuer（基于请求的host）
	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)
	cacheKey := "oidc:discovery:" + issuer

	if h.cache != nil {
		if cached, err := cache.GetJSON[map[string]interface{}](c.Request.Context(), h.cache, cacheKey); err == nil {
			c.JSON(http.StatusOK, cached)
			return
		}
	}

	discovery := map[string]interface{}{
		// 必需字段
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"userinfo_endpoint":      issuer + "/oauth/userinfo",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"introspection_endpoint": issuer + "/oauth/introspect",
		"end_session_endpoint":   issuer + "/oauth/logout",

		// 支持的响应类型：授权提交路径当前只接受 authorization code flow
		"response_types_supported": []string{
			"code",
		},

		// 支持的响应模式：redirect URL 构造只使用 query 参数
		"response_modes_supported": []string{
			"query",
		},

		// 支持的 OIDC prompt 值
		"prompt_values_supported": []string{
			"none",
			"login",
			"consent",
		},

		// 支持的授权类型
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		// 支持的主题标识符类型
		"subject_types_supported": []string{
			"public",
		},

		// 支持的ID Token签名算法：jwt.Manager 当前使用 HS256 签发 id_token
		"id_token_signing_alg_values_supported": []string{
			"HS256",
		},

		// 支持的Token端点认证方法
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none", // 公开客户端
		},

		// 支持的 scope（OIDC 用户 scope + 机器 scope）
		"scopes_supported": model.AllServerSupportedScopes(),

		// 支持的 claims：仅公布当前 ID Token / UserInfo 实际可输出的标准 claim
		"claims_supported": []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"nonce",
			"auth_time",
			"amr",
			"at_hash",
			"azp",
			"name",
			"family_name",
			"given_name",
			"nickname",
			"preferred_username",
			"picture",
			"website",
			"gender",
			"birthdate",
			"zoneinfo",
			"locale",
			"updated_at",
			"email",
			"email_verified",
			"phone_number",
			"phone_number_verified",
			"address",
		},

		// PKCE 支持（仅 S256，plain 已禁用以防止中间人攻击）
		"code_challenge_methods_supported": []string{
			"S256",
		},

		// 其他功能
		"claims_parameter_supported":       false,
		"request_parameter_supported":      false,
		"request_uri_parameter_supported":  false,
		"require_request_uri_registration": false,
		"ui_locales_supported":             []string{"zh-CN", "en"},
		"service_documentation":            issuer + "/docs",

		// Device Authorization (RFC 8628)
		"device_authorization_endpoint": issuer + "/oauth/device/code",

		// 自定义扩展
		"sdk_endpoint":        issuer + "/api/sdk",
		"federation_endpoint": issuer + "/api/federation",
	}

	if h.cache != nil {
		_ = cache.SetJSON(c.Request.Context(), h.cache, cacheKey, discovery, 2*time.Minute)
	}
	c.JSON(http.StatusOK, discovery)
}

// JWKS returns the JSON Web Key Set
// GET /.well-known/jwks.json
func (h *OIDCHandler) JWKS(c *gin.Context) {
	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)
	cacheKey := "oidc:jwks:" + issuer
	if h.cache != nil {
		if cached, err := cache.GetJSON[map[string]interface{}](c.Request.Context(), h.cache, cacheKey); err == nil {
			c.JSON(http.StatusOK, cached)
			return
		}
	}

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{},
	}

	if h.cache != nil {
		_ = cache.SetJSON(c.Request.Context(), h.cache, cacheKey, jwks, 2*time.Minute)
	}
	c.JSON(http.StatusOK, jwks)
}

// WebFinger handles WebFinger requests for OIDC discovery
// GET /.well-known/webfinger
func (h *OIDCHandler) WebFinger(c *gin.Context) {
	resource := c.Query("resource")
	rel := c.Query("rel")

	if resource == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource parameter required"})
		return
	}

	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)

	// 如果请求的是OIDC issuer发现
	if rel == "http://openid.net/specs/connect/1.0/issuer" || rel == "" {
		response := map[string]interface{}{
			"subject": resource,
			"links": []map[string]string{
				{
					"rel":  "http://openid.net/specs/connect/1.0/issuer",
					"href": issuer,
				},
			},
		}
		c.Header("Content-Type", "application/jrd+json")
		c.JSON(http.StatusOK, response)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
}

// Logout handles OIDC logout (RP-initiated)
// GET/POST /oauth/logout
func (h *OIDCHandler) Logout(c *gin.Context) {
	// 获取参数
	idTokenHint := c.Query("id_token_hint")
	if idTokenHint == "" {
		idTokenHint = c.PostForm("id_token_hint")
	}

	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = c.PostForm("post_logout_redirect_uri")
	}

	state := c.Query("state")
	if state == "" {
		state = c.PostForm("state")
	}

	var logoutApp *model.Application
	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)
	if idTokenHint != "" && h.jwtManager != nil {
		claims, err := h.jwtManager.ValidateToken(idTokenHint)
		if err != nil && h.appRepo != nil {
			if unverifiedClaims, parseErr := h.jwtManager.ParseUnverifiedClaims(idTokenHint); parseErr == nil && unverifiedClaims.ClientID != "" {
				if app, findErr := h.appRepo.FindByClientID(unverifiedClaims.ClientID); findErr == nil {
					verifiedClaims, verifyErr := h.jwtManager.ValidateClientIDTokenWithIssuer(idTokenHint, app.ClientID, app.ClientSecret, issuer)
					if verifyErr != nil {
						verifiedClaims, verifyErr = h.jwtManager.ValidateClientIDToken(idTokenHint, app.ClientID, app.ClientSecret)
					}
					if verifyErr == nil {
						claims = verifiedClaims
						err = nil
					}
				}
			}
		}
		if err == nil && claims != nil && claims.TokenType == jwt.TokenTypeIDToken {
			userID := claims.UserID
			if h.oauthRepo != nil && userID != (uuid.UUID{}) {
				h.oauthRepo.RevokeTokensByUserID(userID)
			}
			if h.appRepo != nil && claims.ClientID != "" {
				if app, findErr := h.appRepo.FindByClientID(claims.ClientID); findErr == nil {
					logoutApp = app
				}
			}
		}
	}

	// 如果有已登记重定向 URI，重定向回去
	if postLogoutRedirectURI != "" && logoutApp != nil && logoutApp.ValidateRedirectURI(postLogoutRedirectURI) {
		redirectURL := postLogoutRedirectURI
		if state != "" {
			if u, err := url.Parse(redirectURL); err == nil {
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
				redirectURL = u.String()
			}
		}
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// 否则显示登出成功页面
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}
