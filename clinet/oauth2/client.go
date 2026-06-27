/*
 * Package oauth2 OAuth2 客户端 SDK
 * 功能：提供 OAuth2 Authorization Code (PKCE)、Client Credentials、Device Flow 等授权流程
 *       包含 Token 管理、Webhook 接收、SSE 事件监听、Gin/Echo 中间件集成
 */
package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

/* SDK 错误定义 */
var (
	ErrNoToken             = errors.New("oauth2: no token available")
	ErrTokenExpired        = errors.New("oauth2: token expired")
	ErrInvalidState        = errors.New("oauth2: invalid state parameter")
	ErrInvalidGrant        = errors.New("oauth2: invalid grant")
	ErrServerError         = errors.New("oauth2: server error")
	ErrNetworkError        = errors.New("oauth2: network error")
	ErrRateLimited         = errors.New("oauth2: rate limited")
	ErrInvalidClient       = errors.New("oauth2: invalid client credentials")
	ErrInvalidScope        = errors.New("oauth2: invalid scope")
	ErrAccessDenied        = errors.New("oauth2: access denied")
	ErrConflict            = errors.New("oauth2: conflict")
	ErrMaxRetriesExhausted = errors.New("oauth2: max retries exhausted")
)

/*
 * OAuthError 结构化 OAuth2 错误，携带服务端返回的详细信息
 * 功能：将服务端 error / error_description 封装为可判断的错误类型
 */
type OAuthError struct {
	Code        string /* OAuth2 错误码，如 invalid_grant, invalid_client */
	Description string /* 服务端返回的可读错误描述 */
	StatusCode  int    /* HTTP 状态码 */
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		if e.StatusCode == 0 {
			return fmt.Sprintf("oauth2: %s - %s", e.Code, e.Description)
		}
		return fmt.Sprintf("oauth2: %s - %s (HTTP %d)", e.Code, e.Description, e.StatusCode)
	}
	if e.StatusCode == 0 {
		return fmt.Sprintf("oauth2: %s", e.Code)
	}
	return fmt.Sprintf("oauth2: %s (HTTP %d)", e.Code, e.StatusCode)
}

/*
 * IsOAuthError 判断 err 是否为 OAuthError，并提取其值
 * 用法：if oauthErr, ok := oauth2.IsOAuthError(err); ok { ... }
 */
func IsOAuthError(err error) (*OAuthError, bool) {
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr, true
	}
	return nil, false
}

/*
 * Client OAuth2 客户端
 * 功能：封装 OAuth2 授权流程、Token 管理、用户信息获取等操作
 *       支持自定义 HTTP 客户端、Token 存储和日志器
 */
type Client struct {
	config     *Config
	httpClient *http.Client
	tokenStore TokenStore
	logger     Logger

	// State management for authorization flow
	stateMu sync.RWMutex
	states  map[string]*authState
	stopCh  chan struct{}
}

/* authState 授权请求的状态信息（PKCE + 创建时间） */
type authState struct {
	pkce      *PKCE
	createdAt time.Time
}

/* stateMaxAge auth state 最大存活时间（10 分钟），超过后自动清理防止内存泄漏 */
const stateMaxAge = 10 * time.Minute

/*
 * NewClient 创建新的 OAuth2 客户端实例
 * @param config - 客户端配置（包含服务器地址、client_id、client_secret 等）
 * @return *Client - 客户端实例
 * 自动配置 HTTP 客户端超时和连接池参数
 */
func NewClient(config *Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	/* 设置默认超时 */
	timeout := 30 * time.Second
	if config.TimeoutSec > 0 {
		timeout = time.Duration(config.TimeoutSec) * time.Second
	}

	/* 配置带连接池优化的 HTTP Transport */
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	c := &Client{
		config:     config,
		httpClient: httpClient,
		tokenStore: NewMemoryTokenStore(),
		logger:     NewDefaultLogger(),
		states:     make(map[string]*authState),
		stopCh:     make(chan struct{}),
	}

	/* 启动后台协程清理过期的 auth state，防止内存泄漏 */
	go c.cleanupStaleStates()

	return c, nil
}

/*
 * Close 关闭客户端，停止后台清理协程
 * 功能：释放后台资源，应在客户端不再使用时调用
 */
func (c *Client) Close() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
}

/*
 * cleanupStaleStates 后台定期清理过期的 auth state
 * 功能：每分钟扫描一次，删除超过 stateMaxAge 的 state，防止内存泄漏
 */
func (c *Client) cleanupStaleStates() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.stateMu.Lock()
			now := time.Now()
			for key, s := range c.states {
				if now.Sub(s.createdAt) > stateMaxAge {
					delete(c.states, key)
				}
			}
			c.stateMu.Unlock()
		}
	}
}

/* SetLogger 设置自定义日志器 */
func (c *Client) SetLogger(logger Logger) {
	c.logger = logger
}

/* SetHTTPClient 设置自定义 HTTP 客户端 */
func (c *Client) SetHTTPClient(client *http.Client) {
	c.httpClient = client
}

/* SetTokenStore 设置自定义 Token 存储 */
func (c *Client) SetTokenStore(store TokenStore) {
	c.tokenStore = store
}

/*
 * AuthCodeURL 生成授权服务器的授权页面 URL
 * 功能：自动生成 state 参数和 PKCE，拼接完整的授权 URL
 * @return string - 授权页面 URL
 */
func (c *Client) AuthCodeURL() (string, error) {
	// Generate state
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Build URL
	u, err := url.Parse(c.config.AuthURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.config.ClientID)
	q.Set("redirect_uri", c.config.RedirectURL)
	q.Set("state", state)

	if len(c.config.Scopes) > 0 {
		q.Set("scope", strings.Join(c.config.Scopes, " "))
	}

	// Store state
	authState := &authState{createdAt: time.Now()}

	// Add PKCE if enabled
	if c.config.UsePKCE {
		pkce, err := GeneratePKCE()
		if err != nil {
			return "", err
		}
		q.Set("code_challenge", pkce.CodeChallenge)
		q.Set("code_challenge_method", pkce.Method)
		authState.pkce = pkce
	}

	c.stateMu.Lock()
	c.states[state] = authState
	c.stateMu.Unlock()

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange exchanges an authorization code for a token
func (c *Client) Exchange(ctx context.Context, code, state string) (*Token, error) {
	// Validate state
	c.stateMu.Lock()
	authState, ok := c.states[state]
	if !ok {
		c.stateMu.Unlock()
		return nil, ErrInvalidState
	}
	delete(c.states, state)
	c.stateMu.Unlock()

	// Build request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.config.RedirectURL)
	data.Set("client_id", c.config.ClientID)

	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	if authState.pkce != nil {
		data.Set("code_verifier", authState.pkce.CodeVerifier)
	}

	// Make request
	token, err := c.doTokenRequest(ctx, data)
	if err != nil {
		return nil, err
	}

	// Store token
	if err := c.tokenStore.SetToken(token); err != nil {
		return nil, err
	}

	return token, nil
}

// Refresh refreshes the access token using the refresh token
func (c *Client) Refresh(ctx context.Context) (*Token, error) {
	token, err := c.tokenStore.GetToken()
	if err != nil {
		return nil, err
	}
	if token == nil || token.RefreshToken == "" {
		return nil, ErrNoToken
	}

	// Build request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", token.RefreshToken)
	data.Set("client_id", c.config.ClientID)

	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	// Make request
	newToken, err := c.doTokenRequest(ctx, data)
	if err != nil {
		return nil, err
	}

	// Store token
	if err := c.tokenStore.SetToken(newToken); err != nil {
		return nil, err
	}

	return newToken, nil
}

// GetToken returns the current token, refreshing if necessary
func (c *Client) GetToken(ctx context.Context) (*Token, error) {
	token, err := c.tokenStore.GetToken()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, ErrNoToken
	}

	// Refresh if expired
	if token.IsExpired() && token.RefreshToken != "" {
		return c.Refresh(ctx)
	}

	if !token.IsValid() {
		return nil, ErrTokenExpired
	}

	return token, nil
}

// GetUserInfo fetches user information from the userinfo endpoint
func (c *Client) GetUserInfo(ctx context.Context) (*UserInfo, error) {
	token, err := c.GetToken(ctx)
	if err != nil {
		return nil, err
	}

	return c.getUserInfoWithAccessToken(ctx, token.AccessToken)
}

func (c *Client) getUserInfoWithAccessToken(ctx context.Context, accessToken string) (*UserInfo, error) {
	if c.config.UserInfoURL == "" {
		return nil, errors.New("oauth2: userinfo_url not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth2: userinfo request failed with status %d", resp.StatusCode)
	}

	/* 限制响应体大小（5MB），防止恶意服务端返回超大响应 */
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func deriveOAuthEndpoint(tokenURL, endpoint string) string {
	u, err := url.Parse(tokenURL)
	if err != nil {
		return strings.TrimSuffix(tokenURL, "/token") + "/" + strings.TrimPrefix(endpoint, "/")
	}
	u.Path = strings.TrimSuffix(u.Path, "/token") + "/" + strings.TrimPrefix(endpoint, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func parseOAuthHTTPError(resp *http.Response, body []byte, defaultCode string) error {
	var errResp struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return &OAuthError{
			Code:        errResp.Error,
			Description: errResp.Description,
			StatusCode:  resp.StatusCode,
		}
	}
	return &OAuthError{
		Code:       defaultCode,
		StatusCode: resp.StatusCode,
	}
}

func parseSDKAPIError(statusCode int, body []byte, operation string) error {
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil {
		switch errResp.Error.Code {
		case "INVALID_CLIENT":
			return ErrInvalidClient
		case "FORBIDDEN", "ACCESS_DENIED":
			return ErrAccessDenied
		case "USER_DISABLED":
			return ErrAccessDenied
		case "CONFLICT":
			return ErrConflict
		case "TOKEN_EXPIRED", "TOKEN_INVALID":
			return ErrTokenExpired
		case "UNAUTHORIZED":
			switch errResp.Error.Message {
			case "Invalid client credentials":
				return ErrInvalidClient
			case "Invalid or expired access token", "Invalid or expired refresh token":
				return ErrTokenExpired
			}
		}
	}
	if statusCode == http.StatusUnauthorized {
		return ErrTokenExpired
	}
	if statusCode == http.StatusForbidden {
		return ErrAccessDenied
	}
	if statusCode == http.StatusConflict {
		return ErrConflict
	}
	return fmt.Errorf("oauth2: %s failed with status %d", operation, statusCode)
}

func parseSDKVerifyError(statusCode int, body []byte) error {
	return parseSDKAPIError(statusCode, body, "validate token")
}

/*
 * RevokeToken 撤销令牌 (RFC 7009)
 * 功能：向服务端 revoke 端点发送撤销请求，同时清除本地存储
 * @param ctx           - 上下文
 * @param tokenTypeHint - 令牌类型提示 ("access_token" / "refresh_token"，可为空)
 */
func (c *Client) RevokeToken(ctx context.Context, tokenTypeHint string) error {
	token, err := c.tokenStore.GetToken()
	if err != nil || token == nil {
		return c.tokenStore.DeleteToken()
	}

	/* 确定要撤销的令牌值 */
	revokeToken := token.AccessToken
	if tokenTypeHint == "refresh_token" && token.RefreshToken != "" {
		revokeToken = token.RefreshToken
	}

	revokeURL := deriveOAuthEndpoint(c.config.TokenURL, "revoke")

	data := url.Values{}
	data.Set("token", revokeToken)
	if tokenTypeHint != "" {
		data.Set("token_type_hint", tokenTypeHint)
	}
	data.Set("client_id", c.config.ClientID)
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	req, reqErr := http.NewRequestWithContext(ctx, "POST", revokeURL, strings.NewReader(data.Encode()))
	if reqErr != nil {
		return reqErr
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, doErr := c.httpClient.Do(req)
	if doErr != nil {
		return doErr
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return parseOAuthHTTPError(resp, body, "unknown_error")
	}

	c.logger.Debug("Token revoked successfully")

	/* 清除本地存储 */
	return c.tokenStore.DeleteToken()
}

/*
 * IntrospectToken 令牌自省 (RFC 7662)
 * 功能：查询令牌的元数据（是否有效、scope、过期时间等）
 * @param ctx           - 上下文
 * @param token         - 要查询的令牌字符串
 * @param tokenTypeHint - 令牌类型提示（可为空）
 * @return map[string]interface{} - 自省结果
 */
func (c *Client) IntrospectToken(ctx context.Context, token string, tokenTypeHint string) (map[string]interface{}, error) {
	introspectURL := deriveOAuthEndpoint(c.config.TokenURL, "introspect")

	data := url.Values{}
	data.Set("token", token)
	if tokenTypeHint != "" {
		data.Set("token_type_hint", tokenTypeHint)
	}
	data.Set("client_id", c.config.ClientID)
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, parseOAuthHTTPError(resp, body, "unknown_error")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

/*
 * Logout 登出并清除本地 Token
 * 功能：可选地先向服务端撤销 access_token 和 refresh_token，再清除本地存储
 * @param revokeRemote - 是否同时撤销服务端令牌（推荐生产环境开启）
 */
func (c *Client) Logout(revokeRemote ...bool) error {
	if len(revokeRemote) > 0 && revokeRemote[0] {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		/* 优先撤销 refresh_token（会级联失效关联的 access_token） */
		if err := c.RevokeToken(ctx, "refresh_token"); err != nil {
			c.logger.Debug("Failed to revoke refresh token: %v", err)
			/* 回退：尝试撤销 access_token */
			_ = c.RevokeToken(ctx, "access_token")
		}
		/* RevokeToken 已清除本地存储，直接返回 */
		return nil
	}
	return c.tokenStore.DeleteToken()
}

/*
 * TokenValid 检查当前 token 是否有效（未过期且存在）
 * @return bool - token 有效返回 true
 */
func (c *Client) TokenValid() bool {
	token, err := c.tokenStore.GetToken()
	if err != nil || token == nil {
		return false
	}
	return !token.IsExpired()
}

/*
 * EnsureToken 确保有有效的 token，过期时自动刷新
 * @param ctx - 上下文
 * @return *Token - 有效的 token
 */
func (c *Client) EnsureToken(ctx context.Context) (*Token, error) {
	token, err := c.tokenStore.GetToken()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, ErrNoToken
	}
	if !token.IsExpired() {
		return token, nil
	}
	/* token 已过期，尝试刷新 */
	if token.RefreshToken != "" {
		return c.RefreshToken(ctx)
	}
	return nil, ErrTokenExpired
}

// RefreshToken refreshes the access token using the refresh token
func (c *Client) RefreshToken(ctx context.Context) (*Token, error) {
	token, err := c.tokenStore.GetToken()
	if err != nil {
		return nil, err
	}
	if token == nil || token.RefreshToken == "" {
		return nil, errors.New("oauth2: no refresh token available")
	}

	c.logger.Debug("Refreshing token")

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", token.RefreshToken)
	data.Set("client_id", c.config.ClientID)
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	newToken, err := c.doTokenRequest(ctx, data)
	if err != nil {
		return nil, err
	}

	// Preserve refresh token if not returned
	if newToken.RefreshToken == "" {
		newToken.RefreshToken = token.RefreshToken
	}

	if err := c.tokenStore.SetToken(newToken); err != nil {
		return nil, err
	}

	return newToken, nil
}

/*
 * doTokenRequest 向 Token 端点发送请求
 * 功能：带指数退避重试机制，仅对 5xx 和网络错误重试
 */
func (c *Client) doTokenRequest(ctx context.Context, data url.Values) (*Token, error) {
	maxRetries := 3
	if c.config.MaxRetries > 0 {
		maxRetries = c.config.MaxRetries
	}
	retryDelay := 500 * time.Millisecond
	if c.config.RetryDelay > 0 {
		retryDelay = time.Duration(c.config.RetryDelay) * time.Millisecond
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			/* 指数退避等待 */
			backoff := retryDelay * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			c.logger.Debug(fmt.Sprintf("Retrying token request (attempt %d/%d)", attempt, maxRetries))
		}

		req, err := http.NewRequestWithContext(ctx, "POST", c.config.TokenURL, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			/* 网络错误可重试 */
			continue
		}

		/* 限制响应体大小（5MB） */
		body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		/* 5xx 服务端错误可重试 */
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("oauth2: token request failed with status %d", resp.StatusCode)
			continue
		}

		/* 429 限流错误可重试 */
		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = ErrRateLimited
			continue
		}

		/* 4xx 客户端错误不重试，返回结构化错误 */
		if resp.StatusCode != http.StatusOK {
			var errResp struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
				return nil, &OAuthError{
					Code:        errResp.Error,
					Description: errResp.Description,
					StatusCode:  resp.StatusCode,
				}
			}
			return nil, &OAuthError{
				Code:       "unknown_error",
				StatusCode: resp.StatusCode,
			}
		}

		token, err := parseTokenResponse(body)
		if err != nil {
			return nil, err
		}
		if err := c.validateTokenIDToken(token); err != nil {
			return nil, err
		}
		return token, nil
	}

	return nil, fmt.Errorf("oauth2: token request failed after %d retries: %w", maxRetries, lastErr)
}

// UserInfo represents user information from the userinfo endpoint (OIDC compliant)
type UserInfo struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
	UpdatedAt         int64  `json:"updated_at"`

	// OIDC Standard Claims
	GivenName           string            `json:"given_name,omitempty"`
	FamilyName          string            `json:"family_name,omitempty"`
	Nickname            string            `json:"nickname,omitempty"`
	Gender              string            `json:"gender,omitempty"`
	Birthdate           string            `json:"birthdate,omitempty"`
	PhoneNumber         string            `json:"phone_number,omitempty"`
	PhoneNumberVerified bool              `json:"phone_number_verified,omitempty"`
	Address             *AddressInfo      `json:"address,omitempty"`
	Locale              string            `json:"locale,omitempty"`
	Zoneinfo            string            `json:"zoneinfo,omitempty"`
	Website             string            `json:"website,omitempty"`
	Bio                 string            `json:"bio,omitempty"`
	SocialAccounts      map[string]string `json:"social_accounts,omitempty"`
}

// AddressInfo represents OIDC address claim
type AddressInfo struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// SDKRegisterRequest represents SDK registration request
type SDKRegisterRequest struct {
	Email          string `json:"email"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	ExternalID     string `json:"external_id,omitempty"`
	ExternalSource string `json:"external_source,omitempty"`
}

// SDKLoginRequest represents SDK login request
type SDKLoginRequest struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	ExternalID     string `json:"external_id,omitempty"`
	ExternalSource string `json:"external_source,omitempty"`
}

// SDKUserResponse represents user info in SDK response
type SDKUserResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// SDKTokenResponse represents SDK token response
type SDKTokenResponse struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	IDToken      string          `json:"id_token,omitempty"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    int64           `json:"expires_in"`
	User         SDKUserResponse `json:"user"`
}

func tokenFromSDKTokenResponse(resp *SDKTokenResponse) *Token {
	token := &Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		IDToken:      resp.IDToken,
		TokenType:    resp.TokenType,
	}
	token.SetExpiry(resp.ExpiresIn)
	return token
}

func (c *Client) storeSDKTokenResponse(resp *SDKTokenResponse) (*Token, error) {
	token := tokenFromSDKTokenResponse(resp)
	if err := c.validateTokenIDToken(token); err != nil {
		return nil, err
	}
	if err := c.tokenStore.SetToken(token); err != nil {
		return nil, err
	}
	return token, nil
}

// RegisterUser registers a new user via SDK API
func (c *Client) RegisterUser(ctx context.Context, req *SDKRegisterRequest) (*SDKTokenResponse, error) {
	apiURL := strings.TrimSuffix(c.config.AuthURL, "/oauth/authorize")
	registerURL := apiURL + "/api/sdk/register"

	payload := map[string]string{
		"client_id":     c.config.ClientID,
		"client_secret": c.config.ClientSecret,
		"email":         req.Email,
		"username":      req.Username,
		"password":      req.Password,
	}
	if req.ExternalID != "" {
		payload["external_id"] = req.ExternalID
	}
	if req.ExternalSource != "" {
		payload["external_source"] = req.ExternalSource
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", registerURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, parseSDKAPIError(resp.StatusCode, respBody, "register")
	}

	var result struct {
		Data SDKTokenResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	// Store token
	if _, err := c.storeSDKTokenResponse(&result.Data); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// LoginUser logs in a user via SDK API
func (c *Client) LoginUser(ctx context.Context, req *SDKLoginRequest) (*SDKTokenResponse, error) {
	apiURL := strings.TrimSuffix(c.config.AuthURL, "/oauth/authorize")
	loginURL := apiURL + "/api/sdk/login"

	payload := map[string]string{
		"client_id":     c.config.ClientID,
		"client_secret": c.config.ClientSecret,
		"email":         req.Email,
		"password":      req.Password,
	}
	if req.ExternalID != "" {
		payload["external_id"] = req.ExternalID
	}
	if req.ExternalSource != "" {
		payload["external_source"] = req.ExternalSource
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseSDKAPIError(resp.StatusCode, respBody, "login")
	}

	var result struct {
		Data SDKTokenResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	// Store token
	if _, err := c.storeSDKTokenResponse(&result.Data); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// RefreshSDKUserToken refreshes the SDK user token through /api/sdk/refresh.
func (c *Client) RefreshSDKUserToken(ctx context.Context) (*SDKTokenResponse, error) {
	token, err := c.tokenStore.GetToken()
	if err != nil {
		return nil, err
	}
	if token == nil || token.RefreshToken == "" {
		return nil, errors.New("oauth2: no refresh token available")
	}

	apiURL := strings.TrimSuffix(c.config.AuthURL, "/oauth/authorize")
	refreshURL := apiURL + "/api/sdk/refresh"

	payload := map[string]string{
		"client_id":     c.config.ClientID,
		"client_secret": c.config.ClientSecret,
		"refresh_token": token.RefreshToken,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", refreshURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseSDKAPIError(resp.StatusCode, respBody, "refresh SDK user token")
	}

	var result struct {
		Data SDKTokenResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	if _, err := c.storeSDKTokenResponse(&result.Data); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// EnsureSDKUserToken returns a valid SDK user token, refreshing via /api/sdk/refresh when expired.
func (c *Client) EnsureSDKUserToken(ctx context.Context) (*Token, error) {
	token, err := c.tokenStore.GetToken()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, ErrNoToken
	}
	if !token.IsExpired() {
		return token, nil
	}
	if token.RefreshToken == "" {
		return nil, ErrTokenExpired
	}

	resp, err := c.RefreshSDKUserToken(ctx)
	if err != nil {
		return nil, err
	}
	return tokenFromSDKTokenResponse(resp), nil
}

// SignTokenRequest represents service token signing request
type SignTokenRequest struct {
	Claims    map[string]interface{} `json:"claims,omitempty"`
	ExpiresIn int64                  `json:"expires_in,omitempty"`
}

// SignTokenResponse represents signed token response
type SignTokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in"`
}

// SignToken signs a client-scoped service token.
func (c *Client) SignToken(ctx context.Context, req *SignTokenRequest) (*SignTokenResponse, error) {
	apiURL := strings.TrimSuffix(c.config.AuthURL, "/oauth/authorize")
	signURL := apiURL + "/token/sign"

	payload := map[string]interface{}{
		"client_id":     c.config.ClientID,
		"client_secret": c.config.ClientSecret,
	}
	if req.Claims != nil {
		payload["claims"] = req.Claims
	}
	if req.ExpiresIn > 0 {
		payload["expires_in"] = req.ExpiresIn
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", signURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("oauth2: %s", errResp.Error)
		}
		return nil, fmt.Errorf("oauth2: sign token failed with status %d", resp.StatusCode)
	}

	var result struct {
		Data SignTokenResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// LegacySyncUserRequest 旧版用户同步请求（需要密码）
type LegacySyncUserRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
	Avatar   string `json:"avatar,omitempty"`
}

// LegacySyncUserResponse 旧版用户同步响应
type LegacySyncUserResponse struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Username     string `json:"username"`
	Created      bool   `json:"created"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// LegacySyncUser 旧版同步用户（需要密码，会生成token）
func (c *Client) LegacySyncUser(ctx context.Context, req *LegacySyncUserRequest) (*LegacySyncUserResponse, error) {
	c.logger.Info("Syncing user (legacy)", req.Email)

	// First try to login
	loginResp, err := c.LoginUser(ctx, &SDKLoginRequest{
		Email:    req.Email,
		Password: req.Password,
	})

	if err == nil {
		return &LegacySyncUserResponse{
			UserID:       loginResp.User.ID,
			Email:        loginResp.User.Email,
			Username:     loginResp.User.Username,
			Created:      false,
			AccessToken:  loginResp.AccessToken,
			RefreshToken: loginResp.RefreshToken,
			IDToken:      loginResp.IDToken,
			TokenType:    loginResp.TokenType,
			ExpiresIn:    loginResp.ExpiresIn,
		}, nil
	}

	// Try to register new user
	registerResp, err := c.RegisterUser(ctx, &SDKRegisterRequest{
		Email:    req.Email,
		Username: req.Username,
		Password: req.Password,
	})

	if err != nil {
		return nil, fmt.Errorf("oauth2: sync user failed: %w", err)
	}

	return &LegacySyncUserResponse{
		UserID:       registerResp.User.ID,
		Email:        registerResp.User.Email,
		Username:     registerResp.User.Username,
		Created:      true,
		AccessToken:  registerResp.AccessToken,
		RefreshToken: registerResp.RefreshToken,
		IDToken:      registerResp.IDToken,
		TokenType:    registerResp.TokenType,
		ExpiresIn:    registerResp.ExpiresIn,
	}, nil
}

// ValidateUserToken validates an SDK user token and returns user info.
func (c *Client) ValidateUserToken(ctx context.Context, token string) (*UserInfo, error) {
	c.logger.Debug("Validating user token")

	apiURL := strings.TrimSuffix(c.config.AuthURL, "/oauth/authorize")
	verifyURL := apiURL + "/api/sdk/verify"

	payload := map[string]string{
		"client_id":     c.config.ClientID,
		"client_secret": c.config.ClientSecret,
		"access_token":  token,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", verifyURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseSDKVerifyError(resp.StatusCode, respBody)
	}

	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Valid bool `json:"valid"`
			User  struct {
				ID            string `json:"id"`
				Email         string `json:"email"`
				Username      string `json:"username"`
				Role          string `json:"role"`
				EmailVerified bool   `json:"email_verified"`
				Name          string `json:"name"`
				Avatar        string `json:"avatar"`
			} `json:"user"`
			Claims struct {
				Sub      string `json:"sub"`
				Email    string `json:"email"`
				Role     string `json:"role"`
				ClientID string `json:"client_id"`
			} `json:"claims"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	if !result.Success || !result.Data.Valid {
		return nil, ErrTokenExpired
	}

	userInfo := UserInfo{
		Sub:               result.Data.User.ID,
		Email:             result.Data.User.Email,
		EmailVerified:     result.Data.User.EmailVerified,
		Name:              result.Data.User.Name,
		PreferredUsername: result.Data.User.Username,
		Picture:           result.Data.User.Avatar,
	}
	if userInfo.Sub == "" {
		userInfo.Sub = result.Data.Claims.Sub
	}
	if userInfo.Email == "" {
		userInfo.Email = result.Data.Claims.Email
	}

	return &userInfo, nil
}

// GetAPIBaseURL returns the API base URL from config
func (c *Client) GetAPIBaseURL() string {
	return strings.TrimSuffix(c.config.AuthURL, "/oauth/authorize")
}

/*
 * HealthCheck 检查 OAuth2 服务端连通性和健康状态
 * 功能：向 /health 端点发送 GET 请求，返回服务端健康信息
 * @param ctx - 上下文（可用于超时控制）
 * @return map[string]interface{} - 健康检查结果（status, database, cache 等）
 */
func (c *Client) HealthCheck(ctx context.Context) (map[string]interface{}, error) {
	healthURL := c.GetAPIBaseURL() + "/health"

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to create health check request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2: health check failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to read health check response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("oauth2: failed to parse health check response: %w", err)
	}

	return result, nil
}

// ========== 用户同步 API ==========

// SyncUserRequest 用户同步请求
type SyncUserRequest struct {
	Email          string `json:"email"`
	Username       string `json:"username"`
	ExternalID     string `json:"external_id,omitempty"`
	ExternalSource string `json:"external_source,omitempty"`
	Password       string `json:"password,omitempty"`
	GivenName      string `json:"given_name,omitempty"`
	FamilyName     string `json:"family_name,omitempty"`
	Nickname       string `json:"nickname,omitempty"`
	Gender         string `json:"gender,omitempty"`
	Birthdate      string `json:"birthdate,omitempty"`
	PhoneNumber    string `json:"phone_number,omitempty"`
	Avatar         string `json:"avatar,omitempty"`
	EmailVerified  bool   `json:"email_verified,omitempty"`
}

// SyncUserResponse 用户同步响应
type SyncUserResponse struct {
	Action string `json:"action"` // "created" or "updated"
	User   struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Username string `json:"username"`
	} `json:"user"`
}

// SyncUser 同步单个用户到OAuth系统
func (c *Client) SyncUser(ctx context.Context, req *SyncUserRequest) (*SyncUserResponse, error) {
	c.logger.Debug("Syncing user", "email", req.Email)

	apiURL := c.GetAPIBaseURL() + "/api/sdk/sync/user"

	payload := map[string]interface{}{
		"client_id":      c.config.ClientID,
		"client_secret":  c.config.ClientSecret,
		"email":          req.Email,
		"username":       req.Username,
		"email_verified": req.EmailVerified,
	}

	if req.ExternalID != "" {
		payload["external_id"] = req.ExternalID
	}
	if req.ExternalSource != "" {
		payload["external_source"] = req.ExternalSource
	}
	if req.Password != "" {
		payload["password"] = req.Password
	}
	if req.GivenName != "" {
		payload["given_name"] = req.GivenName
	}
	if req.FamilyName != "" {
		payload["family_name"] = req.FamilyName
	}
	if req.Nickname != "" {
		payload["nickname"] = req.Nickname
	}
	if req.Gender != "" {
		payload["gender"] = req.Gender
	}
	if req.Birthdate != "" {
		payload["birthdate"] = req.Birthdate
	}
	if req.PhoneNumber != "" {
		payload["phone_number"] = req.PhoneNumber
	}
	if req.Avatar != "" {
		payload["avatar"] = req.Avatar
	}

	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errResp)
		return nil, fmt.Errorf("sync user failed: %s", errResp.Error)
	}

	var result struct {
		Data SyncUserResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// BatchSyncResponse 批量同步响应
type BatchSyncResponse struct {
	Total   int `json:"total"`
	Created int `json:"created"`
	Updated int `json:"updated"`
	Failed  int `json:"failed"`
	Results []struct {
		Email  string `json:"email"`
		Action string `json:"action"`
		ID     string `json:"id,omitempty"`
		Error  string `json:"error,omitempty"`
	} `json:"results"`
}

// BatchSyncUsers 批量同步用户
func (c *Client) BatchSyncUsers(ctx context.Context, users []SyncUserRequest) (*BatchSyncResponse, error) {
	c.logger.Debug("Batch syncing users", "count", len(users))

	apiURL := c.GetAPIBaseURL() + "/api/sdk/sync/batch"

	payload := map[string]interface{}{
		"client_id":     c.config.ClientID,
		"client_secret": c.config.ClientSecret,
		"users":         users,
	}

	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errResp)
		return nil, fmt.Errorf("batch sync failed: %s", errResp.Error)
	}

	var result struct {
		Data BatchSyncResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// GetUserByEmail 通过邮箱获取用户信息
func (c *Client) GetUserByEmail(ctx context.Context, email string) (*UserInfo, error) {
	apiURL := c.GetAPIBaseURL() + "/api/sdk/user"

	payload := map[string]string{
		"client_id":     c.config.ClientID,
		"client_secret": c.config.ClientSecret,
		"email":         email,
	}

	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // 用户不存在
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user failed with status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			User UserInfo `json:"user"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result.Data.User, nil
}
