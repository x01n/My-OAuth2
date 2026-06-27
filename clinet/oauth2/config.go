package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	openIDConfigurationPath = "/.well-known/openid-configuration"
	discoveryResponseLimit  = 1 << 20
)

/*
 * Config OAuth2 客户端配置
 * 功能：定义连接 OAuth2 服务器所需的全部参数
 */
type Config struct {
	ClientID     string   /* 应用 client_id */
	ClientSecret string   /* 应用 client_secret（公开客户端可为空） */
	Issuer       string   /* OIDC issuer（Discovery 返回的 issuer，或 SSOConfig 的 issuerURL） */
	AuthURL      string   /* 授权端点 URL */
	TokenURL     string   /* Token 端点 URL */
	UserInfoURL  string   /* UserInfo 端点 URL（可选） */
	RedirectURL  string   /* 回调 URL */
	Scopes       []string /* 请求的权限范围 */
	UsePKCE      bool     /* 是否启用 PKCE (RFC 7636) */

	/* HTTP 客户端配置 */
	TimeoutSec int /* 请求超时秒数（默认 30） */
	MaxRetries int /* 最大重试次数（默认 3，仅对可重试错误生效） */
	RetryDelay int /* 重试间隔毫秒（默认 500，指数退避） */
}

/*
 * Validate 校验配置是否有效
 * 功能：检查必填字段和 URL 格式
 * @return error - 配置无效时返回错误
 */
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return errors.New("oauth2: client_id is required")
	}
	if c.AuthURL == "" {
		return errors.New("oauth2: auth_url is required")
	}
	if c.TokenURL == "" {
		return errors.New("oauth2: token_url is required")
	}
	if c.RedirectURL == "" {
		return errors.New("oauth2: redirect_url is required")
	}

	/* 校验 URL 格式和协议安全性 */
	for _, pair := range []struct {
		name, val string
	}{
		{"auth_url", c.AuthURL},
		{"token_url", c.TokenURL},
		{"redirect_url", c.RedirectURL},
	} {
		if _, err := parseHTTPURL(pair.name, pair.val); err != nil {
			return err
		}
	}
	if c.UserInfoURL != "" {
		if _, err := parseHTTPURL("userinfo_url", c.UserInfoURL); err != nil {
			return err
		}
	}

	return nil
}

/*
 * DefaultConfig 返回默认 OAuth2 服务器的配置
 * 功能：预填本地开发服务器地址，默认启用 PKCE
 * @param clientID     - 应用 client_id
 * @param clientSecret - 应用 client_secret
 * @param redirectURL  - 回调 URL
 */
func DefaultConfig(clientID, clientSecret, redirectURL string) *Config {
	return &Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       "http://localhost:8080",
		AuthURL:      "http://localhost:3000/oauth/authorize",
		TokenURL:     "http://localhost:8080/oauth/token",
		UserInfoURL:  "http://localhost:8080/oauth/userinfo",
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		UsePKCE:      true,
	}
}

/*
 * SSOConfig 返回接入本系统 SSO 的 OAuth2/OIDC 配置
 * 功能：接入方只需提供认证中心根地址，由 SDK 派生授权、Token、UserInfo 端点
 * @param clientID     - 应用 client_id
 * @param clientSecret - 应用 client_secret
 * @param issuerURL    - 认证中心根地址，如 http://localhost:8080
 * @param redirectURL  - 接入应用回调 URL
 */
func SSOConfig(clientID, clientSecret, issuerURL, redirectURL string) *Config {
	baseURL := strings.TrimRight(issuerURL, "/")
	return &Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       baseURL,
		AuthURL:      baseURL + "/oauth/authorize",
		TokenURL:     baseURL + "/oauth/token",
		UserInfoURL:  baseURL + "/oauth/userinfo",
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		UsePKCE:      true,
	}
}

/*
 * DiscoverSSOConfig 通过 OIDC Discovery 获取接入本系统 SSO 的 OAuth2/OIDC 配置
 * 功能：请求 <issuer>/.well-known/openid-configuration，校验 issuer 后生成 Config
 * @param ctx          - 请求上下文
 * @param clientID     - 应用 client_id
 * @param clientSecret - 应用 client_secret
 * @param issuerURL    - 认证中心 issuer 地址，如 http://localhost:8080
 * @param redirectURL  - 接入应用回调 URL
 */
func DiscoverSSOConfig(ctx context.Context, clientID, clientSecret, issuerURL, redirectURL string) (*Config, error) {
	return DiscoverSSOConfigWithClient(ctx, clientID, clientSecret, issuerURL, redirectURL, nil)
}

/*
 * DiscoverSSOConfigWithClient 使用指定 HTTP 客户端通过 OIDC Discovery 生成 SSO 配置
 * 功能：便于接入方注入代理、TLS 配置或测试用 HTTP 客户端
 */
func DiscoverSSOConfigWithClient(ctx context.Context, clientID, clientSecret, issuerURL, redirectURL string, httpClient *http.Client) (*Config, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	discoveryURL, issuer, err := openIDConfigurationURL(issuerURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oauth2: create discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2: discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, discoveryResponseLimit))
	if err != nil {
		return nil, fmt.Errorf("oauth2: read discovery response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth2: discovery request returned status %d", resp.StatusCode)
	}

	var doc openIDConfiguration
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oauth2: parse discovery response: %w", err)
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("oauth2: discovery issuer mismatch")
	}
	if doc.AuthorizationEndpoint == "" {
		return nil, errors.New("oauth2: discovery authorization_endpoint is required")
	}
	if doc.TokenEndpoint == "" {
		return nil, errors.New("oauth2: discovery token_endpoint is required")
	}
	if doc.UserInfoEndpoint == "" {
		return nil, errors.New("oauth2: discovery userinfo_endpoint is required")
	}

	config := &Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       doc.Issuer,
		AuthURL:      doc.AuthorizationEndpoint,
		TokenURL:     doc.TokenEndpoint,
		UserInfoURL:  doc.UserInfoEndpoint,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		UsePKCE:      hasString(doc.CodeChallengeMethodsSupported, "S256"),
	}
	if len(doc.CodeChallengeMethodsSupported) == 0 {
		config.UsePKCE = true
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if _, err := parseHTTPURL("userinfo_url", config.UserInfoURL); err != nil {
		return nil, err
	}
	return config, nil
}

type openIDConfiguration struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	UserInfoEndpoint              string   `json:"userinfo_endpoint"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

func openIDConfigurationURL(issuerURL string) (string, string, error) {
	issuer, err := normalizeIssuerURL(issuerURL)
	if err != nil {
		return "", "", err
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", "", fmt.Errorf("oauth2: invalid issuer_url")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + openIDConfigurationPath
	return parsed.String(), issuer, nil
}

func normalizeIssuerURL(issuerURL string) (string, error) {
	issuerURL = strings.TrimSpace(issuerURL)
	if issuerURL == "" {
		return "", errors.New("oauth2: issuer_url is required")
	}
	parsed, err := parseHTTPURL("issuer_url", issuerURL)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("oauth2: issuer_url must not include query or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

func parseHTTPURL(name, value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("oauth2: invalid " + name)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("oauth2: " + name + " must use http or https scheme")
	}
	return parsed, nil
}

func hasString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
