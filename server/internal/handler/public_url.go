package handler

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

/*
 * OAuthPublicURL 构建 OAuth 站点上的前端页面绝对地址（设备流 / 授权页等）
 * 优先 frontendURL（与嵌入 SPA 同源），否则回退为浏览器可访问的 baseURL
 */
func OAuthPublicURL(baseURL, frontendURL, pathSegment string) string {
	root := OAuthPublicRoot(baseURL, frontendURL)
	seg := strings.Trim(pathSegment, "/")
	if seg == "" {
		return root + "/"
	}
	return root + "/" + seg + "/"
}

/* OAuthPublicRoot 返回 OAuth/SPA 对外根 URL（无尾斜杠） */
func OAuthPublicRoot(baseURL, frontendURL string) string {
	if root := strings.TrimRight(strings.TrimSpace(frontendURL), "/"); root != "" {
		return root
	}
	return BrowserReachableBaseURL(baseURL)
}

/*
 * RequestOAuthRoot 按请求推导对外根 URL
 * 未配置 frontend_url 时优先用 Host（客户端实际访问的地址），避免 bind 0.0.0.0 写入 verification_uri
 */
func RequestOAuthRoot(r *http.Request, configuredBase, frontendURL string) string {
	if root := strings.TrimRight(strings.TrimSpace(frontendURL), "/"); root != "" {
		return root
	}
	if r != nil {
		host := requestHost(r)
		if host != "" && !isUnusablePublicHost(host) {
			return requestScheme(r) + "://" + host
		}
	}
	return BrowserReachableBaseURL(configuredBase)
}

/* BrowserReachableBaseURL 将 0.0.0.0 / :: 等绑定地址替换为 localhost */
func BrowserReachableBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "http://localhost"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimRight(raw, "/")
	}
	host := u.Hostname()
	switch strings.ToLower(host) {
	case "0.0.0.0", "::", "[::]":
		host = "localhost"
		if port := u.Port(); port != "" {
			u.Host = net.JoinHostPort(host, port)
		} else {
			u.Host = host
		}
	}
	return strings.TrimRight(u.String(), "/")
}

/* DeviceVerificationURLs 设备授权页 URL（RFC 8628） */
func DeviceVerificationURLs(oauthRoot, userCode string) (verificationURI, verificationURIComplete string) {
	verificationURI = strings.TrimRight(oauthRoot, "/") + "/device/"
	verificationURIComplete = verificationURI + "?user_code=" + url.QueryEscape(userCode)
	return verificationURI, verificationURIComplete
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
	}
	return "http"
}

func requestHost(r *http.Request) string {
	if xf := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	return strings.TrimSpace(r.Host)
}

func isUnusablePublicHost(host string) bool {
	h := host
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		// IPv6 [::1]:port
		if strings.HasPrefix(h, "[") {
			if j := strings.IndexByte(h, ']'); j > 0 {
				h = h[1:j]
			}
		} else {
			h = h[:i]
		}
	}
	h = strings.Trim(h, "[]")
	switch strings.ToLower(h) {
	case "0.0.0.0", "::", "":
		return true
	default:
		return false
	}
}

/* NormalizeServerBaseURL 若 frontend 为空则保证 base 无尾斜杠 */
func NormalizeServerBaseURL(baseURL string) string {
	return strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

/* JoinServerPath 将相对路径拼到服务根 URL（供 SDK 回退） */
func JoinServerPath(serverBase, path string) string {
	base := BrowserReachableBaseURL(serverBase)
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

/* FormatPublicURL 用于日志 */
func FormatPublicURL(baseURL, frontendURL string) string {
	return fmt.Sprintf("frontend=%q public_root=%q", frontendURL, OAuthPublicRoot(baseURL, frontendURL))
}

/* SamePublicOrigin 判断两个 URL 是否同一对外站点（scheme+host+port） */
func SamePublicOrigin(a, b string) bool {
	return normalizePublicOrigin(a) == normalizePublicOrigin(b)
}

func normalizePublicOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(BrowserReachableBaseURL(raw))
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimRight(raw, "/"))
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + host + ":" + port
}
