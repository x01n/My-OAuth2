package oauth2

import (
	"net"
	"net/url"
	"strings"
)

/*
 * ResolveDeviceVerificationURL 解析设备授权页完整 URL
 * 优先使用服务端返回的 verification_uri_complete；若为相对路径则拼到 OAuth 站点根（apiBase）上
 */
func ResolveDeviceVerificationURL(apiBase string, auth *DeviceAuthResponse) string {
	if auth == nil {
		return ""
	}
	var out string
	if auth.VerificationURIComplete != "" {
		u := strings.TrimSpace(auth.VerificationURIComplete)
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			out = u
		} else {
			base := browserReachableAPIBase(apiBase)
			if strings.HasPrefix(u, "/") {
				out = base + u
			} else {
				out = base + "/" + u
			}
		}
	} else {
		uri := strings.TrimSpace(auth.VerificationURI)
		if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
			out = uri
			if auth.UserCode != "" && !strings.Contains(out, "user_code=") {
				sep := "?"
				if strings.Contains(out, "?") {
					sep = "&"
				}
				out += sep + "user_code=" + url.QueryEscape(auth.UserCode)
			}
		} else {
			base := browserReachableAPIBase(apiBase)
			if uri == "" {
				uri = "/device/"
			} else if !strings.HasPrefix(uri, "/") {
				uri = "/" + uri
			}
			if !strings.HasSuffix(uri, "/") && !strings.Contains(uri, "?") {
				uri += "/"
			}
			out = base + uri
			if auth.UserCode != "" && !strings.Contains(out, "user_code=") {
				sep := "?"
				if strings.Contains(out, "?") {
					sep = "&"
				}
				out += sep + "user_code=" + url.QueryEscape(auth.UserCode)
			}
		}
	}
	return fixUnreachableDeviceURL(out, apiBase)
}

func browserReachableAPIBase(apiBase string) string {
	return strings.TrimRight(fixUnreachableDeviceURL(strings.TrimSpace(apiBase), apiBase), "/")
}

/* fixUnreachableDeviceURL 将服务端误返回的 0.0.0.0 绑定地址改为 localhost 或 apiBase 主机 */
func fixUnreachableDeviceURL(raw, apiBase string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := strings.ToLower(u.Hostname())
	if host != "0.0.0.0" && host != "::" {
		return raw
	}
	if base, err := url.Parse(strings.TrimSpace(apiBase)); err == nil && base.Host != "" {
		h := base.Hostname()
		port := u.Port()
		if port == "" {
			port = base.Port()
		}
		if port != "" {
			u.Host = net.JoinHostPort(h, port)
		} else {
			u.Host = h
		}
		return u.String()
	}
	port := u.Port()
	if port != "" {
		u.Host = net.JoinHostPort("localhost", port)
	} else {
		u.Host = "localhost"
	}
	return u.String()
}
