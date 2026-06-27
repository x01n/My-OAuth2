/*
 * SSO 接入示例 - 业务系统接入本平台统一认证
 * 功能：演示其他平台如何像接入 OAuth2/OIDC Provider 一样接入本平台
 *       - OIDC Discovery 自动发现端点
 *       - Authorization Code + PKCE 登录流程
 *       - 回调后建立业务系统自己的 HttpOnly 会话
 *       - Bearer Token API 保护路由
 * 用法：
 *   OAUTH_CLIENT_ID=your-client-id OAUTH_CLIENT_SECRET=your-client-secret go run main.go
 *
 * 环境变量：
 *   OAUTH_CLIENT_ID      管理后台创建的应用 Client ID
 *   OAUTH_CLIENT_SECRET  管理后台创建的应用 Client Secret
 *   OAUTH_ISSUER_URL     本平台认证中心地址（默认 http://localhost:8080）
 *   APP_BASE_URL         当前业务系统地址（默认 http://localhost:9004）
 *   APP_LISTEN_ADDR      当前业务系统监听地址（默认 :9004）
 *   SESSION_COOKIE_NAME  当前业务系统会话 Cookie 名称（默认 sso_demo_session）
 */
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"client/oauth2"
)

type appSession struct {
	AccessToken string
	UserInfo    *oauth2.UserInfo
	CreatedAt   time.Time
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*appSession
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*appSession)}
}

func (s *sessionStore) create(session *appSession) (string, error) {
	sessionID, err := randomURLSafe(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()
	return sessionID, nil
}

func (s *sessionStore) get(sessionID string) (*appSession, bool) {
	s.mu.RLock()
	session, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	return session, ok
}

func (s *sessionStore) delete(sessionID string) {
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
}

func main() {
	ctx := context.Background()

	issuerURL := getEnv("OAUTH_ISSUER_URL", "http://localhost:8080")
	appBaseURL := strings.TrimRight(getEnv("APP_BASE_URL", "http://localhost:9004"), "/")
	listenAddr := getEnv("APP_LISTEN_ADDR", ":9004")
	cookieName := getEnv("SESSION_COOKIE_NAME", "sso_demo_session")
	redirectURL := appBaseURL + "/callback"

	config, err := oauth2.DiscoverSSOConfig(
		ctx,
		getEnv("OAUTH_CLIENT_ID", "your-client-id"),
		getEnv("OAUTH_CLIENT_SECRET", "your-client-secret"),
		issuerURL,
		redirectURL,
	)
	if err != nil {
		log.Printf("OIDC Discovery failed, using static SSO config: %v", err)
		config = oauth2.SSOConfig(
			getEnv("OAUTH_CLIENT_ID", "your-client-id"),
			getEnv("OAUTH_CLIENT_SECRET", "your-client-secret"),
			issuerURL,
			redirectURL,
		)
	}

	client, err := oauth2.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	sessions := newSessionStore()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, ok := currentSession(r, sessions, cookieName)
		if ok {
			writeHTML(w, http.StatusOK, fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>SSO Demo</title></head>
<body>
<h1>SSO Demo</h1>
<p>已通过本平台统一认证登录。</p>
<ul>
<li>User ID: %s</li>
<li>Email: %s</li>
<li>Name: %s</li>
</ul>
<p><a href="/me">查看当前会话 JSON</a></p>
<p><a href="/logout">退出业务系统会话</a></p>
</body></html>`,
				html.EscapeString(session.UserInfo.Sub),
				html.EscapeString(session.UserInfo.Email),
				html.EscapeString(session.UserInfo.Name),
			))
			return
		}

		writeHTML(w, http.StatusOK, `<!doctype html>
<html><head><meta charset="utf-8"><title>SSO Demo</title></head>
<body>
<h1>SSO Demo</h1>
<p>当前业务系统未登录。</p>
<p><a href="/login">使用本平台统一登录</a></p>
</body></html>`)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		authURL, err := client.AuthCodeURL()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		result, err := client.HandleCallback(r.Context(), oauth2.CallbackRequestFromHTTPRequest(r))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		if result.UserInfo == nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Errorf("userinfo response is empty"))
			return
		}

		sessionID, err := sessions.create(&appSession{
			AccessToken: result.Token.AccessToken,
			UserInfo:    result.UserInfo,
			CreatedAt:   time.Now(),
		})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   3600,
			Secure:   strings.HasPrefix(appBaseURL, "https://"),
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		session, ok := currentSession(r, sessions, cookieName)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"user":       session.UserInfo,
			"created_at": session.CreatedAt,
		})
	})

	mux.Handle("/api/profile", client.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := oauth2.UserInfoFromContext(r.Context())
		if userInfo == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id":       userInfo.Sub,
			"email":    userInfo.Email,
			"name":     userInfo.Name,
			"username": userInfo.PreferredUsername,
		})
	})))

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(cookieName); err == nil {
			sessions.delete(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Secure:   strings.HasPrefix(appBaseURL, "https://"),
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	fmt.Println("SSO demo business app")
	fmt.Printf("Issuer:       %s\n", issuerURL)
	fmt.Printf("App URL:      %s\n", appBaseURL)
	fmt.Printf("Redirect URI: %s\n", redirectURL)
	fmt.Printf("Listen:       %s\n", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func currentSession(r *http.Request, sessions *sessionStore, cookieName string) (*appSession, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	return sessions.get(cookie.Value)
}

func randomURLSafe(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
