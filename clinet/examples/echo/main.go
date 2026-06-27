/*
 * Echo 框架集成示例
 * 功能：演示 Echo 框架集成 OAuth2 认证
 *       - Authorization Code + PKCE 登录流程
 *       - Echo 中间件保护 API 路由（基础 & 高级选项）
 *       - 跳过路径、允许匿名访问、Scope 检查
 * 启动：go run main.go
 * 访问：http://localhost:9003
 */
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"client/oauth2"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	// ========================================
	// 1. 配置 OAuth2 客户端
	// ========================================
	config := &oauth2.Config{
		ClientID:     "your-client-id",     // 替换为你的 Client ID
		ClientSecret: "your-client-secret", // 替换为你的 Client Secret
		AuthURL:      "http://localhost:3000/oauth/authorize",
		TokenURL:     "http://localhost:8080/oauth/token",
		UserInfoURL:  "http://localhost:8080/oauth/userinfo",
		RedirectURL:  "http://localhost:9003/callback",
		Scopes:       []string{"openid", "profile", "email"},
		UsePKCE:      true,
	}

	client, err := oauth2.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// ========================================
	// 2. 设置 Echo 路由
	// ========================================
	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// ---------- 公开路由 ----------

	// 首页
	e.GET("/", func(c echo.Context) error {
		token, _ := client.GetToken(context.Background())
		isLoggedIn := token != nil && token.IsValid()

		html := `<!DOCTYPE html>
<html><head><title>OAuth2 Echo 示例</title>
<style>body{font-family:system-ui;max-width:600px;margin:40px auto;padding:0 20px}
.btn{display:inline-block;padding:10px 20px;border-radius:8px;text-decoration:none;color:white;margin:4px}
.btn-blue{background:#3b82f6}.btn-red{background:#ef4444}.btn-green{background:#22c55e}
.card{background:#f8fafc;border-radius:12px;padding:24px;margin:16px 0}
code{background:#f1f5f9;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>🔐 OAuth2 Echo 示例</h1>`

		if isLoggedIn {
			html += `<div class="card"><p style="color:#22c55e">✓ 已登录</p>
<a href="/api/profile" class="btn btn-green">个人信息</a>
<a href="/api/data" class="btn btn-blue">受保护数据</a>
<a href="/public/info" class="btn btn-blue">公开接口</a>
<a href="/logout" class="btn btn-red">退出</a></div>`
		} else {
			html += `<div class="card"><p>点击下方按钮通过 OAuth2 授权登录</p>
<a href="/login" class="btn btn-blue">使用 OAuth2 登录</a>
<a href="/public/info" class="btn btn-green">访问公开接口</a></div>`
		}

		html += `<div class="card"><h3>中间件演示</h3>
<p><code>/api/*</code> - 需要 Bearer Token 认证</p>
<p><code>/public/*</code> - 允许匿名访问（有 Token 会解析用户信息）</p>
<p><code>/health</code> - 跳过认证</p></div></body></html>`

		return c.HTML(http.StatusOK, html)
	})

	// 登录：重定向到 OAuth2 授权页
	e.GET("/login", func(c echo.Context) error {
		authURL, err := client.AuthCodeURL()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.Redirect(http.StatusFound, authURL)
	})

	// OAuth2 回调
	e.GET("/callback", func(c echo.Context) error {
		code := c.QueryParam("code")
		state := c.QueryParam("state")

		if errParam := c.QueryParam("error"); errParam != "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":       errParam,
				"description": c.QueryParam("error_description"),
			})
		}

		if code == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "missing code"})
		}

		_, err := client.Exchange(c.Request().Context(), code, state)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		return c.Redirect(http.StatusFound, "/")
	})

	// 退出
	e.GET("/logout", func(c echo.Context) error {
		client.Logout()
		return c.Redirect(http.StatusFound, "/")
	})

	// ========================================
	// 3. 受保护的 API 路由（严格认证）
	// ========================================
	api := e.Group("/api")
	api.Use(client.EchoMiddleware()) // 基础中间件，必须携带有效 Token
	{
		api.GET("/profile", func(c echo.Context) error {
			userInfo := oauth2.EchoGetUserInfo(c)
			if userInfo == nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "no user info"})
			}
			return c.JSON(http.StatusOK, map[string]interface{}{
				"id":       userInfo.Sub,
				"email":    userInfo.Email,
				"name":     userInfo.Name,
				"username": userInfo.PreferredUsername,
			})
		})

		api.GET("/data", func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"message":    "这是受保护的数据",
				"user_id":    oauth2.EchoGetUserID(c),
				"user_email": oauth2.EchoGetUserEmail(c),
			})
		})
	}

	// ========================================
	// 4. 带高级选项的路由（允许匿名、跳过路径）
	// ========================================
	public := e.Group("/public")
	public.Use(client.EchoMiddlewareWithOptions(oauth2.EchoMiddlewareOptions{
		AllowAnonymous: true,                // 无 Token 也可访问
		SkipPaths:      []string{"/health"}, // 跳过健康检查
	}))
	{
		public.GET("/info", func(c echo.Context) error {
			userID := oauth2.EchoGetUserID(c)
			if userID != "" {
				return c.JSON(http.StatusOK, map[string]interface{}{
					"message":    "你好，已认证用户！",
					"user_id":    userID,
					"user_email": oauth2.EchoGetUserEmail(c),
				})
			}
			return c.JSON(http.StatusOK, map[string]interface{}{
				"message": "你好，匿名用户！登录后可查看更多信息。",
			})
		})
	}

	// 健康检查（不需要认证）
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	// ========================================
	// 5. 启动服务器
	// ========================================
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║   Echo OAuth2 示例                     ║")
	fmt.Println("║   http://localhost:9003                 ║")
	fmt.Println("╚════════════════════════════════════════╝")
	e.Logger.Fatal(e.Start(":9003"))
}
