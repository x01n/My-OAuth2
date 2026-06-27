/*
 * SDK 接入示例 - 跨系统账号同步
 * 功能：展示如何使用 SDK 接入模式实现跨系统账号互通
 *       通过 SyncUser 方法自动将用户同步到 OAuth2 服务器
 * 用法：go run main.go
 */
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"client/oauth2"
)

func main() {
	// 配置 OAuth2 客户端
	config := &oauth2.Config{
		ClientID:     "your-client-id",     // 从 OAuth2 管理后台获取
		ClientSecret: "your-client-secret", // 从 OAuth2 管理后台获取
		AuthURL:      "http://localhost:3000/oauth/authorize",
		TokenURL:     "http://localhost:8080/oauth/token",
		UserInfoURL:  "http://localhost:8080/oauth/userinfo",
		RedirectURL:  "http://localhost:9000/callback",
	}

	client, err := oauth2.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// 设置日志级别
	client.SetLogger(oauth2.NewDefaultLogger())

	ctx := context.Background()

	// ========================================
	// 示例 1: 用户同步 (推荐)
	// ========================================
	fmt.Println("=== 用户同步示例 ===")

	syncResp, err := client.SyncUser(ctx, &oauth2.SyncUserRequest{
		Email:         "demo@example.com",
		Username:      "demo_user",
		GivenName:     "Demo",
		FamilyName:    "User",
		EmailVerified: true,
	})
	if err != nil {
		log.Printf("同步失败: %v", err)
	} else {
		if syncResp.Action == "created" {
			fmt.Println("✅ 新用户已创建")
		} else {
			fmt.Println("✅ 用户资料已更新")
		}
		fmt.Printf("   用户ID: %s\n", syncResp.User.ID)
		fmt.Printf("   邮箱: %s\n", syncResp.User.Email)
		fmt.Printf("   用户名: %s\n", syncResp.User.Username)
	}

	// ========================================
	// 示例 2: 直接注册用户
	// ========================================
	fmt.Println("\n=== 注册用户示例 ===")

	registerResp, err := client.RegisterUser(ctx, &oauth2.SDKRegisterRequest{
		Email:    fmt.Sprintf("user_%d@example.com", time.Now().Unix()),
		Username: fmt.Sprintf("user_%d", time.Now().Unix()),
		Password: "secure_password_123",
	})
	if err != nil {
		log.Printf("注册失败: %v", err)
	} else {
		fmt.Printf("✅ 用户注册成功\n")
		fmt.Printf("   用户ID: %s\n", registerResp.User.ID)
		fmt.Printf("   邮箱: %s\n", registerResp.User.Email)
		fmt.Printf("   Access Token: %s\n", maskToken(registerResp.AccessToken))
		fmt.Printf("   Refresh Token: %s\n", maskToken(registerResp.RefreshToken))
		fmt.Printf("   ID Token: %s\n", maskToken(registerResp.IDToken))
	}

	// ========================================
	// 示例 3: 刷新 SDK 用户 Token
	// ========================================
	fmt.Println("\n=== 刷新 SDK 用户 Token 示例 ===")

	var tokenForValidation string
	if registerResp != nil {
		refreshResp, err := client.RefreshSDKUserToken(ctx)
		if err != nil {
			log.Printf("Token 刷新失败: %v", err)
			tokenForValidation = registerResp.AccessToken
		} else {
			fmt.Printf("✅ Token 刷新成功\n")
			fmt.Printf("   Access Token: %s\n", maskToken(refreshResp.AccessToken))
			fmt.Printf("   Refresh Token: %s\n", maskToken(refreshResp.RefreshToken))
			fmt.Printf("   ID Token: %s\n", maskToken(refreshResp.IDToken))
			tokenForValidation = refreshResp.AccessToken
		}
	}

	// ========================================
	// 示例 4: 获取有效 SDK 用户 Token
	// ========================================
	fmt.Println("\n=== 获取有效 SDK 用户 Token 示例 ===")

	ensuredToken, err := client.EnsureSDKUserToken(ctx)
	if err != nil {
		log.Printf("获取有效 Token 失败: %v", err)
	} else {
		fmt.Printf("✅ 当前 Token 可用\n")
		fmt.Printf("   Access Token: %s\n", maskToken(ensuredToken.AccessToken))
		fmt.Printf("   Refresh Token: %s\n", maskToken(ensuredToken.RefreshToken))
		fmt.Printf("   ID Token: %s\n", maskToken(ensuredToken.IDToken))
		tokenForValidation = ensuredToken.AccessToken
	}

	// ========================================
	// 示例 5: 验证 Token (使用有效 token)
	// ========================================
	fmt.Println("\n=== 验证 Token 示例 ===")

	if tokenForValidation != "" {
		userInfo, err := client.ValidateUserToken(ctx, tokenForValidation)
		if err != nil {
			log.Printf("Token 验证失败: %v", err)
		} else {
			fmt.Printf("✅ Token 有效\n")
			fmt.Printf("   用户: %s (%s)\n", userInfo.PreferredUsername, userInfo.Email)
		}
	}

	// ========================================
	// 示例 6: 启动 HTTP 服务器处理用户同步
	// ========================================
	fmt.Println("\n=== 启动 HTTP 服务器 ===")
	fmt.Println("服务器运行在 http://localhost:9002")
	fmt.Println("POST /sync - 同步用户")
	fmt.Println("POST /validate - 验证 Token")

	http.HandleFunc("/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		email := r.FormValue("email")
		username := r.FormValue("username")

		resp, err := client.SyncUser(r.Context(), &oauth2.SyncUserRequest{
			Email:    email,
			Username: username,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, "User synced: %s (action: %s)\nUser ID: %s",
			resp.User.Email, resp.Action, resp.User.ID)
	})

	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		userInfo, err := client.ValidateUserToken(r.Context(), token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "Valid token for user: %s (%s)", userInfo.PreferredUsername, userInfo.Email)
	})

	log.Fatal(http.ListenAndServe(":9002", nil))
}

func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 16 {
		return token
	}
	return token[:16] + "..."
}
