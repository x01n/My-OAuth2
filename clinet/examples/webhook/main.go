/*
 * Webhook 接收示例
 * 功能：展示如何设置 Webhook 服务器接收 OAuth2 服务器推送的事件
 *       支持 HMAC-SHA256 签名验证和事件路由
 * 启动：go run main.go
 */
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"client/oauth2"
)

func main() {
	// 创建 Webhook 服务器
	// Secret 需要与 OAuth2 服务器中配置的 Webhook Secret 一致
	webhookServer := oauth2.NewWebhookServer(&oauth2.WebhookHandlerOptions{
		Secret:            "your-webhook-secret", // 替换为你的 Webhook 密钥
		ValidateTimestamp: true,                  // 验证时间戳防止重放攻击
		MaxTimeDrift:      5 * time.Minute,       // 允许的时间偏移
	})

	// 设置自定义日志
	webhookServer.SetLogger(oauth2.NewDefaultLogger())

	// ========================================
	// 注册事件处理器
	// ========================================

	// 监听用户注册事件
	webhookServer.On(oauth2.WebhookEventUserRegistered, func(payload *oauth2.WebhookPayload) error {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("📝 新用户注册!")
		fmt.Printf("   时间: %s\n", payload.Timestamp.Format(time.RFC3339))
		fmt.Printf("   应用ID: %s\n", payload.AppID)
		if userID, ok := payload.Data["user_id"].(string); ok {
			fmt.Printf("   用户ID: %s\n", userID)
		}
		if email, ok := payload.Data["email"].(string); ok {
			fmt.Printf("   邮箱: %s\n", email)
		}

		// 在这里执行你的业务逻辑
		// 例如: 发送欢迎邮件、初始化用户数据等

		return nil
	})

	// 监听用户登录事件
	webhookServer.On(oauth2.WebhookEventUserLogin, func(payload *oauth2.WebhookPayload) error {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("🔐 用户登录!")
		fmt.Printf("   时间: %s\n", payload.Timestamp.Format(time.RFC3339))
		if userID, ok := payload.Data["user_id"].(string); ok {
			fmt.Printf("   用户ID: %s\n", userID)
		}
		if loginType, ok := payload.Data["login_type"].(string); ok {
			fmt.Printf("   登录类型: %s\n", loginType)
		}

		// 在这里执行你的业务逻辑
		// 例如: 记录登录日志、更新最后登录时间等

		return nil
	})

	// 监听 OAuth 授权事件
	webhookServer.On(oauth2.WebhookEventOAuthAuthorized, func(payload *oauth2.WebhookPayload) error {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("✅ OAuth 授权!")
		fmt.Printf("   时间: %s\n", payload.Timestamp.Format(time.RFC3339))
		fmt.Printf("   应用ID: %s\n", payload.AppID)
		if userID, ok := payload.Data["user_id"].(string); ok {
			fmt.Printf("   用户ID: %s\n", userID)
		}
		if scope, ok := payload.Data["scope"].(string); ok {
			fmt.Printf("   授权范围: %s\n", scope)
		}

		return nil
	})

	// 监听 OAuth 撤销事件
	webhookServer.On(oauth2.WebhookEventOAuthRevoked, func(payload *oauth2.WebhookPayload) error {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("❌ OAuth 授权已撤销!")
		fmt.Printf("   时间: %s\n", payload.Timestamp.Format(time.RFC3339))
		if userID, ok := payload.Data["user_id"].(string); ok {
			fmt.Printf("   用户ID: %s\n", userID)
		}

		// 在这里执行你的业务逻辑
		// 例如: 清除用户会话、撤销相关权限等

		return nil
	})

	// 监听所有事件（用于日志记录或调试）
	webhookServer.OnAll(func(payload *oauth2.WebhookPayload) error {
		log.Printf("[Webhook] 收到事件: %s (App: %s)", payload.Event, payload.AppID)
		return nil
	})

	// ========================================
	// 启动 HTTP 服务器
	// ========================================

	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║     Webhook 服务器已启动               ║")
	fmt.Println("╠════════════════════════════════════════╣")
	fmt.Println("║  地址: http://localhost:9001/webhook   ║")
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("支持的事件:")
	fmt.Println("  • user.registered - 用户注册")
	fmt.Println("  • user.login      - 用户登录")
	fmt.Println("  • oauth.authorized- OAuth 授权")
	fmt.Println("  • oauth.revoked   - OAuth 撤销")
	fmt.Println()
	fmt.Println("等待事件中...")
	fmt.Println()

	// 将 webhook 服务器挂载到 /webhook 路径
	http.Handle("/webhook", webhookServer)

	// 添加健康检查端点
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// 启动服务器
	if err := http.ListenAndServe(":9001", nil); err != nil {
		log.Fatal(err)
	}
}
