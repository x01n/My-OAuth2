/*
 * SSE 事件流示例
 * 功能：演示使用 Server-Sent Events (SSE) 实时监听认证事件
 *       适用于实时监控用户登录/注册、仪表盘数据推送、审计日志
 *
 * SSE vs Webhook：
 *   SSE     — 客户端主动连接，保持长连接接收事件（拉模式）
 *   Webhook — 服务器主动推送到 HTTP 端点（推模式）
 *
 * 用法：go run main.go
 * 环境变量：
 *   OAUTH_CLIENT_ID      客户端ID
 *   OAUTH_CLIENT_SECRET  客户端密钥
 *   OAUTH_SERVER_URL     服务器地址（默认 http://localhost:8080）
 */
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"client/oauth2"
)

func main() {
	// 读取配置
	serverURL := getEnv("OAUTH_SERVER_URL", "http://localhost:8080")

	config := &oauth2.Config{
		ClientID:     getEnv("OAUTH_CLIENT_ID", "your-client-id"),
		ClientSecret: getEnv("OAUTH_CLIENT_SECRET", "your-client-secret"),
		AuthURL:      serverURL + "/oauth/authorize",
		TokenURL:     serverURL + "/oauth/token",
		UserInfoURL:  serverURL + "/oauth/userinfo",
		RedirectURL:  "http://localhost:9000/callback",
		UsePKCE:      true,
	}

	client, err := oauth2.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║       SSE 事件流 - 实时认证事件监听              ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  服务器: %s\n", serverURL)
	fmt.Printf("  应用ID: %s\n", config.ClientID)
	fmt.Println()
	fmt.Println("  监听事件类型:")
	fmt.Println("    • auth   - 用户认证（登录、注册、授权）")
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("等待事件中... (Ctrl+C 退出)")
	fmt.Println()

	// 创建可取消的 context，用于优雅关停
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 监听系统信号以优雅退出
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\n收到退出信号，正在关闭 SSE 连接...")
		cancel()
	}()

	// ========================================
	// 方式 1: 使用 ListenEvents 便捷方法（推荐）
	// ========================================
	sseClient := client.NewSSEClient()

	err = sseClient.ListenEvents(ctx, func(event oauth2.AuthEvent) {
		now := time.Now().Format("15:04:05")

		// 根据事件类型显示不同图标
		icon := "📌"
		switch event.Type {
		case "login":
			icon = "🔐"
		case "register":
			icon = "📝"
		case "authorize":
			icon = "✅"
		case "revoke":
			icon = "❌"
		case "token_refresh":
			icon = "🔄"
		}

		fmt.Printf("[%s] %s %s\n", now, icon, event.Type)
		fmt.Printf("        用户: %s (%s)\n", event.Username, event.Email)
		fmt.Printf("        应用: %s (ID: %s)\n", event.AppName, event.AppID)
		if event.Scope != "" {
			fmt.Printf("        Scope: %s\n", event.Scope)
		}
		fmt.Println()
	})

	if err != nil && err != context.Canceled {
		fmt.Printf("\n❌ SSE 连接错误: %v\n", err)
		fmt.Println("\n提示: 确保 OAuth2 服务器已启动并支持 SSE 端点")
		fmt.Println("  端点: GET /api/events/app?app_id=<your-app-id>")

		// 如果 SSE 连接失败，演示手动轮询模式作为备选
		fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("备选方案: 手动控制 SSE 连接")
		showManualExample()
	}

	fmt.Println("\n👋 SSE 监听已停止")
}

// showManualExample 展示手动控制 SSE 连接的方式
func showManualExample() {
	//nolint:govet // 原始字符串中的 % 占位符是示例代码，非 fmt 格式指令
	exampleCode := `
// 手动控制模式示例代码：

sseClient := client.NewSSEClient()

// 连接
if err := sseClient.Connect(ctx); err != nil {
    log.Fatal(err)
}
defer sseClient.Close() // 记得关闭

// 从 channel 读取事件
for {
    select {
    case event, ok := <-sseClient.Events():
        if !ok {
            return // channel 关闭
        }
        fmt.Printf("事件: %%s, 用户: %%s\n", event.Type, event.Username)
    case err := <-sseClient.Errors():
        fmt.Printf("错误: %%v\n", err)
        return
    case <-ctx.Done():
        return
    }
}
`
	fmt.Print(exampleCode)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
