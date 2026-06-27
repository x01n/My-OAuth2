/*
 * Device Flow 示例 (RFC 8628)
 * 功能：演示设备授权流程，适用于智能电视、CLI 工具、IoT 设备等输入受限场景
 * 用法：go run main.go           (交互式，带回调)
 *       go run main.go --simple  (简单模式，阻塞等待)
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
	"os/exec"
	"runtime"
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
	defer client.Close()

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║         Device Flow 设备授权示例                 ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")

	// 判断使用哪种模式
	if len(os.Args) > 1 && os.Args[1] == "--simple" {
		runSimpleDeviceFlow(client)
	} else {
		runCallbackDeviceFlow(client)
	}
}

// runCallbackDeviceFlow 使用回调函数的设备流（推荐）
// 通过回调实时感知授权状态变化
func runCallbackDeviceFlow(client *oauth2.Client) {
	fmt.Println("\n📱 模式: 回调式设备流")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	token, err := client.DeviceFlowWithCallback(ctx, "openid profile email", func(status string, data interface{}) {
		switch status {
		case "device_code":
			// 收到设备码，展示给用户
			if auth, ok := data.(*oauth2.DeviceAuthResponse); ok {
				fmt.Println()
				fmt.Println("┌─────────────────────────────────────────────┐")
				visitURL := oauth2.ResolveDeviceVerificationURL(client.GetAPIBaseURL(), auth)
				fmt.Printf("│  请访问 OAuth 站点: %-26s │\n", truncate(visitURL, 26))
				fmt.Printf("│  验证码: %-34s │\n", auth.UserCode)
				fmt.Println("├─────────────────────────────────────────────┤")
				fmt.Printf("│  完整链接: %-34s │\n", truncate(visitURL, 34))
				fmt.Printf("│  有效期: %d 秒%-30s │\n", auth.ExpiresIn, "")
				fmt.Println("└─────────────────────────────────────────────┘")
				fmt.Println("\n⏳ 等待用户授权...")

				// 尝试自动打开浏览器
				if visitURL != "" {
					openBrowser(visitURL)
				}
			}
		case "pending":
			fmt.Print(".")
		case "polling":
			// 静默轮询
		case "slow_down":
			fmt.Println("\n  [降低轮询频率]")
		case "denied":
			fmt.Println("\n\n❌ 用户拒绝了授权")
		case "expired":
			fmt.Println("\n\n❌ 验证码已过期，请重新开始")
		case "authorized":
			fmt.Println("\n\n✅ 授权成功!")
		}
	})

	if err != nil {
		fmt.Printf("\n错误: %v\n", err)
		return
	}

	printTokenInfo(token)

	// 获取用户信息
	printUserInfo(client)
}

// runSimpleDeviceFlow 简单模式：使用内置的 DeviceFlow 方法
// 方法内部会自动打印提示并轮询，直到完成
func runSimpleDeviceFlow(client *oauth2.Client) {
	fmt.Println("\n📱 模式: 简单设备流")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	token, err := client.DeviceFlow(ctx, "openid profile email")
	if err != nil {
		fmt.Printf("\n错误: %v\n", err)
		return
	}

	fmt.Println("\n✅ 授权成功!")
	printTokenInfo(token)
	printUserInfo(client)
}

// ========== 辅助函数 ==========

func printTokenInfo(token *oauth2.Token) {
	fmt.Println("\n┌─────────────────────────────────────────────┐")
	fmt.Println("│               Token 信息                    │")
	fmt.Println("├─────────────────────────────────────────────┤")
	fmt.Printf("│ Access Token:  %s...%s │\n",
		token.AccessToken[:min(16, len(token.AccessToken))],
		pad(28-min(16, len(token.AccessToken))))
	fmt.Printf("│ Token Type:    %-28s │\n", token.TokenType)
	fmt.Printf("│ 过期时间:      %-28s │\n", token.Expiry.Format("2006-01-02 15:04:05"))
	if token.RefreshToken != "" {
		fmt.Printf("│ Refresh Token: %s...%s │\n",
			token.RefreshToken[:min(16, len(token.RefreshToken))],
			pad(28-min(16, len(token.RefreshToken))))
	}
	fmt.Println("└─────────────────────────────────────────────┘")
}

func printUserInfo(client *oauth2.Client) {
	fmt.Println("\n获取用户信息...")
	userInfo, err := client.GetUserInfo(context.Background())
	if err != nil {
		fmt.Printf("❌ 获取失败: %v\n", err)
		return
	}

	fmt.Println("┌─────────────────────────────────────────────┐")
	fmt.Println("│               用户信息                      │")
	fmt.Println("├─────────────────────────────────────────────┤")
	fmt.Printf("│ ID:      %-33s │\n", truncate(userInfo.Sub, 33))
	fmt.Printf("│ 用户名:  %-33s │\n", truncate(userInfo.PreferredUsername, 33))
	fmt.Printf("│ 邮箱:    %-33s │\n", truncate(userInfo.Email, 33))
	fmt.Printf("│ 名称:    %-33s │\n", truncate(userInfo.Name, 33))
	fmt.Println("└─────────────────────────────────────────────┘")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func pad(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return
	}
	cmd.Start()
}
