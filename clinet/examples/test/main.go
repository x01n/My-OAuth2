/*
 * OAuth2 SDK 综合测试示例
 * 功能：提供完整的 OAuth2 授权流程测试，包括 Web UI 和 CLI 两种模式
 *       支持 Authorization Code (PKCE)、Webhook 接收、用户信息获取等
 * 用法：go run main.go       (Web UI 模式)
 *       go run main.go cli  (CLI 交互模式)
 */
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"client/oauth2"
)

var client *oauth2.Client
const defaultOAuthServerURL = "http://localhost:28080"
const testRedirectURL = "http://localhost:9000/callback"

var serverURL = defaultOAuthServerURL
var clientID = ""
var clientSecret = ""

/* buildTestOAuthConfig 与 Web 授权页 /login 流程一致：浏览器打开 OAuth 站点授权 + 必要时在 Web 登录 */
func buildTestOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  testRedirectURL,
		Scopes:       []string{"openid", "profile", "email", "phone", "address"},
		AuthURL:      serverURL + "/oauth/authorize",
		TokenURL:     serverURL + "/oauth/token",
		UserInfoURL:  serverURL + "/oauth/userinfo",
		UsePKCE:      true,
	}
}

// 存储收到的webhook
var webhookLogs = make([]WebhookLog, 0)
var webhookMutex sync.Mutex

type WebhookLog struct {
	Time    time.Time              `json:"time"`
	Headers map[string]string      `json:"headers"`
	Body    map[string]interface{} `json:"body"`
	Raw     string                 `json:"raw"`
}

func main() {
	// 检查命令行参数
	if len(os.Args) > 1 {
		runCLI()
		return
	}

	// 配置 OAuth2 客户端 - 替换为你的实际值
	clientID = getEnvOrDefault("OAUTH_CLIENT_ID", "db84c0d44df5b5a611d0e498c769023c")
	clientSecret = getEnvOrDefault("OAUTH_CLIENT_SECRET", "5ffb4224b5de948c0a38d3459b4e600635c9356c8a09cbd000c949543c1def2c")
	serverURL = getEnvOrDefault("OAUTH_SERVER_URL", defaultOAuthServerURL)

	var err error
	client, err = oauth2.NewClient(buildTestOAuthConfig())
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// 路由
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/userinfo", handleUserInfo)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/refresh", handleRefresh)
	http.HandleFunc("/oidc", handleOIDC)
	http.HandleFunc("/introspect", handleIntrospect)
	http.HandleFunc("/webhook-test", handleWebhookTest)
	http.HandleFunc("/token-info", handleTokenInfo)
	http.HandleFunc("/oidc-test", handleOIDCTest)
	// 新增功能
	http.HandleFunc("/device", handleDeviceFlow)
	http.HandleFunc("/client-credentials", handleClientCredentials)
	http.HandleFunc("/token-exchange", handleTokenExchange)

	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║           OAuth2/OIDC 综合测试客户端                     ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║  Web界面: http://localhost:9000                          ║")
	fmt.Println("║                                                          ║")
	fmt.Println("║  授权流程:                                               ║")
	fmt.Println("║  - /login              跳转 OAuth Web 授权页(需 Web 登录)   ║")
	fmt.Println("║  - /device             Device Flow (设备流)              ║")
	fmt.Println("║  - /client-credentials Client Credentials (机器认证)    ║")
	fmt.Println("║  - /token-exchange     Token Exchange (令牌交换)         ║")
	fmt.Println("║                                                          ║")
	fmt.Println("║  Token管理:                                              ║")
	fmt.Println("║  - /userinfo           查看用户信息                      ║")
	fmt.Println("║  - /token-info         当前Token详情                     ║")
	fmt.Println("║  - /refresh            刷新Token                         ║")
	fmt.Println("║  - /introspect         Token自省                         ║")
	fmt.Println("║  - /logout             退出登录                          ║")
	fmt.Println("║                                                          ║")
	fmt.Println("║  其他:                                                   ║")
	fmt.Println("║  - /oidc-test          OIDC 综合测试                     ║")
	fmt.Println("║  - /oidc               OIDC发现文档                      ║")
	fmt.Println("║  - /webhook-test       Webhook测试                       ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║  CLI模式: ./test [命令]                                  ║")
	fmt.Println("║  命令: device | login | client-creds | exchange | help   ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	log.Fatal(http.ListenAndServe(":9000", nil))
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

/* printTokenBox 打印 OAuth 三类令牌摘要 */
func printTokenBox(token *oauth2.Token) {
	if token == nil {
		return
	}
	fmt.Println("\n┌─────────────────────────────────────────────────┐")
	fmt.Println("│               Token 信息                        │")
	fmt.Println("├─────────────────────────────────────────────────┤")
	if token.AccessToken != "" {
		fmt.Printf("│ access_token:  %s...%-10s │\n", token.AccessToken[:min(20, len(token.AccessToken))], "")
	}
	if token.RefreshToken != "" {
		fmt.Printf("│ refresh_token: %s...%-10s │\n", token.RefreshToken[:min(20, len(token.RefreshToken))], "")
	}
	if token.IDToken != "" {
		fmt.Printf("│ id_token:      %s...%-10s │\n", token.IDToken[:min(20, len(token.IDToken))], "")
	}
	fmt.Printf("│ Token Type:   %-33s │\n", token.TokenType)
	if !token.Expiry.IsZero() {
		fmt.Printf("│ 过期时间:     %-33s │\n", token.Expiry.Format("2006-01-02 15:04:05"))
	}
	fmt.Println("└─────────────────────────────────────────────────┘")
}

func oauthClientCredentialsHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "invalid_scope"):
		return "应用未配置机器 scope（allowed_scopes）。请在 Dashboard 为应用添加 api.read，或 scope 留空仅获取客户端身份令牌。"
	case strings.Contains(msg, "invalid_grant"):
		return "请确认应用已启用 client_credentials，且为 confidential/machine 类型。"
	case strings.Contains(msg, "invalid_client"):
		return "请检查 OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET 是否与 Dashboard 一致。"
	default:
		return "机器认证不能使用 openid/profile 等用户 scope。"
	}
}

// ============================================================================
// CLI Mode - 命令行模式
// ============================================================================

func runCLI() {
	clientID = getEnvOrDefault("OAUTH_CLIENT_ID", "70e2c01bc1c780287047594ec1967279")
	clientSecret = getEnvOrDefault("OAUTH_CLIENT_SECRET", "f6abbeec2e27f9d13c93473cbc84bde1bdf34be6eeb321708ce62f27a259f534")
	serverURL = getEnvOrDefault("OAUTH_SERVER_URL", defaultOAuthServerURL)

	var err error
	client, err = oauth2.NewClient(buildTestOAuthConfig())
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	cmd := os.Args[1]
	switch cmd {
	case "device":
		cliDeviceFlow()
	case "login":
		cliAuthCodeFlow()
	case "client-creds":
		cliClientCredentials()
	case "exchange":
		cliTokenExchange()
	case "userinfo":
		cliUserInfo()
	case "test-all":
		cliTestAll()
	case "help":
		printCLIHelp()
	default:
		fmt.Printf("未知命令: %s\n", cmd)
		printCLIHelp()
	}
}

func printCLIHelp() {
	fmt.Print(`
OAuth2 CLI 测试工具

用法: ./test [命令]

命令:
  device        使用设备流登录 (适合无浏览器环境)
  login         使用授权码流登录 (自动启动本地服务器接收回调)
  client-creds  使用客户端凭据获取Token (机器对机器)
  exchange      Token交换 (需要先有token)
  userinfo      获取当前用户信息
  test-all      运行所有测试
  help          显示帮助

环境变量:
  OAUTH_CLIENT_ID      客户端ID
  OAUTH_CLIENT_SECRET  客户端密钥
  OAUTH_SERVER_URL     OAuth服务器地址 (默认: http://localhost:28080)

示例:
  ./test device                    # 设备流登录
  ./test login                     # 浏览器授权码流程
  ./test client-creds              # 客户端凭据
  OAUTH_SERVER_URL=https://auth.example.com ./test device
`)
}

// cliDeviceFlow - 设备流CLI模式
func cliDeviceFlow() {
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║           Device Flow - 设备流登录               ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")

	ctx := context.Background()

	// 启动设备流
	token, err := client.DeviceFlowWithCallback(ctx, "openid profile email", func(status string, data interface{}) {
		switch status {
		case "device_code":
			if deviceAuth, ok := data.(*oauth2.DeviceAuthResponse); ok {
				visitURL := oauth2.ResolveDeviceVerificationURL(serverURL, deviceAuth)
				fmt.Println("\n┌─────────────────────────────────────────────────┐")
				fmt.Printf("│  请访问: %-38s │\n", truncateStr(visitURL, 38))
				fmt.Printf("│  输入验证码: %-34s │\n", deviceAuth.UserCode)
				fmt.Printf("│  有效期: %-37d秒 │\n", deviceAuth.ExpiresIn)
				fmt.Println("└─────────────────────────────────────────────────┘")
				fmt.Println("\n等待授权中...")

				if visitURL != "" {
					openBrowser(visitURL)
				}
			}
		case "pending":
			fmt.Print(".")
		case "polling":
			// 静默
		case "slow_down":
			fmt.Println("\n[服务器要求降低轮询频率]")
		case "denied":
			fmt.Println("\n\n✗ 授权被拒绝")
		case "expired":
			fmt.Println("\n\n✗ 验证码已过期")
		case "authorized":
			fmt.Println("\n\n✓ 授权成功!")
		}
	})

	if err != nil {
		fmt.Printf("\n错误: %v\n", err)
		return
	}

	printTokenBox(token)

	// 获取用户信息
	cliUserInfo()
}

// cliAuthCodeFlow - 授权码流CLI模式
func cliAuthCodeFlow() {
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║       Authorization Code Flow - 授权码流程       ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")

	// 获取授权URL
	authURL, err := client.AuthCodeURL()
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}

	fmt.Println("\n请在浏览器中打开以下链接进行授权:")
	fmt.Printf("\n  %s\n\n", authURL)

	// 尝试打开浏览器
	openBrowser(authURL)

	// 启动本地服务器等待回调
	fmt.Println("启动本地服务器等待回调 (http://localhost:9000/callback)...")
	fmt.Println("授权完成后会自动获取Token")

	// 创建一个channel等待回调
	tokenChan := make(chan *oauth2.Token, 1)
	errChan := make(chan error, 1)

	// 临时服务器
	server := &http.Server{Addr: ":9000"}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" {
			errChan <- fmt.Errorf("授权失败: %s", r.URL.Query().Get("error"))
			w.Write([]byte("授权失败,请查看终端"))
			return
		}

		token, err := client.Exchange(context.Background(), code, state)
		if err != nil {
			errChan <- err
			w.Write([]byte("Token交换失败,请查看终端"))
			return
		}

		tokenChan <- token
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`
			<html><body style="font-family:system-ui;text-align:center;padding:50px">
			<h1 style="color:#22c55e">✓ 授权成功!</h1>
			<p>您可以关闭此窗口并返回终端</p>
			</body></html>
		`))
	})

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// 等待结果
	select {
	case token := <-tokenChan:
		server.Shutdown(context.Background())
		fmt.Println("\n✓ 授权成功!")
		printTokenBox(token)
		cliUserInfo()

	case err := <-errChan:
		server.Shutdown(context.Background())
		fmt.Printf("\n✗ 错误: %v\n", err)

	case <-time.After(5 * time.Minute):
		server.Shutdown(context.Background())
		fmt.Println("\n✗ 超时: 5分钟内未完成授权")
	}
}

// cliClientCredentials - 客户端凭据CLI模式
func cliClientCredentials() {
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║       Client Credentials - 客户端凭据模式        ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")

	ctx := context.Background()
	resp, err := client.ClientCredentials(ctx, &oauth2.ClientCredentialsRequest{
		Scope: "api.read",
	})

	if err != nil {
		fmt.Printf("\n✗ 错误: %v\n", err)
		fmt.Println("  提示: client_credentials 不能使用 openid/profile 等用户 scope，请在应用里配置 api.read 等机器 scope。")
		return
	}

	fmt.Println("\n✓ 获取Token成功!")
	fmt.Println("  说明: 机器令牌不会写入登录会话，不能用于 Token Exchange / UserInfo。")
	fmt.Println("\n┌─────────────────────────────────────────────────┐")
	fmt.Println("│           Client Credentials Token              │")
	fmt.Println("├─────────────────────────────────────────────────┤")
	fmt.Printf("│ Access Token: %s...%-10s │\n", resp.AccessToken[:min(20, len(resp.AccessToken))], "")
	fmt.Printf("│ Token Type:   %-33s │\n", resp.TokenType)
	fmt.Printf("│ Expires In:   %-33d │\n", resp.ExpiresIn)
	fmt.Printf("│ Scope:        %-33s │\n", resp.Scope)
	fmt.Println("└─────────────────────────────────────────────────┘")
}

// cliTokenExchange - Token交换CLI模式
func cliTokenExchange() {
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║          Token Exchange - 令牌交换               ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")

	token, err := client.GetToken(context.Background())
	if err != nil || token == nil || token.RefreshToken == "" {
		fmt.Println("\n✗ 需要用户委托令牌（含 refresh_token）作为 subject_token。")
		fmt.Println("  请先执行: login / device / auth，再执行 token-exchange。")
		fmt.Println("  client_credentials 机器令牌不能用于令牌交换（服务端返回 invalid_grant）。")
		return
	}

	// 执行Token Exchange
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", token.AccessToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "openid profile")

	resp, err := http.PostForm(serverURL+"/oauth/token", data)
	if err != nil {
		fmt.Printf("\n✗ 请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("\n✗ Token Exchange 失败 (HTTP %d):\n%s\n", resp.StatusCode, string(body))
		return
	}

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	fmt.Println("\n✓ Token Exchange 成功!")
	fmt.Println("\n┌─────────────────────────────────────────────────┐")
	fmt.Println("│           Exchange Response                     │")
	fmt.Println("├─────────────────────────────────────────────────┤")
	prettyJSON, _ := json.MarshalIndent(result, "", "  ")
	for _, line := range strings.Split(string(prettyJSON), "\n") {
		fmt.Printf("│ %-47s │\n", truncateStr(line, 47))
	}
	fmt.Println("└─────────────────────────────────────────────────┘")
}

// cliUserInfo - 获取用户信息
func cliUserInfo() {
	fmt.Println("\n获取用户信息...")

	userInfo, err := client.GetUserInfo(context.Background())
	if err != nil {
		fmt.Printf("✗ 获取用户信息失败: %v\n", err)
		return
	}

	fmt.Println("\n┌─────────────────────────────────────────────────┐")
	fmt.Println("│               用户信息                          │")
	fmt.Println("├─────────────────────────────────────────────────┤")
	fmt.Printf("│ Sub:      %-37s │\n", truncateStr(userInfo.Sub, 37))
	fmt.Printf("│ 用户名:   %-37s │\n", truncateStr(userInfo.PreferredUsername, 37))
	fmt.Printf("│ 邮箱:     %-37s │\n", truncateStr(userInfo.Email, 37))
	fmt.Printf("│ 名称:     %-37s │\n", truncateStr(userInfo.Name, 37))
	fmt.Println("└─────────────────────────────────────────────────┘")
}

// cliTestAll - 运行所有测试
func cliTestAll() {
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║           OAuth2 全功能测试                      ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")

	passed := 0
	failed := 0

	// 1. 测试OIDC发现
	fmt.Print("\n[1/5] OIDC Discovery... ")
	resp, err := http.Get(serverURL + "/.well-known/openid-configuration")
	if err == nil && resp.StatusCode == 200 {
		fmt.Println("✓ PASS")
		passed++
	} else {
		fmt.Println("✗ FAIL")
		failed++
	}

	// 2. 测试JWKS
	fmt.Print("[2/5] JWKS Endpoint... ")
	resp, err = http.Get(serverURL + "/.well-known/jwks.json")
	if err == nil && resp.StatusCode == 200 {
		fmt.Println("✓ PASS")
		passed++
	} else {
		fmt.Println("✗ FAIL")
		failed++
	}

	// 3. 测试Client Credentials
	fmt.Print("[3/5] Client Credentials... ")
	ccResp, err := client.ClientCredentials(context.Background(), &oauth2.ClientCredentialsRequest{
		Scope: "api.read",
	})
	if err == nil && ccResp.AccessToken != "" {
		fmt.Println("✓ PASS")
		passed++
	} else {
		fmt.Printf("✗ FAIL (%v)\n", err)
		failed++
	}

	// 4. 测试Device Flow初始化
	fmt.Print("[4/5] Device Flow Init... ")
	deviceResp, err := client.DeviceAuthorization(context.Background(), "openid profile")
	if err == nil && deviceResp.UserCode != "" {
		fmt.Printf("✓ PASS (user_code: %s)\n", deviceResp.UserCode)
		passed++
	} else {
		fmt.Printf("✗ FAIL (%v)\n", err)
		failed++
	}

	// 5. 测试Token Introspection
	fmt.Print("[5/5] Token Introspection... ")
	if ccResp != nil {
		data := url.Values{}
		data.Set("token", ccResp.AccessToken)
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		resp, err := http.PostForm(serverURL+"/oauth/introspect", data)
		if err == nil && resp.StatusCode == 200 {
			var result map[string]interface{}
			body, _ := io.ReadAll(resp.Body)
			json.Unmarshal(body, &result)
			if active, ok := result["active"].(bool); ok && active {
				fmt.Println("✓ PASS")
				passed++
			} else {
				fmt.Println("✗ FAIL (token not active)")
				failed++
			}
		} else {
			fmt.Println("✗ FAIL")
			failed++
		}
	} else {
		fmt.Println("✗ SKIP (no token)")
	}

	// 结果
	fmt.Println("\n┌─────────────────────────────────────────────────┐")
	fmt.Printf("│ 测试结果: %d 通过, %d 失败                        │\n", passed, failed)
	fmt.Println("└─────────────────────────────────────────────────┘")
}

// 辅助函数
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

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func readLine(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// 检查是否已登录
	token, _ := client.GetToken(context.Background())
	isLoggedIn := token != nil && token.IsValid()

	html := `<!DOCTYPE html>
<html>
<head>
<title>OAuth2 测试客户端</title>
<style>
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
h1 { color: #1e293b; margin-bottom: 8px; }
.subtitle { color: #64748b; margin-bottom: 32px; }
.card { background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.card h2 { margin-top: 0; color: #334155; font-size: 18px; }
.btn { display: inline-block; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 500; margin-right: 8px; margin-bottom: 8px; }
.btn-primary { background: #3b82f6; color: white; }
.btn-primary:hover { background: #2563eb; }
.btn-success { background: #22c55e; color: white; }
.btn-danger { background: #ef4444; color: white; }
.btn-danger:hover { background: #dc2626; }
.status { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; }
.status-success { background: #dcfce7; color: #166534; }
.status-warning { background: #fef3c7; color: #92400e; }
code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 14px; }
</style>
</head>
<body>
<h1>🔐 OAuth2 测试客户端</h1>
<p class="subtitle">用于测试 OAuth2/OIDC 授权流程</p>

{{if .IsLoggedIn}}
<div class="status status-success">✓ 已登录 - Token 有效</div>
<div class="card">
<h2>已登录操作</h2>
<a href="/userinfo" class="btn btn-success">查看用户信息</a>
<a href="/token-info" class="btn btn-primary">Token 信息</a>
<a href="/refresh" class="btn btn-primary">刷新 Token</a>
<a href="/introspect" class="btn btn-primary">Token 自省</a>
<a href="/logout" class="btn btn-danger">退出登录</a>
</div>
{{else}}
<div class="status status-warning">⚠ 未登录</div>
<div class="card">
<h2>开始授权</h2>
<p>流程：本页 → OAuth 站点授权页 →（未登录则 Web 登录）→ 点「授权」→ 回到本客户端回调</p>
<a href="/login" class="btn btn-primary">使用 OAuth2 登录（Web 授权页）</a>
</div>
{{end}}

<div class="card">
<h2>OIDC / 调试工具</h2>
<a href="/oidc-test" class="btn btn-success">OIDC 综合测试</a>
<a href="/oidc" class="btn btn-primary">OIDC 发现文档</a>
<a href="/webhook-test" class="btn btn-primary">Webhook 测试</a>
</div>

<div class="card">
<h2>配置信息</h2>
<p><strong>OAuth 站点:</strong> <code>{{.ServerURL}}</code></p>
<p><strong>授权端点:</strong> <code>{{.ServerURL}}/oauth/authorize</code>（嵌入 Web 授权 UI）</p>
<p><strong>Token端点:</strong> <code>{{.ServerURL}}/oauth/token</code></p>
<p><strong>UserInfo端点:</strong> <code>{{.ServerURL}}/oauth/userinfo</code></p>
<p><strong>回调地址:</strong> <code>{{.RedirectURL}}</code></p>
<p><strong>Scopes:</strong> <code>{{.Scopes}}</code></p>
</div>
</body>
</html>`

	tmpl := template.Must(template.New("home").Parse(html))
	tmpl.Execute(w, map[string]interface{}{
		"IsLoggedIn":  isLoggedIn,
		"ServerURL":   serverURL,
		"RedirectURL": testRedirectURL,
		"Scopes":      strings.Join(buildTestOAuthConfig().Scopes, " "),
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	authURL, err := client.AuthCodeURL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("[LOGIN] 打开 OAuth Web 授权页（未登录会先进入 %s/login，再回到授权页）: %s\n", serverURL, authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		errMsg := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("授权失败: %s - %s", errMsg, errDesc), http.StatusBadRequest)
		return
	}

	fmt.Printf("[CALLBACK] 收到授权码: %s\n", code[:min(20, len(code))]+"...")

	// 交换 token
	token, err := client.Exchange(context.Background(), code, state)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token交换失败: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("[TOKEN] access_token: %s...\n", token.AccessToken[:min(20, len(token.AccessToken))])
	if token.RefreshToken != "" {
		fmt.Printf("[TOKEN] refresh_token: %s...\n", token.RefreshToken[:min(20, len(token.RefreshToken))])
	}
	if token.IDToken != "" {
		fmt.Printf("[TOKEN] id_token: %s...\n", token.IDToken[:min(20, len(token.IDToken))])
	}
	fmt.Printf("[TOKEN] 过期时间: %s\n", token.Expiry)

	// 授权成功后立即获取用户信息
	userInfo, err := client.GetUserInfo(context.Background())
	if err != nil {
		fmt.Printf("[USERINFO] 获取失败: %v\n", err)
	} else {
		fmt.Printf("[USERINFO] 用户: %s (%s)\n", userInfo.Name, userInfo.Email)
	}

	http.Redirect(w, r, "/userinfo", http.StatusFound)
}

// probeUserInfo 用指定 access_token 调用 UserInfo（不读会话），用于隔离测试机器令牌。
func probeUserInfo(accessToken string) (status int, body string, err error) {
	req, err := http.NewRequest("GET", serverURL+"/oauth/userinfo", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	tokenSource := "当前登录会话（用户委托令牌）"
	isolated := r.URL.Query().Get("access_token")

	if isolated != "" {
		tokenSource = "隔离测试：仅使用 URL 中的 access_token（未读会话）"
		status, body, err := probeUserInfo(isolated)
		if err != nil {
			renderMessage(w, "UserInfo 请求失败", err.Error(), "error")
			return
		}
		renderUserInfoProbeResult(w, tokenSource, status, body)
		return
	}

	sess, _ := client.GetToken(context.Background())
	if sess != nil && sess.RefreshToken == "" {
		renderMessage(w, "无法展示用户资料",
			"当前会话中的 access_token 没有 refresh_token，多半是机器令牌或未完整登录。\n\n"+
				"请先 /login 或 /device；若刚获取 client_credentials 令牌，请在 CC 结果页点击「用此机器令牌测试 UserInfo」验证应返回 403。",
			"error")
		return
	}

	userInfo, err := client.GetUserInfo(context.Background())
	if err != nil {
		renderMessage(w, "UserInfo 失败", fmt.Sprintf("%v\n\n（%s）", err, tokenSource), "error")
		return
	}

	// 格式化 JSON 用于显示
	userJSON, _ := json.MarshalIndent(userInfo, "", "  ")

	html := `<!DOCTYPE html>
<html>
<head>
<title>用户信息 - OAuth2 测试</title>
<style>
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
h1 { color: #1e293b; }
.card { background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.card h2 { margin-top: 0; color: #334155; font-size: 18px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px; }
.info-grid { display: grid; grid-template-columns: 140px 1fr; gap: 12px; }
.label { color: #64748b; font-weight: 500; }
.value { color: #1e293b; word-break: break-all; }
.avatar { width: 64px; height: 64px; border-radius: 50%; background: #3b82f6; color: white; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold; margin-bottom: 16px; }
.btn { display: inline-block; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: 500; margin-right: 8px; }
.btn-secondary { background: #e2e8f0; color: #475569; }
.btn-danger { background: #ef4444; color: white; }
pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
.social { display: flex; gap: 8px; flex-wrap: wrap; }
.social-badge { background: #f1f5f9; padding: 4px 12px; border-radius: 16px; font-size: 13px; }
</style>
</head>
<body>
<h1>👤 用户信息</h1>

<div class="card">
<div class="avatar">{{.Initial}}</div>
<div class="info-grid">
<span class="label">用户ID (sub)</span><span class="value">{{.UserInfo.Sub}}</span>
<span class="label">用户名</span><span class="value">{{.UserInfo.PreferredUsername}}</span>
<span class="label">显示名称</span><span class="value">{{.UserInfo.Name}}</span>
<span class="label">邮箱</span><span class="value">{{.UserInfo.Email}} {{if .UserInfo.EmailVerified}}✓{{end}}</span>
{{if .UserInfo.Nickname}}<span class="label">昵称</span><span class="value">{{.UserInfo.Nickname}}</span>{{end}}
{{if .UserInfo.GivenName}}<span class="label">名</span><span class="value">{{.UserInfo.GivenName}}</span>{{end}}
{{if .UserInfo.FamilyName}}<span class="label">姓</span><span class="value">{{.UserInfo.FamilyName}}</span>{{end}}
{{if .UserInfo.Gender}}<span class="label">性别</span><span class="value">{{.UserInfo.Gender}}</span>{{end}}
{{if .UserInfo.Birthdate}}<span class="label">生日</span><span class="value">{{.UserInfo.Birthdate}}</span>{{end}}
{{if .UserInfo.PhoneNumber}}<span class="label">电话</span><span class="value">{{.UserInfo.PhoneNumber}}</span>{{end}}
{{if .UserInfo.Website}}<span class="label">网站</span><span class="value">{{.UserInfo.Website}}</span>{{end}}
{{if .UserInfo.Bio}}<span class="label">简介</span><span class="value">{{.UserInfo.Bio}}</span>{{end}}
</div>

{{if .HasSocial}}
<h3 style="margin-top: 20px; font-size: 14px; color: #64748b;">社交账号</h3>
<div class="social">
{{range $k, $v := .UserInfo.SocialAccounts}}<span class="social-badge">{{$k}}: {{$v}}</span>{{end}}
</div>
{{end}}
</div>

<div class="card">
<h2>原始 JSON 响应</h2>
<pre>{{.UserJSON}}</pre>
</div>

<a href="/" class="btn btn-secondary">返回首页</a>
<a href="/logout" class="btn btn-danger">退出登录</a>
</body>
</html>`

	initial := "U"
	if userInfo.Name != "" {
		initial = strings.ToUpper(string([]rune(userInfo.Name)[0]))
	}

	tmpl := template.Must(template.New("userinfo").Parse(html))
	tmpl.Execute(w, map[string]interface{}{
		"UserInfo":  userInfo,
		"UserJSON":  string(userJSON),
		"Initial":   initial,
		"HasSocial": len(userInfo.SocialAccounts) > 0,
	})
}

func renderUserInfoProbeResult(w http.ResponseWriter, tokenSource string, status int, body string) {
	ok := status == http.StatusOK
	title := "UserInfo 隔离测试"
	color := "#ef4444"
	if ok {
		color = "#22c55e"
		title = "UserInfo 返回了用户资料"
	}
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>%s</title>
<style>body{font-family:system-ui;max-width:800px;margin:40px auto;padding:0 20px;background:#f8fafc}
.card{background:#fff;border-radius:12px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
h1{color:%s}pre{background:#1e293b;color:#e2e8f0;padding:16px;border-radius:8px;overflow:auto}
.note{background:#fef3c7;padding:12px;border-radius:8px;margin:12px 0;font-size:14px}
.btn{display:inline-block;margin-top:16px;padding:10px 16px;background:#e2e8f0;border-radius:8px;text-decoration:none;color:#475569}
</style></head><body><div class="card">
<h1>%s</h1>
<p><strong>HTTP %d</strong> — %s</p>
<div class="note">机器令牌（client_credentials）应得到 <strong>403 insufficient_scope</strong>；只有用户委托令牌才应 200 并含 sub。</div>
<pre>%s</pre>
<a href="/userinfo" class="btn">返回会话 UserInfo</a>
<a href="/" class="btn">首页</a>
</div></body></html>`, title, color, title, status, tokenSource, body)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := client.Logout(true); err != nil {
		_ = client.Logout()
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleRefresh 刷新Token
func handleRefresh(w http.ResponseWriter, r *http.Request) {
	token, err := client.GetToken(context.Background())
	if err != nil || token == nil {
		renderMessage(w, "错误", "未登录，请先授权", "error")
		return
	}

	fmt.Println("[REFRESH] 尝试刷新Token...")
	newToken, err := client.RefreshToken(context.Background())
	if err != nil {
		renderMessage(w, "刷新失败", fmt.Sprintf("错误: %v", err), "error")
		return
	}

	fmt.Printf("[REFRESH] 新Token: %s...\n", newToken.AccessToken[:min(20, len(newToken.AccessToken))])
	fmt.Printf("[REFRESH] 新过期时间: %s\n", newToken.Expiry)

	renderMessage(w, "刷新成功", fmt.Sprintf("新Token已获取，过期时间: %s", newToken.Expiry.Format("2006-01-02 15:04:05")), "success")
}

/*
 * oidcTestResult 单项 OIDC 测试结果
 * 功能：记录每个测试用例的名称、分类、通过状态、详情和耗时
 */
type oidcTestResult struct {
	Name     string
	Category string
	Pass     bool
	Detail   string
	Duration time.Duration
}

/*
 * handleOIDCTest OIDC 综合自动化测试
 * 功能：依次测试 Discovery / JWKS / WebFinger / UserInfo / Introspect / Revoke / Logout 等端点
 *       输出每项测试的通过/失败状态和详细信息
 */
func handleOIDCTest(w http.ResponseWriter, r *http.Request) {
	var results []oidcTestResult

	httpClient := &http.Client{Timeout: 10 * time.Second}

	/* ========== 1. OIDC Discovery ========== */
	func() {
		t := time.Now()
		resp, err := httpClient.Get(serverURL + "/.well-known/openid-configuration")
		dur := time.Since(t)
		if err != nil {
			results = append(results, oidcTestResult{"Discovery 端点可达", "Discovery", false, err.Error(), dur})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != 200 {
			results = append(results, oidcTestResult{"Discovery 返回 200", "Discovery", false, fmt.Sprintf("status=%d", resp.StatusCode), dur})
			return
		}
		results = append(results, oidcTestResult{"Discovery 端点可达", "Discovery", true, fmt.Sprintf("status=200, %d bytes", len(body)), dur})

		var doc map[string]interface{}
		if err := json.Unmarshal(body, &doc); err != nil {
			results = append(results, oidcTestResult{"Discovery JSON 解析", "Discovery", false, err.Error(), dur})
			return
		}
		results = append(results, oidcTestResult{"Discovery JSON 解析", "Discovery", true, fmt.Sprintf("%d 个字段", len(doc)), dur})

		/* 校验 OIDC Core 必填字段 */
		requiredFields := []string{
			"issuer", "authorization_endpoint", "token_endpoint",
			"jwks_uri", "response_types_supported", "subject_types_supported",
			"id_token_signing_alg_values_supported",
		}
		for _, field := range requiredFields {
			if _, ok := doc[field]; ok {
				results = append(results, oidcTestResult{"Discovery 必填字段: " + field, "Discovery", true, fmt.Sprintf("%v", doc[field]), 0})
			} else {
				results = append(results, oidcTestResult{"Discovery 必填字段: " + field, "Discovery", false, "缺失", 0})
			}
		}

		/* 校验推荐字段 */
		recommendedFields := []string{"userinfo_endpoint", "revocation_endpoint", "introspection_endpoint", "scopes_supported"}
		for _, field := range recommendedFields {
			if _, ok := doc[field]; ok {
				results = append(results, oidcTestResult{"Discovery 推荐字段: " + field, "Discovery", true, fmt.Sprintf("%v", doc[field]), 0})
			} else {
				results = append(results, oidcTestResult{"Discovery 推荐字段: " + field, "Discovery", false, "缺失（建议补充）", 0})
			}
		}
	}()

	/* ========== 2. JWKS ========== */
	func() {
		t := time.Now()
		resp, err := httpClient.Get(serverURL + "/.well-known/jwks.json")
		dur := time.Since(t)
		if err != nil {
			results = append(results, oidcTestResult{"JWKS 端点可达", "JWKS", false, err.Error(), dur})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		results = append(results, oidcTestResult{"JWKS 端点可达", "JWKS", resp.StatusCode == 200, fmt.Sprintf("status=%d", resp.StatusCode), dur})

		var jwks map[string]interface{}
		if err := json.Unmarshal(body, &jwks); err != nil {
			results = append(results, oidcTestResult{"JWKS JSON 解析", "JWKS", false, err.Error(), dur})
			return
		}

		keys, ok := jwks["keys"].([]interface{})
		if !ok || len(keys) == 0 {
			results = append(results, oidcTestResult{"JWKS 包含密钥", "JWKS", false, "keys 数组为空或不存在", 0})
			return
		}
		results = append(results, oidcTestResult{"JWKS 包含密钥", "JWKS", true, fmt.Sprintf("%d 个密钥", len(keys)), 0})

		/* 校验第一个 key 的必要字段 */
		if key, ok := keys[0].(map[string]interface{}); ok {
			for _, field := range []string{"kty", "kid", "use", "n", "e"} {
				if v, exists := key[field]; exists {
					detail := fmt.Sprintf("%v", v)
					if len(detail) > 40 {
						detail = detail[:40] + "..."
					}
					results = append(results, oidcTestResult{"JWKS Key 字段: " + field, "JWKS", true, detail, 0})
				} else {
					results = append(results, oidcTestResult{"JWKS Key 字段: " + field, "JWKS", false, "缺失", 0})
				}
			}
		}
	}()

	/* ========== 3. WebFinger ========== */
	func() {
		t := time.Now()
		resp, err := httpClient.Get(serverURL + "/.well-known/webfinger?resource=acct:admin@localhost&rel=http://openid.net/specs/connect/1.0/issuer")
		dur := time.Since(t)
		if err != nil {
			results = append(results, oidcTestResult{"WebFinger 端点可达", "WebFinger", false, err.Error(), dur})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		results = append(results, oidcTestResult{"WebFinger 端点可达", "WebFinger", resp.StatusCode == 200, fmt.Sprintf("status=%d, %d bytes", resp.StatusCode, len(body)), dur})

		var wf map[string]interface{}
		if err := json.Unmarshal(body, &wf); err == nil {
			if _, ok := wf["subject"]; ok {
				results = append(results, oidcTestResult{"WebFinger subject 字段", "WebFinger", true, fmt.Sprintf("%v", wf["subject"]), 0})
			} else {
				results = append(results, oidcTestResult{"WebFinger subject 字段", "WebFinger", false, "缺失", 0})
			}
			if links, ok := wf["links"].([]interface{}); ok && len(links) > 0 {
				results = append(results, oidcTestResult{"WebFinger links 字段", "WebFinger", true, fmt.Sprintf("%d 个链接", len(links)), 0})
			} else {
				results = append(results, oidcTestResult{"WebFinger links 字段", "WebFinger", false, "缺失或为空", 0})
			}
		}
	}()

	/* ========== 4. UserInfo（需要登录） ========== */
	token, _ := client.GetToken(context.Background())
	hasToken := token != nil && token.IsValid()

	if hasToken {
		func() {
			t := time.Now()
			req, _ := http.NewRequest("GET", serverURL+"/oauth/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token.AccessToken)
			resp, err := httpClient.Do(req)
			dur := time.Since(t)
			if err != nil {
				results = append(results, oidcTestResult{"UserInfo 端点可达", "UserInfo", false, err.Error(), dur})
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results = append(results, oidcTestResult{"UserInfo 端点可达", "UserInfo", resp.StatusCode == 200, fmt.Sprintf("status=%d", resp.StatusCode), dur})

			var userInfo map[string]interface{}
			if err := json.Unmarshal(body, &userInfo); err != nil {
				results = append(results, oidcTestResult{"UserInfo JSON 解析", "UserInfo", false, err.Error(), 0})
				return
			}

			/* 校验 OIDC 标准 claims */
			checkClaims := []struct{ key, label string }{
				{"sub", "sub (必须)"}, {"name", "name"}, {"preferred_username", "preferred_username"},
				{"email", "email"}, {"email_verified", "email_verified"}, {"picture", "picture"},
				{"nickname", "nickname"}, {"given_name", "given_name"}, {"family_name", "family_name"},
				{"gender", "gender"}, {"birthdate", "birthdate"}, {"locale", "locale"},
				{"zoneinfo", "zoneinfo"}, {"website", "website"}, {"bio", "bio"},
				{"phone_number", "phone_number"}, {"phone_number_verified", "phone_number_verified"},
				{"address", "address"}, {"updated_at", "updated_at"},
			}
			for _, claim := range checkClaims {
				if v, ok := userInfo[claim.key]; ok {
					detail := fmt.Sprintf("%v", v)
					if len(detail) > 60 {
						detail = detail[:60] + "..."
					}
					results = append(results, oidcTestResult{"UserInfo 声明: " + claim.label, "UserInfo", true, detail, 0})
				} else {
					results = append(results, oidcTestResult{"UserInfo 声明: " + claim.label, "UserInfo", false, "未返回", 0})
				}
			}
		}()

		/* ========== 5. Token Introspection ========== */
		func() {
			t := time.Now()
			data := url.Values{}
			data.Set("token", token.AccessToken)
			data.Set("client_id", clientID)
			data.Set("client_secret", clientSecret)
			resp, err := httpClient.PostForm(serverURL+"/oauth/introspect", data)
			dur := time.Since(t)
			if err != nil {
				results = append(results, oidcTestResult{"Introspect 端点可达", "Introspect", false, err.Error(), dur})
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results = append(results, oidcTestResult{"Introspect 端点可达", "Introspect", resp.StatusCode == 200, fmt.Sprintf("status=%d", resp.StatusCode), dur})

			var result map[string]interface{}
			json.Unmarshal(body, &result)

			if active, ok := result["active"].(bool); ok && active {
				results = append(results, oidcTestResult{"Introspect active=true", "Introspect", true, "Token 有效", 0})
			} else {
				results = append(results, oidcTestResult{"Introspect active=true", "Introspect", false, fmt.Sprintf("返回: %s", string(body)), 0})
			}

			for _, field := range []string{"scope", "client_id", "token_type", "exp", "sub"} {
				if v, ok := result[field]; ok {
					results = append(results, oidcTestResult{"Introspect 字段: " + field, "Introspect", true, fmt.Sprintf("%v", v), 0})
				} else {
					results = append(results, oidcTestResult{"Introspect 字段: " + field, "Introspect", false, "未返回", 0})
				}
			}
		}()

		/* ========== 6. Token Revocation ========== */
		func() {
			/* 先刷新得到新 token 对，用于专门测试 revoke，不影响当前会话 */
			refreshData := url.Values{}
			refreshData.Set("grant_type", "refresh_token")
			refreshData.Set("refresh_token", token.RefreshToken)
			refreshData.Set("client_id", clientID)
			refreshData.Set("client_secret", clientSecret)
			refreshResp, err := httpClient.PostForm(serverURL+"/oauth/token", refreshData)
			if err != nil || refreshResp.StatusCode != 200 {
				results = append(results, oidcTestResult{"Revoke 准备: 刷新 Token", "Revoke", false, "无法刷新获取测试 Token", 0})
				return
			}
			defer refreshResp.Body.Close()
			var newTokens map[string]interface{}
			body, _ := io.ReadAll(refreshResp.Body)
			json.Unmarshal(body, &newTokens)
			testAccessToken, _ := newTokens["access_token"].(string)
			if testAccessToken == "" {
				results = append(results, oidcTestResult{"Revoke 准备: 获取 Access Token", "Revoke", false, "返回中无 access_token", 0})
				return
			}
			results = append(results, oidcTestResult{"Revoke 准备: 刷新 Token", "Revoke", true, "获得新 Token 对", 0})

			/* 撤销这个新 access_token（独立 token，不影响当前会话） */
			t := time.Now()
			revokeData := url.Values{}
			revokeData.Set("token", testAccessToken)
			revokeData.Set("token_type_hint", "access_token")
			revokeData.Set("client_id", clientID)
			revokeData.Set("client_secret", clientSecret)
			revokeResp, err := httpClient.PostForm(serverURL+"/oauth/revoke", revokeData)
			dur := time.Since(t)
			if err != nil {
				results = append(results, oidcTestResult{"Revoke 端点可达", "Revoke", false, err.Error(), dur})
				return
			}
			defer revokeResp.Body.Close()
			results = append(results, oidcTestResult{"Revoke 端点可达", "Revoke", revokeResp.StatusCode == 200, fmt.Sprintf("status=%d", revokeResp.StatusCode), dur})

			/* 验证撤销后 introspect 返回 active=false */
			verifyData := url.Values{}
			verifyData.Set("token", testAccessToken)
			verifyData.Set("client_id", clientID)
			verifyData.Set("client_secret", clientSecret)
			verifyResp, err := httpClient.PostForm(serverURL+"/oauth/introspect", verifyData)
			if err == nil {
				defer verifyResp.Body.Close()
				vBody, _ := io.ReadAll(verifyResp.Body)
				var vResult map[string]interface{}
				json.Unmarshal(vBody, &vResult)
				if active, ok := vResult["active"].(bool); ok && !active {
					results = append(results, oidcTestResult{"Revoke 验证: introspect active=false", "Revoke", true, "已撤销 Token 正确返回 inactive", 0})
				} else {
					results = append(results, oidcTestResult{"Revoke 验证: introspect active=false", "Revoke", false, fmt.Sprintf("返回: %s", string(vBody)), 0})
				}
			}
		}()

		/* ========== 7. OIDC Logout ========== */
		func() {
			t := time.Now()
			req, _ := http.NewRequest("GET", serverURL+"/oauth/logout", nil)
			/* 不跟随重定向，只检查响应状态 */
			noRedirectClient := &http.Client{
				Timeout: 10 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := noRedirectClient.Do(req)
			dur := time.Since(t)
			if err != nil {
				results = append(results, oidcTestResult{"OIDC Logout 端点可达", "Logout", false, err.Error(), dur})
				return
			}
			defer resp.Body.Close()
			/* Logout 可能返回 200 或 302 重定向 */
			pass := resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 204
			results = append(results, oidcTestResult{"OIDC Logout 端点可达", "Logout", pass, fmt.Sprintf("status=%d", resp.StatusCode), dur})
		}()
	} else {
		results = append(results, oidcTestResult{"UserInfo / Introspect / Revoke / Logout", "Auth", false, "未登录，需要先完成 OAuth 授权才能测试这些端点", 0})
	}

	/* ========== 渲染测试结果页面 ========== */
	passCount, failCount := 0, 0
	for _, r := range results {
		if r.Pass {
			passCount++
		} else {
			failCount++
		}
	}

	html := `<!DOCTYPE html>
<html>
<head><title>OIDC 综合测试</title>
<style>
body { font-family: system-ui; max-width: 1000px; margin: 0 auto; padding: 20px; background: #f8fafc; }
h1 { color: #1e293b; }
.summary { display: flex; gap: 16px; margin-bottom: 24px; }
.summary-card { padding: 16px 24px; border-radius: 12px; font-size: 20px; font-weight: 600; }
.summary-pass { background: #dcfce7; color: #166534; }
.summary-fail { background: #fee2e2; color: #991b1b; }
.summary-total { background: #e0e7ff; color: #3730a3; }
.category { margin-bottom: 24px; }
.category h2 { font-size: 16px; color: #475569; margin-bottom: 8px; border-bottom: 2px solid #e2e8f0; padding-bottom: 4px; }
.test-row { display: flex; align-items: center; padding: 8px 12px; border-radius: 6px; margin-bottom: 2px; font-size: 13px; }
.test-row:nth-child(even) { background: #f8fafc; }
.test-row:nth-child(odd) { background: white; }
.test-icon { width: 24px; flex-shrink: 0; font-size: 16px; }
.test-name { flex: 1; color: #334155; font-weight: 500; }
.test-detail { flex: 2; color: #64748b; font-size: 12px; word-break: break-all; }
.test-time { width: 60px; text-align: right; color: #94a3b8; font-size: 11px; flex-shrink: 0; }
.pass { color: #22c55e; }
.fail { color: #ef4444; }
.btn { display: inline-block; padding: 10px 20px; border-radius: 8px; text-decoration: none; margin-top: 16px; margin-right: 8px; font-weight: 500; }
.btn-primary { background: #3b82f6; color: white; }
.btn-default { background: #e2e8f0; color: #475569; }
.note { background: #fef3c7; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; color: #92400e; }
</style>
</head>
<body>
<h1>🧪 OIDC 综合测试</h1>`

	if !hasToken {
		html += `<div class="note">⚠ 未登录 — 部分测试（UserInfo / Introspect / Revoke / Logout）需要先 <a href="/login">OAuth 授权登录</a> 后才能执行。</div>`
	}

	html += fmt.Sprintf(`
<div class="summary">
<div class="summary-card summary-total">共 %d 项</div>
<div class="summary-card summary-pass">✓ 通过 %d</div>
<div class="summary-card summary-fail">✗ 失败 %d</div>
</div>`, passCount+failCount, passCount, failCount)

	/* 按 Category 分组输出 */
	categories := []string{}
	catMap := make(map[string][]oidcTestResult)
	for _, r := range results {
		if _, exists := catMap[r.Category]; !exists {
			categories = append(categories, r.Category)
		}
		catMap[r.Category] = append(catMap[r.Category], r)
	}

	for _, cat := range categories {
		html += fmt.Sprintf(`<div class="category"><h2>%s</h2>`, cat)
		for _, r := range catMap[cat] {
			icon := `<span class="pass">✓</span>`
			if !r.Pass {
				icon = `<span class="fail">✗</span>`
			}
			durStr := ""
			if r.Duration > 0 {
				durStr = fmt.Sprintf("%dms", r.Duration.Milliseconds())
			}
			html += fmt.Sprintf(`<div class="test-row"><div class="test-icon">%s</div><div class="test-name">%s</div><div class="test-detail">%s</div><div class="test-time">%s</div></div>`,
				icon, r.Name, r.Detail, durStr)
		}
		html += `</div>`
	}

	html += `
<a href="/oidc-test" class="btn btn-primary">重新测试</a>
<a href="/" class="btn btn-default">返回首页</a>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleOIDC 查看OIDC发现文档和相关端点
func handleOIDC(w http.ResponseWriter, r *http.Request) {
	endpoint := r.URL.Query().Get("endpoint")
	if endpoint == "" {
		endpoint = "discovery"
	}

	var url string
	var title string

	switch endpoint {
	case "discovery":
		url = serverURL + "/.well-known/openid-configuration"
		title = "OIDC 发现文档"
	case "jwks":
		url = serverURL + "/.well-known/jwks.json"
		title = "JSON Web Key Set (JWKS)"
	case "webfinger":
		url = serverURL + "/.well-known/webfinger?resource=acct:admin@localhost&rel=http://openid.net/specs/connect/1.0/issuer"
		title = "WebFinger"
	default:
		url = serverURL + "/.well-known/openid-configuration"
		title = "OIDC 发现文档"
	}

	resp, err := http.Get(url)
	if err != nil {
		renderMessage(w, "请求失败", err.Error(), "error")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var data map[string]interface{}
	json.Unmarshal(body, &data)
	prettyJSON, _ := json.MarshalIndent(data, "", "  ")

	// 自定义HTML以显示导航
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%s</title>
<style>
body { font-family: system-ui; max-width: 1000px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
h1 { color: #1e293b; }
.tabs { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }
.tab { padding: 8px 16px; background: #e2e8f0; border-radius: 8px; text-decoration: none; color: #475569; font-size: 14px; }
.tab.active { background: #3b82f6; color: white; }
.card { background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; line-height: 1.5; max-height: 600px; }
.endpoint { color: #64748b; font-size: 14px; margin-bottom: 16px; word-break: break-all; }
.btn { display: inline-block; padding: 10px 20px; background: #e2e8f0; border-radius: 8px; text-decoration: none; margin-top: 20px; color: #475569; }
.info { background: #dbeafe; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; color: #1e40af; }
</style>
</head>
<body>
<h1>🔐 OIDC 端点</h1>

<div class="tabs">
<a href="/oidc?endpoint=discovery" class="tab %s">发现文档</a>
<a href="/oidc?endpoint=jwks" class="tab %s">JWKS 公钥</a>
<a href="/oidc?endpoint=webfinger" class="tab %s">WebFinger</a>
</div>

<div class="info">
<strong>%s</strong><br>
端点: <code>%s</code>
</div>

<div class="card">
<pre>%s</pre>
</div>

<a href="/" class="btn">返回首页</a>
</body>
</html>`,
		title,
		ifActive(endpoint, "discovery"),
		ifActive(endpoint, "jwks"),
		ifActive(endpoint, "webfinger"),
		title, url, string(prettyJSON))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func ifActive(current, target string) string {
	if current == target {
		return "active"
	}
	return ""
}

// handleIntrospect Token自省
func handleIntrospect(w http.ResponseWriter, r *http.Request) {
	token, err := client.GetToken(context.Background())
	if err != nil || token == nil {
		renderMessage(w, "错误", "未登录，请先授权", "error")
		return
	}

	// 调用introspect端点
	reqBody := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s",
		token.AccessToken, clientID, clientSecret)

	resp, err := http.Post(serverURL+"/oauth/introspect",
		"application/x-www-form-urlencoded",
		strings.NewReader(reqBody))
	if err != nil {
		renderMessage(w, "请求失败", err.Error(), "error")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	json.Unmarshal(body, &result)
	prettyJSON, _ := json.MarshalIndent(result, "", "  ")

	renderJSON(w, "Token 自省结果", "/oauth/introspect", string(prettyJSON))
}

// handleTokenInfo 显示当前Token信息和完整OIDC数据
func handleTokenInfo(w http.ResponseWriter, r *http.Request) {
	token, err := client.GetToken(context.Background())
	if err != nil || token == nil {
		renderMessage(w, "错误", "未登录，请先 /login 或 /device", "error")
		return
	}

	tokenKind := "用户委托（含 refresh_token）"
	if token.RefreshToken == "" {
		tokenKind = "疑似机器令牌（无 refresh_token）— UserInfo 可能失败"
	}

	userInfo, userInfoErr := client.GetUserInfo(context.Background())

	// 获取Token自省结果
	reqBody := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s",
		token.AccessToken, clientID, clientSecret)
	resp, _ := http.Post(serverURL+"/oauth/introspect",
		"application/x-www-form-urlencoded",
		strings.NewReader(reqBody))
	var introspectResult map[string]interface{}
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &introspectResult)
		resp.Body.Close()
	}

	html := `<!DOCTYPE html>
<html>
<head><title>OIDC 完整信息</title>
<style>
body { font-family: system-ui; max-width: 1000px; margin: 0 auto; padding: 20px; background: #f8fafc; }
h1 { color: #1e293b; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
.card { background: white; border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.card h2 { margin-top: 0; font-size: 16px; color: #334155; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; display: flex; align-items: center; gap: 8px; }
.card h2 span { font-size: 18px; }
pre { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; line-height: 1.4; max-height: 300px; }
.info-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f1f5f9; }
.info-row:last-child { border-bottom: none; }
.info-label { color: #64748b; font-size: 13px; }
.info-value { color: #1e293b; font-size: 13px; font-weight: 500; text-align: right; word-break: break-all; max-width: 200px; }
.valid { color: #22c55e; }
.invalid { color: #ef4444; }
.btn { display: inline-block; padding: 10px 20px; background: #e2e8f0; border-radius: 8px; text-decoration: none; margin-top: 20px; color: #475569; margin-right: 8px; }
.btn-primary { background: #3b82f6; color: white; }
</style>
</head>
<body>
<h1>🔐 OIDC 完整信息</h1>
<div class="grid">
<div class="card">
<h2><span>🎫</span> Access Token</h2>
<div class="info-row"><span class="info-label">Token</span><span class="info-value">` + maskToken(token.AccessToken) + `</span></div>
<div class="info-row"><span class="info-label">类型</span><span class="info-value">` + token.TokenType + `</span></div>
<div class="info-row"><span class="info-label">过期时间</span><span class="info-value">` + token.Expiry.Format("2006-01-02 15:04:05") + `</span></div>
<div class="info-row"><span class="info-label">剩余时间</span><span class="info-value">` + time.Until(token.Expiry).Round(time.Second).String() + `</span></div>
<div class="info-row"><span class="info-label">状态</span><span class="info-value ` + func() string {
		if token.IsValid() {
			return "valid"
		}
		return "invalid"
	}() + `">` + func() string {
		if token.IsValid() {
			return "✓ 有效"
		}
		return "✗ 已过期"
	}() + `</span></div>
<div class="info-row"><span class="info-label">令牌类别</span><span class="info-value">` + tokenKind + `</span></div>
</div>

<div class="card">
<h2><span>🔄</span> Refresh Token</h2>
<div class="info-row"><span class="info-label">Token</span><span class="info-value">` + maskToken(token.RefreshToken) + `</span></div>
<div class="info-row"><span class="info-label">可用</span><span class="info-value ` + func() string {
		if token.RefreshToken != "" {
			return "valid"
		}
		return "invalid"
	}() + `">` + func() string {
		if token.RefreshToken != "" {
			return "✓ 是"
		}
		return "✗ 无"
	}() + `</span></div>
</div>

<div class="card">
<h2><span>🪪</span> ID Token</h2>
<div class="info-row"><span class="info-label">Token</span><span class="info-value">` + maskToken(token.IDToken) + `</span></div>
<div class="info-row"><span class="info-label">可用</span><span class="info-value ` + func() string {
		if token.IDToken != "" {
			return "valid"
		}
		return "invalid"
	}() + `">` + func() string {
		if token.IDToken != "" {
			return "✓ 是（scope 含 openid）"
		}
		return "✗ 无"
	}() + `</span></div>
</div>

<div class="card">
<h2><span>👤</span> 用户信息 (UserInfo)</h2>`

	if userInfo != nil {
		html += infoRow("Subject (sub)", userInfo.Sub)
		html += infoRow("显示名称", userInfo.Name)
		html += infoRow("用户名", userInfo.PreferredUsername)
		html += infoRow("昵称", userInfo.Nickname)
		html += infoRow("姓", userInfo.FamilyName)
		html += infoRow("名", userInfo.GivenName)
		html += infoRow("邮箱", userInfo.Email)
		html += infoRow("邮箱已验证", fmt.Sprintf("%v", userInfo.EmailVerified))
		html += infoRow("头像", userInfo.Picture)
		html += infoRow("性别", userInfo.Gender)
		html += infoRow("生日", userInfo.Birthdate)
		html += infoRow("电话", userInfo.PhoneNumber)
		html += infoRow("电话已验证", fmt.Sprintf("%v", userInfo.PhoneNumberVerified))
		html += infoRow("语言", userInfo.Locale)
		html += infoRow("时区", userInfo.Zoneinfo)
		html += infoRow("网站", userInfo.Website)
		html += infoRow("简介", userInfo.Bio)
		if userInfo.Address != nil {
			html += infoRow("地址", userInfo.Address.Formatted)
		}
		if userInfo.UpdatedAt > 0 {
			html += infoRow("更新时间", time.Unix(userInfo.UpdatedAt, 0).Format("2006-01-02 15:04:05"))
		}
		if len(userInfo.SocialAccounts) > 0 {
			for k, v := range userInfo.SocialAccounts {
				html += infoRow("社交-"+k, v)
			}
		}
	} else {
		msg := "获取失败（机器令牌应返回 insufficient_scope）"
		if userInfoErr != nil {
			msg = userInfoErr.Error()
		}
		html += `<div class="info-row"><span class="info-label">状态</span><span class="info-value invalid">` + msg + `</span></div>`
	}

	html += `</div>

<div class="card">
<h2><span>🔍</span> Token 自省结果</h2>
<p style="font-size:12px;color:#64748b;margin:0 0 8px">有 <code>sub</code> 才是用户令牌；仅 <code>active</code>/<code>scope</code> 可能是机器令牌。</p>
<pre>` + func() string { b, _ := json.MarshalIndent(introspectResult, "", "  "); return string(b) }() + `</pre>
</div>
</div>

<a href="/refresh" class="btn btn-primary">刷新 Token</a>
<a href="/" class="btn">返回首页</a>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleWebhookTest 测试Webhook
func handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// 接收webhook并存储
		body, _ := io.ReadAll(r.Body)

		// 解析body
		var bodyData map[string]interface{}
		json.Unmarshal(body, &bodyData)

		// 提取重要header
		headers := map[string]string{
			"X-Webhook-Event":     r.Header.Get("X-Webhook-Event"),
			"X-Webhook-Delivery":  r.Header.Get("X-Webhook-Delivery"),
			"X-Webhook-Timestamp": r.Header.Get("X-Webhook-Timestamp"),
			"X-Webhook-Signature": r.Header.Get("X-Webhook-Signature"),
			"Content-Type":        r.Header.Get("Content-Type"),
		}

		// 存储日志
		webhookMutex.Lock()
		webhookLogs = append([]WebhookLog{{
			Time:    time.Now(),
			Headers: headers,
			Body:    bodyData,
			Raw:     string(body),
		}}, webhookLogs...) // 新的在前面
		if len(webhookLogs) > 50 {
			webhookLogs = webhookLogs[:50] // 保留最近50条
		}
		webhookMutex.Unlock()

		fmt.Printf("[WEBHOOK] 收到数据: %s\n", string(body))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"received","message":"Webhook received successfully"}`))
		return
	}

	// GET请求 - 查看日志
	if r.URL.Query().Get("logs") == "json" {
		webhookMutex.Lock()
		logs := webhookLogs
		webhookMutex.Unlock()

		fmt.Printf("[WEBHOOK-API] 返回 %d 条日志\n", len(logs))
		data, _ := json.Marshal(logs)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(data)
		return
	}

	// 发送测试webhook请求
	token, _ := client.GetToken(context.Background())
	accessToken := ""
	if token != nil {
		accessToken = token.AccessToken
	}

	html := `<!DOCTYPE html>
<html>
<head>
<title>Webhook 测试</title>
<style>
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
h1 { color: #1e293b; }
.card { background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.card h2 { margin-top: 0; color: #334155; font-size: 18px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; margin-bottom: 4px; font-weight: 500; color: #475569; }
.form-group input, .form-group textarea { width: 100%; padding: 10px 12px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 14px; }
.form-group textarea { min-height: 120px; font-family: monospace; }
.btn { display: inline-block; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: 500; border: none; cursor: pointer; }
.btn-primary { background: #3b82f6; color: white; }
.btn-secondary { background: #e2e8f0; color: #475569; }
pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
#result { margin-top: 20px; }
</style>
</head>
<body>
<h1>🔔 Webhook 测试</h1>

<div class="card">
<h2>发送测试 Webhook</h2>
<form id="webhookForm">
<div class="form-group">
<label>目标 URL</label>
<input type="text" id="targetUrl" value="http://localhost:9000/webhook-test" />
</div>
<div class="form-group">
<label>事件类型</label>
<input type="text" id="eventType" value="user.login" />
</div>
<div class="form-group">
<label>Payload (JSON)</label>
<textarea id="payload">{
  "event": "user.login",
  "timestamp": "` + time.Now().Format(time.RFC3339) + `",
  "data": {
    "user_id": "test-user-123",
    "email": "test@example.com",
    "ip": "127.0.0.1"
  }
}</textarea>
</div>
<button type="submit" class="btn btn-primary">发送 Webhook</button>
</form>
<div id="result"></div>
</div>

<div class="card">
<h2>📥 收到的 Webhook 日志</h2>
<p>本端点地址: <code>http://localhost:9000/webhook-test</code></p>
<div id="webhookLogs">加载中...</div>
</div>

<div class="card">
<h2>Webhook 配置说明</h2>
<p>在应用设置中配置 Webhook URL，系统会在以下事件发生时推送通知：</p>
<ul>
<li><code>token.issued</code> - Token发放</li>
<li><code>token.refreshed</code> - Token刷新</li>
<li><code>user.login</code> - 用户登录</li>
<li><code>user.registered</code> - 用户注册</li>
<li><code>oauth.authorized</code> - OAuth授权</li>
<li><code>oauth.revoked</code> - Token撤销</li>
</ul>
</div>

<a href="/" class="btn btn-secondary">返回首页</a>

<script>
document.getElementById('webhookForm').onsubmit = async function(e) {
  e.preventDefault();
  const url = document.getElementById('targetUrl').value;
  const payload = document.getElementById('payload').value;
  
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload
    });
    const result = await resp.text();
    document.getElementById('result').innerHTML = '<h3>响应结果</h3><pre>' + result + '</pre>';
    loadLogs(); // 刷新日志
  } catch(err) {
    document.getElementById('result').innerHTML = '<h3>错误</h3><pre>' + err.message + '</pre>';
  }
};

async function loadLogs() {
  try {
    const resp = await fetch('/webhook-test?logs=json');
    const logs = await resp.json();
    if (!logs || logs.length === 0) {
      document.getElementById('webhookLogs').innerHTML = '<p style="color:#64748b">暂无收到的Webhook</p>';
      return;
    }
    let html = '';
    logs.forEach((log, i) => {
      const time = new Date(log.time).toLocaleString();
      const event = log.headers['X-Webhook-Event'] || 'unknown';
      html += '<div style="background:#f8fafc;padding:12px;border-radius:8px;margin-bottom:8px;font-size:13px">';
      html += '<div style="display:flex;justify-content:space-between;margin-bottom:8px">';
      html += '<strong style="color:#3b82f6">' + event + '</strong>';
      html += '<span style="color:#64748b">' + time + '</span>';
      html += '</div>';
      html += '<pre style="background:#1e293b;color:#e2e8f0;padding:8px;border-radius:4px;margin:0;font-size:11px;overflow-x:auto">' + JSON.stringify(log.body, null, 2) + '</pre>';
      html += '</div>';
    });
    document.getElementById('webhookLogs').innerHTML = html;
  } catch(e) {
    document.getElementById('webhookLogs').innerHTML = '<p style="color:#ef4444">加载失败</p>';
  }
}

// 初始加载和定时刷新
loadLogs();
setInterval(loadLogs, 3000);
</script>
</body>
</html>`

	_ = accessToken // 预留使用
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

/* infoRow 生成 UserInfo 信息行 HTML */
func infoRow(label, value string) string {
	if value == "" {
		value = `<span style="color:#94a3b8">-</span>`
	}
	return `<div class="info-row"><span class="info-label">` + label + `</span><span class="info-value">` + value + `</span></div>`
}

// 辅助函数
func maskToken(token string) string {
	if len(token) <= 10 {
		return token
	}
	return token[:10] + "..." + token[len(token)-5:]
}

func renderMessage(w http.ResponseWriter, title, message, msgType string) {
	color := "#3b82f6"
	if msgType == "error" {
		color = "#ef4444"
	} else if msgType == "success" {
		color = "#22c55e"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%s</title>
<style>
body { font-family: system-ui; max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }
.card { background: white; border-radius: 12px; padding: 40px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
h1 { color: %s; }
.btn { display: inline-block; padding: 10px 20px; background: #e2e8f0; border-radius: 8px; text-decoration: none; margin-top: 20px; }
</style>
</head>
<body>
<div class="card">
<h1>%s</h1>
<p>%s</p>
<a href="/" class="btn">返回首页</a>
</div>
</body>
</html>`, title, color, title, message)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func renderJSON(w http.ResponseWriter, title, endpoint, jsonStr string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%s</title>
<style>
body { font-family: system-ui; max-width: 900px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
h1 { color: #1e293b; }
.endpoint { color: #64748b; font-size: 14px; margin-bottom: 20px; }
.card { background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; line-height: 1.5; }
.btn { display: inline-block; padding: 10px 20px; background: #e2e8f0; border-radius: 8px; text-decoration: none; margin-top: 20px; color: #475569; }
</style>
</head>
<body>
<h1>%s</h1>
<p class="endpoint">端点: <code>%s</code></p>
<div class="card">
<pre>%s</pre>
</div>
<a href="/" class="btn">返回首页</a>
</body>
</html>`, title, title, endpoint, jsonStr)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// Web Handlers - 新增OAuth2流程
// ============================================================================

// handleDeviceFlow - 设备流Web界面
func handleDeviceFlow(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// 启动设备流
		ctx := context.Background()
		deviceAuth, err := client.DeviceAuthorization(ctx, "openid profile email")
		if err != nil {
			renderMessage(w, "错误", fmt.Sprintf("设备授权失败: %v", err), "error")
			return
		}

		visitURL := oauth2.ResolveDeviceVerificationURL(serverURL, deviceAuth)
		openURL := visitURL
		if openURL == "" {
			openURL = deviceAuth.VerificationURIComplete
		}

		// 返回设备码信息
		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>设备流授权</title>
<style>
body { font-family: system-ui; max-width: 600px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
.card { background: white; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
h1 { color: #1e293b; margin-bottom: 8px; }
.code { font-size: 48px; font-weight: bold; color: #3b82f6; letter-spacing: 8px; margin: 24px 0; font-family: monospace; }
.url { background: #f1f5f9; padding: 12px; border-radius: 8px; margin: 16px 0; word-break: break-all; }
.btn { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; border-radius: 8px; text-decoration: none; margin: 8px; }
.btn-secondary { background: #e2e8f0; color: #475569; }
.status { margin-top: 24px; padding: 16px; background: #fef3c7; border-radius: 8px; color: #92400e; }
#pollStatus { display: none; }
</style>
</head>
<body>
<div class="card">
<h1>📱 设备授权</h1>
<p>请在另一台设备上访问以下地址并输入验证码</p>

<div class="url">
<strong>%s</strong>
</div>

<div class="code">%s</div>

<p style="color:#64748b">验证码有效期: %d 秒</p>

<a href="%s" target="_blank" class="btn">在新窗口打开授权页面</a>
<a href="/" class="btn btn-secondary">返回首页</a>

<div class="status" id="pollStatus">
<div id="statusText">等待授权中...</div>
</div>
</div>

<script>
var deviceCode = "%s";
var interval = %d;
var pollCount = 0;
var maxPolls = %d;

document.getElementById('pollStatus').style.display = 'block';

function poll() {
    pollCount++;
    if (pollCount > maxPolls) {
        document.getElementById('statusText').innerHTML = '❌ 验证码已过期';
        return;
    }
    
    fetch('/device?poll=1&device_code=' + encodeURIComponent(deviceCode))
        .then(r => r.json())
        .then(data => {
            if (data.status === 'authorized') {
                document.getElementById('statusText').innerHTML = '✅ 授权成功! 正在跳转...';
                setTimeout(() => window.location.href = '/userinfo', 1000);
            } else if (data.status === 'denied') {
                document.getElementById('statusText').innerHTML = '❌ 授权被拒绝';
            } else if (data.status === 'expired') {
                document.getElementById('statusText').innerHTML = '❌ 验证码已过期';
            } else {
                document.getElementById('statusText').innerHTML = '⏳ 等待授权中... (' + pollCount + ')';
                setTimeout(poll, interval * 1000);
            }
        })
        .catch(err => {
            document.getElementById('statusText').innerHTML = '⏳ 等待授权中... (' + pollCount + ')';
            setTimeout(poll, interval * 1000);
        });
}

setTimeout(poll, interval * 1000);
</script>
</body>
</html>`,
			visitURL,
			deviceAuth.UserCode,
			deviceAuth.ExpiresIn,
			openURL,
			deviceAuth.DeviceCode,
			deviceAuth.Interval,
			deviceAuth.ExpiresIn/deviceAuth.Interval)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	// 轮询检查
	if r.URL.Query().Get("poll") == "1" {
		deviceCode := r.URL.Query().Get("device_code")
		ctx := context.Background()
		token, err := client.PollDeviceToken(ctx, deviceCode, 5)

		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			if dfe, ok := err.(*oauth2.DeviceFlowError); ok {
				if dfe.IsAuthorizationPending() {
					json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
				} else if dfe.IsAccessDenied() {
					json.NewEncoder(w).Encode(map[string]string{"status": "denied"})
				} else if dfe.IsExpired() {
					json.NewEncoder(w).Encode(map[string]string{"status": "expired"})
				} else {
					json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
				}
			} else {
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
			}
			return
		}

		_ = token
		json.NewEncoder(w).Encode(map[string]string{"status": "authorized"})
		return
	}

	// GET请求显示启动页面
	html := `<!DOCTYPE html>
<html>
<head><title>设备流授权</title>
<style>
body { font-family: system-ui; max-width: 600px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
.card { background: white; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
h1 { color: #1e293b; }
.btn { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; border-radius: 8px; text-decoration: none; border: none; cursor: pointer; font-size: 16px; }
.info { background: #dbeafe; padding: 16px; border-radius: 8px; margin: 20px 0; }
</style>
</head>
<body>
<div class="card">
<h1>📱 Device Flow - 设备流授权</h1>
<div class="info">
<p><strong>适用场景:</strong></p>
<ul>
<li>智能电视、游戏主机等输入受限设备</li>
<li>CLI命令行工具</li>
<li>IoT设备</li>
</ul>
</div>
<p>点击下方按钮启动设备流授权，系统会生成一个验证码供您在其他设备上输入。</p>
<form method="POST">
<button type="submit" class="btn">🚀 启动设备授权</button>
</form>
<br>
<a href="/" style="color:#64748b">返回首页</a>
</div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleClientCredentials - 客户端凭据Web界面
func handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		scope := r.FormValue("scope")
		if scope == "" {
			scope = "api.read"
		}

		ctx := context.Background()
		resp, err := client.ClientCredentials(ctx, &oauth2.ClientCredentialsRequest{
			Scope: scope,
		})

		if err != nil {
			renderMessage(w, "错误", fmt.Sprintf("客户端凭据授权失败: %v\n\n%s", err, oauthClientCredentialsHint(err)), "error")
			return
		}

		prettyJSON, _ := json.MarshalIndent(resp, "", "  ")

		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Client Credentials 结果</title>
<style>
body { font-family: system-ui; max-width: 700px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
.card { background: white; border-radius: 12px; padding: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
h1 { color: #22c55e; }
pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; }
.btn { display: inline-block; padding: 10px 20px; background: #e2e8f0; border-radius: 8px; text-decoration: none; color: #475569; margin-top: 16px; }
.info { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f1f5f9; }
</style>
</head>
<body>
<div class="card">
<h1>✅ 获取Token成功</h1>
<div class="info"><span>Token Type</span><strong>%s</strong></div>
<div class="info"><span>Expires In</span><strong>%d 秒</strong></div>
<div class="info"><span>Scope</span><strong>%s</strong></div>
<h3>完整响应</h3>
<pre>%s</pre>
<p style="font-size:14px;color:#64748b">此令牌<strong>不会</strong>写入登录会话。可用下方链接单独测 UserInfo（预期 403）。</p>
<a href="/userinfo?access_token=%s" class="btn" style="background:#fef3c7">用此机器令牌测试 UserInfo</a>
<a href="/client-credentials" class="btn">重新获取</a>
<a href="/" class="btn">返回首页</a>
</div>
</body>
</html>`, resp.TokenType, resp.ExpiresIn, resp.Scope, string(prettyJSON), url.QueryEscape(resp.AccessToken))

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	// GET请求显示表单
	html := `<!DOCTYPE html>
<html>
<head><title>Client Credentials</title>
<style>
body { font-family: system-ui; max-width: 600px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
.card { background: white; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
h1 { color: #1e293b; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; margin-bottom: 4px; font-weight: 500; }
.form-group input { width: 100%; padding: 10px; border: 1px solid #e2e8f0; border-radius: 8px; }
.btn { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; border-radius: 8px; border: none; cursor: pointer; font-size: 16px; }
.info { background: #dbeafe; padding: 16px; border-radius: 8px; margin: 20px 0; }
</style>
</head>
<body>
<div class="card">
<h1>🤖 Client Credentials - 机器认证</h1>
<div class="info">
<p><strong>适用场景:</strong></p>
<ul>
<li>后端服务间调用</li>
<li>定时任务、批处理</li>
<li>无用户参与的自动化流程</li>
</ul>
</div>
<form method="POST">
<div class="form-group">
<label>Scope (可选)</label>
<input type="text" name="scope" value="api.read" placeholder="api.read（勿填 openid/profile）">
</div>
<button type="submit" class="btn">🔑 获取 Access Token</button>
</form>
<br>
<a href="/" style="color:#64748b">返回首页</a>
</div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleTokenExchange - Token交换Web界面
func handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		subjectToken := r.FormValue("subject_token")
		scope := r.FormValue("scope")

		if subjectToken == "" {
			token, err := client.GetToken(context.Background())
			if err != nil || token == nil || token.RefreshToken == "" {
				renderMessage(w, "错误", "请粘贴用户授权得到的 subject_token，或先通过 /login、/device 登录（client_credentials 令牌不能用于交换）", "error")
				return
			}
			subjectToken = token.AccessToken
		}

		// 执行Token Exchange
		data := url.Values{}
		data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		data.Set("subject_token", subjectToken)
		data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		if scope != "" {
			data.Set("scope", scope)
		}

		resp, err := http.PostForm(serverURL+"/oauth/token", data)
		if err != nil {
			renderMessage(w, "错误", fmt.Sprintf("Token Exchange 请求失败: %v", err), "error")
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		var result map[string]interface{}
		json.Unmarshal(body, &result)
		prettyJSON, _ := json.MarshalIndent(result, "", "  ")

		statusColor := "#22c55e"
		statusText := "✅ Token Exchange 成功"
		if resp.StatusCode != http.StatusOK {
			statusColor = "#ef4444"
			statusText = fmt.Sprintf("❌ Token Exchange 失败 (HTTP %d)", resp.StatusCode)
			if errDesc, ok := result["error_description"].(string); ok && errDesc != "" {
				statusText += " — " + errDesc
			} else if errCode, ok := result["error"].(string); ok {
				statusText += " — " + errCode
			}
		}

		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Token Exchange 结果</title>
<style>
body { font-family: system-ui; max-width: 700px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
.card { background: white; border-radius: 12px; padding: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
h1 { color: %s; }
pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; }
.btn { display: inline-block; padding: 10px 20px; background: #e2e8f0; border-radius: 8px; text-decoration: none; color: #475569; margin-top: 16px; margin-right: 8px; }
</style>
</head>
<body>
<div class="card">
<h1>%s</h1>
<h3>响应内容</h3>
<pre>%s</pre>
<a href="/token-exchange" class="btn">重新交换</a>
<a href="/" class="btn">返回首页</a>
</div>
</body>
</html>`, statusColor, statusText, string(prettyJSON))

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	currentToken := ""
	currentHint := "（未检测到用户登录会话，请先 /login 或 /device）"
	token, _ := client.GetToken(context.Background())
	if token != nil && token.RefreshToken != "" {
		currentToken = token.AccessToken
		currentHint = "（已填入当前用户会话令牌，可用于 RFC 8693 交换）"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Token Exchange</title>
<style>
body { font-family: system-ui; max-width: 700px; margin: 0 auto; padding: 40px 20px; background: #f8fafc; }
.card { background: white; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
h1 { color: #1e293b; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; margin-bottom: 4px; font-weight: 500; }
.form-group input, .form-group textarea { width: 100%%; padding: 10px; border: 1px solid #e2e8f0; border-radius: 8px; font-family: monospace; }
.form-group textarea { min-height: 80px; }
.btn { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; border-radius: 8px; border: none; cursor: pointer; font-size: 16px; }
.info { background: #dbeafe; padding: 16px; border-radius: 8px; margin: 20px 0; }
</style>
</head>
<body>
<div class="card">
<h1>🔄 Token Exchange - 令牌交换</h1>
<div class="info">
<p><strong>RFC 8693:</strong> 用于在不同安全域之间交换令牌，实现令牌降级、委托等场景。</p>
<p>%s</p>
<p><strong>注意:</strong> 须使用授权码/设备流等<strong>用户委托</strong>令牌；<code>scope</code> 须为 subject 的子集（勿填 <code>all</code>）。</p>
</div>
<form method="POST">
<div class="form-group">
<label>Subject Token (留空则使用当前用户会话)</label>
<textarea name="subject_token" placeholder="eyJhbGciOiJIUzI1NiIs...">%s</textarea>
</div>
<div class="form-group">
<label>Scope (可选，用于请求更小的权限范围)</label>
<input type="text" name="scope" value="openid profile" placeholder="openid profile">
</div>
<button type="submit" class="btn">🔄 执行 Token Exchange</button>
</form>
<br>
<a href="/" style="color:#64748b">返回首页</a>
</div>
</body>
</html>`, currentHint, currentToken)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// init 确保使用了bytes包
var _ = bytes.Buffer{}
