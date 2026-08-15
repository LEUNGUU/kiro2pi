package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Token management with mutex for thread-safety
var (
	tokenMutex            sync.RWMutex
	cachedToken           *TokenData
	tokenExpiresAt        time.Time
	tokenRefreshThreshold = 5 * time.Minute // Refresh token 5 minutes before expiry
)

// TokenData 表示token文件的结构
type TokenData struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// KiroCliToken 表示kiro-cli存储的token结构 (snake_case)
type KiroCliToken struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresAt    string   `json:"expires_at"`
	Region       string   `json:"region"`
	StartUrl     string   `json:"start_url"`
	OAuthFlow    string   `json:"oauth_flow"`
	Scopes       []string `json:"scopes"`
}

// KiroCliProfile 表示kiro-cli存储的profile结构
type KiroCliProfile struct {
	Arn         string `json:"arn"`
	ProfileName string `json:"profile_name"`
}

// KiroCliDeviceRegistration 表示kiro-cli存储的设备注册信息
type KiroCliDeviceRegistration struct {
	ClientId            string   `json:"client_id"`
	ClientSecret        string   `json:"client_secret"`
	ClientSecretExpires string   `json:"client_secret_expires_at"`
	OAuthFlow           string   `json:"oauth_flow"`
	Region              string   `json:"region"`
	Scopes              []string `json:"scopes"`
}

// SSOOIDCTokenRequest AWS SSO OIDC CreateToken请求
type SSOOIDCTokenRequest struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	GrantType    string `json:"grantType"`
	RefreshToken string `json:"refreshToken"`
}

// SSOOIDCTokenResponse AWS SSO OIDC CreateToken响应
type SSOOIDCTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	ExpiresIn    int    `json:"expiresIn"`
	RefreshToken string `json:"refreshToken"`
	TokenType    string `json:"tokenType"`
}

// 全局变量存储从kiro-cli读取的profile ARN
var kiroCliProfileArn string
var kiroCliRegion string

// getKiroCliDbPath 获取kiro-cli SQLite数据库路径
func getKiroCliDbPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	var dataDir string
	switch runtime.GOOS {
	case "darwin":
		dataDir = filepath.Join(homeDir, "Library", "Application Support")
	default:
		dataDir = filepath.Join(homeDir, ".local", "share")
	}
	return filepath.Join(dataDir, "kiro-cli", "data.sqlite3")
}

// getTokenFromKiroCli 从kiro-cli SQLite数据库读取token
func getTokenFromKiroCli() (TokenData, error) {
	dbPath := getKiroCliDbPath()
	if dbPath == "" {
		return TokenData{}, fmt.Errorf("无法获取kiro-cli数据库路径")
	}

	// 检查数据库文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return TokenData{}, fmt.Errorf("kiro-cli数据库不存在: %s", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return TokenData{}, fmt.Errorf("打开kiro-cli数据库失败: %v", err)
	}
	defer db.Close()

	// 查询token - kiro-cli使用auth_kv表存储
	var value string
	err = db.QueryRow("SELECT value FROM auth_kv WHERE key = ?", "kirocli:odic:token").Scan(&value)
	if err != nil {
		return TokenData{}, fmt.Errorf("读取token失败: %v", err)
	}

	// 解析JSON
	var kiroToken KiroCliToken
	if err := json.Unmarshal([]byte(value), &kiroToken); err != nil {
		return TokenData{}, fmt.Errorf("解析token失败: %v", err)
	}

	// 尝试读取profile ARN - 从state表读取
	var profileValue string
	err = db.QueryRow("SELECT value FROM state WHERE key = ?", "api.codewhisperer.profile").Scan(&profileValue)
	if err == nil && profileValue != "" {
		var profile KiroCliProfile
		if json.Unmarshal([]byte(profileValue), &profile) == nil {
			kiroCliProfileArn = profile.Arn
			log.Printf("从kiro-cli读取profile ARN: %s", kiroCliProfileArn)
		}
	}
	if kiroCliProfileArn == "" {
		log.Printf("未能从kiro-cli读取profile ARN")
	}

	// Capture region from token
	if kiroToken.Region != "" {
		kiroCliRegion = kiroToken.Region
		log.Printf("从kiro-cli读取region: %s", kiroCliRegion)
	}

	// 转换为TokenData格式
	return TokenData{
		AccessToken:  kiroToken.AccessToken,
		RefreshToken: kiroToken.RefreshToken,
		ExpiresAt:    kiroToken.ExpiresAt,
	}, nil
}

// getDeviceRegistrationFromKiroCli 从kiro-cli SQLite数据库读取设备注册信息
func getDeviceRegistrationFromKiroCli() (KiroCliDeviceRegistration, error) {
	dbPath := getKiroCliDbPath()
	if dbPath == "" {
		return KiroCliDeviceRegistration{}, fmt.Errorf("无法获取kiro-cli数据库路径")
	}

	// 检查数据库文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return KiroCliDeviceRegistration{}, fmt.Errorf("kiro-cli数据库不存在: %s", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return KiroCliDeviceRegistration{}, fmt.Errorf("打开kiro-cli数据库失败: %v", err)
	}
	defer db.Close()

	// 查询设备注册信息 - 注意key中的typo是 "odic" 而不是 "oidc"
	var value string
	err = db.QueryRow("SELECT value FROM auth_kv WHERE key = ?", "kirocli:odic:device-registration").Scan(&value)
	if err != nil {
		return KiroCliDeviceRegistration{}, fmt.Errorf("读取设备注册信息失败: %v", err)
	}

	// 解析JSON
	var deviceReg KiroCliDeviceRegistration
	if err := json.Unmarshal([]byte(value), &deviceReg); err != nil {
		return KiroCliDeviceRegistration{}, fmt.Errorf("解析设备注册信息失败: %v", err)
	}

	return deviceReg, nil
}

// tryRefreshToken 尝试刷新token（非致命版本，用于服务器自动刷新）
func tryRefreshToken() error {
	// 从kiro-cli SQLite数据库读取token
	currentToken, err := getTokenFromKiroCli()
	if err != nil {
		return fmt.Errorf("读取token失败: %v", err)
	}

	// 读取设备注册信息
	deviceReg, err := getDeviceRegistrationFromKiroCli()
	if err != nil {
		return fmt.Errorf("读取设备注册信息失败: %v", err)
	}

	// 准备AWS SSO OIDC CreateToken请求
	ssoReq := SSOOIDCTokenRequest{
		ClientId:     deviceReg.ClientId,
		ClientSecret: deviceReg.ClientSecret,
		GrantType:    "refresh_token",
		RefreshToken: currentToken.RefreshToken,
	}

	reqBody, err := json.Marshal(ssoReq)
	if err != nil {
		return fmt.Errorf("序列化请求失败: %v", err)
	}

	// 构建SSO OIDC endpoint URL
	region := deviceReg.Region
	if region == "" {
		region = "us-east-1"
	}
	ssoEndpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/token", region)

	log.Printf("自动刷新token，使用SSO OIDC端点: %s", ssoEndpoint)

	// 发送刷新请求
	resp, err := http.Post(
		ssoEndpoint,
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return fmt.Errorf("刷新token请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("刷新token失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	// 解析响应
	var ssoResp SSOOIDCTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&ssoResp); err != nil {
		return fmt.Errorf("解析刷新响应失败: %v", err)
	}

	// 计算过期时间
	expiresAt := time.Now().Add(time.Duration(ssoResp.ExpiresIn) * time.Second).UTC().Format(time.RFC3339Nano)

	// 读取原始token获取其他字段
	dbPath := getKiroCliDbPath()
	db, _ := sql.Open("sqlite", dbPath)
	defer db.Close()
	var originalValue string
	db.QueryRow("SELECT value FROM auth_kv WHERE key = ?", "kirocli:odic:token").Scan(&originalValue)
	var originalToken KiroCliToken
	json.Unmarshal([]byte(originalValue), &originalToken)

	// 构建更新后的token - 保留所有原始字段
	newToken := KiroCliToken{
		AccessToken:  ssoResp.AccessToken,
		RefreshToken: ssoResp.RefreshToken,
		ExpiresAt:    expiresAt,
		Region:       originalToken.Region,
		StartUrl:     originalToken.StartUrl,
		OAuthFlow:    originalToken.OAuthFlow,
		Scopes:       originalToken.Scopes,
	}

	// 更新kiro-cli数据库
	if err := updateTokenInKiroCli(newToken); err != nil {
		return fmt.Errorf("更新token到数据库失败: %v", err)
	}

	log.Printf("Token自动刷新成功! 新过期时间: %s", expiresAt)
	return nil
}

// updateTokenInKiroCli 更新kiro-cli SQLite数据库中的token
func updateTokenInKiroCli(token KiroCliToken) error {
	dbPath := getKiroCliDbPath()
	if dbPath == "" {
		return fmt.Errorf("无法获取kiro-cli数据库路径")
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("打开kiro-cli数据库失败: %v", err)
	}
	defer db.Close()

	// 序列化token
	tokenJson, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("序列化token失败: %v", err)
	}

	// 更新token
	_, err = db.Exec("UPDATE auth_kv SET value = ? WHERE key = ?", string(tokenJson), "kirocli:odic:token")
	if err != nil {
		return fmt.Errorf("更新token失败: %v", err)
	}

	return nil
}

// RefreshRequest 刷新token的请求结构
type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// RefreshResponse 刷新token的响应结构
type RefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// getTokenFilePath 获取跨平台的token文件路径
func getTokenFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("获取用户目录失败: %v\n", err)
		os.Exit(1)
	}

	return filepath.Join(homeDir, ".aws", "sso", "cache", "kiro-auth-token.json")
}

// readToken 读取并显示token信息
func readToken() {
	tokenPath := getTokenFilePath()

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		fmt.Printf("读取token文件失败: %v\n", err)
		os.Exit(1)
	}

	var token TokenData
	if err := json.Unmarshal(data, &token); err != nil {
		fmt.Printf("解析token文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Token信息:")
	fmt.Printf("Access Token: %s\n", token.AccessToken)
	fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
	if token.ExpiresAt != "" {
		fmt.Printf("过期时间: %s\n", token.ExpiresAt)
	}
}

// refreshToken 刷新token - 使用AWS SSO OIDC CreateToken API
func refreshToken() {
	// 从kiro-cli SQLite数据库读取token
	currentToken, err := getTokenFromKiroCli()
	if err != nil {
		fmt.Printf("读取token失败: %v\n", err)
		os.Exit(1)
	}

	// 读取设备注册信息
	deviceReg, err := getDeviceRegistrationFromKiroCli()
	if err != nil {
		fmt.Printf("读取设备注册信息失败: %v\n", err)
		os.Exit(1)
	}

	// 准备AWS SSO OIDC CreateToken请求
	ssoReq := SSOOIDCTokenRequest{
		ClientId:     deviceReg.ClientId,
		ClientSecret: deviceReg.ClientSecret,
		GrantType:    "refresh_token",
		RefreshToken: currentToken.RefreshToken,
	}

	reqBody, err := json.Marshal(ssoReq)
	if err != nil {
		fmt.Printf("序列化请求失败: %v\n", err)
		os.Exit(1)
	}

	// 构建SSO OIDC endpoint URL
	region := deviceReg.Region
	if region == "" {
		region = "us-east-1"
	}
	ssoEndpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/token", region)

	fmt.Printf("使用SSO OIDC端点: %s\n", ssoEndpoint)

	// 发送刷新请求
	resp, err := http.Post(
		ssoEndpoint,
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		fmt.Printf("刷新token请求失败: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("刷新token失败，状态码: %d, 响应: %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	// 解析响应
	var ssoResp SSOOIDCTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&ssoResp); err != nil {
		fmt.Printf("解析刷新响应失败: %v\n", err)
		os.Exit(1)
	}

	// 计算过期时间
	expiresAt := time.Now().Add(time.Duration(ssoResp.ExpiresIn) * time.Second).UTC().Format(time.RFC3339Nano)

	// 读取原始token获取其他字段（如start_url, scopes等）
	dbPath := getKiroCliDbPath()
	db, _ := sql.Open("sqlite", dbPath)
	defer db.Close()
	var originalValue string
	db.QueryRow("SELECT value FROM auth_kv WHERE key = ?", "kirocli:odic:token").Scan(&originalValue)
	var originalToken KiroCliToken
	json.Unmarshal([]byte(originalValue), &originalToken)

	// 构建更新后的token - 保留所有原始字段
	newToken := KiroCliToken{
		AccessToken:  ssoResp.AccessToken,
		RefreshToken: ssoResp.RefreshToken,
		ExpiresAt:    expiresAt,
		Region:       originalToken.Region,
		StartUrl:     originalToken.StartUrl,
		OAuthFlow:    originalToken.OAuthFlow,
		Scopes:       originalToken.Scopes,
	}

	// 更新kiro-cli数据库
	if err := updateTokenInKiroCli(newToken); err != nil {
		fmt.Printf("更新token到数据库失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Token刷新成功!")
	fmt.Printf("新的Access Token: %s...%s\n", newToken.AccessToken[:20], newToken.AccessToken[len(newToken.AccessToken)-10:])
	fmt.Printf("过期时间: %s\n", expiresAt)
}

// exportEnvVars 导出环境变量
func exportEnvVars() {
	tokenPath := getTokenFilePath()

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		fmt.Printf("读取 token失败,请先安装 Kiro 并登录！: %v\n", err)
		os.Exit(1)
	}

	var token TokenData
	if err := json.Unmarshal(data, &token); err != nil {
		fmt.Printf("解析token文件失败: %v\n", err)
		os.Exit(1)
	}

	// 根据操作系统输出不同格式的环境变量设置命令
	if runtime.GOOS == "windows" {
		fmt.Println("CMD")
		fmt.Printf("set ANTHROPIC_BASE_URL=http://localhost:8080\n")
		fmt.Printf("set ANTHROPIC_API_KEY=%s\n\n", token.AccessToken)
		fmt.Println("Powershell")
		fmt.Println(`$env:ANTHROPIC_BASE_URL="http://localhost:8080"`)
		fmt.Printf(`$env:ANTHROPIC_API_KEY="%s"`, token.AccessToken)
	} else {
		fmt.Printf("export ANTHROPIC_BASE_URL=http://localhost:8080\n")
		fmt.Printf("export ANTHROPIC_API_KEY=\"%s\"\n", token.AccessToken)
	}
}

func setClaude() {
	// C:\Users\WIN10\.claude.json
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("获取用户目录失败: %v\n", err)
		os.Exit(1)
	}

	claudeJsonPath := filepath.Join(homeDir, ".claude.json")
	ok, _ := FileExists(claudeJsonPath)
	if !ok {
		fmt.Println("未找到Claude配置文件，请确认是否已安装 Claude Code")
		fmt.Println("npm install -g @anthropic-ai/claude-code")
		os.Exit(1)
	}

	data, err := os.ReadFile(claudeJsonPath)
	if err != nil {
		fmt.Printf("读取 Claude 文件失败: %v\n", err)
		os.Exit(1)
	}

	var jsonData map[string]interface{}

	err = json.Unmarshal(data, &jsonData)

	if err != nil {
		fmt.Printf("解析 JSON 文件失败: %v\n", err)
		os.Exit(1)
	}

	jsonData["hasCompletedOnboarding"] = true
	jsonData["kiro2cc"] = true

	newJson, err := json.MarshalIndent(jsonData, "", "  ")

	if err != nil {
		fmt.Printf("生成 JSON 文件失败: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(claudeJsonPath, newJson, 0644)

	if err != nil {
		fmt.Printf("写入 JSON 文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Claude 配置文件已更新")

}

// isTokenExpiringSoon checks if the token is about to expire
func isTokenExpiringSoon() bool {
	tokenMutex.RLock()
	defer tokenMutex.RUnlock()

	if cachedToken == nil || tokenExpiresAt.IsZero() {
		return true
	}
	return time.Now().Add(tokenRefreshThreshold).After(tokenExpiresAt)
}

// getToken 获取当前token with proactive refresh and thread safety
func getToken() (TokenData, error) {
	// Check if we need to refresh proactively
	if isTokenExpiringSoon() {
		tokenMutex.Lock()
		// Double-check after acquiring write lock
		if cachedToken == nil || time.Now().Add(tokenRefreshThreshold).After(tokenExpiresAt) {
			log.Printf("Token即将过期或未缓存，主动刷新...")
			if err := tryRefreshToken(); err != nil {
				log.Printf("主动刷新token失败: %v, 继续尝试读取现有token", err)
			}
		}
		tokenMutex.Unlock()
	}

	// 优先从kiro-cli SQLite数据库读取token
	token, err := getTokenFromKiroCli()
	if err == nil {
		log.Printf("从kiro-cli数据库读取token成功")

		// Update cache with expiry time
		tokenMutex.Lock()
		cachedToken = &token
		if token.ExpiresAt != "" {
			if expiry, parseErr := time.Parse(time.RFC3339Nano, token.ExpiresAt); parseErr == nil {
				tokenExpiresAt = expiry
			} else if expiry, parseErr := time.Parse(time.RFC3339, token.ExpiresAt); parseErr == nil {
				tokenExpiresAt = expiry
			}
		}
		tokenMutex.Unlock()

		return token, nil
	}
	log.Printf("从kiro-cli读取token失败: %v, 尝试从JSON文件读取", err)

	// 回退到JSON文件
	tokenPath := getTokenFilePath()

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return TokenData{}, fmt.Errorf("读取token文件失败: %v", err)
	}

	if err := json.Unmarshal(data, &token); err != nil {
		return TokenData{}, fmt.Errorf("解析token文件失败: %v", err)
	}

	// Update cache
	tokenMutex.Lock()
	cachedToken = &token
	if token.ExpiresAt != "" {
		if expiry, parseErr := time.Parse(time.RFC3339Nano, token.ExpiresAt); parseErr == nil {
			tokenExpiresAt = expiry
		} else if expiry, parseErr := time.Parse(time.RFC3339, token.ExpiresAt); parseErr == nil {
			tokenExpiresAt = expiry
		}
	}
	tokenMutex.Unlock()

	return token, nil
}
