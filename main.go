package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bestk/kiro2cc/parser"
	_ "modernc.org/sqlite"
)

// Token management with mutex for thread-safety
var (
	tokenMutex       sync.RWMutex
	cachedToken      *TokenData
	tokenExpiresAt   time.Time
	tokenRefreshThreshold = 5 * time.Minute // Refresh token 5 minutes before expiry
)

// Retry configuration
const (
	maxRetries     = 3
	retryBaseDelay = 1 * time.Second
)

// Request size limits
const (
	maxRequestBytes        = 590 * 1024 // 590KB max request payload (Kiro API hard limit is ~615KB)
	maxToolResultContentLen = 10 * 1024  // 10KB max per tool result content
)

// isRetryableStatusCode checks if the HTTP status code is retryable
func isRetryableStatusCode(statusCode int) bool {
	return statusCode == 429 || (statusCode >= 500 && statusCode < 600)
}

// calculateRetryDelay calculates exponential backoff delay with jitter
func calculateRetryDelay(attempt int) time.Duration {
	delay := retryBaseDelay * time.Duration(1<<uint(attempt)) // Exponential: 1s, 2s, 4s
	jitter := time.Duration(rand.Int63n(int64(delay / 4)))    // Add up to 25% jitter
	return delay + jitter
}

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

// getQApiEndpoint returns the Q API endpoint URL based on region
func getQApiEndpoint() string {
	region := kiroCliRegion
	if region == "" {
		region = "us-east-1"
	}
	return fmt.Sprintf("https://q.%s.amazonaws.com/", region)
}

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

// AnthropicTool 表示 Anthropic API 的工具结构
type AnthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// InputSchema 表示工具输入模式的结构
type InputSchema struct {
	Json map[string]any `json:"json"`
}

// ToolSpecification 表示工具规范的结构
type ToolSpecification struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// CodeWhispererTool 表示 CodeWhisperer API 的工具结构
type CodeWhispererTool struct {
	ToolSpecification ToolSpecification `json:"toolSpecification"`
}

// HistoryUserMessage 表示历史记录中的用户消息
type HistoryUserMessage struct {
	UserInputMessage struct {
		Content                 string                         `json:"content"`
		UserInputMessageContext *HistoryUserInputMessageContext `json:"userInputMessageContext,omitempty"`
		Origin                  string                         `json:"origin,omitempty"`
	} `json:"userInputMessage"`
}

type HistoryUserInputMessageContext struct {
	EnvState    *EnvState        `json:"envState,omitempty"`
	ToolResults []map[string]any `json:"toolResults,omitempty"`
}

// HistoryAssistantMessage 表示历史记录中的助手消息
type HistoryAssistantMessage struct {
	AssistantResponseMessage struct {
		MessageId string `json:"messageId,omitempty"`
		Content   string `json:"content"`
		ToolUses  []any  `json:"toolUses,omitempty"` // omitempty: kiro-cli omits this field when no tool uses
	} `json:"assistantResponseMessage"`
}

// AnthropicThinking represents the thinking configuration in Anthropic API
type AnthropicThinking struct {
	Type         string `json:"type"`                    // "enabled" or "disabled"
	BudgetTokens int    `json:"budget_tokens,omitempty"` // Token budget for thinking
}

// AnthropicRequest 表示 Anthropic API 的请求结构
type AnthropicRequest struct {
	Model       string                    `json:"model"`
	MaxTokens   int                       `json:"max_tokens"`
	Messages    []AnthropicRequestMessage `json:"messages"`
	System      []AnthropicSystemMessage  `json:"system,omitempty"`
	Tools       []AnthropicTool           `json:"tools,omitempty"`
	Stream      bool                      `json:"stream"`
	Temperature *float64                  `json:"temperature,omitempty"`
	Metadata    map[string]any            `json:"metadata,omitempty"`
	Thinking    *AnthropicThinking        `json:"thinking,omitempty"` // Extended thinking support
}

// AnthropicStreamResponse 表示 Anthropic 流式响应的结构
type AnthropicStreamResponse struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentDelta struct {
		Text string `json:"text"`
		Type string `json:"type"`
	} `json:"delta,omitempty"`
	Content []struct {
		Text string `json:"text"`
		Type string `json:"type"`
	} `json:"content,omitempty"`
	StopReason   string `json:"stop_reason,omitempty"`
	StopSequence string `json:"stop_sequence,omitempty"`
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage,omitempty"`
}

// AnthropicRequestMessage 表示 Anthropic API 的消息结构
type AnthropicRequestMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // 可以是 string 或 []ContentBlock
}

type AnthropicSystemMessage struct {
	Type string `json:"type"`
	Text string `json:"text"` // 可以是 string 或 []ContentBlock
}

// ContentBlock 表示消息内容块的结构
type ContentBlock struct {
	Type      string  `json:"type"`
	Text      *string `json:"text,omitempty"`
	ToolUseId *string `json:"tool_use_id,omitempty"`
	Content   *string `json:"content,omitempty"`
	Name      *string `json:"name,omitempty"`
	Input     *any    `json:"input,omitempty"`
}

// getMessageContent 从消息中提取文本内容
func getMessageContent(content any) string {
	switch v := content.(type) {
	case string:
		// Return string as-is, even if empty
		return v
	case []interface{}:
		var texts []string
		for _, block := range v {

			if m, ok := block.(map[string]interface{}); ok {
				var cb ContentBlock
				if data, err := json.Marshal(m); err == nil {
					if err := json.Unmarshal(data, &cb); err == nil {
						switch cb.Type {
						case "tool_result":
							if cb.Content != nil {
								texts = append(texts, *cb.Content)
							}
						case "text":
							if cb.Text != nil {
								texts = append(texts, *cb.Text)
							}
						// tool_use blocks are skipped - we only extract text content for history
						}
					}

				}
			}

		}
		if len(texts) == 0 {
			// If no text content (tool-only message), return empty string
			// The history builder will handle skipping or merging these messages
			return ""
		}
		return strings.Join(texts, "\n")
	default:
		// Don't log SSE event data as "uncatch" - it's expected during streaming
		return ""
	}
}

// extractToolUses extracts tool_use blocks from message content
// Based on kiro-cli traffic analysis: input should be an object, not a string
func extractToolUses(content any) []any {
	var toolUses []any
	switch v := content.(type) {
	case []interface{}:
		for _, block := range v {
			if m, ok := block.(map[string]interface{}); ok {
				if blockType, ok := m["type"].(string); ok && blockType == "tool_use" {
					// Extract tool use - input as object (matching kiro-cli format)
					toolUse := map[string]any{
						"toolUseId": m["id"],
						"name":      m["name"],
						"input":     m["input"], // Keep as object, not string
					}
					toolUses = append(toolUses, toolUse)
				}
			}
		}
	}
	return toolUses
}

// hasToolResult 检查消息内容是否包含tool_result
func hasToolResult(content any) bool {
	if blocks, ok := content.([]interface{}); ok {
		for _, block := range blocks {
			if m, ok := block.(map[string]interface{}); ok {
				if m["type"] == "tool_result" {
					return true
				}
			}
		}
	}
	return false
}

// extractToolResults 从用户消息内容中提取tool_result块
func extractToolResults(content any) []map[string]any {
	var toolResults []map[string]any
	if blocks, ok := content.([]interface{}); ok {
		for _, block := range blocks {
			if m, ok := block.(map[string]interface{}); ok {
				if m["type"] == "tool_result" {
					toolResult := map[string]any{
						"toolUseId": m["tool_use_id"],
						"status":    "success",
					}

					// Handle content - support both text and json formats
					switch c := m["content"].(type) {
					case string:
						// Simple text content - truncate if too large
						toolResult["content"] = []map[string]any{
							{"text": truncateString(c, maxToolResultContentLen)},
						}
					case []interface{}:
						// Array of content blocks - convert to kiro format
						var contentBlocks []map[string]any
						for _, block := range c {
							if cb, ok := block.(map[string]interface{}); ok {
								if text, ok := cb["text"].(string); ok {
									contentBlocks = append(contentBlocks, map[string]any{"text": truncateString(text, maxToolResultContentLen)})
								}
							}
						}
						if len(contentBlocks) > 0 {
							toolResult["content"] = contentBlocks
						} else {
							toolResult["content"] = []map[string]any{{"text": ""}}
						}
					default:
						toolResult["content"] = []map[string]any{{"text": ""}}
					}

					toolResults = append(toolResults, toolResult)
				}
			}
		}
	}
	return toolResults
}

// extractCwdFromSystemPrompt extracts the working directory from the system prompt
// Pi-agent and similar tools add "Current working directory: /path/to/dir" to the system prompt
// We need to use this instead of os.Getwd() because kiro2cc runs as a service
// with its own working directory that doesn't match the client's working directory
func extractCwdFromSystemPrompt(systemMsgs []AnthropicSystemMessage) string {
	for _, sysMsg := range systemMsgs {
		// Look for "Current working directory:" pattern
		const prefix = "Current working directory:"
		if idx := strings.Index(sysMsg.Text, prefix); idx != -1 {
			// Extract the path after the prefix
			remaining := sysMsg.Text[idx+len(prefix):]
			// Take everything until newline or end of string
			endIdx := strings.Index(remaining, "\n")
			if endIdx == -1 {
				endIdx = len(remaining)
			}
			cwd := strings.TrimSpace(remaining[:endIdx])
			if cwd != "" {
				log.Printf("Extracted cwd from system prompt: %s", cwd)
				return cwd
			}
		}
	}
	// Fallback to os.Getwd() if not found in system prompt
	cwd, _ := os.Getwd()
	log.Printf("No cwd in system prompt, using os.Getwd(): %s", cwd)
	return cwd
}

// CodeWhispererRequest 表示 CodeWhisperer API 的请求结构 (Q API format)
type CodeWhispererRequest struct {
	ConversationState struct {
		ChatTriggerType       string `json:"chatTriggerType"`
		ConversationId        string `json:"conversationId"`
		AgentContinuationId   string `json:"agentContinuationId,omitempty"`
		AgentTaskType         string `json:"agentTaskType,omitempty"`
		CurrentMessage        struct {
			UserInputMessage struct {
				Content                 string `json:"content"`
				ModelId                 string `json:"modelId"`
				Origin                  string `json:"origin"`
				UserInputMessageContext struct {
					ToolResults []map[string]any    `json:"toolResults,omitempty"`
					Tools       []CodeWhispererTool `json:"tools,omitempty"`
					EnvState    *EnvState           `json:"envState,omitempty"`
				} `json:"userInputMessageContext"`
			} `json:"userInputMessage"`
		} `json:"currentMessage"`
		History []any `json:"history"`
	} `json:"conversationState"`
	ProfileArn string `json:"profileArn"`
}

// EnvState represents environment state in the request
type EnvState struct {
	OperatingSystem         string `json:"operatingSystem"`
	CurrentWorkingDirectory string `json:"currentWorkingDirectory"`
}

// goosToQApi maps Go's runtime.GOOS to Q API accepted operatingSystem values.
// The Q API accepts: LINUX, MAC, WINDOWS (from kiro-cli binary).
// Go's runtime.GOOS returns "darwin", "linux", "windows".
func goosToQApi(goos string) string {
	switch goos {
	case "darwin":
		return "macos"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	default:
		return goos
	}
}

// CodeWhispererEvent 表示 CodeWhisperer 的事件响应
type CodeWhispererEvent struct {
	ContentType string `json:"content-type"`
	MessageType string `json:"message-type"`
	Content     string `json:"content"`
	EventType   string `json:"event-type"`
}

var ModelMap = map[string]string{
	// Kiro supported models
	"claude-sonnet-4.5":         "claude-sonnet-4.5",
	"claude-sonnet-4":           "claude-sonnet-4",
	"claude-haiku-4.5":          "claude-haiku-4.5",
	"claude-opus-4.5":           "claude-opus-4.5",
	"claude-opus-4.6":           "claude-opus-4.6",
	"claude-sonnet-4.6":         "claude-sonnet-4.6",
}

// generateUUID generates a simple UUID v4
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant bits
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// buildCodeWhispererRequest 构建 CodeWhisperer 请求 (Q API format matching kiro-cli)
// estimateInputTokens estimates token count from request using chars/4 heuristic
func estimateInputTokens(req AnthropicRequest) int {
	chars := 0
	for _, sys := range req.System {
		chars += len(sys.Text)
	}
	for _, msg := range req.Messages {
		chars += countMessageChars(msg.Content)
	}
	for _, tool := range req.Tools {
		chars += len(tool.Name) + len(tool.Description)
		if schemaBytes, err := json.Marshal(tool.InputSchema); err == nil {
			chars += len(schemaBytes)
		}
	}
	return (chars + 3) / 4
}

func countMessageChars(content any) int {
	switch v := content.(type) {
	case string:
		return len(v)
	case []interface{}:
		chars := 0
		for _, block := range v {
			if m, ok := block.(map[string]interface{}); ok {
				switch m["type"] {
				case "text":
					if text, ok := m["text"].(string); ok {
						chars += len(text)
					}
				case "tool_use":
					if name, ok := m["name"].(string); ok {
						chars += len(name)
					}
					if input, ok := m["input"]; ok {
						if inputBytes, err := json.Marshal(input); err == nil {
							chars += len(inputBytes)
						}
					}
				case "tool_result":
					if c, ok := m["content"].(string); ok {
						chars += len(c)
					}
				}
			}
		}
		return chars
	}
	return 0
}

// sanitizeJsonSchema removes fields that cause Q API "Improperly formed request" errors.
// Specifically: empty required arrays and additionalProperties fields.
func sanitizeJsonSchema(schema map[string]any) map[string]any {
	if schema == nil {
		return nil
	}
	result := make(map[string]any)
	for key, value := range schema {
		if key == "additionalProperties" {
			continue
		}
		if key == "required" {
			if arr, ok := value.([]interface{}); ok && len(arr) == 0 {
				continue
			}
			if arr, ok := value.([]string); ok && len(arr) == 0 {
				continue
			}
		}
		switch v := value.(type) {
		case map[string]any:
			if key == "properties" {
				props := make(map[string]any)
				for pName, pVal := range v {
					if pm, ok := pVal.(map[string]any); ok {
						props[pName] = sanitizeJsonSchema(pm)
					} else {
						props[pName] = pVal
					}
				}
				result[key] = props
			} else {
				result[key] = sanitizeJsonSchema(v)
			}
		case []interface{}:
			sanitized := make([]interface{}, len(v))
			for i, item := range v {
				if m, ok := item.(map[string]any); ok {
					sanitized[i] = sanitizeJsonSchema(m)
				} else {
					sanitized[i] = item
				}
			}
			result[key] = sanitized
		default:
			result[key] = value
		}
	}
	return result
}

// truncateString truncates a string to maxLen, appending "... [truncated]" if cut.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	suffix := "... [truncated]"
	if maxLen <= len(suffix) {
		return s[:maxLen]
	}
	return s[:maxLen-len(suffix)] + suffix
}

// ensureFirstMessageIsUser prepends a synthetic user message if history doesn't start with one.
func ensureFirstMessageIsUser(history []any) []any {
	if len(history) == 0 {
		return history
	}
	if _, ok := history[0].(HistoryUserMessage); ok {
		return history
	}
	log.Printf("History does not start with user message, prepending synthetic user")
	syntheticUser := HistoryUserMessage{}
	syntheticUser.UserInputMessage.Content = "(empty)"
	syntheticUser.UserInputMessage.Origin = "KIRO_CLI"
	return append([]any{syntheticUser}, history...)
}

// ensureAlternatingRoles merges consecutive same-role messages to maintain strict user/assistant alternation.
func ensureAlternatingRoles(history []any) []any {
	if len(history) < 2 {
		return history
	}
	var result []any
	result = append(result, history[0])
	for i := 1; i < len(history); i++ {
		_, currIsUser := history[i].(HistoryUserMessage)
		_, prevIsUser := result[len(result)-1].(HistoryUserMessage)

		if currIsUser == prevIsUser {
			// Same role — merge into previous
			if currIsUser {
				// Merge user messages
				prev := result[len(result)-1].(HistoryUserMessage)
				curr := history[i].(HistoryUserMessage)
				if curr.UserInputMessage.Content != "" {
					if prev.UserInputMessage.Content != "" {
						prev.UserInputMessage.Content += "\n" + curr.UserInputMessage.Content
					} else {
						prev.UserInputMessage.Content = curr.UserInputMessage.Content
					}
				}
				// Merge toolResults
				if curr.UserInputMessage.UserInputMessageContext != nil && len(curr.UserInputMessage.UserInputMessageContext.ToolResults) > 0 {
					if prev.UserInputMessage.UserInputMessageContext == nil {
						prev.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{}
					}
					prev.UserInputMessage.UserInputMessageContext.ToolResults = append(
						prev.UserInputMessage.UserInputMessageContext.ToolResults,
						curr.UserInputMessage.UserInputMessageContext.ToolResults...,
					)
				}
				result[len(result)-1] = prev
			} else {
				// Merge assistant messages
				prev := result[len(result)-1].(HistoryAssistantMessage)
				curr := history[i].(HistoryAssistantMessage)
				if curr.AssistantResponseMessage.Content != "" {
					if prev.AssistantResponseMessage.Content != "" {
						prev.AssistantResponseMessage.Content += "\n" + curr.AssistantResponseMessage.Content
					} else {
						prev.AssistantResponseMessage.Content = curr.AssistantResponseMessage.Content
					}
				}
				// Merge toolUses
				if len(curr.AssistantResponseMessage.ToolUses) > 0 {
					prev.AssistantResponseMessage.ToolUses = append(
						prev.AssistantResponseMessage.ToolUses,
						curr.AssistantResponseMessage.ToolUses...,
					)
				}
				result[len(result)-1] = prev
			}
			log.Printf("Merged consecutive %s message at index %d", map[bool]string{true: "user", false: "assistant"}[currIsUser], i)
		} else {
			result = append(result, history[i])
		}
	}
	return result
}

// ensureAssistantBeforeToolResults converts orphaned toolResults to text.
// After trimming, a user message may have toolResults with no preceding assistant toolUses.
// The Q API rejects this. Matches kiro-gateway's ensure_assistant_before_tool_results.
func ensureAssistantBeforeToolResults(history []any) []any {
	for i, h := range history {
		um, ok := h.(HistoryUserMessage)
		if !ok || um.UserInputMessage.UserInputMessageContext == nil || len(um.UserInputMessage.UserInputMessageContext.ToolResults) == 0 {
			continue
		}
		// Check if preceding message is an assistant with toolUses
		hasPrecedingToolUses := false
		if i > 0 {
			if am, ok := history[i-1].(HistoryAssistantMessage); ok && len(am.AssistantResponseMessage.ToolUses) > 0 {
				hasPrecedingToolUses = true
			}
		}
		if hasPrecedingToolUses {
			continue
		}
		// Convert orphaned toolResults to text
		var parts []string
		for _, tr := range um.UserInputMessage.UserInputMessageContext.ToolResults {
			toolId, _ := tr["toolUseId"].(string)
			if content, ok := tr["content"].([]map[string]any); ok {
				for _, c := range content {
					if text, ok := c["text"].(string); ok {
						parts = append(parts, fmt.Sprintf("[Tool result %s]: %s", toolId, truncateString(text, 500)))
					}
				}
			}
		}
		if len(parts) > 0 {
			text := strings.Join(parts, "\n")
			if um.UserInputMessage.Content != "" {
				um.UserInputMessage.Content += "\n\n" + text
			} else {
				um.UserInputMessage.Content = text
			}
		}
		um.UserInputMessage.UserInputMessageContext.ToolResults = nil
		history[i] = um
		log.Printf("Converted %d orphaned toolResults to text at history[%d]", len(parts), i)
	}
	return history
}

// trimHistoryToFit drops oldest history pairs until the serialized request fits within maxRequestBytes.
// Re-validates structure after trimming.
func trimHistoryToFit(cwReq *CodeWhispererRequest) {
	trimmed := false

	// Enforce max request size
	for {
		reqBytes, err := json.Marshal(cwReq)
		if err != nil || len(reqBytes) <= maxRequestBytes {
			break
		}
		history := cwReq.ConversationState.History
		if len(history) <= 2 {
			log.Printf("WARNING: Request size %d exceeds limit %d but cannot trim further (history len=%d)",
				len(reqBytes), maxRequestBytes, len(history))
			break
		}
		log.Printf("Request size %d exceeds %d, dropping oldest history pair (remaining=%d)",
			len(reqBytes), maxRequestBytes, len(history)-2)
		cwReq.ConversationState.History = history[2:]
		trimmed = true
	}

	// Re-validate structure after trimming
	if trimmed {
		h := cwReq.ConversationState.History
		h = ensureAssistantBeforeToolResults(h)
		h = ensureFirstMessageIsUser(h)
		h = ensureAlternatingRoles(h)
		cwReq.ConversationState.History = h
	}
}

func buildCodeWhispererRequest(anthropicReq AnthropicRequest) CodeWhispererRequest {
	// 使用从kiro-cli读取的profile ARN，如果没有则从环境变量读取
	profileArn := kiroCliProfileArn
	if profileArn == "" {
		profileArn = os.Getenv("CODEWHISPERER_PROFILE_ARN")
	}
	if profileArn == "" {
		log.Fatal("Profile ARN not found. Set CODEWHISPERER_PROFILE_ARN environment variable or ensure kiro-cli is configured.")
	}
	cwReq := CodeWhispererRequest{
		ProfileArn: profileArn,
	}
	cwReq.ConversationState.ChatTriggerType = "MANUAL"
	cwReq.ConversationState.ConversationId = generateUUID()
	cwReq.ConversationState.AgentContinuationId = generateUUID()
	cwReq.ConversationState.AgentTaskType = "vibe"

	// 获取最后一条消息的内容
	lastMsg := anthropicReq.Messages[len(anthropicReq.Messages)-1]
	// When sending tool results, content should be empty (matching kiro-cli behavior)
	if hasToolResult(lastMsg.Content) {
		cwReq.ConversationState.CurrentMessage.UserInputMessage.Content = ""
	} else {
		cwReq.ConversationState.CurrentMessage.UserInputMessage.Content = getMessageContent(lastMsg.Content)
	}
	// Map Anthropic model to CodeWhisperer model, fallback to "auto"
	modelId := "auto"
	if mappedModel, ok := ModelMap[anthropicReq.Model]; ok {
		modelId = mappedModel
		log.Printf("Model mapping: %s -> %s", anthropicReq.Model, mappedModel)
	} else {
		log.Printf("Model not in map, using auto. Requested: %s", anthropicReq.Model)
	}
	cwReq.ConversationState.CurrentMessage.UserInputMessage.ModelId = modelId
	// Use KIRO_CLI origin like kiro-cli does
	cwReq.ConversationState.CurrentMessage.UserInputMessage.Origin = "KIRO_CLI"

	// cwd extraction for history messages
	cwd := extractCwdFromSystemPrompt(anthropicReq.System)
	cwReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.EnvState = &EnvState{
		OperatingSystem:         goosToQApi(runtime.GOOS),
		CurrentWorkingDirectory: cwd,
	}

	// 处理 tools 信息
	var tools []CodeWhispererTool
	for _, tool := range anthropicReq.Tools {
		cwTool := CodeWhispererTool{}
		cwTool.ToolSpecification.Name = tool.Name
		cwTool.ToolSpecification.Description = tool.Description
		cwTool.ToolSpecification.InputSchema = InputSchema{
			Json: sanitizeJsonSchema(tool.InputSchema),
		}
		tools = append(tools, cwTool)
	}

	// Add thinking tool when thinking is enabled (matching kiro-cli behavior)
	// The Q API implements thinking as a tool, not as a native parameter
	if anthropicReq.Thinking != nil && anthropicReq.Thinking.Type == "enabled" {
		log.Printf("Thinking enabled with budget_tokens=%d, adding thinking tool", anthropicReq.Thinking.BudgetTokens)
		thinkingTool := CodeWhispererTool{}
		thinkingTool.ToolSpecification.Name = "thinking"
		thinkingTool.ToolSpecification.Description = "Thinking is an internal reasoning mechanism improving the quality of complex tasks by breaking their atomic actions down; use it specifically for multi-step problems requiring step-by-step dependencies, reasoning through multiple constraints, synthesizing results from previous tool calls, planning intricate sequences of actions, troubleshooting complex errors, or making decisions involving multiple trade-offs. Avoid using it for straightforward tasks, basic information retrieval, summaries, always clearly define the reasoning challenge, structure thoughts explicitly, consider multiple perspectives, and summarize key insights before important decisions or complex tool interactions."
		thinkingTool.ToolSpecification.InputSchema = InputSchema{
			Json: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"thought": map[string]any{
						"type":        "string",
						"description": "A reflective note or intermediate reasoning step such as \"The user needs to prepare their application for production. I need to complete three major asks including 1: building their code from source, 2: bundling their release artifacts together, and 3: signing the application bundle.",
					},
				},
				"required": []string{"thought"},
			},
		}
		tools = append(tools, thinkingTool)
	}

	if len(tools) > 0 {
		cwReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.Tools = tools
	}

	// Add toolResults to currentMessage when last message contains tool_result (matching kiro-cli)
	if hasToolResult(lastMsg.Content) {
		toolResults := extractToolResults(lastMsg.Content)
		if len(toolResults) > 0 {
			cwReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.ToolResults = toolResults
		}
	}

	// 构建历史消息
	// 先处理 system 消息或者常规历史消息
	if len(anthropicReq.System) > 0 || len(anthropicReq.Messages) > 1 {
		var history []any

		// Check if we have tool results (meaning this is a continuation after tool use)
		hasToolResultInMessages := hasToolResult(lastMsg.Content)

		// Concatenate system prompt for prepending to first user message later
		var systemPrompt string
		if len(anthropicReq.System) > 0 && !hasToolResultInMessages {
			var parts []string
			for _, sysMsg := range anthropicReq.System {
				parts = append(parts, sysMsg.Text)
			}
			systemPrompt = strings.Join(parts, "\n\n")
		}

		// 然后处理常规消息历史 - 确保严格交替 user/assistant
		// CodeWhisperer要求历史记录必须是 user -> assistant -> user -> assistant 的顺序
		var pendingUserContent []string
		for i := 0; i < len(anthropicReq.Messages)-1; i++ {
			msg := anthropicReq.Messages[i]
			if msg.Role == "user" {
				// Check if this user message contains tool results
				if hasToolResult(msg.Content) {
					// For tool_result messages, set content to "" and add toolResults
					toolResults := extractToolResults(msg.Content)
					userMsg := HistoryUserMessage{}
					userMsg.UserInputMessage.Content = "" // Empty when sending tool results
					userMsg.UserInputMessage.Origin = "KIRO_CLI"
					userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
						EnvState: &EnvState{
							OperatingSystem:         goosToQApi(runtime.GOOS),
							CurrentWorkingDirectory: cwd,
						},
						ToolResults: toolResults,
					}
					history = append(history, userMsg)
					pendingUserContent = nil // Clear any pending content

					// Check if the NEXT message is also a user message (not assistant)
					// This can happen when user provides tool_result then sends a new text message
					// CodeWhisperer requires strict alternation, so we need a synthetic assistant between them
					if i+1 < len(anthropicReq.Messages)-1 && anthropicReq.Messages[i+1].Role == "user" {
						log.Printf("DEBUG: Two consecutive user messages detected (tool_result followed by user text), adding synthetic assistant")
						syntheticAssistant := HistoryAssistantMessage{}
						syntheticAssistant.AssistantResponseMessage.MessageId = generateUUID()
						syntheticAssistant.AssistantResponseMessage.Content = "I see the tool results. How would you like me to proceed?"
						history = append(history, syntheticAssistant)
					}
					continue
				}

				// 收集用户消息内容
				content := getMessageContent(msg.Content)
				if content != "" {
					pendingUserContent = append(pendingUserContent, content)
				}

				// 检查下一条消息是否是助手回复
				if i+1 < len(anthropicReq.Messages)-1 && anthropicReq.Messages[i+1].Role == "assistant" {
					nextMsg := anthropicReq.Messages[i+1]
					assistantContent := getMessageContent(nextMsg.Content)

					// Extract tool uses from assistant message
					toolUses := extractToolUses(nextMsg.Content)

					// Include assistant message if it has text OR tool uses (matching kiro-cli behavior)
					if assistantContent != "" || len(toolUses) > 0 {
						// 添加合并的用户消息
						if len(pendingUserContent) > 0 {
							userMsg := HistoryUserMessage{}
							userMsg.UserInputMessage.Content = strings.Join(pendingUserContent, "\n")
							userMsg.UserInputMessage.Origin = "KIRO_CLI"
							userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
								EnvState: &EnvState{
									OperatingSystem:         goosToQApi(runtime.GOOS),
									CurrentWorkingDirectory: cwd,
								},
							}
							history = append(history, userMsg)
							pendingUserContent = nil // 清空
						}

						assistantMsg := HistoryAssistantMessage{}
						// kiro-cli ALWAYS sets messageId for assistant messages
						assistantMsg.AssistantResponseMessage.MessageId = generateUUID()
						// Only set ToolUses when there are tools (kiro-cli omits this field when empty)
						if len(toolUses) > 0 {
							assistantMsg.AssistantResponseMessage.ToolUses = toolUses
						}
						// ToolUses left nil when no tools - omitempty will exclude it from JSON
						assistantMsg.AssistantResponseMessage.Content = assistantContent
						history = append(history, assistantMsg)
					}
					// If no text and no tool uses, keep user content in pending - will be merged with next
					i++ // 跳过已处理的助手消息
				}
			} else if msg.Role == "assistant" {
				assistantContent := getMessageContent(msg.Content)
				toolUses := extractToolUses(msg.Content)

				// Include assistant message if it has text OR tool uses
				if assistantContent != "" || len(toolUses) > 0 {
					// Check if we have pending user content AND this assistant has toolUses
					// This is the abort scenario: user sent new message before providing tool results
					// We need to: add assistant with toolUses -> add user with cancelled results -> keep pending for currentMessage
					if len(pendingUserContent) > 0 && len(toolUses) > 0 {
						// Abort scenario detected: assistant has toolUses but user sent new message without tool_result
						log.Printf("DEBUG: Abort scenario detected - assistant has toolUses but pending user content exists")
						
						// First add the assistant message with toolUses
						assistantMsg := HistoryAssistantMessage{}
						assistantMsg.AssistantResponseMessage.MessageId = generateUUID()
						assistantMsg.AssistantResponseMessage.ToolUses = toolUses
						assistantMsg.AssistantResponseMessage.Content = assistantContent
						history = append(history, assistantMsg)
						
						// Then add user message with cancelled tool results
						var cancelledResults []map[string]any
						for _, toolUse := range toolUses {
							if tu, ok := toolUse.(map[string]any); ok {
								if toolUseId, ok := tu["toolUseId"].(string); ok {
									cancelledResults = append(cancelledResults, map[string]any{
										"toolUseId": toolUseId,
										"content":   []map[string]any{{"text": "Tool use was cancelled by the user"}},
										"status":    "error",
									})
								}
							}
						}
						userMsg := HistoryUserMessage{}
						userMsg.UserInputMessage.Content = ""
						userMsg.UserInputMessage.Origin = "KIRO_CLI"
						userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
							EnvState: &EnvState{
								OperatingSystem:         goosToQApi(runtime.GOOS),
								CurrentWorkingDirectory: cwd,
							},
							ToolResults: cancelledResults,
						}
						history = append(history, userMsg)
						log.Printf("DEBUG: Added assistant with toolUses and user with %d cancelled results, pending content kept for currentMessage", len(cancelledResults))
						// Keep pendingUserContent - it will go to currentMessage
						continue
					}
					
					// Normal case: add pending user content first, then assistant
					if len(pendingUserContent) > 0 {
						userMsg := HistoryUserMessage{}
						userMsg.UserInputMessage.Content = strings.Join(pendingUserContent, "\n")
						userMsg.UserInputMessage.Origin = "KIRO_CLI"
						userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
							EnvState: &EnvState{
								OperatingSystem:         goosToQApi(runtime.GOOS),
								CurrentWorkingDirectory: cwd,
							},
						}
						history = append(history, userMsg)
						pendingUserContent = nil
					}

					assistantMsg := HistoryAssistantMessage{}
					// kiro-cli ALWAYS sets messageId for assistant messages
					assistantMsg.AssistantResponseMessage.MessageId = generateUUID()
					// Only set ToolUses when there are tools (kiro-cli omits this field when empty)
					if len(toolUses) > 0 {
						assistantMsg.AssistantResponseMessage.ToolUses = toolUses
					}
					// ToolUses left nil when no tools - omitempty will exclude it from JSON
					assistantMsg.AssistantResponseMessage.Content = assistantContent
					history = append(history, assistantMsg)
				}
				// If no text and no tool uses, keep pending user content for merging with next
			}
		}

		// Check if last history entry is assistant with toolUses - need to add cancelled tool results
		// This check must run INDEPENDENTLY of pendingUserContent because the paired processing
		// at lines 871-907 clears pendingUserContent, but may leave history ending with an assistant
		// that has toolUses without a corresponding user message with toolResults.
		// IMPORTANT: Only do this if lastMsg does NOT contain real tool_results - if it does,
		// the real results go to currentMessage and we don't need cancelled results in history.
		if !hasToolResult(lastMsg.Content) {
			var cancelledResults []map[string]any
			if len(history) > 0 {
				if lastAssistant, ok := history[len(history)-1].(HistoryAssistantMessage); ok {
					if len(lastAssistant.AssistantResponseMessage.ToolUses) > 0 {
						log.Printf("DEBUG: Found orphaned tool calls in history (no tool_result in lastMsg), generating cancelled tool results")
						for _, toolUse := range lastAssistant.AssistantResponseMessage.ToolUses {
							if tu, ok := toolUse.(map[string]any); ok {
								if toolUseId, ok := tu["toolUseId"].(string); ok {
									cancelledResult := map[string]any{
										"toolUseId": toolUseId,
										"content": []map[string]any{
											{"text": "Tool use was cancelled by the user"},
										},
										"status": "error",
									}
									cancelledResults = append(cancelledResults, cancelledResult)
								}
							}
						}
						log.Printf("DEBUG: Generated %d cancelled tool results", len(cancelledResults))
					}
				}
			}

			// If we have cancelled tool results, add a user message with them
			if len(cancelledResults) > 0 {
				userMsg := HistoryUserMessage{}
				userMsg.UserInputMessage.Content = ""
				userMsg.UserInputMessage.Origin = "KIRO_CLI"
				userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
					EnvState: &EnvState{
						OperatingSystem:         goosToQApi(runtime.GOOS),
						CurrentWorkingDirectory: cwd,
					},
					ToolResults: cancelledResults,
				}
				history = append(history, userMsg)
				log.Printf("DEBUG: Added user message with cancelled tool results")
			}
		}

		// 处理最后剩余的pending用户消息
		// Note: We don't add a default assistant response here because that would be
		// artificial content that the model might mimic. The pending user content
		// will be part of the current request context instead.
		if len(pendingUserContent) > 0 {
			userMsg := HistoryUserMessage{}
			userMsg.UserInputMessage.Content = strings.Join(pendingUserContent, "\n")
			userMsg.UserInputMessage.Origin = "KIRO_CLI"
			userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
				EnvState: &EnvState{
					OperatingSystem:         goosToQApi(runtime.GOOS),
					CurrentWorkingDirectory: cwd,
				},
			}
			history = append(history, userMsg)
		}

		// Handle abort scenario: if the LAST message in anthropicReq.Messages is an assistant with toolUses,
		// it was excluded from the loop (which processes messages 0 to len-2). We need to add it to history
		// along with cancelled tool results. This happens when user aborts a tool call and sends a new message.
		if lastMsg.Role == "assistant" {
			toolUses := extractToolUses(lastMsg.Content)
			if len(toolUses) > 0 {
				log.Printf("DEBUG: Last message is assistant with %d toolUses (abort scenario), adding to history with cancelled results", len(toolUses))
				// Add the assistant message with toolUses to history
				assistantMsg := HistoryAssistantMessage{}
				assistantMsg.AssistantResponseMessage.MessageId = generateUUID()
				assistantMsg.AssistantResponseMessage.Content = getMessageContent(lastMsg.Content)
				assistantMsg.AssistantResponseMessage.ToolUses = toolUses
				history = append(history, assistantMsg)

				// Add user message with cancelled tool results
				var cancelledResults []map[string]any
				for _, toolUse := range toolUses {
					if tu, ok := toolUse.(map[string]any); ok {
						if toolUseId, ok := tu["toolUseId"].(string); ok {
							cancelledResults = append(cancelledResults, map[string]any{
								"toolUseId": toolUseId,
								"content":   []map[string]any{{"text": "Tool use was cancelled by the user"}},
								"status":    "error",
							})
						}
					}
				}
				if len(cancelledResults) > 0 {
					userMsg := HistoryUserMessage{}
					userMsg.UserInputMessage.Content = ""
					userMsg.UserInputMessage.Origin = "KIRO_CLI"
					userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
						EnvState: &EnvState{
							OperatingSystem:         goosToQApi(runtime.GOOS),
							CurrentWorkingDirectory: cwd,
						},
						ToolResults: cancelledResults,
					}
					history = append(history, userMsg)
					log.Printf("DEBUG: Added assistant with toolUses and user with %d cancelled results for abort scenario", len(cancelledResults))
				}
			}
		}

		// Prepend system prompt to the first user message in history (matching kiro-gateway behavior)
		if systemPrompt != "" && len(history) > 0 {
			for i, h := range history {
				if um, ok := h.(HistoryUserMessage); ok {
					um.UserInputMessage.Content = systemPrompt + "\n\n" + um.UserInputMessage.Content
					history[i] = um
					log.Printf("Prepended system prompt to history[%d]", i)
					break
				}
			}
		}

		// Validation pipeline: ensure proper message structure
		history = ensureAssistantBeforeToolResults(history)
		history = ensureFirstMessageIsUser(history)
		history = ensureAlternatingRoles(history)

		cwReq.ConversationState.History = history

		// Trim history if request is too large
		trimHistoryToFit(&cwReq)

		log.Printf("DEBUG buildCodeWhispererRequest: history length=%d", len(cwReq.ConversationState.History))
		for idx, h := range cwReq.ConversationState.History {
			if hBytes, err := json.Marshal(h); err == nil {
				log.Printf("DEBUG history[%d]: %s", idx, string(hBytes)[:min(200, len(string(hBytes)))])
			}
		}
	}

	return cwReq
}

// buildThinkingContinuationRequest creates a continuation request for automatic thinking tool handling
// When Q API returns a thinking tool call, we need to automatically send back an empty tool result
// to continue the conversation and get the actual text response
func buildThinkingContinuationRequest(prevReq CodeWhispererRequest, thinkingToolId string, thinkingInput string) CodeWhispererRequest {
	// Deep copy the history slice to avoid modifying the original
	newHistory := make([]any, len(prevReq.ConversationState.History))
	copy(newHistory, prevReq.ConversationState.History)

	// Preserve the tools array from the previous request
	prevTools := prevReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.Tools
	prevEnvState := prevReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.EnvState

	// CRITICAL: History must alternate user → assistant → user → assistant
	// First, add the previous currentMessage to history as a userInputMessage
	// This is the user message that triggered the thinking tool call
	prevUserContent := prevReq.ConversationState.CurrentMessage.UserInputMessage.Content
	prevUserToolResults := prevReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.ToolResults

	// Build user message for history (matching kiro-cli format)
	userMsg := HistoryUserMessage{}
	userMsg.UserInputMessage.Content = prevUserContent // Can be empty if sending tool results
	userMsg.UserInputMessage.Origin = "KIRO_CLI"
	userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
		EnvState: prevEnvState,
	}
	// If the previous request had tool results, include them in history
	if len(prevUserToolResults) > 0 {
		userMsg.UserInputMessage.UserInputMessageContext.ToolResults = prevUserToolResults
	}
	newHistory = append(newHistory, userMsg)

	// Now add assistant message with thinking tool use to history
	// This records the model's thinking tool call
	assistantMsg := HistoryAssistantMessage{}
	assistantMsg.AssistantResponseMessage.MessageId = generateUUID()
	assistantMsg.AssistantResponseMessage.Content = ""
	assistantMsg.AssistantResponseMessage.ToolUses = []any{
		map[string]any{
			"toolUseId": thinkingToolId,
			"name":      "thinking",
			"input": map[string]any{
				"thought": thinkingInput,
			},
		},
	}
	newHistory = append(newHistory, assistantMsg)

	// Create new request with updated fields
	newReq := prevReq
	newReq.ConversationState.History = newHistory

	// Set current message with empty tool result (matching kiro-cli behavior)
	// The content is empty when sending tool results
	newReq.ConversationState.CurrentMessage.UserInputMessage.Content = ""
	newReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.ToolResults = []map[string]any{
		{
			"toolUseId": thinkingToolId,
			"content": []map[string]any{
				{"text": ""},
			},
			"status": "success",
		},
	}
	// Preserve tools and envState in the continuation request
	newReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.Tools = prevTools
	newReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.EnvState = prevEnvState

	// Generate new continuation ID for this round
	newReq.ConversationState.AgentContinuationId = generateUUID()

	log.Printf("Built thinking continuation request: thinkingToolId=%s, historyLen=%d, toolsCount=%d",
		thinkingToolId, len(newReq.ConversationState.History), len(prevTools))

	return newReq
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法:")
		fmt.Println("  kiro2cc read    - 读取并显示token")
		fmt.Println("  kiro2cc refresh - 刷新token")
		fmt.Println("  kiro2cc export  - 导出环境变量")
		fmt.Println("  kiro2cc claude  - 跳过 claude 地区限制")
		fmt.Println("  kiro2cc server [port] - 启动Anthropic API代理服务器")
		fmt.Println("  author https://github.com/bestK/kiro2cc")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "read":
		readToken()
	case "refresh":
		refreshToken()
	case "export":
		exportEnvVars()

	case "claude":
		setClaude()
	case "server":
		port := "8080" // 默认端口
		if len(os.Args) > 2 {
			port = os.Args[2]
		}
		startServer(port)
	default:
		fmt.Printf("未知命令: %s\n", command)
		os.Exit(1)
	}
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

// logMiddleware 记录所有HTTP请求的中间件
func logMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// DEBUG_ACCESS_LOG=1 enables detailed access logging
		if os.Getenv("DEBUG_ACCESS_LOG") == "1" || os.Getenv("DEBUG_ACCESS_LOG") == "true" {
			fmt.Printf("\n=== 收到请求 ===\n")
			fmt.Printf("时间: %s\n", startTime.Format("2006-01-02 15:04:05"))
			fmt.Printf("请求方法: %s\n", r.Method)
			fmt.Printf("请求路径: %s\n", r.URL.Path)
			fmt.Printf("客户端IP: %s\n", r.RemoteAddr)
		}

		// 调用下一个处理器
		next(w, r)

		// 计算处理时间
		duration := time.Since(startTime)
		fmt.Printf("处理时间: %v\n", duration)
		fmt.Printf("=== 请求结束 ===\n\n")
	}
}

// startServer 启动HTTP代理服务器
func startServer(port string) {
	// 创建路由器
	mux := http.NewServeMux()

	// 注册所有端点
	mux.HandleFunc("/v1/messages", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// 只处理POST请求
		if r.Method != http.MethodPost {
			fmt.Printf("错误: 不支持的请求方法\n")
			http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
			return
		}

		// 获取当前token
		token, err := getToken()
		if err != nil {
			fmt.Printf("错误: 获取token失败: %v\n", err)
			http.Error(w, fmt.Sprintf("获取token失败: %v", err), http.StatusInternalServerError)
			return
		}

		// 读取请求体
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("错误: 读取请求体失败: %v\n", err)
			http.Error(w, fmt.Sprintf("读取请求体失败: %v", err), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		fmt.Printf("\n=========================Anthropic 请求体:\n%s\n=======================================\n", string(body))

		// 解析 Anthropic 请求
		var anthropicReq AnthropicRequest
		if err := json.Unmarshal(body, &anthropicReq); err != nil {
			fmt.Printf("错误: 解析请求体失败: %v\n", err)
			http.Error(w, fmt.Sprintf("解析请求体失败: %v", err), http.StatusBadRequest)
			return
		}

		// 基础校验，给出明确的错误提示
		if anthropicReq.Model == "" {
			http.Error(w, `{"message":"Missing required field: model"}`, http.StatusBadRequest)
			return
		}
		if len(anthropicReq.Messages) == 0 {
			http.Error(w, `{"message":"Missing required field: messages"}`, http.StatusBadRequest)
			return
		}
		if _, ok := ModelMap[anthropicReq.Model]; !ok {
			// 提示可用的模型名称
			available := make([]string, 0, len(ModelMap))
			for k := range ModelMap {
				available = append(available, k)
			}
			http.Error(w, fmt.Sprintf("{\"message\":\"Unknown or unsupported model: %s\",\"availableModels\":[%s]}", anthropicReq.Model, "\""+strings.Join(available, "\",\"")+"\""), http.StatusBadRequest)
			return
		}

		// 如果是流式请求
		if anthropicReq.Stream {
			handleStreamRequest(w, anthropicReq, token.AccessToken)
			return
		}

		// 非流式请求处理
		handleNonStreamRequest(w, anthropicReq, token.AccessToken)
	}))

	// 添加 /v1/models 端点
	mux.HandleFunc("/v1/models", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只支持GET请求", http.StatusMethodNotAllowed)
			return
		}
		models := []map[string]string{
			{"id": "claude-sonnet-4.5", "type": "model", "display_name": "Claude Sonnet 4.5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-sonnet-4", "type": "model", "display_name": "Claude Sonnet 4", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-haiku-4.5", "type": "model", "display_name": "Claude Haiku 4.5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-opus-4.5", "type": "model", "display_name": "Claude Opus 4.5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-opus-4.6", "type": "model", "display_name": "Claude Opus 4.6", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-sonnet-4.6", "type": "model", "display_name": "Claude Sonnet 4.6", "created_at": "2025-01-01T00:00:00Z"},
		}
		resp := map[string]any{
			"data":     models,
			"has_more": false,
			"first_id": "claude-sonnet-4.5",
			"last_id":  "claude-opus-4.6",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	// 添加健康检查端点
	mux.HandleFunc("/health", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// 添加404处理
	mux.HandleFunc("/", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("警告: 访问未知端点\n")
		http.Error(w, "404 未找到", http.StatusNotFound)
	}))

	// 启动服务器
	fmt.Printf("启动Anthropic API代理服务器，监听端口: %s\n", port)
	fmt.Printf("可用端点:\n")
	fmt.Printf("  POST /v1/messages - Anthropic API代理\n")
	fmt.Printf("  GET  /v1/models   - 获取可用模型列表\n")
	fmt.Printf("  GET  /health      - 健康检查\n")
	fmt.Printf("按Ctrl+C停止服务器\n")

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Printf("启动服务器失败: %v\n", err)
		os.Exit(1)
	}
}

// sendQApiRequest sends a request to Q API and returns the response body
// Returns (responseBody, error)
func sendQApiRequest(cwReq CodeWhispererRequest, accessToken string) ([]byte, error) {
	cwReqBody, err := json.Marshal(cwReq)
	if err != nil {
		return nil, fmt.Errorf("serialize request failed: %w", err)
	}

	proxyReq, err := http.NewRequest(
		http.MethodPost,
		getQApiEndpoint(),
		bytes.NewBuffer(cwReqBody),
	)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	proxyReq.Header.Set("Authorization", "Bearer "+accessToken)
	proxyReq.Header.Set("Content-Type", "application/x-amz-json-1.0")
	proxyReq.Header.Set("x-amz-target", "AmazonCodeWhispererStreamingService.GenerateAssistantResponse")
	proxyReq.Header.Set("x-amzn-codewhisperer-optout", "false")
	proxyReq.Header.Set("User-Agent", "aws-sdk-rust/1.3.10 ua/2.1 api/codewhispererstreaming/0.1.12842 os/linux lang/go app/kiro2cc")
	proxyReq.Header.Set("Accept", "*/*")

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// handleStreamRequest 处理流式请求
func handleStreamRequest(w http.ResponseWriter, anthropicReq AnthropicRequest, accessToken string) {
	// 设置SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	messageId := fmt.Sprintf("msg_%s", time.Now().Format("20060102150405"))

	// 构建 CodeWhisperer 请求
	cwReq := buildCodeWhispererRequest(anthropicReq)

	// 序列化请求体
	cwReqBody, err := json.Marshal(cwReq)
	if err != nil {
		sendErrorEvent(w, flusher, "序列化请求失败", err)
		return
	}

	fmt.Printf("CodeWhisperer 流式请求体:\n%s\n", string(cwReqBody))

	// 创建流式请求 - 使用Q API endpoint (like kiro-cli)
	proxyReq, err := http.NewRequest(
		http.MethodPost,
		getQApiEndpoint(),
		bytes.NewBuffer(cwReqBody),
	)
	if err != nil {
		sendErrorEvent(w, flusher, "创建代理请求失败", err)
		return
	}

	// 设置请求头 (matching kiro-cli format)
	proxyReq.Header.Set("Authorization", "Bearer "+accessToken)
	proxyReq.Header.Set("Content-Type", "application/x-amz-json-1.0")
	proxyReq.Header.Set("x-amz-target", "AmazonCodeWhispererStreamingService.GenerateAssistantResponse")
	proxyReq.Header.Set("x-amzn-codewhisperer-optout", "false")
	proxyReq.Header.Set("User-Agent", "aws-sdk-rust/1.3.10 ua/2.1 api/codewhispererstreaming/0.1.12842 os/linux lang/go app/kiro2cc")
	proxyReq.Header.Set("Accept", "*/*")

	// 发送请求
	client := &http.Client{}

	resp, err := client.Do(proxyReq)
	if err != nil {
		sendErrorEvent(w, flusher, "CodeWhisperer reqeust error", fmt.Errorf("reqeust error: %s", err.Error()))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("CodeWhisperer 响应错误，状态码: %d, 响应: %s\n", resp.StatusCode, string(body))

		if resp.StatusCode == 403 {
			log.Printf("收到403错误，尝试刷新token并重试...")
			if err := tryRefreshToken(); err != nil {
				log.Printf("刷新token失败: %v", err)
				sendErrorEvent(w, flusher, "Token刷新失败", err)
				return
			}
			// 获取新token并重试
			newToken, err := getToken()
			if err != nil {
				sendErrorEvent(w, flusher, "获取新token失败", err)
				return
			}
			// 递归调用自己重试请求
			handleStreamRequest(w, anthropicReq, newToken.AccessToken)
			return
		} else if isRetryableStatusCode(resp.StatusCode) {
			// Retry for 429 (rate limit) and 5xx (server errors)
			for attempt := 0; attempt < maxRetries; attempt++ {
				delay := calculateRetryDelay(attempt)
				log.Printf("收到%d错误，%v后重试 (尝试 %d/%d)...", resp.StatusCode, delay, attempt+1, maxRetries)
				time.Sleep(delay)

				// Recreate request for retry - use Q API endpoint
				retryReq, err := http.NewRequest(
					http.MethodPost,
					getQApiEndpoint(),
					bytes.NewBuffer(cwReqBody),
				)
				if err != nil {
					continue
				}
				retryReq.Header.Set("Authorization", "Bearer "+accessToken)
				retryReq.Header.Set("Content-Type", "application/x-amz-json-1.0")
				retryReq.Header.Set("x-amz-target", "AmazonCodeWhispererStreamingService.GenerateAssistantResponse")
				retryReq.Header.Set("x-amzn-codewhisperer-optout", "false")
				retryReq.Header.Set("User-Agent", "aws-sdk-rust/1.3.10 ua/2.1 api/codewhispererstreaming/0.1.12842 os/linux lang/go app/kiro2cc")
				retryReq.Header.Set("Accept", "*/*")

				retryResp, err := client.Do(retryReq)
				if err != nil {
					continue
				}

				if retryResp.StatusCode == http.StatusOK {
					// Success! Replace resp with retryResp and continue processing
					resp.Body.Close()
					resp = retryResp
					goto processResponse
				}
				retryResp.Body.Close()

				if !isRetryableStatusCode(retryResp.StatusCode) {
					// Non-retryable error
					retryBody, _ := io.ReadAll(retryResp.Body)
					sendErrorEvent(w, flusher, "CodeWhisperer请求失败", fmt.Errorf("状态码: %d, 响应: %s", retryResp.StatusCode, string(retryBody)))
					return
				}
			}
			sendErrorEvent(w, flusher, "CodeWhisperer请求失败", fmt.Errorf("重试%d次后仍失败，最后状态码: %d", maxRetries, resp.StatusCode))
			return
		} else {
			sendErrorEvent(w, flusher, "CodeWhisperer请求失败", fmt.Errorf("状态码: %d, 响应: %s", resp.StatusCode, string(body)))
		}
		return
	}

processResponse:

	// 先读取整个响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		sendErrorEvent(w, flusher, "error", fmt.Errorf("CodeWhisperer Error 读取响应失败"))
		return
	}

	// Save raw response for debugging if DEBUG_SAVE_RAW environment variable is set
	if os.Getenv("DEBUG_SAVE_RAW") == "true" || os.Getenv("DEBUG_SAVE_RAW") == "1" {
		os.WriteFile(messageId+"response.raw", respBody, 0644)
		log.Printf("Debug: 保存响应到 %sresponse.raw", messageId)
	}
	log.Printf("响应体大小: %d bytes", len(respBody))

	// Use ParseEventsWithThinking for automatic thinking continuation
	parseResult := parser.ParseEventsWithThinking(respBody)

	if len(parseResult.Events) > 0 {
		// Send message_start once at the beginning
		messageStart := map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"id":            messageId,
				"type":          "message",
				"role":          "assistant",
				"content":       []any{},
				"model":         anthropicReq.Model,
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage": map[string]any{
					"input_tokens":  estimateInputTokens(anthropicReq),
					"output_tokens": 1,
				},
			},
		}
		sendSSEEvent(w, flusher, "message_start", messageStart)
		sendSSEEvent(w, flusher, "ping", map[string]string{"type": "ping"})

		// Note: content_block_start events are now generated by the parser
		// Thinking gets index 0 (if present), text gets index 1 (or 0 if no thinking)
		// This ensures thinking appears before text in the output
	}

	// Continuation loop for automatic thinking handling
	outputTokens := 0
	hasRegularToolUse := false
	continuationCount := 0
	maxContinuations := 10 // Safety limit to prevent infinite loops
	textIndex := parseResult.TextIndex // Track text index (0 if no thinking, 1 if thinking present)

	for continuationCount < maxContinuations {
		continuationCount++

		// Stream events to client (skip message_delta, we'll send our own at the end)
		for _, e := range parseResult.Events {
			if e.Event == "" || e.Data == nil {
				continue
			}
			if e.Event == "message_delta" {
				continue
			}

			sendSSEEvent(w, flusher, e.Event, e.Data)

			// Count output tokens from text deltas
			if e.Event == "content_block_delta" {
				if dataMap, ok := e.Data.(map[string]interface{}); ok {
					if delta, ok := dataMap["delta"].(map[string]interface{}); ok {
						if text, ok := delta["text"].(string); ok {
							outputTokens += len(text)
						}
					}
				}
			}

			time.Sleep(time.Duration(rand.Intn(20)) * time.Millisecond)
		}

		// Check if we need to continue (thinking tool without regular tools)
		if parseResult.ThinkingToolId != "" && !parseResult.HasRegularTools {
			log.Printf("Thinking tool detected (id=%s), sending continuation...", parseResult.ThinkingToolId)

			// Build continuation request with empty thinking tool result
			cwReq = buildThinkingContinuationRequest(cwReq, parseResult.ThinkingToolId, parseResult.ThinkingInput)

			// Send continuation request to Q API
			contRespBody, contErr := sendQApiRequest(cwReq, accessToken)
			if contErr != nil {
				log.Printf("Thinking continuation failed: %v", contErr)
				// Don't fail completely, just end the response
				break
			}

			// Debug: save continuation response
			if os.Getenv("DEBUG_SAVE_RAW") == "true" || os.Getenv("DEBUG_SAVE_RAW") == "1" {
				contFile := fmt.Sprintf("%s_continuation_%d.raw", messageId, continuationCount)
				os.WriteFile(contFile, contRespBody, 0644)
				log.Printf("Debug: 保存continuation响应到 %s", contFile)
			}

			// Parse continuation response
			parseResult = parser.ParseEventsWithThinking(contRespBody)
			log.Printf("Continuation %d: events=%d, thinking=%s, hasRegularTools=%v",
				continuationCount, len(parseResult.Events), parseResult.ThinkingToolId, parseResult.HasRegularTools)

			// Continue to next iteration to process continuation events
			continue
		}

		// No thinking or has regular tools - we're done with continuation
		hasRegularToolUse = parseResult.HasRegularTools
		break
	}

	if continuationCount >= maxContinuations {
		log.Printf("Warning: reached max continuations (%d)", maxContinuations)
	}

	// Close text content block at the correct index
	// textIndex is 0 if no thinking, 1 if thinking is present
	contentBlockStop := map[string]any{"index": textIndex, "type": "content_block_stop"}
	sendSSEEvent(w, flusher, "content_block_stop", contentBlockStop)

	// Send appropriate stop reason
	// Only use "tool_use" if there are regular (non-thinking) tools
	stopReason := "end_turn"
	if hasRegularToolUse {
		stopReason = "tool_use"
	}
	messageDelta := map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   stopReason,
			"stop_sequence": nil,
		},
		"usage": map[string]any{"input_tokens": estimateInputTokens(anthropicReq), "output_tokens": outputTokens},
	}
	sendSSEEvent(w, flusher, "message_delta", messageDelta)

	sendSSEEvent(w, flusher, "message_stop", map[string]any{"type": "message_stop"})
}

// handleNonStreamRequest 处理非流式请求
func handleNonStreamRequest(w http.ResponseWriter, anthropicReq AnthropicRequest, accessToken string) {
	// 构建 CodeWhisperer 请求
	cwReq := buildCodeWhispererRequest(anthropicReq)

	// 序列化请求体
	cwReqBody, err := json.Marshal(cwReq)
	if err != nil {
		fmt.Printf("错误: 序列化请求失败: %v\n", err)
		http.Error(w, fmt.Sprintf("序列化请求失败: %v", err), http.StatusInternalServerError)
		return
	}

	// fmt.Printf("CodeWhisperer 请求体:\n%s\n", string(cwReqBody))

	// 创建请求 - 使用Q API endpoint (like kiro-cli)
	proxyReq, err := http.NewRequest(
		http.MethodPost,
		getQApiEndpoint(),
		bytes.NewBuffer(cwReqBody),
	)
	if err != nil {
		fmt.Printf("错误: 创建代理请求失败: %v\n", err)
		http.Error(w, fmt.Sprintf("创建代理请求失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 设置请求头 (matching kiro-cli format)
	proxyReq.Header.Set("Authorization", "Bearer "+accessToken)
	proxyReq.Header.Set("Content-Type", "application/x-amz-json-1.0")
	proxyReq.Header.Set("x-amz-target", "AmazonCodeWhispererStreamingService.GenerateAssistantResponse")
	proxyReq.Header.Set("x-amzn-codewhisperer-optout", "false")
	proxyReq.Header.Set("User-Agent", "aws-sdk-rust/1.3.10 ua/2.1 api/codewhispererstreaming/0.1.12842 os/linux lang/go app/kiro2cc")
	proxyReq.Header.Set("Accept", "*/*")

	// 发送请求
	client := &http.Client{}

	resp, err := client.Do(proxyReq)
	if err != nil {
		fmt.Printf("错误: 发送请求失败: %v\n", err)
		http.Error(w, fmt.Sprintf("发送请求失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 检查错误并处理重试
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == 403 {
			log.Printf("非流式请求收到403错误: %s，尝试刷新token并重试...", string(body))
			if err := tryRefreshToken(); err != nil {
				log.Printf("刷新token失败: %v", err)
				http.Error(w, fmt.Sprintf("Token刷新失败: %v", err), http.StatusUnauthorized)
				return
			}
			// 获取新token并重试
			newToken, err := getToken()
			if err != nil {
				http.Error(w, fmt.Sprintf("获取新token失败: %v", err), http.StatusInternalServerError)
				return
			}
			// 递归调用自己重试请求
			handleNonStreamRequest(w, anthropicReq, newToken.AccessToken)
			return
		} else if isRetryableStatusCode(resp.StatusCode) {
			// Retry for 429 (rate limit) and 5xx (server errors)
			for attempt := 0; attempt < maxRetries; attempt++ {
				delay := calculateRetryDelay(attempt)
				log.Printf("非流式请求收到%d错误，%v后重试 (尝试 %d/%d)...", resp.StatusCode, delay, attempt+1, maxRetries)
				time.Sleep(delay)

				// Recreate request for retry - use Q API endpoint
				retryReq, err := http.NewRequest(
					http.MethodPost,
					getQApiEndpoint(),
					bytes.NewBuffer(cwReqBody),
				)
				if err != nil {
					continue
				}
				retryReq.Header.Set("Authorization", "Bearer "+accessToken)
				retryReq.Header.Set("Content-Type", "application/x-amz-json-1.0")
				retryReq.Header.Set("x-amz-target", "AmazonCodeWhispererStreamingService.GenerateAssistantResponse")
				retryReq.Header.Set("x-amzn-codewhisperer-optout", "false")
				retryReq.Header.Set("User-Agent", "aws-sdk-rust/1.3.10 ua/2.1 api/codewhispererstreaming/0.1.12842 os/linux lang/go app/kiro2cc")
				retryReq.Header.Set("Accept", "*/*")

				retryResp, err := client.Do(retryReq)
				if err != nil {
					continue
				}

				if retryResp.StatusCode == http.StatusOK {
					// Success! Replace resp with retryResp and continue processing
					resp.Body.Close()
					resp = retryResp
					goto processNonStreamResponse
				}
				retryResp.Body.Close()

				if !isRetryableStatusCode(retryResp.StatusCode) {
					// Non-retryable error
					retryBody, _ := io.ReadAll(retryResp.Body)
					http.Error(w, fmt.Sprintf("CodeWhisperer请求失败: 状态码 %d, 响应: %s", retryResp.StatusCode, string(retryBody)), http.StatusBadGateway)
					return
				}
			}
			http.Error(w, fmt.Sprintf("CodeWhisperer请求失败: 重试%d次后仍失败，最后状态码: %d", maxRetries, resp.StatusCode), http.StatusBadGateway)
			return
		} else {
			http.Error(w, fmt.Sprintf("CodeWhisperer请求失败: 状态码 %d, 响应: %s", resp.StatusCode, string(body)), http.StatusBadGateway)
			return
		}
	}

processNonStreamResponse:
	// 读取响应
	cwRespBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("错误: 读取响应失败: %v\n", err)
		http.Error(w, fmt.Sprintf("读取响应失败: %v", err), http.StatusInternalServerError)
		return
	}

	// fmt.Printf("CodeWhisperer 响应体:\n%s\n", string(cwRespBody))

	// 保存响应体用于调试 (仅在设置了 DEBUG_SAVE_RAW 环境变量时)
	if os.Getenv("DEBUG_SAVE_RAW") == "1" || os.Getenv("DEBUG_SAVE_RAW") == "true" {
		messageId := fmt.Sprintf("msg_%s", time.Now().Format("20060102150405"))
		os.WriteFile(messageId+"_nonstream.raw", cwRespBody, 0644)
		log.Printf("非流式响应体大小: %d bytes, 保存到: %s_nonstream.raw", len(cwRespBody), messageId)
	}

	respBodyStr := string(cwRespBody)

	events := parser.ParseEvents(cwRespBody)

	context := ""
	toolName := ""
	toolUseId := ""
	currentBlockType := "" // Track what type of block we're in: "text", "tool_use", "thinking"

	contexts := []map[string]any{}

	partialJsonStr := ""
	for _, event := range events {
		if event.Data != nil {
			if dataMap, ok := event.Data.(map[string]any); ok {
				switch dataMap["type"] {
				case "content_block_start":
					// Determine block type from content_block
					currentBlockType = ""
					if cb, ok := dataMap["content_block"].(map[string]any); ok {
						if cbType, ok := cb["type"].(string); ok {
							currentBlockType = cbType
						}
						switch currentBlockType {
						case "tool_use":
							partialJsonStr = ""
							if id, ok := cb["id"].(string); ok {
								toolUseId = id
							}
							if name, ok := cb["name"].(string); ok {
								toolName = name
							}
						case "text":
							context = ""
						}
					}
				case "content_block_delta":
					if delta, ok := dataMap["delta"]; ok {

						if deltaMap, ok := delta.(map[string]any); ok {
							switch deltaMap["type"] {
							case "text_delta":
								if text, ok := deltaMap["text"]; ok {
									context += text.(string)
								}
							case "input_json_delta":
								if partial_json, ok := deltaMap["partial_json"]; ok {
									if strPtr, ok := partial_json.(*string); ok && strPtr != nil {
										partialJsonStr = partialJsonStr + *strPtr
									} else if str, ok := partial_json.(string); ok {
										partialJsonStr = partialJsonStr + str
									} else {
										log.Println("partial_json is not string or *string")
									}
								} else {
									log.Println("partial_json not found")
								}

							}
						}
					}

				case "content_block_stop":
					// Use tracked block type instead of hardcoded index
					switch currentBlockType {
					case "tool_use":
						toolInput := map[string]interface{}{}
						if partialJsonStr != "" {
							if err := json.Unmarshal([]byte(partialJsonStr), &toolInput); err != nil {
								log.Printf("json unmarshal error:%s", err.Error())
							}
						}

						contexts = append(contexts, map[string]interface{}{
							"type":  "tool_use",
							"id":    toolUseId,
							"name":  toolName,
							"input": toolInput,
						})
					case "text":
						contexts = append(contexts, map[string]interface{}{
							"text": context,
							"type": "text",
						})
					}
					currentBlockType = ""
				}

			}
		}
	}

	// 回退：如果已累积到文本但未收到 content_block_stop(index=0)，也要返回文本
	if len(contexts) == 0 && strings.TrimSpace(context) != "" {
		contexts = append(contexts, map[string]any{
			"type": "text",
			"text": context,
		})
	}
	
	// 检查是否是错误响应
	if strings.Contains(string(cwRespBody), "Improperly formed request.") {
		fmt.Printf("错误: CodeWhisperer返回格式错误: %s\n", respBodyStr)
		http.Error(w, fmt.Sprintf("请求格式错误: %s", respBodyStr), http.StatusBadRequest)
		return
	}

	// 构建 Anthropic 响应
	anthropicResp := map[string]any{
		"content":       contexts,
		"model":         anthropicReq.Model,
		"role":          "assistant",
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"type":          "message",
		"usage": map[string]any{
			"input_tokens":  estimateInputTokens(anthropicReq),
			"output_tokens": len(context),
		},
	}

	// 发送响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(anthropicResp)
}

// sendSSEEvent 发送 SSE 事件
func sendSSEEvent(w http.ResponseWriter, flusher http.Flusher, eventType string, data any) {

	json, err := json.Marshal(data)
	if err != nil {
		return
	}

	fmt.Printf("event: %s\n", eventType)
	fmt.Printf("data: %v\n\n", string(json))

	fmt.Fprintf(w, "event: %s\n", eventType)
	fmt.Fprintf(w, "data: %s\n\n", string(json))
	flusher.Flush()

}

// sendErrorEvent 发送错误事件
func sendErrorEvent(w http.ResponseWriter, flusher http.Flusher, message string, err error) {
	// Include actual error details in the message
	fullMessage := message
	if err != nil {
		fullMessage = fmt.Sprintf("%s: %v", message, err)
	}

	errorResp := map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    "api_error",
			"message": fullMessage,
		},
	}

	// Log the error for debugging
	log.Printf("发送错误事件: %s", fullMessage)

	sendSSEEvent(w, flusher, "error", errorResp)
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil // 文件或文件夹存在
	}
	if os.IsNotExist(err) {
		return false, nil // 文件或文件夹不存在
	}
	return false, err // 其他错误
}
