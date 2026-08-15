package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Retry configuration
const (
	maxRetries     = 3
	retryBaseDelay = 1 * time.Second
)

// Shared upstream HTTP client. A per-request &http.Client{} has no Timeout
// (zero value = wait forever), leaking goroutines if upstream hangs, and
// disables connection reuse. ResponseHeaderTimeout caps time-to-first-byte
// (response headers), not the streaming body duration.
var upstreamClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
	},
}

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

// getQApiEndpoint returns the Q API endpoint URL based on region
func getQApiEndpoint() string {
	region := kiroCliRegion
	if region == "" {
		region = "us-east-1"
	}
	return fmt.Sprintf("https://runtime.%s.kiro.dev/", region)
}

// responseRecorder captures HTTP response for format conversion
type responseRecorder struct {
	headers http.Header
	body    *bytes.Buffer
	pipe    *io.PipeWriter
	code    int
}

func (r *responseRecorder) Header() http.Header  { return r.headers }
func (r *responseRecorder) WriteHeader(code int) { r.code = code }
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.pipe != nil {
		return r.pipe.Write(b)
	}
	if r.body == nil {
		r.body = &bytes.Buffer{}
	}
	return r.body.Write(b)
}
func (r *responseRecorder) Flush() {
	// no-op for recorder; real flushing happens on the outer writer
}

// copyHeaders forwards captured headers (e.g. Retry-After on a 429) from a
// responseRecorder to the real writer before writing the status code.
func copyHeaders(dst http.ResponseWriter, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Header().Add(k, v)
		}
	}
}

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
	// Initialize observability database
	if err := initObservabilityDB(); err != nil {
		log.Printf("Warning: observability DB init failed: %v", err)
	}

	// Initialize Bedrock client (opt-in)
	initBedrockClient()

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
		os.WriteFile("/tmp/kiro2pi_last_request.json", body, 0644)

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
		ow := &observWriter{ResponseWriter: w, startTime: time.Now()}
		if anthropicReq.Stream {
			handleStreamRequest(ow, anthropicReq, token.AccessToken)
			logCall("/v1/messages", body, anthropicReq, true, ow)
			return
		}

		// 非流式请求处理
		handleNonStreamRequest(ow, anthropicReq, token.AccessToken)
		logCall("/v1/messages", body, anthropicReq, false, ow)
	}))

	// OpenAI-compatible /v1/chat/completions endpoint
	mux.HandleFunc("/v1/chat/completions", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
			return
		}
		token, err := getToken()
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// Parse OpenAI request
		var oaiReq struct {
			Model    string `json:"model"`
			Messages []struct {
				Role      string `json:"role"`
				Content   any    `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls,omitempty"`
				ToolCallID string `json:"tool_call_id,omitempty"`
			} `json:"messages"`
			MaxTokens   int      `json:"max_tokens"`
			Temperature *float64 `json:"temperature,omitempty"`
			Stream      bool     `json:"stream"`
			Tools       []struct {
				Type     string `json:"type"`
				Function struct {
					Name        string         `json:"name"`
					Description string         `json:"description"`
					Parameters  map[string]any `json:"parameters"`
				} `json:"function"`
			} `json:"tools,omitempty"`
			ToolChoice any `json:"tool_choice,omitempty"`
		}
		if err := json.Unmarshal(body, &oaiReq); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusBadRequest)
			return
		}

		// Convert to AnthropicRequest
		var systemMsgs FlexibleSystem
		var chatMsgs []AnthropicRequestMessage
		for _, m := range oaiReq.Messages {
			switch m.Role {
			case "system":
				text := ""
				switch v := m.Content.(type) {
				case string:
					text = v
				default:
					b, _ := json.Marshal(v)
					text = string(b)
				}
				systemMsgs = append(systemMsgs, AnthropicSystemMessage{Type: "text", Text: text})
			case "assistant":
				if len(m.ToolCalls) > 0 {
					// Convert assistant message with tool_calls to Anthropic tool_use content blocks
					var content []any
					if m.Content != nil {
						if text, ok := m.Content.(string); ok && text != "" {
							content = append(content, map[string]any{"type": "text", "text": text})
						}
					}
					for _, tc := range m.ToolCalls {
						var input map[string]any
						json.Unmarshal([]byte(tc.Function.Arguments), &input)
						if input == nil {
							input = map[string]any{}
						}
						content = append(content, map[string]any{
							"type":  "tool_use",
							"id":    tc.ID,
							"name":  tc.Function.Name,
							"input": input,
						})
					}
					chatMsgs = append(chatMsgs, AnthropicRequestMessage{Role: "assistant", Content: content})
				} else {
					chatMsgs = append(chatMsgs, AnthropicRequestMessage{Role: "assistant", Content: m.Content})
				}
			case "tool":
				// Convert tool result to Anthropic tool_result content block in a user message
				toolResult := map[string]any{
					"type":        "tool_result",
					"tool_use_id": m.ToolCallID,
				}
				if m.Content != nil {
					if text, ok := m.Content.(string); ok {
						toolResult["content"] = text
					} else {
						b, _ := json.Marshal(m.Content)
						toolResult["content"] = string(b)
					}
				}
				// Merge consecutive tool results into one user message
				merged := false
				if len(chatMsgs) > 0 {
					last := &chatMsgs[len(chatMsgs)-1]
					if last.Role == "user" {
						if arr, ok := last.Content.([]any); ok {
							last.Content = append(arr, toolResult)
							merged = true
						}
					}
				}
				if !merged {
					chatMsgs = append(chatMsgs, AnthropicRequestMessage{
						Role:    "user",
						Content: []any{toolResult},
					})
				}
			default:
				chatMsgs = append(chatMsgs, AnthropicRequestMessage{Role: m.Role, Content: m.Content})
			}
		}
		maxTok := oaiReq.MaxTokens
		if maxTok == 0 {
			maxTok = 4096
		}
		// Convert OpenAI tools to Anthropic tools
		var anthropicTools []AnthropicTool
		includeTools := true
		if tc, ok := oaiReq.ToolChoice.(string); ok && tc == "none" {
			includeTools = false
		}
		if includeTools {
			for _, t := range oaiReq.Tools {
				anthropicTools = append(anthropicTools, AnthropicTool{
					Name:        t.Function.Name,
					Description: t.Function.Description,
					InputSchema: t.Function.Parameters,
				})
			}
		}

		anthropicReq := AnthropicRequest{
			Model:       oaiReq.Model,
			Messages:    chatMsgs,
			System:      systemMsgs,
			Tools:       anthropicTools,
			MaxTokens:   maxTok,
			Temperature: oaiReq.Temperature,
			Stream:      false, // always non-stream, convert below if needed
		}

		if _, ok := ModelMap[anthropicReq.Model]; !ok {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"Unknown model: %s"}}`, anthropicReq.Model), http.StatusBadRequest)
			return
		}

		fmt.Printf("\n[OpenAI compat] model=%s messages=%d stream=%v\n", oaiReq.Model, len(oaiReq.Messages), oaiReq.Stream)

		ow := &observWriter{ResponseWriter: w, startTime: time.Now()}
		if oaiReq.Stream {
			// Stream: pipe through Anthropic handler, convert SSE format
			anthropicReq.Stream = true
			oaiStreamHandler(ow, anthropicReq, token.AccessToken)
			logCall("/v1/chat/completions", body, anthropicReq, true, ow)
		} else {
			// Non-stream: capture Anthropic response, convert to OpenAI format
			oaiNonStreamHandler(ow, anthropicReq, token.AccessToken)
			logCall("/v1/chat/completions", body, anthropicReq, false, ow)
		}
	}))

	// OpenAI legacy /v1/completions endpoint (adapter for topic-classifier etc.)
	mux.HandleFunc("/v1/completions", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
			return
		}
		token, err := getToken()
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		var legacyReq struct {
			Model       string   `json:"model"`
			Prompt      any      `json:"prompt"`
			MaxTokens   int      `json:"max_tokens"`
			Temperature *float64 `json:"temperature,omitempty"`
			Stream      bool     `json:"stream"`
		}
		if err := json.Unmarshal(body, &legacyReq); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusBadRequest)
			return
		}

		// Convert prompt to string
		var promptText string
		switch v := legacyReq.Prompt.(type) {
		case string:
			promptText = v
		default:
			b, _ := json.Marshal(v)
			promptText = string(b)
		}

		if _, ok := ModelMap[legacyReq.Model]; !ok {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"Unknown model: %s"}}`, legacyReq.Model), http.StatusBadRequest)
			return
		}

		maxTok := legacyReq.MaxTokens
		if maxTok == 0 {
			maxTok = 4096
		}
		anthropicReq := AnthropicRequest{
			Model:       legacyReq.Model,
			Messages:    []AnthropicRequestMessage{{Role: "user", Content: promptText}},
			MaxTokens:   maxTok,
			Temperature: legacyReq.Temperature,
			Stream:      false,
		}

		fmt.Printf("\n[OpenAI legacy completions] model=%s prompt_len=%d stream=%v\n", legacyReq.Model, len(promptText), legacyReq.Stream)

		// Call Anthropic, return in legacy completions format
		rec := &responseRecorder{headers: make(http.Header), body: &bytes.Buffer{}}
		handleNonStreamRequest(rec, anthropicReq, token.AccessToken)
		if rec.code != http.StatusOK && rec.code != 0 {
			copyHeaders(w, rec.headers)
			w.WriteHeader(rec.code)
			w.Write(rec.body.Bytes())
			return
		}
		var anthResp struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Model string `json:"model"`
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(rec.body.Bytes(), &anthResp); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"parse response: %v"}}`, err), http.StatusInternalServerError)
			return
		}
		var text string
		for _, c := range anthResp.Content {
			if c.Type == "text" {
				text += c.Text
			}
		}
		resp := map[string]any{
			"id":     "cmpl-kiro2pi",
			"object": "text_completion",
			"model":  anthResp.Model,
			"choices": []map[string]any{{
				"text":          text,
				"index":         0,
				"finish_reason": "stop",
			}},
			"usage": map[string]any{
				"prompt_tokens":     anthResp.Usage.InputTokens,
				"completion_tokens": anthResp.Usage.OutputTokens,
				"total_tokens":      anthResp.Usage.InputTokens + anthResp.Usage.OutputTokens,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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
			{"id": "claude-opus-4.7", "type": "model", "display_name": "Claude Opus 4.7", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-opus-4.8", "type": "model", "display_name": "Claude Opus 4.8", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-sonnet-4.6", "type": "model", "display_name": "Claude Sonnet 4.6", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-sonnet-5", "type": "model", "display_name": "Claude Sonnet 5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-opus-5", "type": "model", "display_name": "Claude Opus 5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "deepseek-3.2", "type": "model", "display_name": "DeepSeek 3.2", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "minimax-m2.5", "type": "model", "display_name": "MiniMax M2.5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "glm-5", "type": "model", "display_name": "GLM-5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "kimi-k2.5", "type": "model", "display_name": "Kimi K2.5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "gpt-5.5", "type": "model", "display_name": "GPT-5.5", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "gpt-5.6-sol", "type": "model", "display_name": "GPT-5.6 Sol", "created_at": "2025-01-01T00:00:00Z"},
			{"id": "claude-fable-5", "type": "model", "display_name": "Claude Fable 5", "created_at": "2025-01-01T00:00:00Z"},
		}
		resp := map[string]any{
			"data":     models,
			"has_more": false,
			"first_id": "claude-sonnet-4.5",
			"last_id":  "kimi-k2.5",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	// Observability: /stats endpoint
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if observDB == nil {
			http.Error(w, `{"error":"observability not initialized"}`, http.StatusServiceUnavailable)
			return
		}
		model := r.URL.Query().Get("model")
		since := r.URL.Query().Get("since")
		query := `SELECT model, DATE(created_at) as day, COUNT(*) as calls, SUM(input_tokens) as input_tok, SUM(output_tokens) as output_tok, AVG(latency_ms) as avg_latency, AVG(ttft_ms) as avg_ttft FROM call_log WHERE 1=1`
		var args []any
		if model != "" {
			query += " AND model=?"
			args = append(args, model)
		}
		if since != "" {
			query += " AND created_at>=?"
			args = append(args, since)
		}
		query += " GROUP BY model, day ORDER BY day DESC"
		rows, err := observDB.Query(query, args...)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var results []map[string]any
		for rows.Next() {
			var m, day string
			var calls int
			var inputTok, outputTok sql.NullInt64
			var avgLatency, avgTtft sql.NullFloat64
			rows.Scan(&m, &day, &calls, &inputTok, &outputTok, &avgLatency, &avgTtft)
			results = append(results, map[string]any{
				"model": m, "day": day, "calls": calls,
				"input_tokens": inputTok.Int64, "output_tokens": outputTok.Int64,
				"avg_latency_ms": avgLatency.Float64, "avg_ttft_ms": avgTtft.Float64,
			})
		}
		if results == nil {
			results = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	// Observability: /logs endpoint
	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		if observDB == nil {
			http.Error(w, `{"error":"observability not initialized"}`, http.StatusServiceUnavailable)
			return
		}
		limit := 50
		offset := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}
		rows, err := observDB.Query(
			`SELECT id,created_at,model,endpoint,stream,input_tokens,output_tokens,latency_ms,ttft_ms,status_code,error_message,request_hash,has_tools,has_thinking FROM call_log ORDER BY created_at DESC LIMIT ? OFFSET ?`,
			limit, offset,
		)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var results []map[string]any
		for rows.Next() {
			var id, createdAt, model, endpoint, reqHash string
			var stream, statusCode, hasTools, hasThinking int
			var inputTok, outputTok, latency sql.NullInt64
			var ttft sql.NullInt64
			var errMsg sql.NullString
			rows.Scan(&id, &createdAt, &model, &endpoint, &stream, &inputTok, &outputTok, &latency, &ttft, &statusCode, &errMsg, &reqHash, &hasTools, &hasThinking)
			entry := map[string]any{
				"id": id, "created_at": createdAt, "model": model, "endpoint": endpoint,
				"stream": stream == 1, "latency_ms": latency.Int64, "status_code": statusCode,
				"request_hash": reqHash, "has_tools": hasTools == 1, "has_thinking": hasThinking == 1,
			}
			if inputTok.Valid {
				entry["input_tokens"] = inputTok.Int64
			}
			if outputTok.Valid {
				entry["output_tokens"] = outputTok.Int64
			}
			if ttft.Valid {
				entry["ttft_ms"] = ttft.Int64
			}
			if errMsg.Valid {
				entry["error_message"] = errMsg.String
			}
			results = append(results, entry)
		}
		if results == nil {
			results = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	// 添加健康检查端点
	mux.HandleFunc("/health", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Embeddings endpoint (conditional)
	if bedrockClient != nil {
		mux.HandleFunc("/v1/embeddings", logMiddleware(handleEmbeddings))
		mux.HandleFunc("/v1/rerank", logMiddleware(handleRerank))
	}

	// 添加404处理
	mux.HandleFunc("/", logMiddleware(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("警告: 访问未知端点 %s %s\n", r.Method, r.URL.Path)
		http.Error(w, "404 未找到", http.StatusNotFound)
	}))

	// 启动服务器
	fmt.Printf("启动Anthropic API代理服务器，监听端口: %s\n", port)
	fmt.Printf("可用端点:\n")
	fmt.Printf("  POST /v1/messages - Anthropic API代理\n")
	fmt.Printf("  GET  /v1/models   - 获取可用模型列表\n")
	fmt.Printf("  GET  /health      - 健康检查\n")
	fmt.Printf("  GET  /stats       - 调用统计\n")
	fmt.Printf("  GET  /logs        - 调用日志\n")
	if bedrockClient != nil {
		fmt.Printf("  POST /v1/embeddings - Bedrock Embeddings (OpenAI兼容)\n")
		fmt.Printf("  POST /v1/rerank     - Bedrock Rerank (Cohere兼容)\n")
	}
	fmt.Printf("按Ctrl+C停止服务器\n")

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Printf("启动服务器失败: %v\n", err)
		os.Exit(1)
	}
}
