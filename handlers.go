package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bestk/kiro2cc/parser"
)

// retryContentFiltered tries to recover from an upstream CONTENT_FILTERED
// response: one same-model retry first (the filter is probabilistic), then
// one shot on the fallback model. accepted validates a candidate body.
func retryContentFiltered(cwReq CodeWhispererRequest, accessToken string, accepted func([]byte) bool) ([]byte, bool) {
	log.Printf("CONTENT_FILTERED，同模型重试一次...")
	if body, err := sendQApiRequest(cwReq, accessToken); err == nil && accepted(body) {
		log.Printf("CONTENT_FILTERED 重试成功")
		return body, true
	}
	fb := contentFilterFallbackModel[cwReq.ConversationState.CurrentMessage.UserInputMessage.ModelId]
	if fb == "" {
		return nil, false
	}
	log.Printf("CONTENT_FILTERED 重试仍被过滤，降级到 %s ...", fb)
	fbReq := cwReq
	fbReq.ConversationState.CurrentMessage.UserInputMessage.ModelId = fb
	if body, err := sendQApiRequest(fbReq, accessToken); err == nil && accepted(body) {
		log.Printf("CONTENT_FILTERED 降级到 %s 成功", fb)
		return body, true
	}
	return nil, false
}

// logMiddleware 记录所有HTTP请求的中间件
// oaiNonStreamHandler handles OpenAI-format non-streaming requests
func oaiNonStreamHandler(w http.ResponseWriter, anthropicReq AnthropicRequest, accessToken string) {
	// Use a ResponseRecorder to capture the Anthropic response
	rec := &responseRecorder{headers: make(http.Header), body: &bytes.Buffer{}}
	handleNonStreamRequest(rec, anthropicReq, accessToken)

	if rec.code != http.StatusOK && rec.code != 0 {
		copyHeaders(w, rec.headers)
		w.WriteHeader(rec.code)
		w.Write(rec.body.Bytes())
		return
	}

	// Parse Anthropic response
	var anthResp struct {
		Content []struct {
			Type  string         `json:"type"`
			Text  string         `json:"text,omitempty"`
			ID    string         `json:"id,omitempty"`
			Name  string         `json:"name,omitempty"`
			Input map[string]any `json:"input,omitempty"`
		} `json:"content"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &anthResp); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"parse response: %v"}}`, err), http.StatusInternalServerError)
		return
	}

	// Build text and tool_calls from content blocks
	var text string
	var toolCalls []map[string]any
	for _, c := range anthResp.Content {
		switch c.Type {
		case "text":
			text += c.Text
		case "tool_use":
			args, _ := json.Marshal(c.Input)
			toolCalls = append(toolCalls, map[string]any{
				"id":   c.ID,
				"type": "function",
				"function": map[string]any{
					"name":      c.Name,
					"arguments": string(args),
				},
			})
		}
	}

	// Convert to OpenAI format
	finishReason := "stop"
	msg := map[string]any{"role": "assistant", "content": text}
	if len(toolCalls) > 0 {
		msg["tool_calls"] = toolCalls
		finishReason = "tool_calls"
		if text == "" {
			msg["content"] = nil
		}
	}

	oaiResp := map[string]any{
		"id":     "chatcmpl-kiro2pi",
		"object": "chat.completion",
		"model":  anthResp.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       msg,
			"finish_reason": finishReason,
		}},
		"usage": map[string]any{
			"prompt_tokens":     anthResp.Usage.InputTokens,
			"completion_tokens": anthResp.Usage.OutputTokens,
			"total_tokens":      anthResp.Usage.InputTokens + anthResp.Usage.OutputTokens,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(oaiResp)
}

// oaiStreamHandler handles OpenAI-format streaming requests
func oaiStreamHandler(w http.ResponseWriter, anthropicReq AnthropicRequest, accessToken string) {
	// Use a pipe to capture SSE from the Anthropic handler
	pr, pw := io.Pipe()
	rec := &responseRecorder{headers: make(http.Header), body: nil, pipe: pw}

	go func() {
		handleStreamRequest(rec, anthropicReq, accessToken)
		pw.Close()
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	scanner := bufio.NewScanner(pr)
	toolCallIndex := 0 // Track OpenAI tool_call index
	currentBlockIsToolUse := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			break
		}
		var evt map[string]any
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		evtType, _ := evt["type"].(string)
		switch evtType {
		case "content_block_start":
			cb, _ := evt["content_block"].(map[string]any)
			currentBlockIsToolUse = cb != nil && cb["type"] == "tool_use"
			if currentBlockIsToolUse {
				tcDelta := map[string]any{
					"index": toolCallIndex,
					"id":    cb["id"],
					"type":  "function",
					"function": map[string]any{
						"name":      cb["name"],
						"arguments": "",
					},
				}
				chunk := map[string]any{
					"id": "chatcmpl-kiro2pi", "object": "chat.completion.chunk", "model": anthropicReq.Model,
					"choices": []map[string]any{{"index": 0, "delta": map[string]any{"tool_calls": []map[string]any{tcDelta}}}},
				}
				b, _ := json.Marshal(chunk)
				fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			}
		case "content_block_delta":
			delta, _ := evt["delta"].(map[string]any)
			deltaType, _ := delta["type"].(string)
			switch deltaType {
			case "text_delta":
				text, _ := delta["text"].(string)
				if text != "" {
					chunk := map[string]any{
						"id": "chatcmpl-kiro2pi", "object": "chat.completion.chunk", "model": anthropicReq.Model,
						"choices": []map[string]any{{"index": 0, "delta": map[string]any{"content": text}}},
					}
					b, _ := json.Marshal(chunk)
					fmt.Fprintf(w, "data: %s\n\n", b)
					flusher.Flush()
				}
			case "input_json_delta":
				partialJSON, _ := delta["partial_json"].(string)
				if partialJSON != "" {
					chunk := map[string]any{
						"id": "chatcmpl-kiro2pi", "object": "chat.completion.chunk", "model": anthropicReq.Model,
						"choices": []map[string]any{{"index": 0, "delta": map[string]any{
							"tool_calls": []map[string]any{{
								"index":    toolCallIndex,
								"function": map[string]any{"arguments": partialJSON},
							}},
						}}},
					}
					b, _ := json.Marshal(chunk)
					fmt.Fprintf(w, "data: %s\n\n", b)
					flusher.Flush()
				}
			}
		case "content_block_stop":
			if currentBlockIsToolUse {
				toolCallIndex++
				currentBlockIsToolUse = false
			}
		case "message_delta":
			// Send finish_reason based on stop_reason
			md, _ := evt["delta"].(map[string]any)
			stopReason, _ := md["stop_reason"].(string)
			finishReason := "stop"
			if stopReason == "tool_use" {
				finishReason = "tool_calls"
			}
			chunk := map[string]any{
				"id": "chatcmpl-kiro2pi", "object": "chat.completion.chunk", "model": anthropicReq.Model,
				"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": finishReason}},
			}
			b, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case "message_stop":
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
		case "error":
			// Upstream error (e.g. throttling after retries). SSE headers are
			// already sent, so surface it in-band as an OpenAI error chunk
			// instead of silently truncating the stream.
			errObj, _ := evt["error"].(map[string]any)
			msg := "upstream error"
			if errObj != nil {
				if m, ok := errObj["message"].(string); ok {
					msg = m
				}
			}
			chunk := map[string]any{
				"error": map[string]any{"message": msg, "type": "upstream_error"},
			}
			b, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", b)
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
		}
	}
}

// writeRequestTooLarge sends an Anthropic-style request_too_large error (413).
func writeRequestTooLarge(w http.ResponseWriter, size, limit int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	json.NewEncoder(w).Encode(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    "request_too_large",
			"message": fmt.Sprintf("request payload %d bytes exceeds upstream limit %d; reduce context (prompt is too long)", size, limit),
		},
	})
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

	client := upstreamClient
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

	if limit := payloadLimitFor(cwReq.ConversationState.CurrentMessage.UserInputMessage.ModelId); len(cwReqBody) > limit {
		log.Printf("请求体超限: %d bytes > %d", len(cwReqBody), limit)
		writeRequestTooLarge(w, len(cwReqBody), limit)
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
	client := upstreamClient

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
			lastStatus := resp.StatusCode
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
				lastStatus = retryResp.StatusCode

				if !isRetryableStatusCode(retryResp.StatusCode) {
					// Non-retryable error
					retryBody, _ := io.ReadAll(retryResp.Body)
					sendErrorEvent(w, flusher, "CodeWhisperer请求失败", fmt.Errorf("状态码: %d, 响应: %s", retryResp.StatusCode, string(retryBody)))
					return
				}
			}
			// 重试预算耗尽：若最后一次仍是限流(429)，透传可重试的 429 + Retry-After
			// 给调用方，让其自行退避，而不是含糊的 read 超时。
			if lastStatus == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "4")
				w.WriteHeader(http.StatusTooManyRequests)
				sendErrorEvent(w, flusher, "上游限流，请稍后重试", fmt.Errorf("upstream throttled after %d retries", maxRetries))
				return
			}
			sendErrorEvent(w, flusher, "CodeWhisperer请求失败", fmt.Errorf("重试%d次后仍失败，最后状态码: %d", maxRetries, lastStatus))
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

	if parseResult.Refusal != "" && len(parseResult.Events) == 0 {
		// Recover: same-model retry (filter is probabilistic), then fallback
		// model, mirroring Anthropic's automatic-fallback behavior.
		if body, ok := retryContentFiltered(cwReq, accessToken, func(b []byte) bool {
			r := parser.ParseEventsWithThinking(b)
			return r.Refusal == "" && len(r.Events) > 0
		}); ok {
			respBody = body
			parseResult = parser.ParseEventsWithThinking(respBody)
		}
	}

	if parseResult.Refusal != "" && len(parseResult.Events) == 0 {
		// Upstream content filter swallowed the whole response; surface the
		// refusal instead of an empty/broken stream.
		sendErrorEvent(w, flusher, "Upstream refused the request", fmt.Errorf("%s", parseResult.Refusal))
		return
	}

	if len(parseResult.Events) == 0 {
		// No events parsed - send an error response instead of a broken stream
		sendErrorEvent(w, flusher, "Empty response from upstream API", fmt.Errorf("no events parsed from response (%d bytes)", len(respBody)))
		return
	}

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

	// Continuation loop for automatic thinking handling
	outputTokens := 0
	hasRegularToolUse := false
	continuationCount := 0
	maxContinuations := 10                         // Safety limit to prevent infinite loops
	textIndex := parseResult.TextIndex             // Track text index (0 if no thinking, 1 if thinking present)
	textBlockStarted := false                      // Track whether a text content_block_start was emitted
	contextUsagePct := parseResult.ContextUsagePct // Keep the last upstream usage across continuations

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

			// Track if a text content_block_start was emitted
			if e.Event == "content_block_start" {
				if dataMap, ok := e.Data.(map[string]interface{}); ok {
					if cb, ok := dataMap["content_block"].(map[string]interface{}); ok {
						if cb["type"] == "text" {
							textBlockStarted = true
						}
					}
				}
			}

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
			if parseResult.ContextUsagePct > 0 {
				contextUsagePct = parseResult.ContextUsagePct
			}
			log.Printf("Continuation %d: events=%d, thinking=%s, hasRegularTools=%v",
				continuationCount, len(parseResult.Events), parseResult.ThinkingToolId, parseResult.HasRegularTools)

			// Fix indices: continuation parser starts textIndex at 0, but the
			// first parse already emitted thinking at index 0, so all content
			// block indices must be shifted by the offset.
			if textIndex > 0 {
				offset := textIndex // e.g. 1 when thinking used index 0
				for i := range parseResult.Events {
					if dataMap, ok := parseResult.Events[i].Data.(map[string]interface{}); ok {
						if idx, ok := dataMap["index"].(int); ok {
							dataMap["index"] = idx + offset
						} else if idx, ok := dataMap["index"].(float64); ok {
							dataMap["index"] = int(idx) + offset
						}
					}
				}
			}

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

	// Close text content block only if one was actually started
	// Without this guard, sonnet 4.6 (which may return only thinking) causes
	// "Cannot read properties of undefined (reading 'type')" on the client
	if textBlockStarted {
		contentBlockStop := map[string]any{"index": textIndex, "type": "content_block_stop"}
		sendSSEEvent(w, flusher, "content_block_stop", contentBlockStop)
	}

	// Send appropriate stop reason
	// Only use "tool_use" if there are regular (non-thinking) tools
	stopReason := "end_turn"
	if hasRegularToolUse {
		stopReason = "tool_use"
	}
	// Prefer the upstream-reported context usage over the chars/4 estimate.
	upstreamModelId := cwReq.ConversationState.CurrentMessage.UserInputMessage.ModelId
	inputTokens := resolveInputTokens(anthropicReq, upstreamModelId, contextUsagePct)
	messageDelta := map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   stopReason,
			"stop_sequence": nil,
		},
		"usage": map[string]any{"input_tokens": inputTokens, "output_tokens": outputTokens},
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

	if limit := payloadLimitFor(cwReq.ConversationState.CurrentMessage.UserInputMessage.ModelId); len(cwReqBody) > limit {
		log.Printf("请求体超限 (非流式): %d bytes > %d", len(cwReqBody), limit)
		writeRequestTooLarge(w, len(cwReqBody), limit)
		return
	}

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
	client := upstreamClient

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
			lastStatus := resp.StatusCode
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
				lastStatus = retryResp.StatusCode

				if !isRetryableStatusCode(retryResp.StatusCode) {
					// Non-retryable error
					retryBody, _ := io.ReadAll(retryResp.Body)
					http.Error(w, fmt.Sprintf("CodeWhisperer请求失败: 状态码 %d, 响应: %s", retryResp.StatusCode, string(retryBody)), http.StatusBadGateway)
					return
				}
			}
			// 重试预算耗尽：若最后一次仍是限流(429)，透传可重试的 429 + Retry-After。
			if lastStatus == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "4")
				http.Error(w, "上游限流，请稍后重试", http.StatusTooManyRequests)
				return
			}
			http.Error(w, fmt.Sprintf("CodeWhisperer请求失败: 重试%d次后仍失败，最后状态码: %d", maxRetries, lastStatus), http.StatusBadGateway)
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

	if refusal := parser.DetectRefusal(cwRespBody); refusal != "" && len(events) == 0 {
		// Recover: same-model retry, then fallback model.
		if body, ok := retryContentFiltered(cwReq, accessToken, func(b []byte) bool {
			return parser.DetectRefusal(b) == "" && len(parser.ParseEvents(b)) > 0
		}); ok {
			cwRespBody = body
			respBodyStr = string(cwRespBody)
			events = parser.ParseEvents(cwRespBody)
			refusal = ""
		}
		if refusal != "" {
			// Content filter swallowed the whole response; surface the refusal
			// instead of returning an empty message.
			log.Printf("Upstream CONTENT_FILTERED (non-stream): %s", refusal)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"type": "error",
				"error": map[string]any{
					"type":    "invalid_request_error",
					"message": refusal,
				},
			})
			return
		}
	}

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

	// Ensure content array is never empty - JS clients access content[0].type
	if len(contexts) == 0 {
		contexts = append(contexts, map[string]any{
			"type": "text",
			"text": "",
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
			"input_tokens":  resolveInputTokens(anthropicReq, cwReq.ConversationState.CurrentMessage.UserInputMessage.ModelId, parser.DetectContextUsage(cwRespBody)),
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
