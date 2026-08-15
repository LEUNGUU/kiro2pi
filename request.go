package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

// Request size limits
const (
	maxRequestBytes         = 590 * 1024 // 590KB max request payload (Kiro API hard limit is ~615KB)
	maxToolResultContentLen = 10 * 1024  // 10KB max per tool result content
)

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

// extractImages extracts image content blocks from Anthropic messages and converts to Kiro format.
// Anthropic format: {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "..."}}
// Kiro format: {"format": "png", "source": {"bytes": "..."}}
func extractImages(content any) []KiroImage {
	blocks, ok := content.([]interface{})
	if !ok {
		return nil
	}
	var images []KiroImage
	for _, block := range blocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		if m["type"] != "image" {
			continue
		}
		source, ok := m["source"].(map[string]interface{})
		if !ok {
			continue
		}
		// Only support base64 source type
		sourceType, _ := source["type"].(string)
		if sourceType != "base64" {
			if sourceType == "url" {
				log.Printf("WARNING: URL-based images are not supported, skipping")
			}
			continue
		}
		data, _ := source["data"].(string)
		if data == "" {
			continue
		}
		mediaType, _ := source["media_type"].(string)
		if mediaType == "" {
			mediaType = "image/jpeg"
		}
		// Extract format from media_type: "image/jpeg" -> "jpeg"
		format := mediaType
		if idx := strings.LastIndex(mediaType, "/"); idx >= 0 {
			format = mediaType[idx+1:]
		}
		images = append(images, KiroImage{
			Format: format,
			Source: KiroImageSource{Bytes: data},
		})
	}
	if len(images) > 0 {
		log.Printf("Extracted %d image(s) from content", len(images))
	}
	return images
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
				// Merge images
				if len(curr.UserInputMessage.Images) > 0 {
					prev.UserInputMessage.Images = append(prev.UserInputMessage.Images, curr.UserInputMessage.Images...)
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
	// Extract images from the last message and add to currentMessage
	if imgs := extractImages(lastMsg.Content); len(imgs) > 0 {
		cwReq.ConversationState.CurrentMessage.UserInputMessage.Images = imgs
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

	// Prompt caching: models that support it get a checkpoint on the current
	// message so the (potentially huge) conversation prefix is cached upstream.
	if promptCachingModels[modelId] > 0 {
		cwReq.ConversationState.CurrentMessage.UserInputMessage.CachePoint = &CachePoint{Type: "default"}
	}

	// cwd extraction for history messages
	cwd := extractCwdFromSystemPrompt(anthropicReq.System)
	cwReq.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.EnvState = &EnvState{
		OperatingSystem:         goosToQApi(runtime.GOOS),
		CurrentWorkingDirectory: cwd,
	}

	// 处理 tools 信息
	var tools []CodeWhispererTool
	for _, tool := range anthropicReq.Tools {
		tools = append(tools, CodeWhispererTool{ToolSpecification: &ToolSpecification{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: InputSchema{Json: sanitizeJsonSchema(tool.InputSchema)},
		}})
	}

	// Forward thinking config and effort natively for models that support
	// additionalModelRequestFields (validated against the schema returned by
	// ListAvailableModels on the management endpoint).
	if amrf := buildAdditionalModelRequestFields(modelId, anthropicReq); amrf != nil {
		cwReq.ConversationState.CurrentMessage.UserInputMessage.AdditionalModelRequestFields = amrf
		if b, err := json.Marshal(amrf); err == nil {
			log.Printf("Forwarding additionalModelRequestFields for %s: %s", modelId, b)
		}
	}

	// Add thinking tool when thinking is enabled (matching kiro-cli behavior)
	// for models WITHOUT native additionalModelRequestFields support.
	if !(adaptiveThinkingModels[modelId] > 0) && !reasoningEffortModels[modelId] &&
		anthropicReq.Thinking != nil && (anthropicReq.Thinking.Type == "enabled" || anthropicReq.Thinking.Type == "adaptive") {
		effort := ""
		if anthropicReq.OutputConfig != nil {
			effort = anthropicReq.OutputConfig.Effort
		}
		log.Printf("Thinking enabled: type=%s display=%s budget_tokens=%d effort=%s; adding thinking tool", anthropicReq.Thinking.Type, anthropicReq.Thinking.Display, anthropicReq.Thinking.BudgetTokens, effort)
		thinkingTool := CodeWhispererTool{ToolSpecification: &ToolSpecification{}}
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
		// Multi-checkpoint caching: tools are the largest stable prefix, so
		// mark them with their own cache point (Tool union CachePoint variant;
		// schema allows up to 4 checkpoints per request).
		if promptCachingModels[modelId] > 0 {
			tools = append(tools, CodeWhispererTool{CachePoint: &CachePoint{Type: "default"}})
		}
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

		// Concatenate system prompt for prepending to first user message later
		var systemPrompt string
		if len(anthropicReq.System) > 0 {
			var parts []string
			for _, sysMsg := range anthropicReq.System {
				parts = append(parts, sysMsg.Text)
			}
			systemPrompt = strings.Join(parts, "\n\n")
		}

		// 然后处理常规消息历史 - 确保严格交替 user/assistant
		// CodeWhisperer要求历史记录必须是 user -> assistant -> user -> assistant 的顺序
		var pendingUserContent []string
		var pendingUserImages []KiroImage
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
					pendingUserImages = nil

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
				if imgs := extractImages(msg.Content); len(imgs) > 0 {
					pendingUserImages = append(pendingUserImages, imgs...)
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
						if len(pendingUserContent) > 0 || len(pendingUserImages) > 0 {
							userMsg := HistoryUserMessage{}
							userMsg.UserInputMessage.Content = strings.Join(pendingUserContent, "\n")
							userMsg.UserInputMessage.Origin = "KIRO_CLI"
							userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
								EnvState: &EnvState{
									OperatingSystem:         goosToQApi(runtime.GOOS),
									CurrentWorkingDirectory: cwd,
								},
							}
							if len(pendingUserImages) > 0 {
								userMsg.UserInputMessage.Images = pendingUserImages
							}
							history = append(history, userMsg)
							pendingUserContent = nil // 清空
							pendingUserImages = nil
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
					if len(pendingUserContent) > 0 || len(pendingUserImages) > 0 {
						userMsg := HistoryUserMessage{}
						userMsg.UserInputMessage.Content = strings.Join(pendingUserContent, "\n")
						userMsg.UserInputMessage.Origin = "KIRO_CLI"
						userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
							EnvState: &EnvState{
								OperatingSystem:         goosToQApi(runtime.GOOS),
								CurrentWorkingDirectory: cwd,
							},
						}
						if len(pendingUserImages) > 0 {
							userMsg.UserInputMessage.Images = pendingUserImages
						}
						history = append(history, userMsg)
						pendingUserContent = nil
						pendingUserImages = nil
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
		if len(pendingUserContent) > 0 || len(pendingUserImages) > 0 {
			userMsg := HistoryUserMessage{}
			userMsg.UserInputMessage.Content = strings.Join(pendingUserContent, "\n")
			userMsg.UserInputMessage.Origin = "KIRO_CLI"
			userMsg.UserInputMessage.UserInputMessageContext = &HistoryUserInputMessageContext{
				EnvState: &EnvState{
					OperatingSystem:         goosToQApi(runtime.GOOS),
					CurrentWorkingDirectory: cwd,
				},
			}
			if len(pendingUserImages) > 0 {
				userMsg.UserInputMessage.Images = pendingUserImages
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

		// When history is empty (first message in conversation), prepend system prompt to currentMessage
		if systemPrompt != "" && len(history) == 0 {
			cwReq.ConversationState.CurrentMessage.UserInputMessage.Content = systemPrompt + "\n\n" + cwReq.ConversationState.CurrentMessage.UserInputMessage.Content
			log.Printf("Prepended system prompt to currentMessage (no history)")
		}

		// Validation pipeline: ensure proper message structure
		history = ensureAssistantBeforeToolResults(history)
		history = ensureFirstMessageIsUser(history)
		history = ensureAlternatingRoles(history)

		// Multi-checkpoint caching: mark the last history user message so the
		// previous turn's prefix stays cached even when the current message
		// changes (checkpoints so far: tools + this + current message ≤ 4).
		if promptCachingModels[modelId] > 0 {
			for i := len(history) - 1; i >= 0; i-- {
				if um, ok := history[i].(HistoryUserMessage); ok {
					um.UserInputMessage.CachePoint = &CachePoint{Type: "default"}
					history[i] = um
					break
				}
			}
		}

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
