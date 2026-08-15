package main

import (
	"encoding/json"
)

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
// Mirrors the Rust client's Tool union: either a toolSpecification or a
// cachePoint variant (used to mark the stable tools prefix as cacheable).
type CodeWhispererTool struct {
	ToolSpecification *ToolSpecification `json:"toolSpecification,omitempty"`
	CachePoint        *CachePoint        `json:"cachePoint,omitempty"`
}

// HistoryUserMessage 表示历史记录中的用户消息
type HistoryUserMessage struct {
	UserInputMessage struct {
		Content                 string                          `json:"content"`
		UserInputMessageContext *HistoryUserInputMessageContext `json:"userInputMessageContext,omitempty"`
		Origin                  string                          `json:"origin,omitempty"`
		Images                  []KiroImage                     `json:"images,omitempty"`
		CachePoint              *CachePoint                     `json:"cachePoint,omitempty"`
	} `json:"userInputMessage"`
}

// KiroImage represents an image in Kiro API format
type KiroImage struct {
	Format string          `json:"format"`
	Source KiroImageSource `json:"source"`
}

type KiroImageSource struct {
	Bytes string `json:"bytes"`
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
	Type         string `json:"type"`                    // "enabled", "disabled", or "adaptive"
	BudgetTokens int    `json:"budget_tokens,omitempty"` // Token budget for thinking
	Display      string `json:"display,omitempty"`       // Display mode for adaptive thinking
}

type AnthropicOutputConfig struct {
	Effort string `json:"effort,omitempty"`
}

// AnthropicRequest 表示 Anthropic API 的请求结构
type AnthropicRequest struct {
	Model        string                    `json:"model"`
	MaxTokens    int                       `json:"max_tokens"`
	Messages     []AnthropicRequestMessage `json:"messages"`
	System       FlexibleSystem            `json:"system,omitempty"`
	Tools        []AnthropicTool           `json:"tools,omitempty"`
	Stream       bool                      `json:"stream"`
	Temperature  *float64                  `json:"temperature,omitempty"`
	Metadata     map[string]any            `json:"metadata,omitempty"`
	Thinking     *AnthropicThinking        `json:"thinking,omitempty"`      // Extended thinking support
	OutputConfig *AnthropicOutputConfig    `json:"output_config,omitempty"` // Forwarded via additionalModelRequestFields for models that support it
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

// FlexibleSystem handles Anthropic system field being either a string or []AnthropicSystemMessage
type FlexibleSystem []AnthropicSystemMessage

func (fs *FlexibleSystem) UnmarshalJSON(data []byte) error {
	// Try string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*fs = []AnthropicSystemMessage{{Type: "text", Text: s}}
		return nil
	}
	// Otherwise treat as array
	var msgs []AnthropicSystemMessage
	if err := json.Unmarshal(data, &msgs); err != nil {
		return err
	}
	*fs = msgs
	return nil
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

// CodeWhispererRequest 表示 CodeWhisperer API 的请求结构 (Q API format)
type CodeWhispererRequest struct {
	ConversationState struct {
		ChatTriggerType     string `json:"chatTriggerType"`
		ConversationId      string `json:"conversationId"`
		AgentContinuationId string `json:"agentContinuationId,omitempty"`
		AgentTaskType       string `json:"agentTaskType,omitempty"`
		CurrentMessage      struct {
			UserInputMessage struct {
				Content                      string         `json:"content"`
				ModelId                      string         `json:"modelId"`
				Origin                       string         `json:"origin"`
				Images                       []KiroImage    `json:"images,omitempty"`
				AdditionalModelRequestFields map[string]any `json:"additionalModelRequestFields,omitempty"`
				CachePoint                   *CachePoint    `json:"cachePoint,omitempty"`
				UserInputMessageContext      struct {
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

// CachePoint marks a prompt-caching checkpoint in the request
// (mirrors amzn-codewhisperer-streaming-client's CachePoint; only "default").
type CachePoint struct {
	Type string `json:"type"`
}

// CodeWhispererEvent 表示 CodeWhisperer 的事件响应
type CodeWhispererEvent struct {
	ContentType string `json:"content-type"`
	MessageType string `json:"message-type"`
	Content     string `json:"content"`
	EventType   string `json:"event-type"`
}
