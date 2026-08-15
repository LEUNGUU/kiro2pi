package main

import (
	"encoding/json"
)

// contentFilterFallbackModel maps models whose safety classifiers filter
// aggressively to a laxer fallback model, mirroring Anthropic's official
// automatic-fallback behavior (flagged Opus 5 / Fable 5 requests route to
// Opus 4.8, whose classifiers intervene ~85% less often).
var contentFilterFallbackModel = map[string]string{
	"claude-fable-5": "claude-opus-4.8",
	"claude-opus-5":  "claude-opus-4.8",
}

// promptCachingModels lists models with supportsPromptCaching per
// ListAvailableModels, mapped to minimumTokensPerCacheCheckpoint.
var promptCachingModels = map[string]int{
	"claude-opus-5":     1024,
	"claude-sonnet-5":   1024,
	"claude-opus-4.8":   1024,
	"claude-opus-4.7":   4096,
	"claude-opus-4.6":   4096,
	"claude-sonnet-4.6": 1024,
	"claude-fable-5":    4096,
	"gpt-5.6-sol":       1024,
	"gpt-5.6-terra":     1024,
	"gpt-5.6-luna":      1024,
	"auto":              1024,
}

// Models that accept additionalModelRequestFields with thinking/output_config
// (adaptive-thinking Claude models, per additionalModelRequestFieldsSchema
// from the ListAvailableModels management API). Value is the schema's
// max_tokens maximum for the model.
var adaptiveThinkingModels = map[string]int{
	"claude-opus-5":     128000,
	"claude-sonnet-5":   128000,
	"claude-opus-4.8":   128000,
	"claude-opus-4.7":   128000,
	"claude-opus-4.6":   64000,
	"claude-sonnet-4.6": 64000,
	"claude-fable-5":    128000,
}

// Models that accept additionalModelRequestFields with reasoning.effort (GPT models).
var reasoningEffortModels = map[string]bool{
	"gpt-5.6-sol":   true,
	"gpt-5.6-terra": true,
	"gpt-5.6-luna":  true,
}

// buildAdditionalModelRequestFields maps Anthropic thinking/output_config to the
// Q API additionalModelRequestFields payload for models whose schema supports it.
// Returns nil when the model has no schema or nothing needs forwarding.
func buildAdditionalModelRequestFields(modelId string, req AnthropicRequest) map[string]any {
	effort := ""
	if req.OutputConfig != nil {
		effort = req.OutputConfig.Effort
	}
	switch {
	case adaptiveThinkingModels[modelId] > 0:
		fields := map[string]any{}
		if req.Thinking != nil {
			switch req.Thinking.Type {
			case "enabled", "adaptive":
				thinking := map[string]any{"type": "adaptive"}
				if d := req.Thinking.Display; d == "summarized" || d == "omitted" {
					thinking["display"] = d
				}
				fields["thinking"] = thinking
			case "disabled":
				fields["thinking"] = map[string]any{"type": "disabled"}
			}
		}
		// Schema enum: low|medium|high|xhigh|max. Invalid values silently degrade
		// upstream, so filter here.
		switch effort {
		case "low", "medium", "high", "xhigh", "max":
			fields["output_config"] = map[string]any{"effort": effort}
		}
		// Forward max_tokens clamped to the schema range [1024, model max].
		// Note: verified 2026-08 that upstream accepts but does not yet enforce
		// this value (output is not truncated); forwarded for forward-compat.
		if req.MaxTokens > 0 {
			mt := req.MaxTokens
			if mt < 1024 {
				mt = 1024
			}
			if limit := adaptiveThinkingModels[modelId]; mt > limit {
				mt = limit
			}
			fields["max_tokens"] = mt
		}
		if len(fields) == 0 {
			return nil
		}
		return fields
	case reasoningEffortModels[modelId]:
		if req.Thinking != nil && req.Thinking.Type == "disabled" {
			effort = "none"
		}
		// Schema enum: none|low|medium|high|xhigh|max.
		switch effort {
		case "none", "low", "medium", "high", "xhigh", "max":
			return map[string]any{"reasoning": map[string]any{"effort": effort}}
		}
		return nil
	}
	return nil
}

var ModelMap = map[string]string{
	// Kiro supported models
	"claude-opus-4.6":   "claude-opus-4.6",
	"claude-opus-4.7":   "claude-opus-4.7",
	"claude-opus-4.8":   "claude-opus-4.8",
	"claude-sonnet-4.6": "claude-sonnet-4.6",
	"claude-sonnet-5":   "claude-sonnet-5",
	"claude-opus-5":     "claude-opus-5",
	"minimax-m2.5":      "minimax-m2.5",
	"glm-5":             "glm-5",
	"gpt-5.6-sol":       "gpt-5.6-sol",
	"gpt-5.6-terra":     "gpt-5.6-terra",
	"gpt-5.6-luna":      "gpt-5.6-luna",
	"claude-fable-5":    "claude-fable-5",
	// Anthropic SDK normalizes dots to hyphens in model names
	"claude-opus-4-6":   "claude-opus-4.6",
	"claude-opus-4-7":   "claude-opus-4.7",
	"claude-opus-4-8":   "claude-opus-4.8",
	"claude-sonnet-4-6": "claude-sonnet-4.6",
	"minimax-m2-5":      "minimax-m2.5",
	"gpt-5-6-sol":       "gpt-5.6-sol",
	"gpt-5-6-terra":     "gpt-5.6-terra",
	"gpt-5-6-luna":      "gpt-5.6-luna",
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

// modelContextWindow holds maxInputTokens per ListAvailableModels; used to
// convert the upstream contextUsagePercentage into an absolute token count.
var modelContextWindow = map[string]int{
	"claude-opus-5":     1000000,
	"claude-sonnet-5":   1000000,
	"claude-opus-4.8":   1000000,
	"claude-opus-4.7":   1000000,
	"claude-opus-4.6":   1000000,
	"claude-sonnet-4.6": 1000000,
	"claude-fable-5":    1000000,
	"gpt-5.6-sol":       272000,
	"gpt-5.6-terra":     272000,
	"gpt-5.6-luna":      272000,
	"minimax-m2.5":      196000,
	"glm-5":             200000,
	"auto":              1000000,
}

// resolveInputTokens returns the real input token count derived from the
// upstream contextUsagePercentage when available, falling back to the chars/4
// estimate. The percentage is measured against the model's full window
// (modelContextWindow), not the payload-limited effective context.
func resolveInputTokens(anthropicReq AnthropicRequest, modelId string, contextUsagePct float64) int {
	if contextUsagePct > 0 {
		if window := modelContextWindow[modelId]; window > 0 {
			return int(contextUsagePct / 100 * float64(window))
		}
	}
	return estimateInputTokens(anthropicReq)
}

// maxUpstreamPayloadBytes is the measured Q API request size limit (~1.9MB for
// Claude/GPT models, ~600KB for minimax/glm; 2026-08). Reject slightly below
// the Claude/GPT threshold so clients get a clean request_too_large error they
// can react to (e.g. by compacting), instead of an opaque upstream 400.
const maxUpstreamPayloadBytes = 1850 * 1024

const smallModelPayloadBytes = 590 * 1024

// payloadLimitFor returns the request size limit for the given upstream model.
func payloadLimitFor(modelId string) int {
	switch modelId {
	case "minimax-m2.5", "glm-5":
		return smallModelPayloadBytes
	}
	return maxUpstreamPayloadBytes
}
