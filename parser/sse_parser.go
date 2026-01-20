package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
)

// debugEnabled checks if debug logging is enabled via DEBUG_SAVE_RAW env var
func debugEnabled() bool {
	val := os.Getenv("DEBUG_SAVE_RAW")
	return val == "true" || val == "1"
}

type assistantResponseEvent struct {
	Content   string  `json:"content"`
	Input     *string `json:"input,omitempty"`
	Name      string  `json:"name"`
	ToolUseId string  `json:"toolUseId"`
	Stop      bool    `json:"stop"`
}

type SSEEvent struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

// ParseResult contains parsed events and metadata about thinking tool usage
type ParseResult struct {
	Events          []SSEEvent
	ThinkingToolId  string // Original tool ID if thinking was used, empty otherwise
	ThinkingInput   string // Accumulated thinking content for continuation
	HasRegularTools bool   // True if response contains non-thinking tool calls
	TextIndex       int    // Index used for text content blocks (0 if no thinking, 1 if thinking present)
	HasThinking     bool   // True if response contains thinking blocks
}

func ParseEvents(resp []byte) []SSEEvent {

	events := []SSEEvent{}
	startedTools := make(map[string]bool)  // Track which tool_use IDs have been started
	toolIndexMap := make(map[string]int)   // Map tool_use ID to its index
	thinkingToolIds := make(map[string]bool) // Track which tool IDs are thinking tools
	nextToolIndex := 2                     // Next available index for tools (0=thinking if present, 1=text)
	lastContent := ""                      // Track last content for deduplication
	hasThinking := false                   // Track if we've seen thinking blocks
	textIndex := 0                         // Text index: 0 if no thinking, 1 if thinking present

	r := bytes.NewReader(resp)
	for {
		if r.Len() < 12 {
			break
		}

		var totalLen, headerLen uint32
		if err := binary.Read(r, binary.BigEndian, &totalLen); err != nil {
			break
		}
		if err := binary.Read(r, binary.BigEndian, &headerLen); err != nil {
			break
		}

		if int(totalLen) > r.Len()+8 {
			log.Println("Frame length invalid")
			break
		}

		// Skip header
		header := make([]byte, headerLen)
		if _, err := io.ReadFull(r, header); err != nil {
			break
		}

		payloadLen := int(totalLen) - int(headerLen) - 12
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}

		// Skip CRC32
		if _, err := r.Seek(4, io.SeekCurrent); err != nil {
			break
		}

		payloadStr := strings.TrimPrefix(string(payload), "vent")

		var evt assistantResponseEvent
		if err := json.Unmarshal([]byte(payloadStr), &evt); err == nil {
			// Debug log: show all parsed events when DEBUG_SAVE_RAW is enabled
			if debugEnabled() {
				log.Printf("DEBUG ParseEvents: raw payload=%s", payloadStr)
				log.Printf("DEBUG ParseEvents: parsed event Content=%q, ToolUseId=%q, Name=%q, Stop=%v, Input=%v",
					evt.Content, evt.ToolUseId, evt.Name, evt.Stop, evt.Input)
			}

			// Convert event to SSE, tracking started tools to avoid duplicate starts
			// Also track content for deduplication
			sseEvents := convertAssistantEventWithTracking(evt, startedTools, toolIndexMap, thinkingToolIds, &nextToolIndex, &lastContent, &hasThinking, &textIndex)
			events = append(events, sseEvents...)

			// Add message_delta for tool_use stop, but skip for thinking tools
			// Thinking tools are converted to thinking content blocks, not tool_use
			if evt.ToolUseId != "" && evt.Name != "" && evt.Name != "thinking" {
				if evt.Stop {
					events = append(events, SSEEvent{
						Event: "message_delta",
						Data: map[string]interface{}{
							"type": "message_delta",
							"delta": map[string]interface{}{
								"stop_reason":   "tool_use",
								"stop_sequence": nil,
							},
							"usage": map[string]interface{}{"output_tokens": 0},
						},
					})
				}

			}
		} else {
			log.Println("json unmarshal error:", err)
		}
	}

	return events
}

// convertAssistantEventToSSE converts a single event - for events that need multiple SSE events, use convertAssistantEventToSSEMulti
func convertAssistantEventToSSE(evt assistantResponseEvent) SSEEvent {
	if evt.Content != "" {
		return SSEEvent{
			Event: "content_block_delta",
			Data: map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]interface{}{
					"type": "text_delta",
					"text": evt.Content,
				},
			},
		}
	} else if evt.ToolUseId != "" && evt.Name != "" && !evt.Stop {
		// Only return start event here, input delta handled by convertAssistantEventToSSEMulti
		return SSEEvent{
			Event: "content_block_start",
			Data: map[string]interface{}{
				"type":  "content_block_start",
				"index": 1,
				"content_block": map[string]interface{}{
					"type":  "tool_use",
					"id":    evt.ToolUseId,
					"name":  evt.Name,
					"input": map[string]interface{}{},
				},
			},
		}
	} else if evt.Stop {
		return SSEEvent{
			Event: "content_block_stop",
			Data: map[string]interface{}{
				"type":  "content_block_stop",
				"index": 1,
			},
		}
	}

	return SSEEvent{}
}

// thinkingToolIdPrefix is used to identify thinking tool IDs for conversion to thinking blocks
const thinkingToolIdPrefix = "thinking_"

// thinkingState tracks state for processing thinking tool input
// Handles JSON envelope stripping and escape sequence unescaping across fragmented events
type thinkingState struct {
	envelopeStripped bool   // True once we've found and stripped {"thought": "
	accumulator      string // Accumulates chars until we find complete opening pattern
	pendingBackslash bool   // True if previous fragment ended with unprocessed backslash
}

// Global state for thinking processing per tool ID
var thinkingStates = make(map[string]*thinkingState)

func getThinkingState(toolId string) *thinkingState {
	if state, exists := thinkingStates[toolId]; exists {
		return state
	}
	state := &thinkingState{}
	thinkingStates[toolId] = state
	return state
}

func clearThinkingState(toolId string) {
	delete(thinkingStates, toolId)
}

// processThinkingInput processes thinking tool input with stateful tracking
// Handles: 1) JSON envelope stripping {"thought": "..."}, 2) Escape sequence unescaping \n etc.
// Both can be fragmented across events by Q API
func processThinkingInput(toolId string, fragment string) string {
	state := getThinkingState(toolId)

	// Phase 1: Envelope stripping
	if !state.envelopeStripped {
		state.accumulator += fragment

		// Look for complete opening pattern
		openingPatterns := []string{`{"thought": "`, `{"thought":"`}
		for _, pattern := range openingPatterns {
			if idx := strings.Index(state.accumulator, pattern); idx != -1 {
				// Found it - extract content after pattern
				fragment = state.accumulator[idx+len(pattern):]
				state.envelopeStripped = true
				state.accumulator = ""
				break
			}
		}

		if !state.envelopeStripped {
			// Still accumulating - check if we can rule out ever finding pattern
			if len(state.accumulator) > 20 {
				// Something's wrong, pass through as-is
				fragment = state.accumulator
				state.accumulator = ""
				state.envelopeStripped = true
			} else {
				// Still waiting for complete pattern
				return ""
			}
		}
	}

	// Strip closing pattern if present
	if strings.HasSuffix(fragment, `"}`) {
		fragment = strings.TrimSuffix(fragment, `"}`)
	}

	// Phase 2: Escape sequence unescaping with state tracking
	// Handle backslash from previous fragment
	if state.pendingBackslash {
		fragment = `\` + fragment
		state.pendingBackslash = false
	}

	// Check for trailing incomplete escape
	trailingBackslashes := 0
	for i := len(fragment) - 1; i >= 0; i-- {
		if fragment[i] == '\\' {
			trailingBackslashes++
		} else {
			break
		}
	}
	if trailingBackslashes > 0 && trailingBackslashes%2 == 1 {
		state.pendingBackslash = true
		fragment = fragment[:len(fragment)-1]
	}

	// Unescape JSON string sequences
	quoted := `"` + fragment + `"`
	var unescaped string
	if err := json.Unmarshal([]byte(quoted), &unescaped); err == nil {
		return unescaped
	}

	// Fallback: manual replacement
	result := fragment
	result = strings.ReplaceAll(result, `\\`, "\x00BS\x00")
	result = strings.ReplaceAll(result, `\n`, "\n")
	result = strings.ReplaceAll(result, `\r`, "\r")
	result = strings.ReplaceAll(result, `\t`, "\t")
	result = strings.ReplaceAll(result, `\"`, `"`)
	result = strings.ReplaceAll(result, "\x00BS\x00", `\`)
	return result
}

// convertAssistantEventWithTracking handles events with tool tracking to avoid duplicate content_block_start
// Also implements content deduplication to prevent duplicate text content
// Index assignment: thinking gets index 0 (if present), text gets index 1 (or 0 if no thinking), tools get subsequent indexes
func convertAssistantEventWithTracking(evt assistantResponseEvent, startedTools map[string]bool, toolIndexMap map[string]int, thinkingToolIds map[string]bool, nextToolIndex *int, lastContent *string, hasThinking *bool, textIndex *int) []SSEEvent {
	var events []SSEEvent

	// Convert "thinking" tool calls to thinking content blocks
	// The Q API implements thinking as a tool, but clients expect thinking content blocks
	// Check both by Name and by tracked thinking tool IDs (for stop events that may not have Name)
	if evt.Name == "thinking" || (evt.ToolUseId != "" && thinkingToolIds[evt.ToolUseId]) {
		// Mark this tool ID as a thinking tool for future reference (e.g., stop events)
		if evt.Name == "thinking" && evt.ToolUseId != "" {
			thinkingToolIds[evt.ToolUseId] = true
			// First thinking block gets index 0, adjust text to index 1
			if !*hasThinking {
				*hasThinking = true
				*textIndex = 1 // Text will use index 1 since thinking uses index 0
			}
		}
		return convertThinkingToolToThinkingBlock(evt, startedTools, toolIndexMap, nextToolIndex, hasThinking)
	}

	// Debug: log what type of event we're processing
	if debugEnabled() {
		eventType := "unknown"
		if evt.Content != "" {
			eventType = "text_content"
		} else if evt.ToolUseId != "" && evt.Name != "" && !evt.Stop {
			eventType = "tool_use_start"
		} else if evt.Input != nil && *evt.Input != "" {
			eventType = "tool_input_delta"
		} else if evt.Stop {
			eventType = "tool_stop"
		}
		log.Printf("DEBUG convertEvent: type=%s, ToolUseId=%q, Name=%q, Stop=%v, hasInput=%v",
			eventType, evt.ToolUseId, evt.Name, evt.Stop, evt.Input != nil)
	}

	if evt.Content != "" {
		// Content deduplication: skip if same as last content
		if evt.Content == *lastContent {
			// Skip duplicate content
			return events
		}
		*lastContent = evt.Content

		// Send text content_block_start if this is the first text content
		if !startedTools["__text__"] {
			events = append(events, SSEEvent{
				Event: "content_block_start",
				Data: map[string]interface{}{
					"type":  "content_block_start",
					"index": *textIndex,
					"content_block": map[string]interface{}{
						"type": "text",
						"text": "",
					},
				},
			})
			startedTools["__text__"] = true
		}

		events = append(events, SSEEvent{
			Event: "content_block_delta",
			Data: map[string]interface{}{
				"type":  "content_block_delta",
				"index": *textIndex,
				"delta": map[string]interface{}{
					"type": "text_delta",
					"text": evt.Content,
				},
			},
		})
	} else if evt.ToolUseId != "" && evt.Name != "" && !evt.Stop {
		// Get or assign index for this tool
		toolIndex, exists := toolIndexMap[evt.ToolUseId]
		if !exists {
			toolIndex = *nextToolIndex
			toolIndexMap[evt.ToolUseId] = toolIndex
			*nextToolIndex++
		}

		// Only send content_block_start if we haven't started this tool yet
		if !startedTools[evt.ToolUseId] {
			events = append(events, SSEEvent{
				Event: "content_block_start",
				Data: map[string]interface{}{
					"type":  "content_block_start",
					"index": toolIndex,
					"content_block": map[string]interface{}{
						"type":  "tool_use",
						"id":    evt.ToolUseId,
						"name":  evt.Name,
						"input": map[string]interface{}{},
					},
				},
			})
			startedTools[evt.ToolUseId] = true
		}
		// If there's input, send content_block_delta
		if evt.Input != nil && *evt.Input != "" {
			events = append(events, SSEEvent{
				Event: "content_block_delta",
				Data: map[string]interface{}{
					"type":  "content_block_delta",
					"index": toolIndex,
					"delta": map[string]interface{}{
						"type":         "input_json_delta",
						"partial_json": *evt.Input,
					},
				},
			})
		}
	} else if evt.Input != nil && *evt.Input != "" {
		// Input delta without tool start (continuation) - need to find the index
		// This is a fallback case, use index 1 if we don't know the tool
		toolIndex := 1
		if evt.ToolUseId != "" {
			if idx, exists := toolIndexMap[evt.ToolUseId]; exists {
				toolIndex = idx
			}
		}
		events = append(events, SSEEvent{
			Event: "content_block_delta",
			Data: map[string]interface{}{
				"type":  "content_block_delta",
				"index": toolIndex,
				"delta": map[string]interface{}{
					"type":         "input_json_delta",
					"partial_json": *evt.Input,
				},
			},
		})
	} else if evt.Stop {
		// For stop events, find the correct index
		toolIndex := 1 // Default
		if evt.ToolUseId != "" {
			if idx, exists := toolIndexMap[evt.ToolUseId]; exists {
				toolIndex = idx
			}
		}
		events = append(events, SSEEvent{
			Event: "content_block_stop",
			Data: map[string]interface{}{
				"type":  "content_block_stop",
				"index": toolIndex,
			},
		})
	}

	return events
}

// ParseEventsWithThinking parses response and returns metadata about thinking tool usage
// This is used for automatic thinking continuation - when thinking tool is detected,
// the caller can automatically send empty tool result to get continuation
func ParseEventsWithThinking(resp []byte) ParseResult {
	result := ParseResult{}

	startedTools := make(map[string]bool)
	toolIndexMap := make(map[string]int)
	thinkingToolIds := make(map[string]bool)
	nextToolIndex := 2      // Next available index for tools (0=thinking if present, 1=text)
	lastContent := ""
	hasThinking := false    // Track if we've seen thinking blocks
	textIndex := 0          // Text index: 0 if no thinking, 1 if thinking present

	// Track thinking input fragments to accumulate full content
	var thinkingInputBuilder strings.Builder

	r := bytes.NewReader(resp)
	for {
		if r.Len() < 12 {
			break
		}

		var totalLen, headerLen uint32
		if err := binary.Read(r, binary.BigEndian, &totalLen); err != nil {
			break
		}
		if err := binary.Read(r, binary.BigEndian, &headerLen); err != nil {
			break
		}

		if int(totalLen) > r.Len()+8 {
			log.Println("Frame length invalid")
			break
		}

		header := make([]byte, headerLen)
		if _, err := io.ReadFull(r, header); err != nil {
			break
		}

		payloadLen := int(totalLen) - int(headerLen) - 12
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}

		if _, err := r.Seek(4, io.SeekCurrent); err != nil {
			break
		}

		payloadStr := strings.TrimPrefix(string(payload), "vent")

		var evt assistantResponseEvent
		if err := json.Unmarshal([]byte(payloadStr), &evt); err == nil {
			if debugEnabled() {
				log.Printf("DEBUG ParseEventsWithThinking: raw payload=%s", payloadStr)
			}

			// Track thinking tool ID and accumulate input
			if evt.Name == "thinking" {
				if result.ThinkingToolId == "" && evt.ToolUseId != "" {
					result.ThinkingToolId = evt.ToolUseId
				}
				thinkingToolIds[evt.ToolUseId] = true

				// Accumulate thinking input (raw, for sending back in continuation)
				if evt.Input != nil && *evt.Input != "" {
					thinkingInputBuilder.WriteString(*evt.Input)
				}
			} else if evt.ToolUseId != "" && thinkingToolIds[evt.ToolUseId] {
				// Stop event for thinking tool
				if evt.Input != nil && *evt.Input != "" {
					thinkingInputBuilder.WriteString(*evt.Input)
				}
			} else if evt.ToolUseId != "" && evt.Name != "" && evt.Name != "thinking" {
				// Regular (non-thinking) tool detected
				result.HasRegularTools = true
			}

			sseEvents := convertAssistantEventWithTracking(evt, startedTools, toolIndexMap, thinkingToolIds, &nextToolIndex, &lastContent, &hasThinking, &textIndex)
			result.Events = append(result.Events, sseEvents...)

			// Add message_delta for non-thinking tool_use stop
			if evt.ToolUseId != "" && evt.Name != "" && evt.Name != "thinking" {
				if evt.Stop {
					result.Events = append(result.Events, SSEEvent{
						Event: "message_delta",
						Data: map[string]interface{}{
							"type": "message_delta",
							"delta": map[string]interface{}{
								"stop_reason":   "tool_use",
								"stop_sequence": nil,
							},
							"usage": map[string]interface{}{"output_tokens": 0},
						},
					})
				}
			}
		} else {
			log.Println("json unmarshal error:", err)
		}
	}

	// Parse accumulated thinking input to extract actual thought content
	// Input format: {"thought": "actual content here"}
	rawInput := thinkingInputBuilder.String()
	if rawInput != "" {
		// Try to parse as JSON to extract thought field
		var thinkingJSON map[string]string
		if err := json.Unmarshal([]byte(rawInput), &thinkingJSON); err == nil {
			if thought, ok := thinkingJSON["thought"]; ok {
				result.ThinkingInput = thought
			}
		} else {
			// Fallback: store raw input
			result.ThinkingInput = rawInput
		}
	}

	// Set text index and thinking flag in result
	result.TextIndex = textIndex
	result.HasThinking = hasThinking

	return result
}

// convertThinkingToolToThinkingBlock converts a "thinking" tool call to thinking content blocks
// The Q API implements thinking as a tool with input {"thought": "..."}, but Anthropic API
// clients expect thinking as content blocks with type "thinking"
// Thinking blocks always get index 0 to ensure they appear before text content
func convertThinkingToolToThinkingBlock(evt assistantResponseEvent, startedTools map[string]bool, toolIndexMap map[string]int, nextToolIndex *int, hasThinking *bool) []SSEEvent {
	var events []SSEEvent

	// Use a special marker to track thinking blocks (prefixed tool ID)
	thinkingId := thinkingToolIdPrefix + evt.ToolUseId

	if debugEnabled() {
		log.Printf("DEBUG convertThinkingTool: ToolUseId=%q, Stop=%v, hasInput=%v",
			evt.ToolUseId, evt.Stop, evt.Input != nil)
	}

	// Handle thinking tool start - emit thinking content_block_start
	if evt.ToolUseId != "" && !evt.Stop {
		// Thinking always gets index 0 to appear before text content
		thinkingIndex := 0
		if _, exists := toolIndexMap[thinkingId]; !exists {
			toolIndexMap[thinkingId] = thinkingIndex
		}

		// Only send content_block_start if we haven't started this thinking block yet
		if !startedTools[thinkingId] {
			events = append(events, SSEEvent{
				Event: "content_block_start",
				Data: map[string]interface{}{
					"type":  "content_block_start",
					"index": thinkingIndex,
					"content_block": map[string]interface{}{
						"type":     "thinking",
						"thinking": "",
					},
				},
			})
			startedTools[thinkingId] = true
		}

		// If there's input, process it with stateful envelope stripping and escape unescaping
		// The Q API sends {"thought": "content"} but splits it character by character
		// Both the envelope and escape sequences (\n, etc.) can be fragmented
		if evt.Input != nil && *evt.Input != "" {
			// Use stateful processing to handle fragmentation
			content := processThinkingInput(evt.ToolUseId, *evt.Input)

			// Only send if there's actual content after processing
			if content != "" {
				events = append(events, SSEEvent{
					Event: "content_block_delta",
					Data: map[string]interface{}{
						"type":  "content_block_delta",
						"index": thinkingIndex,
						"delta": map[string]interface{}{
							"type":     "thinking_delta",
							"thinking": content,
						},
					},
				})
			}
		}
	} else if evt.Stop {
		// Handle thinking tool stop - emit thinking content_block_stop
		thinkingIndex := 0 // Thinking always at index 0
		if idx, exists := toolIndexMap[thinkingId]; exists {
			thinkingIndex = idx
		}

		// Clear thinking state for this tool
		clearThinkingState(evt.ToolUseId)

		events = append(events, SSEEvent{
			Event: "content_block_stop",
			Data: map[string]interface{}{
				"type":  "content_block_stop",
				"index": thinkingIndex,
			},
		})
	}

	return events
}
