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
}

func ParseEvents(resp []byte) []SSEEvent {

	events := []SSEEvent{}
	startedTools := make(map[string]bool)  // Track which tool_use IDs have been started
	toolIndexMap := make(map[string]int)   // Map tool_use ID to its index
	thinkingToolIds := make(map[string]bool) // Track which tool IDs are thinking tools
	nextToolIndex := 1                     // Next available index for tool_use (0 is reserved for text)
	lastContent := ""                      // Track last content for deduplication

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
			sseEvents := convertAssistantEventWithTracking(evt, startedTools, toolIndexMap, thinkingToolIds, &nextToolIndex, &lastContent)
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

// convertAssistantEventWithTracking handles events with tool tracking to avoid duplicate content_block_start
// Also implements content deduplication to prevent duplicate text content
func convertAssistantEventWithTracking(evt assistantResponseEvent, startedTools map[string]bool, toolIndexMap map[string]int, thinkingToolIds map[string]bool, nextToolIndex *int, lastContent *string) []SSEEvent {
	var events []SSEEvent

	// Convert "thinking" tool calls to thinking content blocks
	// The Q API implements thinking as a tool, but clients expect thinking content blocks
	// Check both by Name and by tracked thinking tool IDs (for stop events that may not have Name)
	if evt.Name == "thinking" || (evt.ToolUseId != "" && thinkingToolIds[evt.ToolUseId]) {
		// Mark this tool ID as a thinking tool for future reference (e.g., stop events)
		if evt.Name == "thinking" && evt.ToolUseId != "" {
			thinkingToolIds[evt.ToolUseId] = true
		}
		return convertThinkingToolToThinkingBlock(evt, startedTools, toolIndexMap, nextToolIndex)
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

		events = append(events, SSEEvent{
			Event: "content_block_delta",
			Data: map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
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
		toolIndex := 1
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
	nextToolIndex := 1
	lastContent := ""

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

			sseEvents := convertAssistantEventWithTracking(evt, startedTools, toolIndexMap, thinkingToolIds, &nextToolIndex, &lastContent)
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

	return result
}

// convertThinkingToolToThinkingBlock converts a "thinking" tool call to thinking content blocks
// The Q API implements thinking as a tool with input {"thought": "..."}, but Anthropic API
// clients expect thinking as content blocks with type "thinking"
func convertThinkingToolToThinkingBlock(evt assistantResponseEvent, startedTools map[string]bool, toolIndexMap map[string]int, nextToolIndex *int) []SSEEvent {
	var events []SSEEvent

	// Use a special marker to track thinking blocks (prefixed tool ID)
	thinkingId := thinkingToolIdPrefix + evt.ToolUseId

	if debugEnabled() {
		log.Printf("DEBUG convertThinkingTool: ToolUseId=%q, Stop=%v, hasInput=%v",
			evt.ToolUseId, evt.Stop, evt.Input != nil)
	}

	// Handle thinking tool start - emit thinking content_block_start
	if evt.ToolUseId != "" && !evt.Stop {
		// Get or assign index for this thinking block
		thinkingIndex, exists := toolIndexMap[thinkingId]
		if !exists {
			thinkingIndex = *nextToolIndex
			toolIndexMap[thinkingId] = thinkingIndex
			*nextToolIndex++
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

		// If there's input, extract the thinking content and send as thinking_delta
		// The input arrives as streaming JSON fragments like:
		// Fragment 1: {"thought": "
		// Fragment 2: The user wants...
		// Fragment N: "}
		// We need to strip the JSON envelope and just send the content
		if evt.Input != nil && *evt.Input != "" {
			input := *evt.Input

			// Strip JSON envelope parts from the input
			// Opening patterns: {"thought":" or {"thought": "
			input = strings.TrimPrefix(input, `{"thought":"`)
			input = strings.TrimPrefix(input, `{"thought": "`)
			// Closing pattern: "} (with possible escaped quote before)
			input = strings.TrimSuffix(input, `"}`)

			// Only send if there's actual content after stripping
			if input != "" {
				events = append(events, SSEEvent{
					Event: "content_block_delta",
					Data: map[string]interface{}{
						"type":  "content_block_delta",
						"index": thinkingIndex,
						"delta": map[string]interface{}{
							"type":     "thinking_delta",
							"thinking": input,
						},
					},
				})
			}
		}
	} else if evt.Stop {
		// Handle thinking tool stop - emit thinking content_block_stop
		thinkingIndex := 1 // Default
		if idx, exists := toolIndexMap[thinkingId]; exists {
			thinkingIndex = idx
		}
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
