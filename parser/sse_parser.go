package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
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

type reasoningContentEvent struct {
	Text            string `json:"text"`
	Signature       string `json:"signature"`
	RedactedContent []byte `json:"redactedContent"`
}

type eventFrame struct {
	EventType string
	Payload   []byte
}

// decodeFrames decodes AWS event-stream frames, returning all complete frames.
// Malformed or truncated input stops decoding without discarding earlier frames.
func decodeFrames(resp []byte) []eventFrame {
	frames := []eventFrame{}
	r := bytes.NewReader(resp)

	for r.Len() >= 12 {
		var totalLen, headerLen uint32
		if err := binary.Read(r, binary.BigEndian, &totalLen); err != nil {
			break
		}
		if err := binary.Read(r, binary.BigEndian, &headerLen); err != nil {
			break
		}

		if totalLen < 16 || headerLen > totalLen-16 || uint64(totalLen)-8 > uint64(r.Len()) {
			break
		}

		// Skip the prelude CRC, which sits between the lengths and headers.
		if _, err := r.Seek(4, io.SeekCurrent); err != nil {
			break
		}

		header := make([]byte, int(headerLen))
		if _, err := io.ReadFull(r, header); err != nil {
			break
		}

		eventType := ""
		for offset := 0; offset < len(header); {
			nameLen := int(header[offset])
			offset++
			if nameLen > len(header)-offset-1 {
				return frames
			}

			name := string(header[offset : offset+nameLen])
			offset += nameLen
			valueType := header[offset]
			offset++

			// Per the event-stream spec, only blob (6) and string (7) values carry
			// a 2-byte length prefix; bool (0/1) has no value bytes and the rest
			// are fixed-width: byte (2), short (3), integer (4), long (5),
			// timestamp (8), uuid (9).
			var valueLen int
			switch valueType {
			case 0, 1:
				valueLen = 0
			case 2:
				valueLen = 1
			case 3:
				valueLen = 2
			case 4:
				valueLen = 4
			case 5, 8:
				valueLen = 8
			case 9:
				valueLen = 16
			case 6, 7:
				if len(header)-offset < 2 {
					return frames
				}
				valueLen = int(binary.BigEndian.Uint16(header[offset : offset+2]))
				offset += 2
			default:
				// Unknown value type: cannot know its width, so stop decoding.
				return frames
			}
			if valueLen > len(header)-offset {
				return frames
			}

			if name == ":event-type" && valueType == 7 {
				eventType = string(header[offset : offset+valueLen])
			}
			offset += valueLen
		}

		payloadLen := int(totalLen - headerLen - 16)
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}
		if _, err := r.Seek(4, io.SeekCurrent); err != nil {
			break
		}

		frames = append(frames, eventFrame{EventType: eventType, Payload: payload})
	}

	return frames
}

type SSEEvent struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

// ParseResult contains parsed events and metadata about thinking tool usage
type ParseResult struct {
	Events          []SSEEvent
	ThinkingToolId  string  // Original tool ID if thinking was used, empty otherwise
	ThinkingInput   string  // Accumulated thinking content for continuation
	HasRegularTools bool    // True if response contains non-thinking tool calls
	TextIndex       int     // Index used for text content blocks (0 if no thinking, 1 if thinking present)
	HasThinking     bool    // True if response contains thinking blocks
	Refusal         string  // Non-empty if upstream stopped with CONTENT_FILTERED; holds the refusal explanation
	ContextUsagePct float64 // contextUsagePercentage from upstream (0 if absent); percentage of the model's real context window
}

// metadataStopDetails mirrors the metadataEvent payload carrying refusal info:
// {"stopDetails":{"refusal":{"category":"CYBER","explanation":"..."}},"stopReason":"CONTENT_FILTERED"}
type metadataStopDetails struct {
	StopReason  string `json:"stopReason"`
	StopDetails struct {
		Refusal struct {
			Category    string `json:"category"`
			Explanation string `json:"explanation"`
		} `json:"refusal"`
	} `json:"stopDetails"`
}

// parseRefusal extracts a human-readable refusal message from a metadataEvent
// payload, or "" if the event does not indicate content filtering.
func parseRefusal(payload []byte) string {
	var md metadataStopDetails
	if err := json.Unmarshal(payload, &md); err != nil {
		return ""
	}
	if md.StopReason != "CONTENT_FILTERED" {
		return ""
	}
	msg := md.StopDetails.Refusal.Explanation
	if msg == "" {
		msg = "Upstream content filter blocked this response."
	}
	if c := md.StopDetails.Refusal.Category; c != "" {
		msg = fmt.Sprintf("[content filter: %s] %s", c, msg)
	}
	return msg
}

// DetectRefusal scans a raw event-stream response for a metadataEvent with
// stopReason CONTENT_FILTERED and returns the refusal message, or "".
func DetectRefusal(resp []byte) string {
	for _, frame := range decodeFrames(resp) {
		if frame.EventType != "metadataEvent" {
			continue
		}
		if r := parseRefusal(frame.Payload); r != "" {
			return r
		}
	}
	return ""
}

// DetectContextUsage scans a raw event-stream response for a contextUsageEvent
// and returns contextUsagePercentage, or 0 if absent.
func DetectContextUsage(resp []byte) float64 {
	for _, frame := range decodeFrames(resp) {
		if frame.EventType != "contextUsageEvent" {
			continue
		}
		var cu struct {
			ContextUsagePercentage float64 `json:"contextUsagePercentage"`
		}
		if err := json.Unmarshal(frame.Payload, &cu); err == nil && cu.ContextUsagePercentage > 0 {
			return cu.ContextUsagePercentage
		}
	}
	return 0
}

func ParseEvents(resp []byte) []SSEEvent {
	events := []SSEEvent{}
	startedTools := make(map[string]bool)    // Track which tool_use IDs have been started
	toolIndexMap := make(map[string]int)     // Map tool_use ID to its index
	thinkingToolIds := make(map[string]bool) // Track which tool IDs are thinking tools
	nextToolIndex := 1                       // Next available index for tools (after text at 0; bumped to 2 if thinking appears)
	lastContent := ""                        // Track last content for deduplication
	hasThinking := false                     // Track if we've seen thinking blocks
	textIndex := 0                           // Text index: 0 if no thinking, 1 if thinking present
	tagParser := NewThinkingTagParser()      // Parser for <thinking> tags in text content
	xmlParser := NewXmlToolParser()          // Parser for XML tool calls in text content
	reasoningOpen := false                   // A native reasoning block is currently open
	reasoningSeen := false                   // At least one native reasoning block was emitted
	reasoningIndex := 0                      // Index of the current native reasoning block

	for _, frame := range decodeFrames(resp) {
		switch frame.EventType {
		case "reasoningContentEvent":
			var evt reasoningContentEvent
			if err := json.Unmarshal(frame.Payload, &evt); err != nil {
				log.Println("json unmarshal error:", err)
				continue
			}
			if debugEnabled() {
				log.Printf("DEBUG ParseEvents: reasoning payload=%s", frame.Payload)
			}

			if !reasoningOpen {
				// Reasoning can resume after text. A content block index may only
				// be started once, so later runs get a fresh index instead of
				// reopening the already-stopped block at index 0.
				if reasoningSeen {
					reasoningIndex = nextToolIndex
					nextToolIndex++
				} else {
					reasoningIndex = 0
					hasThinking = true
					textIndex = 1
					if nextToolIndex < 2 {
						nextToolIndex = 2
					}
				}
				events = append(events, SSEEvent{
					Event: "content_block_start",
					Data: map[string]interface{}{
						"type":  "content_block_start",
						"index": reasoningIndex,
						"content_block": map[string]interface{}{
							"type":     "thinking",
							"thinking": "",
						},
					},
				})
				reasoningOpen = true
				reasoningSeen = true
			}
			if evt.Text != "" {
				events = append(events, SSEEvent{
					Event: "content_block_delta",
					Data: map[string]interface{}{
						"type":  "content_block_delta",
						"index": reasoningIndex,
						"delta": map[string]interface{}{
							"type":     "thinking_delta",
							"thinking": evt.Text,
						},
					},
				})
			}
			if evt.Signature != "" {
				events = append(events, SSEEvent{
					Event: "content_block_delta",
					Data: map[string]interface{}{
						"type":  "content_block_delta",
						"index": reasoningIndex,
						"delta": map[string]interface{}{
							"type":      "signature_delta",
							"signature": evt.Signature,
						},
					},
				})
			}
			continue
		case "initial-response", "metadataEvent", "contextUsageEvent", "meteringEvent":
			if debugEnabled() {
				log.Printf("DEBUG ParseEvents: ignoring %s payload=%s", frame.EventType, frame.Payload)
			}
			continue
		case "assistantResponseEvent", "toolUseEvent", "":
			// Parse through the existing assistant/tool path below.
		default:
			if debugEnabled() {
				log.Printf("DEBUG ParseEvents: unknown event type %q, using assistant fallback", frame.EventType)
			}
		}

		if reasoningOpen {
			events = append(events, SSEEvent{
				Event: "content_block_stop",
				Data: map[string]interface{}{
					"type":  "content_block_stop",
					"index": reasoningIndex,
				},
			})
			reasoningOpen = false
		}

		var evt assistantResponseEvent
		if err := json.Unmarshal(frame.Payload, &evt); err == nil {
			if debugEnabled() {
				log.Printf("DEBUG ParseEvents: raw payload=%s", frame.Payload)
				log.Printf("DEBUG ParseEvents: parsed event Content=%q, ToolUseId=%q, Name=%q, Stop=%v, Input=%v",
					evt.Content, evt.ToolUseId, evt.Name, evt.Stop, evt.Input)
			}

			sseEvents := convertAssistantEventWithTracking(evt, startedTools, toolIndexMap, thinkingToolIds, &nextToolIndex, &lastContent, &hasThinking, &textIndex, tagParser, xmlParser)
			events = append(events, sseEvents...)

			if evt.ToolUseId != "" && evt.Name != "" && evt.Name != "thinking" && evt.Stop {
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
		} else {
			log.Println("json unmarshal error:", err)
		}
	}

	if reasoningOpen {
		events = append(events, SSEEvent{
			Event: "content_block_stop",
			Data: map[string]interface{}{
				"type":  "content_block_stop",
				"index": reasoningIndex,
			},
		})
	}

	// Flush XML tool parser - emit any remaining buffered content
	flushResult := xmlParser.Flush()
	if flushResult.RegularText != "" {
		events = append(events, emitTextEvents(flushResult.RegularText, startedTools, textIndex)...)
	}
	for _, tc := range flushResult.ToolCalls {
		events = append(events, emitXmlToolEvents(tc, startedTools, &nextToolIndex, textIndex)...)
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

// emitThinkingEvents generates SSE events for thinking content from tag parser
func emitThinkingEvents(tagResult ThinkingTagResult, startedTools map[string]bool) []SSEEvent {
	var events []SSEEvent
	thinkingKey := "__thinking_tag__"

	if tagResult.IsFirstChunk && !startedTools[thinkingKey] {
		events = append(events, SSEEvent{
			Event: "content_block_start",
			Data: map[string]interface{}{
				"type":  "content_block_start",
				"index": 0,
				"content_block": map[string]interface{}{
					"type":     "thinking",
					"thinking": "",
				},
			},
		})
		startedTools[thinkingKey] = true
	}

	if tagResult.ThinkingContent != "" {
		events = append(events, SSEEvent{
			Event: "content_block_delta",
			Data: map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]interface{}{
					"type":     "thinking_delta",
					"thinking": tagResult.ThinkingContent,
				},
			},
		})
	}

	if tagResult.IsLastChunk {
		events = append(events, SSEEvent{
			Event: "content_block_stop",
			Data: map[string]interface{}{
				"type":  "content_block_stop",
				"index": 0,
			},
		})
	}
	return events
}

// emitTextEvents generates SSE events for regular text content
func emitTextEvents(content string, startedTools map[string]bool, textIndex int) []SSEEvent {
	var events []SSEEvent
	if !startedTools["__text__"] {
		events = append(events, SSEEvent{
			Event: "content_block_start",
			Data: map[string]interface{}{
				"type":  "content_block_start",
				"index": textIndex,
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
			"index": textIndex,
			"delta": map[string]interface{}{
				"type": "text_delta",
				"text": content,
			},
		},
	})
	return events
}

// emitXmlToolEvents generates SSE events for a tool call detected from XML text.
// Ensures text block is started first (for sequential indices), then emits tool_use events.
func emitXmlToolEvents(tc XmlToolCall, startedTools map[string]bool, nextToolIndex *int, textIndex int) []SSEEvent {
	var events []SSEEvent

	// Ensure text block is emitted first so indices are sequential
	if !startedTools["__text__"] {
		startedTools["__text__"] = true
		events = append(events, SSEEvent{
			Event: "content_block_start",
			Data: map[string]interface{}{
				"type":          "content_block_start",
				"index":         textIndex,
				"content_block": map[string]interface{}{"type": "text", "text": ""},
			},
		})
	}

	toolIndex := *nextToolIndex
	*nextToolIndex++

	// content_block_start for tool_use
	events = append(events, SSEEvent{
		Event: "content_block_start",
		Data: map[string]interface{}{
			"type":  "content_block_start",
			"index": toolIndex,
			"content_block": map[string]interface{}{
				"type":  "tool_use",
				"id":    tc.ID,
				"name":  tc.Name,
				"input": map[string]interface{}{},
			},
		},
	})
	startedTools[tc.ID] = true

	// input_json_delta with full input
	if tc.Input != "" && tc.Input != "{}" {
		events = append(events, SSEEvent{
			Event: "content_block_delta",
			Data: map[string]interface{}{
				"type":  "content_block_delta",
				"index": toolIndex,
				"delta": map[string]interface{}{
					"type":         "input_json_delta",
					"partial_json": tc.Input,
				},
			},
		})
	}

	// content_block_stop
	events = append(events, SSEEvent{
		Event: "content_block_stop",
		Data: map[string]interface{}{
			"type":  "content_block_stop",
			"index": toolIndex,
		},
	})

	// message_delta with stop_reason=tool_use
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

	return events
}

// convertAssistantEventWithTracking handles events with tool tracking to avoid duplicate content_block_start
// Also implements content deduplication to prevent duplicate text content
// Index assignment: thinking gets index 0 (if present), text gets index 1 (or 0 if no thinking), tools get subsequent indexes
func convertAssistantEventWithTracking(evt assistantResponseEvent, startedTools map[string]bool, toolIndexMap map[string]int, thinkingToolIds map[string]bool, nextToolIndex *int, lastContent *string, hasThinking *bool, textIndex *int, tagParser *ThinkingTagParser, xmlParser *XmlToolParser) []SSEEvent {
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
				if *nextToolIndex < 2 {
					*nextToolIndex = 2
				}
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
			return events
		}
		*lastContent = evt.Content

		// Parse content through thinking tag parser
		tagResult := tagParser.Feed(evt.Content)

		// Emit thinking content if found
		if tagResult.ThinkingContent != "" {
			if tagResult.IsFirstChunk && !*hasThinking {
				*hasThinking = true
				*textIndex = 1
				if *nextToolIndex < 2 {
					*nextToolIndex = 2
				}
			}
			events = append(events, emitThinkingEvents(tagResult, startedTools)...)
		}

		// Emit regular content if any - feed through XML tool parser
		if tagResult.RegularContent != "" {
			xmlResult := xmlParser.Feed(tagResult.RegularContent)
			if xmlResult.RegularText != "" {
				events = append(events, emitTextEvents(xmlResult.RegularText, startedTools, *textIndex)...)
			}
			for _, tc := range xmlResult.ToolCalls {
				events = append(events, emitXmlToolEvents(tc, startedTools, nextToolIndex, *textIndex)...)
			}
		}
	} else if evt.ToolUseId != "" && evt.Name != "" && !evt.Stop {
		// Ensure text block is emitted before any tool_use block so indices are sequential
		if !startedTools["__text__"] {
			startedTools["__text__"] = true
			events = append(events, SSEEvent{
				Event: "content_block_start",
				Data: map[string]interface{}{
					"type":          "content_block_start",
					"index":         *textIndex,
					"content_block": map[string]interface{}{"type": "text", "text": ""},
				},
			})
		}
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
	nextToolIndex := 1 // Next available index for tools (after text at 0; bumped to 2 if thinking appears)
	lastContent := ""
	hasThinking := false                // Track if we've seen thinking blocks
	textIndex := 0                      // Text index: 0 if no thinking, 1 if thinking present
	tagParser := NewThinkingTagParser() // Parser for <thinking> tags in text content
	xmlParser := NewXmlToolParser()     // Parser for XML tool calls in text content
	reasoningOpen := false              // A native reasoning block is currently open
	reasoningSeen := false              // At least one native reasoning block was emitted
	reasoningIndex := 0                 // Index of the current native reasoning block

	// Track thinking input fragments to accumulate full content
	var thinkingInputBuilder strings.Builder

	for _, frame := range decodeFrames(resp) {
		switch frame.EventType {
		case "reasoningContentEvent":
			var evt reasoningContentEvent
			if err := json.Unmarshal(frame.Payload, &evt); err != nil {
				log.Println("json unmarshal error:", err)
				continue
			}
			if debugEnabled() {
				log.Printf("DEBUG ParseEventsWithThinking: reasoning payload=%s", frame.Payload)
			}

			if !reasoningOpen {
				// Reasoning can resume after text. A content block index may only
				// be started once, so later runs get a fresh index instead of
				// reopening the already-stopped block at index 0.
				if reasoningSeen {
					reasoningIndex = nextToolIndex
					nextToolIndex++
				} else {
					reasoningIndex = 0
					hasThinking = true
					textIndex = 1
					if nextToolIndex < 2 {
						nextToolIndex = 2
					}
				}
				result.Events = append(result.Events, SSEEvent{
					Event: "content_block_start",
					Data: map[string]interface{}{
						"type":  "content_block_start",
						"index": reasoningIndex,
						"content_block": map[string]interface{}{
							"type":     "thinking",
							"thinking": "",
						},
					},
				})
				reasoningOpen = true
				reasoningSeen = true
			}
			if evt.Text != "" {
				result.Events = append(result.Events, SSEEvent{
					Event: "content_block_delta",
					Data: map[string]interface{}{
						"type":  "content_block_delta",
						"index": reasoningIndex,
						"delta": map[string]interface{}{
							"type":     "thinking_delta",
							"thinking": evt.Text,
						},
					},
				})
			}
			if evt.Signature != "" {
				result.Events = append(result.Events, SSEEvent{
					Event: "content_block_delta",
					Data: map[string]interface{}{
						"type":  "content_block_delta",
						"index": reasoningIndex,
						"delta": map[string]interface{}{
							"type":      "signature_delta",
							"signature": evt.Signature,
						},
					},
				})
			}
			continue
		case "metadataEvent":
			if r := parseRefusal(frame.Payload); r != "" {
				result.Refusal = r
				log.Printf("Upstream CONTENT_FILTERED: %s", r)
			}
			continue
		case "contextUsageEvent":
			var cu struct {
				ContextUsagePercentage float64 `json:"contextUsagePercentage"`
			}
			if err := json.Unmarshal(frame.Payload, &cu); err == nil && cu.ContextUsagePercentage > 0 {
				result.ContextUsagePct = cu.ContextUsagePercentage
			}
			continue
		case "meteringEvent":
			// Not consumed yet; log the structure to learn what upstream reports
			// (credits, cache hits?) before wiring it up.
			log.Printf("meteringEvent payload: %s", frame.Payload)
			continue
		case "initial-response":
			if debugEnabled() {
				log.Printf("DEBUG ParseEventsWithThinking: ignoring %s payload=%s", frame.EventType, frame.Payload)
			}
			continue
		case "assistantResponseEvent", "toolUseEvent", "":
			// Parse through the existing assistant/tool path below.
		default:
			if debugEnabled() {
				log.Printf("DEBUG ParseEventsWithThinking: unknown event type %q, using assistant fallback", frame.EventType)
			}
		}

		if reasoningOpen {
			result.Events = append(result.Events, SSEEvent{
				Event: "content_block_stop",
				Data: map[string]interface{}{
					"type":  "content_block_stop",
					"index": reasoningIndex,
				},
			})
			reasoningOpen = false
		}

		var evt assistantResponseEvent
		if err := json.Unmarshal(frame.Payload, &evt); err == nil {
			if debugEnabled() {
				log.Printf("DEBUG ParseEventsWithThinking: raw payload=%s", frame.Payload)
			}

			// Track thinking tool ID and accumulate input. Native reasoning events
			// deliberately never set these continuation fields.
			if evt.Name == "thinking" {
				if result.ThinkingToolId == "" && evt.ToolUseId != "" {
					result.ThinkingToolId = evt.ToolUseId
				}
				thinkingToolIds[evt.ToolUseId] = true

				if evt.Input != nil && *evt.Input != "" {
					thinkingInputBuilder.WriteString(*evt.Input)
				}
			} else if evt.ToolUseId != "" && thinkingToolIds[evt.ToolUseId] {
				if evt.Input != nil && *evt.Input != "" {
					thinkingInputBuilder.WriteString(*evt.Input)
				}
			} else if evt.ToolUseId != "" && evt.Name != "" && evt.Name != "thinking" {
				result.HasRegularTools = true
			}

			sseEvents := convertAssistantEventWithTracking(evt, startedTools, toolIndexMap, thinkingToolIds, &nextToolIndex, &lastContent, &hasThinking, &textIndex, tagParser, xmlParser)
			result.Events = append(result.Events, sseEvents...)

			if xmlParser.hasDetectedTools {
				result.HasRegularTools = true
			}

			if evt.ToolUseId != "" && evt.Name != "" && evt.Name != "thinking" && evt.Stop {
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
		} else {
			log.Println("json unmarshal error:", err)
		}
	}

	if reasoningOpen {
		result.Events = append(result.Events, SSEEvent{
			Event: "content_block_stop",
			Data: map[string]interface{}{
				"type":  "content_block_stop",
				"index": reasoningIndex,
			},
		})
	}

	// Flush XML tool parser - emit any remaining buffered content
	flushResult := xmlParser.Flush()
	if flushResult.RegularText != "" {
		result.Events = append(result.Events, emitTextEvents(flushResult.RegularText, startedTools, textIndex)...)
	}
	for _, tc := range flushResult.ToolCalls {
		result.Events = append(result.Events, emitXmlToolEvents(tc, startedTools, &nextToolIndex, textIndex)...)
		result.HasRegularTools = true
	}

	// Parse accumulated thinking input to extract actual thought content
	// Input format: {"thought": "actual content here"}
	rawInput := thinkingInputBuilder.String()
	if rawInput != "" {
		var thinkingJSON map[string]string
		if err := json.Unmarshal([]byte(rawInput), &thinkingJSON); err == nil {
			if thought, ok := thinkingJSON["thought"]; ok {
				result.ThinkingInput = thought
			}
		} else {
			result.ThinkingInput = rawInput
		}
	}

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
