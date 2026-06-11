package parser

import (
	"encoding/json"
	"testing"
)

// TestXmlToolCallInText simulates the real bug: after thinking continuation,
// Q API sends tool call as XML text instead of proper structured tool frames.
// The parser should detect and convert the XML to proper tool_use events.
func TestXmlToolCallInText(t *testing.T) {
	// This simulates the continuation response from msg_20260606203457_continuation_1.raw
	frames := []string{
		`{"content":""}`,           // empty frame
		`{"content":"call"}`,       // text before invoke
		`{"content":"\n<invoke name=\"bash\">"}`,
		`{"content":"\n<parameter name=\"command\">"}`,
		`{"content":"ls /tmp"}`,
		`{"content":"</parameter>"}`,
		`{"content":"\n</invoke>"}`,
		`{"content":""}`,           // trailing empty
	}
	res := ParseEventsWithThinking(buildStream(frames))
	dumpEvents(t, "XML tool in text", res.Events)
	t.Logf("HasRegularTools=%v", res.HasRegularTools)

	if !res.HasRegularTools {
		t.Fatal("expected HasRegularTools=true, XML tool call should be detected")
	}

	// Verify a tool_use content_block_start was emitted
	foundToolUse := false
	for _, e := range res.Events {
		if e.Event == "content_block_start" {
			dm := e.Data.(map[string]interface{})
			if cb, ok := dm["content_block"].(map[string]interface{}); ok {
				if cb["type"] == "tool_use" && cb["name"] == "bash" {
					foundToolUse = true
					// Check index is 1 (text is at 0)
					if idx := dm["index"].(int); idx != 1 {
						t.Errorf("tool_use index=%d, want 1", idx)
					}
				}
			}
		}
	}
	if !foundToolUse {
		t.Fatal("no tool_use content_block_start found - XML tool call not converted")
	}

	// Verify tool input contains the command
	for _, e := range res.Events {
		if e.Event == "content_block_delta" {
			dm := e.Data.(map[string]interface{})
			if delta, ok := dm["delta"].(map[string]interface{}); ok {
				if delta["type"] == "input_json_delta" {
					inputJSON := delta["partial_json"].(string)
					var input map[string]interface{}
					if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
						t.Fatalf("failed to parse tool input JSON: %v", err)
					}
					if cmd, ok := input["command"].(string); !ok || cmd != "ls /tmp" {
						t.Errorf("tool input command=%q, want \"ls /tmp\"", cmd)
					}
					return
				}
			}
		}
	}
	t.Fatal("no input_json_delta found for the tool call")
}

// TestXmlToolCallAfterThinking simulates the full scenario:
// initial response has thinking tool, then continuation has XML tool text.
func TestXmlToolCallAfterThinking(t *testing.T) {
	// Simulate what main.go does: first parse thinking, then parse continuation separately
	// The continuation response is what has the XML tool call
	contFrames := []string{
		`{"content":""}`,
		`{"content":"I'll execute the command."}`,
		`{"content":"\n<invoke name=\"read\">"}`,
		`{"content":"\n<parameter name=\"path\">"}`,
		`{"content":"/etc/hosts"}`,
		`{"content":"</parameter>"}`,
		`{"content":"\n</invoke>"}`,
	}
	res := ParseEventsWithThinking(buildStream(contFrames))
	dumpEvents(t, "XML tool after text", res.Events)
	t.Logf("HasRegularTools=%v TextIndex=%d", res.HasRegularTools, res.TextIndex)

	if !res.HasRegularTools {
		t.Fatal("expected HasRegularTools=true")
	}

	// Text "I'll execute the command.\n" should be at index 0
	// Tool "read" should be at index 1
	var textIdx, toolIdx int
	for _, e := range res.Events {
		if e.Event == "content_block_start" {
			dm := e.Data.(map[string]interface{})
			cb := dm["content_block"].(map[string]interface{})
			switch cb["type"] {
			case "text":
				textIdx = dm["index"].(int)
			case "tool_use":
				toolIdx = dm["index"].(int)
				if cb["name"] != "read" {
					t.Errorf("tool name=%q, want \"read\"", cb["name"])
				}
			}
		}
	}
	if textIdx != 0 {
		t.Errorf("text index=%d, want 0", textIdx)
	}
	if toolIdx != 1 {
		t.Errorf("tool index=%d, want 1", toolIdx)
	}
}

// TestXmlMultipleToolCalls tests multiple <invoke> blocks in sequence
func TestXmlMultipleToolCalls(t *testing.T) {
	frames := []string{
		`{"content":"Here are two commands:"}`,
		`{"content":"\n<invoke name=\"bash\">"}`,
		`{"content":"\n<parameter name=\"command\">ls</parameter>"}`,
		`{"content":"\n</invoke>"}`,
		`{"content":"\n<invoke name=\"read\">"}`,
		`{"content":"\n<parameter name=\"path\">/etc/hosts</parameter>"}`,
		`{"content":"\n</invoke>"}`,
	}
	res := ParseEventsWithThinking(buildStream(frames))
	dumpEvents(t, "Multiple XML tools", res.Events)

	toolCount := 0
	for _, e := range res.Events {
		if e.Event == "content_block_start" {
			dm := e.Data.(map[string]interface{})
			if cb, ok := dm["content_block"].(map[string]interface{}); ok {
				if cb["type"] == "tool_use" {
					toolCount++
				}
			}
		}
	}
	if toolCount != 2 {
		t.Fatalf("expected 2 tool_use blocks, got %d", toolCount)
	}
}

// TestNoFalsePositiveXml ensures normal text with < chars doesn't trigger XML detection
func TestNoFalsePositiveXml(t *testing.T) {
	frames := []string{
		`{"content":"Use if x < 5 then do something"}`,
		`{"content":" and <b>bold</b> text"}`,
		`{"content":" with <invoked> not a tool"}`,
	}
	res := ParseEventsWithThinking(buildStream(frames))
	if res.HasRegularTools {
		t.Fatal("should not detect tools in normal text")
	}
	// All content should be text
	for _, e := range res.Events {
		if e.Event == "content_block_start" {
			dm := e.Data.(map[string]interface{})
			if cb, ok := dm["content_block"].(map[string]interface{}); ok {
				if cb["type"] == "tool_use" {
					t.Fatal("false positive: detected tool_use in normal text")
				}
			}
		}
	}
}
