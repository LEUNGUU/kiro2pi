package parser

import "testing"

// Guard: pure-text (no thinking, no tools) stays at index 0.
func TestRegressTextOnly(t *testing.T) {
	res := ParseEventsWithThinking(buildStream([]string{`{"content":"hello world"}`}))
	got := blockIndexOf(t, res.Events, "content_block_start")
	if got != 0 {
		t.Fatalf("text-only block start expected idx 0, got %d", got)
	}
	if res.TextIndex != 0 || res.HasThinking {
		t.Fatalf("TextIndex=%d HasThinking=%v", res.TextIndex, res.HasThinking)
	}
}

// Guard: thinking-first then text (the 4.6 ordering) keeps thinking@0,text@1.
func TestRegressThinkingFirstThenText(t *testing.T) {
	frames := []string{
		`{"toolUseId":"tk","name":"thinking"}`,
		`{"toolUseId":"tk","name":"thinking","input":"{\"thought\": \"x"}`,
		`{"toolUseId":"tk","stop":true}`,
		`{"content":"answer"}`,
	}
	res := ParseEventsWithThinking(buildStream(frames))
	// first start must be thinking@0, then text@1
	var seen []string
	for _, e := range res.Events {
		if e.Event == "content_block_start" {
			dm := e.Data.(map[string]interface{})
			cb := dm["content_block"].(map[string]interface{})
			seen = append(seen, cb["type"].(string))
			if cb["type"] == "thinking" && dm["index"].(int) != 0 {
				t.Fatalf("thinking not at 0: %v", dm["index"])
			}
			if cb["type"] == "text" && dm["index"].(int) != 1 {
				t.Fatalf("text not at 1: %v", dm["index"])
			}
		}
	}
	if !res.HasThinking || res.TextIndex != 1 {
		t.Fatalf("HasThinking=%v TextIndex=%d", res.HasThinking, res.TextIndex)
	}
}

func blockIndexOf(t *testing.T, evs []SSEEvent, event string) int {
	for _, e := range evs {
		if e.Event == event {
			return e.Data.(map[string]interface{})["index"].(int)
		}
	}
	t.Fatalf("no %s event", event)
	return -1
}
