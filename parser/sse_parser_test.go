package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// readFixture loads a testdata fixture, skipping the test when it is absent.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", name, err)
	}
	return data
}

// collectDeltas concatenates the given delta field from content_block_delta
// events emitted at the given index.
func collectDeltas(events []SSEEvent, index int, deltaType, field string) string {
	var sb strings.Builder
	for _, e := range events {
		if e.Event != "content_block_delta" {
			continue
		}
		data, ok := e.Data.(map[string]interface{})
		if !ok || data["index"] != index {
			continue
		}
		delta, ok := data["delta"].(map[string]interface{})
		if !ok || delta["type"] != deltaType {
			continue
		}
		if s, ok := delta[field].(string); ok {
			sb.WriteString(s)
		}
	}
	return sb.String()
}

// blockStartType reports the content_block type started at the given index.
func blockStartType(events []SSEEvent, index int) string {
	for _, e := range events {
		if e.Event != "content_block_start" {
			continue
		}
		data, ok := e.Data.(map[string]interface{})
		if !ok || data["index"] != index {
			continue
		}
		if cb, ok := data["content_block"].(map[string]interface{}); ok {
			if s, ok := cb["type"].(string); ok {
				return s
			}
		}
	}
	return ""
}

func countEvents(events []SSEEvent, event string, index int) int {
	n := 0
	for _, e := range events {
		if e.Event != event {
			continue
		}
		if data, ok := e.Data.(map[string]interface{}); ok && data["index"] == index {
			n++
		}
	}
	return n
}

// TestDecodeFramesEventTypes pins the frame layout fix: before it, the payload
// started 4 bytes early and the ":event-type" header was never read.
func TestDecodeFramesEventTypes(t *testing.T) {
	tests := []struct {
		fixture string
		want    []string
	}{
		{
			fixture: "testdata/reasoning_opus5.bin",
			want: []string{
				"initial-response",
				"reasoningContentEvent", "reasoningContentEvent", "reasoningContentEvent",
				"reasoningContentEvent", "reasoningContentEvent", "reasoningContentEvent",
				"assistantResponseEvent", "assistantResponseEvent", "assistantResponseEvent",
				"assistantResponseEvent", "assistantResponseEvent", "assistantResponseEvent",
				"metadataEvent", "contextUsageEvent", "meteringEvent",
			},
		},
		{
			fixture: "testdata/tooluse_sonnet46.bin",
			want: []string{
				"initial-response",
				"toolUseEvent", "toolUseEvent", "toolUseEvent", "toolUseEvent", "toolUseEvent",
				"toolUseEvent", "toolUseEvent", "toolUseEvent", "toolUseEvent", "toolUseEvent",
				"toolUseEvent", "toolUseEvent", "toolUseEvent", "toolUseEvent", "toolUseEvent",
				"metadataEvent", "contextUsageEvent", "meteringEvent",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			frames := decodeFrames(readFixture(t, tc.fixture))
			if len(frames) != len(tc.want) {
				t.Fatalf("frame count = %d, want %d", len(frames), len(tc.want))
			}
			for i, want := range tc.want {
				if frames[i].EventType != want {
					t.Errorf("frame %d: event type = %q, want %q", i, frames[i].EventType, want)
				}
			}
			// Every payload must be valid JSON; corrupt framing shows up here.
			for i, f := range frames {
				var v interface{}
				if err := json.Unmarshal(f.Payload, &v); err != nil {
					t.Errorf("frame %d (%s): payload not valid JSON: %v (%q)",
						i, f.EventType, err, f.Payload)
				}
			}
		})
	}
}

// TestParseEventsNativeReasoning covers the reasoningContentEvent path used by
// opus models, whose reasoning was previously discarded entirely.
func TestParseEventsNativeReasoning(t *testing.T) {
	const (
		wantReasoning = "Multiplying 17 by 23 gives 391."
		wantText      = "17 × 23 = 17 × 20 + 17 × 3 = 340 + 51 = **391**"
		wantSigPrefix = "CAISogIKcAgQEAEYAipAigEFQBU574YgLJTFeokX"
		wantSigLen    = 396
	)

	result := ParseEventsWithThinking(readFixture(t, "testdata/reasoning_opus5.bin"))

	if got := blockStartType(result.Events, 0); got != "thinking" {
		t.Errorf("index 0 content_block type = %q, want %q", got, "thinking")
	}
	if got := collectDeltas(result.Events, 0, "thinking_delta", "thinking"); got != wantReasoning {
		t.Errorf("reasoning text = %q, want %q", got, wantReasoning)
	}

	sig := collectDeltas(result.Events, 0, "signature_delta", "signature")
	if len(sig) != wantSigLen {
		t.Errorf("signature length = %d, want %d", len(sig), wantSigLen)
	}
	if !strings.HasPrefix(sig, wantSigPrefix) {
		t.Errorf("signature = %q, want prefix %q", sig, wantSigPrefix)
	}

	if got := blockStartType(result.Events, 1); got != "text" {
		t.Errorf("index 1 content_block type = %q, want %q", got, "text")
	}
	if got := collectDeltas(result.Events, 1, "text_delta", "text"); got != wantText {
		t.Errorf("assistant text = %q, want %q", got, wantText)
	}

	if !result.HasThinking {
		t.Error("HasThinking = false, want true")
	}
	if result.TextIndex != 1 {
		t.Errorf("TextIndex = %d, want 1", result.TextIndex)
	}
	// Critical: a non-empty ThinkingToolId makes handleStreamRequest fire a
	// second upstream request, doubling latency and credit spend, even though
	// opus already returned its final text in this same response.
	if result.ThinkingToolId != "" {
		t.Errorf("ThinkingToolId = %q, want empty on the native reasoning path", result.ThinkingToolId)
	}
	if result.ThinkingInput != "" {
		t.Errorf("ThinkingInput = %q, want empty on the native reasoning path", result.ThinkingInput)
	}
	if result.HasRegularTools {
		t.Error("HasRegularTools = true, want false")
	}

	// The thinking block must be closed exactly once, before text starts.
	if n := countEvents(result.Events, "content_block_stop", 0); n != 1 {
		t.Errorf("content_block_stop at index 0 emitted %d times, want 1", n)
	}
	stopAt, textStartAt := -1, -1
	for i, e := range result.Events {
		data, ok := e.Data.(map[string]interface{})
		if !ok {
			continue
		}
		if e.Event == "content_block_stop" && data["index"] == 0 && stopAt == -1 {
			stopAt = i
		}
		if e.Event == "content_block_start" && data["index"] == 1 && textStartAt == -1 {
			textStartAt = i
		}
	}
	if stopAt == -1 || textStartAt == -1 || stopAt > textStartAt {
		t.Errorf("thinking stop (%d) must precede text start (%d)", stopAt, textStartAt)
	}
}

// TestParseEventsThinkingTool guards the pre-existing thinking-tool path, which
// is how sonnet models report reasoning. Unlike native reasoning, it must set
// ThinkingToolId so the continuation request still fires.
func TestParseEventsThinkingTool(t *testing.T) {
	const wantThought = "17 * 23\n\nBreak it down:\n17 * 23 = 17 * 20 + 17 * 3\n= 340 + 51\n= 391"

	result := ParseEventsWithThinking(readFixture(t, "testdata/tooluse_sonnet46.bin"))

	if got := blockStartType(result.Events, 0); got != "thinking" {
		t.Errorf("index 0 content_block type = %q, want %q", got, "thinking")
	}
	if !result.HasThinking {
		t.Error("HasThinking = false, want true")
	}
	if result.ThinkingToolId == "" {
		t.Error("ThinkingToolId is empty, want non-empty so continuation still fires")
	}
	if result.ThinkingInput != wantThought {
		t.Errorf("ThinkingInput = %q, want %q", result.ThinkingInput, wantThought)
	}
	if result.TextIndex != 1 {
		t.Errorf("TextIndex = %d, want 1", result.TextIndex)
	}
	if result.HasRegularTools {
		t.Error("HasRegularTools = true, want false (thinking is not a regular tool)")
	}
	// The thinking tool must not leak through as a tool_use block.
	for _, e := range result.Events {
		if e.Event != "content_block_start" {
			continue
		}
		if data, ok := e.Data.(map[string]interface{}); ok {
			if cb, ok := data["content_block"].(map[string]interface{}); ok {
				if cb["type"] == "tool_use" && cb["name"] == "thinking" {
					t.Error("thinking tool leaked as a tool_use content block")
				}
			}
		}
	}
}

// encodeTypedFrame builds one event-stream frame carrying a ":event-type" header,
// which encodeFrame (empty headers) cannot express.
// Header entry layout: nameLen(1) | name | valueType(1) | valueLen(2) | value.
func encodeTypedFrame(eventType, payload string) []byte {
	var header bytes.Buffer
	name := ":event-type"
	header.WriteByte(byte(len(name)))
	header.WriteString(name)
	header.WriteByte(7) // string value type
	binary.Write(&header, binary.BigEndian, uint16(len(eventType)))
	header.WriteString(eventType)

	headerBytes := header.Bytes()
	totalLen := uint32(16 + len(headerBytes) + len(payload))

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, totalLen)
	binary.Write(&buf, binary.BigEndian, uint32(len(headerBytes)))
	binary.Write(&buf, binary.BigEndian, uint32(0)) // prelude CRC (not validated)
	buf.Write(headerBytes)
	buf.WriteString(payload)
	binary.Write(&buf, binary.BigEndian, uint32(0)) // message CRC (not validated)
	return buf.Bytes()
}

// TestParseEventsReasoningResumesAfterText covers reasoning that resumes after
// text has already been emitted. A content block index may only be started once,
// so the second reasoning run must get a fresh index rather than reopening the
// already-stopped block at index 0. No fixture interleaves this way.
func TestParseEventsReasoningResumesAfterText(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(encodeTypedFrame("reasoningContentEvent", `{"text":"first"}`))
	stream.Write(encodeTypedFrame("assistantResponseEvent", `{"content":"answer"}`))
	stream.Write(encodeTypedFrame("reasoningContentEvent", `{"text":"second"}`))

	result := ParseEventsWithThinking(stream.Bytes())

	// No content block index may be started more than once.
	starts := map[int]int{}
	for _, e := range result.Events {
		if e.Event != "content_block_start" {
			continue
		}
		if data, ok := e.Data.(map[string]interface{}); ok {
			if idx, ok := data["index"].(int); ok {
				starts[idx]++
			}
		}
	}
	for idx, n := range starts {
		if n != 1 {
			t.Errorf("index %d started %d times, want 1", idx, n)
		}
	}

	if got := blockStartType(result.Events, 0); got != "thinking" {
		t.Errorf("index 0 = %q, want thinking", got)
	}
	if got := blockStartType(result.Events, 1); got != "text" {
		t.Errorf("index 1 = %q, want text", got)
	}
	// The resumed reasoning run must land on a fresh index above text.
	if got := blockStartType(result.Events, 2); got != "thinking" {
		t.Errorf("index 2 = %q, want thinking (resumed reasoning)", got)
	}
	if got := collectDeltas(result.Events, 0, "thinking_delta", "thinking"); got != "first" {
		t.Errorf("index 0 reasoning = %q, want %q", got, "first")
	}
	if got := collectDeltas(result.Events, 2, "thinking_delta", "thinking"); got != "second" {
		t.Errorf("index 2 reasoning = %q, want %q", got, "second")
	}
	// Every thinking block the parser opens must also be closed by the parser.
	// The text block is deliberately excluded: handleStreamRequest closes it
	// (main.go, guarded by textBlockStarted), not the parser.
	for _, idx := range []int{0, 2} {
		if n := countEvents(result.Events, "content_block_stop", idx); n != 1 {
			t.Errorf("index %d stopped %d times, want 1", idx, n)
		}
	}
}

// TestParseEventsReasoningParity guards the near-duplicate ParseEvents against
// ParseEventsWithThinking. Both were edited identically for reasoning support, so
// a fix landing in only one is the likeliest defect.
func TestParseEventsReasoningParity(t *testing.T) {
	data := readFixture(t, "testdata/reasoning_opus5.bin")

	plain := ParseEvents(data)
	tracked := ParseEventsWithThinking(data).Events

	if got := blockStartType(plain, 0); got != "thinking" {
		t.Errorf("ParseEvents index 0 = %q, want thinking", got)
	}
	if got := collectDeltas(plain, 0, "thinking_delta", "thinking"); got != "Multiplying 17 by 23 gives 391." {
		t.Errorf("ParseEvents reasoning = %q", got)
	}
	if collectDeltas(plain, 0, "signature_delta", "signature") == "" {
		t.Error("ParseEvents emitted no signature_delta")
	}
	if n := countEvents(plain, "content_block_stop", 0); n != 1 {
		t.Errorf("ParseEvents stopped index 0 %d times, want 1", n)
	}

	// Both functions must agree on the reasoning and text blocks they emit.
	if got, want := blockStartType(plain, 1), blockStartType(tracked, 1); got != want {
		t.Errorf("index 1 type: ParseEvents %q, ParseEventsWithThinking %q", got, want)
	}
	for _, c := range []struct {
		index            int
		deltaType, field string
	}{
		{0, "thinking_delta", "thinking"},
		{0, "signature_delta", "signature"},
		{1, "text_delta", "text"},
	} {
		got := collectDeltas(plain, c.index, c.deltaType, c.field)
		want := collectDeltas(tracked, c.index, c.deltaType, c.field)
		if got != want {
			t.Errorf("index %d %s: ParseEvents %q, ParseEventsWithThinking %q",
				c.index, c.deltaType, got, want)
		}
	}
}

// TestDecodeFramesNonStringHeaders ensures fixed-width header value types are
// skipped correctly. Per the event-stream spec only blob (6) and string (7)
// carry a 2-byte length prefix; bool (0/1) has no value bytes, and byte (2),
// short (3), integer (4), long (5), timestamp (8), uuid (9) are fixed-width.
// Misreading any of them as length-prefixed would desync the header scan and
// silently drop the frame.
func TestDecodeFramesNonStringHeaders(t *testing.T) {
	var header bytes.Buffer
	// :date, timestamp (type 8), 8-byte value — as sent by several AWS services.
	header.WriteByte(5)
	header.WriteString(":date")
	header.WriteByte(8)
	header.Write(make([]byte, 8))
	// bool-true header (type 0), no value bytes.
	header.WriteByte(4)
	header.WriteString(":ack")
	header.WriteByte(0)
	// :event-type, string (type 7).
	eventType := "reasoningContentEvent"
	header.WriteByte(11)
	header.WriteString(":event-type")
	header.WriteByte(7)
	binary.Write(&header, binary.BigEndian, uint16(len(eventType)))
	header.WriteString(eventType)

	payload := `{"text":"hi"}`
	headerBytes := header.Bytes()
	totalLen := uint32(16 + len(headerBytes) + len(payload))

	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, totalLen)
	binary.Write(&frame, binary.BigEndian, uint32(len(headerBytes)))
	binary.Write(&frame, binary.BigEndian, uint32(0)) // prelude CRC (not validated)
	frame.Write(headerBytes)
	frame.WriteString(payload)
	binary.Write(&frame, binary.BigEndian, uint32(0)) // message CRC (not validated)

	frames := decodeFrames(frame.Bytes())
	if len(frames) != 1 {
		t.Fatalf("frame count = %d, want 1", len(frames))
	}
	if frames[0].EventType != eventType {
		t.Errorf("event type = %q, want %q", frames[0].EventType, eventType)
	}
	if string(frames[0].Payload) != payload {
		t.Errorf("payload = %q, want %q", frames[0].Payload, payload)
	}
}

// TestDecodeFramesTruncated ensures a partial stream degrades gracefully rather
// than panicking: upstream responses can be cut off mid-frame.
func TestDecodeFramesTruncated(t *testing.T) {
	data := readFixture(t, "testdata/reasoning_opus5.bin")
	full := len(decodeFrames(data))

	for i := 0; i <= len(data); i++ {
		prefix := data[:i]
		frames := decodeFrames(prefix) // must not panic
		if len(frames) > full {
			t.Fatalf("prefix len %d yielded %d frames, more than the %d in the full stream",
				i, len(frames), full)
		}
		ParseEvents(prefix)
		ParseEventsWithThinking(prefix)
	}
}

// TestContentFilteredRefusal covers the CONTENT_FILTERED metadataEvent observed
// on claude-fable-5 with large inputs: upstream returns 200 with no assistant
// frames and buries the refusal in stopDetails.
func TestContentFilteredRefusal(t *testing.T) {
	payload := `{"stopDetails":{"refusal":{"category":"CYBER","explanation":"The selected model cannot continue this conversation."}},"stopReason":"CONTENT_FILTERED"}`
	resp := encodeTypedFrame("initial-response", `{"conversationId":""}`)
	resp = append(resp, encodeTypedFrame("metadataEvent", payload)...)

	result := ParseEventsWithThinking(resp)
	if len(result.Events) != 0 {
		t.Errorf("expected no events, got %d", len(result.Events))
	}
	if !strings.Contains(result.Refusal, "CYBER") || !strings.Contains(result.Refusal, "cannot continue") {
		t.Errorf("refusal not extracted: %q", result.Refusal)
	}

	if got := DetectRefusal(resp); got != result.Refusal {
		t.Errorf("DetectRefusal mismatch: %q vs %q", got, result.Refusal)
	}

	// A normal metadataEvent (no refusal) must not set Refusal.
	normal := encodeTypedFrame("metadataEvent", `{"stopReason":"end_turn"}`)
	if got := DetectRefusal(normal); got != "" {
		t.Errorf("false positive refusal: %q", got)
	}
}
