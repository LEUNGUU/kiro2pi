package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// encodeFrame builds one CodeWhisperer event-stream frame around a JSON payload.
// Layout: [totalLen u32][headerLen u32][header bytes][ "vent"+payload ][crc u32]
func encodeFrame(payload string) []byte {
	header := []byte{} // empty header; parser only skips it
	body := []byte("vent" + payload)
	headerLen := uint32(len(header))
	totalLen := uint32(12 + len(header) + len(body))
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, totalLen)
	binary.Write(&buf, binary.BigEndian, headerLen)
	buf.Write(header)
	buf.Write(body)
	binary.Write(&buf, binary.BigEndian, uint32(0)) // crc (skipped)
	return buf.Bytes()
}

func buildStream(frames []string) []byte {
	var out bytes.Buffer
	for _, f := range frames {
		out.Write(encodeFrame(f))
	}
	return out.Bytes()
}

func dumpEvents(t *testing.T, label string, evs []SSEEvent) {
	t.Logf("==== %s ====", label)
	for _, e := range evs {
		if e.Event == "" {
			continue
		}
		dm, _ := e.Data.(map[string]interface{})
		idx := dm["index"]
		var detail string
		if cb, ok := dm["content_block"].(map[string]interface{}); ok {
			detail = fmt.Sprintf("block=%v name=%v", cb["type"], cb["name"])
		} else if d, ok := dm["delta"].(map[string]interface{}); ok {
			detail = fmt.Sprintf("delta=%v", d["type"])
		}
		t.Logf("  %-22s idx=%v %s", e.Event, idx, detail)
	}
}

// Scenario A: thinking tool, THEN text, THEN a real tool.
// This is the interleaving the bug report suspects opus 4.8 produces.
func TestReproThinkingThenTextThenTool(t *testing.T) {
	in := func(s string) string { return s }
	_ = in
	frames := []string{
		`{"toolUseId":"tk1","name":"thinking"}`,
		`{"toolUseId":"tk1","name":"thinking","input":"{\"thought\": \"hmm"}`,
		`{"toolUseId":"tk1","stop":true}`,
		`{"content":"Let me read the file."}`,
		`{"toolUseId":"rd1","name":"read"}`,
		`{"toolUseId":"rd1","name":"read","input":"{\"path\":\"/x\"}"}`,
		`{"toolUseId":"rd1","stop":true}`,
	}
	res := ParseEventsWithThinking(buildStream(frames))
	dumpEvents(t, "A thinking->text->tool", res.Events)
	t.Logf("TextIndex=%d HasThinking=%v HasRegularTools=%v", res.TextIndex, res.HasThinking, res.HasRegularTools)
}

// Scenario B: text FIRST, then thinking appears AFTER text already started.
// textIndex was 0 when text block started; thinking later flips textIndex->1
// but the text block is already open at index 0 and thinking also claims 0.
func TestReproTextThenThinkingThenTool(t *testing.T) {
	frames := []string{
		`{"content":"Sure, working on it."}`,
		`{"toolUseId":"tk1","name":"thinking"}`,
		`{"toolUseId":"tk1","name":"thinking","input":"{\"thought\": \"plan"}`,
		`{"toolUseId":"tk1","stop":true}`,
		`{"toolUseId":"rd1","name":"read"}`,
		`{"toolUseId":"rd1","name":"read","input":"{\"path\":\"/x\"}"}`,
		`{"toolUseId":"rd1","stop":true}`,
	}
	res := ParseEventsWithThinking(buildStream(frames))
	dumpEvents(t, "B text->thinking->tool", res.Events)
	t.Logf("TextIndex=%d HasThinking=%v HasRegularTools=%v", res.TextIndex, res.HasThinking, res.HasRegularTools)
}

// Scenario C: tool input continuation frame with NO toolUseId (fallback path).
func TestReproToolInputContinuationNoId(t *testing.T) {
	// two tools; second tool's continuation input arrives with empty toolUseId
	frames := []string{
		`{"content":"hi"}`,
		`{"toolUseId":"a1","name":"read"}`,
		`{"toolUseId":"a1","name":"read","input":"{\"path"}`,
		`{"toolUseId":"a1","stop":true}`,
		`{"toolUseId":"b2","name":"grep"}`,
		`{"toolUseId":"b2","name":"grep","input":"{\"pat"}`,
		`{"input":"tern\":\"x\"}"}`, // continuation, no toolUseId -> fallback index 1
		`{"toolUseId":"b2","stop":true}`,
	}
	res := ParseEventsWithThinking(buildStream(frames))
	dumpEvents(t, "C continuation-no-id", res.Events)
}
