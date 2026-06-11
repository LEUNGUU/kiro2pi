package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// XmlToolParser detects <invoke name="...">...</invoke> XML tool call patterns
// in streaming text content and converts them to proper tool_use events.
// This handles the case where the Q API sends tool calls as XML text
// (typically after thinking continuation) instead of proper structured tool frames.
type XmlToolParser struct {
	buffer           string // accumulated text that might contain XML tool calls
	inInvoke         bool   // true when we're inside an <invoke> block
	prefixBuf        string // text before <invoke> that should be emitted as regular text
	hasDetectedTools bool   // true if any tool calls were detected
}

// XmlToolResult represents the result of feeding text to the parser
type XmlToolResult struct {
	RegularText string     // Text to emit as text_delta (before any <invoke>)
	ToolCalls   []XmlToolCall // Detected tool calls to emit as tool_use blocks
	Buffering   bool       // True if parser is holding back text (potential partial <invoke>)
}

// XmlToolCall represents a parsed tool call from XML
type XmlToolCall struct {
	Name  string
	ID    string
	Input string // JSON string of the tool input
}

// NewXmlToolParser creates a new parser instance
func NewXmlToolParser() *XmlToolParser {
	return &XmlToolParser{}
}

// Feed processes a text content fragment and returns parsed results.
// It detects <invoke name="..."><parameter name="...">...</parameter></invoke> patterns
// and converts them to tool call data.
func (p *XmlToolParser) Feed(content string) XmlToolResult {
	p.buffer += content
	return p.process()
}

// Flush returns any remaining buffered content as regular text.
// Call this when the text stream ends.
func (p *XmlToolParser) Flush() XmlToolResult {
	result := XmlToolResult{RegularText: p.buffer}
	p.buffer = ""
	p.inInvoke = false
	return result
}

// invokeStartRe matches the opening of an <invoke> tag
var invokeStartRe = regexp.MustCompile(`<invoke\s+name="([^"]+)"[^>]*>`)

// invokeEndRe matches the closing </invoke> tag
var invokeEndRe = regexp.MustCompile(`</invoke>`)

// paramRe matches parameter tags within an invoke block
var paramRe = regexp.MustCompile(`<parameter\s+name="([^"]+)">([\s\S]*?)</parameter>`)

func (p *XmlToolParser) process() XmlToolResult {
	var result XmlToolResult

	for {
		if !p.inInvoke {
			// Look for <invoke in the buffer
			idx := strings.Index(p.buffer, "<invoke")
			if idx == -1 {
				// No <invoke found. Check if buffer ends with a partial match
				// that could be the start of "<invoke"
				safeLen := len(p.buffer)
				// Check if any suffix of buffer is a prefix of "<invoke"
				for i := max(0, safeLen-7); i < safeLen; i++ {
					suffix := p.buffer[i:]
					if strings.HasPrefix("<invoke", suffix) && len(suffix) > 0 {
						// This suffix could be the start of <invoke
						result.RegularText += p.buffer[:i]
						p.buffer = suffix
						result.Buffering = true
						return result
					}
				}
				// No partial match - emit all as regular text
				result.RegularText += p.buffer
				p.buffer = ""
				return result
			}

			// Found <invoke at position idx
			// Text before it is regular text
			if idx > 0 {
				result.RegularText += p.buffer[:idx]
				p.buffer = p.buffer[idx:]
			}

			// Check if we have the full opening tag
			loc := invokeStartRe.FindStringIndex(p.buffer)
			if loc == nil {
				// Partial opening tag - keep buffering
				result.Buffering = true
				return result
			}

			// We have a complete opening tag - switch to in-invoke mode
			p.inInvoke = true
		}

		// In invoke mode - look for </invoke>
		endLoc := invokeEndRe.FindStringIndex(p.buffer)
		if endLoc == nil {
			// Haven't found closing tag yet - keep buffering
			result.Buffering = true
			return result
		}

		// We have a complete <invoke>...</invoke> block
		fullBlock := p.buffer[:endLoc[1]]
		p.buffer = p.buffer[endLoc[1]:]
		p.inInvoke = false

		// Parse the block
		toolCall := parseInvokeBlock(fullBlock)
		if toolCall != nil {
			result.ToolCalls = append(result.ToolCalls, *toolCall)
			p.hasDetectedTools = true
		} else {
			// Failed to parse - emit as regular text
			result.RegularText += fullBlock
		}

		// Continue processing remaining buffer (might have more invokes)
	}
}

// parseInvokeBlock parses a complete <invoke>...</invoke> XML block into a tool call
func parseInvokeBlock(block string) *XmlToolCall {
	// Extract tool name
	nameMatch := invokeStartRe.FindStringSubmatch(block)
	if nameMatch == nil {
		return nil
	}
	toolName := nameMatch[1]

	// Extract parameters
	params := make(map[string]interface{})
	paramMatches := paramRe.FindAllStringSubmatch(block, -1)
	for _, m := range paramMatches {
		paramName := m[1]
		paramValue := m[2]
		params[paramName] = paramValue
	}

	// Convert params to JSON
	inputJSON, err := json.Marshal(params)
	if err != nil {
		return nil
	}

	// Generate a tool use ID
	toolID := fmt.Sprintf("tooluse_%s", strings.ReplaceAll(uuid.New().String(), "-", "")[:22])

	return &XmlToolCall{
		Name:  toolName,
		ID:    toolID,
		Input: string(inputJSON),
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
