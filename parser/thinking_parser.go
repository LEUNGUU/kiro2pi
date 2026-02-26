package parser

import "strings"

// ThinkingTagParser parses <thinking> tags from text content
type ThinkingTagParser struct {
	state          int    // 0=PRE_CONTENT, 1=IN_THINKING, 2=STREAMING
	buffer         string
	hasThinking    bool
	openTag        string
	closeTag       string
}

var openTags = []string{"<thinking>", "<think>", "<reasoning>", "<thought>"}

// ParseResult from thinking tag parser
type ThinkingTagResult struct {
	ThinkingContent string
	RegularContent  string
	IsFirstChunk    bool
	IsLastChunk     bool
}

func NewThinkingTagParser() *ThinkingTagParser {
	return &ThinkingTagParser{state: 0}
}

func (p *ThinkingTagParser) Feed(content string) ThinkingTagResult {
	result := ThinkingTagResult{}
	if content == "" {
		return result
	}

	switch p.state {
	case 0: // PRE_CONTENT - looking for opening tag
		p.buffer += content
		stripped := strings.TrimLeft(p.buffer, " \t\n\r")

		for _, tag := range openTags {
			if strings.HasPrefix(stripped, tag) {
				// Found opening tag
				p.state = 1
				p.openTag = tag
				p.closeTag = "</" + tag[1:]
				p.hasThinking = true
				p.buffer = stripped[len(tag):]
				result.IsFirstChunk = true
				// Process buffer for closing tag
				return p.processThinkingBuffer(result)
			}
			// Could still be receiving tag
			if strings.HasPrefix(tag, stripped) && len(stripped) < len(tag) {
				return result
			}
		}
		// No tag found, switch to streaming
		if len(p.buffer) > 20 || !p.couldBeTagPrefix(stripped) {
			p.state = 2
			result.RegularContent = p.buffer
			p.buffer = ""
		}

	case 1: // IN_THINKING
		p.buffer += content
		return p.processThinkingBuffer(result)

	case 2: // STREAMING
		result.RegularContent = content
	}

	return result
}

func (p *ThinkingTagParser) processThinkingBuffer(result ThinkingTagResult) ThinkingTagResult {
	if idx := strings.Index(p.buffer, p.closeTag); idx != -1 {
		// Found closing tag
		result.ThinkingContent = p.buffer[:idx]
		result.IsLastChunk = true
		result.RegularContent = p.buffer[idx+len(p.closeTag):]
		p.state = 2
		p.buffer = ""
	} else if len(p.buffer) > len(p.closeTag) {
		// Send content but keep potential tag fragment
		safeLen := len(p.buffer) - len(p.closeTag)
		result.ThinkingContent = p.buffer[:safeLen]
		p.buffer = p.buffer[safeLen:]
	}
	return result
}

func (p *ThinkingTagParser) couldBeTagPrefix(text string) bool {
	if text == "" {
		return true
	}
	for _, tag := range openTags {
		if strings.HasPrefix(tag, text) {
			return true
		}
	}
	return false
}

func (p *ThinkingTagParser) Finalize() ThinkingTagResult {
	result := ThinkingTagResult{}
	if p.buffer != "" {
		if p.state == 1 {
			result.ThinkingContent = p.buffer
			result.IsLastChunk = true
		} else {
			result.RegularContent = p.buffer
		}
		p.buffer = ""
	}
	return result
}

func (p *ThinkingTagParser) HasThinking() bool {
	return p.hasThinking
}
