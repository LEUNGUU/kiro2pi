package main

import (
	"sort"
	"testing"
)

func TestModelCatalogFromKiroCLI(t *testing.T) {
	// Snapshot of kiro-cli 3.2.0, 2026-11, minus the three intentional exclusions.
	want := map[string]int{
		"claude-opus-5.5":   1000000,
		"claude-sonnet-5.5": 1000000,
		"claude-haiku-5.5":  1000000,
		"claude-opus-5":     1000000,
		"claude-sonnet-5":   1000000,
		"claude-opus-4.8":   1000000,
		"claude-opus-4.7":   1000000,
		"claude-sonnet-4.6": 1000000,
		"claude-opus-4.5":   200000,
		"claude-sonnet-4.5": 200000,
		"claude-haiku-4.5":  200000,
		"claude-fable-5.1":  1000000,
		"gpt-5.6-sol":       986000,
		"gpt-5.6-terra":     986000,
		"gpt-5.6-luna":      986000,
		"grok-4.7":          500000,
		"kimi-k3":           1000000,
		"deepseek-3.2":      164000,
		"minimax-m2.5":      196000,
		"minimax-m2.1":      196000,
		"glm-5":             200000,
	}
	if got := len(listCanonicalModels()); got != len(want) {
		t.Errorf("model count = %d, want %d", got, len(want))
	}
	if len(modelContextWindow) != len(want) {
		t.Errorf("context window count = %d, want %d", len(modelContextWindow), len(want))
	}
	for id, window := range want {
		if ModelMap[id] != id {
			t.Errorf("ModelMap[%q] = %q, want %q", id, ModelMap[id], id)
		}
		if modelContextWindow[id] != window {
			t.Errorf("modelContextWindow[%q] = %d, want %d", id, modelContextWindow[id], window)
		}
		if got := resolveInputTokens(AnthropicRequest{}, id, 10); got != window/10 {
			t.Errorf("resolveInputTokens(%q, 10%%) = %d, want %d", id, got, window/10)
		}
	}
	for alias, id := range map[string]string{
		"claude-haiku-5-5": "claude-haiku-5.5",
		"grok-4-7":         "grok-4.7",
	} {
		if ModelMap[alias] != id {
			t.Errorf("ModelMap[%q] = %q, want %q", alias, ModelMap[alias], id)
		}
	}
	if got := trimLimitFor("claude-haiku-5.5"); got != 980*1024 {
		t.Errorf("Haiku 5.5 trim limit = %d, want %d", got, 980*1024)
	}
}

func TestListCanonicalModels(t *testing.T) {
	got := listCanonicalModels()

	// (a) sorted
	if !sort.StringsAreSorted(got) {
		t.Errorf("listCanonicalModels() is not sorted: %v", got)
	}

	// (b) no duplicates
	seen := make(map[string]bool, len(got))
	for _, id := range got {
		if seen[id] {
			t.Errorf("listCanonicalModels() contains duplicate id %q", id)
		}
		seen[id] = true
	}

	// (c) every ModelMap value appears exactly once
	wantCounts := make(map[string]int)
	for _, canonical := range ModelMap {
		wantCounts[canonical]++
	}
	gotCounts := make(map[string]int)
	for _, id := range got {
		gotCounts[id]++
	}
	for canonical := range wantCounts {
		if gotCounts[canonical] != 1 {
			t.Errorf("expected canonical model %q to appear exactly once, got %d", canonical, gotCounts[canonical])
		}
	}
	for id, count := range gotCounts {
		if wantCounts[id] == 0 {
			t.Errorf("listCanonicalModels() returned %q which is not a ModelMap value", id)
		}
		if count != 1 {
			t.Errorf("listCanonicalModels() returned %q %d times, want 1", id, count)
		}
	}

	// (d) no alias keys leak in as IDs
	for key, canonical := range ModelMap {
		if key != canonical {
			if gotCounts[key] > 0 {
				t.Errorf("listCanonicalModels() leaked alias key %q as an id", key)
			}
		}
	}
}
