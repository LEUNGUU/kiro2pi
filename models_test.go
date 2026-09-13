package main

import (
	"sort"
	"testing"
)

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
