package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCopyHeadersForwardsRetryAfter verifies the OpenAI-compat paths forward
// the Retry-After header captured by responseRecorder onto the real writer,
// so a propagated 429 carries its backoff hint (the bug found in review).
func TestCopyHeadersForwardsRetryAfter(t *testing.T) {
	rec := &responseRecorder{headers: make(http.Header)}
	rec.Header().Set("Retry-After", "4")
	rec.WriteHeader(http.StatusTooManyRequests)

	w := httptest.NewRecorder()
	copyHeaders(w, rec.headers)
	w.WriteHeader(rec.code)

	if got := w.Result().Header.Get("Retry-After"); got != "4" {
		t.Fatalf("Retry-After not forwarded: got %q want %q", got, "4")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status not forwarded: got %d want 429", w.Code)
	}
}
