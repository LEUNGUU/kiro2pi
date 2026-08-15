package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Observability database
var observDB *sql.DB

func initObservabilityDB() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".kiro2pi")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "observability.db"))
	if err != nil {
		return err
	}
	db.Exec("PRAGMA journal_mode=WAL")
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS call_log (
		id TEXT PRIMARY KEY,
		created_at TEXT NOT NULL,
		model TEXT NOT NULL,
		endpoint TEXT NOT NULL,
		stream INTEGER NOT NULL,
		input_tokens INTEGER,
		output_tokens INTEGER,
		latency_ms INTEGER NOT NULL,
		ttft_ms INTEGER,
		status_code INTEGER NOT NULL,
		error_message TEXT,
		request_hash TEXT,
		has_tools INTEGER DEFAULT 0,
		has_thinking INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_call_log_created ON call_log(created_at);
	CREATE INDEX IF NOT EXISTS idx_call_log_model ON call_log(model);`)
	if err != nil {
		db.Close()
		return err
	}
	observDB = db
	return nil
}

// observWriter wraps ResponseWriter to capture status code and time-to-first-byte
type observWriter struct {
	http.ResponseWriter
	statusCode int
	firstWrite time.Time
	startTime  time.Time
	wroteOnce  bool
}

func (w *observWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *observWriter) Write(b []byte) (int, error) {
	if !w.wroteOnce {
		w.wroteOnce = true
		w.firstWrite = time.Now()
	}
	return w.ResponseWriter.Write(b)
}

func (w *observWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func logCall(endpoint string, body []byte, anthropicReq AnthropicRequest, stream bool, ow *observWriter) {
	if observDB == nil {
		return
	}
	latency := time.Since(ow.startTime).Milliseconds()
	var ttft *int64
	if stream && ow.wroteOnce {
		v := ow.firstWrite.Sub(ow.startTime).Milliseconds()
		ttft = &v
	}
	statusCode := ow.statusCode
	if statusCode == 0 {
		statusCode = 200
	}
	hash := sha256.Sum256(body)
	hasTools := 0
	if len(anthropicReq.Tools) > 0 {
		hasTools = 1
	}
	hasThinking := 0
	if anthropicReq.Thinking != nil && (anthropicReq.Thinking.Type == "enabled" || anthropicReq.Thinking.Type == "adaptive") {
		hasThinking = 1
	}
	streamInt := 0
	if stream {
		streamInt = 1
	}
	go func() {
		_, err := observDB.Exec(
			`INSERT INTO call_log (id,created_at,model,endpoint,stream,latency_ms,ttft_ms,status_code,request_hash,has_tools,has_thinking) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			uuid.New().String(), time.Now().UTC().Format(time.RFC3339), anthropicReq.Model, endpoint, streamInt, latency, ttft, statusCode, hex.EncodeToString(hash[:]), hasTools, hasThinking,
		)
		if err != nil {
			log.Printf("observability: insert error: %v", err)
		}
	}()
}
