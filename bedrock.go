package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/google/uuid"
)

// Bedrock client for embeddings (nil if not enabled)
var bedrockClient *bedrockruntime.Client

// initBedrockClient initializes the Bedrock client if enabled via env vars.
func initBedrockClient() {
	profile := os.Getenv("BEDROCK_AWS_PROFILE")
	enabled := os.Getenv("BEDROCK_ENABLED") == "1"
	if profile == "" && !enabled {
		return
	}
	region := os.Getenv("BEDROCK_REGION")
	if region == "" {
		region = "us-west-2"
	}
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		log.Printf("Warning: Bedrock client init failed: %v", err)
		return
	}
	bedrockClient = bedrockruntime.NewFromConfig(cfg)
	log.Printf("Bedrock client initialized (region=%s, profile=%s)", region, profile)
}

// handleEmbeddings handles POST /v1/embeddings requests.
func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	if bedrockClient == nil {
		http.Error(w, `{"error":{"message":"embeddings not enabled"}}`, http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var req struct {
		Model     string `json:"model"`
		Input     any    `json:"input"`
		InputType string `json:"input_type,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusBadRequest)
		return
	}
	if req.Model == "" {
		http.Error(w, `{"error":{"message":"missing required field: model"}}`, http.StatusBadRequest)
		return
	}

	// Normalize input to []string
	var texts []string
	switch v := req.Input.(type) {
	case string:
		texts = []string{v}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				texts = append(texts, s)
			}
		}
	default:
		http.Error(w, `{"error":{"message":"input must be string or array of strings"}}`, http.StatusBadRequest)
		return
	}
	if len(texts) == 0 {
		http.Error(w, `{"error":{"message":"input is empty"}}`, http.StatusBadRequest)
		return
	}

	start := time.Now()
	var allEmbeddings [][]float64
	var totalTokens int

	if strings.HasPrefix(req.Model, "amazon.titan") {
		// Titan: one text per call
		for _, text := range texts {
			payload, _ := json.Marshal(map[string]any{"inputText": text})
			out, err := bedrockClient.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
				ModelId:     aws.String(req.Model),
				ContentType: aws.String("application/json"),
				Body:        payload,
			})
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusBadGateway)
				return
			}
			var resp struct {
				Embedding           []float64 `json:"embedding"`
				InputTextTokenCount int       `json:"inputTextTokenCount"`
			}
			json.Unmarshal(out.Body, &resp)
			allEmbeddings = append(allEmbeddings, resp.Embedding)
			totalTokens += resp.InputTextTokenCount
		}
	} else {
		// Cohere: batch up to 96
		inputType := req.InputType
		if inputType == "" {
			inputType = "search_query"
		}
		const batchSize = 96
		for i := 0; i < len(texts); i += batchSize {
			end := i + batchSize
			if end > len(texts) {
				end = len(texts)
			}
			batch := texts[i:end]
			payload, _ := json.Marshal(map[string]any{
				"texts":      batch,
				"input_type": inputType,
				"truncate":   "END",
			})
			out, err := bedrockClient.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
				ModelId:     aws.String(req.Model),
				ContentType: aws.String("application/json"),
				Body:        payload,
			})
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusBadGateway)
				return
			}
			var resp struct {
				Embeddings [][]float64 `json:"embeddings"`
			}
			json.Unmarshal(out.Body, &resp)
			allEmbeddings = append(allEmbeddings, resp.Embeddings...)
		}
		// Estimate tokens (Cohere doesn't return token count)
		for _, t := range texts {
			totalTokens += len(t) / 4
		}
	}

	// Build OpenAI-compatible response
	data := make([]map[string]any, len(allEmbeddings))
	for i, emb := range allEmbeddings {
		data[i] = map[string]any{"object": "embedding", "index": i, "embedding": emb}
	}
	resp := map[string]any{
		"object": "list",
		"model":  req.Model,
		"data":   data,
		"usage":  map[string]any{"prompt_tokens": totalTokens, "total_tokens": totalTokens},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	// Log to observability
	if observDB != nil {
		latency := time.Since(start).Milliseconds()
		go func() {
			observDB.Exec(
				`INSERT INTO call_log (id,created_at,model,endpoint,stream,input_tokens,latency_ms,status_code) VALUES (?,?,?,?,?,?,?,?)`,
				uuid.New().String(), time.Now().UTC().Format(time.RFC3339), req.Model, "/v1/embeddings", 0, totalTokens, latency, 200,
			)
		}()
	}
}

// rerankModelID is the only Bedrock rerank model this proxy exposes.
const rerankModelID = "cohere.rerank-v3-5:0"

// cohereRerankMaxDocs is the per-request document limit for Cohere Rerank 3.5.
const cohereRerankMaxDocs = 1000

// handleRerank handles POST /v1/rerank requests (Cohere-compatible).
// Forwards to AWS Bedrock Cohere Rerank 3.5 (cohere.rerank-v3-5:0).
func handleRerank(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	if bedrockClient == nil {
		http.Error(w, `{"error":{"message":"rerank not enabled"}}`, http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var req struct {
		// Model is optional; this proxy only serves rerankModelID. A non-empty
		// value that differs from it is rejected rather than silently overridden.
		Model           string `json:"model"`
		Query           string `json:"query"`
		Documents       []any  `json:"documents"`
		TopN            *int   `json:"top_n,omitempty"`
		ReturnDocuments bool   `json:"return_documents,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusBadRequest)
		return
	}
	if req.Model != "" && req.Model != rerankModelID {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"unsupported model %q; only %q is available"}}`, req.Model, rerankModelID), http.StatusBadRequest)
		return
	}
	if req.Query == "" {
		http.Error(w, `{"error":{"message":"missing required field: query"}}`, http.StatusBadRequest)
		return
	}

	// Normalize documents to []string. Accept ["str", ...] or [{"text": "..."}].
	// Reject any other element shape: silently skipping would shift indices and
	// make Bedrock's returned index point at the wrong source document.
	docs := make([]string, 0, len(req.Documents))
	for i, item := range req.Documents {
		switch v := item.(type) {
		case string:
			docs = append(docs, v)
		case map[string]any:
			if s, ok := v["text"].(string); ok {
				docs = append(docs, s)
			} else {
				http.Error(w, fmt.Sprintf(`{"error":{"message":"documents[%d] object missing string \"text\" field"}}`, i), http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, fmt.Sprintf(`{"error":{"message":"documents[%d] must be a string or {\"text\":...} object"}}`, i), http.StatusBadRequest)
			return
		}
	}
	if len(docs) == 0 {
		http.Error(w, `{"error":{"message":"documents is empty"}}`, http.StatusBadRequest)
		return
	}
	if len(docs) > cohereRerankMaxDocs {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"too many documents: %d (max %d)"}}`, len(docs), cohereRerankMaxDocs), http.StatusBadRequest)
		return
	}

	topN := len(docs)
	if req.TopN != nil && *req.TopN > 0 && *req.TopN < topN {
		topN = *req.TopN
	}

	start := time.Now()

	// Bedrock rerank payload (shared by Cohere 3.5 and Amazon Rerank 1.0).
	payload, _ := json.Marshal(map[string]any{
		"query":       req.Query,
		"documents":   docs,
		"top_n":       topN,
		"api_version": 2,
	})
	out, err := bedrockClient.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(rerankModelID),
		ContentType: aws.String("application/json"),
		Body:        payload,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusBadGateway)
		return
	}

	var bedrockResp struct {
		Results []struct {
			Index          int     `json:"index"`
			RelevanceScore float64 `json:"relevance_score"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out.Body, &bedrockResp); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"%v"}}`, err), http.StatusBadGateway)
		return
	}

	// Build Cohere-compatible response.
	results := make([]map[string]any, 0, len(bedrockResp.Results))
	for _, rr := range bedrockResp.Results {
		entry := map[string]any{
			"index":           rr.Index,
			"relevance_score": rr.RelevanceScore,
		}
		if req.ReturnDocuments && rr.Index >= 0 && rr.Index < len(docs) {
			entry["document"] = map[string]any{"text": docs[rr.Index]}
		}
		results = append(results, entry)
	}
	resp := map[string]any{
		"id":      uuid.New().String(),
		"model":   rerankModelID,
		"results": results,
		"meta": map[string]any{
			"api_version": map[string]any{"version": "2"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	// Log to observability.
	if observDB != nil {
		latency := time.Since(start).Milliseconds()
		tokens := len(req.Query) / 4
		for _, d := range docs {
			tokens += len(d) / 4
		}
		go func() {
			observDB.Exec(
				`INSERT INTO call_log (id,created_at,model,endpoint,stream,input_tokens,latency_ms,status_code) VALUES (?,?,?,?,?,?,?,?)`,
				uuid.New().String(), time.Now().UTC().Format(time.RFC3339), rerankModelID, "/v1/rerank", 0, tokens, latency, 200,
			)
		}()
	}
}
