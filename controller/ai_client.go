
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	aiEndpoint = "http://localhost:8080/evaluate"
	aiTimeout  = 120 * time.Second // Gemini call can take a few seconds
)

// EvaluateRequest matches the FastAPI /evaluate input schema.
type EvaluateRequest struct {
	FlowID         string `json:"flow_id"`
	DestIP         string `json:"dest_ip"`
	DestPort       int    `json:"dest_port"`
	Jurisdiction   string `json:"jurisdiction"`
	Classification string `json:"classification"`
	ContentBytes   string `json:"content_bytes"` // base64
	ContentType    string `json:"content_type"`
	Timestamp      string `json:"timestamp"`
}

// EvaluateResponse matches the FastAPI /evaluate output schema.
type EvaluateResponse struct {
	Verdict      string   `json:"verdict"`
	PdpaClause   string   `json:"pdpa_clause"`
	PiiDetected  bool     `json:"pii_detected"`
	PiiTypes     []string `json:"pii_types"`
	Sensitivity  string   `json:"sensitivity"`
	Justification string  `json:"justification"`
}

var aiHTTPClient = &http.Client{Timeout: aiTimeout}

// evaluateFlow sends a reassembled payload to the AI agent and returns the verdict.
// On any error, returns a fail-secure BLOCK.
func evaluateFlow(flowID, destIP string, destPort int,
	jurisdiction, classification string, payload []byte, contentType string) EvaluateResponse {

	req := EvaluateRequest{
		FlowID:         flowID,
		DestIP:         destIP,
		DestPort:       destPort,
		Jurisdiction:   jurisdiction,
		Classification: classification,
		ContentBytes:   base64.StdEncoding.EncodeToString(payload),
		ContentType:    contentType,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return failSecure(fmt.Sprintf("marshal error: %v", err))
	}

	resp, err := aiHTTPClient.Post(aiEndpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return failSecure(fmt.Sprintf("AI request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return failSecure(fmt.Sprintf("AI returned status %d", resp.StatusCode))
	}

	var out EvaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return failSecure(fmt.Sprintf("decode error: %v", err))
	}
	return out
}

// failSecure returns a default BLOCK verdict for error cases.
func failSecure(reason string) EvaluateResponse {
	return EvaluateResponse{
		Verdict:       "BLOCK",
		PdpaClause:    "FAIL-SECURE",
		PiiDetected:   false,
		Justification: reason,
	}
}
