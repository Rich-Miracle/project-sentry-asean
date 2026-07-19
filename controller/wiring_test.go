package main

import (
	"fmt"
	"testing"
)

// TestAIWiring verifies the controller can reach the AI agent,
// send a payload, and parse a verdict. Requires the FastAPI server
// running on localhost:8080.
func TestAIWiring(t *testing.T) {
	payload := []byte("Customer Tan Ah Kow NRIC S8234567A email tan@example.com")
	resp := evaluateFlow(
		"wiring-test", "172.30.0.22", 8080,
		"US", "NON_EQUIVALENT",
		payload, "text/plain",
	)

	fmt.Printf("VERDICT: %s\n", resp.Verdict)
	fmt.Printf("PII detected: %v %v\n", resp.PiiDetected, resp.PiiTypes)
	fmt.Printf("Clause: %s\n", resp.PdpaClause)
	fmt.Printf("Justification: %s\n", resp.Justification)

	if resp.Verdict != "BLOCK" {
		t.Fatalf("expected BLOCK for PII->US, got %s", resp.Verdict)
	}
	if !resp.PiiDetected {
		t.Fatalf("expected PII detected")
	}
	fmt.Println("WIRING OK — controller successfully called AI agent and got a verdict")
}
