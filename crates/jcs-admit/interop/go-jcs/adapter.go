// Copyright 2026 Probity AI. Apache-2.0 license.

// Package gojcs admits the original bytes before calling the pinned Go JCS writer.
package gojcs

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/probityai/jcs-admit/interop/go-jcs/source/jsoncanonicalizer"
)

// Policy selects the admission profile and finite input caps.
type Policy struct {
	Profile  string
	MaxDepth int
	MaxBytes int
}

// Outcome keeps admission, Go writer and agreement refusals separate.
type Outcome struct {
	Status       string `json:"status"`
	Stage        string `json:"stage"`
	ErrorClass   string `json:"error_class,omitempty"`
	CanonicalHex string `json:"canonical_hex,omitempty"`
}

func refused(stage, class string) Outcome {
	return Outcome{Status: "refused", Stage: stage, ErrorClass: class}
}

func validPolicy(policy Policy) bool {
	profile := policy.Profile == "rfc8785" || policy.Profile == "ijson" || policy.Profile == "ijson-integers"
	return profile && policy.MaxDepth >= 0 && policy.MaxDepth <= 128 && policy.MaxBytes >= 0 && policy.MaxBytes <= 20<<20
}

// Transform sends the original bytes to the selected installed admission command.
// Only an accepted object or array reaches Go Transform. The resulting bytes must
// agree with the admitted canonical form. No input value is parsed by this adapter.
func Transform(raw []byte, admissionExecutable string, policy Policy) (Outcome, error) {
	if !validPolicy(policy) {
		return Outcome{}, fmt.Errorf("invalid finite admission policy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, admissionExecutable, policy.Profile, strconv.Itoa(policy.MaxDepth), strconv.Itoa(policy.MaxBytes))
	command.Stdin = bytes.NewReader(raw)
	response, err := command.Output()
	if err != nil {
		return Outcome{}, fmt.Errorf("raw admission command failed: %w", err)
	}
	var admitted struct {
		Status       string `json:"status"`
		ErrorClass   string `json:"error_class"`
		CanonicalHex string `json:"canonical_hex"`
	}
	if err := json.Unmarshal(response, &admitted); err != nil {
		return Outcome{}, fmt.Errorf("admission response is malformed: %w", err)
	}
	if admitted.Status == "refused" && admitted.ErrorClass != "" && admitted.CanonicalHex == "" {
		return refused("raw-admission", admitted.ErrorClass), nil
	}
	if admitted.Status != "accepted" || admitted.ErrorClass != "" || admitted.CanonicalHex == "" {
		return Outcome{}, fmt.Errorf("admission response has no valid outcome")
	}
	expected, err := hex.DecodeString(admitted.CanonicalHex)
	if err != nil {
		return Outcome{}, fmt.Errorf("admission bytes are malformed: %w", err)
	}
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return refused("go-root-domain", "ObjectOrArrayRequired"), nil
	}
	actual, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return refused("go-transform", "GoTransform"), nil
	}
	if !bytes.Equal(actual, expected) {
		return refused("byte-agreement", "CanonicalDisagreement"), nil
	}
	return Outcome{Status: "accepted", Stage: "byte-agreement", CanonicalHex: hex.EncodeToString(actual)}, nil
}

// BareTransform records the pinned writer's raw outcome without an admission gate.
// Use it for comparison records; the consumer entry point is Transform.
func BareTransform(raw []byte) Outcome {
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return refused("go-transform", "GoTransform")
	}
	return Outcome{Status: "accepted", Stage: "go-transform", CanonicalHex: hex.EncodeToString(canonical)}
}
