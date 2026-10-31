// Copyright 2026 Probity AI. Apache-2.0 license.

package gojcs

import (
	"os"
	"path/filepath"
	"testing"
)

func executable(t *testing.T, response string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admission-control")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '"+response+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCanonicalAgreementRefusesSubstitutedAdmissionOutput(t *testing.T) {
	// A selected command returning valid, different bytes cannot authorize those
	// bytes as the output of the pinned Go writer for the original document.
	command := executable(t, `{"status":"accepted","canonical_hex":"5b325d"}`)
	outcome, err := Transform([]byte("[1]"), command, Policy{"rfc8785", 128, 20 << 20})
	if err != nil || outcome.Stage != "byte-agreement" || outcome.ErrorClass != "CanonicalDisagreement" {
		t.Fatalf("want disagreement refusal, got %+v, %v", outcome, err)
	}
}

func TestMalformedAndContradictoryAdmissionResponsesRefuse(t *testing.T) {
	for _, response := range []string{
		"not-json",
		`{"status":"accepted"}`,
		`{"status":"accepted","canonical_hex":"zz"}`,
		`{"status":"refused","error_class":"DuplicateMember","canonical_hex":"7b7d"}`,
		`{"status":"accepted","error_class":"DuplicateMember","canonical_hex":"7b7d"}`,
	} {
		t.Run(response, func(t *testing.T) {
			outcome, err := Transform([]byte("{}"), executable(t, response), Policy{"rfc8785", 128, 20 << 20})
			if err == nil || outcome.Status == "accepted" {
				t.Fatalf("malformed response accepted: %+v, %v", outcome, err)
			}
		})
	}
}

func TestNativeAdmissionSeesDuplicateAndInvalidUTF8Bytes(t *testing.T) {
	command := os.Getenv("GO_JCS_ADMISSION")
	if command == "" {
		t.Fatal("select the installed native GO_JCS_ADMISSION command")
	}
	for _, test := range []struct {
		name  string
		raw   []byte
		class string
	}{
		{"escaped duplicate", []byte(`{"a":1,"\u0061":2}`), "DuplicateMember"},
		{"invalid UTF-8", []byte{'[', '"', 0xc0, 0xaf, '"', ']'}, "StringNotScalar"},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome, err := Transform(test.raw, command, Policy{"rfc8785", 128, 20 << 20})
			if err != nil || outcome.Stage != "raw-admission" || outcome.ErrorClass != test.class {
				t.Fatalf("want original-byte %s refusal, got %+v, %v", test.class, outcome, err)
			}
		})
	}
}
