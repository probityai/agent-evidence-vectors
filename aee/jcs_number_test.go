package aee

import (
	"errors"
	"testing"
)

// TestSafeIntegerProfile pins the integers-only, safe-integer number profile
// (spec:req-wireprofile-toto-attestation-framework-plus-understanding@9b70dfbc01b9a3f6,req-fields-fields-divide-identity-whose-signature@80666d820c397ce5) uniformly across CheckIJSON and Canonicalize, and in
// every JSON notation. The exponent-notation cases are the regression: "1e21"
// is the integer 10^21 and MUST be rejected, but the prior notation-blind check
// only range-checked tokens without '.', 'e', or 'E', so it slipped through.
func TestSafeIntegerProfile(t *testing.T) {
	cases := []struct {
		in         string
		wantReject bool
		wantErr    error // optional: which sentinel, if rejected
	}{
		{"0", false, nil},
		{"100", false, nil},
		{"1e2", false, nil},              // exponent-notation SAFE integer -> ok
		{"100.0", false, nil},            // decimal-point SAFE integer -> ok
		{"9007199254740991", false, nil}, // 2^53 - 1
		{"-9007199254740991", false, nil},
		{"9007199254740992", true, ErrUnsafeInteger},     // 2^53
		{"9007199254740993", true, ErrUnsafeInteger},     // 2^53 + 1, fits int64
		{"99999999999999999999", true, ErrUnsafeInteger}, // exceeds int64
		{"1e21", true, ErrUnsafeInteger},                 // THE bypass: 10^21
		{"1E21", true, ErrUnsafeInteger},
		{"1.0e21", true, ErrUnsafeInteger},
		{"-1e21", true, ErrUnsafeInteger},
		{"1.5", true, ErrNonIntegerNumber}, // non-integer -> rejected
		{"-0.1", true, ErrNonIntegerNumber},
	}
	for _, c := range cases {
		ijsonErr := CheckIJSON([]byte(c.in))
		_, canonErr := Canonicalize([]byte(c.in))
		// The two entry points MUST agree on accept/reject for every input.
		if (ijsonErr != nil) != (canonErr != nil) {
			t.Errorf("%s: CheckIJSON reject=%v disagrees with Canonicalize reject=%v",
				c.in, ijsonErr != nil, canonErr != nil)
		}
		if (ijsonErr != nil) != c.wantReject {
			t.Errorf("%s: reject=%v want=%v (err=%v)", c.in, ijsonErr != nil, c.wantReject, ijsonErr)
			continue
		}
		if c.wantReject && c.wantErr != nil {
			if !errors.Is(ijsonErr, c.wantErr) {
				t.Errorf("%s: want %v, got %v", c.in, c.wantErr, ijsonErr)
			}
			if !errors.Is(canonErr, c.wantErr) {
				t.Errorf("%s: Canonicalize want %v, got %v", c.in, c.wantErr, canonErr)
			}
		}
	}
	// A safe integer in exponent form canonicalizes to plain form.
	got, err := Canonicalize([]byte("1e2"))
	if err != nil || string(got) != "100" {
		t.Fatalf(`Canonicalize("1e2") = %q, %v; want "100", nil`, got, err)
	}
}
