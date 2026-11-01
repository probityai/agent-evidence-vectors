package corpora

// The W3C report reader's two RFC 8785 encodings against the shared table.
//
// testdata/json-encodings.json carries a jcs-sha256 column and an rfc8785
// column, written by scripts/json-encoding-differential-test.py from the
// Python reader. This holds the Go reader to the same cells, refusals
// included, so the two readers are compared over one set of documents.

import (
	"encoding/json"
	"errors"
	"testing"
)

// w3cRefusalText is a refusal as the table writes it: the cause code. The token
// stays out because each reader spells it its own way (serde_json writes 1e21
// back as 1e+21), and the cause is what a reader is asked to name.
func w3cRefusalText(err error) string {
	var refused *w3cDigestRefusal
	if errors.As(err, &refused) {
		return refused.cause
	}
	return err.Error()
}

func TestW3CEncodingsAgreeWithTheSharedTable(t *testing.T) {
	columns, cases := loadEncodingTable(t)
	encoders := map[string]func(any) ([]byte, error){
		"jcs-sha256": jcsSHA256Bytes,
		"rfc8785":    rfc8785Bytes,
	}
	checked := 0
	for _, column := range columns {
		encode, ok := encoders[column]
		if !ok {
			continue
		}
		for _, c := range cases {
			want, ok := c.Cells[column]
			if !ok {
				t.Errorf("%s: no %s cell", c.Name, column)
				continue
			}
			value, err := decodeJSONNumbers([]byte(c.Doc))
			if err != nil {
				t.Fatalf("%s: the document does not decode: %v", c.Name, err)
			}
			got, err := encode(value)
			checkEncodingCell(t, column+" "+c.Name, want, got, err, w3cRefusalText)
			checked++
		}
	}
	if checked < 2*len(cases) {
		t.Fatalf("checked %d cells, want both W3C columns over all %d cases", checked, len(cases))
	}
}

// TestTheProfileDecidesOnTheTokenWithoutMaterialisingIt: an exponent no
// machine could expand is still read at once, and decided the right way.
func TestTheProfileDecidesOnTheTokenWithoutMaterialisingIt(t *testing.T) {
	for _, tc := range []struct {
		token, want string
	}{
		{"1e999999999999999999999999", w3cOutsideSafeRange},
		{"-1e999999999999999999999999", w3cOutsideSafeRange},
		{"1e-999999999999999999999999", w3cNonInteger},
		{"0e999999999999999999999999", ""},
		{"0.000e-999999999999999999", ""},
		{"9007199254740991.000", ""},
		{"90071992547409910e-1", ""},
		{"90071992547409920e-1", w3cOutsideSafeRange},
		{"9007199254740991.5", w3cNonInteger},
		{"100e-2", ""},
		{"15e-1", w3cNonInteger},
	} {
		_, err := jcsProfileNumber(json.Number(tc.token))
		got := ""
		var refused *w3cDigestRefusal
		if errors.As(err, &refused) {
			got = refused.cause
		} else if err != nil {
			t.Fatalf("%s: %v", tc.token, err)
		}
		if got != tc.want {
			t.Errorf("%s: refused for %q, want %q", tc.token, got, tc.want)
		}
	}
	if text, _ := jcsProfileNumber(json.Number("90071992547409910e-1")); text != "9007199254740991" {
		t.Errorf("90071992547409910e-1 writes %s, want 9007199254740991", text)
	}
	if text, _ := jcsProfileNumber(json.Number("-0.000e5")); text != "0" {
		t.Errorf("-0.000e5 writes %s, want 0", text)
	}
}
