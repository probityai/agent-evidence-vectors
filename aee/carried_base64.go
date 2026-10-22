package aee

import (
	"encoding/base64"
	"errors"
)

// errCarriedBase64NotCanonical reports base64 text that decodes but is not the
// one canonical spelling of the bytes it decodes to.
var errCarriedBase64NotCanonical = errors.New("carried base64 is not canonical")

// decodeCarriedBase64 decodes base64 text carried on a signed surface (a
// record's payload, a record signature) under the canonical-base64 rule:
// standard alphabet, minimal padding, no line breaks, no non-alphabet byte,
// fail-closed. The rule is a property of the carried text, so it is checked on
// the text, not on the decoded bytes.
//
// base64.StdEncoding.Strict() enforces every clause but one. encoding/base64
// skips '\r' and '\n' in every decoding mode, Strict() included, so a payload
// broken across lines decodes to the same bytes as the unbroken one and was
// accepted here while the Python rail refused it. The re-encode comparison
// closes that clause, and with it every other spelling that decodes to bytes
// whose canonical encoding differs from the text carried.
func decodeCarriedBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errCarriedBase64NotCanonical
	}
	return b, nil
}
