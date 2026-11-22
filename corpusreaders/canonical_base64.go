package corpusreaders

import (
	"encoding/base64"
	"errors"
)

// errBase64NotCanonical reports base64 text that decodes but is not the one
// spelling an encoder writes for the bytes it decodes to.
var errBase64NotCanonical = errors.New("base64 is not canonical")

// decodeCanonical decodes base64 text carried in a record (a signature, a
// payload, a key, a proof) and refuses every spelling but the canonical one.
//
// encoding/base64 in its default mode ignores the bits of the last character no
// byte uses, so an Ed25519 signature has sixteen spellings that each decode to
// the same 64 bytes; Strict() closes that, but every mode still skips '\r' and
// '\n'. Comparing the text with the encoding of the decoded bytes closes both,
// and every other spelling, the same way the aee package and the Python readers
// do.
func decodeCanonical(enc *base64.Encoding, s string) ([]byte, error) {
	b, err := enc.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if enc.EncodeToString(b) != s {
		return nil, errBase64NotCanonical
	}
	return b, nil
}
