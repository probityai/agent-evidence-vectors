package observedeffect

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ijsonLimit is I-JSON's safe-integer bound. The producer side refuses to ENCODE
// past it; a hostile rail does not use our encoder, so the verifier refuses to
// CONSUME past it as well. The check is a RULE rather than part of decoding, so
// that disabling the rule changes a verdict and the mutation table can measure it.
const ijsonLimit = 1 << 53

// decodeIJSON parses one JSON document and refuses a duplicate member at any
// depth. Nothing in encoding/json refuses one: json.Unmarshal into a map keeps
// the last spelling of a repeated key silently, so two rails reading the same
// bytes can disagree about what the record says while both report a clean parse.
//
// Written here rather than taken from the aee package's canonicalizer on purpose.
// That package is the verification core of a DIFFERENT predicate, and a shared
// parser would make this predicate's refusals move whenever that one's did. The
// cost is one small decoder; the alternative is a coupling nobody declared.
func decodeIJSON(raw []byte) (any, *fault) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, f := decodeValue(dec)
	if f != nil {
		return nil, f
	}
	// Trailing bytes are a second document, not this one.
	if _, err := dec.Token(); err != io.EOF {
		return nil, &fault{stage: verdictMalformed, code: "not-parseable"}
	}
	return value, nil
}

func decodeValue(dec *json.Decoder) (any, *fault) {
	token, err := dec.Token()
	if err != nil {
		return nil, &fault{stage: verdictMalformed, code: "not-parseable"}
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}
	switch delim {
	case '{':
		return decodeObject(dec)
	case '[':
		return decodeArray(dec)
	default:
		return nil, &fault{stage: verdictMalformed, code: "not-parseable"}
	}
}

func decodeObject(dec *json.Decoder) (any, *fault) {
	out := map[string]any{}
	for {
		token, err := dec.Token()
		if err != nil {
			return nil, &fault{stage: verdictMalformed, code: "not-parseable"}
		}
		if delim, ok := token.(json.Delim); ok && delim == '}' {
			return out, nil
		}
		key, ok := token.(string)
		if !ok {
			return nil, &fault{stage: verdictMalformed, code: "not-parseable"}
		}
		if _, seen := out[key]; seen {
			return nil, &fault{stage: verdictMalformed, code: "duplicate-member"}
		}
		value, f := decodeValue(dec)
		if f != nil {
			return nil, f
		}
		out[key] = value
	}
}

func decodeArray(dec *json.Decoder) (any, *fault) {
	out := []any{}
	for {
		if !dec.More() {
			if _, err := dec.Token(); err != nil { // consume the closing bracket
				return nil, &fault{stage: verdictMalformed, code: "not-parseable"}
			}
			return out, nil
		}
		value, f := decodeValue(dec)
		if f != nil {
			return nil, f
		}
		out = append(out, value)
	}
}

// integerOverBound reports whether a decoded number is an integer at or above the
// I-JSON bound. A number carrying a fraction or an exponent is a float, and the
// bound is stated over integers, so a float is exempt here exactly as it is in the
// reference verifier.
func integerOverBound(number json.Number) bool {
	text := number.String()
	if strings.ContainsAny(text, ".eE") {
		return false
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		// Out of int64 range entirely, which is well past 2**53.
		return true
	}
	if value < 0 {
		value = -value
	}
	return value >= ijsonLimit
}

// canonicalStringMap is RFC 8785 for the one shape this predicate signs over: a
// flat object of string members. The prior commitment's preimage is that shape and
// nothing else here is canonicalized, so a general canonicalizer would be
// untested surface. Member names sort by UTF-16 code unit, which is Section
// 3.2.3, and the strings are encoded without HTML escaping, because < for a
// less-than sign is a different byte string and would not verify against a rail
// that wrote the character.
func canonicalStringMap(members map[string]string) []byte {
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return utf16Less(names[i], names[j])
	})
	var out bytes.Buffer
	out.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			out.WriteByte(',')
		}
		out.Write(jsonString(name))
		out.WriteByte(':')
		out.Write(jsonString(members[name]))
	}
	out.WriteByte('}')
	return out.Bytes()
}

func utf16Less(a, b string) bool {
	left, right := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) < len(right)
}

func jsonString(value string) []byte {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	// The only error json.Encoder returns for a string is a write error to a
	// bytes.Buffer, which does not fail.
	_ = enc.Encode(value)
	return bytes.TrimRight(out.Bytes(), "\n")
}
