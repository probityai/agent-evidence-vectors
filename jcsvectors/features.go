package jcsvectors

import (
	"fmt"
	"math/big"
	"slices"
	"strings"
	"unicode/utf8"
)

// Feature names one thing a case exercises, read from its bytes.
type Feature string

// The features a case can carry. Number features describe each number token
// as written in the input, so "1000.0" is a fraction although its value is
// an integer, and "1e3" is an exponent.
const (
	// FeatureInteger is a number token with no fraction or exponent whose
	// value is inside +-(2^53 - 1), the I-JSON exact range.
	FeatureInteger Feature = "integer"
	// FeatureUnsafeInteger is a number token with no fraction or exponent
	// whose value is outside +-(2^53 - 1).
	FeatureUnsafeInteger Feature = "unsafe-integer"
	// FeatureFraction is a number token with a decimal point.
	FeatureFraction Feature = "fraction"
	// FeatureExponent is a number token with an exponent.
	FeatureExponent Feature = "exponent"
	// FeatureNegativeZero is a number token whose value is zero, written
	// with a minus sign. RFC 8785 prints it as 0.
	FeatureNegativeZero Feature = "negative-zero"
	// FeatureEscape is a backslash escape inside a string.
	FeatureEscape Feature = "escape"
	// FeatureNonASCII is a byte above 0x7F in the input or in the canonical
	// output, as an escaped non-ASCII character prints as raw UTF-8.
	FeatureNonASCII Feature = "non-ascii"
	// FeatureNotUTF8 is input that is not valid UTF-8.
	FeatureNotUTF8 Feature = "not-utf8"
)

// Profile names a subset of RFC 8785 that an implementation declares it
// supports. A case outside the declared subset is reported apart, as out of
// profile, rather than as a failure; a divergence inside it is a failure.
type Profile string

const (
	// ProfileRFC8785 is the whole of RFC 8785: it admits every case.
	ProfileRFC8785 Profile = "rfc8785"
	// ProfileIntegerOnly admits a case whose every number token is an
	// integer inside +-(2^53 - 1) written with no fraction or exponent. A
	// fraction, an exponent or an unsafe integer anywhere puts the case out
	// of profile, so a canonicalizer for records whose numbers are counts is
	// scored on the cases it claims.
	ProfileIntegerOnly Profile = "integer-only"
)

// Profiles lists every profile this module knows.
func Profiles() []Profile { return []Profile{ProfileRFC8785, ProfileIntegerOnly} }

// excluded lists, for each profile, the features that put a case outside it.
var excluded = map[Profile][]Feature{
	ProfileRFC8785:     nil,
	ProfileIntegerOnly: {FeatureFraction, FeatureExponent, FeatureUnsafeInteger},
}

// Admits reports whether a case with these features is inside the profile.
// It returns an error for a profile this module does not know, so a typo is
// never read as a profile that admits nothing or everything.
func (p Profile) Admits(features []Feature) (bool, error) {
	out, ok := excluded[p]
	if !ok {
		return false, fmt.Errorf("jcsvectors: unknown profile %q", string(p))
	}
	for _, f := range features {
		if slices.Contains(out, f) {
			return false, nil
		}
	}
	return true, nil
}

// Filter splits vectors into those inside the profile and those outside it,
// keeping their order. Report the two counts apart: a case out of profile is
// neither a pass nor a failure.
func Filter(p Profile, vectors []Vector) (in, out []Vector, err error) {
	for _, v := range vectors {
		ok, err := p.Admits(v.Features)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			in = append(in, v)
		} else {
			out = append(out, v)
		}
	}
	return in, out, nil
}

var maxSafeInteger = new(big.Int).SetInt64(1<<53 - 1)

// features reads what a case exercises from its input and canonical bytes.
// The input may be malformed JSON on purpose, so the scan is lexical: it
// tracks strings and their escapes and classifies every number token outside
// them, and never fails.
func features(input, canonical []byte) []Feature {
	set := map[Feature]bool{}
	if !utf8.Valid(input) {
		set[FeatureNotUTF8] = true
	}
	for _, b := range append(slices.Clip(input), canonical...) {
		if b > 0x7F {
			set[FeatureNonASCII] = true
			break
		}
	}
	inString := false
	for i := 0; i < len(input); i++ {
		b := input[i]
		switch {
		case inString && b == '\\':
			set[FeatureEscape] = true
			i++
		case b == '"':
			inString = !inString
		case !inString && (b == '-' || ('0' <= b && b <= '9')):
			start := i
			for i+1 < len(input) && isNumberByte(input[i+1]) {
				i++
			}
			for _, f := range numberFeatures(string(input[start : i+1])) {
				set[f] = true
			}
		}
	}
	out := make([]Feature, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

func isNumberByte(b byte) bool {
	return ('0' <= b && b <= '9') || b == '-' || b == '+' || b == '.' || b == 'e' || b == 'E'
}

// numberFeatures classifies one number token as written. A token with no
// digit (a lone minus sign before Infinity) is not a number and has none.
func numberFeatures(token string) []Feature {
	significand, _, exponent := strings.Cut(strings.ToLower(token), "e")
	fraction := strings.Contains(significand, ".")
	if !strings.ContainsAny(significand, "0123456789") {
		return nil
	}
	var out []Feature
	if exponent {
		out = append(out, FeatureExponent)
	}
	if fraction {
		out = append(out, FeatureFraction)
	}
	if token[0] == '-' && !strings.ContainsAny(significand, "123456789") {
		out = append(out, FeatureNegativeZero)
	}
	if exponent || fraction {
		return out
	}
	value, ok := new(big.Int).SetString(token, 10)
	if !ok {
		// Digits with a stray sign, such as "1-2": malformed, and refused
		// before any number is read, so it says nothing about the profile.
		return out
	}
	if value.CmpAbs(maxSafeInteger) > 0 {
		return append(out, FeatureUnsafeInteger)
	}
	return append(out, FeatureInteger)
}

// withFeatures fills in each vector's features.
func withFeatures(vectors []Vector) []Vector {
	for i := range vectors {
		vectors[i].Features = features(vectors[i].Input, vectors[i].Canonical)
	}
	return vectors
}
