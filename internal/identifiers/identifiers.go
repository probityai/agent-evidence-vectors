// Package identifiers holds the one rule every Go reader in this module applies
// when it compares an identifier taken from a record with one of ours: which host
// we write identifiers under, and which hosts we read as ours.
//
// A signed record cannot be edited without breaking its signature, so every
// record already issued keeps the identifiers it was signed with, under
// https://probityai.github.io/, forever. From the release that flips
// IdentifierHost, new records carry https://probityai.org/. Both hosts are ours:
// GitHub serves the old one for the probityai organisation and forwards every
// path on it to the same path on the new one, which is verified for that
// organisation. So the two spellings name one type, and a reader that accepted
// only one would reject either every record already issued or every record
// issued from now on. Accepting both widens nothing an attacker controls: an
// identifier is a label, not a credential, and trust comes from the signature
// and the key, which this package does not touch. The match is byte-exact on the
// scheme and the host; no other spelling is recognised.
//
// The comparison is the only thing that changes. What a reader reports back (an
// echoed predicateType, a receipt field) stays the record's own bytes, and the
// bytes a signature covers are never rewritten. The rule is the one
// spec/identifiers/HOSTS.md states, and spec/identifiers/host-equivalence.json
// holds the pairs every implementation of it reproduces.
package identifiers

import "strings"

// IdentifierHost is the host every identifier we write uses. Flipping it to
// probityai.org is a one-line change, made only after a release that reads both
// spellings is published; until then no emitted byte changes.
const IdentifierHost = "probityai.github.io"

// recognisedHosts are the hosts whose identifiers we read as ours.
var recognisedHosts = [...]string{"probityai.github.io", "probityai.org"}

// RecognisedHosts returns the hosts whose identifiers we read as ours, as a copy,
// so no caller can widen the set.
func RecognisedHosts() []string {
	return append([]string(nil), recognisedHosts[:]...)
}

// Identifier is https://<IdentifierHost>/<path>. Every identifier constant in
// this module is built through it, so the host flip is one line.
func Identifier(path string) string {
	return "https://" + IdentifierHost + "/" + path
}

// CanonicalIdentifier returns s with a recognised host replaced by
// IdentifierHost, when s starts with exactly https://<recognised host>/, and s
// unchanged otherwise. The match is byte-exact and case-sensitive: http://,
// www., a port, a trailing dot, upper case, userinfo, probityai.org.example and
// probityai.organisation all stay unrecognised.
func CanonicalIdentifier(s string) string {
	for _, host := range recognisedHosts {
		if rest, found := strings.CutPrefix(s, "https://"+host+"/"); found {
			return Identifier(rest)
		}
	}
	return s
}

// SameIdentifier reports whether a and b name one identifier once both are
// canonical.
func SameIdentifier(a, b string) bool {
	return CanonicalIdentifier(a) == CanonicalIdentifier(b)
}

// CanonicalValue is CanonicalIdentifier over a decoded JSON value: a string is
// made canonical and any other value is returned as it is, so a comparison of
// CanonicalValue(v) with a string constant keeps Go's interface equality, under
// which a number, a list or an absent member never equals a string.
func CanonicalValue(v any) any {
	if s, ok := v.(string); ok {
		return CanonicalIdentifier(s)
	}
	return v
}
