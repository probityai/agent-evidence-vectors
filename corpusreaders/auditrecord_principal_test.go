package corpusreaders

import "testing"

// TestAuditRecordThumbprintMatchesRFC7638: the RSA key of RFC 7638 Section 3.1
// has the thumbprint the RFC prints.
func TestAuditRecordThumbprintMatchesRFC7638(t *testing.T) {
	key := map[string]any{
		"kty": "RSA",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPeb" +
			"WKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic" +
			"AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPks" +
			"INHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
	got, err := arJWKThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Errorf("thumbprint %s, want %s", got, want)
	}
}

// TestAuditRecordPrincipalSentencesAreLoadBearing: dropping each sentence of the
// principal rule fails exactly the member that tests it.
func TestAuditRecordPrincipalSentencesAreLoadBearing(t *testing.T) {
	want := map[string]string{
		"unknown": "PR11", "subject": "PR8", "credential": "PR6", "not-yet-valid": "PR10,PR15",
		"expired": "PR5,PR14", "kid": "PR9", "thumbprint": "PR4",
	}
	for name, member := range want {
		drop := func() func() {
			arPrincipalChecks[name] = false
			return func() { arPrincipalChecks[name] = true }
		}
		if got := arWeakened(t, drop); got != member {
			t.Errorf("without the %s sentence: failing %q, want %q", name, got, member)
		}
	}
}

// TestAuditRecordPrincipalSkewIsTwoSided: the skew tolerance applies on both
// sides of the token's lifetime. With none on the issue side PR13 fails, and
// with none on the expiry side PR12 fails, and nothing else.
func TestAuditRecordPrincipalSkewIsTwoSided(t *testing.T) {
	want := map[string]string{"issued": "PR13", "expires": "PR12"}
	for side, member := range want {
		drop := func() func() {
			arPrincipalSkew[side] = false
			return func() { arPrincipalSkew[side] = true }
		}
		if got := arWeakened(t, drop); got != member {
			t.Errorf("no skew tolerance on the %s side: failing %q, want %q", side, got, member)
		}
	}
}
