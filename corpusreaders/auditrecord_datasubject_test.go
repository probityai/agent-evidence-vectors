package corpusreaders

import (
	"strings"
	"testing"
)

// TestAuditRecordDataSubjectReferenceRecomputes: the server's salt and the
// customer identifier give the reference DS1 records, and a different
// identifier gives a different one.
func TestAuditRecordDataSubjectReferenceRecomputes(t *testing.T) {
	const salt = "KCe6C-0uZ2AMbCxJakcpWm1CbKk-0pkVEAdepodeXv8"
	got, err := arDataSubjectReference(salt, "customer:C-1048213")
	if err != nil {
		t.Fatal(err)
	}
	if want := "8093bf7a19f2d111df3dcf5422d2c43155582021edb84539f0a8610154b0ac7f"; got != want {
		t.Errorf("reference %s, want %s", got, want)
	}
	other, err := arDataSubjectReference(salt, "customer:C-1048214")
	if err != nil {
		t.Fatal(err)
	}
	if other == got || strings.Contains(got, "1048213") {
		t.Errorf("the reference must depend on the identifier and expose none of it")
	}
}

// TestAuditRecordDataSubjectSentencesAreLoadBearing: dropping each sentence of
// the dataSubject rule fails exactly the member that tests it.
func TestAuditRecordDataSubjectSentencesAreLoadBearing(t *testing.T) {
	want := map[string]string{
		"unknown": "DS5", "relation": "DS8", "merged": "DS7", "digest": "DS10", "purpose": "DS9",
	}
	for name, member := range want {
		drop := func() func() {
			arDataSubjectChecks[name] = false
			return func() { arDataSubjectChecks[name] = true }
		}
		if got := arWeakened(t, drop); got != member {
			t.Errorf("without the %s sentence: failing %q, want %q", name, got, member)
		}
	}
}
