package identifiers

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

const (
	oldHost = "https://probityai.github.io/"
	newHost = "https://probityai.org/"
	path    = "agent-evidence-vectors/predicate/v1/observed-effect"
)

func TestIdentifierIsBuiltUnderTheHostWeWrite(t *testing.T) {
	if IdentifierHost != "probityai.github.io" {
		t.Fatalf("the host flips only in the release after both spellings are read; it is %q", IdentifierHost)
	}
	if got := Identifier(path); got != oldHost+path {
		t.Fatalf("Identifier(%q) = %q", path, got)
	}
	if got := Identifier(""); got != oldHost {
		t.Fatalf("Identifier(\"\") = %q", got)
	}
}

func TestRecognisedHostsAreExactlyTheTwoAndCannotBeWidened(t *testing.T) {
	hosts := RecognisedHosts()
	if len(hosts) != 2 || hosts[0] != "probityai.github.io" || hosts[1] != "probityai.org" {
		t.Fatalf("recognised hosts are %v", hosts)
	}
	hosts[0] = "example.invalid"
	if again := RecognisedHosts(); again[0] != "probityai.github.io" {
		t.Fatalf("a caller widened the set through the returned slice: %v", again)
	}
	if got := CanonicalIdentifier("https://example.invalid/" + path); got != "https://example.invalid/"+path {
		t.Fatalf("a host written into the returned slice is read as ours: %q", got)
	}
}

func TestCanonicalIdentifierMapsBothSpellingsToTheHostWeWrite(t *testing.T) {
	for _, s := range []string{oldHost + path, newHost + path} {
		if got := CanonicalIdentifier(s); got != oldHost+path {
			t.Errorf("CanonicalIdentifier(%q) = %q, want %q", s, got, oldHost+path)
		}
	}
	if got := CanonicalIdentifier(newHost); got != oldHost {
		t.Errorf("the bare new host root is %q", got)
	}
	// The rest of the string is carried byte for byte, including what a host
	// match must not interpret: a second host, a query, a fragment, a dot path.
	for _, rest := range []string{"probityai.org/x", "a?b=https://probityai.org/", "a#f", "../x", "A/B"} {
		if got := CanonicalIdentifier(newHost + rest); got != oldHost+rest {
			t.Errorf("CanonicalIdentifier(%q) = %q", newHost+rest, got)
		}
	}
}

// refusedSpellings are every spelling the rule refuses. Each must come back
// byte-identical, and so must never equal either recognised spelling.
var refusedSpellings = []string{
	"http://probityai.org/" + path,
	"http://probityai.github.io/" + path,
	"https://www.probityai.org/" + path,
	"https://probityai.org:443/" + path,
	"https://probityai.org./" + path,
	"https://probityai.github.io./" + path,
	"https://Probityai.org/" + path,
	"https://PROBITYAI.ORG/" + path,
	"HTTPS://probityai.org/" + path,
	"https://user@probityai.org/" + path,
	"https://probityai.org@example.invalid/" + path,
	"https://probityai.org.example/" + path,
	"https://probityai.organisation/" + path,
	"https://probityai.github.io.example/" + path,
	"https://sub.probityai.org/" + path,
	"https://probityai.org",
	"https://probityai.org" + path,
	"https:/probityai.org/" + path,
	"https//probityai.org/" + path,
	" https://probityai.org/" + path,
	"https://probityai.org\\" + path,
	"https://xn--probityai.org/" + path,
	"https://w3id.org/agent-evidence/predicate/v1/agent-card-receipt",
	"https://in-toto.io/Statement/v1",
	"",
}

func TestCanonicalIdentifierRefusesEveryOtherSpelling(t *testing.T) {
	for _, s := range refusedSpellings {
		if got := CanonicalIdentifier(s); got != s {
			t.Errorf("CanonicalIdentifier(%q) = %q, want it unchanged", s, got)
		}
		for _, ours := range []string{oldHost + path, newHost + path} {
			if SameIdentifier(s, ours) || SameIdentifier(ours, s) {
				t.Errorf("SameIdentifier(%q, %q) is true", s, ours)
			}
		}
	}
}

func TestSameIdentifier(t *testing.T) {
	cases := []struct {
		a, b string
		same bool
	}{
		{oldHost + path, newHost + path, true},
		{newHost + path, oldHost + path, true},
		{newHost + path, newHost + path, true},
		{oldHost + path, oldHost + path, true},
		{oldHost + path, newHost + path + "/", false},
		{oldHost + path, newHost + "agent-evidence-vectors/predicate/v2/observed-effect", false},
		{"https://w3id.org/x", "https://w3id.org/x", true},
		{"", "", true},
	}
	for _, c := range cases {
		if got := SameIdentifier(c.a, c.b); got != c.same {
			t.Errorf("SameIdentifier(%q, %q) = %t, want %t", c.a, c.b, got, c.same)
		}
	}
}

func TestCanonicalValueKeepsInterfaceEquality(t *testing.T) {
	want := Identifier(path)
	if got := CanonicalValue(newHost + path); got != want {
		t.Errorf("CanonicalValue of the new spelling is %v", got)
	}
	for _, v := range []any{nil, 1.0, json.Number("1"), true, []any{newHost + path}, map[string]any{"a": newHost + path}} {
		got := CanonicalValue(v)
		if got == want {
			t.Errorf("CanonicalValue(%#v) equals the identifier", v)
		}
	}
	if got := CanonicalValue(nil); got != nil {
		t.Errorf("CanonicalValue(nil) = %v", got)
	}
}

// equivalenceFile is the shared vector file every implementation of the rule
// reproduces. It is written by the Python side of this repository; this test
// holds the Go rule to it.
var equivalenceFile = filepath.Join("..", "..", "spec", "identifiers", "host-equivalence.json")

type equivalence struct {
	Version int `json:"version"`
	Pairs   []struct {
		A    *string `json:"a"`
		B    *string `json:"b"`
		Same *bool   `json:"same"`
		Why  string  `json:"why"`
	} `json:"pairs"`
}

func TestSharedHostEquivalenceVectors(t *testing.T) {
	body, err := os.ReadFile(equivalenceFile)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("%s is not in this tree, so the shared pairs were not checked; "+
			"it is added by the Python side of the same change", equivalenceFile)
	}
	if err != nil {
		t.Fatalf("%s: %v", equivalenceFile, err)
	}
	var file equivalence
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatalf("%s does not parse: %v", equivalenceFile, err)
	}
	if file.Version != 1 {
		t.Fatalf("%s is version %d; this test reads version 1", equivalenceFile, file.Version)
	}
	if len(file.Pairs) == 0 {
		t.Fatalf("%s holds no pairs, so it checks nothing", equivalenceFile)
	}
	sawSame, sawDifferent := false, false
	for i, pair := range file.Pairs {
		if pair.A == nil || pair.B == nil || pair.Same == nil {
			t.Errorf("pair %d lacks a, b or same: %+v", i, pair)
			continue
		}
		if got := SameIdentifier(*pair.A, *pair.B); got != *pair.Same {
			t.Errorf("pair %d (%s): SameIdentifier(%q, %q) = %t, the file says %t",
				i, pair.Why, *pair.A, *pair.B, got, *pair.Same)
		}
		if got := SameIdentifier(*pair.B, *pair.A); got != *pair.Same {
			t.Errorf("pair %d (%s) is not symmetric", i, pair.Why)
		}
		sawSame = sawSame || *pair.Same
		sawDifferent = sawDifferent || !*pair.Same
	}
	if !sawSame || !sawDifferent {
		t.Errorf("%s must hold both a same pair and a refused pair (same: %t, refused: %t)",
			equivalenceFile, sawSame, sawDifferent)
	}
	t.Logf("%d shared pairs reproduced from %s", len(file.Pairs), equivalenceFile)
}
