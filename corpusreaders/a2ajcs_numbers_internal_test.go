package corpusreaders

import "testing"

// A number token no double holds exactly has no canonical form (RFC 7493 section
// 2.2), and an object that repeats a member has none either. The cases are the
// ones the Python canonicalizer and the jcs_canonical/v1 verifier are held to.
func TestA2AAnswerRefusesWhatNoCanonicalFormCovers(t *testing.T) {
	for _, text := range []string{
		`{"n":9007199254740993}`,
		`{"n":-9007199254740993}`,
		`{"n":12345678901234567890}`,
		`{"n":1e-400}`,
		`{"n":3.141592653589793238462643383279}`,
		`{"n":9007199254740993.0}`,
		`{"n":1e999}`,
		`{"a":1,"a":2}`,
		`{"a":{"b":1,"b":1}}`,
	} {
		if produced, err := a2aAnswer("rfc8785", []byte(text)); err == nil {
			t.Errorf("%s: got canonical bytes %q, want a refusal", text, produced)
		}
	}
}

func TestA2AAnswerKeepsTheFormOfANumberADoubleHoldsExactly(t *testing.T) {
	for text, want := range map[string]string{
		`{"n":9007199254740991}`:       `{"n":9007199254740991}`,
		`{"n":100000000000000000000}`:  `{"n":100000000000000000000}`,
		`{"n":1180591620717411303424}`: `{"n":1.1805916207174113e+21}`,
		`{"n":1E21}`:                   `{"n":1e+21}`,
		`{"n":0.1}`:                    `{"n":0.1}`,
		`{"n":1.10}`:                   `{"n":1.1}`,
		`{"n":-0.0}`:                   `{"n":0}`,
		`{"n":0.30000000000000004}`:    `{"n":0.30000000000000004}`,
		`{"n":5e-324}`:                 `{"n":5e-324}`,
	} {
		got, err := a2aAnswer("rfc8785", []byte(text))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v; want %q", text, got, err, want)
		}
	}
}
