package corpusreaders

import (
	"errors"
	"testing"
)

func TestStrictUnmarshalRefusesWhatEncodingJSONKeeps(t *testing.T) {
	for _, text := range []string{
		`{"a": 1, "a": 2}`,
		`{"a": {"b": 1, "b": 1}}`,
		`[{"x": [], "x": []}]`,
		`{"a": 1, "a": 2}`,
	} {
		var v any
		if err := strictUnmarshal([]byte(text), &v); !errors.Is(err, errRepeatedMember) {
			t.Errorf("%s: got %v, want a repeated-member refusal", text, err)
		}
	}
	for _, text := range []string{`{"a": NaN}`, `{"a": Infinity}`, `[1e999]`, `{"a": 1} x`, `{} {}`} {
		var v any
		if err := strictUnmarshal([]byte(text), &v); err == nil {
			t.Errorf("%s: decoded, want a refusal", text)
		}
	}
	var v map[string]any
	if err := strictUnmarshal([]byte(`{"a": [1, {"a": 2}], "b": {"a": 3}}`), &v); err != nil {
		t.Errorf("strict JSON refused: %v", err)
	}
}
