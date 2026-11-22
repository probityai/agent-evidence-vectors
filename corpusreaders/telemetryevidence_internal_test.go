package corpusreaders

import (
	"encoding/json"
	"errors"
	"testing"
)

// The strict parser the telemetry-evidence reader runs over every embedded text
// refuses a repeated member at any depth and anything that is not one JSON value.
// Each refusal is a contradicted decision with its rule's code, never a value.
func TestTelemetryEvidenceStrictRefusesWithTheRuleCode(t *testing.T) {
	for text, want := range map[string]string{
		`{"a":1,"a":2}`:           "no_duplicate_member",
		`{"a":{"b":1,"b":1}}`:     "no_duplicate_member",
		`[{"a":1,"a":1}]`:         "no_duplicate_member",
		`{"a":NaN}`:               "record_shape",
		`NaN`:                     "record_shape",
		`{"a":1} {"b":2}`:         "record_shape",
		`{"a":1`:                  "record_shape",
		`[1,2`:                    "record_shape",
		`{"a":[1,{"b":2,"b":3}]}`: "no_duplicate_member",
	} {
		value, err := teStrict(text)
		var refused *teRefused
		if !errors.As(err, &refused) {
			t.Errorf("%s: got %v, %v; want a refusal", text, value, err)
			continue
		}
		if refused.Error() != want {
			t.Errorf("%s: refused with %q, want %q", text, refused.Error(), want)
		}
	}
}

func TestTelemetryEvidenceStrictKeepsOneValue(t *testing.T) {
	value, err := teStrict(`{"a":[1,{"b":2}],"c":"d"}`)
	if err != nil {
		t.Fatalf("got %v", err)
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 2 {
		t.Fatalf("got %#v", value)
	}
}

// A number outside the integers-only profile has no canonical form.
func TestTelemetryEvidenceJCSNumberRefusesOutsideTheProfile(t *testing.T) {
	for _, token := range []string{"1.5", "-0.25", "1e400", "9007199254740992.0", "-9.007199254740992e15"} {
		if got, err := teJCSNumber(json.Number(token)); err == nil {
			t.Errorf("%s: got %q, want a refusal", token, got)
		}
	}
	for token, want := range map[string]string{
		"12":                 "12",
		"-7":                 "-7",
		"2.0":                "2",
		"0.0":                "0",
		"-0.0":               "0",
		"1e3":                "1000",
		"9007199254740993":   "9007199254740993",
		"9007199254740991.0": "9007199254740991",
	} {
		got, err := teJCSNumber(json.Number(token))
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", token, got, err, want)
		}
	}
}
