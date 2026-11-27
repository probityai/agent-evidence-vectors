package corpusreaders

import "testing"

// The Python readers' strictjson refuses these bytes before any field is read, and
// decodeJSONNumbers has to answer the same, or two readers judge one record two ways.
func TestDecodeJSONNumbersRefusesWhatStrictjsonRefuses(t *testing.T) {
	refused := []string{
		`{"a":1e999}`, `{"a":-1e999}`, `{"a":[1,{"b":1E400}]}`,
		`{"\ud800":1,"\ud801":2}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`,
		`{"a":"\ud800x"}`, `{"a":"\ud800\ud800"}`, `{"a":"\udbff"}`,
		"{\"a\":\"\xff\"}", "{\"a\":\"\xed\xa0\x80\"}",
	}
	for _, text := range refused {
		if _, err := decodeJSONNumbers([]byte(text)); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	read := []string{
		`{"a":"😀"}`, `{"a":1e-999}`, `{"a":"\\ud800"}`, `{"a":123456789012345678901234567890}`,
		`{"a":1.5e300}`, `{"a":"\\\\","b":"😀"}`,
	}
	for _, text := range read {
		if _, err := decodeJSONNumbers([]byte(text)); err != nil {
			t.Errorf("refused %q: %v", text, err)
		}
	}
}

func TestHolderBoundAlgNamesFoldOverASCIIOnly(t *testing.T) {
	for alg, mac := range map[string]bool{
		"hß": false, "Hß256": false, "hſ256": false, "HS256": true, "hs512": true, "None": false,
	} {
		folded := hbASCIIFold(alg)
		if got := len(folded) >= 2 && folded[:2] == "hs"; got != mac {
			t.Errorf("%q folds to %q, MAC=%v want %v", alg, folded, got, mac)
		}
	}
}
