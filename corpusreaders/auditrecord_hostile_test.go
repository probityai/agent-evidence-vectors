package corpusreaders

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The hostile inputs scripts/auditrecord-hostile-input-test.py holds the Python
// reader to, held here to the same answers, so the two rails of the agent audit
// record corpus judge them alike.

func TestAuditRecordInstantReadsRFC3339Only(t *testing.T) {
	read := map[string]time.Time{
		"2026-09-19T11:04:11Z":           time.Date(2026, 9, 19, 11, 4, 11, 0, time.UTC),
		"2026-09-19t11:04:11z":           time.Date(2026, 9, 19, 11, 4, 11, 0, time.UTC),
		"2026-09-19T13:04:11+02:00":      time.Date(2026, 9, 19, 11, 4, 11, 0, time.UTC),
		"2026-09-19T11:04:11-00:00":      time.Date(2026, 9, 19, 11, 4, 11, 0, time.UTC),
		"2026-09-19T11:04:11.5Z":         time.Date(2026, 9, 19, 11, 4, 11, 500000000, time.UTC),
		"2026-09-19T11:04:11.123456789Z": time.Date(2026, 9, 19, 11, 4, 11, 123456000, time.UTC),
		"2016-12-31T23:59:60Z":           time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		"2016-12-31T18:59:60-05:00":      time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		"0001-01-01T00:00:00Z":           time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	for text, want := range read {
		got, err := arInstant(text)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: got %v, %v; want %v", text, got, err, want)
		}
	}
	for _, text := range []string{
		"2026-09-19 11:04:11Z", "2026-W38-6T11:04:11Z", "2026-262T11:04:11Z", "20260919T110411Z",
		"2026-09-19T110411Z", "2026-09-19T11:04Z", "2026-09-19T11Z", "2026-09-19T11:04:11,5Z",
		"2026-09-19T11:04:11+0000", "2026-09-19T11:04:11.5+00", "2026-09-19T11:04:11+00:00:30",
		"2026-09-19T11:04:11+24:00", "2026-09-19T11:04:11+05:60", "2026-09-19T11:04:11.Z",
		"2026-09-19T11:04:11", "+002026-09-19T11:04:11Z", "2026-09-19T11:04:1١Z",
		"2026-02-30T11:04:11Z", "2026-09-19T24:00:00Z", "2026-09-19T23:59:60Z", "2016-12-31T23:58:60Z",
		" 2026-09-19T11:04:11Z", "2026-09-19T11:04:11Z\n",
	} {
		if _, err := arInstant(text); err == nil || err.Error() != "timestamp-malformed" {
			t.Errorf("%q: got %v, want timestamp-malformed", text, err)
		}
	}
}

func TestAuditRecordProfileRefusalsBeforeAnySignature(t *testing.T) {
	cases := map[string]string{
		`{"a":"\ud800"}`:                           "not-parseable",
		`{"\udc00":1}`:                             "not-parseable",
		`{"n":99999999999999999}`:                  "unsafe-integer",
		`{"n":1` + strings.Repeat("0", 4300) + `}`: "unsafe-integer",
		`{"a":NaN}`:                                "not-parseable",
		`{"a":[-Infinity]}`:                        "not-parseable",
		`{"n":9007199254740992}`:                   "unsafe-integer",
	}
	for _, depth := range []int{129, 1000, 5000, 50000} {
		cases[strings.Repeat(`{"a":`, depth)+"1"+strings.Repeat("}", depth)] = "nesting-too-deep"
	}
	for payload, want := range cases {
		_, _, err := arParse([]byte(payload))
		if err == nil || err.Error() != want {
			t.Errorf("%.40q: got %v, want %s", payload, err, want)
		}
	}
}

// arBundle reads one retained member as a generic JSON object.
func arBundle(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var bundle map[string]any
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestAuditRecordAnchorWithinIsReadExactlyAtAnySize(t *testing.T) {
	manifest, heads, bodies, _ := arRetainedMembers(t)
	key := manifest.Keys.Observer.PublicKey
	for within, want := range map[string]string{
		"300000000000":         "well-formed",
		"100000000000000":      "well-formed",
		"9007199254740991":     "well-formed",
		"9007199254740992":     "malformed",
		"18446744073709551616": "malformed",
	} {
		bundle := arBundle(t, bodies["R1"])
		bundle["retention"].(map[string]any)["anchorWithin"] = json.Number(within)
		raw, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		report, dated := arVerifyRetained(raw, manifest.PredicateType, key, heads, "")
		if report.verdict != "valid" || dated.Entry != want {
			t.Errorf("anchorWithin %s: got %s and %+v, want valid and %s", within, report.verdict, dated, want)
		}
	}
}

func TestAuditRecordDatingAtEitherEndOfTheCalendar(t *testing.T) {
	manifest, heads, bodies, _ := arRetainedMembers(t)
	key := manifest.Keys.Observer.PublicKey
	bundle := arBundle(t, bodies["R2"])
	envelope := bundle["envelope"].(map[string]any)
	payload, err := base64.StdEncoding.DecodeString(envelope["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var statement map[string]any
	if err := json.Unmarshal(payload, &statement); err != nil {
		t.Fatal(err)
	}
	for _, issued := range []string{"0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"} {
		statement["predicate"].(map[string]any)["issuedAt"] = issued
		body, err := json.Marshal(statement)
		if err != nil {
			t.Fatal(err)
		}
		envelope["payload"] = base64.StdEncoding.EncodeToString(body)
		for _, at := range []string{"0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"} {
			bundle["retention"].(map[string]any)["receivedAt"] = at
			raw, err := json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			report, dated := arVerifyRetained(raw, manifest.PredicateType, key, heads, "")
			if report.verdict != "malformed" || dated.Entry == "" {
				t.Errorf("issuedAt %s receivedAt %s: got %s and %+v", issued, at, report.verdict, dated)
			}
		}
	}
}
