package corpora

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// The optional sequence member (revision 01): a numbered series a producer
// issues, named by boundary, with a seq that starts at 1 and rises by one.

// arSequenceChecks names each sentence of the sequence rule so a test can drop
// one and see the member that tests it fail.
var arSequenceChecks = map[string]bool{"members": true, "positive": true}

// arRuleSequence: exactly boundary, a non-empty string, and seq, a positive
// integer (SQ1). Any other member (SQ2) or a seq below 1 (SQ3) is refused.
func arRuleSequence(s *arState) error {
	raw, present := s.pred["sequence"]
	if !present {
		return nil
	}
	sequence, ok := raw.(map[string]any)
	if !ok {
		return arRefuse("sequence-malformed")
	}
	if arSequenceChecks["members"] && len(sequence) != 2 {
		return arRefuse("sequence-malformed")
	}
	boundary, ok := sequence["boundary"].(string)
	if !ok || boundary == "" {
		return arRefuse("sequence-malformed")
	}
	seq, ok := arInt(sequence["seq"])
	if !ok || (arSequenceChecks["positive"] && seq < 1) {
		return arRefuse("sequence-malformed")
	}
	return nil
}

// arSeqPoint is one place in a series: a boundary and a seq.
type arSeqPoint struct {
	Boundary string `json:"boundary"`
	Seq      int64  `json:"seq"`
}

func arSeqText(points []arSeqPoint) string {
	parts := make([]string, 0, len(points))
	for _, p := range points {
		parts = append(parts, fmt.Sprintf("%s#%d", p.Boundary, p.Seq))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// arSequenceSetChecks names the two checks across the records of one series so
// a test can drop one.
var arSequenceSetChecks = map[string]bool{"duplicate": true, "gap": true}

// arSequenceSetFindings judges the records that carry sequence. Every record of
// a set verified under the one observer key, so a series is the records with
// one boundary. Two records at one seq with different payload digests fail the
// set (SQ5); a seq below the highest held that no record holds is named as
// issued and not received (SQ4).
func arSequenceSetFindings(predicates []map[string]any, envelopes [][]byte) arSetReport {
	series := map[string]map[int64]map[string]bool{}
	for i, pred := range predicates {
		sequence, ok := pred["sequence"].(map[string]any)
		if !ok {
			continue
		}
		boundary, _ := sequence["boundary"].(string)
		seq, _ := arInt(sequence["seq"])
		digest := arPayloadDigest(envelopes[i])
		if series[boundary] == nil {
			series[boundary] = map[int64]map[string]bool{}
		}
		if series[boundary][seq] == nil {
			series[boundary][seq] = map[string]bool{}
		}
		series[boundary][seq][digest] = true
	}
	if arSequenceSetChecks["duplicate"] {
		for _, held := range series {
			for _, digests := range held {
				if len(digests) > 1 {
					return arSetReport{verdict: "malformed", codes: []string{"sequence-duplicate"}}
				}
			}
		}
	}
	report := arSetReport{verdict: "valid"}
	if !arSequenceSetChecks["gap"] {
		return report
	}
	boundaries := make([]string, 0, len(series))
	for boundary := range series {
		boundaries = append(boundaries, boundary)
	}
	sort.Strings(boundaries)
	for _, boundary := range boundaries {
		var highest int64
		for seq := range series[boundary] {
			if seq > highest {
				highest = seq
			}
		}
		for n := int64(1); n < highest; n++ {
			if series[boundary][n] == nil {
				report.missing = append(report.missing, arSeqPoint{boundary, n})
			}
		}
	}
	return report
}

// arPayloadDigest is the SHA-256 of an envelope's decoded payload, which tells
// two records apart; the envelope is already judged valid.
func arPayloadDigest(envelope []byte) string {
	payload, err := arEnvelopePayload(envelope)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
