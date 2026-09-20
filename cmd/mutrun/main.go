// Command mutrun replays the whole conformance corpus through the in-process
// aee rail and writes one JSON object per vector.
//
// It exists because a forcing measurement replays the corpus once per mutant.
// Driving cmd/aee-verify would cost two process spawns per vector per mutant --
// for the published corpus and the enumerated mutation sites that is on the
// order of a quarter of a million spawns, and the per-process cost dominates
// everything else. mutrun takes the same decision path in process.
//
// The saving is only worth having if the fast path answers what the real one
// answers, so scripts/forcing-gate.py asserts, on the UNMUTATED tree and before
// it scores a single mutant, that the harness verdict computed from these lines
// equals the verdict packaging/run_vectors.py reaches driving the real CLI --
// same status, same per-gate column, same observed codes, same both tier
// columns. A disagreement stops the run rather than being scored.
//
// Both key policies are exercised per vector, because the harness's external-rail
// observation does: the pinned-key pass supplies the byte-pure facts (verdict,
// codes, result) and the no-key pass supplies the tier column that states GATE 2's
// no-TOFU rule. A replay that answered only the first would report nothing for
// tierWithoutKey, and an expectation compared against nothing is an expectation
// that cannot fail -- which is exactly how the shipped CLI's own no-key column
// went unchecked for several revisions.
//
// This command is measurement tooling, not part of the consumer surface.
//
// Usage: mutrun <vectors-dir> <keys.json>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/probityai/agent-evidence-vectors/aee"
)

type keyFile struct {
	SubstrateObservationKeys []struct {
		KeyID        string `json:"keyid"`
		PublicKeyHex string `json:"publicKeyHex"`
	} `json:"substrateObservationKeys"`
}

// observation is one vector's replay, shaped like the dict
// packaging/run_vectors.py's observe_external returns so the two can be compared
// field by field.
type observation struct {
	ID      string `json:"id"`
	Verdict string `json:"verdict"`
	// VerdictWithoutKey is the no-key pass's validity verdict. The harness's
	// observe_external carries it because validity is byte-pure and the two
	// passes cannot disagree about it; a fast path that reported only the
	// pinned-key verdict would differ from the real rail on a field the
	// evaluator now reads, and the ground-truth gate would stop the run.
	VerdictWithoutKey string `json:"verdictWithoutKey,omitempty"`
	// omitempty, matching aee.Report's own tag. The harness reads a missing or
	// null member as ABSENT and a present empty list as an EMPTY ANSWER, so a
	// fast path that emitted `"codes": []` where the CLI omits the member
	// entirely would disagree with it about what the rail established.
	Codes            []string `json:"codes,omitempty"`
	PrimaryCode      string   `json:"primaryCode,omitempty"`
	Result           string   `json:"result,omitempty"`
	Tiers            []string `json:"tiers,omitempty"`
	TiersWithoutKey  []string `json:"tiersWithoutKey,omitempty"`
	ResultWithoutKey string   `json:"resultWithoutKey,omitempty"`
	Panic            string   `json:"panic,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. It returns 0 when every vector was replayed,
// 2 on a usage or I/O error.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: mutrun <vectors-dir> <keys.json>")
		return 2
	}
	vecDir, keysPath := args[0], args[1]

	policy, err := loadPolicy(keysPath)
	if err != nil {
		fmt.Fprintln(stderr, "mutrun:", err)
		return 2
	}
	paths, err := vectorPaths(vecDir)
	if err != nil {
		fmt.Fprintln(stderr, "mutrun:", err)
		return 2
	}

	enc := json.NewEncoder(stdout)
	for _, p := range paths {
		// #nosec G304,G703 -- a corpus path under the vectors directory this tool was
		// pointed at, not attacker-supplied input to a verifier.
		body, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintln(stderr, "mutrun:", err)
			return 2
		}
		if err := enc.Encode(observe(vectorID(p), body, policy)); err != nil {
			fmt.Fprintln(stderr, "mutrun:", err)
			return 2
		}
	}
	return 0
}

func vectorID(path string) string {
	base := filepath.Base(path)
	return base[:len(base)-len(filepath.Ext(base))]
}

func vectorPaths(vecDir string) ([]string, error) {
	var paths []string
	// Every directory the corpus publishes, indeterminate included. A bucket the
	// forcing campaign does not replay is a bucket whose rules the campaign
	// records as unforced whether they are or not, which would make the
	// measurement wrong about the newest part of the corpus first.
	// ONE directory, and no fallback to the per-verdict layout that preceded
	// it. That layout is not merely superseded, it is the defect: measured over
	// each vector's whole path it predicted the verdict perfectly, so a reader
	// that still parses it keeps the leaky structure alive in code where
	// something can write it again, and makes every future change have to be
	// correct twice on a path nothing exercises. A copy of the older corpus
	// gains nothing from being readable here either -- corpusDigest moved for
	// every vector, so such a copy is already incompatible on the digest
	// whatever this harness can parse.
	matches, err := filepath.Glob(filepath.Join(vecDir, "statements", "*.json"))
	if err != nil {
		return nil, err
	}
	paths = append(paths, matches...)
	if len(paths) == 0 {
		return nil, fmt.Errorf(
			"no vectors under %s/statements. This harness reads the flat, "+
				"content-addressed corpus at suiteRevision 28 and later, and "+
				"deliberately does not read the retired per-verdict layout; a "+
				"corpus that still has one is too old for it", vecDir)
	}
	sort.Strings(paths)
	return paths, nil
}

func loadPolicy(keysPath string) (*aee.ConsumerPolicy, error) {
	// #nosec G304,G703 -- the key policy path is an argument this developer tool was
	// pointed at, over the operator's own checkout; G703 is the taint-analysis spelling
	// of the same fact. No privilege boundary is crossed and there is no allow-list a
	// consumer key policy could be validated against.
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("key policy does not parse: %w", err)
	}
	policy := &aee.ConsumerPolicy{}
	for _, k := range kf.SubstrateObservationKeys {
		pub, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("key %q: publicKeyHex is not hex: %w", k.KeyID, err)
		}
		policy.SubstrateObservationKeys = append(policy.SubstrateObservationKeys, pub)
	}
	return policy, nil
}

// observe replays one vector under both key policies.
func observe(id string, body []byte, policy *aee.ConsumerPolicy) observation {
	o := observation{ID: id, Codes: []string{}}
	withKey, panicked := verifySafely(body, policy)
	if panicked != "" {
		// The CLI maps a panic to exit 2 with no JSON line, so the harness parses
		// nothing and falls back to the exit status. Recorded explicitly here so a
		// mutation that only crashes the rail is never scored as a detection.
		o.Verdict = "panic"
		o.Panic = panicked
		return o
	}
	o.Verdict = withKey.Verdict
	for _, c := range withKey.Codes {
		o.Codes = append(o.Codes, string(c))
	}
	o.PrimaryCode = string(withKey.PrimaryCode)
	o.Result = withKey.Result
	o.Tiers = tierStrings(withKey.Tiers)

	// The no-key pass is bare conformance-replay mode: cmd/aee-verify passes a
	// nil policy when neither -keys nor $AEE_SUBSTRATE_KEYS is set, so this must
	// be nil too rather than an empty policy.
	withoutKey, panicked := verifySafely(body, nil)
	if panicked != "" {
		o.Verdict = "panic"
		o.Panic = panicked
		return o
	}
	o.VerdictWithoutKey = withoutKey.Verdict
	o.TiersWithoutKey = tierStrings(withoutKey.Tiers)
	o.ResultWithoutKey = withoutKey.Result
	return o
}

func tierStrings(tiers []aee.Tier) []string {
	if tiers == nil {
		return nil
	}
	out := make([]string, 0, len(tiers))
	for _, t := range tiers {
		out = append(out, string(t))
	}
	return out
}

// verifySafely runs aee.Verify with a panic backstop, because a mutant rail is
// expected to misbehave and a crash must be recorded rather than end the replay.
func verifySafely(body []byte, policy *aee.ConsumerPolicy) (rep *aee.Report, panicked string) {
	defer func() {
		if r := recover(); r != nil {
			rep, panicked = nil, fmt.Sprint(r)
		}
	}()
	return aee.Verify(body, policy), ""
}
