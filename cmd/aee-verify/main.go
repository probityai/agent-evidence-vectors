// Command aee-verify is the consumer MVP for AEE v0.7 statements: it runs
// GATE 0 (well-formedness), GATE 1 (coverage validity), the result
// recompute, derives the per-row evidence tier against a consumer policy,
// and evaluates the consumer-policy step (expected corpus and substrate
// anchors; the Admitted conjunction).
//
// Exit codes: 2 on usage or I/O error; otherwise, when any consumer policy
// is supplied (-keys, -expected-corpus-digest, -expected-substrate-digest),
// 0 iff the statement is ADMITTED (validity AND tier policy AND supplied
// anchors); with no policy supplied (bare conformance-replay mode), 0 iff
// the statement is VALID.
//
// Key policy file (JSON; pinned out of band, never read from the predicate):
//
//	{"substrateObservationKeys": [
//	  {"keyid": "<hint, optional>", "publicKeyHex": "<64-hex raw ed25519 public key>"}
//	]}
//
// The policy path may also arrive in AEE_SUBSTRATE_KEYS instead of -keys. That
// is the channel the conformance harness uses to hand a rail the pinned key
// policy without dictating a flag spelling: it runs each vector twice through
// the same argv, once with the variable set and once with it absent, and
// compares the two tier columns that come back. An explicit -keys always wins,
// and an unset variable is bare conformance-replay mode exactly as before.
//
// In -json mode the whole report is written as ONE line, because the harness
// reads the last line of stdout and parses that line alone. A pretty-printed
// object ends in a line reading "}", which parses as nothing.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// EnvSubstrateKeys names the environment variable carrying a key policy path
// when -keys is not given. The conformance harness sets it for the pinned-key
// pass and leaves it unset for the no-key pass, which is what makes the
// no-pinned-key tier column ("every substrate row is unattested; the substrate
// root is never inferred from the predicate") observable from outside this
// process rather than only from a first-party rail.
const EnvSubstrateKeys = "AEE_SUBSTRATE_KEYS"

type keyFile struct {
	SubstrateObservationKeys []struct {
		KeyID        string `json:"keyid"`
		PublicKeyHex string `json:"publicKeyHex"`
	} `json:"substrateObservationKeys"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: it parses args, verifies the named
// statement, writes output to stdout/stderr, and returns the process exit code
// (0 valid, 1 invalid, 2 usage or I/O error). main wraps it in os.Exit so the
// exit codes and output are exercisable without spawning a subprocess.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aee-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keysPath := fs.String("keys", "", "path to the consumer key policy JSON (optional; falls back to $"+EnvSubstrateKeys+"; without either, every substrate row derives unattested)")
	expectedCorpus := fs.String("expected-corpus-digest", "", "expected observationEnvironment.corpus.digest.sha256 (optional consumer anchor; a mismatch fails admission, never validity)")
	expectedSubstrate := fs.String("expected-substrate-digest", "", "expected observationEnvironment.substrate.digest.sha256 (optional consumer anchor; a mismatch fails admission, never validity)")
	jsonOut := fs.Bool("json", false, "emit the full report as JSON")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: aee-verify [-keys policy.json] [-expected-corpus-digest hex] [-expected-substrate-digest hex] [-json] <statement.json>\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	// A directory argument is a CORPUS, not a statement. One binary judges
	// every corpus in the repository: the directory's MANIFEST.json publishes a
	// suite, the suite selects a reader, and a suite no reader answers for is
	// refused by name. Before this, each corpus shipped a Python runner beside
	// its vectors and every outward command was a different command.
	if info, err := os.Stat(fs.Arg(0)); err == nil && info.IsDir() {
		return runCorpus(fs.Arg(0), *jsonOut, stdout, stderr)
	}

	resolvedKeys := *keysPath
	if resolvedKeys == "" {
		resolvedKeys = os.Getenv(EnvSubstrateKeys)
	}
	policy, err := loadPolicy(resolvedKeys, *expectedCorpus, *expectedSubstrate)
	if err != nil {
		fmt.Fprintf(stderr, "aee-verify: %v\n", err)
		return 2
	}
	body, err := os.ReadFile(fs.Arg(0)) // #nosec G304 -- this CLI verifies a file the caller names by design
	if err != nil {
		fmt.Fprintf(stderr, "aee-verify: %v\n", err)
		return 2
	}

	report, err := verifySafely(body, policy)
	if err != nil {
		fmt.Fprintf(stderr, "aee-verify: %v\n", err)
		return 2
	}
	if *jsonOut {
		// One line, deliberately. The suite's external-rail contract reads the
		// LAST line of stdout and parses that line as the whole report, so an
		// indented encoding is not a prettier form of the same answer: it is an
		// unparseable one. cmd/aee-verify pinned this with MarshalIndent and
		// therefore scored 0 of 186 against the corpus it ships.
		out, err := json.Marshal(report)
		if err != nil {
			fmt.Fprintf(stderr, "aee-verify: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(out))
	} else {
		printHuman(stdout, report, policy)
	}
	// Exit binding: with a supplied consumer policy the exit status is the
	// admission result (a result-only consumer must not read a
	// valid-but-not-admitted statement as admissible); with no policy there
	// is no admission decision to bind to, so bare conformance-replay mode
	// binds to validity alone.
	if policy != nil {
		if !report.Admitted {
			return 1
		}
		return 0
	}
	if report.Verdict != aee.VerdictValid {
		return 1
	}
	return 0
}

// verifySafely runs aee.Verify with a panic backstop. aee.Verify is written to
// never panic on any input, but this CLI ingests untrusted attestation bytes, so
// a recover keeps a hypothetical verifier bug from crashing the process: it maps
// to the I/O-error exit code with a diagnostic rather than a stack trace.
func verifySafely(body []byte, policy *aee.ConsumerPolicy) (report *aee.Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			report, err = nil, fmt.Errorf("internal verifier panic: %v", r)
		}
	}()
	return aee.Verify(body, policy), nil
}

func loadPolicy(path, expectedCorpus, expectedSubstrate string) (*aee.ConsumerPolicy, error) {
	if path == "" && expectedCorpus == "" && expectedSubstrate == "" {
		// No policy supplied at all: bare conformance-replay mode. Every
		// substrate row derives unattested (no TOFU) and no anchor compares.
		return nil, nil
	}
	policy := &aee.ConsumerPolicy{
		ExpectedCorpusDigest:    expectedCorpus,
		ExpectedSubstrateDigest: expectedSubstrate,
	}
	if path == "" {
		return policy, nil
	}
	// #nosec G304,G703 -- this CLI reads a policy file the caller names by
	// design, now by -keys or by $AEE_SUBSTRATE_KEYS. G703 is the taint-analysis
	// spelling of the same fact: the environment here is the operator's own, no
	// privilege boundary is crossed by reading a path they set, and there is no
	// allow-list a consumer key policy could be validated against.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("key policy does not parse: %w", err)
	}
	for _, k := range kf.SubstrateObservationKeys {
		pub, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: publicKeyHex must be %d hex-encoded bytes", k.KeyID, ed25519.PublicKeySize)
		}
		policy.SubstrateObservationKeys = append(policy.SubstrateObservationKeys, ed25519.PublicKey(pub))
	}
	return policy, nil
}

func printHuman(w io.Writer, r *aee.Report, policy *aee.ConsumerPolicy) {
	fmt.Fprintf(w, "verdict: %s\n", r.Verdict)
	if r.Verdict != aee.VerdictValid {
		for _, c := range r.Codes {
			marker := " "
			if c == r.PrimaryCode {
				marker = "*"
			}
			fmt.Fprintf(w, "  %s %s\n", marker, c)
		}
		fmt.Fprintln(w, "result: (not consumed — the attestation is invalid)")
		if policy != nil {
			fmt.Fprintln(w, "admitted: false (the attestation is invalid)")
		}
		return
	}
	fmt.Fprintf(w, "result: %s (recompute-confirmed)\n", r.Result)
	fmt.Fprintln(w, "evidence tiers (per attackResults row, per YOUR consumer policy):")
	for i, tier := range r.Tiers {
		fmt.Fprintf(w, "  row %d: %s\n", i, tier)
	}
	printConsumerFacts(w, r, policy)
}

// printConsumerFacts prints the consumer-relative component facts: the tier
// summary, the anchor comparison, and the Admitted conjunction. Skipped in
// bare conformance-replay mode (no policy), where only the byte-pure facts
// exist.
func printConsumerFacts(w io.Writer, r *aee.Report, policy *aee.ConsumerPolicy) {
	if policy == nil {
		return
	}
	unattested := 0
	for _, tier := range r.Tiers {
		if tier == aee.TierUnattested {
			unattested++
		}
	}
	if unattested == 0 {
		fmt.Fprintln(w, "tier policy: satisfied (every substrate row attested)")
	} else {
		fmt.Fprintf(w, "tier policy: NOT satisfied (%d substrate row(s) unattested)\n", unattested)
	}
	fmt.Fprintf(w, "corpus anchor: %s\n", anchorStatus(policy.ExpectedCorpusDigest, r.PolicyCodes, aee.CodeCorpusAnchorMismatch))
	fmt.Fprintf(w, "substrate anchor: %s\n", anchorStatus(policy.ExpectedSubstrateDigest, r.PolicyCodes, aee.CodeSubstrateAnchorMismatch))
	fmt.Fprintf(w, "admitted: %t\n", r.Admitted)
}

func anchorStatus(expected string, policyCodes []aee.Code, mismatch aee.Code) string {
	if expected == "" {
		return "unsupplied (no comparison)"
	}
	for _, c := range policyCodes {
		if c == mismatch {
			return "MISMATCH (" + string(mismatch) + ")"
		}
	}
	return "match"
}
