// Command aee-verify is the reference verifier for AEE v0.7 statements: it
// runs GATE 0 (well-formedness), GATE 1 (coverage validity), the result
// recompute, derives the per-row evidence tier against a consumer policy, and
// decides ADMISSION: whether the consumer may act on the statement, under the
// pins it supplied.
//
// Exit codes: 2 on usage or I/O error. Otherwise 0 iff the statement is
// ADMITTED, and 1 when it is not. There is no policy under which a statement
// is admitted by default: with nothing pinned, no key credits a substrate row
// and no anchor is compared, so nothing is admitted and the report names every
// pin that is missing. That is deliberate. This command used to exit 0 and
// print "result":"pass" when handed no policy at all, and a pipeline gating on
// the exit status then reported a pass no observer stood behind.
//
// -validity-only asks the narrower question instead, by name: is the statement
// well formed, internally consistent and does its result recompute. Its exit
// status is 0 iff VALID, its report carries "mode":"validity-only" and
// "admitted":false, and it takes the observation keys (for the tier column)
// and no other pin. It is the mode a conformance harness drives, because the
// corpus judges validity and tiers and never admission.
//
// Consumer policy (JSON; pinned out of band, never read from the predicate),
// from -policy or $AEE_CONSUMER_POLICY:
//
//	{"substrateObservationKeys": [{"keyid": "<hint>", "publicKeyHex": "<64-hex ed25519>"}],
//	 "expectedCorpusDigest": "<hex>", "expectedSubstrateDigest": "<hex>",
//	 "expectedSubjectDigest": "<hex>", "allowUnpinnedAnchors": false,
//	 "demandedClasses": ["XA"], "allowUnpinnedScope": false,
//	 "acceptedResults": ["pass"], "admitUninterceptedCleanRows": false,
//	 "maxIssuanceLagSeconds": 86400, "maxEvidenceAgeSeconds": 604800,
//	 "allowPublishedTestKeys": false}
//
// -keys (or $AEE_SUBSTRATE_KEYS) reads the same document shape and is how the
// conformance harness hands a rail its pinned key without dictating a flag
// spelling: it runs each vector twice through the same argv, once with the
// variable set and once with it absent, and compares the two tier columns. The
// flags below set single pins and must agree with a document that sets the
// same pin. vectors-admission/README.md tables what each pin's absence means.
//
// In -json mode the whole report is written as ONE line, because the harness
// reads the last line of stdout and parses that line alone. A pretty-printed
// object ends in a line reading "}", which parses as nothing.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// EnvSubstrateKeys names the environment variable carrying a key policy path
// when -keys is not given. The conformance harness sets it for the pinned-key
// pass and leaves it unset for the no-key pass, which is what makes the
// no-pinned-key tier column ("every substrate row is unattested; the substrate
// root is never inferred from the predicate") observable from outside this
// process rather than only from a first-party rail.
const EnvSubstrateKeys = "AEE_SUBSTRATE_KEYS"

// EnvConsumerPolicy names the environment variable carrying a full consumer
// policy path when -policy is not given. The admission corpus's contract hands
// a verifier its policy through it.
const EnvConsumerPolicy = "AEE_CONSUMER_POLICY"

// The two answers a run can be asked for.
const (
	modeAdmission    = "admission"
	modeValidityOnly = "validity-only"
)

// output is one run's report as printed: the library report plus what this
// run was asked and what no mode of this command establishes.
type output struct {
	*aee.Report
	// Mode says which question the exit status answers.
	Mode string `json:"mode"`
	// NotEstablished names what this run did not check, so a reader of a
	// passing report is told what the pass does not cover. This command reads
	// a bare statement and never an envelope, so the producer's signature is
	// always in the list.
	NotEstablished []string `json:"notEstablished"`
}

type flags struct {
	keysPath, policyPath                                   string
	expectedCorpus, expectedSubstrate, expectedSubject     string
	demandClasses, acceptResults, admitUnintercepted       string
	allowUnpinnedAnchors, allowUnpinnedScope, validityOnly bool
	allowPublishedTestKeys                                 bool
	maxIssuanceLag, maxEvidenceAge                         time.Duration
	jsonOut                                                bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: it parses args, verifies the named
// statement, writes output to stdout/stderr, and returns the process exit code
// (0 admitted, or valid under -validity-only; 1 not; 2 usage or I/O error).
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aee-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f flags
	fs.StringVar(&f.keysPath, "keys", "", "consumer policy document supplying the observation keys (falls back to $"+EnvSubstrateKeys+")")
	fs.StringVar(&f.policyPath, "policy", "", "consumer policy document (falls back to $"+EnvConsumerPolicy+")")
	fs.StringVar(&f.expectedCorpus, "expected-corpus-digest", "", "the corpus digest this consumer expects")
	fs.StringVar(&f.expectedSubstrate, "expected-substrate-digest", "", "the substrate digest this consumer expects")
	fs.StringVar(&f.expectedSubject, "expected-subject-digest", "", "the sha256 of the artifact being admitted; the subject's name is never compared")
	fs.BoolVar(&f.allowUnpinnedAnchors, "allow-unpinned-anchors", false, "decline the corpus, substrate and subject pins by name (an absent pin only, never a mismatched one)")
	fs.StringVar(&f.demandClasses, "demand-classes", "", "comma-separated assessment classes the run must have assessed")
	fs.BoolVar(&f.allowUnpinnedScope, "allow-unpinned-scope", false, "decline the demanded-class pin by name")
	fs.BoolVar(&f.allowPublishedTestKeys, "allow-published-test-keys", false, "admit under an observation key whose seed this suite publishes (a demonstration, never a deployment)")
	fs.StringVar(&f.acceptResults, "accept-results", "", `result threshold: "pass" (the default) or "pass,pass_indirect"`)
	fs.StringVar(&f.admitUnintercepted, "admit-unintercepted-clean-rows", "", `"true" declines the clean-row rule under a widened threshold, "false" keeps it`)
	fs.DurationVar(&f.maxIssuanceLag, "max-issuance-lag", 0, "bound issuedAt minus every verified armedAt")
	fs.DurationVar(&f.maxEvidenceAge, "max-evidence-age", 0, "bound now minus every verified armedAt")
	fs.BoolVar(&f.validityOnly, "validity-only", false, "answer validity alone: exit 0 iff VALID, admitted always false")
	fs.BoolVar(&f.jsonOut, "json", false, "emit the full report as JSON")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: aee-verify [-policy policy.json] [pins...] [-json] <statement.json>\n"+
			"       aee-verify -validity-only [-keys policy.json] [-json] <statement.json>\n"+
			"       aee-verify [-json] <corpus-dir>\n")
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
	// refused by name.
	if info, err := os.Stat(fs.Arg(0)); err == nil && info.IsDir() {
		return runCorpus(fs.Arg(0), f.jsonOut, stdout, stderr)
	}

	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	policy, err := resolvePolicy(f, set)
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
	out := output{Report: report, Mode: modeAdmission, NotEstablished: []string{"envelope-signature"}}
	if f.validityOnly {
		out.Mode = modeValidityOnly
		out.NotEstablished = append(out.NotEstablished, "admission")
		report.Admitted = false
		report.PolicyCodes = nil
	}
	if f.jsonOut {
		// One line, deliberately. The suite's external-rail contract reads the
		// LAST line of stdout and parses that line as the whole report, so an
		// indented encoding is not a prettier form of the same answer: it is an
		// unparseable one. cmd/aee-verify pinned this with MarshalIndent and
		// therefore scored 0 of 186 against the corpus it ships.
		line, err := json.Marshal(out)
		if err != nil {
			fmt.Fprintf(stderr, "aee-verify: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(line))
	} else {
		printHuman(stdout, out)
	}
	if f.validityOnly {
		if report.Verdict != aee.VerdictValid {
			return 1
		}
		return 0
	}
	if !report.Admitted {
		return 1
	}
	return 0
}

// admissionFlags are the pins that ask an admission question. -validity-only
// refuses them, because a run that promised not to decide admission cannot be
// handed the inputs of that decision and quietly ignore them.
var admissionFlags = []string{
	"policy", "expected-corpus-digest", "expected-substrate-digest", "expected-subject-digest",
	"allow-unpinned-anchors", "demand-classes", "allow-unpinned-scope", "accept-results",
	"admit-unintercepted-clean-rows", "max-issuance-lag", "max-evidence-age", "allow-published-test-keys",
}

// resolvePolicy builds the consumer policy from at most one document and the
// single-pin flags. A pin set by both must agree, because a document and a flag
// naming two different digests leave nobody able to say which was checked.
func resolvePolicy(f flags, set map[string]bool) (*aee.ConsumerPolicy, error) {
	if f.validityOnly {
		for _, name := range admissionFlags {
			if set[name] {
				return nil, fmt.Errorf("-validity-only decides no admission, so -%s cannot be honoured", name)
			}
		}
		if os.Getenv(EnvConsumerPolicy) != "" {
			return nil, errors.New("-validity-only decides no admission, so $" + EnvConsumerPolicy + " cannot be honoured")
		}
	}
	path, err := policyPath(f)
	if err != nil {
		return nil, err
	}
	policy := &aee.ConsumerPolicy{}
	if path != "" {
		// #nosec G304,G703 -- this CLI reads a policy file the caller names by
		// design, by flag or by environment variable; there is no allow-list a
		// consumer policy could be validated against.
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if policy, err = aee.ParseConsumerPolicy(raw); err != nil {
			return nil, err
		}
	}
	return applyFlags(policy, f, set)
}

func policyPath(f flags) (string, error) {
	policyFile := f.policyPath
	if policyFile == "" {
		policyFile = os.Getenv(EnvConsumerPolicy)
	}
	keysFile := f.keysPath
	if keysFile == "" {
		keysFile = os.Getenv(EnvSubstrateKeys)
	}
	if policyFile != "" && keysFile != "" {
		return "", errors.New("both a consumer policy and a key policy were supplied; the keys belong in the one policy document")
	}
	if policyFile != "" {
		return policyFile, nil
	}
	return keysFile, nil
}

func applyFlags(p *aee.ConsumerPolicy, f flags, set map[string]bool) (*aee.ConsumerPolicy, error) {
	for _, apply := range []func(*aee.ConsumerPolicy, flags, map[string]bool) error{
		applyAnchorFlags, applyListFlags, applyRowGateFlag, applyTimeFlags,
	} {
		if err := apply(p, f, set); err != nil {
			return nil, err
		}
	}
	if set["allow-unpinned-anchors"] {
		p.AllowUnpinnedAnchors = p.AllowUnpinnedAnchors || f.allowUnpinnedAnchors
	}
	if set["allow-unpinned-scope"] {
		p.AllowUnpinnedScope = p.AllowUnpinnedScope || f.allowUnpinnedScope
	}
	if set["allow-published-test-keys"] {
		p.AllowPublishedTestKeys = p.AllowPublishedTestKeys || f.allowPublishedTestKeys
	}
	return p, nil
}

func applyAnchorFlags(p *aee.ConsumerPolicy, f flags, set map[string]bool) error {
	pins := []struct {
		flag  string
		value string
		field *string
	}{
		{"expected-corpus-digest", f.expectedCorpus, &p.ExpectedCorpusDigest},
		{"expected-substrate-digest", f.expectedSubstrate, &p.ExpectedSubstrateDigest},
		{"expected-subject-digest", f.expectedSubject, &p.ExpectedSubjectDigest},
	}
	for _, pin := range pins {
		if !set[pin.flag] {
			continue
		}
		if *pin.field != "" && *pin.field != pin.value {
			return fmt.Errorf("-%s says %s and the policy document says %s", pin.flag, pin.value, *pin.field)
		}
		*pin.field = pin.value
	}
	return nil
}

func applyListFlags(p *aee.ConsumerPolicy, f flags, set map[string]bool) error {
	if set["demand-classes"] {
		if len(p.DemandedClasses) > 0 {
			return errors.New("-demand-classes and the policy document both demand classes")
		}
		p.DemandedClasses = splitList(f.demandClasses)
	}
	if set["accept-results"] {
		if p.AcceptedResults != nil {
			return errors.New("-accept-results and the policy document both set the result threshold")
		}
		p.AcceptedResults = splitList(f.acceptResults)
	}
	return nil
}

func applyRowGateFlag(p *aee.ConsumerPolicy, f flags, set map[string]bool) error {
	if !set["admit-unintercepted-clean-rows"] {
		return nil
	}
	if p.AdmitUninterceptedCleanRows != nil {
		return errors.New("-admit-unintercepted-clean-rows and the policy document both decide the row rule")
	}
	if f.admitUnintercepted != "true" && f.admitUnintercepted != "false" {
		return fmt.Errorf(`-admit-unintercepted-clean-rows takes "true" or "false", not %q`, f.admitUnintercepted)
	}
	v := f.admitUnintercepted == "true"
	p.AdmitUninterceptedCleanRows = &v
	return nil
}

func applyTimeFlags(p *aee.ConsumerPolicy, f flags, set map[string]bool) error {
	for _, d := range []struct {
		flag  string
		value time.Duration
		field *time.Duration
	}{
		{"max-issuance-lag", f.maxIssuanceLag, &p.MaxIssuanceLag},
		{"max-evidence-age", f.maxEvidenceAge, &p.MaxEvidenceAge},
	} {
		if !set[d.flag] {
			continue
		}
		if d.value <= 0 {
			return fmt.Errorf("-%s must be a positive duration", d.flag)
		}
		if *d.field != 0 && *d.field != d.value {
			return fmt.Errorf("-%s says %s and the policy document says %s", d.flag, d.value, *d.field)
		}
		*d.field = d.value
	}
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
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

func printHuman(w io.Writer, out output) {
	r := out.Report
	fmt.Fprintf(w, "mode: %s\n", out.Mode)
	fmt.Fprintf(w, "verdict: %s\n", r.Verdict)
	if r.Verdict != aee.VerdictValid {
		for _, c := range r.Codes {
			marker := " "
			if c == r.PrimaryCode {
				marker = "*"
			}
			fmt.Fprintf(w, "  %s %s\n", marker, c)
		}
		fmt.Fprintln(w, "result: (not consumed: the attestation is invalid)")
		fmt.Fprintln(w, "admitted: false (the attestation is invalid)")
		return
	}
	fmt.Fprintf(w, "result: %s (the producer's claim, recompute-confirmed; not by itself an admission)\n", r.Result)
	fmt.Fprintln(w, "evidence tiers (per attackResults row, under YOUR keys):")
	for i, tier := range r.Tiers {
		fmt.Fprintf(w, "  row %d: %s\n", i, tier)
	}
	if len(r.ArmedAt) > 0 {
		fmt.Fprintf(w, "observer-signed arming instants: %s\n", strings.Join(r.ArmedAt, ", "))
	} else {
		fmt.Fprintln(w, "observer-signed arming instants: none verified under your keys")
	}
	if out.Mode == modeValidityOnly {
		fmt.Fprintln(w, "admitted: false (validity only: no admission question was asked)")
	} else {
		for _, c := range r.PolicyCodes {
			fmt.Fprintf(w, "  refused: %s\n", c)
		}
		fmt.Fprintf(w, "admitted: %t\n", r.Admitted)
	}
	if len(r.ProducerAsserted) > 0 {
		fmt.Fprintf(w, "producer-asserted, bound by no observer: %s\n", strings.Join(r.ProducerAsserted, ", "))
	}
	fmt.Fprintf(w, "not established by this run: %s\n", strings.Join(out.NotEstablished, ", "))
}
