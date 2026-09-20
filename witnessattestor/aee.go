// Package witnessattestor is a go-witness-compatible attestor for the
// in-toto Adversarial Execution Evidence predicate v0.7. It follows the
// upstream sarif pattern (attestation/sarif/sarif.go: a PostProductRunType
// attestor that picks up an externally produced report file among the
// step's products, integrity-checks it, and embeds it), swapping "parse
// sarif" for "parse + gate-check AEE evidence".
//
// Security scope — what this attestor claims and what it does not:
//
//   - The witness envelope key backs the PRODUCER-ASSERTED plane only: the
//     assembly of the predicate, its gate-validity, and its
//     recompute-consistency at pipeline step time. The SUBSTRATE-COVERED
//     plane travels exclusively in the signed observationRecords inside the
//     predicate, verified per record at the consumer's evidence-tier
//     derivation against consumer-pinned substrate observation keys.
//   - This attestor never claims "witness observed the execution".
//   - go-witness's own commandrun tracing runs in the same trust domain as
//     the artifact and carries none of the reserved record members; it is
//     never basis: substrate coverage and must not be framed as such.
//
// EMIT SEAM — never sign what does not verify: Attest runs GATE 0
// (statement well-formedness) + GATE 1 (coverage validity) + the result
// recompute over the located evidence and returns an error, rather than
// signing, on any failure. GATE 2 (the evidence tier) never runs at emit:
// the tier is trust-relative and consumer-derived by definition. The
// optional expect-substrate-key flag is producer QA — it verifies record
// signatures locally and still derives no tier.
package witnessattestor

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"crypto/ed25519"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"

	"github.com/probityai/agent-evidence-vectors/aee"
)

const (
	// Name is the attestor name surfaced to the witness CLI/config.
	Name = "adversarial-execution-evidence"
	// Type is the AEE predicateType URI; json.Marshal of this attestor is
	// the predicate bytes signed under it (run.go createAndSignEnvelope).
	Type = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
	// DefaultEvidenceFileName is the neutral product filename scanned for
	// when no explicit evidence-path is configured.
	DefaultEvidenceFileName = "aee-evidence.json"
)

// RunType is PostProductRunType: the evidence file is produced by the execution
// step, so the attestor runs post-product, exactly like the sarif attestor.
var RunType = attestation.PostProductRunType

// Compile-time interface asserts. Exporter is MANDATORY: without
// Export()==true the predicate would be buried inside the witness
// attestation collection under the collection predicateType; and an
// Exporter without Subjecter is silently skipped by the run loop — both
// must be implemented or nothing is emitted.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
	_ attestation.Exporter  = &Attestor{}
)

//go:embed schema/aee-v0.7.schema.json
var embeddedSchema []byte

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() },
		registry.StringConfigOption(
			"evidence-path",
			"Path to the substrate-emitted AEE evidence statement JSON (default: scan products for "+DefaultEvidenceFileName+")",
			"",
			func(a attestation.Attestor, path string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type %T", a)
				}
				att.evidencePath = path
				return att, nil
			},
		),
		registry.StringConfigOption(
			"expect-substrate-key",
			"Producer-QA only: path to a 64-hex raw ed25519 public key; every covering observation record must verify under it or the attestor errors. Derives NO evidence tier.",
			"",
			func(a attestation.Attestor, path string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type %T", a)
				}
				att.expectSubstrateKeyPath = path
				return att, nil
			},
		),
	)
}

// Attestor validates and re-emits a substrate-produced AEE statement as a
// signed standalone in-toto statement. Its JSON serialization is EXACTLY
// the validated predicate bytes (MarshalJSON below), so the signed
// predicate cannot drift from what the gates checked.
type Attestor struct {
	predicateRaw           json.RawMessage
	subjectName            string
	subjectDigest          cryptoutil.DigestSet
	evidencePath           string
	expectSubstrateKeyPath string
	// refusalErr remembers why Attest refused, so the MarshalJSON backstop
	// can name the reason. It matters because of an upstream go-witness
	// v0.8.0 bug: attestation/context.go runAttestor is missing a return
	// after recording a failed attestor, so the failure is recorded a
	// second time WITHOUT the error and run.go still tries to sign the
	// exporter; this backstop is what actually stops the signature.
	refusalErr error
}

// New returns an unconfigured attestor.
func New() *Attestor { return &Attestor{} }

// Name implements attestation.Attestor.
func (a *Attestor) Name() string { return Name }

// Type implements attestation.Attestor.
func (a *Attestor) Type() string { return Type }

// RunType implements attestation.Attestor.
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Export implements attestation.Exporter: the AEE statement is emitted as
// its own standalone statement under the AEE predicateType, never buried
// in the collection.
func (a *Attestor) Export() bool { return true }

// parsedSchema is the embedded predicate schema, unmarshaled once at package
// initialization. The embedded bytes are a build-time constant (guarded by
// TestSchemaRoundTripLossless), so a failure here is a build defect, not a
// runtime condition: panic at load rather than let Schema() silently serve an
// empty, misleading schema. This mirrors the regexp.MustCompile idiom.
var parsedSchema = mustParseSchema()

func mustParseSchema() *jsonschema.Schema {
	s := &jsonschema.Schema{}
	if err := json.Unmarshal(embeddedSchema, s); err != nil {
		panic(fmt.Sprintf("witnessattestor: embedded predicate schema failed to unmarshal (build defect): %v", err))
	}
	return s
}

// Schema implements attestation.Attestor. It serves the embedded public
// schema rather than a Go-struct reflection, so the published schema cannot
// drift from the spec's. The schema is NON-NORMATIVE convenience: the
// predicate specification text is authoritative; conflicts are schema bugs.
func (a *Attestor) Schema() *jsonschema.Schema {
	return parsedSchema
}

// Subjects implements attestation.Subjecter: exactly ONE subject, the
// executed artifact by digest, taken from the validated evidence statement
// (binding version 1 requires exactly one subject on substrate-carrying
// statements; the verifier rejects violations fail-closed).
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	if a.subjectName == "" {
		return map[string]cryptoutil.DigestSet{}
	}
	return map[string]cryptoutil.DigestSet{a.subjectName: a.subjectDigest}
}

// MarshalJSON emits the validated predicate bytes verbatim. All
// configuration state stays out of the signed predicate by construction.
func (a *Attestor) MarshalJSON() ([]byte, error) {
	if a.predicateRaw == nil {
		if a.refusalErr != nil {
			return nil, fmt.Errorf("attestor refused the evidence and will not serialize a predicate: %w", a.refusalErr)
		}
		return nil, errors.New("attestor has not validated any evidence; refusing to serialize an empty predicate")
	}
	return a.predicateRaw, nil
}

// UnmarshalJSON re-hydrates a stored predicate (collection parsing path).
func (a *Attestor) UnmarshalJSON(b []byte) error {
	a.predicateRaw = append(json.RawMessage(nil), b...)
	return nil
}

// Attest implements attestation.Attestor. Any failure is remembered in
// refusalErr so the MarshalJSON backstop names the reason (see the
// refusalErr comment for why the backstop matters).
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.attest(ctx); err != nil {
		a.refusalErr = err
		return err
	}
	return nil
}

func (a *Attestor) attest(ctx *attestation.AttestationContext) error {
	path, product, err := a.locateEvidence(ctx)
	if err != nil {
		return err
	}
	// Product paths are recorded relative to the step's working directory.
	if !filepath.IsAbs(path) {
		path = filepath.Join(ctx.WorkingDir(), path)
	}

	// Integrity re-hash before trusting file contents (sarif pattern): the
	// bytes we validate must be the bytes the product attestor recorded.
	digestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
	if err != nil {
		return fmt.Errorf("error calculating digest set from file %s: %w", path, err)
	}
	if !digestSet.Equal(product.Digest) {
		return fmt.Errorf("integrity error: product digest does not match evidence file %s", path)
	}

	body, err := os.ReadFile(path) // #nosec G304 -- path is a step product located and digest-verified above, not attacker input
	if err != nil {
		return fmt.Errorf("error reading evidence file %s: %w", path, err)
	}

	statement, err := aee.ParseStatement(body)
	if err != nil {
		return fmt.Errorf("refusing to sign: evidence does not parse as an in-toto statement: %w", err)
	}
	if statement.PredicateType != Type {
		return fmt.Errorf("refusing to sign: evidence predicateType %q is not %q (fail-closed; no cross-version fallback)", statement.PredicateType, Type)
	}

	// Validation seam: GATE 0 + GATE 1 + recompute equality. The attestor
	// MUST error, never sign, on any failure. The sealed context is reused by
	// the producer-QA signature check below (no re-derivation).
	evalCtx, err := aee.VerifyForEmit(body)
	if err != nil {
		return fmt.Errorf("refusing to sign: %w", err)
	}

	if a.expectSubstrateKeyPath != "" {
		if err := a.producerQACheck(evalCtx); err != nil {
			return fmt.Errorf("producer QA (expect-substrate-key): %w", err)
		}
	}

	// GATE 0 (via VerifyForEmit above) already rejected any statement without
	// exactly one subject carrying a sha256 digest (subject-cardinality,
	// subject-sha256-missing). Re-assert the invariant fail-closed rather than
	// silently build an empty DigestSet (which would bind the signed
	// attestation to no artifact) or drop subjects past the first, in case the
	// gate contract ever changes.
	if len(statement.Subject) != 1 {
		return fmt.Errorf("refusing to sign: AEE binds exactly one subject, statement carries %d", len(statement.Subject))
	}
	subject := statement.Subject[0]
	sha := subject.Digest["sha256"]
	if sha == "" {
		return errors.New("refusing to sign: subject carries no sha256 digest; an empty digest set would bind the attestation to no artifact")
	}
	subjectDigest, err := cryptoutil.NewDigestSet(map[string]string{"sha256": sha})
	if err != nil {
		return fmt.Errorf("error building subject digest set: %w", err)
	}

	a.predicateRaw = statement.PredicateRaw
	a.subjectName = subject.Name
	a.subjectDigest = subjectDigest
	return nil
}

// locateEvidence finds the evidence file among the step's recorded
// products: the configured evidence-path if set, else the product whose
// base name is DefaultEvidenceFileName (deterministic order on ties).
func (a *Attestor) locateEvidence(ctx *attestation.AttestationContext) (string, attestation.Product, error) {
	products := ctx.Products()
	if len(products) == 0 {
		return "", attestation.Product{}, errors.New("no products recorded for this step; the evidence file must be a step product")
	}
	if a.evidencePath != "" {
		return matchConfiguredEvidence(products, a.evidencePath)
	}
	paths := make([]string, 0, len(products))
	for path := range products {
		if filepath.Base(path) == DefaultEvidenceFileName {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		return "", attestation.Product{}, fmt.Errorf("no product named %s; set --attestor-%s-evidence-path", DefaultEvidenceFileName, Name)
	}
	sort.Strings(paths)
	return paths[0], products[paths[0]], nil
}

// matchConfiguredEvidence resolves a caller-configured evidence-path against
// the step's products. The match is on a path-component boundary: a configured
// value equals a product path exactly, or is its trailing path segment
// ("evidence.json" matches "sub/evidence.json"), but never a substring of a
// filename ("evidence.json" must NOT match "attacker-evidence.json"). A
// configured value that resolves to more than one product is a misconfiguration;
// signing an arbitrary map-iteration winner would be nondeterministic and could
// attest the wrong file, so it fails closed with an ambiguity error rather than
// guessing.
func matchConfiguredEvidence(products map[string]attestation.Product, configured string) (string, attestation.Product, error) {
	want := filepath.ToSlash(configured)
	var matches []string
	for path := range products {
		slashed := filepath.ToSlash(path)
		if slashed == want || strings.HasSuffix(slashed, "/"+want) {
			matches = append(matches, path)
		}
	}
	switch len(matches) {
	case 0:
		return "", attestation.Product{}, fmt.Errorf("configured evidence-path %q is not among the step's products", configured)
	case 1:
		return matches[0], products[matches[0]], nil
	default:
		sort.Strings(matches)
		return "", attestation.Product{}, fmt.Errorf("configured evidence-path %q is ambiguous: it matches %d products (%s); refusing to guess which to sign", configured, len(matches), strings.Join(matches, ", "))
	}
}

func (a *Attestor) producerQACheck(evalCtx *aee.EvalContext) error {
	raw, err := os.ReadFile(a.expectSubstrateKeyPath)
	if err != nil {
		return err
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("expected a %d-byte hex-encoded ed25519 public key", ed25519.PublicKeySize)
	}
	return evalCtx.CheckRecordSignatures([]ed25519.PublicKey{ed25519.PublicKey(pubBytes)})
}
