package witnessattestor

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
	"github.com/probityai/agent-evidence-vectors/aeetest"
)

// fakeProducer is a minimal product-run attestor that publishes a fixed product
// set, standing in for go-witness's real product attestor so the AEE attestor's
// Attest path (locate + integrity-rehash + gate + sign) can be exercised end to
// end. It runs at ProductRunType, before the postproduct AEE attestor.
type fakeProducer struct {
	products map[string]attestation.Product
}

func (f *fakeProducer) Name() string                                 { return "fake-product" }
func (f *fakeProducer) Type() string                                 { return "fake-product" }
func (f *fakeProducer) RunType() attestation.RunType                 { return attestation.ProductRunType }
func (f *fakeProducer) Attest(*attestation.AttestationContext) error { return nil }
func (f *fakeProducer) Schema() *jsonschema.Schema                   { return &jsonschema.Schema{} }
func (f *fakeProducer) Products() map[string]attestation.Product     { return f.products }

// ctxHashes mirrors the default hash set NewContext installs, so a product
// digest computed here matches the attestor's integrity rehash.
var ctxHashes = []cryptoutil.DigestValue{
	{Hash: crypto.SHA256},
	{Hash: crypto.SHA256, GitOID: true},
	{Hash: crypto.SHA1, GitOID: true},
}

// stageEvidence writes body to a temp dir under the default evidence filename
// and returns the dir plus a producer advertising it as a product.
func stageEvidence(t *testing.T, body []byte) (string, *fakeProducer) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultEvidenceFileName)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	ds, err := cryptoutil.CalculateDigestSetFromFile(path, ctxHashes)
	if err != nil {
		t.Fatal(err)
	}
	return dir, &fakeProducer{products: map[string]attestation.Product{
		DefaultEvidenceFileName: {MimeType: "application/json", Digest: ds},
	}}
}

// runAttest wires the fake producer and the AEE attestor into a context, runs
// them, and returns the AEE attestor's own completion error. RunAttestors
// collects per-attestor errors rather than aborting, so a refusal surfaces here,
// not in RunAttestors' return.
func runAttest(t *testing.T, dir string, fp *fakeProducer, a *Attestor) error {
	t.Helper()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{fp, a},
		attestation.WithWorkingDir(dir), attestation.WithHashes(ctxHashes))
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.RunAttestors(); err != nil {
		return err
	}
	for _, c := range ctx.CompletedAttestors() {
		if c.Attestor.Name() == a.Name() {
			return c.Error
		}
	}
	t.Fatal("the AEE attestor did not run")
	return nil
}

func TestAttestSignsValidEvidence(t *testing.T) {
	dir, fp := stageEvidence(t, aeetest.Build(aeetest.Options{}))
	a := New()
	if err := runAttest(t, dir, fp, a); err != nil {
		t.Fatalf("RunAttestors errored on valid evidence: %v", err)
	}
	// A signed attestor serializes the validated predicate and exposes exactly
	// one subject (the executed artifact).
	raw, err := a.MarshalJSON()
	if err != nil {
		t.Fatalf("attestor did not produce a predicate: %v", err)
	}
	var stmt map[string]any
	if err := json.Unmarshal(raw, &stmt); err != nil {
		t.Fatalf("predicate is not JSON: %v", err)
	}
	if subjects := a.Subjects(); len(subjects) != 1 {
		t.Fatalf("want exactly one subject, got %d", len(subjects))
	}
}

func TestAttestRefusesInvalidEvidence(t *testing.T) {
	// Result forced to "pass" against a caught row is a recompute mismatch, so
	// the emit seam must refuse rather than sign.
	dir, fp := stageEvidence(t, aeetest.Build(aeetest.Options{Result: "pass"}))
	if err := runAttest(t, dir, fp, New()); err == nil {
		t.Fatal("RunAttestors signed a statement the suite rejects")
	}
}

func TestAttestIntegrityMismatch(t *testing.T) {
	dir, fp := stageEvidence(t, aeetest.Build(aeetest.Options{}))
	// Corrupt the file on disk AFTER the producer recorded its digest: the
	// integrity rehash must catch the divergence and refuse.
	if err := os.WriteFile(filepath.Join(dir, DefaultEvidenceFileName), []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runAttest(t, dir, fp, New()); err == nil {
		t.Fatal("attestor signed despite a product-digest / file-content mismatch")
	}
}

// writeKey writes a hex-encoded ed25519 public key to a file for the
// expect-substrate-key producer-QA flag.
func writeKey(t *testing.T, dir string, pub ed25519.PublicKey) string {
	t.Helper()
	p := filepath.Join(dir, "substrate.pub")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAttestProducerQA(t *testing.T) {
	dir, fp := stageEvidence(t, aeetest.Build(aeetest.Options{}))
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)

	// The records are signed by the substrate-observation key, so producer QA
	// under that key passes and the attestor signs.
	a := New()
	a.expectSubstrateKeyPath = writeKey(t, dir, pub)
	if err := runAttest(t, dir, fp, a); err != nil {
		t.Fatalf("producer QA rejected correctly-signed evidence: %v", err)
	}

	// Under a different expected key, producer QA fails and the attestor refuses.
	wrong := aeetest.TestKey(aeetest.RoleWrongSigner).Public().(ed25519.PublicKey)
	bad := New()
	bad.expectSubstrateKeyPath = writeKey(t, dir, wrong)
	if err := runAttest(t, dir, fp, bad); err == nil {
		t.Fatal("producer QA signed evidence whose records do not verify under the expected key")
	}
}

func TestAttestorInterfaceAccessors(t *testing.T) {
	a := New()
	if a.Name() != Name {
		t.Errorf("Name() = %q, want %q", a.Name(), Name)
	}
	if a.Type() != Type {
		t.Errorf("Type() = %q, want %q", a.Type(), Type)
	}
	if a.RunType() != RunType {
		t.Errorf("RunType() = %q, want %q", a.RunType(), RunType)
	}
	if !a.Export() {
		t.Error("Export() should be true for a subject-carrying attestor")
	}
	// UnmarshalJSON is a deliberate no-op backstop; it must not error.
	if err := a.UnmarshalJSON([]byte(`{"anything":true}`)); err != nil {
		t.Errorf("UnmarshalJSON: %v", err)
	}
}

func TestAttestorEmptyState(t *testing.T) {
	a := New()
	// Before signing, no subject is exposed and serialization refuses.
	if subjects := a.Subjects(); len(subjects) != 0 {
		t.Errorf("fresh attestor exposes %d subjects, want 0", len(subjects))
	}
	if _, err := a.MarshalJSON(); err == nil {
		t.Error("MarshalJSON should refuse to serialize an unvalidated predicate")
	}
}

func TestAttestNoProducts(t *testing.T) {
	dir := t.TempDir()
	empty := &fakeProducer{products: map[string]attestation.Product{}}
	if err := runAttest(t, dir, empty, New()); err == nil {
		t.Fatal("attestor signed with no evidence product present")
	}
}

func TestAttestWrongPredicateType(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(aeetest.Build(aeetest.Options{}), &m); err != nil {
		t.Fatal(err)
	}
	m["predicateType"] = "https://example.com/not-aee/v1"
	wrong, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dir, fp := stageEvidence(t, wrong)
	if err := runAttest(t, dir, fp, New()); err == nil {
		t.Fatal("attestor signed a statement whose predicateType is not AEE")
	}
}

func TestProducerQABadKeyFile(t *testing.T) {
	dir, fp := stageEvidence(t, aeetest.Build(aeetest.Options{}))
	keyPath := filepath.Join(dir, "substrate.pub")
	if err := os.WriteFile(keyPath, []byte("not-hex-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	a.expectSubstrateKeyPath = keyPath
	if err := runAttest(t, dir, fp, a); err == nil {
		t.Fatal("producer QA accepted a malformed key file")
	}
}

// TestFlagOptionSetters exercises the registered evidence-path and
// expect-substrate-key flag closures, confirming each sets its field.
func TestFlagOptionSetters(t *testing.T) {
	found := 0
	for _, entry := range attestation.RegistrationEntries() {
		if entry.Name != Name {
			continue
		}
		for _, opt := range entry.Options {
			co, ok := opt.(*registry.ConfigOption[attestation.Attestor, string])
			if !ok {
				t.Fatalf("option %q is not a string config option", opt.Name())
			}
			got, err := co.Setter()(New(), "/x/path")
			if err != nil {
				t.Fatalf("%s setter: %v", co.Name(), err)
			}
			att := got.(*Attestor)
			switch co.Name() {
			case "evidence-path":
				if att.evidencePath != "/x/path" {
					t.Error("evidence-path flag did not set evidencePath")
				}
			case "expect-substrate-key":
				if att.expectSubstrateKeyPath != "/x/path" {
					t.Error("expect-substrate-key flag did not set expectSubstrateKeyPath")
				}
			default:
				t.Errorf("unexpected option %q", co.Name())
			}
			found++
		}
	}
	if found != 2 {
		t.Fatalf("expected 2 registered flag options, found %d", found)
	}
}
