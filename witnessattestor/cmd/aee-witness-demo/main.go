// Command aee-witness-demo uses go-witness AS A LIBRARY to emit a signed
// standalone AEE statement from a directory containing an evidence file
// named aee-evidence.json (any conformance-suite accept vector body works).
//
// It is the library-mode proof that the attestor plugs into the witness run
// lifecycle: the product attestor records the evidence file's digest, the
// AEE attestor integrity-checks it, runs GATE 0 + GATE 1 + the recompute,
// and only then is it signed and exported as its own statement under the
// AEE predicateType. The demo signer is an ephemeral ed25519 key: it backs
// the producer-asserted plane only and authenticates nothing beyond this
// demo run.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"

	// The attestor package sits at the module root (see BUILD-NOTES.md for
	// the two-module layout and the workspace build).
	witnessattestor "github.com/probityai/agent-evidence-vectors/witnessattestor"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: aee-witness-demo <dir-containing-aee-evidence.json>")
		os.Exit(2)
	}
	dir := os.Args[1]

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	fail(err)
	signer, err := cryptoutil.NewSigner(priv)
	fail(err)

	results, err := witness.RunWithExports(
		"execute-validate",
		witness.RunWithAttestors([]attestation.Attestor{product.New(), witnessattestor.New()}),
		witness.RunWithSigners(signer),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(dir)),
	)
	fail(err)

	for _, r := range results {
		if r.AttestorName != witnessattestor.Name {
			continue
		}
		out, err := json.MarshalIndent(r.SignedEnvelope, "", "  ")
		fail(err)
		fmt.Println(string(out))
		return
	}
	fmt.Fprintln(os.Stderr, "no exported AEE statement in run results (was the evidence file present and valid?)")
	os.Exit(1)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "aee-witness-demo:", err)
		os.Exit(1)
	}
}
