// Command generate writes vectors/cross_lang_signing.json.
//
// Every PAE pre-image and every envelope in the file comes from the DSSE
// reference Go implementation, github.com/secure-systems-lab/go-securesystemslib/dsse,
// at the version pinned in go.mod. The signatures are ed25519 over those
// pre-images, from Go's standard library. Nothing in the file is produced by
// the Rust crate that the file tests.
//
// The output is deterministic: the key is derived from a fixed label, ed25519
// signing is deterministic, and every payload is a constant below. Run it from
// this directory:
//
//	go run . > ../cross_lang_signing.json
//
// and the file must come out byte-identical to the committed one.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"unicode/utf8"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// keyLabel is hashed to the 32-byte ed25519 seed. The key is a published test
// key: it proves byte agreement between implementations and protects nothing.
const keyLabel = "github.com/probityai/dsse cross-language fixture key v1"

const (
	typeStatement = "application/vnd.in-toto+json"
	typeRecord    = "application/vnd.example.record+json"
	typeBinary    = "application/octet-stream"
	typeText      = "text/plain; charset=utf-8"
	// A payload type whose byte length differs from its character length, so a
	// PAE that counts characters instead of bytes fails this case.
	typeUnicode = "application/vnd.example.ünïcødé+json"
)

type signer struct {
	key   ed25519.PrivateKey
	keyID string
}

func (s signer) Sign(_ context.Context, data []byte) ([]byte, error) {
	return s.key.Sign(nil, data, crypto.Hash(0))
}

func (s signer) KeyID() (string, error) { return s.keyID, nil }

type verifier struct {
	pub   ed25519.PublicKey
	keyID string
}

func (v verifier) Verify(_ context.Context, data, sig []byte) error {
	if !ed25519.Verify(v.pub, data, sig) {
		return errors.New("ed25519 verification failed")
	}
	return nil
}

func (v verifier) KeyID() (string, error)   { return v.keyID, nil }
func (v verifier) Public() crypto.PublicKey { return v.pub }

type fixture struct {
	Name         string         `json:"name"`
	PayloadType  string         `json:"payload_type"`
	CanonicalB64 string         `json:"canonical_b64"`
	PAEB64       string         `json:"pae_b64"`
	SignatureB64 string         `json:"signature_b64"`
	Envelope     *dsse.Envelope `json:"envelope"`
	Note         string         `json:"note"`
}

type generator struct {
	Implementation string `json:"implementation"`
	Version        string `json:"version"`
	Go             string `json:"go"`
	Command        string `json:"command"`
}

type bundle struct {
	Description  string    `json:"description"`
	GeneratedBy  generator `json:"generated_by"`
	KeyLabel     string    `json:"key_label"`
	TestSeedHex  string    `json:"test_seed_hex"`
	PublicKeyPEM string    `json:"public_key_pem"`
	KeyID        string    `json:"key_id"`
	Fixtures     []fixture `json:"fixtures"`
}

type body struct {
	name, payloadType, note string
	bytes                   []byte
}

// canonical marshals v with sorted object keys, no insignificant whitespace and
// no HTML escaping. For the ASCII keys, strings and small integers used here
// that is the RFC 8785 form.
func canonical(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func digest(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

func statement(subjects []string, predicate map[string]any) []byte {
	subj := make([]any, 0, len(subjects))
	for _, s := range subjects {
		subj = append(subj, map[string]any{"name": s, "digest": map[string]any{"sha256": digest(s)}})
	}
	return canonical(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subj,
		"predicateType": "https://example.com/predicate/build/v1",
		"predicate":     predicate,
	})
}

func batchRoot() []byte {
	root := sha256.Sum256([]byte("example batch of eight records"))
	out := make([]byte, 8, 40)
	binary.BigEndian.PutUint64(out, 8)
	out = append(out, root[:]...)
	if utf8.Valid(out) {
		panic("the binary fixture must not be valid UTF-8")
	}
	return out
}

func bodies() []body {
	return []body{
		{"statement_0", typeStatement, "an in-toto Statement with one subject",
			statement([]string{"release.tar.gz"}, map[string]any{
				"builder": "https://example.com/builder", "finishedOn": "2026-01-01T00:00:00Z"})},
		{"statement_1", typeStatement, "an in-toto Statement with two subjects",
			statement([]string{"app-linux-amd64", "app-linux-arm64"}, map[string]any{
				"builder": "https://example.com/builder", "reproducible": true})},
		{"statement_nested", typeStatement, "nested arrays, objects, booleans, null and integers",
			statement([]string{"bundle.zip"}, map[string]any{
				"steps": []any{
					map[string]any{"name": "fetch", "exitCode": 0, "cached": false},
					map[string]any{"name": "build", "exitCode": 0, "cached": nil},
				},
				"limits": map[string]any{"cpu": 2, "memoryMiB": 4096}})},
		{"record_0", typeRecord, "a flat event record with a documentation address",
			canonical(map[string]any{"event": "egress_blocked", "host": "example.com",
				"dst_ip": "203.0.113.9", "dst_port": 443, "time": "2026-01-01T00:00:01Z"})},
		{"record_1", typeRecord, "a second record under the same type",
			canonical(map[string]any{"event": "file_write", "path": "/srv/example/output.txt",
				"bytes": 1024, "time": "2026-01-01T00:00:02Z"})},
		{"record_unicode", typeRecord, "multi-byte UTF-8 in the body, so byte and character lengths differ",
			canonical(map[string]any{"event": "annotation",
				"note": "café ✓ 雪 \U0001F642"})},
		{"record_large", typeRecord, "a body over 1000 bytes, so the length prefix has four digits",
			canonical(map[string]any{"event": "bulk", "data": strings.Repeat("0123456789abcdef", 72)})},
		{"text_line", typeText, "a text body ending in a newline",
			[]byte("hello, world\n")},
		{"empty_body", typeText, "an empty body, so the length prefix is zero",
			[]byte{}},
		{"binary_batch_root", typeBinary, "a big-endian u64 count of 8 then a 32-byte SHA-256 root; not valid UTF-8",
			batchRoot()},
		{"unicode_payload_type", typeUnicode, "a payload type whose byte length exceeds its character length",
			canonical(map[string]any{"k": "v"})},
	}
}

func modVersion(path string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		panic("no build info")
	}
	for _, m := range info.Deps {
		if m.Path == path {
			return m.Version
		}
	}
	panic("module not in build info: " + path)
}

func main() {
	seed := sha256.Sum256([]byte(keyLabel))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	kid := sha256.Sum256(pub)
	keyID := hex.EncodeToString(kid[:])

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	es, err := dsse.NewEnvelopeSigner(signer{priv, keyID})
	if err != nil {
		panic(err)
	}
	ev, err := dsse.NewEnvelopeVerifier(verifier{pub, keyID})
	if err != nil {
		panic(err)
	}

	const implPath = "github.com/secure-systems-lab/go-securesystemslib"
	out := bundle{
		Description: "Cross-language DSSE fixtures. Every pae_b64 and envelope was produced by the " +
			"reference Go implementation named in generated_by; the Rust crate must reproduce each " +
			"pre-image byte for byte and verify each signature. The key is a published test key.",
		GeneratedBy: generator{
			Implementation: implPath + "/dsse",
			Version:        modVersion(implPath),
			Go:             runtime.Version(),
			Command:        "cd vectors/generate && go run . > ../cross_lang_signing.json",
		},
		KeyLabel:     keyLabel,
		TestSeedHex:  hex.EncodeToString(seed[:]),
		PublicKeyPEM: string(pemBytes),
		KeyID:        keyID,
	}

	ctx := context.Background()
	for _, b := range bodies() {
		env, err := es.SignPayload(ctx, b.payloadType, b.bytes)
		if err != nil {
			panic(err)
		}
		if _, err := ev.Verify(ctx, env); err != nil {
			panic(fmt.Sprintf("%s: reference verifier refused its own envelope: %v", b.name, err))
		}
		out.Fixtures = append(out.Fixtures, fixture{
			Name:         b.name,
			PayloadType:  b.payloadType,
			CanonicalB64: base64.StdEncoding.EncodeToString(b.bytes),
			PAEB64:       base64.StdEncoding.EncodeToString(dsse.PAE(b.payloadType, b.bytes)),
			SignatureB64: env.Signatures[0].Sig,
			Envelope:     env,
			Note:         b.note,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
