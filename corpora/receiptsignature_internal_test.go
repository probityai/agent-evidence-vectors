package corpora

// The reference verification of the receipt-signature reader, one outcome per
// case. The corpus reaches the outcomes its members encode; these reach the
// ones no member encodes, the undecidable causes among them, so that each
// refusal is shown to be reachable rather than assumed to be.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
)

const rsTestKid = "sb:issuer:testtesttest"

func rsTestKey() (ed25519.PrivateKey, rsJWK) {
	seed := sha256.Sum256([]byte("receipt-signature internal test key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	from, until := "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"
	return private, rsJWK{
		Kty: "OKP", Crv: "Ed25519", Kid: rsTestKid,
		X: base64.RawURLEncoding.EncodeToString(public), ValidFrom: &from, ValidUntil: &until,
	}
}

// rsReceipt signs JCS(payload) and wraps it in the envelope shape, with an
// optional edit to the finished document.
func rsReceipt(t *testing.T, payload map[string]any, edit func(map[string]any)) []byte {
	t.Helper()
	private, _ := rsTestKey()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"payload": payload,
		"signature": map[string]any{
			"alg": "EdDSA", "kid": rsTestKid, "sig": hex.EncodeToString(ed25519.Sign(private, canonical)),
		},
	}
	if edit != nil {
		edit(doc)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rsPayload(issued string) map[string]any {
	return map[string]any{"type": "protectmcp:decision", "issued_at": issued, "issuer_id": rsTestKid}
}

func TestReceiptVerificationOutcomes(t *testing.T) {
	_, key := rsTestKey()
	keys := map[string]rsJWK{rsTestKid: key}
	inside := rsPayload("2026-03-15T00:00:00Z")
	sig := func(doc map[string]any) map[string]any { return doc["signature"].(map[string]any) }
	cases := []struct {
		name string
		body []byte
		keys map[string]rsJWK
		want string
	}{
		{"valid", rsReceipt(t, inside, nil), keys, "valid"},
		{"not json", []byte("not json"), keys, "undecidable not_envelope_shape"},
		{"extra member", rsReceipt(t, inside, func(d map[string]any) { d["extra"] = 1 }), keys,
			"undecidable not_envelope_shape"},
		{"signature not an object", rsReceipt(t, inside, func(d map[string]any) { d["signature"] = "x" }), keys,
			"undecidable bad_signature_object"},
		{"null payload", rsReceipt(t, inside, func(d map[string]any) { d["payload"] = nil }), keys,
			"undecidable payload_not_an_object"},
		{"missing field", rsReceipt(t, map[string]any{"type": "t", "issuer_id": rsTestKid}, nil), keys,
			"undecidable missing_required_field"},
		{"unsupported alg", rsReceipt(t, inside, func(d map[string]any) { sig(d)["alg"] = "ES256" }), keys,
			"undecidable unsupported_alg"},
		{"issuer is not kid", rsReceipt(t, map[string]any{
			"type": "t", "issued_at": "2026-03-15T00:00:00Z", "issuer_id": "someone else",
		}, nil), keys, "invalid issuer_kid_mismatch"},
		{"unknown kid", rsReceipt(t, inside, nil), map[string]rsJWK{}, "undecidable unknown_kid"},
		{"unsupported key", rsReceipt(t, inside, nil), map[string]rsJWK{rsTestKid: {Kty: "EC"}},
			"undecidable unsupported_key"},
		{"bad key", rsReceipt(t, inside, nil), map[string]rsJWK{rsTestKid: {Kty: "OKP", Crv: "Ed25519", X: "!!"}},
			"undecidable bad_key"},
		{"signature not hex", rsReceipt(t, inside, func(d map[string]any) { sig(d)["sig"] = "zz" }), keys,
			"invalid bad_signature_encoding"},
		{"payload repeats a member", []byte(`{"payload":{"type":"t","issued_at":"2026-03-15T00:00:00Z",` +
			`"issuer_id":"` + rsTestKid + `","type":"u"},"signature":{"alg":"EdDSA","kid":"` + rsTestKid +
			`","sig":"` + hex.EncodeToString(make([]byte, 64)) + `"}}`), keys,
			"undecidable payload_not_canonicalizable"},
		{"issued_at not a time", rsReceipt(t, rsPayload("yesterday"), nil), keys,
			"undecidable window_not_applicable"},
		{"issued_at not a string", rsReceipt(t, map[string]any{
			"type": "t", "issued_at": 7, "issuer_id": rsTestKid,
		}, nil), keys, "undecidable window_not_applicable"},
		{"before the window", rsReceipt(t, rsPayload("2025-12-01T00:00:00Z"), nil), keys,
			"invalid key_outside_validity_window"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rsVerify(tc.body, tc.keys).String(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReceiptWindowBoundUnreadable(t *testing.T) {
	_, key := rsTestKey()
	bad := "not a time"
	key.ValidUntil = &bad
	got := rsVerify(rsReceipt(t, rsPayload("2026-03-15T00:00:00Z"), nil), map[string]rsJWK{rsTestKid: key})
	if got.String() != "undecidable window_not_applicable" {
		t.Fatalf("got %q", got)
	}
}

func TestReceiptJudgeRefusesAnUnparsedManifest(t *testing.T) {
	if _, err := (receiptSignature{}).Judge(t.TempDir(), []byte("not json")); err == nil {
		t.Fatal("a manifest that does not parse was judged")
	}
}
