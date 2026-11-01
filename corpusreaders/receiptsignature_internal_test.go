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
			if got := rsVerify(tc.body, tc.keys, false).String(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReceiptWindowBoundUnreadable(t *testing.T) {
	_, key := rsTestKey()
	bad := "not a time"
	key.ValidUntil = &bad
	got := rsVerify(rsReceipt(t, rsPayload("2026-03-15T00:00:00Z"), nil), map[string]rsJWK{rsTestKid: key}, false)
	if got.String() != "undecidable window_not_applicable" {
		t.Fatalf("got %q", got)
	}
}

func TestReceiptJudgeRefusesAnUnparsedManifest(t *testing.T) {
	if _, err := (receiptSignature{}).Judge(t.TempDir(), []byte("not json")); err == nil {
		t.Fatal("a manifest that does not parse was judged")
	}
}

// rsChainedFixture is a genesis, a receipt at position 2 linked to it, and the
// issuer's commitment to a chain of one, all under the internal test key.
func rsChainedFixture(t *testing.T) (genesis, second, commitment []byte) {
	t.Helper()
	genesis = rsReceipt(t, rsPayload("2026-02-01T00:00:00Z"), nil)
	link, ok := rsLink(genesis)
	if !ok {
		t.Fatal("the genesis does not canonicalize")
	}
	payload := rsPayload("2026-03-15T00:00:00Z")
	payload["previousReceiptHash"] = link
	second = rsReceipt(t, payload, nil)
	commitment = rsReceipt(t, map[string]any{
		"type": "x-test:chain-commitment", "issued_at": "2026-02-01T00:00:00Z",
		"issuer_id": rsTestKid, "count": 1, "terminal_hash": link,
	}, nil)
	return genesis, second, commitment
}

func TestReceiptRevocationOutcomes(t *testing.T) {
	_, key := rsTestKey()
	body := rsReceipt(t, rsPayload("2026-03-15T00:00:00Z"), nil)
	for _, tc := range []struct {
		name, revoked, want string
	}{
		{"revoked before issued_at", "2026-03-01T00:00:00Z", "invalid key_revoked"},
		{"revoked at issued_at", "2026-03-15T00:00:00Z", "invalid key_revoked"},
		{"revoked after issued_at", "2026-04-01T00:00:00Z", "valid"},
		{"revoked_at unreadable", "soon", "undecidable window_not_applicable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			revoked := tc.revoked
			key.RevokedAt = &revoked
			keys := map[string]rsJWK{rsTestKid: key}
			if got := rsVerify(body, keys, true).String(); got != tc.want {
				t.Fatalf("gap closed: got %q, want %q", got, tc.want)
			}
			if got := rsVerify(body, keys, false).String(); got != "valid" {
				t.Fatalf("gap open: got %q, want valid", got)
			}
		})
	}
}

func TestReceiptChainAndCommitmentOutcomes(t *testing.T) {
	_, key := rsTestKey()
	keys := map[string]rsJWK{rsTestKid: key}
	genesis, second, commitment := rsChainedFixture(t)
	unlinked := rsReceipt(t, rsPayload("2026-03-15T00:00:00Z"), nil)
	badGenesis := rsReceipt(t, rsPayload("2026-02-01T00:00:00Z"), func(d map[string]any) {
		d["signature"].(map[string]any)["sig"] = hex.EncodeToString(make([]byte, 64))
	})
	stranger := rsReceipt(t, map[string]any{
		"type": "x-test:chain-commitment", "issued_at": "2026-02-01T00:00:00Z",
		"issuer_id": "someone else", "count": 1,
	}, nil)
	noCount := rsReceipt(t, map[string]any{
		"type": "x-test:chain-commitment", "issued_at": "2026-02-01T00:00:00Z", "issuer_id": rsTestKid,
	}, nil)
	wrongHash := rsReceipt(t, map[string]any{
		"type": "x-test:chain-commitment", "issued_at": "2026-02-01T00:00:00Z",
		"issuer_id": rsTestKid, "count": 1, "terminal_hash": "sha256:00",
	}, nil)
	covering := rsReceipt(t, map[string]any{
		"type": "x-test:chain-commitment", "issued_at": "2026-02-01T00:00:00Z",
		"issuer_id": rsTestKid, "count": 2, "terminal_hash": "sha256:00",
	}, nil)
	ctx := func(chain [][]byte, c []byte, at string) *rsReadContext {
		return &rsReadContext{chain: chain, commitment: c, loggedAt: at}
	}
	cases := []struct {
		name   string
		body   []byte
		ctx    *rsReadContext
		closed bool
		want   string
	}{
		{"linked", second, ctx([][]byte{genesis}, nil, ""), false, "valid"},
		{"chain element does not verify", second, ctx([][]byte{badGenesis}, nil, ""), false,
			"undecidable chain_element_not_valid"},
		{"no link", unlinked, ctx([][]byte{genesis}, nil, ""), false, "invalid chain_link_mismatch"},
		{"commitment ignored with the gap open", second, ctx([][]byte{genesis}, commitment, "2026-04-01T00:00:00Z"),
			false, "valid"},
		{"commitment logged after issued_at", second, ctx([][]byte{genesis}, commitment, "2026-04-01T00:00:00Z"),
			true, "invalid issued_at_precedes_excluding_commitment"},
		{"commitment logged before issued_at", second, ctx([][]byte{genesis}, commitment, "2026-03-01T00:00:00Z"),
			true, "valid"},
		{"commitment covers the receipt", second, ctx([][]byte{genesis}, covering, "2026-04-01T00:00:00Z"),
			true, "valid"},
		{"logged time unreadable", second, ctx([][]byte{genesis}, commitment, "later"), true,
			"undecidable commitment_not_applicable"},
		{"commitment by another issuer", second, ctx([][]byte{genesis}, stranger, "2026-04-01T00:00:00Z"),
			true, "undecidable commitment_not_applicable"},
		{"commitment with no count", second, ctx([][]byte{genesis}, noCount, "2026-04-01T00:00:00Z"),
			true, "undecidable commitment_not_applicable"},
		{"terminal hash is not the link", second, ctx([][]byte{genesis}, wrongHash, "2026-04-01T00:00:00Z"),
			true, "undecidable commitment_not_applicable"},
		{"commitment not an envelope", second, ctx([][]byte{genesis}, []byte("{}"), "2026-04-01T00:00:00Z"),
			true, "undecidable commitment_not_applicable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rsVerifyInContext(tc.body, keys, tc.ctx, tc.closed).String(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
