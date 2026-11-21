package corpusreaders

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// sixteenSpellings returns every padded spelling a lenient decoder reads as the
// canonical 88-character Ed25519 signature: its last character carries four
// bits no byte uses.
func sixteenSpellings(t *testing.T, canonical string) []string {
	t.Helper()
	body := strings.TrimSuffix(canonical, "==")
	last := strings.IndexByte(b64Alphabet, body[len(body)-1]) &^ 15
	out := make([]string, 0, 16)
	for low := 0; low < 16; low++ {
		out = append(out, body[:len(body)-1]+string(b64Alphabet[last+low])+"==")
	}
	return out
}

func TestDecodeCanonicalRefusesEverySpellingButOne(t *testing.T) {
	for _, bad := range []string{"QR==", "QQ==\n", "Q\nQ==", "QQ", "QQ==="} {
		if _, err := decodeCanonical(base64.StdEncoding, bad); err == nil {
			t.Errorf("%q decoded; only QQ== may", bad)
		}
	}
	for _, bad := range []string{"QR", "QQ==", "Q\nQ"} {
		if _, err := decodeCanonical(base64.RawURLEncoding, bad); err == nil {
			t.Errorf("%q decoded as unpadded base64url; only QQ may", bad)
		}
	}
	if b, err := decodeCanonical(base64.StdEncoding, "QQ=="); err != nil || string(b) != "A" {
		t.Fatalf("QQ== must decode to A: %v %q", err, b)
	}
}

func TestSignatureCoverageReadsOneSpellingOfTheSignature(t *testing.T) {
	path := filepath.Join("..", "corpora", "vectors-signature-coverage", "cases",
		"allow-one-entry-for-the-key", "record.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record sigCovRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	canonical := record.Envelope.Signature
	read := 0
	for _, spelling := range sixteenSpellings(t, canonical) {
		lenient, err := base64.StdEncoding.DecodeString(spelling)
		if err != nil || len(lenient) != 64 {
			t.Fatalf("%q: a lenient decoder must read it, which is the defect: %v", spelling, err)
		}
		record.Envelope.Signature = spelling
		if _, _, _, err := sigCovBytes(record); err == nil {
			read++
			if spelling != canonical {
				t.Errorf("%q read as the signature; only %q may be", spelling, canonical)
			}
		}
	}
	if read != 1 {
		t.Fatalf("%d of 16 spellings read, want 1", read)
	}
}
