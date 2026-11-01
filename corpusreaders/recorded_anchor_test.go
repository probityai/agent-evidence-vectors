package corpusreaders

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The recorded acknowledgement member carries real OpenTimestamps proofs. Held
// against the header of the next block, a real proof must draw anchor-mismatch,
// and against its own header nothing, so the Go reader runs the proof's
// operations rather than reading its header alone.
func TestARealProofAgainstAnotherHeldHeaderIsRefused(t *testing.T) {
	root := filepath.Join("..", "vectors-recorded")
	raw, err := os.ReadFile(filepath.Join(root, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []struct {
			recordedEntry
			Name string `json:"name"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, e := range manifest.Vectors {
		if e.Name != "hs51-set2-acks" {
			continue
		}
		var own, next *recordedBinding
		for i := range e.Bindings {
			b := &e.Bindings[i]
			if b.Block != nil && b.Subject == "astrogilda/ack_budget.jcs" {
				switch *b.Block.Height {
				case 972403:
					own = b
				case 972405:
					next = b
				}
			}
		}
		if own == nil || next == nil {
			t.Fatal("the member does not bind the astrogilda budget acknowledgement at both blocks")
		}
		dir := filepath.Join(root, filepath.FromSlash(e.Dir))
		got, err := recordedCheck(dir, e.SumsSHA256, []recordedBinding{*own})
		if err != nil || len(got) != 0 {
			t.Fatalf("intact binding: %v %v", got, err)
		}
		height := *own.Block.Height
		wrong := *own
		wrong.Block = &recordedBlock{Height: &height, Header: next.Block.Header, ID: next.Block.ID}
		got, err = recordedCheck(dir, e.SumsSHA256, []recordedBinding{wrong})
		if err != nil || !reflect.DeepEqual(got, []string{"anchor-mismatch"}) {
			t.Fatalf("another block's header: %v %v", got, err)
		}
		return
	}
	t.Fatal("no hs51-set2-acks member in the manifest")
}
