package aee

// Held to the shared vectors every reader of the one signed revocation list
// answers: the same refusal code and index, or the same state, on every case.
// The vectors are a byte-for-byte copy of probityai/probity
// packages/probity-records/vectors/shared/revocation.json at commit 5894259f.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

const (
	revocationVectorsPath   = "testdata/revocation-list.json"
	revocationVectorsSHA256 = "d762714623703accce51db2adedf9d3abeb9f4db568f1749b1754c833f8a4441"
)

type revocationVector struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Roots       []string          `json:"roots"`
	Lists       []json.RawMessage `json:"lists"`
	Expected    struct {
		Refused string `json:"refused"`
		Index   *int   `json:"index"`
		State   *struct {
			ListID   string              `json:"listId"`
			Seq      int64               `json:"seq"`
			Head     string              `json:"head"`
			IssuedAt string              `json:"issuedAt"`
			Roots    []string            `json:"roots"`
			Revoked  map[string][]string `json:"revoked"`
		} `json:"state"`
	} `json:"expected"`
}

func loadRevocationVectors(t *testing.T) []revocationVector {
	t.Helper()
	raw, err := os.ReadFile(revocationVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var vs []revocationVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func TestRevocationVectorsArePinned(t *testing.T) {
	raw, err := os.ReadFile(revocationVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != revocationVectorsSHA256 {
		t.Fatalf("%s has SHA-256 %s; it must be the byte-for-byte copy of probityai/probity "+
			"packages/probity-records/vectors/shared/revocation.json at 5894259f (%s)",
			revocationVectorsPath, got, revocationVectorsSHA256)
	}
	if n := len(loadRevocationVectors(t)); n != 39 {
		t.Fatalf("want 39 vectors, have %d", n)
	}
}

func refusalCode(err error) string {
	code, _, _ := strings.Cut(err.Error(), ":")
	return code
}

func TestRevocationSharedVectors(t *testing.T) {
	for _, v := range loadRevocationVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			state := NewRevocationState(v.Roots)
			for i, list := range v.Lists {
				next, err := state.Apply(list)
				if err != nil {
					if v.Expected.Refused == "" {
						t.Fatalf("%s: list %d refused: %v", v.Description, i, err)
					}
					if got := refusalCode(err); got != v.Expected.Refused {
						t.Fatalf("%s: list %d refused with %q, want %q (%v)", v.Description, i, got, v.Expected.Refused, err)
					}
					if v.Expected.Index == nil || i != *v.Expected.Index {
						t.Fatalf("%s: refused at index %d, want %v", v.Description, i, v.Expected.Index)
					}
					return
				}
				state = next
			}
			if v.Expected.Refused != "" {
				t.Fatalf("%s: every list was accepted, want %q at index %d", v.Description, v.Expected.Refused, *v.Expected.Index)
			}
			want := v.Expected.State
			if state.ListID != want.ListID || state.Seq != want.Seq || state.Head != want.Head ||
				state.IssuedAt != want.IssuedAt {
				t.Fatalf("state %q %d %q %q, want %q %d %q %q", state.ListID, state.Seq, state.Head, state.IssuedAt,
					want.ListID, want.Seq, want.Head, want.IssuedAt)
			}
			if !reflect.DeepEqual(state.Roots, want.Roots) {
				t.Fatalf("roots %v, want %v", state.Roots, want.Roots)
			}
			for _, kind := range RevocationKinds {
				got := state.RevokedIDs(kind)
				if len(got) == 0 && len(want.Revoked[string(kind)]) == 0 {
					continue
				}
				if !reflect.DeepEqual(got, want.Revoked[string(kind)]) {
					t.Fatalf("revoked %s %v, want %v", kind, got, want.Revoked[string(kind)])
				}
			}
		})
	}
}

func TestRevocationRefusalCodesAreTheTenInOrder(t *testing.T) {
	want := []string{
		"revocation_list_shape", "revocation_list_signer_not_a_root", "revocation_list_signature_unverified",
		"revocation_list_other_chain", "revocation_list_rollback", "revocation_list_gap",
		"revocation_list_previous_mismatch", "revocation_list_time_reversed", "revocation_entry_from_future",
		"revocation_list_drops_entry",
	}
	if !reflect.DeepEqual(RevocationRefusalCodes, want) {
		t.Fatalf("codes %v, want %v", RevocationRefusalCodes, want)
	}
	kinds := []RevocationKind{"agent", "build", "grant", "key", "permit", "sponsor", "stream"}
	if !reflect.DeepEqual(RevocationKinds, kinds) {
		t.Fatalf("kinds %v, want %v", RevocationKinds, kinds)
	}
}

// Every case with a state: ListDigest of the accepted body is the head, Revoked and Revokes answer from the
// list in force, an unknown kind is never revoked, and Apply leaves its receiver untouched.
func TestRevocationQueriesAndImmutability(t *testing.T) {
	var found bool
	for _, v := range loadRevocationVectors(t) {
		if v.Expected.State == nil || len(v.Lists) == 0 {
			continue
		}
		before := NewRevocationState(v.Roots)
		state := before
		for _, list := range v.Lists {
			next, err := state.Apply(list)
			if err != nil {
				t.Fatalf("%s: %v", v.ID, err)
			}
			if !reflect.DeepEqual(state, state) || next.Seq != state.Seq+1 {
				t.Fatalf("%s: seq %d after %d", v.ID, next.Seq, state.Seq)
			}
			state = next
		}
		if !reflect.DeepEqual(before, NewRevocationState(v.Roots)) {
			t.Fatalf("%s: Apply changed its receiver", v.ID)
		}
		var signed struct {
			Body json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(v.Lists[len(v.Lists)-1], &signed); err != nil {
			t.Fatal(err)
		}
		digest, err := ListDigest(signed.Body)
		if err != nil || digest != state.Head {
			t.Fatalf("%s: ListDigest %q (%v), head %q", v.ID, digest, err, state.Head)
		}
		for _, kind := range RevocationKinds {
			for _, id := range v.Expected.State.Revoked[string(kind)] {
				found = true
				if !state.Revoked(kind, id) || !state.Revokes(RevocationSubject{KindAgent, "nobody-here"}, RevocationSubject{kind, id}) {
					t.Fatalf("%s: %s %s not revoked", v.ID, kind, id)
				}
				if state.Revoked(kind, id+"x") {
					t.Fatalf("%s: %s %sx revoked", v.ID, kind, id)
				}
			}
		}
		if state.Revoked(RevocationKind("no-such-kind"), "x") || state.Revokes() {
			t.Fatalf("%s: an unknown kind or no pairs must not be revoked", v.ID)
		}
	}
	if !found {
		t.Fatal("no vector held a revoked subject")
	}
}

func TestRevocationApplyRefusesNonLists(t *testing.T) {
	state := NewRevocationState(nil)
	for _, raw := range []string{"", "null", "[]", `{"body":{},"sig":""}`, `{"body":{"seq":1,"seq":2},"sig":""}`,
		`{"body":1,"sig":""}`, `{"body":{"seq":1e400},"sig":""}`} {
		_, err := state.Apply([]byte(raw))
		if err == nil || refusalCode(err) != CodeShape {
			t.Fatalf("%q: want %s, got %v", raw, CodeShape, err)
		}
	}
}

// VerifyRevocationChain answers every shared vector as Apply in a loop does: the same refusal at
// the same index, the state in force when it refused, and the final state when nothing is refused.
func TestVerifyRevocationChainAnswersTheSharedVectors(t *testing.T) {
	for _, v := range loadRevocationVectors(t) {
		lists := make([][]byte, len(v.Lists))
		for i, list := range v.Lists {
			lists[i] = list
		}
		got := VerifyRevocationChain(v.Roots, lists)
		if v.Expected.Refused == "" {
			if got.Verdict != VerdictValid || got.Refusal != nil || got.Index != -1 ||
				got.State.Seq != v.Expected.State.Seq || got.State.Head != v.Expected.State.Head {
				t.Fatalf("%s: %+v, want valid at seq %d", v.ID, got, v.Expected.State.Seq)
			}
			continue
		}
		if got.Verdict != VerdictInvalid || got.Refusal == nil || got.Refusal.Code != v.Expected.Refused ||
			got.Index != *v.Expected.Index {
			t.Fatalf("%s: %+v, want %s at %d", v.ID, got, v.Expected.Refused, *v.Expected.Index)
		}
		held := NewRevocationState(v.Roots)
		for _, list := range lists[:got.Index] {
			held, _ = held.Apply(list)
		}
		if !reflect.DeepEqual(got.State, held) {
			t.Fatalf("%s: state at refusal %+v, want %+v", v.ID, got.State, held)
		}
	}
}
