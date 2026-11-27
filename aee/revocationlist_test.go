package aee

// Held to the shared vectors every reader of the one signed revocation list
// answers: the same refusal code and index, or the same state, on every case.
// Three copies of probityai/probity packages/probity-records/vectors/shared/revocation.json
// are pinned here byte for byte:
//
//   - revocation-list-v2.json at c86b20c4: the current format, lists are deltas,
//     read by NewRevocationState and VerifyRevocationChain;
//   - revocation-list-v1.json at 7955d2b2: the cumulative format with the idp-key
//     kind, read by NewRevocationStateV1 and VerifyRevocationChainV1;
//   - revocation-list.json at 5894259f: the cumulative set the published corpus
//     revocation-list/v1 was generated from (corpora/vectors-revocation-list/gen_vectors.py
//     pins it), read by the V1 entry points too.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/probityai/agent-evidence-vectors/internal/identifiers"
)

type revocationVectorSet struct {
	path, sha256, commit string
	count                int
	v1                   bool
}

var revocationVectorSets = []revocationVectorSet{
	{"testdata/revocation-list-v2.json", "e9d4284dae6414762a3332e3cd10b05f1dcc80ea7074549cd4f6a6be71ef00fc", "c86b20c4", 52, false},
	{"testdata/revocation-list-v1.json", "5489b86d8b3b32b217e520a5d37a0467034b06155991bf24beabf63bc3723581", "7955d2b2", 47, true},
	{"testdata/revocation-list.json", "d762714623703accce51db2adedf9d3abeb9f4db568f1749b1754c833f8a4441", "5894259f", 39, true},
}

func (set revocationVectorSet) state(roots []string) RevocationState {
	if set.v1 {
		return NewRevocationStateV1(roots)
	}
	return NewRevocationState(roots)
}

func (set revocationVectorSet) chain(roots []string, lists [][]byte) RevocationChainVerdict {
	if set.v1 {
		return VerifyRevocationChainV1(roots, lists)
	}
	return VerifyRevocationChain(roots, lists)
}

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

func loadRevocationVectors(t *testing.T, set revocationVectorSet) []revocationVector {
	t.Helper()
	raw, err := os.ReadFile(set.path)
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
	for _, set := range revocationVectorSets {
		raw, err := os.ReadFile(set.path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != set.sha256 {
			t.Fatalf("%s has SHA-256 %s; it must be the byte-for-byte copy of probityai/probity "+
				"packages/probity-records/vectors/shared/revocation.json at %s (%s)", set.path, got, set.commit, set.sha256)
		}
		if n := len(loadRevocationVectors(t, set)); n != set.count {
			t.Fatalf("%s: want %d vectors, have %d", set.path, set.count, n)
		}
	}
}

func refusalCode(err error) string {
	code, _, _ := strings.Cut(err.Error(), ":")
	return code
}

func TestRevocationSharedVectors(t *testing.T) {
	for _, set := range revocationVectorSets {
		for _, v := range loadRevocationVectors(t, set) {
			t.Run(set.path+"/"+v.ID, func(t *testing.T) {
				state := set.state(v.Roots)
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
}

func TestRevocationRefusalCodesAreTheTenInOrder(t *testing.T) {
	common := []string{
		"revocation_list_shape", "revocation_list_signer_not_a_root", "revocation_list_signature_unverified",
		"revocation_list_other_chain", "revocation_list_rollback", "revocation_list_gap",
		"revocation_list_previous_mismatch", "revocation_list_time_reversed", "revocation_entry_from_future",
	}
	if want := append(append([]string{}, common...), "revocation_entry_repeated"); !reflect.DeepEqual(RevocationRefusalCodes, want) {
		t.Fatalf("codes %v, want %v", RevocationRefusalCodes, want)
	}
	if want := append(append([]string{}, common...), "revocation_list_drops_entry"); !reflect.DeepEqual(RevocationRefusalCodesV1, want) {
		t.Fatalf("v1 codes %v, want %v", RevocationRefusalCodesV1, want)
	}
	kinds := []RevocationKind{"agent", "build", "grant", "idp-key", "key", "permit", "sponsor", "stream"}
	if !reflect.DeepEqual(RevocationKinds, kinds) {
		t.Fatalf("kinds %v, want %v", RevocationKinds, kinds)
	}
	if RevocationListType != "https://probityai.github.io/agent-evidence-vectors/predicate/v2/revocation-list" ||
		RevocationListTypeV1 != "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-list" {
		t.Fatalf("types %q %q", RevocationListType, RevocationListTypeV1)
	}
}

// Every case with a state: ListDigest of the accepted body is the head, Revoked and Revokes answer from the
// list in force, an unknown kind is never revoked, and Apply leaves its receiver untouched.
func TestRevocationQueriesAndImmutability(t *testing.T) {
	for _, set := range revocationVectorSets {
		revocationQueries(t, set)
	}
}

func revocationQueries(t *testing.T, set revocationVectorSet) {
	var found bool
	for _, v := range loadRevocationVectors(t, set) {
		if v.Expected.State == nil || len(v.Lists) == 0 {
			continue
		}
		before := set.state(v.Roots)
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
		if !reflect.DeepEqual(before, set.state(v.Roots)) {
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
		t.Fatalf("%s: no vector held a revoked subject", set.path)
	}
}

func TestRevocationApplyRefusesNonLists(t *testing.T) {
	for _, state := range []RevocationState{NewRevocationState(nil), NewRevocationStateV1(nil)} {
		for _, raw := range []string{"", "null", "[]", `{"body":{},"sig":""}`, `{"body":{"seq":1,"seq":2},"sig":""}`,
			`{"body":1,"sig":""}`, `{"body":{"seq":1e400},"sig":""}`} {
			_, err := state.Apply([]byte(raw))
			if err == nil || refusalCode(err) != CodeShape {
				t.Fatalf("%q: want %s, got %v", raw, CodeShape, err)
			}
		}
	}
}

// VerifyRevocationChain answers every shared vector as Apply in a loop does: the same refusal at
// the same index, the state in force when it refused, and the final state when nothing is refused.
func TestVerifyRevocationChainAnswersTheSharedVectors(t *testing.T) {
	for _, set := range revocationVectorSets {
		for _, v := range loadRevocationVectors(t, set) {
			lists := make([][]byte, len(v.Lists))
			for i, list := range v.Lists {
				lists[i] = list
			}
			got := set.chain(v.Roots, lists)
			if v.Expected.Refused == "" {
				if got.Verdict != VerdictValid || got.Refusal != nil || got.Index != -1 ||
					got.State.Seq != v.Expected.State.Seq || got.State.Head != v.Expected.State.Head {
					t.Fatalf("%s %s: %+v, want valid at seq %d", set.path, v.ID, got, v.Expected.State.Seq)
				}
				continue
			}
			if got.Verdict != VerdictInvalid || got.Refusal == nil || got.Refusal.Code != v.Expected.Refused ||
				got.Index != *v.Expected.Index {
				t.Fatalf("%s %s: %+v, want %s at %d", set.path, v.ID, got, v.Expected.Refused, *v.Expected.Index)
			}
			held := set.state(v.Roots)
			for _, list := range lists[:got.Index] {
				held, _ = held.Apply(list)
			}
			if a, b := revocationSummary(got.State), revocationSummary(held); a != b {
				t.Fatalf("%s %s: state at refusal %s, want %s", set.path, v.ID, a, b)
			}
		}
	}
}

// revocationSummary is the state as the shared vectors state it, one string to compare.
func revocationSummary(s RevocationState) string {
	revoked := map[string][]string{}
	for _, kind := range RevocationKinds {
		revoked[string(kind)] = s.RevokedIDs(kind)
	}
	out, _ := json.Marshal(map[string]any{"listId": s.ListID, "seq": s.Seq, "head": s.Head, "issuedAt": s.IssuedAt,
		"roots": s.Roots, "revoked": revoked})
	return string(out)
}

// A reader of either format refuses the other format's type, and RL49 (a v1 list
// handed to the current reader) is the shared vector that holds the current side.
func TestRevocationFormatsRefuseEachOthersType(t *testing.T) {
	v2 := loadRevocationVectors(t, revocationVectorSets[0])
	v1 := loadRevocationVectors(t, revocationVectorSets[1])
	for _, c := range []struct {
		name  string
		chain func([]string, [][]byte) RevocationChainVerdict
		v     revocationVector
	}{
		{"current reader, v1 list", VerifyRevocationChain, v1[0]},
		{"v1 reader, current list", VerifyRevocationChainV1, v2[0]},
	} {
		got := c.chain(c.v.Roots, [][]byte{c.v.Lists[0]})
		if got.Refusal == nil || got.Refusal.Error() != "revocation_list_shape:type" || got.Index != 0 {
			t.Fatalf("%s: %+v, want revocation_list_shape:type at 0", c.name, got)
		}
	}
}

// revocationSigner mints lists under a test key, so the cases the shared vectors do
// not carry (a type under the new host, sibling lists on one state) are signed lists.
type revocationSigner struct {
	key  ed25519.PrivateKey
	root string
}

func newRevocationSigner(label string) revocationSigner {
	seed := sha256.Sum256([]byte("agent-evidence-vectors/aee/revocationlist_test/" + label))
	key := ed25519.NewKeyFromSeed(seed[:])
	id := sha256.Sum256(key.Public().(ed25519.PublicKey))
	return revocationSigner{key: key, root: hex.EncodeToString(id[:])}
}

// thumbprint is the RFC 7638 JWK thumbprint of the signer's public key: the id an
// idp-key entry names.
func (r revocationSigner) thumbprint() string {
	x := base64.RawURLEncoding.EncodeToString(r.key.Public().(ed25519.PublicKey))
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type revocationTestEntry struct{ kind, id, at string }

func (r revocationSigner) list(t *testing.T, listType string, seq int, previous, issuedAt string,
	entries ...revocationTestEntry) []byte {
	t.Helper()
	rows := make([]map[string]any, len(entries))
	for i, e := range entries {
		rows[i] = map[string]any{"kind": e.kind, "id": e.id, "revokedAt": e.at}
	}
	var prev any
	if previous != "" {
		prev = previous
	}
	body := map[string]any{"type": listType, "listId": "test-revocations", "seq": seq, "previous": prev,
		"issuedAt": issuedAt, "issuerKey": base64.StdEncoding.EncodeToString(r.key.Public().(ed25519.PublicKey)),
		"entries": rows}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(r.key, append([]byte(RevocationDomain), canon...))
	signed, err := json.Marshal(map[string]any{"body": json.RawMessage(canon), "sig": base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func headOf(t *testing.T, signed []byte) string {
	t.Helper()
	var s struct {
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(signed, &s); err != nil {
		t.Fatal(err)
	}
	digest, err := ListDigest(s.Body)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// Both hosts name one type (internal/identifiers): a list typed under https://probityai.org/
// is read as its format, and every near spelling stays another type.
func TestRevocationTypeUnderEitherHost(t *testing.T) {
	signer := newRevocationSigner("hosts")
	idp := signer.thumbprint()
	for _, f := range []struct {
		name     string
		typePath string
		state    func([]string) RevocationState
	}{
		{"current", "agent-evidence-vectors/predicate/v2/revocation-list", NewRevocationState},
		{"v1", "agent-evidence-vectors/predicate/v1/revocation-list", NewRevocationStateV1},
	} {
		for _, spelling := range []string{"https://probityai.github.io/", "https://probityai.org/"} {
			list := signer.list(t, spelling+f.typePath, 1, "", "2026-06-01T00:00:00Z",
				revocationTestEntry{"idp-key", idp, "2026-06-01T00:00:00Z"})
			state, err := f.state([]string{signer.root}).Apply(list)
			if err != nil || !state.Revoked(KindIdpKey, idp) {
				t.Fatalf("%s under %s: %v", f.name, spelling, err)
			}
		}
		for _, spelling := range []string{"http://probityai.org/", "https://www.probityai.org/", "https://probityai.org:443/",
			"https://probityai.org./", "https://PROBITYAI.ORG/", "https://probityai.org.example/", "https://probityai.organisation/"} {
			list := signer.list(t, spelling+f.typePath, 1, "", "2026-06-01T00:00:00Z")
			if _, err := f.state([]string{signer.root}).Apply(list); err == nil || err.Error() != "revocation_list_shape:type" {
				t.Fatalf("%s under %s: want revocation_list_shape:type, got %v", f.name, spelling, err)
			}
		}
	}
}

// The core keeps its own copy of the host rule because it imports only the standard
// library; this holds the copy to the module's one rule.
func TestRevocationHostRuleIsTheModuleRule(t *testing.T) {
	path := "agent-evidence-vectors/predicate/v2/revocation-list"
	for _, a := range []string{"https://probityai.github.io/", "https://probityai.org/", "http://probityai.org/",
		"https://www.probityai.org/", "https://probityai.org:443/", "https://probityai.org./", "https://PROBITYAI.org/",
		"https://probityai.org.example/", "https://probityai.organisation/", "https://example.org/", ""} {
		for _, b := range []string{"https://probityai.github.io/", "https://probityai.org/", "http://probityai.github.io/"} {
			if got, want := sameRevocationType(a+path, b+path), identifiers.SameIdentifier(a+path, b+path); got != want {
				t.Fatalf("%q vs %q: core says %v, internal/identifiers says %v", a+path, b+path, got, want)
			}
		}
	}
	if sameRevocationType(json.Number("1"), RevocationListType) || sameRevocationType(nil, RevocationListType) {
		t.Fatal("a value that is not text is never the type")
	}
}

// Lists are deltas: two lists applied to one state give two independent states, an
// older state never sees a later list's entries, and folding costs the delta, not
// the chain. Run under -race with readers on every state.
func TestRevocationDeltaStatesAreIndependent(t *testing.T) {
	signer := newRevocationSigner("branches")
	first := signer.list(t, RevocationListType, 1, "", "2026-06-01T00:00:00Z",
		revocationTestEntry{"agent", "agent:one", "2026-06-01T00:00:00Z"})
	base, err := NewRevocationState([]string{signer.root}).Apply(first)
	if err != nil {
		t.Fatal(err)
	}
	left := signer.list(t, RevocationListType, 2, headOf(t, first), "2026-06-02T00:00:00Z",
		revocationTestEntry{"agent", "agent:left", "2026-06-02T00:00:00Z"})
	right := signer.list(t, RevocationListType, 2, headOf(t, first), "2026-06-02T00:00:00Z",
		revocationTestEntry{"agent", "agent:right", "2026-06-02T00:00:00Z"})
	var wg sync.WaitGroup
	states := make([]RevocationState, 2)
	for i, list := range [][]byte{left, right} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next, err := base.Apply(list)
			if err != nil {
				t.Error(err)
			}
			states[i] = next
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = base.RevokedIDs(KindAgent)
			_ = base.Revoked(KindAgent, "agent:left")
		}()
	}
	wg.Wait()
	if got := fmt.Sprint(base.RevokedIDs(KindAgent)); got != "[agent:one]" {
		t.Fatalf("the base state sees %s", got)
	}
	if got := fmt.Sprint(states[0].RevokedIDs(KindAgent)); got != "[agent:left agent:one]" {
		t.Fatalf("left sees %s", got)
	}
	if got := fmt.Sprint(states[1].RevokedIDs(KindAgent)); got != "[agent:one agent:right]" {
		t.Fatalf("right sees %s", got)
	}
	if states[0].Revoked(KindAgent, "agent:right") || states[1].Revoked(KindAgent, "agent:left") {
		t.Fatal("a sibling list's entry leaked into the other state")
	}
	// The state after left extends; its parent and its sibling are unchanged.
	third := signer.list(t, RevocationListType, 3, headOf(t, left), "2026-06-03T00:00:00Z",
		revocationTestEntry{"stream", "stream-9", "2026-06-03T00:00:00Z"})
	var leftState RevocationState
	for _, s := range states {
		if s.Revoked(KindAgent, "agent:left") {
			leftState = s
		}
	}
	after, err := leftState.Apply(third)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Revoked(KindStream, "stream-9") || leftState.Revoked(KindStream, "stream-9") || base.Revoked(KindStream, "stream-9") {
		t.Fatal("a later list's entry is visible to an earlier state, or missing from its own")
	}
	repeat := signer.list(t, RevocationListType, 4, headOf(t, third), "2026-06-04T00:00:00Z",
		revocationTestEntry{"agent", "agent:one", "2026-06-04T00:00:00Z"})
	if _, err := after.Apply(repeat); err == nil || err.Error() != "revocation_entry_repeated:agent:agent:one" {
		t.Fatalf("want revocation_entry_repeated:agent:agent:one, got %v", err)
	}
}
