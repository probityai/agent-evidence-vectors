package aee_test

// Conformance-vector runner: loads every vector from the sibling vector
// suite and asserts, per vector and per key policy:
//
//	accept  → verdict valid, result matches the suite's declared result,
//	          tier columns match where the suite pins them
//	reject  → verdict invalid, primary code ∈ the suite's expected code set,
//	          NO result and NO tiers (invalid-emits-nothing behavior)
//
//	indeterminate → verdict invalid and NO result/tiers, exactly as a reject;
//	          the primary code is one the suite DECLARED some conformant
//	          reading predicts, and across each family the primary codes are
//	          all predicted by ONE declared reading. The specification settles
//	          the verdict here and not the condition (it carries no
//	          failure-code vocabulary and calls its own stage ordering
//	          informative), so pinning a single condition would fail a
//	          from-spec rail for a non-defect and naming both would stop
//	          measuring the question. What is required instead is that the
//	          rail have A reading and keep to it.
//
// Two suite layouts are supported:
//
//  1. MANIFEST mode — a MANIFEST.json at the suite root with one subdirectory
//     per vector kind (the conformance-repo landing layout). The MANIFEST is
//     the machine-readable SSOT here, and the runner fails if any committed
//     vector file lacks a MANIFEST row or vice versa.
//  2. STAGED mode — the draft-local layout produced by the vector
//     generators: valid/ + invalid/ subdirectories whose INDEX.md files
//     carry the per-vector expectations (result for accepts, failure-code
//     set for rejects). The INDEX tables are the machine-readable SSOT in
//     this mode; the runner fails if any committed vector file lacks an
//     INDEX row or vice versa.
//
// The suite directory defaults to ../../vectors relative to this package
// (override with AEE_VECTORS_DIR). The test SKIPS with an explicit message
// only when NEITHER layout is present, so the core stays green before the
// vector generator has produced its output.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
)

type manifestVector struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Expected struct {
		Verdict           string            `json:"verdict"`
		Codes             []string          `json:"codes"`
		Result            string            `json:"result"`
		TierWithPinnedKey []string          `json:"tierWithPinnedKey"`
		TierWithoutKey    []string          `json:"tierWithoutKey"`
		Family            string            `json:"family"`
		Readings          map[string]string `json:"readings"`
	} `json:"expected"`
}

type suiteManifest struct {
	PredicateType string           `json:"predicateType"`
	Counts        map[string]int   `json:"counts"`
	Vectors       []manifestVector `json:"vectors"`
	Index         []manifestVector `json:"index"` // tolerated alternate key
}

func suiteDir() string {
	if dir := os.Getenv("AEE_VECTORS_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "vectors")
}

func TestConformanceVectors(t *testing.T) {
	dir := suiteDir()
	if _, err := os.Stat(filepath.Join(dir, "MANIFEST.json")); err == nil {
		runManifestMode(t, dir)
		return
	}
	validDir := filepath.Join(dir, "valid")
	invalidDir := filepath.Join(dir, "invalid")
	if statDir(validDir) && statDir(invalidDir) {
		runStagedMode(t, validDir, invalidDir)
		return
	}
	if os.Getenv("AEE_SKIP_VECTORS") == "1" {
		t.Skipf("vector suite not present at %s and AEE_SKIP_VECTORS=1 set; skipping conformance replay", dir)
	}
	t.Fatalf("vector suite not present at %s (set AEE_VECTORS_DIR to relocate it, or AEE_SKIP_VECTORS=1 to skip): the conformance gate must not silently no-op", dir)
}

func statDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// ---------------------------------------------------------------------------
// MANIFEST mode (landing layout)
// ---------------------------------------------------------------------------

func runManifestMode(t *testing.T, dir string) {
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest suiteManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("MANIFEST.json does not parse: %v", err)
	}
	vectors := manifest.Vectors
	if len(vectors) == 0 {
		vectors = manifest.Index
	}
	if len(vectors) == 0 {
		t.Fatal("MANIFEST.json carries no vectors under 'vectors' or 'index'")
	}
	checkManifestClosure(t, dir, &manifest, vectors)

	// Primary code this rail reports per indeterminate vector, collected as the
	// vectors run and asserted family-wide afterwards. The per-vector check can
	// only ask whether the answer is one somebody declared; whether the answers
	// hang together is a property of several of them at once.
	answers := map[string]string{}

	for _, v := range vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			// The kind names the directory directly. It used to select one
			// through a switch whose default was "accept", so a kind nobody
			// had taught this runner about would have been read out of
			// accept/ and replayed as an accept. checkManifestClosure refuses
			// an unreplayed kind by name before the loop is reached.
			// The MANIFEST names the file. It used to be derived from the
			// kind and the id, which works only while a vector's directory
			// spells its verdict -- and a corpus laid out that way tells a
			// rail the answer before the rail opens anything, so it cannot
			// measure whether an implementation read the statement at all.
			if v.File == "" {
				t.Fatalf("MANIFEST row %s declares no file", v.ID)
			}
			body, err := os.ReadFile(filepath.Join(dir, v.File))
			if err != nil {
				t.Fatalf("vector body missing: %v", err)
			}
			if v.Kind == "indeterminate" {
				answers[v.ID] = checkIndeterminate(t, body, v)
				return
			}
			checkVector(t, body, v.Kind == "accept", v.Expected.Result,
				v.Expected.Codes, v.Expected.TierWithPinnedKey, v.Expected.TierWithoutKey)
		})
	}

	t.Run("indeterminate-family-coherence", func(t *testing.T) {
		checkFamilyCoherence(t, vectors, answers)
	})
}

// replayedKinds are the vector kinds the assertions in this file actually
// cover. Nothing is selected by it: it is the coverage claim this runner makes
// about itself, checked against the corpus by checkManifestClosure. A kind the
// corpus grows and this file does not replay fails there by name, rather than
// being routed to some default directory and scored under somebody else's
// contract.
var replayedKinds = map[string]bool{
	"accept":        true,
	"reject":        true,
	"indeterminate": true,
}

// suiteNonVectorDirs are the directories under the suite root that carry no
// conformance vectors in any encoding, and so are the only ones exempt from
// having to be a MANIFEST kind. Sorted, because it is printed in a failure.
//
//   - keys/ holds the published test-key derivation recipe and no vectors;
//     the keys themselves are derived from that recipe rather than committed.
//   - __pycache__/ is a gitignored artifact of running the Python generators
//     in the tree. It is absent in CI, which is why nothing here requires an
//     entry to correspond to a directory that exists.
var suiteNonVectorDirs = []string{"__pycache__", "keys"}

// flatLayout returns the single directory every MANIFEST row declares its file
// under, and fails the test when there is not exactly one.
//
// A REQUIREMENT rather than a detection, with no per-verdict fallback behind
// it. A vector sitting in reject/ told this runner the expected verdict before
// it opened the file -- measured over the whole path it predicted the verdict
// perfectly -- so reading that layout is reading the defect, not supporting an
// older corpus. A copy old enough to have one is already incompatible on
// corpusDigest, which moved for every vector.
func flatLayout(t *testing.T, vectors []manifestVector) string {
	t.Helper()
	dirs := map[string]bool{}
	for _, v := range vectors {
		i := strings.Index(v.File, "/")
		if v.File == "" || i < 0 {
			t.Fatalf("MANIFEST row %s declares no file under a directory, so this "+
				"runner would have to derive a path from its kind -- the derivation "+
				"the flat layout exists to remove", v.ID)
		}
		dirs[v.File[:i]] = true
	}
	if len(dirs) != 1 {
		t.Fatalf("the MANIFEST spreads its vectors over %d directories; this runner "+
			"reads one flat directory of content-addressed statements", len(dirs))
	}
	for d := range dirs {
		if replayedKinds[d] {
			t.Fatalf("the MANIFEST declares its vectors under %q, which is a verdict "+
				"name; that layout is retired and is not read", d)
		}
		return d
	}
	return ""
}

// checkManifestClosure asserts that the MANIFEST and the vector files on disk
// name each other exactly, in both directions and per kind.
//
// The replay below is driven by the MANIFEST, so it can only ever exercise the
// vectors the MANIFEST names: a .json committed into a vector directory with no
// MANIFEST row would sit there replayed by nothing and compared to nothing while
// every assertion in this file still passed. Comparing the two listings is what
// makes "every vector was replayed" a measured claim rather than an assumption
// about whoever last regenerated the suite. The sibling STAGED runner has
// enforced exactly this against its own layout since it was written, and both
// downstream rails that vendor this corpus were hardened for it after an
// indeterminate/ directory arrived, was vendored, and was exercised by nothing.
//
// The counts come from the tree. MANIFEST.json also publishes a counts block,
// which is a third copy of the same number, so it is checked against the other
// two rather than trusted or ignored.
func checkManifestClosure(t *testing.T, dir string, m *suiteManifest, vectors []manifestVector) {
	flat := flatLayout(t, vectors)
	t.Helper()

	if m.PredicateType != "" && m.PredicateType != aee.PredicateType {
		t.Errorf("MANIFEST predicateType %q is not the type this rail verifies (%q)",
			m.PredicateType, aee.PredicateType)
	}

	listed := map[string][]string{}
	declaredKinds := map[string]bool{}
	for _, v := range vectors {
		declaredKinds[v.Kind] = true
	}
	for _, v := range vectors {
		if !replayedKinds[v.Kind] {
			t.Errorf("MANIFEST lists %s under kind %q, which no assertion in this file replays. "+
				"Add the replay and name the kind in replayedKinds -- naming it alone is the same "+
				"absence with a green tick on it", v.ID, v.Kind)
			continue
		}
		if v.File == "" {
			t.Errorf("MANIFEST row %s declares no file, so this runner would have to "+
				"guess one from its kind -- which is the derivation the flat layout "+
				"exists to remove", v.ID)
		} else if _, err := os.Stat(filepath.Join(dir, v.File)); err != nil {
			t.Errorf("MANIFEST row %s declares file %q, which is not readable: %v",
				v.ID, v.File, err)
		}
		listed[v.Kind] = append(listed[v.Kind], v.ID)
	}
	for kind := range replayedKinds {
		if len(listed[kind]) == 0 {
			t.Errorf("replayedKinds names kind %q that the MANIFEST no longer carries, so the "+
				"replay for it runs over nothing and asserts nothing", kind)
		}
	}

	// A directory the MANIFEST does not name as a kind is the exact shape the
	// downstream rails were hardened against: the files are on disk, the
	// listing walks past them because the directory's name is in no literal,
	// and nothing reports it.
	//
	// The rule is set equality against suiteNonVectorDirs, not "holds files
	// this runner recognises as vectors". The earlier formulation asked whether
	// the directory held any .json, which decided the question by file
	// extension: a directory carrying the same corpus in another encoding --
	// .cbor, .yaml, a tarball -- holds zero .json, so it passed the kind check
	// silently AND contributed nothing to any per-kind count, which is the pair
	// of blind spots that lets an unreplayed set look like an absent one. Naming
	// the exceptions costs one line per exception and stops inferring
	// vector-ness from a suffix.
	//
	// An allowlisted directory keeps the old contents check on top, so keys/
	// cannot quietly become a vector directory in the corpus's own encoding
	// either. A stale entry here exempts nothing (there is no directory to
	// exempt), so presence is not required -- which matters because
	// __pycache__ is a gitignored local artifact and is simply absent in CI.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if declaredKinds[e.Name()] {
			continue
		}
		if e.Name() == flat {
			continue // the one directory every vector is declared to live in
		}
		if !containsString(suiteNonVectorDirs, e.Name()) {
			t.Errorf("%s/ is named by no MANIFEST kind and is not one of the suite's declared "+
				"non-vector directories %v, so whatever it carries is replayed by nothing. "+
				"Add the kind to the MANIFEST or name the directory in suiteNonVectorDirs",
				e.Name(), suiteNonVectorDirs)
			continue
		}
		if n := len(jsonVectors(t, filepath.Join(dir, e.Name()))); n > 0 {
			t.Errorf("%s/ is declared to hold no vectors and holds %d vector file(s)", e.Name(), n)
		}
	}

	held := jsonVectors(t, filepath.Join(dir, flat))
	total := 0
	for kind, ids := range listed {
		total += len(ids)
		if got, ok := m.Counts[kind]; !ok {
			t.Errorf("MANIFEST counts declares no entry for kind %q, which %d rows carry",
				kind, len(ids))
		} else if got != len(ids) {
			// One directory holds every kind, so a per-kind count cannot be
			// read off it. The rows carry the kind; the total below is what
			// keeps the directory in the chain.
			t.Errorf("MANIFEST counts[%q] is %d; the MANIFEST carries %d row(s) of that kind",
				kind, got, len(ids))
		}
	}
	if len(held) != total {
		t.Errorf("%s/ holds %d vector file(s) and the MANIFEST carries %d row(s)",
			flat, len(held), total)
	}
	for kind := range m.Counts {
		if _, ok := listed[kind]; !ok {
			t.Errorf("MANIFEST counts declares kind %q that no MANIFEST row carries", kind)
		}
	}

	for kind := range m.Counts {
		if _, ok := listed[kind]; !ok {
			t.Errorf("MANIFEST counts declares kind %q that no MANIFEST row carries", kind)
		}
	}
}

// checkIndeterminate asserts the determined half of an indeterminate vector's
// contract and returns the condition this rail committed to.
//
// The verdict is checked exactly as a reject vector's, because indeterminacy is
// scoped to the condition: a vector whose verdict were open would certify
// nothing. CLOSURE is then the per-vector half -- the primary code must be one
// some declared reading predicts. An answer outside that set is a failure and
// never a reason to widen it, because a set widened until every answer fits is
// how a vector stops measuring the thing it was written for.
func checkIndeterminate(t *testing.T, body []byte, v manifestVector) string {
	t.Helper()
	if len(v.Expected.Readings) < 2 {
		t.Fatalf("%s declares %d reading(s); a family with fewer than two is a reject vector",
			v.ID, len(v.Expected.Readings))
	}
	var committed string
	for _, pc := range []struct {
		name   string
		policy *aee.ConsumerPolicy
	}{{"pinned", pinnedPolicy()}, {"none", &aee.ConsumerPolicy{}}} {
		r := aee.Verify(body, pc.policy)
		if r.Verdict != aee.VerdictInvalid {
			t.Fatalf("[%s] %s: expected invalid, got valid (result %q)", pc.name, v.ID, r.Result)
		}
		if r.Result != "" || r.Tiers != nil {
			t.Fatalf("[%s] %s: invalid verdict leaked result/tiers", pc.name, v.ID)
		}
		predicted := false
		for _, want := range v.Expected.Readings {
			if want == string(r.PrimaryCode) {
				predicted = true
			}
		}
		if !predicted {
			t.Fatalf("[%s] %s: primary code %s is predicted by no declared reading %v (all: %v). "+
				"An undeclared reading is added to the family by name, never by widening the set",
				pc.name, v.ID, r.PrimaryCode, v.Expected.Readings, r.Codes)
		}
		if committed != "" && committed != string(r.PrimaryCode) {
			t.Fatalf("%s: the reported condition moved with the key policy (%s vs %s); "+
				"which condition is reported is byte-pure and cannot depend on consumer trust",
				v.ID, committed, r.PrimaryCode)
		}
		committed = string(r.PrimaryCode)
	}
	return committed
}

// checkFamilyCoherence asserts that one declared reading explains every member
// of each family. Either answer is admissible; answering two members under
// different readings is not, because the reported condition is then a function
// of incidental structure -- here, the wire order of two faulted records --
// rather than of a policy the rail applies. A single-fault corpus can never see
// that, which is why the families carry more than one member.
func checkFamilyCoherence(t *testing.T, vectors []manifestVector, answers map[string]string) {
	t.Helper()
	families := map[string][]manifestVector{}
	for _, v := range vectors {
		if v.Kind == "indeterminate" && v.Expected.Family != "" {
			families[v.Expected.Family] = append(families[v.Expected.Family], v)
		}
	}
	for family, members := range families {
		var matched []string
		for reading := range members[0].Expected.Readings {
			all := true
			for _, m := range members {
				if m.Expected.Readings[reading] != answers[m.ID] {
					all = false
				}
			}
			if all {
				matched = append(matched, reading)
			}
		}
		if len(matched) == 0 {
			var got []string
			for _, m := range members {
				got = append(got, m.ID+" -> "+answers[m.ID])
			}
			sort.Strings(got)
			t.Fatalf("family %s: no declared reading explains this rail's answers (%v); "+
				"declared readings %v", family, got, members[0].Expected.Readings)
		}
		sort.Strings(matched)
		t.Logf("family %s: this rail reads %s", family, strings.Join(matched, ", "))
	}
}

// ---------------------------------------------------------------------------
// STAGED mode (draft-local valid/ + invalid/ layout)
// ---------------------------------------------------------------------------

// validIndexRow matches "| ok-NNN-slug | result | ... |" table rows in
// valid/INDEX.md; cell 2 is the declared result.
var validIndexRow = regexp.MustCompile(`^\|\s*(ok-[0-9a-z-]+)\s*\|\s*([a-zA-Z]+)\s*\|`)

// invalidIndexRow matches "| `bad-NNN-slug` | parent | fault | rederive |
// conditions | codes | spec |" rows in invalid/INDEX.md.
var invalidIndexRow = regexp.MustCompile("^\\|\\s*`(bad-[0-9a-z-]+)`\\s*\\|")

var backtickToken = regexp.MustCompile("`([a-z0-9-]+)`")

func parseValidIndex(t *testing.T, path string) map[string]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("valid INDEX.md unreadable: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if m := validIndexRow.FindStringSubmatch(line); m != nil {
			out[m[1]] = m[2]
		}
	}
	return out
}

func parseInvalidIndex(t *testing.T, path string) map[string][]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("invalid INDEX.md unreadable: %v", err)
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		m := invalidIndexRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 8 {
			t.Fatalf("invalid INDEX row for %s has %d cells, want >= 8", m[1], len(cells))
		}
		// cells: 0 "", 1 id, 2 parent, 3 fault, 4 rederive, 5 conditions,
		// 6 codes, 7 spec anchors.
		var codes []string
		for _, tok := range backtickToken.FindAllStringSubmatch(cells[6], -1) {
			codes = append(codes, tok[1])
		}
		if len(codes) == 0 {
			t.Fatalf("invalid INDEX row for %s declares no backtick-quoted codes: %q", m[1], cells[6])
		}
		out[m[1]] = codes
	}
	return out
}

func jsonVectors(t *testing.T, dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(out)
	return out
}

// Pinned tier columns for the flagship mixed-tier vector (declared in the
// suite's valid/INDEX.md row for ok-024 and in the BUILD-SPEC re-pin).
var pinnedTiers = map[string][2][]string{
	"vcf5a4601dee5c2ee": {
		{"attested", "unattested", "declared"},   // with pinned key
		{"unattested", "unattested", "declared"}, // without key
	},
}

func runStagedMode(t *testing.T, validDir, invalidDir string) {
	acceptExpect := parseValidIndex(t, filepath.Join(validDir, "INDEX.md"))
	rejectExpect := parseInvalidIndex(t, filepath.Join(invalidDir, "INDEX.md"))

	accepts := jsonVectors(t, validDir)
	rejects := jsonVectors(t, invalidDir)
	if len(accepts) == 0 || len(rejects) == 0 {
		t.Fatalf("staged suite empty: %d accepts, %d rejects", len(accepts), len(rejects))
	}
	t.Logf("staged suite: %d accept vectors, %d reject vectors", len(accepts), len(rejects))

	// Bidirectional closure between committed files and INDEX rows.
	for id := range acceptExpect {
		if !containsString(accepts, id) {
			t.Errorf("valid INDEX row %s has no committed vector file", id)
		}
	}
	for id := range rejectExpect {
		if !containsString(rejects, id) {
			t.Errorf("invalid INDEX row %s has no committed vector file", id)
		}
	}

	for _, id := range accepts {
		id := id
		t.Run(id, func(t *testing.T) {
			wantResult, ok := acceptExpect[id]
			if !ok {
				t.Fatalf("committed accept vector %s has no valid/INDEX.md row", id)
			}
			body, err := os.ReadFile(filepath.Join(validDir, id+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var pinnedCols, noKeyCols []string
			if cols, ok := pinnedTiers[id]; ok {
				pinnedCols, noKeyCols = cols[0], cols[1]
			}
			checkVector(t, body, true, wantResult, nil, pinnedCols, noKeyCols)
		})
	}
	for _, id := range rejects {
		id := id
		t.Run(id, func(t *testing.T) {
			wantCodes, ok := rejectExpect[id]
			if !ok {
				t.Fatalf("committed reject vector %s has no invalid/INDEX.md row", id)
			}
			body, err := os.ReadFile(filepath.Join(invalidDir, id+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if reason, quarantined := knownDefectiveVectors[id]; quarantined {
				checkQuarantinedReject(t, body, wantCodes, reason)
				return
			}
			checkVector(t, body, false, "", wantCodes, nil, nil)
		})
	}
}

// knownDefectiveVectors are committed vectors this rail found to be
// DOUBLE-FAULTED: the statement carries a second, undeclared fault beyond
// the INDEX's named one, so the deterministic primary code legitimately
// differs from the expected set. The checker is NOT weakened to admit
// them; the quarantine asserts the vector is still rejected AND that every
// expected code is among the reported ones, and flags the vector for
// regeneration. This is the single-fault-discipline self-check doing its
// job across rails.
//
// Currently EMPTY. The one catch so far — bad-807, which inherited a
// duplicate attackId across manifest classes because the generator's
// _b804 mutated a shared module-level manifest in place — was root-cause
// fixed at the generator (environment() now deep-copies the manifest) and
// the vector regenerated; it passes the strict path with its declared sole
// code. The mechanism stays for the next cross-rail catch.
var knownDefectiveVectors = map[string]string{}

func checkQuarantinedReject(t *testing.T, body []byte, wantCodes []string, reason string) {
	t.Helper()
	t.Logf("QUARANTINED double-faulted vector: %s — verifying rejection + expected-code presence only", reason)
	for _, policy := range []*aee.ConsumerPolicy{pinnedPolicy(), {}} {
		r := aee.Verify(body, policy)
		if r.Verdict != aee.VerdictInvalid {
			t.Fatalf("quarantined vector verified valid")
		}
		for _, want := range wantCodes {
			found := false
			for _, c := range r.Codes {
				if string(c) == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected code %s absent from %v", want, r.Codes)
			}
		}
		if r.Result != "" || r.Tiers != nil {
			t.Fatalf("invalid verdict leaked result/tiers")
		}
	}
}

// ---------------------------------------------------------------------------
// Shared per-vector assertions
// ---------------------------------------------------------------------------

// rowBases decodes the basis member of each attackResults row, preserving the
// absent case. It reads the vector's own bytes rather than anything the
// verifier derived, so the invariant it feeds is stated against the statement
// and not against the answer under test.
func rowBases(t *testing.T, body []byte) []*string {
	t.Helper()
	var shape struct {
		Predicate struct {
			Rows []struct {
				Basis *string `json:"basis"`
			} `json:"attackResults"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(body, &shape); err != nil {
		t.Fatalf("accept vector does not decode for the tier invariant: %v", err)
	}
	out := make([]*string, len(shape.Predicate.Rows))
	for i := range shape.Predicate.Rows {
		out[i] = shape.Predicate.Rows[i].Basis
	}
	return out
}

// checkTierPartition asserts the property that holds over the WHOLE accept
// corpus under EVERY key policy: the tier column partitions on the row's basis
// and on nothing else. A basis: substrate row is attested or unattested
// depending on the consumer's keys (spec:766-775); every other row -- artifact,
// or fail-closed on an absent or unknown basis -- is declared, because its
// vantage can strengthen nothing and no key policy can promote it
// (spec:1122-1123).
//
// This is stated as an invariant rather than as more pinned columns on purpose.
// The suite pins the tier column for a single one of its accept vectors, and
// the generic no-TOFU rule below can only see a promotion that survives an
// EMPTY policy. A promotion visible only under the pinned policy, on a row
// shape that one pinned vector does not carry, is invisible to both. Pinning a
// column on every remaining accept vector would close that by hand and go stale
// the first time the corpus is regenerated; the partition is derived from each
// vector's own bytes, so it covers every accept vector the suite will ever
// carry, including the ones nobody thought to pin.
func checkTierPartition(t *testing.T, policyName string, bases []*string, tiers []aee.Tier) {
	t.Helper()
	if len(bases) != len(tiers) {
		t.Fatalf("[%s] the statement carries %d attackResults row(s) and the tier column has %d entries",
			policyName, len(bases), len(tiers))
	}
	for i, tier := range tiers {
		substrate := bases[i] != nil && *bases[i] == aee.BasisSubstrate
		basis := "<absent>"
		if bases[i] != nil {
			basis = *bases[i]
		}
		if substrate && tier == aee.TierDeclared {
			t.Fatalf("[%s] tier[%d]=declared for a basis: substrate row; a substrate row is attested "+
				"or unattested under the consumer's keys and is never demoted out of the trust-relative "+
				"pair", policyName, i)
		}
		if !substrate && tier != aee.TierDeclared {
			t.Fatalf("[%s] tier[%d]=%s for a row whose basis is %s; only a basis: substrate row can be "+
				"promoted past declared, and no key policy may promote one that is not",
				policyName, i, tier, basis)
		}
	}
}

func checkVector(t *testing.T, body []byte, accept bool, wantResult string,
	wantCodes, tierWithPinned, tierWithout []string) {
	t.Helper()
	pinned := pinnedPolicy()
	empty := &aee.ConsumerPolicy{}
	var bases []*string
	if accept {
		bases = rowBases(t, body)
	}

	for _, pc := range []struct {
		name   string
		policy *aee.ConsumerPolicy
	}{{"pinned", pinned}, {"none", empty}} {
		r := aee.Verify(body, pc.policy)
		if accept {
			if r.Verdict != aee.VerdictValid {
				t.Fatalf("[%s] expected valid, got invalid %v", pc.name, r.Codes)
			}
			if wantResult != "" && r.Result != wantResult {
				t.Fatalf("[%s] result %q want %q", pc.name, r.Result, wantResult)
			}
			wantTiers := tierWithPinned
			if pc.name == "none" {
				wantTiers = tierWithout
			}
			if len(wantTiers) > 0 {
				if len(r.Tiers) != len(wantTiers) {
					t.Fatalf("[%s] tier count %d want %d (%v)", pc.name, len(r.Tiers), len(wantTiers), r.Tiers)
				}
				for i := range wantTiers {
					if string(r.Tiers[i]) != wantTiers[i] {
						t.Fatalf("[%s] tier[%d]=%s want %s", pc.name, i, r.Tiers[i], wantTiers[i])
					}
				}
			}
			// Tier soundness, policy-independent: the column partitions on
			// basis. This holds for every accept vector under both policies,
			// where the pinned columns above hold for one.
			checkTierPartition(t, pc.name, bases, r.Tiers)
			// Tier soundness: with no pinned keys, no row may reach attested
			// (the no-TOFU rule), regardless of what the suite pins.
			if pc.name == "none" {
				for i, tier := range r.Tiers {
					if tier == aee.TierAttested {
						t.Fatalf("[none] tier[%d] is attested with an empty key policy (TOFU)", i)
					}
				}
			}
		} else {
			if r.Verdict != aee.VerdictInvalid {
				t.Fatalf("[%s] expected invalid(%v), got valid (result %q)", pc.name, wantCodes, r.Result)
			}
			if len(wantCodes) > 0 && !containsString(wantCodes, string(r.PrimaryCode)) {
				t.Fatalf("[%s] primary code %s not in expected set %v (all: %v)",
					pc.name, r.PrimaryCode, wantCodes, r.Codes)
			}
			if r.Result != "" || r.Tiers != nil {
				t.Fatalf("[%s] invalid verdict leaked result/tiers", pc.name)
			}
		}
	}
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// pairedRecordFaultVector is the corpus statement carrying a duplicate record
// AND a record whose payload does not decode. It is named here because the
// assertion below is about that statement specifically and nothing else in the
// corpus can stand in for it.
const pairedRecordFaultVector = "v7622b2c58c2e272d"

// TestSetEmissionOnPairedRecordFaults holds THIS rail to reporting both
// conditions the paired-fault vector carries, over the vector's own committed
// bytes.
//
// It is a claim about this rail and deliberately not a conformance requirement.
// The suite's reject contract is a code SET a rail's answer has to intersect,
// so that a strict rail naming one condition and a superset-emitting rail
// naming every condition it found both pass the same MANIFEST; that contract is
// right and this test does not touch it. What it does instead is machine-check
// the sentence the harness has always published about the reference rails --
// that they emit the SET of every failure they detect -- against a statement
// where emitting the set is the whole question.
//
// Without it the vector is inert. Replaying it through checkVector above cannot
// see the defect it was written for: a decode failure and a duplicate live in
// the same expected set and the decode failure is appended first, so the primary
// code is record-undecodable whether or not the duplicate is ever looked for,
// and the vector passes either way. Measured, not assumed -- with the pre-fix
// shared guard restored, the corpus replay stays green here and the whole
// harness reports every vector passing through the mutant CLI, while this
// assertion goes red and names the vector.
// vectorPath returns the file the MANIFEST declares for a vector id.
func vectorPath(t *testing.T, id string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(suiteDir(), "MANIFEST.json"))
	if err != nil {
		return filepath.Join(suiteDir(), id+".json")
	}
	var m suiteManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("MANIFEST.json does not parse: %v", err)
	}
	rows := m.Vectors
	if len(rows) == 0 {
		rows = m.Index
	}
	for _, v := range rows {
		if v.ID == id && v.File != "" {
			return filepath.Join(suiteDir(), v.File)
		}
	}
	t.Fatalf("the MANIFEST declares no file for %s, which this assertion is about", id)
	return ""
}

func TestSetEmissionOnPairedRecordFaults(t *testing.T) {
	// Resolved through the MANIFEST rather than built from a kind directory.
	// A path spelled "reject/<id>.json" only exists while the layout spells the
	// verdict, and this assertion is about one specific statement, so it must
	// find that statement rather than a place one used to sit.
	path := vectorPath(t, pairedRecordFaultVector)
	body, err := os.ReadFile(path) // #nosec G304 -- a corpus path under the suite directory
	if err != nil {
		if os.Getenv("AEE_SKIP_VECTORS") == "1" {
			t.Skipf("vector suite not present at %s and AEE_SKIP_VECTORS=1 set; skipping", path)
		}
		t.Fatalf("%s is the statement this assertion is about and it is unreadable: %v", path, err)
	}
	for _, pc := range []struct {
		name   string
		policy *aee.ConsumerPolicy
	}{{"pinned", pinnedPolicy()}, {"none", &aee.ConsumerPolicy{}}} {
		r := aee.Verify(body, pc.policy)
		for _, want := range []aee.Code{aee.CodeRecordUndecodable, aee.CodeDuplicateRecord} {
			if !containsString(codeStrings(r.Codes), string(want)) {
				t.Fatalf("[%s] %s: this rail reported %v and did not report %s. The statement "+
					"carries a duplicate among the records that DID decode and one record that "+
					"did not; a scan that waits for every record to decode answers the decode "+
					"failure and drops the duplicate finding, which is what this vector exists "+
					"to ask", pc.name, pairedRecordFaultVector, r.Codes, want)
			}
		}
	}
}

func codeStrings(codes []aee.Code) []string {
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		out = append(out, string(c))
	}
	return out
}

// Guard: the pinned-policy key used against the suite must be the DERIVED
// test key, so the runner never depends on any committed private material.
//
// The recipe is spelled out below rather than called, and that is the whole
// point of the test. Deriving the expected key through aeetest.TestKey would
// make this a comparison of a function with itself, which passes under every
// possible recipe; the earlier version compared the key's LENGTH against
// ed25519.PublicKeySize, which is 32 bytes for every seed there has ever been. The
// literal here is the published recipe, so an edit to aeetest/build.go
// diverges from it rather than being followed by it.
//
// The recipe is cross-rail load-bearing: the TypeScript rail re-derives the
// same key from the same published string, so a change made on one side and
// not the other stops the two rails from agreeing about which vectors are
// attested, while both stay green against their own key.
func TestPinnedPolicyIsDerived(t *testing.T) {
	const recipe = "in-toto-aee-test-key/substrate-observation-test/v1"
	seed := sha256.Sum256([]byte(recipe))
	want := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)

	policy := pinnedPolicy()
	if len(policy.SubstrateObservationKeys) != 1 {
		t.Fatalf("pinned policy names %d substrate-observation key(s), want exactly 1",
			len(policy.SubstrateObservationKeys))
	}
	if got := policy.SubstrateObservationKeys[0]; !got.Equal(want) {
		t.Fatalf("the pinned policy's substrate-observation key is %x, but the published recipe "+
			"sha256(%q) derives %x. The suite is signed under the published recipe and the sibling "+
			"rails re-derive it, so the key the runner pins is the recipe or the rails have diverged",
			[]byte(got), recipe, []byte(want))
	}
}
