package corpora

// The Go refund-connected reader is held to the Python reader on mutated runs.
// testdata/refundconnected-differential.json holds, for each mutation of a retained
// run, the edits that make it and the verdicts the Python reader derives from it
// (written by vectors-refund-connected/tests/test_differential.py, which also checks
// it). A mutation the Python reader stops on with an exception it does not catch is
// recorded as a fault, and the Go reader must stop on it too. Some mutations are judged
// with a signature check that accepts any signature of the right size, so that edits to
// signed payloads reach the rules behind the signatures. The second half of the
// test skips one rule at a time and requires some mutation to notice: a rule whose
// removal changes no verdict on any run that fires it is not tested.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type rcDiffWant struct {
	OK bool             `json:"ok"`
	C  map[string][]int `json:"c"`
	K  []int            `json:"k"`
}

type rcDiffMutation struct {
	ID       string      `json:"id"`
	Run      string      `json:"run"`
	Trusting bool        `json:"trusting"`
	Ops      [][]any     `json:"ops"`
	Want     *rcDiffWant `json:"want"`
}

type rcDiffFixture struct {
	Steps     []string         `json:"steps"`
	Checks    []string         `json:"checks"`
	Verdicts  []string         `json:"verdicts"`
	Mutations []rcDiffMutation `json:"mutations"`
}

// rcDiffRuns are the retained runs the mutations start from.
var rcDiffRuns = map[string]string{
	"r1": "../vectors-refund-connected/source/j01-connected-20261028-r1",
	"r2": "../vectors-refund-connected/source/j01-connected-20261028-r2",
}

// rcDiffSkipExempt lists rules that no mutation of the retained runs can show missing,
// each with the reason, so the exemption is read and not assumed.
var rcDiffSkipExempt = map[string]string{}

func loadRCDiff(t *testing.T) *rcDiffFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/refundconnected-differential.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx rcDiffFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	return &fx
}

// rcDiffHarness keeps one scratch copy of each run and puts a mutation's edits on it,
// then takes them off again, so a mutation costs the files it touches.
type rcDiffHarness struct {
	dirs map[string]string
	base map[string]map[string][]byte
}

func newRCDiffHarness(t *testing.T) *rcDiffHarness {
	t.Helper()
	h := &rcDiffHarness{dirs: map[string]string{}, base: map[string]map[string][]byte{}}
	for run, src := range rcDiffRuns {
		dir := filepath.Join(t.TempDir(), "run")
		files := map[string][]byte{}
		err := filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return walkErr
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			body, err := os.ReadFile(path) // #nosec G304,G122 -- the retained run tree under test
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = body
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		h.dirs[run], h.base[run] = dir, files
		for rel, body := range files {
			h.write(t, run, rel, body)
		}
	}
	return h
}

func (h *rcDiffHarness) write(t *testing.T, run, rel string, body []byte) {
	t.Helper()
	path := filepath.Join(h.dirs[run], filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func rcDiffDecode(t *testing.T, field any) []byte {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(field.(string))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// apply puts the mutation's edits on the scratch copy of its run and returns the path.
func (h *rcDiffHarness) apply(t *testing.T, m rcDiffMutation) string {
	t.Helper()
	root := h.dirs[m.Run]
	for _, op := range m.Ops {
		rel := op[1].(string)
		path := filepath.Join(root, filepath.FromSlash(rel))
		switch op[0].(string) {
		case "d":
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		case "w":
			h.write(t, m.Run, rel, rcDiffDecode(t, op[2]))
		case "s":
			data, err := os.ReadFile(path) // #nosec G304 -- the scratch copy
			if err != nil {
				t.Fatal(err)
			}
			head, cut := int(op[2].(float64)), int(op[3].(float64))
			spliced := append(append(append([]byte{}, data[:head]...), rcDiffDecode(t, op[4])...), data[head+cut:]...)
			h.write(t, m.Run, rel, spliced)
		default:
			t.Fatalf("mutation %s: unknown edit %v", m.ID, op[0])
		}
	}
	return root
}

// restore puts the files a mutation touched back as the retained run has them.
func (h *rcDiffHarness) restore(t *testing.T, m rcDiffMutation) {
	t.Helper()
	root := h.dirs[m.Run]
	for _, op := range m.Ops {
		rel := op[1].(string)
		if body, kept := h.base[m.Run][rel]; kept {
			h.write(t, m.Run, rel, body)
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		for dir := filepath.Dir(path); dir != root; dir = filepath.Dir(dir) {
			if os.Remove(dir) != nil {
				break
			}
		}
	}
}

// judge runs the Go reader on one mutation, with one rule skipped when skip is set.
func (h *rcDiffHarness) judge(t *testing.T, m rcDiffMutation, skip string) (*rcResult, map[string]int, *rcFault) {
	t.Helper()
	root := h.apply(t, m)
	defer h.restore(t, m)
	if m.Trusting {
		verify := rcEdVerify
		rcEdVerify = func(pub, _, sig []byte) bool {
			return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize
		}
		defer func() { rcEdVerify = verify }()
	}
	return rcJudgeRun(root, skip)
}

// rcDiffCompare is empty when the Go answer is the Python answer, and names the first
// difference otherwise.
func rcDiffCompare(fx *rcDiffFixture, result *rcResult, fault *rcFault, want *rcDiffWant) string {
	if want == nil {
		if fault == nil {
			return "the Python reader stops on this run and the Go reader does not"
		}
		return ""
	}
	if fault != nil {
		return fmt.Sprintf("the Go reader stops (%s) where the Python reader judges", fault)
	}
	if result.ok != want.OK {
		return fmt.Sprintf("ok is %v, Python says %v", result.ok, want.OK)
	}
	if len(result.steps) != len(want.C) {
		return fmt.Sprintf("%d cases judged, Python judged %d", len(result.steps), len(want.C))
	}
	for name, indexes := range want.C {
		steps, found := result.steps[name]
		if !found {
			return fmt.Sprintf("case %s is not judged", name)
		}
		for i, step := range fx.Steps {
			if steps[step] != fx.Verdicts[indexes[i]] {
				return fmt.Sprintf("case %s step %s: Go %q, Python %q", name, step, steps[step], fx.Verdicts[indexes[i]])
			}
		}
	}
	if len(result.checks) != len(fx.Checks) {
		return fmt.Sprintf("%d run checks, Python has %d", len(result.checks), len(fx.Checks))
	}
	for i, check := range result.checks {
		if check.name != fx.Checks[i] || check.verdict != fx.Verdicts[want.K[i]] {
			return fmt.Sprintf("run check %s: Go %q, Python %s %q", check.name, check.verdict, fx.Checks[i], fx.Verdicts[want.K[i]])
		}
	}
	return ""
}

func TestRefundConnectedAgreesWithPython(t *testing.T) {
	fx := loadRCDiff(t)
	h := newRCDiffHarness(t)
	firedBy := map[string][]int{}
	var agree, faults, replayed int
	for i, m := range fx.Mutations {
		if i%rcDiffStride != 0 && m.Want != nil {
			continue
		}
		replayed++
		result, fired, fault := h.judge(t, m, "")
		if diff := rcDiffCompare(fx, result, fault, m.Want); diff != "" {
			t.Errorf("%s: %s", m.ID, diff)
			continue
		}
		agree++
		if m.Want == nil {
			faults++
		}
		for code := range fired {
			firedBy[code] = append(firedBy[code], i)
		}
	}
	t.Logf("%d of %d agree (%d of them stops on an exception the Python reader does not catch)", agree, replayed, faults)
	if agree != replayed {
		t.Fatalf("%d of %d agree", agree, replayed)
	}
	t.Run("a skipped rule is noticed", func(t *testing.T) {
		codes := make([]string, 0, len(firedBy))
		for code := range firedBy {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		var noticed int
		for _, code := range codes {
			if reason, exempt := rcDiffSkipExempt[code]; exempt {
				t.Logf("%s: exempt, %s", code, reason)
				continue
			}
			if rcDiffKilled(t, h, fx, code, firedBy[code]) {
				noticed++
				continue
			}
			if rcDiffStride > 1 {
				t.Logf("skipping %s changes no verdict on the sampled mutations that fire it", code)
				continue
			}
			t.Errorf("skipping %s changes no verdict on any of the %d mutations that fire it", code, len(firedBy[code]))
		}
		t.Logf("%d of %d rules noticed when skipped", noticed, len(codes))
	})
}

// rcDiffKilled is true when skipping the rule changes the Go answer away from the
// Python one on some mutation that fires it.
func rcDiffKilled(t *testing.T, h *rcDiffHarness, fx *rcDiffFixture, code string, indexes []int) bool {
	t.Helper()
	for _, i := range indexes {
		m := fx.Mutations[i]
		result, _, fault := h.judge(t, m, code)
		if rcDiffCompare(fx, result, fault, m.Want) != "" {
			return true
		}
	}
	return false
}
