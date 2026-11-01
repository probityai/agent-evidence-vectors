package corpora

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func init() { register(refundConnected{}) }

// refundConnected judges vectors-refund-connected/. Each member is one case of a
// retained connected refund run: the inputs and trust files of the case, the
// admission state, the signed handoffs and resolutions, the executor's four
// streams and the payment simulator's own record. The reader re-derives the six
// step verdicts of the case and the five checks over its run from those bytes
// alone and compares them with what the manifest records. It never opens the
// run's results.json or verdicts.json. The rules are those of
// packaging/agent_evidence_vectors/refundconnected.py, down to the inputs that
// make that reader stop: a differential test holds the two to the same answer on
// every mutation of a retained run.
//
// A member's kind is how its case ends, read from the manifest's own verdicts:
// established when every step holds, rejected when a layer refused the case,
// contradicted or not-established when the bytes disagree or are absent, and
// not-reached when an earlier layer ended the case legitimately. A rejected or
// contradicted member is one the reader refuses, and the intake record lists it
// as such.
type refundConnected struct{}

func (refundConnected) Suite() string { return rcSuite }

type rcManifest struct {
	CorpusDigest string                `json:"corpusDigest"`
	Runs         map[string]rcRunEntry `json:"runs"`
	Vectors      []json.RawMessage     `json:"vectors"`
}

type rcRunEntry struct {
	Files map[string]string `json:"files"`
	Path  string            `json:"path"`
}

type rcVector struct {
	ID       string `json:"id"`
	Case     string `json:"case"`
	Path     string `json:"path"`
	Run      string `json:"run"`
	Expected struct {
		Steps     map[string]string `json:"steps"`
		RunChecks map[string]string `json:"run_checks"`
	} `json:"expected"`
}

// rcOutcome is one run directory judged once for every member that names it.
type rcOutcome struct {
	result *rcResult
	fault  *rcFault
}

func (refundConnected) Judge(dir string, raw []byte) (*Result, error) {
	var manifest rcManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	judged := map[string]*rcOutcome{}
	for _, entry := range manifest.Vectors {
		var v rcVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		outcome, seen := judged[v.Path]
		if !seen {
			outcome = &rcOutcome{}
			outcome.result, _, outcome.fault = rcJudgeRun(filepath.Join(dir, v.Path), "")
			judged[v.Path] = outcome
		}
		member := Member{ID: v.ID, Kind: rcMemberKind(v)}
		member.Findings = rcMemberFindings(v, outcome, manifest.Runs)
		result.Members = append(result.Members, member)
	}
	trees, findings := rcCheckTrees(dir, manifest.Runs)
	result.Findings = append(result.Findings, findings...)
	if len(findings) == 0 {
		if finding := rcCorpusDigest(raw, trees, manifest.CorpusDigest); finding != "" {
			result.Findings = append(result.Findings, finding)
		}
	}
	return result, nil
}

// rcMemberKind is how the case ends, by the first step the manifest records as
// anything but established.
func rcMemberKind(v rcVector) string {
	for _, step := range rcSteps {
		verdict := v.Expected.Steps[step]
		switch {
		case verdict == rcEstablished:
			continue
		case strings.HasPrefix(verdict, rcRefused+":"):
			return "rejected"
		case strings.HasPrefix(verdict, rcContra+":"):
			return "contradicted"
		case strings.HasPrefix(verdict, rcAbsent+":"):
			return "not-established"
		case verdict == rcNotReached:
			return "not-reached"
		}
		return "unrecognized"
	}
	return "established"
}

func rcMemberFindings(v rcVector, outcome *rcOutcome, runs map[string]rcRunEntry) []string {
	var findings []string
	if _, declared := runs[v.Run]; !declared {
		findings = append(findings, fmt.Sprintf("the member names the run %q, which the manifest does not declare", v.Run))
	}
	if outcome.fault != nil {
		return append(findings, fmt.Sprintf("the reader stopped judging the run %s: %s", v.Path, outcome.fault))
	}
	steps, found := outcome.result.steps[v.Case]
	if !found {
		return append(findings, fmt.Sprintf("the case %q is not a case directory of the run %s", v.Case, v.Path))
	}
	findings = append(findings, rcCompare("step", rcSteps, steps, v.Expected.Steps)...)
	derived := map[string]string{}
	var names []string
	for _, check := range outcome.result.checks {
		derived[check.name] = check.verdict
		names = append(names, check.name)
	}
	return append(findings, rcCompare("run check", names, derived, v.Expected.RunChecks)...)
}

// rcCompare names every place the verdicts the reader derived and the verdicts the
// manifest records differ, in both directions.
func rcCompare(what string, names []string, derived, recorded map[string]string) []string {
	var findings []string
	for _, name := range names {
		want, present := recorded[name]
		switch {
		case !present:
			findings = append(findings, fmt.Sprintf("%s %s: the manifest records none and the reader derived %q", what, name, derived[name]))
		case want != derived[name]:
			findings = append(findings, fmt.Sprintf("%s %s: the manifest records %q and the reader derived %q", what, name, want, derived[name]))
		}
	}
	known := map[string]bool{}
	for _, name := range names {
		known[name] = true
	}
	for _, name := range sortedKeys(recorded) {
		if !known[name] {
			findings = append(findings, fmt.Sprintf("%s %s: the manifest records %q and the reader has no such %s", what, name, recorded[name], what))
		}
	}
	return findings
}

// rcTreeFiles is every file of one run tree with its SHA-256, keyed by its path
// inside the tree.
func rcTreeFiles(root string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { // #nosec G703 -- the run tree is the path the manifest names
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, statErr := os.Stat(path) // #nosec G304,G703,G122 -- the run tree is the path the manifest names
		if statErr != nil || !info.Mode().IsRegular() {
			return nil
		}
		body, readErr := os.ReadFile(path) // #nosec G304,G703,G122 -- as above
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		files[filepath.ToSlash(rel)] = sha(body)
		return nil
	})
	return files, err
}

// rcCheckTrees compares each run's tree with the files the manifest declares for
// it: one finding per run, naming what is missing, extra or changed.
func rcCheckTrees(dir string, runs map[string]rcRunEntry) (map[string]map[string]string, []string) {
	trees := map[string]map[string]string{}
	var findings []string
	if len(runs) == 0 {
		findings = append(findings, "the manifest declares no run")
	}
	for _, key := range sortedKeys(runs) {
		tree, err := rcTreeFiles(filepath.Join(dir, runs[key].Path))
		if err != nil {
			findings = append(findings, fmt.Sprintf("run %s: the tree %s cannot be read: %v", key, runs[key].Path, err))
			continue
		}
		trees[key] = tree
		if diff := rcTreeDiff(runs[key].Files, tree); diff != "" {
			findings = append(findings, fmt.Sprintf("run %s: the tree %s differs from the manifest: %s", key, runs[key].Path, diff))
		}
	}
	return trees, findings
}

func rcTreeDiff(declared, tree map[string]string) string {
	var missing, extra, changed []string
	for _, name := range sortedKeys(declared) {
		got, present := tree[name]
		switch {
		case !present:
			missing = append(missing, name)
		case got != declared[name]:
			changed = append(changed, name)
		}
	}
	for _, name := range sortedKeys(tree) {
		if _, declaredFile := declared[name]; !declaredFile {
			extra = append(extra, name)
		}
	}
	var parts []string
	for _, group := range []struct {
		label string
		names []string
	}{{"missing", missing}, {"extra", extra}, {"changed", changed}} {
		if len(group.names) > 0 {
			parts = append(parts, fmt.Sprintf("%d %s (%s)", len(group.names), group.label, strings.Join(group.names, ", ")))
		}
	}
	return strings.Join(parts, "; ")
}

// rcCorpusDigest recomputes the published corpus digest: SHA-256 over the runs
// (each with the files found in its tree) and the vectors as CPython's
// json.dumps(indent=2, sort_keys=True) writes them, plus a newline.
func rcCorpusDigest(raw []byte, trees map[string]map[string]string, published string) string {
	value, err := decodeJSONNumbers(raw)
	doc, ok := value.(map[string]any)
	if err != nil || !ok {
		return "the manifest cannot be re-read to recompute its digest"
	}
	runs := map[string]any{}
	declared, _ := doc["runs"].(map[string]any)
	for key, entry := range declared {
		fields, isObject := entry.(map[string]any)
		if !isObject {
			return fmt.Sprintf("run %s is not an object", key)
		}
		copied := map[string]any{}
		for name, field := range fields {
			copied[name] = field
		}
		files := map[string]any{}
		for name, digest := range trees[key] {
			files[name] = digest
		}
		copied["files"] = files
		runs[key] = copied
	}
	compact, err := pythonCompactJSON(map[string]any{"runs": runs, "vectors": doc["vectors"]})
	if err != nil {
		return fmt.Sprintf("the manifest cannot be re-encoded: %v", err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, compact, "", "  "); err != nil {
		return fmt.Sprintf("the manifest cannot be re-encoded: %v", err)
	}
	indented.WriteByte('\n')
	if got := sha(indented.Bytes()); got != published {
		return fmt.Sprintf("corpusDigest %s does not match the recomputed %s", short(published), short(got))
	}
	return ""
}
