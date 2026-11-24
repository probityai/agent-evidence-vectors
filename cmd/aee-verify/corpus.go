package main

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
	"sort"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

// runCorpus judges one corpus directory and returns the process exit code:
// 0 when every member behaves as its manifest declares, 1 when one does not,
// 2 when the corpus could not be read or its suite names no reader here.
//
// The distinction between 1 and 2 is the point. A corpus that fails names the
// members that failed; a corpus this binary cannot judge says so with the suite
// in the message and never exits 0, because a skipped corpus and a clean corpus
// otherwise print the same nothing.
func runCorpus(dir string, jsonOut bool, stdout, stderr io.Writer) int {
	result, err := corpusreaders.Judge(dir)
	if err != nil {
		fmt.Fprintf(stderr, "aee-verify: %v\n", err)
		return 2
	}
	if jsonOut {
		out, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintf(stderr, "aee-verify: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(out))
		if result.OK() {
			return 0
		}
		return 1
	}
	printCorpus(stdout, result)
	if result.OK() {
		return 0
	}
	return 1
}

func printCorpus(w io.Writer, r *corpusreaders.Result) {
	fmt.Fprintf(w, "suite: %s\n", r.Suite)
	fmt.Fprintf(w, "members: %d\n", len(r.Members))
	counts := r.CountsByVerdict()
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		fmt.Fprintf(w, "  %s: %d\n", kind, counts[kind])
	}
	failed := 0
	for _, m := range r.Members {
		if m.OK() {
			continue
		}
		failed++
		for _, finding := range m.Findings {
			fmt.Fprintf(w, "FAIL %s: %s\n", m.ID, finding)
		}
	}
	for _, finding := range r.Findings {
		fmt.Fprintf(w, "FAIL corpus: %s\n", finding)
	}
	if r.OK() {
		fmt.Fprintln(w, "verdict: every member behaves as MANIFEST.json declares")
		return
	}
	fmt.Fprintf(w, "verdict: %d member(s) and %d corpus-level claim(s) do not hold\n",
		failed, len(r.Findings))
}

// runVerdictLines prints one verdict line per member of every corpus named, in
// the shared format, and returns 0 when every corpus was read (the verdicts are
// judged against the manifests by the format's checker, not here), 2 when a
// corpus could not be read or none was named.
func runVerdictLines(dirs []string, stdout, stderr io.Writer) int {
	if len(dirs) == 0 {
		fmt.Fprintln(stderr, "aee-verify: -verdict-lines needs at least one corpus directory")
		return 2
	}
	verifier := corpusreaders.Verifier{Name: "aee-verify", Version: buildVersion()}
	for _, dir := range dirs {
		lines, err := corpusreaders.VerdictLines(dir, verifier)
		if err != nil {
			fmt.Fprintf(stderr, "aee-verify: NOT RUN: %v\n", err)
			return 2
		}
		for _, line := range lines {
			out, err := json.Marshal(line)
			if err != nil {
				fmt.Fprintf(stderr, "aee-verify: %v\n", err)
				return 2
			}
			fmt.Fprintln(stdout, string(out))
		}
	}
	return 0
}

// buildVersion is the module version this binary was built at, or the VCS
// revision for a build from a checkout, so a verdict line names the code that
// produced it.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return "devel+" + s.Value
		}
	}
	return "devel"
}
