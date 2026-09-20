package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/probityai/agent-evidence-vectors/corpora"
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
	result, err := corpora.Judge(dir)
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

func printCorpus(w io.Writer, r *corpora.Result) {
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
