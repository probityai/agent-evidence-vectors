// Command aev-verdicts prints the verdict a v2 reader derives for every case
// of one corpus directory.
//
// Usage: aev-verdicts <corpus-dir>
//
// For every manifest vector, in manifest order, it prints one line
// "<id>\t<decision>\t<reason>". The verdict comes from the case's record.json
// alone; the manifest's expected answer is never read. Exit 0 when the run
// completed, 2 when the corpus is unreadable or its suite is unknown.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: aev-verdicts <corpus-dir>")
		return 2
	}
	lines, err := corpusreaders.VerdictLines(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "aev-verdicts: %v\n", err)
		return 2
	}
	out := bufio.NewWriter(stdout)
	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
	if err := out.Flush(); err != nil {
		fmt.Fprintf(stderr, "aev-verdicts: %v\n", err)
		return 2
	}
	return 0
}
