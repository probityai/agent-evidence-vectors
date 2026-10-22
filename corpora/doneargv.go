package corpora

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// The argv model the done readers compare runs by, and the POSIX path rules it needs.
//
// This file mirrors packaging/agent_evidence_vectors/doneargv.py, which restates
// probity-verify's done_argv.invocation. A claimed run and an observed exec match when
// they run the same program with the same canonical arguments: for pytest, the set of
// targets and the sorted options that choose what runs, reporting options dropped; for
// any other program, the arguments in order.
//
// Go's path package does not normalize as Python's posixpath does (it collapses a leading
// "//" and treats "" as "."), so the readers carry their own copy of the four functions
// they use.

var (
	// doneArgvInterpreter is Python's re.match(r"(python|pypy)[0-9.]*$"): `$` also matches
	// before one final newline.
	doneArgvInterpreter = regexp.MustCompile(`^(python|pypy)[0-9.]*\n?$`)
	doneReporting       = map[string]bool{"-q": true, "--quiet": true, "-v": true, "--verbose": true,
		"-s": true, "-x": true, "--exitfirst": true, "--no-header": true, "--no-summary": true,
		"-l": true, "--showlocals": true, "--capture=no": true, "--disable-warnings": true,
		"--disable-pytest-warnings": true, "--strict-markers": true, "-ra": true, "-rA": true,
		"-rf": true, "-rs": true, "-rx": true, "-rX": true, "-rE": true, "-rp": true, "-rP": true,
		"-rN": true}
	doneReportingPrefix = []string{"--tb=", "--color=", "--durations=", "--maxfail=", "--capture=",
		"--code-highlight="}
	doneReportingValue = map[string]bool{"--tb": true, "--color": true, "--durations": true,
		"--maxfail": true, "--capture": true}
	doneSelectingValue = map[string]bool{"-k": true, "-m": true, "-W": true, "--deselect": true,
		"-c": true, "-o": true, "--override-ini": true, "--rootdir": true, "--confcutdir": true,
		"-p": true, "--ignore": true, "--ignore-glob": true, "--basetemp": true, "--import-mode": true}
	doneInterpreterValues = map[string]bool{"-W": true, "-X": true, "--check-hash-based-pycs": true}
)

// doneInvocation is a program and its canonical arguments, encoded so equal invocations
// compare equal as strings.
type doneInvocation struct{ program, args string }

func donePlain(word string) string {
	if strings.HasPrefix(word, "./") && len(word) > 2 {
		return word[2:]
	}
	return word
}

// doneModuleRun is (module, rest) for `<interpreter> [options] -m <module> rest`.
func doneModuleRun(argv []string) (string, []string, bool) {
	words := append([]string{}, argv[1:]...)
	for len(words) > 0 && strings.HasPrefix(words[0], "-") && words[0] != "-" {
		option := words[0]
		words = words[1:]
		if option == "-m" {
			if len(words) == 0 {
				return "", nil, false
			}
			return words[0], words[1:], true
		}
		if strings.HasPrefix(option, "-m") && len(option) > 2 {
			return option[2:], words, true
		}
		if doneInterpreterValues[option] && len(words) > 0 {
			words = words[1:]
		}
	}
	return "", nil, false
}

func doneHasReportingPrefix(word string) bool {
	for _, prefix := range doneReportingPrefix {
		if strings.HasPrefix(word, prefix) {
			return true
		}
	}
	return false
}

// donePytestArgs is the sorted set of targets and the sorted selecting options.
func donePytestArgs(args []string) string {
	targets := map[string]bool{}
	selecting := [][]string{}
	words := append([]string{}, args...)
	for len(words) > 0 {
		word := words[0]
		words = words[1:]
		switch {
		case word == "--":
			for _, item := range words {
				targets[pyNormpath(donePlain(item))] = true
			}
			words = nil
		case !strings.HasPrefix(word, "-") || word == "-":
			targets[pyNormpath(donePlain(word))] = true
		case doneReporting[word] || doneHasReportingPrefix(word):
		case doneReportingValue[word]:
			if len(words) > 0 {
				words = words[1:]
			}
		case doneSelectingValue[word]:
			value := ""
			if len(words) > 0 {
				value, words = words[0], words[1:]
			}
			selecting = append(selecting, []string{word, value})
		default:
			selecting = append(selecting, []string{word})
		}
	}
	sortedTargets := make([]string, 0, len(targets))
	for target := range targets {
		sortedTargets = append(sortedTargets, target)
	}
	sort.Strings(sortedTargets)
	sort.Slice(selecting, func(a, b int) bool { return doneTupleLess(selecting[a], selecting[b]) })
	encoded, _ := json.Marshal([]any{sortedTargets, selecting})
	return "P" + string(encoded)
}

// doneTupleLess orders string tuples as Python does: element by element, a prefix first.
func doneTupleLess(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// doneInvocationOf is the invocation an argv runs; exe, when not empty, names the file the
// kernel ran.
func doneInvocationOf(argv []string, exe string) doneInvocation {
	name := pyBasename(argv[0])
	if exe != "" {
		name = pyBasename(exe)
	}
	program, args := pyBasename(argv[0]), argv[1:]
	if doneArgvInterpreter.MatchString(name) || doneArgvInterpreter.MatchString(program) {
		if module, rest, ok := doneModuleRun(argv); ok {
			program, args = module, rest
		}
	}
	if program == "pytest" || program == "py.test" {
		return doneInvocation{"pytest", donePytestArgs(args)}
	}
	plain := make([]string, 0, len(args))
	for _, word := range args {
		plain = append(plain, donePlain(word))
	}
	encoded, _ := json.Marshal(plain)
	return doneInvocation{program, "A" + string(encoded)}
}

// --- posixpath --------------------------------------------------------------------------

// pyNormpath is Python's posixpath.normpath.
func pyNormpath(path string) string {
	if path == "" {
		return "."
	}
	initial := 0
	if strings.HasPrefix(path, "/") {
		initial = 1
		if strings.HasPrefix(path, "//") && !strings.HasPrefix(path, "///") {
			initial = 2
		}
	}
	parts := []string{}
	for _, part := range strings.Split(path, "/") {
		switch {
		case part == "" || part == ".":
		case part != "..":
			parts = append(parts, part)
		case (initial == 0 && len(parts) == 0) || (len(parts) > 0 && parts[len(parts)-1] == ".."):
			parts = append(parts, part)
		case len(parts) > 0:
			parts = parts[:len(parts)-1]
		}
	}
	out := strings.Repeat("/", initial) + strings.Join(parts, "/")
	if out == "" {
		return "."
	}
	return out
}

// pyJoin is Python's posixpath.join of two parts.
func pyJoin(a, b string) string {
	if strings.HasPrefix(b, "/") {
		return b
	}
	if a == "" || strings.HasSuffix(a, "/") {
		return a + b
	}
	return a + "/" + b
}

// pySplit is Python's posixpath.split.
func pySplit(path string) (string, string) {
	index := strings.LastIndex(path, "/") + 1
	head, tail := path[:index], path[index:]
	if head != "" && head != strings.Repeat("/", len(head)) {
		head = strings.TrimRight(head, "/")
	}
	return head, tail
}

func pyDirname(path string) string {
	head, _ := pySplit(path)
	return head
}

func pyBasename(path string) string {
	return path[strings.LastIndex(path, "/")+1:]
}

// pyIsSpace is the whitespace Python's \s matches in a str pattern.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}
