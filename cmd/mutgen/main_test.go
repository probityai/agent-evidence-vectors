package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture exercises every operator mutgen claims to have. It is compiled by
// nothing, so it may name types the rail defines (Code, appendCode) without
// importing anything: the mutator is purely syntactic and never typechecks.
const fixture = `package rail

type Code string

func appendCode(cs []Code, c Code) []Code { return append(cs, c) }

const CodeA Code = "a"

type ev struct{ valid bool }

func Guard(a, b, c bool, codes []Code) []Code {
	if a {
		codes = appendCode(codes, CodeA)
	}
	if a || b {
		codes = appendCode(codes, CodeA)
	}
	if a && b {
		codes = appendCode(codes, CodeA)
	}
	switch {
	case c:
		codes = appendCode(codes, CodeA)
	case a || b:
		codes = appendCode(codes, CodeA)
	case a && b:
		codes = appendCode(codes, CodeA)
	}
	return codes
}

func Kind(s string) string {
	switch s {
	case "one":
		return "1"
	case "two":
		return "2"
	}
	return ""
}

func Pred(a, b bool) bool {
	if a {
		return b
	}
	return false
}

func Assign(e *ev, a bool) {
	e.valid = a
}

// Every member must be CodeA: a universal LOOP_FIRST weakens to its first
// witness.
func All(xs []Code, codes []Code) []Code {
	for i := range xs {
		if xs[i] != CodeA {
			codes = appendCode(codes, CodeA)
		}
	}
	return codes
}

// An accumulator. It asserts nothing about any member, so LOOP_FIRST must not
// enumerate it.
func Gather(xs []Code) []Code {
	out := []Code{}
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

// A body that always leaves on its first element. A break appended here could
// never run, so LOOP_FIRST must not enumerate it either.
func Head(xs []Code) Code {
	for _, x := range xs {
		return x
	}
	return CodeA
}

// A code splice. The emission is the loop's own element, so the loop judges
// nothing and LOOP_FIRST must not enumerate it.
func Splice(src []Code, dst []Code) []Code {
	for _, c := range src {
		dst = appendCode(dst, c)
	}
	return dst
}

// Every arm of the switch leaves the body and a default covers the rest, so an
// appended break could never run.
func Scan(xs []Code) bool {
	for _, x := range xs {
		switch x {
		case CodeA:
			continue
		default:
			return false
		}
	}
	return true
}

// A universal that reports through a nested splice. The inner loop emits its
// own range variable and is not a quantifier; the outer one judges each member
// and is. Both readings have to come out of one enumeration.
func Nested(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		for _, c := range Splice([]Code{x}, nil) {
			codes = appendCode(codes, c)
		}
	}
	return codes
}
`

func fixturePkg(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	// A _test.go file in the same directory must be ignored: mutating a test
	// would measure the tests rather than the rail.
	if err := os.WriteFile(filepath.Join(dir, "rail_test.go"), []byte("package rail\n\nfunc Ignored(a bool) bool {\n\tif a {\n\t\treturn true\n\t}\n\treturn false\n}\n"), 0o600); err != nil {
		t.Fatalf("write test fixture: %v", err)
	}
	return dir
}

func listSites(t *testing.T, dir string) []site {
	t.Helper()
	var out, errs bytes.Buffer
	if code := run([]string{"-pkg", dir, "-list"}, &out, &errs); code != 0 {
		t.Fatalf("-list exited %d: %s", code, errs.String())
	}
	var sites []site
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var s site
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		sites = append(sites, s)
	}
	return sites
}

func TestListCoversEveryOperator(t *testing.T) {
	sites := listSites(t, fixturePkg(t))
	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.Op] = true
		if s.File != "rail.go" {
			t.Errorf("site %s came from %s; only non-test sources may be enumerated", s.Key, s.File)
		}
	}
	for _, op := range []string{
		"IF_OFF", "IF_DISJ", "IF_CONJ", "CASE_OFF", "CASE_DISJ", "CASE_CONJ",
		"CASE_DEL", "RET_TRUE", "RET_FALSE", "CODE_OFF", "VALID_TRUE",
		"LOOP_FIRST",
	} {
		if !seen[op] {
			t.Errorf("operator %s produced no site; the fixture or the enumerator lost it", op)
		}
	}
}

// The quantifier operator has to be narrow to mean anything. A loop that builds
// a value out of every element makes no claim about any of them, so weakening
// it measures how the rail computes rather than what the corpus forces; and a
// loop that always leaves on its first element is already existential, so the
// appended break would be a mutation that changes nothing and scores DEAD for a
// reason that is about this operator rather than about the corpus. Both would
// be reported as universals the suite does not force, which is the specific
// false claim this test exists to keep out of the baseline.
func TestLoopFirstOnlyEnumeratesQuantifiers(t *testing.T) {
	count := map[string]int{}
	for _, s := range listSites(t, fixturePkg(t)) {
		if s.Op == "LOOP_FIRST" {
			count[s.Func]++
		}
	}
	for _, fn := range []string{"All", "Nested"} {
		if count[fn] == 0 {
			t.Errorf("%s ranges over a collection and reports a violating member; "+
				"LOOP_FIRST enumerated no site there, so the operator fires nowhere", fn)
		}
	}
	for _, fn := range []string{"Gather", "Head", "Splice", "Scan"} {
		if count[fn] != 0 {
			t.Errorf("LOOP_FIRST enumerated %d site(s) in %s, which carries no universal",
				count[fn], fn)
		}
	}
	// Nested holds two loops and exactly one of them is a quantifier. Counting
	// is the point: the inner loop emits its own range variable and the test
	// would pass on presence alone if both were enumerated.
	if count["Nested"] != 1 {
		t.Errorf("Nested has one quantifier and one splice; LOOP_FIRST enumerated %d site(s)",
			count["Nested"])
	}
}

// loopFirstSites parses one function and counts the quantifier sites in it.
//
// The snippets below are never compiled, only parsed, which is the same footing
// the mutator itself works on: it is purely syntactic and typechecks nothing. So
// they may name identifiers no fixture declares.
func loopFirstSites(t *testing.T, decl string) int {
	t.Helper()
	src := "package rail\n\ntype Code string\n\nfunc appendCode(cs []Code, c Code) []Code { return cs }\n\n" +
		"const CodeA Code = \"a\"\n\n" + decl
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "rail.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("the fixture does not parse: %v\n%s", err, src)
	}
	n := 0
	for _, s := range collect(fset, f, "rail.go") {
		if s.Op == "LOOP_FIRST" {
			n++
		}
	}
	return n
}

// Whether a break appended to a loop body could run is decided by Go's own
// terminating-statement rule, and every arm of that rule is a way for this
// operator to mint an equivalent mutant if it answers wrongly. An equivalent
// mutant scores DEAD, and a DEAD quantifier row is published as a universal the
// corpus does not force -- a claim about the corpus that the operator would have
// manufactured. So each arm gets a case, and each case says which way it goes.
func TestLoopFirstTerminationRule(t *testing.T) {
	cases := []struct {
		name string
		want int
		decl string
	}{
		{"a labelled statement that leaves", 0, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		if x == CodeA { codes = appendCode(codes, CodeA) }
	Done:
		return codes
	}
	return codes
}`},
		{"a block that leaves", 0, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		if x == CodeA { codes = appendCode(codes, CodeA) }
		{ return codes }
	}
	return codes
}`},
		{"a panic", 0, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		if x == CodeA { codes = appendCode(codes, CodeA) }
		panic("unreachable")
	}
	return codes
}`},
		{"a trailing call that is not panic", 1, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		if x == CodeA { codes = appendCode(codes, CodeA) }
		println(x)
	}
	return codes
}`},
		{"a trailing expression that is not a call", 1, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		if x == CodeA { codes = appendCode(codes, CodeA) }
		x
	}
	return codes
}`},
		{"a type switch whose every arm leaves", 0, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		if x == CodeA { codes = appendCode(codes, CodeA) }
		switch any(x).(type) {
		case string:
			continue
		default:
			return codes
		}
	}
	return codes
}`},
		{"a select whose every arm leaves", 0, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		if x == CodeA { codes = appendCode(codes, CodeA) }
		select {
		case <-ch:
			continue
		default:
			return codes
		}
	}
	return codes
}`},
		{"an unconditional inner loop", 0, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		if x == CodeA { codes = appendCode(codes, CodeA) }
		for {
		}
	}
	return codes
}`},
		// The two break cases are the pair worth having. An unlabelled break in a
		// switch arm leaves the SWITCH and falls through to the end of the body,
		// so the appended break still runs and the site is real. A labelled one
		// leaves the loop, so it does not.
		{"an unlabelled break inside a switch arm", 1, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		switch x {
		case CodeA:
			codes = appendCode(codes, CodeA)
			break
		default:
			return codes
		}
	}
	return codes
}`},
		{"a labelled break inside a switch arm", 0, `
func F(xs []Code, codes []Code) []Code {
Outer:
	for _, x := range xs {
		switch x {
		case CodeA:
			codes = appendCode(codes, CodeA)
			break Outer
		default:
			return codes
		}
	}
	return codes
}`},
		{"a fallthrough", 1, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		switch x {
		case CodeA:
			codes = appendCode(codes, CodeA)
			fallthrough
		default:
			return codes
		}
	}
	return codes
}`},
		{"a switch arm with an empty body", 1, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		codes = appendCode(codes, CodeA)
		switch x {
		case CodeA:
		default:
			return codes
		}
	}
	return codes
}`},
		{"a switch with no default", 1, `
func F(xs []Code, codes []Code) []Code {
	for _, x := range xs {
		codes = appendCode(codes, CodeA)
		switch x {
		case CodeA:
			return codes
		}
	}
	return codes
}`},
		{"a violation reported by a bare return", 1, `
func F(xs []Code) Code {
	for _, x := range xs {
		if x == CodeA {
			return CodeA
		}
	}
	return CodeA
}`},
		{"a return that belongs to a func literal", 0, `
func F(xs []Code) {
	for _, x := range xs {
		f := func() Code { return x }
		_ = f
	}
}`},
		{"an empty loop body", 0, `
func F(xs []Code) {
	for _, x := range xs {
	}
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loopFirstSites(t, tc.decl); got != tc.want {
				t.Errorf("LOOP_FIRST enumerated %d site(s), want %d", got, tc.want)
			}
		})
	}
}

// The weakening itself: the body gains a break and nothing else moves. Checked
// on the printed source rather than on the AST, because the printed source is
// what the campaign compiles.
func TestLoopFirstAppendsExactlyABreak(t *testing.T) {
	dir := fixturePkg(t)
	var target site
	for _, s := range listSites(t, dir) {
		if s.Op == "LOOP_FIRST" {
			target = s
			break
		}
	}
	if target.Key == "" {
		t.Fatal("no LOOP_FIRST site in the fixture")
	}
	var out, errs bytes.Buffer
	if code := run([]string{"-pkg", dir, "-apply", target.Key}, &out, &errs); code != 0 {
		t.Fatalf("-apply %s exited %d: %s", target.Key, code, errs.String())
	}
	got := out.String()
	if strings.Count(got, "break") != strings.Count(fixture, "break")+1 {
		t.Errorf("expected exactly one break to be added:\n%s", got)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "mutant.go", got, 0); err != nil {
		t.Fatalf("the weakened loop does not parse: %v\n%s", err, got)
	}
	// The break must close the loop BODY. Printed adjacent to the previous
	// statement it would still parse and would still be inside the body, so the
	// shape is asserted rather than assumed.
	if !strings.Contains(got, "\t\tbreak\n\t}") {
		t.Errorf("the break did not land as the last statement of the loop body:\n%s", got)
	}
}

// A key that moved when unrelated lines moved would make the forcing baseline
// unusable as a ratchet: one inserted rule would read as several hundred
// simultaneous regressions.
func TestKeysAreStableUnderLineShifts(t *testing.T) {
	before := listSites(t, fixturePkg(t))

	shifted := t.TempDir()
	body := "package rail\n\n// a comment that did not exist\n// and a second line of it\n" +
		strings.TrimPrefix(fixture, "package rail\n")
	if err := os.WriteFile(filepath.Join(shifted, "rail.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	after := listSites(t, shifted)

	if len(before) != len(after) {
		t.Fatalf("site count changed under a comment insertion: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Key != after[i].Key {
			t.Errorf("key moved under a line shift: %s -> %s", before[i].Key, after[i].Key)
		}
		if before[i].Line == after[i].Line {
			t.Errorf("site %s did not move at all; the fixture failed to shift anything", before[i].Key)
		}
	}
}

// Two identical sites in one function are exactly what `if err != nil { return
// err }` produces, and they must not collide into one baseline row.
func TestRepeatedSitesAreSeparatedByOrdinal(t *testing.T) {
	dir := t.TempDir()
	// Byte-identical guards, which is what a repeated `if err != nil { return err }`
	// looks like to a syntactic mutator.
	body := "package rail\n\nfunc Twice(a bool) int {\n\tif a {\n\t\treturn 1\n\t}\n\tif a {\n\t\treturn 1\n\t}\n\treturn 3\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sites := listSites(t, dir)
	if len(sites) != 2 {
		t.Fatalf("expected 2 sites, got %d", len(sites))
	}
	if sites[0].Key == sites[1].Key {
		t.Fatalf("two identical sites collided on one key: %s", sites[0].Key)
	}
	if !strings.HasSuffix(sites[1].Key, "#2") {
		t.Errorf("the second occurrence should carry an ordinal, got %s", sites[1].Key)
	}
}

// Every mutation must still PARSE: a mutant that does not compile scores as
// inconclusive, which measures nothing. Parsing is the strongest check available
// without a typechecker, and it catches the whole class of naive rewrites (a bare
// `false` in a tagged case arm, a deleted clause that strands a comment).
func TestEveryMutationStillParses(t *testing.T) {
	dir := fixturePkg(t)
	sites := listSites(t, dir)
	if len(sites) == 0 {
		t.Fatal("no sites")
	}
	for _, s := range sites {
		var out, errs bytes.Buffer
		if code := run([]string{"-pkg", dir, "-apply", s.Key}, &out, &errs); code != 0 {
			t.Fatalf("-apply %s exited %d: %s", s.Key, code, errs.String())
		}
		if out.String() == fixture {
			t.Errorf("-apply %s changed nothing", s.Key)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), "mutant.go", out.String(), 0); err != nil {
			t.Errorf("-apply %s produced unparseable Go: %v\n%s", s.Key, err, out.String())
		}
	}
}

func TestApplyWriteRewritesTheFileInPlace(t *testing.T) {
	dir := fixturePkg(t)
	sites := listSites(t, dir)
	target := sites[0]
	var out, errs bytes.Buffer
	if code := run([]string{"-pkg", dir, "-apply", target.Key, "-write"}, &out, &errs); code != 0 {
		t.Fatalf("exited %d: %s", code, errs.String())
	}
	if out.Len() != 0 {
		t.Errorf("-write should not also print to stdout, got %d bytes", out.Len())
	}
	body, err := os.ReadFile(filepath.Join(dir, "rail.go"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(body) == fixture {
		t.Fatal("-write left the file unchanged")
	}
	if !strings.Contains(string(body), "false && (") {
		t.Errorf("expected a short-circuited guard in the rewritten file:\n%s", body)
	}
}

func TestUsageFailures(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no package", []string{"-list"}, "-pkg is required"},
		{"neither mode", []string{"-pkg", "."}, "exactly one of"},
		{"both modes", []string{"-pkg", ".", "-list", "-apply", "x"}, "exactly one of"},
		{"unknown flag", []string{"-nope"}, "flag provided but not defined"},
		{"missing package", []string{"-pkg", filepath.Join(t.TempDir(), "absent"), "-list"}, "no such file"},
		{"key names no file", []string{"-pkg", ".", "-apply", "nonsense"}, "does not name a source file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errs bytes.Buffer
			if code := run(tc.args, &out, &errs); code != 2 {
				t.Fatalf("exited %d, want 2", code)
			}
			if !strings.Contains(errs.String(), tc.want) {
				t.Errorf("stderr %q does not carry %q", errs.String(), tc.want)
			}
		})
	}
}

func TestApplyUnknownKeyIsRefused(t *testing.T) {
	dir := fixturePkg(t)
	var out, errs bytes.Buffer
	code := run([]string{"-pkg", dir, "-apply", "rail.go::Guard::IF_OFF::000000000000"}, &out, &errs)
	if code != 2 {
		t.Fatalf("exited %d, want 2", code)
	}
	if !strings.Contains(errs.String(), "no site") {
		t.Errorf("stderr %q does not name the missing site", errs.String())
	}
}

func TestApplyUnparseablePackage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte("package rail\nfunc ("), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, args := range [][]string{
		{"-pkg", dir, "-list"},
		{"-pkg", dir, "-apply", "rail.go::x::IF_OFF::000000000000"},
	} {
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != 2 {
			t.Errorf("%v exited %d, want 2", args, code)
		}
	}
}

func TestWriteToAnUnwritablePathIsRefused(t *testing.T) {
	dir := fixturePkg(t)
	sites := listSites(t, dir)
	target := filepath.Join(dir, "rail.go")
	if err := os.Chmod(target, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o600) })
	if os.Geteuid() == 0 {
		t.Skip("running as root, where a read-only file is still writable")
	}
	var out, errs bytes.Buffer
	if code := run([]string{"-pkg", dir, "-apply", sites[0].Key, "-write"}, &out, &errs); code != 2 {
		t.Fatalf("exited %d, want 2", code)
	}
}

func TestSiteKeyOrdinalAndFileRecovery(t *testing.T) {
	first := siteKey("validity.go", "checkRow", "IF_OFF", "if a {}", 1)
	second := siteKey("validity.go", "checkRow", "IF_OFF", "if a {}", 2)
	if first == second {
		t.Fatal("ordinal did not separate two identical sites")
	}
	if got := fileOfKey(first); got != "validity.go" {
		t.Errorf("fileOfKey(%q) = %q", first, got)
	}
	if got := fileOfKey("nofile"); got != "nofile" {
		t.Errorf("fileOfKey on a keyless string = %q", got)
	}
}

func TestSnippetIsBounded(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("aaaaaaaaaa || ", 40) + "b"
	body := "package rail\n\nfunc Long(aaaaaaaaaa, b bool) int {\n\tif " + long + " {\n\t\treturn 1\n\t}\n\treturn 0\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, s := range listSites(t, dir) {
		if len(s.Snippet) > maxSnippet+3 {
			t.Errorf("snippet of %s is %d characters, over the %d bound", s.Key, len(s.Snippet), maxSnippet)
		}
	}
}

// apply reports rather than silently succeeding when the node it was handed is
// not reachable from the file it was handed.
func TestApplyRefusesAnUnreachableNode(t *testing.T) {
	dir := fixturePkg(t)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(dir, "rail.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sites := collect(fset, f, "rail.go")
	var expr *site
	for _, s := range sites {
		if s.kind == "expr" {
			expr = s
			break
		}
	}
	if expr == nil {
		t.Fatal("no expression site in the fixture")
	}
	other, err := parser.ParseFile(fset, "other.go", "package rail\n\nfunc Other() {}\n", 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := apply(other, expr); err == nil {
		t.Fatal("apply reported success for a node the file does not contain")
	}
}

// A type switch whose bound symbol only one arm reads. Deleting that arm used to
// leave `p` declared and unused, a mutant Go refuses to build; the campaign then
// recorded the site as INCONCLUSIVE and it could never be measured.
const typeSwitchFixture = `package rail

func Previous(v any, seq int) (string, bool) {
	switch p := v.(type) {
	case nil:
		if seq != 1 {
			return "", false
		}
	case string:
		if seq == 1 {
			return "", false
		}
		return p, true
	default:
		return "", false
	}
	return "", true
}
`

func typecheck(t *testing.T, src string) error {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "rail.go", src, 0)
	if err != nil {
		return err
	}
	_, err = (&types.Config{}).Check("rail", fset, []*ast.File{f}, nil)
	return err
}

func TestEveryCaseDelMutantOfATypeSwitchTypechecks(t *testing.T) {
	if err := typecheck(t, typeSwitchFixture); err != nil {
		t.Fatalf("the unmutated fixture must typecheck: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte(typeSwitchFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	var deleted []string
	for _, s := range listSites(t, dir) {
		if s.Op != "CASE_DEL" {
			continue
		}
		var out, errs bytes.Buffer
		if code := run([]string{"-pkg", dir, "-apply", s.Key}, &out, &errs); code != 0 {
			t.Fatalf("-apply %s exited %d: %s", s.Key, code, errs.String())
		}
		if err := typecheck(t, out.String()); err != nil {
			t.Errorf("CASE_DEL %q does not typecheck: %v\n%s", s.Snippet, err, out.String())
		}
		deleted = append(deleted, out.String())
	}
	if len(deleted) != 2 {
		t.Fatalf("want the two value arms deleted one at a time, got %d mutants", len(deleted))
	}
	// The binding goes only when no remaining arm reads it.
	var unbound, kept int
	for _, src := range deleted {
		switch {
		case strings.Contains(src, "switch v.(type)"):
			unbound++
		case strings.Contains(src, "switch p := v.(type)"):
			kept++
		}
	}
	if unbound != 1 || kept != 1 {
		t.Fatalf("want one mutant unbound (string arm gone) and one still bound (nil arm gone), got %d and %d", unbound, kept)
	}
}
