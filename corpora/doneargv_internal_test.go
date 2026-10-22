package corpora

// The Go done reader compares runs by the argv model of doneargv.py and Python's posixpath.
// testdata/done-argv.json holds what Python answers on the spellings that decide each rule
// (written by vectors-done-receipt/tests/test_done_argv_cases.py, which also checks it), and
// this test requires the same answer from Go on every one.

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type doneArgvCases struct {
	Invocations []struct {
		Argv []string       `json:"argv"`
		Exe  string         `json:"exe"`
		Want map[string]any `json:"want"`
	} `json:"invocations"`
	Normpath []struct {
		Path string `json:"path"`
		Want string `json:"want"`
	} `json:"normpath"`
	Join []struct {
		A    string `json:"a"`
		B    string `json:"b"`
		Want string `json:"want"`
	} `json:"join"`
	Split []struct {
		Path string    `json:"path"`
		Want [2]string `json:"want"`
	} `json:"split"`
	Space []struct {
		Rune rune `json:"rune"`
		Want bool `json:"want"`
	} `json:"space"`
}

func loadDoneArgvCases(t *testing.T) doneArgvCases {
	t.Helper()
	raw, err := os.ReadFile("testdata/done-argv.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases doneArgvCases
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases.Invocations) == 0 || len(cases.Normpath) == 0 || len(cases.Join) == 0 ||
		len(cases.Split) == 0 || len(cases.Space) == 0 {
		t.Fatal("a section of done-argv.json is empty")
	}
	return cases
}

// decodeDoneInvocation is the invocation in the fixture's shape.
func decodeDoneInvocation(t *testing.T, found doneInvocation) map[string]any {
	t.Helper()
	var body []any
	if err := json.Unmarshal([]byte(found.args[1:]), &body); err != nil {
		t.Fatalf("args %q: %v", found.args, err)
	}
	if found.args[0] == 'P' {
		return map[string]any{"program": found.program, "targets": body[0], "selecting": body[1]}
	}
	return map[string]any{"program": found.program, "args": body}
}

func TestDoneArgvAgreesWithPython(t *testing.T) {
	cases := loadDoneArgvCases(t)
	for _, item := range cases.Invocations {
		got := decodeDoneInvocation(t, doneInvocationOf(item.Argv, item.Exe))
		if !reflect.DeepEqual(got, item.Want) {
			t.Errorf("invocation(%q, %q): got %v, Python gives %v", item.Argv, item.Exe, got, item.Want)
		}
	}
	for _, item := range cases.Normpath {
		if got := pyNormpath(item.Path); got != item.Want {
			t.Errorf("normpath(%q): got %q, Python gives %q", item.Path, got, item.Want)
		}
	}
	for _, item := range cases.Join {
		if got := pyJoin(item.A, item.B); got != item.Want {
			t.Errorf("join(%q, %q): got %q, Python gives %q", item.A, item.B, got, item.Want)
		}
	}
	for _, item := range cases.Split {
		if head, tail := pySplit(item.Path); [2]string{head, tail} != item.Want {
			t.Errorf("split(%q): got %q %q, Python gives %q", item.Path, head, tail, item.Want)
		}
	}
	for _, item := range cases.Space {
		if got := pyIsSpace(item.Rune); got != item.Want {
			t.Errorf("isspace(%U): got %v, Python gives %v", item.Rune, got, item.Want)
		}
	}
}

// Python orders tuples element by element and a prefix first; the selecting options are
// sorted that way.
func TestDoneTupleLessOrdersAsPython(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"-k", "a"}, []string{"-k", "b"}, true},
		{[]string{"-k", "b"}, []string{"-k", "a"}, false},
		{[]string{"-k"}, []string{"-k", "a"}, true},
		{[]string{"-k", "a"}, []string{"-k"}, false},
		{[]string{"-k", "a"}, []string{"-k", "a"}, false},
		{[]string{"-m", "a"}, []string{"-k", "z"}, false},
		{[]string{"--lf"}, []string{"-k", "a"}, true},
		{[]string{}, []string{"-k"}, true},
	}
	for _, item := range cases {
		if got := doneTupleLess(item.a, item.b); got != item.want {
			t.Errorf("%q < %q: got %v, want %v", item.a, item.b, got, item.want)
		}
	}
}
