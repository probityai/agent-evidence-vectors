package corpora

// The Go done reader's tool-shadow rules are held to the Python reader's answers.
// testdata/done-events.json holds exec, loader, write and link cases with what the Python
// reader answers for each (written by vectors-done-receipt/tests/test_done_event_cases.py,
// which also checks it). This test calls the Go function of each section and requires the
// same answer.

import (
	"os"
	"reflect"
	"sort"
	"testing"
)

type doneStartedCase struct {
	Event   doneObject `json:"event"`
	Started []any      `json:"started"`
	Zero    *string    `json:"zero"`
	Replace []string   `json:"replacing"`
	Safe    *bool      `json:"safe"`
}

type doneEventFixture struct {
	Started  []doneStartedCase `json:"started"`
	TopLevel []struct {
		Name      string `json:"name"`
		Directory string `json:"directory"`
		Want      string `json:"want"`
	} `json:"top_level"`
	Entries []struct {
		Key   string   `json:"key"`
		Value string   `json:"value"`
		Cwd   string   `json:"cwd"`
		Want  []string `json:"want"`
	} `json:"entries"`
	Excused []struct {
		Name    string   `json:"name"`
		Allowed []string `json:"allowed"`
		Want    bool     `json:"want"`
	} `json:"excused"`
	Importable []struct {
		Directory string   `json:"directory"`
		Written   []string `json:"written"`
		Links     []string `json:"links"`
		Allowed   []string `json:"allowed"`
		Want      []string `json:"want"`
	} `json:"importable"`
	Exempt []struct {
		Event      doneObject `json:"event"`
		Writes     []string   `json:"writes"`
		Own        []string   `json:"own"`
		Exempt     bool       `json:"exempt"`
		Ownship    bool       `json:"ownship"`
		OwnshipNil bool       `json:"ownship_none"`
	} `json:"exempt"`
	Links []struct {
		Record doneObject `json:"record"`
		Before int64      `json:"before"`
		Want   []string   `json:"want"`
	} `json:"links"`
}

func doneSet(items []string) map[string]bool {
	out := map[string]bool{}
	for _, item := range items {
		out[item] = true
	}
	return out
}

func doneSortedKeys(set map[string]bool) []string {
	out := []string{}
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func loadDoneEvents(t *testing.T) doneEventFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/done-events.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases doneEventFixture
	if err := doneDecodeNumbers(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases.Started) == 0 || len(cases.TopLevel) == 0 || len(cases.Entries) == 0 ||
		len(cases.Excused) == 0 || len(cases.Importable) == 0 || len(cases.Exempt) == 0 ||
		len(cases.Links) == 0 {
		t.Fatal("a section of done-events.json is empty")
	}
	return cases
}

func TestDoneEventsAgreeWithPython(t *testing.T) {
	cases := loadDoneEvents(t)
	checkDoneStarted(t, cases)
	checkDoneNames(t, cases)
	checkDoneWrites(t, cases)
}

func checkDoneStartedOne(t *testing.T, item doneStartedCase) {
	t.Helper()
	started, ok := doneStartedOf(item.Event)
	if (item.Started != nil) != ok {
		t.Errorf("started(%v): ran %v, Python gives %v", item.Event, ok, item.Started)
		return
	}
	if !ok {
		return
	}
	var mode, value any
	if started.mode != "" {
		mode = started.mode
	}
	if started.has {
		value = started.value
	}
	got := []any{}
	for _, flag := range doneSortedKeys(started.flags) {
		got = append(got, flag)
	}
	if !reflect.DeepEqual(got, item.Started[0].([]any)) || mode != item.Started[1] || value != item.Started[2] {
		t.Errorf("started(%v): got %v %v %v, Python gives %v", item.Event, got, mode, value, item.Started)
	}
	if safe := doneSafe(started.flags, item.Event); item.Safe == nil || safe != *item.Safe {
		t.Errorf("safe(%v): got %v, Python gives %v", item.Event, safe, item.Safe)
	}
}

func checkDoneStarted(t *testing.T, cases doneEventFixture) {
	t.Helper()
	for _, item := range cases.Started {
		checkDoneStartedOne(t, item)
		zero, found := donePythonPathZero(item.Event)
		if found != (item.Zero != nil) || (found && zero != *item.Zero) {
			t.Errorf("pathzero(%v): got %q %v, Python gives %v", item.Event, zero, found, item.Zero)
		}
		if replacing := doneSortedKeys(doneReplacing(item.Event)); !reflect.DeepEqual(replacing, item.Replace) {
			t.Errorf("replacing(%v): got %v, Python gives %v", item.Event, replacing, item.Replace)
		}
	}
}

func checkDoneNames(t *testing.T, cases doneEventFixture) {
	t.Helper()
	for _, item := range cases.TopLevel {
		if got := doneTopLevel(item.Name, item.Directory); got != item.Want {
			t.Errorf("toplevel(%q, %q): got %q, Python gives %q", item.Name, item.Directory, got, item.Want)
		}
	}
	for _, item := range cases.Entries {
		if got := doneLoaderEntries(item.Key, item.Value, item.Cwd); !reflect.DeepEqual(got, item.Want) {
			t.Errorf("entries(%q, %q, %q): got %q, Python gives %q", item.Key, item.Value, item.Cwd, got, item.Want)
		}
	}
	for _, item := range cases.Excused {
		if got := doneExcused(item.Name, item.Allowed); got != item.Want {
			t.Errorf("excused(%q, %q): got %v, Python gives %v", item.Name, item.Allowed, got, item.Want)
		}
	}
}

func checkDoneWrites(t *testing.T, cases doneEventFixture) {
	t.Helper()
	for _, item := range cases.Importable {
		got := doneImportableWrites(item.Directory, doneSet(item.Written), doneSet(item.Links), item.Allowed)
		if !reflect.DeepEqual(got, item.Want) {
			t.Errorf("importable(%q, links %q, allowed %q): got %q, Python gives %q", item.Directory, item.Links, item.Allowed, got, item.Want)
		}
	}
	for _, item := range cases.Exempt {
		if got := doneExempt(item.Event, item.Writes); got != item.Exempt {
			t.Errorf("exempt(%v, %q): got %v, Python gives %v", item.Event, item.Writes, got, item.Exempt)
		}
		own := doneSet(item.Own)
		if got := doneOwn(item.Event, own, item.Writes); got != item.Ownship {
			t.Errorf("own(%v, %q): got %v, Python gives %v", item.Event, item.Writes, got, item.Ownship)
		}
		if got := doneOwn(item.Event, own, nil); got != item.OwnshipNil {
			t.Errorf("own(%v, nil): got %v, Python gives %v", item.Event, got, item.OwnshipNil)
		}
	}
	for _, item := range cases.Links {
		if got := doneSortedKeys(doneLinks(item.Record, item.Before)); !reflect.DeepEqual(got, item.Want) {
			t.Errorf("links(%v, %d): got %q, Python gives %q", item.Record, item.Before, got, item.Want)
		}
	}
}
