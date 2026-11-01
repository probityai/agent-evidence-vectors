package corpora

// The Go encoders against one shared table of documents.
//
// testdata/json-encodings.json holds JSON documents written the way a producer
// writes them, and for each digest encoding the bytes the Python
// implementation writes (hex) or the reason it refuses.
// scripts/json-encoding-differential-test.py computes every cell from the
// Python code and refuses a table that differs from it; this test refuses a Go
// encoder that differs from the table. Between them a Go encoder and its
// Python twin are compared over the same inputs, which a list of expectations
// typed into a Go test cannot do: those claimed CPython's output for -0 and
// were never run against it.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type encodingCell struct {
	Hex     *string `json:"hex"`
	Refused *string `json:"refused"`
}

type encodingCase struct {
	Name  string                  `json:"name"`
	Doc   string                  `json:"doc"`
	Cells map[string]encodingCell `json:"-"`
}

func (c *encodingCase) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	c.Cells = map[string]encodingCell{}
	for key, value := range fields {
		var err error
		switch key {
		case "name":
			err = json.Unmarshal(value, &c.Name)
		case "doc":
			err = json.Unmarshal(value, &c.Doc)
		default:
			var cell encodingCell
			err = json.Unmarshal(value, &cell)
			c.Cells[key] = cell
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// loadEncodingTable reads the shared table and refuses an empty or columnless one.
func loadEncodingTable(t *testing.T) ([]string, []encodingCase) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "json-encodings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Columns []string       `json:"columns"`
		Cases   []encodingCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Columns) == 0 || len(table.Cases) == 0 {
		t.Fatal("the shared encoding table holds no columns or no cases")
	}
	return table.Columns, table.Cases
}

// checkEncodingCell compares what a Go encoder wrote, or refused, with one cell.
func checkEncodingCell(t *testing.T, where string, want encodingCell, got []byte, err error, refusal func(error) string) {
	t.Helper()
	switch {
	case want.Refused != nil:
		if err == nil {
			t.Errorf("%s: the table refuses (%s) and Go wrote %q", where, *want.Refused, got)
		} else if r := refusal(err); r != *want.Refused {
			t.Errorf("%s: the table refuses with %q and Go refuses with %q", where, *want.Refused, r)
		}
	case want.Hex != nil:
		if err != nil {
			t.Errorf("%s: the table writes %s and Go refused: %v", where, *want.Hex, err)
		} else if h := hex.EncodeToString(got); h != *want.Hex {
			t.Errorf("%s: the table writes %s and Go wrote %s (%q)", where, *want.Hex, h, got)
		}
	default:
		t.Errorf("%s: the cell holds neither bytes nor a refusal", where)
	}
}

func TestPythonCompactJSONAgreesWithTheSharedTable(t *testing.T) {
	columns, cases := loadEncodingTable(t)
	spellings := map[string]pyEncodeOpts{
		"cpython-ascii": {EnsureASCII: true},
		"cpython-raw":   {},
		"cpython-utf16": {UTF16Order: true},
	}
	checked := 0
	for _, column := range columns {
		opts, ok := spellings[column]
		if !ok {
			continue
		}
		for _, c := range cases {
			want, ok := c.Cells[column]
			if !ok {
				t.Errorf("%s: no %s cell", c.Name, column)
				continue
			}
			value, err := decodeJSONNumbers([]byte(c.Doc))
			if err != nil {
				t.Fatalf("%s: the document does not decode: %v", c.Name, err)
			}
			got, err := pythonCompactJSONOpts(value, opts)
			// The Python side names a refusal by its class; this encoder says
			// it in its own words, and any other refusal is reported as it is.
			checkEncodingCell(t, column+" "+c.Name, want, got, err, func(err error) string {
				if strings.Contains(err.Error(), "is a JSON float") {
					return "float"
				}
				return err.Error()
			})
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no cpython column was checked, so this test held nothing")
	}
}

// TestNumberTruthAgreesWithTheSharedTable: a Python reader tests the truth of
// the value it parsed, so -0, 0.0 and a token too small for a double are false
// there. The Go readers compared the token's text with "0" and read them as
// true; jsonNumberIsZero reads the value, and the table's answers are CPython's.
func TestNumberTruthAgreesWithTheSharedTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "json-encodings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Truth []struct {
			Token string `json:"token"`
			Falsy bool   `json:"cpython-falsy"`
		} `json:"number-truth"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Truth) == 0 {
		t.Fatal("the shared table holds no number-truth tokens")
	}
	for _, row := range table.Truth {
		if got := jsonNumberIsZero(json.Number(row.Token)); got != row.Falsy {
			t.Errorf("%s: CPython reads it as false=%t, jsonNumberIsZero says %t", row.Token, row.Falsy, got)
		}
		if got := moTruthy(json.Number(row.Token)); got == row.Falsy {
			t.Errorf("%s: the mcp-owasp reader's truth test says %t, CPython's bool says %t", row.Token, got, !row.Falsy)
		}
		if got := isFalsy(json.Number(row.Token)); got != row.Falsy {
			t.Errorf("%s: the cross-run record reader's falsiness test says %t, CPython says %t", row.Token, got, row.Falsy)
		}
	}
}
