// Package jcsvectors carries RFC 8785 (JSON Canonicalization Scheme) test
// vectors as embedded files, so a Go test can check a canonicalizer against
// them with no download and no network.
//
// The files are byte copies of two corpora in
// https://github.com/probityai/agent-evidence-vectors: vectors-a2a-jcs-v01
// (one file per vector, listed with its SHA-256 in MANIFEST.json) and
// jcs-byte-vectors (cases.json). Every function checks each file it reads
// against the SHA-256 recorded for it when the module was generated, the
// manifest and cases.json included, and each a2a vector against its manifest
// digest too, before returning anything.
//
//	vectors, err := jcsvectors.Canonical()
//	for _, v := range vectors {
//		got, err := canonicalize(v.Input)
//		// got must equal v.Canonical byte for byte
//	}
//
// An implementation that supports a subset of RFC 8785 declares a [Profile]
// and scores the accept cases outside it apart, by the [Feature] list each
// case carries; every case it must refuse stays in:
//
//	in, out, err := jcsvectors.Filter(jcsvectors.ProfileIntegerOnly, vectors)
//	// a divergence on in is a failure; out is reported as out of profile
//
// [ParserDifferential] yields the byte strings two JSON readers read apart,
// with what RFC 8785 and the bounded I-JSON profile each do with them.
package jcsvectors

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// FS holds the vector files at the paths the corpora publish them under:
// vectors-a2a-jcs-v01/MANIFEST.json, vectors-a2a-jcs-v01/<group>/<id>.json
// and jcs-byte-vectors/cases.json.
//
//go:embed vectors-a2a-jcs-v01 jcs-byte-vectors
var FS embed.FS

// source is what readFile reads: FS, except in the test that edits one byte
// of a copy to prove the digest check refuses it.
var source fs.FS = FS

const (
	a2aCorpus  = "vectors-a2a-jcs-v01"
	byteCorpus = "jcs-byte-vectors"
	// rfc8785Clause prefixes the clause of every a2a vector that tests RFC 8785
	// itself. The others test the A2A Agent Card rule that removes the
	// signatures member before canonicalizing, which is not RFC 8785.
	rfc8785Clause = "RFC8785-"
)

// Vector is one RFC 8785 test case.
type Vector struct {
	// ID is the case's identifier in its corpus.
	ID string
	// Corpus is the corpus the case comes from: "vectors-a2a-jcs-v01" or
	// "jcs-byte-vectors".
	Corpus string
	// Clause is the RFC 8785 clause the case tests, such as "RFC8785-3.2.3".
	// It is empty for jcs-byte-vectors cases, which do not name one.
	Clause string
	// Input is the JSON text to canonicalize.
	Input []byte
	// Canonical is the RFC 8785 output for Input. It is nil for a case that
	// a canonicalizer must refuse.
	Canonical []byte
	// Features names what the case exercises, read from its bytes: the kinds
	// of number token, string escapes, non-ASCII text and input that is not
	// UTF-8. A [Profile] admits or excludes the case by them. Sorted, with no
	// repeats.
	Features []Feature
}

// Canonical returns every case whose input a canonicalizer must accept, with
// the exact bytes RFC 8785 requires for it, noncharacters included: RFC 8785
// prints a Unicode noncharacter as its UTF-8 bytes, although an I-JSON profile
// refuses it.
func Canonical() ([]Vector, error) {
	accept, _, err := load()
	return accept, err
}

// Reject returns every case whose input a canonicalizer must refuse: duplicate
// members (also spelled with an escape, or nested), lone surrogates, invalid
// UTF-8, numbers with no finite IEEE 754 value, trailing content, malformed
// JSON and other input with no RFC 8785 form. Some inputs are not UTF-8, so
// compare bytes.
func Reject() ([]Vector, error) {
	_, reject, err := load()
	return reject, err
}

// Drift is bytes that a producer printed and presented as the canonical form
// of a value, which RFC 8785 does not print that way. A check that these bytes
// are canonical must answer no, and canonicalizing Input must give Canonical.
type Drift struct {
	// ID is the case's identifier, such as "drift-html-less-than".
	ID string
	// Family is "html-escape", "non-ascii-escape" or "number-format".
	Family string
	// Source names the printer the bytes come from, such as "go-encoding-json".
	Source string
	// Input is the JSON text of the value.
	Input []byte
	// Presented is the drifted output, which is not canonical.
	Presented []byte
	// Canonical is the RFC 8785 output for the value.
	Canonical []byte
}

// SourceGo marks a [Drift] whose Presented bytes are what Go's encoding/json
// prints for the value.
const SourceGo = "go-encoding-json"

// DepthCap is the nesting depth the corpus admits. Input nested one level
// deeper must be refused.
const DepthCap = 128

// Drifts returns every drift case, each checked against its SHA-256.
func Drifts() ([]Drift, error) {
	var cases byteCases
	if err := readJSON(byteCorpus+"/cases.json", &cases); err != nil {
		return nil, err
	}
	var out []Drift
	for _, c := range cases.DriftCases {
		canonical, err := hex.DecodeString(c.CanonicalHex)
		if err != nil || len(canonical) == 0 {
			return nil, fmt.Errorf("%s case %s: no canonical bytes", byteCorpus, c.ID)
		}
		if err := checkDigest(byteCorpus+" case "+c.ID, canonical, c.SHA256); err != nil {
			return nil, err
		}
		out = append(out, Drift{
			ID: c.ID, Family: c.Family, Source: c.Source,
			Input: []byte(c.Input), Presented: []byte(c.Presented), Canonical: canonical,
		})
	}
	return out, nil
}

// TooDeep returns the cases nested past [DepthCap], which an admission gate
// with that cap must refuse. They are not RFC 8785 refusals, so [Reject] does
// not carry them. A case nested exactly [DepthCap] deep is in [DepthAdmitted].
func TooDeep() ([]Vector, error) {
	reject, _, err := depthCases()
	return reject, err
}

// DepthAdmitted returns the cases nested exactly [DepthCap] deep, which an
// admission gate with that cap must accept and canonicalize to Canonical.
func DepthAdmitted() ([]Vector, error) {
	_, accept, err := depthCases()
	return accept, err
}

func depthCases() (reject, accept []Vector, err error) {
	var cases byteCases
	if err := readJSON(byteCorpus+"/cases.json", &cases); err != nil {
		return nil, nil, err
	}
	for _, c := range cases.DepthCases {
		v := Vector{ID: c.ID, Corpus: byteCorpus, Input: []byte(c.Input)}
		switch c.Expect {
		case "reject":
			reject = append(reject, v)
			continue
		case "accept":
		default:
			return nil, nil, fmt.Errorf("%s case %s: unknown expect %q", byteCorpus, c.ID, c.Expect)
		}
		canonical, err := hex.DecodeString(c.CanonicalHex)
		if err != nil || len(canonical) == 0 {
			return nil, nil, fmt.Errorf("%s case %s: no canonical bytes", byteCorpus, c.ID)
		}
		if err := checkDigest(byteCorpus+" case "+c.ID, canonical, c.SHA256); err != nil {
			return nil, nil, err
		}
		v.Canonical = canonical
		accept = append(accept, v)
	}
	return withFeatures(reject), withFeatures(accept), nil
}

type a2aManifest struct {
	Vectors []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"vectors"`
	Targets struct {
		RFC8785 struct {
			Vectors int `json:"vectors"`
		} `json:"rfc8785"`
	} `json:"targets"`
}

type a2aVector struct {
	ID          string          `json:"id"`
	Clause      string          `json:"clause"`
	Disposition string          `json:"disposition"`
	Input       json.RawMessage `json:"input"`
	InputRaw    *string         `json:"input_raw"`
	Expected    struct {
		CanonicalHex string `json:"canonical_utf8_hex"`
	} `json:"expected"`
}

// acceptCase is a case RFC 8785 accepts, with its exact output. Bounded and
// BoundedError say whether the corpus's bounded profile (I-JSON strings and
// safe integers only) admits it too.
type acceptCase struct {
	ID           string `json:"id"`
	Family       string `json:"family"`
	Input        string `json:"input"`
	CanonicalHex string `json:"canonicalHex"`
	SHA256       string `json:"sha256"`
	Bounded      string `json:"bounded"`
	BoundedError string `json:"boundedError"`
}

// canonical returns the case's pinned output, checked against its digest.
func (c acceptCase) canonical() ([]byte, error) {
	canonical, err := hex.DecodeString(c.CanonicalHex)
	if err != nil || len(canonical) == 0 {
		return nil, fmt.Errorf("%s case %s: no canonical bytes", byteCorpus, c.ID)
	}
	if err := checkDigest(byteCorpus+" case "+c.ID, canonical, c.SHA256); err != nil {
		return nil, err
	}
	return canonical, nil
}

type byteCases struct {
	Format         string       `json:"format"`
	CanonicalCases []acceptCase `json:"canonicalCases"`
	RejectCases    []struct {
		ID       string `json:"id"`
		Input    string `json:"input"`
		JCSError string `json:"jcsError"`
		// BoundedError is the code an I-JSON reader refuses the input with,
		// where RFC 8785 alone does not.
		BoundedError string `json:"boundedError"`
	} `json:"rejectCases"`
	DriftCases []struct {
		ID           string `json:"id"`
		Family       string `json:"family"`
		Source       string `json:"source"`
		Input        string `json:"input"`
		Presented    string `json:"presented"`
		CanonicalHex string `json:"canonicalHex"`
		SHA256       string `json:"sha256"`
	} `json:"driftCases"`
	DepthCases []struct {
		ID           string `json:"id"`
		Input        string `json:"input"`
		Expect       string `json:"expect"`
		CanonicalHex string `json:"canonicalHex"`
		SHA256       string `json:"sha256"`
	} `json:"depthCases"`
	// NoncharacterCases put a Unicode noncharacter, or the scalar value next to
	// one, in a string; RFC 8785 prints each as its UTF-8 bytes, so each is an
	// accept case here (an I-JSON profile refuses the noncharacters).
	NoncharacterCases []acceptCase `json:"noncharacterCases"`
	// RefusalCases is input that is not one valid RFC 8785 input at all, which
	// no profile excuses a canonicalizer for printing. InputHex carries input
	// that is not UTF-8.
	RefusalCases []struct {
		ID       string  `json:"id"`
		Family   string  `json:"family"`
		Error    string  `json:"error"`
		Expect   string  `json:"expect"`
		Input    *string `json:"input"`
		InputHex *string `json:"inputHex"`
	} `json:"refusalCases"`
}

func load() (accept, reject []Vector, err error) {
	accept, reject, err = loadA2A()
	if err != nil {
		return nil, nil, err
	}
	byteAccept, byteReject, err := loadBytes()
	if err != nil {
		return nil, nil, err
	}
	return withFeatures(append(accept, byteAccept...)), withFeatures(append(reject, byteReject...)), nil
}

func loadA2A() (accept, reject []Vector, err error) {
	var manifest a2aManifest
	if err := readJSON(a2aCorpus+"/MANIFEST.json", &manifest); err != nil {
		return nil, nil, err
	}
	for _, entry := range manifest.Vectors {
		name := a2aCorpus + "/" + entry.Path
		raw, err := readFile(name)
		if err != nil {
			return nil, nil, err
		}
		if err := checkDigest(name, raw, entry.SHA256); err != nil {
			return nil, nil, err
		}
		var vector a2aVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		if !strings.HasPrefix(vector.Clause, rfc8785Clause) {
			continue
		}
		parsed, err := vector.toVector()
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		if parsed.Canonical != nil {
			accept = append(accept, parsed)
		} else {
			reject = append(reject, parsed)
		}
	}
	if got, want := len(accept)+len(reject), manifest.Targets.RFC8785.Vectors; got != want {
		return nil, nil, fmt.Errorf("%s: read %d RFC 8785 vectors, the manifest declares %d", a2aCorpus, got, want)
	}
	return accept, reject, nil
}

func (v a2aVector) toVector() (Vector, error) {
	out := Vector{ID: v.ID, Corpus: a2aCorpus, Clause: v.Clause}
	switch v.Disposition {
	case "MUST-ACCEPT":
		canonical, err := hex.DecodeString(v.Expected.CanonicalHex)
		if err != nil || len(canonical) == 0 {
			return Vector{}, fmt.Errorf("vector %s: no canonical bytes", v.ID)
		}
		out.Input, out.Canonical = v.Input, canonical
	case "MUST-REJECT":
		if v.InputRaw == nil {
			return Vector{}, fmt.Errorf("vector %s: no input_raw", v.ID)
		}
		out.Input = []byte(*v.InputRaw)
	default:
		return Vector{}, fmt.Errorf("vector %s: unknown disposition %q", v.ID, v.Disposition)
	}
	return out, nil
}

func loadBytes() (accept, reject []Vector, err error) {
	var cases byteCases
	if err := readJSON(byteCorpus+"/cases.json", &cases); err != nil {
		return nil, nil, err
	}
	if cases.Format != "jcs-byte-vectors/v1" {
		return nil, nil, fmt.Errorf("%s: unknown format %q", byteCorpus, cases.Format)
	}
	for _, c := range append(append([]acceptCase{}, cases.CanonicalCases...), cases.NoncharacterCases...) {
		canonical, err := c.canonical()
		if err != nil {
			return nil, nil, err
		}
		accept = append(accept, Vector{ID: c.ID, Corpus: byteCorpus, Input: []byte(c.Input), Canonical: canonical})
	}
	// A case with only a boundedError is refused by an application profile
	// that admits safe integers alone, not by RFC 8785, so it is left out.
	for _, c := range cases.RejectCases {
		if c.JCSError != "" {
			reject = append(reject, Vector{ID: c.ID, Corpus: byteCorpus, Input: []byte(c.Input)})
		}
	}
	for _, c := range cases.RefusalCases {
		if c.Expect != "reject" {
			return nil, nil, fmt.Errorf("%s case %s: a refusal case expects %q, not reject", byteCorpus, c.ID, c.Expect)
		}
		input, err := refusalInput(c.ID, c.Input, c.InputHex)
		if err != nil {
			return nil, nil, err
		}
		reject = append(reject, Vector{ID: c.ID, Corpus: byteCorpus, Input: input})
	}
	return accept, reject, nil
}

// refusalInput is a refusal case's input: its text, or the bytes its hex
// spells when the input is not UTF-8. A case gives exactly one of the two.
func refusalInput(id string, text, inputHex *string) ([]byte, error) {
	switch {
	case text != nil && inputHex == nil:
		return []byte(*text), nil
	case text == nil && inputHex != nil:
		decoded, err := hex.DecodeString(*inputHex)
		if err != nil {
			return nil, fmt.Errorf("%s case %s: inputHex is not hex", byteCorpus, id)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("%s case %s: needs exactly one of input and inputHex", byteCorpus, id)
	}
}

// readFile reads an embedded file and checks it against the digest recorded
// for it when the module was generated.
func readFile(name string) ([]byte, error) {
	raw, err := fs.ReadFile(source, name)
	if err != nil {
		return nil, err
	}
	for _, entry := range fileDigests {
		if entry[0] == name {
			if err := checkDigest(name, raw, entry[1]); err != nil {
				return nil, err
			}
			return raw, nil
		}
	}
	return nil, fmt.Errorf("%s: no recorded digest", name)
}

func readJSON(name string, into any) error {
	raw, err := readFile(name)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkDigest(name string, data []byte, want string) error {
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("%s: sha256 %s, the corpus records %s", name, got, want)
	}
	return nil
}
