package corpusreaders

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func init() {
	register(dnsAidCorpus{suite: "dns-aid-sig-binding/v1", decisions: true, judged: "record"})
	register(dnsAidCorpus{suite: "dns-aid-rrset/v1", judged: "rrset"})
}

// dnsAidCorpus judges that corpora/vectors-dns-aid-sig-v01/ and
// corpora/vectors-dns-aid-rrset-v01/ are intact. It does not judge the members:
// each one's verdict, codes and (for the sig corpus) decision are the answer a
// verifier under test must give, run through the external-verifier contract,
// and each corpus carries its own judging reader (check_vectors.py). This reader
// checks what a verifier cannot: every member file is the one the manifest
// names and names its own case, each declared answer fits its kind (an accept is
// valid with no codes, a reject is invalid with exactly the codes it lists), the
// sig corpus maps agrees to valid and contradicted or cannot-tell to invalid,
// and the counts and corpus digest agree with the tree.
//
// It also refuses a manifest that names one member twice in an object, exactly or in
// another letter case: encoding/json matches a name to a field without regard to
// case and keeps the last, while the Python reader reads the exact name, so a manifest
// carrying "expected" and "Expected" would show each reader a different answer. A
// file under cases/ that the manifest does not list, and a declared code listed twice,
// are findings too. A member file is strict JSON except inside its judged member
// (the record or the RRset): a repeat there is a defect the corpus's own reader names
// as the member's verdict, and one member carries it on purpose.
type dnsAidCorpus struct {
	suite     string
	decisions bool
	judged    string
}

func (d dnsAidCorpus) Suite() string { return d.suite }

type dnsAidManifest struct {
	Suite        string         `json:"suite"`
	Counts       map[string]int `json:"counts"`
	CorpusDigest string         `json:"corpusDigest"`
	Vectors      []dnsAidEntry  `json:"vectors"`
}

type dnsAidEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Expected struct {
		Verdict  string   `json:"verdict"`
		Codes    []string `json:"codes"`
		Decision string   `json:"decision"`
	} `json:"expected"`
}

func (d dnsAidCorpus) Judge(dir string, raw []byte) (*Result, error) {
	var m dnsAidManifest
	if err := strictUnmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	if name := foldedRepeat(raw); name != "" {
		result.Findings = append(result.Findings,
			fmt.Sprintf("MANIFEST.json names %q twice in one object (in another letter case)", name))
	}
	seen := map[string]bool{}
	measured := map[string]int{}
	for _, e := range m.Vectors {
		member := Member{ID: e.ID, Kind: e.Kind}
		if seen[e.ID] {
			member.Findings = append(member.Findings, "duplicate id")
		}
		seen[e.ID] = true
		if e.Kind == "accept" || e.Kind == "reject" {
			measured[e.Kind]++
		}
		d.judgeMember(dir, e, &member)
		result.Members = append(result.Members, member)
	}
	sort.Slice(result.Members, func(i, j int) bool { return result.Members[i].ID < result.Members[j].ID })
	ids, files := make([]string, len(m.Vectors)), make([]string, len(m.Vectors))
	for i, e := range m.Vectors {
		ids[i], files[i] = e.ID, e.File
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		return nil, err
	}
	if digest != m.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the members on disk")
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	if extra := dnsAidUnlisted(dir, files); extra != "" {
		result.Findings = append(result.Findings, extra)
	}
	return result, nil
}

// dnsAidUnlisted names every file under cases/ the manifest does not list: a harness
// that runs the directory would judge a member nobody declared an answer for.
func dnsAidUnlisted(dir string, files []string) string {
	entries, err := os.ReadDir(filepath.Join(dir, "cases"))
	if err != nil {
		return "cases/ cannot be read: " + err.Error()
	}
	listed := map[string]bool{}
	for _, f := range files {
		listed[f] = true
	}
	var extra []string
	for _, e := range entries {
		if !listed["cases/"+e.Name()] {
			extra = append(extra, e.Name())
		}
	}
	if len(extra) == 0 {
		return ""
	}
	sort.Strings(extra)
	return fmt.Sprintf("cases/ holds files the manifest does not list: %v", extra)
}

func (d dnsAidCorpus) judgeMember(dir string, e dnsAidEntry, out *Member) {
	switch {
	case e.Kind == "accept" && e.Expected.Verdict == "valid" && len(e.Expected.Codes) == 0:
	case e.Kind == "reject" && e.Expected.Verdict == "invalid" && len(e.Expected.Codes) > 0:
	default:
		out.Findings = append(out.Findings,
			"the declared answer does not fit the kind: an accept is valid with no codes, a reject is invalid with codes")
	}
	if !sort.StringsAreSorted(e.Expected.Codes) {
		out.Findings = append(out.Findings, "the declared codes are not sorted")
	}
	for i := 1; i < len(e.Expected.Codes); i++ {
		if e.Expected.Codes[i] == e.Expected.Codes[i-1] {
			out.Findings = append(out.Findings, "the declared codes list "+e.Expected.Codes[i]+" twice: codes are a set")
			break
		}
	}
	if d.decisions {
		want := map[string]bool{"agrees": e.Kind == "accept", "contradicted": e.Kind == "reject", "cannot-tell": e.Kind == "reject"}
		if ok, known := want[e.Expected.Decision]; !known || !ok {
			out.Findings = append(out.Findings,
				fmt.Sprintf("decision %q does not fit the kind: agrees is an accept, contradicted and cannot-tell are rejects", e.Expected.Decision))
		}
	}
	if !strings.HasPrefix(e.File, "cases/") || strings.Contains(e.File, "..") {
		out.Findings = append(out.Findings, "the member file is not under cases/")
		return
	}
	body, err := readIn(dir, e.File)
	if err != nil {
		out.Findings = append(out.Findings, "the member file is missing")
		return
	}
	if sha(body) != e.SHA256 {
		out.Findings = append(out.Findings, "declared sha256 does not recompute from the file")
	}
	var member struct {
		Case string `json:"case"`
	}
	if err := strictUnmarshalExcept(body, &member, d.judged); err != nil {
		out.Findings = append(out.Findings, "the member does not parse: "+err.Error())
		return
	}
	if member.Case != e.ID {
		out.Findings = append(out.Findings, "the member names another case")
	}
}
