package corpusreaders

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func init() { register(ocsfDecision{}) }

// ocsfDecision judges corpora/vectors-ocsf-decision/. Each member is a stream of
// OCSF API Activity decision records (the Praxis Policy Engine's ocsf-audit sink
// writes them, and AID-EMIT-1 specifies them) in the member's own `records`
// text, one record per line, with the relying party's key set (`trust_policy`),
// the heads it holds independently (`relying_party`) and the profile a verdict
// is taken under (`profile`).
//
// The reader reads each stream by the published rule, in Go and from that rule
// alone (ocsfjson.go, ocsfrecord.go, ocsfstream.go): every record's structure,
// decision, fingerprint, signature and key binding, then the stream's uniqueness,
// chain, sequence and tail, then the strict profile's own dimensions. Each member
// declares a verdict, the code of the first dimension that refused, and the
// status of the dimensions it exercises; a member that reads otherwise is a
// finding naming it.
//
// Corpus level: the manifest's counts against the verdicts read, every member
// file present and no file unlisted, the corpus digest recomputed over the
// members in manifest order, and the vendored source files against the SHA-256
// and length the manifest pins.
type ocsfDecision struct{}

func (ocsfDecision) Suite() string { return "ocsf-decision/v1" }

type ocsfPin struct {
	SHA256 string `json:"sha256"`
	Length int    `json:"length"`
}

type ocsfSourceDoc struct {
	Repository string             `json:"repository"`
	Commit     string             `json:"commit"`
	Path       string             `json:"path"`
	Files      map[string]ocsfPin `json:"files"`
}

type ocsfManifest struct {
	Suite  string `json:"suite"`
	Format struct {
		ClassUID    int    `json:"class_uid"`
		Rule        string `json:"rule"`
		PayloadType string `json:"payload_type"`
	} `json:"format"`
	Source       ocsfSourceDoc     `json:"source"`
	Profiles     map[string]string `json:"profiles"`
	Counts       map[string]int    `json:"counts"`
	Vectors      []json.RawMessage `json:"vectors"`
	CorpusDigest string            `json:"corpusDigest"`
}

type ocsfExpected struct {
	Verdict    string                     `json:"verdict"`
	Code       *string                    `json:"code"`
	Dimensions map[string]json.RawMessage `json:"dimensions"`
}

type ocsfVector struct {
	ID       string       `json:"id"`
	Path     string       `json:"path"`
	Profile  string       `json:"profile"`
	Expected ocsfExpected `json:"expected"`
}

func (ocsfDecision) Judge(dir string, raw []byte) (*Result, error) {
	var manifest ocsfManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	find := func(format string, args ...any) {
		result.Findings = append(result.Findings, fmt.Sprintf(format, args...))
	}
	if manifest.Format.ClassUID != ocsfClassUID || manifest.Format.PayloadType != ocsfPayloadType {
		find("the manifest's format is class_uid %d and payload type %q, and the reader judges class_uid %d under %q",
			manifest.Format.ClassUID, manifest.Format.PayloadType, ocsfClassUID, ocsfPayloadType)
	}
	for _, profile := range []string{"baseline", "strict"} {
		if manifest.Profiles[profile] == "" {
			find("the manifest does not describe the %s profile", profile)
		}
	}
	listed := map[string]bool{}
	ids := map[string]bool{}
	var vectors []ocsfVector
	for _, entry := range manifest.Vectors {
		var v ocsfVector
		if err := json.Unmarshal(entry, &v); err != nil {
			find("a manifest row does not parse: %v", err)
			continue
		}
		vectors = append(vectors, v)
		if ids[v.ID] || listed[v.Path] {
			find("member %s: the manifest lists its id or its path twice", v.ID)
		}
		ids[v.ID], listed[v.Path] = true, true
		kind, findings := ocsfJudgeMember(dir, v)
		result.Members = append(result.Members, Member{ID: v.ID, Kind: kind, Findings: findings})
	}
	if len(vectors) == 0 {
		find("the manifest lists no member, so a clean verdict here would mean nothing")
	}
	for _, name := range ocsfUnlisted(dir, listed, find) {
		find("the member file %s is not listed in the manifest", name)
	}
	if finding := countsDisagree(manifest.Counts, result.CountsByVerdict()); finding != "" {
		find("%s", finding)
	}
	if finding := ocsfDigestFinding(dir, vectors, manifest.CorpusDigest); finding != "" {
		find("%s", finding)
	}
	for _, s := range ocsfSourceFindings(dir, manifest.Source) {
		find("%s", s)
	}
	return result, nil
}

// ocsfUnlisted names every member file in members/ the manifest does not list.
func ocsfUnlisted(dir string, listed map[string]bool, find func(string, ...any)) []string {
	entries, err := os.ReadDir(filepath.Join(dir, "members"))
	if err != nil {
		find("the members directory cannot be read: %v", err)
		return nil
	}
	var out []string
	for _, entry := range entries {
		rel := "members/" + entry.Name()
		if !listed[rel] {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// ocsfDigestFinding recomputes the corpus digest the way digest.py publishes it:
// SHA-256 over one line per member, "<path> <sha256 of the file>\n", in manifest
// order. A member file that cannot be read is a member finding, made where the
// member is judged; here it only leaves the digest unable to match.
func ocsfDigestFinding(dir string, vectors []ocsfVector, declared string) string {
	h := sha256.New()
	for _, v := range vectors {
		body, err := readIn(dir, v.Path)
		if err != nil {
			continue
		}
		h.Write([]byte(v.Path + " " + sha(body) + "\n"))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != declared {
		return fmt.Sprintf("the corpus digest does not recompute: manifest %s, members %s", short(declared), short(got))
	}
	return ""
}

// ocsfSourceFindings checks the vendored published samples against the SHA-256
// and length the manifest pins, and the manifest's pins against source/SOURCE.json.
func ocsfSourceFindings(dir string, pinned ocsfSourceDoc) []string {
	var out []string
	if len(pinned.Files) == 0 {
		return []string{"the manifest pins no vendored source file, so nothing records what this corpus certifies against"}
	}
	for _, name := range sortedKeys(pinned.Files) {
		rel, pin := "source/"+name, pinned.Files[name]
		if finding := checkVendored(dir, rel, pin.SHA256, "published sample"); finding != "" {
			out = append(out, finding)
			continue
		}
		if body, err := readIn(dir, rel); err == nil && len(body) != pin.Length {
			out = append(out, fmt.Sprintf("the vendored published sample %s is %d bytes, the manifest pins %d", rel, len(body), pin.Length))
		}
	}
	body, err := readIn(dir, "source/SOURCE.json")
	if err != nil {
		return append(out, fmt.Sprintf("source/SOURCE.json cannot be read: %v", err))
	}
	var doc ocsfSourceDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return append(out, fmt.Sprintf("source/SOURCE.json does not parse: %v", err))
	}
	if doc.Repository != pinned.Repository || doc.Commit != pinned.Commit || doc.Path != pinned.Path {
		out = append(out, "source/SOURCE.json names another repository, commit or path than the manifest")
	}
	for _, name := range sortedKeys(pinned.Files) {
		if doc.Files[name] != pinned.Files[name] {
			out = append(out, fmt.Sprintf("source/SOURCE.json pins %s differently from the manifest", name))
		}
	}
	for _, name := range sortedKeys(doc.Files) {
		if _, pinnedHere := pinned.Files[name]; !pinnedHere {
			out = append(out, fmt.Sprintf("source/SOURCE.json pins %s and the manifest does not", name))
		}
	}
	return out
}

// ocsfJudgeMember reads one member and returns the verdict it reads to (the
// declared verdict when the member cannot be read at all) with every way it
// behaves otherwise than the manifest declares.
func ocsfJudgeMember(dir string, v ocsfVector) (string, []string) {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	kind := v.Expected.Verdict
	if !filepath.IsLocal(v.Path) {
		return kind, []string{fmt.Sprintf("the path %q leaves the corpus directory", v.Path)}
	}
	if v.Path != "members/"+v.ID+".json" {
		add("the path %s is not members/%s.json", v.Path, v.ID)
	}
	body, err := readIn(dir, v.Path)
	if err != nil {
		return kind, append(out, fmt.Sprintf("%s cannot be read: %v", v.Path, err))
	}
	value, err := ocsfParseEnvelope(string(body))
	if err != nil {
		return kind, append(out, fmt.Sprintf("%s does not parse: %v", v.Path, err))
	}
	member, isObject := value.(map[string]any)
	records, hasRecords := member["records"].(string)
	if !isObject || !hasRecords {
		return kind, append(out, v.Path+" is not an object with a string `records`")
	}
	profile := "baseline"
	if p, present := member["profile"]; present {
		profile, _ = p.(string)
	}
	if profile != "baseline" && profile != "strict" {
		return kind, append(out, fmt.Sprintf("the member names profile %v, which is neither baseline nor strict", member["profile"]))
	}
	if profile != v.Profile {
		add("the member names profile %s and the manifest row names %q", profile, v.Profile)
	}
	rep := ocsfRead(records, member["trust_policy"], member["relying_party"])
	verdict, code := ocsfVerdict(rep, profile)
	kind = verdict
	declared := ""
	if v.Expected.Code != nil {
		declared = *v.Expected.Code
	}
	if verdict != v.Expected.Verdict || code != declared {
		add("read %s %q, the manifest declares %s %q", verdict, code, v.Expected.Verdict, declared)
	}
	return kind, append(out, ocsfDimensionFindings(rep, v.Expected.Dimensions)...)
}

// ocsfDimensionFindings compares every dimension a member declares with the one
// the reader reports. A declared name the report has no dimension for is a
// finding, never skipped.
func ocsfDimensionFindings(rep *ocsfReport, declared map[string]json.RawMessage) []string {
	var out []string
	check := func(label string, got ocsfDim, ok bool, want string) {
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: the reader has no such dimension", label))
		case got.status != want:
			out = append(out, fmt.Sprintf("%s: declared %s, read %s", label, want, got.status))
		}
	}
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "strict" {
			var want map[string]string
			if err := json.Unmarshal(declared[name], &want); err != nil {
				out = append(out, "strict: the declared dimensions are not an object of statuses")
				continue
			}
			for _, k := range sortedKeys(want) {
				got, ok := rep.strict[k]
				check("strict."+k, got, ok, want[k])
			}
			continue
		}
		var want string
		if err := json.Unmarshal(declared[name], &want); err != nil {
			out = append(out, fmt.Sprintf("%s: the declared status is not a string", name))
			continue
		}
		got, ok := rep.dims[name]
		check(name, got, ok, want)
	}
	return out
}

// ocsfSummary renders a report's statuses, one dimension per entry, for a test
// that has to say what a member read to.
func ocsfSummary(rep *ocsfReport) string {
	var parts []string
	for _, name := range ocsfReportDims() {
		parts = append(parts, name+"="+rep.dims[name].status)
	}
	for _, name := range ocsfStrictDims {
		parts = append(parts, "strict."+name+"="+rep.strict[name].status)
	}
	return strings.Join(parts, " ")
}
