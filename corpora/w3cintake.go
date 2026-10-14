package corpora

// The intake criteria for a submitted conformance result, judged in Go.
//
// packaging/agent_evidence_vectors/w3cintake.py is the reader this one is held
// to: the same 45 grounds, the same record shape, the same judge over
// vectors-w3c-intake/, and the same lines printed by aee-verify.
// scripts/w3c-intake-parity-test.py diffs the two over the committed corpus and
// over copies with one byte flipped in one member. The rules are the W3C
// public-agent-conformance group's (intake criteria v2, 2026Oct/0067, with the
// deltas of 0070, 0073 and 0075); the record shape is the Python module's, and
// its docstring says which field carries which rule.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func init() { register(w3cIntake{}) }

type w3cIntake struct{}

func (w3cIntake) Suite() string { return "w3c-intake-v2-conformance" }

const intakeFormat = "public-agent-conformance/intake-record/v2"

func wI(n int) string { return fmt.Sprintf("W3C-I-%03d", n) }

const intakeGrounds = 45

var (
	intakeStates           = set("pass", "fail", "inconclusive", "not-exercised", "void")
	intakeSelectorLangs    = set("id-glob")
	intakeSelectorRequire  = set("exactly-one", "at-least-one")
	intakeExitRules        = set("zero-iff-every-check-passes", "undeclared")
	intakeNativeFormats    = set("corpus-result-json-v1")
	intakeCarry            = set("carried", "referenced", "absent")
	intakeAnchorKinds      = set("digest-list-line")
	intakeAnchorVerdicts   = set("fail", "inconclusive", "not-exercised", "void")
	intakeRelationships    = set("same-implementation", "reference-derived", "written-from-specification")
	intakeEncodings        = set("jcs-sha256")
	intakeReplayStates     = set("stable", "varies", "not-measured")
	intakeOrderings        = set("emission-order", "sorted", "hash-order")
	intakeExposure         = set("visible", "hidden")
	intakeNativeClaims     = set("unchanged", "changed")
	intakeIsolationClaims  = set("isolates", "does-not-isolate")
	intakeAnchorFailures   = []string{"availability-failure", "integrity-failure"}
	intakeScopeLimits      = []string{"whole-attack-surface", "implementation-ranking", "threats-outside-corpus", "action-occurred-or-authority"}
	intakeInputLiterals    = set("aggregate", "exit-code")
	intakeIDFields         = []string{"kind", "family", "requirements", "root", "tree", "record", "expected"}
	intakeRevisionGitHexes = map[int]bool{40: true, 64: true}
)

// ---------------------------------------------------------------------------
// Small readers, each the Python helper of the same name.
// ---------------------------------------------------------------------------

func iObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func iStr(v any) bool { s, ok := v.(string); return ok && s != "" }

func iInt(v any) bool { _, ok := intValue(v); return ok }

func iStrs(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok || s == "" {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func iHex(v any, lengths map[int]bool) bool {
	s, ok := v.(string)
	if !ok || !lengths[len(s)] {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

var hex64 = map[int]bool{64: true}

func iField(v any, key string) any {
	if m, ok := v.(map[string]any); ok {
		return m[key]
	}
	return nil
}

func iList(v any, key string) []any {
	if items, ok := iField(v, key).([]any); ok {
		return items
	}
	return nil
}

func iIn(v any, allowed map[string]bool) bool {
	s, ok := v.(string)
	return ok && allowed[s]
}

func iEq(v any, want string) bool { s, ok := v.(string); return ok && s == want }

type listingEntry struct{ path, digest string }

// intakeListing is sha256-listing-v1: SHA-256 over "<sha256>  <path>\n" lines
// sorted by path (and by digest where two paths are equal).
func intakeListing(entries []listingEntry) string {
	sorted := append([]listingEntry(nil), entries...)
	sort.Slice(sorted, func(a, b int) bool {
		if sorted[a].path != sorted[b].path {
			return sorted[a].path < sorted[b].path
		}
		return sorted[a].digest < sorted[b].digest
	})
	var buf bytes.Buffer
	for _, e := range sorted {
		buf.WriteString(e.digest + "  " + e.path + "\n")
	}
	return sha(buf.Bytes())
}

// intakeGlob is id-glob: "*" matches any run of characters, anything else itself.
func intakeGlob(pattern, text string) bool {
	p, t, star, mark := 0, 0, -1, 0
	pr, tr := []rune(pattern), []rune(text)
	for t < len(tr) {
		switch {
		case p < len(pr) && pr[p] == '*':
			star, mark = p, t
			p++
		case p < len(pr) && pr[p] == tr[t]:
			p++
			t++
		case star >= 0:
			p = star + 1
			mark++
			t = mark
		default:
			return false
		}
	}
	for p < len(pr) && pr[p] == '*' {
		p++
	}
	return p == len(pr)
}

func intakeSafePath(v any) bool {
	rel, ok := v.(string)
	if !ok || rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return false
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func intakeRead(root string, rel any) ([]byte, bool) {
	if !intakeSafePath(rel) {
		return nil, false
	}
	path := filepath.Join(root, filepath.FromSlash(rel.(string)))
	if !existsIn(root, filepath.FromSlash(rel.(string))) {
		return nil, false
	}
	body, err := os.ReadFile(path) // #nosec G304 -- a path the record names, under the root the operator named
	if err != nil {
		return nil, false
	}
	return body, true
}

// intakeWalk lists the files under root/rel whose names end in suffix, as
// record paths, sorted.
func intakeWalk(root, rel, suffix string, recursive bool) []string {
	base := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Stat(base)
	if err != nil || !info.IsDir() {
		return nil
	}
	var found []string
	if recursive {
		_ = filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if st, err := os.Stat(path); err != nil || st.IsDir() {
				return nil
			}
			relPath, err := filepath.Rel(root, path)
			if err == nil {
				found = append(found, filepath.ToSlash(relPath))
			}
			return nil
		})
	} else {
		entries, _ := os.ReadDir(base)
		for _, e := range entries {
			if st, err := os.Stat(filepath.Join(base, e.Name())); err == nil && !st.IsDir() {
				found = append(found, rel+"/"+e.Name())
			}
		}
	}
	out := found[:0]
	for _, f := range found {
		if strings.HasSuffix(f, suffix) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

func intakeSourceListing(root string, paths []string) (string, bool) {
	var entries []listingEntry
	for _, rel := range paths {
		if !intakeSafePath(rel) {
			return "", false
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(full)
		if err != nil {
			return "", false
		}
		files := []string{rel}
		if info.IsDir() {
			files = intakeWalk(root, rel, "", true)
		}
		for _, name := range files {
			body, ok := intakeRead(root, name)
			if !ok {
				return "", false
			}
			entries = append(entries, listingEntry{name, sha(body)})
		}
	}
	return intakeListing(entries), true
}

// intakeDecodeStrict parses one JSON value and refuses trailing data, as
// Python's json.loads does.
func intakeDecodeStrict(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON value")
	}
	return value, nil
}

// ---------------------------------------------------------------------------
// The grounds.
// ---------------------------------------------------------------------------

type intakeFound map[string]bool

func (f intakeFound) add(n int) { f[wI(n)] = true }

func intakeManifestIDs(record map[string]any) ([]string, bool) {
	return iStrs(iField(record["manifest"], "ids"))
}

func intakeMemberIDs(record map[string]any) []string {
	var out []string
	for _, m := range iList(record, "members") {
		if id, ok := iField(m, "id").(string); ok && id != "" {
			if _, isObj := iObj(m); isObj {
				out = append(out, id)
			}
		}
	}
	return out
}

func intakeMemberFiles(record map[string]any) []listingEntry {
	var out []listingEntry
	for _, member := range iList(record, "members") {
		for _, pin := range iList(member, "files") {
			path, ok := iField(pin, "path").(string)
			if _, isObj := iObj(pin); isObj && ok && path != "" && iHex(iField(pin, "sha256"), hex64) {
				out = append(out, listingEntry{path, iField(pin, "sha256").(string)})
			}
		}
	}
	return out
}

func intakeMemberPins(record map[string]any, f intakeFound) {
	members, ok := record["members"].([]any)
	if !ok {
		f.add(1)
	}
	for _, member := range members {
		files, isList := iField(member, "files").([]any)
		if !iStr(iField(member, "id")) || !isList || len(files) == 0 {
			f.add(1)
			continue
		}
		for _, pin := range files {
			if _, isObj := iObj(pin); !isObj || !iStr(iField(pin, "path")) || !iHex(iField(pin, "sha256"), hex64) {
				f.add(1)
			}
		}
	}
	pinned := map[string]bool{}
	for _, id := range intakeMemberIDs(record) {
		pinned[id] = true
	}
	ids, _ := intakeManifestIDs(record)
	for _, id := range ids {
		if !pinned[id] {
			f.add(1)
		}
	}
}

func intakeCorpusDigest(record map[string]any, f intakeFound) {
	manifest := record["manifest"]
	digest := record["corpus-digest"]
	if !iStr(iField(manifest, "path")) || !iHex(iField(manifest, "sha256"), hex64) {
		f.add(2)
		return
	}
	if _, ok := iObj(digest); !ok || !iHex(iField(digest, "sha256"), hex64) {
		f.add(2)
		return
	}
	if !iEq(iField(digest, "serialization"), "sha256-listing-v1") {
		return
	}
	entries := append(intakeMemberFiles(record), listingEntry{
		iField(manifest, "path").(string), iField(manifest, "sha256").(string),
	})
	if intakeListing(entries) != iField(digest, "sha256").(string) {
		f.add(2)
	}
}

func intakePinsOnDisk(record map[string]any, root string, f intakeFound) {
	for _, e := range intakeMemberFiles(record) {
		body, ok := intakeRead(root, e.path)
		if !ok || sha(body) != e.digest {
			f.add(3)
		}
	}
	manifest := record["manifest"]
	path := iField(manifest, "path")
	if iStr(path) && iHex(iField(manifest, "sha256"), hex64) {
		body, ok := intakeRead(root, path)
		if !ok || sha(body) != iField(manifest, "sha256").(string) {
			f.add(2)
		}
	}
}

func intakeManifest(record map[string]any, f intakeFound) {
	manifest, isObj := iObj(record["manifest"])
	ids, ok := intakeManifestIDs(record)
	if !isObj || manifest["closed"] != true || !ok {
		f.add(4)
		return
	}
	known := map[string]bool{}
	for _, id := range ids {
		if known[id] {
			f.add(4)
		}
		known[id] = true
	}
	seen := map[string]bool{}
	for _, id := range intakeMemberIDs(record) {
		if seen[id] {
			f.add(4)
		}
		seen[id] = true
		if !known[id] {
			f.add(4)
		}
	}
}

type intakeLocation struct {
	dir, suffix string
	recursive   bool
}

func intakeBoundary(record map[string]any, f intakeFound) []intakeLocation {
	boundary, isObj := iObj(record["boundary"])
	locations, isList := iField(boundary, "member-locations").([]any)
	_, completeBool := iField(boundary, "complete").(bool)
	ok := isObj && intakeSafePath(boundary["root"]) && completeBool && isList && len(locations) > 0
	var out []intakeLocation
	if ok {
		for _, loc := range locations {
			dir, dirOK := iField(loc, "dir").(string)
			suffix, suffixOK := iField(loc, "suffix").(string)
			recursive, recOK := iField(loc, "recursive").(bool)
			if _, locObj := iObj(loc); !locObj || !dirOK || (dir != "" && !intakeSafePath(dir)) || !suffixOK || !recOK {
				ok = false
				continue
			}
			out = append(out, intakeLocation{dir, suffix, recursive})
		}
	}
	if !ok {
		f.add(9)
		return nil
	}
	return out
}

func intakeBoundaryOnDisk(record map[string]any, locations []intakeLocation, root string, f intakeFound) {
	boundary, _ := iObj(record["boundary"])
	if boundary["complete"] != true {
		return
	}
	pinned := map[string]bool{}
	for _, e := range intakeMemberFiles(record) {
		pinned[e.path] = true
	}
	base := boundary["root"].(string)
	for _, loc := range locations {
		rel := base
		if loc.dir != "" {
			rel = base + "/" + loc.dir
		}
		for _, path := range intakeWalk(root, rel, loc.suffix, loc.recursive) {
			if !pinned[path] {
				f.add(8)
			}
		}
	}
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func intakeSelection(record map[string]any, f intakeFound) ([]string, bool) {
	selector, isObj := iObj(record["selector"])
	ids, idsOK := intakeManifestIDs(record)
	selectedRaw, isList := iField(selector, "selected").([]any)
	var selected []string
	allStr := true
	for _, s := range selectedRaw {
		str, ok := s.(string)
		if !ok || str == "" {
			allStr = false
		}
		selected = append(selected, str)
	}
	_, exprOK := iField(selector, "expression").(string)
	matched, matchedOK := intValue(iField(selector, "matched"))
	if !(isObj && iIn(selector["language"], intakeSelectorLangs) && exprOK &&
		iIn(selector["require"], intakeSelectorRequire) && isList && allStr && matchedOK) {
		f.add(10)
		return nil, false
	}
	if !idsOK {
		return nil, false
	}
	expression := selector["expression"].(string)
	recomputed := []string{}
	for _, id := range ids {
		if intakeGlob(expression, id) {
			recomputed = append(recomputed, id)
		}
	}
	if !equalStrings(sortedCopy(recomputed), sortedCopy(selected)) {
		f.add(10)
	}
	if matched != int64(len(selected)) {
		f.add(10)
	}
	if len(recomputed) == 0 {
		f.add(11)
	} else if selector["require"] == "exactly-one" && len(recomputed) > 1 {
		f.add(12)
	}
	return recomputed, true
}

func intakeChecks(record map[string]any) []map[string]any {
	var out []map[string]any
	for _, c := range iList(record, "checks") {
		if m, ok := iObj(c); ok && iStr(m["check"]) {
			out = append(out, m)
		}
	}
	return out
}

func intakePopulation(record map[string]any, declared []string, declaredOK bool, f intakeFound) {
	if !declaredOK {
		declared, declaredOK = intakeManifestIDs(record)
	}
	if !declaredOK {
		return
	}
	seen := map[string]bool{}
	var order []string
	for _, c := range intakeChecks(record) {
		id := c["check"].(string)
		if seen[id] {
			f.add(6)
		} else {
			order = append(order, id)
		}
		seen[id] = true
	}
	inDeclared := map[string]bool{}
	for _, id := range declared {
		inDeclared[id] = true
		if !seen[id] {
			f.add(5)
		}
	}
	for _, id := range order {
		if !inDeclared[id] {
			f.add(7)
		}
	}
}

func intakeCarriedResult(record map[string]any, f intakeFound) bool {
	checks, isList := record["checks"].([]any)
	ok := isList
	for _, c := range checks {
		if m, isObj := iObj(c); !isObj || !iStr(m["check"]) || !iIn(m["state"], intakeStates) {
			ok = false
		}
	}
	aggregate, aggObj := iObj(record["aggregate"])
	counts, countsObj := iObj(iField(aggregate, "counts"))
	ok = ok && aggObj && iStr(aggregate["line"]) && iInt(aggregate["total"]) && countsObj
	for _, v := range counts {
		if !iInt(v) {
			ok = false
		}
	}
	ok = ok && iInt(record["exit-code"]) && iIn(record["exit-rule"], intakeExitRules)
	if !ok {
		f.add(13)
	}
	return ok
}

func intakeVerdict(check map[string]any) (string, bool) {
	v, ok := iField(check["native"], "verdict").(string)
	return v, ok && v != ""
}

func intakeRecount(record map[string]any, f intakeFound) {
	checks := record["checks"].([]any)
	aggregate := record["aggregate"].(map[string]any)
	total, _ := intValue(aggregate["total"])
	if total != int64(len(checks)) {
		f.add(14)
	}
	recount := map[string]int64{}
	for _, c := range checks {
		if v, ok := intakeVerdict(c.(map[string]any)); ok {
			recount[v]++
		}
	}
	printed := aggregate["counts"].(map[string]any)
	same := len(printed) == len(recount)
	for k, v := range printed {
		n, _ := intValue(v)
		if got, ok := recount[k]; !ok || got != n {
			same = false
		}
	}
	if !same {
		f.add(14)
	}
	everyPass := true
	for _, c := range checks {
		if c.(map[string]any)["state"] != "pass" {
			everyPass = false
		}
	}
	exitCode, _ := intValue(record["exit-code"])
	if record["exit-rule"] == "zero-iff-every-check-passes" && (exitCode == 0) != everyPass {
		f.add(14)
	}
	state := "fail"
	if everyPass {
		state = "pass"
	}
	if !iEq(record["state"], state) {
		f.add(15)
	}
	for _, c := range checks {
		check := c.(map[string]any)
		if reasons, ok := iField(check["native"], "reasons").([]any); ok {
			if (check["state"] == "pass") != (len(reasons) == 0) {
				f.add(15)
			}
		}
	}
}

func intakeRefusals(record map[string]any, f intakeFound) {
	verdicts, verdictsOK := iStrs(record["refusal-verdicts"])
	refusals, refusalsOK := record["refusals"].([]any)
	if !verdictsOK || !refusalsOK {
		f.add(16)
		return
	}
	refusing := map[string]bool{}
	for _, v := range verdicts {
		refusing[v] = true
	}
	named := map[string]map[string]any{}
	for _, item := range refusals {
		if m, ok := iObj(item); ok && iStr(m["check"]) {
			named[m["check"].(string)] = m
		}
	}
	members := map[string]bool{}
	for _, id := range intakeMemberIDs(record) {
		members[id] = true
	}
	returned := map[string]bool{}
	for _, c := range intakeChecks(record) {
		returned[c["check"].(string)] = true
	}
	for _, check := range intakeChecks(record) {
		verdict, hasVerdict := intakeVerdict(check)
		if !(hasVerdict && refusing[verdict]) && check["state"] != "fail" {
			continue
		}
		item := named[check["check"].(string)]
		inputs, inputsOK := iStrs(iField(item, "inputs"))
		if !iStr(iField(item, "rule")) || !inputsOK || len(inputs) == 0 {
			f.add(16)
			continue
		}
		for _, ref := range inputs {
			kind, name, _ := strings.Cut(ref, ":")
			inside := intakeInputLiterals[ref] ||
				(kind == "member" && members[name]) ||
				(kind == "check" && returned[name])
			if !inside {
				f.add(17)
			}
		}
	}
}

func intakeNative(record map[string]any, f intakeFound) {
	native, isObj := iObj(record["native"])
	status, statusOK := intValue(iField(iField(native, "process-status"), "exit-code"))
	summary := iField(native, "summary")
	if !(isObj && iIn(native["format"], intakeNativeFormats) && iStr(native["cases"]) &&
		(summary == nil || iStr(summary)) && statusOK) {
		f.add(18)
		return
	}
	for _, check := range intakeChecks(record) {
		_, hasVerdict := intakeVerdict(check)
		reasons, isList := iField(check["native"], "reasons").([]any)
		allStr := true
		for _, r := range reasons {
			if _, ok := r.(string); !ok {
				allStr = false
			}
		}
		if !hasVerdict || !isList || !allStr {
			f.add(18)
		}
	}
	if code, ok := intValue(record["exit-code"]); ok && status != code {
		f.add(19)
	}
}

func intakeObservation(record map[string]any, id any) (map[string]any, bool) {
	for _, item := range iList(record, "observations") {
		if m, ok := iObj(item); ok && jsonEqual(m["id"], id) {
			return m, true
		}
	}
	return nil, false
}

func intakeObservedBytes(record map[string]any, id any, root string) ([]byte, bool) {
	item, ok := intakeObservation(record, id)
	if !ok {
		return nil, false
	}
	if item["carry"] == "carried" {
		carried, ok := item["carried"].(string)
		return []byte(carried), ok
	}
	reference, isObj := iObj(item["reference"])
	if item["carry"] != "referenced" || !isObj {
		return nil, false
	}
	body, ok := intakeRead(root, reference["path"])
	if !ok || !iEq(reference["sha256"], sha(body)) {
		return nil, false
	}
	return body, true
}

func intakeCountText(value string) (int64, bool) {
	if len(value) == 0 || len(value) > 18 {
		return 0, false
	}
	var n int64
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

type intakeSummary struct {
	line   string
	total  int64
	counts map[string]int64
}

func intakeParseSummary(text string) (intakeSummary, bool) {
	out := intakeSummary{counts: map[string]int64{}}
	haveTotal, haveLine := false, false
	for _, raw := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(raw, "members: "):
			n, ok := intakeCountText(raw[len("members: "):])
			if !ok {
				return out, false
			}
			out.total, haveTotal = n, true
		case strings.HasPrefix(raw, "  ") && strings.Contains(raw, ": "):
			kind, value, _ := strings.Cut(raw[2:], ": ")
			n, ok := intakeCountText(value)
			if !ok {
				return out, false
			}
			out.counts[kind] = n
		case strings.HasPrefix(raw, "verdict: "):
			out.line, haveLine = raw, true
		}
	}
	return out, haveTotal && haveLine
}

func intakeNativeOnDisk(record map[string]any, root string, f intakeFound) {
	native, isObj := iObj(record["native"])
	if !isObj || !iIn(native["format"], intakeNativeFormats) {
		return
	}
	var document any
	if body, ok := intakeObservedBytes(record, native["cases"], root); ok {
		document, _ = intakeDecodeStrict(body)
	}
	members, isList := iField(document, "members").([]any)
	if !isList {
		f.add(19)
		return
	}
	nativeLines := make([]any, 0, len(members))
	for _, m := range members {
		reasons := iField(m, "findings")
		if reasons == nil {
			reasons = []any{}
		}
		nativeLines = append(nativeLines, []any{iField(m, "id"), iField(m, "kind"), reasons})
	}
	carriedLines := []any{}
	for _, c := range iList(record, "checks") {
		if m, ok := iObj(c); ok {
			carriedLines = append(carriedLines,
				[]any{m["check"], iField(m["native"], "verdict"), iField(m["native"], "reasons")})
		}
	}
	if !jsonEqual(nativeLines, carriedLines) {
		f.add(19)
	}
	summary := native["summary"]
	if summary == nil {
		return
	}
	text, ok := intakeObservedBytes(record, summary, root)
	var parsed intakeSummary
	if ok {
		parsed, ok = intakeParseSummary(string(text))
	}
	if !ok {
		f.add(19)
		return
	}
	aggregate := record["aggregate"]
	total, totalOK := intValue(iField(aggregate, "total"))
	carried, countsObj := iObj(iField(aggregate, "counts"))
	same := iEq(iField(aggregate, "line"), parsed.line) && totalOK && total == parsed.total &&
		countsObj && len(carried) == len(parsed.counts)
	for k, v := range carried {
		n, isInt := intValue(v)
		if want, ok := parsed.counts[k]; !isInt || !ok || n != want {
			same = false
		}
	}
	if !same {
		f.add(19)
	}
}

func intakeObservations(record map[string]any, f intakeFound) {
	observations, ok := record["observations"].([]any)
	if !ok {
		f.add(20)
		return
	}
	ids := map[string]bool{}
	for _, item := range observations {
		id, idOK := iField(item, "id").(string)
		carry := iField(item, "carry")
		if !idOK || id == "" || !iIn(carry, intakeCarry) || ids[id] {
			f.add(20)
			continue
		}
		ids[id] = true
		m := item.(map[string]any)
		switch carry {
		case "referenced":
			reference, isObj := iObj(m["reference"])
			if !isObj || !intakeSafePath(reference["path"]) || !iHex(reference["sha256"], hex64) {
				f.add(20)
			}
		case "carried":
			if _, present := m["carried"]; !present {
				f.add(21)
			}
		}
	}
}

func intakeAnchor(record map[string]any, f intakeFound) {
	anchor, isObj := iObj(record["anchor"])
	reference, refObj := iObj(iField(anchor, "reference"))
	verdicts, verdictsObj := iObj(iField(anchor, "verdicts"))
	ok := isObj && iIn(anchor["kind"], intakeAnchorKinds) && refObj && iStr(reference["uri"]) &&
		intakeSafePath(reference["path"]) && iHex(anchor["sha256"], hex64) && iStr(anchor["manifest"]) &&
		jsonEqual(anchor["manifest"], iField(record["manifest"], "path")) && verdictsObj
	for _, k := range intakeAnchorFailures {
		if !iIn(verdicts[k], intakeAnchorVerdicts) {
			ok = false
		}
	}
	if !ok {
		f.add(22)
	}
}

func intakeBinds(line string, digest, manifest any) bool {
	if strings.HasPrefix(line, "#") {
		return false
	}
	var fields []string
	for _, field := range strings.Split(line, " ") {
		if field != "" {
			fields = append(fields, field)
		}
	}
	return len(fields) >= 2 && iEq(digest, fields[0]) && iEq(manifest, fields[1])
}

func intakeAnchorOnDisk(record map[string]any, root string, f intakeFound) {
	anchor := record["anchor"]
	path := iField(iField(anchor, "reference"), "path")
	if !intakeSafePath(path) {
		return
	}
	body, ok := intakeRead(root, path)
	if !ok {
		f.add(23)
		return
	}
	want, manifest := iField(anchor, "sha256"), iField(anchor, "manifest")
	bound := false
	for _, line := range strings.Split(string(body), "\n") {
		if intakeBinds(line, want, manifest) {
			bound = true
		}
	}
	if !bound {
		f.add(24)
		return
	}
	var declared any
	if iStr(manifest) {
		if pinned, ok := intakeRead(root, manifest); ok {
			if document, err := intakeDecodeStrict(pinned); err == nil {
				declared = iField(document, "corpusDigest")
			}
		}
	}
	if !jsonEqual(declared, want) || declared == nil {
		f.add(24)
	}
}

func intakeSerializations(record map[string]any, f intakeFound) {
	declared := iEq(record["pin-serialization"], "bytes") &&
		iEq(iField(record["corpus-digest"], "serialization"), "sha256-listing-v1")
	if anchor, ok := iObj(record["anchor"]); ok {
		declared = declared && iEq(anchor["serialization"], "corpus-routine") && iStr(anchor["routine"])
	}
	checker := record["checker"]
	revision := iField(checker, "revision")
	if iEq(iField(revision, "kind"), "source-listing") {
		declared = declared && iEq(iField(revision, "serialization"), "sha256-listing-v1")
	}
	for _, key := range []string{"dependencies", "helpers"} {
		for _, item := range iList(checker, key) {
			declared = declared && iEq(iField(item, "serialization"), "bytes")
		}
	}
	for _, item := range iList(record, "observations") {
		reference, isObj := iObj(iField(item, "reference"))
		if iEq(iField(item, "carry"), "referenced") && isObj {
			declared = declared && iEq(reference["serialization"], "bytes")
		}
	}
	if !declared {
		f.add(33)
	}
	if !iIn(iField(record["canonicalization"], "encoding"), intakeEncodings) {
		f.add(32)
	}
}

func intakeRevisionPinned(revision any) bool {
	switch iField(revision, "kind") {
	case "git-commit":
		return iHex(iField(revision, "value"), intakeRevisionGitHexes)
	case "source-listing":
		paths, ok := iStrs(iField(revision, "paths"))
		if !ok || len(paths) == 0 {
			return false
		}
		for _, p := range paths {
			if !intakeSafePath(p) {
				return false
			}
		}
		return iHex(iField(revision, "sha256"), hex64)
	}
	return false
}

func intakeChecker(record map[string]any, f intakeFound) {
	checker := record["checker"]
	commands, commandsOK := iStrs(iField(checker, "commands"))
	if !intakeRevisionPinned(iField(checker, "revision")) || !commandsOK || len(commands) == 0 {
		f.add(25)
	}
	runtime, runtimeObj := iObj(iField(checker, "runtime"))
	dependencies, depsList := iField(checker, "dependencies").([]any)
	ok := runtimeObj && iStr(runtime["name"]) && iStr(runtime["version"]) && depsList
	for _, d := range dependencies {
		if _, isObj := iObj(d); !isObj || !intakeSafePath(iField(d, "path")) || !iHex(iField(d, "sha256"), hex64) {
			ok = false
		}
	}
	if !ok {
		f.add(26)
	}
	helpers, helpersList := iField(checker, "helpers").([]any)
	ok = helpersList
	for _, h := range helpers {
		if _, isObj := iObj(h); !isObj || !iStr(iField(h, "uri")) || !iHex(iField(h, "sha256"), hex64) {
			ok = false
		}
	}
	if !ok {
		f.add(27)
	}
	readers := append([]any{checker}, iList(record, "non-author-runs")...)
	for _, reader := range readers {
		relationship := iField(reader, "relationship")
		if !iIn(relationship, intakeRelationships) {
			f.add(29)
			continue
		}
		shared, sharedOK := iStrs(iField(reader, "shared-verification-code"))
		switch {
		case !sharedOK:
			f.add(30)
		case relationship == "written-from-specification" && len(shared) > 0:
			f.add(30)
		case relationship == "same-implementation" && len(shared) == 0:
			f.add(30)
		}
	}
	specReaders, isList := record["specification-readers"].([]any)
	ok = isList
	for _, r := range specReaders {
		if _, isObj := iObj(r); !isObj || !iStr(iField(r, "reader")) {
			ok = false
		}
	}
	if !ok {
		f.add(31)
	}
}

func intakeCheckerOnDisk(record map[string]any, root string, f intakeFound) {
	checker := record["checker"]
	revision := iField(checker, "revision")
	if paths, ok := iStrs(iField(revision, "paths")); ok && iEq(iField(revision, "kind"), "source-listing") {
		recomputed, ok := intakeSourceListing(root, paths)
		if !ok || !iEq(iField(revision, "sha256"), recomputed) {
			f.add(25)
		}
	}
	for _, dep := range iList(checker, "dependencies") {
		if _, isObj := iObj(dep); isObj && intakeSafePath(iField(dep, "path")) {
			body, ok := intakeRead(root, iField(dep, "path"))
			if !ok || !iEq(iField(dep, "sha256"), sha(body)) {
				f.add(26)
			}
		}
	}
	for _, helper := range iList(checker, "helpers") {
		if _, isObj := iObj(helper); !isObj {
			continue
		}
		body, ok := intakeRead(root, iField(helper, "path"))
		if !ok || !iEq(iField(helper, "sha256"), sha(body)) {
			f.add(28)
		}
	}
}

func intakeReplay(record map[string]any, f intakeFound) {
	identity, identityObj := iObj(record["byte-identity"])
	stability, stabilityObj := iObj(record["replay-stability"])
	pins, pinsOK := intValue(iField(identity, "pins"))
	runs, runsList := iField(stability, "runs").([]any)
	state := iField(stability, "state")
	ok := identityObj && pinsOK && pins == int64(len(intakeMemberFiles(record))) &&
		stabilityObj && iIn(state, intakeReplayStates) && runsList &&
		(state == "not-measured" || len(runs) >= 2)
	for _, r := range runs {
		if _, isObj := iObj(r); !isObj || !iStr(iField(r, "process")) || !iHex(iField(r, "sha256"), hex64) {
			ok = false
		}
	}
	if !ok {
		f.add(34)
		return
	}
	if len(runs) == 0 {
		return
	}
	ordering := stability["ordering"]
	if !iIn(ordering, intakeOrderings) || (ordering == "hash-order" && !iStr(stability["seed"])) {
		f.add(35)
	}
	digests := map[string]bool{}
	for _, r := range runs {
		digests[iField(r, "sha256").(string)] = true
	}
	if len(digests) > 1 && state == "stable" {
		f.add(36)
	}
	if len(digests) > 1 && state == "varies" && !iStr(stability["cause"]) {
		f.add(37)
	}
}

func intakeFaults(record map[string]any, f intakeFound) {
	if !iIn(record["exposure"], intakeExposure) {
		f.add(38)
	}
	returned := map[string]bool{}
	for _, c := range intakeChecks(record) {
		returned[c["check"].(string)] = true
	}
	faults, ok := record["faults"].([]any)
	if !ok {
		f.add(39)
	}
	for _, fault := range faults {
		id, idOK := iField(fault, "id").(string)
		if !idOK || id == "" || !iStr(iField(fault, "injected")) {
			f.add(39)
		} else if returned[id] {
			f.add(39)
		}
		if !iIn(iField(iField(fault, "result"), "state"), intakeStates) {
			f.add(40)
		}
	}
}

func intakeControlResult(v any) (string, []string, bool) {
	grounds, ok := iStrs(iField(v, "grounds"))
	state, stateOK := iField(v, "state").(string)
	_, isObj := iObj(v)
	return state, grounds, isObj && ok && stateOK && intakeStates[state]
}

func intakeRelaxedControls(record map[string]any, f intakeFound) {
	controls, ok := record["relaxed-controls"].([]any)
	if !ok {
		f.add(41)
		return
	}
	for _, control := range controls {
		baseState, baseGrounds, baseOK := intakeControlResult(iField(control, "baseline"))
		relState, relGrounds, relOK := intakeControlResult(iField(control, "relaxed"))
		if !iStr(iField(control, "relaxed-check")) || !relOK || !baseOK {
			f.add(41)
			continue
		}
		unchanged := baseState == relState && equalStrings(sortedCopy(baseGrounds), sortedCopy(relGrounds))
		native := iField(control, "native-claim")
		if !iIn(native, intakeNativeClaims) || (native == "unchanged") != unchanged {
			f.add(42)
		}
		isolates := relState == "pass" && len(relGrounds) == 0
		isolation := iField(control, "isolation-claim")
		if !iIn(isolation, intakeIsolationClaims) || (isolation == "isolates") != isolates {
			f.add(43)
		}
	}
}

func intakeScope(record map[string]any, f intakeFound) {
	scope := record["scope"]
	establishes, estOK := iStrs(iField(scope, "establishes"))
	leaves, leavesOK := iStrs(iField(scope, "leaves-open"))
	if !estOK || len(establishes) == 0 || !leavesOK || len(leaves) == 0 {
		f.add(44)
		if !estOK {
			establishes = nil
		}
	}
	disclaimed, _ := iStrs(iField(scope, "does-not-claim"))
	has := func(values []string, want string) bool {
		for _, v := range values {
			if v == want {
				return true
			}
		}
		return false
	}
	for _, limit := range intakeScopeLimits {
		if !has(disclaimed, limit) || has(establishes, limit) {
			f.add(45)
		}
	}
}

// intakeRejections is rejections() of the Python reader: the sorted grounds a
// record is refused under, reading bytes on disk only when hasRoot is set.
func intakeRejections(value any, root string, hasRoot bool) []string {
	f := intakeFound{}
	record, ok := iObj(value)
	if !ok || !iEq(record["format"], intakeFormat) {
		for n := 1; n <= intakeGrounds; n++ {
			f.add(n)
		}
		return intakeSorted(f)
	}
	intakeMemberPins(record, f)
	intakeCorpusDigest(record, f)
	intakeManifest(record, f)
	locations := intakeBoundary(record, f)
	declared, declaredOK := intakeSelection(record, f)
	intakePopulation(record, declared, declaredOK, f)
	if intakeCarriedResult(record, f) {
		intakeRecount(record, f)
	}
	intakeRefusals(record, f)
	intakeNative(record, f)
	intakeObservations(record, f)
	intakeAnchor(record, f)
	intakeChecker(record, f)
	intakeSerializations(record, f)
	intakeReplay(record, f)
	intakeFaults(record, f)
	intakeRelaxedControls(record, f)
	intakeScope(record, f)
	if hasRoot {
		intakePinsOnDisk(record, root, f)
		if locations != nil {
			intakeBoundaryOnDisk(record, locations, root, f)
		}
		intakeNativeOnDisk(record, root, f)
		intakeAnchorOnDisk(record, root, f)
		intakeCheckerOnDisk(record, root, f)
	}
	return intakeSorted(f)
}

func intakeSorted(f intakeFound) []string {
	out := make([]string, 0, len(f))
	for ground := range f {
		out = append(out, ground)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// The judge.
// ---------------------------------------------------------------------------

func intakeTreeDigest(dir, rel string) string {
	var entries []listingEntry
	for _, path := range intakeWalk(dir, rel, "", true) {
		body, _ := intakeRead(dir, path)
		entries = append(entries, listingEntry{path[len(rel)+1:], sha(body)})
	}
	return intakeListing(entries)
}

func intakeIdentify(document map[string]any) (string, bool) {
	payload := map[string]any{}
	for _, k := range intakeIDFields {
		payload[k] = document[k]
	}
	raw, err := pythonCompactJSON(payload)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(raw)
	return "v" + hex.EncodeToString(sum[:])[:16], true
}

func (w3cIntake) Judge(dir string, raw []byte) (*Result, error) {
	value, err := decodeJSONNumbers(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestName, err)
	}
	manifest, ok := iObj(value)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", ManifestName)
	}
	result := &Result{Suite: w3cIntake{}.Suite(), Dir: dir}
	known := map[string]bool{}
	var knownOrder []string
	for _, row := range iList(manifest, "requirements") {
		id, _ := iField(row, "id").(string)
		if known[id] {
			result.Findings = append(result.Findings, id+": duplicate requirement identifier")
		}
		if !known[id] {
			knownOrder = append(knownOrder, id)
		}
		known[id] = true
		result.Findings = append(result.Findings, intakeRequirementFindings(dir, row)...)
	}
	seen := map[string]bool{}
	for _, entry := range iList(manifest, "vectors") {
		id, _ := iField(entry, "id").(string)
		kind, _ := iField(entry, "kind").(string)
		member := Member{ID: id, Kind: kind}
		if seen[id] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[id] = true
		member.Findings = append(member.Findings, intakeMemberFindings(dir, manifest, entry, known)...)
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, intakeCorpusFindings(dir, manifest, knownOrder)...)
	return result, nil
}

func intakeRequirementFindings(dir string, row any) []string {
	rid := pyRepr(iField(row, "id"))
	vendored := iField(row, "vendored")
	body, ok := intakeRead(dir, vendored)
	if !ok {
		return []string{fmt.Sprintf("%s: names a vendored file %v that is not here", rid, vendored)}
	}
	text := string(body)
	sentence, isStr := iField(row, "sentence").(string)
	ascii := isStr
	for _, c := range sentence {
		if c > 0x7F {
			ascii = false
		}
	}
	if !ascii {
		return []string{rid + ": the pinned sentence is not ASCII"}
	}
	var out []string
	if !iEq(iField(row, "sentenceDigest"), sha([]byte(sentence))) {
		out = append(out, rid+": the pinned sentence digest does not recompute from the sentence")
	}
	index := strings.Index(text, sentence)
	if index < 0 {
		return append(out, rid+": quotes a sentence the vendored copy no longer carries")
	}
	if strings.Contains(text[index+1:], sentence) {
		out = append(out, rid+": quotes a sentence that appears more than once, so it identifies nothing")
	}
	line := int64(strings.Count(text[:index], "\n") + 1)
	if recorded, ok := intValue(iField(row, "line")); !ok || recorded != line {
		out = append(out, fmt.Sprintf("%s: records line %s and the sentence sits on line %d",
			rid, pyRepr(iField(row, "line")), line))
	}
	return out
}

// pyRepr prints a decoded JSON scalar the way a Python f-string prints it.
func pyRepr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		return x.String()
	case string:
		return x
	}
	raw, _ := pythonCompactJSON(v)
	return string(raw)
}

func intakeMemberFindings(dir string, manifest map[string]any, entry any, known map[string]bool) []string {
	var out []string
	want := intakeEntryVocabulary(manifest, entry, known, &out)
	document, ok := intakeLoadDocument(dir, entry, &out)
	if !ok {
		return out
	}
	root, hasRoot, usable := intakeMemberRoot(dir, document, &out)
	if !usable {
		return out
	}
	observed := intakeRejections(document["record"], root, hasRoot)
	sort.Strings(want)
	if !equalStrings(observed, want) {
		out = append(out, fmt.Sprintf("the checker refuses under %s and the manifest expects %s",
			w3cList(observed), w3cList(want)))
	}
	return out
}

func intakeEntryVocabulary(manifest map[string]any, entry any, known map[string]bool, out *[]string) []string {
	kind := iField(entry, "kind")
	if !iIn(kind, set("accept", "reject")) {
		*out = append(*out, "declares kind "+pyRepr(kind))
	}
	families, _ := iObj(manifest["families"])
	family, familyOK := iField(entry, "family").(string)
	if _, defined := families[family]; !familyOK || !defined {
		*out = append(*out, "cites family "+pyRepr(iField(entry, "family"))+" the manifest does not define")
	}
	requirements, _ := iField(entry, "requirements").([]any)
	cited := map[string]bool{}
	for _, r := range requirements {
		rid, _ := r.(string)
		cited[rid] = true
		if !known[rid] {
			*out = append(*out, "cites requirement "+pyRepr(r)+" the manifest does not carry")
		}
	}
	if len(requirements) == 0 {
		*out = append(*out, "cites no requirement, so a specification change cannot tell it broke")
	}
	expected, _ := iObj(iField(entry, "expected"))
	if !jsonEqual(expected["verdict"], kind) {
		*out = append(*out, "expects a verdict that is not its kind")
	}
	rejects, isList := expected["rejects"].([]any)
	if !isList {
		*out = append(*out, "declares no rejects list")
		return nil
	}
	if kind == "accept" && len(rejects) > 0 {
		*out = append(*out, "is an accept member that expects a rejection")
	}
	if kind == "reject" && len(rejects) != 1 {
		*out = append(*out, "is a reject member that does not name exactly one ground")
	}
	var want []string
	for _, r := range rejects {
		rid := pyRepr(r)
		if !cited[rid] {
			*out = append(*out, "expects rejection under "+rid+" and does not cite it")
		}
		want = append(want, rid)
	}
	return want
}

func intakeLoadDocument(dir string, entry any, out *[]string) (map[string]any, bool) {
	body, ok := intakeRead(dir, iField(entry, "file"))
	if !ok {
		*out = append(*out, "the manifest names a vector file that does not exist")
		return nil, false
	}
	value, err := intakeDecodeStrict(body)
	if err != nil {
		*out = append(*out, "the vector file does not parse")
		return nil, false
	}
	document, ok := iObj(value)
	if !ok {
		*out = append(*out, "the vector file is not a JSON object")
		return nil, false
	}
	for _, field := range []string{"kind", "family", "requirements", "expected", "root"} {
		if !jsonEqual(document[field], iField(entry, field)) {
			*out = append(*out, "the vector file and the manifest disagree about "+field)
		}
	}
	if !jsonEqual(document["id"], iField(entry, "id")) {
		*out = append(*out, "the vector file carries a different identifier")
	}
	if id, ok := intakeIdentify(document); !ok || !iEq(iField(entry, "id"), id) {
		*out = append(*out, "identifier does not recompute from the member's own bytes")
	}
	return document, true
}

// intakeMemberRoot is the directory a member's record is judged under. The
// third result is false when the member names a root that is not here.
func intakeMemberRoot(dir string, document map[string]any, out *[]string) (string, bool, bool) {
	rel := document["root"]
	if rel == nil {
		if document["tree"] != nil {
			*out = append(*out, "the member carries a tree digest and no root")
		}
		return "", false, true
	}
	if !intakeSafePath(rel) {
		*out = append(*out, "the member names a root "+pyRepr(rel)+" that is not a directory here")
		return "", false, false
	}
	full := filepath.Join(dir, filepath.FromSlash(rel.(string)))
	if info, err := os.Stat(full); err != nil || !info.IsDir() {
		*out = append(*out, "the member names a root "+pyRepr(rel)+" that is not a directory here")
		return "", false, false
	}
	if !iEq(document["tree"], intakeTreeDigest(dir, rel.(string))) {
		*out = append(*out, "the tree under the member's root does not match its tree digest")
	}
	return full, true, true
}

func intakeCorpusDigestOf(dir string, manifest map[string]any) string {
	var entries []listingEntry
	roots := map[string]bool{}
	for _, entry := range iList(manifest, "vectors") {
		if body, ok := intakeRead(dir, iField(entry, "file")); ok {
			entries = append(entries, listingEntry{iField(entry, "file").(string), sha(body)})
		}
		if root, ok := iField(entry, "root").(string); ok && root != "" {
			roots[root] = true
		}
	}
	for root := range roots {
		for _, path := range intakeWalk(dir, root, "", true) {
			body, _ := intakeRead(dir, path)
			entries = append(entries, listingEntry{path, sha(body)})
		}
	}
	return intakeListing(entries)
}

func intakeCorpusFindings(dir string, manifest map[string]any, known []string) []string {
	var out []string
	accepting, rejecting := map[string]bool{}, map[string]bool{}
	for _, entry := range iList(manifest, "vectors") {
		target := rejecting
		if iField(entry, "kind") == "accept" {
			target = accepting
		}
		for _, r := range iList(entry, "requirements") {
			if s, ok := r.(string); ok {
				target[s] = true
			}
		}
	}
	sortedKnown := sortedCopy(known)
	var noAccept, noReject []string
	for _, r := range sortedKnown {
		if !accepting[r] {
			noAccept = append(noAccept, r)
		}
		if !rejecting[r] {
			noReject = append(noReject, r)
		}
	}
	if len(noAccept) > 0 {
		out = append(out, "grounds no accept member passes: "+w3cList(noAccept))
	}
	if len(noReject) > 0 {
		out = append(out, "grounds no reject member is refused under: "+w3cList(noReject))
	}
	families, _ := iObj(manifest["families"])
	used := map[string]bool{}
	for _, entry := range iList(manifest, "vectors") {
		if s, ok := iField(entry, "family").(string); ok {
			used[s] = true
		}
	}
	var unused []string
	for family := range families {
		if !used[family] {
			unused = append(unused, family)
		}
	}
	if len(unused) > 0 {
		out = append(out, "families declared and carried by no member: "+w3cList(sortedCopy(unused)))
	}
	out = append(out, intakeVendoredFindings(dir, manifest)...)
	accept, reject := int64(0), int64(0)
	for _, entry := range iList(manifest, "vectors") {
		switch iField(entry, "kind") {
		case "accept":
			accept++
		case "reject":
			reject++
		}
	}
	counts, _ := iObj(manifest["counts"])
	gotAccept, okA := intValue(counts["accept"])
	gotReject, okR := intValue(counts["reject"])
	if len(counts) != 2 || !okA || !okR || gotAccept != accept || gotReject != reject {
		out = append(out, fmt.Sprintf("counts disagree: manifest %s, measured {accept=%d, reject=%d}",
			intakeRenderCounts(counts), accept, reject))
	}
	if !iEq(manifest["corpusDigest"], intakeCorpusDigestOf(dir, manifest)) {
		out = append(out, "corpusDigest does not match the vector files on disk")
	}
	return out
}

func intakeRenderCounts(counts map[string]any) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+pyRepr(counts[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func intakeVendoredFindings(dir string, manifest map[string]any) []string {
	pins, _ := iObj(manifest["specVendored"])
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, key := range keys {
		path := iField(pins[key], "path")
		body, ok := intakeRead(dir, path)
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("the vendored file for %s %s is missing", key, pyRepr(path)))
		case !iEq(iField(pins[key], "sha256"), sha(body)):
			out = append(out, fmt.Sprintf("the vendored file for %s %s does not match its pinned digest", key, pyRepr(path)))
		}
	}
	return out
}
