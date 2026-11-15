package corpusreaders

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func init() { register(aveIDResolution{}) }

// aveIDResolution judges corpora/vectors-ave-id-resolution/. Each member is a
// tool's SARIF or JSON findings output and a release of the AVE records file
// pinned by its SHA-256; the reader answers whether every AVE id the output
// carries resolves to an active record. It reads ids where resolve_ids.py
// reads them and applies the same four rules, so the two readers answer every
// member the same way: resolves, fails with its codes, no-ids, or unreadable.
type aveIDResolution struct{}

func (aveIDResolution) Suite() string { return "ave-id-resolution/v1" }

var (
	aveID        = regexp.MustCompile(`^AVE-[0-9]{4}-[0-9]{5}$`)
	aveJSONIDKey = regexp.MustCompile(`(?i)^ave[_-]?ids?$`)
)

type aveSnapshotPin struct {
	Files         map[string]string `json:"files"`
	RecordsSha256 string            `json:"recordsSha256"`
}

type aveVector struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Sha256   string `json:"sha256"`
	Snapshot string `json:"snapshot"`
	Expected struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
}

type aveManifest struct {
	CorpusDigest string                    `json:"corpusDigest"`
	Rules        []string                  `json:"rules"`
	Snapshots    map[string]aveSnapshotPin `json:"snapshots"`
	Vectors      []aveVector               `json:"vectors"`
}

// aveClaim is one value read as an AVE id, and where it was read.
type aveClaim struct {
	value any
	where string
}

func (aveIDResolution) Judge(dir string, raw []byte) (*Result, error) {
	var manifest aveManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	if finding := aveCorpusDigest(dir, manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	seen := map[string]bool{}
	for _, v := range manifest.Vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Verdict}
		pin, known := manifest.Snapshots[v.Snapshot]
		if !known {
			member.Findings = append(member.Findings, fmt.Sprintf("names snapshot %q, which the manifest does not pin", v.Snapshot))
			result.Members = append(result.Members, member)
			continue
		}
		if body, err := os.ReadFile(filepath.Join(dir, v.Path)); err != nil || sha(body) != v.Sha256 { // #nosec G304 -- a member file named by the manifest
			member.Findings = append(member.Findings, v.Path+": the output is not the bytes the manifest pins")
		}
		snapshot := filepath.Join(dir, "snapshots", v.Snapshot, "ave-records.json")
		verdict, codes := aveRun(filepath.Join(dir, v.Path), snapshot, pin.RecordsSha256)
		for _, code := range codes {
			seen[code] = true
		}
		want := append([]string{}, v.Expected.Codes...)
		if verdict != v.Expected.Verdict || strings.Join(codes, ",") != strings.Join(want, ",") {
			member.Findings = append(member.Findings, fmt.Sprintf("answered %s [%s], the manifest declares %s [%s]",
				verdict, strings.Join(codes, " "), v.Expected.Verdict, strings.Join(want, " ")))
		}
		result.Members = append(result.Members, member)
	}
	for _, rule := range manifest.Rules {
		if !seen[rule] {
			result.Findings = append(result.Findings, fmt.Sprintf("rule %s: produced by no member", rule))
		}
	}
	return result, nil
}

// aveSnapshotFiles is snapshot_files of gen_vectors.py: every vendored release
// asset matches the release's SHA256SUMS, the file set is exactly those assets,
// and ave-records.json is the pinned bytes.
func aveSnapshotFiles(dir, release string, pin aveSnapshotPin) (map[string]string, error) {
	directory := filepath.Join(dir, "snapshots", release)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", release, err)
	}
	files := map[string]string{}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			body, err := os.ReadFile(filepath.Join(directory, entry.Name())) // #nosec G304 -- a file of the corpus being judged
			if err != nil {
				return nil, fmt.Errorf("snapshot %s: %w", release, err)
			}
			files[entry.Name()] = sha(body)
		}
	}
	sums, err := os.ReadFile(filepath.Join(directory, "SHA256SUMS")) // #nosec G304 -- a file of the corpus being judged
	if err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", release, err)
	}
	listed := map[string]bool{"SHA256SUMS": true}
	scanner := bufio.NewScanner(bytes.NewReader(sums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		listed[name] = true
		if files[name] != fields[0] {
			return nil, fmt.Errorf("snapshot %s/%s: does not match the release SHA256SUMS", release, name)
		}
	}
	if len(listed) != len(files) {
		return nil, fmt.Errorf("snapshot %s: file set differs from SHA256SUMS", release)
	}
	for name := range files {
		if !listed[name] {
			return nil, fmt.Errorf("snapshot %s: file set differs from SHA256SUMS", release)
		}
	}
	if files["ave-records.json"] != pin.RecordsSha256 {
		return nil, fmt.Errorf("snapshot %s: ave-records.json is not the pinned bytes", release)
	}
	return files, nil
}

// aveCorpusDigest is corpus_digest of gen_vectors.py, recomputed from the files
// on disk: the sorted [path, sha256] pairs of every snapshot asset and every
// member output, as compact JSON.
func aveCorpusDigest(dir string, manifest aveManifest) string {
	var entries [][2]string
	for release, pin := range manifest.Snapshots {
		files, err := aveSnapshotFiles(dir, release, pin)
		if err != nil {
			return err.Error()
		}
		if len(files) != len(pin.Files) {
			return fmt.Sprintf("snapshot %s: file digests differ from the manifest", release)
		}
		for name, digest := range files {
			if pin.Files[name] != digest {
				return fmt.Sprintf("snapshot %s: file digests differ from the manifest", release)
			}
			entries = append(entries, [2]string{"snapshots/" + release + "/" + name, digest})
		}
	}
	for _, v := range manifest.Vectors {
		body, err := os.ReadFile(filepath.Join(dir, v.Path)) // #nosec G304 -- a member file named by the manifest
		if err != nil || sha(body) != v.Sha256 {
			return v.ID + ": file digest mismatch"
		}
		entries = append(entries, [2]string{v.Path, v.Sha256})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i][0] != entries[j][0] {
			return entries[i][0] < entries[j][0]
		}
		return entries[i][1] < entries[j][1]
	})
	encoded, err := json.Marshal(entries)
	if err != nil {
		return fmt.Sprintf("the digest entries cannot be encoded: %v", err)
	}
	if got := sha(encoded); got != manifest.CorpusDigest {
		return fmt.Sprintf("corpusDigest %s does not match the recomputed %s", short(manifest.CorpusDigest), short(got))
	}
	return ""
}

// aveRun is run() of resolve_ids.py: an unreadable input answers unreadable.
func aveRun(output, snapshot, pinned string) (string, []string) {
	statuses, err := aveLoadSnapshot(snapshot, pinned)
	if err != nil {
		return "unreadable", []string{}
	}
	body, err := os.ReadFile(output) // #nosec G304 -- a member file named by the manifest
	if err != nil {
		return "unreadable", []string{}
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "unreadable", []string{}
	}
	return aveJudge(doc, statuses, pinned)
}

// aveStatus is a record's status, and whether the record carried one.
type aveStatus struct {
	value string
	set   bool
}

func aveLoadSnapshot(path, pinned string) (map[string]aveStatus, error) {
	body, err := os.ReadFile(path) // #nosec G304 -- the snapshot file of the corpus being judged
	if err != nil {
		return nil, err
	}
	if sha(body) != strings.ToLower(pinned) {
		return nil, fmt.Errorf("snapshot sha256 is not the pin")
	}
	var records []any
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, err
	}
	statuses := map[string]aveStatus{}
	for _, item := range records {
		record, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("snapshot is not a list of records carrying ave_id")
		}
		id, ok := record["ave_id"].(string)
		if !ok {
			return nil, fmt.Errorf("snapshot is not a list of records carrying ave_id")
		}
		status, isString := record["status"].(string)
		statuses[id] = aveStatus{value: status, set: isString}
	}
	return statuses, nil
}

func aveObject(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

func aveList(value any) []any {
	list, _ := value.([]any)
	return list
}

func aveClaimsAVE(value any) bool {
	s, ok := value.(string)
	return ok && strings.HasPrefix(strings.ToUpper(s), "AVE-")
}

// aveText is str() of a declared digest: the string itself, else its JSON.
func aveText(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}

func aveSARIF(doc map[string]any) ([]aveClaim, []string) {
	var claims []aveClaim
	var declared []string
	for i, item := range aveList(doc["runs"]) {
		run := aveObject(item)
		if sha, ok := aveObject(run["properties"])["ave_records_sha256"]; ok && sha != nil {
			declared = append(declared, aveText(sha))
		}
		rules := aveList(aveObject(aveObject(run["tool"])["driver"])["rules"])
		for j, item := range rules {
			rule, where := aveObject(item), fmt.Sprintf("runs[%d].tool.driver.rules[%d]", i, j)
			if aveClaimsAVE(rule["id"]) {
				claims = append(claims, aveClaim{rule["id"], where + ".id"})
			}
			if id, ok := aveObject(rule["properties"])["ave_id"]; ok {
				claims = append(claims, aveClaim{id, where + ".properties.ave_id"})
			}
		}
		for k, item := range aveList(run["results"]) {
			result, where := aveObject(item), fmt.Sprintf("runs[%d].results[%d]", i, k)
			ruleID, present := result["ruleId"]
			if !present {
				ruleID = aveObject(result["rule"])["id"]
			}
			if aveClaimsAVE(ruleID) {
				claims = append(claims, aveClaim{ruleID, where + ".ruleId"})
			}
			if id, ok := aveObject(result["properties"])["ave_id"]; ok {
				claims = append(claims, aveClaim{id, where + ".properties.ave_id"})
			}
		}
	}
	return claims, declared
}

func aveWalk(node any, path string, claims *[]aveClaim) {
	switch value := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if aveJSONIDKey.MatchString(key) {
				items, isList := value[key].([]any)
				if !isList {
					items = []any{value[key]}
				}
				for _, item := range items {
					*claims = append(*claims, aveClaim{item, path + "." + key})
				}
				continue
			}
			aveWalk(value[key], path+"."+key, claims)
		}
	case []any:
		for n, item := range value {
			aveWalk(item, fmt.Sprintf("%s[%d]", path, n), claims)
		}
	}
}

func aveExtract(doc any) ([]aveClaim, []string) {
	object, isObject := doc.(map[string]any)
	if isObject {
		if _, isList := object["runs"].([]any); isList {
			return aveSARIF(object)
		}
	}
	var claims []aveClaim
	aveWalk(doc, "$", &claims)
	if sha, ok := object["ave_records_sha256"]; isObject && ok && sha != nil {
		return claims, []string{aveText(sha)}
	}
	return claims, nil
}

func aveJudge(doc any, statuses map[string]aveStatus, pinned string) (string, []string) {
	claims, declared := aveExtract(doc)
	codes := map[string]bool{}
	for _, claim := range claims {
		id, isString := claim.value.(string)
		status, known := statuses[id]
		known = known && isString
		switch {
		case !isString || !aveID.MatchString(id):
			codes["id-malformed"] = true
		case !known:
			codes["id-unknown"] = true
		case !status.set || status.value != "active":
			codes["id-not-active"] = true
		}
	}
	for _, digest := range declared {
		if strings.ToLower(digest) != strings.ToLower(pinned) {
			codes["run-snapshot-differs"] = true
		}
	}
	sorted := make([]string, 0, len(codes))
	for code := range codes {
		sorted = append(sorted, code)
	}
	sort.Strings(sorted)
	switch {
	case len(sorted) > 0:
		return "fails", sorted
	case len(claims) > 0:
		return "resolves", sorted
	}
	return "no-ids", sorted
}
