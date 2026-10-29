package corpora

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
)

func init() { register(mcpServerProfile{}) }

// mcpServerProfile judges vectors-mcp-server-profile/. The subject is a server
// run record: what a recorder saw when it launched one version of one MCP
// server. The reader recomputes every derived field (pin mismatches, version
// diff, undeclared hosts, the outcome rules) from the observed ones and compares
// the conditions it finds broken with the ones the member declares. The same
// rules are written in vectors-mcp-server-profile/check_server_record.py, and
// the corpus is what holds the two together.
type mcpServerProfile struct{}

func (mcpServerProfile) Suite() string { return "mcp-server-profile" }

type mspManifest struct {
	Conditions   map[string]json.RawMessage `json:"conditions"`
	Counts       map[string]int             `json:"counts"`
	CorpusDigest string                     `json:"corpusDigest"`
	Vectors      []mspVector                `json:"vectors"`
}

type mspVector struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Record     string   `json:"record"`
	Conditions []string `json:"conditions"`
	Expected   struct {
		Violates []string `json:"violates"`
	} `json:"expected"`
}

func (m mcpServerProfile) Judge(dir string, raw []byte) (*Result, error) {
	var manifest mspManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	seen := map[string]bool{}
	accepted, rejected, used := map[string]bool{}, map[string]bool{}, map[string]bool{}
	ids, files := make([]string, 0, len(manifest.Vectors)), make([]string, 0, len(manifest.Vectors))
	measured := map[string]int{"accept": 0, "reject": 0}
	for _, v := range manifest.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.Record)
		if _, known := measured[v.Kind]; known {
			measured[v.Kind]++
		}
		for _, c := range v.Conditions {
			used[c] = true
			switch v.Kind {
			case "accept":
				accepted[c] = true
			case "reject":
				rejected[c] = true
			}
		}
		m.judgeMember(dir, &manifest, v, &member)
		result.Members = append(result.Members, member)
	}
	if orphan := orphanTwins(accepted, rejected); len(orphan) > 0 {
		result.Findings = append(result.Findings, fmt.Sprintf(
			"conditions that reject and never accept: %v. A checker that refuses every "+
				"record would score full marks on them.", orphan))
	}
	if idle := declaredMinusUsed(manifest.Conditions, used); len(idle) > 0 {
		result.Findings = append(result.Findings,
			fmt.Sprintf("conditions declared and carried by no member: %v", idle))
	}
	if bad := countsDisagree(manifest.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		return nil, err
	}
	if digest != manifest.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the record files on disk")
	}
	return result, nil
}

func (mcpServerProfile) judgeMember(dir string, manifest *mspManifest, v mspVector, out *Member) {
	if v.Kind != "accept" && v.Kind != "reject" {
		out.Findings = append(out.Findings, fmt.Sprintf("declares kind %q", v.Kind))
	}
	if len(v.Conditions) == 0 {
		out.Findings = append(out.Findings, "cites no condition")
		return
	}
	for _, condition := range v.Conditions {
		if _, defined := manifest.Conditions[condition]; !defined {
			out.Findings = append(out.Findings, "cites condition "+condition+" the manifest does not define")
		}
	}
	if !existsIn(dir, v.Record) {
		out.Findings = append(out.Findings, "the manifest names a record file that does not exist")
		return
	}
	body, err := readIn(dir, v.Record)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		out.Findings = append(out.Findings, "the record does not parse: "+err.Error())
		return
	}
	checkRunRecordIdentity(body, mcpVector{ID: v.ID, Kind: v.Kind, Conditions: v.Conditions}, out)

	found := checkServerRecord(record)
	declared := append([]string{}, v.Expected.Violates...)
	sort.Strings(declared)
	if !reflect.DeepEqual(mspNonNil(found), mspNonNil(declared)) {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares the broken conditions %v and the checker finds %v", declared, found))
	}
	switch v.Kind {
	case "accept":
		if len(found) > 0 {
			out.Findings = append(out.Findings, fmt.Sprintf("is an accept member and breaks %v", found))
		}
	case "reject":
		if len(found) != 1 || (len(v.Conditions) == 1 && found[0] != v.Conditions[0]) {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"is a reject member for %v and the checker finds %v. A reject member must break "+
					"exactly the one condition it cites.", v.Conditions, found))
		}
	}
}

func mspNonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

var mspImmutable = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// mspStringMap reads an object whose values are strings, ignoring any other value.
func mspStringMap(value any) map[string]string {
	out := map[string]string{}
	for k, v := range objectAt(value) {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// mspStringList reads a list of strings, sorted, so a comparison ignores order.
func mspStringList(value any) []string {
	list, _ := value.([]any)
	out := []string{}
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func mspSortedKeys(set map[string]bool) []string {
	out := []string{}
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkServerRecord is the criterion, restated from check_server_record.py.
func checkServerRecord(record map[string]any) []string {
	if kind, _ := record["recordType"].(string); kind == "run-set" {
		return checkServerRunSet(record)
	}
	violated := []string{}
	tools := objectAt(record["tools"])
	pinned, served := mspStringMap(tools["pinned"]), mspStringMap(tools["served"])
	mismatches := map[string]bool{}
	for name, digest := range served {
		if p, ok := pinned[name]; !ok || p != digest {
			mismatches[name] = true
		}
	}
	if !reflect.DeepEqual(mspStringList(tools["mismatchReported"]), mspSortedKeys(mismatches)) {
		violated = append(violated, "msp-c-1")
	}

	diff := objectAt(record["diff"])
	before := mspStringMap(diff["previousTools"])
	changed, added, removed := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for name, digest := range served {
		if prev, ok := before[name]; !ok {
			added[name] = true
		} else if prev != digest {
			changed[name] = true
		}
	}
	for name := range before {
		if _, ok := served[name]; !ok {
			removed[name] = true
		}
	}
	reported := objectAt(diff["reported"])
	for key, want := range map[string]map[string]bool{"changed": changed, "added": added, "removed": removed} {
		if !reflect.DeepEqual(mspStringList(reported[key]), mspSortedKeys(want)) {
			violated = append(violated, "msp-c-2")
			break
		}
	}

	egress := objectAt(record["egress"])
	declaredHosts := map[string]bool{}
	for _, h := range mspStringList(record["declaredEgress"]) {
		declaredHosts[h] = true
	}
	undeclared := map[string]bool{}
	for _, h := range mspStringList(egress["observed"]) {
		if !declaredHosts[h] {
			undeclared[h] = true
		}
	}
	if !reflect.DeepEqual(mspStringList(egress["undeclaredReported"]), mspSortedKeys(undeclared)) {
		violated = append(violated, "msp-c-3")
	}

	outcome, _ := record["outcome"].(string)
	if observation, _ := egress["observation"].(string); observation != "recorded" && outcome != "couldnt-run" {
		violated = append(violated, "msp-c-4")
	}
	if outcome == "clean" && (len(mismatches) > 0 || len(undeclared) > 0) {
		violated = append(violated, "msp-c-5")
	}
	if digest, _ := objectAt(record["server"])["artifactDigest"].(string); !mspImmutable.MatchString(digest) {
		violated = append(violated, "msp-c-6")
	}
	return violated
}

func checkServerRunSet(record map[string]any) []string {
	attempted, attemptedOK := numberOf(record["attempted"])
	denominator, denominatorOK := numberOf(record["headlineDenominator"])
	sum := 0
	for _, v := range objectAt(record["results"]) {
		if n, ok := numberOf(v); ok {
			sum += n
		}
	}
	if !attemptedOK || !denominatorOK || sum != attempted || denominator != attempted {
		return []string{"msp-c-7"}
	}
	return []string{}
}
