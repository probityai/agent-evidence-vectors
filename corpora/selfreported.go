package corpora

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
)

func init() { register(selfReportedRecord{}) }

// selfReportedRecord judges vectors-self-reported-record/, the corpus for the
// contract at spec/self-reported-record/v1.md.
//
// It is the Go RAIL over that corpus. The corpus ships its own reference
// verifier in Python beside the vectors, and the six rules below are that
// verifier restated here rather than imported from it. Two independent
// spellings of one rule set is the only arrangement that finds a rule both
// implementations get wrong the same way, and this repository has already paid
// for the alternative once: its two rails disagreeing on identical bytes at one
// exact depth is how a real defect surfaced.
//
// The corpus's subject is a record an agent runtime keeps about itself. The
// rules are almost all negative, because that is what such a record admits: a
// turn the named key did not sign, a memory digest taken over something other
// than the bytes at the path the record names, an attesting key the record's own
// declaration puts inside the runtime, two carried ledgers that disagree, and a
// field claiming an observation nothing carries.
type selfReportedRecord struct{}

func (selfReportedRecord) Suite() string { return "self-reported-record-conformance" }

const (
	srrStatementType = "https://in-toto.io/Statement/v1"
	srrPredicateType = "https://probityai.github.io/agent-evidence-vectors/" +
		"predicate/v1/self-reported-record"
	srrTurnContext  = "agent-evidence/self-reported-record/v1/turn"
	srrFieldContext = "agent-evidence/self-reported-record/v1/field"
)

var (
	srrHex64      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	srrRFC3339UTC = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
)

// srrVocabularies are the closed value sets, each a registered term in
// agent-evidence-vocabulary. A value the registry does not carry makes the
// record malformed; no value has a default and no verifier may supply one.
var srrVocabularies = map[string][]string{
	"originKind":            {"self", "third-party-control-plane", "log-import"},
	"attestationTier":       {"voluntary", "authoritative"},
	"observationVantage":    {"substrate", "artifact"},
	"observationDirectness": {"intercepted", "reconstructed"},
}

var srrFieldEvidence = []string{"substrate_covered", "producer_asserted"}

var srrRequired = []string{
	"recordId", "sessionId", "hashAlgorithm", "originKind", "attestationTier",
	"observationVantage", "observationDirectness", "attestingKey", "selfSigners",
	"turns", "memoryReads", "ledgers", "fields", "doesNotAssert", "issuedAt",
}

// srrRules in the order a verifier applies them. Well-formedness is stage one
// and byte-pure; the five below read members for meaning and run only after it
// passes, because a rule reading a malformed record reports a type error
// wearing a refusal's name.
var srrRules = []string{
	"rule_wellformed",
	"rule_turn_attestation",
	"rule_memory_digest_over_named_path",
	"rule_attesting_key_disjoint",
	"rule_ledgers_agree",
	"rule_field_coverage",
}

var srrCodeOfRule = map[string]string{
	"rule_wellformed":                    "record-malformed",
	"rule_turn_attestation":              "turn-unsigned-by-attesting-key",
	"rule_memory_digest_over_named_path": "memory-digest-not-over-named-path",
	"rule_attesting_key_disjoint":        "attesting-key-in-self-signers",
	"rule_ledgers_agree":                 "ledger-members-disagree",
	"rule_field_coverage":                "field-claims-coverage-uncovered",
}

type srrManifest struct {
	Contract       string            `json:"contract"`
	ContractDigest string            `json:"contractDigest"`
	Conditions     map[string]string `json:"conditions"`
	Codes          map[string]string `json:"codes"`
	Counts         map[string]int    `json:"counts"`
	CorpusDigest   string            `json:"corpusDigest"`
	Vectors        []srrVector       `json:"vectors"`
}

type srrVector struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	File       string      `json:"file"`
	Parent     string      `json:"parent"`
	Conditions []string    `json:"conditions"`
	Expected   srrExpected `json:"expected"`
}

type srrExpected struct {
	Verdict string   `json:"verdict"`
	Codes   []string `json:"codes"`
}

func (s selfReportedRecord) Judge(dir string, raw []byte) (*Result, error) {
	var manifest srrManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	accepted, rejected, used := map[string]bool{}, map[string]bool{}, map[string]bool{}
	accepts := map[string]bool{}
	ids := make([]string, 0, len(manifest.Vectors))
	files := make([]string, 0, len(manifest.Vectors))
	seen := map[string]bool{}

	for _, v := range manifest.Vectors {
		if v.Kind == "accept" {
			accepts[v.ID] = true
		}
		for _, c := range v.Conditions {
			used[c] = true
			if v.Kind == "accept" {
				accepted[c] = true
			} else {
				rejected[c] = true
			}
		}
		ids, files = append(ids, v.ID), append(files, v.File)
	}
	for _, v := range manifest.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		s.judgeMember(dir, &manifest, v, accepts, &member)
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, srrCorpusFindings(dir, &manifest, srrSets{
		accepted: accepted, rejected: rejected, used: used, ids: ids, files: files,
	})...)
	return result, nil
}

// srrSets carries what the per-member pass already measured, so the
// corpus-level pass reads it instead of walking the members a second time.
type srrSets struct {
	accepted, rejected, used map[string]bool
	ids, files               []string
}

func srrCorpusFindings(dir string, manifest *srrManifest, sets srrSets) []string {
	var findings []string
	if orphan := orphanTwins(sets.accepted, sets.rejected); len(orphan) > 0 {
		findings = append(findings, fmt.Sprintf(
			"conditions that reject and never accept: %v. A verifier that refused every "+
				"member would score full marks on them.", orphan))
	}
	if idle := declaredMinusUsed(manifest.Conditions, sets.used); len(idle) > 0 {
		findings = append(findings,
			fmt.Sprintf("conditions declared and carried by no member: %v", idle))
	}
	measured := map[string]int{"accept": 0, "reject": 0}
	for _, v := range manifest.Vectors {
		if _, known := measured[v.Kind]; known {
			measured[v.Kind]++
		}
	}
	if bad := countsDisagree(manifest.Counts, measured); bad != "" {
		findings = append(findings, bad)
	}
	digest, err := orderedCorpusDigest(dir, sets.ids, sets.files)
	if err != nil {
		findings = append(findings, "the corpus digest could not be recomputed: "+err.Error())
	} else if digest != manifest.CorpusDigest {
		findings = append(findings, "corpusDigest does not match the member files on disk")
	}
	// The contract sits above the corpus directory, so it resolves against the
	// parent. A corpus whose contract is missing measures a rule nobody can read.
	if bad := checkVendored(filepath.Dir(dir), manifest.Contract,
		manifest.ContractDigest, "contract"); bad != "" {
		findings = append(findings, bad)
	}
	return findings
}

func (s selfReportedRecord) judgeMember(
	dir string, manifest *srrManifest, v srrVector, accepts map[string]bool, out *Member,
) {
	if v.Kind != "accept" && v.Kind != "reject" {
		out.Findings = append(out.Findings, fmt.Sprintf("declares kind %q", v.Kind))
	}
	if len(v.Conditions) == 0 {
		out.Findings = append(out.Findings, "cites no condition")
		return
	}
	for _, condition := range v.Conditions {
		if _, defined := manifest.Conditions[condition]; !defined {
			out.Findings = append(out.Findings,
				"cites condition "+condition+" the manifest does not define")
		}
	}
	if v.Kind == "reject" && !accepts[v.Parent] {
		out.Findings = append(out.Findings,
			"names a parent that is not an accepted member of this corpus")
	}
	body, err := readIn(dir, v.File)
	if err != nil {
		out.Findings = append(out.Findings, "the manifest names a member file that cannot be read")
		return
	}
	if idFromBytes(body) != v.ID {
		out.Findings = append(out.Findings, "identifier does not recompute from the member's own bytes")
	}
	statement, err := decodeJSONNumbers(body)
	if err != nil {
		out.Findings = append(out.Findings, "the member does not parse: "+err.Error())
		return
	}
	s.checkAgainstContract(objectAt(statement), v, out)
}

// checkAgainstContract runs the contract. This is the check the manifest cannot
// do for itself: the manifest says what a verifier must decide, and only a
// verifier decides it.
func (selfReportedRecord) checkAgainstContract(statement map[string]any, v srrVector, out *Member) {
	firing := srrFiringRules(statement)
	verdict, codes := srrVerdict(firing)
	if verdict != v.Expected.Verdict {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares verdict %s and this rail answers %s with codes %v",
			v.Expected.Verdict, verdict, codes))
	}
	if !srrSameStrings(codes, v.Expected.Codes) {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares codes %v and this rail names %v", v.Expected.Codes, codes))
	}
	switch {
	case v.Kind == "accept" && len(firing) > 0:
		out.Findings = append(out.Findings,
			fmt.Sprintf("is an accept member refused by %v", firing))
	case v.Kind == "reject" && len(firing) != 1:
		out.Findings = append(out.Findings, fmt.Sprintf(
			"is a reject member tripping %v. A member failing two rules cannot tell a "+
				"reader which one its code refers to.", firing))
	}
}

// srrFiringRules is every rule that refuses this statement, in application
// order. All of them and not the first: a corpus reporting only the first
// refusal cannot tell a member failing one rule from a member failing three,
// and the second is a member whose published code does not name what caught it.
func srrFiringRules(statement map[string]any) []string {
	if !srrWellformed(statement) {
		return []string{"rule_wellformed"}
	}
	predicate := objectAt(statement["predicate"])
	checks := map[string]func(map[string]any) bool{
		"rule_turn_attestation":              srrTurnAttestation,
		"rule_memory_digest_over_named_path": srrMemoryDigestOverNamedPath,
		"rule_attesting_key_disjoint":        srrAttestingKeyDisjoint,
		"rule_ledgers_agree":                 srrLedgersAgree,
		"rule_field_coverage":                srrFieldCoverage,
	}
	var firing []string
	for _, rule := range srrRules[1:] {
		if !checks[rule](predicate) {
			firing = append(firing, rule)
		}
	}
	return firing
}

func srrVerdict(firing []string) (string, []string) {
	if len(firing) == 0 {
		return "valid", []string{}
	}
	codes := make([]string, 0, len(firing))
	for _, rule := range firing {
		codes = append(codes, srrCodeOfRule[rule])
	}
	if len(firing) == 1 && firing[0] == "rule_wellformed" {
		return "malformed", codes
	}
	return "invalid", codes
}

// ---------------------------------------------------------------------------
// the six rules
// ---------------------------------------------------------------------------

func srrWellformed(statement map[string]any) bool {
	if str(statement["_type"]) != srrStatementType {
		return false
	}
	if str(statement["predicateType"]) != srrPredicateType {
		return false
	}
	if !srrSubjectWellformed(statement["subject"]) {
		return false
	}
	predicate, ok := statement["predicate"].(map[string]any)
	if !ok {
		return false
	}
	for _, member := range srrRequired {
		if _, present := predicate[member]; !present {
			return false
		}
	}
	for member, allowed := range srrVocabularies {
		if !srrIn(allowed, str(predicate[member])) {
			return false
		}
	}
	if str(predicate["hashAlgorithm"]) != "sha256" {
		return false
	}
	key := objectAt(predicate["attestingKey"])
	if !srrIsHex64(key["keyid"]) || !srrIsHex64(key["publicKey"]) {
		return false
	}
	for _, keyid := range srrArray(predicate["selfSigners"]) {
		if !srrIsHex64(keyid) {
			return false
		}
	}
	if len(srrArray(predicate["ledgers"])) < 2 {
		return false
	}
	if !srrRFC3339UTC.MatchString(str(predicate["issuedAt"])) {
		return false
	}
	return srrRowsWellformed(predicate)
}

func srrSubjectWellformed(value any) bool {
	subject := srrArray(value)
	if len(subject) != 1 {
		return false
	}
	entry := objectAt(subject[0])
	if _, ok := entry["name"].(string); !ok {
		return false
	}
	return srrIsHex64(objectAt(entry["digest"])["sha256"])
}

func srrRowsWellformed(predicate map[string]any) bool {
	for _, item := range srrArray(predicate["turns"]) {
		row := objectAt(item)
		attested := objectAt(row["attestedBy"])
		if _, ok := row["turnId"].(string); !ok {
			return false
		}
		if !srrIsHex64(attested["keyid"]) {
			return false
		}
		if _, ok := attested["sig"].(string); !ok {
			return false
		}
		if _, ok := row["changeIds"].([]any); !ok {
			return false
		}
	}
	for _, item := range srrArray(predicate["memoryReads"]) {
		row := objectAt(item)
		if _, ok := row["path"].(string); !ok {
			return false
		}
		if !srrIsHex64(row["assertedDigest"]) || !srrIsHex64(row["pathDigest"]) {
			return false
		}
	}
	for _, item := range srrArray(predicate["ledgers"]) {
		row := objectAt(item)
		if _, ok := row["name"].(string); !ok {
			return false
		}
		if _, ok := row["members"].([]any); !ok {
			return false
		}
	}
	return srrFieldRowsWellformed(predicate)
}

func srrFieldRowsWellformed(predicate map[string]any) bool {
	for _, item := range srrArray(predicate["fields"]) {
		row := objectAt(item)
		if _, ok := row["name"].(string); !ok {
			return false
		}
		if _, ok := row["value"].(string); !ok {
			return false
		}
		if !srrIn(srrFieldEvidence, str(row["evidence"])) {
			return false
		}
	}
	return true
}

// srrTurnAttestation is srr-c-1: every turn is signed by the key the record
// names. A turn is the unit a reader takes as history, and a record carrying a
// turn nothing signed is carrying the producer's own assertion in a ledger
// entry's shape.
func srrTurnAttestation(predicate map[string]any) bool {
	public := str(objectAt(predicate["attestingKey"])["publicKey"])
	session := predicate["sessionId"]
	for _, item := range srrArray(predicate["turns"]) {
		row := objectAt(item)
		payload, err := pythonCompactJSONOpts(map[string]any{
			"changeIds":  row["changeIds"],
			"context":    srrTurnContext,
			"goalMarker": row["goalMarker"],
			"priorTurn":  row["priorTurn"],
			"sessionId":  session,
			"turnId":     row["turnId"],
		}, pyEncodeOpts{UTF16Order: true})
		if err != nil {
			return false
		}
		if !srrEd25519OK(public, payload, str(objectAt(row["attestedBy"])["sig"])) {
			return false
		}
	}
	return true
}

// srrMemoryDigestOverNamedPath is srr-c-2: the digest the record reports is the
// digest of the bytes at the path it names. The two members exist separately
// because they come from two places, and a runtime holding both while reporting
// one reports the one nothing downstream reads.
func srrMemoryDigestOverNamedPath(predicate map[string]any) bool {
	for _, item := range srrArray(predicate["memoryReads"]) {
		row := objectAt(item)
		if str(row["assertedDigest"]) != str(row["pathDigest"]) {
			return false
		}
	}
	return true
}

// srrAttestingKeyDisjoint is srr-c-3: the attesting key is not one the record
// itself says the runtime holds. The rule is not that such a signature is bad.
// It verifies perfectly. The rule is that the record's own declaration
// contradicts its claim to have been attested by something else.
func srrAttestingKeyDisjoint(predicate map[string]any) bool {
	keyid := str(objectAt(predicate["attestingKey"])["keyid"])
	for _, signer := range srrArray(predicate["selfSigners"]) {
		if str(signer) == keyid {
			return false
		}
	}
	return true
}

// srrLedgersAgree is srr-c-4: every ledger names the same change set. A runtime
// keeping two answers to one question can apply a removal to one of them, and
// both surfaces stay internally consistent while no read reconciles them.
func srrLedgersAgree(predicate map[string]any) bool {
	var first []string
	for index, item := range srrArray(predicate["ledgers"]) {
		members := make([]string, 0)
		for _, member := range srrArray(objectAt(item)["members"]) {
			members = append(members, str(member))
		}
		sort.Strings(members)
		members = srrDedupe(members)
		if index == 0 {
			first = members
			continue
		}
		if !srrSameStrings(first, members) {
			return false
		}
	}
	return true
}

// srrFieldCoverage is srr-c-5, and it is the rule the whole contract is built
// around. Carrying a caller-supplied value is not a defect; the accept twin in
// this corpus carries twelve of them, each declared the producer's own
// assertion. What is refused is the same value declared as covered by an
// observation, with nothing carrying the observation.
func srrFieldCoverage(predicate map[string]any) bool {
	selfSigners := map[string]bool{}
	for _, signer := range srrArray(predicate["selfSigners"]) {
		selfSigners[str(signer)] = true
	}
	recordID := predicate["recordId"]
	for _, item := range srrArray(predicate["fields"]) {
		row := objectAt(item)
		covered, present := row["coveredBy"]
		if str(row["evidence"]) == "producer_asserted" {
			if present {
				return false
			}
			continue
		}
		key := objectAt(covered)
		if len(key) == 0 || selfSigners[str(key["keyid"])] {
			return false
		}
		payload, err := pythonCompactJSONOpts(map[string]any{
			"context":  srrFieldContext,
			"name":     row["name"],
			"recordId": recordID,
			"value":    row["value"],
		}, pyEncodeOpts{UTF16Order: true})
		if err != nil {
			return false
		}
		if !srrEd25519OK(str(key["publicKey"]), payload, str(key["sig"])) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// small helpers, named apart from the package's shared ones
// ---------------------------------------------------------------------------

// srrEd25519OK verifies, refusing rather than panicking on anything the carried
// bytes get wrong. Every failure mode here is a refusal: a key of the wrong
// length, a signature that is not base64, a signature that does not verify.
func srrEd25519OK(publicHex string, payload []byte, signatureB64 string) bool {
	public, err := hex.DecodeString(publicHex)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(public), payload, signature)
}

func str(value any) string {
	s, _ := value.(string)
	return s
}

func srrIsHex64(value any) bool {
	s, ok := value.(string)
	return ok && srrHex64.MatchString(s)
}

func srrArray(value any) []any {
	items, _ := value.([]any)
	return items
}

func srrIn(allowed []string, value string) bool {
	for _, candidate := range allowed {
		if candidate == value {
			return true
		}
	}
	return false
}

func srrSameStrings(a, b []string) bool {
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

func srrDedupe(sorted []string) []string {
	out := sorted[:0]
	for i, value := range sorted {
		if i == 0 || value != sorted[i-1] {
			out = append(out, value)
		}
	}
	return out
}
