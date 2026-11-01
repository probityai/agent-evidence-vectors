package corpora

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func init() {
	register(cardReceipt{suite: crReceiptSuite})
	register(cardReceipt{suite: crReleaseSuite})
}

// cardReceipt judges vectors-agent-card-receipt/ and vectors-credential-release/.
// The two suites share one reader because a credential release is judged against
// the receipt it names. The checks, their order and their codes are the ones the
// Python reader applies (packaging/agent_evidence_vectors/cardreceipt.py); the
// reader names the first that fails.
//
// agent-card-receipt/v1: the statement is strict JSON with the four Statement
// members, then its type, predicate type and subject, then the predicate, then
// the validity window, then the card (an I-JSON object whose RFC 8785 form
// without its top-level signatures hashes to the subject digest), then the check
// time against the window, then the signed revocation list.
//
// credential-release/v1: the same Statement checks plus the closed credential
// object, then the receipt the release names (its digest, shape, copied fields,
// subject, result, currency at releasedAt, and that the credential does not
// outlive it), then the revocation list the release consulted.
type cardReceipt struct{ suite string }

const (
	crReceiptSuite = "agent-card-receipt/v1"
	crReleaseSuite = "credential-release/v1"

	crStatementType  = "https://in-toto.io/Statement/v1"
	crReceiptType    = "https://w3id.org/agent-evidence/predicate/v1/agent-card-receipt"
	crReleaseType    = "https://w3id.org/agent-evidence/predicate/v1/credential-release"
	crRevocationType = "application/vnd.agent-evidence.agent-card-receipt-revocations.v1+json"
	crTimeLayout     = "2006-01-02T15:04:05Z"
)

var (
	crHex        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	crTimeText   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	crThumbprint = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	crResults    = []string{"fail", "degraded", "pass_indirect", "pass"}
)

type crObj = map[string]any

func (c cardReceipt) Suite() string { return c.suite }

type crVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
}

func (c cardReceipt) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v crVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		if !filepath.IsLocal(filepath.FromSlash(v.Path)) {
			member.Findings = []string{v.Path + " leaves the corpus directory"}
		} else {
			member.Findings = c.judgeMember(filepath.Join(dir, filepath.FromSlash(v.Path)), v)
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func (c cardReceipt) judgeMember(caseDir string, v crVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	if entries, err := os.ReadDir(caseDir); err == nil {
		for _, e := range entries {
			if _, declared := v.Files[e.Name()]; !declared && !e.IsDir() {
				findings = append(findings, e.Name()+" is present and not declared")
			}
		}
	}
	got, err := c.decide(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func (c cardReceipt) decide(dir string) (scDecision, error) {
	context, key, err := crContext(dir)
	if err != nil {
		return scDecision{}, err
	}
	if c.suite == crReceiptSuite {
		return crReceiptDecide(dir, context, key)
	}
	return crReleaseDecide(dir, context, key)
}

func crReject(reason string) scDecision { return scDecision{"reject", reason} }

// crRead returns a file's bytes and whether the file exists.
func crRead(dir, name string) ([]byte, bool) {
	if !existsIn(dir, name) {
		return nil, false
	}
	body, err := readIn(dir, name)
	return body, err == nil
}

func crContext(dir string) (crObj, []byte, error) {
	body, ok := crRead(dir, "context.json")
	if !ok {
		return nil, nil, fmt.Errorf("context.json cannot be read")
	}
	context, ok := crObject(body)
	if !ok {
		return nil, nil, fmt.Errorf("context.json does not parse")
	}
	key, ok := crB64(context["issuerKey"])
	if !ok {
		return nil, nil, fmt.Errorf("context.json issuerKey is not base64")
	}
	return context, key, nil
}

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

func crObject(data []byte) (crObj, bool) {
	value, err := cabStrict(data)
	if err != nil {
		return nil, false
	}
	object, ok := value.(crObj)
	return object, ok
}

func crB64(value any) ([]byte, bool) {
	text, ok := value.(string)
	if !ok || strings.ContainsAny(text, "\r\n") {
		return nil, false
	}
	out, err := base64.StdEncoding.DecodeString(text)
	return out, err == nil
}

// crMembers reports whether value is an object whose keys are the required set
// plus any of the optional ones.
func crMembers(value any, required []string, optional ...string) (crObj, bool) {
	object, ok := value.(crObj)
	if !ok {
		return nil, false
	}
	allowed := map[string]bool{}
	for _, name := range required {
		if _, has := object[name]; !has {
			return nil, false
		}
		allowed[name] = true
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name := range object {
		if !allowed[name] {
			return nil, false
		}
	}
	return object, true
}

func crText(value any) bool {
	text, ok := value.(string)
	return ok && text != ""
}

func crHTTPS(value any) bool {
	text, ok := value.(string)
	return ok && strings.HasPrefix(text, "https://") && len(text) > len("https://")
}

// crSHA returns the hex of a {"sha256": hex} digest object.
func crSHA(value any) (string, bool) {
	object, ok := value.(crObj)
	if !ok || len(object) != 1 {
		return "", false
	}
	text, ok := object["sha256"].(string)
	return text, ok && crHex.MatchString(text)
}

func crTime(value any) (time.Time, bool) {
	text, ok := value.(string)
	if !ok || !crTimeText.MatchString(text) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(crTimeLayout, text)
	if err != nil || parsed.Year() < 1 {
		return time.Time{}, false
	}
	return parsed, true
}

func crResultIndex(value any) int {
	text, _ := value.(string)
	for i, name := range crResults {
		if name == text {
			return i
		}
	}
	return -1
}

func crSortedUnique(list []any) bool {
	var previous string
	for i, item := range list {
		text, ok := item.(string)
		if !ok || (i > 0 && text <= previous) {
			return false
		}
		previous = text
	}
	return true
}

// crStatement is the first Statement-level check that fails, or "".
func crStatement(statement crObj, predicateType string) string {
	if _, ok := crMembers(statement, []string{"_type", "subject", "predicateType", "predicate"}); !ok {
		return "statement_malformed"
	}
	if statement["_type"] != crStatementType {
		return "statement_type_wrong"
	}
	if statement["predicateType"] != predicateType {
		return "predicate_type_wrong"
	}
	subjects, ok := statement["subject"].([]any)
	if !ok || len(subjects) != 1 {
		return "subject_malformed"
	}
	subject, ok := crMembers(subjects[0], []string{"name", "digest"})
	if !ok || !crText(subject["name"]) {
		return "subject_malformed"
	}
	if _, ok := crSHA(subject["digest"]); !ok {
		return "subject_malformed"
	}
	return ""
}

func crReceiptPredicateOK(value any) bool {
	p, ok := crMembers(value, []string{"run", "result", "registryDigest", "issuedAt", "validUntil",
		"revocationList"}, "agentKeyThumbprints")
	if !ok {
		return false
	}
	run, ok := crMembers(p["run"], []string{"predicateType", "digest"})
	if !ok || !crHTTPS(run["predicateType"]) {
		return false
	}
	if _, ok := crSHA(run["digest"]); !ok {
		return false
	}
	if crResultIndex(p["result"]) < 0 {
		return false
	}
	if _, ok := crSHA(p["registryDigest"]); !ok {
		return false
	}
	if _, ok := crTime(p["issuedAt"]); !ok {
		return false
	}
	if _, ok := crTime(p["validUntil"]); !ok {
		return false
	}
	if !crHTTPS(p["revocationList"]) {
		return false
	}
	if thumbs, has := p["agentKeyThumbprints"]; has {
		list, ok := thumbs.([]any)
		if !ok || len(list) == 0 || !crSortedUnique(list) {
			return false
		}
		for _, item := range list {
			if !crThumbprint.MatchString(item.(string)) {
				return false
			}
		}
	}
	return true
}

var crCredentialMembers = []string{"kind", "audience", "scope"}

func crCredentialOK(value any) bool {
	c, ok := crMembers(value, crCredentialMembers)
	if !ok || !crText(c["kind"]) || !crHTTPS(c["audience"]) {
		return false
	}
	scope, ok := c["scope"].([]any)
	if !ok || len(scope) == 0 || !crSortedUnique(scope) {
		return false
	}
	for _, item := range scope {
		if !crText(item) {
			return false
		}
	}
	return true
}

func crTTLOK(value any) bool {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(number), ".eE") {
		return false
	}
	n, err := number.Int64()
	return err == nil && n > 0 && n < 1<<31
}

func crReleasePredicateOK(value any) bool {
	p, ok := crMembers(value, []string{"releaseId", "releasedAt", "ttlSeconds", "receipt", "minResult",
		"revocationList", "credential", "broker", "registryDigest"})
	if !ok || !crText(p["releaseId"]) || !crTTLOK(p["ttlSeconds"]) {
		return false
	}
	if _, ok := crTime(p["releasedAt"]); !ok {
		return false
	}
	receipt, ok := crMembers(p["receipt"], []string{"predicateType", "digest", "result", "validUntil"})
	if !ok || receipt["predicateType"] != crReceiptType || crResultIndex(receipt["result"]) < 0 {
		return false
	}
	if _, ok := crSHA(receipt["digest"]); !ok {
		return false
	}
	if _, ok := crTime(receipt["validUntil"]); !ok {
		return false
	}
	if crResultIndex(p["minResult"]) < 2 {
		return false
	}
	list, ok := crMembers(p["revocationList"], []string{"digest"})
	if !ok {
		return false
	}
	if _, ok := crSHA(list["digest"]); !ok {
		return false
	}
	broker, ok := crMembers(p["broker"], []string{"id"})
	if !ok || !crHTTPS(broker["id"]) || !crCredentialOK(p["credential"]) {
		return false
	}
	_, ok = crSHA(p["registryDigest"])
	return ok
}

// crCredentialFields is true when the credential object has a member outside
// the closed set.
func crCredentialFields(predicate any) bool {
	p, ok := predicate.(crObj)
	if !ok {
		return false
	}
	credential, ok := p["credential"].(crObj)
	if !ok {
		return false
	}
	for name := range credential {
		if name != "kind" && name != "audience" && name != "scope" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The card digest
// ---------------------------------------------------------------------------

// crCardDigest is the SHA-256 of RFC 8785 of the card as served, without its
// top-level signatures (A2A 8.4.1 rules 2 and 3; rule 1 is open in
// a2aproject/A2A issue 2122 and is not applied). It reports false for a card
// that is not an I-JSON object or has no canonical form.
func crCardDigest(card []byte) (string, bool) {
	value, err := cabStrict(card)
	if err != nil {
		return "", false
	}
	object, ok := value.(crObj)
	if !ok {
		return "", false
	}
	delete(object, "signatures")
	var buf strings.Builder
	if err := a2aWrite(&buf, object); err != nil {
		return "", false
	}
	return sha([]byte(buf.String())), true
}

// ---------------------------------------------------------------------------
// The revocation list
// ---------------------------------------------------------------------------

type crList struct {
	issued, next time.Time
	revoked      map[string]bool
}

func crParseList(envelope []byte) (crList, []byte, [][]byte, bool) {
	var none crList
	env, ok := crObject(envelope)
	if !ok {
		return none, nil, nil, false
	}
	if _, ok := crMembers(env, []string{"payloadType", "payload", "signatures"}); !ok ||
		env["payloadType"] != crRevocationType {
		return none, nil, nil, false
	}
	payload, ok := crB64(env["payload"])
	if !ok {
		return none, nil, nil, false
	}
	sigs, ok := crParseSignatures(env["signatures"])
	if !ok {
		return none, nil, nil, false
	}
	out, ok := crParseListing(payload)
	if !ok {
		return none, nil, nil, false
	}
	return out, payload, sigs, true
}

// crParseSignatures decodes the envelope's non-empty signature array.
func crParseSignatures(value any) ([][]byte, bool) {
	items, isList := value.([]any)
	if !isList || len(items) == 0 {
		return nil, false
	}
	var sigs [][]byte
	for _, item := range items {
		entry, ok := crMembers(item, []string{"sig"}, "keyid")
		if !ok {
			return nil, false
		}
		sig, ok := crB64(entry["sig"])
		if !ok {
			return nil, false
		}
		sigs = append(sigs, sig)
	}
	return sigs, true
}

// crParseListing decodes the signed revocation listing payload.
func crParseListing(payload []byte) (crList, bool) {
	var none crList
	listing, ok := crObject(payload)
	if !ok {
		return none, false
	}
	if _, ok := crMembers(listing, []string{"issuedAt", "nextUpdate", "revoked"}); !ok {
		return none, false
	}
	issued, okA := crTime(listing["issuedAt"])
	next, okB := crTime(listing["nextUpdate"])
	revoked, okC := listing["revoked"].([]any)
	if !okA || !okB || !okC || !issued.Before(next) || !crSortedUnique(revoked) {
		return none, false
	}
	out := crList{issued: issued, next: next, revoked: map[string]bool{}}
	for _, item := range revoked {
		text := item.(string)
		if !crHex.MatchString(text) {
			return none, false
		}
		out.revoked[text] = true
	}
	return out, true
}

func crSignedBy(key, payload []byte, sigs [][]byte) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	message := caPAE(crRevocationType, payload)
	for _, sig := range sigs {
		if ed25519.Verify(key, message, sig) {
			return true
		}
	}
	return false
}

// crRevocation is the first revocation-list check that fails at the given time,
// or "". present is false when no list was supplied.
func crRevocation(envelope []byte, present bool, key []byte, at time.Time, receiptDigest string) string {
	if !present {
		return "revocation_list_absent"
	}
	list, payload, sigs, ok := crParseList(envelope)
	if !ok {
		return "revocation_list_malformed"
	}
	if !crSignedBy(key, payload, sigs) {
		return "revocation_list_signature"
	}
	if at.Before(list.issued) || !at.Before(list.next) {
		return "revocation_list_stale"
	}
	if list.revoked[receiptDigest] {
		return "receipt_revoked"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Judging one member
// ---------------------------------------------------------------------------

// crReceiptFailure is the Statement and predicate checks of a receipt.
func crReceiptFailure(raw []byte) (string, crObj) {
	statement, ok := crObject(raw)
	if !ok {
		return "statement_malformed", nil
	}
	if failure := crStatement(statement, crReceiptType); failure != "" {
		return failure, statement
	}
	if !crReceiptPredicateOK(statement["predicate"]) {
		return "predicate_malformed", statement
	}
	return "", statement
}

func crSubjectDigest(statement crObj) string {
	digest, _ := crSHA(statement["subject"].([]any)[0].(crObj)["digest"])
	return digest
}

func crReceiptDecide(dir string, context crObj, key []byte) (scDecision, error) {
	raw, _ := crRead(dir, "statement.json")
	failure, statement := crReceiptFailure(raw)
	if failure != "" {
		return crReject(failure), nil
	}
	now, ok := crTime(context["now"])
	if !ok {
		return scDecision{}, fmt.Errorf("context.json now is not a time")
	}
	predicate := statement["predicate"].(crObj)
	start, _ := crTime(predicate["issuedAt"])
	until, _ := crTime(predicate["validUntil"])
	if !start.Before(until) {
		return crReject("validity_window_inverted"), nil
	}
	card, _ := crRead(dir, "card.json")
	digest, ok := crCardDigest(card)
	if !ok {
		return crReject("card_malformed"), nil
	}
	if crSubjectDigest(statement) != digest {
		return crReject("card_digest_mismatch"), nil
	}
	if now.Before(start) {
		return crReject("receipt_not_yet_valid"), nil
	}
	if !now.Before(until) {
		return crReject("receipt_expired"), nil
	}
	list, present := crRead(dir, "revocations.json")
	if failure := crRevocation(list, present, key, now, sha(raw)); failure != "" {
		return crReject(failure), nil
	}
	return scDecision{"accept", "receipt_current"}, nil
}

func crReleaseStatementFailure(raw []byte) (string, crObj) {
	statement, ok := crObject(raw)
	if !ok {
		return "statement_malformed", nil
	}
	if failure := crStatement(statement, crReleaseType); failure != "" {
		return failure, statement
	}
	if crCredentialFields(statement["predicate"]) {
		return "credential_fields", statement
	}
	if !crReleasePredicateOK(statement["predicate"]) {
		return "predicate_malformed", statement
	}
	return "", statement
}

func crReleaseDecide(dir string, _ crObj, key []byte) (scDecision, error) {
	raw, _ := crRead(dir, "statement.json")
	failure, statement := crReleaseStatementFailure(raw)
	if failure != "" {
		return crReject(failure), nil
	}
	predicate := statement["predicate"].(crObj)
	declared := predicate["receipt"].(crObj)
	receiptBytes, _ := crRead(dir, "receipt.json")
	named, _ := crSHA(declared["digest"])
	if sha(receiptBytes) != named {
		return crReject("receipt_digest_mismatch"), nil
	}
	receiptFailure, receipt := crReceiptFailure(receiptBytes)
	if receiptFailure != "" {
		return crReject("receipt_malformed"), nil
	}
	held := receipt["predicate"].(crObj)
	if declared["result"] != held["result"] || declared["validUntil"] != held["validUntil"] {
		return crReject("receipt_fields_differ"), nil
	}
	if crSubjectDigest(statement) != crSubjectDigest(receipt) {
		return crReject("subject_not_receipted"), nil
	}
	if crResultIndex(declared["result"]) < crResultIndex(predicate["minResult"]) {
		return crReject("receipt_not_passing"), nil
	}
	at, _ := crTime(predicate["releasedAt"])
	start, _ := crTime(held["issuedAt"])
	until, _ := crTime(held["validUntil"])
	if at.Before(start) || !at.Before(until) {
		return crReject("receipt_not_current"), nil
	}
	ttl, _ := predicate["ttlSeconds"].(json.Number).Int64()
	if at.Add(time.Duration(ttl) * time.Second).After(until) {
		return crReject("credential_outlives_receipt"), nil
	}
	list, present := crRead(dir, "revocations.json")
	listed, _ := crSHA(predicate["revocationList"].(crObj)["digest"])
	if !present || sha(list) != listed {
		return crReject("revocation_list_digest_mismatch"), nil
	}
	if failure := crRevocation(list, present, key, at, sha(receiptBytes)); failure != "" {
		return crReject(failure), nil
	}
	return scDecision{"accept", "release_bound"}, nil
}
