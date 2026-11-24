package corpusreaders

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"time"
)

func init() { register(actorMarker{}) }

// actorMarker judges corpora/vectors-actor-marker-survival/. Each member is a chain
// of signed statements: an origin issuer's statement of the token it sent, then one
// statement per hop of the token it received and the token it sent, in the native
// form of each side's protocol (RFC 8693 nested act claims, or the A2A actorChain
// shape proposed in a2aproject/A2A issue 2028). Signatures are Ed25519 over the RFC
// 8785 bytes of each statement, under keys and roles from the corpus's TRUST.json,
// never from the record. The reader applies the twenty checks of the Python reader
// (packaging/agent_evidence_vectors/actormarker.py) in the same order and derives
// each member's decision from the record alone.
type actorMarker struct{}

const amContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/actor-marker-survival"

func (actorMarker) Suite() string { return "actor-marker-survival/v1" }

var (
	amTime   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	amHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	amB64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	errAM    = errors.New("record_malformed")
)

type amDelivered struct {
	Actors  []string `json:"actors"`
	Subject string   `json:"subject"`
}

type amRetained struct {
	Delivered     *amDelivered `json:"delivered"`
	SigningInputs []string     `json:"signingInputs"`
}

type amVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained amRetained        `json:"retained"`
}

type amManifest struct {
	CorpusDigest string            `json:"corpusDigest"`
	TrustSHA256  string            `json:"trustSha256"`
	Vectors      []json.RawMessage `json:"vectors"`
}

type amWriter struct {
	Key  string `json:"key"`
	Role string `json:"role"`
}

type amTrust struct {
	Writers map[string]amWriter `json:"writers"`
}

type amPrincipals struct {
	Subject string
	Actors  []string
}

func (p amPrincipals) equal(o amPrincipals) bool {
	return p.Subject == o.Subject && slices.Equal(p.Actors, o.Actors)
}

func (actorMarker) Judge(dir string, raw []byte) (*Result, error) {
	var manifest amManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	trustBytes, err := readIn(dir, "TRUST.json")
	if err != nil {
		return nil, fmt.Errorf("%s/TRUST.json cannot be read: %w", dir, err)
	}
	if sha(trustBytes) != manifest.TrustSHA256 {
		result.Findings = append(result.Findings, "TRUST.json does not match the digest the manifest pins")
	}
	var trust amTrust
	if err := strictUnmarshal(trustBytes, &trust); err != nil {
		return nil, fmt.Errorf("%s/TRUST.json does not parse: %w", dir, err)
	}
	for _, entry := range manifest.Vectors {
		var v amVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = amJudgeMember(filepath.Join(dir, v.Path), v, trust)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(scManifest{CorpusDigest: manifest.CorpusDigest, Vectors: manifest.Vectors}); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func amJudgeMember(caseDir string, v amVector, trust amTrust) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, "record.json cannot be read")
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, "record.json does not parse: "+err.Error())
	}
	record, _ := value.(map[string]any)
	retained := amRetain(record)
	if !reflect.DeepEqual(retained, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	for index, digest := range retained.SigningInputs {
		pinned, err := readIn(caseDir, fmt.Sprintf("signing-input-%d.jcs", index))
		if err != nil || sha(pinned) != digest {
			findings = append(findings, fmt.Sprintf("signing-input-%d.jcs is not the RFC 8785 form of statement %d", index, index))
		}
	}
	if got := amDecide(record, trust); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// Shape ------------------------------------------------------------------------------

func amObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func amStr(v any) (string, bool) { s, ok := v.(string); return s, ok }

func amIsTime(v any) bool { s, ok := amStr(v); return ok && amTime.MatchString(s) }

func amSeconds(s string) int64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func amSub(v any) (string, error) {
	m, ok := amObj(v)
	if !ok {
		return "", errAM
	}
	s, ok := amStr(m["sub"])
	if !ok || s == "" {
		return "", errAM
	}
	return s, nil
}

// amDecode reads the subject and the ordered actors (first actor first) of one token.
func amDecode(part any) (amPrincipals, error) {
	holder, ok := amObj(part)
	if !ok {
		return amPrincipals{}, errAM
	}
	token, ok := amObj(holder["token"])
	if !ok {
		return amPrincipals{}, errAM
	}
	switch holder["protocol"] {
	case "rfc8693":
		header, okH := amObj(token["header"])
		claims, okC := amObj(token["claims"])
		if !okH || !okC {
			return amPrincipals{}, errAM
		}
		if crit, present := header["crit"]; present {
			list, ok := crit.([]any)
			if !ok {
				return amPrincipals{}, errAM
			}
			for _, c := range list {
				if _, ok := amStr(c); !ok {
					return amPrincipals{}, errAM
				}
			}
		}
		if exp, present := claims["exp"]; present && exp != nil {
			n, ok := exp.(json.Number)
			if _, err := n.Int64(); !ok || err != nil {
				return amPrincipals{}, errAM
			}
		}
		subject, err := amSub(claims)
		if err != nil {
			return amPrincipals{}, err
		}
		var actors []string
		act, present := claims["act"]
		for present && act != nil {
			sub, err := amSub(act)
			if err != nil {
				return amPrincipals{}, err
			}
			actors = append(actors, sub)
			act, present = act.(map[string]any)["act"]
		}
		slices.Reverse(actors)
		return amPrincipals{subject, actors}, nil
	case "a2a-actor-chain":
		chain, ok := amObj(token["actorChain"])
		if !ok {
			return amPrincipals{}, errAM
		}
		listed, ok := chain["actors"].([]any)
		if !ok {
			return amPrincipals{}, errAM
		}
		subject, err := amSub(chain["origin"])
		if err != nil {
			return amPrincipals{}, err
		}
		actors := []string{}
		for _, a := range listed {
			sub, err := amSub(a)
			if err != nil {
				return amPrincipals{}, err
			}
			actors = append(actors, sub)
		}
		return amPrincipals{subject, actors}, nil
	}
	return amPrincipals{}, errAM
}

func amShapeSide(v any, to bool) bool {
	side, ok := amObj(v)
	if !ok || !amIsTime(side["at"]) {
		return false
	}
	if to {
		if s, ok := amStr(side["to"]); !ok || s == "" {
			return false
		}
	}
	_, err := amDecode(side)
	return err == nil
}

func amShapeEntry(index int, v any) bool {
	item, ok := amObj(v)
	if !ok {
		return false
	}
	if _, ok := amStr(item["signature"]); !ok {
		return false
	}
	statement, ok := amObj(item["statement"])
	if !ok {
		return false
	}
	if _, ok := amStr(statement["writer"]); !ok {
		return false
	}
	if t, present := item["transport"]; present {
		transport, ok := amObj(t)
		headers, okH := amObj(transport["headers"])
		if !ok || !okH {
			return false
		}
		for _, h := range headers {
			if _, ok := amStr(h); !ok {
				return false
			}
		}
	}
	kind := "hop"
	if index == 0 {
		kind = "origin"
	}
	if statement["kind"] != kind || !amShapeSide(statement["sent"], true) {
		return false
	}
	if index == 0 {
		if e, present := statement["humanEvidence"]; present && e != nil {
			evidence, ok := amObj(e)
			if _, okM := amStr(evidence["method"]); !ok || !okM || !amIsTime(evidence["at"]) {
				return false
			}
		}
		return true
	}
	if prev, ok := amStr(statement["prev"]); !ok || !amHex64.MatchString(prev) {
		return false
	}
	if !amShapeSide(statement["received"], false) {
		return false
	}
	if d, present := statement["deferred"]; present && d != nil {
		deferred, ok := amObj(d)
		if !ok || !amIsTime(deferred["enqueuedAt"]) || !amIsTime(deferred["dispatchedAt"]) {
			return false
		}
		sent, _ := amObj(statement["sent"])
		if deferred["dispatchedAt"] != sent["at"] {
			return false
		}
		if amSeconds(deferred["enqueuedAt"].(string)) > amSeconds(deferred["dispatchedAt"].(string)) {
			return false
		}
	}
	return true
}

func amShape(record map[string]any) bool {
	items, ok := record["statements"].([]any)
	if !ok || len(items) < 2 {
		return false
	}
	for index, item := range items {
		if !amShapeEntry(index, item) {
			return false
		}
	}
	return true
}

// The chain ---------------------------------------------------------------------------

type amChain struct {
	items      []map[string]any
	statements []map[string]any
	writers    map[string]amWriter
}

func newAMChain(record map[string]any, trust amTrust) amChain {
	c := amChain{writers: trust.Writers}
	for _, item := range record["statements"].([]any) {
		entry := item.(map[string]any)
		c.items = append(c.items, entry)
		c.statements = append(c.statements, entry["statement"].(map[string]any))
	}
	return c
}

func (c amChain) role(s map[string]any) string { return c.writers[s["writer"].(string)].Role }

func amSide(s map[string]any, name string) map[string]any { return s[name].(map[string]any) }

func amMust(part any) amPrincipals { p, _ := amDecode(part); return p }

func amJCS(v any) []byte { b, _ := rfc8785Bytes(v); return b }

func amCritical(part map[string]any) []string {
	if part["protocol"] != "rfc8693" {
		return nil
	}
	header := amSide(amSide(part, "token"), "header")
	var out []string
	if list, ok := header["crit"].([]any); ok {
		for _, c := range list {
			out = append(out, c.(string))
		}
	}
	return out
}

func amExpiry(part map[string]any) (int64, bool) {
	if part["protocol"] != "rfc8693" {
		return 0, false
	}
	n, ok := amSide(amSide(part, "token"), "claims")["exp"].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	return v, err == nil
}

func (c amChain) owed(s map[string]any) amPrincipals {
	p := amMust(s["received"])
	actors := slices.Clone(p.Actors)
	if c.role(s) == "agent" {
		actors = append(actors, s["writer"].(string))
	}
	return amPrincipals{p.Subject, actors}
}

func amUnB64URL(s string, length int) []byte {
	if !amB64URL.MatchString(s) || len(s)%4 == 1 {
		return nil
	}
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(data) != length || base64.RawURLEncoding.EncodeToString(data) != s {
		return nil
	}
	return data
}

func (c amChain) writerUnknown() bool {
	for i, s := range c.statements {
		w, ok := c.writers[s["writer"].(string)]
		if !ok || (w.Role == "origin") != (i == 0) || (i > 0 && w.Role != "agent" && w.Role != "relay") {
			return true
		}
	}
	return false
}

func (c amChain) signatureInvalid() bool {
	for _, item := range c.items {
		s := item["statement"].(map[string]any)
		key := amUnB64URL(c.writers[s["writer"].(string)].Key, ed25519.PublicKeySize)
		sig := amUnB64URL(item["signature"].(string), ed25519.SignatureSize)
		if key == nil || sig == nil || !ed25519.Verify(ed25519.PublicKey(key), amJCS(s), sig) {
			return true
		}
	}
	return false
}

func (c amChain) hopsAny(fails func(i int, s map[string]any) bool) bool {
	for i := 1; i < len(c.statements); i++ {
		if fails(i, c.statements[i]) {
			return true
		}
	}
	return false
}

func amToken(side map[string]any) []byte {
	return amJCS(map[string]any{"protocol": side["protocol"], "token": side["token"]})
}

func amClassify(expected, sent []string) string {
	switch {
	case slices.Equal(sent, expected):
		return ""
	case len(sent) == 0:
		return "downgraded_to_user_alone"
	case amSameMultiset(sent, expected):
		return "actor_order_changed"
	case len(sent) < len(expected) && amSubsequence(sent, expected):
		if slices.Equal(expected[len(expected)-len(sent):], sent) {
			return "chain_truncated"
		}
		return "marker_stripped"
	case len(sent) > len(expected) && amSubsequence(expected, sent):
		return "actor_inserted"
	}
	return "agent_replaced"
}

func amSameMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func amSubsequence(short, long []string) bool {
	i := 0
	for _, item := range long {
		if i < len(short) && short[i] == item {
			i++
		}
	}
	return i == len(short)
}

type amCheck struct {
	reason string
	fails  func() bool
}

func (c amChain) checks() []amCheck {
	out := []amCheck{
		{"statement_writer_unknown", c.writerUnknown},
		{"statement_signature_invalid", c.signatureInvalid},
		{"hop_link_broken", func() bool {
			return c.hopsAny(func(i int, s map[string]any) bool { return s["prev"] != sha(amJCS(c.statements[i-1])) })
		}},
		{"audience_mismatch", func() bool {
			return c.hopsAny(func(i int, s map[string]any) bool { return s["writer"] != amSide(c.statements[i-1], "sent")["to"] })
		}},
		{"received_not_sent", func() bool {
			return c.hopsAny(func(i int, s map[string]any) bool {
				return string(amToken(amSide(s, "received"))) != string(amToken(amSide(c.statements[i-1], "sent")))
			})
		}},
		{"unknown_critical_attribute_ignored", func() bool {
			return c.hopsAny(func(_ int, s map[string]any) bool { return len(amCritical(amSide(s, "received"))) > 0 })
		}},
		{"principals_expired_at_use", func() bool {
			return c.hopsAny(func(_ int, s map[string]any) bool {
				exp, ok := amExpiry(amSide(s, "received"))
				return ok && amSeconds(amSide(s, "sent")["at"].(string)) > exp
			})
		}},
		{"marker_unsigned", func() bool {
			return c.hopsAny(func(i int, s map[string]any) bool {
				writer := s["writer"].(string)
				if c.role(s) != "agent" || slices.Contains(amMust(s["sent"]).Actors, writer) {
					return false
				}
				transport, _ := amObj(c.items[i]["transport"])
				headers, _ := amObj(transport["headers"])
				for _, h := range headers {
					if h == writer {
						return true
					}
				}
				return false
			})
		}},
		{"deferred_dispatch_without_stored_principals", func() bool {
			return c.hopsAny(func(_ int, s map[string]any) bool {
				d, present := s["deferred"]
				return present && d != nil && !amMust(s["sent"]).equal(c.owed(s))
			})
		}},
		{"subject_replaced", func() bool {
			return c.hopsAny(func(_ int, s map[string]any) bool { return amMust(s["sent"]).Subject != amMust(s["received"]).Subject })
		}},
	}
	for _, class := range []string{"downgraded_to_user_alone", "chain_truncated", "marker_stripped",
		"agent_replaced", "actor_order_changed", "actor_inserted"} {
		out = append(out, amCheck{class, func() bool {
			return c.hopsAny(func(_ int, s map[string]any) bool {
				return amClassify(c.owed(s).Actors, amMust(s["sent"]).Actors) == class
			})
		}})
	}
	return append(out, amCheck{"user_alone_without_human_evidence", func() bool {
		if len(amMust(amSide(c.statements[len(c.statements)-1], "sent")).Actors) > 0 {
			return false
		}
		evidence, ok := amObj(c.statements[0]["humanEvidence"])
		return !ok || evidence["method"] != "user-presence"
	}})
}

func amDecide(record map[string]any, trust amTrust) scDecision {
	if record == nil {
		return scDecision{"reject", "record_malformed"}
	}
	contract, present := record["contractId"]
	if !present {
		return scDecision{"reject", "contract_id_missing"}
	}
	if contract != amContractID {
		return scDecision{"reject", "contract_id_unknown"}
	}
	if !amShape(record) {
		return scDecision{"reject", "record_malformed"}
	}
	chain := newAMChain(record, trust)
	for _, check := range chain.checks() {
		if check.fails() {
			return scDecision{"reject", check.reason}
		}
	}
	return scDecision{"accept", "marker_survives"}
}

func amRetain(record map[string]any) amRetained {
	if record == nil || !amShape(record) {
		return amRetained{SigningInputs: []string{}}
	}
	items := record["statements"].([]any)
	last := items[len(items)-1].(map[string]any)["statement"].(map[string]any)
	p := amMust(last["sent"])
	actors := p.Actors
	if actors == nil {
		actors = []string{}
	}
	inputs := []string{}
	for _, item := range items {
		inputs = append(inputs, sha(amJCS(item.(map[string]any)["statement"])))
	}
	return amRetained{Delivered: &amDelivered{Actors: actors, Subject: p.Subject}, SigningInputs: inputs}
}
