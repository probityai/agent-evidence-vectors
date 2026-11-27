package corpusreaders

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
)

func init() { register(destExchange{}) }

// destExchange judges corpora/vectors-destination-narrowed-exchange/. Each member is a
// chain of signed statements: an issuer's delegated token, optional revocations, an
// exchanger's exchange of that token for one token aimed at one destination, and the
// destination verifier's presentation of what it received. Signatures are Ed25519 over
// the RFC 8785 bytes of each statement, under keys and roles from the corpus's
// TRUST.json, never from the record. The reader applies the 31 checks of the Python
// reader (packaging/agent_evidence_vectors/destexchange.py) in the same order and
// derives each member's decision from the record alone.
type destExchange struct{}

const deContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/destination-narrowed-exchange"

func (destExchange) Suite() string { return "destination-narrowed-exchange/v1" }

type deDelivered struct {
	Actors   []string `json:"actors"`
	Rights   []string `json:"rights"`
	Subject  string   `json:"subject"`
	Verifier string   `json:"verifier"`
}

type deRetained struct {
	Delivered     []deDelivered `json:"delivered"`
	SigningInputs []string      `json:"signingInputs"`
}

type deVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained deRetained        `json:"retained"`
}

type deBad struct{ why string }

// deNeed stops the shape check at the first thing the contract does not read. The
// shape check recovers it, and any other failed assertion, as "record_malformed".
func deNeed(ok bool, why string) {
	if !ok {
		panic(deBad{why})
	}
}

func deObj(v any) map[string]any {
	m, ok := v.(map[string]any)
	deNeed(ok, "not an object")
	return m
}

func deText(v any) bool { s, ok := v.(string); return ok && s != "" }

// deInt reads a JSON integer of any size, as Python reads an int. A float is not one.
func deInt(v any) (*big.Int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	return new(big.Int).SetString(n.String(), 10)
}

func deSeconds(s string) int64 {
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	deNeed(err == nil && t.Year() >= 1, "not a time")
	return t.Unix()
}

func deScopes(text string) map[string]bool {
	set := map[string]bool{}
	for _, part := range strings.Split(text, " ") {
		deNeed(part != "" && !set[part], "scope is not distinct names")
		set[part] = true
	}
	return set
}

func deClaims(side map[string]any) map[string]any { return deObj(deObj(side["token"])["claims"]) }

func deTokenBytes(side map[string]any) []byte {
	return amJCS(map[string]any{"protocol": side["protocol"], "token": side["token"]})
}

func deMust(side any) amPrincipals { p, _ := amDecode(side); return p }

// Shape ------------------------------------------------------------------------------

func deShapeToken(v any, delegated bool) {
	side := deObj(v)
	deNeed(amIsTime(side["at"]), "at")
	deNeed(side["protocol"] == "rfc8693", "protocol")
	_, err := amDecode(side)
	deNeed(err == nil, "decode")
	body := deClaims(side)
	scope, ok := body["scope"].(string)
	deNeed(ok, "scope")
	deScopes(scope)
	iat, okIat := deInt(body["iat"])
	exp, okExp := deInt(body["exp"])
	deNeed(okIat && okExp && iat.Cmp(exp) <= 0, "iat and exp")
	if !delegated {
		deNeed(deText(body["aud"]), "aud is not one verifier")
		return
	}
	audience, ok := body["aud"].([]any)
	deNeed(ok && len(audience) > 0, "aud")
	for _, a := range audience {
		deNeed(deText(a), "aud member")
	}
	deNeed(deText(body["jti"]), "jti")
	if cnf := body["cnf"]; cnf != nil {
		deNeed(deText(deObj(cnf)["jkt"]), "cnf")
	}
}

func deShapeProof(v any) {
	proof := deObj(v)
	jwk := deObj(proof["jwk"])
	_, okX := jwk["x"].(string)
	deNeed(jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && okX, "proof.jwk")
	payload := deObj(proof["payload"])
	_, okAth := payload["ath"].(string)
	_, okAud := payload["aud"].(string)
	_, okIat := deInt(payload["iat"])
	deNeed(len(payload) == 3 && okAth && okAud && okIat, "proof.payload")
	_, okSig := proof["signature"].(string)
	deNeed(okSig, "proof.signature")
}

var deCarriers = []string{"authorization-header", "query", "form-body"}

func deShapeReceived(v any, exchange bool) {
	side := deObj(v)
	carried, _ := side["carriedIn"].(string)
	deNeed(slices.Contains(deCarriers, carried), "carriedIn")
	deShapeToken(side, exchange)
	if exchange {
		deNeed(deText(side["from"]), "from")
		if proof, present := side["proof"]; present {
			deShapeProof(proof)
		}
	}
}

func deTime(s map[string]any) int64 {
	switch s["kind"] {
	case "origin":
		return deSeconds(deObj(s["sent"])["at"].(string))
	case "revocation":
		return deSeconds(s["at"].(string))
	}
	return deSeconds(deObj(s["received"])["at"].(string))
}

func deShapeStatement(index int, v any) {
	s := deObj(v)
	_, ok := s["writer"].(string)
	deNeed(ok, "writer")
	kind, _ := s["kind"].(string)
	deNeed((kind == "origin") == (index == 0), "the origin is not the first statement")
	deNeed(slices.Contains([]string{"origin", "revocation", "exchange", "presentation"}, kind), "kind")
	if index > 0 {
		prev, ok := s["prev"].(string)
		deNeed(ok && amHex64.MatchString(prev), "prev")
	}
	switch kind {
	case "origin":
		deShapeToken(s["sent"], true)
		deNeed(deText(deObj(s["sent"])["to"]), "sent.to")
		for _, value := range deObj(s["entitlements"]) {
			text, ok := value.(string)
			deNeed(ok, "entitlements")
			deScopes(text)
		}
	case "revocation":
		deNeed(amIsTime(s["at"]) && deText(s["jti"]), "revocation")
	case "exchange":
		deShapeReceived(s["received"], true)
		deShapeToken(s["sent"], false)
		deNeed(deText(deObj(s["sent"])["to"]), "sent.to")
		deNeed(deSeconds(deObj(s["received"])["at"].(string)) <= deSeconds(deObj(s["sent"])["at"].(string)), "order")
		if check := s["destinationCheck"]; check != nil {
			c := deObj(check)
			digest, ok := c["allowlistSha256"].(string)
			deNeed(len(c) == 2 && deText(c["destination"]) && ok && amHex64.MatchString(digest), "destinationCheck")
		}
	default:
		deShapeReceived(s["received"], false)
	}
}

// deShape reports whether the record has the shape this contract reads. Any failed
// assertion inside it is "record_malformed", as any exception is in the Python reader.
func deShape(record map[string]any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	items, isList := record["statements"].([]any)
	deNeed(isList && len(items) >= 2, "statements")
	var previous int64
	for index, entry := range items {
		item := deObj(entry)
		_, hasSig := item["signature"].(string)
		deNeed(hasSig, "entry")
		deShapeStatement(index, item["statement"])
		now := deTime(item["statement"].(map[string]any))
		deNeed(index == 0 || previous <= now, "statements are not in time order")
		previous = now
	}
	return true
}

// The chain ---------------------------------------------------------------------------

type deChain struct {
	items      []map[string]any
	statements []map[string]any
	trust      map[string]any
	writers    map[string]any
	origin     map[string]any
	delegated  map[string]any
}

func newDEChain(record, trust map[string]any) deChain {
	c := deChain{trust: trust, writers: trust["writers"].(map[string]any)}
	for _, entry := range record["statements"].([]any) {
		item := entry.(map[string]any)
		c.items = append(c.items, item)
		c.statements = append(c.statements, item["statement"].(map[string]any))
	}
	c.origin = c.statements[0]
	c.delegated = deClaims(deObj(c.origin["sent"]))
	return c
}

func deSide(s map[string]any, name string) map[string]any { return s[name].(map[string]any) }

func (c deChain) exchanges() []map[string]any { return c.ofKind("exchange") }

func (c deChain) ofKind(kind string) []map[string]any {
	var out []map[string]any
	for _, s := range c.statements {
		if s["kind"] == kind {
			out = append(out, s)
		}
	}
	return out
}

// presentations returns each presentation with the statement before it.
func (c deChain) presentations() (out [][2]map[string]any) {
	for i, s := range c.statements {
		if s["kind"] == "presentation" {
			out = append(out, [2]map[string]any{s, c.statements[i-1]})
		}
	}
	return out
}

func deRole(kind any) string {
	switch kind {
	case "origin", "revocation":
		return "issuer"
	case "exchange":
		return "exchanger"
	}
	return "destination"
}

func (c deChain) writerUnknown() bool {
	for _, s := range c.statements {
		writer, ok := c.writers[s["writer"].(string)].(map[string]any)
		if !ok || writer["role"] != deRole(s["kind"]) {
			return true
		}
	}
	return false
}

func deUnB64(v any, length int) []byte {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return amUnB64URL(s, length)
}

func (c deChain) signatureInvalid() bool {
	for _, item := range c.items {
		s := item["statement"].(map[string]any)
		key := deUnB64(c.writers[s["writer"].(string)].(map[string]any)["key"], ed25519.PublicKeySize)
		sig := deUnB64(item["signature"], ed25519.SignatureSize)
		if key == nil || sig == nil || !ed25519.Verify(ed25519.PublicKey(key), amJCS(s), sig) {
			return true
		}
	}
	return false
}

func (c deChain) linkBroken() bool {
	for i := 1; i < len(c.statements); i++ {
		if c.statements[i]["prev"] != sha(amJCS(c.statements[i-1])) {
			return true
		}
	}
	return false
}

func (c deChain) unrecorded() bool {
	for _, p := range c.presentations() {
		if p[1]["kind"] != "exchange" {
			return true
		}
	}
	return false
}

func (c deChain) receivedNotSent() bool {
	issued := string(deTokenBytes(deSide(c.origin, "sent")))
	for _, s := range c.exchanges() {
		if string(deTokenBytes(deSide(s, "received"))) != issued {
			return true
		}
	}
	for _, p := range c.presentations() {
		if string(deTokenBytes(deSide(p[0], "received"))) != string(deTokenBytes(deSide(p[1], "sent"))) {
			return true
		}
	}
	return false
}

func (c deChain) offDestination() bool {
	for _, p := range c.presentations() {
		minted := deSide(p[1], "sent")
		if p[0]["writer"] != minted["to"] || p[0]["writer"] != deClaims(minted)["aud"] {
			return true
		}
	}
	return false
}

func (c deChain) inParameter() bool {
	for _, s := range c.statements {
		if (s["kind"] == "exchange" || s["kind"] == "presentation") &&
			deSide(s, "received")["carriedIn"] != "authorization-header" {
			return true
		}
	}
	return false
}

func (c deChain) unmarked() bool { return len(deMust(deSide(c.origin, "sent")).Actors) == 0 }

func (c deChain) outsideIntermediaries() bool {
	for _, s := range c.exchanges() {
		found := false
		for _, a := range c.delegated["aud"].([]any) {
			found = found || a == s["writer"]
		}
		if !found {
			return true
		}
	}
	return false
}

func (c deChain) revoked() bool {
	var revokedAt *int64
	for _, s := range c.statements {
		switch s["kind"] {
		case "revocation":
			if s["jti"] == c.delegated["jti"] {
				when := deSeconds(s["at"].(string))
				if revokedAt == nil || when < *revokedAt {
					revokedAt = &when
				}
			}
		case "exchange":
			if revokedAt != nil && *revokedAt <= deSeconds(deSide(s, "received")["at"].(string)) {
				return true
			}
		}
	}
	return false
}

func (c deChain) expired() bool {
	exp, _ := deInt(c.delegated["exp"])
	for _, s := range c.exchanges() {
		if big.NewInt(deSeconds(deSide(s, "received")["at"].(string))).Cmp(exp) >= 0 {
			return true
		}
	}
	return false
}

func (c deChain) lifetimeOver() bool {
	exp, _ := deInt(c.delegated["exp"])
	iat, _ := deInt(c.delegated["iat"])
	limit, ok := new(big.Rat).SetString(c.trust["maxDelegatedLifetimeSeconds"].(json.Number).String())
	deNeed(ok, "maxDelegatedLifetimeSeconds")
	return new(big.Rat).SetInt(new(big.Int).Sub(exp, iat)).Cmp(limit) > 0
}

func (c deChain) unbound() bool { return c.delegated["cnf"] == nil }

func (c deChain) proofMissing() bool {
	for _, s := range c.exchanges() {
		if _, present := deSide(s, "received")["proof"]; !present {
			return true
		}
	}
	return false
}

func deThumbprint(jwk map[string]any) string {
	digest := sha256.Sum256(amJCS(map[string]any{"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (c deChain) proofInvalid() bool {
	for _, s := range c.exchanges() {
		received := deSide(s, "received")
		proof := deSide(received, "proof")
		jwk, payload := deSide(proof, "jwk"), deSide(proof, "payload")
		key := deUnB64(jwk["x"], ed25519.PublicKeySize)
		sig := deUnB64(proof["signature"], ed25519.SignatureSize)
		if key == nil || sig == nil ||
			deThumbprint(jwk) != deSide(c.delegated, "cnf")["jkt"] ||
			!ed25519.Verify(ed25519.PublicKey(key), amJCS(payload), sig) {
			return true
		}
		held := sha256.Sum256(deTokenBytes(received))
		iat, _ := deInt(payload["iat"])
		if payload["ath"] != base64.RawURLEncoding.EncodeToString(held[:]) ||
			payload["aud"] != s["writer"] ||
			iat.Cmp(big.NewInt(deSeconds(received["at"].(string)))) != 0 {
			return true
		}
	}
	return false
}

func (c deChain) checkSkipped() bool {
	digest := sha(amJCS(c.trust["destinations"]))
	for _, s := range c.exchanges() {
		check, ok := s["destinationCheck"].(map[string]any)
		if !ok || check["allowlistSha256"] != digest {
			return true
		}
	}
	return false
}

func (c deChain) destination(s map[string]any) string {
	return deSide(s, "destinationCheck")["destination"].(string)
}

func (c deChain) offAllowlist() bool {
	listed := c.trust["destinations"].(map[string]any)
	for _, s := range c.exchanges() {
		if _, ok := listed[c.destination(s)]; !ok {
			return true
		}
	}
	return false
}

func (c deChain) verifierMismatch() bool {
	listed := c.trust["destinations"].(map[string]any)
	for _, s := range c.exchanges() {
		verifier := listed[c.destination(s)].(map[string]any)["verifier"]
		sent := deSide(s, "sent")
		if sent["to"] != verifier || deClaims(sent)["aud"] != verifier {
			return true
		}
	}
	return false
}

func (c deChain) subjectReplaced() bool {
	for _, s := range c.exchanges() {
		if deMust(s["sent"]).Subject != deMust(s["received"]).Subject {
			return true
		}
	}
	return false
}

// deClassify names the actor-chain check an exchanged token fails, or "". The token
// owes the received chain with the exchanger appended as the current actor (RFC 8693
// section 4.1).
func deClassify(received []string, exchanger string, sent []string) string {
	owed := append(slices.Clone(received), exchanger)
	switch {
	case slices.Equal(sent, owed):
		return ""
	case len(sent) == 0:
		return "actor_lost_at_exchange"
	case len(received) > 0 && !slices.Contains(sent, received[len(received)-1]):
		return "agent_marker_dropped"
	case len(sent) < len(owed) && slices.Equal(owed[len(owed)-len(sent):], sent):
		return "previous_hop_dropped"
	case slices.Equal(sent, received):
		return "exchanger_not_in_chain"
	}
	return "chain_altered_at_exchange"
}

func (c deChain) actorClass(name string) bool {
	for _, s := range c.exchanges() {
		if deClassify(deMust(s["received"]).Actors, s["writer"].(string), deMust(s["sent"]).Actors) == name {
			return true
		}
	}
	return false
}

func deSubset(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// deRights names the rights check an exchanged token fails, or "". The token for one
// destination may carry only rights the delegation names for that destination.
func deRights(destination string, delegated, full, sent map[string]bool) string {
	here := map[string]bool{}
	for s := range delegated {
		if strings.HasPrefix(s, destination+":") {
			here[s] = true
		}
	}
	for s := range sent {
		if !strings.HasPrefix(s, destination+":") {
			return "rights_beyond_destination"
		}
	}
	switch {
	case deSubset(sent, here):
		return ""
	case deSubset(sent, full) && deSubset(full, sent) && deSubset(here, full) && len(here) < len(full):
		return "rights_not_narrowed"
	}
	return "rights_widened"
}

func (c deChain) rightsClass(name string) bool {
	entitlements := c.origin["entitlements"].(map[string]any)
	for _, s := range c.exchanges() {
		destination := c.destination(s)
		full := map[string]bool{}
		if text, _ := entitlements[destination].(string); text != "" {
			full = deScopes(text)
		}
		got := deRights(destination, deScopes(c.delegated["scope"].(string)), full,
			deScopes(deClaims(deSide(s, "sent"))["scope"].(string)))
		if got == name {
			return true
		}
	}
	return false
}

func (c deChain) exchangedExpired() bool {
	for _, p := range c.presentations() {
		exp, _ := deInt(deClaims(deSide(p[1], "sent"))["exp"])
		if big.NewInt(deSeconds(deSide(p[0], "received")["at"].(string))).Cmp(exp) >= 0 {
			return true
		}
	}
	return false
}

type deCheck struct {
	reason string
	fails  func() bool
}

func (c deChain) checks() []deCheck {
	out := []deCheck{
		{"statement_writer_unknown", c.writerUnknown},
		{"statement_signature_invalid", c.signatureInvalid},
		{"hop_link_broken", c.linkBroken},
		{"exchange_unrecorded", c.unrecorded},
		{"received_not_sent", c.receivedNotSent},
		{"token_presented_off_destination", c.offDestination},
		{"token_in_request_parameter", c.inParameter},
		{"delegated_token_unmarked", c.unmarked},
		{"exchanger_not_intermediary", c.outsideIntermediaries},
		{"delegated_token_revoked", c.revoked},
		{"delegated_token_expired", c.expired},
		{"delegated_lifetime_over_limit", c.lifetimeOver},
		{"delegated_token_unbound", c.unbound},
		{"holder_proof_missing", c.proofMissing},
		{"holder_proof_invalid", c.proofInvalid},
		{"destination_check_skipped", c.checkSkipped},
		{"destination_not_allowlisted", c.offAllowlist},
		{"destination_verifier_mismatch", c.verifierMismatch},
		{"subject_replaced", c.subjectReplaced},
	}
	for _, class := range []string{"actor_lost_at_exchange", "agent_marker_dropped",
		"previous_hop_dropped", "exchanger_not_in_chain", "chain_altered_at_exchange"} {
		out = append(out, deCheck{class, func() bool { return c.actorClass(class) }})
	}
	for _, class := range []string{"rights_beyond_destination", "rights_not_narrowed", "rights_widened"} {
		out = append(out, deCheck{class, func() bool { return c.rightsClass(class) }})
	}
	return append(out, deCheck{"exchanged_token_expired_at_use", c.exchangedExpired})
}

func deDecide(record, trust map[string]any) scDecision {
	if record == nil {
		return scDecision{"reject", "record_malformed"}
	}
	contract, present := record["contractId"]
	if !present {
		return scDecision{"reject", "contract_id_missing"}
	}
	if contract != deContractID {
		return scDecision{"reject", "contract_id_unknown"}
	}
	if !deShape(record) {
		return scDecision{"reject", "record_malformed"}
	}
	chain := newDEChain(record, trust)
	for _, check := range chain.checks() {
		if check.fails() {
			return scDecision{"reject", check.reason}
		}
	}
	return scDecision{"accept", "exchange_narrowed"}
}

func deRetain(record map[string]any) deRetained {
	if record == nil || !deShape(record) {
		return deRetained{SigningInputs: []string{}}
	}
	out := deRetained{Delivered: []deDelivered{}, SigningInputs: []string{}}
	for _, entry := range record["statements"].([]any) {
		s := entry.(map[string]any)["statement"].(map[string]any)
		out.SigningInputs = append(out.SigningInputs, sha(amJCS(s)))
		if s["kind"] != "presentation" {
			continue
		}
		received := deSide(s, "received")
		p := deMust(received)
		rights := []string{}
		for name := range deScopes(deClaims(received)["scope"].(string)) {
			rights = append(rights, name)
		}
		sort.Strings(rights)
		out.Delivered = append(out.Delivered, deDelivered{
			Actors: append([]string{}, p.Actors...), Rights: rights,
			Subject: p.Subject, Verifier: s["writer"].(string),
		})
	}
	return out
}

// Judge ------------------------------------------------------------------------------

func (destExchange) Judge(dir string, raw []byte) (*Result, error) {
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
	value, err := decodeJSONNumbers(trustBytes)
	trust, isObject := value.(map[string]any)
	if err != nil || !isObject {
		return nil, fmt.Errorf("%s/TRUST.json does not parse", dir)
	}
	for _, entry := range manifest.Vectors {
		var v deVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = deJudgeMember(filepath.Join(dir, v.Path), v, trust)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(scManifest{CorpusDigest: manifest.CorpusDigest, Vectors: manifest.Vectors}); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func deJudgeMember(caseDir string, v deVector, trust map[string]any) []string {
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
	retained := deRetain(record)
	if !reflect.DeepEqual(retained, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	for index, digest := range retained.SigningInputs {
		pinned, err := readIn(caseDir, fmt.Sprintf("signing-input-%d.jcs", index))
		if err != nil || sha(pinned) != digest {
			findings = append(findings, fmt.Sprintf("signing-input-%d.jcs is not the RFC 8785 form of statement %d", index, index))
		}
	}
	if got := deDecide(record, trust); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}
