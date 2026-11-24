package corpusreaders

import (
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

func init() { register(x402PaymentBinding{}) }

// x402PaymentBinding judges corpora/vectors-x402-payment-binding/: one x402
// evidence record, judged twice. The authorization verdict asks whether the
// record identifies one EIP-3009 authorization (network, asset contract, payer
// and nonce together); the settlement verdict asks whether the chain read
// identifies the Transfer log that settled it. The rules, their order and the
// x402 v1 network table are those of packaging/agent_evidence_vectors/x402binding.py.
type x402PaymentBinding struct{}

func (x402PaymentBinding) Suite() string { return "x402-payment-binding/v1" }

type xbVerdict struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type xbExpected struct {
	Authorization xbVerdict `json:"authorization"`
	Settlement    xbVerdict `json:"settlement"`
}

type xbVector struct {
	ID          string            `json:"id"`
	Path        string            `json:"path"`
	Files       map[string]string `json:"files"`
	Description string            `json:"description"`
	Rationale   string            `json:"rationale"`
	Expected    xbExpected        `json:"expected"`
	Twin        string            `json:"twin"`
}

func (e xbExpected) accepted() bool {
	return e.Authorization.State == "verified" && e.Settlement.State == "verified"
}

var xbCAIP2 = regexp.MustCompile(`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$`)

var xbInteger = regexp.MustCompile(`^-?[0-9]+$`)

var xbDigits = regexp.MustCompile(`^[0-9]+$`)

var xbV1ChainIDs = map[string]int{
	"base": 8453, "base-sepolia": 84532, "ethereum": 1, "polygon": 137,
	"polygon-amoy": 80002, "avalanche": 43114, "avalanche-fuji": 43113,
	"abstract": 2741, "abstract-testnet": 11124, "iotex": 4689, "sei": 1329,
	"sei-testnet": 1328, "peaq": 3338, "story": 1514, "educhain": 41923,
	"skale-base-sepolia": 324705682, "megaeth": 4326, "monad": 143,
	"monad-testnet": 10143, "stable": 988, "stable-testnet": 2201, "celo": 42220,
	"flare": 14, "hemi": 43111, "hemi-testnet": 743111,
}

// xbNetwork is the chain a served identifier names, or "" when it names none.
func xbNetwork(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	if xbCAIP2.MatchString(s) {
		return s
	}
	if chain, known := xbV1ChainIDs[s]; known {
		return "eip155:" + strconv.Itoa(chain)
	}
	return ""
}

// xbSame is equality, with strings compared without regard to letter case.
func xbSame(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return strings.EqualFold(as, bs)
	}
	return reflect.DeepEqual(a, b)
}

// xbTruthy is Python's truth value for a decoded JSON value.
func xbTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		f, err := strconv.ParseFloat(fmt.Sprint(t), 64)
		return err != nil || f != 0
	}
}

func xbKind(r any) any { return rlGet(r, "binding.kind") }

func xbBoundNetwork(r any) any {
	if xbKind(r) == "accepted_option" {
		return rlGet(r, "offer.accepted.network")
	}
	return rlGet(r, "binding.authorization.network")
}

func xbLogs(r any) []map[string]any {
	var out []map[string]any
	for _, item := range rlList(rlGet(r, "chain_read.logs")) {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func xbAssetLogs(r any, event string) []map[string]any {
	asset := rlGet(r, "binding.authorization.asset")
	if !xbTruthy(asset) {
		asset = rlGet(r, "offer.accepted.asset")
	}
	var out []map[string]any
	for _, g := range xbLogs(r) {
		if g["event"] == event && xbSame(g["address"], asset) {
			out = append(out, g)
		}
	}
	return out
}

func xbReadOfBoundNetwork(r any) bool {
	bound := xbNetwork(xbBoundNetwork(r))
	return bound != "" && bound == xbNetwork(rlGet(r, "chain_read.network"))
}

func xbReadOK(r any) bool {
	return rlGet(r, "chain_read.status") == "ok" && xbReadOfBoundNetwork(r)
}

func xbScopeIncomplete(r any) bool {
	if xbKind(r) == "accepted_option" {
		return false
	}
	if xbKind(r) != "authorization" {
		return true
	}
	for _, f := range []string{"network", "asset", "payer", "nonce"} {
		if !xbTruthy(rlGet(r, "binding.authorization."+f)) {
			return true
		}
	}
	return false
}

func xbNetworkUnknown(r any) bool {
	if xbNetwork(xbBoundNetwork(r)) == "" {
		return true
	}
	return rlGet(r, "binding.settlement") != nil && xbNetwork(rlGet(r, "binding.settlement.network")) == ""
}

func xbBindingNotRecordAuthorization(r any) bool {
	if xbKind(r) != "authorization" {
		return false
	}
	bound := xbNetwork(rlGet(r, "binding.authorization.network"))
	pairs := [][2]any{
		{bound, xbNetwork(rlGet(r, "offer.accepted.network"))},
		{rlGet(r, "binding.authorization.asset"), rlGet(r, "offer.accepted.asset")},
	}
	if rlGet(r, "payment.authorization") != nil {
		pairs = append(pairs,
			[2]any{rlGet(r, "binding.authorization.payer"), rlGet(r, "payment.authorization.from")},
			[2]any{rlGet(r, "binding.authorization.nonce"), rlGet(r, "payment.authorization.nonce")})
	}
	if rlGet(r, "binding.settlement") != nil {
		pairs = append(pairs, [2]any{bound, xbNetwork(rlGet(r, "binding.settlement.network"))})
	}
	for _, p := range pairs {
		if !xbSame(p[0], p[1]) {
			return true
		}
	}
	return false
}

func xbOptionFitsMoreThanOne(r any) bool {
	if xbKind(r) != "accepted_option" || !xbReadOK(r) {
		return false
	}
	fits := 0
	for _, g := range xbAssetLogs(r, "Transfer") {
		if xbSame(g["to"], rlGet(r, "offer.accepted.payTo")) && xbSame(g["value"], rlGet(r, "offer.accepted.amount")) {
			fits++
		}
	}
	return fits > 1
}

func xbEventFor(r any, event string) map[string]any {
	payer, nonce := rlGet(r, "binding.authorization.payer"), rlGet(r, "binding.authorization.nonce")
	for _, g := range xbAssetLogs(r, event) {
		if xbSame(g["authorizer"], payer) && xbSame(g["nonce"], nonce) {
			return g
		}
	}
	return nil
}

// xbStateUsed is authorizationState(payer, nonce) at the read's head: 1 used,
// 0 unused, -1 when the read did not ask about this authorization.
func xbStateUsed(r any) int {
	state, ok := rlGet(r, "chain_read.authorization_state").(map[string]any)
	if !ok || !xbSame(state["authorizer"], rlGet(r, "binding.authorization.payer")) ||
		!xbSame(state["nonce"], rlGet(r, "binding.authorization.nonce")) {
		return -1
	}
	used, ok := state["used"].(bool)
	switch {
	case !ok:
		return -1
	case used:
		return 1
	default:
		return 0
	}
}

func xbPastValidBefore(r any) bool {
	before := rlStr(rlGet(r, "payment.authorization.validBefore"))
	head := fmt.Sprint(rlGet(r, "chain_read.head.timestamp"))
	if !xbDigits.MatchString(before) || !xbInteger.MatchString(head) {
		return false
	}
	b, errB := strconv.ParseInt(before, 10, 64)
	h, errH := strconv.ParseInt(head, 10, 64)
	return errB == nil && errH == nil && rlGet(r, "chain_read.head.finalized") == true && h >= b
}

func xbUsedTransaction(r any) any {
	if used := xbEventFor(r, "AuthorizationUsed"); used != nil {
		return used["transaction"]
	}
	return nil
}

func xbIdentifiedTransfer(r any) map[string]any {
	tx := xbUsedTransaction(r)
	if index := rlGet(r, "binding.settlement.log_index"); index != nil {
		for _, g := range xbLogs(r) {
			if xbSame(g["transaction"], tx) && reflect.DeepEqual(g["log_index"], index) {
				return g
			}
		}
		return nil
	}
	var transfers []map[string]any
	for _, g := range xbAssetLogs(r, "Transfer") {
		if xbSame(g["transaction"], tx) {
			transfers = append(transfers, g)
		}
	}
	if len(transfers) == 1 {
		return transfers[0]
	}
	return nil
}

func xbTransferCount(r any) int {
	tx, count := xbUsedTransaction(r), 0
	for _, g := range xbAssetLogs(r, "Transfer") {
		if xbSame(g["transaction"], tx) {
			count++
		}
	}
	return count
}

func xbTransferNotTerms(r any) bool {
	g := xbIdentifiedTransfer(r)
	if g == nil {
		return true
	}
	return g["event"] != "Transfer" ||
		!xbSame(g["address"], rlGet(r, "binding.authorization.asset")) ||
		!xbSame(g["from"], rlGet(r, "binding.authorization.payer")) ||
		!xbSame(g["to"], rlGet(r, "offer.accepted.payTo")) ||
		!xbSame(g["value"], rlGet(r, "offer.accepted.amount"))
}

func xbOtherTransaction(r any) bool {
	named := rlGet(r, "binding.settlement.transaction")
	used := xbEventFor(r, "AuthorizationUsed")
	return used != nil && named != nil && !xbSame(named, used["transaction"])
}

type xbRule struct {
	code, state string
	fires       func(r any, authorization xbVerdict) bool
}

var xbAuthorizationRules = []xbRule{
	{"authorization_scope_incomplete", "indeterminate", func(r any, _ xbVerdict) bool { return xbScopeIncomplete(r) }},
	{"binding_network_unknown", "indeterminate", func(r any, _ xbVerdict) bool { return xbNetworkUnknown(r) }},
	{"binding_not_record_authorization", "contradicted", func(r any, _ xbVerdict) bool { return xbBindingNotRecordAuthorization(r) }},
	{"option_fits_more_than_one_payment", "indeterminate", func(r any, _ xbVerdict) bool { return xbOptionFitsMoreThanOne(r) }},
	{"bound_by_accepted_option_only", "indeterminate", func(r any, _ xbVerdict) bool { return xbKind(r) == "accepted_option" }},
}

var xbSettlementRules = []xbRule{
	{"authorization_not_identified", "indeterminate", func(_ any, a xbVerdict) bool { return a.State != "verified" }},
	{"no_chain_read", "not_evaluated", func(r any, _ xbVerdict) bool { return rlGet(r, "chain_read") == nil }},
	{"chain_read_failed", "indeterminate", func(r any, _ xbVerdict) bool { return rlGet(r, "chain_read.status") != "ok" }},
	{"chain_read_not_bound_network", "indeterminate", func(r any, _ xbVerdict) bool { return !xbReadOfBoundNetwork(r) }},
	{"authorization_canceled", "contradicted", func(r any, _ xbVerdict) bool { return xbEventFor(r, "AuthorizationCanceled") != nil }},
	{"authorization_expired_unused", "contradicted", func(r any, _ xbVerdict) bool {
		return xbEventFor(r, "AuthorizationUsed") == nil && xbStateUsed(r) == 0 && xbPastValidBefore(r)
	}},
	{"authorization_not_yet_used", "indeterminate", func(r any, _ xbVerdict) bool {
		return xbEventFor(r, "AuthorizationUsed") == nil && xbStateUsed(r) == 0
	}},
	{"authorization_use_not_read", "indeterminate", func(r any, _ xbVerdict) bool { return xbEventFor(r, "AuthorizationUsed") == nil }},
	{"transaction_did_not_use_authorization", "contradicted", func(r any, _ xbVerdict) bool { return xbOtherTransaction(r) }},
	{"transaction_carries_more_than_one_transfer", "indeterminate", func(r any, _ xbVerdict) bool {
		return rlGet(r, "binding.settlement.log_index") == nil && xbTransferCount(r) > 1
	}},
	{"transfer_not_authorization_terms", "contradicted", func(r any, _ xbVerdict) bool { return xbTransferNotTerms(r) }},
}

func xbDecide(record any) xbExpected {
	out := xbExpected{
		Authorization: xbVerdict{State: "verified", Reason: "authorization_identified"},
		Settlement:    xbVerdict{State: "verified", Reason: "transfer_identified"},
	}
	for _, rule := range xbAuthorizationRules {
		if rule.fires(record, out.Authorization) {
			out.Authorization = xbVerdict{State: rule.state, Reason: rule.code}
			break
		}
	}
	for _, rule := range xbSettlementRules {
		if rule.fires(record, out.Authorization) {
			out.Settlement = xbVerdict{State: rule.state, Reason: rule.code}
			break
		}
	}
	return out
}

func (c x402PaymentBinding) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	accepted := map[string]bool{}
	var vectors []xbVector
	for _, entry := range manifest.Vectors {
		var v xbVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		accepted[v.ID] = v.Expected.accepted()
		vectors = append(vectors, v)
	}
	for _, v := range vectors {
		kind := v.Expected.Authorization.State + "/" + v.Expected.Settlement.State
		member := Member{ID: v.ID, Kind: kind}
		member.Findings = c.judgeMember(filepath.Join(dir, v.Path), v)
		if !v.Expected.accepted() && !accepted[v.Twin] {
			member.Findings = append(member.Findings, "a member not verified twice must name an accepted twin")
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func (x402PaymentBinding) judgeMember(caseDir string, v xbVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "case.json")
	if err != nil {
		return append(findings, "case.json cannot be read: "+err.Error())
	}
	record, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, "case.json does not parse: "+err.Error())
	}
	if got := xbDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s and %s/%s, the manifest declares %s/%s and %s/%s",
			got.Authorization.State, got.Authorization.Reason, got.Settlement.State, got.Settlement.Reason,
			v.Expected.Authorization.State, v.Expected.Authorization.Reason,
			v.Expected.Settlement.State, v.Expected.Settlement.Reason))
	}
	return findings
}
