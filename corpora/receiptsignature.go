package corpora

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(receiptSignature{}) }

// receiptSignature judges vectors-receipt-signature/: signed decision receipts
// in the envelope shape of draft-farley-acta-signed-receipts-03.
//
// It runs every member through a reference verification twice, once against the
// external key set with its validity windows and once against the same keys
// without them, and requires each outcome to be the one the manifest declares.
// It also holds the grading to the text: a member whose only defect is the
// window tests a SHOULD, so it must be indeterminate and cite only SHOULD-level
// requirements, and a reject must cite a MUST.
type receiptSignature struct{}

func (receiptSignature) Suite() string { return "receipt-signature-conformance" }

// Verdicts of the reference verification. Undecidable is the outcome where the
// check could not run, which is never reported as valid or invalid.
const (
	rsValid       = "valid"
	rsInvalid     = "invalid"
	rsUndecidable = "undecidable"
)

type rsOutcome struct {
	Verdict string  `json:"verdict"`
	Code    *string `json:"code"`
}

func (o rsOutcome) String() string {
	if o.Code == nil {
		return o.Verdict
	}
	return o.Verdict + " " + *o.Code
}

type rsVector struct {
	ID                     string     `json:"id"`
	Kind                   string     `json:"kind"`
	File                   string     `json:"file"`
	Conditions             []string   `json:"conditions"`
	KeyID                  string     `json:"keyId"`
	Expected               rsOutcome  `json:"expected"`
	ExpectedWithoutWindows rsOutcome  `json:"expectedWithoutWindows"`
	ExpectedIfNotHonoured  *rsOutcome `json:"expectedIfNotHonoured"`
	SignedInputHex         string     `json:"signedInputHex"`
}

type rsRequirement struct {
	ID             string `json:"id"`
	Level          string `json:"level"`
	Sentence       string `json:"sentence"`
	SentenceDigest string `json:"sentenceDigest"`
}

type rsCondition struct {
	Requirements []string `json:"requirements"`
}

type rsKeySet struct {
	File   string `json:"file"`
	Sha256 string `json:"sha256"`
}

type rsManifest struct {
	SpecVendored string `json:"specVendored"`
	SpecDigest   string `json:"specDigest"`
	Contract     string `json:"contract"`
	KeySets      struct {
		WithWindows    rsKeySet `json:"withWindows"`
		WithoutWindows rsKeySet `json:"withoutWindows"`
	} `json:"keySets"`
	Origin struct {
		Members []struct {
			UpstreamFile string `json:"upstreamFile"`
			ID           string `json:"id"`
			Sha256       string `json:"sha256"`
		} `json:"members"`
	} `json:"origin"`
	CodeRegistry map[string]string      `json:"codeRegistry"`
	Requirements []rsRequirement        `json:"requirements"`
	Conditions   map[string]rsCondition `json:"conditions"`
	Counts       map[string]int         `json:"counts"`
	CorpusDigest string                 `json:"corpusDigest"`
	Vectors      []rsVector             `json:"vectors"`
}

// rsJWK is one key of the external key set. The window members are pointers so
// an absent bound, which leaves the window open on that side, is not a zero time.
type rsJWK struct {
	Kty        string  `json:"kty"`
	Crv        string  `json:"crv"`
	Kid        string  `json:"kid"`
	X          string  `json:"x"`
	ValidFrom  *string `json:"valid_from"`
	ValidUntil *string `json:"valid_until"`
}

// rsJudging is what one Judge call carries between its steps.
type rsJudging struct {
	dir      string
	manifest rsManifest
	levels   map[string]string // requirement id -> level
	withW    map[string]rsJWK
	withoutW map[string]rsJWK
	result   *Result
}

func (r receiptSignature) Judge(dir string, raw []byte) (*Result, error) {
	var manifest rsManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	j := &rsJudging{dir: dir, manifest: manifest, result: &Result{}}
	j.checkText()
	j.checkKeySets()
	j.judgeMembers()
	if err := j.checkCorpus(); err != nil {
		return nil, err
	}
	return j.result, nil
}

func (j *rsJudging) find(format string, args ...any) {
	j.result.Findings = append(j.result.Findings, fmt.Sprintf(format, args...))
}

// checkText binds every requirement to the vendored specification: the file
// hashes to its pin, each quoted sentence is in it, each digest is over the
// sentence, and each level is a keyword the sentence itself carries.
func (j *rsJudging) checkText() {
	m := j.manifest
	if bad := checkVendored(j.dir, m.SpecVendored, m.SpecDigest, "specification"); bad != "" {
		j.find("%s", bad)
	}
	if !existsIn(j.dir, m.Contract) {
		j.find("the manifest names the verifier contract at %s and no such file is there", m.Contract)
	}
	text := ""
	if body, err := readIn(j.dir, m.SpecVendored); err == nil {
		text = collapseSpace(string(body))
	}
	j.levels = map[string]string{}
	for _, req := range m.Requirements {
		j.checkRequirement(req, text)
	}
}

// checkRequirement binds one requirement to the vendored text.
func (j *rsJudging) checkRequirement(req rsRequirement, text string) {
	if _, dup := j.levels[req.ID]; dup {
		j.find("requirement %s is declared twice", req.ID)
	}
	j.levels[req.ID] = req.Level
	if !strings.Contains(text, req.Sentence) {
		j.find("requirement %s quotes a sentence the vendored specification does not contain", req.ID)
	}
	if sha([]byte(req.Sentence)) != req.SentenceDigest {
		j.find("requirement %s has a sentenceDigest that is not the digest of its sentence", req.ID)
	}
	if req.Level != "MUST" && req.Level != "SHOULD" {
		j.find("requirement %s declares level %q", req.ID, req.Level)
	} else if !strings.Contains(req.Sentence, req.Level) {
		j.find("requirement %s declares level %s and its sentence does not say %s", req.ID, req.Level, req.Level)
	}
}

var rsSpace = regexp.MustCompile(`\s+`)

func collapseSpace(s string) string { return rsSpace.ReplaceAllString(s, " ") }

// checkKeySets loads both key sets and requires the windowless one to be the
// windowed one with the windows removed: the same kids and the same public keys.
// Two key sets that differ in anything else would make the two passes measure
// two things at once.
func (j *rsJudging) checkKeySets() {
	ks := j.manifest.KeySets
	j.withW = j.loadKeySet(ks.WithWindows, "withWindows")
	j.withoutW = j.loadKeySet(ks.WithoutWindows, "withoutWindows")
	windowed := false
	for _, kid := range sortedKeys(j.withW) {
		key := j.withW[kid]
		bare, ok := j.withoutW[kid]
		if !ok || bare.X != key.X {
			j.find("the key sets disagree on key %s beyond its window", kid)
		}
		windowed = windowed || key.ValidFrom != nil || key.ValidUntil != nil
	}
	if len(j.withW) != len(j.withoutW) {
		j.find("the key sets carry %d and %d keys", len(j.withW), len(j.withoutW))
	}
	j.checkBareSet()
	if !windowed {
		j.find("the windowed key set carries no window, so the two passes are the same pass")
	}
}

// checkBareSet refuses a window in the set that is meant to carry none.
func (j *rsJudging) checkBareSet() {
	for _, kid := range sortedKeys(j.withoutW) {
		if key := j.withoutW[kid]; key.ValidFrom != nil || key.ValidUntil != nil {
			j.find("the windowless key set carries a window on key %s", kid)
		}
	}
}

func (j *rsJudging) loadKeySet(ks rsKeySet, name string) map[string]rsJWK {
	body, err := readIn(j.dir, ks.File)
	if err != nil {
		j.find("the %s key set %s cannot be read", name, ks.File)
		return map[string]rsJWK{}
	}
	if sha(body) != ks.Sha256 {
		j.find("the %s key set %s does not match its pinned digest", name, ks.File)
	}
	var set struct {
		Keys []rsJWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		j.find("the %s key set %s does not parse: %v", name, ks.File, err)
		return map[string]rsJWK{}
	}
	out := map[string]rsJWK{}
	for _, key := range set.Keys {
		if _, dup := out[key.Kid]; dup {
			j.find("the %s key set names key %s twice", name, key.Kid)
		}
		out[key.Kid] = key
	}
	return out
}

func (j *rsJudging) judgeMembers() {
	seen := map[string]bool{}
	for _, v := range j.manifest.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		member.Findings = append(member.Findings, j.judgeMember(v)...)
		j.result.Members = append(j.result.Members, member)
	}
}

func (j *rsJudging) judgeMember(v rsVector) []string {
	findings := j.checkDeclaration(v)
	if !existsIn(j.dir, v.File) {
		return append(findings, "the manifest names a receipt file that does not exist")
	}
	body, err := readIn(j.dir, v.File)
	if err != nil {
		return append(findings, err.Error())
	}
	if idFromBytes(body) != v.ID {
		findings = append(findings, "identifier does not recompute from the receipt's own bytes")
	}
	withW := rsVerify(body, j.withW)
	if withW.String() != v.Expected.String() {
		findings = append(findings, fmt.Sprintf(
			"with the windowed key set the reference verification is %s and the manifest declares %s",
			withW, v.Expected))
	}
	withoutW := rsVerify(body, j.withoutW)
	if withoutW.String() != v.ExpectedWithoutWindows.String() {
		findings = append(findings, fmt.Sprintf(
			"without the windows the reference verification is %s and the manifest declares %s",
			withoutW, v.ExpectedWithoutWindows))
	}
	return append(findings, j.checkSignedInput(v, body)...)
}

// checkDeclaration holds a member's kind to the level of what it cites.
func (j *rsJudging) checkDeclaration(v rsVector) []string {
	if len(v.Conditions) == 0 {
		return []string{"cites no condition"}
	}
	levels, findings := j.conditionLevels(v)
	findings = append(findings, j.unregisteredCodes(v)...)
	switch v.Kind {
	case "accept":
		findings = append(findings, rsCheckAccept(v)...)
	case "reject":
		findings = append(findings, rsCheckReject(v, levels)...)
	case "indeterminate":
		findings = append(findings, rsCheckIndeterminate(v, levels)...)
	default:
		findings = append(findings, fmt.Sprintf("declares kind %q", v.Kind))
	}
	return findings
}

// conditionLevels is the set of levels the member's conditions cite, and a
// finding for each condition the manifest does not define.
func (j *rsJudging) conditionLevels(v rsVector) (map[string]bool, []string) {
	var findings []string
	levels := map[string]bool{}
	for _, c := range v.Conditions {
		cond, ok := j.manifest.Conditions[c]
		if !ok {
			findings = append(findings, "cites condition "+c+" the manifest does not define")
			continue
		}
		for _, req := range cond.Requirements {
			levels[j.levels[req]] = true
		}
	}
	return levels, findings
}

func (j *rsJudging) unregisteredCodes(v rsVector) []string {
	var findings []string
	for _, outcome := range []rsOutcome{v.Expected, v.ExpectedWithoutWindows} {
		if outcome.Code == nil {
			continue
		}
		if _, ok := j.manifest.CodeRegistry[*outcome.Code]; !ok {
			findings = append(findings, "expects code "+*outcome.Code+" the code registry does not define")
		}
	}
	return findings
}

func rsCheckAccept(v rsVector) []string {
	var findings []string
	if v.Expected.Verdict != rsValid || v.ExpectedWithoutWindows.Verdict != rsValid {
		findings = append(findings, "is an accept member expecting something other than valid")
	}
	if v.ExpectedIfNotHonoured != nil {
		findings = append(findings, "is an accept member carrying expectedIfNotHonoured, which only a SHOULD member has")
	}
	return findings
}

// rsCheckReject: a reject must be refused in both passes, because a defect a
// MUST names does not depend on the key's window, and it must cite a MUST.
func rsCheckReject(v rsVector, levels map[string]bool) []string {
	var findings []string
	if v.Expected.Verdict != rsInvalid || v.ExpectedWithoutWindows.Verdict != rsInvalid {
		findings = append(findings, "is a reject member not expected invalid in both passes")
	}
	if !levels["MUST"] {
		findings = append(findings, "is a reject member citing no MUST, so a conformant verifier may decline to refuse it")
	}
	if v.ExpectedIfNotHonoured != nil {
		findings = append(findings, "is a reject member carrying expectedIfNotHonoured, which only a SHOULD member has")
	}
	return findings
}

// rsCheckIndeterminate: a member whose defect only a SHOULD names has two
// permitted outcomes with the windows, and the manifest must declare both.
func rsCheckIndeterminate(v rsVector, levels map[string]bool) []string {
	var findings []string
	if levels["MUST"] || !levels["SHOULD"] {
		findings = append(findings, "is an indeterminate member whose conditions do not cite only SHOULD-level requirements")
	}
	if v.ExpectedIfNotHonoured == nil {
		return append(findings, "is an indeterminate member with no expectedIfNotHonoured")
	}
	if v.Expected.Verdict != rsInvalid || v.ExpectedIfNotHonoured.Verdict != rsValid {
		findings = append(findings, "is an indeterminate member whose two outcomes are not invalid when honoured and valid when not")
	}
	if v.ExpectedWithoutWindows.Verdict != rsValid {
		findings = append(findings, "is an indeterminate member expected invalid without the windows, which no rule it cites decides")
	}
	return findings
}

// checkSignedInput proves the manifest says what was signed: the signature must
// verify over signedInputHex, and for every member that is not a defect in the
// signing input, those bytes must be JCS(payload).
func (j *rsJudging) checkSignedInput(v rsVector, body []byte) []string {
	env, fail := rsParse(body)
	if fail != nil {
		return nil
	}
	if env.kid != v.KeyID {
		return []string{"keyId is not the kid the receipt's signature names"}
	}
	signed, err := hex.DecodeString(v.SignedInputHex)
	if err != nil {
		return []string{"signedInputHex is not hex"}
	}
	if !j.verifiesOver(env, signed) {
		return []string{"the signature does not verify over signedInputHex, so the manifest does not say what was signed"}
	}
	if v.Kind == "reject" {
		return nil
	}
	canonical, cerr := aee.Canonicalize(env.payload)
	if cerr != nil || string(canonical) != string(signed) {
		return []string{"is not a signing-input defect and its signedInputHex is not JCS(payload)"}
	}
	return nil
}

// verifiesOver reports whether the receipt's signature verifies over the given
// bytes under the key the windowed set resolves for its kid.
func (j *rsJudging) verifiesOver(env *rsEnvelope, signed []byte) bool {
	key, ok := j.withW[env.kid]
	pub, bad := rsPublicKey(key)
	return ok && bad == "" && len(env.sig) == ed25519.SignatureSize && ed25519.Verify(pub, signed, env.sig)
}

// checkCorpus is everything that belongs to no single member.
func (j *rsJudging) checkCorpus() error {
	m := j.manifest
	accepted, rejected, used := map[string]bool{}, map[string]bool{}, map[string]bool{}
	measured := map[string]int{"accept": 0, "indeterminate": 0, "reject": 0}
	ids, files := make([]string, 0, len(m.Vectors)), make([]string, 0, len(m.Vectors))
	for _, v := range m.Vectors {
		ids, files = append(ids, v.ID), append(files, v.File)
		if _, known := measured[v.Kind]; known {
			measured[v.Kind]++
		}
		for _, c := range v.Conditions {
			used[c] = true
			if v.Kind == "accept" {
				accepted[c] = true
			} else {
				rejected[c] = true
			}
		}
	}
	if orphan := orphanTwins(accepted, rejected); len(orphan) > 0 {
		j.find("conditions that are refused and never accepted: %v. A verifier that refuses "+
			"every receipt would score full marks on them.", orphan)
	}
	if idle := declaredMinusUsed(m.Conditions, used); len(idle) > 0 {
		j.find("conditions declared and carried by no member: %v", idle)
	}
	j.checkRequirementsCited()
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		j.find("%s", bad)
	}
	digest, err := orderedCorpusDigest(j.dir, ids, files)
	if err != nil {
		return err
	}
	if digest != m.CorpusDigest {
		j.find("corpusDigest does not match the receipt files on disk")
	}
	j.checkOrigin()
	return nil
}

func (j *rsJudging) checkRequirementsCited() {
	cited := map[string]bool{}
	for _, name := range sortedKeys(j.manifest.Conditions) {
		for _, req := range j.manifest.Conditions[name].Requirements {
			if _, ok := j.levels[req]; !ok {
				j.find("condition %s cites requirement %s the manifest does not declare", name, req)
			}
			cited[req] = true
		}
	}
	if idle := declaredMinusUsed(j.levels, cited); len(idle) > 0 {
		j.find("requirements declared and cited by no condition: %v", idle)
	}
}

// checkOrigin holds the lifted members to the upstream digests the manifest
// records, so "lifted unchanged" is a property the reader checks.
func (j *rsJudging) checkOrigin() {
	files := map[string]string{}
	for _, v := range j.manifest.Vectors {
		files[v.ID] = v.File
	}
	for _, o := range j.manifest.Origin.Members {
		rel, ok := files[o.ID]
		if !ok {
			j.find("origin names %s as member %s and the manifest has no such member", o.UpstreamFile, o.ID)
			continue
		}
		body, err := readIn(j.dir, rel)
		if err != nil || sha(body) != o.Sha256 {
			j.find("member %s is not the upstream bytes of %s", o.ID, o.UpstreamFile)
		}
	}
}

// rsEnvelope is a receipt in the envelope shape, parsed as far as the checks
// that precede the signature need.
type rsEnvelope struct {
	payload  json.RawMessage
	fields   map[string]json.RawMessage
	kid, alg string
	sig      []byte
	sigHexOK bool
}

func rsResult(verdict, code string) rsOutcome {
	return rsOutcome{Verdict: verdict, Code: &code}
}

// rsParse reads the envelope shape of Section 2.1: exactly a payload member and
// a signature object carrying exactly alg, kid and sig.
func rsParse(body []byte) (*rsEnvelope, *rsOutcome) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || len(top) != 2 || top["payload"] == nil || top["signature"] == nil {
		out := rsResult(rsUndecidable, "not_envelope_shape")
		return nil, &out
	}
	signature, ok := rsSignatureObject(top["signature"])
	if !ok {
		out := rsResult(rsUndecidable, "bad_signature_object")
		return nil, &out
	}
	env := &rsEnvelope{payload: top["payload"], kid: signature["kid"], alg: signature["alg"]}
	if err := json.Unmarshal(env.payload, &env.fields); err != nil || env.fields == nil {
		out := rsResult(rsUndecidable, "payload_not_an_object")
		return nil, &out
	}
	sig, err := hex.DecodeString(signature["sig"])
	env.sig, env.sigHexOK = sig, err == nil && len(sig) == ed25519.SignatureSize
	return env, nil
}

// rsSignatureObject reads the signature object of Section 2.1.1: exactly alg,
// kid and sig, each a non-empty string.
func rsSignatureObject(raw json.RawMessage) (map[string]string, bool) {
	var signature map[string]string
	if err := json.Unmarshal(raw, &signature); err != nil || len(signature) != 3 {
		return nil, false
	}
	return signature, signature["alg"] != "" && signature["kid"] != "" && signature["sig"] != ""
}

func rsPublicKey(key rsJWK) (ed25519.PublicKey, string) {
	if key.Kty != "OKP" || key.Crv != "Ed25519" {
		return nil, "unsupported_key"
	}
	raw, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "bad_key"
	}
	return ed25519.PublicKey(raw), ""
}

// rsVerify is the reference verification: Sections 2.1, 2.2, 5.2, 6.6 and 9.2 of
// draft-03, with the key resolved only from the external key set (Section 9.5)
// and the window, where the key set publishes one, applied to issued_at.
func rsVerify(body []byte, keys map[string]rsJWK) rsOutcome {
	env, fail := rsParse(body)
	if fail != nil {
		return *fail
	}
	if out := rsPrecheck(env); out != nil {
		return *out
	}
	key, ok := keys[env.kid]
	if !ok {
		return rsResult(rsUndecidable, "unknown_kid")
	}
	pub, bad := rsPublicKey(key)
	if bad != "" {
		return rsResult(rsUndecidable, bad)
	}
	if !env.sigHexOK {
		return rsResult(rsInvalid, "bad_signature_encoding")
	}
	canonical, err := aee.Canonicalize(env.payload)
	if err != nil {
		return rsResult(rsUndecidable, "payload_not_canonicalizable")
	}
	if !ed25519.Verify(pub, canonical, env.sig) {
		return rsResult(rsInvalid, "signature_invalid")
	}
	return rsWindow(env, key)
}

// rsPrecheck is everything decided before a key is resolved.
func rsPrecheck(env *rsEnvelope) *rsOutcome {
	for _, field := range []string{"type", "issued_at", "issuer_id"} {
		if env.fields[field] == nil {
			out := rsResult(rsUndecidable, "missing_required_field")
			return &out
		}
	}
	if _, carried := env.fields["signature"]; carried {
		out := rsResult(rsInvalid, "signature_in_signing_input")
		return &out
	}
	if env.alg != "EdDSA" {
		out := rsResult(rsUndecidable, "unsupported_alg")
		return &out
	}
	var issuer string
	if err := json.Unmarshal(env.fields["issuer_id"], &issuer); err != nil || issuer != env.kid {
		out := rsResult(rsInvalid, "issuer_kid_mismatch")
		return &out
	}
	return nil
}

// rsWindow applies the key's validity window: valid_from included, valid_until
// excluded. A key with no window leaves the receipt valid.
func rsWindow(env *rsEnvelope, key rsJWK) rsOutcome {
	var issued string
	if err := json.Unmarshal(env.fields["issued_at"], &issued); err != nil {
		return rsResult(rsUndecidable, "window_not_applicable")
	}
	at, err := time.Parse(time.RFC3339, issued)
	if err != nil {
		return rsResult(rsUndecidable, "window_not_applicable")
	}
	for _, bound := range []struct {
		value  *string
		inside func(time.Time) bool
	}{
		{key.ValidFrom, func(b time.Time) bool { return !at.Before(b) }},
		{key.ValidUntil, func(b time.Time) bool { return at.Before(b) }},
	} {
		if bound.value == nil {
			continue
		}
		b, err := time.Parse(time.RFC3339, *bound.value)
		if err != nil {
			return rsResult(rsUndecidable, "window_not_applicable")
		}
		if !bound.inside(b) {
			return rsResult(rsInvalid, "key_outside_validity_window")
		}
	}
	return rsOutcome{Verdict: rsValid}
}
