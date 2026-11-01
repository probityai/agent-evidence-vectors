package corpora

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
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
	ID                                string     `json:"id"`
	Kind                              string     `json:"kind"`
	File                              string     `json:"file"`
	Context                           *rsContext `json:"context"`
	Conditions                        []string   `json:"conditions"`
	KeyID                             string     `json:"keyId"`
	Expected                          rsOutcome  `json:"expected"`
	ExpectedWithoutWindows            rsOutcome  `json:"expectedWithoutWindows"`
	ExpectedIfNotHonoured             *rsOutcome `json:"expectedIfNotHonoured"`
	ExpectedIfGapClosed               *rsOutcome `json:"expectedIfGapClosed"`
	ExpectedIfGapClosedWithoutWindows *rsOutcome `json:"expectedIfGapClosedWithoutWindows"`
	SignedInputHex                    string     `json:"signedInputHex"`
}

// rsContext places a member's receipt after the receipts of a chain, and
// optionally against a commitment to that chain recorded at a given time.
type rsContext struct {
	Chain              []string `json:"chain"`
	Commitment         string   `json:"commitment,omitempty"`
	CommitmentLoggedAt string   `json:"commitmentLoggedAt,omitempty"`
}

// rsGap is a question the draft does not decide, with the code of the rule
// proposed to close it.
type rsGap struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}

type rsRequirement struct {
	ID             string `json:"id"`
	Level          string `json:"level"`
	Sentence       string `json:"sentence"`
	SentenceDigest string `json:"sentenceDigest"`
}

type rsCondition struct {
	Requirements []string `json:"requirements"`
	Gaps         []string `json:"gaps"`
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
	Origins []struct {
		Path    string `json:"path"`
		Members []struct {
			UpstreamFile string `json:"upstreamFile"`
			File         string `json:"file"`
			Sha256       string `json:"sha256"`
		} `json:"members"`
	} `json:"origins"`
	CodeRegistry map[string]string      `json:"codeRegistry"`
	Requirements []rsRequirement        `json:"requirements"`
	Gaps         []rsGap                `json:"gaps"`
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
	RevokedAt  *string `json:"revoked_at"`
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
		if key := j.withoutW[kid]; key.ValidFrom != nil || key.ValidUntil != nil || key.RevokedAt != nil {
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
	ctx, bad := j.readContext(v)
	if len(bad) > 0 {
		return append(findings, bad...)
	}
	if preimage, perr := rsPreimage(j.dir, v); perr != nil || idFromBytes(preimage) != v.ID {
		findings = append(findings, "identifier does not recompute from the member's own bytes")
	}
	type pass struct {
		label string
		keys  map[string]rsJWK
		draft rsOutcome
	}
	passes := []pass{
		{"with the windowed key set", j.withW, v.Expected},
		{"without the windows", j.withoutW, v.ExpectedWithoutWindows},
	}
	closed := []rsOutcome{v.Expected, v.ExpectedWithoutWindows}
	if v.Kind == "gap" {
		closed = []rsOutcome{rsOrAbsent(v.ExpectedIfGapClosed), rsOrAbsent(v.ExpectedIfGapClosedWithoutWindows)}
	}
	for i, p := range passes {
		if got := rsVerifyInContext(body, p.keys, ctx, false); got.String() != p.draft.String() {
			findings = append(findings, fmt.Sprintf(
				"%s the reference verification is %s and the manifest declares %s", p.label, got, p.draft))
		}
		if got := rsVerifyInContext(body, p.keys, ctx, true); got.String() != closed[i].String() {
			findings = append(findings, fmt.Sprintf(
				"%s the reference verification with every gap closed is %s and the manifest declares %s",
				p.label, got, closed[i]))
		}
	}
	return append(findings, j.checkSignedInput(v, body)...)
}

// rsOrAbsent renders a missing outcome the way the Python reader does.
func rsOrAbsent(o *rsOutcome) rsOutcome {
	if o == nil {
		return rsOutcome{Verdict: "absent"}
	}
	return *o
}

// readContext reads a member's context from disk: each chain receipt must be a
// member presented without a context, and the commitment must be named after
// its own bytes and come with the time it was logged.
func (j *rsJudging) readContext(v rsVector) (*rsReadContext, []string) {
	if v.Context == nil {
		return nil, nil
	}
	if len(v.Context.Chain) == 0 {
		return nil, []string{"carries a context that names no chain"}
	}
	plain := map[string]bool{}
	for _, m := range j.manifest.Vectors {
		if m.Context == nil {
			plain[m.File] = true
		}
	}
	var findings []string
	ctx := &rsReadContext{loggedAt: v.Context.CommitmentLoggedAt}
	for _, rel := range v.Context.Chain {
		body, err := readIn(j.dir, rel)
		if err != nil || !plain[rel] {
			findings = append(findings, "its chain names "+rel+", which is not a member without a context")
			continue
		}
		ctx.chain = append(ctx.chain, body)
	}
	if rel := v.Context.Commitment; rel != "" {
		body, err := readIn(j.dir, rel)
		switch {
		case err != nil:
			findings = append(findings, "its context names a commitment "+rel+" that does not exist")
		case "context/c"+sha(body)[:16]+".json" != rel:
			findings = append(findings, "its commitment "+rel+" is not named after its own bytes")
		default:
			ctx.commitment = body
		}
	}
	if (v.Context.Commitment == "") != (v.Context.CommitmentLoggedAt == "") {
		findings = append(findings, "its context names a commitment without a time, or a time without one")
	}
	return ctx, findings
}

// rsPreimage is what a member's identifier and the corpus digest hash: its
// receipt's bytes and, for a member with a context, that context in RFC 8785
// form and the bytes of the commitment it names.
func rsPreimage(dir string, v rsVector) ([]byte, error) {
	body, err := readIn(dir, v.File)
	if err != nil || v.Context == nil {
		return body, err
	}
	raw, err := json.Marshal(v.Context)
	if err != nil {
		return nil, err
	}
	canonical, err := aee.Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	out := append(append([]byte{}, body...), canonical...)
	if v.Context.Commitment == "" {
		return out, nil
	}
	commitment, err := readIn(dir, v.Context.Commitment)
	if err != nil {
		return nil, err
	}
	return append(out, commitment...), nil
}

// checkDeclaration holds a member's kind to the level of what it cites.
func (j *rsJudging) checkDeclaration(v rsVector) []string {
	if len(v.Conditions) == 0 {
		return []string{"cites no condition"}
	}
	levels, findings := j.conditionLevels(v)
	findings = append(findings, j.unregisteredCodes(v)...)
	if v.Kind != "gap" && (v.ExpectedIfGapClosed != nil || v.ExpectedIfGapClosedWithoutWindows != nil) {
		findings = append(findings, "carries a gap-closed outcome, which only a gap member has")
	}
	switch v.Kind {
	case "gap":
		findings = append(findings, j.checkGap(v, levels)...)
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
	outcomes := []rsOutcome{v.Expected, v.ExpectedWithoutWindows}
	for _, o := range []*rsOutcome{v.ExpectedIfNotHonoured, v.ExpectedIfGapClosed, v.ExpectedIfGapClosedWithoutWindows} {
		if o != nil {
			outcomes = append(outcomes, *o)
		}
	}
	for _, outcome := range outcomes {
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

// checkGap: a member whose verdict the draft decides and whose decision is the
// gap. It cites gaps and no requirement, the draft accepts it in both passes,
// and the rule that closes one of its gaps refuses it with that gap's code.
func (j *rsJudging) checkGap(v rsVector, levels map[string]bool) []string {
	var findings []string
	gaps := j.gapsCited(v)
	if len(levels) > 0 || len(gaps) == 0 {
		findings = append(findings, "is a gap member whose conditions cite a requirement or no gap")
	}
	if v.Expected.Verdict != rsValid || v.ExpectedWithoutWindows.Verdict != rsValid {
		findings = append(findings, "is a gap member the draft does not accept in both passes")
	}
	closed := v.ExpectedIfGapClosed
	if closed == nil || closed.Verdict != rsInvalid || v.ExpectedIfGapClosedWithoutWindows == nil {
		findings = append(findings, "is a gap member with no invalid outcome when the gap is closed")
	}
	if closed != nil && !j.gapNamesCode(gaps, closed.Code) {
		findings = append(findings, "is a gap member closed with a code none of its gaps names")
	}
	if v.ExpectedIfNotHonoured != nil {
		findings = append(findings, "is a gap member carrying expectedIfNotHonoured, which only a SHOULD member has")
	}
	return findings
}

// gapsCited is every gap the member's conditions cite.
func (j *rsJudging) gapsCited(v rsVector) map[string]bool {
	gaps := map[string]bool{}
	for _, c := range v.Conditions {
		for _, g := range j.manifest.Conditions[c].Gaps {
			gaps[g] = true
		}
	}
	return gaps
}

// gapNamesCode reports whether one of the cited gaps declares the code.
func (j *rsJudging) gapNamesCode(gaps map[string]bool, code *string) bool {
	for _, g := range j.manifest.Gaps {
		if gaps[g.ID] && code != nil && *code == g.Code {
			return true
		}
	}
	return false
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
	measured := map[string]int{"accept": 0, "gap": 0, "indeterminate": 0, "reject": 0}
	for _, v := range m.Vectors {
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
	digest, err := j.corpusDigest()
	if err != nil {
		return err
	}
	if digest != m.CorpusDigest {
		j.find("corpusDigest does not match the receipt files on disk")
	}
	j.checkOrigins()
	return nil
}

// corpusDigest is SHA-256 over every member's preimage in identifier order. A
// file that cannot be read contributes nothing, so the digest disagrees and the
// finding names the corpus rather than stopping the judgement.
func (j *rsJudging) corpusDigest() (string, error) {
	ordered := append([]rsVector{}, j.manifest.Vectors...)
	sort.Slice(ordered, func(a, b int) bool { return ordered[a].ID < ordered[b].ID })
	h := sha256.New()
	for _, v := range ordered {
		preimage, _ := rsPreimage(j.dir, v)
		if _, err := h.Write(preimage); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	j.checkGapsCited()
}

// checkGapsCited: every gap a condition cites is declared, and every declared
// gap is cited.
func (j *rsJudging) checkGapsCited() {
	declared, cited := map[string]bool{}, map[string]bool{}
	for _, g := range j.manifest.Gaps {
		declared[g.ID] = true
	}
	for _, name := range sortedKeys(j.manifest.Conditions) {
		for _, g := range j.manifest.Conditions[name].Gaps {
			if !declared[g] {
				j.find("condition %s cites gap %s the manifest does not declare", name, g)
			}
			cited[g] = true
		}
	}
	if idle := declaredMinusUsed(declared, cited); len(idle) > 0 {
		j.find("gaps declared and cited by no condition: %v", idle)
	}
}

// checkOrigins holds every lifted file to the upstream digest the manifest
// records, so "lifted unchanged" is a property the reader checks.
func (j *rsJudging) checkOrigins() {
	for _, o := range j.manifest.Origins {
		for _, m := range o.Members {
			body, err := readIn(j.dir, m.File)
			if err != nil || sha(body) != m.Sha256 {
				j.find("%s is not the upstream bytes of %s/%s", m.File, o.Path, m.UpstreamFile)
			}
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
// and the window, where the key set publishes one, applied to issued_at. With
// gapClosed the closing rule of RS-G-001 applies after the window.
func rsVerify(body []byte, keys map[string]rsJWK, gapClosed bool) rsOutcome {
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
	window := rsWindow(env, key)
	if window.Verdict != rsValid || !gapClosed {
		return window
	}
	return rsRevocation(env, key)
}

// rsRevocation is the closing rule of RS-G-001: a receipt issued at or after its
// key's revoked_at is invalid.
func rsRevocation(env *rsEnvelope, key rsJWK) rsOutcome {
	if key.RevokedAt == nil {
		return rsOutcome{Verdict: rsValid}
	}
	at, ok := rsInstant(env.fields["issued_at"])
	revoked, err := time.Parse(time.RFC3339, *key.RevokedAt)
	if !ok || err != nil {
		return rsResult(rsUndecidable, "window_not_applicable")
	}
	if !at.Before(revoked) {
		return rsResult(rsInvalid, "key_revoked")
	}
	return rsOutcome{Verdict: rsValid}
}

func rsInstant(raw json.RawMessage) (time.Time, bool) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, value)
	return at, err == nil
}

// rsReadContext is a member's context as read from disk.
type rsReadContext struct {
	chain      [][]byte
	commitment []byte
	loggedAt   string
}

// rsLink is Section 6.7: "sha256:" and the lowercase hex of SHA-256 over the
// whole signed receipt in RFC 8785 form.
func rsLink(body []byte) (string, bool) {
	canonical, err := aee.Canonicalize(body)
	if err != nil {
		return "", false
	}
	return "sha256:" + sha(canonical), true
}

// rsPayloadString reads one string member of a receipt's payload.
func rsPayloadString(body []byte, member string) (string, bool) {
	env, fail := rsParse(body)
	if fail != nil || env.fields[member] == nil {
		return "", false
	}
	var value string
	return value, json.Unmarshal(env.fields[member], &value) == nil
}

// rsVerifyInContext is the receipt, then its chain position (Section 6.7), then,
// with the gap closed, the time of the commitment (RS-G-002).
func rsVerifyInContext(body []byte, keys map[string]rsJWK, ctx *rsReadContext, gapClosed bool) rsOutcome {
	alone := rsVerify(body, keys, gapClosed)
	if alone.Verdict != rsValid || ctx == nil {
		return alone
	}
	for _, element := range ctx.chain {
		if rsVerify(element, keys, gapClosed).Verdict != rsValid {
			return rsResult(rsUndecidable, "chain_element_not_valid")
		}
	}
	receipts := append(append([][]byte{}, ctx.chain...), body)
	for i := 1; i < len(receipts); i++ {
		want, ok := rsLink(receipts[i-1])
		got, present := rsPayloadString(receipts[i], "previousReceiptHash")
		if !ok || !present || got != want {
			return rsResult(rsInvalid, "chain_link_mismatch")
		}
	}
	if !gapClosed || ctx.commitment == nil {
		return rsOutcome{Verdict: rsValid}
	}
	return rsCommitmentTime(body, keys, ctx)
}

// rsCommitment is the payload of an issuer's commitment to a chain.
type rsCommitment struct {
	Count        *int64  `json:"count"`
	TerminalHash *string `json:"terminal_hash"`
}

// rsCommitmentTime is the closing rule of RS-G-002: a commitment of count c
// below this receipt's position p, whose terminal_hash is the link to position
// c, logged at t, means the receipt was not issued before t.
func rsCommitmentTime(body []byte, keys map[string]rsJWK, ctx *rsReadContext) rsOutcome {
	notApplicable := rsResult(rsUndecidable, "commitment_not_applicable")
	logged, err := time.Parse(time.RFC3339, ctx.loggedAt)
	issuer, _ := rsPayloadString(body, "issuer_id")
	env, fail := rsParse(ctx.commitment)
	if err != nil || fail != nil || !rsSignedBy(env, keys, issuer) {
		return notApplicable
	}
	var c rsCommitment
	if json.Unmarshal(env.payload, &c) != nil || c.Count == nil || c.TerminalHash == nil || *c.Count < 1 {
		return notApplicable
	}
	position := int64(len(ctx.chain) + 1)
	if *c.Count >= position {
		return rsOutcome{Verdict: rsValid}
	}
	if want, ok := rsLink(ctx.chain[*c.Count-1]); !ok || *c.TerminalHash != want {
		return notApplicable
	}
	issuedEnv, _ := rsParse(body)
	issued, ok := rsInstant(issuedEnv.fields["issued_at"])
	if !ok {
		return notApplicable
	}
	if issued.Before(logged) {
		return rsResult(rsInvalid, "issued_at_precedes_excluding_commitment")
	}
	return rsOutcome{Verdict: rsValid}
}

// rsSignedBy reports whether the commitment is signed, over JCS of its payload,
// by the receipt's issuer under the external key set.
func rsSignedBy(env *rsEnvelope, keys map[string]rsJWK, issuer string) bool {
	var claimed string
	if json.Unmarshal(env.fields["issuer_id"], &claimed) != nil || claimed != issuer || env.kid != issuer {
		return false
	}
	pub, bad := rsPublicKey(keys[env.kid])
	canonical, err := aee.Canonicalize(env.payload)
	return bad == "" && err == nil && env.sigHexOK && ed25519.Verify(pub, canonical, env.sig)
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
	at, ok := rsInstant(env.fields["issued_at"])
	if !ok {
		return rsResult(rsUndecidable, "window_not_applicable")
	}
	// Every bound is read before any is compared, so an unreadable bound is
	// undecidable whichever side of the other bound issued_at falls on.
	bounds := make([]*time.Time, 2)
	for i, value := range []*string{key.ValidFrom, key.ValidUntil} {
		if value == nil {
			continue
		}
		b, err := time.Parse(time.RFC3339, *value)
		if err != nil {
			return rsResult(rsUndecidable, "window_not_applicable")
		}
		bounds[i] = &b
	}
	if (bounds[0] != nil && at.Before(*bounds[0])) || (bounds[1] != nil && !at.Before(*bounds[1])) {
		return rsResult(rsInvalid, "key_outside_validity_window")
	}
	return rsOutcome{Verdict: rsValid}
}
