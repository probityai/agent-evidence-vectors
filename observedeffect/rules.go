package observedeffect

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

// One function per rule the predicate states. The mutation table disables exactly
// one at a time and asserts that something stops being refused, because a rule
// whose removal changes no verdict measures nothing.

// ruleIJSONIntegers refuses an integer at or above 2**53 anywhere, at any depth.
// The producer side refuses to encode one; nothing enforced it on the way IN, so a
// byteRange of 9007199254740993 was accepted and two rails read two different
// numbers from one set of bytes.
func ruleIJSONIntegers(c *ctx) *fault {
	var over bool
	var walk func(node any)
	walk = func(node any) {
		if over {
			return
		}
		switch typed := node.(type) {
		case json.Number:
			if integerOverBound(typed) {
				over = true
			}
		case map[string]any:
			for _, value := range typed {
				walk(value)
			}
		case []any:
			for _, value := range typed {
				walk(value)
			}
		}
	}
	walk(c.stmt)
	if over {
		return malformed("integer-not-ijson-safe")
	}
	return nil
}

// rulePredicateType makes the statement say which predicate these fields belong
// to. A consumer routes by this value.
func rulePredicateType(c *ctx) *fault {
	if c.policy.PredicateType == "" || c.str(c.stmt, "predicateType") != c.policy.PredicateType {
		return malformed("predicate-type-unexpected")
	}
	return nil
}

// ruleSubjectBinding binds the subject to the interval's after-state, and to
// nothing else. Its absence made every other rule optional: a consumer gates on
// the subject digest, so while nothing bound it to the interval a record could
// carry an honest, fully authoritative interval beside a subject naming an
// artifact the interval never produced.
func ruleSubjectBinding(c *ctx) *fault {
	subject, ok := c.stmt["subject"].([]any)
	if !ok || len(subject) != 1 {
		return malformed("subject-not-a-single-member")
	}
	member, ok := subject[0].(map[string]any)
	if !ok {
		return malformed("subject-not-a-single-member")
	}
	if f := requireMembers(member, "name", "digest"); f != nil {
		return f
	}
	algorithm := c.str(c.pred, "hashAlgorithm")
	digest, ok := member["digest"].(map[string]any)
	if !ok || len(digest) != 1 {
		return malformed("subject-digest-algorithm-mismatch")
	}
	value, present := digest[algorithm]
	if !present {
		return malformed("subject-digest-algorithm-mismatch")
	}
	text, _ := value.(string)
	if text != c.str(c.interval(), "afterRoot") {
		return malformed("subject-not-the-after-root")
	}
	return nil
}

// ruleRequiredMembers states that no member has a default and no verifier may
// supply one.
func ruleRequiredMembers(c *ctx) *fault {
	if f := requireMembers(c.pred,
		"intervalId", "tier", "mutation", "hashAlgorithm", "interval", "pathScope",
		"authorityDigest", "observation", "reads", "writes", "dualValues",
		"doesNotAssert", "issuedAt"); f != nil {
		return f
	}
	if f := requireMembers(c.interval(),
		"beforeRoot", "afterRoot", "baseResolution", "openedAt", "sealedAt"); f != nil {
		return f
	}
	return requireMembers(c.observation(), "vantage", "coverage", "observedSigners", "origin")
}

// ruleClosedVocabularies fails closed on an unknown value. A verifier that ignores
// a value it does not know has read a record it does not understand as conforming.
func ruleClosedVocabularies(c *ctx) *fault {
	checks := []struct {
		value string
		known map[string]bool
		code  string
	}{
		{c.str(c.pred, "tier"), tiers, "tier-unknown"},
		{c.str(c.pred, "mutation"), mutations, "mutation-unknown"},
		{c.str(c.pred, "hashAlgorithm"), hashAlgorithms, "hash-algorithm-unknown"},
		{c.str(c.observation(), "vantage"), vantages, "vantage-unknown"},
		{c.str(c.observation(), "origin"), origins, "origin-unknown"},
	}
	for _, check := range checks {
		if !check.known[check.value] {
			return malformed(check.code)
		}
	}
	return nil
}

// ruleTimestampGrammar fixes the grammar so that a lexical comparison of two
// timestamps IS a comparison of two instants. Two records defeated the ordering
// rules while it was open: an offset of -05:00 sorted an hour-late commitment
// before the interval it was meant to precede, and a fractional second sorted an
// identical instant strictly before itself.
func ruleTimestampGrammar(c *ctx) *fault {
	interval := c.interval()
	for _, name := range []string{"openedAt", "sealedAt"} {
		if !timestampOK(interval[name]) {
			return malformed("timestamp-not-utc-basic:interval." + name)
		}
	}
	if !timestampOK(c.pred["issuedAt"]) {
		return malformed("timestamp-not-utc-basic:issuedAt")
	}
	commitment, present := c.commitment()
	if present {
		if _, carries := commitment["committedAt"]; carries {
			if !timestampOK(commitment["committedAt"]) {
				return malformed("timestamp-not-utc-basic:priorCommitment.committedAt")
			}
		}
	}
	return nil
}

// ruleIntervalOrder is the ordering the grammar above makes checkable by string
// comparison.
func ruleIntervalOrder(c *ctx) *fault {
	interval := c.interval()
	opened, sealed := c.str(interval, "openedAt"), c.str(interval, "sealedAt")
	if opened >= sealed {
		return malformed("interval-not-ordered")
	}
	if c.str(c.pred, "issuedAt") < sealed {
		return malformed("issued-before-sealed")
	}
	return nil
}

// ruleBaseVocabulary closes the base-resolution vocabulary. Resolution is ordered
// -- supplied, then the authority's recorded parent, then the empty tree -- and a
// value outside the three is a fourth resolution nobody defined.
func ruleBaseVocabulary(c *ctx) *fault {
	if !baseResolutions[c.str(c.interval(), "baseResolution")] {
		return malformed("base-resolution-unknown")
	}
	return nil
}

// ruleEmptyTreeConstant requires the constant for the DECLARED algorithm, not
// either one. This is what makes beforeRoot unconditionally required rather than
// optional-when-unknown: the terminal case has a value, so there is no case in
// which a producer may leave the base out.
func ruleEmptyTreeConstant(c *ctx) *fault {
	interval := c.interval()
	if c.str(interval, "baseResolution") != "empty-tree" {
		return nil
	}
	if c.str(interval, "beforeRoot") != emptyTree[c.str(c.pred, "hashAlgorithm")] {
		return malformed("empty-tree-constant-wrong-algorithm")
	}
	return nil
}

// rulePathScopeLiteral refuses a pattern. A universal scope is the literal "/".
func rulePathScopeLiteral(c *ctx) *fault {
	for _, entry := range c.list(c.pred, "pathScope") {
		text, ok := entry.(string)
		if !ok || !strings.HasPrefix(text, "/") {
			return malformed("path-scope-not-absolute")
		}
		if strings.ContainsAny(text, globMetacharacters) {
			return malformed("path-scope-glob-metacharacter")
		}
	}
	return nil
}

// rulePathsNormalized refuses a dot or dot-dot segment. Without it
// /srv/app/../../../etc/shadow starts with /srv/app/ and a write to /etc/shadow
// travels as in-scope.
func rulePathsNormalized(c *ctx) *fault {
	for _, entry := range c.list(c.pred, "pathScope") {
		if !pathNormalized(entry, true) {
			return malformed("path-scope-not-normalized")
		}
	}
	for _, name := range []string{"reads", "writes"} {
		for _, entry := range c.list(c.pred, name) {
			row, _ := entry.(map[string]any)
			if row == nil || !pathNormalized(row["path"], false) {
				return malformed("path-not-normalized")
			}
		}
	}
	return nil
}

func pathNormalized(value any, allowTrailingSlash bool) bool {
	text, ok := value.(string)
	if !ok || !strings.HasPrefix(text, "/") {
		return false
	}
	body := text[1:]
	if strings.HasSuffix(body, "/") {
		if !allowTrailingSlash {
			return false
		}
		body = body[:len(body)-1]
	}
	if body == "" {
		return true
	}
	for _, segment := range strings.Split(body, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// under is containment at a segment boundary, never by string prefix.
// /srv/application-secrets/id_ed25519 starts with /srv/app and is not under it.
func under(path, scope string) bool {
	prefix := scope
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return path == strings.TrimSuffix(scope, "/") || strings.HasPrefix(path, prefix)
}

// ruleMutationCoherence refuses a record whose own carried evidence refutes its
// own claim.
func ruleMutationCoherence(c *ctx) *fault {
	interval := c.interval()
	writes := c.list(c.pred, "writes")
	if c.str(c.pred, "mutation") == "none" {
		if len(writes) > 0 {
			return malformed("mutation-contradicted-by-writes")
		}
		if c.str(interval, "beforeRoot") != c.str(interval, "afterRoot") {
			return malformed("mutation-none-with-moved-root")
		}
		return nil
	}
	if len(writes) == 0 {
		return malformed("mutation-observed-without-writes")
	}
	return nil
}

// ruleWriteChain requires the ordered composition to carry beforeRoot to
// afterRoot. A chain that does not reach the after-root is a record whose rows do
// not add up to its own claim.
func ruleWriteChain(c *ctx) *fault {
	interval := c.interval()
	writes := c.list(c.pred, "writes")
	if len(writes) == 0 {
		return nil
	}
	cursor := c.str(interval, "beforeRoot")
	for _, entry := range writes {
		row, _ := entry.(map[string]any)
		if f := requireMembers(row, "path", "preStateDigest", "postStateDigest", "inScope"); f != nil {
			return f
		}
		if c.str(row, "preStateDigest") != cursor {
			return malformed("write-chain-broken")
		}
		cursor = c.str(row, "postStateDigest")
	}
	if cursor != c.str(interval, "afterRoot") {
		return malformed("write-chain-does-not-reach-after-root")
	}
	return nil
}

// ruleReadBindings states what a read row carries, and refuses a zero-length
// range: a range of zero bytes proves that a path existed, and reads as proof that
// its contents were seen.
func ruleReadBindings(c *ctx) *fault {
	for _, entry := range c.list(c.pred, "reads") {
		row, _ := entry.(map[string]any)
		if f := requireMembers(row, "path", "preStateDigest", "blobDigest", "readState"); f != nil {
			return f
		}
		state := c.str(row, "readState")
		if !readStates[state] {
			return malformed("read-state-unknown")
		}
		if state != "bytes-read" {
			_, hasRange := row["byteRange"]
			_, hasDigest := row["rangeDigest"]
			if hasRange || hasDigest {
				return malformed("read-state-carries-range")
			}
			continue
		}
		if f := requireMembers(row, "byteRange", "rangeDigest"); f != nil {
			return f
		}
		if f := checkByteRange(row["byteRange"]); f != nil {
			return f
		}
	}
	return nil
}

func checkByteRange(value any) *fault {
	span, _ := value.(map[string]any)
	if f := requireMembers(span, "start", "end"); f != nil {
		return f
	}
	start, startOK := jsonInt(span["start"])
	end, endOK := jsonInt(span["end"])
	if !startOK || !endOK {
		return malformed("byte-range-not-integer")
	}
	if start < 0 {
		return malformed("byte-range-negative")
	}
	if end <= start {
		return malformed("byte-range-empty")
	}
	return nil
}

func jsonInt(value any) (int64, bool) {
	number, ok := numberText(value)
	if !ok {
		return 0, false
	}
	if strings.ContainsAny(number.String(), ".eE") {
		return 0, false
	}
	parsed, err := number.Int64()
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// ruleRangePreimage binds blob length and both offsets, never the range bytes
// alone. A verifier that does not hold the blob holds the range digest as an
// opaque commitment and cannot check it, which is why the predicate calls three of
// the four read bindings checkable rather than four.
func ruleRangePreimage(c *ctx) *fault {
	for _, entry := range c.list(c.pred, "reads") {
		row, _ := entry.(map[string]any)
		if c.str(row, "readState") != "bytes-read" {
			continue
		}
		blob, held := c.policy.Blobs[c.str(row, "blobDigest")]
		if !held {
			continue
		}
		span, _ := row["byteRange"].(map[string]any)
		start, _ := jsonInt(span["start"])
		end, _ := jsonInt(span["end"])
		if start < 0 || end > int64(len(blob)) || end < start {
			return malformed("range-digest-preimage-wrong")
		}
		preimage := []byte(strconv.Itoa(len(blob)) + "\x00" +
			strconv.FormatInt(start, 10) + "\x00" + strconv.FormatInt(end, 10) + "\x00")
		preimage = append(preimage, blob[start:end]...)
		if c.str(row, "rangeDigest") != sha256Hex(preimage) {
			return malformed("range-digest-preimage-wrong")
		}
	}
	return nil
}

// ruleReadChain requires a read's pre-state to be a state this interval actually
// passed through.
func ruleReadChain(c *ctx) *fault {
	reachable := set(c.str(c.interval(), "beforeRoot"))
	for _, entry := range c.list(c.pred, "writes") {
		row, _ := entry.(map[string]any)
		reachable[c.str(row, "postStateDigest")] = true
	}
	for _, entry := range c.list(c.pred, "reads") {
		row, _ := entry.(map[string]any)
		if !reachable[c.str(row, "preStateDigest")] {
			return malformed("read-pre-state-not-in-interval")
		}
	}
	return nil
}

// ruleEmptyTreeHoldsNoBytes refuses a record that reads bytes at the empty tree.
// The terminal case of base resolution is the strongest thing a producer can claim
// about the past -- there was nothing before -- and a record that claims it and
// then reads 64 bytes from a file at that root has said both.
func ruleEmptyTreeHoldsNoBytes(c *ctx) *fault {
	before := c.str(c.interval(), "beforeRoot")
	if before != emptyTree[c.str(c.pred, "hashAlgorithm")] {
		return nil
	}
	for _, entry := range c.list(c.pred, "reads") {
		row, _ := entry.(map[string]any)
		if c.str(row, "readState") == "bytes-read" && c.str(row, "preStateDigest") == before {
			return malformed("bytes-read-from-the-empty-tree")
		}
	}
	return nil
}

// ruleCoverageCoherence refuses a record that declares complete coverage and then
// names a gap inside the scope it says it covered.
func ruleCoverageCoherence(c *ctx) *fault {
	coverage := c.obj(c.observation(), "coverage")
	if f := requireMembers(coverage, "scopeComplete", "gaps"); f != nil {
		return f
	}
	complete, _ := coverage["scopeComplete"].(bool)
	if !complete {
		return nil
	}
	for _, entry := range c.list(coverage, "gaps") {
		gap, _ := entry.(string)
		for _, scopeEntry := range c.list(c.pred, "pathScope") {
			scope, _ := scopeEntry.(string)
			if under(gap, scope) {
				return malformed("coverage-self-contradictory")
			}
		}
	}
	return nil
}

// ruleCoverageGapsNamed makes an incomplete observation say WHERE it was blind. An
// empty gaps list satisfied the tier recompute's coverage clause vacuously, so a
// record could admit it did not cover its own scope, name no gap, and still grade
// authoritative. The blind spot is where the writes went.
func ruleCoverageGapsNamed(c *ctx) *fault {
	coverage := c.obj(c.observation(), "coverage")
	complete, _ := coverage["scopeComplete"].(bool)
	if !complete && len(c.list(coverage, "gaps")) == 0 {
		return malformed("coverage-incomplete-without-gaps")
	}
	return nil
}

// ruleOriginCarriesTheVantage lets only a producer that observed the execution
// itself claim to have stood below it. Without the member there was no place in
// the record where an importer had to say it imported, so a record assembled from
// another vendor's exported log could be emitted as a first-hand below-observed
// observation and no field in the statement contradicted it. The lie was not a
// false value anywhere; it was a claim the format had no slot to refuse.
func ruleOriginCarriesTheVantage(c *ctx) *fault {
	obs := c.observation()
	if c.str(obs, "vantage") == "below-observed" && c.str(obs, "origin") != "first-hand" {
		return malformed("origin-cannot-carry-below-observed-vantage")
	}
	return nil
}

// ruleImportOriginPlatform refuses a hardware-rooted runtime claim from a record
// that holds somebody else's log.
//
// An importer has no quote to present. Whatever the exporting platform measured,
// the importing party cannot produce the evidence for it, so a record whose origin
// is third-party-control-plane or log-import declares a software-only runtime
// platform and a verifier rejects it otherwise. self and first-hand are the two
// origins that may carry a hardware-rooted platform, because both of them
// observed the execution on a machine they were present on.
//
// The vocabulary states this as a MUST beside the origin enum it registers, and
// nothing enforced it: no statement in the corpus carried a runtime member at all,
// and the predicate document named no platform field, so the second half of the
// origin rule was a sentence in a registry with no verifier behind it.
func ruleImportOriginPlatform(c *ctx) *fault {
	if !importOrigins[c.str(c.observation(), "origin")] {
		return nil
	}
	runtime := c.obj(c.observation(), "runtime")
	if runtime == nil {
		return malformed("import-origin-requires-software-only-platform")
	}
	if c.str(runtime, "platform") != "software-only" {
		return malformed("import-origin-requires-software-only-platform")
	}
	return nil
}

// rulePriorCommitmentPresent requires a prior commitment wherever the vantage is
// below-observed. The Fields section says so and nothing enforced it, so a record
// could carry the independence claim with nothing behind it. Refusing it here is
// what makes the tier recompute's commitment clause unreachable, which is why that
// clause is gone rather than kept as a sentence.
func rulePriorCommitmentPresent(c *ctx) *fault {
	obs := c.observation()
	if c.str(obs, "vantage") != "below-observed" {
		return nil
	}
	if _, present := c.commitment(); !present {
		return malformed("prior-commitment-absent-for-vantage")
	}
	return nil
}

// commitmentPreimage is the four members the commitment digest and signature are
// taken over. Four, not two: authorityDigest is in it so an observer cannot select
// a permissive authority after the interval closed, and intervalId is in it so one
// signed commitment cannot serve two intervals that share a before-root.
func (c *ctx) commitmentPreimage(commitment map[string]any) []byte {
	return canonicalStringMap(map[string]string{
		"authorityDigest": c.str(c.pred, "authorityDigest"),
		"beforeRoot":      c.str(c.interval(), "beforeRoot"),
		"intervalId":      c.str(c.pred, "intervalId"),
		"witnessNonce":    c.str(commitment, "witnessNonce"),
	})
}

func ruleCommitmentDigest(c *ctx) *fault {
	commitment, present := c.commitment()
	if !present {
		return nil
	}
	if f := requireMembers(commitment, "committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig"); f != nil {
		return f
	}
	if c.str(commitment, "commitmentDigest") != sha256Hex(c.commitmentPreimage(commitment)) {
		return malformed("commitment-digest-mismatch")
	}
	return nil
}

// ruleKeyidForm fixes one spelling per key identifier, so the disjointness check
// below cannot be dodged by case. An observed party that listed its own key
// uppercase in observedSigners and committed with it lowercase passed the
// discriminator with the same key on both sides.
func ruleKeyidForm(c *ctx) *fault {
	obs := c.observation()
	for _, entry := range c.list(obs, "observedSigners") {
		if !lowerHex(entry) {
			return malformed("keyid-not-lowercase-hex")
		}
	}
	commitment, present := c.commitment()
	if present && !lowerHex(commitment["keyid"]) {
		return malformed("keyid-not-lowercase-hex")
	}
	return nil
}

func lowerHex(value any) bool {
	text, ok := value.(string)
	if !ok || text == "" {
		return false
	}
	for _, character := range text {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

// ruleAgreementDerivable makes the agreement a function of the two carried values.
func ruleAgreementDerivable(c *ctx) *fault {
	for _, entry := range c.list(c.pred, "dualValues") {
		row, _ := entry.(map[string]any)
		if f := requireMembers(row, "fact", "observedValue", "reportedValue", "agreement"); f != nil {
			return f
		}
		declared := c.str(row, "agreement")
		if !agreements[declared] {
			return malformed("agreement-unknown")
		}
		observed, reported := c.str(row, "observedValue"), c.str(row, "reportedValue")
		if observed == "" && reported == "" {
			// Neither side carries a value, so there is no comparison to
			// declare. This read as one-sided and let a record carry any number
			// of dual values that looked like cross-checks and asserted nothing.
			return malformed("dual-value-carries-no-value")
		}
		derived := "disagree"
		switch {
		case observed == "" || reported == "":
			derived = "one-sided"
		case observed == reported:
			derived = "agree"
		}
		if declared != derived {
			return malformed("agreement-not-derivable")
		}
	}
	return nil
}

// ruleDualValueRecomputes recomputes the observed side of any fact the statement
// determines about itself. dualValues is the member the predicate offers as the one
// that catches a lying producer without trusting anyone, and the observed side was
// a free string: a record carrying two writes could declare writes.count observed
// as 7 and agree with itself.
func ruleDualValueRecomputes(c *ctx) *fault {
	for _, entry := range c.list(c.pred, "dualValues") {
		row, _ := entry.(map[string]any)
		derive, known := selfDerivable[c.str(row, "fact")]
		if !known {
			continue
		}
		if c.str(row, "observedValue") != derive(c) {
			return malformed("dual-value-not-recomputable")
		}
	}
	return nil
}

// ruleCommitmentSignature checks the signature rather than noting that one is
// there. Stage two named this gate and nothing implemented it, so sixty-four zero
// bytes in sig produced an authoritative record. Checking it against the key the
// consumer anchored also narrows the two-key attack: the second key a
// self-observer commits with is no longer any key it likes, it is a key the
// consumer has to have anchored.
func ruleCommitmentSignature(c *ctx) *fault {
	commitment, present := c.commitment()
	if !present {
		return nil
	}
	signature, err := hex.DecodeString(c.str(commitment, "sig"))
	if err != nil {
		return malformed("commitment-signature-unreadable")
	}
	key, err := hex.DecodeString(c.policy.ObserverPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return malformed("commitment-signature-unreadable")
	}
	if !ed25519.Verify(key, c.commitmentPreimage(commitment), signature) {
		return invalid("commitment-signature-invalid")
	}
	return nil
}

// ruleCommitmentOrder requires the commitment to precede the interval. A
// commitment made after the fact commits to nothing.
func ruleCommitmentOrder(c *ctx) *fault {
	commitment, present := c.commitment()
	if !present {
		return nil
	}
	if c.str(commitment, "committedAt") >= c.str(c.interval(), "openedAt") {
		return invalid("commitment-not-prior")
	}
	return nil
}

// ruleCommitmentKeyidDisjoint is the offline discriminator. Necessary, and the
// predicate says not sufficient.
func ruleCommitmentKeyidDisjoint(c *ctx) *fault {
	commitment, present := c.commitment()
	if !present {
		return nil
	}
	keyid := c.str(commitment, "keyid")
	for _, entry := range c.list(c.observation(), "observedSigners") {
		signer, _ := entry.(string)
		if signer == keyid {
			return invalid("commitment-keyid-not-disjoint")
		}
	}
	return nil
}

// ruleWriteScope derives the in-scope label from the path and the scope rather
// than reading a producer's opinion of it, and refuses an authoritative record
// whose writes went outside the scope it claims to have covered.
func ruleWriteScope(c *ctx) *fault {
	for _, entry := range c.list(c.pred, "writes") {
		row, _ := entry.(map[string]any)
		covered := c.coveredByScope(c.str(row, "path"))
		claimed, _ := row["inScope"].(bool)
		if covered != claimed {
			return invalid("write-in-scope-mislabelled")
		}
		if !covered && c.str(c.pred, "tier") == "authoritative" {
			return invalid("write-outside-path-scope")
		}
	}
	return nil
}

func (c *ctx) coveredByScope(path string) bool {
	for _, entry := range c.list(c.pred, "pathScope") {
		scope, _ := entry.(string)
		if under(path, scope) {
			return true
		}
	}
	return false
}

// ruleTierRecompute recomputes the tier and never reads it as a claim. Failure is
// invalid rather than a silent downgrade, because a caller that selected its own
// tier and got it quietly corrected learns nothing.
//
// There is no prior-commitment clause and no mutation-shape clause. Both were
// proved UNREACHABLE by the mutation sweep: a below-observed record with no
// commitment is already refused in stage one, a record whose vantage is anything
// else fails the vantage clause first, and a record whose mutation claim disagrees
// with its write set is already malformed. A clause no input can reach is a
// sentence, not a gate, and worse than absent -- it made the coherence rule look
// measured when nothing measured it.
func ruleTierRecompute(c *ctx) *fault {
	obs := c.observation()
	coverage := c.obj(obs, "coverage")
	complete, _ := coverage["scopeComplete"].(bool)
	gapInsideScope := false
	for _, entry := range c.list(coverage, "gaps") {
		gap, _ := entry.(string)
		if c.coveredByScope(gap) {
			gapInsideScope = true
		}
	}
	clauses := []struct {
		code string
		held bool
	}{
		{"authoritative-vantage-not-independent", c.str(obs, "vantage") == "below-observed"},
		{"authoritative-empty-path-scope", len(c.list(c.pred, "pathScope")) > 0},
		{"authoritative-coverage-incomplete", complete || !gapInsideScope},
	}
	derived := "authoritative"
	for _, clause := range clauses {
		if !clause.held {
			derived = "voluntary"
		}
	}
	c.derivedTier = derived
	claimed := c.str(c.pred, "tier")
	if claimed == derived {
		return nil
	}
	c.derivedTier = derived
	if claimed == "authoritative" {
		for _, clause := range clauses {
			if !clause.held {
				return invalid(clause.code)
			}
		}
	}
	return invalid("tier-recompute-mismatch")
}

// ruleAuthoritativeCarriesRows requires an authoritative record to have observed
// something. The non-empty path scope clause closed one spelling of the vacuous
// record; a scope of ["/"] with no reads and no writes is the same record, graded
// the strongest tier, asserting that nothing happened anywhere. A mutation of none
// is a positive claim about an interval, and it needs a row to be a claim about
// anything.
func ruleAuthoritativeCarriesRows(c *ctx) *fault {
	if c.str(c.pred, "tier") != "authoritative" {
		return nil
	}
	if len(c.list(c.pred, "reads")) == 0 && len(c.list(c.pred, "writes")) == 0 {
		return invalid("authoritative-without-observed-rows")
	}
	return nil
}
