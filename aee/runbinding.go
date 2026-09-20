package aee

import "fmt"

// BindingVersion is the only run-binding construction this implementation
// derives. A future version that changes the construction names a new
// binding version; a verifier MUST reject, fail-closed, a binding version
// it does not implement rather than attempt more than one construction
// (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530). There is deliberately exactly ONE construction here.
const BindingVersion = "2"

// RunBindingPreimage builds the RFC 8785 canonical bytes of the binding
// pre-image object (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530):
//
//	{"aeeBindingVersion":"2","catchPolicy":"<hex>","corpus":"<hex>",
//	 "networkPosture":"<hex>","observationVocabulary":"<hex>",
//	 "runEntropy":"<hex>","subject":"<hex>","substrate":"<hex>"}
//
// The member names are emitted in their JCS (UTF-16 code unit) order, which
// for these eight ASCII names is the literal order below. Values are taken
// verbatim (no case-folding, no null fill, spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530); a value that is not
// lowercase 64-hex has already been rejected at GATE 0 for any statement
// that reaches a binding derivation, with the two exceptions the version-2
// construction introduces: networkPosture is a digest OVER the carried object
// rather than a value read from it, and observationVocabulary carries no
// canonicality rule of its own because the vocabulary digest-integrity check
// recomputes it from the arrays beside it. Hex strings never require JSON
// string escaping, so direct formatting below emits exactly the JCS bytes.
func RunBindingPreimage(catchPolicy, corpus, networkPosture, observationVocabulary, runEntropy, subject, substrate string) []byte {
	return []byte(fmt.Sprintf(
		`{"aeeBindingVersion":%q,"catchPolicy":%q,"corpus":%q,"networkPosture":%q,"observationVocabulary":%q,"runEntropy":%q,"subject":%q,"substrate":%q}`,
		BindingVersion, catchPolicy, corpus, networkPosture, observationVocabulary, runEntropy, subject, substrate))
}

// DeriveRunBinding returns the lowercase 64-hex SHA-256 of the binding
// pre-image. A verifier derives this from the statement alone; no field
// carries it (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530).
func DeriveRunBinding(catchPolicy, corpus, networkPosture, observationVocabulary, runEntropy, subject, substrate string) string {
	return SHA256Hex(RunBindingPreimage(catchPolicy, corpus, networkPosture, observationVocabulary, runEntropy, subject, substrate))
}

// posturePreimageDigest is the version-2 networkPosture input: the RFC 8785
// canonical digest of the CARRIED networkPosture object, never of that
// object's own digest member. Binding the member's digest (which is what
// version 1 did) leaves the posture string beside it unsigned, and the posture
// configuration that digest is taken over travels nowhere in the statement, so
// nothing could ever have compared the string against it. Hashing the object
// puts the string, its pinned digest and every further member a producer
// carries there inside the comparison every record already runs.
//
// An absent member, or one that is not a JSON object, contributes the empty
// string, exactly as an absent digest member does elsewhere in this file:
// those statements are already malformed on their own codes, and inventing a
// second failure here would only mask the first. The same reasoning covers a
// canonicalizer error: a lone surrogate or an unsafe integer inside the object
// is caught by the I-JSON profile at GATE 0, so this returns the empty string
// and lets that code be the one the reader sees.
func posturePreimageDigest(env *Environment) string {
	if env == nil || env.Raw == nil {
		return ""
	}
	raw, ok := env.Raw["networkPosture"]
	if !ok || !isJSONObject(raw) {
		return ""
	}
	canonical, err := Canonicalize(raw)
	if err != nil {
		return ""
	}
	return SHA256Hex(canonical)
}

// deriveStatementBinding derives the run binding for a substrate-carrying
// statement whose GATE 0 checks have passed (every input present and, where
// the construction reads it verbatim, lowercase 64-hex).
// The exported GATE 2 / producer-QA entry points (DeriveTiers,
// CheckRecordSignatures) are reachable from a library consumer that may pass a
// statement which has NOT passed GATE 0 (empty subject, absent environment).
// Fail closed rather than panic: a missing subject or environment yields a
// binding built from empty inputs, which matches no real record's binding, so
// substrate rows fall to unattested and the QA check reports a mismatch.
func deriveStatementBinding(s *Statement) string {
	env := s.Predicate.Env
	if env == nil {
		return DeriveRunBinding("", "", "", "", "", "", "")
	}
	subjectHash := ""
	if len(s.Subject) > 0 {
		subjectHash = s.Subject[0].Digest["sha256"]
	}
	return DeriveRunBinding(
		env.CatchPolicy.Sha256(),
		env.Corpus.Sha256(),
		posturePreimageDigest(env),
		env.Vocabulary.Sha256(),
		env.RunEntropy.Sha256(),
		subjectHash,
		env.Substrate.Sha256(),
	)
}
