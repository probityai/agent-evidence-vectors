package corpusreaders

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// The dataSubject member (revision 04, rows DS1 to DS10): a keyed reference to
// the person whose data a call read, kept apart from the delegated subject, and
// a purpose taken from the list the server declared. The rule restates
// packaging/agent_evidence_vectors/auditrecord.py (_rule_data_subject) and
// refuses in the same order with the same codes.

var arDataSubjectMembers = []string{
	"scheme", "saltId", "reference", "relation", "purpose", "purposes", "purposesDigest",
}

var arDataSubjectOptional = []string{"delegateReference"}

// arDataSubjectScheme is SHA-256, as hex, of the RFC 8785 bytes of
// {"salt": <base64url salt>, "subject": <identifier>}.
const arDataSubjectScheme = "salted-sha256-jcs"

var arDataSubjectRelations = []string{"delegate", "other"}

// arDataSubjectChecks names each sentence of the rule after the shape, so a test
// can weaken one at a time and see exactly its member fail.
var arDataSubjectChecks = map[string]bool{
	"unknown": true, "relation": true, "merged": true, "digest": true, "purpose": true,
}

// arCanonicalDigest is the hex SHA-256 of the RFC 8785 bytes of a JSON value.
func arCanonicalDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := aee.Canonicalize(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// arDataSubjectReference is what the server recomputes from its salt
// (base64url) and an identifier when it answers an access request.
func arDataSubjectReference(salt, subjectID string) (string, error) {
	return arCanonicalDigest(map[string]any{"salt": salt, "subject": subjectID})
}

func arDataSubjectPurposes(raw any) bool {
	purposes, ok := raw.([]any)
	if !ok || len(purposes) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, item := range purposes {
		text, ok := item.(string)
		if !ok || text == "" || seen[text] {
			return false
		}
		seen[text] = true
	}
	return true
}

func arDataSubjectShape(raw any) (map[string]any, error) {
	value, ok := raw.(map[string]any)
	if !ok {
		return nil, arRefuse("data-subject-malformed")
	}
	for _, name := range arDataSubjectMembers {
		if _, has := value[name]; !has {
			return nil, arRefuse("data-subject-member-missing")
		}
	}
	if arDataSubjectChecks["unknown"] {
		for name := range value {
			if !arContains(arDataSubjectMembers, name) && !arContains(arDataSubjectOptional, name) {
				return nil, arRefuse("data-subject-member-unknown")
			}
		}
	}
	digests := []string{arStr(value, "reference"), arStr(value, "purposesDigest")}
	if _, has := value["delegateReference"]; has {
		digests = append(digests, arStr(value, "delegateReference"))
	}
	bad := arStr(value, "scheme") != arDataSubjectScheme ||
		!arContains(arDataSubjectRelations, arStr(value, "relation")) ||
		!arNonEmpty(value["saltId"]) || !arNonEmpty(value["purpose"]) ||
		!arDataSubjectPurposes(value["purposes"])
	for _, text := range digests {
		bad = bad || !arIsDigest(text)
	}
	if bad {
		return nil, arRefuse("data-subject-malformed")
	}
	return value, nil
}

// arDataSubjectRelation: a user caller names its own reference beside the data
// subject's unless the two are one person; a system caller has no delegate to
// name.
func arDataSubjectRelation(value map[string]any, subjectKind string) error {
	isUser := subjectKind == "user"
	_, hasDelegate := value["delegateReference"]
	if arDataSubjectChecks["relation"] {
		if arStr(value, "relation") == "delegate" {
			if !isUser || hasDelegate {
				return arRefuse("data-subject-relation-mismatch")
			}
		} else if hasDelegate != isUser {
			return arRefuse("data-subject-relation-mismatch")
		}
	}
	if arDataSubjectChecks["merged"] && hasDelegate &&
		arStr(value, "delegateReference") == arStr(value, "reference") {
		return arRefuse("data-subject-merged")
	}
	return nil
}

func arRuleDataSubject(s *arState) error {
	raw, present := s.pred["dataSubject"]
	if !present {
		return nil
	}
	value, err := arDataSubjectShape(raw)
	if err != nil {
		return err
	}
	if err := arDataSubjectRelation(value, arStr(s.pred, "delegation.subjectKind")); err != nil {
		return err
	}
	if arDataSubjectChecks["digest"] {
		sum, err := arCanonicalDigest(value["purposes"])
		if err != nil || sum != arStr(value, "purposesDigest") {
			return arRefuse("data-subject-purposes-digest-mismatch")
		}
	}
	if arDataSubjectChecks["purpose"] {
		purposes, _ := value["purposes"].([]any)
		for _, item := range purposes {
			if item == value["purpose"] {
				return nil
			}
		}
		return arRefuse("data-subject-purpose-undeclared")
	}
	return nil
}
