package corpusreaders

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(descriptorDigest{}) }

// descriptorDigest judges corpora/vectors-tool-descriptor-digest/. Each member is
// one pin and one observation of an MCP tool descriptor, each a profile, a digest
// and the descriptor the digest was computed from. The reader derives each
// member's decision with the checks the Python reader applies, in the same order:
//
//  1. contract_id_missing; 2. contract_id_unknown;
//  3. profile_unknown: a profile that is present is one of the three;
//  4. descriptor_not_canonicalizable: each descriptor has an RFC 8785 form;
//  5. digest_not_recomputed: each stated digest equals the one recomputed from
//     its descriptor under its own profile.
//
// A record that passes is then compared: a missing profile is a gap
// (profile_absent), two profiles that differ are a gap (profiles_differ) even
// when the digests are equal, equal profiles with different digests are
// contradicted (descriptor_changed), and equal profiles with equal digests are a
// match (descriptor_unchanged). The RFC 8785 bytes come from aee.Canonicalize,
// not from a copy of the Python encoder.
type descriptorDigest struct{}

const (
	ddContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/tool-descriptor-digest"
	ddNDI        = "name-description-inputschema.omit-absent.jcs"
	ddNDIO       = "name-description-inputschema-outputschema.empty-description.jcs"
	ddWhole      = "whole-descriptor.omit-absent.jcs"
)

func (descriptorDigest) Suite() string { return "tool-descriptor-digest/v1" }

type ddRetained struct {
	DigestsEqual string `json:"digestsEqual"`
	Observation  string `json:"observation"`
	Pin          string `json:"pin"`
}

type ddVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained ddRetained        `json:"retained"`
}

type ddSide struct {
	Profile    *string                    `json:"profile"`
	Digest     string                     `json:"digest"`
	Descriptor map[string]json.RawMessage `json:"descriptor"`
}

type ddRecord struct {
	ContractID  json.RawMessage `json:"contractId"`
	Pin         ddSide          `json:"pin"`
	Observation ddSide          `json:"observation"`
}

func (descriptorDigest) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v ddVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = ddJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func ddJudgeMember(caseDir string, v ddVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record ddRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	if kept := ddRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := ddDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func ddRetain(r ddRecord) ddRetained {
	name := func(s ddSide) string {
		if s.Profile == nil {
			return "absent"
		}
		return *s.Profile
	}
	equal := "false"
	if r.Pin.Digest == r.Observation.Digest {
		equal = "true"
	}
	return ddRetained{DigestsEqual: equal, Observation: name(r.Observation), Pin: name(r.Pin)}
}

func ddKnown(profile string) bool {
	return profile == ddNDI || profile == ddNDIO || profile == ddWhole
}

// ddProject is the members a profile covers, with its absent-member rule applied.
func ddProject(descriptor map[string]json.RawMessage, profile string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	if profile == ddWhole {
		for key, value := range descriptor {
			if key != "_meta" {
				out[key] = value
			}
		}
		return out
	}
	covered := []string{"name", "description", "inputSchema"}
	if profile == ddNDIO {
		covered = append(covered, "outputSchema")
	}
	for _, key := range covered {
		if value, ok := descriptor[key]; ok {
			out[key] = value
		}
	}
	if profile == ddNDIO {
		if text, ok := out["description"]; !ok || !bytes.HasPrefix(bytes.TrimSpace(text), []byte(`"`)) {
			out["description"] = json.RawMessage(`""`)
		}
	}
	return out
}

// ddDigest is sha256- and the base64 of the SHA-256 of the RFC 8785 bytes of the projection.
func ddDigest(descriptor map[string]json.RawMessage, profile string) (string, error) {
	projected, err := json.Marshal(ddProject(descriptor, profile))
	if err != nil {
		return "", err
	}
	canonical, err := aee.Canonicalize(projected)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

type ddCheck struct {
	reason string
	fails  bool
}

// ddSides pairs each side's profile with the side, for the checks that read both.
func ddSides(r ddRecord) []ddSide { return []ddSide{r.Pin, r.Observation} }

func ddUnknownProfile(r ddRecord) bool {
	for _, side := range ddSides(r) {
		if side.Profile != nil && !ddKnown(*side.Profile) {
			return true
		}
	}
	return false
}

func ddUncanonicalizable(r ddRecord) bool {
	for _, side := range ddSides(r) {
		if side.Profile == nil || !ddKnown(*side.Profile) || side.Descriptor == nil {
			continue
		}
		if _, err := ddDigest(side.Descriptor, *side.Profile); err != nil {
			return true
		}
	}
	return false
}

func ddNotRecomputed(r ddRecord) bool {
	for _, side := range ddSides(r) {
		if side.Profile == nil || !ddKnown(*side.Profile) || side.Descriptor == nil {
			continue
		}
		if got, err := ddDigest(side.Descriptor, *side.Profile); err != nil || got != side.Digest {
			return true
		}
	}
	return false
}

func ddDecide(r ddRecord) scDecision {
	var contract string
	known := len(r.ContractID) > 0 && strictUnmarshal(r.ContractID, &contract) == nil && contract == ddContractID
	checks := []ddCheck{
		{"contract_id_missing", len(r.ContractID) == 0},
		{"contract_id_unknown", len(r.ContractID) > 0 && !known},
		{"profile_unknown", ddUnknownProfile(r)},
		{"descriptor_not_canonicalizable", ddUncanonicalizable(r)},
		{"digest_not_recomputed", ddNotRecomputed(r)},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"refused", check.reason}
		}
	}
	switch {
	case r.Pin.Profile == nil || r.Observation.Profile == nil:
		return scDecision{"gap", "profile_absent"}
	case *r.Pin.Profile != *r.Observation.Profile:
		return scDecision{"gap", "profiles_differ"}
	case r.Pin.Digest != r.Observation.Digest:
		return scDecision{"contradicted", "descriptor_changed"}
	}
	return scDecision{"match", "descriptor_unchanged"}
}
