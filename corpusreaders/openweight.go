package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

func init() { register(openWeight{}) }

// openWeight judges vectors-open-weight-art53/. Each member is a model release
// record and the decision a checker must reach on whether the record evidences
// the conditions of Article 53(2) of the EU AI Act. The reader
// applies the six checks the Python reader applies, in the same order: licence,
// weights, architecture, usage, monetisation and systemic risk. A condition
// that fails outranks one the record is silent on, and the first finding of the
// winning class names the reason. The reader fetches nothing and judges no
// licence in law; it reports what the record carries.
type openWeight struct{}

func (openWeight) Suite() string { return "open-weight-art53/v1" }

const (
	owExempt         = "exempt"
	owNotExempt      = "not-exempt"
	owNotEstablished = "not-established"
	// owComputeThreshold is the Article 51(2) presumption, in floating point operations.
	owComputeThreshold = 1e25
)

var owOpenLicences = map[string]bool{
	"Apache-2.0": true, "MIT": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
	"MPL-2.0": true, "CC-BY-4.0": true, "CC-BY-SA-4.0": true, "GPL-3.0-only": true,
	"LGPL-3.0-only": true, "AGPL-3.0-only": true, "ISC": true, "Unlicense": true,
}

var owRestrictedLicences = map[string]bool{
	"CC-BY-NC-4.0": true, "CC-BY-NC-SA-4.0": true, "CC-BY-NC-ND-4.0": true, "CC-BY-ND-4.0": true,
}

type owVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
}

type owCase struct {
	Release string `json:"release"`
}

type owLocator struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Access string `json:"access"`
	SPDX   string `json:"spdx"`
}

type owRelease struct {
	Licence      owLocator `json:"licence"`
	Weights      owLocator `json:"weights"`
	Architecture owLocator `json:"architecture"`
	Usage        owLocator `json:"usage"`
	Monetisation *[]any    `json:"monetisation"`
	Training     struct {
		Compute any `json:"compute_flop"`
	} `json:"training"`
	SystemicRisk struct {
		Designation string `json:"commission_designation"`
		NotSystemic string `json:"commission_decision_not_systemic"`
	} `json:"systemic_risk"`
}

func (openWeight) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v owVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = owJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func owJudgeMember(caseDir string, v owVector) []string {
	var findings []string
	for _, name := range sortedKeys(v.Files) {
		body, err := readIn(caseDir, name)
		if err != nil {
			findings = append(findings, name+" is declared and absent")
		} else if sha(body) != v.Files[name] {
			findings = append(findings, name+" does not match its manifest digest")
		}
	}
	var c owCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	var release owRelease
	if err := scReadJSON(caseDir, c.Release, &release); err != nil {
		return append(findings, err.Error())
	}
	if got := owAssess(release); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func owHTTPS(url string) bool { return strings.HasPrefix(url, "https://") }

func owHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// owFinding is one condition's outcome; an empty class means the condition holds.
type owFinding struct{ class, reason string }

func owLicence(r owRelease) owFinding {
	switch {
	case owRestrictedLicences[r.Licence.SPDX]:
		return owFinding{owNotExempt, "licence_restricts_use"}
	case !owOpenLicences[r.Licence.SPDX]:
		return owFinding{owNotEstablished, "licence_not_recognised"}
	}
	return owFinding{}
}

func owWeights(r owRelease) owFinding {
	switch r.Weights.Access {
	case "private":
		return owFinding{owNotExempt, "weights_not_public"}
	case "gated":
		return owFinding{owNotEstablished, "weights_access_gated"}
	case "public":
		if !owHTTPS(r.Weights.URL) || !owHex64(r.Weights.SHA256) {
			return owFinding{owNotEstablished, "weights_not_digest_bound"}
		}
		return owFinding{}
	}
	return owFinding{owNotEstablished, "weights_not_evidenced"}
}

func owMonetisation(r owRelease) owFinding {
	switch {
	case r.Monetisation == nil:
		return owFinding{owNotEstablished, "monetisation_not_stated"}
	case len(*r.Monetisation) > 0:
		return owFinding{owNotExempt, "monetised_release"}
	}
	return owFinding{}
}

func owSystemicRisk(r owRelease) owFinding {
	if r.SystemicRisk.Designation != "" {
		return owFinding{owNotExempt, "systemic_risk_designated"}
	}
	if owHTTPS(r.SystemicRisk.NotSystemic) {
		return owFinding{}
	}
	compute, ok := r.Training.Compute.(float64)
	if !ok || compute <= 0 {
		return owFinding{owNotEstablished, "training_compute_not_stated"}
	}
	if compute > owComputeThreshold {
		return owFinding{owNotExempt, "systemic_risk_presumed"}
	}
	return owFinding{}
}

func owAssess(r owRelease) scDecision {
	findings := []owFinding{owLicence(r), owWeights(r)}
	if !owHTTPS(r.Architecture.URL) {
		findings = append(findings, owFinding{owNotEstablished, "architecture_not_evidenced"})
	} else {
		findings = append(findings, owFinding{})
	}
	if !owHTTPS(r.Usage.URL) {
		findings = append(findings, owFinding{owNotEstablished, "usage_information_not_evidenced"})
	} else {
		findings = append(findings, owFinding{})
	}
	findings = append(findings, owMonetisation(r), owSystemicRisk(r))
	for _, class := range []string{owNotExempt, owNotEstablished} {
		for _, f := range findings {
			if f.class == class {
				return scDecision{Decision: class, Reason: f.reason}
			}
		}
	}
	return scDecision{Decision: owExempt, Reason: "all_conditions_evidenced"}
}
