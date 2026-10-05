package corpora_test

// A head signed by a party other than the Guardian is two different cases in
// the two profiles, and the corpus has to say so with two different shapes.
//
// Under ACS-Crypto the signature verifies only under a key other than the one
// its key_id resolves to, and anyone holding the Guardian's public key can tell
// the signer is wrong: a rejection with SIGNATURE_INVALID, checkable from
// outside the trust domain. Under the HMAC baseline the verification key is
// the signing key, so a MAC computed by the other key-holder verifies exactly
// as the Guardian's would, and nothing in the head or the public material
// names who computed it. Grading that member allow or deny would grade an
// attribution nobody can make. "Signer is wrong" and "signer cannot be
// determined" are different outcomes, and a corpus that gives them one shape
// has erased the difference a verifier is required to report.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type wrongSignerRow struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	File         string   `json:"file"`
	Requirements []string `json:"requirements"`
	Expected     struct {
		Verdict             string  `json:"verdict"`
		Code                *string `json:"code"`
		UnmeasurableBecause *string `json:"unmeasurableBecause"`
	} `json:"expected"`
	WitnessScope string `json:"witnessScope"`
}

type wrongSignerPayload struct {
	Profile          string `json:"profile"`
	SignedBy         string `json:"signed_by"`
	GuardianResponse *struct {
		Signature struct {
			Algorithm string `json:"algorithm"`
		} `json:"signature"`
	} `json:"guardian_response"`
}

type wrongSignerMember struct {
	row       wrongSignerRow
	algorithm string
}

// wrongSignerMembers returns, per profile, every member whose payload is a
// Guardian response signed by some party other than the Guardian.
func wrongSignerMembers(t *testing.T) map[string][]wrongSignerMember {
	t.Helper()
	dir := corpusPath("vectors-acs-core")
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatalf("reading the ACS-Core manifest: %v", err)
	}
	var manifest struct {
		Vectors []wrongSignerRow `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("the ACS-Core manifest does not parse: %v", err)
	}
	if len(manifest.Vectors) == 0 {
		t.Fatal("the ACS-Core manifest lists no members, so an absence below would prove nothing")
	}
	found := map[string][]wrongSignerMember{}
	for _, row := range manifest.Vectors {
		body, err := os.ReadFile(filepath.Join(dir, row.File))
		if err != nil {
			t.Fatalf("%s: reading the vector file: %v", row.ID, err)
		}
		var document struct {
			Payload wrongSignerPayload `json:"payload"`
		}
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatalf("%s: the vector file does not parse: %v", row.ID, err)
		}
		p := document.Payload
		if p.GuardianResponse == nil || p.SignedBy == "" || p.SignedBy == "guardian" {
			continue
		}
		found[p.Profile] = append(found[p.Profile],
			wrongSignerMember{row, p.GuardianResponse.Signature.Algorithm})
	}
	return found
}

func TestACSWrongSignerIsTwoShapesAcrossProfiles(t *testing.T) {
	found := wrongSignerMembers(t)

	crypto := found["ACS-Crypto"]
	if len(crypto) != 1 {
		t.Fatalf("want exactly one ACS-Crypto wrong-signer member, found %d", len(crypto))
	}
	c := crypto[0]
	if c.algorithm == "HMAC-SHA256" || c.algorithm == "" {
		t.Errorf("%s: the ACS-Crypto member must carry an asymmetric signature, carries %q", c.row.ID, c.algorithm)
	}
	if c.row.Kind != "reject" || c.row.Expected.Verdict != "deny" {
		t.Errorf("%s: want a reject expecting deny, got kind %q verdict %q", c.row.ID, c.row.Kind, c.row.Expected.Verdict)
	}
	if c.row.Expected.Code == nil || *c.row.Expected.Code != "SIGNATURE_INVALID" {
		t.Errorf("%s: want code SIGNATURE_INVALID, got %v", c.row.ID, c.row.Expected.Code)
	}
	if c.row.WitnessScope != "EXTERNAL" {
		t.Errorf("%s: a public key lets a third party see the wrong signer, so want EXTERNAL, got %q",
			c.row.ID, c.row.WitnessScope)
	}

	core := found["ACS-Core"]
	if len(core) != 1 {
		t.Fatalf("want exactly one ACS-Core wrong-signer member, found %d", len(core))
	}
	h := core[0]
	if h.algorithm != "HMAC-SHA256" {
		t.Errorf("%s: the ACS-Core member must carry the HMAC baseline, carries %q", h.row.ID, h.algorithm)
	}
	if h.row.Kind != "indeterminate" || h.row.Expected.Verdict != "unmeasurable" {
		t.Errorf("%s: want an indeterminate member expecting unmeasurable, got kind %q verdict %q",
			h.row.ID, h.row.Kind, h.row.Expected.Verdict)
	}
	if h.row.Expected.Code != nil {
		t.Errorf("%s: an undeterminable signer asserts no code, got %q", h.row.ID, *h.row.Expected.Code)
	}
	if h.row.Expected.UnmeasurableBecause == nil || *h.row.Expected.UnmeasurableBecause == "" {
		t.Errorf("%s: an unmeasurable member must record why", h.row.ID)
	}
	citesNonRepudiation := false
	for _, r := range h.row.Requirements {
		if r == "ACS-R-021" {
			citesNonRepudiation = true
		}
	}
	if !citesNonRepudiation {
		t.Errorf("%s: want the member to cite ACS-R-021, the section 8.6 sentence that puts "+
			"non-repudiation in ACS-Crypto; it cites %v", h.row.ID, h.row.Requirements)
	}

	if c.row.Expected.Verdict == h.row.Expected.Verdict {
		t.Errorf("%s and %s share the verdict %q, so a wrong signer and an undeterminable one read the same",
			c.row.ID, h.row.ID, c.row.Expected.Verdict)
	}
}

// An HMAC head offered to a third party as proof of which Guardian issued it
// is a claim the symmetric tier cannot carry, and grading it weak lets it
// through. The corpus therefore needs a member that refuses the claim: the
// signature verifies and the signer is honest, and the verdict is still deny.
// It must not share the undeterminable member's verdict, or a surface that can
// only say "weak" passes it.
func TestACSSymmetricHeadClaimedExternalIsRefused(t *testing.T) {
	dir := corpusPath("vectors-acs-core")
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatalf("reading the ACS-Core manifest: %v", err)
	}
	var manifest struct {
		Vectors []wrongSignerRow `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("the ACS-Core manifest does not parse: %v", err)
	}
	if len(manifest.Vectors) == 0 {
		t.Fatal("the ACS-Core manifest lists no members, so an absence below would prove nothing")
	}
	var claimed, peer, undeterminable []wrongSignerRow
	for _, row := range manifest.Vectors {
		body, err := os.ReadFile(filepath.Join(dir, row.File))
		if err != nil {
			t.Fatalf("%s: reading the vector file: %v", row.ID, err)
		}
		var document struct {
			Payload struct {
				wrongSignerPayload
				PresentedAs *struct {
					WitnessScope string `json:"witness_scope"`
				} `json:"presented_as"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatalf("%s: the vector file does not parse: %v", row.ID, err)
		}
		p := document.Payload
		if p.Profile != "ACS-Core" || p.GuardianResponse == nil ||
			p.GuardianResponse.Signature.Algorithm != "HMAC-SHA256" {
			continue
		}
		switch {
		case p.PresentedAs != nil && p.PresentedAs.WitnessScope == "EXTERNAL":
			claimed = append(claimed, row)
		case p.PresentedAs != nil && p.PresentedAs.WitnessScope == "PEER":
			peer = append(peer, row)
		case row.Expected.Verdict == "unmeasurable":
			undeterminable = append(undeterminable, row)
		}
	}
	// The refusal must be of the claim, not of the algorithm: the same head
	// presented to a key-holder is allowed, or a verifier refusing every HMAC
	// head passes the member above.
	if len(peer) != 1 || peer[0].Kind != "accept" || peer[0].Expected.Verdict != "allow" {
		t.Errorf("want one accepting twin presenting the same HMAC head at PEER scope, found %d", len(peer))
	}
	if len(claimed) != 1 {
		t.Fatalf("want exactly one ACS-Core HMAC head presented as EXTERNAL evidence, found %d", len(claimed))
	}
	r := claimed[0]
	if r.Kind != "reject" || r.Expected.Verdict != "deny" {
		t.Errorf("%s: want a reject expecting deny, got kind %q verdict %q", r.ID, r.Kind, r.Expected.Verdict)
	}
	if r.Expected.Code != nil {
		t.Errorf("%s: the signature verifies, so no registry code names this refusal; got %q", r.ID, *r.Expected.Code)
	}
	cites := false
	for _, id := range r.Requirements {
		if id == "ACS-R-021" {
			cites = true
		}
	}
	if !cites {
		t.Errorf("%s: want the member to cite ACS-R-021; it cites %v", r.ID, r.Requirements)
	}
	if r.WitnessScope != "EXTERNAL" {
		t.Errorf("%s: the algorithm and the claim are in the presented bytes, so want EXTERNAL, got %q",
			r.ID, r.WitnessScope)
	}
	for _, u := range undeterminable {
		if u.Expected.Verdict == r.Expected.Verdict {
			t.Errorf("%s and %s share the verdict %q", r.ID, u.ID, r.Expected.Verdict)
		}
	}
	if len(undeterminable) == 0 {
		t.Error("the undeterminable HMAC member this refusal is contrasted with is missing")
	}
}
