package corpora

import "fmt"

func init() { register(scittCose{}) }

// scittCose is registered and NOT implemented, which is a deliberate third
// state between "judged" and "unknown".
//
// The suite exists: vectors-scitt-cose/ carries 27 members and a
// check_vectors.py that judges them. What that checker needs, and what no
// reader here yet supplies, is a CBOR reader: RFC 8949 decoding with the
// deterministic map-order test of Section 4.2.1, COSE_Sign1 decoding per
// RFC 9052 including reattaching a detached payload into the Sig_structure
// before the Ed25519 check, the CWT claims map, the two algorithm identifiers
// RFC 9864 registers, and RFC 9162 Section 2.1.3.2 inclusion-proof
// application. The Go module here declares no dependencies and its
// verification core is stdlib-only by design, so that decoder is a build of
// its own rather than an import.
//
// Registering the suite rather than leaving it out is the point. Left out, the
// registry would refuse it as an unknown name, which reads as a typo. Named
// here, the refusal says the corpus is real, says exactly what is missing, and
// still exits non-zero, so nothing about this corpus is ever reported as clean
// by a binary that did not read it. Its check_vectors.py stays where it is
// until this reader lands.
type scittCose struct{}

func (scittCose) Suite() string { return "scitt-cose-carriage-conformance" }

func (s scittCose) Judge(dir string, _ []byte) (*Result, error) {
	return nil, fmt.Errorf(
		"%s declares suite %q, which this binary knows and cannot yet judge: no reader "+
			"here carries a CBOR decoder (RFC 8949 including the Section 4.2.1 deterministic "+
			"map order), COSE_Sign1 verification (RFC 9052, with a detached payload "+
			"reattached into the Sig_structure), the CWT claims map, the RFC 9864 algorithm "+
			"identifiers, or RFC 9162 Section 2.1.3.2 inclusion-proof application. Run that "+
			"corpus's check_vectors.py until this reader lands. This refusal is not a pass: "+
			"a corpus nothing read is never reported as clean",
		dir, s.Suite())
}
