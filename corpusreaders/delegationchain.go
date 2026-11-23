package corpusreaders

import "fmt"

func init() { register(delegationChain{}) }

// delegationChain is registered and NOT implemented, the same third state as
// scittCose: between "judged" and "unknown".
//
// The suite exists: corpora/vectors-delegation-chain/ carries 20 members and a
// check_vectors.py that judges them through the reference reader
// packaging/agent_evidence_vectors/delegationchain.py (fifteen ordered checks
// over a signed chain of grants). No reader here yet ports that logic, so a
// directory run through this binary refuses by name and exits non-zero rather
// than reporting a corpus nothing read as clean. Run that corpus's
// check_vectors.py until the Go reader lands.
type delegationChain struct{}

func (delegationChain) Suite() string { return "delegation-chain/v1" }

func (s delegationChain) Judge(dir string, _ []byte) (*Result, error) {
	return nil, fmt.Errorf(
		"%s declares suite %q, which this binary knows and cannot yet judge: its only "+
			"reader is the Python reference reader (packaging/agent_evidence_vectors/delegationchain.py), "+
			"which checks the fifteen ordered rules over a signed chain of grants. Run that "+
			"corpus's check_vectors.py until a Go reader lands. This refusal is not a pass: "+
			"a corpus nothing read is never reported as clean",
		dir, s.Suite())
}
