// Command ijson-gate-shim exposes the reference I-JSON ingress gate
// (aee.CheckIJSON) over a line-delimited JSON protocol on stdin/stdout, so a
// cross-implementation differential harness can drive the REAL reference gate as
// one rail alongside the other verifier implementations -- never a
// reimplementation. CheckIJSON runs the same well-formedness the verifier
// applies to a record payload before any schema is read: the value grammar, the
// duplicate-member and safe-integer rules, the nesting-depth bound, and the
// raw-byte string-scalar scan (surrogates, noncharacters, raw control bytes).
//
// Request  (one JSON object per stdin line):
//
//	{"id": 1, "mode": "gate", "input_b64": "<base64 of raw JSON bytes>"}
//
// Response (one JSON object per stdout line):
//
//	{"id": 1, "rail": "aee", "mode": "gate", "accept": true}
//	{"id": 1, "rail": "aee", "mode": "gate", "accept": false, "reason": "<error>"}
//
// input_b64 carries the candidate as base64 so arbitrary bytes -- including
// forms that are not valid UTF-8 or that JSON-escape ambiguously -- survive
// transport verbatim, which is the whole point of a differential over the gate.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/probityai/agent-evidence-vectors/aee"
)

type request struct {
	ID       int64  `json:"id"`
	Mode     string `json:"mode"`
	InputB64 string `json:"input_b64"`
}

type response struct {
	ID     int64  `json:"id"`
	Rail   string `json:"rail"`
	Mode   string `json:"mode"`
	Accept bool   `json:"accept"`
	Reason string `json:"reason,omitempty"`
}

func main() {
	run(os.Stdin, os.Stdout, os.Stderr)
}

// run reads one request object per line from stdin and writes one response
// object per line to stdout, so the protocol loop is exercisable in a test
// without a real process boundary.
func run(stdin io.Reader, stdout, stderr io.Writer) {
	in := bufio.NewScanner(stdin)
	// Candidates can be large; raise the line cap well above the 64 KiB default.
	in.Buffer(make([]byte, 0, 1<<20), 16<<20)
	out := bufio.NewWriter(stdout)
	// A failed final flush to a broken stdout is unactionable (the harness went
	// away); discard it explicitly, as the loop below already handles a mid-stream
	// flush error by returning.
	defer func() { _ = out.Flush() }()

	enc := json.NewEncoder(out)
	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		var resp response
		if err := json.Unmarshal(line, &req); err != nil {
			// A malformed control line is a harness bug, not a gate verdict.
			resp = response{Rail: "aee", Accept: false, Reason: "shim: bad request: " + err.Error()}
		} else {
			resp = handle(req)
		}
		// A write/flush failure means stdout is broken (the harness went away);
		// there is nothing left to report to, so stop the loop.
		if err := enc.Encode(resp); err != nil {
			fmt.Fprintln(stderr, "shim: encode failed:", err)
			return
		}
		if err := out.Flush(); err != nil {
			fmt.Fprintln(stderr, "shim: flush failed:", err)
			return
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(stderr, "shim: read failed:", err)
	}
}

func handle(req request) response {
	resp := response{ID: req.ID, Rail: "aee", Mode: req.Mode}
	raw, err := base64.StdEncoding.DecodeString(req.InputB64)
	if err != nil {
		resp.Accept = false
		resp.Reason = "shim: bad input_b64: " + err.Error()
		return resp
	}
	switch req.Mode {
	case "gate":
		if err := aee.CheckIJSON(raw); err != nil {
			resp.Accept = false
			resp.Reason = err.Error()
			return resp
		}
		resp.Accept = true
		return resp
	default:
		resp.Accept = false
		resp.Reason = fmt.Sprintf("shim: unknown mode %q", req.Mode)
		return resp
	}
}
