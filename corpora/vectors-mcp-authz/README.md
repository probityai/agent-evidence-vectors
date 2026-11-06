# MCP authorization observation vectors

Recorded observations of what an MCP server publishes about its OAuth protection, each with the verdict and finding codes a verifier must return for it.

This is for anyone who builds or operates an MCP authorization check and wants an outside answer key: a server author, an identity provider, a scanner or a gateway. The fixtures are synthetic (`example.test` hosts, no real key or token).

```sh
pip install agent-evidence-vectors==0.35.0
agent-evidence-vectors --corpus vectors-mcp-authz --verifier "python3 my_verifier.py"
```

The harness runs `my_verifier.py <observation file>` once per member. The verifier prints, as its last stdout line, one JSON object with `verdict` (`valid` or `invalid`) and `codes` (the finding codes, a set), and exits 0 for `valid`. A reject member passes when the verifier says `invalid` and names at least one of the member's codes. The report states `vectors executed N of N`.

## What the observations cover

Protected Resource Metadata (RFC 9728), Authorization Server metadata (RFC 8414), the Bearer challenge on a request with no token (RFC 6750 section 3), the server's authorization settings, and whether a request with no token, or without a required scope, is refused. JWTs are carried decoded and signatures are outside this corpus.

`MANIFEST.json` lists every member with its answer. `INDEX.md` is the same table for a reader. `gen_vectors.py` writes the observations, the manifest and the index; do not edit them by hand.

## Check the corpus itself

`aee-verify vectors-mcp-authz` checks that the corpus is intact: each file is the one the manifest names, each answer is well formed, every observation is marked synthetic, and the counts and digest agree. It does not judge the verdicts. That is the job of the verifier you name above.
