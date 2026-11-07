# MCP authorization observation vectors

Recorded observations of what an MCP server publishes about its OAuth protection, each with the verdict and finding codes a verifier must return for it.

This is for anyone who builds or operates an MCP authorization check and wants an outside answer key: a server author, an identity provider, a scanner or a gateway. The fixtures are synthetic (`example.test` hosts, no real key or token).

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

```sh
pip install agent-evidence-vectors==0.36.3
agent-evidence-vectors --corpus vectors-mcp-authz --verifier "python3 my_verifier.py"
```

The harness runs `my_verifier.py <observation file>` once per member. The verifier prints, as its last stdout line, one JSON object with `verdict` (`valid` or `invalid`) and `codes` (the finding codes, a set), and exits 0 for `valid`. A reject member passes when the verifier says `invalid` and names at least one of the member's codes. The report states `vectors executed N of N`.

## What the observations cover

Protected Resource Metadata (RFC 9728), Authorization Server metadata (RFC 8414), the Bearer challenge on a request with no token (RFC 6750 section 3), the server's authorization settings, and whether a request with no token, or without a required scope, is refused. Four extension surfaces follow: a DPoP proof and its binding to the token (RFC 9449), a workload identity token exchanged for scopes, an OAuth Client ID Metadata Document and an identity assertion authorization grant. JWTs are carried decoded and signatures are outside this corpus.

`MANIFEST.json` lists every member with its answer. `INDEX.md` is the same table for a reader. `gen_vectors.py` writes the observations, the manifest and the index; do not edit them by hand.

## Check the corpus itself

`aee-verify vectors-mcp-authz` checks that the corpus is intact: each file is the one the manifest names, each answer is well formed, every observation is marked synthetic, and the counts and digest agree. It does not judge the verdicts. That is the job of the verifier you name above.
