# Credential reachability vectors

Cases for `credential-reachability/v1`, the
[Credential Reachability predicate](../../spec/predicates/credential-reachability.md): a
probe ran inside an AI agent's environment, with the agent's own identity and view, and
tried every ambient credential class of a closed list (SSH agent sockets and key files,
cloud metadata endpoints, cloud and registry credential files, browser cookie stores,
environment tokens, cluster service-account tokens, git credential helpers and host
keyrings). A key outside the agent's reach signed what it found, bound to the
environment's contract, a verifier's challenge and an audience.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Replay from the installed package:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-credential-reachability
```

## The rule under test

A verifier holds a policy: the trusted signer keys, the keys the agent holds, the
environment's name and contract digest, the audience, the challenge it issued, the time
it judges at, the oldest result it accepts and, optionally, the probe digests it
accepts. It applies the predicate's 26 rules in order and names the first that fails.
The rules that matter most:

- A record signed by a key the agent holds is refused, whatever `keyid` it names, and so
  is an envelope the agent co-signed.
- A record for another environment, another contract, another audience or an earlier
  challenge is refused.
- Every class of the list must be reported, once.
- A probe that did not run, or failed, is never `not_reachable`: the verifier recomputes
  each class verdict and the result from the attempts and refuses one that is better
  than the attempts support.
- An attempt carries a locator and, for a credential it found, a 12-hex-digit prefix of
  its digest. An attempt that carries a value, a full digest or any other member is
  refused.

A record that passes is `supported`: `contained_verified`, `exposed_verified` or
`incomplete_verified`. Only `contained` supports the claim that no credential other
than one issued to the agent is reachable from the agent's environment. A supported `exposed` record
is a verified finding; the `exposed` member is the positive control.

Each refused member names its supported twin and differs from it by one scripted
mutation. [INDEX.md](INDEX.md) lists every member; `MANIFEST.json` holds the expected
`decision` and `reason` for each.

## Keys

Every envelope is signed with test keys whose seeds are the SHA-256 of public labels in
`gen_vectors.py`: the environment host's key, a key the agent holds and a key no policy
names. Anyone can re-derive them. They are test keys only.

## Tools

- `gen_vectors.py` writes every case, `MANIFEST.json` and `INDEX.md` deterministically.
- `check_vectors.py` runs the packaged reference reader, or a named verifier with
  `--verifier "<cmd>"`. The contract: `<cmd> <case-dir>/case.json --json` prints one
  JSON object with `decision` and `reason` on its last line, and exits 0 for
  `supported`, 1 for `contradicted` or `not_established`, and 2 when no verdict was
  reached.
- `mutation_check.py` switches each rule of the reader off alone and requires some
  member to change its answer.
- The Go reader, `corpusreaders/credreach.go`, reaches the same decision and reason on
  every member.
