# Assertion grade vectors

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Cases for `assertion-grade/v1`: a reader grades every assertion in a record bundle by who could have
written its content, names whom each grade is independent of, and never takes a grade from the bundle's
own claim. One bundle can mix grades. These grades describe record custody and witnessing only; they are
not identity assurance levels.

Replay from the installed package:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-assertion-grade
```

## The grades

| Grade | Means | Routes |
| --- | --- | --- |
| I | content-origin independently attested, with witnessed continuity | `I-HOSTED-WITNESS-QUORUM`, `I-NOTARY`, `I-TEE`, `I-COUNTERPARTY` |
| W+ | no hidden history: witnessed, origin self-attested, every signature of the key accounted for by an attested counter | `W+-HSM-STREAM`, `W+-TEE-JOURNAL` |
| W | a witnessed commitment whose content is attested only by the party it describes | `W-WITNESSED`, `W-MANAGED-CUSTOMER-WITNESS` |
| S | a locally signed commitment with no qualifying witness | `S-LOCAL` |

A witness counts only when neither the record key's operator nor the log's operator runs it; I and W+
need one outside the tenant, the counterparty and the gateway operator. A grade earned only through
witnesses on a staging list, or under a test attestation root, prints `staging-grade`.

- `I-HOSTED-WITNESS-QUORUM`: the gateway operator's key signs what the tenant's agent did and an external
  witness cosigns. Independent of the tenant.
- `I-NOTARY`: an external notary received the request itself at the submission boundary and signed what
  it saw. A notary that signed only a commitment, runs under the tenant, or has a key under a
  customer-custody root earns W. Independent of the tenant and the gateway operator.
- `I-TEE`: the decision path runs in a measured enclave that terminates the agent's channel, quoted under
  a pinned attestation root, with an external witness against rollback. Independent of the tenant and the
  gateway operator.
- `I-COUNTERPARTY`: a receipt binding (target id, key id, salted request commitment, actor stamp digest,
  permit id, stage, outcome, signing time), under a key bound to the target from a public root (a key
  document under the target's domain with its certificate chain, a naming log entry made under
  domain-control validation, or a rail operator's listing), valid at log inclusion, included within the
  stage's receipt window, with a map proof that the log's (permit id, stage) map holds exactly this
  receipt. Independent of the tenant only: the counterparty self-attests. A key the tenant declares is W,
  printed `tenant-declared counterparty`.
- The managed mode (the gateway operator's log with only the tenant's witness) is W for a third party and
  independent of the gateway operator for the tenant; with an external witness in its quorum it is I.
- An assertion about the gateway's own decision is W for a third party. A tenant agent's
  proof-of-possession signature over the request prints `mutually signed` and never raises it.

## The bundle

`case.json` holds `trust` (what the relying party pins: log keys, witness keys with operator class, list
and validity, record keys with operator, role and root, web roots, naming logs, rail operators,
attestation roots and measurements, hardware modules, receipt windows, agent keys, its challenge) and
`bundle` (the assertions, each with its signed statement, log reference and route evidence, and one log:
C2SP checkpoints with an Ed25519 log signature and `cosignature/v1` lines, and the RFC 9162 consistency
proofs between them). A key the grade rests on always comes from `trust` or from content signed under a
root `trust` holds.

The receipt map is a compact sparse Merkle map of depth 256: key
`SHA-256("agent-evidence-receipt-map/v1 key" || SHA-256(issuer key) || u16 len || permit id || u16 len ||
stage)`, entry `SHA-256(0x00 || key || u64 leaf index || leaf hash)`, node `SHA-256(0x01 || left ||
right)`, empty subtree 32 zero bytes, a one-entry subtree is its entry. Its root is a log leaf
`{"format": "agent-evidence-receipt-map-commitment/v1", "root": <hex>}` written after the receipts, so
every cosignature covers it.

## The decision

A bundle is `accepted` when every assertion is graded and no claim exceeds what was derived. It is
`rejected` with the first rule that capped a claimed grade, `claim_route_mismatch` when the claimed route
differs at the same grade, or `coverage_overclaimed` when a claimed witness coverage interval is wider
than the first to last cosignature the witness gave. [INDEX.md](INDEX.md) lists every member;
`MANIFEST.json` holds each member's expected answer.

## Tools

- `gen_vectors.py` writes every case and `MANIFEST.json` deterministically; the expected answers are
  written by hand in it, never by the reader.
- `check_vectors.py` runs the packaged reference reader, or a named verifier with `--verifier "<cmd>"`.
  The contract: `<cmd> <case-dir>/case.json --json` prints `decision`, `reason` and `assertions` (each
  with `id`, `grade`, `route`, `independentOf`, `custody`, `boundary`, `witnesses`, `anchors`,
  `properties`, `label`, `qualifier`), and exits 0 for `accepted` and 1 for `rejected`.
- `mutation_check.py` switches off each rule in turn and fails unless some rejected member changes its
  answer, and no accepted member is refused.
- `corpusreaders/assertiongrade.go` is a second, independent reader in Go.

The attestation root here is a corpus test root, so every TEE fixture prints `staging-grade`. A fixture
under a vendor's production root comes from real hardware and cannot be regenerated from published seeds.
