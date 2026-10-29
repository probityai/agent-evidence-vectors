# Conformance vectors (MCP server profile)

Every member of this suite in one table. The subject under test is a **server
run record**: what a recorder saw when it launched one version of one MCP
server, and the verdict it drew.

This corpus is 19 vectors, of which 9 a conformant verifier must
not fail closed on and 10 it must reject.

Every member is synthetic and names no server or party. A reject member differs
from its accepting twin in one observed or reported field and violates exactly
one condition.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-mcp-server-profile/` from the repository root.
Check a record: `python3 check_server_record.py records/<id>.json`.

## Conditions

| id | what it requires |
|---|---|
| `msp-c-1` | The record lists every served tool whose definition digest differs from its approved pin, and every served tool that has no pin. Because a tool-description change after approval is the rug pull, and a record that omits it reads as a clean run. |
| `msp-c-2` | The record's version diff lists exactly the tools changed, added and removed against the previous version's digests. Because a reviewer approving an update reads the diff, so an omitted tool is a change nobody was shown. |
| `msp-c-3` | Every host the server contacted that its declared egress does not name is listed as undeclared. Because the egress record is the only part of the run that shows where data left, and an unlisted host is the one that mattered. |
| `msp-c-4` | A run whose egress was not recorded ends as couldnt-run, never as clean or flagged. Because a missing observation read as an empty one is how a server that crashed on start gets a clean badge. |
| `msp-c-5` | A clean outcome requires no pin mismatch and no undeclared host once both are recomputed from the observed fields. Because the outcome is the field a registry ingests, so it must follow from the observations beside it. |
| `msp-c-6` | The record binds the artifact it ran by a sha256 digest, not by a version string. Because a version string is a name its owner can re-point, so a record naming one describes whatever the name resolves to later. |
| `msp-c-7` | A run set's results add up to the servers attempted, and its headline denominator is the servers attempted. Because a server that crashed is still a server the registry asked about, and a headline over the survivors turns a failure rate into a pass rate. |

## Vectors

| id | kind | condition | conditions the checker finds broken |
|---|---|---|---|
| `v008e1b9151983d15` | accept | msp-c-5 | nothing |
| `v07128aefbe8fc27f` | reject | msp-c-1 | msp-c-1 |
| `v134e643936d01386` | reject | msp-c-1 | msp-c-1 |
| `v17b25e5379c4d174` | accept | msp-c-1 | nothing |
| `v1fcad08d1c44eceb` | reject | msp-c-3 | msp-c-3 |
| `v3db5193cc1d684ab` | accept | msp-c-1 | nothing |
| `v4714d7db4e51b9ee` | reject | msp-c-6 | msp-c-6 |
| `v590165bf3f0bb010` | accept | msp-c-7 | nothing |
| `v65e1ad3185ee13a4` | reject | msp-c-7 | msp-c-7 |
| `v796c20aa9a0258ad` | accept | msp-c-3 | nothing |
| `v7edd682bd96524f3` | accept | msp-c-2 | nothing |
| `v8649f4d39185bfec` | reject | msp-c-4 | msp-c-4 |
| `v8c9bee6b148cc91f` | accept | msp-c-2 | nothing |
| `v997b8b4e4ac22707` | reject | msp-c-5 | msp-c-5 |
| `v9d78b607a7174892` | accept | msp-c-4 | nothing |
| `vb5e69eeb01696f43` | reject | msp-c-2 | msp-c-2 |
| `vba853866ea639814` | accept | msp-c-6 | nothing |
| `vc82e812a80909c3a` | reject | msp-c-7 | msp-c-7 |
| `ve8c625cb2ce52929` | reject | msp-c-2 | msp-c-2 |
