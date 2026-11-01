# Unterminated final line: the real 73-line stream

`terminated.jsonl` and `sidecar.json` are the pair Tetsurohhori published as
`docs/cases/unterminated-final-line/` in `aos-standard/catalog` at the tag
`anchors-verify-v0.12` (commit `df8b9ee`), brought to
probityai/agent-evidence#24 (comment 6247271655). The unterminated member is
`terminated.jsonl` with its last byte (`0a`) removed and the same sidecar kept,
so the two members differ by one byte.

| file | bytes | sha256 |
|---|---|---|
| `terminated.jsonl` | 19237 | `7817d72fe446dacc3659ddaca29ce79877aca5ccf497cfc3e0b2c406467f9723` |
| `sidecar.json` | 5304 | `7c6a3023efe4271a91aecf0bbfffddadddab2688ea27e26d407c8d480ccaa165` |

Both are the published bytes, unmodified. The stop reason that matters is
`digest mismatch at line 73`, reached by the digest comparison and not by a
length guard or a parse error on the last line.
