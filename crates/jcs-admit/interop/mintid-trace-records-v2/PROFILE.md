# MintID manifest-v2 consumer profile

The profile ID is `mintid-trace-records-v2`. Control IDs `MTRV2-001` through `MTRV2-089` belong to this profile. They do not replace any earlier corpus, comparison or study.

## Original inputs

[SOURCE-SELECTION.json](SOURCE-SELECTION.json) pins twelve files from public source `e4efba09598fe0110a929e224a814cb706cc9d0c`: the records directory's ten original members, LICENSE and NOTICE. Every byte length, SHA-256 and Git blob is checked before qualification. The selected records are:

- `revocation-trace-local-20261004T122943Z`: 198 events and 85 decisions.
- `revocation-trace-testnet-20261004T153434Z`: 75 events and 23 decisions.
- `revocation-trace-testnet-20261005T022948Z`: 75 events and 23 decisions.

These are later published copies of older records. The originally advertised October 4 tag was unavailable when checked. The public project and available tag/tree routes supplied positive controls. The later source pin does not authenticate an older deployed revision. In all three original manifests, `source`, `deployment.build` and `policy` are null. Operator assertions remain under `stated`.

The imported records retain MintID's Apache-2.0 LICENSE and NOTICE. The Go source and its license remain under the unchanged existing Go profile.

## One installed entry point

Use the installed wheel and trusted absolute paths to the Go and admission executables:

```sh
/absolute/qualification/reader/bin/python -m mintid_trace \
  --records /absolute/path/to/records \
  --record revocation-trace-testnet-20261005T022948Z \
  --go /absolute/qualification/commands/go-jcs \
  --admission /absolute/qualification/commands/go-jcs-admission \
  --capture-dir /absolute/new/private/capture \
  --limits /absolute/host-selected/limits.json
```

The record directory must be canonical. Each member must be a regular file with its exact expected basename. The reader does not follow symlinks or open names from the manifest's hash map. Every declared member must match the actual SHA-256. A new capture directory under an existing parent prevents overwriting an earlier result.

The reader uses the existing I-JSON admission profile. Fractions remain supported. Unsafe integral tokens, duplicate names, malformed UTF-8, non-scalar strings, excessive depth and scalar roots refuse before Python parses the original bytes. Native refusal classes remain unchanged. For example, the I-JSON gate refuses `1e309` as `UnsafeInteger` before its nonfinite-number check.

Each member and JSONL line retains the existing 20 MiB admission ceiling and 128-level nesting ceiling. POSIX no-follow, nonblocking opens reject links and special files before reads. Fixed chunks grow with actual bytes; a one-byte file does not allocate the whole ceiling. The maintained workflow runs on Linux.

The host must select one limits JSON file with exactly these positive integer fields. Booleans, duplicate fields and missing fields refuse. These values show the qualification policy; they are not universal supported workload limits:

```json
{"input_bytes":1048576,"events":256,"native_calls":257,"native_output_bytes":2097152,"capture_bytes":4194304,"capture_files":2048}
```

Aggregate input, raw row count and required native-call count are checked before repeated native work. A malformed admitted row refuses immediately. The three published originals contain 165302/81938/83421 input bytes, 198/75/75 events and 199/76/76 native calls. Their base retained regular member/call files number 799/307/307; including directories, they need 1000/385/385 filesystem entries. `capture_files` counts the root, member and call directories as well as regular files, so it is also an inode budget. `qualify.py` retains the actual policy and its SHA-256 alongside results. Hosts can choose another explicit policy; a refusal never silently drops rows or changes a grade.

Before each child, the reader reserves input, file slots, a bounded normal response and its receipt. Native stdout and stderr share the output and retained-byte budgets. Both streams go straight to retained files through bounded chunks. A complete oversized response retains its original bytes and actual exit before protocol refusal. A host-budget excess stops only the new child process group, retains the observed prefix, waits for its actual exit and marks output incomplete. That record makes no semantic native-verdict or complete-output claim. The receipt reserves space before payload writes. Native safe-integer exponent serialization can expand `1e15` to sixteen digits; the response reservation accounts for this expansion before hex encoding. The unchanged one-document native interfaces remain in use; this profile adds no batch protocol.

## Facts and limits

The consumer independently projects the manifest's finite v2 fields from the admitted events. Boolean values cannot replace numbers. Root timestamps must be null or strings; their shape does not authenticate a clock. A summary decision must bind an actual decision and its enclosing path. Both selected revoked decisions must share one actual agent. Each cascade key must match that agent. A cascade row without a selected decision cannot establish the key's identity. Named acceptance/refusal slots must match the actual literal outcome; null slots stay unknown. A decision-log identity must be unique and bind the same outcome. A declared ring must match its recorded event. Source/build/service/policy observations stay separate from operator assertions. Policy digests use MintID's stated sorted compact Python JSON format; they do not become JCS digests.

A first `status_root_stale` refusal alone does not establish revocation. The issuer path records the roles `sibling_control` and `sibling_refreshed` separately. Each consumed decision must match its actual recorded role. Those names do not authenticate shared credential identity. Witness refresh observations keep `refused`, `not_refused_within_budget` and `not_recorded` distinct. An original absent cascade refresh stays absent. Without either selected revoked decision, the actor, attributed refresh and legacy refresh refusal offset stay unknown. An anonymous holder or another named holder cannot identify that missing subject.

Authored outage controls keep unavailable challenges separate from decisions. Each selected challenge must bind the enclosing outage path. Generic decisions during an outage retain their actual outcomes. A named acceptance after restoration needs an actual acceptance. The three original bundles contain no outage workload. Root fields declared in the JSONL summary do not establish independent chain observations. Recorded wall clocks and relative offsets do not establish an external time anchor.

Markdown never enters the JSON parser or canonicalizer. Its original hash, raw-event filename, chain label and authority narrative disclosures are checked separately. The consumer does not grade all prose or authenticate its narrative identity claims.

## Qualification and retention

`qualify.py` runs the unchanged Cargo and Go checks, builds one wheel, and imports it outside the checkout. It compares each installed module byte-for-byte with selected source. It retains actual runtime probes, wheel and executable hashes, all three original results, 89 actual test outcomes, original member bytes and each native admission call's input/output/exit.

The first control run had two wrong expectations about I-JSON refusal ordering. Its full failed capture remains preserved separately. The correction changes the expected native class, without rewriting the native outcome.

These are author-operated technical checks. A maintained outside job needs the host's selected source pin and actual execution. Required merge enforcement, an outside operator, independent custody, chain/proof validation and external action effects need their own evidence. This profile creates no registry release or host acceptance.

Controls MTRV2-039 through MTRV2-060 cover FIFO refusal, small reads, retained complete/partial native output, root and height types, agent attribution, host resource policies, dense invalid rows and actual native exponent expansion. Every mutated control fixture remains in its capture with no-follow type/link/absence facts; refused links and FIFOs are not read.

Controls MTRV2-061 through MTRV2-074 cover cascade key/decision contradictions, enclosing paths, distinct issuer control roles, unresolved cascade identities and timestamp shapes. Actual original-derived controls retain raw admission before semantic refusal. Null and fractional timestamp strings remain supported. Earlier installed-reader captures that accepted a false cascade label and boolean timestamp remain separate original failure evidence; passing earlier controls does not cover these cases.

Controls MTRV2-075 through MTRV2-081 cover the same agent across a revoked history, literal outcomes in named summary roles and an outage challenge's enclosing path. A positive authored control retains an actual refusal during an outage and leaves acceptance after restoration unknown. Earlier source captures remain scoped to their original cases.

Controls MTRV2-082 through MTRV2-086 cover nullable exact-string shapes for consumed decision, start, selected refresh and outage UTC timestamps. This is the finite consumer's shape policy; it does not impose a universal upstream date format. Null stays unknown, strings retain their original text, and relative clocks retain their separate numeric checks. The reader does not parse a calendar or authenticate a time anchor.

The receipt reservation includes the actual label and worst-case count/exit metadata before work. A failed executable spawn retains its actual error class and errno with `native_started: false` and `native_exit: null`; it does not invent a native exit. JSONL framing removes only the line delimiter and preserves other original whitespace in each admitted input.

Controls MTRV2-087 through MTRV2-089 preserve legitimate null selections with absent, null and named holder-refresh actors. All three raw-admitted records keep the selected actor, refresh and legacy refusal offset unknown. The original events remain retained; they do not identify an unselected subject. Earlier installed-reader failure and 86-control matrix captures keep their original scope.
