# APS raw admission and receipt comparison

Node 20.20.2 and 22.23.3 each ran the same 1,223 pinned cases. jcs-admit matched
all 1,048 declared byte accepts and 175 refusals. APS's parsed serializer accepted
42 raw-refusal rows; its strict parser differed on 23 policy rows. Those rows
include numeric and Unicode profile differences, so they are kept individually.

Five signed receipt controls keep raw admission, receipt identity, stage and
signature results separate. Both duplicate-issuer variants stopped before
signature checks; parsing those inputs first erased the duplicate evidence and
the resulting objects verified. Machine outcomes agree across runtimes; 88
SyntaxError messages differ in prose.

```sh
python3 experiments/aps-jcs-2026-10-04/validate_capsule.py
```

[Report](report.json), [provenance](provenance.json), [source lock](source-lock.json),
[Node 20 original](original-node20.zip), [Node 22 original](original-node22.zip)
and [selected licensed source](selected-source.zip).

The [pinned adapter and replay commands](https://github.com/probityai/agent-evidence-vectors/blob/fa3e6705746e0131a7884591a86e5c05b6c050ab/interop/aps-jcs/README.md)
name APS `646490a` and jcs-admit `ecc8b5e`. Source and native output capsules are
separate. Registry dependencies restore from the retained integrity lockfiles;
Node and Rust runtimes are outside the capsules. These are author-operated
conformance runs. The separately proposed APS test dependency and its maintainer
approval remain separate from these measured results.
