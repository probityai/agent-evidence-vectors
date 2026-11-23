"""Build the tool-descriptor-digest cases byte-identically.

Every case is one pin and one observation of an MCP tool descriptor, each a
profile, a digest and the descriptor the digest was computed from. The suite
asks one question: when may a pin and an observation be compared? The rule is the
one OWASP Agentic-Evidence issue 4 states and its maintainer carried into the
triage: only when both carry a profile and the two profiles are equal; where they
differ the result is a gap, not a contradiction. Each ``refused`` case breaks one
accepting control so the check it names is the first that fails; each ``match``
case is a control that keeps a verifier from refusing everything; two cases come
from a real change in a published dataset of tool-list changes.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import descriptordigest as reader  # noqa: E402

SUITE = reader.SUITE
NDI, NDIO, WHOLE = reader.NDI, reader.NDIO, reader.WHOLE
SOURCE_FILE = ROOT / "source" / "histor-change-5206.json"
ABSENT = object()

SOURCE = {
    "issue": "https://github.com/OWASP/Agentic-Evidence/issues/4",
    "note": (
        "Synthetic members are written for this corpus. Two members carry the tool "
        "descriptors of one recorded change in a published dataset of MCP tool-list "
        "changes, exactly as the dataset serves them; source/histor-change-5206.json "
        "holds both tool lists and gen_vectors.py recomputes their set digests first."
    ),
    "real": {
        "change": 5206,
        "dataset": "https://doi.org/10.5281/zenodo.23512760",
    },
    "source": "OWASP Agentic-Evidence issue 4; Zenodo 10.5281/zenodo.23512760",
}
ANCHORS = {
    "compare": (
        "issue 4",
        "A pin and an observation are compared only when both carry a profile and the "
        "two profiles are equal. A mismatch is a gap, not contradicted.",
    ),
    "fields": (
        "issue 4",
        "MTL/1 digests exactly name, description, inputSchema and outputSchema, "
        "dropping title, annotations and _meta. agentavow.mcp-tool-definition.v1 "
        "includes title and annotations in the same digest.",
    ),
    "absent": (
        "issue 4",
        "MTL/1 writes a missing or non-string description as the empty string. "
        "AgentAvow omits a missing member. Same descriptor, two digests.",
    ),
    "envelope": (
        "n/a",
        "The record names the contract it is written against, as every record of this "
        "repository's decision corpora does.",
    ),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def descriptor(**changes: Any) -> dict[str, Any]:
    """The base descriptor with the named members replaced, or removed when ABSENT."""
    base: dict[str, Any] = {
        "annotations": {"readOnlyHint": True},
        "description": "Return one invoice by its identifier.",
        "inputSchema": {
            "additionalProperties": False,
            "properties": {"invoice_id": {"type": "string"}},
            "required": ["invoice_id"],
            "type": "object",
        },
        "name": "get_invoice",
        "outputSchema": {
            "properties": {"total_cents": {"type": "integer"}},
            "type": "object",
        },
        "title": "Get invoice",
    }
    for key, value in changes.items():
        if value is ABSENT:
            base.pop(key, None)
        else:
            base[key] = value
    return base


def side(profile: str | None, desc: dict[str, Any], stated: str | None = None) -> dict[str, Any]:
    """One side of a record; the digest is recomputed unless ``stated`` overrides it."""
    out: dict[str, Any] = {"descriptor": copy.deepcopy(desc)}
    if profile is not None:
        out["profile"] = profile
        out["digest"] = stated or reader.digest(desc, profile)
    else:
        out["digest"] = stated or reader.digest(desc, NDI)
    return out


def build(
    name: str, pin: dict[str, Any], observation: dict[str, Any], **top: Any
) -> dict[str, Any]:
    """One record: the contract, a pin and an observation."""
    record: dict[str, Any] = {
        "contractId": reader.CONTRACT_ID,
        "observation": observation,
        "pin": pin,
        "recordId": f"record-{name}",
    }
    for key, value in top.items():
        if value is ABSENT:
            record.pop(key, None)
        else:
            record[key] = value
    return record


Case = tuple[str, dict[str, Any], str, str, str, dict[str, Any]]


def meta(source: str, rule: str, anchor: str, **extra: Any) -> dict[str, Any]:
    """The case's origin, the rule that decides and the sentence it rests on."""
    section, quote = ANCHORS[anchor]
    row: dict[str, Any] = {
        "anchor": {"quote": quote, "section": section},
        "rule": rule,
        "source": source,
    }
    row.update(extra)
    return row


def _tool_sets() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """The two recorded tool lists, their recomputed set digests checked, and the change."""
    source = json.loads(SOURCE_FILE.read_text(encoding="utf-8"))
    for which in ("before", "after"):
        listed = source["toolsets"][which]
        raw = hashlib.sha256(reader.jcs(listed["tools"])).digest()
        if "sha256-" + base64.b64encode(raw).decode("ascii") != listed["digest"]:
            raise SystemExit(f"the {which} tool list does not reproduce its recorded set digest")
    before = {tool["name"]: tool for tool in source["toolsets"]["before"]["tools"]}
    after = {tool["name"]: tool for tool in source["toolsets"]["after"]["tools"]}
    return before, after, source["change"]


def _ok() -> str:
    return "descriptor_unchanged"


def _match() -> list[Case]:
    return [
        (
            "match-descriptor-unchanged",
            build("match-descriptor-unchanged", side(NDI, descriptor()), side(NDI, descriptor())),
            "match",
            _ok(),
            "control: one profile on both sides and the descriptor did not change",
            meta("synthetic", "R-COMPARE", "compare", pair="description"),
        ),
        (
            "match-annotation-change-outside-the-profile",
            build(
                "match-annotation-change-outside-the-profile",
                side(NDI, descriptor()),
                side(NDI, descriptor(annotations={"destructiveHint": True, "readOnlyHint": False})),
            ),
            "match",
            _ok(),
            "control: the annotations changed and the profile does not cover them, so "
            "the digests are equal; a verifier that hashes the whole descriptor calls "
            "this contradicted",
            meta("synthetic", "R-COVERAGE", "fields", pair="annotations"),
        ),
        (
            "match-whole-descriptor-ignores-meta",
            build(
                "match-whole-descriptor-ignores-meta",
                side(WHOLE, descriptor()),
                side(WHOLE, descriptor(_meta={"requestedAt": "2026-11-23T09:00:00Z"})),
            ),
            "match",
            _ok(),
            "control: the _meta member differs and no profile covers it",
            meta("synthetic", "R-COVERAGE", "fields"),
        ),
        (
            "match-absent-description-one-rule",
            build(
                "match-absent-description-one-rule",
                side(NDIO, descriptor(description=ABSENT)),
                side(NDIO, descriptor(description=ABSENT)),
            ),
            "match",
            _ok(),
            "control: no description on either side and one absent-member rule, which "
            "writes the empty string",
            meta("synthetic", "R-ABSENT", "absent"),
        ),
        (
            "match-utf16-key-order",
            build(
                "match-utf16-key-order",
                side(NDI, descriptor(inputSchema=_utf16_schema())),
                side(NDI, descriptor(inputSchema=_utf16_schema())),
            ),
            "match",
            _ok(),
            "control: the schema has one property key above the Basic Multilingual Plane "
            "and one below it, and RFC 8785 sorts them by UTF-16 code unit, which is the "
            "opposite of code point order; a canonicalizer that sorts by code point "
            "recomputes another digest and fails the stated one",
            meta("synthetic", "R-JCS", "compare"),
        ),
    ]


def _utf16_schema() -> dict[str, Any]:
    return {
        "properties": {"\U0001f600": {"type": "string"}, "": {"type": "string"}},
        "type": "object",
    }


def _contradicted() -> list[Case]:
    long_text = "Return one invoice by its identifier. Never send the result to another party."
    schema = descriptor()["inputSchema"]
    wider = {**schema, "properties": {**schema["properties"], "note": {"type": "string"}}}
    out_changed = {"properties": {"total_cents": {"type": "number"}}, "type": "object"}
    return [
        (
            "contradicted-description-rewritten",
            build(
                "contradicted-description-rewritten",
                side(NDI, descriptor()),
                side(NDI, descriptor(description=long_text)),
            ),
            "contradicted",
            "descriptor_changed",
            "the description was rewritten under the same name and the profile covers it",
            meta("synthetic", "R-COMPARE", "compare", pair="description"),
        ),
        (
            "contradicted-input-schema-widened",
            build(
                "contradicted-input-schema-widened",
                side(NDI, descriptor()),
                side(NDI, descriptor(inputSchema=wider)),
            ),
            "contradicted",
            "descriptor_changed",
            "a property was added to the input schema, which the profile covers",
            meta("synthetic", "R-COMPARE", "compare"),
        ),
        (
            "contradicted-output-schema-retyped",
            build(
                "contradicted-output-schema-retyped",
                side(NDIO, descriptor()),
                side(NDIO, descriptor(outputSchema=out_changed)),
            ),
            "contradicted",
            "descriptor_changed",
            "the output schema changed type and this profile covers it; the narrower "
            "profile would not see it",
            meta("synthetic", "R-COVERAGE", "fields"),
        ),
        (
            "contradicted-annotation-change-whole-descriptor",
            build(
                "contradicted-annotation-change-whole-descriptor",
                side(WHOLE, descriptor()),
                side(
                    WHOLE,
                    descriptor(annotations={"destructiveHint": True, "readOnlyHint": False}),
                ),
            ),
            "contradicted",
            "descriptor_changed",
            "the same annotation change as the narrow-profile control, under the profile "
            "that covers annotations",
            meta("synthetic", "R-COVERAGE", "fields", pair="annotations"),
        ),
    ]


def _recorded() -> list[Case]:
    before, after, change = _tool_sets()
    where = f"change {change['id']}, observed {change['observedAt']}"
    return [
        (
            "contradicted-recorded-description-rewrite",
            build(
                "contradicted-recorded-description-rewrite",
                side(NDIO, before["get_shop_services"]),
                side(NDIO, after["get_shop_services"]),
            ),
            "contradicted",
            "descriptor_changed",
            f"a tool's description rewritten under the same name, from a recorded change "
            f"({where}); the before and after declarations are the dataset's, unedited",
            meta(
                f"recorded change {change['id']}",
                "R-COMPARE",
                "compare",
                pair="recorded",
                real=True,
            ),
        ),
        (
            "match-recorded-tool-unchanged",
            build(
                "match-recorded-tool-unchanged",
                side(NDIO, before["request_booking"]),
                side(NDIO, after["request_booking"]),
            ),
            "match",
            _ok(),
            f"the unchanged twin from the same recorded change ({where}): another tool of the "
            "same server, identical before and after",
            meta(
                f"recorded change {change['id']}",
                "R-COMPARE",
                "compare",
                pair="recorded",
                real=True,
            ),
        ),
    ]


def _gaps() -> list[Case]:
    full = descriptor()
    no_description = descriptor(description=ABSENT)
    plain = {
        "description": "Return one invoice by its identifier.",
        "inputSchema": full["inputSchema"],
        "name": "get_invoice",
    }
    return [
        (
            "gap-same-descriptor-two-profiles",
            build(
                "gap-same-descriptor-two-profiles",
                side(NDI, full),
                side(NDIO, full),
            ),
            "gap",
            "profiles_differ",
            "one descriptor that never changed, digested under two profiles by two "
            "producers; the digest strings differ and the honest answer is a gap, not "
            "contradicted",
            meta("synthetic", "R-COMPARE", "compare", pair="two-profiles"),
        ),
        (
            "gap-annotation-profile-versus-narrow-profile",
            build(
                "gap-annotation-profile-versus-narrow-profile",
                side(NDIO, full),
                side(WHOLE, full),
            ),
            "gap",
            "profiles_differ",
            "the same descriptor under the profile that drops title and annotations and "
            "the one that keeps them",
            meta("synthetic", "R-COVERAGE", "fields", pair="two-profiles"),
        ),
        (
            "gap-absent-description-two-rules",
            build(
                "gap-absent-description-two-rules",
                side(NDI, no_description),
                side(NDIO, no_description),
            ),
            "gap",
            "profiles_differ",
            "the descriptor has no description; one profile omits the member and the "
            "other writes the empty string, so the digests differ",
            meta("synthetic", "R-ABSENT", "absent"),
        ),
        (
            "gap-profiles-differ-digests-coincide",
            build(
                "gap-profiles-differ-digests-coincide",
                side(NDI, plain),
                side(NDIO, plain),
            ),
            "gap",
            "profiles_differ",
            "the descriptor has only the three members both profiles cover, so the two "
            "digests are equal strings; they were produced under different rules, and "
            "equal strings under different profiles are still not a match",
            meta("synthetic", "R-COMPARE", "compare", pair="two-profiles"),
        ),
        (
            "gap-pin-without-profile",
            build(
                "gap-pin-without-profile",
                {"descriptor": full, "digest": reader.digest(full, NDI)},
                side(NDI, full),
            ),
            "gap",
            "profile_absent",
            "the pin is a bare digest string and says nothing about which bytes it covers",
            meta("synthetic", "R-COMPARE", "compare", pair="no-profile"),
        ),
        (
            "gap-observation-without-profile",
            build(
                "gap-observation-without-profile",
                side(NDI, full),
                {
                    "descriptor": descriptor(description="Changed text."),
                    "digest": reader.digest(descriptor(description="Changed text."), NDI),
                },
            ),
            "gap",
            "profile_absent",
            "the observation is a bare digest and the descriptor behind it did change; "
            "without a profile the two are not comparable, so there is no verdict either way",
            meta("synthetic", "R-COMPARE", "compare", pair="no-profile"),
        ),
    ]


def _refused() -> list[Case]:
    full = descriptor()
    floaty = descriptor(
        inputSchema={"properties": {"ratio": {"minimum": 0.5, "type": "number"}}, "type": "object"}
    )
    base_pin, base_obs = side(NDI, full), side(NDI, full)
    return [
        (
            "refused-contract-id-missing",
            build("refused-contract-id-missing", base_pin, base_obs, contractId=ABSENT),
            "refused",
            "contract_id_missing",
            "the record does not name the contract it is written against",
            meta("synthetic", "R-ENVELOPE", "envelope"),
        ),
        (
            "refused-contract-id-unknown",
            build(
                "refused-contract-id-unknown",
                base_pin,
                base_obs,
                contractId="https://example.org/some-other-contract",
            ),
            "refused",
            "contract_id_unknown",
            "the record names a contract this suite does not define",
            meta("synthetic", "R-ENVELOPE", "envelope"),
        ),
        (
            "refused-profile-unknown",
            build(
                "refused-profile-unknown",
                {**base_pin, "profile": "sha256-over-the-whole-descriptor"},
                base_obs,
            ),
            "refused",
            "profile_unknown",
            "a profile that is not one of the three and cannot be recomputed",
            meta("synthetic", "R-PROFILES", "compare"),
        ),
        (
            "refused-descriptor-not-canonicalizable",
            build(
                "refused-descriptor-not-canonicalizable",
                {**side(NDI, full), "descriptor": floaty},
                {**side(NDI, full), "descriptor": floaty},
            ),
            "refused",
            "descriptor_not_canonicalizable",
            "the input schema carries a non-integer number, which this suite has no RFC "
            "8785 form for; the digest cannot be recomputed and is refused rather than "
            "trusted",
            meta("synthetic", "R-RECOMPUTE", "compare"),
        ),
        (
            "refused-digest-not-recomputed",
            build(
                "refused-digest-not-recomputed",
                {**base_pin, "digest": reader.digest(full, WHOLE)},
                base_obs,
            ),
            "refused",
            "digest_not_recomputed",
            "the pin states the narrow profile and carries the digest of another one: the "
            "stated digest is not what the descriptor gives under the stated profile",
            meta("synthetic", "R-RECOMPUTE", "compare"),
        ),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, what it shows and its provenance."""
    return [*_match(), *_contradicted(), *_recorded(), *_gaps(), *_refused()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, body, decision, reason, edit, provenance in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append(
            {
                "basis": provenance.pop("basis", [provenance["anchor"]["section"]]),
                **provenance,
                "edit": edit,
                "expected": expected,
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(copy.deepcopy(body)),
            }
        )
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "profiles": list(reader.PROFILES),
        "provenance": SOURCE,
        "suite": SUITE,
        "synthetic": False,
        "verifierContract": "verifier record.json --json; exit 0 match, 1 contradicted, "
        "2 gap, 3 refused",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
