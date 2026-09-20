#!/usr/bin/env python3
"""Spec/corpus non-drift gate.

The vendored predicate spec (``spec/predicates/adversarial-execution-evidence.md``)
is the authority the conformance corpus certifies against. ``gen_manifest.py``
records its SHA-256 in ``vectors/MANIFEST.json`` (``specDigest``) at every
regeneration. This gate recomputes that digest and fails closed if the vendored
spec has changed without a corpus regeneration, so spec/corpus drift cannot land
silently.

Discipline it enforces: edit the spec -> regenerate the vectors -> regenerate
the manifest (which re-pins ``specDigest``) -> bump ``suiteRevision``. Skipping
the regeneration trips this gate.

Usage: python3 scripts/spec-drift-gate.py
Exit 0 when the recorded digest matches the vendored spec; 1 on drift.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spec_anchors as sa  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"
PIN = REPO_ROOT / "spec" / "VENDOR-PIN.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    recorded = manifest.get("specDigest")
    spec_rel = manifest.get("specPath")
    if not recorded or not spec_rel:
        print(
            "FAIL: MANIFEST.json is missing specDigest/specPath; "
            "regenerate it with python3 vectors/gen_manifest.py",
            file=sys.stderr,
        )
        return 1

    spec_path = REPO_ROOT / spec_rel
    if not spec_path.is_file():
        print(f"FAIL: vendored spec not found at {spec_rel}", file=sys.stderr)
        return 1

    actual = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    if actual != recorded:
        print(
            "FAIL: spec/corpus drift.\n"
            f"  vendored spec:   {spec_rel}\n"
            f"  recorded digest: {recorded}\n"
            f"  actual digest:   {actual}\n"
            "The vendored spec changed without a corpus regeneration. Run the "
            "vector generators + python3 vectors/gen_manifest.py and bump "
            "suiteRevision, then commit the regenerated corpus.",
            file=sys.stderr,
        )
        return 1

    # The provenance half of the same question. MANIFEST.specDigest says the
    # corpus was regenerated against these bytes; VENDOR-PIN.json says which
    # upstream commit these bytes came from. Both must agree with what is on
    # disk, because an outside implementer diffs the vendored copy against the
    # pinned commit to certify no version skew, and a pin naming the wrong
    # commit reports a drift that does not exist or hides one that does.
    if not PIN.is_file():
        print(
            f"FAIL: {PIN.relative_to(REPO_ROOT)} is missing; re-vendor with "
            "python3 scripts/vendor-spec.py --from <attestation checkout>",
            file=sys.stderr,
        )
        return 1
    pin = json.loads(PIN.read_text(encoding="utf-8"))
    if pin.get("specDigest") != actual:
        print(
            "FAIL: vendor pin does not describe the vendored bytes.\n"
            f"  pinned commit:  {pin.get('commit')}\n"
            f"  pinned digest:  {pin.get('specDigest')}\n"
            f"  actual digest:  {actual}\n"
            "The vendored spec was edited in place instead of re-vendored. Edit "
            "the spec upstream, then run scripts/vendor-spec.py so the pin names "
            "a commit that actually contains these bytes.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: vendored spec matches MANIFEST specDigest ({recorded[:12]}...) "
        f"and VENDOR-PIN commit {str(pin.get('commit'))[:12]}."
    )

    return check_citations()


def check_citations() -> int:
    """The half that makes a citation survive an edit to the text it names.

    The whole-file digest above answers "did these bytes change". It cannot
    answer "did the sentence my code cites change", and it fires on every
    reflow, which is why editing the spec has always cost a corpus
    regeneration. This half answers the sharper question: every anchor named by
    the source is resolved in the file that holds it, the text it covers is
    re-digested, and a mismatch fails closed.

    Four ways to fail, and each is named rather than rolled up, because a
    reader told only "drift" cannot tell a reworded requirement from a deleted
    anchor:

      MISSING-FROM-MANIFEST  the source cites an anchor CITATION-ANCHORS.json
                             does not record
      FILE-ABSENT            the manifest names a file that is not on disk
      ANCHOR-ABSENT          the file does not carry the anchor
      DIGEST-CHANGED         the anchor is there and the text under it moved

    A COULD-NOT-MEASURE IS NEVER A PASS. An absent file and an absent anchor
    are failures here, not skips: a citation whose target cannot be read is
    unresolved, and unresolved has to look different from clean.
    """
    problems: list[str] = []
    try:
        manifest = sa.load_manifest(REPO_ROOT)
    except FileNotFoundError:
        print(
            f"FAIL: {sa.MANIFEST_REL} is missing; regenerate it with "
            "python3 scripts/gen_spec_anchors.py --apply",
            file=sys.stderr,
        )
        return 1
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    # 1. every recorded anchor still resolves to the text it recorded
    recomputed: dict[str, str] = {}
    cache: dict[str, list[str]] = {}
    for aid, rec in sorted(manifest.items()):
        path = REPO_ROOT / rec.file
        if rec.file not in cache:
            if not path.is_file():
                problems.append(f"FILE-ABSENT      {aid}: {rec.file} is not on disk")
                cache[rec.file] = []
                continue
            cache[rec.file] = path.read_text(encoding="utf-8").split("\n")
        lines = cache[rec.file]
        if not lines:
            problems.append(f"FILE-ABSENT      {aid}: {rec.file} is not on disk")
            continue
        i = sa.find_anchor(lines, aid)
        if i is None:
            problems.append(
                f"ANCHOR-ABSENT    {aid}: {rec.file} carries no <a id=\"{aid}\"></a>"
            )
            continue
        text = sa.anchored_text(lines, i, rec.blocks)
        if text is None:
            problems.append(
                f"ANCHOR-ABSENT    {aid}: fewer than {rec.blocks} block(s) follow it in {rec.file}"
            )
            continue
        got = sa.digest(text)
        recomputed[aid] = got
        if got != rec.sha256:
            problems.append(
                f"DIGEST-CHANGED   {aid}: {rec.file} recomputes {got[:16]}, "
                f"manifest records {rec.sha256[:16]}\n"
                f"                   recorded text was: {rec.excerpt}\n"
                f"                   text there now is: {sa.excerpt_of(text)}"
            )

    # 2. every citation in the source names a recorded anchor and a live digest
    cited = 0
    for f in sa.source_files(REPO_ROOT):
        txt = f.read_text(encoding="utf-8")
        rel = str(f.relative_to(REPO_ROOT))
        for m in sa.LEGACY_CITATION_RE.finditer(txt):
            problems.append(f"LINE-NUMBER      {rel}: {m.group(0)} -- migrate it to an anchor")
        for m in sa.ORPHAN_TAIL_RE.finditer(txt):
            problems.append(
                f"LINE-NUMBER      {rel}: orphaned line numbers trail a migrated citation"
                f" ({m.group(0)[-22:]})"
            )
        for m in sa.CITATION_RE.finditer(txt):
            for aid, prefix in sa.parse_citation(m.group("body")):
                cited += 1
                if aid not in manifest:
                    problems.append(f"MISSING-FROM-MANIFEST {rel}: {aid}")
                    continue
                live = recomputed.get(aid)
                if live is None:
                    continue  # already reported against the anchor itself
                if not live.startswith(prefix):
                    problems.append(
                        f"DIGEST-CHANGED   {rel}: cites {aid}@{prefix} but that anchor "
                        f"now digests to {live[: sa.INLINE_PREFIX_LEN]}"
                    )

    if problems:
        print(
            f"FAIL: {len(problems)} citation problem(s). A citation names a sentence, "
            "so a sentence that changed under it is a real failure and not a lint:",
            file=sys.stderr,
        )
        for line in problems:
            print("  " + line, file=sys.stderr)
        print(
            "\nTo repair: if the specification text changed on purpose, re-run "
            "python3 scripts/gen_spec_anchors.py --apply so the manifest and every "
            "inline digest name the new text, and read the diff to confirm the code "
            "under each changed citation is still correct.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {cited} citation(s) resolve against {len(manifest)} anchor(s); "
        "every anchor is present and its text digests to the recorded value."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
