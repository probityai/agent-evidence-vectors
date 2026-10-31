#!/usr/bin/env python3
"""Write data/open-cells.toml from an atlas cell export, keeping only cells whose source is confirmed.

    python3 tools/export_open_cells.py CELLS.json PROPERTIES.json MECHANISMS.json
    python3 tools/export_open_cells.py CELLS.json PROPERTIES.json MECHANISMS.json --verify

An open cell is a mechanism and a property where the mechanism's own documentation, or the
document that defines it, says the mechanism cannot establish the property. The inputs are
the atlas cell export: CELLS.json is a list of {mechanism, property, words, url},
PROPERTIES.json a list of {id, title, question}, MECHANISMS.json a list of {id, title}.

A cell is written only when EVIDENCE below names a short excerpt that appears verbatim on
its source page, and a basis: "states the limit" when the page says the limit itself, or
"states the scope" when the page states the function the limit bounds. A cell with no
excerpt is left out and printed with its reason from LEFT_OUT. With --verify, every source
is fetched and every excerpt must be found in it (whitespace collapsed), or nothing is
written. The words and the source URL are copied exactly as the export gives them.
"""

from __future__ import annotations

import html
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "open-cells.toml"
UA = "Mozilla/5.0 (compatible; atlas-open-cells)"

STATES, SCOPE = "states the limit", "states the scope"

# (mechanism, property) -> (basis, excerpt found verbatim on the source page)
EVIDENCE: dict[tuple[str, str], tuple[str, str]] = {
    ("mech:hash-chained-audit-log", "prop:effect"): (STATES, "Audit Logs Record Attempts, Not Outcomes"),
    ("mech:in-process-interception-hook", "prop:effect"): (STATES, "verify whether the action actually succeeded in the external world"),
    ("mech:kernel-event-sensor", "prop:effect"): (SCOPE, "Tetragon is able to observe critical hooks in the kernel through its sensors"),
    ("mech:oauth-delegation", "prop:effect"): (SCOPE, "a new token that is appropriate to include in a call to a backend service"),
    ("mech:policy-decision-point", "prop:effect"): (SCOPE, "The policy decision is sent back as the result of the query"),
    ("mech:gateway-mediation", "prop:event-completeness"): (STATES, "states what it does not prove: whether anything happened outside the boundary Pipelock mediates"),
    ("mech:in-process-interception-hook", "prop:event-completeness"): (STATES, "the eight interception points do not guarantee complete mediation"),
    ("mech:incident-reporting-regime", "prop:event-completeness"): (STATES, "after the provider has established a causal link between the AI system and the serious incident"),
    ("mech:policy-decision-point", "prop:event-completeness"): (SCOPE, "Services integrate with OPA by executing _queries_ when policy decisions are needed"),
    ("mech:scitt-receipt", "prop:event-completeness"): (STATES, "selectively submit some but not all the Statements they issue"),
    ("mech:self-emitted-event-log", "prop:event-completeness"): (STATES, "logging capabilities shall enable the recording of events relevant for"),
    ("mech:supervisor-audit-merkle-root", "prop:event-completeness"): (STATES, "5. Fast-path: if path is in initial set, open + inject fd immediately"),
    ("mech:benchmark-evaluation", "prop:occurrence"): (STATES, "intended to support inspection of evidence, not to certify models or providers"),
    ("mech:canonical-json-signature", "prop:occurrence"): (STATES, "can produce a valid-looking Level 0 record for a run that never happened"),
    ("mech:dsse-signature", "prop:occurrence"): (SCOPE, "Simple, foolproof standard for signing arbitrary data"),
    ("mech:proof-of-possession-binding", "prop:occurrence"): (SCOPE, "enables a client to prove the possession of a public/"),
    ("mech:scitt-receipt", "prop:occurrence"): (STATES, "registering a Statement only proves it was produced by an Issuer"),
    ("mech:tee-remote-attestation", "prop:occurrence"): (STATES, "Hardware attestation proves the TRACE signing key and policy engine were measured in silicon before execution"),
    ("mech:transparency-log", "prop:occurrence"): (SCOPE, "provide an immutable tamper resistant ledger of metadata"),
    ("mech:workload-identity-credential", "prop:occurrence"): (SCOPE, "a framework and set of standards for identifying and securing communications between application services"),
    ("mech:scitt-receipt", "prop:ordering"): (STATES, "cannot assume that the ordering of Signed Statements in the VDS matches the ordering of their issuance"),
    ("mech:cot-monitoring", "prop:reasoning-fidelity"): (STATES, "Companies with closed source models do not typically disclose"),
    ("mech:transcript-review", "prop:reasoning-fidelity"): (STATES, "instead of the summaries that AISI receives from the model API"),
    ("mech:application-kernel-trace-stream", "prop:vantage-independence"): (STATES, "the monitoring process must validate and never trust input received from the Sentry"),
    ("mech:in-process-interception-hook", "prop:vantage-independence"): (STATES, "interceptors run in-process with full data access"),
    ("mech:self-emitted-event-log", "prop:vantage-independence"): (SCOPE, "High-risk AI systems shall technically allow for the automatic recording of events (logs)"),
    ("mech:probabilistic-guardrail-classifier", "prop:authorization"): (SCOPE, "model-layer defenses are probabilistic by construction"),
    ("mech:synchronous-llm-monitor", "prop:authorization"): (SCOPE, "block those that cross your risk threshold"),
    ("mech:self-declared-conformance", "prop:reader-agreement"): (STATES, "Who verifies a conformance claim: nobody, in v0.1.0"),
}

# Cells of the export that are not written, with the reason, checked against the sources on 2026-10-13.
LEFT_OUT: dict[tuple[str, str], str] = {
    ("mech:dsse-signature", "prop:event-completeness"): "the README does not say how an unsigned event or its absence is recorded",
    ("mech:hash-chained-audit-log", "prop:event-completeness"): "the directory page does not state the truncation result the words describe",
    ("mech:otel-span-emission", "prop:event-completeness"): "the README does not mention sampling or missing spans",
    ("mech:parent-process-tracer", "prop:event-completeness"): "the file handles execve and openat only, but says nothing of an eBPF ring buffer",
    ("mech:content-credential-manifest", "prop:occurrence"): "the README only points to the published specification",
    ("mech:microvm-isolation", "prop:occurrence"): "the README does not say what Firecracker records",
    ("mech:tpm-ima-measurement", "prop:occurrence"): "the file does not mention IMA or measurement",
    ("mech:hash-chained-audit-log", "prop:vantage-independence"): "the AGT page confirms local-only anchoring, but the ACS half is not on it",
    ("mech:otel-span-emission", "prop:vantage-independence"): "the README does not say which process writes spans",
    ("mech:parent-process-tracer", "prop:workload-unforgeability"): "the file does not show the signer's uid or the child's environment",
    ("mech:otel-span-emission", "prop:integrity"): "the README does not mention signatures",
    ("mech:w3c-trace-context-propagation", "prop:integrity"): "the README does not describe the traceparent header",
}

# The cells to start first, in order, with what a passing case would show. A start entry must
# name a written cell. The hash-chained audit log x event completeness cell was chosen for this
# list but is left out above until its source is confirmed.
START: list[tuple[str, str, str]] = [
    ("mech:policy-decision-point", "prop:effect",
     "a passing case binds an allow decision to an effect observed from a vantage the decider does not control"),
    ("mech:canonical-json-signature", "prop:occurrence",
     "a passing case refuses a well-signed record with no independent observation of the run"),
]


def toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def fetch_text(url: str) -> str:
    raw = url
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/blob/([0-9a-f]+)/(.+)", url)
    if m:
        raw = f"https://raw.githubusercontent.com/{m[1]}/{m[2]}/{m[3]}"
    headers = {"User-Agent": UA}
    if "publications.europa.eu" in url:
        headers |= {"Accept": "application/xhtml+xml", "Accept-Language": "eng"}
    with urllib.request.urlopen(urllib.request.Request(raw, headers=headers), timeout=120) as resp:
        body = resp.read()
    if body[:5] == b"%PDF-":
        with tempfile.TemporaryDirectory() as tmp:
            pdf = Path(tmp) / "source.pdf"
            pdf.write_bytes(body)
            text = subprocess.run(["pdftotext", str(pdf), "-"], capture_output=True, check=True).stdout.decode("utf-8", "replace")
    else:
        text = body.decode("utf-8", "replace")
        if "<html" in text[:4096].lower():
            text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
            text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return re.sub(r"\s+", " ", text)


def build(cells: list[dict], props: dict[str, dict], mechs: dict[str, dict]) -> tuple[str, list[str]]:
    keys = [(c["mechanism"], c["property"]) for c in cells]
    if len(set(keys)) != len(keys):
        raise SystemExit("duplicate cell in the export")
    unknown = (set(EVIDENCE) | set(LEFT_OUT)) - set(keys)
    if unknown or set(EVIDENCE) & set(LEFT_OUT):
        raise SystemExit(f"evidence table names cells the export does not hold: {sorted(unknown)}")
    out = [
        "# GENERATED by tools/export_open_cells.py from the atlas cell export; rerun it, do not edit by hand.",
        "# One entry per open cell whose source page was confirmed: the words and URL are copied",
        "# exactly; `excerpt` is found verbatim on the source page, and `basis` says whether the page",
        "# states the limit itself or states the scope the limit bounds.",
        "",
    ]
    left = []
    for c, key in zip(cells, keys):
        if key not in EVIDENCE:
            left.append(f"{key[0]} x {key[1]}: {LEFT_OUT.get(key, 'no confirmed excerpt')} ({c['url']})")
            continue
        basis, excerpt = EVIDENCE[key]
        m, p = mechs[key[0]], props[key[1]]
        out += [
            "[[cell]]",
            f"mechanism = {toml_str(m['id'])}",
            f"mechanism_title = {toml_str(m['title'])}",
            f"property = {toml_str(p['id'])}",
            f"property_title = {toml_str(p['title'])}",
            f"property_question = {toml_str(p['question'])}",
            f"words = {toml_str(c['words'])}",
            f"url = {toml_str(c['url'])}",
            f"basis = {toml_str(basis)}",
            f"excerpt = {toml_str(excerpt)}",
            "",
        ]
    for rank, (mech, prop, passing) in enumerate(START, 1):
        if (mech, prop) not in EVIDENCE:
            raise SystemExit(f"start cell {mech} x {prop} is not written")
        out += ["[[start]]", f"rank = {rank}", f"mechanism = {toml_str(mech)}",
                f"property = {toml_str(prop)}", f"passing_case = {toml_str(passing)}", ""]
    return "\n".join(out), left


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 3:
        print(__doc__)
        return 2
    cells = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    props = {p["id"]: p for p in json.loads(Path(args[1]).read_text(encoding="utf-8"))}
    mechs = {m["id"]: m for m in json.loads(Path(args[2]).read_text(encoding="utf-8"))}
    text, left = build(cells, props, mechs)
    if "--verify" in argv:
        pages: dict[str, str] = {}
        missing = []
        for c in cells:
            key = (c["mechanism"], c["property"])
            if key not in EVIDENCE:
                continue
            if c["url"] not in pages:
                pages[c["url"]] = fetch_text(c["url"])
            if EVIDENCE[key][1] not in pages[c["url"]]:
                missing.append(f"{key[0]} x {key[1]}: excerpt not found at {c['url']}")
        if missing:
            print("\n".join(missing))
            return 1
        print(f"verified {len(EVIDENCE)} excerpts against {len(pages)} source pages")
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(EVIDENCE)} cells; left out {len(left)}:")
    for line in left:
        print("  " + line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
