"""Measure the verifier isolation family on every rail and refuse a claim the measurement does not support.

    python3 conformance/run_verifier_isolation_conformance.py            # check
    python3 conformance/run_verifier_isolation_conformance.py --write    # rewrite the map
    python3 conformance/run_verifier_isolation_conformance.py --skip-mutations

The family is `registry/verifier-isolation.json`: nine obligations, one per reward-tampering
vector of terminal-bench issue 2086, and the seven hardening steps that issue lists. Three rails
carry it, each held to the one vector file `rego/verifier_isolation_vectors.json`:

* `rego`, the reference: `rego/verifier_isolation.rego`.
* `kyverno-cel`: `kyverno/imagevalidatingpolicy-verifier-isolation.yaml`, run through Kyverno's own
  CEL compiler. Each validation is also run on its own, so the rail returns a refusal reason per
  rule and not only a verdict.
* `cue`: `policy-controller/clusterimagepolicy-verifier-isolation-cue.yaml`, run with `cue vet`
  and, a second time, as policy-controller's evaluator reads it (see below).

An obligation is `enforced` on the rego rail only when all of these hold:

1. The baseline vector admits, so a refusal is not a module that refuses everything.
2. The module answers every vector with exactly the refusal set the vector declares.
3. At least one vector opens the obligation, and the module's answer to it names a `vi-N:` reason.
4. The module has at least one refusal rule for the obligation, and deleting each one in turn
   turns the module's own tests red. A rule no test exercises is found here and named.
5. Every hardening step in the registry is claimed by an obligation, and every step an
   obligation claims is in the registry.
6. The obligations table in docs/VERIFIER-ISOLATION.md lists, for each obligation, exactly the
   refusal reasons the module can return and the hardening steps the registry claims.

On the two engine rails the signature is the engine's to check, so the reference is the rego
module under the pins an engine gives it: the signature declared verified and the contract pin the
vector carries. An obligation is `enforced` on an engine rail when the rail refuses every vector
that opens it, names the same reasons the reference does (CEL), and deleting each of its rules
turns a vector it alone refuses into an admit.

THE CUE GAP, MEASURED. `cue vet` reports a required member that is absent. cosign's evaluator
(`pkg/policy/eval.go`, `evaluateCue`) unifies the policy with the statement and calls `Validate()`
with neither `Final` nor `Concrete`, under which an absent member leaves an incomplete value and
the policy's own constraint fills it. This driver runs every vector a second time with the
required-member markers dropped, which is that reading, and records the vectors the second run
admits that `cue vet` refuses. The family fails closed on a fact that is absent, so a CUE row whose
opening vectors include one of those is `unreachable (absent-member-not-denied)` and never
`enforced`. cosign itself is not executed here, and a failure to prove the gap is a failure of this
run: every vector in the gap must be one that omits a fact the baseline carries.

Anything less is `unreachable` with the obstruction named, never `enforced`. The result is
written to `verifier-isolation/PROFILE-MAP.json`, and without `--write` the committed file must
equal what this run measured. The map lives outside `profiles/` on purpose: `profile-map-gate.py`
reads every map there as a rail over the 93 adversarial-execution-evidence obligations.

Needs `opa`, `kyverno` and `cue` on the path (or OPA_BIN, KYVERNO_BIN, CUE_BIN). Exit 0 when the
claim holds, 1 on a disagreement, 2 when the run could not happen.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import verifier_isolation_rails as rails
from verifier_isolation_rails import CouldNotRun

MODULE = ROOT / "rego" / "verifier_isolation.rego"
TESTS = ROOT / "rego" / "verifier_isolation_test.rego"
VECTORS = ROOT / "rego" / "verifier_isolation_vectors.json"
REGISTRY = ROOT / "registry" / "verifier-isolation.json"
MAP = ROOT / "verifier-isolation" / "PROFILE-MAP.json"
PAGE = ROOT / "docs" / "VERIFIER-ISOLATION.md"

RULE_RE = re.compile(r"^errors contains (?:sprintf\()?\"(?P<reason>[^\"]+)\"[^\n]*\{\n.*?\n\}\n", re.MULTILINE | re.DOTALL)
BASELINE = "baseline-admitted"

# The closed vocabulary a row's obstruction comes from. An open one would let "it is complicated"
# pass as a reason.
OBSTRUCTIONS = {
    "no-refusal-rule": "The rail has no rule that refuses a report leaving this obligation open.",
    "no-vector-opens-it": "No vector opens this obligation, so nothing here forces the rail either way.",
    "rule-survives-deletion": "A rule for this obligation can be deleted and no check turns red.",
    "module-diverges-from-vector": "The rego module answers a vector with other reasons than the vector declares.",
    "rail-diverges-from-vector": "The rail answers a vector that opens this obligation differently from the rego reference.",
    "absent-member-not-denied": (
        "The rail admits a vector that opens this obligation by omitting a fact the baseline carries, because "
        "policy-controller's CUE evaluator leaves an absent member incomplete instead of failing it. The family "
        "fails closed on an absent fact."
    ),
}


def opa_bin() -> str:
    found = os.environ.get("OPA_BIN") or shutil.which("opa")
    if not found:
        raise CouldNotRun("opa was not found; install it or set OPA_BIN")
    return found


def answer(opa: str, case: dict[str, Any], work: Path, consumer: dict[str, Any] | None = None) -> list[str]:
    """The reasons the rego module returns for a vector, under the vector's pins unless others are given."""
    pins = case["consumer"] if consumer is None else consumer
    (work / "in.json").write_text(json.dumps(case["input"]), encoding="utf-8")
    (work / "data.json").write_text(json.dumps({"verifier_isolation_consumer": pins}), encoding="utf-8")
    proc = subprocess.run(
        [opa, "eval", "-f", "json", "-d", str(MODULE), "-d", str(work / "data.json"), "-i", str(work / "in.json"),
         "data.verifier_isolation.reasons"],
        capture_output=True, text=True, check=False,
    )
    try:
        return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise CouldNotRun(f"opa returned no value: {proc.stderr.strip()[:300]}") from exc


def rules_by_obligation(source: str, ids: list[str]) -> dict[str, list[tuple[int, int, str]]]:
    found: dict[str, list[tuple[int, int, str]]] = {i: [] for i in ids}
    for m in RULE_RE.finditer(source):
        reason = m.group("reason")
        head = reason.split(":", 1)[0]
        if head in found:
            found[head].append((m.start(), m.end(), reason))
    return found


def survives(opa: str, source: str, span: tuple[int, int, str]) -> bool:
    """True when deleting this rule leaves the module's own tests green."""
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        shutil.copy(TESTS, work / TESTS.name)
        shutil.copy(VECTORS, work / VECTORS.name)
        (work / MODULE.name).write_text(source[: span[0]] + source[span[1]:], encoding="utf-8")
        proc = subprocess.run([opa, "test", "--timeout", "120s", str(work)], capture_output=True, text=True, check=False)
    return proc.returncode == 0


def page_rows() -> dict[str, tuple[set[str], set[str]]]:
    """Per obligation, the reasons and hardening steps the docs page lists."""
    text = PAGE.read_text(encoding="utf-8").split("## The obligations", 1)[1].split("\n## ", 1)[0]
    rows: dict[str, tuple[set[str], set[str]]] = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and re.fullmatch(r"`vi-[0-9]+`", cells[0]):
            steps = {f"H{n}" for n in re.findall(r"[1-7]", cells[2])}
            rows[cells[0].strip("`")] = (set(re.findall(r"`([^`]+)`", cells[3])), steps)
    return rows


def page_disagreements(rules: dict[str, list[tuple[int, int, str]]], obligations: list[dict[str, Any]]) -> list[str]:
    try:
        rows = page_rows()
    except (OSError, IndexError) as exc:
        raise CouldNotRun(f"cannot read the obligations table in {PAGE.name}: {exc}") from exc
    out: list[str] = []
    for o in obligations:
        oid = o["id"]
        shown = {r.replace("%s", "<name>") for r in (x[2] for x in rules[oid])}
        want = {r.split(":", 1)[1] for r in shown}
        got, steps = rows.get(oid, (set(), set()))
        if got != want:
            out.append(f"{PAGE.name} lists {sorted(got)} for {oid}; the module can return {sorted(want)}")
        if steps != set(o["hardening"]):
            out.append(f"{PAGE.name} lists hardening {sorted(steps)} for {oid}; the registry claims {sorted(o['hardening'])}")
    return out


def leaves(node: Any, prefix: str = "") -> Iterator[str]:
    """The path of every value in a document; an empty object or list is a value at its own path."""
    if isinstance(node, dict) and node:
        for k, v in node.items():
            yield from leaves(v, f"{prefix}.{k}")
    elif isinstance(node, list) and node:
        for i, v in enumerate(node):
            yield from leaves(v, f"{prefix}[{i}]")
    else:
        yield prefix


def omits_a_fact(baseline: dict[str, Any], vector: dict[str, Any]) -> bool:
    """True when the vector leaves out a value the baseline carries, as opposed to changing one."""
    return bool(set(leaves(baseline)) - set(leaves(vector)))


def rule_key(reason: str) -> str:
    """The rule a reason comes from: the per-loader reasons all come from one rule."""
    return re.sub(r"^(vi-9:unsafe_loader):.*$", r"\1", reason.replace(":%s", ""))


def expected_for(rail_rules: set[str], reference: list[str]) -> list[str]:
    """The reference's reasons that a rail has a rule for. One it has no rule for is that rail's recorded gap."""
    return [r for r in reference if rule_key(r) in rail_rules]


def vi_rules(rules: set[str], oid: str) -> list[str]:
    return sorted(k for k in rules if k.startswith(f"{oid}:"))


class Engine:
    """One engine rail: its rules, and how to ask it a question about a vector."""

    def __init__(self, name: str, artifact: str, rules: list[str]) -> None:
        self.name = name
        self.artifact = artifact
        self.rules = set(rules)
        self.admit: dict[str, bool] = {}
        self.reasons: dict[str, list[str]] | None = None


def engine_rows(
    engine: Engine, cases: dict[str, Any], ref: dict[str, list[str]], oids: list[str], rego_rules: dict[str, set[str]],
    flips: Any, extra_failed: set[str], skip_mutations: bool, failures: list[str],
) -> dict[str, Any]:
    """The per-obligation rows of one engine rail. `flips(vector, rule)` is True when deleting the rule admits the vector."""
    rows: dict[str, Any] = {}
    for oid in oids:
        own = vi_rules(engine.rules, oid)
        missing = sorted(rego_rules[oid] - set(own))
        for stray in sorted(set(own) - rego_rules[oid]):
            failures.append(f"{engine.name}: a rule returns {stray}, which the rego module has no rule for")
        opening = sorted(n for n, c in cases.items() if c.get("opens") in (oid, "all"))
        exercising = [n for n in opening if any(r.startswith(f"{oid}:") for r in ref[n])]
        row: dict[str, Any] = {"rules": own, "vectors_opening": len(exercising)}
        if missing:
            row["rules_missing"] = missing
        diverging = [n for n in exercising if not engine_agrees(engine, n, ref[n])]
        obstruction = None
        if not own or missing:
            obstruction = "no-refusal-rule"
        elif not exercising:
            obstruction = "no-vector-opens-it"
        elif diverging:
            obstruction = "rail-diverges-from-vector"
        elif not skip_mutations:
            alive = []
            for rule in own:
                isolating = [n for n in cases if [rule_key(r) for r in expected_for(engine.rules, ref[n])] == [rule]]
                if not isolating:
                    failures.append(f"{engine.name}: no vector is refused by {rule} alone, so deleting it cannot be observed")
                    alive.append(rule)
                elif not all(flips(n, rule) for n in isolating):
                    failures.append(f"{engine.name}: deleting the rule for {rule} leaves a vector it alone refuses refused")
                    alive.append(rule)
            row["rules_deleted"] = len(own)
            row["rules_surviving"] = len(alive)
            if alive:
                obstruction = "rule-survives-deletion"
        if obstruction is None and set(exercising) & extra_failed:
            obstruction = "absent-member-not-denied"
        if obstruction:
            row["disposition"] = "unreachable"
            row["obstruction"] = obstruction
        else:
            row["disposition"] = "enforced"
        rows[oid] = row
    return rows


def engine_agrees(engine: Engine, name: str, reference: list[str]) -> bool:
    want = expected_for(engine.rules, reference)
    if engine.reasons is not None and engine.reasons[name] != sorted(want):
        return False
    return engine.admit[name] == (want == [])


def check_engine(engine: Engine, cases: dict[str, Any], ref: dict[str, list[str]], failures: list[str]) -> None:
    for name in sorted(cases):
        if engine_agrees(engine, name, ref[name]):
            continue
        want = expected_for(engine.rules, ref[name])
        got = engine.reasons[name] if engine.reasons is not None else ("admit" if engine.admit[name] else "refuse")
        failures.append(f"{engine.name} vector {name}: expected {sorted(want) or 'admit'}, rail returned {got or 'admit'}")


def measure_engines(
    opa: str, cases: dict[str, Any], oids: list[str], rego_rules: dict[str, set[str]], rego_all: set[str],
    skip_mutations: bool, failures: list[str],
) -> dict[str, Any]:
    kyverno = rails.tool("KYVERNO_BIN", "kyverno")
    cue_bin = rails.tool("CUE_BIN", "cue")
    baseline = cases[BASELINE]["input"]
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        cel = rails.CelRail(kyverno, work)
        cue = rails.CueRail(cue_bin, kyverno, work)
        ref = {n: rails.normalise(answer(opa, c, work, rails.engine_consumer(c))) for n, c in cases.items()}
        pins = {n: rails.contract_pin(c) for n, c in cases.items()}
        if all(r == [] for r in ref.values()) or not any(r == [] for r in ref.values()):
            failures.append("the engine reference admits all or none of the vectors; it measures nothing")

        engines: dict[str, Engine] = {}
        for tag, rule_list, artifact in (
            ("kyverno-cel", cel.reasons_in_policy(), "kyverno/imagevalidatingpolicy-verifier-isolation.yaml"),
            ("cue", cue.reasons_in_policy(), "policy-controller/clusterimagepolicy-verifier-isolation-cue.yaml"),
        ):
            engines[tag] = Engine(tag, artifact, rule_list)
            for stray in sorted(set(rule_list) - rego_all):
                failures.append(f"{tag}: a rule returns {stray}, which the rego module has no rule for")

        celr = engines["kyverno-cel"]
        celr.reasons = {n: cel.reasons(c["input"], pins[n]) for n, c in cases.items()}
        celr.admit = {n: cel.admits(c["input"], pins[n]) for n, c in cases.items()}
        for n in cases:
            if celr.admit[n] != (celr.reasons[n] == []):
                failures.append(f"kyverno-cel vector {n}: the whole policy and the one-rule-at-a-time run disagree")

        cuer = engines["cue"]
        cuer.admit = {n: cue.admits(c["input"], pins[n]) for n, c in cases.items()}
        lenient = {n: cue.admits(c["input"], pins[n], lenient=True) for n, c in cases.items()}

        # The gap: what policy-controller's evaluator admits that `cue vet` refuses. It has to be
        # exactly the vectors that leave out a fact the baseline carries, or it is a different gap.
        gap = sorted(n for n in cases if not cuer.admit[n] and lenient[n])
        for n in cases:
            if cuer.admit[n] and not lenient[n]:
                failures.append(f"cue vector {n}: `cue vet` admits what the lenient reading refuses")
        for n in gap:
            if not omits_a_fact(baseline, cases[n]["input"]):
                failures.append(f"cue vector {n}: the lenient reading admits it and it omits no fact; the gap is not what is claimed")
        if not gap:
            failures.append("cue: the lenient reading admits nothing `cue vet` refuses, so the recorded gap is unproven")

        for e in engines.values():
            check_engine(e, cases, ref, failures)

        def cel_flips(n: str, rule: str) -> bool:
            return cel.admits(cases[n]["input"], pins[n], without=rule)

        def cue_flips(n: str, rule: str) -> bool:
            return cue.admits(cases[n]["input"], pins[n], without=rule)

        rows = {
            "kyverno-cel": engine_rows(celr, cases, ref, oids, rego_rules, cel_flips, set(), skip_mutations, failures),
            "cue": engine_rows(cuer, cases, ref, oids, rego_rules, cue_flips, set(gap), skip_mutations, failures),
        }
        for oid, row in rows["cue"].items():
            opening = [n for n, c in cases.items() if c.get("opens") in (oid, "all") and any(r.startswith(f"{oid}:") for r in ref[n])]
            row["refused_by_cue_vet"] = sum(1 for n in opening if not cuer.admit[n])
            row["refused_as_policy_controller_reads_it"] = sum(1 for n in opening if not lenient[n])

    verdict = {n: ("admit" if r == [] else "refuse") for n, r in ref.items()}
    agree = {
        "kyverno-cel": sum(1 for n in cases if celr.admit[n] == (ref[n] == [])),
        "cue": sum(1 for n in cases if cuer.admit[n] == (ref[n] == [])),
        "cue-policy-controller": sum(1 for n in cases if lenient[n] == (ref[n] == [])),
    }
    return {
        "rows": rows,
        "artifacts": {e.name: e.artifact for e in engines.values()},
        "cross_rail": {
            "reference": "rego under the pins an engine gives it: the signature checked, and the contract pin the vector carries",
            "vectors": len(cases),
            "admitted": sum(1 for v in verdict.values() if v == "admit"),
            "refused": sum(1 for v in verdict.values() if v == "refuse"),
            "agree": agree,
            "policy_controller_gap": gap,
        },
        "verdicts": {
            "rego": verdict,
            "kyverno-cel": {n: ("admit" if celr.admit[n] else "refuse") for n in sorted(cases)},
            "cue": {n: ("admit" if cuer.admit[n] else "refuse") for n in sorted(cases)},
            "cue-policy-controller": {n: ("admit" if lenient[n] else "refuse") for n in sorted(cases)},
        },
    }


def measure(skip_mutations: bool) -> tuple[dict[str, Any], list[str]]:
    opa = opa_bin()
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    obligations = registry["obligations"]
    ids = [o["id"] for o in obligations]
    hardening = set(registry["hardening"])
    cases: dict[str, Any] = json.loads(VECTORS.read_text(encoding="utf-8"))["verifier_isolation_vectors"]["cases"]
    source = MODULE.read_text(encoding="utf-8")
    failures: list[str] = []

    if BASELINE not in cases or cases[BASELINE]["reasons"]:
        raise CouldNotRun(f"the vectors carry no admitting baseline named {BASELINE}")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        got: dict[str, list[str]] = {}
        for name in sorted(cases):
            got[name] = answer(opa, cases[name], work)
            if got[name] != sorted(cases[name]["reasons"]):
                failures.append(f"vector {name}: expected {sorted(cases[name]['reasons'])}, module returned {got[name]}")

    claimed = {h for o in obligations for h in o["hardening"]}
    for missing in sorted(hardening - claimed):
        failures.append(f"hardening step {missing} is claimed by no obligation")
    for stray in sorted(claimed - hardening):
        failures.append(f"an obligation claims {stray}, which the registry does not list")

    rules = rules_by_obligation(source, ids)
    module_heads = {m.group("reason").split(":", 1)[0] for m in RULE_RE.finditer(source) if m.group("reason").startswith("vi-")}
    for stray in sorted(module_heads - set(ids)):
        failures.append(f"the module refuses with {stray}, which the registry does not list")

    failures += page_disagreements(rules, obligations)

    out: dict[str, Any] = {}
    for o in obligations:
        oid = o["id"]
        opening = sorted(n for n, c in cases.items() if c.get("opens") in (oid, "all"))
        exercising = [n for n in opening if any(r.startswith(f"{oid}:") for r in got.get(n, []))]
        row: dict[str, Any] = {"vector": o["vector"], "name": o["name"], "hardening": o["hardening"],
                               "rules": sorted(r for _, _, r in rules[oid]), "vectors_opening": len(exercising)}
        obstruction = None
        if not rules[oid]:
            obstruction = "no-refusal-rule"
        elif not exercising:
            obstruction = "no-vector-opens-it"
        elif not skip_mutations:
            alive = [r for s, e, r in rules[oid] if survives(opa, source, (s, e, r))]
            row["rules_deleted"] = len(rules[oid])
            row["rules_surviving"] = len(alive)
            if alive:
                obstruction = "rule-survives-deletion"
                failures.append(f"{oid}: deleting the rule for {alive} leaves the module's tests green")
        if any(f.startswith(f"vector {n}:") for n in opening for f in failures):
            obstruction = "module-diverges-from-vector"
        if obstruction:
            row["disposition"] = "unreachable"
            row["obstruction"] = obstruction
        else:
            row["disposition"] = "enforced"
        out[oid] = row

    rego_rules = {oid: {rule_key(r) for _, _, r in rules[oid]} for oid in ids}
    rego_all = {rule_key(m.group("reason")) for m in RULE_RE.finditer(source)}
    engines = measure_engines(opa, cases, ids, rego_rules, rego_all, skip_mutations, failures)

    for rail_rows in engines["rows"].values():
        for oid, row in rail_rows.items():
            if row.get("obstruction") and row["obstruction"] not in OBSTRUCTIONS:
                failures.append(f"{oid}: obstruction {row['obstruction']!r} is not in the closed vocabulary")
    doc = {
        "family": registry["family"],
        "vectors": len(cases),
        "rails": {
            "rego": {"artifact": "rego/verifier_isolation.rego", "obligations": out},
            "kyverno-cel": {"artifact": engines["artifacts"]["kyverno-cel"], "obligations": engines["rows"]["kyverno-cel"]},
            "cue": {"artifact": engines["artifacts"]["cue"], "obligations": engines["rows"]["cue"]},
        },
        "cross_rail": engines["cross_rail"],
        "verdicts": engines["verdicts"],
    }
    return doc, failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--write", action="store_true", help="rewrite verifier-isolation/PROFILE-MAP.json")
    parser.add_argument("--skip-mutations", action="store_true", help="skip the rule deletion sweep (a map written this way is refused)")
    args = parser.parse_args(argv[1:])
    if args.write and args.skip_mutations:
        print("a map is not written without the mutation sweep", file=sys.stderr)
        return 2
    try:
        doc, failures = measure(args.skip_mutations)
    except CouldNotRun as exc:
        print(f"could not run: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    for rail, body in doc["rails"].items():
        enforced = sum(1 for r in body["obligations"].values() if r["disposition"] == "enforced")
        print(f"{rail}: {enforced} of {len(body['obligations'])} obligations enforced over {doc['vectors']} vectors")
    cross = doc["cross_rail"]
    print("cross rail: " + ", ".join(f"{k} agrees on {v} of {cross['vectors']}" for k, v in cross["agree"].items()))
    if not args.skip_mutations and not failures:
        if args.write:
            MAP.parent.mkdir(parents=True, exist_ok=True)
            MAP.write_text(rendered, encoding="utf-8")
            print(f"wrote {MAP}")
        elif not MAP.is_file() or MAP.read_text(encoding="utf-8") != rendered:
            failures.append(f"{MAP.relative_to(ROOT)} is not what this run measured; rerun with --write and commit")
    for f in failures:
        print(f, file=sys.stderr)
    print(f"{len(failures)} disagreement(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
