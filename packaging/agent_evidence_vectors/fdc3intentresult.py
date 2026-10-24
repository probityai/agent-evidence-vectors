"""Judge FDC3 intent-result message sequences against a set of FDC3 schemas.

The corpus this module reads is for finos/FDC3 issue #2271: the Desktop Agent
Communication Protocol (DACP) gives an app's agent proxy no message for an
intent handler that throws or returns a rejected Promise, although
``IntentResolution.getResult()`` must then reject with
``ResultError.IntentHandlerRejected``. ``intentResultRequest`` requires
``intentResult`` and sets ``additionalProperties: false``, so an ``error``
field is refused, while ``raiseIntentResultResponse`` (agent to raising app)
already carries either a result or an error.

Each case is a sequence of DACP messages, one per step, and each message is
judged against the schema its ``type`` names (``<type>.schema.json`` in the
API schema directory). A sequence is ``accepted`` when every message is valid,
and ``rejected`` otherwise; the answer also names the steps that were refused.
Every case is judged against several schema sets, each laid out as a sparse
FDC3 checkout:

- ``fdc3-39505b1``: the FDC3 schemas at commit 39505b1, as issue #2271 cites;
- ``optional-error``: those schemas with ``error`` added to the
  ``intentResultRequest`` payload as an optional property, the first option
  the issue lists. It is generated here and is nobody's proposal: it exists to
  show what an optional field admits;
- ``proposed-oneof``: the payload as an alternative, ``intentResult`` or
  ``error`` (a ``ResultError`` value) and never both, as the FDC3 maintainers
  asked on the issue. Its ``intentResultRequest`` schema is the one on the
  branch the manifest names.

The validator is a stdlib draft-07 subset: ``$ref``, ``type``, ``const``,
``enum``, ``properties``, ``required``, ``additionalProperties``, ``allOf``,
``anyOf``, ``oneOf``, ``not`` and boolean schemas. Annotations are ignored, and so are
``format`` (draft-07 makes it an annotation unless a validator opts in) and
``unevaluatedProperties``, which is not a draft-07 keyword. Any other keyword
is refused rather than skipped, so a schema the subset cannot judge produces
an error and never a verdict. The corpus test checks every verdict against
``jsonschema.Draft7Validator``.

The external-verifier contract: ``<verifier> <case-dir>/case.json
<fdc3-checkout> --json`` prints one JSON object carrying ``decision`` and
``rejectedSteps``, and exits 0 for ``accepted`` and 1 for ``rejected``. The
checkout is a directory holding ``packages/fdc3-schema/schemas/api`` and
``packages/fdc3-context/schemas/context``: a schema set from this corpus, or
an FDC3 clone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import shlex
import subprocess
from pathlib import Path
from typing import Any

SUITE = "fdc3-intent-result-error/v1"
ACCEPTED, REJECTED = "accepted", "rejected"
EXIT_FOR = {ACCEPTED: 0, REJECTED: 1}
# Where the schema directories sit inside an FDC3 checkout, keyed by the
# directory names the schemas' own relative references use.
LAYOUT = {
    "api": "packages/fdc3-schema/schemas/api",
    "context": "packages/fdc3-context/schemas/context",
}
# Keywords the subset judges, and the ones it may ignore. Anything else in a
# schema it reaches is an error.
ASSERTIONS = ("type", "const", "enum", "required", "properties", "additionalProperties",
              "allOf", "anyOf", "oneOf", "not")
IGNORED = frozenset({"$schema", "$id", "$comment", "title", "description", "examples",
                     "default", "format", "unevaluatedProperties", "$defs", "definitions"})

_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-fdc3-intent-result" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-fdc3-intent-result")


class UnsupportedSchema(ValueError):
    """The schema uses something the draft-07 subset does not judge."""


def _is_type(value: Any, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (
            isinstance(value, float) and value.is_integer())
    raise UnsupportedSchema(f"type {name!r}")


class SchemaSet:
    """The schema files of one FDC3 checkout, loaded on demand."""

    def __init__(self, checkout: Path, off: frozenset[str] = frozenset()) -> None:
        self.checkout = checkout
        self.off = off
        self._docs: dict[str, Any] = {}

    def _doc(self, name: str) -> Any:
        if name not in self._docs:
            top, _, rest = name.partition("/")
            if top not in LAYOUT or not rest or "/" in rest:
                raise UnsupportedSchema(f"reference outside the FDC3 layout: {name}")
            path = self.checkout / LAYOUT[top] / rest
            self._docs[name] = json.loads(path.read_text(encoding="utf-8"))
        return self._docs[name]

    def _resolve(self, ref: str, base: str) -> tuple[Any, str]:
        target, _, fragment = ref.partition("#")
        name = posixpath.normpath(posixpath.join(posixpath.dirname(base), target)) \
            if target else base
        node = self._doc(name)
        for part in [p for p in fragment.split("/") if p]:
            node = node[part.replace("~1", "/").replace("~0", "~")]
        return node, name

    def valid(self, instance: Any, schema: Any, base: str) -> bool:
        """Whether ``instance`` is valid against ``schema`` found in file ``base``."""
        if schema is True or schema is False:
            return bool(schema)
        if not isinstance(schema, dict):
            raise UnsupportedSchema(f"schema is not an object in {base}")
        if "$ref" in schema:
            # draft-07: every keyword beside $ref is ignored
            target, name = self._resolve(schema["$ref"], base)
            return self.valid(instance, target, name)
        unknown = set(schema) - IGNORED - set(ASSERTIONS)
        if unknown:
            raise UnsupportedSchema(f"{sorted(unknown)} in {base}")
        return all(self._keyword(k, instance, schema, base)
                   for k in ASSERTIONS if k in schema and k not in self.off)

    def _keyword(self, key: str, instance: Any, schema: dict[str, Any], base: str) -> bool:
        return bool(_KEYWORDS[key](self, instance, schema[key], schema, base))

    def _all_of(self, instance: Any, value: Any, _schema: Any, base: str) -> bool:
        return all(self.valid(instance, s, base) for s in value)

    def _any_of(self, instance: Any, value: Any, _schema: Any, base: str) -> bool:
        return any(self.valid(instance, s, base) for s in value)

    def _one_of(self, instance: Any, value: Any, _schema: Any, base: str) -> bool:
        return sum(self.valid(instance, s, base) for s in value) == 1

    def _not(self, instance: Any, value: Any, _schema: Any, base: str) -> bool:
        return not self.valid(instance, value, base)

    def _properties(self, instance: Any, value: Any, _schema: Any, base: str) -> bool:
        return not isinstance(instance, dict) or all(
            self.valid(instance[n], s, base) for n, s in value.items() if n in instance)

    def _additional(self, instance: Any, value: Any, schema: dict[str, Any], base: str) -> bool:
        """Judge the members ``properties`` does not name."""
        named = schema.get("properties", {})
        return not isinstance(instance, dict) or all(
            self.valid(instance[n], value, base) for n in instance if n not in named)

    def message_valid(self, message: Any) -> bool:
        """Judge one DACP message against the schema its ``type`` names."""
        kind = message.get("type") if isinstance(message, dict) else None
        if not isinstance(kind, str) or not kind or "/" in kind or "." in kind:
            return False
        name = f"api/{kind}.schema.json"
        if not (self.checkout / LAYOUT["api"] / f"{kind}.schema.json").is_file():
            return False
        return self.valid(message, self._doc(name), name)


def _type(_s: SchemaSet, instance: Any, value: Any, _schema: Any, _base: str) -> bool:
    return any(_is_type(instance, n) for n in (value if isinstance(value, list) else [value]))


def _required(_s: SchemaSet, instance: Any, value: Any, _schema: Any, _base: str) -> bool:
    return not isinstance(instance, dict) or all(name in instance for name in value)


_KEYWORDS: dict[str, Any] = {
    "type": _type,
    "const": lambda _s, i, v, _sc, _b: _json_equal(i, v),
    "enum": lambda _s, i, v, _sc, _b: any(_json_equal(i, x) for x in v),
    "required": _required,
    "properties": SchemaSet._properties,
    "additionalProperties": SchemaSet._additional,
    "allOf": SchemaSet._all_of,
    "anyOf": SchemaSet._any_of,
    "oneOf": SchemaSet._one_of,
    "not": SchemaSet._not,
}


def _json_equal(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b, strict=True))
    return type(a) is type(b) and a == b


def verify(case_path: Path, checkout: Path, off: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Judge every message of one case against the schemas in ``checkout``.

    A keyword in ``off`` is skipped wherever it appears, which is how the
    corpus test shows each keyword is load-bearing.
    """
    case = json.loads(case_path.read_text(encoding="utf-8"))
    schemas = SchemaSet(checkout, off)
    rejected = [step["step"] for step in case["sequence"]
                if not schemas.message_valid(step["message"])]
    return {"decision": REJECTED if rejected else ACCEPTED, "rejectedSteps": rejected}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _schema_set_error(root: Path, name: str, files: dict[str, Any]) -> str | None:
    base = root / "schema-sets" / name
    present = {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()}
    if present != set(files):
        return f"schema set {name}: file set changed"
    for rel, pin in files.items():
        if _sha256(base / rel) != pin["sha256"]:
            return f"schema set {name}: {rel} digest mismatch"
    return None


def _validated(root: Path) -> tuple[dict[str, Any], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("suite") != SUITE:
        return manifest, "unexpected suite"
    entries = manifest["vectors"]
    if not entries or len({e["id"] for e in entries}) != len(entries):
        return manifest, "empty or duplicate vector identifiers"
    if any(e.get("path") != f"cases/{e['id']}" for e in entries):
        return manifest, "case path does not match identifier"
    if {p.name for p in (root / "cases").iterdir() if p.is_dir()} != {e["id"] for e in entries}:
        return manifest, "case directories do not match manifest"
    sets = manifest["schemaSets"]
    if {p.name for p in (root / "schema-sets").iterdir() if p.is_dir()} != set(sets):
        return manifest, "schema-set directories do not match manifest"
    for name, schema_set in sets.items():
        error = _schema_set_error(root, name, schema_set["files"])
        if error:
            return manifest, error
    if any(set(e["expected"]) != set(sets) for e in entries):
        return manifest, "a vector does not state a verdict for every schema set"
    return manifest, None


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    declared = entry["files"]
    if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
        return "fixture file set changed"
    if any(_sha256(directory / n) != d for n, d in declared.items()):
        return "fixture digest mismatch"
    return None


def _external_answer(command: list[str], case_path: Path,
                     checkout: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), str(checkout), "--json"],
                                capture_output=True, text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    try:
        answer = json.loads(lines[-1])
        observed = {"decision": answer["decision"],
                    "rejectedSteps": list(answer["rejectedSteps"])}
    except (ValueError, KeyError, TypeError, IndexError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    off: frozenset[str] = frozenset(), checkout: Path | None = None,
    against: str = "proposed-oneof",
) -> tuple[int, list[str]]:
    """Check every case against every schema set, or against one checkout.

    With ``checkout`` the cases are judged against that FDC3 checkout and held
    to the verdicts of the schema set named by ``against``: run against an FDC3
    clone, this says whether its schemas behave as the proposal does. Returns
    the number of judgements made and every disagreement.
    """
    try:
        manifest, error = _validated(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if error:
        return 0, [error]
    if checkout is not None and against not in manifest["schemaSets"]:
        return 0, [f"no schema set named {against}"]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    targets = ({against: checkout} if checkout is not None else
               {name: root / "schema-sets" / name for name in manifest["schemaSets"]})
    errors: list[str] = []
    answered = 0
    for entry in manifest["vectors"]:
        fixture_error = _fixture_error(root / entry["path"], entry)
        if fixture_error:
            errors.append(f"{entry['id']}: {fixture_error}")
            continue
        for set_name, target in targets.items():
            ran, error = _judge(command, root, entry, set_name, target, off)
            answered += int(ran)
            if error:
                errors.append(f"{entry['id']} [{set_name}]: {error}")
    return answered, errors


def _judge(command: list[str] | None, root: Path, entry: dict[str, Any], set_name: str,
           target: Path, off: frozenset[str]) -> tuple[bool, str | None]:
    """Judge one case against one schema set; return whether it ran and any error."""
    case_path = root / entry["path"] / "case.json"
    observed: dict[str, Any] | str
    if command is None:
        try:
            ran, observed = True, verify(case_path, target, off)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            ran, observed = True, f"reader error: {exc}"
    else:
        ran, observed = _external_answer(command, case_path, target)
    expected = entry["expected"][set_name]
    if isinstance(observed, str):
        return ran, observed
    if observed != expected:
        return ran, f"expected {expected}, got {observed}"
    return ran, None


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"]) * len(manifest["schemaSets"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} judgements, "
          f"{len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("checkout", nargs="?",
                        help="the FDC3 checkout or schema set to judge the case against")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    parser.add_argument("--fdc3-checkout",
                        help="judge every case against this FDC3 clone instead of the "
                             "vendored schema sets")
    parser.add_argument("--against", default="proposed-oneof",
                        help="the schema set whose verdicts --fdc3-checkout is held to")
    args = parser.parse_args(argv)
    if args.case:
        if not args.checkout:
            parser.error("a case needs the checkout to judge it against")
        answer = verify(Path(args.case), Path(args.checkout))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['rejectedSteps']}")
        return EXIT_FOR[answer["decision"]]
    checkout = Path(args.fdc3_checkout) if args.fdc3_checkout else None
    answered, errors = check(args.verifier, checkout=checkout, against=args.against)
    for error in errors:
        print(error)
    print(f"answered {answered} judgements, {len(errors)} disagreements")
    return 1 if errors or not answered else 0


if __name__ == "__main__":
    raise SystemExit(main())
