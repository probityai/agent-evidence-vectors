"""Replay exactly the frozen twelve cases with a separately maintained consumer."""

import argparse
import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path

from json_profile import Refusal, digest, parse, require
from mapping import check_mapping_ceiling
from reader import read

HERE = Path(__file__).resolve().parent.parent
FROZEN_INPUT_MANIFEST = "3c7e54efb1351f84fa39b4fba8c6d3b89416b06b823ad1241af8839c92a51bdf"


def load_cases(root):
    raw = (root / "INPUT-MANIFEST.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == FROZEN_INPUT_MANIFEST, "input_manifest_changed")
    manifest = parse(raw)
    cases = manifest["cases"]
    require(type(cases) is list and len(cases) == 12, "frozen_case_count")
    names = [case["path"] for case in cases]
    require(len(set(names)) == 12, "duplicate_case_path")
    directory = root / "private-inputs"
    require(not directory.is_symlink(), "symlink_case_directory")
    require(
        set(p.name for p in directory.iterdir()) == {Path(n).name for n in names},
        "case_population_changed",
    )
    selected = []
    for item in cases:
        relative = Path(item["path"])
        require(relative.parent.as_posix() == "private-inputs", "unsafe_case_path")
        path = root / relative
        require(path.is_file() and not path.is_symlink(), "regular_case_required")
        data = path.read_bytes()
        require(type(item["bytes"]) is int and len(data) == item["bytes"], "case_size_changed")
        require(hashlib.sha256(data).hexdigest() == item["sha256"], "case_digest_changed")
        selected.append((path.name, item["sha256"], parse(data)))
    return manifest, digest(raw), selected


def compare_case(name, source_digest, case):
    observed = read(case["input"])
    expected = case["expected"]
    expected_decision = "BOUND" if "mapping" in expected else "REFUSED"
    comparisons = {"binding_decision": observed["decision"] == expected_decision}
    if "mapping" in expected and observed["decision"] == "BOUND":
        try:
            check_mapping_ceiling(expected["mapping"], observed)
            comparisons["native_fields_and_ceiling"] = True
        except Refusal:
            comparisons["native_fields_and_ceiling"] = False
        comparisons["missing_required_fields"] = (
            sorted(expected["mapping"]["absent_required"]) == observed["missing_trace_required"]
        )
    return {
        "case": name,
        "source_sha256": source_digest,
        "upstream_expected": expected,
        "observed": observed,
        "comparisons": comparisons,
        "agreement": all(comparisons.values()),
        "refusal_code_equivalence_assumed": False,
    }


def replay(root):
    manifest, manifest_digest, cases = load_cases(root)
    rows = [compare_case(*case) for case in cases]
    return {
        "schema": "probity-trace-m1-consumer-result/1",
        "source_repository": manifest["upstream_repository"],
        "source_commit": manifest["upstream_commit"],
        "merged_commit": manifest["merged_commit"],
        "source_tree": manifest["merged_tree_equal"],
        "trace_schema_pin": manifest["trace_schema_pin"],
        "input_manifest_digest": manifest_digest,
        "runtime": {
            "python": platform.python_version(),
            "cryptography": importlib.metadata.version("cryptography"),
            "pynacl": importlib.metadata.version("pynacl"),
        },
        "cases": len(rows),
        "agreements": sum(row["agreement"] for row in rows),
        "rows": rows,
        "scope": (
            "Frozen public synthetic known-answer population. Original consumer uses cryptography "
            "and PyNaCl/libsodium for point admissibility, "
            "imports no REMORA runtime/reference verifier, and was authored after reading the "
            "producer protocol. It checks signature/report/context bindings and native-field "
            "preservation, not the truth of native claims. Reasons are not equated. Bounded ASCII "
            "JSON/P1Y/explicit-digest profile, not a general mapper, JCS or TRACE qualification. "
            "No workload identity, authority, effect, host adoption or commercial claim."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    result = replay(HERE)
    raw_report = (json.dumps(result, indent=2) + "\n").encode("ascii")
    (args.out / "report.json").write_bytes(raw_report)
    public = {key: value for key, value in result.items() if key != "rows"}
    public["retained_full_report_sha256"] = hashlib.sha256(raw_report).hexdigest()
    public["projection"] = (
        "Own decisions and native fields; producer expected mappings and declared context bodies "
        "are retained locally, omitted from this public result."
    )
    public["rows"] = []
    for row in result["rows"]:
        observed = {key: value for key, value in row["observed"].items() if key != "bound_context"}
        observed["context_bound"] = row["observed"].get("bound_context") is not None
        public["rows"].append(
            {
                **{
                    key: row[key]
                    for key in (
                        "case",
                        "source_sha256",
                        "comparisons",
                        "agreement",
                        "refusal_code_equivalence_assumed",
                    )
                },
                "observed": observed,
            }
        )
    (args.out / "public-report.json").write_text(json.dumps(public, indent=2) + "\n")
    print(json.dumps({"cases": result["cases"], "agreements": result["agreements"]}))
    return 0 if result["agreements"] == result["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
