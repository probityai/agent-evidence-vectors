"""The checker refuses a broken member, a broken rule, an untested rule and drifted text.

Each test copies this directory, breaks one thing, and runs the checker on the
copy. The PDF is extracted once for the whole module and handed to every run;
the CI step that runs check_vectors.py on this directory extracts it afresh.

    uv run --extra dev python -m unittest discover -s interop/nist-ai-300-1 -p test_check_vectors.py
"""

from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_vectors  # noqa: E402
import extract as X  # noqa: E402
import gen_vectors as G  # noqa: E402


class CheckerRefuses(unittest.TestCase):
    transcript: ClassVar[dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.transcript = G.transcript(HERE / "source" / "NIST.AI.300-1.ipd.pdf")

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "nist-ai-300-1"
        shutil.copytree(HERE, self.root, ignore=shutil.ignore_patterns("__pycache__"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def run_check(self, transcript: dict[str, Any] | None = None) -> list[str]:
        tr = self.transcript if transcript is None else transcript
        return check_vectors.run(self.root, lambda _pdf: tr)

    def census_broken(self, change: Callable[[dict[str, Any]], None], *needles: str) -> None:
        tr = copy.deepcopy(self.transcript)
        change(tr["census"])
        failures = self.run_check(tr)
        self.assertTrue(failures, "the checker passed a census that misses part of the PDF")
        for needle in needles:
            self.assertTrue(any(needle in f for f in failures), (needle, failures))

    def edit(self, rel: str) -> Any:
        return json.loads((self.root / rel).read_text(encoding="utf-8"))

    def save(self, rel: str, value: Any) -> None:
        (self.root / rel).write_text(
            json.dumps(value, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
        )

    def member(self, member_id: str) -> dict[str, Any]:
        manifest = self.edit("MANIFEST.json")
        found = [e for e in manifest["members"] if e["id"] == member_id]
        self.assertEqual(len(found), 1)
        entry: dict[str, Any] = found[0]
        return entry

    def assert_refused(self, *needles: str) -> None:
        failures = self.run_check()
        self.assertTrue(failures, "the checker passed a broken tree")
        for needle in needles:
            self.assertTrue(any(needle in f for f in failures), (needle, failures))

    def test_untouched_copy_passes(self) -> None:
        self.assertEqual(self.run_check(), [])

    def test_wrong_expected_verdict(self) -> None:
        manifest = self.edit("MANIFEST.json")
        entry = next(e for e in manifest["members"] if e["id"] == "A21-violates-1.5.1-required")
        entry["expected"]["conformance"] = "valid"
        self.save("MANIFEST.json", manifest)
        self.assert_refused("A21-violates-1.5.1-required: conformance invalid, expected valid")

    def test_member_bytes_changed(self) -> None:
        rel = self.member("A21-control-every-field")["file"]
        doc = self.edit(rel)
        doc["fields"]["1"]["content"] = "Changed."
        self.save(rel, doc)
        self.assert_refused("A21-control-every-field: bytes differ")

    def test_member_broken_and_rehashed(self) -> None:
        manifest = self.edit("MANIFEST.json")
        entry = next(e for e in manifest["members"] if e["id"] == "A21-control-every-field")
        doc = self.edit(entry["file"])
        del doc["fields"]["4"]
        self.save(entry["file"], doc)
        entry["sha256"] = X.sha256_file(self.root / entry["file"])
        self.save("MANIFEST.json", manifest)
        self.assert_refused("A21-control-every-field: conformance invalid, expected valid")

    def test_rule_deleted_from_schema(self) -> None:
        rel = "schemas/table-a.2.1.conformance.schema.json"
        schema = self.edit(rel)
        schema["allOf"] = [
            e for e in schema["allOf"] if e["$comment"] != "rule:table-a.2.1/field-4.2/required"
        ]
        self.save(rel, schema)
        self.assert_refused(
            "A21-violates-4.2-required: conformance valid, expected invalid",
            "table-a.2.1 conformance schema rules differ from MANIFEST.json",
        )

    def test_condition_dropped_in_schema(self) -> None:
        rel = "schemas/table-a.3.1.conformance.schema.json"
        schema = self.edit(rel)
        tag = "rule:table-a.3.1/field-1.10/required"
        schema["allOf"] = [
            {"$comment": tag, **e["then"]} if e["$comment"] == tag else e for e in schema["allOf"]
        ]
        self.save(rel, schema)
        self.assert_refused(
            "A31-inapplicable-1.10-required: conformance invalid, expected valid",
            "table-a.3.1 conformance schema is not the one its rules generate",
        )

    def test_rule_no_member_depends_on(self) -> None:
        manifest = self.edit("MANIFEST.json")
        rule = "table-a.2.1/field-4.4/required"
        for e in manifest["members"]:
            e["roles"] = [r for r in e["roles"] if r["rule"] != rule]
        self.save("MANIFEST.json", manifest)
        self.assert_refused(f"{rule}: no member violates it")

    def test_transcript_drift(self) -> None:
        templates = self.edit("templates.json")
        templates["tables"]["table-a.3.1"]["fields"][0]["designation"] = "Recommended"
        self.save("templates.json", templates)
        self.assert_refused("table-a.3.1: templates.json differs from the PDF's text")

    def test_source_changed(self) -> None:
        pdf = self.root / "source" / "NIST.AI.300-1.ipd.pdf"
        pdf.write_bytes(pdf.read_bytes() + b"\n")
        self.assert_refused("source PDF sha256")

    def test_census_a_table_extract_does_not_read(self) -> None:
        title = "Table A.4.1: Default AI system profile"

        def add(c: dict[str, Any]) -> None:
            c["captions"].append({"page": 54, "title": title})
            c["ruled"].append({"page": 54, "first": title, "ids": ["1"]})

        self.census_broken(
            add,
            "page 54 captions a table this corpus does not read",
            "none of the 4 tables are",
            "census re-counted from the PDF",
        )

    def test_census_a_row_extract_merged_away(self) -> None:
        def add(c: dict[str, Any]) -> None:
            box = next(b for b in c["ruled"] if b["page"] == 40)
            box["ids"].insert(1, "4.4.9")

        self.census_broken(add, "table-a.2.1 has 72 rows by its cell grid and 71 by extract.py")

    def test_census_a_table_page_left_out(self) -> None:
        def drop(c: dict[str, Any]) -> None:
            c["ruled"] = [b for b in c["ruled"] if b["page"] != 53]

        self.census_broken(drop, "table-a.3.1 is ruled on pages", "census re-counted")

    def test_stray_member_file(self) -> None:
        (self.root / "members" / "extra.json").write_text("{}\n", encoding="utf-8")
        self.assert_refused("members/ and MANIFEST.json disagree")


if __name__ == "__main__":
    unittest.main()
