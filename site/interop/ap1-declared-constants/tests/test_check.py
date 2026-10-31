"""Known answers for check.py on synthetic derivations, one defect each."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "..", "check.py")
sys.path.insert(0, os.path.join(HERE, ".."))

from check import read_derivations, report

CONSUMED = """
def derive_q01(ctx):
    total = D(ctx["a"]) * D("3") / D("12")
    return {"intermediates": [{"inputs": [{"source": "a"}, {"constant": "3"}, {"constant": "12"}]}]}
"""

UNCONSUMED = """
def derive_q01(ctx):
    total = D(ctx["a"]) * D("3")
    return {"intermediates": [{"inputs": [{"source": "a"}, {"constant": "3"}, {"constant": "4"}]}]}
"""

SAME_VALUE = """
def derive_q01(ctx):
    total = D(ctx["a"]) / D("12.0")
    return {"intermediates": [{"inputs": [{"constant": "12"}]}]}
"""

BARE_NUMBER = """
def derive_q01(ctx):
    total = D(ctx["a"]) * 3
    return {"intermediates": [{"inputs": [{"constant": "3"}]}]}
"""

OTHER_STEP = """
def derive_q01(ctx):
    a = D(ctx["a"]) * D("3")
    b = a * D("2")
    return {"intermediates": [
        {"label": "a", "inputs": [{"constant": "2"}]},
        {"label": "b", "inputs": [{"constant": "3"}]},
    ]}
"""


def run(source: str) -> dict[str, object]:
    return report(read_derivations(source))


class KnownAnswers(unittest.TestCase):
    def test_every_declared_constant_consumed_passes(self) -> None:
        self.assertEqual(run(CONSUMED)["result"], "pass")

    def test_declared_and_unused_constant_fails(self) -> None:
        result = run(UNCONSUMED)
        self.assertEqual(result["result"], "fail")
        self.assertEqual([row["constant"] for row in result["unconsumed"]], ["4"])  # type: ignore[union-attr]

    def test_values_compare_as_decimals(self) -> None:
        self.assertEqual(run(SAME_VALUE)["result"], "pass")

    def test_bare_number_counts_as_used(self) -> None:
        self.assertEqual(run(BARE_NUMBER)["result"], "pass")

    def test_declaration_value_is_not_its_own_use(self) -> None:
        # The "4" inside {"constant": "4"} must not count as a use of 4.
        self.assertEqual(run(UNCONSUMED)["declaredConstants"], 2)
        self.assertEqual(len(run(UNCONSUMED)["unconsumed"]), 1)  # type: ignore[arg-type]

    def test_comparison_is_per_function_not_per_step(self) -> None:
        # The stated limit: 2 is declared on step a and used only in step b.
        self.assertEqual(run(OTHER_STEP)["result"], "pass")


class CommandLine(unittest.TestCase):
    def _exit(self, source: bytes) -> int:
        with tempfile.NamedTemporaryFile("wb", suffix=".py", delete=False) as fh:
            fh.write(source)
            path = fh.name
        try:
            return subprocess.run(
                [sys.executable, "-I", CHECK, path], capture_output=True, check=False
            ).returncode
        finally:
            os.unlink(path)

    def test_exit_codes(self) -> None:
        self.assertEqual(self._exit(CONSUMED.encode()), 0)
        self.assertEqual(self._exit(UNCONSUMED.encode()), 1)

    def test_byte_order_mark_is_read(self) -> None:
        self.assertEqual(self._exit(b"\xef\xbb\xbf" + UNCONSUMED.encode()), 1)

    def test_no_derivation_is_not_a_pass(self) -> None:
        self.assertEqual(self._exit(b"x = 1\n"), 2)


if __name__ == "__main__":
    unittest.main()
