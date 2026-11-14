"""No workflow job takes a runner on a plain pull request (scripts/check_ci_batch_only.py)."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_ci_batch_only", ROOT / "scripts/check_ci_batch_only.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

GOOD = f"""on:
  pull_request:
  push:
jobs:
  select:
    if: ${{{{ {CHECK.GATE} }}}}
    runs-on: ubuntu-24.04
  build:
    needs: select
    runs-on: ubuntu-24.04
  test:
    needs: [select, build]
    if: ${{{{ needs.select.outputs.run == 'true' }}}}
  ci-ok:
    if: ${{{{ always() && ({CHECK.GATE}) }}}}
    needs:
      - select
      - test
"""


class BatchOnly(unittest.TestCase):
    def test_repository_workflows_are_batch_only(self):
        self.assertEqual(CHECK.check_dir(ROOT / ".github/workflows"), [])

    def test_good_shape_passes(self):
        self.assertEqual(CHECK.check_text("ci.yml", GOOD), [])

    def test_ungated_root_job_is_refused(self):
        bad = GOOD + "  stray:\n    runs-on: ubuntu-24.04\n"
        self.assertIn("stray", " ".join(CHECK.check_text("ci.yml", bad)))

    def test_always_without_gate_is_refused(self):
        bad = GOOD.replace(f"always() && ({CHECK.GATE})", "always()")
        self.assertIn("ci-ok", " ".join(CHECK.check_text("ci.yml", bad)))

    def test_missing_gate_is_refused(self):
        bad = GOOD.replace(f"if: ${{{{ {CHECK.GATE} }}}}", "if: true")
        self.assertTrue(CHECK.check_text("ci.yml", bad))

    def test_no_pull_request_trigger_is_ignored(self):
        self.assertEqual(CHECK.check_text("x.yml", "on:\n  push:\njobs:\n  a:\n    runs-on: x\n"), [])


if __name__ == "__main__":
    unittest.main()
