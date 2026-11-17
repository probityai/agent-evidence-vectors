"""Fixture candidate for the mutation stage: the reference verifier's own validity verdict.

    python reference_candidate.py [--flip-one INDEX] <statement.json>

Exit 0 when agent-evidence-verify reads the statement as valid, 1 otherwise. With
--flip-one N it answers the opposite on the mutant numbered N (its file name ends
in -m<N>.json), so exactly one verdict disagrees with the reference.
"""

import importlib.util
import sys
from pathlib import Path

STAGE = Path(__file__).resolve().parents[3] / "action-reference-stage.py"
spec = importlib.util.spec_from_file_location("stage", STAGE)
if spec is None or spec.loader is None:
    raise SystemExit(f"cannot load {STAGE}")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

args = sys.argv[1:]
flip = None
if args[:1] == ["--flip-one"]:
    flip, args = int(args[1]), args[2:]
path = Path(args[0])
verdict = stage.aee_decide({"id": path.stem, "file": path.name}, path.parent, [])["verdict"]
valid = verdict == "valid"
if flip is not None and path.stem.endswith(f"-m{flip:06d}"):
    valid = not valid
sys.exit(0 if valid else 1)
