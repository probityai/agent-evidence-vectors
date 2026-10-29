"""Retain actual unittest counts and named outcomes from installed commands."""
import json
import os
import sys
import unittest
from pathlib import Path
from typing import cast


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records: list[dict[str, str]] = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"id": test.id(), "status": "pass"})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append({"id": test.id(), "status": "failure", "detail": self._exc_info_to_string(err, test)})  # pyright: ignore[reportAttributeAccessIssue]  # private CPython API, absent from the stubs

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append({"id": test.id(), "status": "error", "detail": self._exc_info_to_string(err, test)})  # pyright: ignore[reportAttributeAccessIssue]  # private CPython API, absent from the stubs

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.records.append({"id": test.id(), "status": "skip", "reason": reason})


suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_reader.py")
result = cast(RecordedResult, unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite))
Path(os.environ["MINTID_CONTROL_RESULTS"]).write_text(json.dumps({"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skips": len(result.skipped), "records": result.records}, indent=2) + "\n")
sys.exit(0 if result.wasSuccessful() and result.testsRun == 89 and not result.skipped else 1)
