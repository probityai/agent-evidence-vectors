"""Retain actual unittest counts and named outcomes from installed commands."""
import json
import os
import sys
import unittest
from pathlib import Path


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"id": test.id(), "status": "pass"})

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.records.append({"id": test.id(), "status": "failure", "detail": self._exc_info_to_string(error, test)})

    def addError(self, test, error):
        super().addError(test, error)
        self.records.append({"id": test.id(), "status": "error", "detail": self._exc_info_to_string(error, test)})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.records.append({"id": test.id(), "status": "skip", "reason": reason})


suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_reader.py")
result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
Path(os.environ["MINTID_CONTROL_RESULTS"]).write_text(json.dumps({"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skips": len(result.skipped), "records": result.records}, indent=2) + "\n")
sys.exit(0 if result.wasSuccessful() and result.testsRun == 89 and not result.skipped else 1)
