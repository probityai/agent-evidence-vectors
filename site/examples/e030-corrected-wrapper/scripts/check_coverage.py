#!/usr/bin/env python3
"""Check per-file test coverage against threshold.

This script runs pytest with coverage and reports files below the threshold.
Unlike pytest-cov's --fail-under which checks aggregate coverage, this script
enforces the per-file coverage requirement.

Usage:
    python scripts/check_coverage.py --src-dir src/mypackage              # Default 80% threshold
    python scripts/check_coverage.py --src-dir src/mypackage --threshold 90    # Custom threshold
    python scripts/check_coverage.py --src-dir src/mypackage --json            # Output JSON for CI
    python scripts/check_coverage.py --src-dir src/mypackage --summary         # Package-level summary

Exit codes:
    0: All files meet coverage threshold
    1: Some files below threshold
    2: Error running coverage

Example output:
    === Coverage Report (threshold: 80%) ===

    54 files below 80% coverage:

    EXTRACTION (25 files):
      extraction/entities/extractor.py                    28.81%
      extraction/entities/registry.py                     53.85%
      ...

    MODELS (12 files):
      models/ontology.py                                   7.09%
      ...
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class FileCoverage:
    """Coverage data for a single file."""

    path: str
    covered_lines: int
    total_lines: int
    percent: float
    base_path: str
    missing_lines: list[int] = field(default_factory=list)

    @property
    def package(self) -> str:
        """Extract package name from path.

        Example:
            >>> fc = FileCoverage('src/mypackage/validation/base.py', 45, 45, 100.0, 'src/mypackage/')
            >>> fc.package
            'validation'
        """
        parts = self.path.replace(self.base_path, "").split("/")
        return parts[0] if parts else "unknown"

    @property
    def relative_path(self) -> str:
        """Path relative to base_path.

        Example:
            >>> fc = FileCoverage('src/mypackage/validation/base.py', 45, 45, 100.0, 'src/mypackage/')
            >>> fc.relative_path
            'validation/base.py'
        """
        return self.path.replace(self.base_path, "")


@dataclass
class CoverageReport:
    """Aggregated coverage report."""

    files: list[FileCoverage]
    threshold: float

    @property
    def files_below_threshold(self) -> list[FileCoverage]:
        """Files that don't meet the coverage threshold."""
        return [f for f in self.files if f.percent < self.threshold]

    @property
    def files_meeting_threshold(self) -> list[FileCoverage]:
        """Files that meet or exceed the coverage threshold."""
        return [f for f in self.files if f.percent >= self.threshold]

    @property
    def by_package(self) -> dict[str, list[FileCoverage]]:
        """Group files below threshold by package."""
        grouped: dict[str, list[FileCoverage]] = defaultdict(list)
        for f in self.files_below_threshold:
            grouped[f.package].append(f)
        # Sort files within each package by coverage (lowest first)
        for pkg in grouped:
            grouped[pkg].sort(key=lambda x: x.percent)
        return dict(grouped)

    @property
    def aggregate_coverage(self) -> float:
        """Calculate aggregate coverage across all files."""
        total_covered = sum(f.covered_lines for f in self.files)
        total_lines = sum(f.total_lines for f in self.files)
        return (total_covered / total_lines * 100) if total_lines > 0 else 0.0


def run_coverage(test_path: str, src_dir: str) -> Optional[dict[str, Any]]:
    """Run pytest with JSON coverage output.

    Args:
        test_path: Path to test directory
        src_dir: Source directory to measure coverage for

    Returns:
        Parsed coverage JSON data, or None if error

    """
    # Start the tracer before pytest imports plugins and test modules.
    coverage_json = Path(".coverage.json")

    # Clean up old coverage data + any parallel-mode shards from a
    # prior aborted run.
    for old_file in [coverage_json, Path(".coverage")]:
        if old_file.exists():
            old_file.unlink()
    for shard in Path().glob(".coverage.*"):
        shard.unlink()

    # Step 1: coverage run -m pytest
    run_cmd = [
        "coverage",
        "run",
        "-m",
        "pytest",
        test_path,
        "-q",  # Quiet mode
        "--tb=no",  # No tracebacks
    ]
    print("Running pytest under coverage...", file=sys.stderr)
    run_result = subprocess.run(run_cmd, capture_output=True, text=True)
    if run_result.returncode:
        print(f"Error: pytest exited {run_result.returncode}", file=sys.stderr)
        print(f"run stdout: {run_result.stdout}", file=sys.stderr)
        print(f"run stderr: {run_result.stderr}", file=sys.stderr)
        return None

    # Step 2: coverage combine (no-op if not parallel; harmless to always run)
    combine_result = subprocess.run(
        ["coverage", "combine"],
        capture_output=True,
        text=True,
    )

    # Step 3: coverage json
    json_result = subprocess.run(
        ["coverage", "json", "-o", str(coverage_json), f"--include={src_dir}/*"],
        capture_output=True,
        text=True,
    )

    if json_result.returncode or not coverage_json.exists():
        print(
            f"Error: Coverage JSON not generated successfully (exit {json_result.returncode})",
            file=sys.stderr,
        )
        print(f"run stdout: {run_result.stdout}", file=sys.stderr)
        print(f"run stderr: {run_result.stderr}", file=sys.stderr)
        print(f"combine stderr: {combine_result.stderr}", file=sys.stderr)
        print(f"json stderr: {json_result.stderr}", file=sys.stderr)
        return None

    with open(coverage_json) as json_file:
        data: dict[str, Any] = json.load(json_file)

    # Clean up
    coverage_json.unlink()

    return data


def parse_coverage_data(data: dict[str, Any], src_dir: str) -> list[FileCoverage]:
    """Parse coverage JSON into FileCoverage objects.

    Args:
        data: Raw coverage JSON data
        src_dir: Source directory to filter for

    Returns:
        List of FileCoverage objects for files in src_dir
    """
    files = []

    # Normalize src_dir to ensure it ends with /
    base_path = src_dir if src_dir.endswith("/") else f"{src_dir}/"

    for filepath, file_data in data.get("files", {}).items():
        # Only include files from src_dir, exclude __init__.py
        if not filepath.startswith(base_path):
            continue
        if filepath.endswith("__init__.py"):
            continue

        summary = file_data.get("summary", {})
        covered = summary.get("covered_lines", 0)
        total = summary.get("num_statements", 0)
        percent = summary.get("percent_covered", 0.0)
        missing = file_data.get("missing_lines", [])

        files.append(
            FileCoverage(
                path=filepath,
                covered_lines=covered,
                total_lines=total,
                percent=percent,
                base_path=base_path,
                missing_lines=missing,
            )
        )

    return files


def format_report(report: CoverageReport) -> str:
    """Format coverage report for terminal output.

    Args:
        report: CoverageReport to format

    Returns:
        Formatted string for terminal display
    """
    lines = []
    lines.append(f"=== Coverage Report (threshold: {report.threshold}%) ===")
    lines.append("")

    below = report.files_below_threshold
    meeting = report.files_meeting_threshold

    lines.append(f"Total files: {len(report.files)}")
    lines.append(f"Files at or above {report.threshold}%: {len(meeting)}")
    lines.append(f"Files below {report.threshold}%: {len(below)}")
    lines.append(f"Aggregate coverage: {report.aggregate_coverage:.2f}%")
    lines.append("")

    if not below:
        lines.append("All files meet coverage threshold!")
        return "\n".join(lines)

    lines.append(f"{len(below)} files below {report.threshold}% coverage:")
    lines.append("")

    # Group by package
    by_pkg = report.by_package
    # Sort packages by number of failing files (most first)
    sorted_pkgs = sorted(by_pkg.keys(), key=lambda p: -len(by_pkg[p]))

    for pkg in sorted_pkgs:
        pkg_files = by_pkg[pkg]
        lines.append(f"{pkg.upper()} ({len(pkg_files)} files):")
        for fc in pkg_files:
            # Right-align percentage
            lines.append(f"  {fc.relative_path:<55} {fc.percent:>6.2f}%")
        lines.append("")

    return "\n".join(lines)


def format_json(report: CoverageReport) -> str:
    """Format coverage report as JSON.

    Args:
        report: CoverageReport to format

    Returns:
        JSON string
    """
    output = {
        "threshold": report.threshold,
        "total_files": len(report.files),
        "files_passing": len(report.files_meeting_threshold),
        "files_failing": len(report.files_below_threshold),
        "aggregate_coverage": round(report.aggregate_coverage, 2),
        "passing": report.threshold <= report.aggregate_coverage
        and len(report.files_below_threshold) == 0,
        "files_below_threshold": [
            {
                "path": f.path,
                "package": f.package,
                "percent": round(f.percent, 2),
                "missing_lines": len(f.missing_lines),
            }
            for f in report.files_below_threshold
        ],
    }
    return json.dumps(output, indent=2)


def format_summary(report: CoverageReport) -> str:
    """Format package-level summary.

    Args:
        report: CoverageReport to format

    Returns:
        Formatted summary string
    """
    lines = []
    lines.append(f"=== Package Summary (threshold: {report.threshold}%) ===")
    lines.append("")

    # Group all files by package
    all_by_pkg: dict[str, list[FileCoverage]] = defaultdict(list)
    for f in report.files:
        all_by_pkg[f.package].append(f)

    # Calculate per-package stats
    pkg_stats = []
    for pkg, files in all_by_pkg.items():
        total = len(files)
        passing = sum(1 for f in files if f.percent >= report.threshold)
        failing = total - passing
        avg_cov = sum(f.percent for f in files) / total if total > 0 else 0
        pkg_stats.append((pkg, total, passing, failing, avg_cov))

    # Sort by failing count (most failing first)
    pkg_stats.sort(key=lambda x: (-x[3], x[0]))

    lines.append(f"{'Package':<20} {'Total':>6} {'Pass':>6} {'Fail':>6} {'Avg %':>8}")
    lines.append("-" * 50)

    for pkg, total, passing, failing, avg_cov in pkg_stats:
        status = "✅" if failing == 0 else "❌"
        lines.append(
            f"{pkg:<20} {total:>6} {passing:>6} {failing:>6} {avg_cov:>7.1f}% {status}"
        )

    lines.append("-" * 50)
    total_files = len(report.files)
    total_passing = len(report.files_meeting_threshold)
    total_failing = len(report.files_below_threshold)
    lines.append(
        f"{'TOTAL':<20} {total_files:>6} {total_passing:>6} {total_failing:>6} {report.aggregate_coverage:>7.1f}%"
    )

    return "\n".join(lines)


def main() -> int:
    """Main entry point.

    Returns:
        Exit code (0=success, 1=files below threshold, 2=error)
    """
    parser = argparse.ArgumentParser(
        description="Check per-file test coverage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--src-dir",
        required=True,
        help="Source directory to measure coverage for (e.g., src/mypackage)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=80.0,
        help="Coverage threshold percentage (default: 80)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON format (for CI)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show package-level summary only",
    )
    parser.add_argument(
        "--test-path",
        default="tests/unit/",
        help="Path to test directory (default: tests/unit/)",
    )

    args = parser.parse_args()

    # Run coverage
    data = run_coverage(args.test_path, args.src_dir)
    if data is None:
        return 2

    # Parse and analyze
    files = parse_coverage_data(data, args.src_dir)
    report = CoverageReport(files=files, threshold=args.threshold)

    # Output
    if args.json:
        print(format_json(report))
    elif args.summary:
        print(format_summary(report))
    else:
        print(format_report(report))

    # Exit code
    return 0 if len(report.files_below_threshold) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
