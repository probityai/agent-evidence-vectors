"""Prepare only this experiment's exact public read-only input checkouts."""

import subprocess
from pathlib import Path

from e030_case.regression import SOURCES, clean_environment, validate_sources

URLS = {
    "review": "https://github.com/altrudev/Frequency-Federation-Review.git",
    "aps": "https://github.com/aeoess/agent-passport-system.git",
    "priorseal": "https://github.com/imokokok/PriorSeal.git",
}


def main():
    """Clone into this owned preparation; never clean or reset another checkout."""
    base = Path(__file__).resolve().parents[1] / ".inputs"
    base.mkdir(exist_ok=True)
    env = clean_environment()
    for name, commit in SOURCES.items():
        destination = base / name
        if destination.exists():
            continue
        for argv in (
            ["git", "clone", "--filter=blob:none", "--no-checkout", URLS[name], str(destination)],
            ["git", "-C", str(destination), "fetch", "--depth=1", "origin", commit],
            ["git", "-C", str(destination), "checkout", "--detach", commit],
        ):
            print("INPUT_COMMAND", argv, flush=True)
            subprocess.run(argv, env=env, check=True, timeout=180)
    validate_sources({name: (base / name).resolve() for name in SOURCES})


if __name__ == "__main__":
    main()
