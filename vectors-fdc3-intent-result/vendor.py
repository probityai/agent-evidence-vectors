"""Vendor the upstream FDC3 schema sets byte for byte, or check the vendored copies.

    python3 vectors-fdc3-intent-result/vendor.py          # fetch every upstream set
    python3 vectors-fdc3-intent-result/vendor.py --check  # refetch and compare

Each file is fetched from the commit its set pins in ``gen_vectors.UPSTREAM``,
so the bytes are upstream's and not a copy of anyone's working tree. The check
mode exits 1 on the first file whose committed bytes differ from the commit's.
After vendoring, run ``gen_vectors.py`` to re-pin the manifest.
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_vectors import CLOSURE, HERE, UPSTREAM  # noqa: E402


def _url(source: dict[str, str], rel: str) -> str:
    raw = source["repository"].replace("https://github.com/", "https://raw.githubusercontent.com/")
    return f"{raw}/{source['commit']}/{rel}"


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
        data: bytes = response.read()
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="compare the committed files with the pinned commits")
    args = parser.parse_args(argv)
    for name, source in UPSTREAM.items():
        for rel in CLOSURE:
            data = _fetch(_url(source, rel))
            path = HERE / "schema-sets" / name / rel
            if args.check:
                if path.read_bytes() != data:
                    print(f"DIFFERS {name}/{rel}: committed bytes are not {source['commit']}'s")
                    return 1
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print("checked" if args.check else "vendored",
          sum(len(CLOSURE) for _ in UPSTREAM), "files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
