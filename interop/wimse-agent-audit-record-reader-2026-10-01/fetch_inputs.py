#!/usr/bin/env python3
"""Fetch the two pinned repositories into an isolated reproduction directory."""

import hashlib
import json
from pathlib import Path
from urllib.request import urlopen


HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "INPUTS.json").read_text())


def fetch(kind):
    pin = PINS[kind]
    target = HERE / ".build" / kind
    for name, expected in pin["sha256"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"invalid path: {name}")
        url = f"https://raw.githubusercontent.com/{pin['repo']}/{pin['commit']}/{name}"
        with urlopen(url, timeout=30) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"source changed: {kind}/{name}")
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(f"{kind}: {len(pin['sha256'])} pinned files")


if __name__ == "__main__":
    fetch("reader")
    fetch("corpus")
