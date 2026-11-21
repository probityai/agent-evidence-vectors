"""Judge what one fetch of a Web Bot Auth key directory says, and what it does not.

A verifier that meets a signed request resolves the Signature-Agent URL to a
JWK Set and selects the key by ``keyid``. The fetch can end five ways: a
directory that lists the key, a directory that does not, a redirect, an error
status or transport failure, or a response that is not a directory at all. The
protocol (draft-ietf-webbotauth-httpsig-protocol-01, Sections 5.5, 5.5.1 and
6.10) gives them two different meanings for the verifier's cache, and that is
the property this suite measures:

- a directory that resolves is evidence. It replaces whatever the verifier
  held for that URL, so a key removed from it, or an empty key set served on
  purpose, stops verifying (Section 6.10, second paragraph);
- a fetch that fails, a redirect, a 404 and a page that is not a directory are
  not evidence. They MUST NOT evict a cached entry, or an operator's outage
  revokes its keys at every verifier at once (Section 6.10).

A verifier that reads a 404, a 503 or an HTML error page served with 200 as
"the keys were removed" gets the second half wrong; one that keeps a key the
directory stopped listing gets the first half wrong. Every case in the corpus
pins both the decision for the request in hand and the cache the verifier
holds afterwards, so either mistake is caught.

The reader checks in a fixed order and names the first that fails:

1. the fetch was not answered by a redirect (``redirect_not_followed``,
   Section 5.5: a verifier MUST NOT automatically follow redirects);
2. the fetch completed with status 200 (``discovery_failed``, Section 5.5:
   every other status, and every transport failure, is a discovery failure);
3. the response is a directory: at the well-known URI it carries the media
   type ``application/http-message-signatures-directory+json``, and it parses
   as a JWK Set with a ``keys`` array (``not_a_directory``, Section 5.5.1);
4. no entry for the key is dropped as malformed: at the well-known URI a
   ``kid``, when present, MUST be the RFC 7638 thumbprint of its key
   (``kid_not_thumbprint``, Section 5.5);
5. the directory lists the key ``keyid`` names (``key_absent_from_directory``).

The first three leave the cache as it was; the last two replace it with the
directory's well-formed keys. A request that passes all five is ``attributed``
with reason ``key_in_directory``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision``, ``reason``, ``cache`` and
``cacheAfter``, and exits 0 for ``attributed`` and 1 for ``not_attributed``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shlex
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agent_evidence_vectors import strictjson

SUITE = "web-bot-auth-key-directory-observation/v1"
ATTRIBUTED, NOT_ATTRIBUTED = "attributed", "not_attributed"
EXIT_FOR = {ATTRIBUTED: 0, NOT_ATTRIBUTED: 1}
REPLACED, KEPT = "replaced", "kept"
WELL_KNOWN_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "redirect_not_followed",
    "discovery_failed",
    "not_a_directory",
    "kid_not_thumbprint",
    "key_absent_from_directory",
)
# A failure of one of these says nothing about the keys, so the cache stays.
NOT_EVIDENCE = frozenset({"redirect_not_followed", "discovery_failed", "not_a_directory"})
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-key-directory-observation" if
        (_HERE / "corpora").exists() else
        _HERE.parents[1] / "corpora" / "vectors-key-directory-observation")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict[str, Any]) -> str | None:
    """The RFC 7638 SHA-256 thumbprint of an OKP Ed25519 JWK, or None for any other key."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
        return None
    try:
        raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    except ValueError:
        return None
    if len(raw) != 32 or _b64url(raw) != jwk["x"]:
        return None
    member = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": jwk["x"]},
                        separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(member.encode()).digest())


def at_well_known(url: str) -> bool:
    """Whether a directory URL is the registered well-known URI (the query is not part of it)."""
    parts = urlsplit(url)
    return parts.scheme == "https" and parts.path == WELL_KNOWN_PATH


@dataclass(frozen=True)
class _Case:
    url: str
    keyid: str
    cached: tuple[str, ...]
    outcome: str
    status: int | None
    media_type: str | None
    body: bytes | None

    def keys(self) -> list[dict[str, Any]] | None:
        """The ``keys`` array of the response body, or None when it is not a JWK Set."""
        if self.body is None:
            return None
        try:
            parsed = strictjson.loads(self.body)
        except ValueError:
            return None
        if not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), list):
            return None
        return [k for k in parsed["keys"] if isinstance(k, dict)]

    def entries(self) -> list[tuple[str, bool]]:
        """(thumbprint, well formed) for every Ed25519 entry the directory lists."""
        found = []
        for jwk in self.keys() or []:
            thumb = jwk_thumbprint(jwk)
            if thumb is None:
                continue
            ok = not (at_well_known(self.url) and "kid" in jwk and jwk["kid"] != thumb)
            found.append((thumb, ok))
        return found


def _load(case_path: Path) -> _Case:
    case = strictjson.loads(case_path.read_text(encoding="utf-8"))
    fetch = case["fetch"]
    body = None
    if fetch.get("body") is not None:
        body = (case_path.parent / fetch["body"]).read_bytes()
    return _Case(str(case["directoryUrl"]), str(case["keyid"]), tuple(case.get("cached", [])),
                 str(fetch["outcome"]), fetch.get("status"), fetch.get("mediaType"), body)


def _first_failure(c: _Case, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the observation fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    answered = c.outcome == "response" and c.status is not None
    failures: dict[str, Callable[[], bool]] = {
        "redirect_not_followed": lambda: answered and 300 <= int(c.status or 0) < 400,
        "discovery_failed": lambda: not answered or c.status != 200,
        "not_a_directory": lambda: c.keys() is None or (
            at_well_known(c.url) and c.media_type != DIRECTORY_MEDIA_TYPE),
        "kid_not_thumbprint": lambda: any(t == c.keyid and not ok for t, ok in c.entries()),
        "key_absent_from_directory": lambda: c.keyid not in {t for t, ok in c.entries() if ok},
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, Any]:
    """The reference reader's decision, reason and the cache it leaves, for one case."""
    c = _load(case_path)
    failure = _first_failure(c, skip)
    if failure in NOT_EVIDENCE:
        return {"decision": NOT_ATTRIBUTED, "reason": failure, "cache": KEPT,
                "cacheAfter": sorted(c.cached)}
    after = sorted({t for t, ok in c.entries() if ok})
    if failure is not None:
        return {"decision": NOT_ATTRIBUTED, "reason": failure, "cache": REPLACED,
                "cacheAfter": after}
    return {"decision": ATTRIBUTED, "reason": "key_in_directory", "cache": REPLACED,
            "cacheAfter": after}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = strictjson.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


_ANSWER_KEYS = ("decision", "reason", "cache", "cacheAfter")


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
        observed = {key: answer[key] for key in _ANSWER_KEYS}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every case, through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement.
    """
    try:
        entries, manifest_error = _validated_entries(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        case_path = directory / "case.json"
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(case_path, skip)
        else:
            ran, observed = _external_answer(command, case_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = strictjson.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the answer as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']} cache {answer['cache']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
