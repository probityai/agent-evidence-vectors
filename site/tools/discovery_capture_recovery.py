"""Read-only recovery supplements and explicitly reviewed local public exports.

Recovery observes process identity, not exit code or end time. Public reports
exclude prompts, responses, metadata values, native errors and runtime settings.
No operation in this module contacts a service or publishes files.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlsplit

import discovery_capture_journal as custody


def identity_status(recorded, read_identity=custody.read_process_identity):
    if recorded is None or recorded["boot_id"] is None or recorded["start_ticks"] is None:
        return "unknown"
    try:
        current = read_identity(recorded["pid"])
    except FileNotFoundError as error:
        return "not_original_identity" if error.filename == f"/proc/{recorded['pid']}/stat" else "unknown"
    except (OSError, ValueError, IndexError):
        return "unknown"
    if current["boot_id"] is None:
        return "unknown"
    if current["boot_id"] != recorded["boot_id"] or current["start_ticks"] != recorded["start_ticks"]:
        if current["boot_id"] == recorded["boot_id"] and current["start_ticks"] is None:
            return "unknown"
        return "not_original_identity"
    return "identity_present"


def recover(directory, output, read_identity=custody.read_process_identity):
    directory = Path(directory)
    custody.require(not Path(output).resolve().is_relative_to(directory.resolve()), "recovery supplement must be outside original capture")
    with custody.attempt_lock(directory, shared=True):
        record = custody.derive_record(directory)
        rows, _ = custody.read_journal(directory)
        identities = [row["facts"] for row in rows if row["kind"] == "launched"]
        supplement = {"schema_version": 2, "kind": "recovery_supplement",
                      "checked_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                      "original_process_identity": identity_status(identities[0] if identities else None, read_identity),
                      "record": record,
                      "limits": "Identity presence can include a zombie. Identity absence does not prove an exit code or end time. Unobserved retained bytes have unknown original durability and observation time."}
        custody.exclusive_write(Path(output), custody.canonical(supplement))
        return supplement


def approved_pages(manifest_path, page_root):
    """Validate all selected bytes before creating any public copy."""
    manifest = custody.strict_json(custody.read_small(manifest_path))
    custody.require(isinstance(manifest, dict) and set(manifest) == {"schema_version", "reviewed", "pages"}
                    and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and manifest["reviewed"] is True,
                    "an explicit reviewed page manifest is required")
    pages = manifest["pages"]
    custody.require(isinstance(pages, list) and len(pages) <= 256, "invalid approved page list")
    root = Path(page_root)
    custody.require(root.is_dir() and not root.is_symlink(), "page root must be a real directory")
    approved, names, total = [], set(), 0
    for page in pages:
        custody.require(isinstance(page, dict) and set(page) == {"path", "sha256", "bytes", "url", "output_name"}, "approved page fields differ")
        name, relative = page["output_name"], page["path"]
        custody.require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) and name not in names, "invalid or duplicate public page name")
        custody.require(isinstance(relative, str) and relative and "\\" not in relative and "\x00" not in relative,
                        "page path must be a relative POSIX path")
        parts = PurePosixPath(relative).parts
        custody.require(not PurePosixPath(relative).is_absolute() and relative == PurePosixPath(relative).as_posix()
                        and all(part not in {"..", "."} for part in parts), "page path escapes its root or is not canonical")
        path = root
        for part in parts:
            path = path / part
            custody.require(not path.is_symlink(), "page path contains a symlink")
        custody.require(type(page["bytes"]) is int and 0 <= page["bytes"] <= custody.PARSE_LIMIT, "approved page exceeds export budget")
        total += page["bytes"]
        custody.require(total <= custody.JSON_LIMIT, "approved pages exceed total export budget")
        custody.require(isinstance(page["url"], str) and not any(character.isspace() for character in page["url"]), "invalid declared page URL")
        url = urlsplit(page["url"])
        custody.require(url.scheme == "https" and url.hostname and url.username is None and url.password is None, "approved page needs a credential-free HTTPS URL")
        data = custody.read_small(path, custody.PARSE_LIMIT)
        custody.require(len(data) == page["bytes"] and custody.digest(data) == page["sha256"], "approved page bytes differ")
        names.add(name)
        approved.append((page, data))
    return approved


def public_report(record):
    """All fields are explicit; no raw error or arbitrary event type is copied."""
    from jsonschema import Draft202012Validator
    from discovery_capture_v2 import schema
    custody.require(next(Draft202012Validator(schema()).iter_errors(record), None) is None,
                    "public export requires a closed receiver record")
    return {"schema_version": 2, "kind": "public_receiver_summary", "attempt": record["attempt"],
            "scope": "PEER: retained local bytes and same-author receiver observations. No independent operation, outside adoption, blinding or discovery acceptance is established.",
            "clock_semantics": "UTC is sampled receiver observation time. Monotonic values order one receiver_clock_id; journal sequence orders writer epochs. Unobserved retained bytes have unknown original durability and observation time.",
            "driver_closure_semantics": "Driver closure records durable capture-loop closure. It does not prove projection publication or an operating-system driver exit code.",
            "retained_bytes": {key: record["sources"][key] for key in ("native_events", "stderr", "journal")},
            "journal_partial_tail": record["journal_partial_tail"],
            "events": [{"offset": event["offset"], "length": event["length"], "sha256": event["sha256"],
                        "parse_state": event["parse_state"], "category": event["event_type"] if event["event_type"] in custody.EVENT_CATEGORIES else "other",
                        "observation": event["observation"]} for event in record["events"]],
            "response": record["response"],
            "response_semantics": "State describes retained response evidence, not proof that the client produced no other answer. Native event text is distinct from optional native output-file bytes. Multiple captures do not choose a final answer.",
            "contract": {key: record["contract"][key] for key in ("origin", "state", "metadata", "refusal", "observation")},
            "contract_semantics": "supplied_metadata validates a caller-supplied grammar. It does not establish native answer equality or correctness.",
            "native_closure": record["native_closure"], "driver_closure": record["driver_closure"]}


def export_public(record, output, approval_manifest=None, page_root=None):
    output = Path(output)
    custody.require(not output.exists() and not output.is_symlink(), "public output must be new")
    custody.require((approval_manifest is None) == (page_root is None), "page approval needs an explicit page root")
    approved = approved_pages(approval_manifest, page_root) if approval_manifest is not None else []
    report = public_report(record)
    report["approved_pages"] = []
    if approved:
        pages_directory = output.with_name(output.name + ".pages")
        pages_directory.mkdir(mode=0o700)
        custody.sync_directory(pages_directory.parent)
        for page, data in approved:
            custody.exclusive_write(pages_directory / page["output_name"], data)
            report["approved_pages"].append({key: page[key] for key in ("output_name", "sha256", "bytes", "url")})
    custody.exclusive_write(output, custody.canonical(report))
    return report
