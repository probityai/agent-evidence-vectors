"""Generate the FDC3 intent-result cases, the derived schema set and the manifest.

The two upstream schema sets under ``schema-sets/`` are vendored byte for byte
by ``vendor.py`` and are inputs here, never outputs. This script derives the
third set (``optional-error``) from ``proposed-oneof``, writes every case, and
writes ``MANIFEST.json`` with the pins of every schema file and every case.

Run from the repository root: ``python3 vectors-fdc3-intent-result/gen_vectors.py``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SUITE = "fdc3-intent-result-error/v1"
ISSUE = "https://github.com/finos/FDC3/issues/2271"
ALTERNATIVE = "https://github.com/finos/FDC3/issues/2271#issuecomment-6194982724"
API = "packages/fdc3-schema/schemas/api"
CONTEXT = "packages/fdc3-context/schemas/context"
# The files the two message schemas reach through $ref, and no others.
CLOSURE = (
    f"{API}/agentResponse.schema.json",
    f"{API}/api.schema.json",
    f"{API}/appRequest.schema.json",
    f"{API}/common.schema.json",
    f"{API}/intentResultRequest.schema.json",
    f"{API}/raiseIntentResultResponse.schema.json",
    f"{CONTEXT}/context.schema.json",
)
UPSTREAM = {
    "fdc3-39505b1": {
        "repository": "https://github.com/finos/FDC3",
        "commit": "39505b1efa72c8772de762c170bf442fbb1f639b",
        "status": "upstream",
        "note": "The FDC3 schemas at the commit issue #2271 cites.",
    },
}
DERIVED = {
    "proposed-oneof": {
        "derivedFrom": "fdc3-39505b1",
        "status": "proposal",
        "note": ("fdc3-39505b1 with two files edited by hand: intentResultRequest's payload "
                 "is intentResult or error (a ResultError), never both, as the FDC3 "
                 "maintainers asked; agentResponse's success branch no longer also matches "
                 "an error payload. The other five files are byte-identical to "
                 "fdc3-39505b1."),
    },
    "optional-error": {
        "derivedFrom": "proposed-oneof",
        "status": "counterfactual",
        "note": ("proposed-oneof with intentResultRequest's payload reverted to a single "
                 "object that keeps intentResult required and gains error as an optional "
                 "property: the first option issue #2271 lists. Nobody proposes it; it "
                 "shows that a failed handler can then only be reported as a void result "
                 "plus an error, which is the payload the maintainers ruled out."),
    },
}
SETS = ("fdc3-39505b1", "optional-error", "proposed-oneof")
# The sets generate() writes; every other set is an input committed by hand or by vendor.py.
GENERATED = ("optional-error",)
A, R = "accepted", "rejected"


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324


def optional_error_schema(proposed: dict[str, Any]) -> dict[str, Any]:
    """The proposal's intentResultRequest with the payload as one object whose
    ``error`` is merely optional."""
    schema = copy.deepcopy(proposed)
    defs = schema["$defs"]
    payload = copy.deepcopy(defs["IntentResultRequestSuccessPayload"])
    payload["title"] = "IntentResult Request Payload"
    payload["properties"]["error"] = {"$ref": "api.schema.json#/definitions/ResultError"}
    defs["IntentResultRequestPayload"] = payload
    del defs["IntentResultRequestSuccessPayload"]
    del defs["IntentResultRequestErrorPayload"]
    return schema


# ----------------------------------------------------------------------------
# messages

CONTEXT_RESULT = {"type": "fdc3.instrument", "name": "Apple", "id": {"ticker": "AAPL"}}


def _request(payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": "intentResultRequest",
            "meta": {"requestUuid": "event-0001", "timestamp": "2026-10-21T12:00:01.000Z"},
            "payload": {"intentEventUuid": "event-0001",
                        "raiseIntentRequestUuid": "raise-0001", **payload}}


def _response(payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": "raiseIntentResultResponse",
            "meta": {"requestUuid": "raise-0001", "responseUuid": "response-0002",
                     "timestamp": "2026-10-21T12:00:01.050Z"},
            "payload": payload}


RESULT_METADATA = {"source": {"appId": "app-b", "instanceId": "app-b-1"},
                   "timestamp": "2026-10-21T12:00:01.050Z", "traceId": "trace-0001"}
HANDLER_REJECTED = "IntentHandlerRejected"


def _proxy(message: dict[str, Any], step: int) -> dict[str, Any]:
    return {"step": step, "from": "agent proxy of the resolving app",
            "to": "Desktop Agent", "message": message}


def _agent(message: dict[str, Any], step: int) -> dict[str, Any]:
    return {"step": step, "from": "Desktop Agent", "to": "agent proxy of the raising app",
            "message": message}


def _v(*verdicts: tuple[str, list[int]]) -> dict[str, dict[str, Any]]:
    return {name: {"decision": d, "rejectedSteps": steps}
            for name, (d, steps) in zip(SETS, verdicts, strict=True)}


def members() -> list[dict[str, Any]]:
    """Every case: its sequence, the verdict per schema set, and what it forces."""
    failed = [
        _proxy(_request({"error": HANDLER_REJECTED}), 1),
        _agent(_response({"error": HANDLER_REJECTED}), 2),
    ]
    return [
        {"id": "handler-resolves-context",
         "trigger": "the intent handler resolves with a context",
         "sequence": [
             _proxy(_request({"intentResult": {"context": CONTEXT_RESULT}}), 1),
             _agent(_response({"intentResult": {"context": CONTEXT_RESULT},
                               "resultMetadata": RESULT_METADATA}), 2)],
         "expected": _v((A, []), (A, []), (A, [])),
         "rule": "a result travels as intentResult on both legs; no schema set may refuse it"},
        {"id": "handler-resolves-void",
         "trigger": "the intent handler resolves with no result",
         "sequence": [
             _proxy(_request({"intentResult": {}}), 1),
             _agent(_response({"intentResult": {}, "resultMetadata": RESULT_METADATA}), 2)],
         "expected": _v((A, []), (A, []), (A, [])),
         "rule": ("a void result is an empty intentResult. At 39505b1 it is also the only "
                  "thing a proxy can send for a failed handler, and the raising app then "
                  "reads the failure as success")},
        {"id": "handler-throws",
         "trigger": "the intent handler throws synchronously",
         "sequence": copy.deepcopy(failed),
         "expected": _v((R, [1, 2]), (R, [1]), (A, [])),
         "rule": ("getResult() must reject with IntentHandlerRejected (Types.md, getResult). "
                  "At 39505b1 neither leg can say so: intentResultRequest refuses error, and "
                  "an error payload on raiseIntentResultResponse matches both branches of "
                  "agentResponse's payload oneOf")},
        {"id": "handler-returns-rejected-promise",
         "trigger": "the intent handler returns a rejected Promise",
         "sequence": copy.deepcopy(failed),
         "expected": _v((R, [1, 2]), (R, [1]), (A, [])),
         "rule": ("the same two messages as a synchronous throw: the API gives both the same "
                  "ResultError, so the wire does not tell them apart")},
        {"id": "proxy-reports-handler-error",
         "trigger": "the proxy reports the failure to the Desktop Agent",
         "sequence": [_proxy(_request({"error": HANDLER_REJECTED}), 1)],
         "expected": _v((R, [1]), (R, [1]), (A, [])),
         "rule": ("intentResultRequest needs a way to carry the handler's ResultError; at "
                  "39505b1 it requires intentResult and sets additionalProperties false")},
        {"id": "agent-forwards-result-error",
         "trigger": "the Desktop Agent forwards the ResultError to the raising app",
         "sequence": [_agent(_response({"error": HANDLER_REJECTED}), 1)],
         "expected": _v((R, [1]), (A, []), (A, [])),
         "rule": ("raiseIntentResultResponse declares an error alternative, but at 39505b1 "
                  "agentResponse's payload oneOf has a branch that admits any object, so an "
                  "error payload matches two branches and draft-07 refuses it")},
        {"id": "both-result-and-error",
         "trigger": "the proxy sends a result and an error in one payload",
         "sequence": [_proxy(_request({"intentResult": {}, "error": HANDLER_REJECTED}), 1)],
         "expected": _v((R, [1]), (A, []), (R, [1])),
         "rule": ("the error is an alternative to intentResult, one or the other and never "
                  "both, as the maintainers asked. With error merely optional beside a "
                  "required intentResult, this is the only way a failed handler can be "
                  "reported, and the raising app cannot tell it from a void result")},
        {"id": "neither-result-nor-error",
         "trigger": "the proxy sends neither a result nor an error",
         "sequence": [_proxy(_request({}), 1)],
         "expected": _v((R, [1]), (R, [1]), (R, [1])),
         "rule": "a payload must carry exactly one of intentResult and error"},
        {"id": "error-with-app-metadata",
         "trigger": "the proxy sends app-provided metadata with an error",
         "sequence": [_proxy(_request({"error": HANDLER_REJECTED,
                                       "metadata": {"traceId": "trace-0001"}}), 1)],
         "expected": _v((R, [1]), (R, [1]), (R, [1])),
         "rule": ("metadata accompanies a context result (ContextWithMetadata); a failed "
                  "handler returned none, so the proposal carries no metadata with an error")},
        {"id": "error-is-not-a-result-error",
         "trigger": "the proxy reports an error that is not a ResultError",
         "sequence": [_proxy(_request({"error": "NoAppsFound"}), 1)],
         "expected": _v((R, [1]), (R, [1]), (R, [1])),
         "rule": ("a handler failure is a ResultError; NoAppsFound is a ResolveError, which "
                  "only the Desktop Agent's resolution can produce")},
        {"id": "agent-sends-result-and-error",
         "trigger": "the Desktop Agent sends a result and an error in one payload",
         "sequence": [_agent(_response({"intentResult": {}, "error": HANDLER_REJECTED,
                                        "resultMetadata": RESULT_METADATA}), 1)],
         "expected": _v((R, [1]), (R, [1]), (R, [1])),
         "rule": ("raiseIntentResultResponse already makes result and error alternatives; "
                  "the proposal gives intentResultRequest the same shape")},
    ]


# ----------------------------------------------------------------------------
# output

def _pins(base: Path, source: dict[str, Any] | None) -> dict[str, Any]:
    files: dict[str, Any] = {}
    for rel in CLOSURE:
        data = (base / rel).read_bytes()
        pin: dict[str, Any] = {"sha256": hashlib.sha256(data).hexdigest(),
                               "gitBlob": _git_blob(data)}
        if source is not None:
            pin["url"] = (source["repository"].replace("https://github.com/",
                                                       "https://raw.githubusercontent.com/")
                          + f"/{source['commit']}/{rel}")
        files[rel] = pin
    return files


def generate(target: Path = HERE) -> None:
    sets = target / "schema-sets"
    derived = sets / "optional-error"
    if derived.exists():
        shutil.rmtree(derived)
    proposed_root = sets / "proposed-oneof"
    for rel in CLOSURE:
        out = derived / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith("intentResultRequest.schema.json"):
            proposed = json.loads((proposed_root / rel).read_text(encoding="utf-8"))
            out.write_bytes(_json(optional_error_schema(proposed)))
        else:
            out.write_bytes((proposed_root / rel).read_bytes())
    schema_sets: dict[str, Any] = {}
    for name in SETS:
        upstream = UPSTREAM.get(name)
        meta = dict(upstream) if upstream is not None else dict(DERIVED[name])
        schema_sets[name] = {**meta, "files": _pins(sets / name, upstream)}

    cases = target / "cases"
    if cases.exists():
        shutil.rmtree(cases)
    vectors = []
    for member in members():
        directory = cases / member["id"]
        directory.mkdir(parents=True)
        data = _json({"id": member["id"], "trigger": member["trigger"],
                      "sequence": member["sequence"]})
        (directory / "case.json").write_bytes(data)
        vectors.append({
            "id": member["id"],
            "path": f"cases/{member['id']}",
            "files": {"case.json": hashlib.sha256(data).hexdigest()},
            "expected": member["expected"],
            "rule": member["rule"],
        })
    manifest = {
        "suite": SUITE,
        "specification": {
            "document": "DACP intentResultRequest and raiseIntentResultResponse schemas",
            "issue": ISSUE,
            "maintainerRequirement": ALTERNATIVE,
            "bytes": ("fdc3-39505b1 is upstream's as vendored; proposed-oneof is a proposed "
                      "edit of it; optional-error is derived here"),
        },
        "schemaSets": schema_sets,
        "corpusDigest": hashlib.sha256(_json({"schemaSets": schema_sets,
                                              "vectors": vectors})).hexdigest(),
        "vectors": vectors,
    }
    (target / "MANIFEST.json").write_bytes(_json(manifest))


if __name__ == "__main__":
    generate(Path(sys.argv[1]) if len(sys.argv) > 1 else HERE)
