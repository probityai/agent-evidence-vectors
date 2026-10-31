"""Send the token request and the resource push to the Vanta API with the standard library."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from .payloads import RESOURCE_PATH, SCOPE, TOKEN_PATH

TIMEOUT_SECONDS = 30
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
MAX_ATTEMPTS = 3


class VantaError(RuntimeError):
    """A request failed, was refused, or came back with a rejection."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would resend the bearer token to a host nobody named."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def check_base(api_base: str) -> str:
    """Return the base URL, refusing plain http anywhere but loopback."""
    parts = urllib.parse.urlsplit(api_base)
    loopback = parts.hostname in LOOPBACK_HOSTS
    if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
        raise VantaError(f"api base {api_base!r} must be https (http is allowed on loopback only)")
    if not parts.hostname:
        raise VantaError(f"api base {api_base!r} names no host")
    return api_base.rstrip("/")


def _send(method: str, url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        snippet = error.read(300).decode("utf-8", "replace")
        raise _Status(error.code, f"{method} {url} answered {error.code}: {snippet}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise _Status(0, f"{method} {url} failed: {error}") from None
    try:
        parsed = json.loads(raw)
    except ValueError:
        raise VantaError(f"{method} {url} answered a body that is not JSON") from None
    if not isinstance(parsed, dict):
        raise VantaError(f"{method} {url} answered JSON that is not an object")
    return parsed


class _Status(VantaError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def request_token(api_base: str, client_id: str, client_secret: str) -> str:
    """Exchange client credentials for a one-hour access token (it revokes the previous one)."""
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": SCOPE,
        "grant_type": "client_credentials",
    }
    reply = _send("POST", api_base + TOKEN_PATH, {"Content-Type": "application/json"}, payload)
    token = reply.get("access_token")
    if not isinstance(token, str) or not token:
        raise VantaError("token reply carries no access_token")
    return token


def put_resources(
    api_base: str,
    token: str,
    body: dict[str, Any],
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, int]:
    """PUT the full resource state, retrying a throttled or failing server; return the counts.

    The PUT is idempotent on uniqueId, so a retry cannot duplicate a record.
    """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    last: VantaError | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return _counts(_send("PUT", api_base + RESOURCE_PATH, headers, body), body)
        except _Status as error:
            if error.status not in RETRY_STATUSES and error.status != 0:
                raise
            last = error
            if attempt < MAX_ATTEMPTS:
                sleep(2.0**attempt)
    raise last or VantaError("the push was never attempted")


def _counts(reply: dict[str, Any], body: dict[str, Any]) -> dict[str, int]:
    results = reply.get("results")
    if not isinstance(results, dict):
        raise VantaError("resource reply carries no results object")
    accepted, rejected = results.get("accepted"), results.get("rejected")
    if not isinstance(accepted, int) or not isinstance(rejected, int):
        raise VantaError(f"resource reply counts are {accepted!r} and {rejected!r}")
    if rejected or accepted != len(body["resources"]):
        raise VantaError(
            f"vanta accepted {accepted} and rejected {rejected} of {len(body['resources'])} records"
        )
    return {"accepted": accepted, "rejected": rejected}
