"""A validator for a discovery snapshot under draft-arsentev-llm-context-discovery-00.

The draft is an individual Internet-Draft (Informational, September 2026)
defining how a publisher advertises a context file for language-model
consumers and how a consumer resolves it: a well-known URI, a link relation,
and a robots.txt record, with a precedence between them and the robots
exclusion protocol above all three. Its text is vendored beside the corpus that
cites it and pinned by digest; each rule here is bound to one sentence of that
text by a requirement identifier the corpus mints (``LCD-R-nnn``).

A member is a SNAPSHOT: what the origin served on each mechanism, which
resources exist and whether each is an index or a detail resource, what the
robots.txt carries, and what one consumer then did. The publisher-side rows
read the mechanisms and the consumer-side rows read the consumer's record
against them, so one document can answer for either side.

``corpora/contextdiscovery.go`` is the same statement in Go and the parity
test diffs the two.
"""

from __future__ import annotations

from typing import Any

WELL_KNOWN = "/.well-known/llm-context"
REDIRECTS = (301, 302, 307, 308)

R = {n: f"LCD-R-{n:03d}" for n in range(1, 12)}


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_obj(value: Any) -> bool:
    return isinstance(value, dict)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def shape_errors(document: Any) -> list[str]:
    """Every way the document fails to be a discovery snapshot at all."""
    if not _is_obj(document):
        return ["the document is not a JSON object"]
    out: list[str] = []
    if not _is_str(document.get("origin")):
        out.append("the snapshot carries no string origin")
    if not _is_obj(document.get("resources")):
        out.append("the snapshot carries no resources object")
    if not _is_obj(document.get("consumer")):
        out.append("the snapshot carries no consumer object")
    for slot in ("well-known", "link", "robots"):
        if slot in document and document[slot] is not None and not _is_obj(document[slot]):
            out.append(f"{slot} is present and is not an object")
    _shape_lists(document, out)
    return out


def _list_of(container: Any, key: str, where: str, item: str, out: list[str]) -> None:
    """``container[key]``, when present, is an array whose every element is of one type.

    Absent is allowed; any other JSON type, null included, is a shape defect,
    never an empty list.
    """
    if not _is_obj(container) or key not in container:
        return
    value = container[key]
    test = _is_str if item == "string" else _is_obj
    if not isinstance(value, list) or not all(test(v) for v in value):
        out.append(f"{where}.{key} is present and is not a list of {item}s")


def _shape_lists(document: dict[str, Any], out: list[str]) -> None:
    """The members the draft gives a JSON type that the rows then iterate.

    Section 4.3 and RFC 9309 make robots.txt exclusion rules and records
    sequences, a consumer's retrievals are a list of URIs, and every entry of
    resources describes one resource.
    """
    robots = document.get("robots")
    _list_of(robots, "disallow", "robots", "string", out)
    _list_of(robots, "records", "robots", "object", out)
    _list_of(document.get("consumer"), "retrieved", "consumer", "string", out)
    resources: Any = document.get("resources")
    if _is_obj(resources):
        for uri in sorted(resources):
            if not _is_obj(resources[uri]):
                out.append(f"resources.{uri} is not an object")


def _absolute(uri: Any) -> bool:
    return _is_str(uri) and (uri.startswith("https://") or uri.startswith("http://"))


def _origin_of(uri: str) -> str:
    scheme, _, rest = uri.partition("://")
    return scheme + "://" + rest.split("/", 1)[0]


def _path_of(uri: str) -> str:
    _, _, rest = uri.partition("://")
    return "/" + rest.split("/", 1)[1] if "/" in rest else "/"


def _disallowed(uri: str, origin: str, robots: dict[str, Any] | None) -> bool:
    if not _absolute(uri) or _origin_of(uri) != origin or robots is None:
        return False
    rules = [r for r in robots.get("disallow", []) if r]
    return any(_path_of(uri).startswith(rule) for rule in rules)


def _records(robots: dict[str, Any] | None) -> list[Any]:
    if robots is None:
        return []
    out = []
    for record in robots.get("records", []):
        if not _is_str(record.get("name")):
            continue
        if record["name"].lower() == "llm-context":
            out.append(record.get("value"))
    return out


def _well_known_target(document: dict[str, Any], out: set[str]) -> str | None:
    """The URI the well-known mechanism advertises, or None when it advertises nothing."""
    response = document.get("well-known")
    if response is None:
        return None
    status = response.get("status")
    if status == 404:
        return None
    if _is_int(status) and 200 <= status < 300:
        content_type = response.get("content-type")
        if _is_str(content_type) and content_type.lower().startswith("text/html"):
            out.add(R[1])
        if response.get("negotiated") is True and not _is_str(response.get("content-language")):
            out.add(R[10])
        return str(document["origin"]) + WELL_KNOWN
    if status in REDIRECTS and _absolute(response.get("location")):
        return str(response["location"])
    out.add(R[3])
    return None


def _rows_publisher(document: dict[str, Any], out: set[str]) -> str | None:
    """The publisher rows, returning the URI the precedence rule selects."""
    origin = document["origin"]
    resources = document["resources"]
    robots = document.get("robots")
    link: Any = document.get("link")
    link_target = link.get("target") if _is_obj(link) else None
    well_known = _well_known_target(document, out)
    robots_targets: list[str] = []
    for value in _records(robots):
        if not _absolute(value):
            out.add(R[4])
            continue
        if _disallowed(value, origin, robots):
            out.add(R[5])
        robots_targets.append(value)
    targets = [t for t in [link_target, well_known, *robots_targets] if _is_str(t)]
    for target in targets:
        resource = resources.get(target)
        if resource is not None and resource.get("role") == "detail":
            out.add(R[2])
            break
    if _is_str(link_target):
        return link_target
    if well_known is not None:
        return well_known
    return robots_targets[0] if robots_targets else None


def _rows_consumer(document: dict[str, Any], selected: str | None, out: set[str]) -> None:
    origin = document["origin"]
    resources = document["resources"]
    robots = document.get("robots")
    consumer = document["consumer"]
    resolved = consumer.get("resolved")
    if resolved is not None and resolved != selected:
        out.add(R[6])
    retrieved: list[str] = consumer.get("retrieved", [])
    known = [u for u in retrieved if u in resources]
    indexes = [u for u in known if resources[u].get("role") == "index"]
    if len(indexes) > 1:
        out.add(R[7])
    foreign = _absolute(resolved) and _origin_of(str(resolved)) != origin
    if foreign and consumer.get("attributed-to") == origin:
        out.add(R[8])
    ceiling = consumer.get("ceiling-octets")
    if not _is_int(ceiling) or ceiling <= 0:
        out.add(R[9])
    if any(_disallowed(u, origin, robots) for u in retrieved):
        out.add(R[11])


def rejections(document: dict[str, Any]) -> list[str]:
    """The requirement identifiers this snapshot is rejected under, sorted."""
    out: set[str] = set()
    selected = _rows_publisher(document, out)
    _rows_consumer(document, selected, out)
    return sorted(out)
