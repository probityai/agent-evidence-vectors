"""Write the differential fixtures the Go attack test reads (verifier of W4-2 r3).

Run from the repository root: ``python scripts/verify-w42-attack-gen.py <outdir>``.
It writes keys.jsonl, sigs.jsonl and records.jsonl. Each line carries what the Python
reference reader answers; corpusreaders/verify_w42_attack_test.go asks the Go readers
the same question and fails on any difference.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import importlib.util
import json
import random
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging"))
import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import assurancelevels as al  # noqa: E402
from agent_evidence_vectors import destexchange as de  # noqa: E402
from agent_evidence_vectors import holderbound as hb  # noqa: E402
from agent_evidence_vectors import strictjson  # noqa: E402

rail.ed25519_verify = functools.lru_cache(maxsize=None)(rail.ed25519_verify)

CAP_PLAIN = 260
CAP_DEEP = 160


def load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hb_gen = load("hb_gen", ROOT / "corpora/vectors-holder-bound-credential/gen_vectors.py")
de_gen = load("de_gen", ROOT / "corpora/vectors-destination-narrowed-exchange/gen_vectors.py")
DE_TRUST = json.loads((ROOT / "corpora/vectors-destination-narrowed-exchange/TRUST.json").read_text())

SCALARS = [None, 0, 1, -1, 10**30, -(10**30), 1.5, 1.0, True, False, "", " ", "x", [], {}, "0", "é"]
STRING_EDITS = [
    lambda s: s + " ",
    lambda s: " " + s,
    lambda s: s + " ",
    lambda s: " " + s,
    lambda s: s + "\x1c",
    lambda s: s + "\x85",
    lambda s: s + "\n",
    lambda s: s.upper(),
    lambda s: s.swapcase(),
    lambda s: s[:-1],
    lambda s: s + "A",
    lambda s: unicodedata.normalize("NFD", s + "é"),
    lambda s: s.replace("a", "а", 1),
]


def paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for k, v in node.items():
            yield from paths(v, prefix + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from paths(v, prefix + (i,))


def get(root, path):
    for p in path:
        root = root[p]
    return root


def put(root, path, value):
    root = copy.deepcopy(root)
    if not path:
        return value
    parent = get(root, path[:-1])
    parent[path[-1]] = value
    return root


def delete(root, path):
    root = copy.deepcopy(root)
    parent = get(root, path[:-1])
    if isinstance(parent, dict):
        del parent[path[-1]]
    else:
        del parent[path[-1]]
    return root


def edits_for(node):
    out = [("set", v) for v in SCALARS]
    if isinstance(node, str):
        out += [("set", f(node)) for f in STRING_EDITS]
    if isinstance(node, int) and not isinstance(node, bool):
        out += [("set", node + 1), ("set", node - 1), ("set", -node), ("set", node + 10**20),
                ("set", float(node))]
    if isinstance(node, list) and node:
        out += [("set", node[:-1]), ("set", node + [copy.deepcopy(node[0])]),
                ("set", list(reversed(node)))]
    if isinstance(node, dict):
        out += [("set", {**node, "extra": 1})]
    return out


def mutants(record, rng, cap):
    plan = []
    for path in paths(record):
        node = get(record, path)
        if path:
            plan.append((path, ("del", None)))
        for edit in edits_for(node):
            plan.append((path, edit))
    rng.shuffle(plan)
    for path, (kind, value) in plan[:cap]:
        try:
            yield delete(record, path) if kind == "del" else put(record, path, value)
        except (KeyError, IndexError, TypeError):
            continue


def compact(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def b64(data: bytes) -> str:
    return hb.b64url(data)


def unb64(text: str) -> bytes:
    return hb.unb64url(text) or b""


HOLDER_SEED = hashlib.sha256(b"holder-bound-credential/v1 test key holder").digest()


def resign(record, index, edit):
    """Decode presentation ``index``, mutate its header and claims, sign with the holder."""
    record = copy.deepcopy(record)
    proof = record["presentations"][index]["proof"]
    head = json.loads(unb64(proof["protected"]))
    body = json.loads(unb64(proof["payload"]))
    edit(head, body)
    protected, payload = b64(compact(head)), b64(compact(body))
    sig = rail.ed25519_sign(HOLDER_SEED, f"{protected}.{payload}".encode("ascii"))
    record["presentations"][index]["proof"] = {
        "protected": protected, "payload": payload, "signature": b64(sig)}
    return record


def judge(suite: str, text: str):
    try:
        record = strictjson.loads(text)
    except (ValueError, UnicodeDecodeError):
        return {"decision": "reject", "reason": "record_malformed"}
    if not isinstance(record, dict):
        return {"decision": "reject", "reason": "record_malformed"}
    try:
        if suite == "hbc":
            return hb.judge(record)
        if suite == "ial":
            return al.judge(record)
        return de.judge(record, DE_TRUST)
    except Exception as exc:  # a crash is itself an answer the Go side must not match silently
        return {"decision": "PYCRASH", "reason": type(exc).__name__}


def emit(out, suite: str, text: str, tag: str) -> None:
    answer = judge(suite, text)
    out.write(json.dumps({"suite": suite, "tag": tag, "text": text, **answer}) + "\n")


# ---- key differential -------------------------------------------------------------------

P, L = rail._P, rail._L


def small_order_points():
    found = {}
    rng = random.Random("torsion")
    while len(found) < 8:
        y = rng.randrange(2, P)
        pt = rail._pt_decompress(y.to_bytes(32, "little"))
        if pt is None:
            continue
        t = rail._pt_mul(L, pt)
        found[rail._pt_compress(t)] = t
    return found


def key_cases():
    cases = {}

    def add(raw: bytes, tag: str) -> None:
        cases.setdefault(raw, tag)

    torsion = small_order_points()
    for raw in torsion:
        add(raw, "torsion")
        flipped = bytearray(raw)
        flipped[31] ^= 0x80
        add(bytes(flipped), "torsion-signflip")
    for y in list(range(0, 20)) + [P - 1, P - 2, P - 19]:
        for sign in (0, 1):
            add((y | (sign << 255)).to_bytes(32, "little"), f"y={y}")
            if y + P < (1 << 255):
                add(((y + P) | (sign << 255)).to_bytes(32, "little"), f"y+p={y}")
    add(((1 << 256) - 1).to_bytes(32, "little"), "all-ones")
    add(((1 << 255) - 1).to_bytes(32, "little"), "2^255-1")
    add(bytes(32), "zero")
    add(bytes(31), "short")
    add(bytes(33), "long")
    honest = [rail.ed25519_public_key(hashlib.sha256(f"k{i}".encode()).digest()) for i in range(6)]
    for raw in honest:
        add(raw, "honest")
        flipped = bytearray(raw)
        flipped[31] ^= 0x80
        add(bytes(flipped), "honest-signflip")
        point = rail._pt_decompress(raw)
        for t in torsion.values():
            add(rail._pt_compress(rail._pt_add(point, t)), "mixed")
        for bit in range(0, 256, 17):
            mutated = bytearray(raw)
            mutated[bit // 8] ^= 1 << (bit % 8)
            add(bytes(mutated), f"bitflip-{bit}")
    rng = random.Random("random-keys")
    for i in range(600):
        add(rng.randbytes(32), "random")
    # points of the curve found by y scan, to hit both square-root branches and the sign bit
    for y in range(2, 200):
        for sign in (0, 1):
            add((y | (sign << 255)).to_bytes(32, "little"), f"scan-{y}")
    return cases


def write_keys(path: Path) -> None:
    with path.open("w") as out:
        for raw, tag in key_cases().items():
            out.write(json.dumps({"hex": raw.hex(), "tag": tag, "ok": bool(hb._prime_order(raw))}) + "\n")


def write_sigs(path: Path) -> None:
    seed = hashlib.sha256(b"sig-differential").digest()
    pub = rail.ed25519_public_key(seed)
    msg = b"message to sign"
    sig = rail.ed25519_sign(seed, msg)
    r, s = sig[:32], int.from_bytes(sig[32:], "little")
    cases = {"honest": (pub, msg, sig)}
    cases["s+L"] = (pub, msg, r + ((s + L) % (1 << 256)).to_bytes(32, "little"))
    cases["s+2L"] = (pub, msg, r + ((s + 2 * L) % (1 << 256)).to_bytes(32, "little"))
    cases["s=L"] = (pub, msg, r + L.to_bytes(32, "little"))
    cases["s=0"] = (pub, msg, r + bytes(32))
    cases["s-1"] = (pub, msg, r + ((s - 1) % L).to_bytes(32, "little"))
    cases["msg2"] = (pub, msg + b"!", sig)
    cases["short"] = (pub, msg, sig[:63])
    cases["long"] = (pub, msg, sig + b"\x00")
    ry = int.from_bytes(r, "little") & ((1 << 255) - 1)
    cases["R-signflip"] = (pub, msg, bytes(r[:31]) + bytes([r[31] ^ 0x80]) + sig[32:])
    cases["R-identity"] = (pub, msg, (1).to_bytes(32, "little") + sig[32:])
    cases["R-order2"] = (pub, msg, (P - 1).to_bytes(32, "little") + sig[32:])
    cases["R-y+p"] = (pub, msg, ((ry + P) if ry + P < (1 << 255) else ry).to_bytes(32, "little") + sig[32:])
    cases["zero-sig"] = (pub, msg, bytes(64))
    for t in small_order_points():
        cases[f"R+T-{t.hex()[:6]}"] = (pub, msg, rail._pt_compress(
            rail._pt_add(rail._pt_decompress(r), rail._pt_decompress(t))) + sig[32:])
    for i in range(0, 256, 5):
        mutated = bytearray(sig)
        mutated[i // 8] ^= 1 << (i % 8)
        cases[f"sigbit-{i}"] = (pub, msg, bytes(mutated))
    with path.open("w") as out:
        for tag, (k, m, sg) in cases.items():
            out.write(json.dumps({
                "tag": tag, "key": k.hex(), "msg": m.hex(), "sig": sg.hex(),
                "ok": bool(rail.ed25519_verify(k, m, sg))}) + "\n")


# ---- record differential ----------------------------------------------------------------

ALGS = [None, 5, True, ["none"], {}, "none", "NONE", "nOnE", "None", "HS256", "hs256", "hS", "hß",
        "Hß256", "hſ256", "ſhs", "EdDSA", "eddsa", "EdDSA ", "ES256", "RS256", "", " none"]
TYPS = [None, 5, "dpop+jwt", "DPoP+JWT", "dpop+jwt ", "JWT", ""]
WEAK = [(1).to_bytes(32, "little"), (P - 1).to_bytes(32, "little"), bytes(32),
        (P).to_bytes(32, "little"), (1 | (1 << 255)).to_bytes(32, "little"),
        ((P - 1) | (1 << 255)).to_bytes(32, "little"), (1 + P).to_bytes(32, "little")]


def hbc_targeted(record, rng):
    holder = hb_gen.jwk("holder")
    heads = []
    for alg in ALGS:
        heads.append(lambda h, b, a=alg: h.__setitem__("alg", a) if a is not None else h.pop("alg", None))
    for typ in TYPS:
        heads.append(lambda h, b, a=typ: h.__setitem__("typ", a) if a is not None else h.pop("typ", None))
    for raw in WEAK:
        heads.append(lambda h, b, r=raw: h.__setitem__("jwk", {**holder, "x": b64(r)}))
    for x in [holder["x"] + "=", holder["x"][:-1], holder["x"] + "A", holder["x"].replace("-", "+"),
              holder["x"] + "\n", " " + holder["x"], holder["x"].upper(), ""]:
        heads.append(lambda h, b, v=x: h.__setitem__("jwk", {**holder, "x": v}))
    for extra in ("d", "p", "k", "kid"):
        heads.append(lambda h, b, e=extra: h.__setitem__("jwk", {**holder, e: "AA"}))
    heads.append(lambda h, b: h.__setitem__("crit", ["x"]))
    heads.append(lambda h, b: h.pop("jwk", None))
    heads.append(lambda h, b: h.__setitem__("jwk", {**holder, "kty": "okp"}))
    heads.append(lambda h, b: h.__setitem__("jwk", {**holder, "crv": "ed25519"}))
    for name in ("jti", "htm", "htu", "iat", "ath"):
        for value in SCALARS + ["POST ", "post", "https://x/?a=1", 10**30]:
            heads.append(lambda h, b, n=name, v=value: b.__setitem__(n, v))
        heads.append(lambda h, b, n=name: b.pop(n, None))
    base_at = record["presentations"][0]["at"]
    for delta in (-61, -60, -59, 4, 5, 6, 0):
        heads.append(lambda h, b, d=delta, a=base_at: b.__setitem__("iat", a + d))
    heads.append(lambda h, b: b.__setitem__("extra", 1))
    rng.shuffle(heads)
    for edit in heads[:CAP_DEEP]:
        for index in range(len(record["presentations"])):
            try:
                yield resign(record, index, edit)
            except Exception:
                continue
            break


def raw_variants(text: str):
    """Texts the readers must refuse or read alike: not valid strict JSON in some way."""
    yield "﻿" + text
    yield " \n" + text + " \n"
    yield text + " x"
    yield text + text
    yield text.rstrip()[:-1] + ',"contractId":1}'
    yield text.replace("{", '{"a":1,"a":2,', 1)
    yield text.replace("{", '{"\\ud800":1,"\\ud801":2,', 1)
    yield text.replace("{", '{"a":NaN,', 1)
    yield text.replace("{", '{"a":1e999,', 1)
    yield text.replace("{", '{"a":-0,', 1)
    yield text.replace("{", '{"a":0.0,', 1)
    yield text.replace("{", '{"a":"\\u0000",', 1)
    yield text.replace("{", '{"é":1,"e\\u0301":2,', 1)
    yield text.replace("{", '{"b":[' * 1 + "[" * 300 + "]" * 300 + "],", 1)
    yield text.encode().decode("ascii", "ignore")[:-2]


def corpus_members(corpus: str):
    base = ROOT / "corpora" / corpus / "cases"
    for case in sorted(base.iterdir()):
        yield case.name, (case / "record.json").read_text(encoding="utf-8")


def write_records(path: Path) -> None:
    suites = {"hbc": "vectors-holder-bound-credential", "ial": "vectors-identity-assurance",
              "dne": "vectors-destination-narrowed-exchange"}
    with path.open("w") as out:
        for suite, corpus in suites.items():
            for name, text in corpus_members(corpus):
                record = json.loads(text)
                emit(out, suite, text, f"{name}:member")
                rng = random.Random(f"{suite}:{name}")
                for i, mutated in enumerate(mutants(record, rng, CAP_PLAIN)):
                    emit(out, suite, json.dumps(mutated), f"{name}:plain-{i}")
                for i, variant in enumerate(raw_variants(text)):
                    emit(out, suite, variant, f"{name}:raw-{i}")
                if suite == "hbc":
                    for i, mutated in enumerate(hbc_targeted(record, rng)):
                        emit(out, suite, json.dumps(mutated), f"{name}:targeted-{i}")
                if suite == "dne":
                    for i, mutated in enumerate(mutants(record, rng, CAP_DEEP)):
                        try:
                            entries = copy.deepcopy(mutated["statements"])
                            sealed = de_gen.seal(entries)
                            emit(out, suite, json.dumps({**mutated, "statements": sealed}),
                                 f"{name}:resealed-{i}")
                        except Exception:
                            continue


def main() -> int:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    write_keys(out / "keys.jsonl")
    write_sigs(out / "sigs.jsonl")
    write_records(out / "records.jsonl")
    for name in ("keys", "sigs", "records"):
        print(name, sum(1 for _ in (out / f"{name}.jsonl").open()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
