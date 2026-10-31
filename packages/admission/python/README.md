# agent-evidence-admission

Checks that an artifact has the digest its document names: a TEA artifact, a CycloneDX SBOM or VEX, or an in-toto statement.

It is for manufacturers, integrators and admission controllers that receive a compliance document for a release and need to know the document covers the bytes they actually hold.

## Install

Start in a new directory with Python 3.10 or newer and [uv](https://github.com/astral-sh/uv).
Install the checker in its own environment:

```sh
uv venv admission-env
uv pip install --python admission-env/bin/python agent-evidence-admission==0.2.0
```

## Example

Create three known bytes and a synthetic in-toto statement that names their digest:

```sh
printf 'abc' > artifact.txt
cat > statement.json <<'JSON'
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "artifact.txt", "digest": {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}],
  "predicateType": "https://example.org/digest-demo/v1",
  "predicate": {}
}
JSON
admission-env/bin/agent-evidence-admission digest-check statement.json artifact.txt
```

It prints:

```text
PASS artifact.txt has sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad, named in statement.json
```

A match binds the document to bytes. It does not verify a signature or admit a workload.

For an existing CycloneDX SBOM and JAR, provide both files in your working directory:

```bash
uvx agent-evidence-admission==0.2.0 digest-check bom.json log4j-core-2.26.1.jar
```

The check runs three steps: read the document (a path or an https URL), recompute the artifact's digest with every algorithm the document names, and compare. It prints one line and exits 0 when a named digest matches:

```
PASS log4j-core-2.26.1.jar has sha512:..., named in bom.json
```

It exits 1 with `FAIL digest-mismatch` when the bytes differ, or `FAIL no-digest-named` when the document names no digest at all, and 2 when the document or the artifact could not be read. Plain http URLs are refused.

## Coverage check

`agent-evidence-admission coverage-check bom.json --require library,service,machine-learning-model` reports, for each class a buyer requires, whether a CycloneDX BOM or an SPDX 3 document assessed it, marked it not assessed with a reason (`unknown` or `withheld`), points at a covering document, or says nothing. It exits 1 on a missing or doubly selected class and on a not-assessed entry with no reason and no covering reference. `--required` reads the list from a file, `--json` prints the report. The [vectors](vectors/coverage/manifest.json) are its positive and negative cases.

## Client MCP allowlists

`agent-evidence-admission generate admit-list.json --out generated` turns one list of admitted MCP
servers into the allowlist that Claude Code, Cursor and Windsurf each enforce, plus a static MCP
registry for the GitHub Copilot registry-only policy. Each server is written as its exact command
and arguments or its exact URL. The report names, for each server, what each client matches. No
client hashes the bytes it starts, so the admitted digest is listed as unbound. A server a client
cannot express exactly is refused for that client (exit 1), not widened. See
[the guide](https://github.com/probityai/agent-evidence/blob/main/packages/admission/docs/CLIENT-ALLOWLISTS.md)
and the [vectors](vectors/generate/manifest.json).

## Conformance result records

`agent-evidence-admission conformance run|replay|verify` runs a corpus against an implementation, signs the score as a DSSE-wrapped in-toto statement, files it in a public run registry, and checks records another party signed. `replay` turns the rows of the vectors' `docs/INDEPENDENT-RUNS.json` into records. See [the result format](https://github.com/probityai/agent-evidence/blob/main/packages/admission/docs/CONFORMANCE-RESULT.md).

## Status

Version 0.2.0. The Kubernetes admission policies (Rego, Kyverno, policy-controller) live in the same repository; see the [repository README](https://github.com/probityai/agent-evidence/tree/main/packages/admission#readme).

## Build packages

From the repository root, check the license copy, build both archives and check their license text and metadata:

```bash
python scripts/python-license-gate.py
python -m build python --outdir dist
python scripts/python-license-gate.py --dist dist
```

The repository `LICENSE` is the source of the existing Apache-2.0 grant. `python/LICENSE` is its byte-for-byte distribution copy because license-file paths must stay within the Python project. Copy the root file when it changes; the gate refuses drift. Both the wheel and source archive include that text, and the source archive can build without the repository parent.
