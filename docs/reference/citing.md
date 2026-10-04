# Cite a corpus or run

Retain these identifiers with a result:

| Identifier | Use |
| --- | --- |
| Release tag and commit | The software and corpus tree that ran |
| Suite revision and corpus digest | The tested population and its bytes |
| Version DOI, when archived | One fixed archived release |
| Verifier source digest and report | The implementation and result being cited |

The concept DOI [10.5281/zenodo.22758687](https://doi.org/10.5281/zenodo.22758687) points to the newest archived release. Use a version DOI to cite a fixed deposit. The README snapshot at `bbdef583` records archives for releases 0.10.1 and 0.11.1; use the Zenodo record's Versions list to select the deposit you actually ran.

[CITATION.cff](../../CITATION.cff) carries the concept DOI and the newest archived version DOI under `identifiers`. Tags precede the archive deposit, so the version DOI is added to the default branch afterward. GitHub renders its citation from that file.

This software citation names release 0.16.0 and the concept DOI. Attach the fixed corpus and verifier identifiers when citing a measured run.

```bibtex
@software{gilda_agent_evidence_vectors,
  author    = {Gilda, Sankalp},
  title     = {agent-evidence-vectors: conformance vectors for agent execution evidence},
  version   = {0.16.0},
  publisher = {Zenodo},
  year      = {2026},
  doi       = {10.5281/zenodo.22758687},
  url       = {https://doi.org/10.5281/zenodo.22758687}
}
```
