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

For an unreleased checkout, cite the full source commit and corpus digest. The preferred citation in `CITATION.cff` names the published release. This example uses that release URL; attach the corpus and verifier identifiers for a measured run.

```bibtex
@software{gilda_agent_evidence_vectors,
  author    = {Gilda, Sankalp},
  title     = {agent-evidence-vectors: conformance vectors for agent execution evidence},
  version   = {0.17.4},
  year      = {2026},
  url       = {https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.17.4}
}
```

## Cite a vector by its member id

When your project changes because of a vector here, name the vector's member id
(for example `bad-742` in `vectors/`, with the corpus directory when it is not
`vectors/`) in your commit message or pull request body, beside the suite
revision you ran. The member id is stable across releases and is how a later
reader of your history finds the exact bytes and the rule they force, even after
the surrounding text has been rewritten.
