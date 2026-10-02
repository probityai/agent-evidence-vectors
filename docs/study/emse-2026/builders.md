# Build a verifier from the specification alone

Part of the study "Agreement Is Not Independence", for the Empirical Software Engineering special issue on agentic software engineering.

**Reply by:** freeze your build before 2026-10-10 12:00 UTC; the seed is fixed by drand round 6540566 at 2026-10-10 16:00 UTC

Build a verifier for a proposed in-toto predicate from the text alone, and help measure what agreement between verifiers is worth.

I am studying the conformance corpus for the Adversarial Execution Evidence predicate proposed in in-toto/attestation#570. Two people outside the author group have built verifiers so far, both with coding agents, and their first runs failed in different ways on different rules. Two is not enough to say whether independently built verifiers share their mistakes. I am asking for a few more builds, made under rules that keep the first run honest.

What a build involves: read the specification at the pinned revision, https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.12.1/spec/predicates/adversarial-execution-evidence.md (SHA-256 `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`), and write a verifier in any language that reads one statement and prints its verdict, the recomputed result token when valid, and a reason when not. The one-line output the test harness reads is documented under "What the suite compares" in the agent-evidence-vectors 0.12.1 README on PyPI (https://pypi.org/project/agent-evidence-vectors/0.12.1/). You may use any tools, including coding agents; please record which, and which model. Please do not read the conformance corpus, its changelog or either existing implementation before your build is frozen; if you already have, you are still welcome; just let me know, and your build is reported in a separate group.

Freezing: publish your source (a public repository or a tarball) and post its commit, the source's SHA-256 and the command that runs it before 2026-10-10 12:00 UTC. Four hours later a public randomness beacon (drand round 6540566) fixes the seed of a set of fresh test statements that nobody, including me, has seen. I run your frozen build on them and on the public corpus, publish the raw outputs, and send you the results before anything is written up. Your first run is kept exactly as it came out; any fix you make afterwards is reported separately and never replaces it.

What you get: your results, the full comparison with every other build, and acknowledgement in the paper by name or anonymously, as you prefer. The consent text is below. Questions are welcome in the thread where you were invited.

## How to take part

Reply where you were invited to say you are building, then post your frozen build (commit, source SHA-256, run command) there before the cutoff.

## Consent

- Taking part is voluntary. You can withdraw at any time before publication, and anything you sent is then removed from the study.
- What is published: your builds, readings or codings and the results computed from them. Whether your name appears is your choice: by name, by a pseudonym you choose, or anonymously.
- What is recorded about how you worked: the tools and models you tell me you used, and whether you had seen the corpus, its changelog or other implementations. Session logs are published only if you agree to that separately.
- Nothing is published about you beyond what you send for the study and the choice above.
- The study is run by the specification's author, which is a competing interest the paper declares.
- Questions or withdrawal: reply in the thread or message where you were invited.

Other roles in the same study: [builders](builders.md), [readers](readers.md), [coders](coders.md).
