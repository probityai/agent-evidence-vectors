# Build a verifier from the spec: an invitation

I'm writing a paper for the journal Empirical Software Engineering about a plain question. When several people build a checker from the same written spec, do they make the same mistakes? If they do, then "every checker agrees" is weaker evidence than it looks.

The spec is one I proposed to in-toto for recording adversarial test runs, the Adversarial Execution Evidence predicate (in-toto/attestation#570). Two people outside my group have built verifiers for it so far. Their first runs failed on different statements, and two builds are too few to tell whether separate builds share mistakes. So I'm asking a few more people to build one, people who have not seen my test set.

## What I'm asking

Read the spec and write a verifier for it in any language. It reads one statement and says whether the statement is valid. When it is valid, the verifier prints the result it works out; when it is not, a reason. Use any tools you like, coding agents included; just tell me which ones, and which model.

The spec is about 22,000 words, so plan on a couple of hours of reading before any code.

Please don't look at my test set, its changelog or the two existing verifiers before you post your build. If you already have, you are still welcome. Tell me, and your build is reported in a group of its own.

## The deadline, and why it is a fixed hour

Please post your finished code by 12:00 UTC on 10 October 2026. That afternoon I generate a fresh set of test statements from a public random number that nobody, me included, can know in advance. Because your code is public before those statements exist, I can't shape them around your build.

To post it, reply where you were invited with three things. They are a link to the code (a public repository or a tarball), its commit and SHA-256, and the command that runs it.

## What happens next

I run your build on the fresh statements and on the public test set, and I publish the raw outputs. You get your results before I write anything about them. Your first run is kept exactly as it came out. If you fix something afterwards, the fix is reported on its own and never replaces the first run.

## What you get

I'd like to offer you co-authorship of the paper.

The journal asks every author to help write or revise the paper, approve the submitted version, and stand behind all of it. So as a co-author you would read the whole draft before I submit it on 14 October. You would correct anything you think is wrong, check how your build is described, and approve the submission. The journal generally does not add authors after submission, which is why this all happens before the 14th.

Two things co-authorship does not touch: your build's first run, and the analysis plan, which was written down and timestamped before any build was scored. If you disagree with the analysis, say so and I will answer it in the paper. The numbers that count were fixed in advance.

If you'd rather not be an author, I'll thank you by name in the paper, or leave your name out if you prefer. Either way you get your results and the full comparison with every other build.

## How to say yes

Reply where you were invited and say you're building. Questions are welcome there too.

## Exact rules, for anyone who wants them

- Spec, at the pinned revision: https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.12.1/spec/predicates/adversarial-execution-evidence.md (SHA-256 `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`).

- Output: the one line the test harness reads is documented under "What the suite compares" in the agent-evidence-vectors 0.12.1 README on PyPI (https://pypi.org/project/agent-evidence-vectors/0.12.1/).

- Timing: the fresh statements are seeded from drand round 6540566, published at 16:00 UTC on 10 October 2026.

- The four hours after the 12:00 cutoff are for adding your build to a list that is committed and timestamped before that round.

- A build posted after 12:00 goes in only if that list can still be timestamped before the round. Otherwise it waits for a later batch, and a seed is never regenerated.

- What is recorded about each build: who built it, and the tools and model used. Also recorded: whether the builder had seen the test set, its changelog or another implementation.

## Consent

- Taking part is voluntary. You can pull out at any time before publication, and whatever you sent is then removed from the study.

- What gets published: your build and the results worked out from it.

- Your name appears only if you choose: as a co-author, by name in the thanks, under a pseudonym you pick, or not at all.

- What I record about how you worked: the tools and models you tell me you used. I also record whether you had seen the test set, its changelog or other implementations.

- Session logs are published only if you agree to that separately. Nothing else about you is published.

- To ask a question or pull out, reply in the thread or message where you were invited.

## Competing interest

I wrote the spec and the test set, and I run the study. The paper says so. If builders join as co-authors, the paper also says that some of its authors built verifiers it scores.

Other roles in the same study: [builders](builders.md), [readers](readers.md), [coders](coders.md).
