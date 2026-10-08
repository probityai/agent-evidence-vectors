# Build a verifier from the spec: an invitation

I'd like you to build a verifier from a spec I wrote, and to post it by 12:00 UTC on 10 October 2026. In return I'm offering you co-authorship of the paper it goes into.

I need your help because of a question my paper asks. The paper is for the journal Empirical Software Engineering, and the question is plain: when several people build a checker from the same written spec, do they make the same mistakes? If they do, then "every checker agrees" is weaker evidence than it looks.

The spec is the Adversarial Execution Evidence predicate, a format for recording adversarial test runs that I wrote for in-toto (in-toto/attestation#570). Two people outside my group have built verifiers for it so far. Their first runs failed on different statements. That's interesting, but two builds can't tell me whether separate builds share mistakes. I need a few more, from people who haven't seen my test set.

## What the work is

You read the spec and write a verifier in any language you like. Your verifier reads one statement and decides whether it's valid. For a valid statement it prints the result the spec says it produces, and for an invalid one it prints a reason.

Use whatever tools you normally use, coding agents included. I only ask that you tell me which tools and which model you used.

The spec is about 22,000 words. Expect a couple of hours of reading before you write any code.

Please don't look at my test set, its changelog or the two existing verifiers before you post your build. If you already have, you're still welcome. Just tell me, and I'll report your build in a group of its own.

If you've already written a verifier for this spec, I'd like to include it as it stands. Tell me which commit to run and I'll record its SHA.

## Why the deadline is a fixed hour

That afternoon I generate a fresh set of test statements from a public random number that nobody can know in advance, me included. Before that number exists, I fix the program that makes them and timestamp its fingerprint. That way I can't shape the statements around your build, and you don't have to take my word for it.

To post your build, reply where you were invited with three things: a link to the code (a public repository or a tarball), its commit and SHA-256, and the command that runs it.

## What happens after you post

I run your build on the fresh statements and on the public test set. Then I publish the statements and the raw outputs. You see your results before I write anything about them.

I keep your first run exactly as it came out. If you fix something afterwards, I report the fix on its own, and it never replaces the first run.

## What you get

I'd like you to be a co-author. The journal asks every author to help write or revise the paper, approve the submitted version, and stand behind all of it. So you'd read the whole draft before I submit it on 14 October. You'd correct anything you think is wrong, check how I describe your build, and approve the submission.

The journal generally doesn't add authors after submission, which is why all of this happens before the 14th. The draft reaches you soon after the run, so you'll have a few days with it.

I want to be upfront that co-authors can't change two things. One is your build's first run. The other is the analysis plan, which I wrote down and timestamped before any build was scored. If you disagree with the analysis, tell me and I'll answer it in the paper. But the numbers that count were fixed in advance.

If you'd rather not be an author, I'll thank you by name in the paper, or leave your name out if you prefer. Either way you get your results and the full comparison with every other build.

## How to say yes

Reply where you were invited and say you're building. Ask me anything there, too.

## The details, if you want them

The spec, at the pinned revision, is https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.12.1/spec/predicates/adversarial-execution-evidence.md. Its SHA-256 is `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`.

Your verifier should print the one line the test harness reads. That line is documented under "What the suite compares" in the agent-evidence-vectors 0.12.1 README on PyPI (https://pypi.org/project/agent-evidence-vectors/0.12.1/).

The fresh statements are seeded from drand round 6540566, which is published at 16:00 UTC on 10 October 2026. I use the four hours after the 12:00 cutoff to add your build to a list, and I commit and timestamp that list before the round. If you post after 12:00, your build goes in only if I can still timestamp the list before the round. Otherwise it waits for a later batch. I never regenerate a seed.

For each build I record who built it and the tools and model they used, including whether a coding agent wrote it. I also record whether the builder had seen the test set, its changelog or another implementation.

## Consent

Taking part is voluntary. You can pull out at any time before publication, and if you do, I remove whatever you sent from the study.

I publish your build and the results from it. Your name appears only if you choose, and you can choose any of four ways: as a co-author, by name in the thanks, under a pseudonym you pick, or not at all.

All I write down is the tools and models you tell me you used, and whether you'd seen the test set, its changelog or other implementations. I publish your session logs only if you agree to that separately. I publish nothing else about you.

To ask a question or pull out, reply in the thread or message where you were invited.

## My competing interest

I wrote the spec and the test set, and I run the study. The paper says so. If builders join as co-authors, the paper also says that some of its authors built verifiers it scores.

Other roles in the same study: [builders](builders.md), [readers](readers.md), [coders](coders.md).
