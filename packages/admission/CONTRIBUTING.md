# Contributing

Issues and pull requests are welcome: a policy rail that admits what it should
refuse, a vector the rails disagree on, a profile you need registered, or a
defect in the harness.

## Before you open a pull request

Run `bash .githooks/install.sh` once per clone. It points git at the tracked
hooks, which check commit messages and run the pre-push checks; CI runs the same
rules, so a clone that skips it finds out on the pull request instead.

The rails are measured, not asserted. A change to a policy under `rego/`,
`kyverno/` or `policy-controller/` needs the conformance harness to agree with
it; [Running the conformance harness](docs/DESIGN.md#running-the-conformance-harness)
says how, and [Continuous integration](docs/DESIGN.md#continuous-integration) lists
what CI refuses.

## Documentation

Start a human guide with one practical question and a worked result. Put source pin inventories and contract tables after that example or in one linked reference. Preserve the original text, commands and heading anchors when you move details. Link the exact technical contract instead of copying it.

## Convergence and review

A proposal that asks more than one party to agree names a date by which it
should converge. If it has not converged by then, whoever opened it posts the
options that emerged and asks a narrower yes-or-no question. A reply that never
came is recorded as no reply, never as consent.

A pull request that has waited a week with no reviewer goes on the next
maintainer review as a standing line, with one question: who reviews it, by
when. The line stays until a reviewer is named or the pull request is closed
with a reason.

## License

Contributions are accepted under the repository's license,
[Apache-2.0](LICENSE), per section 5 of that license. There is no contributor
license agreement to sign; the one thing asked beyond the license is the
sign-off below.

## Signing off your commits

Every commit in a pull request carries a sign-off: a line at the end of the
commit message, in the name and email of the commit's author.

    Signed-off-by: Your Name <you@example.org>

The line certifies the [Developer Certificate of Origin](DCO): that you wrote the
change or otherwise have the right to submit it under this repository's license,
and that the record of your contribution is public. The text in [`DCO`](DCO) is
the Linux Foundation's Developer Certificate of Origin, version 1.1, unmodified.
It is the sign-off that in-toto and the Linux Foundation's projects ask for,
written the same way, so a commit you have signed off for one of them needs
nothing extra here.

`git commit --signoff` (or `-s`) adds the line. To add it to commits already on
your branch, run `git rebase --signoff main` and force-push the branch.

The `dco/sign-off` check verifies the line on every pull request and names each
commit that lacks one. It does not ask for a sign-off on a merge commit, on a
commit by a bot account, or on a maintainer's own commits, which the maintainers
license by publishing them.

A sign-off is a statement a person makes. If a coding assistant or another tool
wrote part of a change, you review the change, you are the commit's author, and
the sign-off is yours; a tool does not add one on your behalf.
