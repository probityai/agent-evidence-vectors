# Contributing

Issues and pull requests are welcome. The most useful contributions are a
reproducible evidence run for the Open Evidence Lab and a correction to a
recorded claim. Each has an issue form: **Evidence run** and **Evidence
correction**. State the question before scoring, then name the specific claim
and contract. Fill in the source revision, the exact command and the result,
so anyone can rerun it. Retain the report and provenance in the artifact
manifest, and name the authors, operators and custodians separately.

## Before you open a pull request

Run `pytest` from the repository root. A change to a recorded claim or a run
links the source it rests on. A change to what a check accepts comes with a test
that fails without it.

## License

Contributions are accepted under the repository's license,
[Apache-2.0](LICENSE), per section 5 of that license. There is no contributor
license agreement to sign; the one thing asked beyond the license is the
sign-off below.

## Signing off your commits

Every commit in a pull request carries a sign-off: a line at the end of the
commit message, in the name and email of the commit's author.

    Signed-off-by: Your Name <you@example.org>

The line certifies the [Developer Certificate of Origin](DCO): that you wrote
the change or otherwise have the right to submit it under this repository's
license, and that the record of your contribution is public. `git commit
--signoff` (or `-s`) adds the line.
