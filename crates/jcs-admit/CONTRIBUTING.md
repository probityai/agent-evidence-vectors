# Contributing

Issues and pull requests are welcome, and a document this crate admits that it
should refuse, or refuses that it should admit, is the most useful report of all.
Include the bytes.

## Before you open a pull request

`cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo doc` must
pass with no warnings. A new refusal comes with a test that fails without it;
[`docs/MUTATION-SWEEP.md`](docs/MUTATION-SWEEP.md) records how every existing
refusal was checked that way.

## License

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed under the MIT license and the Apache License, Version 2.0, without
any additional terms or conditions. That is the same clause most Rust crates
use. There is no contributor license agreement to sign; the one thing asked
beyond the license is the sign-off below.

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
