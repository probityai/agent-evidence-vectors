# Proposed text for draft-gilda-audit-agent-audit-record-05: the deadline of a held zero settlement

Change text for the next revision of Section 5.9. A held entry of an `upto` permit that settled 0
keeps the hold until a later record of the ledger shows the key released. Under this text a
record dated exactly at the held entry's deadline does not release it: the record is valid, and
the set is malformed (`consumption-set-release-unshown`). A record dated after the deadline
releases the hold under both texts.

The member that tests this sentence is `CS55`. Revision 04 prints `CS54` with its published
reading, a record dated exactly at the deadline releasing the hold, and that reading is not
changed here: `CS54` stays valid.

The rationale for moving the boundary, that a block stamped exactly at the deadline can still
settle the permit, is the proposer's reading, carried by pull request #590. It rests on the claim
that Permit2 reverts only when the block timestamp is greater than the permit's deadline. That is
the proposer's reading and not this repository's finding: nothing in the corpus verifies it
against the contract source.
