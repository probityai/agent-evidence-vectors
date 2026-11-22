# Proposed text for draft-gilda-audit-agent-audit-record-05: the deadline of a held zero settlement

Change text for the next revision of Section 5.9. A held entry of an `upto` permit that settled 0
keeps the hold until a later record of the ledger shows the key released. Under this text a
record dated exactly at the held entry's deadline does not release it: the record is valid, and
the set is malformed (`consumption-set-release-unshown`), because a block stamped exactly at the
deadline can still settle the permit. A record dated after the deadline releases the hold, as
`CS54` shows under revision 04.

The member that tests this sentence is `CS55`. Revision 04 prints `CS54` with its published
reading, a record at the deadline ending the hold, and that reading is not changed here.

The rationale is the one carried by the pull request that proposed this boundary (#590): Permit2
reverts only when the block timestamp is greater than the permit's deadline. That statement is
the proposer's and is not re-verified against the contract source in this text.
