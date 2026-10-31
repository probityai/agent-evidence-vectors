# Design decisions

## Exact input comparison

The first author-created profile compares exact SQL bytes and ordered typed parameter bytes.
It does not introduce SQL equivalence or parameter coercion. Native prepared-statement audit formats need an explicit adapter contract before such comparisons.
Database instance, database, schema, application account, and database principal are different facts.

## Statement, transaction, and later state

A successful statement can roll back. A correctly committed statement can precede a later independent write.
The reader reports these observations separately. Supplied before/after bytes do not prove historical capture or attribute a later writer.

## Complete collection is a declaration

An absence result carries the supplied collector scope. A wrong scope or incomplete collection cannot establish an absence for the approved request.
The reader does not verify the collector's declaration. This limit belongs to the input authority, not SQL normalisation.

## Accepted complexity

`assess` coordinates strict input checks, three supplied records, a uniquely selected audit join, and an independent later-state comparison.
Its branching follows those separate evidence states. It is accepted as orchestration and nested data traversal.
The test mutation dispatcher has many trivial branches because each payload attacks a different input boundary.
It is test data dispatch, not a production state machine.

## Destination

This illustration lives in the existing Atlas repository, alongside the Lab's other worked examples.
It does not justify a separate public product repository, an invented Tadpole export field, or a compatibility alias.
