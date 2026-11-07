# Proposed text for draft-gilda-audit-agent-audit-record-04: whose data a call touched, and why

Change text for the next revision of the members section, written for access requests under
privacy law. Each paragraph names the members of `vectors-agent-audit-record` that test it. The
predicate URI does not change: `dataSubject` is an optional member, so a record without it is
judged exactly as under revision 03. The cases come from the issue Joshua Moffat opened
([#423](https://github.com/probityai/agent-evidence-vectors/issues/423), from the Financial
Services Interest Group discussion in the Model Context Protocol organisation); the member and the
rows below follow his three checks.

## 1. Why the member exists

A bank runs a server. An agent acting for a member of staff calls a tool that reads customer C's
account history. Later C asks who has accessed their data and why. Under GDPR Article 15, as the
Court of Justice read it in its Pankki S judgment of 22 June 2023, the right of access covers the dates and
purposes of consultations of a person's data, and PIPEDA Schedule 1 principle 4.9.1 asks for an
account of the use made of the information. The record already carries the delegated subject, the
person the agent acts for, which here is the staff member and not C. C's identifier is in the
call's arguments, which the record holds only as `resource.argumentsDigest`. Nothing in the signed
bytes says whose data the call touched or why it was made. `dataSubject` carries both answers
without carrying the customer's identifier.

## 2. The member

Add to Section 5, after `principal`:

> `dataSubject`, OPTIONAL. Whose data the call read, and the purpose of the call. When present it
> is an object carrying exactly these members, and MAY carry `delegateReference`; a record missing
> one of them or carrying any other member in it, a raw identifier included, is malformed
> (vectors `DS4`, `DS5`):
>
> * `scheme`, `salted-sha256-jcs`.
> * `saltId`, the name by which the server keeps the salt the references were made with.
> * `reference`, the keyed reference to the data subject: the SHA-256 digest, as lowercase hex, of
>   the RFC 8785 bytes of `{"salt": <the salt, base64url>, "subject": <the identifier>}`. The server
>   recomputes it from the salt and the identifier when it answers an access request; a holder of the
>   record alone cannot recover the identifier (vector `DS6` refuses a raw identifier here).
> * `relation`, `delegate` when the data subject is the user the agent acts for, `other` when it is
>   another person.
> * `delegateReference`, the same reference for the delegated user. It is present exactly when
>   `delegation.subjectKind` is `user` and `relation` is `other`, so the record shows both people. It
>   MUST differ from `reference` (vector `DS7`). Under `relation` `delegate`, or a `system` caller,
>   it is absent (vector `DS8`).
> * `purpose`, the purpose of the call.
> * `purposes`, the list of purposes the server declares: a non-empty array of distinct strings,
>   for example the enumeration of a tool parameter in the server's schema.
> * `purposesDigest`, the SHA-256 digest of the RFC 8785 bytes of `purposes`. It MUST recompute from
>   the list the record carries (vector `DS10`), and `purpose` MUST be one of `purposes` (vector
>   `DS9`).

## 3. Verifying a record

Add after the principal check, in this order:

> When `dataSubject` is present, a verifier checks its members (`DS4`, `DS5`), that the references,
> the scheme, the relation and the lists are well formed (`DS6`), that the relation agrees with the
> delegation kind and the delegate reference (`DS8`), that the data subject is not merged with the
> delegated user (`DS7`), that `purposesDigest` recomputes from `purposes` (`DS10`), and that `purpose`
> is on `purposes` (`DS9`). A record failing any of these is malformed.

The reference reader's codes for these refusals are `data-subject-member-missing`,
`data-subject-member-unknown`, `data-subject-malformed`, `data-subject-relation-mismatch`,
`data-subject-merged`, `data-subject-purposes-digest-mismatch` and `data-subject-purpose-undeclared`.
The Python and Go readers (`packaging/agent_evidence_vectors/auditrecord.py`,
`corpusreaders/auditrecord_datasubject.go`) judge every row the same way, and both expose the
recomputation (`data_subject_reference`, `arDataSubjectReference`) a server runs for an access
request.

## 4. Accepted and refused rows

`DS1` is a staff member acting on customer C's data, `DS2` a customer reading their own data
(relation `delegate`), and `DS3` a system caller with its own declared list. Each reject row changes
one value of an accepted row, so each accepted row is the safe control of the rows built from it:
`DS4` to `DS7`, `DS9` and `DS10` from `DS1`, `DS8` from `DS3`.

## 5. What the member does not establish

That the reference names the person the call really read: the server vouches for that when it
recomputes the reference. That the declared list is the list the server published, which the
digest binds the record to without proving. That the purpose was the true reason for the call, or
that the call was lawful for that purpose. Rows read as `MANIFEST.json` of
`vectors-agent-audit-record` states them (`row` and `expected`).
