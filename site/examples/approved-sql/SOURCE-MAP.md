# Approved SQL: approval, execution, and a later change

Cho HyunJong (`hangum`) nominated this case in [the Open Evidence Lab thread](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6529865364). He described a Settle approval record and `executed_sql_resource`, compared with a database-native audit record. He did not supply a fixture or a database run in that comment.

The useful check compares four things: exact SQL and bound parameters, database and schema, the database principal, and the actual outcome. A later database read is a separate observation. It cannot by itself tell us who made an earlier change.

## What the public source supplies

Source pin: `hangum/TadpoleForDBTools` at `d72351937e7c0d8a0742348a828283cf45d6e16a`. The captured GitHub tree has 4,685 entries and `truncated: false`. This read covers the public engine and relational database source directories. The current product pages are separate producer descriptions; they do not qualify this older source as the current enterprise implementation.

| Input | Observed public source | Boundary to resolve with one native pair |
|---|---|---|
| Application execution identity | `ExecutedSqlResourceDAO.user_seq`, set from the Tadpole session | This is an application user identifier. It does not establish the database principal. |
| Application database reference | `ExecutedSqlResourceDAO.db_seq`, set from `UserDBDAO.seq` | The export needs the database instance, database, and schema used at execution time. A current mutable connection definition is not a historical snapshot. |
| SQL text | `ExecutedSqlResourceDataDAO.sql_data`, linked by `executed_sql_resource_seq` | Preserve exact bytes and the binding of parameters. The inspected resource data class has SQL text, not a typed parameter export. |
| Application outcome | `result`, `tdb_result_code`, `message`, `row`, and start/end times | A statement result is separate from a transaction commit. Error and rollback records must remain distinct from committed success. |
| Approval | The current MCP page names `create_settle_request`, `approve_settle_request`, `execute_approved_settle`, and `get_settle_detail` | The sample shows approval `seq`, `group_seq`, target, approver, and mode. The current draft Integration API supplies more fields; it does not supply the nominated native approval/audit pair. |
| Database audit | Not supplied in the nomination | Pick the actual database and its audit format. Preserve native event/transaction identifiers, principal, target, SQL representation, outcome, and collection scope. |
| Later database state | A new observation, with its own time and target | Keep it separate from the execution record. A later difference does not invalidate a correctly joined earlier execution. |

[Resource fields](https://github.com/hangum/TadpoleForDBTools/blob/d72351937e7c0d8a0742348a828283cf45d6e16a/com.hangum.tadpole.engine/src/com/hangum/tadpole/engine/query/dao/system/ExecutedSqlResourceDAO.java), [SQL data fields](https://github.com/hangum/TadpoleForDBTools/blob/d72351937e7c0d8a0742348a828283cf45d6e16a/com.hangum.tadpole.engine/src/com/hangum/tadpole/engine/query/dao/system/ExecutedSqlResourceDataDAO.java), [record write path](https://github.com/hangum/TadpoleForDBTools/blob/d72351937e7c0d8a0742348a828283cf45d6e16a/com.hangum.tadpole.engine/src/com/hangum/tadpole/engine/query/sql/TadpoleSystem_ExecutedSQL.java), [execution path](https://github.com/hangum/TadpoleForDBTools/blob/d72351937e7c0d8a0742348a828283cf45d6e16a/com.hangum.tadpole.engine/src/com/hangum/tadpole/engine/sql/util/executer/ExecuteDMLCommand.java), [current MCP page](https://tadpolehub.com/mcp/), [current product page](https://tadpolehub.com/product/).

The inspected DML path saves `reqQuery.getSql()` in the application history, then calls `SQLUtil.makeExecutableSQL()` before `statement.execute()`. The two representations need an explicit relationship; equal-looking SQL is not enough. The history writer can return `-1` when no profile record is written and catches write errors in its wrapper. An absent application record therefore does not prove an absent database execution.

## Finite cases

| Case | What the check should report |
|---|---|
| Approval exists, no execution record, incomplete audit collection | Insufficient evidence. Do not report "not executed." |
| Approval exists, no match in an explicitly complete declared audit window | No match in the declared window. Keep the scope and the collector's assertion visible. |
| Different SQL bytes or typed parameters | Execution differs from approval. Do not trim SQL, infer parameters, or collapse booleans into integers. |
| Different database instance, database, schema, or database principal | Execution differs from approval. Do not treat an application account as the database principal. |
| Statement succeeds, then the transaction rolls back | No committed success. Keep rollback distinct from a failed statement and from an unknown commit state. |
| Application reports success, database audit reports failure | Outcome disagreement. Keep both records. |
| One execution matches, then a later independent write changes the state | Earlier match and later state difference. Do not attribute the later write to the approved request. |
| Two audit events match one request without a unique join | Ambiguous evidence. Do not choose the first event. |

## Smallest native input

One shareable, version-pinned example is enough to start: the approved Settle export, its application execution record and SQL child record, and the corresponding database-native audit event. Include the database/version, the join rule, typed bound parameters, execution-time target and principal, transaction outcome, and audit collection scope. If a field cannot be exported, keep that field unknown.

The [runnable illustration](README.md) implements this comparison with 17 author-created fixtures. Its fields belong to the illustration. They are not claimed as Tadpole's export fields or a database-native adapter.

Producer semantics stay with Tadpole and the database's audit specification. We own the comparison code and its test cases. A native export, an outside run, and a kept downstream check remain separate tasks.

## Current draft API and export boundaries

The public [OpenAPI reference](https://tadpoledbhub.atlassian.net/wiki/pages/viewpage.action?pageId=3320479761), page version 1, provides the attachment `tadpole-integration-v1.yaml`. Its captured SHA-256 is `8abd24714b912420e101e90d0f010570cd79296c22ab7c4fbdfde3f2d90e821e`; its `info.version` is `1.0.0-draft`. We read its request, execution, transaction, and audit schemas. This is a producer-published draft contract, not a native run or installed SDK qualification.

| Draft field | Source meaning | Comparison boundary |
|---|---|---|
| `SqlStatementRequest.sql`, `params`, `catalog`, `schemaName`, `databaseId` | Exact submitted SQL, typed parameter envelopes, and the requested connection context | Keep the original request. Do not recover it from a hash or a result summary. |
| `Execution.executionId`, `approvalId`, `approvalSubjectHash`, `hashVersion` | A separate execution identifier and nullable approval reference/subject hash | Retain each identifier. An equal hash string is not a verified preimage or a historical database write. |
| `Execution.context.principal`, `tenantId`, `channel` | Server-resolved identity/context; workflow metadata can remain client asserted | The principal describes a Tadpole user or service account. A database-native principal still needs its own evidence. |
| `AuditEvent.requestId` | Explicitly a turn-level correlation identifier | Do not alias it to this illustration's per-comparison `request_id`. One turn can have several events. Use the actual execution/event join. |
| `AuditEvent.executionId`, `auditSource`, `databaseId`, `principalId`, `result` | Audit projection fields; execution and principal can be null | These fields alone do not supply exact SQL, bound parameters, schema, or native database commit proof. |
| `Transaction.transactionId`, `status`, `expiresAtMs` | Transaction session and a server status message | `status` is not a fixed enum in this draft. Do not invent aliases to our three transaction outcomes. |

The draft API separates explicit transaction commit/rollback from statement execution. An execution `SUCCEEDED` response is therefore insufficient by itself to establish a commit in a transaction session. Its request timeout also stays separate from client connection closure; a lost response does not prove cancellation.

The [approval manual](https://tadpoledbhub.atlassian.net/wiki/pages/viewpage.action?pageId=2445049894), version 6, documents `ONE_TIME`, `TERM`, and an expiry. A native adapter must preserve those conditions and distinguish one approved execution from several permitted executions. This illustration compares records; it does not qualify those authorization conditions.

The [external log guide](https://tadpoledbhub.atlassian.net/wiki/pages/viewpage.action?pageId=3335880708), version 3, documents a 20-minute export cycle. It also describes truncation, skipped oversized logs, unescaped comma output, and a button that marks data sent without sending it. An absent SIEM event therefore cannot stand alone as evidence of no execution. Preserve export configuration, gaps, pagination, time scope, and the database-native source separately.

## What this enables next

The same check can connect an approval owner, a database operator, and an independent reader without giving them a new governance job. Each can contribute one bounded piece: a pair, a reader, or a kept CI check.
The source also gives three concrete next controls: distinguish application identity from the database principal; check audit collection gaps before absence claims; retain statement and transaction outcomes separately after a lost response. These connect this case to the Lab's refund-retry and request/effect cases. No new public repository is needed; the existing Lab components can own the reader and regression cases.

## Source and check records

The links above identify the producer's pinned public code and current documentation.
The [check record](QUALIFICATION.json) binds the original illustration source and its author-run results.
The [retained test output](qualification/tests.stdout), [test report](qualification/tests.xml),
and [CLI case outputs](qualification/steps.json) preserve the passing run.
The original source captures also retain a failed documentation route: `/docs/` returned HTTP 404;
the linked wiki API returned the current documentation. The manual title query was paginated,
so this source map does not claim an exhaustive manual audit.
