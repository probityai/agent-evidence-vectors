# Readers' pack: checking 272 statements against the specification

Thank you for reading. This pack has everything you need, and nothing else:

- `SPECIFICATION.md`: the specification at the pinned revision (the Adversarial Execution Evidence
  predicate, version 0.7.0, as proposed in in-toto/attestation#570). Its SHA-256 is
  `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`; `sha256sum SPECIFICATION.md`
  should print that value.
- `statements/S001.txt` to `statements/S272.txt`: 272 in-toto statements under neutral labels.
- `ANSWER-SHEET.tsv`: one row per statement, with the label filled in and the rest left for you.

## What to decide

For each statement, decide from the specification text alone whether a verifier that checks the
statement from its own bytes, with no trust anchor or key policy supplied by the consumer, must treat
it as **valid** or **invalid**. If the specification does not decide the question, say so: record
**undecided**. That is a real answer, not a failure to finish, and the study counts it as one.

Each statement file shows the statement's bytes decoded as UTF-8. Any byte that is not part of a
valid UTF-8 sequence is shown as a backslash-x escape of its hexadecimal value, for example `\xed`.
Read such an escape as that single raw byte, not as the four characters `\`, `x`, `e`, `d`. Two of the
272 files contain escapes of this kind.

## Work from the specification alone

The corpus's expected answers are withheld from you on purpose, and so are the file names, the
descriptions, the changelog and every existing verifier. The study asks whether a careful reader of
the text reaches the same answer the corpus author wrote down, so please do not look the statements
up, run them through an implementation, or compare notes with another reader until you have sent
your sheet. If you use any tool or assistant while reading, that is fine; please just tell us which
when you send the sheet, because it is recorded per reader.

## How to fill ANSWER-SHEET.tsv

The file is tab-separated. Open it in a spreadsheet or a text editor and keep the tabs. Per row:

| Column | What to write |
|---|---|
| `label` | already filled in; leave it as it is |
| `verdict` | `valid`, `invalid` or `undecided` |
| `result` | if `valid`, the overall result token the specification's recompute gives for this statement; otherwise leave it blank |
| `clause` | a verbatim quotation of the specification sentence that decides it (copy and paste, no paraphrase; if two sentences decide it together, quote both). For `undecided`, quote the sentence that comes closest and leaves the question open |
| `confidence` | a whole number from 1 (a guess) to 5 (certain) |

Leave a row entirely blank for any statement you did not read. A blank row means "not read"; it is
never counted as an answer.

## How much to take

The study wants two independent readings of every statement. You may take all 272, or a subset: if
you were assigned a block of labels, read those; if not, pick any block you like. A returned sheet
that covers any contiguous block of labels (for example `S041` to `S080`) is useful on its own, so
please send back what you have finished rather than waiting to finish everything. A statement takes
roughly five to fifteen minutes.

## Sending it back

Reply to the message that brought you this pack with `ANSWER-SHEET.tsv` attached, and say whether you
would like to be acknowledged by name or anonymously, whether you have been involved with this
specification before, and which tools, if any, you used while reading. Every disagreement with the
corpus's answers is adjudicated against the specification text, and every one is published with the
study, together with how it was resolved.
