# SKILL.md frontmatter parse vectors

Cases for `skill-frontmatter-parse/v1`: the exact octets of a `SKILL.md` and the outcome a client
must reach when it reads the frontmatter. The Agent Skills specification says which fields a skill
declares and not which bytes are the declaration, so deployed readers disagree about where the
block closes, what a document-end line does and what a repeated key means. [`SPEC.md`](SPEC.md)
proposes eleven numbered steps with one refusal code each; every case here is tied to one step.
`SPEC.md` is a proposal for the upstream specification, not upstream text.

Each case is a directory `cases/<id>/` holding one `SKILL.md`. The manifest row gives the expected
outcome: `ok` with the top-level keys in order and, where the case pins it, the body; or `error`
with the refusal code and, where the step names one, the 1-based line.

A client conforms when it gives every case its listed outcome. The two cases marked `needsYaml`
exercise step 11 (the block must load as one YAML 1.2 document) and apply only to a client that
runs a YAML processor.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-skill-frontmatter
```

The reference reader uses only the standard library. With PyYAML installed it also runs the
`needsYaml` cases; without it the run prints how many it did not run, and they are counted in the
report as `notApplicable`, never as passes.

To parse one file with the reference reader:

```sh
python3 -m agent_evidence_vectors.skillfrontmatter path/to/SKILL.md --json
```

To judge your own parser: a verifier takes `SKILL.md --json`, prints one JSON object, and exits 0
when it answered. For an accepted file the object carries `outcome: "ok"`, `keys` and `body`; for a
refused one `outcome: "error"`, `code` and `line` (`null` when the refusal concerns the whole
file). Fields a case does not pin are not compared.

```sh
agent-evidence-vectors --corpus vectors-skill-frontmatter --verifier './verifier'
```

A verifier that has a YAML processor sets `AEV_SKILL_YAML_PROCESSOR=1` to be given the
`needsYaml` cases too. Regenerate the cases with `python3 vectors-skill-frontmatter/gen_vectors.py`.

## Cases

| Case | Step | Outcome | What it pins |
| --- | --- | --- | --- |
| minimal | all | ok | two required keys, body follows |
| no-body | 6 | ok | closing delimiter is the last line, no terminator |
| crlf | 2 | ok | CRLF line endings accepted, body bytes untouched |
| cr-only | 2 | ok | lone CR is a line terminator |
| mixed-terminators | 2 | ok | LF, CRLF and CR mixed in one file |
| trailing-space-on-delimiters | 3 | ok | delimiter lines tolerate trailing space and tab |
| unicode-line-separator-is-content | 2 | ok | U+2028 is not a line terminator |
| dashes-inside-value | 6 | ok | --- inside a value does not close the block |
| dashes-inside-body | 6 | ok | a later --- line in the body is body text |
| comment-lines | 9 | ok | blank and comment lines in the block are ignored |
| nested-mapping | 9 | ok | indented lines belong to the preceding key |
| same-key-nested-not-duplicate | 10 | ok | a key repeated only at depth is not a top-level repeat |
| block-scalar-contents | 9 | ok | block scalar lines are not entries |
| sequence-at-key-indent | 9 | ok | a column-0 sequence continues the preceding empty-valued key |
| quoted-keys | 10 | ok | quoted keys are keys |
| document-end-in-body | 4 | ok | a ... line in the body is body text |
| hyphen-key | 10 | ok | a key may begin with a hyphen when no space follows |
| body-keeps-bom-after-frontmatter | 2 | ok | a U+FEFF after the frontmatter is body text |
| empty-file | 3 | refused `no-opening-delimiter` | an empty file has no opening delimiter |
| no-delimiter | 3 | refused `no-opening-delimiter` | plain markdown declares nothing and is refused |
| blank-line-before-opening | 3 | refused `no-opening-delimiter` | opening delimiter must be line 1 |
| html-comment-before-opening | 3 | refused `no-opening-delimiter` | a comment before the delimiter is refused |
| code-fence-wrapped | 3 | refused `no-opening-delimiter` | a fenced frontmatter is refused |
| four-dash-opening | 3 | refused `no-opening-delimiter` | four hyphens do not open |
| leading-space-opening | 3 | refused `no-opening-delimiter` | an indented opening does not open |
| bom | 2 | refused `byte-order-mark` | a leading BOM is refused by name, not read as no frontmatter |
| invalid-utf8 | 2 | refused `invalid-utf8` | invalid UTF-8 octets |
| overlong-utf8 | 2 | refused `invalid-utf8` | overlong encoding is invalid UTF-8 |
| unterminated | 6 | refused `unterminated-frontmatter` | no closing delimiter: refused, never the rest of the file |
| four-dash-closing | 6 | refused `unterminated-frontmatter` | four hyphens do not close |
| indented-closing | 6 | refused `unterminated-frontmatter` | an indented --- does not close |
| closing-with-text | 6 | refused `unterminated-frontmatter` | --- followed by text is not a closing line |
| opening-only | 3 | refused `unterminated-frontmatter` | a file that is only the opening delimiter |
| empty-frontmatter | 8 | refused `frontmatter-empty` | two adjacent delimiters declare nothing |
| comment-only-frontmatter | 8 | refused `frontmatter-empty` | comments alone declare nothing |
| document-end | 7 | refused `document-end-marker` | a ... line is a document-end marker |
| document-end-with-comment | 7 | refused `document-end-marker` | ... followed by a comment is still the marker |
| document-end-first | 7 | refused `document-end-marker` | a marker is reported ahead of structural faults |
| document-start-with-content | 7 | refused `document-start-marker` | --- followed by content starts a second document |
| duplicate-same-value | 10 | refused `duplicate-key` | a repeated key is refused even when the values agree |
| duplicate-different-value | 10 | refused `duplicate-key` | a repeated key is refused when the values differ |
| duplicate-unknown-key | 10 | refused `duplicate-key` | the rule covers keys the parser does not read |
| duplicate-quoted-and-plain | 10 | refused `duplicate-key` | a quoted key and a plain key are the same key |
| duplicate-escaped | 10 | refused `duplicate-key` | an escaped quoted key is compared decoded |
| scalar-root | 9 | refused `root-not-block-mapping` | a bare scalar is not a mapping |
| sequence-root | 9 | refused `root-not-block-mapping` | a sequence is not a mapping |
| flow-mapping-root | 9 | refused `root-not-block-mapping` | a flow mapping root is not a block mapping |
| flow-sequence-root | 9 | refused `root-not-block-mapping` | a flow sequence root is not a mapping |
| indented-root | 9 | refused `root-not-block-mapping` | entries must start at column 0 |
| tab-root | 9 | refused `root-not-block-mapping` | a tab is not indentation |
| block-scalar-root | 9 | refused `root-not-block-mapping` | a block scalar root is not a mapping |
| directive-line | 10 | refused `root-not-block-mapping` | a % directive is not an entry |
| stray-scalar-after-entry | 10 | refused `invalid-entry` | a column-0 line that is no entry |
| sequence-after-valued-key | 10 | refused `invalid-entry` | a column-0 sequence entry after a valued key |
| sequence-after-nested-content | 10 | refused `invalid-entry` | a column-0 sequence entry after indented content |
| key-without-space | 10 | refused `invalid-entry` | name:value is a scalar, not an entry |
| multiline-quoted-key | 10 | refused `invalid-entry` | an implicit key is on one line |
| nul-in-block | 8 | refused `control-character` | NUL in the block |
| escape-in-block | 8 | refused `control-character` | ESC in the block |
| frontmatter-too-large | 5 | refused `frontmatter-too-large` | a block over 65536 octets |
| frontmatter-at-limit | 5 | ok | a block of exactly 65536 octets is accepted |
| file-too-large | 1 | refused `file-too-large` | a file over 1048576 octets |
| file-at-limit | 1 | ok | a file of exactly 1048576 octets is accepted |
| yaml-syntax-error | 11 | refused `yaml-syntax-error` | a structurally valid block the YAML processor refuses (needs YAML) |
| yaml-bad-indent | 11 | refused `yaml-syntax-error` | inconsistent indentation under a key (needs YAML) |
