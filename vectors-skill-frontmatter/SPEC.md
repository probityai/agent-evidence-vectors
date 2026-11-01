# Parsing a SKILL.md

This is the text proposed for the "SKILL.md format" part of the Agent Skills specification
(`agentskills/agentskills`, `docs/specification.mdx` at commit
`27a9f0c075e876ad632fc2e88b8866c5dc8ca15c`). It is a proposal, not the upstream text. The cases in
`cases/` are its executable form: one `SKILL.md` per case and the outcome the steps below assign it.

### Parsing

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY in this section are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in capitals.

The field table above says what a skill declares. This section says which octets are the declaration, so that every client reading the same file reaches the same answer. A client MUST apply the steps below, in order, to the octets of a `SKILL.md`. The first step that fails refuses the file with the code shown. A client MUST report a refusal to its caller or user, and MUST NOT silently skip the skill, substitute an empty set of declarations, or repair the file and retry.

A **line terminator** is `LF` (U+000A), `CR LF`, or a lone `CR` (U+000D). No other character ends a line, including U+0085, U+2028 and U+2029. **Trimmed** means with trailing spaces (U+0020) and tabs (U+0009) removed.

1. **File size.** If the file is longer than 1,048,576 octets, refuse with `file-too-large`.
2. **Encoding.** If the file begins with the octets `EF BB BF` (a byte order mark), refuse with `byte-order-mark`. Otherwise decode the file as UTF-8; if it is not valid UTF-8, refuse with `invalid-utf8`.
3. **Opening delimiter.** If the trimmed first line is not exactly `---`, refuse with `no-opening-delimiter`. A file with no frontmatter is refused: a `SKILL.md` always has some. Four or more hyphens, leading whitespace, a preceding blank line, comment, or code fence do not open frontmatter.
4. **Closing delimiter.** The frontmatter block is the text between the opening line and the first later line whose trimmed content is exactly `---`. If there is no such line, refuse with `unterminated-frontmatter`. The remainder of the file MUST NOT be taken as frontmatter. A `---` that is not a whole line (inside a value, or with other text on its line) does not close the block.
5. **Block size.** If the block is longer than 65,536 octets of UTF-8, refuse with `frontmatter-too-large`.
6. **Control characters.** If the block contains a control character other than tab, `LF` or `CR` (U+0000 to U+001F, or U+007F), refuse with `control-character`.
7. **Document markers.** If any line of the block begins with `...` or `---` followed by a space, a tab or the end of the line, refuse with `document-end-marker` (for `...`) or `document-start-marker` (for `---`). A client MUST NOT parse the block as a YAML stream and keep its first document.
8. **Empty block.** If every line of the block is blank or a comment, refuse with `frontmatter-empty`.
9. **Block mapping.** The first line of the block that is not blank and not a comment MUST be an entry of the form `key: value` that begins in column 0, where the key is a plain scalar or a single-line quoted scalar and the colon is followed by a space, a tab or the end of the line. Otherwise (a scalar, a sequence, a flow collection, a block scalar, a directive, an indented line) refuse with `root-not-block-mapping`. Every later line of the block that begins in column 0 and is not blank or a comment MUST be either another such entry, or a sequence item (`- `) continuing the immediately preceding entry whose inline value is empty. Otherwise refuse with `invalid-entry`. Lines that begin with a space or tab continue the preceding entry.
10. **Duplicate keys.** If two column-0 entries have the same key, after decoding quoting and escapes, refuse with `duplicate-key`. This applies to every top-level key, including keys the client does not use, and whether or not the values agree. A client MUST NOT resolve a repeated key by keeping the first or the last occurrence.
11. **Values.** The block MUST then load as a single YAML 1.2 document, and a processor error refuses the file with `yaml-syntax-error`. Value types and the constraints in the field table are applied after this step.

The body is everything after the line terminator that ends the closing delimiter line, byte for byte; a client MUST NOT alter its line terminators.

Steps 1 to 10 are decidable by a line scan with no YAML library; step 11 needs a YAML processor.

## Conformance

A client conforms when, for every case in this corpus, it accepts the file with the listed keys and
body or refuses it with the listed code. The cases marked `needsYaml` exercise step 11 and apply only
to a client that runs a YAML processor.
