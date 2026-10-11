# Public tool schemas, captured verbatim

Real tool definitions for testing anything that reads a tool schema and decides
what an argument may do: a scanner, a gate, a policy compiler, an evidence
format. Eight are the `tools/list` result of a public MCP server, pinned to an
exact release and captured over stdio on the date in
[`MANIFEST.json`](MANIFEST.json). Two are lifted from the OpenAI and Anthropic
tool-use documentation. Every file is the bytes as received, and the manifest
carries its SHA-256, the exact command or URL, and the server's own reported
name and version, so a run against them can say exactly which input it read.

## What each set actually does

A schema says what an argument is. It does not say what the tool does with it,
and the gap between the two is where a misclassified argument hides. One
sentence per set, from running the server or reading its source:

| file | what the tools do |
| --- | --- |
| `filesystem.tools-list.json` | reads, writes, edits, moves and searches files under the directories the server was started with |
| `git.tools-list.json` | runs git against one repository: status, diff, add, commit, reset, branch, checkout, log, show |
| `fetch.tools-list.json` | fetches any URL the caller names and returns it as markdown |
| `memory.tools-list.json` | creates, links, edits and deletes entities in a local knowledge graph file |
| `playwright.tools-list.json` | drives a real browser: navigate, click, type, upload files, run JavaScript, manage tabs |
| `notion.tools-list.json` | calls the Notion API with the configured token: search, read, create, update and move pages, edit and delete blocks, comment, and manage data sources |
| `time.tools-list.json` | returns the current time and converts between time zones; nothing it does has a side effect |
| `everything.tools-list.json` | the MCP reference test server, exercising each protocol feature with harmless tools |
| `openai-crm-namespace.json` | looks up a customer profile and lists open orders by customer ID |
| `anthropic-get-weather.json` | returns the weather for a location; a control with nothing protected in it |

## Two arguments worth a first look

Both are enums that choose which operation runs, so a reader that treats an
enum as bounded data marks the verb itself as safe to author:

- `playwright` `browser_tabs.action`: `list`, `new`, `close`, `select`.
- `notion` `API-update-page-markdown.type`: `replace_content`, `update_content`,
  `insert_content`, `replace_content_range`. Replacing a page and inserting into
  it are different actions behind one tool name.

## Rebuilding

Each MCP entry's `source` is the command that produced it; `<directory>` is any
empty directory (a git repository for `git`). The Notion server lists its tools
without a working token, and the capture ran with the token set to a dummy
value.
