package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

func init() { register(skillFrontmatter{}) }

// skillFrontmatter judges vectors-skill-frontmatter/. Each member is the exact
// octets of a SKILL.md and the outcome the parse algorithm in the corpus's
// SPEC.md assigns it. The reader applies steps 1 to 10 of that algorithm to the
// file and compares the result with the manifest; it never echoes the manifest.
// Step 11 needs a YAML processor this package does not carry, so the members
// marked needsYaml are reported with the kind "needs-yaml" and are not judged.
type skillFrontmatter struct{}

func (skillFrontmatter) Suite() string { return "skill-frontmatter-parse/v1" }

const (
	sfMaxFileOctets        = 1024 * 1024
	sfMaxFrontmatterOctets = 64 * 1024
)

type sfExpected struct {
	Outcome string   `json:"outcome"`
	Code    string   `json:"code"`
	Line    *int     `json:"line"`
	Keys    []string `json:"keys"`
	Body    *string  `json:"body"`
}

type sfVector struct {
	ID        string            `json:"id"`
	Path      string            `json:"path"`
	Files     map[string]string `json:"files"`
	NeedsYaml bool              `json:"needsYaml"`
	Expected  sfExpected        `json:"expected"`
}

func (skillFrontmatter) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v sfVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: "refused"}
		if v.Expected.Outcome == "ok" {
			member.Kind = "accepted"
		}
		if v.NeedsYaml {
			member.Kind = "needs-yaml"
		}
		member.Findings = sfJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func sfJudgeMember(caseDir string, v sfVector) []string {
	var findings []string
	for _, name := range sortedKeys(v.Files) {
		body, err := readIn(caseDir, name)
		if err != nil {
			findings = append(findings, name+" is declared and absent")
		} else if sha(body) != v.Files[name] {
			findings = append(findings, name+" does not match its manifest digest")
		}
	}
	data, err := readIn(caseDir, "SKILL.md")
	if err != nil {
		return append(findings, err.Error())
	}
	if v.NeedsYaml {
		return findings
	}
	if got := sfParse(data); !got.matches(v.Expected) {
		findings = append(findings, fmt.Sprintf("derived %s, the manifest declares %s",
			got.describe(), sfDescribe(v.Expected)))
	}
	return findings
}

// sfResult is the outcome of the parse steps: an accepted file or a refusal.
type sfResult struct {
	accepted bool
	keys     []string
	body     string
	code     string
	line     int // 0 when the refusal concerns the whole file
}

func sfRefuse(code string, line int) sfResult { return sfResult{code: code, line: line} }

func (r sfResult) matches(e sfExpected) bool {
	if r.accepted {
		return e.Outcome == "ok" && slices.Equal(r.keys, e.Keys) && (e.Body == nil || *e.Body == r.body)
	}
	return e.Outcome == "error" && r.code == e.Code && (e.Line == nil || *e.Line == r.line)
}

func (r sfResult) describe() string {
	if r.accepted {
		return fmt.Sprintf("ok keys=%v", r.keys)
	}
	return fmt.Sprintf("error %s line=%d", r.code, r.line)
}

func sfDescribe(e sfExpected) string {
	if e.Outcome == "ok" {
		return fmt.Sprintf("ok keys=%v", e.Keys)
	}
	if e.Line != nil {
		return fmt.Sprintf("error %s line=%d", e.Code, *e.Line)
	}
	return "error " + e.Code
}

// sfLines splits on LF, CR LF and lone CR: the line contents and the offset
// just past each terminator.
func sfLines(text string) ([]string, []int) {
	var contents []string
	var ends []int
	start := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\n':
			contents, ends = append(contents, text[start:i]), append(ends, i+1)
			start = i + 1
		case '\r':
			end := i + 1
			if end < len(text) && text[end] == '\n' {
				end++
			}
			contents, ends = append(contents, text[start:i]), append(ends, end)
			start, i = end, end-1
		}
	}
	if start < len(text) {
		contents, ends = append(contents, text[start:]), append(ends, len(text))
	}
	return contents, ends
}

func sfTrim(line string) string { return strings.TrimRight(line, " \t") }

func sfBlankOrComment(line string) bool {
	rest := strings.TrimLeft(line, " \t")
	return rest == "" || rest[0] == '#'
}

func sfHasControl(block string) bool {
	for i := 0; i < len(block); i++ {
		c := block[i]
		if (c < 0x20 && c != '\t' && c != '\r' && c != '\n') || c == 0x7F {
			return true
		}
	}
	return false
}

// sfDocumentMarker: a line starting "..." or "---" then a space, tab or its end.
func sfDocumentMarker(line string) bool {
	if !strings.HasPrefix(line, "...") && !strings.HasPrefix(line, "---") {
		return false
	}
	return len(line) == 3 || line[3] == ' ' || line[3] == '\t'
}

var sfDoubleEscapes = map[byte]byte{
	'\\': '\\', '"': '"', '/': '/', 'n': '\n', 't': '\t', 'r': '\r', '0': 0, ' ': ' ',
}

func sfDecodeDoubleQuoted(raw string) (string, bool) {
	var out []byte
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			continue
		}
		if i+1 >= len(raw) {
			return "", false
		}
		replacement, ok := sfDoubleEscapes[raw[i+1]]
		if !ok {
			return "", false
		}
		out = append(out, replacement)
		i++
	}
	return string(out), true
}

func sfClosingQuote(line string) int {
	quote := line[0]
	for i := 1; i < len(line); {
		switch {
		case quote == '"' && line[i] == '\\':
			i += 2
		case line[i] != quote:
			i++
		case quote == '\'' && i+1 < len(line) && line[i+1] == '\'':
			i += 2
		default:
			return i
		}
	}
	return -1
}

func sfQuotedKey(line string) (string, string, bool) {
	end := sfClosingQuote(line)
	if end < 0 {
		return "", "", false
	}
	rest := strings.TrimLeft(line[end+1:], " \t")
	if !strings.HasPrefix(rest, ":") || (len(rest) > 1 && rest[1] != ' ' && rest[1] != '\t') {
		return "", "", false
	}
	raw := line[1:end]
	if line[0] == '\'' {
		return strings.ReplaceAll(raw, "''", "'"), rest[1:], true
	}
	key, ok := sfDecodeDoubleQuoted(raw)
	return key, rest[1:], ok
}

// sfKeyColon is the index of the first colon followed by a space, a tab or the
// end of the line, or -1.
func sfKeyColon(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] == ':' && (i+1 == len(line) || line[i+1] == ' ' || line[i+1] == '\t') {
			return i
		}
	}
	return -1
}

func sfPlainKey(line string) (string, string, bool) {
	if strings.ContainsRune("#&*!|>'\"%@`[]{},", rune(line[0])) {
		return "", "", false
	}
	if line[0] == '?' && (len(line) == 1 || line[1] == ' ' || line[1] == '\t') {
		return "", "", false
	}
	colon := sfKeyColon(line)
	if colon < 0 {
		return "", "", false
	}
	key := strings.TrimRight(line[:colon], " \t")
	if key == "" || strings.Contains(key, " #") || strings.Contains(key, "\t#") {
		return "", "", false
	}
	return key, line[colon+1:], true
}

func sfEntry(line string) (string, string, bool) {
	if line[0] == '\'' || line[0] == '"' {
		return sfQuotedKey(line)
	}
	return sfPlainKey(line)
}

func sfSequenceEntry(line string) bool {
	return line[0] == '-' && (len(line) == 1 || line[1] == ' ' || line[1] == '\t')
}

// sfScanEntries is steps 9 and 10 over the block's lines.
func sfScanEntries(blockLines []string, first int) ([]string, *sfResult) {
	var keys []string
	seen := map[string]bool{}
	openForSequence := false
	for i, line := range blockLines {
		number := first + i
		if sfBlankOrComment(line) {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(keys) == 0 {
				r := sfRefuse("root-not-block-mapping", number)
				return nil, &r
			}
			openForSequence = false
			continue
		}
		if sfSequenceEntry(line) && openForSequence {
			continue
		}
		key, rest, ok := sfEntry(line)
		if !ok {
			code := "root-not-block-mapping"
			if len(keys) > 0 {
				code = "invalid-entry"
			}
			r := sfRefuse(code, number)
			return nil, &r
		}
		if seen[key] {
			r := sfRefuse("duplicate-key", number)
			return nil, &r
		}
		seen[key] = true
		keys = append(keys, key)
		openForSequence = sfBlankOrComment(rest)
	}
	return keys, nil
}

// sfParse applies steps 1 to 10 of the algorithm to the octets of a SKILL.md.
func sfParse(data []byte) sfResult {
	if len(data) > sfMaxFileOctets {
		return sfRefuse("file-too-large", 0)
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return sfRefuse("byte-order-mark", 1)
	}
	if !utf8.Valid(data) {
		return sfRefuse("invalid-utf8", 0)
	}
	text := string(data)
	lines, ends := sfLines(text)
	if len(lines) == 0 || sfTrim(lines[0]) != "---" {
		return sfRefuse("no-opening-delimiter", 1)
	}
	closing := -1
	for i := 1; i < len(lines); i++ {
		if sfTrim(lines[i]) == "---" {
			closing = i
			break
		}
	}
	if closing < 0 {
		return sfRefuse("unterminated-frontmatter", 1)
	}
	block := ""
	if closing > 1 {
		block = text[ends[0]:ends[closing-1]]
	}
	blockLines := lines[1:closing]
	if len(block) > sfMaxFrontmatterOctets {
		return sfRefuse("frontmatter-too-large", 2)
	}
	if sfHasControl(block) {
		return sfRefuse("control-character", 0)
	}
	for i, line := range blockLines {
		if sfDocumentMarker(line) {
			code := "document-start-marker"
			if strings.HasPrefix(line, "...") {
				code = "document-end-marker"
			}
			return sfRefuse(code, 2+i)
		}
	}
	empty := true
	for _, line := range blockLines {
		if !sfBlankOrComment(line) {
			empty = false
			break
		}
	}
	if empty {
		return sfRefuse("frontmatter-empty", 2)
	}
	keys, refusal := sfScanEntries(blockLines, 2)
	if refusal != nil {
		return *refusal
	}
	return sfResult{accepted: true, keys: keys, body: text[ends[closing]:]}
}
