package corpora

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func init() { register(a2aJCS{}) }

// a2aJCS judges vectors-a2a-jcs-v01/, the a2a Agent Card canonicalization
// corpus vendored byte for byte from a2aproject/a2a-tck. Its expected bytes
// came from two RFC 8785 oracles upstream; this reader is a third, written
// here from the RFC text. It checks the corpus digest and every member's
// sha256 against the manifest, then answers every vector for each target the
// manifest names (rfc8785 and card-signing-input) and scores the answer the
// way the upstream runners do. The packaged Python reader is the other rail.
type a2aJCS struct{}

func (a2aJCS) Suite() string { return "a2a-agent-card-canonicalization-conformance" }

const (
	a2aRuleThree = "a2a-spec-8.4.1-rule-3"
	a2aRFCPrefix = "RFC8785-"
)

type a2aManifest struct {
	CorpusDigest string `json:"corpusDigest"`
	Targets      map[string]struct {
		Vectors int `json:"vectors"`
	} `json:"targets"`
	Vectors []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"vectors"`
}

type a2aVector struct {
	ID          string          `json:"id"`
	Clause      string          `json:"clause"`
	Disposition string          `json:"disposition"`
	Input       json.RawMessage `json:"input"`
	InputRaw    *string         `json:"input_raw"`
	Expected    struct {
		Hex string `json:"canonical_utf8_hex"`
	} `json:"expected"`
}

var errA2ARefused = errors.New("no canonical form")

func (a2aJCS) Judge(dir string, raw []byte) (*Result, error) {
	var manifest a2aManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	if finding := a2aDigest(raw, manifest.CorpusDigest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	owned := map[string]int{}
	for _, entry := range manifest.Vectors {
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(entry.Path))) // #nosec G304 -- a path the corpus manifest names
		if err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("%s cannot be read: %v", entry.Path, err))
			continue
		}
		sum := sha256.Sum256(body)
		var v a2aVector
		if err := json.Unmarshal(body, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("%s does not parse: %v", entry.Path, err))
			continue
		}
		member := Member{ID: v.ID, Kind: strings.ToLower(v.Disposition)}
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			member.Findings = append(member.Findings, "the file does not match its manifest sha256")
		}
		for _, target := range []string{"rfc8785", "card-signing-input"} {
			if !a2aOwns(target, v.Clause) {
				continue
			}
			owned[target]++
			if outcome := a2aOutcome(v, target); outcome != "pass" {
				member.Findings = append(member.Findings, target+": "+outcome)
			}
		}
		result.Members = append(result.Members, member)
	}
	for target, declared := range manifest.Targets {
		if owned[target] != declared.Vectors {
			result.Findings = append(result.Findings, fmt.Sprintf(
				"target %s declares %d vectors and owns %d", target, declared.Vectors, owned[target]))
		}
	}
	return result, nil
}

// a2aDigest recomputes the upstream corpus digest from the file bytes: the
// sha256 of the manifest as written without its last member, corpusDigest.
func a2aDigest(raw []byte, declared string) string {
	tail := []byte(",\n  \"corpusDigest\": \"" + declared + "\"\n}\n")
	if !bytes.HasSuffix(raw, tail) {
		return "MANIFEST.json does not end with its corpusDigest member as upstream writes it"
	}
	body := append(append([]byte{}, raw[:len(raw)-len(tail)]...), "\n}"...)
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != declared {
		return "corpusDigest does not match the MANIFEST body"
	}
	return ""
}

func a2aOwns(target, clause string) bool {
	if strings.HasPrefix(clause, a2aRFCPrefix) {
		return true
	}
	return target == "card-signing-input" && clause == a2aRuleThree
}

// a2aOutcome answers one vector for one target and scores it: pass,
// diverged, refused, or accepted.
func a2aOutcome(v a2aVector, target string) string {
	text := []byte(v.Input)
	if v.InputRaw != nil {
		text = []byte(*v.InputRaw)
	}
	produced, err := a2aAnswer(target, text)
	if v.Disposition == "MUST-ACCEPT" {
		want, herr := hex.DecodeString(v.Expected.Hex)
		switch {
		case herr != nil:
			return "the expected bytes are not hex"
		case err != nil:
			return "refused"
		case !bytes.Equal(produced, want):
			return fmt.Sprintf("diverged: got %q want %q", produced, want)
		}
		return "pass"
	}
	if v.Clause == a2aRuleThree {
		if err != nil {
			return "refused a well-formed card"
		}
		if bytes.Equal(produced, text) {
			return "accepted: the signing bytes still carry signatures"
		}
		return "pass"
	}
	if err == nil {
		return fmt.Sprintf("accepted: produced %q for input with no canonical form", produced)
	}
	return "pass"
}

func a2aAnswer(target string, text []byte) ([]byte, error) {
	if !utf8.Valid(text) || a2aLoneSurrogate(text) {
		return nil, errA2ARefused
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, errA2ARefused
	}
	if card, ok := value.(map[string]any); ok && target == "card-signing-input" {
		delete(card, "signatures")
	}
	var buf strings.Builder
	if err := a2aWrite(&buf, value); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// a2aLoneSurrogate reports a \u escape naming a surrogate that is not half of
// a pair. encoding/json would replace it with U+FFFD and canonicalize the
// replacement, which is the silent repair RFC 8785 input must refuse.
func a2aLoneSurrogate(text []byte) bool {
	s := string(text)
	for i := 0; i+5 < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		if s[i+1] != 'u' {
			i++
			continue
		}
		code, err := strconv.ParseUint(s[i+2:i+6], 16, 16)
		if err != nil {
			return true
		}
		switch {
		case code >= 0xDC00 && code <= 0xDFFF:
			return true
		case code >= 0xD800 && code <= 0xDBFF:
			if i+12 > len(s) {
				return true
			}
			if s[i+6] != '\\' || s[i+7] != 'u' {
				return true
			}
			low, err := strconv.ParseUint(s[i+8:i+12], 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return true
			}
			i += 11
		default:
			i += 5
		}
	}
	return false
}

func a2aWrite(buf *strings.Builder, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case json.Number:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return errA2ARefused
		}
		buf.WriteString(a2aNumber(f))
	case string:
		a2aString(buf, v)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := a2aWrite(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return a2aUTF16Less(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			a2aString(buf, k)
			buf.WriteByte(':')
			if err := a2aWrite(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return errA2ARefused
	}
	return nil
}

func a2aUTF16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func a2aString(buf *strings.Builder, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// a2aNumber is ECMAScript Number::toString of a finite double: the shortest
// round-tripping digits, placed by the specification's four cases.
func a2aNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	if f < 0 {
		return "-" + a2aNumber(-f)
	}
	sci := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±XX
	mant, expText, _ := strings.Cut(sci, "e")
	exp, _ := strconv.Atoi(expText)
	digits := strings.TrimRight(strings.Replace(mant, ".", "", 1), "0")
	k, n := len(digits), exp+1
	switch {
	case k <= n && n <= 21:
		return digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + digits
	}
	e := n - 1
	sign := "+"
	if e < 0 {
		sign, e = "-", -e
	}
	if k == 1 {
		return digits + "e" + sign + strconv.Itoa(e)
	}
	return digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(e)
}
