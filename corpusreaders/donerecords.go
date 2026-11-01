package corpora

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The records of a done run, and the rules a reader names a refused record under.
//
// This file mirrors packaging/agent_evidence_vectors/donerecords.py rule for rule and
// code for code, and spec/predicates/done-records.md states the rules. Both restate the
// done adapters of probity-verify (probityai/probity, packages/probity-verify). A record
// is refused at the first rule it breaks, in the order the specification lists them, so
// the two rails give one code.

// doneObject is a decoded JSON object.
type doneObject = map[string]any

// doneError is a refused record: no verdict was reached.
type doneError struct{ code string }

func (e *doneError) Error() string { return e.code }

func refuse(code string) error { return &doneError{code} }

var (
	doneMutations = map[string]bool{"write": true, "create": true, "rename": true, "link": true,
		"unlink": true, "truncate": true, "chmod": true}
	doneMutationList = []string{"chmod", "create", "link", "rename", "truncate", "unlink", "write"}
	doneHex64        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	doneInstant      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	doneInt          = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	doneOrigin       = []string{"claim_id", "invocation_id", "producer", "vantage", "witness_scope"}
	doneScopes       = []string{"PEER", "EXTERNAL"}
	doneVantages     = []string{"independent", "self_reported"}
	doneLoaderEnv    = map[string]bool{"PATH": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
		"LD_AUDIT": true, "PYTHONPATH": true, "PYTHONHOME": true, "PYTHONSAFEPATH": true,
		"PYTHONSTARTUP": true, "PYTHONUSERBASE": true, "PYTHONNOUSERSITE": true,
		"PYTHONPYCACHEPREFIX": true, "PYTHONWARNINGS": true, "PYTEST_ADDOPTS": true,
		"PYTEST_PLUGINS": true, "NODE_OPTIONS": true, "NODE_PATH": true}
	doneGraderFiles    = map[string]bool{"sitecustomize.py": true, "usercustomize.py": true, "reward.json": true, "reward.txt": true}
	doneGraderSegments = map[string]bool{"site-packages": true, "dist-packages": true, "verifier": true}
	doneAncestorConfig = map[string]bool{"conftest.py": true, "pytest.ini": true, "pyproject.toml": true,
		"tox.ini": true, "setup.cfg": true}
	doneSurfaceForbidden = map[string]bool{"/": true, "/tmp": true, "/var/tmp": true}
	doneExecFields       = []string{"argv", "exit", "exe", "cwd", "env"}
	doneDetectorReasons  = []string{"impure_on_visible", "type_strict_on_visible", "repeat_divergence", "isolated_branch"}
)

const (
	doneMaxArtifact = 16 * 1024 * 1024
	doneAliasHops   = 40
	doneUnwitnessed = "no witness bundle is pinned for this record"
)

// --- strict JSON and member rules ---------------------------------------------------------

// doneStrictJSON parses UTF-8 JSON, refusing a duplicate member and a non-JSON number.
func doneStrictJSON(data []byte, record string) (any, error) {
	if !utf8.Valid(data) {
		return nil, refuse(record + "_json_invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := doneDecode(dec, record)
	if err == nil {
		if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
			err = refuse(record + "_json_invalid")
		}
	}
	if err != nil {
		var refused *doneError
		if errors.As(err, &refused) {
			return nil, err
		}
		if doneHasConstant(data) {
			return nil, refuse(record + "_json_number")
		}
		return nil, refuse(record + "_json_invalid")
	}
	return value, nil
}

func doneDecode(dec *json.Decoder, record string) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	if delim == '[' {
		list := []any{}
		for dec.More() {
			item, err := doneDecode(dec, record)
			if err != nil {
				return nil, err
			}
			list = append(list, item)
		}
		_, err = dec.Token()
		return list, err
	}
	object := doneObject{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := key.(string)
		if _, seen := object[name]; seen {
			return nil, refuse(record + "_json_duplicate_key")
		}
		item, err := doneDecode(dec, record)
		if err != nil {
			return nil, err
		}
		object[name] = item
	}
	_, err = dec.Token()
	return object, err
}

// doneHasConstant reports a bare NaN or Infinity outside any string.
func doneHasConstant(data []byte) bool {
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case !inString && (bytes.HasPrefix(data[i:], []byte("NaN")) ||
			bytes.HasPrefix(data[i:], []byte("Infinity")) ||
			bytes.HasPrefix(data[i:], []byte("-Infinity"))):
			return true
		}
	}
	return false
}

func doneFields(value any, record string, required []string, optional ...string) (doneObject, error) {
	object, ok := value.(doneObject)
	if !ok {
		return nil, refuse(record + "_fields")
	}
	allowed := map[string]bool{}
	for _, name := range required {
		allowed[name] = true
		if _, present := object[name]; !present {
			return nil, refuse(record + "_fields")
		}
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name := range object {
		if !allowed[name] {
			return nil, refuse(record + "_fields")
		}
	}
	return object, nil
}

func doneText(value any, code string) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return "", refuse(code)
	}
	return text, nil
}

func doneDigest(value any, code string) (string, error) {
	text, ok := value.(string)
	if !ok || !doneHex64.MatchString(text) {
		return "", refuse(code)
	}
	return text, nil
}

func doneInstantOf(value any, code string) (time.Time, error) {
	text, ok := value.(string)
	if !ok || !doneInstant.MatchString(text) {
		return time.Time{}, refuse(code)
	}
	moment, err := time.Parse("2006-01-02T15:04:05Z", text)
	if err != nil {
		return time.Time{}, refuse(code)
	}
	return moment, nil
}

// doneInteger returns an integer member; JSON `1.0` and `1e2` are not integers.
func doneInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || !doneInt.MatchString(number.String()) {
		return 0, false
	}
	parsed, err := number.Int64()
	return parsed, err == nil
}

func doneCount(value any, code string) (int64, error) {
	n, ok := doneInteger(value)
	if !ok || n < 0 {
		return 0, refuse(code)
	}
	return n, nil
}

func doneExit(value any, code string) (int64, error) {
	n, ok := doneInteger(value)
	if !ok || n < -255 || n > 255 {
		return 0, refuse(code)
	}
	return n, nil
}

func doneChoice(value any, code string, allowed ...string) (string, error) {
	text, ok := value.(string)
	if ok {
		for _, name := range allowed {
			if text == name {
				return text, nil
			}
		}
	}
	return "", refuse(code)
}

func doneRelPath(value any, code string) (string, error) {
	name, err := doneText(value, code)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return "", refuse(code)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return "", refuse(code)
		}
	}
	return name, nil
}

// doneAbsPath is a normalized absolute POSIX path, as the observer writes container paths.
func doneAbsPath(value any, code string) (string, error) {
	name, err := doneText(value, code)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(name, 0) || !strings.HasPrefix(name, "/") || strings.HasPrefix(name, "//") ||
		pyNormpath(name) != name {
		return "", refuse(code)
	}
	return name, nil
}

func doneArgv(value any, code string) ([]string, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return nil, refuse(code)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok {
			return nil, refuse(code)
		}
		out = append(out, text)
	}
	if out[0] == "" {
		return nil, refuse(code)
	}
	return out, nil
}

// doneStrings is a list of strings, or nil when the value is not one.
func doneStrings(value any) []string {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok {
			return nil
		}
		out = append(out, text)
	}
	return out
}

func doneDistinct(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

// doneSortedDistinct reports a list of strings that is sorted and has no repeat.
func doneSortedDistinct(values []string) bool {
	return doneDistinct(values) && sort.StringsAreSorted(values)
}

func doneUnder(name, prefix string) bool {
	return name == prefix || strings.HasPrefix(name, strings.TrimRight(prefix, "/")+"/")
}

// doneProtects reports whether a protected entry covers a path, after its exclusions: a
// name without `/` is a segment left out at any depth, one with `/` a path left out with
// everything below it.
func doneProtects(entry doneObject, name string) bool {
	path, _ := entry["path"].(string)
	if !doneUnder(name, path) {
		return false
	}
	var below []string
	if name != path {
		below = strings.Split(name[len(path)+1:], "/")
	}
	for _, item := range doneStrings(entry["exclude"]) {
		if strings.Contains(item, "/") {
			if doneUnder(name, item) {
				return false
			}
			continue
		}
		for _, part := range below {
			if part == item {
				return false
			}
		}
	}
	return true
}

func doneAncestorConfigPath(name, root string) bool {
	head, base := pySplit(name)
	return doneAncestorConfig[base] && doneUnder(root, head)
}

func doneGraderPath(name string) bool {
	parts := strings.Split(name, "/")
	last := parts[len(parts)-1]
	if doneGraderFiles[last] || strings.HasSuffix(last, ".pth") {
		return true
	}
	for _, part := range parts[:len(parts)-1] {
		if doneGraderSegments[part] {
			return true
		}
	}
	return false
}

func doneSortedLines(lines map[string]string) string {
	names := make([]string, 0, len(lines))
	for name := range lines {
		names = append(names, name)
	}
	sort.Strings(names)
	var text strings.Builder
	for _, name := range names {
		text.WriteString(lines[name] + "  " + name + "\n")
	}
	sum := sha256.Sum256([]byte(text.String()))
	return hex.EncodeToString(sum[:])
}

// doneTreeDigest is the SHA-256 of sorted "<sha256>  <path>\n" lines.
func doneTreeDigest(files map[string]string) string { return doneSortedLines(files) }

// doneRecordDigest is the probity-tree/v2 digest: one sorted line per entry.
func doneRecordDigest(record doneObject) string {
	executable := map[string]bool{}
	for _, name := range doneStrings(record["executable"]) {
		executable[name] = true
	}
	lines := map[string]string{}
	for name, value := range doneObj(record["files"]) {
		digest, _ := value.(string)
		if executable[name] {
			digest = "x:" + digest
		}
		lines[name] = digest
	}
	for name, value := range doneObj(record["symlinks"]) {
		target, _ := value.(string)
		lines[name] = "l:" + sha([]byte(target))
	}
	for name, value := range doneObj(record["special"]) {
		kind, _ := value.(string)
		lines[name] = "s:" + kind
	}
	return doneSortedLines(lines)
}

func doneObj(value any) doneObject {
	object, _ := value.(doneObject)
	return object
}

func doneList(value any) []any {
	list, _ := value.([]any)
	return list
}

func doneStr(value any) string {
	text, _ := value.(string)
	return text
}

func doneNum(value any) int64 {
	n, _ := doneInteger(value)
	return n
}

// --- the done contract --------------------------------------------------------------------

func doneDistinctPaths(value any, code string) ([]string, error) {
	values := doneStrings(value)
	if values == nil || !doneDistinct(values) {
		return nil, refuse(code)
	}
	for _, item := range values {
		if _, err := doneRelPath(item, code); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func doneExclude(value any, entryPath, kind string) error {
	const code = "contract_exclude_invalid"
	list, ok := value.([]any)
	if kind != "directory" || !ok || len(list) == 0 {
		return refuse(code)
	}
	names := doneStrings(value)
	if names == nil || !doneDistinct(names) {
		return refuse(code)
	}
	for _, item := range names {
		if strings.Contains(item, "/") {
			if _, err := doneRelPath(item, code); err != nil {
				return err
			}
			if item == entryPath || !doneUnder(item, entryPath) {
				return refuse(code)
			}
		} else if item == "" || item == "." || item == ".." || strings.ContainsRune(item, 0) {
			return refuse(code)
		}
	}
	return nil
}

func doneProtectedEntry(item any) (doneObject, error) {
	entry, err := doneFields(item, "contract_protected_path", []string{"path", "kind", "sha256"}, "exclude", "equivalence")
	if err != nil {
		return nil, err
	}
	name, err := doneRelPath(entry["path"], "contract_protected_path_not_normalized")
	if err != nil {
		return nil, err
	}
	kind, err := doneChoice(entry["kind"], "contract_protected_kind", "file", "directory")
	if err != nil {
		return nil, err
	}
	if _, err := doneDigest(entry["sha256"], "contract_digest_malformed"); err != nil {
		return nil, err
	}
	if _, present := entry["exclude"]; present {
		if err := doneExclude(entry["exclude"], name, kind); err != nil {
			return nil, err
		}
	}
	if _, present := entry["equivalence"]; present {
		if _, err := doneChoice(entry["equivalence"], "contract_equivalence", "python_ast"); err != nil {
			return nil, err
		}
		if kind != "file" {
			return nil, refuse("contract_equivalence")
		}
	}
	return entry, nil
}

func doneSortedAbsolute(value any, code string) error {
	values := doneStrings(value)
	if len(values) == 0 || !doneSortedDistinct(values) {
		return refuse(code)
	}
	for _, name := range values {
		if _, err := doneAbsPath(name, code); err != nil {
			return err
		}
	}
	return nil
}

func doneSeal(entry doneObject) error {
	_, hasCwd := entry["cwd"]
	_, hasExe := entry["exe"]
	if hasCwd != hasExe {
		return refuse("contract_acceptance_seal")
	}
	if hasCwd {
		if _, err := doneAbsPath(entry["cwd"], "contract_acceptance_seal"); err != nil {
			return err
		}
		if _, isList := entry["exe"].([]any); isList {
			if err := doneSortedAbsolute(entry["exe"], "contract_acceptance_seal"); err != nil {
				return err
			}
		} else if _, err := doneAbsPath(entry["exe"], "contract_acceptance_seal"); err != nil {
			return err
		}
	}
	if _, present := entry["interpreter"]; present {
		if !hasExe {
			return refuse("contract_acceptance_interpreter")
		}
		if err := doneSortedAbsolute(entry["interpreter"], "contract_acceptance_interpreter"); err != nil {
			return err
		}
	}
	return nil
}

func doneAcceptanceEntry(item any) (doneObject, error) {
	entry, err := doneFields(item, "contract_acceptance", []string{"id", "argv"},
		"ids", "run_writes", "cwd", "exe", "interpreter", "tier", "probe", "in_process_twin_of")
	if err != nil {
		return nil, err
	}
	if _, present := entry["tier"]; present {
		if _, err := doneChoice(entry["tier"], "contract_acceptance_tier", "trusted", "synthesized"); err != nil {
			return nil, err
		}
	}
	if _, present := entry["probe"]; present {
		if _, err := doneChoice(entry["probe"], "contract_acceptance_probe", "determinism", "type_strict", "import_side_effects"); err != nil {
			return nil, err
		}
	}
	if _, err := doneText(entry["id"], "contract_acceptance_id"); err != nil {
		return nil, err
	}
	if _, err := doneArgv(entry["argv"], "contract_acceptance_argv"); err != nil {
		return nil, err
	}
	if err := doneSeal(entry); err != nil {
		return nil, err
	}
	return entry, doneCommandExtras(entry)
}

// doneCommandExtras checks a command's twin, sealed test ids and run writes.
func doneCommandExtras(entry doneObject) error {
	if _, present := entry["in_process_twin_of"]; present {
		if _, err := doneText(entry["in_process_twin_of"], "contract_acceptance_twin"); err != nil {
			return err
		}
	}
	if _, present := entry["ids"]; present {
		ids := doneStrings(entry["ids"])
		if len(ids) == 0 || !doneDistinct(ids) {
			return refuse("contract_acceptance_ids")
		}
		for _, id := range ids {
			if id == "" {
				return refuse("contract_acceptance_ids")
			}
		}
	}
	if _, present := entry["run_writes"]; present {
		if _, err := doneDistinctPaths(entry["run_writes"], "contract_acceptance_run_writes"); err != nil {
			return err
		}
	}
	return nil
}

func doneContractHead(record doneObject) error {
	if _, present := record["strength"]; present {
		if _, err := doneChoice(record["strength"], "contract_strength", "gated", "reference_free", "synthesized_spec"); err != nil {
			return err
		}
	}
	if raw, present := record["native_loaded"]; present {
		list, ok := raw.([]any)
		if !ok {
			return refuse("contract_native_loaded")
		}
		for _, item := range list {
			entry, err := doneFields(item, "contract_native_loaded", []string{"path", "sha256"})
			if err != nil {
				return err
			}
			if _, err := doneRelPath(entry["path"], "contract_native_loaded"); err != nil {
				return err
			}
			if _, err := doneDigest(entry["sha256"], "contract_native_loaded"); err != nil {
				return err
			}
		}
	}
	if record["schema_version"] != "probity-done-contract/v1" {
		return refuse("contract_schema_unsupported")
	}
	if _, err := doneText(record["contract_id"], "contract_id"); err != nil {
		return err
	}
	if _, present := record["task"]; present {
		if _, err := doneText(record["task"], "contract_task"); err != nil {
			return err
		}
	}
	for _, key := range []string{"heldout_split_sha256", "mutant_set_sha256", "authority_sha256"} {
		if _, present := record[key]; present {
			if _, err := doneDigest(record[key], "contract_digest_malformed"); err != nil {
				return err
			}
		}
	}
	return nil
}

func doneProtectedList(value any) error {
	list, ok := value.([]any)
	if !ok {
		return refuse("contract_protected_paths_type")
	}
	seen := map[string]bool{}
	for _, item := range list {
		entry, err := doneProtectedEntry(item)
		if err != nil {
			return err
		}
		name := doneStr(entry["path"])
		if seen[name] {
			return refuse("contract_protected_duplicate")
		}
		seen[name] = true
	}
	return nil
}

func doneAcceptanceList(value any) error {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return refuse("contract_acceptance_empty")
	}
	ids := map[string]bool{}
	for _, item := range list {
		entry, err := doneAcceptanceEntry(item)
		if err != nil {
			return err
		}
		id := doneStr(entry["id"])
		if ids[id] {
			return refuse("contract_acceptance_duplicate_id")
		}
		ids[id] = true
	}
	for _, item := range list {
		entry := doneObj(item)
		raw, present := entry["in_process_twin_of"]
		if !present {
			continue
		}
		twin := doneStr(raw)
		if twin == doneStr(entry["id"]) || !ids[twin] {
			return refuse("contract_acceptance_twin")
		}
		for _, other := range list {
			otherEntry := doneObj(other)
			if _, probe := otherEntry["probe"]; probe && doneStr(otherEntry["id"]) == twin {
				return refuse("contract_acceptance_twin")
			}
		}
	}
	return nil
}

func doneSurfaceRule(record doneObject) error {
	if _, present := record["execution_surface"]; present {
		if err := doneSortedAbsolute(record["execution_surface"], "contract_execution_surface"); err != nil {
			return err
		}
		for _, name := range doneStrings(record["execution_surface"]) {
			if doneSurfaceForbidden[name] {
				return refuse("contract_execution_surface_shared_root")
			}
		}
	}
	if raw, present := record["surface_aliases"]; present {
		aliases, ok := raw.(doneObject)
		if _, surface := record["execution_surface"]; !ok || !surface {
			return refuse("contract_surface_aliases")
		}
		for link, target := range aliases {
			if _, err := doneAbsPath(link, "contract_surface_aliases"); err != nil {
				return err
			}
			if _, err := doneAbsPath(target, "contract_surface_aliases"); err != nil {
				return err
			}
		}
	}
	return nil
}

func doneAdequacy(value any) error {
	adequacy, err := doneFields(value, "contract_adequacy", []string{"mutants", "killed"}, "by_class", "kill_vector_sha256", "gates")
	if err != nil {
		return err
	}
	if raw, present := adequacy["gates"]; present {
		gates, ok := raw.(doneObject)
		if !ok {
			return refuse("contract_adequacy_gates")
		}
		for _, gate := range gates {
			pass, isBool := doneObj(gate)["pass"].(bool)
			_ = pass
			if _, isObject := gate.(doneObject); !isObject || !isBool {
				return refuse("contract_adequacy_gates")
			}
		}
	}
	mutants, err := doneCount(adequacy["mutants"], "contract_adequacy_count")
	if err != nil {
		return err
	}
	killed, err := doneCount(adequacy["killed"], "contract_adequacy_count")
	if err != nil {
		return err
	}
	if killed > mutants {
		return refuse("contract_adequacy_overcount")
	}
	if _, present := adequacy["kill_vector_sha256"]; present {
		if _, err := doneDigest(adequacy["kill_vector_sha256"], "contract_digest_malformed"); err != nil {
			return err
		}
	}
	if raw, present := adequacy["by_class"]; present {
		return doneByClass(raw, mutants, killed)
	}
	return nil
}

func doneByClass(raw any, mutants, killed int64) error {
	const code = "contract_adequacy_by_class"
	classes, ok := raw.(doneObject)
	if !ok || len(classes) == 0 {
		return refuse(code)
	}
	var made, dead int64
	for name, value := range classes {
		if name == "" {
			return refuse(code)
		}
		counts, err := doneFields(value, code, []string{"mutants", "killed"})
		if err != nil {
			return err
		}
		m, err := doneCount(counts["mutants"], code)
		if err != nil {
			return err
		}
		k, err := doneCount(counts["killed"], code)
		if err != nil {
			return err
		}
		if k > m {
			return refuse(code)
		}
		made, dead = made+m, dead+k
	}
	if made != mutants || dead != killed {
		return refuse(code)
	}
	return nil
}

func doneContract(data []byte) (doneObject, error) {
	raw, err := doneStrictJSON(data, "contract")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(raw, "contract",
		[]string{"schema_version", "contract_id", "protected_paths", "acceptance", "adequacy"},
		"task", "heldout_split_sha256", "mutant_set_sha256", "authority_sha256", "module_under_test",
		"strength", "native_loaded", "execution_surface", "surface_aliases")
	if err != nil {
		return nil, err
	}
	for _, step := range []func() error{
		func() error { return doneContractHead(record) },
		func() error { return doneProtectedList(record["protected_paths"]) },
		func() error { return doneAcceptanceList(record["acceptance"]) },
		func() error { return doneSurfaceRule(record) },
		func() error { return doneAdequacy(record["adequacy"]) },
	} {
		if err := step(); err != nil {
			return nil, err
		}
	}
	if _, present := record["module_under_test"]; present {
		modules, err := doneDistinctPaths(record["module_under_test"], "contract_module_under_test")
		if err != nil {
			return nil, err
		}
		if len(modules) == 0 {
			return nil, refuse("contract_module_under_test")
		}
	}
	return record, nil
}

// doneSurface is the contract's execution surface and aliases, checked against the run.
func doneSurface(contract, record doneObject) ([]string, map[string]string, error) {
	if contract == nil || record == nil {
		return nil, nil, nil
	}
	if _, present := contract["execution_surface"]; !present {
		return nil, nil, nil
	}
	root := doneStr(record["workspace_root"])
	entries := doneStrings(contract["execution_surface"])
	for _, name := range entries {
		if doneUnder(name, root) || doneUnder(root, name) {
			return nil, nil, refuse("contract_execution_surface_covers_workspace")
		}
	}
	aliases := map[string]string{}
	for link, target := range doneObj(contract["surface_aliases"]) {
		aliases[link] = doneStr(target)
	}
	return entries, aliases, nil
}

// doneResolve replaces each image link prefix by what it resolves to, longest first.
func doneResolve(name string, aliases map[string]string) (string, error) {
	for hop := 0; hop < doneAliasHops; hop++ {
		link := ""
		found := false
		for key := range aliases {
			if doneUnder(name, key) && (!found || len(key) > len(link)) {
				link, found = key, true
			}
		}
		if !found {
			return name, nil
		}
		name = strings.TrimRight(aliases[link], "/") + name[len(link):]
		if name == "" {
			name = "/"
		}
	}
	return "", refuse("contract_surface_aliases_cycle")
}

func doneOnSurface(name string, entries []string, aliases map[string]string) (bool, error) {
	resolved, err := doneResolve(name, aliases)
	if err != nil {
		return false, err
	}
	for _, candidate := range []string{name, resolved} {
		for _, entry := range entries {
			if doneUnder(candidate, entry) {
				return true, nil
			}
		}
	}
	return false, nil
}

// doneSurfaceEffects reports an outside mutation of any type on the execution surface.
func doneSurfaceEffects(record doneObject, entries []string, aliases map[string]string) (bool, error) {
	for _, item := range doneList(record["external_mutations"]) {
		for _, name := range doneStrings(doneObj(item)["paths"]) {
			on, err := doneOnSurface(name, entries, aliases)
			if err != nil || on {
				return on, err
			}
		}
	}
	return false, nil
}

// --- the observed records ---------------------------------------------------------------

func doneOriginFields(record doneObject, name string) error {
	for _, key := range []string{"claim_id", "invocation_id", "producer"} {
		if _, err := doneText(record[key], name+"_"+key); err != nil {
			return err
		}
	}
	if _, err := doneChoice(record["vantage"], name+"_vantage", doneVantages...); err != nil {
		return err
	}
	_, err := doneChoice(record["witness_scope"], name+"_witness_scope", doneScopes...)
	return err
}

func doneTreeEntries(record doneObject) ([]string, error) {
	names := []string{}
	for _, member := range []string{"files", "symlinks", "special"} {
		entries, ok := record[member].(doneObject)
		if !ok {
			return nil, refuse("tree_entries_type")
		}
		keys := make([]string, 0, len(entries))
		for name := range entries {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			if _, err := doneRelPath(name, "tree_path_not_normalized"); err != nil {
				return nil, err
			}
			names = append(names, name)
			var err error
			switch member {
			case "files":
				_, err = doneDigest(entries[name], "tree_digest_malformed")
			case "symlinks":
				_, err = doneText(entries[name], "tree_symlink_target")
			default:
				_, err = doneChoice(entries[name], "tree_special_kind", "fifo", "socket", "char", "block")
			}
			if err != nil {
				return nil, err
			}
		}
	}
	return names, nil
}

func doneTree(data []byte) (doneObject, error) {
	raw, err := doneStrictJSON(data, "tree")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(raw, "tree", append([]string{"schema_version", "tree_sha256", "files",
		"executable", "symlinks", "special"}, doneOrigin...))
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-tree/v2" {
		return nil, refuse("tree_schema_unsupported")
	}
	if err := doneOriginFields(record, "tree"); err != nil {
		return nil, err
	}
	names, err := doneTreeEntries(record)
	if err != nil {
		return nil, err
	}
	if !doneDistinct(names) {
		return nil, refuse("tree_path_duplicate")
	}
	sort.Strings(names)
	for i := 1; i < len(names); i++ {
		if doneUnder(names[i], names[i-1]) {
			return nil, refuse("tree_path_nested")
		}
	}
	executable := doneStrings(record["executable"])
	files := doneObj(record["files"])
	if executable == nil || !doneSortedDistinct(executable) {
		return nil, refuse("tree_executable")
	}
	for _, name := range executable {
		if _, listed := files[name]; !listed {
			return nil, refuse("tree_executable")
		}
	}
	computed := doneRecordDigest(record)
	stated, err := doneDigest(record["tree_sha256"], "tree_digest_malformed")
	if err != nil {
		return nil, err
	}
	if computed != stated {
		return nil, refuse("tree_digest_mismatch")
	}
	return record, nil
}

func doneScope(value any, name string) (doneObject, error) {
	found, err := doneFields(value, name+"_scope", []string{"id", "start", "end"})
	if err != nil {
		return nil, err
	}
	if _, err := doneText(found["id"], name+"_scope_id"); err != nil {
		return nil, err
	}
	start, err := doneInstantOf(found["start"], name+"_scope_instant")
	if err != nil {
		return nil, err
	}
	end, err := doneInstantOf(found["end"], name+"_scope_instant")
	if err != nil {
		return nil, err
	}
	if end.Before(start) {
		return nil, refuse(name + "_scope_order")
	}
	return found, nil
}

func doneGaps(record doneObject, start, end time.Time) error {
	gaps, present := record["gaps"]
	if record["coverage"] == "incomplete" {
		if list, ok := gaps.([]any); !present || !ok || len(list) == 0 {
			return refuse("observation_gaps_required")
		}
	} else if present {
		return refuse("observation_gaps_unexpected")
	}
	for _, item := range doneList(gaps) {
		gap, err := doneFields(item, "observation_gap", []string{"start", "end", "gap_cause"})
		if err != nil {
			return err
		}
		if _, err := doneChoice(gap["gap_cause"], "observation_gap_cause", "agent", "host", "sensor", "unknown"); err != nil {
			return err
		}
		from, err := doneInstantOf(gap["start"], "observation_gap_instant")
		if err != nil {
			return err
		}
		to, err := doneInstantOf(gap["end"], "observation_gap_instant")
		if err != nil {
			return err
		}
		if from.Before(start) || !from.Before(to) || to.After(end) {
			return refuse("observation_gap_outside_scope")
		}
	}
	return nil
}

func doneExecFieldsRule(event doneObject) error {
	if _, err := doneArgv(event["argv"], "observation_exec_argv"); err != nil {
		return err
	}
	if _, err := doneAbsPath(event["exe"], "observation_exec_exe"); err != nil {
		return err
	}
	if _, err := doneAbsPath(event["cwd"], "observation_exec_cwd"); err != nil {
		return err
	}
	env, ok := event["env"].(doneObject)
	if !ok {
		return refuse("observation_exec_env")
	}
	for key, value := range env {
		if _, isText := value.(string); !doneLoaderEnv[key] || !isText {
			return refuse("observation_exec_env")
		}
	}
	if _, present := event["exit"]; present {
		if _, err := doneExit(event["exit"], "observation_exec_exit"); err != nil {
			return err
		}
	}
	for _, key := range []string{"path", "target", "address"} {
		if _, present := event[key]; present {
			return refuse("observation_exec_path")
		}
	}
	return nil
}

func doneOtherFields(event doneObject, kind string) error {
	for _, key := range doneExecFields {
		if _, present := event[key]; present {
			return refuse("observation_argv_on_file_event")
		}
	}
	_, hasPath := event["path"]
	_, hasTarget := event["target"]
	if kind == "connect" {
		if _, isText := event["address"].(string); !isText || hasPath || hasTarget {
			return refuse("observation_connect_address")
		}
		return nil
	}
	if _, present := event["address"]; present {
		return refuse("observation_address_unexpected")
	}
	if doneMutations[kind] && !hasPath {
		return refuse("observation_path_required")
	}
	if hasPath {
		if _, err := doneRelPath(event["path"], "observation_path_not_normalized"); err != nil {
			return err
		}
	}
	if hasTarget {
		if kind != "rename" && kind != "link" {
			return refuse("observation_target_unexpected")
		}
		if _, err := doneRelPath(event["target"], "observation_path_not_normalized"); err != nil {
			return err
		}
	}
	return nil
}

func doneEvent(item any, execIDs map[string]bool) (doneObject, error) {
	event, err := doneFields(item, "observation_event", []string{"id", "type", "time", "step"},
		"path", "target", "origin", "address", "argv", "exit", "exe", "cwd", "env")
	if err != nil {
		return nil, err
	}
	if _, err := doneText(event["id"], "observation_event_id"); err != nil {
		return nil, err
	}
	kind, err := doneText(event["type"], "observation_event_type")
	if err != nil {
		return nil, err
	}
	if _, err := doneCount(event["step"], "observation_step"); err != nil {
		return nil, err
	}
	if origin, present := event["origin"]; present && !execIDs[doneStr(origin)] {
		return nil, refuse("observation_origin_unknown")
	}
	if kind == "exec" {
		err = doneExecFieldsRule(event)
	} else {
		err = doneOtherFields(event, kind)
	}
	return event, err
}

func doneExternal(item any, execIDs map[string]bool, root string) (doneObject, error) {
	entry, err := doneFields(item, "observation_external", []string{"id", "step", "time", "type", "paths", "location"}, "origin")
	if err != nil {
		return nil, err
	}
	if _, err := doneText(entry["id"], "observation_external_id"); err != nil {
		return nil, err
	}
	if _, err := doneCount(entry["step"], "observation_step"); err != nil {
		return nil, err
	}
	if _, err := doneChoice(entry["type"], "observation_external_type", doneMutationList...); err != nil {
		return nil, err
	}
	if _, err := doneChoice(entry["location"], "observation_external_location", "grader_path", "outside_workspace"); err != nil {
		return nil, err
	}
	paths, ok := entry["paths"].([]any)
	if !ok || len(paths) == 0 {
		return nil, refuse("observation_external_paths")
	}
	for _, name := range paths {
		found, err := doneAbsPath(name, "observation_external_paths")
		if err != nil {
			return nil, err
		}
		if doneUnder(found, root) {
			return nil, refuse("observation_external_in_workspace")
		}
	}
	if origin, present := entry["origin"]; present && !execIDs[doneStr(origin)] {
		return nil, refuse("observation_origin_unknown")
	}
	return entry, nil
}

type doneRow struct {
	item    any
	outside bool
	index   int
	step    int64
}

// doneRows are both lists' entries in step order (a stable sort, events first on a tie).
func doneRows(events, external []any) ([]doneRow, error) {
	rows := []doneRow{}
	for index, item := range events {
		rows = append(rows, doneRow{item: item, index: index})
	}
	for index, item := range external {
		rows = append(rows, doneRow{item: item, outside: true, index: index})
	}
	for i := range rows {
		step, ok := doneInteger(doneObj(rows[i].item)["step"])
		if _, isObject := rows[i].item.(doneObject); !isObject || !ok {
			return nil, refuse("observation_step")
		}
		rows[i].step = step
	}
	sort.SliceStable(rows, func(a, b int) bool { return rows[a].step < rows[b].step })
	return rows, nil
}

func doneObservationEvents(record doneObject, root string, start, end time.Time) error {
	events, eventsOK := record["events"].([]any)
	external, externalOK := record["external_mutations"].([]any)
	if !eventsOK || !externalOK {
		return refuse("observation_events_type")
	}
	rows, err := doneRows(events, external)
	if err != nil {
		return err
	}
	seen, steps, execIDs := map[string]bool{}, map[int64]bool{}, map[string]bool{}
	next := map[bool]int{false: 0, true: 0}
	for _, row := range rows {
		var entry doneObject
		if row.outside {
			entry, err = doneExternal(row.item, execIDs, root)
		} else {
			entry, err = doneEvent(row.item, execIDs)
		}
		if err != nil {
			return err
		}
		moment, err := doneInstantOf(entry["time"], "observation_event_instant")
		if err != nil {
			return err
		}
		if steps[row.step] || row.index != next[row.outside] {
			return refuse("observation_steps_not_increasing")
		}
		next[row.outside]++
		id := doneStr(entry["id"])
		if seen[id] || moment.Before(start) || moment.After(end) {
			return refuse("observation_event_duplicate_or_outside")
		}
		seen[id], steps[row.step] = true, true
		if !row.outside && entry["type"] == "exec" {
			execIDs[id] = true
		}
	}
	return nil
}

func doneObservation(data []byte) (doneObject, error) {
	raw, err := doneStrictJSON(data, "observation")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(raw, "observation", append([]string{"schema_version", "scope", "coverage",
		"workspace_root", "events", "external_mutations"}, doneOrigin...), "gaps")
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-observation/v3" {
		return nil, refuse("observation_schema_unsupported")
	}
	if err := doneOriginFields(record, "observation"); err != nil {
		return nil, err
	}
	scope, err := doneScope(record["scope"], "observation")
	if err != nil {
		return nil, err
	}
	root, err := doneAbsPath(record["workspace_root"], "observation_workspace_root")
	if err != nil {
		return nil, err
	}
	if _, err := doneChoice(record["coverage"], "observation_coverage", "complete", "incomplete", "unknown"); err != nil {
		return nil, err
	}
	start, _ := doneInstantOf(scope["start"], "observation_scope_instant")
	end, _ := doneInstantOf(scope["end"], "observation_scope_instant")
	if err := doneGaps(record, start, end); err != nil {
		return nil, err
	}
	if err := doneObservationEvents(record, root, start, end); err != nil {
		return nil, err
	}
	return record, nil
}

// doneWritten is every container path the run made or changed, before a step when one is given.
func doneWritten(record doneObject, events []any, before int64, bounded bool) map[string]bool {
	root := strings.TrimRight(doneStr(record["workspace_root"]), "/")
	found := map[string]bool{}
	for _, item := range events {
		event := doneObj(item)
		kind := doneStr(event["type"])
		if !doneMutations[kind] || kind == "unlink" || (bounded && doneNum(event["step"]) >= before) {
			continue
		}
		for _, key := range []string{"path", "target"} {
			if name, present := event[key]; present {
				found[root+"/"+doneStr(name)] = true
			}
		}
	}
	for _, item := range doneList(record["external_mutations"]) {
		entry := doneObj(item)
		if entry["type"] == "unlink" || (bounded && doneNum(entry["step"]) >= before) {
			continue
		}
		for _, name := range doneStrings(entry["paths"]) {
			found[name] = true
		}
	}
	return found
}

// doneAgentGap is the contradiction a gap the agent caused gives, or "".
func doneAgentGap(record doneObject) string {
	agent := false
	for _, item := range doneList(record["gaps"]) {
		gap := doneObj(item)
		if gap["gap_cause"] != "agent" {
			continue
		}
		agent = true
		if gap["end"] == doneObj(record["scope"])["end"] {
			return "tracer_terminated_prematurely"
		}
	}
	if agent {
		return "coverage_sabotaged"
	}
	return ""
}

func doneExternalGraderEffects(record doneObject) bool {
	root := doneStr(record["workspace_root"])
	for _, item := range doneList(record["external_mutations"]) {
		entry := doneObj(item)
		if entry["location"] == "grader_path" {
			return true
		}
		for _, name := range doneStrings(entry["paths"]) {
			if doneGraderPath(name) || doneAncestorConfigPath(name, root) {
				return true
			}
		}
	}
	return false
}

func doneCapability(data []byte) (doneObject, error) {
	raw, err := doneStrictJSON(data, "capability")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(raw, "capability", []string{"schema_version", "claim_id", "invocation_id", "producer", "visible_event_types"})
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-capabilities/v1" {
		return nil, refuse("capability_schema_unsupported")
	}
	for _, key := range []string{"claim_id", "invocation_id", "producer"} {
		if _, err := doneText(record[key], "capability_"+key); err != nil {
			return nil, err
		}
	}
	types := doneStrings(record["visible_event_types"])
	if types == nil {
		return nil, refuse("capability_types")
	}
	for _, kind := range types {
		if kind == "" {
			return nil, refuse("capability_types")
		}
	}
	if !doneDistinct(types) {
		return nil, refuse("capability_types_duplicate")
	}
	return record, nil
}

func doneResult(item any) (doneObject, error) {
	entry, err := doneFields(item, "grade_result", []string{"id", "argv", "exit"}, "collected", "replay", "timed_out", "failure_kind")
	if err != nil {
		return nil, err
	}
	if _, err := doneText(entry["id"], "grade_result_id"); err != nil {
		return nil, err
	}
	if _, err := doneArgv(entry["argv"], "grade_result_argv"); err != nil {
		return nil, err
	}
	exit, err := doneExit(entry["exit"], "grade_result_exit")
	if err != nil {
		return nil, err
	}
	if raw, present := entry["timed_out"]; present {
		if flag, ok := raw.(bool); !ok || !flag || exit == 0 {
			return nil, refuse("grade_result_timed_out")
		}
	}
	if _, present := entry["failure_kind"]; present {
		if _, err := doneChoice(entry["failure_kind"], "grade_result_failure_kind", "assertion", "candidate_exit", "candidate"); err != nil {
			return nil, err
		}
		if exit == 0 {
			return nil, refuse("grade_result_failure_kind")
		}
	}
	if _, present := entry["collected"]; present {
		if _, err := doneCount(entry["collected"], "grade_result_collected"); err != nil {
			return nil, err
		}
	}
	if _, present := entry["replay"]; present {
		if err := doneReplay(entry["replay"]); err != nil {
			return nil, err
		}
	}
	return entry, nil
}

func doneReplay(value any) error {
	replay, err := doneFields(value, "grade_result_replay", []string{"calls_intercepted", "distinct_calls"})
	if err != nil {
		return err
	}
	calls, err := doneCount(replay["calls_intercepted"], "grade_result_replay")
	if err != nil {
		return err
	}
	distinct, err := doneCount(replay["distinct_calls"], "grade_result_replay")
	if err != nil {
		return err
	}
	if distinct > calls {
		return refuse("grade_result_replay")
	}
	return nil
}

func doneHunk(item any) error {
	hunk, err := doneFields(item, "grade_hunk", []string{"path", "lines", "mutants", "killed"})
	if err != nil {
		return err
	}
	if _, err := doneRelPath(hunk["path"], "grade_hunk"); err != nil {
		return err
	}
	lines, ok := hunk["lines"].([]any)
	if !ok || len(lines) != 2 {
		return refuse("grade_hunk")
	}
	first, okFirst := doneInteger(lines[0])
	last, okLast := doneInteger(lines[1])
	if !okFirst || !okLast || first < 1 || last < 1 || first > last {
		return refuse("grade_hunk")
	}
	killed, err := doneCount(hunk["killed"], "grade_hunk")
	if err != nil {
		return err
	}
	mutants, err := doneCount(hunk["mutants"], "grade_hunk")
	if err != nil {
		return err
	}
	if killed > mutants {
		return refuse("grade_hunk")
	}
	return nil
}

func doneDetectors(value any) error {
	const code = "grade_detectors"
	block, err := doneFields(value, code, []string{"status", "findings"})
	if err != nil {
		return err
	}
	if _, err := doneText(block["status"], code); err != nil {
		return err
	}
	findings, ok := block["findings"].([]any)
	if !ok {
		return refuse(code)
	}
	for _, item := range findings {
		finding, err := doneFields(item, code, []string{"reason", "refuses", "evidence"}, "attribution")
		if err != nil {
			return err
		}
		reason, err := doneText(finding["reason"], code)
		if err != nil {
			return err
		}
		refuses, isBool := finding["refuses"].(bool)
		if !isBool {
			return refuse(code)
		}
		if refuses {
			if _, err := doneChoice(reason, code, doneDetectorReasons...); err != nil {
				return err
			}
		}
		if _, present := finding["attribution"]; present {
			if reason != "visible_test_unsatisfiable" {
				return refuse(code)
			}
			if _, err := doneChoice(finding["attribution"], code, "agent", "test_author"); err != nil {
				return err
			}
		}
	}
	return nil
}

func doneGrade(data []byte) (doneObject, error) {
	raw, err := doneStrictJSON(data, "grade")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(raw, "grade", append([]string{"schema_version", "contract_sha256", "tree_sha256", "results"}, doneOrigin...),
		"hunks", "visible_detectors")
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-acceptance-grade/v1" {
		return nil, refuse("grade_schema_unsupported")
	}
	if err := doneOriginFields(record, "grade"); err != nil {
		return nil, err
	}
	for _, key := range []string{"contract_sha256", "tree_sha256"} {
		if _, err := doneDigest(record[key], "grade_digest_malformed"); err != nil {
			return nil, err
		}
	}
	results, ok := record["results"].([]any)
	if !ok {
		return nil, refuse("grade_results_type")
	}
	seen := map[string]bool{}
	for _, item := range results {
		entry, err := doneResult(item)
		if err != nil {
			return nil, err
		}
		id := doneStr(entry["id"])
		if seen[id] {
			return nil, refuse("grade_result_duplicate_id")
		}
		seen[id] = true
	}
	if raw, present := record["hunks"]; present {
		hunks, ok := raw.([]any)
		if !ok {
			return nil, refuse("grade_hunks_type")
		}
		for _, item := range hunks {
			if err := doneHunk(item); err != nil {
				return nil, err
			}
		}
	}
	if _, present := record["visible_detectors"]; present {
		if err := doneDetectors(record["visible_detectors"]); err != nil {
			return nil, err
		}
	}
	return record, nil
}

func doneClaimEntries(value any) error {
	items, ok := value.([]any)
	if !ok {
		return refuse("claims_type")
	}
	seen := map[string]bool{}
	for _, item := range items {
		entry, err := doneFields(item, "claims_entry", []string{"id", "argv"}, "exit")
		if err != nil {
			return err
		}
		name, err := doneText(entry["id"], "claims_entry_id")
		if err != nil {
			return err
		}
		if _, err := doneArgv(entry["argv"], "claims_entry_argv"); err != nil {
			return err
		}
		if _, present := entry["exit"]; present {
			if _, err := doneExit(entry["exit"], "claims_entry_exit"); err != nil {
				return err
			}
		}
		if seen[name] {
			return refuse("claims_duplicate_id")
		}
		seen[name] = true
	}
	return nil
}

func doneClaims(data []byte) (doneObject, error) {
	raw, err := doneStrictJSON(data, "claims")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(raw, "claims", []string{"schema_version", "claim_id", "invocation_id", "producer", "claims", "completion"})
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-tool-claims/v2" {
		return nil, refuse("claims_schema_unsupported")
	}
	completion, err := doneFields(record["completion"], "claims_completion", []string{"asserted", "basis"})
	if err != nil {
		return nil, err
	}
	asserted, isBool := completion["asserted"].(bool)
	if !isBool {
		return nil, refuse("claims_completion_asserted")
	}
	bases := []string{"none"}
	if asserted {
		bases = []string{"final_text", "tool_claim", "both"}
	}
	if _, err := doneChoice(completion["basis"], "claims_completion_basis", bases...); err != nil {
		return nil, err
	}
	for _, key := range []string{"claim_id", "invocation_id", "producer"} {
		if _, err := doneText(record[key], "claims_"+key); err != nil {
			return nil, err
		}
	}
	if err := doneClaimEntries(record["claims"]); err != nil {
		return nil, err
	}
	return record, nil
}

func doneIndependent(record, pin doneObject, observedParty string) bool {
	return record["vantage"] == "independent" && pin["vantage"] == "independent" &&
		record["producer"] == pin["producer"] && record["producer"] != observedParty
}

// donePair is a record and the consumer's pin for it; the record is nil when unbound.
type donePair struct{ record, pin doneObject }

// doneScopeFields is the witness scope a verdict rests on: always PEER here, since these
// readers verify no witness co-signature, with the EXTERNAL claims nothing earned.
func doneScopeFields(pairs ...donePair) map[string]any {
	out := map[string]any{"witness_scope": "PEER"}
	claims := []any{}
	for _, pair := range pairs {
		if pair.record != nil && pair.record["witness_scope"] == "EXTERNAL" {
			claims = append(claims, map[string]any{"witness": pair.pin["id"], "claimed": "EXTERNAL",
				"earned": "PEER", "reason": doneUnwitnessed})
		}
	}
	if len(claims) > 0 {
		out["unwitnessed_scope_claims"] = claims
	}
	return out
}

// --- consumer case and policy ------------------------------------------------------------

// doneMemberFile reads a regular file under root through no link; nil means absent.
func doneMemberFile(root, name, code string) ([]byte, error) {
	parts := strings.Split(name, "/")
	for index := 1; index < len(parts); index++ {
		info, err := os.Lstat(filepath.Join(root, filepath.Join(parts[:index]...))) // #nosec G703 -- a path the corpus member names inside the directory the caller named
		if os.IsNotExist(err) {
			return nil, nil
		}
		if err != nil || !info.IsDir() {
			return nil, refuse(code)
		}
	}
	target := filepath.Join(root, name)
	info, err := os.Lstat(target) // #nosec G703 -- a path the corpus member names inside the directory the caller named
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > doneMaxArtifact {
		return nil, refuse(code)
	}
	return os.ReadFile(target) // #nosec G304,G703 -- a corpus member the caller named
}

func doneArtifact(root string, meta any) ([]byte, doneObject, error) {
	found, err := doneFields(meta, "case_artifact", []string{"path", "sha256", "length"})
	if err != nil {
		return nil, nil, err
	}
	rel, err := doneText(found["path"], "case_artifact_path")
	if err != nil {
		return nil, nil, err
	}
	if strings.ContainsRune(rel, 0) || strings.HasPrefix(rel, "/") {
		return nil, nil, refuse("case_artifact_path_not_normalized")
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, nil, refuse("case_artifact_path_not_normalized")
		}
	}
	pinned, err := doneDigest(found["sha256"], "case_artifact_digest_malformed")
	if err != nil {
		return nil, nil, err
	}
	length, ok := doneInteger(found["length"])
	if !ok || length < 0 || length > doneMaxArtifact {
		return nil, nil, refuse("case_artifact_length")
	}
	data, err := doneMemberFile(root, rel, "case_artifact_unsafe")
	if err != nil {
		return nil, nil, err
	}
	if data == nil {
		return nil, doneObject{"status": "unavailable"}, nil
	}
	if int64(len(data)) != length || sha(data) != pinned {
		return nil, nil, refuse("case_artifact_binding_mismatch")
	}
	return data, doneObject{"status": "bound", "sha256": pinned}, nil
}

func doneWitness(caseDoc, policy doneObject, id, root string, observed bool) ([]byte, doneObject, error) {
	witnesses := doneObj(policy["witnesses"])
	raw, present := witnesses[id]
	if !present {
		return nil, nil, refuse("policy_witness_unknown")
	}
	needed := []string{"artifact", "sha256", "authority"}
	var optional []string
	if observed {
		needed = append(needed, "producer", "vantage", "witness_scope")
		optional = []string{"witnessed"}
	}
	pinIn, err := doneFields(raw, "policy_witness", needed, optional...)
	if err != nil {
		return nil, nil, err
	}
	artifactID, err := doneText(pinIn["artifact"], "policy_witness_artifact")
	if err != nil {
		return nil, nil, err
	}
	meta, present := doneObj(caseDoc["artifacts"])[artifactID]
	if !present {
		return nil, nil, refuse("case_artifact_unknown")
	}
	pinned, err := doneDigest(pinIn["sha256"], "policy_witness_digest_malformed")
	if err != nil {
		return nil, nil, err
	}
	if _, err = doneText(pinIn["authority"], "policy_witness_authority"); err != nil {
		return nil, nil, err
	}
	data, binding, err := doneArtifact(root, meta)
	if err != nil {
		return nil, nil, err
	}
	if binding["sha256"] != pinned {
		data = nil
	}
	pin := doneObject{"id": id, "artifact": artifactID, "consumer_pinned_sha256": pinned}
	if observed {
		if pin["producer"], err = doneText(pinIn["producer"], "policy_witness_producer"); err != nil {
			return nil, nil, err
		}
		if pin["vantage"], err = doneChoice(pinIn["vantage"], "policy_witness_vantage", doneVantages...); err != nil {
			return nil, nil, err
		}
		if pin["witness_scope"], err = doneChoice(pinIn["witness_scope"], "policy_witness_scope", doneScopes...); err != nil {
			return nil, nil, err
		}
		if witnessed, present := pinIn["witnessed"]; present {
			pin["witnessed"] = witnessed
		}
	}
	return data, pin, nil
}

// doneStart validates the case and policy envelopes and returns the case's assessment.
func doneStart(caseValue, policyValue any, claimType string, required []string, optional ...string) (string, doneObject, doneObject, doneObject, error) {
	caseDoc, err := doneFields(caseValue, "case", []string{"schema_version", "case_id", "artifacts"})
	if err != nil {
		return "", nil, nil, nil, err
	}
	policy, err := doneFields(policyValue, "policy", []string{"schema_version", "witnesses", "assessments"})
	if err != nil {
		return "", nil, nil, nil, err
	}
	if caseDoc["schema_version"] != "probity-case/v1" || policy["schema_version"] != "probity-policy/v1" {
		return "", nil, nil, nil, refuse("case_schema_unsupported")
	}
	caseID, err := doneText(caseDoc["case_id"], "case_id")
	if err != nil {
		return "", nil, nil, nil, err
	}
	_, artifactsOK := caseDoc["artifacts"].(doneObject)
	_, witnessesOK := policy["witnesses"].(doneObject)
	if !artifactsOK || !witnessesOK {
		return "", nil, nil, nil, refuse("case_objects")
	}
	assessments, ok := policy["assessments"].(doneObject)
	if _, present := assessments[caseID]; !ok || !present {
		return "", nil, nil, nil, refuse("policy_assessment_missing")
	}
	assessment, err := doneFields(assessments[caseID], "policy_assessment", required, optional...)
	if err != nil {
		return "", nil, nil, nil, err
	}
	if assessment["claim_type"] != claimType {
		return "", nil, nil, nil, refuse("policy_claim_type_unsupported")
	}
	return caseID, assessment, caseDoc, policy, nil
}

type doneBound struct {
	data []byte
	pin  doneObject
}

// doneBind binds each named witness role; observed roles need producer, vantage and scope
// pins. An EXTERNAL pin must name a witness bundle, which these readers do not verify, so
// it is refused; a bundle beside a PEER pin is refused too.
func doneBind(caseDoc, policy, assessment doneObject, root string, roles []string, observed map[string]bool) (map[string]doneBound, error) {
	ids := map[string]string{}
	seenID := map[string]bool{}
	for _, role := range roles {
		id, err := doneText(assessment[role+"_witness"], "policy_"+role+"_witness")
		if err != nil {
			return nil, err
		}
		if seenID[id] {
			return nil, refuse("policy_witness_shared")
		}
		seenID[id] = true
		ids[role] = id
	}
	out := map[string]doneBound{}
	for _, role := range roles {
		data, pin, err := doneWitness(caseDoc, policy, ids[role], root, observed[role])
		if err != nil {
			return nil, err
		}
		out[role] = doneBound{data, pin}
	}
	seenArtifact := map[string]bool{}
	for _, role := range roles {
		artifact := doneStr(out[role].pin["artifact"])
		if seenArtifact[artifact] {
			return nil, refuse("policy_artifact_shared")
		}
		seenArtifact[artifact] = true
	}
	for _, role := range roles {
		pin := out[role].pin
		_, witnessed := pin["witnessed"]
		if observed[role] && pin["witness_scope"] == "EXTERNAL" {
			if !witnessed {
				return nil, refuse("policy_witness_unwitnessed")
			}
			return nil, refuse("policy_witness_witnessed_unverified")
		}
		if witnessed {
			return nil, refuse("policy_witness_witnessed_unexpected")
		}
	}
	return out, nil
}

// doneSource is a file's bytes by its SHA-256, from the case artifact `source:<sha256>`.
func doneSource(caseDoc doneObject, root, digest string) ([]byte, error) {
	meta, present := doneObj(caseDoc["artifacts"])["source:"+digest]
	if !present {
		return nil, nil
	}
	data, binding, err := doneArtifact(root, meta)
	if err != nil || binding["sha256"] != digest {
		return nil, err
	}
	return data, nil
}
