package corpusreaders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// errRepeatedMember is the refusal for an object that names one member twice.
var errRepeatedMember = errors.New("repeated object member")

// strictUnmarshal is json.Unmarshal for bytes a reader did not write. encoding/json
// already refuses NaN, Infinity and a literal too large for a float64, and keeps the
// LAST of two members with one name. A reader in another language may keep the first,
// and a signature covers the bytes rather than either reading, so a record that
// repeats a member is a record two readers judge two ways. It is refused here before it
// is decoded, as the Python readers refuse it (packaging/agent_evidence_vectors/
// strictjson.py), so the two rails never judge different members of one record.
func strictUnmarshal(data []byte, v any) error {
	if err := refuseRepeatedMembers(data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// strictUnmarshalExcept is strictUnmarshal for a top-level object whose member
// `except` is left unchecked: a repeated member inside that one value is named by a
// later rule of the reader, and refusing it here would replace the named verdict with
// an unparsed envelope. A repeated member anywhere else, the top level included, is
// still refused.
func strictUnmarshalExcept(body []byte, v any, except string) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return json.Unmarshal(body, v)
	}
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		name, _ := key.(string)
		if seen[name] {
			return fmt.Errorf("%w %q", errRepeatedMember, name)
		}
		seen[name] = true
		if name == except {
			var skip json.RawMessage
			err = dec.Decode(&skip)
		} else {
			err = walkUnique(dec)
		}
		if err != nil {
			return err
		}
	}
	return json.Unmarshal(body, v)
}

// refuseRepeatedMembers walks one JSON value and refuses an object, at any depth,
// that names a member twice. Bytes that are not one JSON value are refused with the
// decoder's own error, which is the error json.Unmarshal would have returned.
func refuseRepeatedMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkUnique(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return json.Unmarshal(data, new(any))
	}
	return nil
}

func walkUnique(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, _ := key.(string)
			if seen[name] {
				return fmt.Errorf("%w %q", errRepeatedMember, name)
			}
			seen[name] = true
			if err := walkUnique(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkUnique(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// foldedRepeat returns the first object member name in data that repeats within one
// object, compared the way encoding/json matches a name to a struct field
// (bytes.EqualFold: Unicode simple case folding, so "Expected", "EXPECTED" and
// "expected" are one field, and so are "s" and the long s U+017F), or "" when none
// does. json.Unmarshal into a struct gives the last such member to the field, while a
// reader in another language reads the exact name, so a manifest that carries both
// shows the two rails two different answers. Bytes that are not one JSON value give
// "": the caller's decode reports those.
func foldedRepeat(data []byte) string {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	name, _ := walkFolded(dec)
	return name
}

func walkFolded(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return "", nil
	}
	seen := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return "", err
			}
			name, _ := key.(string)
			folded := foldFieldName(name)
			if seen[folded] {
				return name, nil
			}
			seen[folded] = true
		}
		if name, err := walkFolded(dec); name != "" || err != nil {
			return name, err
		}
	}
	_, err = dec.Token() // the closing delimiter
	return "", err
}

// foldFieldName maps a name to the smallest rune of each rune's simple fold orbit, so
// two names map to one string exactly when bytes.EqualFold reports them equal.
func foldFieldName(name string) string {
	var out []byte
	for _, r := range name {
		out = utf8.AppendRune(out, smallestFold(r))
	}
	return string(out)
}

func smallestFold(r rune) rune {
	least := r
	for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
		if next < least {
			least = next
		}
	}
	return least
}
