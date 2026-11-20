package corpusreaders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
