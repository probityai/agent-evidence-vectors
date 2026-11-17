package corpusreaders

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
)

func init() { register(keyDirectory{}) }

// keyDirectory judges corpora/vectors-key-directory-observation/. Each member is
// one fetch of a Web Bot Auth key directory made while checking a signed request:
// the directory URL, the keyid the request names, the thumbprints the verifier
// held before the fetch, and the fetch as observed. The reader derives the
// decision for the request and the cache the verifier holds afterwards, with the
// checks the Python reader applies, in the same order, and names the first that
// fails (draft-ietf-webbotauth-httpsig-protocol-01 Sections 5.5, 5.5.1, 6.10):
//
//  1. the response is not a redirect: redirect_not_followed;
//  2. the fetch completed with status 200: discovery_failed;
//  3. the response is a JWK Set, at the well-known URI with the registered media
//     type: not_a_directory;
//  4. at the well-known URI the entry for the key carries no kid or its RFC 7638
//     thumbprint: kid_not_thumbprint;
//  5. the directory lists the key: key_absent_from_directory.
//
// The first three are not evidence and keep the cache; the last two replace it
// with the directory's well-formed keys.
type keyDirectory struct{}

func (keyDirectory) Suite() string { return "web-bot-auth-key-directory-observation/v1" }

const (
	kdWellKnownPath = "/.well-known/http-message-signatures-directory"
	kdMediaType     = "application/http-message-signatures-directory+json"
)

type kdExpected struct {
	Cache      string   `json:"cache"`
	CacheAfter []string `json:"cacheAfter"`
	Decision   string   `json:"decision"`
	Reason     string   `json:"reason"`
}

type kdVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected kdExpected        `json:"expected"`
}

type kdCase struct {
	Cached       []string `json:"cached"`
	DirectoryURL string   `json:"directoryUrl"`
	KeyID        string   `json:"keyid"`
	Fetch        struct {
		Outcome   string  `json:"outcome"`
		Status    *int    `json:"status"`
		MediaType *string `json:"mediaType"`
		Body      *string `json:"body"`
	} `json:"fetch"`
	body []byte
}

type kdEntry struct {
	thumb string
	ok    bool
}

func (keyDirectory) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v kdVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = kdJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func kdJudgeMember(caseDir string, v kdVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c kdCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	if c.Fetch.Body != nil {
		body, err := readIn(caseDir, *c.Fetch.Body)
		if err != nil {
			return append(findings, *c.Fetch.Body+" cannot be read")
		}
		c.body = body
	}
	got := kdDecide(&c)
	want := v.Expected
	if want.CacheAfter == nil {
		want.CacheAfter = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		findings = append(findings, fmt.Sprintf("derived %s/%s cache %s %v, the manifest declares %s/%s cache %s %v",
			got.Decision, got.Reason, got.Cache, got.CacheAfter,
			want.Decision, want.Reason, want.Cache, want.CacheAfter))
	}
	return findings
}

// kdThumbprint is the RFC 7638 SHA-256 thumbprint of an OKP Ed25519 JWK, or ""
// for any other key.
func kdThumbprint(jwk map[string]any) string {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	x, ok := jwk["x"].(string)
	if kty != "OKP" || crv != "Ed25519" || !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != x {
		return ""
	}
	member := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`
	sum := sha256.Sum256([]byte(member))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func kdAtWellKnown(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Path == kdWellKnownPath
}

// kdKeys is the keys array of the response body, or nil when it is not a JWK Set.
func kdKeys(body []byte) ([]map[string]any, bool) {
	if body == nil {
		return nil, false
	}
	var parsed map[string]any
	if json.Unmarshal(body, &parsed) != nil {
		return nil, false
	}
	list, ok := parsed["keys"].([]any)
	if !ok {
		return nil, false
	}
	keys := []map[string]any{}
	for _, item := range list {
		if key, isObject := item.(map[string]any); isObject {
			keys = append(keys, key)
		}
	}
	return keys, true
}

func kdEntries(c *kdCase) []kdEntry {
	keys, _ := kdKeys(c.body)
	wellKnown := kdAtWellKnown(c.DirectoryURL)
	var found []kdEntry
	for _, key := range keys {
		thumb := kdThumbprint(key)
		if thumb == "" {
			continue
		}
		kid, hasKid := key["kid"]
		ok := !(wellKnown && hasKid && kid != thumb)
		found = append(found, kdEntry{thumb, ok})
	}
	return found
}

func kdSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func kdDecide(c *kdCase) kdExpected {
	answered := c.Fetch.Outcome == "response" && c.Fetch.Status != nil
	status := 0
	if c.Fetch.Status != nil {
		status = *c.Fetch.Status
	}
	kept := func(reason string) kdExpected {
		return kdExpected{Cache: "kept", CacheAfter: kdSorted(c.Cached), Decision: "not_attributed", Reason: reason}
	}
	if answered && status >= 300 && status < 400 {
		return kept("redirect_not_followed")
	}
	if !answered || status != 200 {
		return kept("discovery_failed")
	}
	_, isSet := kdKeys(c.body)
	media := ""
	if c.Fetch.MediaType != nil {
		media = *c.Fetch.MediaType
	}
	if !isSet || (kdAtWellKnown(c.DirectoryURL) && media != kdMediaType) {
		return kept("not_a_directory")
	}
	entries := kdEntries(c)
	var after []string
	listed, malformed := false, false
	for _, e := range entries {
		if e.ok {
			after = append(after, e.thumb)
			if e.thumb == c.KeyID {
				listed = true
			}
		} else if e.thumb == c.KeyID {
			malformed = true
		}
	}
	replaced := kdExpected{Cache: "replaced", CacheAfter: kdSorted(after), Decision: "not_attributed"}
	switch {
	case malformed:
		replaced.Reason = "kid_not_thumbprint"
	case !listed:
		replaced.Reason = "key_absent_from_directory"
	default:
		replaced.Decision, replaced.Reason = "attributed", "key_in_directory"
	}
	return replaced
}
