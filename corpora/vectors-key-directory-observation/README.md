# Web Bot Auth key-directory observation vectors

Cases for `web-bot-auth-key-directory-observation/v1`: one fetch of an HTTP
Message Signatures key directory, made by a verifier checking a signed request,
and what that fetch lets the verifier conclude. The expected decision, reason
and resulting cache for every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

A key directory answers two questions at once, and a verifier that merges them
fails one way or the other. A directory that resolves is evidence about the
keys: a key it no longer lists, or an empty key set served on purpose when an
agent is withdrawn, stops verifying. A fetch that fails is evidence about the
network: a 404, a 503, a refused connection, a redirect or a CDN error page
served with 200 says nothing about the keys, and evicting cached keys on it
lets one operator outage revoke an agent at every verifier at once.
draft-ietf-webbotauth-httpsig-protocol-01 Section 6.10 states both halves and
says verifiers MUST keep them apart. Each case here pins both the decision for
the request in hand and the cache the verifier holds afterwards, so either
mistake fails.

| Case | Fetch | Expected | Cache |
| --- | --- | --- | --- |
| key-listed | 200, directory lists the key | attributed, `key_in_directory` | replaced |
| key-listed-among-several | 200, old and new key | attributed, `key_in_directory` | replaced |
| empty-key-set-evicts | 200, empty key set | not attributed, `key_absent_from_directory` | replaced, empty |
| key-removed-other-kept | 200, the other key only | not attributed, `key_absent_from_directory` | replaced |
| status-404-keeps-cache | 404 | not attributed, `discovery_failed` | kept |
| status-503-keeps-cache | 503 | not attributed, `discovery_failed` | kept |
| transport-failure-keeps-cache | no response | not attributed, `discovery_failed` | kept |
| redirect-not-followed | 302 | not attributed, `redirect_not_followed` | kept |
| html-error-page-with-200 | 200, an HTML error page | not attributed, `not_a_directory` | kept |
| wrong-media-type-at-well-known | 200, JWK Set as `application/json` | not attributed, `not_a_directory` | kept |
| kid-not-thumbprint-at-well-known | 200, the draft's Section 5.5.1 example | not attributed, `kid_not_thumbprint` | replaced, empty |
| kid-thumbprint-at-well-known | 200, the same key with its thumbprint as `kid` | attributed, `key_in_directory` | replaced |
| kid-label-off-well-known | 200 at another URL, `kid` an operator label | attributed, `key_in_directory` | replaced |

## What a case holds

- `case.json`: the directory URL, the `keyid` the request names (an RFC 7638
  thumbprint), the thumbprints the verifier held for that URL before the fetch
  (`cached`), and the fetch as observed (`outcome`, `status`, `mediaType`,
  `body`).
- `response.body`: the response bytes, when there was a response.

## The checks, in order

A verifier names the first check that fails. The order is part of the contract.

1. The response is not a redirect (`redirect_not_followed`, Section 5.5).
2. The fetch completed with status 200 (`discovery_failed`, Section 5.5).
3. The response is a JWK Set, served at the well-known URI with media type
   `application/http-message-signatures-directory+json` (`not_a_directory`,
   Section 5.5.1).
4. At the well-known URI, the entry for the key carries no `kid` or carries its
   RFC 7638 thumbprint (`kid_not_thumbprint`, Section 5.5).
5. The directory lists the key (`key_absent_from_directory`).

The first three keep the cache; the last two replace it with the directory's
well-formed keys. A request that passes all five is `attributed` with reason
`key_in_directory`.

Two choices here go one step past the draft's wording, and each is stated so a
reader can contest it: a malformed entry at the well-known URI is dropped rather
than trusted (Section 5.5.1 says a verifier SHOULD reject malformed entries),
and the request in hand is never attributed through a cached key after a failed
fetch, because no failure case names a key the cache holds.

## Running it

```sh
pip install agent-evidence-vectors
python3 corpora/vectors-key-directory-observation/check_vectors.py
python3 corpora/vectors-key-directory-observation/check_vectors.py --verifier "my-verifier"
```

A named verifier is run as `<verifier> <case-dir>/case.json --json`. It prints
one JSON object with `decision`, `reason`, `cache` and `cacheAfter`, and exits 0
for `attributed` and 1 for `not_attributed`. Regenerate the cases with
`python3 corpora/vectors-key-directory-observation/gen_vectors.py`.
