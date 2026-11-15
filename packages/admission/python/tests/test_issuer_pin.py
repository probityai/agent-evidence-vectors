"""RFC 7638 thumbprint pinning of token issuers."""

import pytest
from agent_evidence_admission import issuer_pin as ip

# RFC 7638 section 3.1, https://www.rfc-editor.org/rfc/rfc7638.txt
RFC7638_KEY = {
    "kty": "RSA",
    "n": ("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
          "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
          "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
          "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
          "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
          "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
# RFC 8037 appendix A.3, https://www.rfc-editor.org/rfc/rfc8037.txt
RFC8037_KEY = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

ISSUER = "https://example.okta.com/oauth2/default"
OTHER = "https://login.microsoftonline.com/tenant/v2.0"
KID = "2011-04-29"


def serving(jwks, calls=None):
    def fetch(issuer):
        if calls is not None:
            calls.append(issuer)
        return jwks
    return fetch


def test_rfc7638_known_answer():
    assert ip.jwk_thumbprint(RFC7638_KEY) == RFC7638_THUMBPRINT


def test_rfc8037_okp_known_answer():
    assert ip.jwk_thumbprint(RFC8037_KEY) == RFC8037_THUMBPRINT


def test_thumbprint_uses_only_required_members():
    bare = {k: RFC7638_KEY[k] for k in ("kty", "n", "e")}
    assert ip.jwk_thumbprint(bare) == RFC7638_THUMBPRINT


def test_correct_pin_accepted():
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)},
                            fetch=serving({"keys": [RFC7638_KEY]}))
    assert pins.key_for(ISSUER, KID)["n"] == RFC7638_KEY["n"]
    assert pins.pinning == ip.PINNED


def test_thumbprint_mismatch_refused():
    swapped = dict(RFC7638_KEY, n=RFC7638_KEY["n"][:-2] + "AA")
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)},
                            fetch=serving({"keys": [swapped]}))
    with pytest.raises(ip.ThumbprintMismatch):
        pins.key_for(ISSUER, KID)


def test_mixed_configuration_refused_before_any_call():
    calls = []
    with pytest.raises(ip.MixedConfiguration):
        ip.PinnedIssuers([ISSUER, OTHER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)}, fetch=serving({}, calls))
    assert calls == []


def test_unpinned_declaration_with_pins_refused():
    with pytest.raises(ip.MixedConfiguration):
        ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)}, unpinned=True)


def test_pin_for_an_issuer_not_called_refused():
    with pytest.raises(ip.MixedConfiguration):
        ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT), OTHER: ip.PinSet.of(1, RFC8037_THUMBPRINT)})


def test_conflicting_pins_refused():
    with pytest.raises(ip.ConflictingPins):
        ip.PinnedIssuers([ISSUER], [(ISSUER, ip.PinSet.of(1, RFC7638_THUMBPRINT)), (ISSUER + "/", ip.PinSet.of(1, RFC8037_THUMBPRINT))])


def test_repeated_identical_pin_accepted():
    one = ip.PinSet.of(1, RFC7638_THUMBPRINT)
    pins = ip.PinnedIssuers([ISSUER], [(ISSUER, one), (ISSUER, one)])
    assert pins.pin_for(ISSUER) == one


def test_fetch_failure_never_downgrades():
    def broken(issuer):
        raise OSError("connection reset")
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)}, fetch=broken)
    with pytest.raises(ip.FetchFailed):
        pins.key_for(ISSUER, KID)
    assert pins.pinning == ip.PINNED


def test_malformed_jwks_refused():
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)}, fetch=serving({"keys": "x"}))
    with pytest.raises(ip.FetchFailed):
        pins.key_for(ISSUER, KID)


@pytest.mark.parametrize("keys", [[], [RFC7638_KEY, RFC7638_KEY]])
def test_kid_absent_or_ambiguous_refused(keys):
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)}, fetch=serving({"keys": keys}))
    with pytest.raises(ip.KeyNotFound):
        pins.key_for(ISSUER, KID)


@pytest.mark.parametrize("key", [dict(RFC7638_KEY, d="secret"), {"kty": "oct", "k": "AAAA", "kid": KID}])
def test_private_or_symmetric_key_refused(key):
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)}, fetch=serving({"keys": [key]}))
    with pytest.raises(ip.InvalidKey):
        pins.key_for(ISSUER, KID)


def test_unpinned_is_explicit_and_reported():
    with pytest.raises(ip.MixedConfiguration):
        ip.PinnedIssuers([ISSUER])
    pins = ip.PinnedIssuers([ISSUER], unpinned=True, fetch=serving({"keys": [RFC7638_KEY]}))
    assert pins.pinning == ip.UNPINNED
    assert pins.key_for(ISSUER, KID)["kid"] == KID


def test_unconfigured_issuer_refused():
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)}, fetch=serving({"keys": []}))
    with pytest.raises(ip.PinError):
        pins.key_for(OTHER, KID)


@pytest.mark.parametrize("bad", ["", "short", RFC7638_THUMBPRINT[:-1] + "+", RFC7638_THUMBPRINT + "A"])
def test_malformed_pin_refused(bad):
    with pytest.raises(ip.PinError):
        ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, bad)})


def test_http_issuer_refused():
    with pytest.raises(ip.PinError):
        ip.PinnedIssuers(["http://example.okta.com"], unpinned=True)


def test_https_fetch_refuses_non_https_jwks_uri(monkeypatch):
    import io
    import json

    def fake_urlopen(url, timeout):
        body = {"issuer": ISSUER, "jwks_uri": "http://example.okta.com/keys"}
        return io.BytesIO(json.dumps(body).encode())

    monkeypatch.setattr(ip.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ip.FetchFailed):
        ip.https_fetch(ISSUER)


def test_https_fetch_refuses_issuer_mismatch(monkeypatch):
    import io
    import json

    def fake_urlopen(url, timeout):
        return io.BytesIO(json.dumps({"issuer": OTHER, "jwks_uri": "https://other.example.com/keys"}).encode())

    monkeypatch.setattr(ip.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ip.FetchFailed):
        ip.https_fetch(ISSUER)


@pytest.mark.parametrize("key", [{"kty": "DSA"}, {"kty": "EC", "crv": "P-256", "x": "AAAA"}])
def test_thumbprint_of_unusable_key_refused(key):
    with pytest.raises(ip.InvalidKey):
        ip.jwk_thumbprint(key)


def test_no_issuer_refused():
    with pytest.raises(ip.PinError):
        ip.PinnedIssuers([], unpinned=True)


def test_fetch_refusal_passes_through_unchanged():
    def refusing(issuer):
        raise ip.FetchFailed("refused upstream")
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: ip.PinSet.of(1, RFC7638_THUMBPRINT)}, fetch=refusing)
    with pytest.raises(ip.FetchFailed, match="refused upstream"):
        pins.key_for(ISSUER, KID)


def test_https_fetch_unreachable_refused(monkeypatch):
    def down(url, timeout):
        raise OSError("unreachable")

    monkeypatch.setattr(ip.urllib.request, "urlopen", down)
    with pytest.raises(ip.FetchFailed):
        ip.https_fetch(ISSUER)


def test_https_fetch_without_jwks_uri_refused(monkeypatch):
    import io
    import json

    monkeypatch.setattr(ip.urllib.request, "urlopen",
                        lambda url, timeout: io.BytesIO(json.dumps({"issuer": ISSUER}).encode()))
    with pytest.raises(ip.FetchFailed):
        ip.https_fetch(ISSUER)


def test_https_fetch_reads_jwks(monkeypatch):
    import io
    import json

    def fake(url, timeout):
        if url.endswith("openid-configuration"):
            return io.BytesIO(json.dumps({"issuer": ISSUER, "jwks_uri": "https://example.okta.com/keys"}).encode())
        return io.BytesIO(json.dumps({"keys": [RFC7638_KEY]}).encode())

    monkeypatch.setattr(ip.urllib.request, "urlopen", fake)
    assert ip.https_fetch(ISSUER)["keys"][0]["kid"] == KID


ONE = ip.PinSet.of(1, RFC7638_THUMBPRINT)
TWO = ip.PinSet.of(2, RFC7638_THUMBPRINT, RFC8037_THUMBPRINT)
OKP_KEY = dict(RFC8037_KEY, kid=KID)


def test_overlap_set_accepts_either_key():
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: TWO}, fetch=serving({"keys": [OKP_KEY]}))
    assert pins.key_for(ISSUER, KID)["kty"] == "OKP"


def test_rotation_is_a_new_client_and_reports_its_epoch():
    old = ip.PinnedIssuers([ISSUER], {ISSUER: ONE}, fetch=serving({"keys": [OKP_KEY]}))
    new = old.rotate(ISSUER, TWO)
    assert new.key_for(ISSUER, KID)["kty"] == "OKP"
    with pytest.raises(ip.ThumbprintMismatch):
        old.key_for(ISSUER, KID)
    assert (old.epochs, new.epochs) == ({ISSUER: 1}, {ISSUER: 2})


def test_rotation_may_retire_a_key_at_a_newer_epoch():
    three = ip.PinSet.of(3, RFC8037_THUMBPRINT)
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: TWO}, fetch=serving({"keys": [RFC7638_KEY]})).rotate(ISSUER, three)
    with pytest.raises(ip.ThumbprintMismatch):
        pins.key_for(ISSUER, KID)


def test_rotation_to_an_older_epoch_refused():
    with pytest.raises(ip.PinDowngrade):
        ip.PinnedIssuers([ISSUER], {ISSUER: TWO}).rotate(ISSUER, ONE)


def test_same_epoch_different_set_refused_and_same_set_idempotent():
    pins = ip.PinnedIssuers([ISSUER], {ISSUER: TWO})
    with pytest.raises(ip.ConflictingPins):
        pins.rotate(ISSUER, ip.PinSet.of(2, RFC7638_THUMBPRINT))
    assert pins.rotate(ISSUER, TWO).pin_for(ISSUER) == TWO


def test_restart_below_seen_epoch_refused():
    with pytest.raises(ip.PinDowngrade):
        ip.PinnedIssuers([ISSUER], {ISSUER: ONE}, seen_epochs={ISSUER: 2})
    assert ip.PinnedIssuers([ISSUER], {ISSUER: TWO}, seen_epochs={ISSUER: 2}).epochs == {ISSUER: 2}


def test_restart_unpinned_after_pinning_refused():
    with pytest.raises(ip.PinDowngrade):
        ip.PinnedIssuers([ISSUER], unpinned=True, seen_epochs={ISSUER: 1})


@pytest.mark.parametrize("seen", [{OTHER: 1}, {ISSUER: 0}, {ISSUER: True}])
def test_bad_seen_epochs_refused(seen):
    with pytest.raises(ip.PinError):
        ip.PinnedIssuers([ISSUER], {ISSUER: ONE}, seen_epochs=seen)


@pytest.mark.parametrize("bad", [ip.PinSet(0, frozenset({RFC7638_THUMBPRINT})), ip.PinSet(1, frozenset()),
                                 ip.PinSet(True, frozenset({RFC7638_THUMBPRINT})), "not-a-set"])
def test_bad_pin_set_refused(bad):
    with pytest.raises(ip.PinError):
        ip.PinnedIssuers([ISSUER], {ISSUER: bad})
    with pytest.raises(ip.PinError):
        ip.PinnedIssuers([ISSUER], {ISSUER: ONE}).rotate(ISSUER, bad)


def test_rotation_of_unpinned_issuer_refused():
    with pytest.raises(ip.MixedConfiguration):
        ip.PinnedIssuers([ISSUER], unpinned=True).rotate(ISSUER, ONE)


def test_two_epochs_in_one_configuration_refused():
    with pytest.raises(ip.ConflictingPins):
        ip.PinnedIssuers([ISSUER], [(ISSUER, ONE), (ISSUER, TWO)])
