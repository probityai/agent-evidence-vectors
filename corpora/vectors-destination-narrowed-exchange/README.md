# Destination-narrowed token exchange

A user's issuer mints one short-lived delegated token for an agent. An intermediary exchanges
it for a token aimed at one destination's verifier (RFC 8693 section 2.1, `audience` and
`resource`). Narrowing the destination does not narrow the rights. This corpus refuses an
exchange unless all of these hold:

- the holder proved the key its token is bound to (RFC 9449 `cnf.jkt`, RFC 7638);
- the exchanger is an intermediary the token names, and it checked the destination against the
  reviewed list the verifier pins;
- the delegated token was live (RFC 7519 `exp`) and unrevoked at the exchange;
- the actor chain survived with the exchanger appended as the current actor (RFC 8693
  section 4.1);
- the exchanged token carries only rights the delegation names for that destination;
- no token travelled in a query or form parameter (RFC 6750 section 2.3).

## Run it

```sh
python3 corpora/vectors-destination-narrowed-exchange/check_vectors.py
python3 corpora/vectors-destination-narrowed-exchange/check_vectors.py --verifier "<your verifier>"
```

A verifier is called as `<verifier> <case>/record.json --trust TRUST.json --json`, prints one
JSON object with `decision` and `reason`, and exits 0 for `accept` and 1 for `reject`.

## Record

A record is a list of statements, each Ed25519-signed (RFC 8032) over its RFC 8785 bytes, each
after the first carrying `prev`, the SHA-256 of the previous statement's signed bytes:

- `origin` (role `issuer`): the delegated token it sent and the user's full rights per
  destination;
- `revocation` (role `issuer`): the `jti` it revoked and when;
- `exchange` (role `exchanger`): the token it received, where it was carried, the holder proof,
  the destination check (destination and the SHA-256 of the reviewed list it read) and the
  token it sent;
- `presentation` (role `destination`): the token the verifier received.

Keys, roles, the reviewed list and the lifetime limit come from `TRUST.json`, which
`MANIFEST.json` pins by digest. The checks run in the order of `CHECKS` in the reader and the
first that fails is named. Every member is synthetic: keys come from public seeds in
`gen_vectors.py`.

## Regenerate

```sh
python3 corpora/vectors-destination-narrowed-exchange/gen_vectors.py
```

The output is byte-identical; never edit a case by hand.
