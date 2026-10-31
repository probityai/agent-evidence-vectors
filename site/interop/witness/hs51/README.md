# Witness key for the horizon-shield#51 pilot

`witness-key.json` holds the Ed25519 public key that signs witness acknowledgements for the two pilot statements in [horizon-shield#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51). It is a separate key: it never signs corpus records, card walks or board runs.

## What an acknowledgement says

Each one is a `musubi.ca2a.witness-ack.v0` object, as `witness_ack.py` in horizon-shield writes it. It covers two things only:

- this key received the item, kept its exact bytes here, and names the item's SHA-256 over its RFC 8785 form;
- the item was public after the Bitcoin block it names and, once anchored, before the anchor block.

It does not approve the budget or the criteria. It does not record a payment, endorse a party, or observe any effect of the call, and the key holder is not a party to the call.

## When it signs

Only after both statements, their issuer keys, the acknowledgement schema, the helper revision and the run's log id are pinned on the issue. Each signed item and its acknowledgement will be kept in this directory.

## Check one

```sh
pip install cryptography rfc8785
python3 witness_ack.py check ack.json item.json
```

It prints `ok: witness 58c98ed4... acknowledged item ...` when the signature and the item digest hold.
