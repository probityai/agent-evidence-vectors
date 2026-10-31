# Sources and custody

Horizon Shield supplied the pair in [Atlas #49](https://github.com/probityai/agent-evidence/issues/24#issuecomment-6247270215).
That comment documents sorted-key JSON without spaces, `jidec-path-v1`, exact purpose
URLs and signatures over the record bytes. This implementation was written from
those fields and the supplied records, without reading or copying the producer reader.

| Input | Primary source | Exact SHA-256 |
| --- | --- | --- |
| A record | [Pavlo's signed record](https://ledger.horizonshield.dev/witness/747ecd97635e104e75185212cfb70e3cc37310ea1f41966a818bfb5b5d57df15) | `747ecd97635e104e75185212cfb70e3cc37310ea1f41966a818bfb5b5d57df15` |
| B record | [kuangmi-bit's signed record](https://ledger.horizonshield.dev/witness/e1521f115d61116e3c4d7957903c12afe88617cff468403351f5cea432894b24) | `e1521f115d61116e3c4d7957903c12afe88617cff468403351f5cea432894b24` |
| A key response | [Pavlo's key URL](https://pipavlo82.github.io/keys/witness.json) | `c2aeb7c14095aa8e22eeb6fea2d7d8975ba77db87825a25738155ff77f0bf609` |
| B key response | [kuangmi-bit's key URL](https://kuangmi-bit.github.io/conduct-witness/conduct-witness-key.json) | `cb761905d8a2af4145c62e453fa8c65a4c9bb616ecbf727f4aacddb1f65131f2` |

Original API responses and key files are retained unchanged in `fixtures`; `pins.json`
names the independent input pins. The keys were fetched on October 9, 2026. That
fetch does not establish who controlled a key or its domain at either October 7 walk.
The 1,599-byte [ledger 73 OpenTimestamps file](https://ledger.horizonshield.dev/ledger/73/ots)
is retained as `ledger73.ots`, SHA-256
`a425332429d9cda7ba9ed5030d3df11bad951def96a23c84601587c1db273f93`.
No timestamp-proof validation is included in this reader.

Both records explicitly report `card_signature.verified: null`. A also discloses
prior collaboration and shared technical context in `vantage_limitation`. B records
a GitHub Actions vantage. The reader carries those declarations without promoting
them to verified card provenance or unaffiliated observation.

The original comment's `7/7` and `4/4` count the evaluated assertions. The signed
arrays each contain eight entries, including one and four null results respectively.
The reader reports all three states directly.

Cryptography uses the official [Ed25519 verification API](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/),
pinned to the stable [50.0.2 release](https://cryptography.io/en/50.0.2/changelog/).
Tests sign clearly author-created mutations with a test-only private key. Those
controls do not change the supplied witnesses' records or imply new witness runs.
