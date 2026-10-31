# Retained reader check

The October 9, 2026 check ran on an ordinary shared BoxPool runner with burst
disabled and the 15 GiB free-space floor. The final driver exited 0 on CPython
3.14.7 with Cryptography 50.0.2. All 62 tests passed, with no skips or errors.
Both nonempty runtime files passed the 80% per-file coverage gate; combined
statement and branch coverage was 100% for `io.py` and 98.65% for `reader.py`.

The tested source commit was `029f45b6475044c7e66f4bb69b43bc120009a34b`.
The exact BoxPool snapshot was `0fac00ef3707cfa8de762d62ca8e601cd3836a34`.
Source and all 23 copied receipts matched the remote byte inventory.

| Actual CLI read | Exit | Result |
| --- | --- | --- |
| A against `/a2a` | 0 | matching signed observation |
| B against `/a2a` | 1 | target mismatch |
| A against `/a2a/` | 1 | target mismatch |
| B against `/a2a/` | 1 | target mismatch |

Both supplied signatures verified over the exact canonical bytes under their
separately pinned current local keys. A kept seven true results and one null;
B kept four true results and four nulls. The reader carried each witness's
declared vantage and nullable card-signature result. It did not perform a new
walk, verify the card or response claims, validate OpenTimestamps, or establish
historical key control or unaffiliated observation.

The earlier R1 check exited 2 with 61 of 62 tests passing. Its deep-array control
received a different refusal code than expected, and the parser lacked an
explicit nesting boundary. R2 added a 64-container limit before decoding, with
accepted-boundary and quoted-bracket controls. Original records, keys and pins
were unchanged. The R1 source and adverse receipts are retained.

Probity wrote and ran this second reader from the supplied format. The witness
records belong to Pavlo (`pipavlo82`) and `kuangmi-bit`; Horizon Shield supplied
the pair. This author-operated check is not an outside run of the new reader.
