# Reader ownership

- Preserve the original API, record and key bytes. Keep fixture mutations in tests.
- Write this reader from the signed record format, not the producer reader implementation.
- Use this project’s `.venv/bin/python` for Python commands.
- Run full checks on an ordinary shared BoxPool runner with no burst and the 15 GiB floor.
- Verify signatures over exact UTF-8 record bytes using the separately pinned local key.
- Preserve true, false and null assertion results. A null result is unevaluated.
- Keep current key verification, historical key control and timestamp validation separate.
- Root owns Atlas integration and publication. This lane prepares source and checked receipts.
