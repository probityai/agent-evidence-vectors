# Motebit approval triad reader

This offline reader checks the public fixture pinned in [SOURCE.json](SOURCE.json)
without importing its producer's reader. It uses separate signature and JSON
canonicalization libraries and compares its results with the retained expected
output. It refuses malformed input and reports disagreements rather than silently
updating that output.

From the repository root, install the pinned libraries into your Python environment
and run the reader:

```sh
python -m pip install -r examples/motebit-approval-triad/requirements.txt
python examples/motebit-approval-triad/reader.py
```

The report distinguishes agreement, disagreement and setup errors; the reader's
exit status is successful only on agreement. To run the reader's tests, collect
coverage and run the Atlas checks, use the helper with `uv` and the repository's
build prerequisites available:

```sh
bash examples/motebit-approval-triad/run_checks.sh
```

An optional second argument to that helper is a checkout of the pinned producer
fixture directory. This also runs the producer's own Python reader and mutation
tests; omitting it does not run those controls. See the public paths and hashes in
the source manifest before supplying a producer checkout.

The records use public demo keys. Their relations compare native field values;
they do not join by an approval digest or establish an authorised identity. Times
are signer assertions, effects are simulated, and the separate deny receipt is
unjoined. Expected outputs were available to the reader's developers, so this
comparison is not a blinded evaluation. The Python replay does not qualify the
TypeScript SDK or a deployed approval service.
