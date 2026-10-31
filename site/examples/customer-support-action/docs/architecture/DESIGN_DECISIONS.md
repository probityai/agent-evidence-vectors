# Design decisions

## Admit the complete corpus before invoking a reader

`run.py::corpus_entries` keeps the required checks in one read-only pass over the closed manifest and its nested case records. It checks the selected contract, commitment, fixture closure, file hashes, expected outcomes and derived populations.

Its complexity follows those distinct admission rules. A helper for each predicate would move the branches without simplifying the contract or its failure order. No reader runs until every invariant passes. Review this choice when another corpus contract is added.
