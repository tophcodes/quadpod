# Constraints

Rules that must stay true, with the command that decides them. The reasoning
lives in the design specs under `docs/superpowers/specs/`; this file only
holds the check, so a rule cannot quietly stop being enforced.

A non-indented line is a rule. An indented `check:` line is the command that
verifies it — non-zero exit means the rule is broken.

## Storage addressing

Only `shelf::ShelfKey` mints a subgraph IRI.
    → 2026-07-28-jsonld-datasets-design.md §3.1, §3.2 invariant 1. The key is a
    pure function of (resource IRI, graph name) with a `0x00` separator; a
    second place building that string by hand is how two resources come to
    share one shelf, which is a cross-resource read and write.
    check: ! rg -q "urn:pod:subgraph" src --glob '!src/shelf.rs'

Only `dataset` mints or recognises a skolem IRI.
    → §4. Skolemization preserves meaning only while the skolem IRIs occur
    nowhere else (RDF 1.1 §3.5); a second place that writes or matches
    `urn:pod:bnode:` is a second place that can get the round trip wrong.
    check: ! rg -q "urn:pod:bnode" src --glob '!src/dataset.rs'
