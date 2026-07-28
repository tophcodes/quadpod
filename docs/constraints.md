# Constraints

Rules that must stay true, with the command that decides them. The reasoning
lives in the design specs under `docs/superpowers/specs/`; this file only
holds the check, so a rule cannot quietly stop being enforced.

A non-indented line is a rule. An indented `check:` line is the command that
verifies it — non-zero exit means the rule is broken. `arch-check` runs them
all; `arch-check --only <substring>` runs one.

Every rule here was demonstrated to go red against a real violation before it
was added. A check that cannot fail is worse than no check: this project has
already shipped a test that asked for its property in a form where it held
trivially.

## Type model

Only `AuxUrl` may be deleted on its own; only `ResourceUrl` and `ContainerUrl` may be written directly.
    → 2026-07-27-acl-auxiliary-model-design.md §5, §6; the doc comments on
    `space::DirectlyWritable` / `DirectlyDeletable`; `tests/unrepresentable.rs`.
    Plan 7 found `aux::` was a convention rather than a construction —
    `put_rdf(&foo.aux(Acl))` compiled and skipped the subject-existence guard,
    planting a policy document that nearest-ACL-wins then makes permanent. Two
    of Plan 6's seven defect classes are unrepresentable only because of these
    two `impl` lines. The compiler enforces the bound at every call site;
    nothing enforces that the bound keeps its membership.
    check: [ "$(rg -o 'impl DirectlyDeletable for [A-Za-z]+' src | wc -l)" = 1 ] && [ "$(rg -o 'impl DirectlyWritable for [A-Za-z]+' src | wc -l)" = 2 ]

`space::GraphName` stays sealed.
    → `space.rs`'s own comment on the trait; 2026-07-28-jsonld-datasets-design.md §3.6.
    Every implementor's `graph_iri` is interpolated verbatim into SPARQL, so only
    types minted through `StorageSpace::resolve` may implement it. Plan 7's review
    found the trait unsealed and compiled the repro: `impl GraphName for String`
    fed a raw request path straight into `INSERT DATA`. `mod sealed` being private
    is compile-enforced; the supertrait bound staying on `GraphName` is not —
    deleting five characters unseals all three traits at once.
    check: rg -q 'pub trait GraphName: sealed::Sealed' src/space.rs

## Storage addressing

Only `resource` builds a system-graph IRI.
    → 2026-07-28-jsonld-datasets-design.md §3, §3.2 invariant 5; `resource.rs`'s
    module header. The presence marker is what makes existence a stored fact
    rather than a triple count — the ambiguity that made an empty ACL mean the
    opposite of what its author wrote. Its safety argument is that no
    user-addressable path can name a `urn:pod:` graph; a second place deriving
    `urn:pod:sys:<iri>` is a second place that can scope it wrong, and the shelf
    registry is about to write into that same graph. Quote-anchored, because
    `shelf.rs` legitimately mentions the scheme in prose.
    check: ! rg -q '"urn:pod:sys:' src --glob '!src/resource.rs'

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

## Boundaries that have no compiler behind them

`FetchPolicy::permissive` stays `#[cfg(test)]`.
    → docs/deployment.md, "What it does not relax": there is no flag that turns
    the SSRF filter off globally, and the blanket-permissive policy cannot be
    constructed in a release build. This is the control between an
    unauthenticated pre-auth fetch and the cloud-metadata endpoint. No test can
    observe a missing `cfg` gate — tests run with `cfg(test)` on — so it is a
    published operator promise with nothing else enforcing it.
    check: rg -qU '#\[cfg\(test\)\]\s*\n\s*pub fn permissive' src/auth/safe_fetch.rs

`SparqlStore` has exactly one implementor.
    → 2026-07-24-sparql-solid-pod-design.md §16 ADR-2;
    2026-07-28-jsonld-datasets-design.md §5.2. A tripwire, not a prohibition:
    dyn dispatch exists precisely so a backend can be swapped, but the
    `;`-sequence atomicity every write path rests on is a property of
    `OxigraphStore` rather than of SPARQL. A second implementor must reopen that
    decision, and today nothing would make anyone do it.
    check: [ "$(rg -o 'impl SparqlStore for [A-Za-z]+' src | wc -l)" = 1 ]

`ResourceUrl::ancestors` is the only multi-hop walk up the container chain.
    → tests/unrepresentable.rs's header; Plan 6 finding F2. Plan 6 had two
    separate walks — `ensure_ancestors` mutated every ancestor to the root while
    only the immediate parent was authorized — and the fix was to derive the
    authorization loop and the materialization plan from one `ancestors()` call.
    The weakest rule here: it catches the shape the defect took (a loop over
    `.parent()`) but not a recursive re-derivation, and single-hop `.parent()`
    calls are legitimate everywhere.
    check: ! rg -qU '(while|for)[^;{]*\.parent\(\)' src --glob '!src/space.rs'
