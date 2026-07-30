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
    user-addressable path can name a `urn:quadpod:` graph; a second place deriving
    `urn:quadpod:sys:<iri>` is a second place that can scope it wrong, and the shelf
    registry is about to write into that same graph. Quote-anchored, because
    `shelf.rs` legitimately mentions the scheme in prose.
    check: ! rg -q '"urn:quadpod:sys:' src --glob '!src/resource.rs'

Only `shelf::ShelfKey` mints a subgraph IRI.
    → 2026-07-28-jsonld-datasets-design.md §3.1, §3.2 invariant 1. The key is a
    pure function of (resource IRI, graph name) with a `0x00` separator; a
    second place building that string by hand is how two resources come to
    share one shelf, which is a cross-resource read and write.
    check: ! rg -q "urn:quadpod:subgraph" src --glob '!src/shelf.rs'

Only `dataset` mints or recognises a skolem IRI.
    → §4. Skolemization preserves meaning only while the skolem IRIs occur
    nowhere else (RDF 1.1 §3.5); a second place that writes or matches
    `urn:quadpod:bnode:` is a second place that can get the round trip wrong.
    check: ! rg -q "urn:quadpod:bnode" src --glob '!src/dataset.rs'

A SPARQL literal is never interpolated by hand.
    → 2026-07-29-non-rdf-resources-design.md §8.2; `sparql::Literal`. Every
    `<...>` interpolation in this crate is fed by a sealed or validated type, so
    the IRI half needs no rule; the quote half had exactly one site and no rule
    at all. A hand-written `"{}"` is a value that can close its own literal and
    continue the update as syntax, and it fails by executing rather than by
    erroring. `src/http.rs` and `src/dataset.rs` are excluded: their `\"{`
    matches build an HTTP `Link` header, a `Warning` header and an `ETag`
    (`blob_etag`) in `src/http.rs`, and an `ETag` (`Skolemized::etag`) in
    `src/dataset.rs` — all quoted per their own RFC, never SPARQL.
    check: ! rg -q '\\"\{' src --glob '!src/sparql.rs' --glob '!src/http.rs' --glob '!src/dataset.rs'

Only `blob::BlobKey` builds an object key.
    → 2026-07-29-non-rdf-resources-design.md §3.2. The key is the resource's
    own path, so two resources sharing one object is a cross-resource read and
    write — the same failure `ShelfKey` guards against one layer up. It is also
    what the derived-key argument rests on: an interrupted write heals only
    because every writer computes the same key from the same URL.
    check: ! rg -q 'Path::(from|parse)' src --glob '!src/blob.rs'

## Boundaries that have no compiler behind them

`FetchPolicy::permissive` stays `#[cfg(test)]`.
    → docs/deployment.md, "What it does not relax": there is no flag that turns
    the SSRF filter off globally, and the blanket-permissive policy cannot be
    constructed in a release build. This is the control between an
    unauthenticated pre-auth fetch and the cloud-metadata endpoint. No test can
    observe a missing `cfg` gate — tests run with `cfg(test)` on — so it is a
    published operator promise with nothing else enforcing it.
    check: rg -qU '#\[cfg\(test\)\]\s*\n\s*pub fn permissive' src/auth/safe_fetch.rs

Every `SparqlEvaluator` disables the default HTTP `SERVICE` handler.
    → 2026-07-30-shape-validation-design.md §2.1. `rudof_lib` pulls
    `http-client` into the tree, which gives a bare `SparqlEvaluator::new()`
    a live `SERVICE` handler by default — a capability this pod's own
    server-authored queries never use and nothing here should be able to
    reach for. The compiler does not require the opt-out:
    `.without_default_http_service_handler()` is a builder call a future
    query site can simply omit and still compile.
    check: [ "$(rg -o 'SparqlEvaluator::new\(\)' src | wc -l)" = "$(rg -o 'without_default_http_service_handler' src | wc -l)" ]

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

There is one content-negotiation path, one parser and one ETag.
    → 2026-07-28-jsonld-datasets-design.md §6.3, §6.1. `Format` and
    `negotiate` replaced `format_for_content_type` / `format_for_accept` /
    `rdf::parse` / `rdf::serialize` / `rdf::etag`. Two of each is how the
    Turtle path and the dataset path drift apart, and drift here is silent:
    both answer, one answers wrong.
    check: ! rg -q 'fn (format_for_accept|format_for_content_type)\b' src

No `#[allow]` attributes in `src/`.
    → Plan 6 Task 1 recorded this as a global constraint, and it was
    load-bearing once already: it forced a plan-mandated `Result<String, ()>`
    (which trips `clippy::result_unit_err`) to become a named error type. The
    dataset skeleton suspended it deliberately, with `// skeleton:` comments;
    this rule is what removes them.
    check: ! rg -q '#\[allow' src

The `Accept` header is parsed in exactly one place.
    → 2026-07-29-non-rdf-resources-design.md §6.1. `negotiate` and
    `accept_allows` ask different questions of the same header. The existing
    negotiation rule pins that two *named* functions do not return; this pins
    the property those names stood for. The q-value parse is what a second
    reader cannot avoid rewriting, which is what makes this fail against a real
    violation rather than against a naming convention.
    check: [ "$(rg -o 'strip_prefix\("q="\)' src | wc -l)" = 1 ]

## Shape validation

Only `shapes` reads the constraint binding.
    → 2026-07-30-shape-validation-design.md §3.1, §3.2. The binding is what
    decides whether a write is checked at all; a second reader is a second
    answer to "is this container constrained", and the one that says no wins
    silently. The lookup is also the seam a shape-tree binding would replace
    (§8), which only stays a second lookup while there is exactly one. Three
    conjuncts, because a second reader can take three different shapes: it can
    spell the IRI itself (bare-quoted, as `container.rs` spells
    `LDP_CONTAINS`'s value, or angle-bracketed inside a SPARQL string, as
    every other metadata read in this crate does); or it can skip the spelling
    entirely by importing `LDP_CONSTRAINED_BY` and comparing against that.
    `src/http.rs` is excluded from the first conjunct rather than cleared
    outright: its `#[cfg(test)]` fixtures `PUT` a Turtle body to set a binding
    up, which is data, not a read, but it is still the IRI in text — so the
    second conjunct pins today's count instead, and a new occurrence anywhere
    in the file, reader or fixture, goes red. The count includes one
    non-fixture occurrence: the `422` refusal's own `Link:
    rel="…ldp#constrainedBy"` header (§3.1) — the response naming the shape
    that refused it is not a second *read* of the binding, since it is built
    from the `Shape` `shapes::load` already returned, but it is one more
    place this file spells the IRI, so it counts here rather than being
    carved out like the fixtures are. The third conjunct is what stops the
    import: `LDP_CONSTRAINED_BY` stays private, so nothing outside
    `shapes.rs` can name it to compare against — and `pub(crate)` counts as
    exported for this purpose, so the pattern below matches both.
    check: ! rg -q 'ldp#constrainedBy' src --glob '!src/shapes.rs' --glob '!src/http.rs' && [ "$(rg -o 'ldp#constrainedBy' src/http.rs | wc -l)" = 7 ] && ! rg -q 'pub(\(crate\))? const LDP_CONSTRAINED_BY' src/shapes.rs

The query string is read in exactly one place.
    → §6. `?validate` is the only query parameter this pod gives meaning to,
    and the reason it is safe is that it changes no path and therefore no WAC
    target. A second reader elsewhere is behaviour hidden behind a parameter
    that no URL shows and no ACL names.
    check: [ "$(rg -o 'RawQuery' src | wc -l)" = 5 ]

## RDF version

The wire contract is RDF 1.1, and it is checked rather than assumed.
    → 2026-07-24-sparql-solid-pod-design.md §3; 2026-07-30-shape-validation-design.md §2.1.
    `rudof_lib` turns on oxigraph's `rdf-12` feature transitively, and Cargo
    unifies features crate-wide, so the linked parser accepts RDF 1.2 whether
    this pod wants it or not. Before that dependency the non-goal held because
    nothing had enabled the feature — an accident, not a property. `oxttl` has
    no version switch, so the refusal is ours and lives in the one parser.
    check: rg -q 'Term::Triple\(_\)' src/rdf.rs
