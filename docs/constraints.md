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

`OxigraphStore` reaches for its store handle in exactly one place.
    → `store.rs`'s doc comment on `OxigraphStore::blocking`. Oxigraph is
    synchronous: an evaluation runs to completion on the calling thread, so a
    `SparqlStore` method that awaits it directly occupies a Tokio worker for
    the whole query. A runtime has one worker per core, which makes a handful
    of concurrent reads a stall on *every* request in flight, including those
    that never touch the store. Nothing catches it: the method is already
    `async`, so the blocking body compiles, and against the in-memory store an
    evaluation is microseconds — the tests cannot see the difference, and only
    a durable backend under load makes it visible. `blocking` is the one
    offload point, so the property reduces to the handle having one reader.
    The check counts `self.inner`, which is why the doc comment above says
    "store handle" rather than spelling the field — prose would count as a
    second reader. It was demonstrated red against the real violation it
    exists for: before the offload, all four trait methods evaluated inline
    and the count was 4.
    check: [ "$(rg -c 'self\.inner' src/store.rs)" = 1 ] && rg -q 'spawn_blocking' src/store.rs
    
`GuardedClient` is the only `reqwest::Client` this crate builds.
    → 2026-07-31-auth-caching-design.md §1; `safe_fetch.rs`'s own comment on the
    type. `guarded_get` no longer validates addresses for the connection it is
    about to make — its client does, in the DNS resolver it was built with. That
    is what allows one client to be shared, and it is also what makes a bare
    `reqwest::Client` dangerous here: it satisfies nothing at the type level but
    resolves through the system resolver, so an SSRF filter that reads as present
    at every call site is absent at the only place it acts. The private field
    makes `GuardedClient::new` the only constructor today; nothing stops a second
    one, or an `inner()`, being added — the same membership gap the
    `DirectlyWritable` rule exists for. Counts constructions, not mentions: the
    `reqwest::Client` type is named in `GuardedClient`'s own field.
    check: [ "$(rg -o 'reqwest::Client::(builder|new)' src | wc -l)" = 1 ]

Every `SparqlEvaluator` disables the default HTTP `SERVICE` handler.
    → 2026-07-30-shape-validation-design.md §2.1. `rudof_lib` pulls
    `http-client` into the tree, which gives a bare `SparqlEvaluator::new()`
    a live `SERVICE` handler by default — a capability this pod's own
    server-authored queries never use and nothing here should be able to
    reach for. The compiler does not require the opt-out:
    `.without_default_http_service_handler()` is a builder call a future
    query site can simply omit and still compile. `SparqlEvaluator` also
    implements `Default`, so `SparqlEvaluator::default()` constructs the same
    live-`SERVICE` evaluator and must count as a construction site too — a
    check pinned to `::new()` alone is a check a rewrite to `::default()`
    walks straight past while staying green.
    check: [ "$(rg -o 'SparqlEvaluator::(new|default)\(\)' src | wc -l)" = "$(rg -o 'without_default_http_service_handler' src | wc -l)" ]

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

The write advertisement is built from `Format::ALL`.
    → 2026-07-31-accept-put-post-design.md §2, §6. `Accept-Put` and
    `Accept-Post` name the media types `classify_body` admits, and a
    hand-maintained second list is how the header comes to advertise a type
    the parser refuses — a disagreement invisible from either side, because
    both halves keep looking plausible on their own. `aux_links` builds from
    `AuxKind::ALL` against the same failure. Anchored on the loop rather than
    on the absence of literals: `http.rs` legitimately names
    `application/trig` and `application/ld+json` in the `rel="alternate"`
    links of §6.2, and every format by name across its tests.
    check: rg -q 'for f in Format::ALL' src/http.rs

`patch` never reaches the store.
    → 2026-07-30-n3-patch-design.md §3, §6. The argument that no client SPARQL
    exists rests on the patch document being parsed to terms in one place and
    turned into queries in another: `patch` decides whether a document is
    acceptable, `resource::patch_dataset` decides what it does to a resource.
    Give `patch` a store and the two questions merge, the shape validation stops
    being testable without one, and the module that holds client-authored
    structure gains the ability to execute it. The narrower grep is deliberate —
    the word "store" appears in this module's prose, and a rule that trips over
    its own doc comment is a rule someone deletes.
    check: ! rg -q 'crate::store|SparqlStore' src/patch.rs

No `#[allow]` attributes in `src/`.
    → Plan 6 Task 1 recorded this as a global constraint, and it was
    load-bearing once already: it forced a plan-mandated `Result<String, ()>`
    (which trips `clippy::result_unit_err`) to become a named error type. The
    dataset skeleton suspended it deliberately, with `// skeleton:` comments;
    this rule is what removes them.
    check: ! rg -q '#\[allow' src

Only `aux` patches an auxiliary.
    → 2026-07-30-n3-patch-design.md §8; `docs/constraints.md`'s `DirectlyWritable`
    rule, whose defect this is the patch-shaped version of. `patch_guarded` takes
    any `GraphName` so an auxiliary can reach it, and an auxiliary reaching it
    without the subject-existence guard plants a policy document on a path that
    no longer exists — permanent, because nearest-ACL-wins then hands it out.
    The type system cannot express "guarded" here; this check can.
    What the grep pins is narrower than the sentence above it: that no other
    file names the symbol at all, doc comment included — it does not stop
    `aux.rs` itself from passing an empty guard. What pins that is one test,
    `aux::tests::a_patch_whose_subject_vanishes_under_the_write_writes_nothing`:
    it stages the auxiliary present with its subject gone, the only state that
    reaches the guarded write, and asserts the auxiliary's graph is unchanged.
    No other test reaches the guard — the ones that look as though they do are
    refused by `aux::patch`'s opening `exists` check, because `delete_subject`
    cascades the auxiliary away with its subject. Replacing the guard argument
    with `""` makes that one test fail and no other.
    check: ! rg -q 'patch_guarded' src --glob '!src/aux.rs' --glob '!src/resource.rs'

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
    `shapes.rs` can name it to compare against — and any restricted-visibility
    modifier (`pub(crate)`, `pub(super)`, `pub(in path)`) counts as exported
    for this purpose, since `shapes` is a top-level module and `pub(super)`
    is exactly `pub(crate)` here, so the pattern below matches all of them.
    check: ! rg -q 'ldp#constrainedBy' src --glob '!src/shapes.rs' --glob '!src/http.rs' && [ "$(rg -o 'ldp#constrainedBy' src/http.rs | wc -l)" = 7 ] && ! rg -q 'pub(\([^)]*\))? const LDP_CONSTRAINED_BY' src/shapes.rs

The query string is read in exactly one place.
    → §6. `?validate` is the only query parameter this pod gives meaning to,
    and the reason it is safe is that it changes no path and therefore no WAC
    target. A second reader elsewhere is behaviour hidden behind a parameter
    that no URL shows and no ACL names.
    check: [ "$(rg -o 'RawQuery' src | wc -l)" = 5 ]

## RDF version

The RDF version of a dataset is classified in exactly one place.
    → 2026-07-30-rdf12-design.md §3.1, §10. The write-side refusal and the
    read-side projection ask the same question, and two classifiers is how
    they drift apart — silently, because both answer and one answers wrong.
    That already happened once: the refusal this replaced matched
    `Term::Triple` and never looked at `Literal::direction`, so every
    directional language-tagged string walked into storage while the rule
    above it claimed the wire was RDF 1.1. The check counts the
    classification *body*, not the name: `SparqlStore::rdf_version` has the
    same signature for a different question (what a backend can hold).
    check: [ "$(rg -o 'Term::Triple\(_\) => RdfVersion' src | wc -l)" = 1 ]

The N3 Patch path refuses both RDF 1.2 additions, not just triple terms.
    → 2026-07-30-rdf12-design.md §2; 2026-07-30-n3-patch-design.md. A patch is
    the only way into the store that does not go through `Format::parse`: a
    `text/n3` body builds no `Dataset`, so it cannot ask
    `Dataset::rdf_version`, and the refusal has to be repeated in `patch.rs`.
    It is repeated over **both** additions, because a directional
    language-tagged string is an ordinary `Literal` and a match on
    `N3Term::Triple` alone lets it through — the exact half-check
    `Format::parse` shipped with.
    **Honest about its own strength:** measured, `oxttl`'s N3 parser already
    refuses both at the syntax level (`<<(` is "not a valid RDF value",
    `@en--ltr` is "rdf:dirLangString is not supported in N3"), so today these
    two arms are depth behind the parser rather than the live refusal. The
    rule pins them so they are still there if `oxttl` gains RDF 1.2 syntax for
    N3 — which is the only way they become load-bearing.
    check: rg -q 'N3Term::Triple\(_\) => Err' src/patch.rs && rg -q 'l.direction\(\).is_some\(\) => Err' src/patch.rs

The `version` media-type parameter is read in exactly one place.
    → 2026-07-30-rdf12-design.md §4, §10. `Content-Type` on write and
    `Accept` on read ask the same question of the same syntax; a second
    reader is how `1.2` comes to mean one thing on the way in and another on
    the way out. Mirrors the single q-value parse rule above, and it is why
    `Repr::Rdf` carries the declared version through the write path instead
    of the handler re-reading the header it already parsed.
    The check counts the idioms that *extract* the value, not every mention
    of the word: calling `RdfVersion::from_media_type` twice is the one
    reader being used twice and is fine, while a hand-rolled second parse is
    what this forbids. A looser pattern counted a test assertion as a
    violation.
    check: [ "$(rg -o 'eq_ignore_ascii_case\("version"\)|strip_prefix\("version="\)|starts_with\("version="\)' src | wc -l)" = 1 ]

## WAC

The guard names the store exactly twice: the field it holds and the probe that fills it.
    → 2026-07-31-request-scoped-guard-design.md §5, §9. The decision methods are
    synchronous and hold no store, so a second resolution of the same ACL — which
    would repeat the ancestor walk and could straddle a concurrent write — is not
    something a later edit has to remember not to write. Restoring a store parameter
    to any of the three makes this three. Anchored on the declaration rather than on
    a regex over one signature, so it cannot be satisfied by a method spelled
    differently.
    check: [ "$(rg -o 'dyn SparqlStore' src/wac/guard.rs | wc -l)" = 2 ]
