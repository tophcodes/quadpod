# Constraints

Rules that must stay true, with the command that decides them. The reasoning
lives in [`architecture.md`](architecture.md) and [`decisions.md`](decisions.md);
this file only holds the check, so a rule cannot quietly stop being enforced.

A non-indented line is a rule. An indented `check:` line is the command that
verifies it. A non-zero exit means the rule is broken. `arch-check` runs them
all; `arch-check --only <substring>` runs one.

Every rule here goes red against a real violation. A check that cannot fail is
worse than no check.

## Type model

Only `AuxUrl` may be deleted on its own; only `ResourceUrl` and `ContainerUrl` may be written directly.
    → the doc comments on
    `space::DirectlyWritable` / `DirectlyDeletable`; `tests/unrepresentable.rs`.
    `aux::` is a convention rather than a construction: without these bounds
    `put_rdf(&foo.aux(Acl))` compiles and skips the subject-existence guard,
    planting a policy document that nearest-ACL-wins then makes permanent. Two
    defect classes are unrepresentable only because of these two `impl` lines.
    The compiler enforces the bound at every call site; nothing enforces that
    the bound keeps its membership.
    check: [ "$(rg -o 'impl DirectlyDeletable for [A-Za-z]+' src | wc -l)" = 1 ] && [ "$(rg -o 'impl DirectlyWritable for [A-Za-z]+' src | wc -l)" = 2 ]

`space::GraphName` stays sealed.
    → `space.rs`'s own comment on the trait; Every implementor's `graph_iri` is interpolated verbatim into SPARQL, so only
    types minted through `StorageSpace::resolve` may implement it. Unsealed,
    `impl GraphName for String` compiles and feeds a raw request path straight
    into `INSERT DATA`. `mod sealed` being private is compile-enforced; nothing
    holds the supertrait bound on `GraphName`, and deleting five characters
    unseals all three traits at once.
    check: rg -q 'pub trait GraphName: sealed::Sealed' src/space.rs

## Storage addressing

Only `resource` builds a system-graph IRI.
    → `resource.rs`'s
    module header. The presence marker is what makes existence a stored fact
    rather than a triple count. That ambiguity made an empty ACL mean the
    opposite of what its author wrote. Its safety argument is that no
    user-addressable path can name a `urn:quadpod:` graph; a second place deriving
    `urn:quadpod:sys:<iri>` is a second place that can scope it wrong, and the shelf
    registry is about to write into that same graph. Quote-anchored, because
    `shelf.rs` legitimately mentions the scheme in prose.
    check: ! rg -q '"urn:quadpod:sys:' src --glob '!src/resource.rs'

Only `shelf::ShelfKey` mints a subgraph IRI.
    → The key is a
    pure function of (resource IRI, graph name) with a `0x00` separator; a
    second place building that string by hand is how two resources come to
    share one shelf, which is a cross-resource read and write.
    check: ! rg -q "urn:quadpod:subgraph" src --glob '!src/shelf.rs'

Only `dataset` mints or recognises a skolem IRI.
    → Skolemization preserves meaning only while the skolem IRIs occur
    nowhere else (RDF 1.1 §3.5); a second place that writes or matches
    `urn:quadpod:bnode:` is a second place that can get the round trip wrong.
    check: ! rg -q "urn:quadpod:bnode" src --glob '!src/dataset.rs'

A SPARQL literal is never interpolated by hand.
    → `sparql::Literal`. Every
    `<...>` interpolation in this crate is fed by a sealed or validated type, so
    the IRI half needs no rule; the quote half had exactly one site and no rule
    at all. A hand-written `"{}"` is a value that can close its own literal and
    continue the update as syntax, and it fails by executing rather than by
    erroring. `src/http.rs` and `src/dataset.rs` are excluded: their `\"{`
    matches build an HTTP `Link` header, a `Warning` header and an `ETag`
    (`blob_etag`) in `src/http.rs`, and an `ETag` (`Skolemized::etag`) in
    `src/dataset.rs`, all quoted per their own RFC and never SPARQL. Two of the
    HTTP tests are excluded for the same reason, by name rather than as a
    subtree: `src/http/tests/acl.rs` asserts on that `Warning` header and
    `src/http/tests/events.rs` interpolates a Turtle request body, while their
    sibling files hand-build SPARQL against the store and stay
    covered.
    check: ! rg -q '\\"\{' src --glob '!src/sparql.rs' --glob '!src/http.rs' --glob '!src/http/tests/acl.rs' --glob '!src/http/tests/events.rs' --glob '!src/dataset.rs'

Only `blob::BlobKey` builds an object key.
    → The key is the resource's
    own path, so two resources sharing one object is a cross-resource read and
    write, the same failure `ShelfKey` guards against one layer up. It is also
    what the derived-key argument rests on: an interrupted write heals only
    because every writer computes the same key from the same URL.
    check: ! rg -q 'Path::(from|parse)' src --glob '!src/blob.rs'

## Boundaries that have no compiler behind them

`FetchPolicy::permissive` stays `#[cfg(test)]`.
    → docs/deployment.md, "What it does not relax": there is no flag that turns
    the SSRF filter off globally, and the blanket-permissive policy cannot be
    constructed in a release build. This is the control between an
    unauthenticated pre-auth fetch and the cloud-metadata endpoint. No test can
    observe a missing `cfg` gate, since tests run with `cfg(test)` on, so it is a
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
    evaluation is microseconds: the tests cannot see the difference, and only
    a durable backend under load makes it visible. `blocking` is the one
    offload point, so the property reduces to the handle having one reader.
    The check counts `self.inner`, which is why the doc comment above says
    "store handle" rather than spelling the field, because prose would count as
    a second reader. Without the offload all four trait methods evaluate
    inline and the count is 4.
    check: [ "$(rg -c 'self\.inner' src/store.rs)" = 1 ] && rg -q 'spawn_blocking' src/store.rs
    
`GuardedClient` is the only `reqwest::Client` this crate builds.
    → `safe_fetch.rs`'s own comment on the
    type. `guarded_get` does not validate addresses for the connection it is
    about to make. Its client does, in the DNS resolver it was built with. That
    is what allows one client to be shared, and it is also what makes a bare
    `reqwest::Client` dangerous here: it satisfies nothing at the type level but
    resolves through the system resolver, so an SSRF filter that reads as present
    at every call site is absent at the only place it acts. The private field
    makes `GuardedClient::new` the only constructor today; nothing stops a second
    one, or an `inner()`, being added, which is the same membership gap the
    `DirectlyWritable` rule exists for. Counts constructions, not mentions: the
    `reqwest::Client` type is named in `GuardedClient`'s own field.
    check: [ "$(rg -o 'reqwest::Client::(builder|new)' src | wc -l)" = 1 ]

Every `SparqlEvaluator` disables the default HTTP `SERVICE` handler.
    → `rudof_lib` pulls
    `http-client` into the tree, which gives a bare `SparqlEvaluator::new()`
    a live `SERVICE` handler by default, a capability this pod's own
    server-authored queries never use and nothing here should be able to
    reach for. The compiler does not require the opt-out:
    `.without_default_http_service_handler()` is a builder call a future
    query site can omit and still compile. `SparqlEvaluator` also
    implements `Default`, so `SparqlEvaluator::default()` constructs the same
    live-`SERVICE` evaluator and must count as a construction site too: a
    check pinned to `::new()` alone is one that a rewrite to `::default()`
    walks straight past while staying green.
    check: [ "$(rg -o 'SparqlEvaluator::(new|default)\(\)' src | wc -l)" = "$(rg -o 'without_default_http_service_handler' src | wc -l)" ]

`SparqlStore` has exactly one implementor.
    → `docs/decisions.md`, ADR-2. A tripwire, not a prohibition:
    dyn dispatch exists precisely so a backend can be swapped, but the
    `;`-sequence atomicity every write path rests on is a property of
    `OxigraphStore` rather than of SPARQL. A second implementor must reopen that
    decision, and today nothing would make anyone do it. Matched in every
    spelling that names the trait, because the path is the loophole: the check
    read `impl SparqlStore for` alone while `src/http/tests/fixture.rs` writes
    `impl crate::store::SparqlStore for FailingStore` and passed unseen. That
    `#[cfg(test)]` double is a backend outage the HTTP handlers have to answer,
    not a second backend, so it is carved out by file and pinned to one there in
    turn, so a real second implementor goes red wherever it lands.
    check: [ "$(rg -o 'impl (crate::)?(store::)?SparqlStore for [A-Za-z]+' src --glob '!src/http/tests/fixture.rs' | wc -l)" = 1 ] && [ "$(rg -o 'impl (crate::)?(store::)?SparqlStore for [A-Za-z]+' src/http/tests/fixture.rs | wc -l)" = 1 ]

`ResourceUrl::ancestors` is the only multi-hop walk up the container chain.
    → tests/unrepresentable.rs's header. Two separate walks drift: one that
    mutates every ancestor to the root while only the immediate parent is
    authorized. The authorization loop and the materialization plan both derive
    from a single `ancestors()` call. The weakest rule here: it catches a loop
    over `.parent()` but not a recursive re-derivation, and single-hop
    `.parent()` calls are legitimate everywhere.
    check: ! rg -qU '(while|for)[^;{]*\.parent\(\)' src --glob '!src/space.rs'

There is one content-negotiation path, one parser and one ETag.
    → `Format` and
    `negotiate` replaced `format_for_content_type` / `format_for_accept` /
    `rdf::parse` / `rdf::serialize` / `rdf::etag`. Two of each is how the
    Turtle path and the dataset path drift apart, and drift here is silent:
    both answer, one answers wrong.
    check: ! rg -q 'fn (format_for_accept|format_for_content_type)\b' src

The write advertisement is built from `Format::ALL`.
    → `Accept-Put` and
    `Accept-Post` name the media types `classify_body` admits, and a
    hand-maintained second list is how the header comes to advertise a type
    the parser refuses, a disagreement invisible from either side, because
    both halves keep looking plausible on their own. `aux_links` builds from
    `AuxKind::ALL` against the same failure. Anchored on the loop rather than
    on the absence of literals: `http.rs` legitimately names
    `application/trig` and `application/ld+json` in the `rel="alternate"`
    links of §6.2, and every format by name across its tests.
    check: rg -q 'for f in Format::ALL' src/http.rs

`patch` never reaches the store.
    → `docs/decisions.md`, ADR-8. The argument that no client SPARQL
    exists rests on the patch document being parsed to terms in one place and
    turned into queries in another: `patch` decides whether a document is
    acceptable, `resource::patch_dataset` decides what it does to a resource.
    Give `patch` a store and the two questions merge, the shape validation stops
    being testable without one, and the module that holds client-authored
    structure gains the ability to execute it. The narrower grep is deliberate:
    the word "store" appears in this module's prose, and a rule that trips over
    its own doc comment is a rule someone deletes.
    check: ! rg -q 'crate::store|SparqlStore' src/patch.rs

No `#[allow]` attributes in `src/`.
    → A global constraint. The lint an `#[allow]` would silence is the one
    naming the defect: `clippy::result_unit_err` on a `Result<String, ()>` is
    what turns it into a named error type. The dataset skeleton suspends this
    rule deliberately, with `// skeleton:` comments; this rule is what removes
    them.
    check: ! rg -q '#\[allow' src

Only `aux` patches an auxiliary.
    → `docs/constraints.md`'s `DirectlyWritable`
    rule, whose defect this is the patch-shaped version of. `patch_guarded` takes
    any `GraphName` so an auxiliary can reach it, and an auxiliary reaching it
    without the subject-existence guard plants a policy document on a path that
    no longer exists, permanently, because nearest-ACL-wins then hands it out.
    The type system cannot express "guarded" here; this check can.
    What the grep pins is narrower than the sentence above it: that no other
    file names the symbol at all, doc comment included. It does not stop
    `aux.rs` itself from passing an empty guard. What pins that is one test,
    `aux::tests::a_patch_whose_subject_vanishes_under_the_write_writes_nothing`:
    it stages the auxiliary present with its subject gone, the only state that
    reaches the guarded write, and asserts the auxiliary's graph is unchanged.
    No other test reaches the guard. The ones that look as though they do are
    refused by `aux::patch`'s opening `exists` check, because `delete_subject`
    cascades the auxiliary away with its subject. Replacing the guard argument
    with `""` makes that one test fail and no other.
    check: ! rg -q 'patch_guarded' src --glob '!src/aux.rs' --glob '!src/resource.rs'

The `Accept` header is parsed in exactly one place.
    → `negotiate` and
    `accept_allows` ask different questions of the same header. The existing
    negotiation rule pins that two *named* functions do not return; this pins
    the property those names stood for. The q-value parse is what a second
    reader cannot avoid rewriting, so this fails against a real violation
    rather than against a naming convention.
    check: [ "$(rg -o 'strip_prefix\("q="\)' src | wc -l)" = 1 ]

## Shape validation

Only `shapes` reads the constraint binding.
    → The binding is what
    decides whether a write is checked at all; a second reader is a second
    answer to "is this container constrained", and the one that says no wins
    silently. The lookup is also the seam a shape-tree binding would replace
    (§8), which only stays a second lookup while there is exactly one. Three
    conjuncts, because a second reader can take three different shapes: it can
    spell the IRI itself (bare-quoted, as `container.rs` spells
    `LDP_CONTAINS`'s value, or angle-bracketed inside a SPARQL string, as
    every other metadata read in this crate does); or it can skip the spelling
    entirely by importing `LDP_CONSTRAINED_BY` and comparing against that.
    `src/http.rs` and `src/http/tests/shapes.rs` are excluded from the first
    conjunct rather than cleared outright: the shape tests `PUT` a Turtle body
    to set a binding up, which is data, not a read, but it is still the IRI in
    text, so the second conjunct pins today's count across the two instead,
    and a new occurrence in either, reader or fixture, goes red. The count
    includes one non-fixture occurrence: the `422` refusal's own `Link:
    rel="…ldp#constrainedBy"` header (§3.1): the response naming the shape
    that refused it is no second *read* of the binding, since it is built
    from the `Shape` `shapes::load` already returned, and it is one more
    place the HTTP layer spells the IRI, so it counts here rather than being
    carved out like the fixtures are. The third conjunct is what stops the
    import: `LDP_CONSTRAINED_BY` stays private, so nothing outside
    `shapes.rs` can name it to compare against. Any restricted-visibility
    modifier (`pub(crate)`, `pub(super)`, `pub(in path)`) counts as exported
    for this purpose, since `shapes` is a top-level module and `pub(super)`
    is exactly `pub(crate)` here, so the pattern below matches all of them.
    check: ! rg -q 'ldp#constrainedBy' src --glob '!src/shapes.rs' --glob '!src/http.rs' --glob '!src/http/tests/shapes.rs' && [ "$(rg -o 'ldp#constrainedBy' src/http.rs src/http/tests/shapes.rs | wc -l)" = 7 ] && ! rg -q 'pub(\([^)]*\))? const LDP_CONSTRAINED_BY' src/shapes.rs

The query string is read in exactly one place.
    → `?validate` is the only query parameter this pod gives meaning to,
    and the reason it is safe is that it changes no path and therefore no WAC
    target. A second reader elsewhere is behaviour hidden behind a parameter
    that no URL shows and no ACL names.
    check: [ "$(rg -o 'RawQuery' src | wc -l)" = 5 ]

## RDF version

The RDF version of a dataset is classified in exactly one place.
    → The write-side refusal and the
    read-side projection ask the same question, and two classifiers is how
    they drift apart, silently, because both answer and one answers wrong.
    A refusal that matches `Term::Triple` and never looks at
    `Literal::direction` walks every directional language-tagged string into
    storage while the rule above it claims the wire is RDF 1.1. The check
    counts the classification *body*, not the name: `SparqlStore::rdf_version`
    has the same signature for a different question (what a backend can hold).
    check: [ "$(rg -o 'Term::Triple\(_\) => RdfVersion' src | wc -l)" = 1 ]

The N3 Patch path refuses both RDF 1.2 additions, not just triple terms.
    → A patch is
    the only way into the store that does not go through `Format::parse`: a
    `text/n3` body builds no `Dataset`, so it cannot ask
    `Dataset::rdf_version`, and the refusal has to be repeated in `patch.rs`.
    It is repeated over **both** additions, because a directional
    language-tagged string is an ordinary `Literal` and a match on
    `N3Term::Triple` alone lets it through, which is the exact half-check
    `Format::parse` shipped with.
    **Honest about its own strength:** measured, `oxttl`'s N3 parser already
    refuses both at the syntax level (`<<(` is "not a valid RDF value",
    `@en--ltr` is "rdf:dirLangString is not supported in N3"), so today these
    two arms are depth behind the parser rather than the live refusal. The
    rule pins them so they are still there if `oxttl` gains RDF 1.2 syntax for
    N3, which is the only way they become load-bearing.
    check: rg -q 'N3Term::Triple\(_\) => Err' src/patch.rs && rg -q 'l.direction\(\).is_some\(\) => Err' src/patch.rs

The `version` media-type parameter is read in exactly one place.
    → `Content-Type` on write and
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

## Configuration

The config file is never found, only named.
    → A pod must not be able to start
    against a file that is invisible to whoever reads the command line, so
    `--config`/`POD_CONFIG` is the only route in and there is no search path.
    The rule is cheap to break by accident: adding a "just look in the working
    directory too" convenience is one line, reads as helpful, and silently
    makes two pods with identical invocations behave differently depending on
    where they were started. The `.toml"` alternative is deliberately blunt:
    it matches *any* string literal ending in `.toml`, whatever expression it
    sits in, so `Path::new`, `PathBuf::from`, a bare `.join(...)` argument and
    a `static` all count the same as a `const` or `let`. A narrower pattern
    anchored on `const`/`let` was tried and abandoned: `PathBuf::from` and
    `Path::new` are how a path gets written in Rust, so it missed the
    likeliest shape of the very convenience the rule exists to stop.
    **This over-matches, and that is the accepted trade.** A legitimate
    `.toml`-suffixed literal in a test fixture trips it too; twice during
    implementation it did, and both fixtures were rewritten around the check.
    If you hit it and your literal is data a test writes rather than a path
    the pod looks for, build the name with `.with_extension("toml")`, as
    `config.rs`'s `write_temp_toml` does, rather than loosening this rule.
    A false positive here argues with you out loud; a false negative would
    let a search path in without a word. Demonstrated red,
    each injected into and then reverted out of `src/config.rs` in turn,
    against `let p = std::path::PathBuf::from("quadpod.toml");`, that same
    call as a bare expression with no binding, `let p =
    std::path::Path::new("quadpod.toml");`,
    `std::env::current_dir().unwrap().join("quadpod.toml")`, `static
    SEARCH_PATH: &str = "quadpod.toml";`, and a `dirs::config_dir()` /
    `std::env::var("XDG_CONFIG_HOME")` / `home_dir()` lookup; demonstrated to
    stay green on the unmodified tree, where the two fixture lines above
    build their temp filename through `std::env::temp_dir().join(...)` and
    `.with_extension("toml")` rather than a `.toml`-suffixed string literal.
    **What it does not catch:** a search path built by joining a non-literal
    base, such as `std::env::current_dir().unwrap().join("quadpod").with_extension("toml")`,
    the very idiom this rule's own prose recommends above for a test
    fixture's filename, produces no matching string literal and passes
    unseen, and a search path whose filename does not end in `.toml` at all
    is invisible to a check anchored on that suffix, even though `--config`
    itself accepts any path. Both were verified to pass unseen against the
    unmodified tree.
    check: ! rg -q 'XDG_CONFIG|dirs::|home_dir|\.toml"' src

Precedence is clap's, never hand-written.
    → `config.rs`'s module header,
    which states the property this pins. File values reach clap as defaults,
    so flag > env > file > default falls out of clap's own resolution with no
    merge logic anywhere. The alternative, reading `ArgMatches::value_source`
    and overwriting whatever came from a default, needs one arm per field,
    and a field whose arm is forgotten silently ignores the file. Nothing but
    a missing test would catch that, and that is why it is worth a rule.
    Scoped to all of `src`, not just `config.rs`: `Config::load()`'s result is
    consumed in `main.rs`, so a merge helper placed there instead
    would be the same hand-written precedence and a check confined to
    `config.rs` would not see it. Demonstrated red against a
    `value_source("listen")` merge helper injected into `main.rs`.
    check: ! rg -q 'value_source' src
## WAC

The guard names the store exactly twice: the field it holds and the probe that fills it.
    → The decision methods are
    synchronous and hold no store, so a second resolution of the same ACL, which
    would repeat the ancestor walk and could straddle a concurrent write, is not
    something a later edit has to remember not to write. Restoring a store parameter
    to any of the three makes this three. Anchored on the declaration rather than on
    a regex over one signature, so it cannot be satisfied by a method spelled
    differently.
    check: [ "$(rg -o 'dyn SparqlStore' src/wac/guard.rs | wc -l)" = 2 ]

`wac` names no HTTP type and calls nothing in `http`.
    → issue #46; the doc comment on `wac::guard::Denial`. `pdp` is pure and
    `prp` owns the I/O, and that is what makes the decision table-testable;
    `guard` undid half of that by answering every refusal as an
    `axum::response::Response` and calling `crate::http::internal_error` for a
    store failure. A refusal built inside the decision layer is a status code
    and a body chosen where neither belongs, it makes the guard's tests assert
    renderings instead of decisions, and it costs a `clippy::result_large_err`
    on four hot signatures. `Denial` is the seam: the guard says which refusal,
    `impl IntoResponse for Denial` in `src/http.rs` says what it costs.
    Nothing but this rule holds the direction: the dependency compiles either
    way, and one `crate::http::` call is all it takes to go back.
    Anchored on both halves, because they are two different ways in: `axum`
    catches a type named directly (`Response`, `StatusCode`, a `header::`
    constant), `http::` catches both a reach back into this crate's own
    `http` module and a `use http::StatusCode` from the same `http` crate
    axum re-exports, which is a direct dependency here and would otherwise
    slip past a check spelled `axum` alone. `http::` does not match the
    `https://` and `http://` IRIs this subtree's fixtures are full of, and
    `crate::http` without a trailing `::`, a rustdoc link rather than a call, is
    deliberately still allowed. Demonstrated red, each injected into and then
    reverted out of `src/wac/guard.rs` in turn, against `use
    axum::response::Response;`, a bare `axum::http::StatusCode::OK` expression,
    `crate::http::internal_error(&e)`, and `use http::StatusCode;`;
    demonstrated green on the tree as it stands.
    **What it does not catch:** HTTP smuggled in without either spelling. A
    `Denial` variant named after a status code, a bare `404` handed back for a
    caller to trust, or a response type re-exported from a third module under
    another name. It pins the import, not the layering.
    check: ! rg -q 'axum|http::' src/wac

## Failure reporting

Only `internal_error` builds a `500`.
    → issue #43; the doc comment on `http::internal_error`, which claims every
    `500` this crate builds goes through it. That claim is what makes the
    fixed `INTERNAL_ERROR_BODY` safe: the detail is dropped from the response
    only because the same call put it in the log. A second site that builds a
    `500` breaks both halves at once, and it breaks them in the direction that
    is invisible: the client still gets a plausible answer, the operator gets
    nothing, and no test fails. Before this rule the crate had thirty-odd such
    sites, each answering with the backend's own error text.
    Anchored on the two ways a `500` response is written rather than
    on the status name: `StatusCode::INTERNAL_SERVER_ERROR` appears
    legitimately in `put_status` and `shape_status`, which return a *status*
    that `put_error`/`shape_status` then route through `internal_error`, in
    two auth test handlers that mock a failing upstream, and in every test that
    asserts one. None of those build a response, and none of them match.
    Demonstrated red, each injected into and then reverted out of
    `src/http.rs` in turn, against
    `StatusCode::INTERNAL_SERVER_ERROR.into_response()` and
    `(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()`, the
    second being the exact shape the issue was filed about; demonstrated green
    on the tree as it stands, where the single match is `internal_error`'s own
    body.
    **What it does not catch:** a `500` spelled some other way:
    `Response::builder().status(500)`, a `StatusCode::from_u16(500)`, or a
    handler returning a bare `StatusCode` that axum renders itself. It also
    says nothing about `4xx`, which deliberately keep their own text. And it
    pins the construction, not the logging: deleting the `tracing::error!`
    from `internal_error` leaves this rule green, and `tests/observability.rs` is
    what fails then.
    check: [ "$(rg -o 'INTERNAL_SERVER_ERROR[,)]?\.into_response\(\)|\(StatusCode::INTERNAL_SERVER_ERROR,' src | wc -l)" = 1 ]

## Notifications

Every write handler emits exactly once.
    → Emission at each success site
    instead would be fifteen places to forget in `http.rs`, where a new write
    path compiles silently without an event and no test names the omission.
    Anchored on the router's method table rather than on a call count: the
    check reads the handlers registered under `put`/`post`/`patch`/`delete` in
    `router`, follows each to the `*_impl` it delegates to, and requires
    exactly one `crate::notify::emit_` in each of those and none anywhere else
    in the file. A fifth write route is therefore red the moment it is
    registered without an event, and a handler that stops calling its emit is
    red while it still compiles. `get` and `options` sit on the same table and
    are not counted: they register under no write method.
    Narrower than its sentence in three ways. It is textual, so an emit behind
    a branch that some success path misses still counts as one. It sees only
    what `router` registers, so a write path mounted through a nested `Router`
    or a tower service is invisible to it. And it expects the call in the
    `*_impl` itself, so a handler that emits from a helper it calls reads as a
    handler that never emits.
    check: awk '/\.route\(/ { s = $0; while (match(s, /(put|post|patch|delete)\([a-z_0-9]+\)/)) { h = substr(s, RSTART, RLENGTH); sub(/^[a-z]+\(/, "", h); sub(/\)$/, "", h); want[h] = 1; s = substr(s, RSTART + RLENGTH) } } /^[ \t]*(pub[a-z()]* )?(async )?fn [a-z_0-9]+/ { fn = $0; sub(/^.*fn /, "", fn); sub(/[^a-z_0-9].*/, "", fn) } match($0, /[a-z_0-9]+_impl\(/) { c = substr($0, RSTART, RLENGTH); sub(/\($/, "", c); if (index(" " callee[fn] " ", " " c " ") == 0) callee[fn] = callee[fn] " " c } /crate::notify::emit_/ { emits[fn]++ } END { for (h in want) { if (callee[h] == "") exit 1; k = split(callee[h], a, " "); for (j = 1; j <= k; j++) w[a[j]] = 1 } n = 0; for (i in w) { if (emits[i] != 1) exit 1; n += emits[i] } t = 0; for (f in emits) t += emits[f]; exit (t != n) }' src/http.rs

Only `notify` fixes a format for `state`.
    → `state` is the N-Quads
    validator at the held version; a second site choosing a format is a second
    answer to "which of this resource's ETags is its state", and the two would
    drift silently because both would keep producing a plausible tag.
    Anchored on the *fixed* format rather than on the media type: `rdf.rs`
    names `application/n-quads` in `Format::media_type` and `http.rs` in
    `SERVABLE`, both legitimately, so a literal-based check is red on arrival.
    What distinguishes this call is that every other `.etag(` site passes a
    negotiated format (`etag_candidates`, `get_impl` and `legacy_graph_read`
    all pass a variable), and only `state` pins one. Narrower than its
    sentence: it catches the copy-paste, not a second site that re-derives
    N-Quads under another name.
    check: ! rg -q 'etag\(nquads\(\)' src --glob '!src/notify.rs'

`Topic` is built only from a `Target`.
    → The registry is where #18
    authorizes subscriptions, so a key that did not pass
    `StorageSpace::resolve` is a subscription to a path the space never
    admitted. The private tuple field makes `From<&Target>` the only
    constructor today, and the compiler holds that only while the field stays
    private: widening it to `pub(crate)` opens the constructor to the whole
    crate, which is the shape the violation takes. Narrower than its
    sentence: it catches a topic minted anywhere but `notify.rs`, not a second
    `From` impl added beside the first one there.
    check: ! rg -q 'Topic\(' src --glob '!src/notify.rs'

Only `op::keys` touches the key file.
    → The signing key set is the one secret this process persists, and
    `KeySet::load_or_generate` is its single doorway: the 0600 mode, the
    RFC 7638 `kid` fallback and the never-rewrite rule all live behind it,
    and a second reader would re-decide them silently. Narrower than its
    sentence: it catches filesystem access anywhere else in `src/op/`, not a
    reader outside the module that is handed the path.
    check: ! rg -q 'std::fs' src/op --glob '!src/op/keys.rs'

`op` names no HTTP type and calls nothing in `http`.
    → Same boundary as `wac`: `op` issues and serializes, `http` routes and
    answers. The `/.well-known/` handlers call in; nothing calls out. This is
    what keeps #58's endpoints from growing response construction inside the
    signing module.
    check: ! rg -q 'axum|http::' src/op
