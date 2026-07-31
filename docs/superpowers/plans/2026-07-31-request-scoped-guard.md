# Request-Scoped Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-level ancestor re-walk in WAC authorization with one probe per request, carried by a `Guard` value whose decision methods cannot reach the store.

**Architecture:** A request touches exactly one path chain, derivable from its target. `Guard::probe` resolves every existence fact for that chain in one `SELECT` and the chain's ACLs in one more; `authorize` is then synchronous and pure; `materialize` consumes the guard, because the probe describes the store before the writes. A counting store in `tests/` pins the cost first, so the improvement is measured rather than asserted.

**Tech Stack:** Rust, axum 0.8, oxigraph (embedded, `rdf-12`), tokio, `async-trait`, `tower` (`ServiceExt::oneshot`) for driving the router in tests.

## Global Constraints

- **The skeleton's signatures are given.** Commits `275b092` and `433a160` fixed the public surface of `resource::exists_many`, `prp::load_chain_acls`, `wac::guard::Guard`. Tasks fill bodies and migrate callers. **No new public functions, no new modules.** One exception is called out explicitly in Task 2 (a `?Sized` bound on an existing helper).
- **Build and test only inside the Nix dev shell.** Every `cargo` command in this plan must be run as `nix develop --command cargo …`. A bare `cargo` fails on `openssl-sys` because `pkg-config` is not on the ambient PATH.
- **`docs/constraints.md` must stay green.** Run `arch-check` before every commit; it prints nothing when all 22 rules hold. Two rules bear directly on this work: *"Only `resource` builds a system-graph IRI"* (so the `urn:quadpod:sys:` prefix may appear only in `src/resource.rs`) and *"`SparqlStore` has exactly one implementor"* (so the counting store must live in `tests/`, never in `src/`).
- **No `#[allow]` attributes anywhere in `src/`.** This is rule 15 and it has no exceptions.
- **Conventional commits.** Subject line concise; a body only where the *why* is not obvious from the diff.
- **The design document is `docs/superpowers/specs/2026-07-31-request-scoped-guard-design.md`.** Section references below (§3, §4, …) are to it.

---

### Task 1: The counting store and today's budgets

Nothing else in this plan can be believed without this. It lands first, asserting the counts as they are **today**, so the later tasks show their improvement in a diff rather than in prose.

**Files:**
- Create: `tests/call_budget.rs`
- Read (for the fixture pattern): `tests/route_coverage.rs:1-70`

**Interfaces:**
- Consumes: `sparql_pod::store::{SparqlStore, StoreError, OxigraphStore}`, `sparql_pod::http::{router, AppState}` — all already `pub`.
- Produces: nothing other tasks import. Task 9 re-tightens the constants defined here.

- [ ] **Step 1: Confirm the test dependencies are already present**

Run: `nix develop --command cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].dependencies[] | "\(.kind // "normal") \(.name)"' | sort | grep -E "tower|async-trait|http-body-util|tokio"`

Expected: `async-trait` and `tokio` as `normal`, `tower` and `http-body-util` present (either kind). Both `[dependencies]` and `[dev-dependencies]` are visible to an integration test, so nothing needs adding. If `tower` or `http-body-util` is missing, stop and report — `tests/route_coverage.rs` already uses `tower`, so its absence would mean the metadata query is wrong, not the manifest.

- [ ] **Step 2: Write the counting store and a public-access fixture**

Create `tests/call_budget.rs`:

```rust
//! What one request costs the store.
//!
//! The budgets are upper bounds, not equalities: a budget that fails when the
//! count drops punishes the improvement it exists to protect. They are
//! committed against the counts as they were before
//! `2026-07-31-request-scoped-guard-design.md` was implemented, and tightened
//! in the commit that makes the lower numbers true.
//!
//! The store decorator lives here rather than in `src/` because
//! `docs/constraints.md` pins `SparqlStore` to one implementor under `src/`,
//! and that rule is about a backend carrying ADR-2's atomicity obligation. A
//! decorator that forwards every call is not a second backend — but the check
//! cannot tell, and weakening it would weaken it against a real one too.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use oxigraph::model::Triple;
use oxigraph::sparql::QuerySolution;
use sparql_pod::{
    auth::{AuthConfig, StaticJwksResolver, StaticWebIdIssuers, Jwks},
    aux, container,
    http::{router, AppState},
    rdf::{Format, RdfVersion},
    space::{AuxKind, GraphName, StorageSpace, Target},
    store::{OxigraphStore, SparqlStore, StoreError},
};
use tower::ServiceExt;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
struct Counts {
    update: usize,
    query_triples: usize,
    ask: usize,
    query_solutions: usize,
}

impl Counts {
    fn total(self) -> usize {
        self.update + self.query_triples + self.ask + self.query_solutions
    }
}

/// Forwards every call to `inner` and tallies it. Holds no state of its own,
/// so it inherits `OxigraphStore`'s `;`-sequence atomicity rather than
/// claiming its own.
struct CountingStore {
    inner: OxigraphStore,
    counts: Mutex<Counts>,
}

impl CountingStore {
    fn new(inner: OxigraphStore) -> Self {
        Self { inner, counts: Mutex::new(Counts::default()) }
    }

    /// Read the tally and reset it, so each test measures one request.
    fn take(&self) -> Counts {
        std::mem::take(&mut self.counts.lock().unwrap())
    }
}

#[async_trait::async_trait]
impl SparqlStore for CountingStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        self.counts.lock().unwrap().update += 1;
        self.inner.update(sparql).await
    }

    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError> {
        self.counts.lock().unwrap().query_triples += 1;
        self.inner.query_triples(sparql).await
    }

    async fn ask(&self, sparql: &str) -> Result<bool, StoreError> {
        self.counts.lock().unwrap().ask += 1;
        self.inner.ask(sparql).await
    }

    async fn query_solutions(&self, sparql: &str) -> Result<Vec<QuerySolution>, StoreError> {
        self.counts.lock().unwrap().query_solutions += 1;
        self.inner.query_solutions(sparql).await
    }

    fn rdf_version(&self) -> RdfVersion {
        self.inner.rdf_version()
    }
}

const PUBLIC_AGENT_CLASS: &str = "http://www.w3.org/ns/auth/acl#agentClass";
const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";

/// An app whose root ACL grants **everyone** read, write and control.
///
/// Public access is what makes this file credential-free: `auth::testsupport`
/// is `#[cfg(test)]` and so invisible to an integration test, and minting DPoP
/// proofs by hand here would measure the auth layer rather than the store. The
/// store-call counts are identical either way — `pdp::decide` is pure, and the
/// one branch that differs for an anonymous agent (reusing the user decision
/// as the public one) touches nothing stored.
async fn app() -> (axum::Router, Arc<CountingStore>) {
    let counting = Arc::new(CountingStore::new(OxigraphStore::in_memory().unwrap()));
    let store: Arc<dyn SparqlStore> = counting.clone();
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();

    container::provision_root(store.as_ref(), &space.root()).await.unwrap();

    let root = space.root();
    let root_acl = root.as_resource().aux(AuxKind::Acl);
    let root_iri = root.graph_iri().to_owned();
    let turtle = Format::from_content_type("text/turtle").unwrap();
    let triples: Vec<Triple> = turtle
        .parse(
            format!(
                "<#public> <{PUBLIC_AGENT_CLASS}> <{FOAF_AGENT}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <{root_iri}> ; \
                 <http://www.w3.org/ns/auth/acl#default> <{root_iri}> ; \
                 <http://www.w3.org/ns/auth/acl#mode> \
                   <http://www.w3.org/ns/auth/acl#Read>, \
                   <http://www.w3.org/ns/auth/acl#Write>, \
                   <http://www.w3.org/ns/auth/acl#Control> ."
            )
            .as_bytes(),
            root_acl.graph_iri(),
            RdfVersion::Rdf11,
        )
        .unwrap()
        .quads().iter().cloned().map(Triple::from).collect();
    aux::put(store.as_ref(), &root_acl, &triples).await.unwrap();

    let Target::Resource(seeded) = space.resolve("/seeded").unwrap() else {
        unreachable!("/seeded is a resource path")
    };
    let content: Vec<Triple> = turtle
        .parse(
            b"<#it> <http://schema.org/name> \"seed\" .",
            seeded.graph_iri(),
            RdfVersion::Rdf11,
        )
        .unwrap()
        .quads().iter().cloned().map(Triple::from).collect();
    sparql_pod::resource::put_rdf(store.as_ref(), &seeded, &content).await.unwrap();

    let app = router(AppState {
        store,
        blobs: Arc::new(sparql_pod::blob::ObjectStoreBlobs::in_memory()),
        space,
        resolver: Arc::new(StaticJwksResolver::new("https://idp.example/", Jwks::default())),
        webid_verifier: Arc::new(StaticWebIdIssuers::new()),
        auth_config: Arc::new(AuthConfig::default()),
        max_body_bytes: 64 * 1024 * 1024,
    });
    (app, counting)
}
```

If `Jwks::default()` or `StaticWebIdIssuers::new()` does not compile, read `tests/route_coverage.rs:56-70` and copy its construction verbatim — that file builds the same `AppState` and is known to compile.

- [ ] **Step 3: Add one measuring test and print what it costs**

Append to `tests/call_budget.rs`:

```rust
#[tokio::test]
async fn a_get_stays_within_budget() {
    let (app, counts) = app().await;
    counts.take(); // discard the fixture's own writes

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/seeded")
                .header(header::ACCEPT, "text/turtle")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let c = counts.take();
    println!("GET /seeded: {c:?} total={}", c.total());
    assert!(c.total() <= GET_BUDGET, "GET /seeded cost {c:?}, budget {GET_BUDGET}");
}
```

Add a placeholder constant above it so the file compiles: `const GET_BUDGET: usize = 100;`

- [ ] **Step 4: Run it and record the real number**

Run: `nix develop --command cargo test --test call_budget -- --nocapture`

Expected: PASS, with a line like `GET /seeded: Counts { update: 0, query_triples: 2, ask: 6, query_solutions: 2 } total=10`.

Set `GET_BUDGET` to exactly the `total=` value printed. Do not round it and do not pad it — the point of this commit is that the number is measured.

- [ ] **Step 5: Add the remaining five budgets the same way**

Write one test per method, each following Step 3's shape exactly: build the app, `counts.take()` to discard setup, drive one request, assert the status, `counts.take()`, `println!`, assert against a constant.

The six methods and their requests:

| Constant | Request | Expected status |
|---|---|---|
| `GET_BUDGET` | `GET /seeded`, `Accept: text/turtle` | `200 OK` |
| `PUT_EXISTING_BUDGET` | `PUT /seeded`, `Content-Type: text/turtle`, body `<#it> <http://schema.org/name> "two" .` | `204 NO_CONTENT` |
| `PUT_DEEP_BUDGET` | `PUT /a/b/c`, same headers and body | `201 CREATED` |
| `POST_BUDGET` | `POST /`, `Content-Type: text/turtle`, `Slug: child`, same body | `201 CREATED` |
| `DELETE_BUDGET` | `DELETE /seeded` | `204 NO_CONTENT` |
| `PATCH_BUDGET` | `PATCH /seeded`, `Content-Type: text/n3`, body below | `204 NO_CONTENT` |

The N3 Patch body:

```
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:patch a solid:InsertDeletePatch ;
  solid:inserts { <https://pod.toph.so/seeded#it> <http://schema.org/name> "patched" . } .
```

`PUT_DEEP_BUDGET` is the one that matters most: it is the *d²* case, and it is the number Task 9 will cut hardest.

- [ ] **Step 6: Run the whole file, fill in every constant, run again**

Run: `nix develop --command cargo test --test call_budget -- --nocapture`

Expected: six PASSes, each printing its `total=`. Set each constant to its printed value and re-run. Expected: six PASSes, no output changes.

- [ ] **Step 7: Verify the constraint check still holds**

Run: `arch-check`

Expected: no output. In particular *"`SparqlStore` has exactly one implementor"* stays green, because it counts `impl` blocks under `src/` and `CountingStore` is under `tests/`.

- [ ] **Step 8: Commit**

```bash
git add tests/call_budget.rs
git commit -m "test: pin what each method costs the store

Upper bounds against today's counts, so the guard refactor shows its
improvement in a diff instead of in prose. The decorator lives in tests/
because the one-implementor rule counts impls under src/ and a
forwarding decorator is not a second backend."
```

---

### Task 2: `resource::exists_many`

**Files:**
- Modify: `src/resource.rs` — the `exists_many` body (currently `todo!()`), and the `sys_graph_iri` bound
- Test: `src/resource.rs`, in its existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `SparqlStore::query_solutions`, `space::GraphName`.
- Produces: `pub async fn exists_many(store: &dyn SparqlStore, graphs: &[&dyn GraphName]) -> Result<HashSet<String>, ResourceError>` — returns the graph IRIs, as `String`, of those inputs that carry a presence marker.

- [ ] **Step 1: Write the failing tests**

Add to `src/resource.rs`'s test module:

```rust
#[tokio::test]
async fn exists_many_returns_only_the_present() {
    let store = OxigraphStore::in_memory().unwrap();
    let sp = StorageSpace::new("https://pod.toph.so/").unwrap();
    let here = match sp.resolve("/here").unwrap() { Target::Resource(r) => r, _ => unreachable!() };
    let gone = match sp.resolve("/gone").unwrap() { Target::Resource(r) => r, _ => unreachable!() };
    put_rdf(&store, &here, &[]).await.unwrap();

    let found = exists_many(&store, &[&here as &dyn GraphName, &gone]).await.unwrap();
    assert_eq!(found.len(), 1);
    assert!(found.contains(here.graph_iri()));
    assert!(!found.contains(gone.graph_iri()));
}

// An empty graph that is marked present is present — the same distinction
// `exists` draws, and the reason presence is a stored fact rather than a
// triple count.
#[tokio::test]
async fn exists_many_agrees_with_exists_on_every_input() {
    let store = OxigraphStore::in_memory().unwrap();
    let sp = StorageSpace::new("https://pod.toph.so/").unwrap();
    let empty = match sp.resolve("/empty").unwrap() { Target::Resource(r) => r, _ => unreachable!() };
    let absent = match sp.resolve("/absent").unwrap() { Target::Resource(r) => r, _ => unreachable!() };
    put_rdf(&store, &empty, &[]).await.unwrap();

    let found = exists_many(&store, &[&empty as &dyn GraphName, &absent]).await.unwrap();
    for g in [&empty, &absent] {
        assert_eq!(
            found.contains(g.graph_iri()),
            exists(&store, g).await.unwrap(),
            "exists_many disagreed with exists about {}", g.graph_iri()
        );
    }
}

// The degenerate input must not produce `VALUES { }`, which is a parse error
// rather than an empty answer.
#[tokio::test]
async fn exists_many_of_nothing_asks_nothing() {
    let store = OxigraphStore::in_memory().unwrap();
    assert!(exists_many(&store, &[]).await.unwrap().is_empty());
}
```

The test module may already import what these need. If `StorageSpace`, `Target` or `GraphName` are unresolved, add them to the module's existing `use` block rather than writing a fully-qualified path.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop --command cargo test --lib resource::tests::exists_many`

Expected: three FAILs, each panicking at `not yet implemented: design §4: one SELECT over a VALUES block of (system graph, own IRI) pairs`.

- [ ] **Step 3: Widen `sys_graph_iri` to accept an unsized argument**

`exists_many` holds `&dyn GraphName`, and `impl GraphName` implies `Sized`. In `src/resource.rs`, change:

```rust
pub fn sys_graph_iri(g: &impl GraphName) -> String {
```

to:

```rust
pub fn sys_graph_iri<G: GraphName + ?Sized>(g: &G) -> String {
```

The body is unchanged. This keeps the system-graph prefix in the one function the constraint names, instead of `exists_many` spelling it a second time in the same file.

- [ ] **Step 4: Implement `exists_many`**

Replace the `todo!()`:

```rust
pub async fn exists_many(
    store: &dyn SparqlStore,
    graphs: &[&dyn GraphName],
) -> Result<std::collections::HashSet<String>, ResourceError> {
    if graphs.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let mut values = String::new();
    for g in graphs {
        let iri = g.graph_iri();
        let sys = sys_graph_iri(*g);
        values.push_str(&format!("(<{sys}> <{iri}>) "));
    }
    let rows = store
        .query_solutions(&format!(
            "SELECT ?g WHERE {{ VALUES (?sys ?g) {{ {values} }} \
             GRAPH ?sys {{ ?g <{SYS_PRESENT}> true }} }}"
        ))
        .await?;
    Ok(rows
        .iter()
        .filter_map(|row| match row.get("g") {
            Some(oxigraph::model::Term::NamedNode(n)) => Some(n.as_str().to_owned()),
            _ => None,
        })
        .collect())
}
```

Duplicate inputs are harmless: the result is a set, and `VALUES` with a repeated row yields the same solution twice.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop --command cargo test --lib resource::tests::exists_many`

Expected: three PASSes.

- [ ] **Step 6: Run the whole suite and the constraint check**

Run: `nix develop --command cargo test && arch-check`

Expected: all tests pass; `arch-check` prints nothing. The system-graph rule is the one to watch — it is green only because the new `format!` uses `sys_graph_iri` rather than the literal prefix.

- [ ] **Step 7: Commit**

```bash
git add src/resource.rs
git commit -m "feat(resource): answer presence for a whole set in one query"
```

---

### Task 3: `prp::load_chain_acls`

**Files:**
- Modify: `src/wac/prp.rs` — the `load_chain_acls` body
- Test: `src/wac/prp.rs`, in its existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `resource::exists_many`'s output shape (`HashSet<String>` of graph IRIs), `SparqlStore::query_solutions`.
- Produces: `pub async fn load_chain_acls(store: &dyn SparqlStore, chain: &[ResourceUrl], present: &HashSet<String>) -> Result<HashMap<String, Vec<Triple>>, ResourceError>` — keyed by the **governed** IRI (the chain element's own graph IRI), not by the ACL's.

- [ ] **Step 1: Write the failing tests**

Add to `src/wac/prp.rs`'s test module:

```rust
use std::collections::{HashMap, HashSet};

/// The probe's answer for a chain, computed the honest way so these tests
/// exercise `load_chain_acls` rather than a hand-built fixture.
async fn probe(store: &OxigraphStore, chain: &[ResourceUrl]) -> HashSet<String> {
    let auxes: Vec<_> = chain.iter().map(|r| r.aux(AuxKind::Acl)).collect();
    let refs: Vec<&dyn crate::space::GraphName> =
        auxes.iter().map(|a| a as &dyn crate::space::GraphName).collect();
    crate::resource::exists_many(store, &refs).await.unwrap()
}

#[tokio::test]
async fn load_chain_acls_keys_by_governed_iri() {
    let store = OxigraphStore::in_memory().unwrap();
    write_acl(&store, "/box/", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    let chain = vec![res("/box/item"), res("/box/"), res("/")];
    let present = probe(&store, &chain).await;

    let acls = load_chain_acls(&store, &chain, &present).await.unwrap();
    assert_eq!(acls.len(), 1, "only /box/ has an ACL");
    let triples = acls.get("https://pod.toph.so/box/").expect("keyed by what it governs");
    assert!(triples.iter().any(|t| t.predicate.as_str() == ACL_MODE));
}

// The fixture that makes empty ACLs work: an ACL that exists but holds no
// triples is a policy ("nothing is granted here") and must appear in the map,
// or the guard walks past it to an ancestor grant it was written to override.
#[tokio::test]
async fn an_existing_but_empty_acl_gets_an_entry() {
    let store = OxigraphStore::in_memory().unwrap();
    write_acl(&store, "/locked/", "").await;
    let chain = vec![res("/locked/x"), res("/locked/"), res("/")];
    let present = probe(&store, &chain).await;

    let acls = load_chain_acls(&store, &chain, &present).await.unwrap();
    let triples = acls.get("https://pod.toph.so/locked/").expect("an empty ACL is still an ACL");
    assert!(triples.is_empty());
}

#[tokio::test]
async fn two_acls_in_one_chain_both_load() {
    let store = OxigraphStore::in_memory().unwrap();
    write_acl(&store, "/", &format!(
        "<#root> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    write_acl(&store, "/box/", &format!(
        "<#box> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    let chain = vec![res("/box/item"), res("/box/"), res("/")];
    let present = probe(&store, &chain).await;

    let acls = load_chain_acls(&store, &chain, &present).await.unwrap();
    assert_eq!(acls.len(), 2);
    assert!(acls.contains_key("https://pod.toph.so/"));
    assert!(acls.contains_key("https://pod.toph.so/box/"));
}

#[tokio::test]
async fn a_chain_with_no_acls_loads_nothing() {
    let store = OxigraphStore::in_memory().unwrap();
    let chain = vec![res("/foo")];
    let acls = load_chain_acls(&store, &chain, &HashSet::new()).await.unwrap();
    assert!(acls.is_empty());
}
```

`res` and `write_acl` already exist in this test module. `AuxKind` is already imported there.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop --command cargo test --lib wac::prp::tests`

Expected: four FAILs at `not yet implemented: design §5: one SELECT ?g ?s ?p ?o over the chain's existing ACL graphs`. The module's pre-existing tests still pass.

- [ ] **Step 3: Implement `load_chain_acls`**

Replace the `todo!()`:

```rust
pub async fn load_chain_acls(
    store: &dyn SparqlStore,
    chain: &[ResourceUrl],
    present: &std::collections::HashSet<String>,
) -> Result<std::collections::HashMap<String, Vec<Triple>>, ResourceError> {
    // ACL graph IRI -> the IRI of the resource it governs.
    let mut governed: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut values = String::new();
    for element in chain {
        let acl = element.aux(AuxKind::Acl);
        let acl_iri = acl.graph_iri();
        if !present.contains(acl_iri) {
            continue;
        }
        values.push_str(&format!("<{acl_iri}> "));
        governed.insert(acl_iri.to_owned(), element.graph_iri().to_owned());
    }
    // Seeded with an empty vector per existing ACL *before* the query: an ACL
    // that holds no triples yields no solutions, and it must still be found —
    // an empty ACL grants nothing, which is the opposite of falling through to
    // an ancestor.
    let mut out: std::collections::HashMap<String, Vec<Triple>> =
        governed.values().map(|g| (g.clone(), Vec::new())).collect();
    if governed.is_empty() {
        return Ok(out);
    }

    let rows = store
        .query_solutions(&format!(
            "SELECT ?g ?s ?p ?o WHERE {{ VALUES ?g {{ {values} }} \
             GRAPH ?g {{ ?s ?p ?o }} }}"
        ))
        .await?;
    for row in &rows {
        let (Some(oxigraph::model::Term::NamedNode(g)), Some(s), Some(p), Some(o)) =
            (row.get("g"), row.get("s"), row.get("p"), row.get("o"))
        else {
            continue;
        };
        let (Some(key), Ok(subject), oxigraph::model::Term::NamedNode(predicate)) = (
            governed.get(g.as_str()),
            oxigraph::model::Subject::try_from(s.clone()),
            p.clone(),
        ) else {
            continue;
        };
        out.entry(key.clone())
            .or_default()
            .push(Triple::new(subject, predicate, o.clone()));
    }
    Ok(out)
}
```

If `Subject::try_from(Term)` does not exist in this oxigraph version, match on the term instead — `Term::NamedNode(n) => Subject::NamedNode(n)`, `Term::BlankNode(b) => Subject::BlankNode(b)`, anything else `continue`. A literal in subject position cannot occur in a stored graph, so skipping it loses nothing.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop --command cargo test --lib wac::prp::tests`

Expected: all PASS — the four new ones and the module's eight existing ones.

- [ ] **Step 5: Commit**

```bash
git add src/wac/prp.rs
git commit -m "feat(wac): load a chain's ACLs in one query

Keyed by governed IRI and seeded with an empty vector per existing ACL,
so an ACL that holds no triples is still found — an empty ACL grants
nothing, which is the opposite of falling through to an ancestor."
```

---

### Task 4: `Guard::probe`, `authorize`, `existed`, `deny`

The decision core. `authorize_parent`, `authorize_aux` and `materialize` follow in Tasks 5 and 6 and keep their `todo!()` until then.

**Files:**
- Modify: `src/wac/guard.rs` — the `probe`, `authorize`, `existed` and `deny` bodies
- Test: `src/wac/guard.rs`, in its existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `resource::exists_many`, `prp::load_chain_acls`, `pdp::decide`, the free `deny`.
- Produces: a working `Guard::probe` / `Guard::authorize` / `Guard::existed` / `Guard::deny`, and a private `Guard::decide_from(&self, start: usize, required: Mode) -> Result<Decision, Response>` that Tasks 5 and 6 both build on.

- [ ] **Step 1: Write the failing tests**

Add to `src/wac/guard.rs`'s test module. These mirror the free-function tests already there, which must keep passing untouched:

```rust
/// Probe a guard for `path` as `agent`, panicking on a store failure.
async fn guard_for(store: &OxigraphStore, agent: Agent, path: &str) -> Guard<'_> {
    Guard::probe(store, agent, sp().resolve(path).unwrap()).await.expect("probe")
}

#[tokio::test]
async fn a_probed_guard_grants_what_the_free_function_grants() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/foo", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    let g = guard_for(&store, alice(), "/foo").await;
    assert!(g.authorize(Mode::Read).is_ok());
    assert_eq!(status(g.authorize(Mode::Write)), Some(StatusCode::FORBIDDEN));
}

#[tokio::test]
async fn a_guard_denies_an_anonymous_caller_with_a_challenge() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/foo", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    let g = guard_for(&store, Agent::Public, "/foo").await;
    let res = g.authorize(Mode::Read).expect_err("denied");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(res.headers().get(header::WWW_AUTHENTICATE).is_some());
    // `deny` is the same refusal, for the caller that has to make it itself.
    assert_eq!(g.deny().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_guard_inherits_from_the_nearest_ancestor_acl() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/box/", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    let g = guard_for(&store, alice(), "/box/item").await;
    assert!(g.authorize(Mode::Read).is_ok());
}

// The resource's own empty ACL wins over the ancestor grant it was written to
// override — the fixture that fails if the chain is searched in the wrong
// direction, or if an empty ACL is treated as an absent one.
#[tokio::test]
async fn a_guard_lets_an_own_empty_acl_win() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/", &format!(
        "<#root> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    seed_acl(&store, "/foo", "").await;
    let g = guard_for(&store, alice(), "/foo").await;
    assert_eq!(status(g.authorize(Mode::Read)), Some(StatusCode::FORBIDDEN));
}

// An auxiliary is decided against its subject and requires Control, whatever
// mode the caller names.
#[tokio::test]
async fn a_guard_requires_control_for_an_acl_target() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/foo", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    let g = guard_for(&store, alice(), "/.aux/foo.acl").await;
    assert_eq!(status(g.authorize(Mode::Read)), Some(StatusCode::FORBIDDEN));
}

#[tokio::test]
async fn existed_reports_the_pre_request_state() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/foo", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
         <{ACL_MODE}> <{ACL_READ}> ."
    )).await;
    assert!(guard_for(&store, alice(), "/foo").await.existed());
    assert!(!guard_for(&store, alice(), "/nothing").await.existed());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop --command cargo test --lib wac::guard::tests`

Expected: the six new tests FAIL at `not yet implemented: design §4: chain + ACLs + slash counterparts in one exists_many, then load_chain_acls`. The module's existing tests still pass.

- [ ] **Step 3: Implement `probe`**

```rust
pub async fn probe(
    store: &'a dyn SparqlStore,
    agent: Agent,
    target: Target,
) -> Result<Self, Response> {
    let subject: ResourceUrl = match &target {
        Target::Resource(r) => r.clone(),
        Target::Container(c) => c.as_resource().clone(),
        Target::Aux(a) => a.subject().clone(),
    };
    // Nearest first, ending at the root: the one chain this request touches
    // (design §3). `ResourceUrl::ancestors` is the only derivation of it.
    let mut chain = vec![subject.clone()];
    chain.extend(subject.ancestors().iter().map(|c| c.as_resource().clone()));

    // Everything anyone in this request may ask about, unconditionally —
    // a probe set that varied by method would be a second derivation of the
    // same table (design §4).
    let auxes: Vec<_> = chain
        .iter()
        .flat_map(|r| AuxKind::ALL.iter().map(move |k| r.aux(*k)))
        .collect();
    let counterparts: Vec<_> = chain.iter().filter_map(|r| r.slash_counterpart()).collect();
    let mut candidates: Vec<&dyn GraphName> = Vec::new();
    candidates.extend(chain.iter().map(|r| r as &dyn GraphName));
    candidates.extend(auxes.iter().map(|a| a as &dyn GraphName));
    candidates.extend(counterparts.iter().map(|r| r as &dyn GraphName));

    let present = resource::exists_many(store, &candidates)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    let acls = prp::load_chain_acls(store, &chain, &present)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

    Ok(Self { store, agent, target, chain, present, acls })
}
```

`resource` and `prp` are already imported in this module; add `space::GraphName` to the `use` block if it is not there.

- [ ] **Step 4: Implement the private decision helper, then `authorize`, `existed` and `deny`**

```rust
/// Decide `required` against the nearest ACL at or above `chain[start]`.
///
/// Nearest wins entirely: ancestor rules are never merged in, because
/// merging would make revoking access on a subtree impossible. `inherited`
/// is true for anything above `start`, which is what makes `acl:default`
/// apply rather than `acl:accessTo`.
fn decide_from(&self, start: usize, required: Mode) -> Result<Decision, Response> {
    let found = self.chain[start..]
        .iter()
        .enumerate()
        .find_map(|(offset, element)| {
            self.acls.get(element.graph_iri()).map(|t| (element, t, offset > 0))
        });
    let Some((element, triples, inherited)) = found else {
        return Err(deny(&self.agent)); // WAC has no implicit grant
    };
    let governed = element.graph_iri();
    let user = pdp::decide(triples, &self.agent, governed, inherited);
    let public = match self.agent {
        Agent::Public => user,
        Agent::WebId(_) => pdp::decide(triples, &Agent::Public, governed, inherited),
    };
    if user.allows(required) {
        Ok(Decision { user, public })
    } else {
        Err(deny(&self.agent))
    }
}

pub fn authorize(&self, mode: Mode) -> Result<Decision, Response> {
    let required = match &self.target {
        Target::Aux(a) => required_mode_for_aux(a.kind()),
        _ => mode,
    };
    self.decide_from(0, required)
}

pub fn existed(&self) -> bool {
    self.present.contains(self.target.graph_iri())
}

pub fn deny(&self) -> Response {
    deny(&self.agent)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop --command cargo test --lib wac::guard::tests`

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add src/wac/guard.rs
git commit -m "feat(wac): decide from the probe, without the store

authorize is synchronous and holds no store parameter, so a second
resolution of the same ACL is not something a later edit has to remember
not to write."
```

---

### Task 5: `authorize_parent` and `authorize_aux`

**Files:**
- Modify: `src/wac/guard.rs`
- Test: `src/wac/guard.rs` test module

**Interfaces:**
- Consumes: `Guard::decide_from` from Task 4.
- Produces: `authorize_parent(&self, Mode) -> Result<Option<Decision>, Response>` (`None` at the root) and `authorize_aux(&self, AuxKind) -> Result<Option<Decision>, Response>` (`None` when no such auxiliary exists).

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn authorize_parent_decides_one_level_up_and_is_none_at_the_root() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_container(&store, "/box/").await;
    seed_acl(&store, "/box/", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/> ; \
         <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; <{ACL_MODE}> <{ACL_WRITE}> ."
    )).await;
    let g = guard_for(&store, alice(), "/box/item").await;
    assert!(g.authorize_parent(Mode::Write).unwrap().is_some());

    let root = guard_for(&store, alice(), "/").await;
    assert!(root.authorize_parent(Mode::Write).unwrap().is_none(), "the root has no parent");
}

#[tokio::test]
async fn authorize_aux_is_none_when_the_auxiliary_does_not_exist() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/box/", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
         <{ACL_MODE}> <{ACL_CONTROL}> ."
    )).await;
    crate::resource::put_rdf(&store, &resource("/box/doc"), &[]).await.unwrap();
    let g = guard_for(&store, alice(), "/box/doc").await;
    assert!(g.authorize_aux(AuxKind::Acl).unwrap().is_none());
}

// Control on the subject is what an ACL auxiliary requires — Write is not
// enough, or a narrowing ACL could be erased by someone holding merely Write.
#[tokio::test]
async fn authorize_aux_requires_control_over_the_subject() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/box/", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
         <{ACL_MODE}> <{ACL_WRITE}> ."
    )).await;
    seed_acl(&store, "/box/doc", "").await;
    let g = guard_for(&store, alice(), "/box/doc").await;
    assert_eq!(status(g.authorize_aux(AuxKind::Acl)), Some(StatusCode::FORBIDDEN));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop --command cargo test --lib wac::guard::tests::authorize_`

Expected: three FAILs at `not yet implemented: design §5`.

- [ ] **Step 3: Implement both methods**

```rust
pub fn authorize_parent(&self, mode: Mode) -> Result<Option<Decision>, Response> {
    // chain[0] is the subject, so chain[1] is its parent — absent only at
    // the root, whose `ancestors()` is empty.
    if self.chain.len() < 2 {
        return Ok(None);
    }
    self.decide_from(1, mode).map(Some)
}

pub fn authorize_aux(&self, kind: AuxKind) -> Result<Option<Decision>, Response> {
    let aux = self.chain[0].aux(kind);
    if !self.present.contains(aux.graph_iri()) {
        return Ok(None); // nothing there to authorize
    }
    // An auxiliary is decided against its subject, which is chain[0].
    self.decide_from(0, required_mode_for_aux(kind)).map(Some)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop --command cargo test --lib wac::guard::tests`

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wac/guard.rs
git commit -m "feat(wac): the two derived targets a handler may ask about"
```

---

### Task 6: `Guard::materialize`

**Files:**
- Modify: `src/wac/guard.rs`
- Test: `src/wac/guard.rs` test module

**Interfaces:**
- Consumes: `Guard::decide_from`, `self.present`, `container::ensure_container`, `container::add_containment`.
- Produces: `async fn materialize(self) -> Result<(), Response>`.

**A correction to be aware of.** An earlier draft of the skeleton had this return a `Created { target_existed }`, on the belief that `put_impl` chose `201` over `204` from it. It does not — `created()` (`src/http.rs:405`) answers `201` unconditionally — so the type had no consumer and was removed before this task was dispatched. `existed()` from Task 4 remains, and `POST` in Task 8 is its consumer.

Read the doc comment on the existing `authorize_and_materialize` before starting. The logic below is that function with two substitutions — `resource::exists(store, x)` becomes `self.present.contains(x.graph_iri())`, and `authorize(store, agent, Target::Container(a), Append)` becomes `self.decide_from(i + 1, Mode::Append)` — and no change at all to the order in which it decides, checks and writes.

- [ ] **Step 1: Write the failing tests**

```rust
// An existing target gains no containment triple — its parent already records
// it — so materializing over one must not demand Append at the level above.
// This is the "you may edit this file" grant, where an agent holds Write on
// one document and nothing on the container around it.
#[tokio::test]
async fn materializing_over_an_existing_target_needs_nothing_above_it() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_container(&store, "/box/").await;
    crate::resource::put_rdf(&store, &resource("/box/doc"), &[]).await.unwrap();
    seed_acl(&store, "/box/doc", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/doc> ; \
         <{ACL_MODE}> <{ACL_WRITE}> ."
    )).await;
    let g = guard_for(&store, alice(), "/box/doc").await;
    assert!(g.materialize().await.is_ok(), "an overwrite adds no containment");
}

#[tokio::test]
async fn a_guarded_deep_create_materializes_and_links_the_whole_chain() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
         <{ACL_DEFAULT}> <https://pod.toph.so/> ; <{ACL_MODE}> <{ACL_WRITE}> ."
    )).await;
    guard_for(&store, alice(), "/a/b/c").await.materialize().await.unwrap();

    for path in ["/a/b/", "/a/", "/"] {
        assert!(resource::exists(&store, &container(path)).await.unwrap(), "{path} must exist");
    }
    assert!(contains(&store, &container("/a/b/"), "https://pod.toph.so/a/b/c").await);
}

#[tokio::test]
async fn a_guarded_walk_writes_nothing_when_a_level_denies() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/box/", &format!(
        "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
         <{ACL_MODE}> <{ACL_WRITE}> ."
    )).await;
    let g = guard_for(&store, bob(), "/box/sub/file").await;
    assert!(g.materialize().await.is_err(), "creating /box/sub/ mutates /box/");
    assert!(!resource::exists(&store, &container("/box/sub/")).await.unwrap(),
        "nothing may be materialized when the walk denies");
}

#[tokio::test]
async fn a_guarded_walk_stops_at_the_first_existing_ancestor() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_container(&store, "/inbox/").await;
    seed_acl(&store, "/inbox/", &format!(
        "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/inbox/> ; \
         <{ACL_MODE}> <{ACL_APPEND}> ."
    )).await;
    guard_for(&store, bob(), "/inbox/note").await.materialize().await.unwrap();
    assert!(contains(&store, &container("/inbox/"), "https://pod.toph.so/inbox/note").await);
    assert!(!resource::exists(&store, &container("/")).await.unwrap(),
        "the walk must never touch the root");
}

#[tokio::test]
async fn a_guarded_write_refuses_the_other_half_of_a_slash_pair() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
         <{ACL_DEFAULT}> <https://pod.toph.so/> ; <{ACL_MODE}> <{ACL_WRITE}> ."
    )).await;
    crate::resource::put_rdf(&store, &resource("/box"), &[]).await.unwrap();
    let g = guard_for(&store, alice(), "/box/").await;
    assert_eq!(status(g.materialize().await), Some(StatusCode::CONFLICT));
}

#[tokio::test]
async fn a_guarded_aux_write_still_needs_its_subject_to_exist() {
    let store = OxigraphStore::in_memory().unwrap();
    seed_acl(&store, "/", &format!(
        "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
         <{ACL_DEFAULT}> <https://pod.toph.so/> ; <{ACL_MODE}> <{ACL_CONTROL}> ."
    )).await;
    let g = guard_for(&store, alice(), "/.aux/ghost.acl").await;
    assert_eq!(status(g.materialize().await), Some(StatusCode::NOT_FOUND));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop --command cargo test --lib wac::guard::tests`

Expected: six FAILs at `not yet implemented: design §6`.

- [ ] **Step 3: Implement `materialize`**

```rust
pub async fn materialize(self) -> Result<(), Response> {
    let subject = &self.chain[0];
    let target_existed = self.existed();
    let may_be_member = !matches!(self.target, Target::Aux(_));
    // An auxiliary is never a container member, and neither is a target that
    // already exists: re-inserting the containment triple changes nothing, so
    // demanding Append for it would refuse the ordinary "you may edit this
    // file" grant.
    let is_member = may_be_member && !target_existed;

    let mut creations: Vec<&ResourceUrl> = Vec::new();
    if is_member {
        creations.push(subject);
    }
    let mut child_iri = self.target.graph_iri().to_string();
    let mut record_child = is_member;
    let mut plan: Vec<(ContainerUrl, Option<String>)> = Vec::new();
    for (i, ancestor) in subject.ancestors().into_iter().enumerate() {
        let existed = self.present.contains(ancestor.graph_iri());
        if existed && !record_child {
            break; // nothing observable changes at or above this level
        }
        self.decide_from(i + 1, Mode::Append)?;
        plan.push((ancestor.clone(), record_child.then(|| child_iri.clone())));
        if existed {
            break;
        }
        creations.push(&self.chain[i + 1]);
        child_iri = ancestor.graph_iri().to_string();
        record_child = true;
    }

    // Every ancestor is authorized by here, so a missing subject may finally
    // be reported — before the plan below materializes anything for a write
    // that could never succeed.
    if matches!(self.target, Target::Aux(_)) && !self.present.contains(subject.graph_iri()) {
        return Err((StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response());
    }

    // Protocol §3.1, over everything this write would create. Deliberately
    // after the whole chain is authorized: a caller about to be refused for an
    // ancestor must be refused without learning what else exists.
    for created in &creations {
        if let Some(counterpart) = created.slash_counterpart() {
            if self.present.contains(counterpart.graph_iri()) {
                return Err((StatusCode::CONFLICT, SLASH_PAIR_MESSAGE).into_response());
            }
        }
    }

    for (ancestor, child_iri) in plan {
        container::ensure_container(self.store, &ancestor)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        if let Some(child_iri) = child_iri {
            container::add_containment(self.store, &ancestor, &child_iri)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        }
    }
    Ok(())
}
```

`self.chain[i + 1]` and `ancestor` name the same container — the chain is the subject followed by its ancestors in the same order — so the index arithmetic is not an assumption but the chain's construction in `probe`. If a bounds panic appears in testing, that invariant is what broke; fix `probe`, not this loop.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop --command cargo test --lib wac::guard::tests`

Expected: all PASS, including the pre-existing free-function tests.

- [ ] **Step 5: Commit**

```bash
git add src/wac/guard.rs
git commit -m "feat(wac): materialize from the probe and consume the guard

Taking self makes the stale window uninhabitable rather than commented:
the probe describes the store before these writes, and after this
returns there is no guard left to read a stale answer from."
```

---

### Task 7: Migrate the read paths and `PATCH`

From here the crate has two working implementations. They coexist until Task 9 removes the old one, so every step in Tasks 7 and 8 leaves the suite green.

**Files:**
- Modify: `src/http.rs` — lines `565`, `600`, `1569`, `1691`, `1908`
- Test: `src/http.rs` test module (existing tests are the check; no new ones needed)

**Interfaces:**
- Consumes: `Guard::probe`, `Guard::authorize`, `Guard::deny`.
- Produces: nothing new.

- [ ] **Step 1: Migrate the two `GET`/`HEAD` sites**

At `src/http.rs:1569` and `src/http.rs:1691`, replace

```rust
if let Err(res) = authorize(store, &agent, &target, Mode::Read).await {
```

with

```rust
let guard = match Guard::probe(store, agent, target.clone()).await {
    Ok(g) => g,
    Err(res) => return res,
};
if let Err(res) = guard.authorize(Mode::Read) {
```

and likewise for the `let decision = match authorize(...)` form at line `1691`, which becomes `match guard.authorize(Mode::Read)`. Add `Guard` to the module's `use crate::wac::…` block.

`target.clone()` is needed because the handlers keep using `target` after this point (for `with_aux_links`, content negotiation and the response). `Target` is `Clone`.

- [ ] **Step 2: Run the tests**

Run: `nix develop --command cargo test --lib http::tests`

Expected: all PASS. Any failure here is a behaviour change, not a refactor — stop and diagnose rather than adjusting the test.

- [ ] **Step 3: Migrate `PATCH` (lines 565 and 600)**

Line 565's `authorize(store, &agent, &target, Mode::Append)` becomes `guard.authorize(Mode::Append)` against a guard probed at the top of the handler. Line 600's `deny(&agent)` becomes `guard.deny()` — the agent now lives in the guard, which is why `Guard::deny` exists.

- [ ] **Step 4: Migrate the `DELETE` authorization at line 1908**

```rust
let guard = match Guard::probe(store, agent, target.clone()).await {
    Ok(g) => g,
    Err(res) => return res,
};
if let Err(res) = guard.authorize(Mode::Write) {
    return with_aux_links(res, &target);
}
```

Leave the parent and auxiliary checks (lines 1928 and 1950) alone for now — they are Task 8.

- [ ] **Step 5: Run the whole suite and the budgets**

Run: `nix develop --command cargo test`

Expected: all PASS. The budget tests still pass because the budgets are upper bounds and the counts have only gone down.

- [ ] **Step 6: Commit**

```bash
git add src/http.rs
git commit -m "refactor(http): read paths and PATCH decide through the guard"
```

---

### Task 8: Migrate the write paths

**Files:**
- Modify: `src/http.rs` — lines `710`, `1093`, `1115`, `1231`, `1340`, `1382`, `1434`, `1928`, `1950`
- Test: `src/http.rs` test module

**Interfaces:**
- Consumes: `Guard::probe`, `authorize`, `authorize_parent`, `authorize_aux`, `existed`, `materialize`.
- Produces: nothing new.

- [ ] **Step 1: Migrate `put_impl` (lines 1093, 1115) and drop its second read**

Probe once at the top, authorize `Write`, and take the created/updated distinction from `materialize`:

```rust
let guard = match Guard::probe(store, agent, target.clone()).await {
    Ok(g) => g,
    Err(res) => return res,
};
if let Err(res) = guard.authorize(Mode::Write) {
    return with_aux_links(res, &target);
}
```

At the site where the walk runs (line 1117 in the blob branch and its RDF counterpart), replace `authorize_and_materialize(store, &agent, &target).await` with `guard.materialize().await`:

```rust
if let Err(res) = guard.materialize().await {
    return with_aux_links(res, &target);
}
```

**Change no status code.** `created()` answers `201` unconditionally today and must still answer `201` unconditionally after this task; whether that is right is design §10's explicitly out-of-scope question. This task is a refactor whose entire claim is that behaviour is unchanged, and a `204` appearing here would falsify it.

Note the borrow: `guard.materialize()` consumes the guard, so anything a branch still wants from `guard.existed()` must be read **before** it. If the compiler objects, that is the design working — move the read up, do not clone the guard.

- [ ] **Step 2: Run the tests**

Run: `nix develop --command cargo test --lib http::tests`

Expected: all PASS — unchanged, since no status code changes in this step.

- [ ] **Step 3: Migrate `post_impl` (lines 1340, 1382, 1434) to two guards**

Per design §3, `POST` builds two guards and must:

```rust
// Guard 1: the container, authorized before the child's name is minted, so
// nothing — not even the name-collision check — answers ahead of the guard.
let parent_guard = match Guard::probe(store, agent.clone(), target.clone()).await {
    Ok(g) => g,
    Err(res) => return res,
};
if let Err(res) = parent_guard.authorize(Mode::Append) {
    return with_aux_links(res, &target);
}
```

Then, after `child` is settled by `container::child_name`, replace the `name_is_taken(store, &child).await` call with a probe of the child and a read of `existed()`:

```rust
let mut child_guard = match Guard::probe(store, agent.clone(), child.clone()).await {
    Ok(g) => g,
    Err(res) => return res,
};
if child_guard.existed() {
    let unique = format!("{name}-{}{suffix}", uuid::Uuid::new_v4());
    child = match classify(&st.space, &format!("{}{unique}", parent.path())) {
        Ok(t) => t,
        Err(status) => return status.into_response(),
    };
    child_guard = match Guard::probe(store, agent.clone(), child.clone()).await {
        Ok(g) => g,
        Err(res) => return res,
    };
}
if let Err(res) = child_guard.authorize(Mode::Append) {
    return with_aux_links(res, &child);
}
```

and at line 1434, `authorize_and_materialize(store, &agent, &child).await` becomes `child_guard.materialize().await`.

`Agent` must be `Clone` for this; it is an enum of `Public` and `WebId(String)`. If it is not, derive `Clone` on it — that is a one-line change with no other consequence.

`name_is_taken` now has no callers. Leave it; Task 9 removes it with the rest.

- [ ] **Step 4: Run the tests**

Run: `nix develop --command cargo test --lib http::tests`

Expected: all PASS, in particular the `Slug` collision tests.

- [ ] **Step 5: Migrate the remaining three sites**

- Line `710` (`authorize_and_materialize` in the aux `PUT` path) → probe, authorize, `materialize`.
- Line `1231` (same, in its handler) → the same shape.
- Lines `1928` and `1950` in `delete_impl` → `guard.authorize_parent(Mode::Write)?` and, in the `AuxKind::ALL` loop, `guard.authorize_aux(*kind)?`. The loop's `exists(store, &aux)` call goes away: `authorize_aux` returns `Ok(None)` for an auxiliary that is not there, which is exactly the `Ok(false)` arm.

- [ ] **Step 6: Run everything**

Run: `nix develop --command cargo test && arch-check`

Expected: all tests pass, no `arch-check` output.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs
git commit -m "refactor(http): write paths decide through the guard

POST's child probe absorbs name_is_taken, and delete_impl drops its
per-auxiliary existence read. No status code changes."
```

---

### Task 9: Remove the old path, tighten the budgets, pin the rule

**Files:**
- Modify: `src/wac/guard.rs` (delete the free `authorize`, `authorize_and_materialize`, `refuse_slash_pair`)
- Modify: `src/wac/prp.rs` (delete `effective_acl` and `EffectiveAcl` if nothing uses them)
- Modify: `src/http.rs` (delete `name_is_taken`)
- Modify: `tests/call_budget.rs` (lower every constant)
- Modify: `docs/constraints.md` (one new rule)

**Interfaces:**
- Consumes: everything above.
- Produces: the final public surface — exactly what the skeleton declared, minus the free functions it replaced.

- [ ] **Step 1: Find what is now unused**

Run: `nix develop --command cargo build 2>&1 | grep -A 3 "never used"`

Expected: warnings naming `authorize`, `authorize_and_materialize`, `refuse_slash_pair`, `name_is_taken`, and possibly `effective_acl` / `EffectiveAcl`. The free `deny` stays — `Guard::deny` calls it.

- [ ] **Step 2: Delete them, and their tests that tested the free functions specifically**

Delete each function reported above. In `src/wac/guard.rs`'s test module, the older tests that call the free `authorize` / `authorize_and_materialize` go with them — their guard-based counterparts from Tasks 4, 5 and 6 already cover the same properties, and the ordering tests named in design §7 (`a_guarded_walk_writes_nothing_when_a_level_denies`, `a_guarded_write_refuses_the_other_half_of_a_slash_pair`) must remain.

Do **not** delete `prp`'s tests wholesale — `load_chain_acls` has its own from Task 3, and the module's other tests belong to whatever survives.

- [ ] **Step 3: Run everything**

Run: `nix develop --command cargo test`

Expected: all PASS.

- [ ] **Step 4: Re-measure and tighten every budget**

Temporarily raise nothing; just run with output:

Run: `nix develop --command cargo test --test call_budget -- --nocapture`

Expected: six PASSes, each printing a `total=` **lower** than its constant. Set each constant to the newly printed value. Design §5's claim is that authorization now costs two queries; `PUT_DEEP_BUDGET` is where that shows most.

Run again: `nix develop --command cargo test --test call_budget`

Expected: six PASSes against the tightened constants.

- [ ] **Step 5: Demonstrate the new constraint goes red before adding it**

Add a temporary store parameter to `Guard::authorize` — `pub fn authorize(&self, _store: &dyn SparqlStore, mode: Mode)` — and run:

Run: `[ "$(rg -o 'dyn SparqlStore' src/wac/guard.rs | wc -l)" = 2 ]; echo $?`

Expected: `1` — the check fails, which is the point. Revert the temporary parameter and run it again.

Expected: `0`.

A rule that cannot fail is worse than no rule; this file has already shipped a test that held trivially, which is why this step is not optional.

- [ ] **Step 6: Add the rule to `docs/constraints.md`**

Under the WAC section (or a new one if none exists), following the file's format exactly — rule, indented reasoning, indented `check:`:

```
The guard names the store exactly twice: the field it holds and the probe that fills it.
    → 2026-07-31-request-scoped-guard-design.md §5, §9. The decision methods are
    synchronous and hold no store, so a second resolution of the same ACL — which
    would repeat the ancestor walk and could straddle a concurrent write — is not
    something a later edit has to remember not to write. Restoring a store parameter
    to any of the three makes this three. Anchored on the declaration rather than on
    a regex over one signature, so it cannot be satisfied by a method spelled
    differently.
    check: [ "$(rg -o 'dyn SparqlStore' src/wac/guard.rs | wc -l)" = 2 ]
```

- [ ] **Step 7: Verify every rule**

Run: `arch-check`

Expected: no output, and `arch-check --json | jq '.checked'` reports `23`.

- [ ] **Step 8: Correct the clause the design supersedes**

Design §11 records one delta against a document already in force, and it has to be applied rather than merely noted. In `docs/superpowers/specs/2026-07-26-wac-enforcement-design.md` around line 208, the sentence reading

> The exists-vs-new distinction for PUT requires one store lookup. It runs **after** …

is no longer true: it requires none, because the probe already holds the answer. Rewrite the sentence in place, present tense, keeping the ordering requirement it was protecting and pointing at where that requirement now lives:

> The exists-vs-new distinction for PUT costs no lookup of its own — the request's probe already
> holds it (`2026-07-31-request-scoped-guard-design.md` §6). The ordering it protected is
> unchanged and restated there as §7: no refusal that reads a probed fact is produced before
> `authorize` has returned.

Do not delete the surrounding paragraph; only the claim about the lookup has changed.

- [ ] **Step 9: Run the conformance harness as a regression check**

Run: `conformance/run.sh` (read `conformance/README.md` first for the environment it needs)

Expected: no new failures against the last recorded run. This is a regression check, not evidence for the feature — the suite asserts protocol behaviour, and this change asserts none.

- [ ] **Step 10: Commit**

```bash
git add src/wac/guard.rs src/wac/prp.rs src/http.rs tests/call_budget.rs docs/constraints.md
git commit -m "refactor(wac): retire the per-level ancestor re-walk

The free authorize/authorize_and_materialize and prp::effective_acl have
no callers left. Budgets tightened to the measured counts, and the rule
that keeps the decision store-free goes in with the check that was shown
red against a restored store parameter."
```

---

## Notes for whoever executes this

**Where the design is likely to fight back.** Task 8's `POST` migration is the one with real thinking in it — two guards, a re-probe on collision, and an ordering that exists to avoid an oracle. If something has to give there, re-read design §3's `POST` paragraph before changing the order.

**What must not be "fixed" along the way.** The ordering of refusals in `materialize` (design §7): the slash-pair `409` and the aux-subject `404` come after the whole chain is authorized, and the tests that pin that must pass unchanged. If one of them only passes after being rewritten, that is the failure mode the design names, not a test that needed updating.

**What is deliberately left alone.** Prepared statements, any cache outliving a request, and `ensure_container` / `add_containment` being two updates where one `;`-sequence would do. All three are design §10, and the last is worth an issue.
