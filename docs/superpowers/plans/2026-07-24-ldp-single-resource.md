# SPARQL Solid Pod — Plan 2: Single-Resource LDP (dyn store, conneg, DELETE, conditional)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the *single RDF resource* LDP lifecycle: a runtime-swappable store behind `Arc<dyn SparqlStore>`, content negotiation across the Solid-mandated formats (Turtle + JSON-LD, plus N-Triples), `DELETE`, and conditional requests (ETag / `If-Match` / `If-None-Match`).

**Architecture:** Reshape `SparqlStore` to be object-safe (via `async-trait`) and return **structured triples** (`Vec<oxigraph::model::Triple>`) instead of pre-serialized Turtle, so the HTTP edge can serialize to any format. A new `src/rdf.rs` centralizes format negotiation + parse/serialize using `oxigraph::io` (`oxrdfio`, which now supports JSON-LD via `oxjsonld` — no `rdf_dynsyn`/sophia bridge needed). `resource.rs` works in triples; `http.rs` negotiates format, adds DELETE and conditional handling.

**Tech Stack:** Rust, `oxigraph` 0.5 (`oxigraph::io` for Turtle/JSON-LD/N-Triples, `oxigraph::model::Triple`), `axum` 0.8, `async-trait`, `sha2` (stable content-hash ETag). Build only via the flake dev shell.

**Builds on:** Plan 1 (merged to `main`): `space::StorageSpace`, `store::{SparqlStore, OxigraphStore}`, `resource::{put_rdf, get_rdf}`, `http::{AppState, router}`. Design spec: `docs/superpowers/specs/2026-07-24-sparql-solid-pod-design.md`.

## Global Constraints

- **Build/test ONLY via the flake dev shell.** Bare `cargo` fails (oxigraph → RocksDB → libclang). Every command: `nix develop -c cargo test` / `nix develop -c cargo build` / `nix develop -c cargo clippy --all-targets`. Output must be pristine (zero warnings), clippy clean.
- **Latest dependency versions.** Add deps with `cargo add <crate>` (no pinned version).
- **URL = identity from config, never the socket.** Graph IRIs come from `StorageSpace::graph_iri` (already validated — returns `Result`, rejects IRI-breaking input with `SpaceError::InvalidResourceIri`). (Spec §5, §10)
- **Strict RDF 1.1 on the wire.** Solid mandates Turtle + JSON-LD; we also offer N-Triples. No RDF-star. (Spec §5)
- **Store access only via SPARQL 1.1 query/update strings**, no Oxigraph-proprietary mutation APIs, no deprecated APIs, no `#[allow(...)]`. `Store::query` is deprecated → use `SparqlEvaluator`; `Store::update` is fine. (Spec §4)
- **RDF resources are triple-preserving, not byte-preserving.** Tests assert triple content / cross-format round-trips, never byte equality. (Spec §5)
- **Runtime backend swap.** `AppState` holds `Arc<dyn SparqlStore>`; nothing downstream names a concrete store type. (Spec success-criterion #4; resolves final-review finding I3)
- Conventional commits. TDD: failing test first, minimal impl, commit per task.

**Execution grouping (IMPORTANT):** Tasks 1–3 are a single coupled refactor — changing the store's return type and `resource.rs` signatures necessarily breaks `http.rs` until all three are done. **Implement Tasks 1–3 as ONE deliverable: one implementer dispatch, ONE commit (at the end of Task 3), ONE review.** The whole crate is only green after Task 3. Do NOT commit after Task 1 or Task 2 (their "run tests" steps target the module under change; the whole-crate `cargo test` only passes after Task 3). Tasks 4 (DELETE) and 5 (ETag) are separate deliverables with their own commits/reviews.

**Known oxigraph 0.5.9 API (from Plan 1):**
- Query: `SparqlEvaluator::new().parse_query(sparql)?.on_store(&self.inner).execute()?` → `QueryResults::Graph(iter of Result<Triple,_>)`.
- Serialize: `oxigraph::io::RdfSerializer::from_format(fmt).for_writer(Vec::new())`, `.serialize_triple(&t)` per triple, `.finish() -> io::Result<W>`.
- Parse: `oxigraph::io::RdfParser::from_format(fmt).with_base_iri(base)?.for_slice(bytes)` → iterator of `Result<Quad, RdfSyntaxError>` (Turtle's graph term is always default).
- `RdfFormat` variants include `Turtle`, `NTriples`, `JsonLd { profile }` (via `oxjsonld`). For `JsonLd`, construct with a default profile — confirm the exact `JsonLdProfileSet::default()` / `RdfFormat::JsonLd { profile: JsonLdProfileSet::empty() }` constructor against docs.rs/oxrdfio/0.2.5.

---

### Task 1: Object-safe `SparqlStore` returning structured triples

Resolves final-review finding I3 (runtime backend swap) and M-b (store returned pre-serialized Turtle). This is a refactor: keep behavior, change the seam.

**Files:**
- Modify: `src/store.rs` (trait + impl), `Cargo.toml` (add `async-trait`)
- Test: inline `#[cfg(test)]` in `src/store.rs` (update existing 2 tests)

**Interfaces:**
- Produces:
  - `#[async_trait::async_trait] pub trait SparqlStore: Send + Sync` with:
    - `async fn update(&self, sparql: &str) -> Result<(), StoreError>`
    - `async fn query_triples(&self, sparql: &str) -> Result<Vec<oxigraph::model::Triple>, StoreError>` — executes a CONSTRUCT/DESCRIBE and returns the triples (empty vec if none). **Replaces** `query_construct` (which returned Turtle `String`).
  - `OxigraphStore` unchanged in construction (`in_memory()`), impl updated.
- Consumes: nothing new from other tasks.

- [ ] **Step 1: Add `async-trait`**

Run: `nix develop -c cargo add async-trait`

- [ ] **Step 2: Update the two existing store tests to the new signature**

Replace the body of the `#[cfg(test)] mod tests` in `src/store.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn update_then_query_triples_roundtrips() {
        let store = OxigraphStore::in_memory().unwrap();
        store.update(
            "INSERT DATA { GRAPH <https://pod.toph.so/foo> { \
             <https://pod.toph.so/foo#it> <http://schema.org/name> \"Toph\" } }",
        ).await.unwrap();

        let triples = store.query_triples(
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <https://pod.toph.so/foo> { ?s ?p ?o } }",
        ).await.unwrap();

        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].predicate.as_str(), "http://schema.org/name");
    }

    #[tokio::test]
    async fn query_of_absent_graph_is_empty() {
        let store = OxigraphStore::in_memory().unwrap();
        let triples = store.query_triples(
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <https://pod.toph.so/missing> { ?s ?p ?o } }",
        ).await.unwrap();
        assert!(triples.is_empty());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `nix develop -c cargo test store::`
Expected: FAIL — `query_triples` not defined / signature mismatch.

- [ ] **Step 4: Rewrite the trait and impl**

```rust
// src/store.rs — replace the trait + impl (keep StoreError as-is)
use oxigraph::model::Triple;
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::Store;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store backend error: {0}")]
    Backend(String),
}

#[async_trait::async_trait]
pub trait SparqlStore: Send + Sync {
    async fn update(&self, sparql: &str) -> Result<(), StoreError>;
    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError>;
}

pub struct OxigraphStore {
    inner: Store,
}

impl OxigraphStore {
    pub fn in_memory() -> Result<Self, StoreError> {
        Store::new().map(|inner| Self { inner }).map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[async_trait::async_trait]
impl SparqlStore for OxigraphStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        self.inner.update(sparql).map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError> {
        let results = SparqlEvaluator::new()
            .parse_query(sparql).map_err(|e| StoreError::Backend(e.to_string()))?
            .on_store(&self.inner)
            .execute().map_err(|e| StoreError::Backend(e.to_string()))?;
        let QueryResults::Graph(triples) = results else {
            return Err(StoreError::Backend("expected CONSTRUCT/graph results".into()));
        };
        triples
            .map(|t| t.map_err(|e| StoreError::Backend(e.to_string())))
            .collect()
    }
}
```

- [ ] **Step 5: Run the store tests (do NOT commit yet — continue to Task 2)**

Run: `nix develop -c cargo test store::` → PASS (2). A whole-crate `cargo build` WILL fail now (`resource.rs`/`http.rs` still call the removed `query_construct`) — that is expected; Tasks 2–3 restore it. **No commit here** — this refactor commits once, at the end of Task 3.

---

### Task 2: `src/rdf.rs` — format negotiation + parse/serialize; `resource.rs` works in triples

**Files:**
- Create: `src/rdf.rs`
- Modify: `src/lib.rs` (add `pub mod rdf;`), `src/resource.rs` (use triples + `rdf::serialize`/`parse`)
- Test: inline `#[cfg(test)]` in `src/rdf.rs`

**Interfaces:**
- Produces (in `src/rdf.rs`):
  - `pub enum RdfError { Parse(String), Serialize(String), UnsupportedType }` (`Debug`, `thiserror::Error`).
  - `pub fn format_for_content_type(ct: &str) -> Option<RdfFormat>` — maps a `Content-Type` (ignoring `; params`) to an `RdfFormat`. `text/turtle`→Turtle, `application/ld+json`→JsonLd(default profile), `application/n-triples`→NTriples. Else `None`.
  - `pub fn format_for_accept(accept: &str) -> Option<RdfFormat>` — picks a supported format from an `Accept` header (comma-separated, ignore q-values for v1, first supported match wins; `*/*` or empty ⇒ Turtle). `None` only if the header lists media types and none are supported (→ caller returns 406).
  - `pub fn parse(bytes: &[u8], fmt: RdfFormat, base_iri: &str) -> Result<Vec<Triple>, RdfError>`.
  - `pub fn serialize(triples: &[Triple], fmt: RdfFormat) -> Result<Vec<u8>, RdfError>`.
- Consumes: `oxigraph::model::Triple`, `oxigraph::io::{RdfFormat, RdfParser, RdfSerializer}`.
- Changes `resource.rs`:
  - `pub async fn put_rdf(store: &dyn SparqlStore, space: &StorageSpace, request_path: &str, triples: &[Triple]) -> Result<(), ResourceError>` — builds the atomic `DROP SILENT GRAPH <g>; INSERT DATA { GRAPH <g> { …triples via Display… } }` from the already-parsed triples (parsing now happens at the HTTP edge).
  - `pub async fn get_rdf(store: &dyn SparqlStore, space: &StorageSpace, request_path: &str) -> Result<Option<Vec<Triple>>, ResourceError>` — `None` if the graph is empty.
  - `ResourceError` gains `#[error(transparent)] Rdf(#[from] RdfError)` if needed; keeps `InvalidIri`, `Store`.

- [ ] **Step 1: Write failing tests in `src/rdf.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use oxigraph::model::{Triple, NamedNode, Literal};

    fn sample() -> Vec<Triple> {
        vec![Triple::new(
            NamedNode::new("https://pod.toph.so/foo#it").unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("Toph"),
        )]
    }

    #[test]
    fn content_type_mapping() {
        assert!(format_for_content_type("text/turtle").is_some());
        assert!(format_for_content_type("text/turtle; charset=utf-8").is_some());
        assert!(format_for_content_type("application/ld+json").is_some());
        assert!(format_for_content_type("application/n-triples").is_some());
        assert!(format_for_content_type("application/json").is_none());
    }

    #[test]
    fn accept_defaults_to_turtle_and_picks_supported() {
        assert!(format_for_accept("*/*").is_some());
        assert!(format_for_accept("").is_some());
        assert!(format_for_accept("application/ld+json").is_some());
        assert!(format_for_accept("application/xhtml+xml, application/ld+json").is_some());
        assert!(format_for_accept("image/png").is_none());
    }

    #[test]
    fn turtle_to_jsonld_roundtrip_preserves_triples() {
        let ttl = serialize(&sample(), format_for_content_type("text/turtle").unwrap()).unwrap();
        let via_ttl = parse(&ttl, format_for_content_type("text/turtle").unwrap(), "https://pod.toph.so/foo").unwrap();
        let jsonld = serialize(&via_ttl, format_for_content_type("application/ld+json").unwrap()).unwrap();
        let via_json = parse(&jsonld, format_for_content_type("application/ld+json").unwrap(), "https://pod.toph.so/foo").unwrap();
        assert_eq!(via_json.len(), 1);
        assert_eq!(via_json[0].predicate.as_str(), "http://schema.org/name");
        assert!(String::from_utf8_lossy(&jsonld).contains("schema.org/name"));
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `nix develop -c cargo test rdf::`
Expected: FAIL — module/functions not defined.

- [ ] **Step 3: Implement `src/rdf.rs`**

```rust
use oxigraph::io::{RdfFormat, RdfParser, RdfSerializer};
use oxigraph::model::Triple;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RdfError {
    #[error("rdf parse error: {0}")]
    Parse(String),
    #[error("rdf serialize error: {0}")]
    Serialize(String),
    #[error("unsupported media type")]
    UnsupportedType,
}

fn turtle() -> RdfFormat { RdfFormat::Turtle }
fn ntriples() -> RdfFormat { RdfFormat::NTriples }
// Confirm the exact JsonLd constructor against docs.rs/oxrdfio/0.2.5:
// RdfFormat::JsonLd { profile: <default/empty set> }.
fn jsonld() -> RdfFormat {
    RdfFormat::JsonLd { profile: oxigraph::io::JsonLdProfileSet::empty() }
}

fn media_type(ct: &str) -> &str { ct.split(';').next().unwrap_or("").trim() }

pub fn format_for_content_type(ct: &str) -> Option<RdfFormat> {
    match media_type(ct) {
        "text/turtle" => Some(turtle()),
        "application/ld+json" => Some(jsonld()),
        "application/n-triples" => Some(ntriples()),
        _ => None,
    }
}

pub fn format_for_accept(accept: &str) -> Option<RdfFormat> {
    let a = accept.trim();
    if a.is_empty() { return Some(turtle()); }
    let mut saw_type = false;
    for part in a.split(',') {
        let mt = media_type(part);
        if mt == "*/*" || mt == "text/*" { return Some(turtle()); }
        saw_type = true;
        if let Some(f) = format_for_content_type(mt) { return Some(f); }
    }
    if saw_type { None } else { Some(turtle()) }
}

pub fn parse(bytes: &[u8], fmt: RdfFormat, base_iri: &str) -> Result<Vec<Triple>, RdfError> {
    let parser = RdfParser::from_format(fmt)
        .with_base_iri(base_iri).map_err(|e| RdfError::Parse(e.to_string()))?;
    let mut out = Vec::new();
    for quad in parser.for_slice(bytes) {
        let q = quad.map_err(|e| RdfError::Parse(e.to_string()))?;
        out.push(Triple { subject: q.subject, predicate: q.predicate, object: q.object });
    }
    Ok(out)
}

pub fn serialize(triples: &[Triple], fmt: RdfFormat) -> Result<Vec<u8>, RdfError> {
    let mut ser = RdfSerializer::from_format(fmt).for_writer(Vec::new());
    for t in triples {
        ser.serialize_triple(t).map_err(|e| RdfError::Serialize(e.to_string()))?;
    }
    ser.finish().map_err(|e| RdfError::Serialize(e.to_string()))
}
```

(Adjust `JsonLdProfileSet` path/constructor and the `Quad`→`Triple` field access to the exact 0.5.9/0.2.5 API if they differ — confirm on docs.rs. The `for_slice` iterator item type was confirmed as `Result<Quad, _>` in Plan 1.)

- [ ] **Step 4: Rewrite `src/resource.rs` to work in triples**

```rust
use crate::{rdf::RdfError, space::{StorageSpace, SpaceError}, store::{SparqlStore, StoreError}};
use oxigraph::model::Triple;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("invalid resource IRI")]
    InvalidIri,
    #[error(transparent)]
    Rdf(#[from] RdfError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<SpaceError> for ResourceError {
    fn from(_: SpaceError) -> Self { ResourceError::InvalidIri }
}

pub async fn put_rdf(
    store: &dyn SparqlStore, space: &StorageSpace, request_path: &str, triples: &[Triple],
) -> Result<(), ResourceError> {
    let g = space.graph_iri(request_path)?;
    let mut body = String::new();
    for t in triples {
        body.push_str(&format!("{} {} {} .\n", t.subject, t.predicate, t.object));
    }
    let update = format!("DROP SILENT GRAPH <{g}>; INSERT DATA {{ GRAPH <{g}> {{ {body} }} }}");
    store.update(&update).await?;
    Ok(())
}

pub async fn get_rdf(
    store: &dyn SparqlStore, space: &StorageSpace, request_path: &str,
) -> Result<Option<Vec<Triple>>, ResourceError> {
    let g = space.graph_iri(request_path)?;
    let q = format!("CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{g}> {{ ?s ?p ?o }} }}");
    let triples = store.query_triples(&q).await?;
    if triples.is_empty() { Ok(None) } else { Ok(Some(triples)) }
}
```

Remove the old `turtle_to_ntriples` helper and the old tests that asserted on Turtle strings; add/keep triple-level tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{space::StorageSpace, store::OxigraphStore, rdf};
    use oxigraph::io::RdfFormat;

    fn space() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    #[tokio::test]
    async fn put_then_get_roundtrips_triples() {
        let store = OxigraphStore::in_memory().unwrap();
        let t = rdf::parse(b"<#it> <http://schema.org/name> \"Toph\" .", RdfFormat::Turtle,
            "https://pod.toph.so/foo").unwrap();
        put_rdf(&store, &space(), "/foo", &t).await.unwrap();
        let got = get_rdf(&store, &space(), "/foo").await.unwrap().expect("exists");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].predicate.as_str(), "http://schema.org/name");
    }

    #[tokio::test]
    async fn put_replaces_not_appends() {
        let store = OxigraphStore::in_memory().unwrap();
        let a = rdf::parse(b"<#it> <http://schema.org/name> \"A\" .", RdfFormat::Turtle, "https://pod.toph.so/foo").unwrap();
        let b = rdf::parse(b"<#it> <http://schema.org/name> \"B\" .", RdfFormat::Turtle, "https://pod.toph.so/foo").unwrap();
        put_rdf(&store, &space(), "/foo", &a).await.unwrap();
        put_rdf(&store, &space(), "/foo", &b).await.unwrap();
        let got = get_rdf(&store, &space(), "/foo").await.unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert!(matches!(&got[0].object, oxigraph::model::Term::Literal(l) if l.value() == "B"));
    }

    #[tokio::test]
    async fn get_absent_is_none() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(get_rdf(&store, &space(), "/nope").await.unwrap().is_none());
    }
}
```

- [ ] **Step 5: Add module, run tests**

Add `pub mod rdf;` to `src/lib.rs`. Note `put_rdf`/`get_rdf` now take `&dyn SparqlStore` — `OxigraphStore` coerces via `&store`. Run:
`nix develop -c cargo test rdf:: resource::`
Expected: PASS. (`http.rs` still references old APIs and won't compile yet — fixed in Task 3. **Still no commit** — continue to Task 3.)

---

### Task 3: HTTP content negotiation + `Arc<dyn SparqlStore>`

**Files:**
- Modify: `src/http.rs`, `src/main.rs`
- Test: inline `#[cfg(test)]` in `src/http.rs`

**Interfaces:**
- Produces:
  - `pub struct AppState { pub store: std::sync::Arc<dyn SparqlStore>, pub space: StorageSpace }` (store is now a trait object).
  - `router(state) -> Router` unchanged in shape; handlers negotiate format.
    - `PUT`: `Content-Type` → `rdf::format_for_content_type`; `415` if unsupported; parse body via `rdf::parse` (base = the resource graph IRI); `400` on parse error or invalid IRI; `500` on store error; else `201` + `Location` = public graph IRI.
    - `GET`: `Accept` → `rdf::format_for_accept`; `406` if the client demanded only unsupported types; `404` if absent; else `200` with `Content-Type` set to the negotiated format's media type and the serialized body.
- Consumes: `rdf::{format_for_content_type, format_for_accept, parse, serialize}`, `resource::{put_rdf, get_rdf}`.

- [ ] **Step 1: Update/extend the HTTP tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;
    use std::sync::Arc;
    use crate::{space::StorageSpace, store::OxigraphStore};

    fn app() -> axum::Router {
        let state = AppState {
            store: Arc::new(OxigraphStore::in_memory().unwrap()),
            space: StorageSpace::new("https://pod.toph.so/").unwrap(),
        };
        router(state)
    }

    async fn body_string(res: axum::response::Response) -> String {
        let b = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        String::from_utf8_lossy(&b).into_owned()
    }

    #[tokio::test]
    async fn put_turtle_then_get_jsonld_negotiates() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        assert_eq!(app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        let get = Request::builder().method("GET").uri("/foo")
            .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
        let res = app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/ld+json");
        assert!(body_string(res).await.contains("schema.org/name"));
    }

    #[tokio::test]
    async fn get_default_accept_is_turtle() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();
        let res = app.oneshot(Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle");
    }

    #[tokio::test]
    async fn get_unsupported_accept_is_406() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();
        let res = app.oneshot(Request::builder().method("GET").uri("/foo")
            .header(header::ACCEPT, "image/png").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn put_unsupported_content_type_is_415() {
        let res = app().oneshot(Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "application/json").body(Body::from("{}")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn get_missing_is_404() {
        let res = app().oneshot(Request::builder().method("GET").uri("/nope").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn iri_breaking_path_is_400() {
        let res = app().oneshot(Request::builder().method("GET").uri("/foo%3E%20bar").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test http::`
Expected: FAIL — `AppState.store` type mismatch / negotiation not implemented.

- [ ] **Step 3: Rewrite handlers**

```rust
// src/http.rs
use std::sync::Arc;
use axum::{Router, routing::get, extract::{State, Path}, body::Bytes,
    http::{StatusCode, HeaderMap, header}, response::{IntoResponse, Response}};
use crate::{space::StorageSpace, store::SparqlStore, resource::{put_rdf, get_rdf, ResourceError},
    rdf::{format_for_content_type, format_for_accept, parse, serialize}};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn SparqlStore>,
    pub space: StorageSpace,
}

pub fn router(state: AppState) -> Router {
    Router::new().route("/{*path}", get(handle_get).put(handle_put)).with_state(state)
}

fn put_status(e: &ResourceError) -> StatusCode {
    match e {
        ResourceError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

async fn handle_put(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap, body: Bytes,
) -> Response {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_content_type(ct) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let req_path = format!("/{path}");
    let g = match st.space.graph_iri(&req_path) {
        Ok(g) => g,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let triples = match parse(&body, fmt, &g) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match put_rdf(st.store.as_ref(), &st.space, &req_path, &triples).await {
        Ok(()) => (StatusCode::CREATED, [(header::LOCATION, g)]).into_response(),
        Err(e) => (put_status(&e), e.to_string()).into_response(),
    }
}

async fn handle_get(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap,
) -> Response {
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_accept(accept) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    let req_path = format!("/{path}");
    match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(Some(triples)) => match serialize(&triples, fmt) {
            Ok(bytes) => ([(header::CONTENT_TYPE, fmt.media_type())], bytes).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(ResourceError::InvalidIri) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
```

(Confirm `RdfFormat::media_type()` exists on oxrdfio 0.2.5 — Plan 1's format.rs inspection shows a media-type method; if the name differs, map the format to its media-type string locally.)

- [ ] **Step 4: Update `main.rs`**

Change the store field construction to a trait object:

```rust
// src/main.rs — the state line becomes:
let state = AppState {
    store: std::sync::Arc::new(OxigraphStore::in_memory().expect("store")),
    space: StorageSpace::new(base).expect("valid POD_BASE_URI (absolute, trailing slash)"),
};
```

(`Arc<OxigraphStore>` coerces to `Arc<dyn SparqlStore>` at the field type.)

- [ ] **Step 5: Run full suite**

Run: `nix develop -c cargo test`
Expected: PASS (whole crate green again — this is the first green whole-crate point since Task 1 began). Then `nix develop -c cargo clippy --all-targets` clean, `nix develop -c cargo build 2>&1 | grep -i warning` empty.

- [ ] **Step 6: Commit the whole Tasks 1–3 refactor as one commit**

```bash
git add Cargo.toml Cargo.lock src/store.rs src/rdf.rs src/resource.rs src/http.rs src/lib.rs src/main.rs
git commit -m "feat: conneg over Arc<dyn SparqlStore> returning structured triples

Object-safe SparqlStore (async-trait) returning Vec<Triple>; central rdf
module for format negotiation + parse/serialize via oxigraph::io (Turtle,
JSON-LD, N-Triples); resource layer works in triples; HTTP negotiates
Content-Type/Accept. Resolves final-review I3 (runtime backend swap) and
M-b (store no longer returns pre-serialized Turtle)."
```

---

### Task 4: `DELETE` verb

**Files:**
- Modify: `src/resource.rs` (add `delete_rdf`), `src/http.rs` (route + handler)
- Test: inline tests in both

**Interfaces:**
- Produces:
  - `resource::delete_rdf(store: &dyn SparqlStore, space: &StorageSpace, request_path: &str) -> Result<bool, ResourceError>` — returns `true` if the resource existed and was dropped, `false` if it was already absent. Implementation: check existence via `get_rdf` (or an `ASK`), then `DROP SILENT GRAPH <g>` via `update`.
  - `http`: `DELETE /{*path}` → `204 No Content` if existed, `404` if absent, `400` on invalid IRI.

- [ ] **Step 1: Failing tests**

```rust
// in src/resource.rs tests
#[tokio::test]
async fn delete_removes_and_reports_existence() {
    let store = OxigraphStore::in_memory().unwrap();
    let t = rdf::parse(b"<#it> <http://schema.org/name> \"Toph\" .", oxigraph::io::RdfFormat::Turtle, "https://pod.toph.so/foo").unwrap();
    put_rdf(&store, &space(), "/foo", &t).await.unwrap();
    assert!(delete_rdf(&store, &space(), "/foo").await.unwrap());       // existed
    assert!(get_rdf(&store, &space(), "/foo").await.unwrap().is_none()); // gone
    assert!(!delete_rdf(&store, &space(), "/foo").await.unwrap());      // already absent
}
```

```rust
// in src/http.rs tests
#[tokio::test]
async fn delete_existing_is_204_then_404() {
    let app = app();
    let put = Request::builder().method("PUT").uri("/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    app.clone().oneshot(put).await.unwrap();
    let del = Request::builder().method("DELETE").uri("/foo").body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
    let del2 = Request::builder().method("DELETE").uri("/foo").body(Body::empty()).unwrap();
    assert_eq!(app.oneshot(del2).await.unwrap().status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test delete`
Expected: FAIL — `delete_rdf` / DELETE route missing.

- [ ] **Step 3: Implement**

```rust
// src/resource.rs
pub async fn delete_rdf(
    store: &dyn SparqlStore, space: &StorageSpace, request_path: &str,
) -> Result<bool, ResourceError> {
    let existed = get_rdf(store, space, request_path).await?.is_some();
    if existed {
        let g = space.graph_iri(request_path)?;
        store.update(&format!("DROP SILENT GRAPH <{g}>")).await?;
    }
    Ok(existed)
}
```

```rust
// src/http.rs — add `delete` to the route and a handler
// route: .route("/{*path}", get(handle_get).put(handle_put).delete(handle_delete))
async fn handle_delete(State(st): State<AppState>, Path(path): Path<String>) -> Response {
    let req_path = format!("/{path}");
    match crate::resource::delete_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(ResourceError::InvalidIri) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
```

Update the `use axum::routing::get;` line to also import nothing new (chained `.delete` is a method on `MethodRouter`).

- [ ] **Step 4: Run tests**

Run: `nix develop -c cargo test` → PASS; clippy clean; zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/resource.rs src/http.rs
git commit -m "feat: DELETE resource (DROP GRAPH), 204/404 semantics"
```

---

### Task 5: ETag + conditional requests

**Files:**
- Modify: `src/rdf.rs` (add `etag`), `src/http.rs` (emit ETag on GET; honor `If-None-Match` on GET, `If-Match` / `If-None-Match: *` on PUT), `Cargo.toml` (add `sha2`, `hex`)
- Test: inline tests in `src/http.rs` (+ an `etag` unit test in `src/rdf.rs`)

**Interfaces:**
- Produces:
  - `rdf::etag(triples: &[Triple]) -> String` — a strong ETag: sort the triples' N-Triples serializations, SHA-256 the concatenation, hex-encode, wrap in quotes (`"<hex>"`). Order-independent so it is stable regardless of store iteration order.
  - `http` GET: sets `ETag`; if `If-None-Match` matches the current ETag → `304 Not Modified` (no body). GET of an absent resource is unaffected (404).
  - `http` PUT: if `If-Match` is present and does **not** match the current resource's ETag (or the resource is absent) → `412 Precondition Failed`; if `If-None-Match: *` is present and the resource **exists** → `412` (create-only). Otherwise proceed.

- [ ] **Step 1: Add deps**

Run: `nix develop -c cargo add sha2 hex`

- [ ] **Step 2: Failing tests**

```rust
// src/rdf.rs tests
#[test]
fn etag_is_order_independent_and_changes_with_content() {
    use oxigraph::model::{Triple, NamedNode, Literal};
    let s = NamedNode::new("https://pod.toph.so/foo#it").unwrap();
    let p1 = NamedNode::new("http://schema.org/name").unwrap();
    let p2 = NamedNode::new("http://schema.org/age").unwrap();
    let t1 = Triple::new(s.clone(), p1, Literal::new_simple_literal("Toph"));
    let t2 = Triple::new(s, p2, Literal::new_simple_literal("40"));
    let ab = etag(&[t1.clone(), t2.clone()]);
    let ba = etag(&[t2, t1]);
    assert_eq!(ab, ba);                       // order-independent
    assert_ne!(ab, etag(&[t1]));              // content-sensitive
    assert!(ab.starts_with('"') && ab.ends_with('"'));
}
```

```rust
// src/http.rs tests
#[tokio::test]
async fn get_emits_etag_and_304_on_if_none_match() {
    let app = app();
    let put = Request::builder().method("PUT").uri("/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    app.clone().oneshot(put).await.unwrap();

    let res = app.clone().oneshot(Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap()).await.unwrap();
    let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    let cond = Request::builder().method("GET").uri("/foo")
        .header(header::IF_NONE_MATCH, &etag).body(Body::empty()).unwrap();
    assert_eq!(app.oneshot(cond).await.unwrap().status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn put_if_match_mismatch_is_412() {
    let app = app();
    let put = Request::builder().method("PUT").uri("/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    app.clone().oneshot(put).await.unwrap();

    let stale = Request::builder().method("PUT").uri("/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_MATCH, "\"deadbeef\"")
        .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
    assert_eq!(app.oneshot(stale).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn put_if_none_match_star_on_existing_is_412() {
    let app = app();
    let put = Request::builder().method("PUT").uri("/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    app.clone().oneshot(put).await.unwrap();

    let create_only = Request::builder().method("PUT").uri("/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_NONE_MATCH, "*")
        .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
    assert_eq!(app.oneshot(create_only).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
}
```

- [ ] **Step 3: Run to verify failure**

Run: `nix develop -c cargo test etag conditional if_`
Expected: FAIL.

- [ ] **Step 4: Implement `etag`**

```rust
// src/rdf.rs
use sha2::{Digest, Sha256};

pub fn etag(triples: &[Triple]) -> String {
    let mut lines: Vec<String> = triples.iter()
        .map(|t| format!("{} {} {} .", t.subject, t.predicate, t.object))
        .collect();
    lines.sort();
    let mut h = Sha256::new();
    for l in &lines { h.update(l.as_bytes()); h.update(b"\n"); }
    format!("\"{}\"", hex::encode(h.finalize()))
}
```

- [ ] **Step 5: Wire conditionals into the handlers**

In `handle_get`, after fetching `Some(triples)`, compute `let tag = crate::rdf::etag(&triples);`. If the request's `If-None-Match` header equals `tag`, return `StatusCode::NOT_MODIFIED` (with the `ETag` header set, no body). Otherwise set `ETag: tag` alongside `Content-Type`.

```rust
// handle_get, replace the Ok(Some(triples)) arm:
Ok(Some(triples)) => {
    let tag = crate::rdf::etag(&triples);
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, tag)]).into_response();
    }
    match serialize(&triples, fmt) {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, fmt.media_type().to_string()), (header::ETAG, tag)],
            bytes,
        ).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
```

In `handle_put`, before writing, evaluate preconditions against the current resource:

```rust
// handle_put, after computing `g` and before parse (needs current state):
let current = get_rdf(st.store.as_ref(), &st.space, &req_path).await;
let current_tag = match &current {
    Ok(Some(tr)) => Some(crate::rdf::etag(tr)),
    Ok(None) => None,
    Err(e) => return (put_status(e), e.to_string()).into_response(),
};
if let Some(im) = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()) {
    if Some(im) != current_tag.as_deref() {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }
}
if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some("*")
    && current_tag.is_some() {
    return StatusCode::PRECONDITION_FAILED.into_response();
}
```

(These two blocks reference `get_rdf`, already imported. `handle_get` gains no new imports; `header::{ETAG, IF_NONE_MATCH, IF_MATCH}` are in `axum::http::header`.)

- [ ] **Step 6: Run tests**

Run: `nix develop -c cargo test` → PASS (all, including the new conditional tests). Clippy clean, zero warnings.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/rdf.rs src/http.rs
git commit -m "feat: strong ETag + If-Match/If-None-Match conditional requests"
```

---

## Self-Review

**Spec coverage (Plan 2 scope):**
- Runtime backend swap / `Arc<dyn SparqlStore>` (spec success #4, final-review I3) → Task 1 + Task 3. ✓
- Structured store return (final-review M-b) → Task 1. ✓
- Conneg Turtle + JSON-LD (Solid-mandated) + N-Triples (spec §5) → Tasks 2, 3. ✓ (via `oxigraph::io`/`oxjsonld`; `rdf_dynsyn` proven unnecessary.)
- Triple-preserving round-trips (spec §5) → Task 2 cross-format test, Task 3 turtle→jsonld test. ✓
- Conditional requests / ETag (LDP/Solid conditional writes) → Task 5. ✓
- DELETE (LDP) → Task 4. ✓
- **Deferred to Plan 3+ (explicitly out of scope):** containers + `ldp:contains` + POST; N3-Patch; blobs + `object_store` + `urn:pod:sys:`; auth/DPoP; WAC/PRP/PDP; the `//foo` path-normalization Minor (arrives with container path handling); the escaping regression test (safe; fold into container work).

**Placeholder scan:** No "TBD/handle errors/similar-to". Third-party API points (JsonLd profile constructor, `RdfFormat::media_type`, `Quad`→`Triple` field access) each carry an explicit "confirm against docs.rs/oxrdfio 0.2.5 and adjust this file" instruction — concrete verification, not hand-waving; localized so a mismatch fails a unit test fast.

**Type consistency:** `SparqlStore::query_triples -> Vec<Triple>`, `put_rdf(&dyn SparqlStore, …, &[Triple])`, `get_rdf -> Option<Vec<Triple>>`, `delete_rdf -> bool`, `AppState { store: Arc<dyn SparqlStore>, space }`, `rdf::{format_for_content_type, format_for_accept, parse, serialize, etag}` used identically across Tasks 1–5. `ResourceError` variants (`InvalidIri`, `Rdf`, `Store`) consistent. ✓

**Transient-breakage note:** Task 1 leaves `resource.rs`/`http.rs` referencing the removed `query_construct`; Task 2 fixes `resource.rs`, Task 3 fixes `http.rs`. The whole crate is green again at the end of Task 3. If per-commit green is required, the implementer may squash Tasks 1–3 — flagged in Task 1 Step 5.
