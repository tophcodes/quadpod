# SPARQL Solid Pod — Plan 1: Walking Skeleton + De-Risk

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A running pod that stores and retrieves a single RDF (Turtle) resource, where the resource URL *is* the named-graph name, minted from a configured public base-URI — proving the core mapping and de-risking Manas + atomicity before layering LDP/WAC/blobs/auth.

**Architecture:** A thin `axum` HTTP server (plain HTTP, public-URL from config) over a `SparqlStore` trait. The reference `SparqlStore` impl wraps the embedded `oxigraph` crate (in-memory for tests, portable SPARQL 1.1 strings so an HTTP-backed impl can swap in later). A `StorageSpace` value carries the public base-URI and maps `request path → graph IRI`. PUT parses Turtle and atomically replaces the resource's named graph; GET CONSTRUCTs it back.

**Tech Stack:** Rust (stable), `tokio`, `axum`, `oxigraph` (embedded store + Turtle parse/serialize), `tower`/`http` for tests. Design docs: `docs/superpowers/specs/2026-07-24-sparql-solid-pod-design.md`.

## Global Constraints

- **URL = identity.** Every minted graph IRI derives from the configured public base-URI, never the request socket scheme/host. (Spec §5, §10)
- **Resource URL = named-graph name, 1:1.** (Spec §5)
- **Strict RDF 1.1.** No RDF-star. (Spec §5)
- **Store access only via `SparqlStore` (SPARQL 1.1 query/update strings).** No Oxigraph-proprietary features in the mapping layer, so Fuseki/GraphDB can swap in later. (Spec §4)
- **RDF resources are triple-preserving, not byte-preserving.** Round-trip asserts triple-set equality, never byte equality. (Spec §5)
- **No hardcoded root/base-URI/owner** — thread a `StorageSpace`. (Spec §9)
- Conventional commits. TDD: failing test first, minimal impl, commit per task.

---

### Task 0: Spike — verify Manas crates compile (de-risk, not committed)

Discharges Spec §14 risk #1 before any later plan depends on Manas. Produces a written note, not committed dependencies.

**Files:**
- Create (throwaway, git-ignored): `/tmp/manas-spike/` — a scratch crate.
- Modify: `docs/superpowers/specs/2026-07-24-sparql-solid-pod-design.md` (append a "Spike Results" note under §14).

- [ ] **Step 1: Create a scratch crate and add the Manas crates we intend to reuse**

```bash
cd "$CLAUDE_JOB_DIR/tmp" 2>/dev/null || cd /tmp
cargo new --lib manas-spike && cd manas-spike
cargo add rdf_dynsyn dpop solid_oidc_types webid acp manas_access_control manas_space 2>&1 | tail -20
```

- [ ] **Step 2: Attempt to build on current stable Rust**

Run: `cargo build 2>&1 | tail -40`
Expected: either a clean build, OR concrete error output. Record which crates fail and why.

- [ ] **Step 3: Record versions + licenses**

```bash
cargo tree -p manas_access_control -p manas_space --depth 0 2>&1 | head
for c in rdf_dynsyn dpop solid_oidc_types webid acp manas_access_control manas_space; do
  echo -n "$c: "; curl -s "https://crates.io/api/v1/crates/$c" -H "User-Agent: spike" | jq -r '.crate.max_version, .versions[0].license' | paste -sd' ' -
done
```

- [ ] **Step 4: Append findings to the spec under §14**

Write a short "Spike Results (2026-07-24)" note: does it compile? versions? licenses? If a crate is bit-rotted, record whether we fork-that-crate or reimplement — this decision feeds Plans 2/5. This task does **not** add these deps to the real project.

- [ ] **Step 5: Commit the spec note**

```bash
cd /home/toph/Projects/sparql-pod
git add docs/superpowers/specs/2026-07-24-sparql-solid-pod-design.md
git commit -m "docs: record Manas crate compile-spike results"
```

---

### Task 1: Project scaffold + green build

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/lib.rs`
- Create: `rust-toolchain.toml`

**Interfaces:**
- Produces: crate `sparql_pod` (lib) + binary `sparql-pod`. Nothing else yet.

- [ ] **Step 1: Write a trivial failing test in the lib**

```rust
// src/lib.rs
#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(2 + 2, 4);
    }
}
```

- [ ] **Step 2: Create `Cargo.toml` with Plan-1 dependencies only**

**Use latest versions everywhere.** Prefer `cargo add <crate>` (resolves the newest release) over hand-editing versions. Versions below are the latest as of 2026-07-24 — if `cargo add` pulls something newer, keep the newer one and adjust any API in later tasks to match.

```bash
cargo add tokio --features full
cargo add axum
cargo add oxigraph
cargo add thiserror
cargo add tracing tracing-subscriber
cargo add --dev tower --features util
cargo add --dev http-body-util
```

Resulting `[dependencies]` should be at least:

```toml
[dependencies]
tokio = { version = "1.53", features = ["full"] }
axum = "0.8"          # 0.8 wildcard route syntax is "/{*path}", NOT "/*path"
oxigraph = "0.5"      # 0.5 I/O API lives under oxigraph::io (oxrdfio)
thiserror = "2"
tracing = "0.1"
tracing-subscriber = "0.3"

[dev-dependencies]
tower = { version = "0.5", features = ["util"] }
http-body-util = "0.1"
```

Also add `[lib] name = "sparql_pod"` / `[[bin]] name = "sparql-pod"` targets and `edition = "2021"` (or newer if the toolchain defaults higher).

- [ ] **Step 3: Minimal `main.rs`**

```rust
fn main() {
    println!("sparql-pod");
}
```

- [ ] **Step 4: Run the build and test**

Run: `cargo test`
Expected: PASS (`crate_builds`), clean compile.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml rust-toolchain.toml src/
git commit -m "chore: scaffold sparql-pod crate"
```

---

### Task 2: `StorageSpace` — public-URL identity mapping

**Files:**
- Create: `src/space.rs`
- Modify: `src/lib.rs` (add `pub mod space;`)
- Test: inline `#[cfg(test)]` in `src/space.rs`

**Interfaces:**
- Produces:
  - `struct StorageSpace { base: String }` where `base` is the public base-URI incl. trailing slash, e.g. `https://pod.toph.so/`.
  - `impl StorageSpace`:
    - `fn new(base: impl Into<String>) -> Result<Self, SpaceError>` — rejects a base without a trailing `/` or without an `https?://` scheme.
    - `fn graph_iri(&self, request_path: &str) -> String` — maps a request path (e.g. `/foo`) to the absolute graph IRI (`https://pod.toph.so/foo`) using `base`, **ignoring** any request host. Leading `/` on the path is collapsed against the trailing `/` of base.
  - `enum SpaceError { NotAbsolute, NoTrailingSlash }` (derive `Debug`, `thiserror::Error`).

- [ ] **Step 1: Write failing tests**

```rust
// src/space.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_iri_uses_config_base_not_request_host() {
        let s = StorageSpace::new("https://pod.toph.so/").unwrap();
        assert_eq!(s.graph_iri("/foo"), "https://pod.toph.so/foo");
        assert_eq!(s.graph_iri("/a/b"), "https://pod.toph.so/a/b");
        assert_eq!(s.graph_iri("/"), "https://pod.toph.so/");
    }

    #[test]
    fn rejects_base_without_trailing_slash() {
        assert!(matches!(StorageSpace::new("https://pod.toph.so"),
            Err(SpaceError::NoTrailingSlash)));
    }

    #[test]
    fn rejects_non_absolute_base() {
        assert!(matches!(StorageSpace::new("pod.toph.so/"),
            Err(SpaceError::NotAbsolute)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test space::`
Expected: FAIL — `StorageSpace` not defined.

- [ ] **Step 3: Implement `StorageSpace`**

```rust
// src/space.rs (above the tests module)
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SpaceError {
    #[error("base URI must be absolute (http:// or https://)")]
    NotAbsolute,
    #[error("base URI must end with a trailing slash")]
    NoTrailingSlash,
}

#[derive(Debug, Clone)]
pub struct StorageSpace {
    base: String,
}

impl StorageSpace {
    pub fn new(base: impl Into<String>) -> Result<Self, SpaceError> {
        let base = base.into();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(SpaceError::NotAbsolute);
        }
        if !base.ends_with('/') {
            return Err(SpaceError::NoTrailingSlash);
        }
        Ok(Self { base })
    }

    /// Map a request path to the absolute graph IRI, using the configured
    /// base only — the request host/scheme is deliberately ignored.
    pub fn graph_iri(&self, request_path: &str) -> String {
        let trimmed = request_path.strip_prefix('/').unwrap_or(request_path);
        format!("{}{}", self.base, trimmed)
    }
}
```

- [ ] **Step 4: Add module + run tests**

Add `pub mod space;` to `src/lib.rs`, then:
Run: `cargo test space::`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/space.rs src/lib.rs
git commit -m "feat: StorageSpace maps request path to public graph IRI"
```

---

### Task 3: `SparqlStore` trait + embedded Oxigraph impl

**Files:**
- Create: `src/store.rs`
- Modify: `src/lib.rs` (add `pub mod store;`)
- Test: inline `#[cfg(test)]` in `src/store.rs`

**Interfaces:**
- Produces:
  - `trait SparqlStore` (async, `Send + Sync`):
    - `async fn update(&self, sparql: &str) -> Result<(), StoreError>` — executes a SPARQL 1.1 Update.
    - `async fn query_construct(&self, sparql: &str) -> Result<String, StoreError>` — executes a CONSTRUCT, returns the result serialized as **Turtle**.
  - `struct OxigraphStore` wrapping `oxigraph::store::Store` (in-memory via `Store::new()`).
  - `impl OxigraphStore { fn in_memory() -> Result<Self, StoreError> }`.
  - `enum StoreError { Backend(String) }` (`Debug`, `thiserror::Error`).
- Consumes: `oxigraph` crate. Confirm exact method names against `docs.rs/oxigraph/0.5` — the intended calls are `Store::new()`, `store.update(&str)`, `store.query(&str)` returning `QueryResults::Graph(iter)`, and serializing the resulting triples to Turtle via `oxigraph::io::RdfSerializer` (0.5 API). If a method name differs in the pinned version, adjust the impl (the trait signature stays).

- [ ] **Step 1: Write failing tests**

```rust
// src/store.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn update_then_construct_roundtrips_a_triple() {
        let store = OxigraphStore::in_memory().unwrap();
        store.update(
            "INSERT DATA { GRAPH <https://pod.toph.so/foo> { \
             <https://pod.toph.so/foo#it> <http://schema.org/name> \"Toph\" } }",
        ).await.unwrap();

        let ttl = store.query_construct(
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <https://pod.toph.so/foo> { ?s ?p ?o } }",
        ).await.unwrap();

        assert!(ttl.contains("schema.org/name"));
        assert!(ttl.contains("Toph"));
    }

    #[tokio::test]
    async fn construct_of_absent_graph_is_empty() {
        let store = OxigraphStore::in_memory().unwrap();
        let ttl = store.query_construct(
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <https://pod.toph.so/missing> { ?s ?p ?o } }",
        ).await.unwrap();
        assert!(!ttl.contains("schema.org"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test store::`
Expected: FAIL — `OxigraphStore` not defined.

- [ ] **Step 3: Implement the trait + Oxigraph impl**

```rust
// src/store.rs (above tests)
use oxigraph::store::Store;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store backend error: {0}")]
    Backend(String),
}

pub trait SparqlStore: Send + Sync {
    fn update(&self, sparql: &str)
        -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    fn query_construct(&self, sparql: &str)
        -> impl std::future::Future<Output = Result<String, StoreError>> + Send;
}

pub struct OxigraphStore {
    inner: Store,
}

impl OxigraphStore {
    pub fn in_memory() -> Result<Self, StoreError> {
        Store::new().map(|inner| Self { inner }).map_err(|e| StoreError::Backend(e.to_string()))
    }
}

impl SparqlStore for OxigraphStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        self.inner.update(sparql).map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn query_construct(&self, sparql: &str) -> Result<String, StoreError> {
        use oxigraph::sparql::QueryResults;
        let results = self.inner.query(sparql).map_err(|e| StoreError::Backend(e.to_string()))?;
        let QueryResults::Graph(triples) = results else {
            return Err(StoreError::Backend("expected CONSTRUCT/graph results".into()));
        };
        // Serialize triples to Turtle. Confirm the exact serializer API against
        // docs.rs/oxigraph/0.4 (RdfSerializer::from_format(RdfFormat::Turtle))
        // and write each triple; return the resulting String.
        let mut buf = Vec::new();
        let mut ser = oxigraph::io::RdfSerializer::from_format(oxigraph::io::RdfFormat::Turtle)
            .serialize_to_write(&mut buf);
        for t in triples {
            let t = t.map_err(|e| StoreError::Backend(e.to_string()))?;
            ser.write_triple(&t).map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        ser.finish().map_err(|e| StoreError::Backend(e.to_string()))?;
        String::from_utf8(buf).map_err(|e| StoreError::Backend(e.to_string()))
    }
}
```

- [ ] **Step 4: Add module + run tests**

Add `pub mod store;` to `src/lib.rs`, then:
Run: `cargo test store::`
Expected: PASS (2 tests). If a serializer/method name mismatches the pinned oxigraph, fix the call (signatures in this file only) until green.

- [ ] **Step 5: Commit**

```bash
git add src/store.rs src/lib.rs
git commit -m "feat: SparqlStore trait + embedded Oxigraph impl"
```

---

### Task 4: RDF resource mapping — atomic put/get by URL

Discharges Spec §14 risk #3 (atomic multi-statement update) at single-graph scope.

**Files:**
- Create: `src/resource.rs`
- Modify: `src/lib.rs` (add `pub mod resource;`)
- Test: inline `#[cfg(test)]` in `src/resource.rs`

**Interfaces:**
- Consumes: `StorageSpace::graph_iri`, `SparqlStore::{update, query_construct}`.
- Produces:
  - `async fn put_rdf<S: SparqlStore>(store: &S, space: &StorageSpace, request_path: &str, turtle: &str) -> Result<(), ResourceError>` — parses `turtle` (base = the resource's graph IRI), then **atomically** replaces the named graph via a single update string: `DROP SILENT GRAPH <g>; INSERT DATA { GRAPH <g> { …parsed triples as N-Triples… } }`.
  - `async fn get_rdf<S: SparqlStore>(store: &S, space: &StorageSpace, request_path: &str) -> Result<Option<String>, ResourceError>` — CONSTRUCTs graph `<g>`; returns `None` if empty, else `Some(turtle)`.
  - `enum ResourceError { Parse(String), Store(StoreError) }`.
- Note: parse Turtle → N-Triples using `oxigraph::io::RdfParser` (0.5 API; confirm on docs.rs/oxigraph/0.5). The single combined update string is one `Store::update` call → atomic on Oxigraph; the `DROP; INSERT DATA` pair is standard SPARQL 1.1 and portable.

- [ ] **Step 1: Write failing tests**

```rust
// src/resource.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{space::StorageSpace, store::OxigraphStore};

    fn space() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    #[tokio::test]
    async fn put_then_get_preserves_triples() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        let ttl = "<#it> <http://schema.org/name> \"Toph\" .";
        put_rdf(&store, &sp, "/foo", ttl).await.unwrap();

        let got = get_rdf(&store, &sp, "/foo").await.unwrap().expect("exists");
        assert!(got.contains("schema.org/name"));
        assert!(got.contains("Toph"));
    }

    #[tokio::test]
    async fn put_replaces_not_appends() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        put_rdf(&store, &sp, "/foo", "<#it> <http://schema.org/name> \"A\" .").await.unwrap();
        put_rdf(&store, &sp, "/foo", "<#it> <http://schema.org/name> \"B\" .").await.unwrap();
        let got = get_rdf(&store, &sp, "/foo").await.unwrap().unwrap();
        assert!(got.contains("\"B\""));
        assert!(!got.contains("\"A\""));
    }

    #[tokio::test]
    async fn get_absent_resource_is_none() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(get_rdf(&store, &space(), "/nope").await.unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test resource::`
Expected: FAIL — `put_rdf`/`get_rdf` not defined.

- [ ] **Step 3: Implement mapping**

```rust
// src/resource.rs (above tests)
use crate::{space::StorageSpace, store::{SparqlStore, StoreError}};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("turtle parse error: {0}")]
    Parse(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Parse Turtle (resolved against `base_iri`) into N-Triples lines.
/// Confirm the parser API against docs.rs/oxigraph (oxttl / RdfParser with a base IRI).
fn turtle_to_ntriples(turtle: &str, base_iri: &str) -> Result<String, ResourceError> {
    use oxigraph::io::{RdfParser, RdfFormat};
    let parser = RdfParser::from_format(RdfFormat::Turtle)
        .with_base_iri(base_iri).map_err(|e| ResourceError::Parse(e.to_string()))?;
    let mut out = String::new();
    for quad in parser.parse_read(turtle.as_bytes()) {
        let q = quad.map_err(|e| ResourceError::Parse(e.to_string()))?;
        // N-Triples line for the triple (graph term dropped; we place it explicitly).
        out.push_str(&format!("{} {} {} .\n", q.subject, q.predicate, q.object));
    }
    Ok(out)
}

pub async fn put_rdf<S: SparqlStore>(
    store: &S, space: &StorageSpace, request_path: &str, turtle: &str,
) -> Result<(), ResourceError> {
    let g = space.graph_iri(request_path);
    let triples = turtle_to_ntriples(turtle, &g)?;
    let update = format!(
        "DROP SILENT GRAPH <{g}>; INSERT DATA {{ GRAPH <{g}> {{ {triples} }} }}",
    );
    store.update(&update).await?;
    Ok(())
}

pub async fn get_rdf<S: SparqlStore>(
    store: &S, space: &StorageSpace, request_path: &str,
) -> Result<Option<String>, ResourceError> {
    let g = space.graph_iri(request_path);
    let q = format!("CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{g}> {{ ?s ?p ?o }} }}");
    let ttl = store.query_construct(&q).await?;
    if ttl.trim().is_empty() { Ok(None) } else { Ok(Some(ttl)) }
}
```

- [ ] **Step 4: Add module + run tests**

Add `pub mod resource;` to `src/lib.rs`, then:
Run: `cargo test resource::`
Expected: PASS (3 tests). Adjust parser/serializer calls to the pinned oxigraph API until green.

- [ ] **Step 5: Commit**

```bash
git add src/resource.rs src/lib.rs
git commit -m "feat: atomic put/get of an RDF resource by URL-as-graph"
```

---

### Task 5: HTTP handlers — end-to-end PUT/GET over axum

**Files:**
- Create: `src/http.rs`
- Modify: `src/lib.rs` (add `pub mod http;`), `src/main.rs` (start the server)
- Test: inline `#[cfg(test)]` in `src/http.rs` (via `tower::ServiceExt::oneshot`)

**Interfaces:**
- Consumes: `StorageSpace`, `SparqlStore` (`OxigraphStore`), `put_rdf`, `get_rdf`.
- Produces:
  - `struct AppState { store: Arc<OxigraphStore>, space: StorageSpace }`
  - `fn router(state: AppState) -> axum::Router` with `GET /*path` and `PUT /*path`.
    - `PUT`: requires `Content-Type: text/turtle` (else `415`); body parsed+stored; `201 Created` with `Location` = the public graph IRI.
    - `GET`: `200` with `Content-Type: text/turtle` and the Turtle body if present, else `404`.

- [ ] **Step 1: Write failing end-to-end tests**

```rust
// src/http.rs
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

    #[tokio::test]
    async fn put_then_get_roundtrips_over_http() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        let res = app.clone().oneshot(put).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/foo");

        let get = Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap();
        let res = app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Toph"));
    }

    #[tokio::test]
    async fn get_missing_is_404() {
        let res = app().oneshot(
            Request::builder().method("GET").uri("/nope").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_wrong_content_type_is_415() {
        let req = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}")).unwrap();
        assert_eq!(app().oneshot(req).await.unwrap().status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test http::`
Expected: FAIL — `router`/`AppState` not defined.

- [ ] **Step 3: Implement handlers**

```rust
// src/http.rs (above tests)
use std::sync::Arc;
use axum::{Router, routing::get, extract::{State, Path}, body::Bytes,
    http::{StatusCode, HeaderMap, header}, response::{IntoResponse, Response}};
use crate::{space::StorageSpace, store::OxigraphStore, resource::{put_rdf, get_rdf}};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<OxigraphStore>,
    pub space: StorageSpace,
}

pub fn router(state: AppState) -> Router {
    // axum 0.8 wildcard capture syntax: "/{*path}" (NOT the old "/*path").
    Router::new().route("/{*path}", get(handle_get).put(handle_put)).with_state(state)
}

async fn handle_put(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap, body: Bytes,
) -> Response {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.starts_with("text/turtle") {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let req_path = format!("/{path}");
    let turtle = String::from_utf8_lossy(&body);
    match put_rdf(st.store.as_ref(), &st.space, &req_path, &turtle).await {
        Ok(()) => {
            let loc = st.space.graph_iri(&req_path);
            (StatusCode::CREATED, [(header::LOCATION, loc)]).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn handle_get(State(st): State<AppState>, Path(path): Path<String>) -> Response {
    let req_path = format!("/{path}");
    match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(Some(ttl)) => ([(header::CONTENT_TYPE, "text/turtle")], ttl).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
```

- [ ] **Step 4: Add module + run tests**

Add `pub mod http;` to `src/lib.rs`, then:
Run: `cargo test http::`
Expected: PASS (3 tests). (axum 0.8 wildcard route = `"/{*path}"`; confirm extractor signatures against docs.rs/axum/0.8 and adjust if a newer minor differs.)

- [ ] **Step 5: Wire `main.rs` to actually serve**

```rust
// src/main.rs
use std::sync::Arc;
use sparql_pod::{http::{AppState, router}, space::StorageSpace, store::OxigraphStore};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let base = std::env::var("POD_BASE_URI").unwrap_or_else(|_| "http://localhost:3000/".into());
    let state = AppState {
        store: Arc::new(OxigraphStore::in_memory().expect("store")),
        space: StorageSpace::new(base).expect("valid POD_BASE_URI (absolute, trailing slash)"),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    tracing::info!("sparql-pod listening on 127.0.0.1:3000");
    axum::serve(listener, router(state)).await.unwrap();
}
```

- [ ] **Step 6: Manually verify end-to-end**

```bash
POD_BASE_URI="http://localhost:3000/" cargo run &
sleep 1
curl -i -X PUT http://localhost:3000/foo -H 'Content-Type: text/turtle' \
  --data '<#it> <http://schema.org/name> "Toph" .'
curl -i http://localhost:3000/foo
kill %1
```
Expected: PUT → `201` + `Location: http://localhost:3000/foo`; GET → `200` + Turtle containing `Toph`.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs src/main.rs src/lib.rs
git commit -m "feat: HTTP PUT/GET for RDF resources end-to-end"
```

---

## Self-Review

**Spec coverage (Plan 1 scope only — Plans 2–6 cover the rest):**
- URL = named-graph mapping (§5) → Tasks 2, 4. ✓
- Public-URL-from-config, not socket (§5, §10) → Task 2 (`graph_iri` ignores host) + test `graph_iri_uses_config_base_not_request_host`. ✓
- `SparqlStore` over portable SPARQL 1.1 (§4) → Task 3. ✓
- Triple-preserving round-trip (§5) → Task 4 tests assert triple content, never bytes. ✓
- Atomic replace (§14 #3, single-graph) → Task 4 (`DROP SILENT; INSERT DATA` in one update) + `put_replaces_not_appends`. ✓
- Manas compile de-risk (§14 #1) → Task 0. ✓
- `StorageSpace` threaded, no hardcoded base (§9) → Tasks 2, 5. ✓
- **Deferred by design (later plans):** containers/conneg/N3-Patch/ETags (Plan 2), blobs + `urn:pod:sys:` (Plan 3), auth/DPoP `htu` (Plan 4), WAC/PRP/PDP (Plan 5). Explicitly out of Plan 1.

**Placeholder scan:** No "TBD/handle errors/similar-to". Third-party API calls (oxigraph parser/serializer, axum route syntax) carry an explicit "confirm exact signature against docs.rs and adjust this file" instruction — a concrete verification step, not a hand-wave, because pinned minor versions vary.

**Type consistency:** `StorageSpace::graph_iri`, `SparqlStore::{update, query_construct}`, `put_rdf`/`get_rdf`, `AppState { store, space }`, `router` used identically across Tasks 2–5. ✓

**Cross-cutting risk:** exact oxigraph 0.4 I/O API (parser base-IRI, serializer) is the one place the code may need adjustment; Tasks 3 & 4 localize it and gate on green tests, so a signature mismatch fails fast in unit tests rather than propagating.
