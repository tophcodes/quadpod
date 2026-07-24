# SPARQL Solid Pod — Plan 3: LDP Containers

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add LDP BasicContainer support — trailing-slash container URLs backed by their own named graph, server-managed `ldp:contains` membership, auto-created ancestor containers, an auto-provisioned root, container `GET`/`PUT`/`DELETE` with the Solid-mandated 409 rules, and `POST` (Slug-based child creation).

**Architecture:** A new `src/container.rs` owns container identity (trailing-slash convention), the LDP vocabulary constants, and the store operations that maintain containment (`ldp:contains` triples live in the parent container's own graph, server-managed, written on create/delete). `resource.rs` write paths gain ancestor-ensuring + containment maintenance; `http.rs` branches container vs resource by trailing slash and adds `POST` + a root (`/`) route. The store seam (`SparqlStore` update/`query_triples`) is unchanged — containers are just more SPARQL over the same named-graph model.

**Tech Stack:** Rust, `oxigraph` 0.5 (`SparqlStore`, `oxigraph::model`), `axum` 0.8, `uuid` (v4, for no-Slug child names). Build only via the flake dev shell.

**Builds on:** Plan 2 (merged to `main`): `space::StorageSpace` (`graph_iri -> Result<String, SpaceError>`), `store::{SparqlStore, OxigraphStore}` (`update`, `query_triples -> Vec<Triple>`), `resource::{put_rdf, get_rdf, delete_rdf, ResourceError}`, `rdf::{format_for_content_type, format_for_accept, parse, serialize, etag}`, `http::{AppState, router}`. Design spec: `docs/superpowers/specs/2026-07-24-sparql-solid-pod-design.md` (§5).

## Global Constraints

- **Build/test ONLY via the flake dev shell.** Bare `cargo` fails (oxigraph → RocksDB → libclang). Every command: `nix develop -c cargo test` / `nix develop -c cargo build 2>&1 | grep -i warning` (empty) / `nix develop -c cargo clippy --all-targets` (clean). Output pristine.
- **Latest deps** via `cargo add <crate>` (no pinned version).
- **Container = trailing-slash URL.** `<base>/foo/` is a container (own graph, typed `ldp:Container`, `ldp:BasicContainer`); `<base>/foo` is a resource. (Spec §5)
- **Containment is server-managed, stored.** `<container> ldp:contains <child>` triples live in the container's own graph; the server writes them on create/delete. Clients MUST NOT set them. (Spec §5; Solid Protocol)
- **Solid MUSTs (verified against the Solid Protocol):**
  - `DELETE` on a **non-empty** container → **409**. No server-side recursion.
  - `PUT`/`PATCH` on a container that would update its containment triples (or resource-metadata statements) → **409**.
  - When a contained resource is deleted, the server MUST remove the corresponding containment triple.
- **Auto-create ancestor containers** on `PUT`/`POST` to a deep path; **root `/` is auto-provisioned** at startup. (Design decision, single-pod v1)
- **URL = identity from config, never the socket.** All graph IRIs via `StorageSpace::graph_iri` (validated). (Spec §5, §10)
- Store access via SPARQL 1.1 strings only; no proprietary mutation APIs; no deprecated APIs (`Store::update` OK, `Store::query` deprecated → the store already uses `SparqlEvaluator`); no `#[allow(...)]`.
- Conventional commits. TDD: failing test first, minimal impl, commit per task.

**Cross-graph atomicity note (v1, accepted):** a resource write + its parent's `ldp:contains` update are separate `SparqlStore::update` calls, not one atomic transaction. Acceptable for a single-user personal pod; a later plan may fold them into one update string if needed. Do not add a transaction abstraction now (YAGNI).

---

### Task 1: `container.rs` — LDP constants + path helpers

**Files:**
- Create: `src/container.rs`
- Modify: `src/lib.rs` (add `pub mod container;`)
- Test: inline `#[cfg(test)]` in `src/container.rs`

**Interfaces:**
- Produces:
  - `pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";`
  - `pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";`
  - `pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";`
  - `pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";`
  - `pub fn is_container_path(request_path: &str) -> bool` — true iff `request_path` ends with `/`.
  - `pub fn parent_container(request_path: &str) -> Option<String>` — the parent container path (always trailing-slash), or `None` for `/`. `"/a/b/c" -> "/a/b/"`, `"/a/b/" -> "/a/"`, `"/foo" -> "/"`, `"/" -> None`.

- [ ] **Step 1: Write failing tests**

```rust
// src/container.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_paths_end_with_slash() {
        assert!(is_container_path("/foo/"));
        assert!(is_container_path("/"));
        assert!(!is_container_path("/foo"));
        assert!(!is_container_path("/a/b"));
    }

    #[test]
    fn parent_of_resource_and_container() {
        assert_eq!(parent_container("/a/b/c").as_deref(), Some("/a/b/"));
        assert_eq!(parent_container("/a/b/").as_deref(), Some("/a/"));
        assert_eq!(parent_container("/foo").as_deref(), Some("/"));
        assert_eq!(parent_container("/foo/").as_deref(), Some("/"));
        assert_eq!(parent_container("/"), None);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test container::`
Expected: FAIL — module/functions undefined.

- [ ] **Step 3: Implement**

```rust
// src/container.rs (above tests)
pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

pub fn is_container_path(request_path: &str) -> bool {
    request_path.ends_with('/')
}

/// Parent container path (always trailing-slash), or None for the root "/".
pub fn parent_container(request_path: &str) -> Option<String> {
    if request_path == "/" {
        return None;
    }
    let trimmed = request_path.strip_suffix('/').unwrap_or(request_path);
    match trimmed.rfind('/') {
        Some(idx) => Some(trimmed[..=idx].to_string()),
        None => Some("/".to_string()),
    }
}
```

- [ ] **Step 4: Add module, run tests**

Add `pub mod container;` to `src/lib.rs`. Run: `nix develop -c cargo test container::` → PASS (2).

- [ ] **Step 5: Commit**

```bash
git add src/container.rs src/lib.rs
git commit -m "feat: container path helpers + LDP vocabulary constants"
```

---

### Task 2: `container.rs` — store operations for containment

**Files:**
- Modify: `src/container.rs` (add store ops), `Cargo.toml` (nothing new here)
- Test: inline tests in `src/container.rs` (in-memory store)

**Interfaces:**
- Consumes: `StorageSpace::graph_iri`, `SparqlStore::{update, query_triples}`, the constants + `parent_container` from Task 1, `resource::ResourceError`.
- Produces (all `async`, taking `store: &dyn SparqlStore, space: &StorageSpace`):
  - `ensure_container(store, space, path: &str) -> Result<(), ResourceError>` — idempotently assert `<c> a ldp:Container, ldp:BasicContainer` in graph `<c>`. (`INSERT DATA` is a set-op → safe to repeat.)
  - `add_containment(store, space, parent: &str, child: &str) -> Result<(), ResourceError>` — idempotently `INSERT` `<parent> ldp:contains <child>` in graph `<parent>`.
  - `remove_containment(store, space, parent: &str, child: &str) -> Result<(), ResourceError>` — `DELETE DATA` that triple.
  - `container_is_empty(store, space, path: &str) -> Result<bool, ResourceError>` — true if the container has no `ldp:contains` triple.
  - `ensure_ancestors(store, space, request_path: &str) -> Result<(), ResourceError>` — walk up via `parent_container`; for each ancestor ensure the container exists and link `parent ldp:contains child`. Terminates at root.
  - `provision_root(store, space) -> Result<(), ResourceError>` — `ensure_container(store, space, "/")`.

- [ ] **Step 1: Write failing tests**

```rust
// add to src/container.rs tests module
use crate::{space::StorageSpace, store::OxigraphStore};

fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

#[tokio::test]
async fn ensure_ancestors_creates_chain_and_links() {
    let store = OxigraphStore::in_memory().unwrap();
    let space = sp();
    ensure_ancestors(&store, &space, "/a/b/c").await.unwrap();

    // /a/b/ contains /a/b/c
    assert!(!container_is_empty(&store, &space, "/a/b/").await.unwrap());
    // /a/ contains /a/b/
    assert!(!container_is_empty(&store, &space, "/a/").await.unwrap());
    // root contains /a/
    assert!(!container_is_empty(&store, &space, "/").await.unwrap());
    // /a/b/ is typed as a container (its graph is non-empty with type triples)
    let g = crate::resource::get_rdf(&store, &space, "/a/b/").await.unwrap().unwrap();
    assert!(g.iter().any(|t| t.predicate.as_str() == RDF_TYPE
        && matches!(&t.object, oxigraph::model::Term::NamedNode(n) if n.as_str() == LDP_BASIC_CONTAINER)));
}

#[tokio::test]
async fn add_then_remove_containment_toggles_emptiness() {
    let store = OxigraphStore::in_memory().unwrap();
    let space = sp();
    ensure_container(&store, &space, "/c/").await.unwrap();
    assert!(container_is_empty(&store, &space, "/c/").await.unwrap());
    add_containment(&store, &space, "/c/", "/c/x").await.unwrap();
    assert!(!container_is_empty(&store, &space, "/c/").await.unwrap());
    remove_containment(&store, &space, "/c/", "/c/x").await.unwrap();
    assert!(container_is_empty(&store, &space, "/c/").await.unwrap());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test container::`
Expected: FAIL — functions undefined.

- [ ] **Step 3: Implement the store ops**

```rust
// src/container.rs (add near the top, below the consts)
use crate::{space::StorageSpace, store::SparqlStore, resource::ResourceError};

pub async fn ensure_container(
    store: &dyn SparqlStore, space: &StorageSpace, path: &str,
) -> Result<(), ResourceError> {
    let c = space.graph_iri(path)?;
    let update = format!(
        "INSERT DATA {{ GRAPH <{c}> {{ \
         <{c}> <{RDF_TYPE}> <{LDP_CONTAINER}> . \
         <{c}> <{RDF_TYPE}> <{LDP_BASIC_CONTAINER}> }} }}",
    );
    store.update(&update).await?;
    Ok(())
}

pub async fn add_containment(
    store: &dyn SparqlStore, space: &StorageSpace, parent: &str, child: &str,
) -> Result<(), ResourceError> {
    let p = space.graph_iri(parent)?;
    let c = space.graph_iri(child)?;
    store.update(&format!(
        "INSERT DATA {{ GRAPH <{p}> {{ <{p}> <{LDP_CONTAINS}> <{c}> }} }}",
    )).await?;
    Ok(())
}

pub async fn remove_containment(
    store: &dyn SparqlStore, space: &StorageSpace, parent: &str, child: &str,
) -> Result<(), ResourceError> {
    let p = space.graph_iri(parent)?;
    let c = space.graph_iri(child)?;
    store.update(&format!(
        "DELETE DATA {{ GRAPH <{p}> {{ <{p}> <{LDP_CONTAINS}> <{c}> }} }}",
    )).await?;
    Ok(())
}

pub async fn container_is_empty(
    store: &dyn SparqlStore, space: &StorageSpace, path: &str,
) -> Result<bool, ResourceError> {
    let c = space.graph_iri(path)?;
    let triples = store.query_triples(&format!(
        "CONSTRUCT {{ <{c}> <{LDP_CONTAINS}> ?x }} \
         WHERE {{ GRAPH <{c}> {{ <{c}> <{LDP_CONTAINS}> ?x }} }}",
    )).await?;
    Ok(triples.is_empty())
}

pub async fn ensure_ancestors(
    store: &dyn SparqlStore, space: &StorageSpace, request_path: &str,
) -> Result<(), ResourceError> {
    let mut child = request_path.to_string();
    while let Some(parent) = parent_container(&child) {
        ensure_container(store, space, &parent).await?;
        add_containment(store, space, &parent, &child).await?;
        child = parent;
    }
    Ok(())
}

pub async fn provision_root(
    store: &dyn SparqlStore, space: &StorageSpace,
) -> Result<(), ResourceError> {
    ensure_container(store, space, "/").await
}
```

- [ ] **Step 4: Run tests**

Run: `nix develop -c cargo test container::` → PASS (4). Clippy clean, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/container.rs
git commit -m "feat: container store ops (ensure/containment/ancestors/root)"
```

---

### Task 3: Resource writes maintain containment; root provisioning + root route

**Files:**
- Modify: `src/http.rs` (PUT/DELETE resource paths call container ops; add `/` route), `src/main.rs` (provision root at startup)
- Test: inline tests in `src/http.rs`

**Interfaces:**
- Consumes: `container::{ensure_ancestors, remove_containment, parent_container, provision_root}`.
- Produces: no new public API. Behavior:
  - `PUT /a/b/c` (resource, non-container path) → `ensure_ancestors("/a/b/c")` then `put_rdf`; the parent now `ldp:contains` the resource.
  - `DELETE /a/b/c` (resource) → `delete_rdf`; if it existed, `remove_containment(parent_container("/a/b/c"), "/a/b/c")`.
  - `GET /` works (root container) — add a `/` route mapping to the same GET handler.
  - `main.rs` calls `provision_root` before serving.

- [ ] **Step 1: Write failing tests**

```rust
// src/http.rs tests — helper that provisions root
async fn provisioned_app() -> axum::Router {
    let store = std::sync::Arc::new(crate::store::OxigraphStore::in_memory().unwrap());
    let space = crate::space::StorageSpace::new("https://pod.toph.so/").unwrap();
    crate::container::provision_root(store.as_ref(), &space).await.unwrap();
    router(AppState { store, space })
}

#[tokio::test]
async fn put_deep_resource_creates_ancestor_containment() {
    let app = provisioned_app().await;
    let put = Request::builder().method("PUT").uri("/a/b/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    // GET the parent container /a/b/ — it must list the doc via ldp:contains
    let res = app.oneshot(Request::builder().method("GET").uri("/a/b/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(body.contains("ldp#contains"));
    assert!(body.contains("https://pod.toph.so/a/b/doc"));
}

#[tokio::test]
async fn delete_resource_removes_containment() {
    let app = provisioned_app().await;
    let put = Request::builder().method("PUT").uri("/a/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    app.clone().oneshot(put).await.unwrap();
    let del = Request::builder().method("DELETE").uri("/a/doc").body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);

    let res = app.oneshot(Request::builder().method("GET").uri("/a/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert!(!body_string(res).await.contains("https://pod.toph.so/a/doc"));
}

#[tokio::test]
async fn get_root_container_is_200() {
    let app = provisioned_app().await;
    let res = app.oneshot(Request::builder().method("GET").uri("/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_string(res).await.contains("ldp#BasicContainer"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test http::`
Expected: FAIL — root route missing / no containment maintained.

- [ ] **Step 3: Wire containment into the resource handlers + add root route**

In `src/http.rs`:
- Add `/` route: `Router::new().route("/", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete)).route("/{*path}", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete)).with_state(state)` — but `handle_post` is added in Task 5; for THIS task use `get(handle_get).put(handle_put).delete(handle_delete)` on both routes (add `.post` in Task 5).
- The `/` route's `Path` extractor: for the root, there is no `{*path}` capture. Give the root its own tiny handlers that call the shared logic with `request_path = "/"`. Simplest: extract the shared body into functions taking `req_path: &str`, and have both the wildcard handler (`Path(path)` → `format!("/{path}")`) and a root handler (`"/"`) call them.

```rust
// refactor handle_get/put/delete to take an explicit req_path via small wrappers.
// Wildcard handlers:
async fn handle_get(State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap) -> Response {
    get_impl(st, format!("/{path}"), headers).await
}
async fn handle_get_root(State(st): State<AppState>, headers: HeaderMap) -> Response {
    get_impl(st, "/".to_string(), headers).await
}
// ...and similarly put/delete wrappers calling put_impl/delete_impl.
// Route:
// .route("/", get(handle_get_root).put(handle_put_root).delete(handle_delete_root))
// .route("/{*path}", get(handle_get).put(handle_put).delete(handle_delete))
```

- In `put_impl` (the shared PUT logic), for a **non-container** path (`!container::is_container_path(&req_path)`), call `container::ensure_ancestors(st.store.as_ref(), &st.space, &req_path).await` (map error to its status) BEFORE `put_rdf`. Container paths are handled in Task 4 — for now, a PUT to a container path may fall through to the plain `put_rdf`; Task 4 replaces that branch.
- In `delete_impl`, after a successful `delete_rdf` returning `true`, if `let Some(parent) = container::parent_container(&req_path)`, call `container::remove_containment(st.store.as_ref(), &st.space, &parent, &req_path).await` (log/propagate error as 500).

Concrete `put_impl` resource branch:

```rust
async fn put_impl(st: AppState, req_path: String, headers: HeaderMap, body: Bytes) -> Response {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_content_type(ct) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let g = match st.space.graph_iri(&req_path) {
        Ok(g) => g,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    // (conditional-request precondition block from Plan 2 stays here, unchanged)
    let triples = match parse(&body, fmt, &g) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // Task 4 will branch container paths here; for now, resource path only:
    if let Err(e) = container::ensure_ancestors(st.store.as_ref(), &st.space, &req_path).await {
        return (put_status(&e), e.to_string()).into_response();
    }
    match put_rdf(st.store.as_ref(), &st.space, &req_path, &triples).await {
        Ok(()) => (StatusCode::CREATED, [(header::LOCATION, g)]).into_response(),
        Err(e) => (put_status(&e), e.to_string()).into_response(),
    }
}
```

(Keep the Plan-2 conditional-request precondition block in `put_impl` exactly as it was. `delete_impl` mirrors the existing `handle_delete` body plus the `remove_containment` follow-up.)

- [ ] **Step 4: Provision root in `main.rs`**

```rust
// src/main.rs — after building `state`, before serving:
let state = AppState {
    store: std::sync::Arc::new(OxigraphStore::in_memory().expect("store")),
    space: StorageSpace::new(base).expect("valid POD_BASE_URI (absolute, trailing slash)"),
};
sparql_pod::container::provision_root(state.store.as_ref(), &state.space)
    .await.expect("provision root container");
```

- [ ] **Step 5: Run tests**

Run: `nix develop -c cargo test` → PASS (all, incl. the 3 new). Clippy clean, zero warnings. Confirm the axum wildcard capture preserves the trailing slash for container paths (a request to `/a/b/` yields `path = "a/b/"` → `req_path = "/a/b/"`); if axum strips it, adjust the route/normalization and note it.

- [ ] **Step 6: Commit**

```bash
git add src/http.rs src/main.rs
git commit -m "feat: maintain ldp:contains on resource writes; provision + route root"
```

---

### Task 4: Container GET / PUT (409) / DELETE (409-if-non-empty)

**Files:**
- Modify: `src/http.rs` (container branch in PUT + DELETE), `src/container.rs` (helper: does a triple set touch containment?)
- Test: inline tests in `src/http.rs`

**Interfaces:**
- Consumes: `container::{is_container_path, container_is_empty, ensure_container, ensure_ancestors, remove_containment, parent_container, LDP_CONTAINS}`, `resource::get_rdf`.
- Produces:
  - `container::body_sets_containment(triples: &[Triple]) -> bool` — true if any triple has predicate `ldp:contains` (client attempting to set server-managed containment).
  - HTTP behavior:
    - `PUT /foo/` (container): `409` if `body_sets_containment`; else `ensure_ancestors`, then store user triples **plus** re-asserted server-managed type triples **plus** preserved existing `ldp:contains`; `201`/`204` with `Location`.
    - `DELETE /foo/` (container): `409` if `!container_is_empty`; else `delete_rdf` (drops the graph) + `remove_containment(parent, "/foo/")`; `204`.
    - `GET /foo/`: unchanged (`get_rdf` returns the container graph incl. type + containment) — already works from Task 3; add a test.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test]
async fn put_container_rejecting_client_containment_is_409() {
    let app = provisioned_app().await;
    let put = Request::builder().method("PUT").uri("/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(
            "<https://pod.toph.so/box/> <http://www.w3.org/ns/ldp#contains> <https://pod.toph.so/box/x> .",
        )).unwrap();
    assert_eq!(app.oneshot(put).await.unwrap().status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn put_container_stores_user_triples_and_keeps_type() {
    let app = provisioned_app().await;
    let put = Request::builder().method("PUT").uri("/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<https://pod.toph.so/box/> <http://purl.org/dc/terms/title> \"My Box\" .")).unwrap();
    assert_eq!(app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
    let res = app.oneshot(Request::builder().method("GET").uri("/box/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    let body = body_string(res).await;
    assert!(body.contains("My Box"));                 // user triple kept
    assert!(body.contains("ldp#BasicContainer"));     // server type re-asserted
}

#[tokio::test]
async fn delete_nonempty_container_is_409_empty_is_204() {
    let app = provisioned_app().await;
    // create a child → parent /box/ becomes non-empty
    app.clone().oneshot(Request::builder().method("PUT").uri("/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
    let del_full = Request::builder().method("DELETE").uri("/box/").body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(del_full).await.unwrap().status(), StatusCode::CONFLICT);
    // remove child, then container is deletable
    app.clone().oneshot(Request::builder().method("DELETE").uri("/box/doc").body(Body::empty()).unwrap()).await.unwrap();
    let del_empty = Request::builder().method("DELETE").uri("/box/").body(Body::empty()).unwrap();
    assert_eq!(app.oneshot(del_empty).await.unwrap().status(), StatusCode::NO_CONTENT);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test http::`
Expected: FAIL — container branches not implemented.

- [ ] **Step 3: Implement**

Add the containment-probe helper to `src/container.rs`:

```rust
use oxigraph::model::Triple;

pub fn body_sets_containment(triples: &[Triple]) -> bool {
    triples.iter().any(|t| t.predicate.as_str() == LDP_CONTAINS)
}
```

In `src/http.rs` `put_impl`, branch on container paths after parsing `triples`:

```rust
if container::is_container_path(&req_path) {
    if container::body_sets_containment(&triples) {
        return StatusCode::CONFLICT.into_response();
    }
    if let Err(e) = container::ensure_ancestors(st.store.as_ref(), &st.space, &req_path).await {
        return (put_status(&e), e.to_string()).into_response();
    }
    // preserve existing containment, re-assert type, add user triples (minus any type/contains the server owns)
    let existing = match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(v) => v.unwrap_or_default(),
        Err(e) => return (put_status(&e), e.to_string()).into_response(),
    };
    let kept_containment: Vec<_> = existing.into_iter()
        .filter(|t| t.predicate.as_str() == container::LDP_CONTAINS)
        .collect();
    // Build the new graph: user triples + kept containment; then ensure_container re-adds type.
    let mut merged = triples.clone();
    merged.extend(kept_containment);
    if let Err(e) = put_rdf(st.store.as_ref(), &st.space, &req_path, &merged).await {
        return (put_status(&e), e.to_string()).into_response();
    }
    if let Err(e) = container::ensure_container(st.store.as_ref(), &st.space, &req_path).await {
        return (put_status(&e), e.to_string()).into_response();
    }
    let g = st.space.graph_iri(&req_path).unwrap_or_default();
    return (StatusCode::CREATED, [(header::LOCATION, g)]).into_response();
}
// ...existing resource branch (ensure_ancestors + put_rdf) follows...
```

In `src/http.rs` `delete_impl`, branch container paths:

```rust
if container::is_container_path(&req_path) {
    match container::container_is_empty(st.store.as_ref(), &st.space, &req_path).await {
        Ok(false) => return StatusCode::CONFLICT.into_response(),
        Ok(true) => {}
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    // is the container present at all? (root always is)
    let present = matches!(get_rdf(st.store.as_ref(), &st.space, &req_path).await, Ok(Some(_)));
    if !present {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(e) = crate::resource::delete_rdf(st.store.as_ref(), &st.space, &req_path).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Some(parent) = container::parent_container(&req_path) {
        let _ = container::remove_containment(st.store.as_ref(), &st.space, &parent, &req_path).await;
    }
    return StatusCode::NO_CONTENT.into_response();
}
// ...existing resource DELETE branch follows...
```

- [ ] **Step 4: Run tests**

Run: `nix develop -c cargo test` → PASS (all). Clippy clean, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/http.rs src/container.rs
git commit -m "feat: container PUT (409 on containment) / DELETE (409 non-empty) / GET"
```

---

### Task 5: `POST` to a container + `Slug`

**Files:**
- Modify: `src/http.rs` (add `handle_post`/`handle_post_root` + wire `.post(...)` onto both routes), `src/container.rs` (slug sanitize + unique child name), `Cargo.toml` (add `uuid`)
- Test: inline tests in `src/http.rs`

**Interfaces:**
- Consumes: `container::{is_container_path, ensure_ancestors, add_containment}`, `resource::put_rdf`, `rdf::{format_for_content_type, parse}`, `uuid`.
- Produces:
  - `container::child_name(slug: Option<&str>) -> String` — sanitize the Slug to `[A-Za-z0-9._-]` (drop other chars); if the result is empty (or no slug), return a fresh `uuid v4` string. (Uniqueness against existing resources is resolved in the handler.)
  - HTTP: `POST /foo/` — `405`/`400` if the target isn't a container; parse body by `Content-Type` (415 if unsupported); compute a unique child path `/foo/<name>` (append a `uuid` suffix if the candidate already exists); `ensure_ancestors` + `put_rdf` + `add_containment(parent="/foo/", child)`; return `201` + `Location: <child graph IRI>`.

- [ ] **Step 1: Add `uuid`**

Run: `nix develop -c cargo add uuid --features v4`

- [ ] **Step 2: Write failing tests**

```rust
#[tokio::test]
async fn post_with_slug_creates_named_child() {
    let app = provisioned_app().await;
    let post = Request::builder().method("POST").uri("/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    let res = app.clone().oneshot(post).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/box/note");
    // the child is retrievable and the container lists it
    let got = app.oneshot(Request::builder().method("GET").uri("/box/note").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(got.status(), StatusCode::OK);
}

#[tokio::test]
async fn post_slug_collision_gets_distinct_url() {
    let app = provisioned_app().await;
    let mk = || Request::builder().method("POST").uri("/box/")
        .header(header::CONTENT_TYPE, "text/turtle").header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    let loc1 = app.clone().oneshot(mk()).await.unwrap().headers().get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
    let loc2 = app.oneshot(mk()).await.unwrap().headers().get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
    assert_ne!(loc1, loc2);
}

#[tokio::test]
async fn post_to_non_container_is_conflict() {
    let app = provisioned_app().await;
    // /doc is a resource path (no trailing slash) → POST not allowed there
    let post = Request::builder().method("POST").uri("/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(app.oneshot(post).await.unwrap().status(), StatusCode::CONFLICT);
}
```

- [ ] **Step 3: Implement `child_name` + handlers**

```rust
// src/container.rs
pub fn child_name(slug: Option<&str>) -> String {
    let cleaned: String = slug.unwrap_or("").chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if cleaned.is_empty() { uuid::Uuid::new_v4().to_string() } else { cleaned }
}
```

```rust
// src/http.rs — POST handlers + shared impl
async fn handle_post(State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap, body: Bytes) -> Response {
    post_impl(st, format!("/{path}"), headers, body).await
}
async fn handle_post_root(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    post_impl(st, "/".to_string(), headers, body).await
}

async fn post_impl(st: AppState, container_path: String, headers: HeaderMap, body: Bytes) -> Response {
    if !container::is_container_path(&container_path) {
        return StatusCode::CONFLICT.into_response(); // POST target must be a container
    }
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_content_type(ct) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let slug = headers.get("slug").and_then(|v| v.to_str().ok());
    // unique child path
    let mut name = container::child_name(slug);
    let mut child_path = format!("{container_path}{name}");
    if matches!(get_rdf(st.store.as_ref(), &st.space, &child_path).await, Ok(Some(_))) {
        name = format!("{name}-{}", uuid::Uuid::new_v4());
        child_path = format!("{container_path}{name}");
    }
    let g = match st.space.graph_iri(&child_path) {
        Ok(g) => g,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let triples = match parse(&body, fmt, &g) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if let Err(e) = container::ensure_ancestors(st.store.as_ref(), &st.space, &child_path).await {
        return (put_status(&e), e.to_string()).into_response();
    }
    match put_rdf(st.store.as_ref(), &st.space, &child_path, &triples).await {
        Ok(()) => (StatusCode::CREATED, [(header::LOCATION, g)]).into_response(),
        Err(e) => (put_status(&e), e.to_string()).into_response(),
    }
}
```

Wire `.post(...)` onto both routes:
```rust
.route("/", get(handle_get_root).put(handle_put_root).post(handle_post_root).delete(handle_delete_root))
.route("/{*path}", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete))
```

(`ensure_ancestors(child_path)` links the child into `container_path`, so no separate `add_containment` call is needed — its first iteration adds `container_path ldp:contains child`.)

- [ ] **Step 4: Run tests**

Run: `nix develop -c cargo test` → PASS (all). Clippy clean, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/http.rs src/container.rs
git commit -m "feat: POST to container with Slug-based child naming"
```

---

## Self-Review

**Spec coverage (Plan 3 scope):**
- Container = trailing-slash URL, own graph, typed (spec §5) → Tasks 1, 2. ✓
- Server-managed stored `ldp:contains` (spec §5) → Task 2 (ops), Task 3 (resource writes), Task 4 (container PUT preserves). ✓
- Auto-create ancestors + root provisioning (design decision) → Tasks 2, 3. ✓
- Solid MUST: DELETE non-empty container → 409 → Task 4. ✓
- Solid MUST: PUT/PATCH changing containment → 409 → Task 4 (`body_sets_containment`). ✓
- Solid MUST: delete contained resource removes containment triple → Task 3 (`remove_containment`). ✓
- Container GET representation (type + containment + user triples via conneg) → Task 3/4 tests. ✓
- POST + Slug (secondary path) → Task 5. ✓
- Root route `/` (never handled in Plans 1–2) → Task 3. ✓
- **Deferred to later plans (explicitly out of scope):** N3-Patch (incl. PATCH-changes-containment → 409); blobs + `object_store` + `urn:pod:sys:`; auth/DPoP; WAC/PRP/PDP (the PRP container-walk builds on `parent_container` from Task 1); RFC-7232 conditional gaps carried from Plan 2; cross-graph write atomicity.

**Placeholder scan:** No "TBD/handle errors/similar-to". The one API-verification point (axum wildcard preserving the trailing slash for container paths) is called out in Task 3 Step 5 with the exact expectation and a "adjust + note" instruction. All handler/store code is shown in full.

**Type consistency:** `container::{is_container_path, parent_container, ensure_container, add_containment, remove_containment, container_is_empty, ensure_ancestors, provision_root, body_sets_containment, child_name}`, the four `LDP_*`/`RDF_TYPE` consts, and `ResourceError` (reused, no new variant needed — all container ops return `Result<_, ResourceError>` via `graph_iri`'s `SpaceError: From` and `SparqlStore`'s `StoreError: From`) are used consistently across Tasks 1–5. HTTP `*_impl(st, req_path, ...)` shared-body refactor (Task 3) is consumed by Tasks 4–5. ✓

**Refactor note (Task 3):** extracting `get_impl`/`put_impl`/`delete_impl` (+ `post_impl` in Task 5) from the Plan-2 handlers is a prerequisite for the root route and container branching. Keep the Plan-2 conditional-request precondition logic intact inside `put_impl`.
