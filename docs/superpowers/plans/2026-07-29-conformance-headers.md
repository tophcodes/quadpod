# Response Headers and `OPTIONS` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit `WAC-Allow` on reads, answer `OPTIONS`, and reflect CORS headers onto every response, closing conformance ranks 2, 4 and 5.

**Architecture:** A `from_fn` middleware wrapping the existing auth layer adds the CORS fields to whatever response comes back, including the `401` the auth layer itself produces. An `OPTIONS` route answers from the request URL's shape alone, without authorizing. `wac::guard::authorize` stops discarding its decision and returns it, so a read can describe the access it was granted from the same evaluation that granted it.

**Tech Stack:** Rust, axum 0.8, oxigraph. No new dependencies.

## Global Constraints

- **Design spec:** [`docs/superpowers/specs/2026-07-29-conformance-headers-design.md`](../specs/2026-07-29-conformance-headers-design.md). Section references below (§3.1 etc.) point there.
- **No new crates.** `Cargo.toml` is unchanged by this plan.
- **Build and test command:** `nix develop -c cargo test`. Bare `cargo` does not work in this repo — oxigraph needs bindgen/libclang, which only the flake dev shell provides.
- **`Vary` values are compared case-sensitively by the test suite.** Emit the literal `Origin`, capital O. `header::ORIGIN.as_str()` is lowercase `origin` and will fail `match header Vary contains 'Origin'`.
- **`Vary` is appended, never inserted.** `get_impl` and `legacy_graph_read` already set `Vary: Accept`; `insert` would drop it.
- **The ACL URL shape is `/.aux/{path}.acl`** — `/foo` → `/.aux/foo.acl`, `/box/` → `/.aux/box/.acl`, root → `/.aux/.acl`. Pinned by `src/space.rs:577` (`aux_urls_have_the_documented_shape`).
- **No `Access-Control-Allow-Credentials` and no `Access-Control-Max-Age`** anywhere in this plan (§3.2). Adding either is out of scope.
- **Comments state present facts.** No "moved from", "used to be", "this task", or plan references in source. See the repo's `CLAUDE.md`.

---

## File Structure

| File | Change | Responsible for |
|---|---|---|
| `src/http.rs` | Modify | `cors_layer`, the `OPTIONS` handlers, `allowed_methods`, `wac_allow_value`, `with_read_headers`, router wiring, and the unit tests for all of it |
| `src/wac/mod.rs` | Modify | the `Decision` type |
| `src/wac/guard.rs` | Modify | `authorize` returns `Decision` |
| `tests/route_coverage.rs` | Modify | records why `OPTIONS` is exempt from the unauthenticated-refusal sweep |
| `docs/conformance-findings.md` | Modify | the third run's numbers |

Everything lands in files that already exist. `src/http.rs` is large (3788 lines) but is the established home for the HTTP edge, and this work is HTTP-edge work; splitting it is out of scope.

**Task order:** Tasks 1 and 2 are independent of each other. Task 4 depends on Task 3. Task 5 depends on all of them.

---

### Task 1: CORS middleware

**Files:**
- Modify: `src/http.rs` — imports (line 8-19), `router` (line 30-37), new `cors_layer` and `EXPOSED_HEADERS`
- Test: `src/http.rs`, in the existing `#[cfg(test)] mod tests` block (starts line ~874)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `pub async fn cors_layer(req: axum::extract::Request, next: axum::middleware::Next) -> Response`, and the constant `EXPOSED_HEADERS: &str`. Task 4 adds `WAC-Allow` to that constant's value — it is already listed there from this task, so Task 4 does not touch it.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `src/http.rs`:

```rust
#[tokio::test]
async fn no_origin_means_no_cors_headers() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    assert!(res.headers().get(header::ACCESS_CONTROL_EXPOSE_HEADERS).is_none());
}

#[tokio::test]
async fn an_origin_is_reflected_and_vary_keeps_accept() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/")
        .header(header::ORIGIN, "https://app.example")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://app.example"
    );
    // Both, and `Origin` with a capital O: the suite compares the field value
    // as a case-sensitive string.
    let vary: Vec<&str> = res.headers().get_all(header::VARY)
        .iter().map(|v| v.to_str().unwrap()).collect();
    assert!(vary.contains(&"Accept"), "{vary:?}");
    assert!(vary.contains(&"Origin"), "{vary:?}");
}

#[tokio::test]
async fn expose_headers_is_enumerated_and_not_a_wildcard() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/")
        .header(header::ORIGIN, "https://app.example")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    let exposed = res.headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS).unwrap().to_str().unwrap();
    assert_ne!(exposed, "*");
    assert!(exposed.contains("ETag"), "{exposed}");
    assert!(exposed.contains("WAC-Allow"), "{exposed}");
}

// The reason the middleware wraps `auth_layer` instead of sitting inside it:
// `protocol/cors/simple-requests` asserts the CORS fields on an anonymous
// request, which this pod answers 401.
#[tokio::test]
async fn cors_headers_survive_a_401() {
    let f = fixture().await;
    let get = Request::builder().method("GET").uri("/")
        .header(header::ORIGIN, "https://app.example")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://app.example"
    );
    assert!(res.headers().get(header::ACCESS_CONTROL_EXPOSE_HEADERS).is_some());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::` and look for the four new names.
Expected: `no_origin_means_no_cors_headers` PASSES (nothing sets the headers yet); the other three FAIL on `unwrap()` of a `None` header.

That one already-passing test is not a mistake — it pins the absence, and it must keep passing after Step 3.

- [ ] **Step 3: Implement**

Extend the `axum` import at `src/http.rs:9` so `HeaderValue` is in scope:

```rust
use axum::{Router, routing::get, extract::{State, Path}, body::Bytes, Extension,
    http::{StatusCode, HeaderMap, HeaderValue, header, header::{IF_MATCH, IF_NONE_MATCH}}, response::{IntoResponse, Response}};
```

Add above `router`:

```rust
/// The response headers a browser may read off a cross-origin response.
///
/// Enumerated rather than `*` because a wildcard tells a client nothing it can
/// act on, and because every name here is a field some handler on this pod
/// actually emits. `protocol/cors/enumerate-headers` asserts both that the
/// field is present and that it is not `*`.
const EXPOSED_HEADERS: &str =
    "Allow, Content-Type, ETag, Link, Location, Vary, WAC-Allow, Warning, WWW-Authenticate";

/// Reflect a request's `Origin` onto its response.
///
/// Wraps `auth_layer` rather than sitting inside it, because the CORS fields
/// are required on the `401` that layer produces for an anonymous request
/// (`protocol/cors/simple-requests`), and a layer inside it never sees that
/// response.
///
/// No `Access-Control-Allow-Credentials`. This pod authenticates from an
/// `Authorization` header, which CORS treats as a request header to allow, not
/// as a credential to flag; the flag exists for cookies and TLS client
/// certificates, which this pod does not accept. Setting it is what would make
/// an origin's ambient authority usable here, so reflecting an arbitrary origin
/// without it grants a foreign page nothing: the browser attaches no credential
/// of its own, and a page that already holds a token never needed CORS to use
/// it.
pub async fn cors_layer(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).cloned();
    let mut res = next.run(req).await;
    let Some(origin) = origin else { return res };
    let h = res.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    // `append`, not `insert`: a negotiated read has already set `Vary: Accept`,
    // and replacing it would make a cache serve the wrong representation to fix
    // a CORS assertion. The literal spelling matters too — the suite compares
    // this field value as a case-sensitive string, and `header::ORIGIN` is
    // lowercase.
    h.append(header::VARY, HeaderValue::from_static("Origin"));
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSED_HEADERS),
    );
    res
}
```

`HeaderValue::from_static` requires a `&'static str`, which `EXPOSED_HEADERS` is.

Wire it as the outermost layer — `Router::layer` wraps everything built so far, so the *last* `.layer` call is the outermost:

```rust
pub fn router(state: AppState) -> Router {
    // axum 0.8 wildcard capture syntax: "/{*path}" (NOT the old "/*path").
    Router::new()
        .route("/", get(handle_get_root).put(handle_put_root).post(handle_post_root).delete(handle_delete_root))
        .route("/{*path}", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_layer))
        .layer(axum::middleware::from_fn(cors_layer))
        .with_state(state)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib http::tests::`
Expected: all four PASS.

- [ ] **Step 5: Run the whole suite**

Run: `nix develop -c cargo test`
Expected: PASS. Nothing else asserts on `Vary`, but the append-vs-insert choice is exactly the kind of change that breaks a negotiation test, so the full run is the check.

- [ ] **Step 6: Commit**

```bash
git add src/http.rs
git commit -m "feat: reflect the request Origin onto every response"
```

---

### Task 2: `OPTIONS`

**Files:**
- Modify: `src/http.rs` — `allowed_methods` (line ~94-107), `router`, new `handle_options_root` / `handle_options` / `options_impl`
- Modify: `tests/route_coverage.rs` — lines 63-92 and 96-118
- Test: `src/http.rs` tests module

**Interfaces:**
- Consumes: nothing from other tasks. Independent of Task 1 — but the `OPTIONS` response only carries `Access-Control-Allow-Origin` once Task 1 is in, so run both before judging a conformance result.
- Produces: `fn options_impl(target: Target, headers: HeaderMap) -> Response`, and `allowed_methods` now includes `OPTIONS` in every arm.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `src/http.rs`:

```rust
// Preflight carries no credentials by construction — the browser sends it
// before, and without, the credentialed request.
#[tokio::test]
async fn options_answers_without_credentials() {
    let f = fixture().await;
    let req = Request::builder().method("OPTIONS").uri("/")
        .header(header::ORIGIN, "https://app.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(body_string(res).await, "");
}

#[tokio::test]
async fn options_mirrors_exactly_the_requested_headers() {
    let f = fixture().await;
    let req = Request::builder().method("OPTIONS").uri("/")
        .header(header::ORIGIN, "https://app.example")
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "X-CUSTOM, Content-Type")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(req).await.unwrap();
    let allowed = res.headers()
        .get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap().to_str().unwrap();
    assert!(allowed.contains("X-CUSTOM"), "{allowed}");
    assert!(allowed.contains("Content-Type"), "{allowed}");
    // The negative half: `accept-acah` asserts Accept is ABSENT when it was
    // not requested, in an otherwise identical request. A fixed list fails it.
    assert!(!allowed.contains("Accept"), "{allowed}");
}

#[tokio::test]
async fn options_omits_allow_headers_when_none_were_requested() {
    let f = fixture().await;
    let req = Request::builder().method("OPTIONS").uri("/")
        .header(header::ORIGIN, "https://app.example")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(res.headers().get(header::ACCESS_CONTROL_ALLOW_HEADERS).is_none());
}

#[tokio::test]
async fn options_advertises_the_methods_the_target_accepts() {
    let f = fixture().await;

    let on_container = Request::builder().method("OPTIONS").uri("/box/")
        .body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(on_container).await.unwrap();
    let allow = res.headers().get(header::ALLOW).unwrap().to_str().unwrap().to_string();
    let acam = res.headers()
        .get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap().to_str().unwrap();
    assert!(allow.contains("POST"), "{allow}");
    assert!(allow.contains("OPTIONS"), "{allow}");
    assert_eq!(allow, acam, "Allow and Access-Control-Allow-Methods must agree");

    let on_resource = Request::builder().method("OPTIONS").uri("/foo")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(on_resource).await.unwrap();
    let allow = res.headers().get(header::ALLOW).unwrap().to_str().unwrap();
    assert!(!allow.contains("POST"), "{allow}");
    assert!(allow.contains("OPTIONS"), "{allow}");
}

// `classify` still decides what a path means: the reserved namespace is not
// storage, and OPTIONS does not get to pretend otherwise.
#[tokio::test]
async fn options_on_the_unallocated_reserved_namespace_is_404() {
    let f = fixture().await;
    let req = Request::builder().method("OPTIONS").uri("/.aux/bogus/x")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::options`
Expected: FAIL — every one returns `405 Method Not Allowed`, because no route serves `OPTIONS`.

- [ ] **Step 3: Implement**

Replace `allowed_methods` (`src/http.rs:94-107`) — the doc comment's claim about `OPTIONS` becomes false and must go:

```rust
/// The methods a target actually accepts, as an `Allow` field value.
///
/// Derived from the router's own shape rather than a fixed list: a container
/// is the only thing `POST` may address, and the root is the only container
/// `DELETE` refuses (`delete_impl`). `OPTIONS` is accepted everywhere — it
/// answers from the request URL alone and needs no representation to describe.
fn allowed_methods(target: &Target) -> &'static str {
    match target {
        Target::Container(c) if c.as_resource().parent().is_none() => "GET, HEAD, POST, PUT, OPTIONS",
        Target::Container(_) => "GET, HEAD, POST, PUT, DELETE, OPTIONS",
        Target::Resource(_) | Target::Aux(_) => "GET, HEAD, PUT, DELETE, OPTIONS",
    }
}
```

Add the handlers next to the other `handle_*` pairs:

```rust
/// Answer a CORS preflight — and a bare `OPTIONS`, which the suite also sends
/// (`protocol/cors/acao-vary` omits `Access-Control-Request-Method`).
///
/// Deliberately unauthorized. A preflight arrives without credentials by
/// construction, so demanding them would make this pod unusable from a browser;
/// and the answer is derived entirely from the request URL's shape —
/// `allowed_methods` takes a `Target` and never touches the store — so it
/// discloses nothing about what exists. That is the same line `post_impl` draws
/// when it answers `409` from the path shape rather than let `POST` become an
/// existence oracle.
///
/// `Access-Control-Allow-Headers` mirrors what was asked for rather than
/// listing a fixed set: `protocol/cors/accept-acah` sends two otherwise
/// identical preflights and requires `Accept` to be absent from the answer to
/// the one that did not request it.
fn options_impl(target: &Target, headers: &HeaderMap) -> Response {
    let mut out = HeaderMap::new();
    let methods = allowed_methods(target);
    out.insert(header::ALLOW, HeaderValue::from_static(methods));
    out.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(methods));
    if let Some(requested) = headers.get("access-control-request-headers") {
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
    }
    (StatusCode::NO_CONTENT, out).into_response()
}

async fn handle_options_root(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match classify(&st.space, "/") {
        Ok(target) => options_impl(&target, &headers),
        Err(code) => code.into_response(),
    }
}

async fn handle_options(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) => options_impl(&target, &headers),
        Err(code) => code.into_response(),
    }
}
```

The `format!("/{path}")` and the `classify` error handling above are the same shape `handle_get` (`src/http.rs:636-644`) and `handle_get_root` use. Keep them identical — a second derivation of a request path is exactly the drift this pod's `classify`-once rule exists to prevent.

Wire the routes:

```rust
        .route("/", get(handle_get_root).put(handle_put_root).post(handle_post_root).delete(handle_delete_root).options(handle_options_root))
        .route("/{*path}", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete).options(handle_options))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib http::tests::options`
Expected: all five PASS.

- [ ] **Step 5: Record the exemption in the route-coverage sweep**

`tests/route_coverage.rs` asserts every route and verb refuses an unauthenticated request. `OPTIONS` now deliberately does not, and that must be written down where a reader of the sweep will find it rather than left as a silent hole in the `methods` array.

In `no_route_serves_an_unauthenticated_request` (line ~72), extend the comment above `methods`:

```rust
    // HEAD is served by the same handler axum's `get()` route installs, so it
    // is guarded like GET — but this test exists to be structural, and a verb
    // that reaches a handler belongs in the list whether or not it currently
    // shares one. Only the status is asserted: a HEAD response has no body.
    //
    // OPTIONS is absent on purpose, and is the only such verb. A CORS
    // preflight carries no credentials by construction, and the answer is
    // derived from the request URL's shape alone — it reaches no store and so
    // reveals nothing a 404 for an unrouted path would not. See
    // `the_unallocated_reserved_namespace_serves_nothing_either`, which does
    // include it: OPTIONS is exempt from authorization, not from `classify`.
    let methods = ["GET", "HEAD", "PUT", "POST", "DELETE"];
```

In `the_unallocated_reserved_namespace_serves_nothing_either` (line ~101), add `OPTIONS` to the list, so the exemption is bounded by a test rather than by a comment:

```rust
    let methods = ["GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS"];
```

- [ ] **Step 6: Run the whole suite**

Run: `nix develop -c cargo test`
Expected: PASS, including both `route_coverage` tests.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs tests/route_coverage.rs
git commit -m "feat: answer OPTIONS from the request URL's shape"
```

---

### Task 3: `authorize` returns its decision

**Files:**
- Modify: `src/wac/mod.rs` — add `Decision` after `AccessModes`
- Modify: `src/wac/guard.rs` — `authorize` (line ~115-140)
- Modify: `src/http.rs` — every `authorize(...)` call site

**Interfaces:**
- Consumes: `AccessModes` and `Mode` from `src/wac/mod.rs`, `pdp::decide` and `prp::effective_acl` as they are.
- Produces: `pub struct Decision { pub user: AccessModes, pub public: AccessModes }` in `crate::wac`, and `pub async fn authorize(store, agent, target, mode) -> Result<Decision, Response>`. Task 4 consumes both.

This task changes no behaviour. The existing suite is the test: it must pass unchanged, both before and after.

- [ ] **Step 1: Add the `Decision` type**

In `src/wac/mod.rs`, after the `impl AccessModes` block:

```rust
/// What the governing ACL says about a target: for the agent who asked, and
/// for anyone at all.
///
/// Both halves come from one `prp` resolution and two `pdp::decide` calls, so
/// a response that reports access and the decision that granted it cannot
/// disagree — they are the same evaluation. `decide` is pure, so the second
/// call costs nothing beside the ancestor walk that produced the ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub user: AccessModes,
    pub public: AccessModes,
}
```

- [ ] **Step 2: Return it from `authorize`**

In `src/wac/guard.rs`, change the `use super::` line to bring `Decision` in:

```rust
use super::{pdp, prp, Decision, Mode};
```

and replace the tail of `authorize`:

```rust
pub async fn authorize(
    store: &dyn SparqlStore,
    agent: &Agent,
    target: &Target,
    mode: Mode,
) -> Result<Decision, Response> {
    let (subject, required) = match target {
        Target::Aux(a) => (a.subject().clone(), required_mode_for_aux(a.kind())),
        Target::Resource(r) => (r.clone(), mode),
        Target::Container(c) => (c.as_resource().clone(), mode),
    };

    let acl = match prp::effective_acl(store, &subject).await {
        Ok(Some(acl)) => acl,
        Ok(None) => return Err(deny(agent)),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    };

    let user = pdp::decide(&acl.triples, agent, &acl.governed_iri, acl.inherited);
    // An anonymous request has already computed the public answer: asking the
    // same question twice would double the cost of the one case that gains
    // nothing from it.
    let public = match agent {
        Agent::Public => user,
        Agent::WebId(_) => {
            pdp::decide(&acl.triples, &Agent::Public, &acl.governed_iri, acl.inherited)
        }
    };

    if user.allows(required) {
        Ok(Decision { user, public })
    } else {
        Err(deny(agent))
    }
}
```

Update `authorize`'s doc comment's first line to say what it now answers — "May `agent` perform `mode` on `target`, and what else may they and the public do?" — keeping the two existing paragraphs about auxiliaries unchanged.

- [ ] **Step 3: Find every call site and build**

Run: `rg -n 'authorize\(' src/`
Then: `nix develop -c cargo build`

Expected: errors only of the form `expected `()`, found `Decision``, one per call site. Fix each by binding or discarding:

- A caller that does not need the decision keeps its shape — `if let Err(res) = authorize(...).await { return ...; }` still compiles, because the `Ok` arm is unused.
- If a call site is written `authorize(...).await?;` in a function returning `Result<(), Response>`, it now needs `let _ = authorize(...).await?;`. Prefer naming it if the value is about to be used in Task 4.

Do **not** change `authorize_and_materialize`'s signature. It calls `authorize` internally for ancestor levels and has no use for the returned decision.

- [ ] **Step 4: Run the whole suite**

Run: `nix develop -c cargo test`
Expected: PASS, with no test changed. A failure here means the refactor changed behaviour, which it must not.

- [ ] **Step 5: Commit**

```bash
git add src/wac/mod.rs src/wac/guard.rs src/http.rs
git commit -m "refactor: authorize returns the decision it made"
```

---

### Task 4: `WAC-Allow`

**Files:**
- Modify: `src/http.rs` — new `wac_allow_value` and `with_read_headers`; `get_impl` (line ~655-728) and `legacy_graph_read` (line ~738-...)
- Test: `src/http.rs` tests module

**Interfaces:**
- Consumes: `crate::wac::Decision` and `authorize`'s new return type, both from Task 3.
- Produces: no new public API.

- [ ] **Step 1: Write the failing tests**

Two tests cover all four behaviours the design's §4 test list names. The "an agent with read only renders exactly `read`" case is covered by the `public` group in the second test — it is the same rendering code path, and it avoids standing up a second identity for no extra coverage.

```rust
// The root ACL grants the owner Read/Write/Control and nobody else anything,
// so this pins three things at once: both groups are always present, an empty
// group is `""` rather than omitted, and `write` reports `append` with it.
#[tokio::test]
async fn wac_allow_reports_both_groups_and_appends_with_write() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("wac-allow").unwrap().to_str().unwrap(),
        "user=\"read write append control\",public=\"\""
    );
}

#[tokio::test]
async fn wac_allow_reports_public_read_when_the_acl_grants_it() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    let acl = format!(
        "<#public> <http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent> ; \
                   <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/foo> ; \
                   <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> . \
         <#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                  <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/foo> ; \
                  <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
                                                       <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/foo.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl)).unwrap();
    let status = f.app.clone().oneshot(put_acl).await.unwrap().status();
    assert!(status.is_success(), "writing the ACL returned {status}");

    let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("wac-allow").unwrap().to_str().unwrap(),
        "user=\"read control\",public=\"read\""
    );
}
```

The second test's ACL is written at `/.aux/foo.acl` — the shape `src/space.rs:577` pins. It grants the owner no `Write`, which is why the expected `user` group is `read control` and not the root ACL's set: a resource's own ACL replaces inheritance entirely.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::wac_allow`
Expected: FAIL on `unwrap()` of a `None` header — nothing emits `WAC-Allow` yet.

- [ ] **Step 3: Implement the rendering**

Add near `with_allow` in `src/http.rs`:

```rust
/// `WAC-Allow` as WAC defines it: what the requester may do on this resource,
/// and what an anonymous caller may do.
///
/// Both groups always appear. An empty group is `public=""` rather than an
/// omitted group — the conformance suite parses the field into a list per group
/// and asserts an empty list, which an absent group does not produce.
///
/// Modes are read through `AccessModes::allows`, so a grant of `acl:Write`
/// reports `append` alongside `write`. That is WAC's own subsumption rule, and
/// the suite pins it: its `read/write/append` row is checked for set equality,
/// so an answer missing `append` fails.
fn wac_allow_value(decision: &crate::wac::Decision) -> String {
    fn group(m: crate::wac::AccessModes) -> String {
        [(Mode::Read, "read"), (Mode::Write, "write"),
         (Mode::Append, "append"), (Mode::Control, "control")]
            .iter()
            .filter(|(mode, _)| m.allows(*mode))
            .map(|(_, name)| *name)
            .collect::<Vec<_>>()
            .join(" ")
    }
    format!("user=\"{}\",public=\"{}\"", group(decision.user), group(decision.public))
}

/// The headers every successful read carries: the auxiliary advertisements, the
/// `Allow` Protocol §4.1 makes a MUST on `GET`/`HEAD`, and `WAC-Allow`.
///
/// One helper rather than three nested calls at four sites, so a read path
/// added later cannot pick up two of the three and look correct.
fn with_read_headers(res: Response, target: &Target, decision: &crate::wac::Decision) -> Response {
    let mut res = with_allow(with_aux_links(res, target), target);
    res.headers_mut().insert(
        "wac-allow",
        wac_allow_value(decision).parse().expect("mode names are header-safe"),
    );
    res
}
```

Add `AccessModes` to the `wac::` import at `src/http.rs:19` if it is not already there:

```rust
    wac::{guard::{authorize, authorize_and_materialize}, pdp, AccessModes, Decision, Mode}};
```

and then use the short names `Decision` / `AccessModes` in the two signatures above instead of the `crate::wac::` prefix.

- [ ] **Step 4: Thread the decision through the read paths**

In `get_impl`, bind the decision:

```rust
async fn get_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap) -> Response {
    let store = st.store.as_ref();
    let decision = match authorize(store, &agent, &target, Mode::Read).await {
        Ok(d) => d,
        Err(res) => return with_aux_links(res, &target),
    };
    let Target::Resource(r) = &target else {
        return legacy_graph_read(st, &decision, target, headers).await; // containers, auxiliaries
    };
```

Change `legacy_graph_read`'s signature — the `_agent` parameter is unused and the decision replaces it:

```rust
async fn legacy_graph_read(
    st: AppState, decision: &Decision, target: Target, headers: HeaderMap,
) -> Response {
```

Then replace every `with_allow(with_aux_links(X, &target), &target)` in both functions with `with_read_headers(X, &target, &decision)` — in `legacy_graph_read` the binding is already a reference, so it is `with_read_headers(X, &target, decision)`.

Run `rg -n 'with_allow\(' src/http.rs` to find them all. There are four: two in `get_impl` (the `304` branch and the final success) and two in `legacy_graph_read`. `with_allow` itself stays — `with_read_headers` calls it.

The `404` and `406` branches keep `with_aux_links` alone and gain nothing: `WAC-Allow` describes access to a representation that was served.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib http::tests::wac_allow`
Expected: both PASS.

- [ ] **Step 6: Run the whole suite**

Run: `nix develop -c cargo test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs
git commit -m "feat: report access modes in WAC-Allow on reads"
```

---

### Task 5: Measure

**Files:**
- Modify: `docs/conformance-findings.md`

**Interfaces:**
- Consumes: Tasks 1-4, all committed.
- Produces: the third run's numbers, for the next plan to diff against.

- [ ] **Step 1: Run the suite**

Run: `./conformance/run.sh`
Expected: ~4 minutes including the build. A non-zero exit is expected while any scenario fails — the report is the deliverable.

If `report.html` is missing, the harness aborted during its own setup and measured nothing. Read `conformance/.run/harness.log` from the bottom before drawing any conclusion.

- [ ] **Step 2: Extract the per-feature counts**

```bash
jq -r '.featureSummary[] | "\(.passedCount)/\(.scenarioCount)\t\(.relativePath)"' \
  conformance/.run/karate/karate-reports/karate-summary-json.txt | sort
```

- [ ] **Step 3: Write up the third run**

Append a section to `docs/conformance-findings.md` in the shape of the existing "Second run" section: date, pod commit (`git rev-parse --short HEAD`), the karate totals table, and a reconciliation against the second run's 609 failures.

Reconcile per feature, not only in aggregate — the second run's write-up did exactly that and it is what caught two fixes nobody had attributed. State explicitly:

- how many of the 50 `wac-allow` scenarios now pass, and for any that still fail, **which assertion** they now reach. A scenario that moves from failing at `!= null` to failing at `contains only` has produced new information, and the write-up should say what the pod answered.
- whether the 4 `OPTIONS` scenarios and the 5 CORS scenarios passed.
- any scenario that regressed. There should be none; if there is, it is a defect and belongs in Bucket 3 with a reproduction.

Then update the ranked gap table near the top: ranks 2, 4 and 5 are resolved or reduced, and the `Rank` column's remaining rows renumber accordingly.

- [ ] **Step 4: Update the conformance README's status line**

`conformance/README.md` states the current counts under "Current status" (`As of 1fe4953: 41 features, 652 scenarios, 43 passed, 609 failed`). Replace the commit and the four numbers with this run's.

- [ ] **Step 5: Commit**

```bash
git add docs/conformance-findings.md conformance/README.md
git commit -m "docs: record the third conformance run"
```

---

## Verification

Before calling this plan done:

- [ ] `nix develop -c cargo test` passes.
- [ ] `nix develop -c cargo build` emits no warnings about unused imports or parameters — Task 4 removes `legacy_graph_read`'s `_agent`, and Task 3 may leave an unused binding behind.
- [ ] `rg -n 'aux/acl' conformance/ docs/conformance-findings.md` returns nothing — the ACL URL shape is `/.aux/{path}.acl`.
- [ ] `docs/conformance-findings.md` carries a third run whose totals reconcile against the second run's 609.
- [ ] No source comment added by this plan refers to a task number, a plan file, or what the code used to do.
