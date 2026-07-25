# SPARQL Solid Pod — Plan 4: Verify-Only Solid-OIDC + DPoP Auth

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authenticate incoming requests — verify a Solid-OIDC DPoP-bound access token + its DPoP proof against the issuer's keys, extract the caller's WebID, and attach an `Agent` (Public or WebId) to each request; reject forged/expired/replayed/mis-bound credentials with `401`. No access enforcement yet (that is Plan 5 / WAC).

**Architecture:** A new `src/auth/` module. A `JwksResolver` trait resolves an issuer's signing keys (a static in-memory impl for hermetic tests; a cached HTTP impl doing OIDC discovery for production). `verify_access_token` checks the access-token JWS + claims; `verify_dpop` (via the maintained `dpop-verifier` crate) checks the proof's signature, `htu`/`htm` (against the **configured public URL**, not the socket), freshness, replay, and `cnf.jkt` proof-of-possession binding. An axum middleware runs `authenticate` and inserts the `Agent` into request extensions; missing credentials → `Agent::Public` (pass through), invalid credentials → `401`.

**Tech Stack:** Rust, `josekit` (JOSE: JWK, JWS verify, RFC 7638 thumbprints), `dpop-verifier` (DPoP proof verification + replay store), `reqwest` (JWKS fetch, prod only, rustls to avoid OpenSSL on Nix), `axum` 0.8. `webid` (Manas types) optional for WebID typing. Build only via the flake dev shell.

**Builds on:** Plans 1–3 (merged to `main`): `http::{AppState, router, *_impl}`, `space::StorageSpace` (public base-URI is authoritative for URL identity — DPoP `htu` derives from it). Design spec §3 (verify-only, external IdP), §4, §10 (DPoP binds to the configured public URL, never the socket). **Security note:** this is the pod's security boundary — the final whole-branch review MUST be adversarial.

## Global Constraints

- **Build/test ONLY via the flake dev shell.** Bare `cargo` fails (oxigraph → RocksDB → libclang). Every command: `nix develop -c cargo test` / `nix develop -c cargo build 2>&1 | grep -i warning` (empty) / `nix develop -c cargo clippy --all-targets` (clean). Pristine output.
- **Latest deps** via `cargo add <crate>` (no pinned version). For `reqwest`: `cargo add reqwest --no-default-features --features json,rustls-tls` (avoid OpenSSL/native-tls on NixOS).
- **Verify-only, external IdP.** The pod is NOT an IdP. It verifies tokens issued by an external Solid-OIDC IdP. (Spec §3)
- **Attach, don't enforce.** Valid credentials → `Agent::WebId(webid)` in request extensions. **No** credentials → `Agent::Public` (request proceeds). Invalid/malformed credentials → `401`. Access decisions are Plan 5 (WAC). Do NOT add authorization gates here.
- **DPoP `htu`/`htm` bind to the CONFIGURED public URL**, reconstructed from `StorageSpace` + the request path + method — never the request socket scheme/host (spoofable behind the reverse proxy). (Spec §10)
- **No deprecated APIs; no `#[allow(...)]`;** the security-critical crypto path especially must be warning-free and clippy clean.
- **Fail closed.** Any verification error, missing key, algorithm mismatch, or malformed input on a request that *presents* credentials → `401`, never a silent pass as authenticated. Only the *total absence* of credentials yields `Public`.
- Conventional commits. TDD: failing test first, minimal impl, commit per task.

---

### Task 0: Spike — nail the crypto stack + token-minting recipe (de-risk, not committed)

Discharges the security-critical unknowns before any real auth code. Produces a written recipe (the exact `josekit` + `dpop-verifier` calls) that Tasks 1–4 transcribe. Not committed to `src/`.

**Files:**
- Create (throwaway): `$CLAUDE_JOB_DIR/tmp/auth-spike/` scratch crate.
- Modify: this plan file (append a "Spike Results" note at the bottom) — committed.

- [ ] **Step 1: Scratch crate + deps**

```bash
cd "$CLAUDE_JOB_DIR/tmp" && cargo new --lib auth-spike && cd auth-spike
cargo add josekit dpop-verifier serde_json 2>&1 | tail
nix develop -c true 2>/dev/null || true   # ensure flake env available if needed
```
(Run `cargo build`/`cargo test` for the spike from within `nix develop -c` if libclang is transitively needed; josekit itself should not need it.)

- [ ] **Step 2: Prove the full round-trip in one spike test**

Write a test that, using `josekit`:
1. Generates an EC P-256 keypair (ES256) — the "IdP" signing key — and a second EC keypair — the "client" DPoP key.
2. Mints a JWS **access token** signed by the IdP key, with claims `iss`, `sub`, `webid`, `exp` (future), `iat`, and `cnf: { jkt: <RFC7638 thumbprint of the client DPoP public JWK> }`.
3. Verifies that access-token JWS against the IdP **public** JWK (the resolver path) and reads the claims back.
4. Mints a **DPoP proof** JWT signed by the client key, header `typ: dpop+jwt` + embedded public `jwk`, claims `htu`, `htm`, `iat`, `jti`.
5. Runs `dpop-verifier` on the proof for a given `htu`/`htm`, and confirms the proof's key thumbprint equals the access token's `cnf.jkt`.

Run it under the flake shell and iterate until green.

- [ ] **Step 3: Record the recipe**

Append a "## Spike Results (2026-07-25)" section to THIS plan file capturing, as copy-pasteable Rust:
- josekit: generate EC key, build a signer/verifier, sign a JWS with custom claims, verify a JWS with a public JWK, compute an RFC 7638 JWK thumbprint (`Jwk::thumbprint` or the exact call).
- dpop-verifier: the exact entrypoint (constructor + verify call), what it checks (htu/htm/iat/jti/replay), whether it also checks `cnf.jkt` or if we must compare thumbprints ourselves, and its replay-store trait.
- The resolved crate versions + licenses.

- [ ] **Step 4: Commit the recipe**

```bash
cd /home/toph/Projects/sparql-pod
git add docs/superpowers/plans/2026-07-25-auth-verify-only.md
git commit -m "docs: record auth crypto-stack spike recipe (josekit + dpop-verifier)"
```

---

### Task 1: `Agent` type, `JwksResolver` trait, static resolver + test-support minting

**Files:**
- Create: `src/auth/mod.rs`, `src/auth/agent.rs`, `src/auth/jwks.rs`, `src/auth/testsupport.rs`
- Modify: `src/lib.rs` (add `pub mod auth;`), `Cargo.toml` (add `josekit`, `serde_json`)
- Test: inline in `src/auth/testsupport.rs`

**Interfaces:**
- Produces:
  - `agent.rs`: `#[derive(Clone, Debug, PartialEq)] pub enum Agent { Public, WebId(String) }`.
  - `jwks.rs`: `pub struct Jwks { pub keys: Vec<josekit::jwk::Jwk> }`; `#[async_trait::async_trait] pub trait JwksResolver: Send + Sync { async fn resolve(&self, issuer: &str) -> Result<Jwks, AuthError>; }`; `pub struct StaticJwksResolver { map: HashMap<String, Jwks> }` with `new(issuer: &str, jwks: Jwks) -> Self` and the trait impl (returns `AuthError::UnknownIssuer` if absent).
  - `mod.rs`: `#[derive(Debug, thiserror::Error)] pub enum AuthError { Malformed(String), BadSignature, Expired, UnknownIssuer, DpopInvalid(String), Binding, MissingKey }` and re-exports.
  - `testsupport.rs` (compiled for tests; gate with `#[cfg(any(test, feature = "testsupport"))]` or a plain module used only by tests): using the Task-0 recipe — `pub struct TestIdp { /* IdP EC keypair */ }` with `new()`, `jwks() -> Jwks` (public keys), and `mint_access_token(webid: &str, dpop_jkt: &str, exp_unix: i64) -> String`; and `pub struct TestClient { /* client DPoP EC keypair */ }` with `new()`, `jkt() -> String` (RFC 7638 thumbprint), `mint_dpop(htu: &str, htm: &str, iat_unix: i64, jti: &str) -> String`.
- Consumes: the Task-0 spike recipe (exact josekit calls).

- [ ] **Step 1: Write a failing test for the mint↔resolve round-trip**

```rust
// src/auth/testsupport.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwks::JwksResolver;

    #[tokio::test]
    async fn idp_jwks_resolves_and_client_jkt_is_stable() {
        let idp = TestIdp::new();
        let resolver = crate::auth::jwks::StaticJwksResolver::new("https://idp.example/", idp.jwks());
        assert!(resolver.resolve("https://idp.example/").await.is_ok());
        assert!(resolver.resolve("https://other/").await.is_err());

        let client = TestClient::new();
        let jkt1 = client.jkt();
        assert_eq!(jkt1, client.jkt());          // deterministic thumbprint
        assert!(!jkt1.is_empty());

        // tokens are non-empty compact JWS strings (three dot-separated parts)
        let at = idp.mint_access_token("https://alice.example/card#me", &jkt1, 9_999_999_999);
        assert_eq!(at.matches('.').count(), 2);
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-1");
        assert_eq!(proof.matches('.').count(), 2);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test auth::`
Expected: FAIL — modules/types undefined.

- [ ] **Step 3: Implement** `agent.rs`, `jwks.rs`, `AuthError`, and `testsupport.rs` using the Task-0 recipe for all josekit calls (key generation, signing, thumbprint). Add `pub mod auth;` to `lib.rs`; in `auth/mod.rs` declare the submodules. Add deps: `nix develop -c cargo add josekit serde_json`.

(The exact josekit API — `Jwk::generate_ec_key`, `jws::ES256.signer_from_jwk`, `JwtPayload`, `jwt::encode_with_signer`, `Jwk::thumbprint` — comes from the Task-0 spike recipe; transcribe it, do not guess.)

- [ ] **Step 4: Run tests**

Run: `nix develop -c cargo test auth::` → PASS. Clippy clean, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/auth src/lib.rs
git commit -m "feat: auth Agent + JwksResolver trait + static resolver + test minting"
```

---

### Task 2: `verify_access_token` — JWS signature + claims

**Files:**
- Create: `src/auth/access_token.rs`
- Modify: `src/auth/mod.rs` (declare submodule + re-export)
- Test: inline in `src/auth/access_token.rs`

**Interfaces:**
- Consumes: `JwksResolver`, `AuthError`, `testsupport::{TestIdp, TestClient}`.
- Produces:
  - `pub struct AccessClaims { pub webid: String, pub jkt: String, pub issuer: String }`.
  - `pub async fn verify_access_token(token: &str, resolver: &dyn JwksResolver, now_unix: i64) -> Result<AccessClaims, AuthError>` — decode JWS header (get `kid`/`alg`); decode payload to read `iss`; `resolver.resolve(iss)`; select the JWK (by `kid`, else by a signing-capable key); **verify the JWS signature**; check `exp > now_unix` (→ `Expired`); extract `webid` (the `webid` claim; if absent, error `Malformed`) and `cnf.jkt` (→ `Binding` if absent). Any decode/lookup/verify failure → the matching `AuthError`. **Fail closed.**

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{jwks::StaticJwksResolver, testsupport::{TestIdp, TestClient}, AuthError};

    fn setup() -> (StaticJwksResolver, TestClient, TestIdp) {
        let idp = TestIdp::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        (resolver, TestClient::new(), idp)
    }

    #[tokio::test]
    async fn valid_token_yields_webid_and_jkt() {
        let (resolver, client, idp) = setup();
        let jkt = client.jkt();
        let at = idp.mint_access_token("https://alice.example/card#me", &jkt, 9_999_999_999);
        let claims = verify_access_token(&at, &resolver, 1_000).await.unwrap();
        assert_eq!(claims.webid, "https://alice.example/card#me");
        assert_eq!(claims.jkt, jkt);
        assert_eq!(claims.issuer, "https://idp.example/");
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (resolver, client, idp) = setup();
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 500);
        assert!(matches!(verify_access_token(&at, &resolver, 1_000).await, Err(AuthError::Expired)));
    }

    #[tokio::test]
    async fn unknown_issuer_is_rejected() {
        let (_r, client, idp) = setup();
        let empty = StaticJwksResolver::new("https://someone-else/", idp.jwks());
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        assert!(matches!(verify_access_token(&at, &empty, 1_000).await, Err(AuthError::UnknownIssuer)));
    }

    #[tokio::test]
    async fn token_signed_by_wrong_key_is_rejected() {
        let (resolver, client, _idp) = setup();
        // a DIFFERENT idp signs, but resolver holds the ORIGINAL idp's jwks
        let attacker = TestIdp::new();
        let at = attacker.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        assert!(matches!(verify_access_token(&at, &resolver, 1_000).await, Err(AuthError::BadSignature)));
    }
}
```

- [ ] **Step 2: Run to verify failure** — `nix develop -c cargo test auth::access_token` → FAIL.

- [ ] **Step 3: Implement** `verify_access_token` per the interface, using the Task-0 recipe for josekit JWS verification and claim extraction. Fail closed on every error path; map to the precise `AuthError`.

- [ ] **Step 4: Run tests** — `nix develop -c cargo test auth::access_token` → PASS (4). Clippy clean, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/auth/access_token.rs src/auth/mod.rs
git commit -m "feat: verify Solid-OIDC access-token JWS + claims (fail-closed)"
```

---

### Task 3: `verify_dpop` + `authenticate` orchestration

**Files:**
- Create: `src/auth/dpop.rs` (DPoP proof verification), `src/auth/authenticate.rs` (orchestration)
- Modify: `src/auth/mod.rs`, `Cargo.toml` (add `dpop-verifier`)
- Test: inline in both

**Interfaces:**
- Consumes: `verify_access_token`, `AccessClaims`, `JwksResolver`, `Agent`, `AuthError`, testsupport.
- Produces:
  - `dpop.rs`: `pub async fn verify_dpop(proof: &str, htu: &str, htm: &str, expected_jkt: &str, now_unix: i64) -> Result<(), AuthError>` — via `dpop-verifier`: verify the proof's own signature (embedded jwk), `htu` == `htu` arg, `htm` == method, `iat` fresh, and the proof key thumbprint == `expected_jkt` (the access token's `cnf.jkt`). If `dpop-verifier` doesn't itself compare the thumbprint, compute the proof-key thumbprint (Task-0 recipe) and compare here. Replay (`jti`): use `dpop-verifier`'s in-memory replay store (a process-lifetime store is acceptable for v1; note the limitation).
  - `authenticate.rs`: `pub async fn authenticate(auth_header: Option<&str>, dpop_header: Option<&str>, htm: &str, htu: &str, resolver: &dyn JwksResolver, now_unix: i64) -> Result<Agent, AuthError>` — if BOTH headers absent → `Ok(Agent::Public)`. Otherwise (either present): parse `Authorization: DPoP <token>` (the scheme MUST be `DPoP`; a `Bearer` token without DPoP → `AuthError::DpopInvalid` since Solid-OIDC tokens are DPoP-bound), require the `DPoP` proof header, `verify_access_token` → claims, `verify_dpop(proof, htu, htm, claims.jkt, now)`, then `Ok(Agent::WebId(claims.webid))`. Any failure → `Err(_)` (caller maps to 401). **Fail closed.**

- [ ] **Step 1: Write failing tests** (dpop.rs)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{testsupport::TestClient, AuthError};

    #[tokio::test]
    async fn valid_proof_matching_jkt_passes() {
        let client = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-a");
        assert!(verify_dpop(&proof, "https://pod.toph.so/foo", "GET", &client.jkt(), 1_010).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_htu_is_rejected() {
        let client = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-b");
        assert!(verify_dpop(&proof, "https://pod.toph.so/OTHER", "GET", &client.jkt(), 1_010).await.is_err());
    }

    #[tokio::test]
    async fn jkt_mismatch_is_binding_error() {
        let client = TestClient::new();
        let other = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-c");
        // proof is from `client`, but we claim the token was bound to `other`'s key
        assert!(verify_dpop(&proof, "https://pod.toph.so/foo", "GET", &other.jkt(), 1_010).await.is_err());
    }
}
```

- [ ] **Step 2: Write failing tests** (authenticate.rs)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{jwks::StaticJwksResolver, testsupport::{TestIdp, TestClient}, Agent};

    #[tokio::test]
    async fn no_credentials_is_public() {
        let idp = TestIdp::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let agent = authenticate(None, None, "GET", "https://pod.toph.so/foo", &resolver, 1_000).await.unwrap();
        assert_eq!(agent, Agent::Public);
    }

    #[tokio::test]
    async fn valid_credentials_yield_webid() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-x");
        let agent = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", &resolver, 1_010).await.unwrap();
        assert_eq!(agent, Agent::WebId("https://alice.example/card#me".into()));
    }

    #[tokio::test]
    async fn token_without_dpop_proof_is_error() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        assert!(authenticate(Some(&format!("DPoP {at}")), None, "GET",
            "https://pod.toph.so/foo", &resolver, 1_010).await.is_err());
    }
}
```

- [ ] **Step 3: Run to verify failure** — `nix develop -c cargo test auth::dpop auth::authenticate` → FAIL.

- [ ] **Step 4: Implement** `verify_dpop` (via `dpop-verifier`, per the Task-0 recipe — add dep: `nix develop -c cargo add dpop-verifier`) and `authenticate` per the interfaces. Fail closed everywhere.

- [ ] **Step 5: Run tests** — `nix develop -c cargo test auth::` → PASS (all auth tests). Clippy clean, zero warnings.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/auth/dpop.rs src/auth/authenticate.rs src/auth/mod.rs
git commit -m "feat: DPoP proof verification + authenticate orchestration (fail-closed)"
```

---

### Task 4: axum middleware + HTTP JWKS resolver; wire into the server

**Files:**
- Create: `src/auth/http_jwks.rs` (cached OIDC-discovery resolver, prod), `src/auth/middleware.rs` (axum layer)
- Modify: `src/http.rs` (attach the layer; `AppState` gains a resolver handle), `src/main.rs` (construct `HttpJwksResolver`), `Cargo.toml` (add `reqwest` rustls, a TTL cache)
- Test: inline HTTP tests in `src/auth/middleware.rs` (using `StaticJwksResolver`)

**Interfaces:**
- Consumes: `authenticate`, `Agent`, `JwksResolver`, `StorageSpace` (for the public `htu`).
- Produces:
  - `http_jwks.rs`: `pub struct HttpJwksResolver { /* reqwest client + TTL cache: issuer -> (Jwks, fetched_at) */ }` implementing `JwksResolver` by OIDC discovery (`GET <issuer>/.well-known/openid-configuration` → `jwks_uri` → fetch JWKS), cached with a TTL (e.g. 300s). Network + parse errors → `AuthError`.
  - `middleware.rs`: `pub async fn auth_layer(State(st): State<AppState>, req: Request, next: Next) -> Response` (an axum `middleware::from_fn_with_state` fn) that: builds `htu` = `st.space.graph_iri(request_path)` semantics — i.e. the configured public URL for this request's path (reuse the same base-URI derivation, NOT the socket); reads `Authorization` + `DPoP` headers and the method; calls `authenticate(...)`; on `Ok(agent)` inserts `agent` into `req.extensions_mut()` and calls `next.run(req)`; on `Err(_)` returns `401 Unauthorized`. `now_unix` comes from `std::time::SystemTime` (real clock in the middleware; tests inject via the `authenticate` unit tests, not here).
  - `AppState` gains `pub resolver: std::sync::Arc<dyn JwksResolver>`.
- Note: `router()` applies the layer over all routes so every handler sees an `Agent` in extensions (handlers ignore it until Plan 5).

- [ ] **Step 1: Write failing HTTP tests** (middleware.rs) — a test router that echoes the `Agent` from extensions

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get, body::Body, extract::Extension,
        http::{Request, StatusCode, header}, response::IntoResponse};
    use tower::ServiceExt;
    use std::sync::Arc;
    use crate::{space::StorageSpace, store::OxigraphStore,
        auth::{Agent, jwks::StaticJwksResolver, testsupport::{TestIdp, TestClient}}};

    async fn whoami(Extension(agent): Extension<Agent>) -> impl IntoResponse {
        match agent { Agent::Public => "public".to_string(), Agent::WebId(w) => w }
    }

    fn app_with(resolver: Arc<dyn crate::auth::jwks::JwksResolver>) -> Router {
        let state = crate::http::AppState {
            store: Arc::new(OxigraphStore::in_memory().unwrap()),
            space: StorageSpace::new("https://pod.toph.so/").unwrap(),
            resolver,
        };
        Router::new().route("/{*path}", get(whoami))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth_layer))
            .with_state(state)
    }

    #[tokio::test]
    async fn no_credentials_passes_as_public() {
        let idp = TestIdp::new();
        let app = app_with(Arc::new(StaticJwksResolver::new("https://idp.example/", idp.jwks())));
        let res = app.oneshot(Request::builder().uri("/foo").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn tampered_token_is_401() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let app = app_with(Arc::new(StaticJwksResolver::new("https://idp.example/", idp.jwks())));
        let mut at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        at.push('x'); // corrupt the signature
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-http");
        let req = Request::builder().uri("/foo")
            .header(header::AUTHORIZATION, format!("DPoP {at}"))
            .header("dpop", proof).body(Body::empty()).unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
```

(A valid-token end-to-end HTTP test is timing-sensitive because the real clock is used in the middleware; rely on the exhaustive `authenticate` unit tests from Task 3 for the valid path, and keep the HTTP tests to `public` and `401` behaviors — where the clock doesn't matter. Note this in the report.)

- [ ] **Step 2: Run to verify failure** — `nix develop -c cargo test auth::middleware` → FAIL.

- [ ] **Step 3: Implement** the middleware + `HttpJwksResolver` (add deps: `nix develop -c cargo add reqwest --no-default-features --features json,rustls-tls` and a small TTL cache — either hand-rolled with `tokio::sync::RwLock<HashMap<...>>` or `cargo add moka --features future`). Add `resolver` to `AppState`. Apply the layer in `router()`.

- [ ] **Step 4: Wire `main.rs`** to construct `Arc::new(HttpJwksResolver::new())` as the resolver.

- [ ] **Step 5: Run full suite** — `nix develop -c cargo test` → PASS. Clippy clean, zero warnings. Verify the existing Plan 1–3 handler tests still pass (they now run under the auth layer, which returns `Public` when they send no credentials — confirm no regression).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/auth src/http.rs src/main.rs
git commit -m "feat: axum auth middleware + cached HTTP JWKS resolver; attach Agent"
```

---

## Self-Review

**Spec coverage (Plan 4 scope):**
- Verify-only, external IdP (spec §3) → Tasks 2–4. ✓
- DPoP-bound access-token verification (JWS + `cnf.jkt` binding) → Tasks 2, 3. ✓
- DPoP `htu`/`htm` from configured public URL, not socket (spec §10) → Task 4 middleware. ✓
- Attach-not-enforce (Agent::Public / WebId; 401 on invalid; no gate) → Tasks 3, 4. ✓
- Fail-closed on every credentialed error path → Tasks 2–4 (explicit in each `AuthError` mapping + tests: expired, wrong-key, wrong-htu, jkt-mismatch, tampered). ✓
- Hermetic tests (no network): `StaticJwksResolver` + `TestIdp`/`TestClient` minting → Tasks 1–4. ✓
- **Deferred (explicitly out of scope):** WAC/enforcement (Plan 5 reads the attached `Agent`); persistent/shared DPoP replay store (v1 uses process-lifetime, noted); `aud` claim policy hardening and full OIDC-discovery edge cases; token introspection for opaque tokens (we assume JWS access tokens per Solid-OIDC); N3-Patch, blobs.

**Placeholder scan:** The security-critical josekit/dpop-verifier calls are gated behind the Task-0 spike, which records the exact copy-pasteable API into this plan before Tasks 1–4 transcribe it — this is deliberate (do not guess crypto APIs), not a placeholder. All non-crypto code (Agent, resolver trait, orchestration control-flow, middleware, tests) is shown in full. No "TBD/handle errors/similar-to".

**Type consistency:** `Agent{Public,WebId}`, `AuthError` variants, `JwksResolver::resolve`, `Jwks{keys}`, `AccessClaims{webid,jkt,issuer}`, `verify_access_token(token, &dyn JwksResolver, now)`, `verify_dpop(proof, htu, htm, expected_jkt, now)`, `authenticate(auth_header, dpop_header, htm, htu, resolver, now)`, `AppState{store,space,resolver}`, `TestIdp`/`TestClient` minting signatures — consistent across Tasks 1–4. ✓

**Security emphasis:** Every task's error paths fail closed; the test suites deliberately include negative cases (expired, wrong signing key, wrong htu, jkt binding mismatch, tampered signature, token-without-proof). The final whole-branch review MUST be adversarial and specifically probe: algorithm-confusion / `alg:none`, key-selection (does an attacker-supplied `kid` or embedded key ever get trusted for the access token?), missing `cnf.jkt` enforcement, htu/htm normalization mismatches, and replay across the process-lifetime store.

---

## Spike Results (2026-07-25)

Scratch crate (`cargo new --lib auth-spike`; not committed) proved the full round-trip green with a single `#[tokio::test]`: generate IdP + client EC P-256 keys → mint access token (JWS, `cnf.jkt`) → verify against IdP public JWK, read claims → mint DPoP proof (embedded `jwk`, `htu`/`htm`/`iat`/`jti`) → verify with `dpop-verifier` → confirm proof-key thumbprint == access token's `cnf.jkt`. Also exercised: wrong-signer rejection, wrong-`htu` rejection (`DpopError::HtuMismatch`), and same-`jti` replay rejection (`DpopError::Replay`).

**Resolved versions (from `Cargo.lock`, `cargo add` with no pin):**
- `josekit = "0.10.3"` — license `MIT OR Apache-2.0`. **Must enable the `vendored` feature** (`josekit = { version = "0.10.3", features = ["vendored"] }`) — see blocker below.
- `dpop-verifier = "4.4.0"` — license `MIT OR Apache-2.0`.
- `async-trait = "0.1.91"` — required as a **direct** dependency (the `ReplayStore` trait impl needs the same proc-macro the trait was declared with; without it, `#[async_trait] impl ReplayStore for X` fails with `E0195 lifetime parameters ... do not match the trait declaration`).
- `serde_json = "1.0.151"`, `tokio = "1.53.1"` (features `rt`, `macros`, `rt-multi-thread`).

**Blocker/gotcha #1 — `josekit` needs vendored OpenSSL, not libclang.** Plain `cargo build`/`test` fails: `josekit` depends unconditionally on the `openssl` crate (for RSA/PSS support), which needs `pkg-config` + system OpenSSL dev headers — absent on a bare NixOS shell outside the flake dev shell. Fix: enable josekit's `vendored` feature, which builds OpenSSL from source (needs only a C compiler, already present) — no libclang/RocksDB-style dependency at all. **This must be added to `Cargo.toml` in Task 1**: `cargo add josekit --features vendored` (or edit the line after `cargo add josekit`).

**Blocker/gotcha #2 — `JwtPayload::set_issued_at`/`set_expires_at` encode floats, `dpop-verifier` wants ints.** `josekit::jwt::JwtPayload::set_issued_at(&SystemTime)` (and `set_expires_at`) serialize the claim as a JSON **float** with fractional seconds (e.g. `"iat":1784986197.359083`). `dpop-verifier`'s internal `DpopClaims { iat: i64, .. }` (see `dpop_verifier::verify` source) fails strict `serde_json` deserialization of a float into an `i64` field, surfacing as the unhelpful `DpopError::MalformedJws` (looks like a signature/encoding problem, isn't). **Fix:** for the DPoP proof's `iat` (and, for consistency, the access token's `iat`/`exp` too), set the claim as a plain integer via `payload.set_claim("iat", Some(serde_json::json!(unix_ts)))`, never via `set_issued_at`/`set_expires_at`. Task 1/2/3 test-support minting (`TestIdp::mint_access_token`, `TestClient::mint_dpop`) MUST use integer claims for `iat`/`exp`, matching the `i64` unix-timestamp params already in their signatures.

### josekit recipe (copy-pasteable)

```rust
use josekit::jwk::Jwk;
use josekit::jwk::alg::ec::EcCurve;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use serde_json::json;

// --- Generate an EC P-256 keypair; derive the public JWK ---
let priv_jwk: Jwk = Jwk::generate_ec_key(EcCurve::P256)?;   // contains "d" (private)
let pub_jwk: Jwk = priv_jwk.to_public_key()?;                // strips "d"

// --- Extract raw x/y (base64url, no padding) — needed for the RFC 7638 thumbprint ---
let x: String = pub_jwk.parameter("x").unwrap().as_str().unwrap().to_string();
let y: String = pub_jwk.parameter("y").unwrap().as_str().unwrap().to_string();

// --- RFC 7638 thumbprint: josekit 0.10.3 has NO `Jwk::thumbprint` method (verified absent
// from the crate). Use dpop_verifier::thumbprint_ec_p256(x, y) instead (see below) — using the
// SAME function on both the minting side and the verifying side guarantees agreement, and it's
// already a transitive dependency once Task 3 adds dpop-verifier.
let jkt: String = dpop_verifier::thumbprint_ec_p256(&x, &y)?; // 43-char base64url, no '='

// --- Build a signer/verifier for ES256 from a JWK ---
let signer = ES256.signer_from_jwk(&priv_jwk)?;   // impl JwsSigner
let verifier = ES256.verifier_from_jwk(&pub_jwk)?; // impl JwsVerifier

// --- Mint a JWS with custom claims, incl. nested `cnf` ---
let mut header = JwsHeader::new();
header.set_token_type("JWT");           // sets "typ": "JWT"

let mut payload = JwtPayload::new();
payload.set_issuer("https://idp.example/");        // "iss"
payload.set_subject("https://alice.example/card#me"); // "sub"
payload.set_claim("iat", Some(json!(iat_unix)))?;   // PLAIN INTEGER — see gotcha #2
payload.set_claim("exp", Some(json!(exp_unix)))?;   // PLAIN INTEGER — see gotcha #2
payload.set_claim("webid", Some(json!("https://alice.example/card#me")))?;
payload.set_claim("cnf", Some(json!({ "jkt": jkt })))?; // nested object claim works directly

let jws: String = jwt::encode_with_signer(&payload, &header, &signer)?; // 3-part compact JWS

// --- Verify a JWS against a public JWK; read claims back ---
let (verified_payload, verified_header) = jwt::decode_with_verifier(&jws, &verifier)?;
// JoseError on: bad signature, wrong key, malformed input. Fails closed (Err), never silent.
let webid: &str = verified_payload.claim("webid").unwrap().as_str().unwrap();
let exp: i64 = verified_payload.claim("exp").unwrap().as_i64().unwrap();
let jkt_claim: &str = verified_payload.claim("cnf").unwrap().get("jkt").unwrap().as_str().unwrap();
// `verified_header` also available (e.g. `verified_header.key_id()` if the IdP's real JWKS uses `kid`
// to pick the verifying key among several — this spike used a single-key resolver so didn't need it;
// Task 2's kid-based key selection should be tested against a JwkSet with 2+ keys).

// --- Mint a DPoP proof: header typ "dpop+jwt" + embedded PUBLIC jwk; claims htu/htm/iat/jti ---
let dpop_signer = ES256.signer_from_jwk(&priv_jwk)?; // the CLIENT's key, not the IdP's
let mut dpop_header = JwsHeader::new();
dpop_header.set_token_type("dpop+jwt");   // "typ": "dpop+jwt" — dpop-verifier requires this exact value
dpop_header.set_jwk(pub_jwk.clone());     // embeds {"kty","crv","x","y"} — MUST be the public key only

let mut dpop_payload = JwtPayload::new();
dpop_payload.set_claim("htu", Some(json!("https://pod.toph.so/foo")))?;
dpop_payload.set_claim("htm", Some(json!("GET")))?;
dpop_payload.set_claim("iat", Some(json!(iat_unix)))?; // PLAIN INTEGER — see gotcha #2
dpop_payload.set_claim("jti", Some(json!("unique-id")))?;

let dpop_proof: String = jwt::encode_with_signer(&dpop_payload, &dpop_header, &dpop_signer)?;
```

### dpop-verifier recipe (copy-pasteable)

```rust
use dpop_verifier::{DpopVerifier, DpopError, ReplayContext, ReplayStore};
use async_trait::async_trait;
use std::collections::HashSet;

// --- Replay store: process-lifetime in-memory HashSet<[u8;32]> is sufficient for v1 ---
struct MemoryStore(HashSet<[u8; 32]>);

#[async_trait]
impl ReplayStore for MemoryStore {
    async fn insert_once(&mut self, jti_hash: [u8; 32], _ctx: ReplayContext<'_>)
        -> Result<bool, DpopError>
    {
        Ok(self.0.insert(jti_hash)) // true = first time seen (OK); false = replay
    }
}

// --- Construct + verify (builder pattern) ---
let verifier = DpopVerifier::new()
    .with_max_age_seconds(300)     // rejects DpopError::Stale if iat older than this
    .with_future_skew_seconds(5);  // rejects DpopError::FutureSkew if iat too far ahead

let mut store = MemoryStore(HashSet::new());
let verified = verifier
    .verify(
        &mut store,
        &dpop_proof,             // compact JWS string from the `DPoP` header
        "https://pod.toph.so/foo", // expected_htu — the CONFIGURED public URL, not the socket
        "GET",                    // expected_htm
        None,                      // access_token: Some(at) binds `ath` (SHA-256 of the AT) —
                                   // NOT needed for cnf.jkt checking; leave None unless also
                                   // enforcing `ath` binding (Solid-OIDC doesn't require it).
    )
    .await?; // Result<VerifiedDpop, DpopError>

// pub struct VerifiedDpop { pub jkt: String, pub jti: String, pub iat: i64 }
```

**What `dpop-verifier`'s `.verify()` checks internally** (from reading `dpop_verifier::verify::DpopVerifier::verify` source, v4.4.0): JWS structure (3 parts, valid base64url) → header `typ == "dpop+jwt"` → header `jwk` is EC/P-256 (or Ed25519 with `eddsa` feature) and contains **no** private `d` member (rejects `BadJwk` otherwise) → verifies the **proof's own signature** using the embedded public `jwk` → computes the proof key's RFC 7638 thumbprint (`jkt`) via its own `thumbprint_ec_p256` → decodes claims (`jti`, `iat`, `htm`, `htu`, optional `ath`, `nonce`) → `jti` length ≤ 512 → **`htm`/`htu` exact match** after normalization (case-insensitive scheme/host, default-port stripping, dot-segment removal, query/fragment stripping — but **path is case-sensitive**, confirmed by its own test `htu_path_case_mismatch_fails`) → optional `ath` binding if `access_token: Some(..)` passed → **freshness** (`iat` within `[now - max_age, now + future_skew]`, else `Stale`/`FutureSkew`) → optional nonce checks (`NonceMode`, unused here) → **replay** via the `ReplayStore` (`SHA-256(jti)` inserted; `false` return ⇒ `DpopError::Replay`).

**Confirmed: `dpop-verifier` does NOT check `cnf.jkt` binding itself** — it has no concept of an access token's `cnf` claim at all (its only access-token-related feature is the separate, optional `ath` hash-binding check, which is a different mechanism). `VerifiedDpop.jkt` is simply the thumbprint of the key that signed the *proof*. **Task 3's `verify_dpop` MUST, after calling `.verify()`, separately compare `verified.jkt == expected_jkt` (the access token's `cnf.jkt`) and return `AuthError::Binding` on mismatch** — this is exactly the shape already specified in the Task 3 interface (`verify_dpop(proof, htu, htm, expected_jkt, now)`), so no interface change is needed, just confirmation the comparison is entirely our responsibility.

**Replay store trait** (already shown above): `ReplayStore::insert_once(&mut self, jti_hash: [u8; 32], ctx: ReplayContext<'_>) -> Result<bool, DpopError>`, where `ReplayContext<'a> { jkt: Option<&'a str>, htm: Option<&'a str>, htu: Option<&'a str>, client_id: Option<&'a str>, iat: i64 }`. A `HashSet<[u8;32]>`-backed impl (shown above) is a fine v1 process-lifetime store, matching the plan's noted limitation.

**Error type:** `dpop_verifier::DpopError` (via `thiserror`) has variants including `MalformedJws`, `InvalidAlg(String)`, `UnsupportedAlg(String)`, `InvalidSignature`, `BadJwk(&'static str)`, `HtmMismatch`, `HtuMismatch`, `MissingAth`/`AthMalformed`/`AthMismatch`, `FutureSkew`, `Stale`, `Replay`, `JtiTooLong`, plus nonce-related variants unused here. Task 3 should map all of these to `AuthError::DpopInvalid(String)` (via `.to_string()`) except perhaps surfacing `Replay`/`Stale` distinctly if useful for logging — the plan's `AuthError::DpopInvalid(String)` catch-all is adequate.

**No other API-shape mismatches found** — `dpop-verifier` consumes a plain compact-JWS `&str` for the proof (no custom request/proof struct required), so it plugs directly into the `verify_dpop(proof: &str, ...)` signature already specified in Task 3 with no adaptation needed.
