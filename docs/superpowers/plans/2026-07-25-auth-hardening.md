# SPARQL Solid Pod — Plan 5: Auth Hardening (pre-production residuals)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the five pre-production hardening residuals the Plan-4 final security review deferred: a bounded/TTL DPoP replay store, a DNS-rebinding-safe pinned-IP fetch, an optional trusted-issuer allowlist + negative-cache, access-token `aud` validation, and WebID-profile content negotiation.

**Architecture:** Small, mostly-independent changes to the existing `src/auth/` modules. Introduce an `AuthConfig` (read from env in `main.rs`, injected for tests) to carry the new operator knobs (trusted issuers, expected audience). No new subsystems; the identity-verification logic from Plan 4 is unchanged except where these items bolt on.

**Tech Stack:** Rust, existing auth stack (`josekit`, `dpop-verifier`, `reqwest` rustls), `oxigraph::io` for RDF. Build only via the flake dev shell.

**Builds on:** Plan 4 (merged to `main`): `src/auth/{dpop,safe_fetch,http_jwks,webid_issuer,access_token,authenticate,middleware}.rs`. Final-review residual list is in `docs/superpowers/plans/2026-07-25-auth-verify-only.md` and the SDD ledger. Design spec §3, §10.

## Global Constraints

- **Build/test ONLY via the flake dev shell.** Bare `cargo` fails (oxigraph → libclang). Every command: `nix develop -c cargo test` / `nix develop -c cargo build 2>&1 | grep -i warning` (empty) / `nix develop -c cargo clippy --all-targets` (clean). Pristine.
- **Latest deps** via `cargo add`. No deprecated APIs; NO `#[allow(...)]`.
- **Fail closed** — every new check rejects (401/error) on doubt; none opens a path that Plan 4 closed.
- **Do not weaken Plan 4's verified properties** (ES256 pin, cnf.jkt binding, SSRF IP block, WebID-issuer binding, fail-closed middleware). Each task's review re-confirms none regressed.
- Config knobs are **opt-in with safe defaults**: unset allowlist = open federation (spec-correct); unset expected-audience = skip `aud` (backward-compatible); the SSRF/replay hardening is always on.
- Conventional commits. TDD: failing test first, minimal impl, commit per task.

---

### Task 1: Bounded/TTL DPoP replay store

Fixes the unbounded, never-evicting process-lifetime `REPLAY_JTIS` set (memory-DoS + no expiry) noted in the review. Keep it in-process/single-instance (a shared Redis store is a separate future item — out of scope; note it).

**Files:** Modify `src/auth/dpop.rs`. Test: inline.

**Interfaces:**
- Change the replay set to store `(jti_hash, recorded_at_unix)` and evict entries older than `MAX_AGE_SECONDS + FUTURE_SKEW_SECONDS` on each insert (a jti can never be replayed within the freshness window, and outside it the freshness check already rejects — so eviction past the window is safe).
- `record_jti_or_reject_replay(jti: &str, now_unix: i64) -> Result<(), AuthError>` gains the `now_unix` param (thread the same `now_unix` already passed to `verify_dpop`). Insert `(hash, now_unix)`; first evict all entries with `recorded_at < now_unix - (MAX_AGE + SKEW)`; then if the hash is already present → replay error, else insert.

- [ ] **Step 1: Failing test**

```rust
#[tokio::test]
async fn replayed_jti_outside_window_is_allowed_again_and_set_stays_bounded() {
    let client = crate::auth::testsupport::TestClient::new();
    // first use at t=1000
    let p1 = client.mint_dpop("https://pod.toph.so/a", "GET", 1_000, "jti-ttl");
    assert!(verify_dpop(&p1, "https://pod.toph.so/a", "GET", &client.jkt(), 1_010).await.is_ok());
    // immediate replay (same jti, within window) → rejected
    assert!(verify_dpop(&p1, "https://pod.toph.so/a", "GET", &client.jkt(), 1_010).await.is_err());
    // a NEW proof with the SAME jti but far in the future (past the eviction window) → allowed
    let p2 = client.mint_dpop("https://pod.toph.so/a", "GET", 1_000_000, "jti-ttl");
    assert!(verify_dpop(&p2, "https://pod.toph.so/a", "GET", &client.jkt(), 1_000_010).await.is_ok());
}
```

- [ ] **Step 2: Run to verify failure** — `nix develop -c cargo test auth::dpop` → the third assertion FAILs against the current unbounded store (old jti still present).
- [ ] **Step 3: Implement** the `(hash, recorded_at)` store + eviction-before-insert in `record_jti_or_reject_replay(jti, now_unix)`; update the call site in `verify_dpop` to pass `now_unix`.
- [ ] **Step 4: Run full suite** → PASS; clippy clean; zero warnings.
- [ ] **Step 5: Commit** — `fix: bounded/TTL DPoP replay store (evict past freshness window)` — and add a comment: a shared/persistent (Redis) store is still needed for multi-replica deployments.

---

### Task 2: DNS-rebinding-safe fetch (pin the validated IP)

`guarded_get` validates the host's resolved IPs, then hands the URL to `reqwest`, which **re-resolves** — a name answering public-then-private races past the check. Pin the connection to the exact IP that passed validation.

**Files:** Modify `src/auth/safe_fetch.rs`. Test: inline.

**Interfaces:**
- In `guarded_get`, after resolving the host and confirming EVERY resolved IP passes `is_forbidden_ip` (unless `allow_private_ips`), pick one validated `SocketAddr` and pin it: build the request with reqwest's `.resolve(host, addr)` override (on a per-request `ClientBuilder`, preserving redirects-disabled + timeouts) OR set it on the passed client. Confirm the exact reqwest 0.13 API (`ClientBuilder::resolve(domain, SocketAddr)` / `resolve_to_addrs`) against docs.rs and use it so the actual TCP connection targets the pre-validated IP, not a fresh resolution. Host header + TLS SNI stay the original hostname.
- Signature unchanged externally; the pinning is internal.

- [ ] **Step 1: Failing/《characterizing》 test** — since a live rebinding race is hard to reproduce hermetically, assert the pinning path deterministically: a hostname test-configured to resolve (via the pinned override) to a **forbidden** IP is rejected, and one pinned to the permissive local server (with `FetchPolicy::permissive()`) succeeds AND connected to the pinned addr. If reqwest's `.resolve` can't be observed directly, add a unit test on the new helper that selects the validated `SocketAddr` (assert it returns a non-forbidden addr and errors when all are forbidden), plus keep the existing loopback-block test.

```rust
#[tokio::test]
async fn pins_to_validated_ip_and_rejects_when_all_forbidden() {
    // helper that resolves + filters
    let addrs = resolve_allowed("example.com", 443, &FetchPolicy::default()).await;
    // (public host → Ok(non-empty) in CI-less env may be flaky; if so, test the filter fn directly)
    let forbidden = resolve_allowed("localhost", 443, &FetchPolicy::default()).await;
    assert!(forbidden.is_err()); // localhost → 127.0.0.1 → forbidden
    let _ = addrs;
}
```
(If a public DNS lookup is unavailable in the sandbox, drop that arm and test `resolve_allowed` against `127.0.0.1`/`10.0.0.1` literals + a permissive-policy allow — no external network.)

- [ ] **Step 2: Run to verify failure.** **Step 3: Implement** `resolve_allowed(host, port, policy) -> Result<Vec<SocketAddr>, AuthError>` (lookup + `is_forbidden_ip` filter, error if none/any-forbidden per policy) and pin the chosen addr into the reqwest request via `.resolve(...)`. Keep the existing scheme/IP checks. **Step 4: full suite green, clippy clean, zero warnings. Step 5: Commit** — `fix: pin fetch to the validated IP (close DNS-rebinding race)`

---

### Task 3: `AuthConfig` + trusted-issuer allowlist + negative-cache

**Files:** Create `src/auth/config.rs`; modify `src/auth/http_jwks.rs`, `src/auth/authenticate.rs`, `src/http.rs` (AppState), `src/main.rs`, `src/auth/mod.rs`. Test: inline.

**Interfaces:**
- `config.rs`: `#[derive(Clone, Default)] pub struct AuthConfig { pub trusted_issuers: Option<std::collections::HashSet<String>>, pub expected_audience: Option<String> }` with `pub fn from_env() -> Self` (read `POD_TRUSTED_ISSUERS` = comma-separated; `POD_EXPECTED_AUDIENCE`; both optional).
- **Allowlist enforcement in `authenticate`** (before any fetch — this also shrinks the SSRF surface): after decoding the token's `iss` but BEFORE `verify_access_token`'s JWKS fetch, if `config.trusted_issuers` is `Some(set)` and `iss ∉ set` → `Err(AuthError::UntrustedIssuer)` (add variant). If `None` → open (spec-correct federation; the WebID-issuer binding remains the primary control). Thread `&AuthConfig` into `authenticate` and expose the token's raw `iss` for this pre-check (a small helper that decodes only `iss`, reusing the existing pre-verification peek — it is used ONLY to reject, never to accept).
- **Negative-cache** in `HttpJwksResolver`: cache discovery/JWKS *failures* for a short TTL (e.g. 30s) keyed by issuer, so a flapping/hostile issuer isn't re-probed on every request. (The success cache already exists.)
- `AppState` gains `pub auth_config: std::sync::Arc<AuthConfig>` (or pass config into the middleware which forwards to `authenticate`).

- [ ] **Step 1: Failing tests**

```rust
// authenticate.rs tests
#[tokio::test]
async fn issuer_not_in_allowlist_is_rejected_before_fetch() {
    let idp = crate::auth::testsupport::TestIdp::new();
    let client = crate::auth::testsupport::TestClient::new();
    let resolver = crate::auth::jwks::StaticJwksResolver::new("https://idp.example/", idp.jwks());
    let mut webids = crate::auth::webid_issuer::StaticWebIdIssuers::new();
    webids.allow("https://alice.example/card#me", "https://idp.example/");
    let mut cfg = crate::auth::config::AuthConfig::default();
    cfg.trusted_issuers = Some(["https://ONLY-this.example/".to_string()].into_iter().collect());
    let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
    let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-allow");
    let r = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
        "https://pod.toph.so/foo", &resolver, &webids, &cfg, 1_010).await;
    assert!(matches!(r, Err(crate::auth::AuthError::UntrustedIssuer)));
}
```
(An empty/`None` allowlist keeps the existing valid-path tests passing — update all `authenticate(...)` call sites to pass a default `AuthConfig`.)

- [ ] **Step 2–4:** run-fail, implement (`from_env`, the pre-fetch allowlist check, `UntrustedIssuer` variant, negative-cache in the resolver, thread `AuthConfig` through `authenticate`/`middleware`/`AppState`/`main.rs`), run full suite green + clippy + zero warnings.
- [ ] **Step 5: Commit** — `feat: AuthConfig with optional trusted-issuer allowlist + JWKS negative-cache`

---

### Task 4: Access-token `aud` (audience) validation

**Files:** Modify `src/auth/access_token.rs` (extract `aud`), `src/auth/authenticate.rs` (enforce against config). Test: inline.

**Interfaces:**
- `AccessClaims` gains `pub audience: Vec<String>` — parse `aud` from the verified payload as either a JSON string or array (Solid-OIDC access tokens carry `aud`, often including `"solid"` and/or the RS URL).
- In `authenticate`, if `config.expected_audience` is `Some(a)` and `a ∉ claims.audience` → `Err(AuthError::WrongAudience)` (add variant). If `None` → skip (backward-compatible). Enforce AFTER signature verification (claims are trusted only post-verify).

- [ ] **Step 1: Failing tests** — `TestIdp::mint_access_token` needs to set an `aud` claim; add an `aud` param or a second minting helper `mint_access_token_aud(webid, jkt, exp, aud: &[&str])`. Test: expected-audience set + token `aud` contains it → success; token `aud` lacks it → `WrongAudience`; config `None` → success regardless.

```rust
#[tokio::test]
async fn wrong_audience_is_rejected_when_expected_set() {
    // idp mints aud=["https://other-rs.example/"]; config expects "https://pod.toph.so/"
    // → authenticate → Err(WrongAudience)
}
```

- [ ] **Step 2–4:** run-fail, implement (`aud` parse in `verify_access_token`, `WrongAudience`, enforcement in `authenticate` gated on `config.expected_audience`, extend the mint helper), full suite green + clippy + zero warnings.
- [ ] **Step 5: Commit** — `feat: optional access-token aud validation`

---

### Task 5: WebID-profile content negotiation

`HttpWebIdIssuers` parses the profile as Turtle only → a real IdP serving JSON-LD/other → `401` (interop bug). Negotiate.

**Files:** Modify `src/auth/webid_issuer.rs`. Test: inline.

**Interfaces:**
- The WebID fetch sends `Accept: text/turtle, application/ld+json;q=0.9` (via `guarded_get`, which already takes an `accept` arg).
- Parse the response by its `Content-Type`: map `text/turtle` → `RdfFormat::Turtle`, `application/ld+json` → `RdfFormat::JsonLd{..}` (reuse `rdf::format_for_content_type` from Plan 2); default to Turtle if the header is missing/unknown. `guarded_get` currently returns only the body `String` — extend it (or add a sibling `guarded_get_with_type`) to also return the response `Content-Type`, and thread it here. Then `rdf::parse(body, fmt, doc_url)` and run the same `solid:oidcIssuer` triple check.

- [ ] **Step 1: Failing test** — local server (permissive policy) serving the profile as **JSON-LD** with `Content-Type: application/ld+json`, declaring `<...#me> solid:oidcIssuer <...>`; assert `authorizes` returns `true` (today it would fail, parsing JSON-LD as Turtle).
- [ ] **Step 2–4:** run-fail, implement (return + branch on Content-Type; JSON-LD path via `rdf::parse`), full suite green + clippy + zero warnings.
- [ ] **Step 5: Commit** — `feat: content-negotiate WebID profile (Turtle + JSON-LD)`

---

## Self-Review

**Coverage of the final-review residual list:**
- Bounded/TTL replay store → Task 1. ✓ (shared/Redis multi-replica store still noted as future.)
- DNS-rebinding pinned IP → Task 2. ✓
- Trusted-issuer allowlist + negative-cache (outbound amplification / defense-in-depth) → Task 3. ✓
- Access-token `aud` validation → Task 4. ✓
- WebID content negotiation (interop) → Task 5. ✓
- **Still deferred (out of scope, documented):** shared/persistent replay store for multi-replica; outbound rate-limiting beyond negative-cache; a full trusted-issuer *federation policy* UI.

**Placeholder scan:** Two third-party API-confirm points are explicit (reqwest 0.13 `.resolve`/`resolve_to_addrs` in Task 2; `aud`-as-string-or-array parse in Task 4) with "confirm against docs.rs and adjust" instructions — deliberate for uncertain APIs, not hand-waves. All logic/interfaces are shown.

**Type consistency:** `record_jti_or_reject_replay(jti, now_unix)`, `AuthConfig{trusted_issuers, expected_audience}`, `authenticate(auth_header, dpop_header, htm, htu, resolver, webid_verifier, config, now_unix)` (new `&AuthConfig` arg — every call site updated), `AccessClaims{webid, jkt, issuer, audience}`, `AuthError::{UntrustedIssuer, WrongAudience}` (new variants), `resolve_allowed(host, port, policy)` — consistent across Tasks 1–5. ✓

**Security note:** none of these tasks may weaken Plan 4's verified boundary. Each task's review must re-confirm: ES256 pin, cnf.jkt binding, SSRF IP block (Task 2 tightens it), WebID-issuer binding (Task 5 changes only the parse format, not the triple check), and fail-closed authenticate (Tasks 3/4 add rejects, never a new accept path).
