# SPARQL Solid Pod — Plan 8: Run the Conformance Suite

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the official Solid conformance harness against this pod, from one command, and turn the result into a triaged findings document.

**Architecture:** The harness needs a Solid-OIDC IdP; this pod is verify-only and its outbound fetches are SSRF-hardened, so a local IdP is unreachable by construction. Rather than weakening that hardening globally or testing a binary nobody deploys, a repeatable `--allow-insecure-host` names the hosts the operator vouches for, and relaxes the private-IP and https-only rules **for those hosts only**. A shell runner then starts a local CSS, mints client credentials, starts the pod, and drives both manifests.

**Tech Stack:** Rust (`clap`, `reqwest`), `solidproject/conformance-test-harness` (Docker), Community Solid Server (as IdP only), Bash.

**Builds on:** Plans 1–7, merged to `main` (236 lib + 4 integration tests green). Spec: `docs/superpowers/specs/2026-07-27-conformance-harness-design.md`. Research: `.superpowers/sdd/conformance-suite-research.md`.

## Global Constraints

- **Build/test ONLY via the flake dev shell.** Bare `cargo` fails (oxigraph → bindgen → libclang). Every command: `nix develop -c cargo test`, `nix develop -c cargo clippy --all-targets`, `nix develop -c cargo build 2>&1 | grep -i warning` (must print nothing).
- **NO `#[allow(...)]`.** No deprecated APIs. Clippy clean, zero build warnings.
- **The SSRF hardening is relaxed for named hosts only, never globally.** No flag may make the private-IP filter or the https-only rule inapplicable to a host the operator did not list. Redirect refusal, IP pinning, the body cap and the timeout stay in force for **every** host without exception.
- `FetchPolicy::permissive()` stays `#[cfg(test)]`-gated. Nothing this plan adds may make the fully-permissive combination constructible in a release build.
- **`POD_BASE_URI` must be byte-identical to the origin the harness dials**, or every DPoP `htu` comparison fails.
- **`TEST_CONTAINER` is an absolute pod URL**, which skips the harness's `findStorage()` — that would otherwise require `pim:storage` in the WebID and a `rel="type"` `pim:Storage` link this pod does not emit.
- The pod needs **no ACL bootstrap**: `main.rs` provisions the root ACL for `--owner-webid` at boot. Any step that PUTs an ACL before the run is wrong.
- Conventional commits. TDD for the Rust work; the runner and the triage are driven by evidence, not tests.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/auth/safe_fetch.rs` | outbound fetch policy and its enforcement | `FetchPolicy` gains an operator-named host set |
| `src/auth/http_jwks.rs`, `src/auth/webid_issuer.rs` | the two guarded fetchers | production constructors take a policy |
| `src/config.rs` | CLI/env configuration | `--allow-insecure-host` |
| `src/main.rs` | wiring | passes the policy to both resolvers |
| `conformance/run.sh` | one-command run: CSS, credentials, pod, harness | **new** |
| `conformance/README.md` | what it does, what it needs, how to read the report | **new** |
| `docs/conformance-findings.md` | the triaged result | **new**, Task 3 |

---

### Task 0: Spike — does a CSS client-credentials token satisfy this pod?

The most likely place this whole setup stalls, and it needs no pod changes. Open question 1 of the spec: whether CSS's client-credentials tokens carry `webid` and `iss` in the exact form this pod compares.

**Files:**
- Modify: this plan file — add a `## Spike Results (2026-07-27)` section at the end

**Interfaces:**
- Produces: a recorded recipe — the exact CSS version and start command, how credentials are minted, a decoded specimen token, and a verdict on each of the four claim questions below. Tasks 1 and 2 read it instead of rediscovering it.

- [ ] **Step 1: Start a CSS with client credentials enabled**

```bash
mkdir -p /tmp/conformance-spike && cd /tmp/conformance-spike
npx --yes @solid/community-server@latest -p 3001 -c @css:config/default.json -f ./data &
```

Register a test account through its web UI or its account API, note the WebID it issues, then mint client credentials with the harness's helper (`createCredentials.js` in `solid-contrib/conformance-test-harness`) or CSS's own `/idp/credentials/` endpoint. Record the exact commands that worked.

- [ ] **Step 2: Obtain an access token and decode it**

Exchange the credentials for a DPoP-bound access token. Decode the payload (`base64 -d` on the middle segment) and record it verbatim in the spike section.

- [ ] **Step 3: Answer the four questions that decide the plan**

For each, record the observed value and a yes/no:

1. **`webid` claim** — is there one, and is it the account's WebID? This pod reads `webid` (falling back to `sub` — check `src/auth/access_token.rs` for the exact rule) and compares it as an IRI.
2. **`iss`** — exactly what string? It must match a `--trusted-issuer` entry after the allowlist's slash- and case-insensitive comparison, and it is what the WebID document must name via `solid:oidcIssuer`.
3. **The WebID document** — fetch it as Turtle and as JSON-LD. Does it contain `<webid> solid:oidcIssuer <iss>` with the *same* issuer string? This pod requires a `NamedNode` object, not a literal.
4. **`cnf.jkt`** — present, and does it match the thumbprint of the DPoP key the client uses? Without it the proof-of-possession binding fails.

- [ ] **Step 4: Record the verdict**

Write the `## Spike Results (2026-07-27)` section: the working commands, the specimen token, the four answers, and — if any answer is no — what it means for the plan. A "no" on question 3 is the serious one: it would mean CSS's profile does not satisfy this pod's WebID-issuer binding, and Task 1's smoke test cannot pass without changing either the CSS config or that binding. Say which.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/plans/2026-07-27-conformance-harness.md
git commit -m "docs: record the CSS client-credentials spike for the conformance run"
```

---

### Task 1: `--allow-insecure-host`

**Files:**
- Modify: `src/auth/safe_fetch.rs`, `src/auth/http_jwks.rs`, `src/auth/webid_issuer.rs`, `src/config.rs`, `src/main.rs`, `docs/uri-space.md`
- Test: inline in `src/auth/safe_fetch.rs` and `src/config.rs`

**Interfaces:**
- Consumes: Task 0's recipe (for the smoke test at the end).
- Produces:
  - `FetchPolicy::with_insecure_hosts(hosts: impl IntoIterator<Item = String>) -> FetchPolicy` — the production constructor; the default posture plus an operator-named host set.
  - `FetchPolicy::permits_insecure(&self, host: &str, port: u16) -> bool` — private; an entry matches either `host` (any port) or `host:port` (that port only).
  - `HttpJwksResolver::new(policy: FetchPolicy)` and `HttpWebIdIssuers::new(policy: FetchPolicy)` — the existing no-argument constructors take the policy instead.
  - `Config::allow_insecure_hosts: Vec<String>` (`--allow-insecure-host`, repeatable, env `POD_ALLOW_INSECURE_HOSTS`) and `Config::fetch_policy(&self) -> FetchPolicy`.

- [ ] **Step 1: Write the failing tests**

Add to `src/auth/safe_fetch.rs`'s test module:

```rust
    fn named(hosts: &[&str]) -> FetchPolicy {
        FetchPolicy::with_insecure_hosts(hosts.iter().map(|h| h.to_string()))
    }

    // The rule is "named by the operator", not "private vs public": a host
    // the operator vouched for may be private and may be plain http.
    #[tokio::test]
    async fn a_named_host_may_be_private() {
        let addrs = resolve_allowed("127.0.0.1", 3001, &named(&["127.0.0.1"])).await;
        assert!(addrs.is_ok(), "an operator-named host must be reachable");
    }

    #[tokio::test]
    async fn an_unnamed_host_is_still_blocked() {
        let addrs = resolve_allowed("127.0.0.1", 3001, &named(&["other.example"])).await;
        assert!(addrs.is_err(), "naming one host must not unblock another");
    }

    // Naming a host:port must not open every port on that host — port
    // scanning is most of what an SSRF primitive is worth.
    #[tokio::test]
    async fn naming_a_port_does_not_open_the_others() {
        let policy = named(&["127.0.0.1:3001"]);
        assert!(resolve_allowed("127.0.0.1", 3001, &policy).await.is_ok());
        assert!(resolve_allowed("127.0.0.1", 9999, &policy).await.is_err());
    }

    #[tokio::test]
    async fn naming_a_bare_host_opens_every_port_on_it() {
        let policy = named(&["127.0.0.1"]);
        assert!(resolve_allowed("127.0.0.1", 3001, &policy).await.is_ok());
        assert!(resolve_allowed("127.0.0.1", 9999, &policy).await.is_ok());
    }

    #[tokio::test]
    async fn an_empty_host_list_is_the_default_posture() {
        let addrs = resolve_allowed("127.0.0.1", 3001, &named(&[])).await;
        assert!(addrs.is_err());
    }

    // http is permitted for a named host and refused everywhere else.
    #[tokio::test]
    async fn http_is_refused_for_an_unnamed_host() {
        let c = reqwest::Client::new();
        let r = guarded_get(&c, "http://example.com/x", "text/turtle", &named(&["other.example"])).await;
        assert!(matches!(r, Err(AuthError::FetchBlocked(_))));
    }
```

And to `src/config.rs`'s test module:

```rust
    #[test]
    fn insecure_hosts_are_repeatable_and_default_empty() {
        let c = parse(&["--owner-webid", "https://alice.example/card#me"]).unwrap();
        assert!(c.allow_insecure_hosts.is_empty());

        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--allow-insecure-host", "localhost:3001",
            "--allow-insecure-host", "css.local",
        ]).unwrap();
        assert_eq!(c.allow_insecure_hosts, vec!["localhost:3001", "css.local"]);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test --lib safe_fetch:: config::`
Expected: FAIL — `with_insecure_hosts` and `allow_insecure_hosts` do not exist. (Run the two filters separately; this cargo takes one positional filter.)

- [ ] **Step 3: Implement the policy**

In `src/auth/safe_fetch.rs`, extend the struct and its documentation:

```rust
/// `Default` is the production-safe posture: https-only, private IPs
/// blocked, no named hosts.
///
/// `insecure_hosts` is the operator's explicit exception list. The
/// distinction that matters for SSRF is not private-versus-public but
/// **named-by-the-operator versus chosen-by-the-attacker**: the fetch that
/// this policy guards happens before any credential is verified, so the URL
/// is attacker-influenced — unless the operator has named the host, which is
/// what this list is. For a named host the private-IP filter and the
/// https-only rule do not apply. Everything else still does, for every host:
/// redirects are refused, the connection is pinned to the validated IP, and
/// the body cap and timeout hold.
#[derive(Clone, Default)]
pub struct FetchPolicy {
    allow_http: bool,
    allow_private_ips: bool,
    insecure_hosts: std::sync::Arc<std::collections::HashSet<String>>,
}

impl FetchPolicy {
    /// The production constructor: the safe default plus the hosts the
    /// operator vouched for. An entry may be `host` (any port on it) or
    /// `host:port` (that port only).
    pub fn with_insecure_hosts(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            insecure_hosts: std::sync::Arc::new(hosts.into_iter().collect()),
            ..Self::default()
        }
    }

    /// Whether this exact host (and port) is on the operator's list.
    fn permits_insecure(&self, host: &str, port: u16) -> bool {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        self.insecure_hosts.contains(host)
            || self.insecure_hosts.contains(&format!("{host}:{port}"))
    }
}
```

In `resolve_allowed`, replace the private-IP condition so it consults the list — self-contained, so the signature does not change:

```rust
    let allow_private = policy.allow_private_ips || policy.permits_insecure(host, port);
    if !allow_private && resolved.iter().any(|addr| is_forbidden_ip(addr.ip())) {
```

In `guarded_get`, the scheme check currently runs before the host is parsed. Move the host and port extraction above it, then:

```rust
    let insecure_ok = policy.permits_insecure(host, port);
    match parsed.scheme() {
        "https" => {}
        "http" if policy.allow_http || insecure_ok => {}
        other => {
            return Err(AuthError::FetchBlocked(format!(
                "refusing non-https scheme: {other}"
            )))
        }
    }
```

- [ ] **Step 4: Thread it through**

`HttpJwksResolver::new()` and `HttpWebIdIssuers::new()` currently build a default policy internally. Change both to take `policy: FetchPolicy` and store it. Their `with_policy` test constructors stay as they are.

In `src/config.rs`:

```rust
    /// A host the operator vouches for: the private-IP filter and the
    /// https-only rule do not apply to it. Repeatable. `host` opens every
    /// port on that host; `host:port` opens only that port. Everything else
    /// — redirect refusal, IP pinning, body cap, timeout — still applies.
    /// Pair it with `--trusted-issuer` so an untrusted issuer is rejected
    /// before any fetch is attempted.
    #[arg(long = "allow-insecure-host", env = "POD_ALLOW_INSECURE_HOSTS", value_delimiter = ',')]
    pub allow_insecure_hosts: Vec<String>,
```

and

```rust
    pub fn fetch_policy(&self) -> crate::auth::safe_fetch::FetchPolicy {
        crate::auth::safe_fetch::FetchPolicy::with_insecure_hosts(
            self.allow_insecure_hosts.iter().cloned(),
        )
    }
```

In `src/main.rs`, pass `cfg.fetch_policy()` to both resolvers. When the list is non-empty, log it at startup — an operator should see in the log which hosts their pod will talk to over plain http.

- [ ] **Step 5: Run to verify pass**

Run `nix develop -c cargo test`, then clippy and the warning check. Full suite green.

- [ ] **Step 6: Document it**

Add a section to `docs/uri-space.md` (or a new `docs/deployment.md` if it fits badly there — say which you chose and why): what the flag relaxes, what it does not, and the honest cost — for a listed host the pre-authentication fetch surface is open again, bounded by exactly the entries the operator typed.

- [ ] **Step 7: Smoke-test against the spike's CSS**

Using Task 0's recipe: start the CSS, start the pod with `--allow-insecure-host` and `--trusted-issuer` naming it, and drive one authenticated request (a `PUT` and a `GET` of the same resource) with a real client-credentials token and a real DPoP proof. Record the actual requests and responses in your report.

This is the step that proves the plan is viable. If it fails, stop and report — do not proceed to the runner.

- [ ] **Step 8: Commit**

```bash
git add src/ docs/
git commit -m "feat: --allow-insecure-host for operator-named fetch targets"
```

---

### Task 2: The runner

**Files:**
- Create: `conformance/run.sh`, `conformance/README.md`
- Create: `conformance/harness.env.example` (the harness configuration, with secrets left blank)

**Interfaces:**
- Consumes: Task 0's recipe, Task 1's flag.
- Produces: `conformance/run.sh` — one command, no manual steps, that leaves a harness report on disk.

- [ ] **Step 1: Write the runner**

It must, in order: start a CSS on a fixed port as IdP only; register the test users and mint client credentials (the harness ships `createCredentials.js` — use it rather than reimplementing); write the harness configuration with `TEST_CONTAINER` set to an **absolute pod URL** and the users' credentials; start the pod with `--base-uri` byte-identical to the origin the harness will dial, `--owner-webid` set to the first test user's WebID, `--allow-insecure-host` and `--trusted-issuer` naming the CSS; wait for both to be ready; run the harness image against the `protocol` and `web-access-control` manifests; and stop everything, leaving the report.

**The exact configuration keys, the harness image tag, the manifest names and the `createCredentials.js` invocation are all recorded in `.superpowers/sdd/conformance-suite-research.md` with their sources — read it rather than guessing, and if something there turns out to be wrong, correct that file as part of this task so the next reader is not misled.**

Constraints to honour, each of which the research established:
- **Do not PUT an ACL anywhere.** The pod provisions its root ACL at boot for `--owner-webid`.
- Cleanup between runs is a **pod restart** — the store is in-memory.
- Do not enable the `sparql-update` manifest; it is commented out of the harness's own configuration for good reason here.

- [ ] **Step 2: Make it re-runnable**

Run it twice in a row from a clean checkout. The second run must behave like the first — no leftover state, no port conflicts, no manual cleanup. If it does not, fix the script rather than documenting a workaround.

- [ ] **Step 3: Write `conformance/README.md`**

What the script starts, which ports it uses, what it needs installed (Docker, Node, the flake shell), where the report lands, and how to read it. State plainly that the CSS is an IdP for the test only — it is not part of the pod and nothing in the pod depends on it.

- [ ] **Step 4: Commit**

```bash
git add conformance/
git commit -m "test: one-command conformance harness runner"
```

---

### Task 3: First run and triage

**Files:**
- Create: `docs/conformance-findings.md`

- [ ] **Step 1: Run both manifests**

Run `conformance/run.sh`. Capture the full report.

- [ ] **Step 2: Classify every failure**

Into exactly one of three buckets, with the evidence for the classification:

- **Expected gap** — a feature this pod deliberately does not have. The research predicts: CORS (7 features), `WWW-Authenticate`/`Allow`/`WAC-Allow` (7), `OPTIONS` → 405 (2 scenarios), PATCH (2 partial), and — the big one — everything downstream of non-RDF support, because all six WAC `protected-operation` features build a `text/plain` fixture in a `callonce` background and abort wholesale when it 415s.
- **Pending decision** — the pod behaves deliberately, differently from the test's expectation. Two are predicted: `content-type-reject` expects 400 where this pod answers 415, and `post-target-not-found` expects 404 where this pod materialises ancestors and answers 201. Do not change either; write down what the test wants, what the pod does, and why.
- **Defect** — anything else, and specifically: POST/`Slug`/`Location`, `If-None-Match: *`, containment removal, 409 on a non-empty container, Turtle↔JSON-LD negotiation, the four `acl-object` features, the anonymous-401 rows, or any failure inside `prepareServer`.

A failure you cannot classify goes in a fourth list, named as unclassified, with what you tried. That is more useful than a guess.

- [ ] **Step 3: Write `docs/conformance-findings.md`**

The three buckets, the numbers, and for each defect a one-line reproduction. Head it with the harness version, the manifest revisions and the date, because the next run will want to diff against this one.

- [ ] **Step 4: Commit**

```bash
git add docs/conformance-findings.md
git commit -m "docs: first conformance run — triaged findings"
```

---

### Task 4: Fix the defects

**Files:** determined by Task 3.

- [ ] **Step 1: Fix only the defect bucket**

One commit per defect, each with a regression test at the level the defect lives (a unit test where the logic is wrong, an HTTP test where the response is wrong). Expected gaps and pending decisions are **not** in scope — they leave as named follow-ups.

- [ ] **Step 2: Re-run and diff**

Re-run the harness and confirm each fixed defect now passes and nothing else regressed. Update `docs/conformance-findings.md` with the after-numbers.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "fix: conformance defects from the first run"
```

---

## Verification Summary

For the Rust work (Tasks 1 and 4):

```bash
nix develop -c cargo test
nix develop -c cargo clippy --all-targets
nix develop -c cargo build 2>&1 | grep -i warning   # must print nothing
```

For Tasks 2 and 3 the evidence is the harness report itself, and the runner must produce it twice in a row without manual intervention.

## What this plan does not do

- It does not add non-RDF/blob support, which the research names as the single largest blocker to the WAC manifest. That is its own plan, and this one's findings document is what should justify its priority.
- It does not put the harness in CI. Worth doing once the run is reproducible; the second run in Task 2 Step 2 is the evidence for that, not a substitute.

---

## Spike Results (2026-07-27)

**Verdict: all four questions are YES. The plan is viable as written.** A CSS
client-credentials token satisfies every check this pod performs. Proven not by
inspection but by running a real token through the *production* code path:
`auth::authenticate` with `HttpJwksResolver` + `HttpWebIdIssuers` (the only
substitution being `FetchPolicy::permissive()` in place of the
`--allow-insecure-host` policy Task 1 adds) returned
`Agent::WebId("http://localhost:3001/alice/profile/card#me")` for a live CSS
token, a live DPoP proof, and a live profile fetch. The probe was a temporary
test, run and then reverted; the repository is unchanged by this task.

### The recipe

CSS version: **`@solid/community-server@7.2.0`** (npm `latest` on 2026-07-27;
`next` is `8.0.0-alpha.3`, untested here). Node v22.22.3.

```bash
mkdir -p /tmp/conformance-spike && cd /tmp/conformance-spike
npx --yes @solid/community-server@7.2.0 -p 3001 -c @css:config/default.json -f ./data &
# ready when this returns 200:
until curl -sf -o /dev/null http://localhost:3001/; do sleep 2; done
```

Credentials — the harness's own `createCredentials.js` works **unmodified**
against CSS 7.2.0's account API (version `0.5`). It registers alice and bob,
creates their pods, and prints exactly the four env lines the CTH wants:

```bash
# NOTE: the script lives in solid-contrib/specification-tests, NOT in
# solid-contrib/conformance-test-harness (see "Research correction" below).
curl -sS -o createCredentials.js \
  https://raw.githubusercontent.com/solid-contrib/specification-tests/main/createCredentials.js
node createCredentials.js http://localhost:3001/
```

Observed output (values change per run; the *order of the two users is not
deterministic* — the script runs both `outputCredentials` calls concurrently, so
Task 2 must parse by key, never by line number):

```
USERS_ALICE_CLIENTID=token_9a22fd71-29e0-49bc-a23c-3b46fb00a920
USERS_ALICE_CLIENTSECRET=939ce2dd…35535913f
USERS_BOB_CLIENTID=token_8826b9a1-8151-4355-bdd0-d5bdf035e38c
USERS_BOB_CLIENTSECRET=e218c5f1…047d97d45
```

WebIDs issued: `http://localhost:3001/alice/profile/card#me` and
`http://localhost:3001/bob/profile/card#me`.

Token exchange (what `createCredentials.js` does *not* do — the harness does it
internally; reproduced here to get a specimen). `POST` to the discovered
`token_endpoint` `http://localhost:3001/.oidc/token` with
`grant_type=client_credentials&scope=webid`, HTTP Basic auth over
**URL-encoded** id and secret, and a `DPoP` proof whose `htu` is the token
endpoint and `htm` is `POST`. Discovery (`/.well-known/openid-configuration`)
advertises `client_credentials` in `grant_types_supported` and
`client_secret_basic` in `token_endpoint_auth_methods_supported`. The response
is `{"access_token": "…", "expires_in": 600, "token_type": "DPoP"}`.

### Specimen access token

Header (`cut -d. -f1 token | tr '_-' '/+' | base64 -d`):

```json
{"alg":"ES256","typ":"at+jwt","kid":"0Bgk2ZjgQJqUmIYOvqCr6LL5CkFHweTpT7YQyRAfy5M"}
```

Payload (`cut -d. -f2 token | tr '_-' '/+' | base64 -d`), verbatim:

```json
{"webid":"http://localhost:3001/alice/profile/card#me","jti":"_i6OMT8BWUPxGgAQa7qCd","sub":"token_9a22fd71-29e0-49bc-a23c-3b46fb00a920","iat":1785167501,"exp":1785168101,"client_id":"token_9a22fd71-29e0-49bc-a23c-3b46fb00a920","iss":"http://localhost:3001/","aud":"solid","cnf":{"jkt":"b1E83VAMsxCGg85mcY6CNg7gktdJ-ZeXxBztNIqxyFo"}}
```

### The four answers

**1. `webid` claim — YES.**
Observed: `"webid": "http://localhost:3001/alice/profile/card#me"`, exactly the
WebID `createCredentials.js` reported for the pod it created.

Correction to the question as written: `access_token.rs:77-81` reads `webid` and
has **no `sub` fallback** — a missing `webid` is
`AuthError::Malformed("missing webid claim")`. That is fine here: CSS sets
`webid` on client-credentials tokens, and its `sub` is the *client id*
(`token_9a22fd71-…`), not a WebID, so a `sub` fallback would have been actively
wrong.

**2. `iss` — YES.**
Observed: `"iss": "http://localhost:3001/"` — with trailing slash, scheme `http`,
host `localhost`, port `3001`.

Correction to the question as written: the allowlist comparison
(`authenticate.rs:76-81` → `webid_issuer.rs:154-156`,
`a.trim_end_matches('/') == b.trim_end_matches('/')`) is trailing-slash
insensitive but **case-SENSITIVE**. Verified both directions against the live
token: `--trusted-issuer http://localhost:3001` (no slash) authenticates;
`HTTP://LocalHost:3001/` is rejected with `AuthError::UntrustedIssuer`. So Task 2
must pass the issuer in the same case CSS emits it. Either
`--trusted-issuer http://localhost:3001/` or `…:3001` works.

**3. The WebID document — YES.** This is the one that could have sunk the plan;
it does not.

`GET http://localhost:3001/alice/profile/card` (the fragment-stripped document,
which is what `webid_issuer.rs:123` derives) answers **200** directly — no
redirect, which matters because `guarded_get` refuses 3xx. With the pod's exact
`Accept: text/turtle, application/ld+json;q=0.9` it returns `Content-Type:
text/turtle`:

```turtle
@prefix foaf: <http://xmlns.com/foaf/0.1/>.
@prefix solid: <http://www.w3.org/ns/solid/terms#>.
@prefix pim: <http://www.w3.org/ns/pim/space#>.

<>
    a foaf:PersonalProfileDocument;
    foaf:maker <http://localhost:3001/alice/profile/card#me>;
    foaf:primaryTopic <http://localhost:3001/alice/profile/card#me>.

<http://localhost:3001/alice/profile/card#me>

    solid:oidcIssuer <http://localhost:3001/>;

    a foaf:Person.
```

With `Accept: application/ld+json` it returns `Content-Type: application/ld+json`
and expanded JSON-LD carrying the same statement as a node reference (`@id`, not
a string literal):

```json
{
  "@id": "http://localhost:3001/alice/profile/card#me",
  "http://www.w3.org/ns/solid/terms#oidcIssuer": [
    { "@id": "http://localhost:3001/" }
  ],
  "@type": [ "http://xmlns.com/foaf/0.1/Person" ]
}
```

Every requirement of `HttpWebIdIssuers::authorizes` holds:
- subject is the **exact** WebID `http://localhost:3001/alice/profile/card#me`
  (written absolute in the Turtle, so no base-resolution risk);
- predicate is `http://www.w3.org/ns/solid/terms#oidcIssuer`;
- object is an **IRI node** (`<…>` in Turtle, `{"@id": …}` in JSON-LD) — not a
  literal, which is what the pod requires;
- the object string is `http://localhost:3001/`, **byte-identical** to the
  token's `iss`. No trailing-slash and no case difference to absorb — the
  normalization is not even load-bearing here.

Confirmed against the production verifier, not just by eye: `HttpWebIdIssuers`
(fetch + content-type-negotiated parse + NamedNode match) returned `true` for
(`…/card#me`, `http://localhost:3001/`) and `false` for a different issuer.

**4. `cnf.jkt` — YES.**
Observed: `"cnf": {"jkt": "b1E83VAMsxCGg85mcY6CNg7gktdJ-ZeXxBztNIqxyFo"}`, equal
to the RFC 7638 SHA-256 thumbprint of the ES256 key that signed the DPoP proof
sent to the token endpoint. `token_type` is `DPoP`, and CSS's
`dpop_signing_alg_values_supported` includes `ES256`. `verify_dpop`'s
`verified.jkt != expected_jkt` check passed against a proof minted for the pod's
own `htu`.

### Facts Tasks 1 and 2 need that fell out of this

- **`aud` is the string `"solid"`**, not a pod URL. If Task 2 sets
  `--expected-audience` at all it must be `solid`; setting it to the pod's base
  URI would reject every request. Leaving it unset is also fine.
- **CSS signs access tokens with ES256** (`/.oidc/jwks` publishes a single
  `EC`/`P-256`/`alg: ES256` key with a `kid`, and the token header carries that
  `kid`). This matters because `verify_access_token` pins ES256 regardless of the
  header's `alg` — an RS256-signing IdP would have failed here. CSS does not.
- **`--allow-insecure-host` must name `localhost:3001`**, not `127.0.0.1:3001`.
  All three URLs the pod fetches use the literal host `localhost`:
  `http://localhost:3001/.well-known/openid-configuration`,
  `http://localhost:3001/.oidc/jwks`, and
  `http://localhost:3001/alice/profile/card`. `permits_insecure` matches on the
  host string as written in the URL, before resolution. One entry covers all
  three.
- **Access tokens live 600 s.** The harness re-mints from client credentials, so
  this is not a constraint on run length — but a runner that mints one token up
  front and reuses it would break on any run longer than ten minutes.
- **The profile has no `pim:storage`.** CSS 7.2.0's pod template only emits it
  when `linkStorage` is set, and the account-API pod creation used here does not
  set it. This confirms rather than contradicts the plan's existing constraint:
  `TEST_CONTAINER` must be an absolute pod URL so the harness never calls
  `findStorage()`.
- CSS's own root ACL grants public read (`WAC-Allow: user="read",public="read"`
  on the profile), so the pod's unauthenticated profile fetch works without any
  credential.

### Research correction

`.superpowers/sdd/conformance-suite-research.md` places `createCredentials.js` at
`specification-tests/createCredentials.js` **inside**
`solid-contrib/conformance-test-harness`. That path does not exist: the harness
repo's root has no `specification-tests/` directory. The script is at the root of
the *separate* repository `solid-contrib/specification-tests`
(`https://raw.githubusercontent.com/solid-contrib/specification-tests/main/createCredentials.js`),
which is also where `run.sh`, `application.yaml`, `test-subjects.ttl`,
`protocol/` and `web-access-control/` live. Task 2 should fix that file when it
reads it.
