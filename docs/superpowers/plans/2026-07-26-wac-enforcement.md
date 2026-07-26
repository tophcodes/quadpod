# SPARQL Solid Pod — Plan 6: WAC Enforcement

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the attached-but-unused `Agent` identity into enforced Web Access Control: resolve the applicable ACL (PRP), decide from it (PDP), and gate every LDP handler on that decision.

**Architecture:** A new `src/wac/` module with one responsibility per file — `pdp.rs` (pure decision function, no I/O), `prp.rs` (ACL resolution + upward container walk), `provision.rs` (root ACL bootstrap), `guard.rs` (the `authorize` call handlers make). Handlers in `src/http.rs` each call `authorize(...)` before touching the store. Configuration moves from scattered `std::env::var` reads into a `clap` derive struct, which makes the required owner WebID a startup precondition.

**Tech Stack:** Rust, axum 0.8.9, oxigraph 0.5.9 (`oxrdf` model: `Triple { subject: NamedOrBlankNode, predicate: NamedNode, object: Term }`), `clap` (new), existing auth stack from Plans 4/5.

**Builds on:** Plans 1–5 (all merged to `main`, 100 tests green). Design spec: `docs/superpowers/specs/2026-07-26-wac-enforcement-design.md`. Parent spec §5 (graph layout), §8 (access control).

## Global Constraints

- **Build/test ONLY via the flake dev shell.** Bare `cargo` fails (oxigraph → bindgen → libclang). Every command: `nix develop -c cargo test`, `nix develop -c cargo clippy --all-targets`, `nix develop -c cargo build 2>&1 | grep -i warning` (must be empty).
- **Latest deps** via `cargo add`. No deprecated APIs. NO `#[allow(...)]`.
- **Fail closed.** Every uncertainty denies. A store error during authorization is a 500, never an allow. No ACL found anywhere = deny.
- **Do not weaken Plans 4/5.** The identity-verification boundary (ES256 pin, `cnf.jkt` binding, SSRF IP block, WebID-issuer binding, fail-closed middleware) stays exactly as is. WAC sits *after* it and only ever removes access.
- **No owner bypass.** After root provisioning, the ACL alone decides. The configured owner WebID is an input to provisioning, never a shortcut in `authorize`.
- **Never interpolate unvalidated strings into SPARQL.** Any IRI that reaches an `INSERT DATA`/`DELETE DATA` string must pass `NamedNode::new` first (the Plan-1 injection lesson).
- **Vocabulary IRIs** (use these exact strings):
  - `acl:` = `http://www.w3.org/ns/auth/acl#`
  - `foaf:Agent` = `http://xmlns.com/foaf/0.1/Agent`
  - `rdf:type` = `http://www.w3.org/1999/02/22-rdf-syntax-ns#type` (already `container::RDF_TYPE`)
- Conventional commits. TDD: failing test first, minimal implementation, one commit per task.

---

### Task 0: PDP spike — is `manas_access_control` usable with our own PRP?

Resolves open risk #2 of the parent spec. Everything downstream depends only on the *signature* in Task 2, so this spike decides the body of one file and nothing else.

**Files:**
- Create (throwaway): `tests/spike_wac_pdp.rs`
- Modify (temporarily): `Cargo.toml` (dev-dependencies)
- Modify (permanently): this plan file — add a `## Spike Results (2026-07-26)` section

**Interfaces:**
- Produces: a written verdict — either "rent `manas_access_control`" plus the exact API recipe (constructor calls, type conversions, the `resolve_grants` signature), or "build our own" plus the reason. Task 2 reads this section and nothing else about manas.

- [ ] **Step 1: Add the crates as dev-dependencies**

```bash
nix develop -c cargo add --dev manas_access_control manas_space
nix develop -c cargo build --tests 2>&1 | tail -20
```

Expected: compiles. If it does not compile at all on the current toolchain, that is already the verdict — record it and skip to Step 5.

- [ ] **Step 2: Write the spike test**

Create `tests/spike_wac_pdp.rs`. The goal is to answer four questions in code, not to write a good test:

1. Can a `manas_space::SolidStorageSpace` (or whatever the concrete type is called) be constructed from a plain base URI like `https://pod.toph.so/`, without pulling in `manas_repo`?
2. Does `WacDecisionPoint` accept an ACL graph we build ourselves, and in which RDF term model (`sophia`? `rdf-types`? its own)?
3. If it is a foreign term model: how many lines does converting `Vec<oxigraph::model::Triple>` into it take?
4. What exactly does `resolve_grants` return, and how do we ask "does this contain `acl:Read`"?

```rust
// Spike: throwaway. Not a real test — it exists to answer four questions.
#[tokio::test]
async fn wac_decision_point_accepts_a_hand_built_acl() {
    // 1. build the space from our base URI
    // 2. build this ACL graph in whatever term model the crate wants:
    //      <https://pod.toph.so/.acl#owner> a acl:Authorization ;
    //          acl:agent <https://alice.example/card#me> ;
    //          acl:accessTo <https://pod.toph.so/foo> ;
    //          acl:mode acl:Read .
    // 3. ask: may <https://alice.example/card#me> Read <https://pod.toph.so/foo>?
    // 4. assert yes; then assert a DIFFERENT webid gets no Read.
    todo!("spike body — see the four questions above")
}
```

- [ ] **Step 3: Make it compile and pass**

Run: `nix develop -c cargo test --test spike_wac_pdp -- --nocapture`
Expected: PASS. Iterate against docs.rs for the actual API names; `todo!()` must be gone.

- [ ] **Step 4: Record the verdict in this plan file**

Add a `## Spike Results (2026-07-26)` section at the end of this document containing:
- the exact constructor/call sequence that worked (copy-pasteable),
- the term-model conversion cost in lines,
- the verdict against these criteria:

| Criterion | Rent manas if | Build own if |
|---|---|---|
| Compiles on our toolchain | yes | no |
| Needs `manas_repo` | no | yes |
| Term-model conversion | under ~30 lines | more, or needs a new dependency tree |
| `SolidStorageSpace` construction | takes our base URI as-is | forces a different URI/slot model on `StorageSpace` |

Any single "build own" column hit decides for our own implementation. Rented is the default only if all four favour it.

- [ ] **Step 5: Clean up**

If the verdict is "build own": `nix develop -c cargo remove --dev manas_access_control manas_space` and `rm tests/spike_wac_pdp.rs`.
If the verdict is "rent": `rm tests/spike_wac_pdp.rs` and move the two crates from `[dev-dependencies]` to `[dependencies]` (`nix develop -c cargo remove --dev …` then `nix develop -c cargo add …`).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "docs: record WAC PDP spike verdict (manas_access_control vs own)"
```

---

### Task 1: `clap` configuration layer

Replaces the scattered `std::env::var` reads with one validated config struct, and makes the owner WebID a startup precondition.

**Files:**
- Create: `src/config.rs`
- Modify: `src/lib.rs` (add `pub mod config;`)
- Modify: `src/main.rs` (all 20 lines — it becomes config-driven)
- Modify: `src/auth/config.rs` (remove `AuthConfig::from_env` and `parse_trusted`; the env parsing moves into `Config`)
- Test: inline in `src/config.rs`

**Interfaces:**
- Produces:
  - `sparql_pod::config::Config` — `clap::Parser` struct with fields `base_uri: String`, `owner_webid: String`, `trusted_issuers: Vec<String>`, `expected_audience: Option<String>`, `listen: std::net::SocketAddr`.
  - `Config::auth_config(&self) -> crate::auth::AuthConfig` — maps an empty `trusted_issuers` vec to `None` (open federation), a non-empty one to `Some(HashSet)`.
  - `Config::space(&self) -> Result<crate::space::StorageSpace, crate::space::SpaceError>`.
  - `Config::validated_owner_webid(&self) -> Result<String, ()>` — `Err(())` when the value is not an absolute IRI (`oxigraph::model::NamedNode::new` fails). Task 4 relies on this having run before provisioning.
- Consumes: nothing from other tasks.

- [ ] **Step 1: Add the dependency**

```bash
nix develop -c cargo add clap --features derive,env
```

- [ ] **Step 2: Write the failing tests**

Create `src/config.rs` with only the tests (the struct comes in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_parse_from(std::iter::once("sparql-pod").chain(args.iter().copied()))
    }

    #[test]
    fn owner_webid_is_required() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn flags_populate_every_field() {
        let c = parse(&[
            "--base-uri", "https://pod.toph.so/",
            "--owner-webid", "https://alice.example/card#me",
            "--trusted-issuer", "https://idp.example/",
            "--trusted-issuer", "https://other.example/",
            "--expected-audience", "https://pod.toph.so/",
            "--listen", "0.0.0.0:8080",
        ]).expect("parses");
        assert_eq!(c.base_uri, "https://pod.toph.so/");
        assert_eq!(c.owner_webid, "https://alice.example/card#me");
        assert_eq!(c.trusted_issuers.len(), 2);
        assert_eq!(c.expected_audience.as_deref(), Some("https://pod.toph.so/"));
        assert_eq!(c.listen.to_string(), "0.0.0.0:8080");
    }

    // Plan 5's lesson: a set-but-empty issuer list must mean "open federation",
    // not "trust nobody" (which would be a total auth lockout).
    #[test]
    fn empty_issuer_list_is_open_federation() {
        let c = parse(&["--owner-webid", "https://alice.example/card#me"]).unwrap();
        assert!(c.auth_config().trusted_issuers.is_none());
    }

    #[test]
    fn populated_issuer_list_becomes_the_allowlist() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--trusted-issuer", "https://idp.example/",
        ]).unwrap();
        let set = c.auth_config().trusted_issuers.expect("allowlist");
        assert!(set.contains("https://idp.example/"));
    }

    #[test]
    fn non_iri_owner_webid_is_rejected() {
        let c = parse(&["--owner-webid", "not an iri"]).unwrap();
        assert!(c.validated_owner_webid().is_err());
    }

    #[test]
    fn iri_owner_webid_is_accepted() {
        let c = parse(&["--owner-webid", "https://alice.example/card#me"]).unwrap();
        assert_eq!(
            c.validated_owner_webid().unwrap(),
            "https://alice.example/card#me"
        );
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `nix develop -c cargo test config::`
Expected: FAIL — `cannot find type Config in this scope`.

- [ ] **Step 4: Implement**

Prepend to `src/config.rs`:

```rust
//! Process configuration: command-line flags with environment-variable
//! fallbacks. `clap` provides the precedence (flag > env > default); there is
//! deliberately no hand-written precedence logic on top of it.

use std::collections::HashSet;
use std::net::SocketAddr;

use clap::Parser;
use oxigraph::model::NamedNode;

use crate::auth::AuthConfig;
use crate::space::{SpaceError, StorageSpace};

#[derive(Parser, Debug, Clone)]
#[command(name = "sparql-pod", about = "A SPARQL-authoritative Solid pod")]
pub struct Config {
    /// Public base URI of this pod. Absolute, with a trailing slash. All
    /// minted URLs and the DPoP `htu` derive from this, never from the socket.
    #[arg(long, env = "POD_BASE_URI", default_value = "http://localhost:3000/")]
    pub base_uri: String,

    /// WebID of the pod owner. Required: the root ACL is provisioned for it,
    /// and a pod with no known owner could only be all-open or all-closed.
    #[arg(long, env = "POD_OWNER_WEBID")]
    pub owner_webid: String,

    /// Trusted access-token issuer. Repeatable; may also be given as a
    /// comma-separated list via the environment variable. Empty = open
    /// federation (any issuer may proceed to the WebID-issuer binding check).
    #[arg(long = "trusted-issuer", env = "POD_TRUSTED_ISSUERS", value_delimiter = ',')]
    pub trusted_issuers: Vec<String>,

    /// Expected access-token `aud` value. Unset = no audience check.
    #[arg(long, env = "POD_EXPECTED_AUDIENCE")]
    pub expected_audience: Option<String>,

    /// Address to bind. Plain HTTP — keep it behind the reverse proxy.
    #[arg(long, env = "POD_LISTEN", default_value = "127.0.0.1:3000")]
    pub listen: SocketAddr,
}

impl Config {
    pub fn auth_config(&self) -> AuthConfig {
        let set: HashSet<String> = self
            .trusted_issuers
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        AuthConfig {
            trusted_issuers: if set.is_empty() { None } else { Some(set) },
            expected_audience: self.expected_audience.clone(),
        }
    }

    pub fn space(&self) -> Result<StorageSpace, SpaceError> {
        StorageSpace::new(self.base_uri.clone())
    }

    /// The owner WebID, confirmed to be an absolute IRI. Provisioning
    /// interpolates it into SPARQL, so it must never be unvalidated.
    pub fn validated_owner_webid(&self) -> Result<String, ()> {
        NamedNode::new(&self.owner_webid)
            .map(|_| self.owner_webid.clone())
            .map_err(|_| ())
    }
}
```

Add `pub mod config;` to `src/lib.rs`.

Delete `AuthConfig::from_env` and `parse_trusted` (plus their five `parse_trusted` unit tests) from `src/auth/config.rs`; keep the `AuthConfig` struct, its `Default`, and the `default_is_open_federation` test. Update the doc comment there to point at `crate::config::Config` as the source.

Rewrite `src/main.rs`:

```rust
use std::sync::Arc;
use clap::Parser;
use sparql_pod::{auth::{HttpJwksResolver, HttpWebIdIssuers}, config::Config,
    http::{AppState, router}, store::OxigraphStore};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cfg = Config::parse();
    let space = match cfg.space() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invalid --base-uri: {e}");
            std::process::exit(2);
        }
    };
    if cfg.validated_owner_webid().is_err() {
        eprintln!("invalid --owner-webid: must be an absolute IRI");
        std::process::exit(2);
    }
    let state = AppState {
        store: Arc::new(OxigraphStore::in_memory().expect("store")),
        space,
        resolver: Arc::new(HttpJwksResolver::new()),
        webid_verifier: Arc::new(HttpWebIdIssuers::new()),
        auth_config: Arc::new(cfg.auth_config()),
    };
    sparql_pod::container::provision_root(state.store.as_ref(), &state.space)
        .await.expect("provision root container");
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    tracing::info!("sparql-pod listening on {}", cfg.listen);
    axum::serve(listener, router(state)).await.unwrap();
}
```

(Task 4 adds the root-ACL provisioning call here.)

- [ ] **Step 5: Run the full suite**

Run: `nix develop -c cargo test`
Expected: PASS. Then `nix develop -c cargo clippy --all-targets` (clean) and `nix develop -c cargo build 2>&1 | grep -i warning` (empty).

- [ ] **Step 6: Verify the binary refuses to start without an owner**

```bash
env -u POD_OWNER_WEBID nix develop -c cargo run -- --help
env -u POD_OWNER_WEBID nix develop -c cargo run
```
Expected: `--help` lists all five flags with their env fallbacks; the bare run exits non-zero with clap's "required argument was not provided" error mentioning `--owner-webid`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: clap CLI config with env fallback; require owner WebID at startup"
```

---

### Task 2: `wac/pdp.rs` — the decision function

A pure function: ACL triples in, granted modes out. No store, no async, no I/O — which is why it can be tested exhaustively as a table.

**Files:**
- Create: `src/wac/mod.rs`, `src/wac/pdp.rs`
- Modify: `src/lib.rs` (add `pub mod wac;`)
- Test: inline in `src/wac/pdp.rs`

**Interfaces:**
- Produces (later tasks depend on these exact names):
  - `wac::Mode` — `enum Mode { Read, Write, Append, Control }`, `Copy`.
  - `wac::AccessModes` — `struct { read: bool, write: bool, append: bool, control: bool }`, with `fn allows(self, mode: Mode) -> bool` where `Append` is satisfied by `write` too.
  - `wac::pdp::decide(acl: &[Triple], agent: &Agent, governed_iri: &str, inherited: bool) -> AccessModes`.
    `governed_iri` is the IRI of the resource the ACL document belongs to. `inherited = false` → only `acl:accessTo` authorizations apply; `inherited = true` → only `acl:default` ones.
- Consumes: `crate::auth::Agent`, `oxigraph::model::{Triple, NamedOrBlankNode, Term}`. Plus, if Task 0's verdict was "rent", `manas_access_control` inside the function body only.

- [ ] **Step 1: Write the failing tests**

Create `src/wac/pdp.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdf;
    use oxigraph::io::RdfFormat;

    const ALICE: &str = "https://alice.example/card#me";
    const BOB: &str = "https://bob.example/card#me";
    const FOO: &str = "https://pod.toph.so/foo";
    const BOX_: &str = "https://pod.toph.so/box/";

    fn acl(turtle: &str) -> Vec<Triple> {
        rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, "https://pod.toph.so/foo.acl")
            .expect("test ACL parses")
    }

    fn alice() -> Agent { Agent::WebId(ALICE.to_string()) }

    #[test]
    fn named_agent_gets_its_listed_modes() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
             <{ACL_MODE}> <{ACL_READ}>, <{ACL_WRITE}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Read));
        assert!(m.allows(Mode::Write));
        assert!(m.allows(Mode::Append), "write subsumes append");
        assert!(!m.allows(Mode::Control));
    }

    #[test]
    fn other_agent_gets_nothing() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        let m = decide(&a, &Agent::WebId(BOB.to_string()), FOO, false);
        assert!(!m.allows(Mode::Read));
    }

    #[test]
    fn foaf_agent_grants_the_public_too() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT_CLASS}> <{FOAF_AGENT}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(decide(&a, &Agent::Public, FOO, false).allows(Mode::Read));
        assert!(decide(&a, &alice(), FOO, false).allows(Mode::Read));
    }

    #[test]
    fn authenticated_agent_class_excludes_the_public() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT_CLASS}> <{ACL_AUTHENTICATED_AGENT}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(decide(&a, &alice(), FOO, false).allows(Mode::Read));
        assert!(!decide(&a, &Agent::Public, FOO, false).allows(Mode::Read));
    }

    // An authorization scoped to a DIFFERENT resource must not leak across.
    #[test]
    fn access_to_another_resource_does_not_apply() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/other> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(!decide(&a, &alice(), FOO, false).allows(Mode::Read));
    }

    // acl:default only applies when we reached this ACL by inheritance;
    // acl:accessTo only when we did not. The two must not cross over.
    #[test]
    fn scope_predicate_depends_on_inheritance() {
        let default_only = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <{BOX_}> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(decide(&default_only, &alice(), BOX_, true).allows(Mode::Read));
        assert!(!decide(&default_only, &alice(), BOX_, false).allows(Mode::Read));

        let access_only = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{BOX_}> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(decide(&access_only, &alice(), BOX_, false).allows(Mode::Read));
        assert!(!decide(&access_only, &alice(), BOX_, true).allows(Mode::Read));
    }

    #[test]
    fn authorization_without_modes_grants_nothing() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(!m.allows(Mode::Read) && !m.allows(Mode::Write)
            && !m.allows(Mode::Append) && !m.allows(Mode::Control));
    }

    #[test]
    fn control_is_independent_of_read_and_write() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_CONTROL}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Control));
        assert!(!m.allows(Mode::Read));
        assert!(!m.allows(Mode::Write));
    }

    #[test]
    fn append_alone_does_not_grant_write() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_APPEND}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Append));
        assert!(!m.allows(Mode::Write));
    }

    // Two authorizations, one matching agent + one matching class: the union
    // of their modes applies.
    #[test]
    fn matching_authorizations_union_their_modes() {
        let a = acl(&format!(
            "<#a> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> .\n\
             <#b> <{ACL_AGENT_CLASS}> <{ACL_AUTHENTICATED_AGENT}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Read) && m.allows(Mode::Write));
    }

    #[test]
    fn empty_acl_grants_nothing() {
        assert!(!decide(&[], &alice(), FOO, false).allows(Mode::Read));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test wac::pdp`
Expected: FAIL — `cannot find function decide`, unresolved constants.

- [ ] **Step 3: Implement**

Prepend to `src/wac/pdp.rs`:

```rust
//! The WAC policy decision point: given the applicable ACL triples, which
//! access modes does this agent hold on the governed resource?
//!
//! Deliberately pure — no store access, no async. Everything I/O-shaped lives
//! in `super::prp`. That split is what makes the decision exhaustively
//! table-testable, and it keeps the choice of decision engine local to this
//! file.

use oxigraph::model::{NamedOrBlankNode, Term, Triple};

use crate::auth::Agent;

use super::{AccessModes, Mode};

pub const ACL_AGENT: &str = "http://www.w3.org/ns/auth/acl#agent";
pub const ACL_AGENT_CLASS: &str = "http://www.w3.org/ns/auth/acl#agentClass";
pub const ACL_ACCESS_TO: &str = "http://www.w3.org/ns/auth/acl#accessTo";
pub const ACL_DEFAULT: &str = "http://www.w3.org/ns/auth/acl#default";
pub const ACL_MODE: &str = "http://www.w3.org/ns/auth/acl#mode";
pub const ACL_READ: &str = "http://www.w3.org/ns/auth/acl#Read";
pub const ACL_WRITE: &str = "http://www.w3.org/ns/auth/acl#Write";
pub const ACL_APPEND: &str = "http://www.w3.org/ns/auth/acl#Append";
pub const ACL_CONTROL: &str = "http://www.w3.org/ns/auth/acl#Control";
pub const ACL_AUTHENTICATED_AGENT: &str =
    "http://www.w3.org/ns/auth/acl#AuthenticatedAgent";
pub const ACL_AUTHORIZATION: &str = "http://www.w3.org/ns/auth/acl#Authorization";
pub const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";

/// Which modes `agent` holds on `governed_iri`, according to `acl`.
///
/// `inherited` selects the scope predicate: an ACL reached by walking up to a
/// container grants through `acl:default`, one found directly on the resource
/// through `acl:accessTo`. The two never cross over — otherwise a container's
/// own `accessTo` rules would silently apply to every child.
pub fn decide(acl: &[Triple], agent: &Agent, governed_iri: &str, inherited: bool) -> AccessModes {
    let scope_predicate = if inherited { ACL_DEFAULT } else { ACL_ACCESS_TO };
    let mut granted = AccessModes::default();

    for subject in authorization_subjects(acl) {
        if !has_object(acl, &subject, scope_predicate, governed_iri) {
            continue;
        }
        if !matches_agent(acl, &subject, agent) {
            continue;
        }
        for t in acl.iter().filter(|t| t.subject == subject && t.predicate.as_str() == ACL_MODE) {
            if let Term::NamedNode(m) = &t.object {
                match m.as_str() {
                    ACL_READ => granted.read = true,
                    ACL_WRITE => granted.write = true,
                    ACL_APPEND => granted.append = true,
                    ACL_CONTROL => granted.control = true,
                    _ => {}
                }
            }
        }
    }
    granted
}

/// Every distinct subject in the ACL graph. We do not require an explicit
/// `a acl:Authorization` type triple — WAC treats the scope/agent/mode
/// predicates themselves as what makes an authorization, and many real ACLs
/// omit the type.
fn authorization_subjects(acl: &[Triple]) -> Vec<NamedOrBlankNode> {
    let mut out: Vec<NamedOrBlankNode> = Vec::new();
    for t in acl {
        if !out.contains(&t.subject) {
            out.push(t.subject.clone());
        }
    }
    out
}

fn has_object(acl: &[Triple], subject: &NamedOrBlankNode, predicate: &str, object_iri: &str) -> bool {
    acl.iter().any(|t| {
        t.subject == *subject
            && t.predicate.as_str() == predicate
            && matches!(&t.object, Term::NamedNode(n) if n.as_str() == object_iri)
    })
}

/// `acl:agent <webid>` matches that WebID exactly; `acl:agentClass foaf:Agent`
/// matches everyone including the public; `acl:agentClass acl:AuthenticatedAgent`
/// matches any verified WebID but never the public.
fn matches_agent(acl: &[Triple], subject: &NamedOrBlankNode, agent: &Agent) -> bool {
    if has_object(acl, subject, ACL_AGENT_CLASS, FOAF_AGENT) {
        return true;
    }
    match agent {
        Agent::Public => false,
        Agent::WebId(webid) => {
            has_object(acl, subject, ACL_AGENT_CLASS, ACL_AUTHENTICATED_AGENT)
                || has_object(acl, subject, ACL_AGENT, webid)
        }
    }
}
```

Create `src/wac/mod.rs`:

```rust
//! Web Access Control: resolve the applicable ACL (`prp`), decide from it
//! (`pdp`), and enforce that decision at the HTTP edge (`guard`).

pub mod pdp;

/// A single WAC access mode, as requested by a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Read,
    Write,
    Append,
    Control,
}

/// The set of modes an agent holds on one resource.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessModes {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub control: bool,
}

impl AccessModes {
    /// `Write` subsumes `Append` (a writer may also append); no other mode
    /// implies another. In particular `Control` grants only ACL access, and
    /// neither `Read` nor `Write` implies it.
    pub fn allows(self, mode: Mode) -> bool {
        match mode {
            Mode::Read => self.read,
            Mode::Write => self.write,
            Mode::Append => self.append || self.write,
            Mode::Control => self.control,
        }
    }
}
```

Add `pub mod wac;` to `src/lib.rs`.

If Task 0's verdict was "rent manas": keep this exact `decide` signature and these tests, and implement the body by delegating to `WacDecisionPoint` per the recipe recorded in the Spike Results section. The tests above are the acceptance criteria either way.

- [ ] **Step 4: Run to verify pass**

Run: `nix develop -c cargo test wac::pdp`
Expected: PASS, 11 tests. Then the full suite, clippy, and the warning check.

- [ ] **Step 5: Commit**

```bash
git add src/wac/mod.rs src/wac/pdp.rs src/lib.rs
git commit -m "feat: WAC policy decision point (accessTo/default, agent, agentClass, modes)"
```

---

### Task 3: `wac/prp.rs` — ACL resolution and the upward walk

Finds *which* ACL applies, by looking for `<res>.acl` and otherwise walking up containers to `/.acl`. Also excludes `.acl` graphs from containment, so they never appear in container listings.

**Files:**
- Create: `src/wac/prp.rs`
- Modify: `src/wac/mod.rs` (add `pub mod prp;`)
- Modify: `src/container.rs:43-63` (`add_containment` and `remove_containment` skip ACL children)
- Test: inline in `src/wac/prp.rs`, plus one in `src/container.rs`

**Interfaces:**
- Produces:
  - `wac::prp::acl_path(request_path: &str) -> String` — `/foo` → `/foo.acl`, `/box/` → `/box/.acl`, `/` → `/.acl`.
  - `wac::prp::is_acl_path(request_path: &str) -> bool`.
  - `wac::prp::acl_subject_path(acl_request_path: &str) -> String` — inverse of `acl_path`; `/foo.acl` → `/foo`, `/.acl` → `/`.
  - `wac::prp::EffectiveAcl { pub triples: Vec<Triple>, pub governed_iri: String, pub inherited: bool }`.
  - `wac::prp::effective_acl(store: &dyn SparqlStore, space: &StorageSpace, request_path: &str) -> Result<Option<EffectiveAcl>, ResourceError>`.
- Consumes: `container::parent_container`, `resource::get_rdf`, `space.graph_iri`, and `pdp`'s constants in tests.

- [ ] **Step 1: Write the failing tests**

Create `src/wac/prp.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{ACL_ACCESS_TO, ACL_AGENT, ACL_DEFAULT, ACL_MODE, ACL_READ};
    use crate::{rdf, resource::put_rdf, store::OxigraphStore};
    use oxigraph::io::RdfFormat;

    const ALICE: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    async fn write_acl(store: &OxigraphStore, path: &str, turtle: &str) {
        let base = sp().graph_iri(path).unwrap();
        let t = rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, &base).unwrap();
        put_rdf(store, &sp(), path, &t).await.unwrap();
    }

    #[test]
    fn acl_path_appends_dot_acl() {
        assert_eq!(acl_path("/foo"), "/foo.acl");
        assert_eq!(acl_path("/box/"), "/box/.acl");
        assert_eq!(acl_path("/"), "/.acl");
    }

    #[test]
    fn acl_subject_path_is_the_inverse() {
        assert_eq!(acl_subject_path("/foo.acl"), "/foo");
        assert_eq!(acl_subject_path("/box/.acl"), "/box/");
        assert_eq!(acl_subject_path("/.acl"), "/");
    }

    #[test]
    fn is_acl_path_only_matches_the_suffix() {
        assert!(is_acl_path("/foo.acl"));
        assert!(is_acl_path("/.acl"));
        assert!(!is_acl_path("/foo"));
        assert!(!is_acl_path("/acl"));
        assert!(!is_acl_path("/x.acl/")); // a container that merely looks like one
    }

    #[tokio::test]
    async fn direct_acl_is_found_and_not_marked_inherited() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/foo").await.unwrap().expect("found");
        assert!(!acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/foo");
    }

    #[tokio::test]
    async fn missing_direct_acl_inherits_from_the_nearest_container() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/box/.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/box/item").await.unwrap().expect("found");
        assert!(acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/box/");
    }

    #[tokio::test]
    async fn walk_ascends_all_the_way_to_the_root_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/a/b/c").await.unwrap().expect("found");
        assert!(acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/");
    }

    // WAC: the nearest ACL wins COMPLETELY. An ancestor's rules must not be
    // merged in — otherwise revoking access on a subtree would be impossible.
    #[tokio::test]
    async fn nearest_acl_wins_entirely_over_ancestors() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/.acl", &format!(
            "<#root> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        write_acl(&store, "/box/.acl", &format!(
            "<#box> <{ACL_AGENT}> <https://bob.example/card#me> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/box/item").await.unwrap().expect("found");
        assert_eq!(acl.governed_iri, "https://pod.toph.so/box/");
        assert!(!acl.triples.iter().any(|t| matches!(&t.object,
            oxigraph::model::Term::NamedNode(n) if n.as_str() == ALICE)),
            "root rules must not be merged into the nearer ACL");
    }

    #[tokio::test]
    async fn no_acl_anywhere_is_none() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(effective_acl(&store, &sp(), "/foo").await.unwrap().is_none());
    }

    // An ACL for a resource must not be shadowed by that resource's own
    // graph: /foo.acl is looked up as a graph, /foo is never consulted.
    #[tokio::test]
    async fn resource_data_is_not_mistaken_for_its_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo", "<#it> <http://schema.org/name> \"Toph\" .").await;
        assert!(effective_acl(&store, &sp(), "/foo").await.unwrap().is_none());
    }
}
```

And append to `src/container.rs`'s test module:

```rust
    // ACLs are system resources: they are addressable, but they must never
    // show up as ldp:contains children of their container (Plan 3 deferred
    // this decision; Plan 6 settles it).
    #[tokio::test]
    async fn acl_children_are_not_recorded_as_containment() {
        let store = OxigraphStore::in_memory().unwrap();
        let space = sp();
        ensure_container(&store, &space, "/c/").await.unwrap();
        add_containment(&store, &space, "/c/", "/c/x.acl").await.unwrap();
        assert!(container_is_empty(&store, &space, "/c/").await.unwrap());
        add_containment(&store, &space, "/c/", "/c/x").await.unwrap();
        assert!(!container_is_empty(&store, &space, "/c/").await.unwrap());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test wac::prp` and `nix develop -c cargo test container::`
Expected: both FAIL — missing `effective_acl` etc.; the containment test fails because `.acl` is currently recorded like any child.

- [ ] **Step 3: Implement the PRP**

Prepend to `src/wac/prp.rs`:

```rust
//! The WAC policy retrieval point: find the ACL that governs a resource.
//!
//! The ACL for `<res>` lives in the named graph `<res>.acl` (design spec §5).
//! If that graph does not exist, WAC inheritance applies: walk up the
//! container hierarchy and use the first `.acl` found there, evaluated
//! through `acl:default`. The first ACL found wins completely — ancestor
//! rules are never merged in.

use oxigraph::model::Triple;

use crate::{
    container::parent_container,
    resource::{get_rdf, ResourceError},
    space::StorageSpace,
    store::SparqlStore,
};

/// The ACL that governs a resource, plus the context needed to evaluate it.
pub struct EffectiveAcl {
    /// The ACL graph's triples.
    pub triples: Vec<Triple>,
    /// IRI of the resource this ACL document belongs to — the object that
    /// `acl:accessTo`/`acl:default` must name for an authorization to apply.
    pub governed_iri: String,
    /// True when this ACL was reached by walking up to a container, i.e.
    /// authorizations apply through `acl:default` rather than `acl:accessTo`.
    pub inherited: bool,
}

const ACL_SUFFIX: &str = ".acl";

/// The request path of the ACL governing `request_path`.
pub fn acl_path(request_path: &str) -> String {
    format!("{request_path}{ACL_SUFFIX}")
}

/// True if `request_path` addresses an ACL resource.
pub fn is_acl_path(request_path: &str) -> bool {
    request_path.ends_with(ACL_SUFFIX)
}

/// Inverse of [`acl_path`]: the resource an ACL path governs. Returns the
/// input unchanged if it is not an ACL path.
pub fn acl_subject_path(acl_request_path: &str) -> String {
    acl_request_path
        .strip_suffix(ACL_SUFFIX)
        .unwrap_or(acl_request_path)
        .to_string()
}

/// Resolve the ACL governing `request_path`: the resource's own `.acl` if it
/// exists, else the nearest ancestor container's, else `None` (which the
/// guard turns into a denial — WAC has no implicit grant).
pub async fn effective_acl(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    request_path: &str,
) -> Result<Option<EffectiveAcl>, ResourceError> {
    if let Some(triples) = get_rdf(store, space, &acl_path(request_path)).await? {
        return Ok(Some(EffectiveAcl {
            triples,
            governed_iri: space.graph_iri(request_path)?,
            inherited: false,
        }));
    }
    let mut current = request_path.to_string();
    while let Some(parent) = parent_container(&current) {
        if let Some(triples) = get_rdf(store, space, &acl_path(&parent)).await? {
            return Ok(Some(EffectiveAcl {
                triples,
                governed_iri: space.graph_iri(&parent)?,
                inherited: true,
            }));
        }
        current = parent;
    }
    Ok(None)
}
```

Add `pub mod prp;` to `src/wac/mod.rs`.

- [ ] **Step 4: Implement the containment exclusion**

In `src/container.rs`, add an early return at the top of both `add_containment` and `remove_containment` (before the `graph_iri` calls):

```rust
    // ACLs are addressable resources but not container members: listing them
    // as ldp:contains children would put server-managed access-control
    // documents into every client's view of the container.
    if crate::wac::prp::is_acl_path(child) {
        return Ok(());
    }
```

- [ ] **Step 5: Run to verify pass**

Run: `nix develop -c cargo test wac::prp` then `nix develop -c cargo test`
Expected: PASS, all of them. Clippy clean, zero warnings.

- [ ] **Step 6: Commit**

```bash
git add src/wac/prp.rs src/wac/mod.rs src/container.rs
git commit -m "feat: WAC policy retrieval point (.acl lookup + container walk); exclude ACLs from containment"
```

---

### Task 4: Root ACL provisioning

Without this, an empty pod has no ACL anywhere, so the PRP walk terminates empty and everything is denied — including for the owner. Provisioning is what makes a fresh pod usable.

**Files:**
- Create: `src/wac/provision.rs`
- Modify: `src/wac/mod.rs` (add `pub mod provision;`)
- Modify: `src/main.rs` (call it after `provision_root`)
- Test: inline in `src/wac/provision.rs`

**Interfaces:**
- Produces: `wac::provision::provision_root_acl(store: &dyn SparqlStore, space: &StorageSpace, owner_webid: &str) -> Result<(), ResourceError>`. Idempotent: writes only when the `/.acl` graph is empty. `owner_webid` must already be IRI-validated (`Config::validated_owner_webid` from Task 1); the function re-validates and returns `ResourceError::InvalidIri` rather than trusting the caller, because the value is interpolated into SPARQL.
- Consumes: `resource::get_rdf`, `space.graph_iri`, `pdp`'s ACL constants.

- [ ] **Step 1: Write the failing tests**

Create `src/wac/provision.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{decide, ACL_AGENT_CLASS, FOAF_AGENT};
    use crate::wac::Mode;
    use crate::{auth::Agent, store::OxigraphStore, wac::prp::effective_acl};

    const OWNER: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    #[tokio::test]
    async fn provisioned_root_acl_grants_the_owner_full_control() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER).await.unwrap();

        let acl = effective_acl(&store, &sp(), "/").await.unwrap().expect("root acl");
        let owner = Agent::WebId(OWNER.to_string());
        let direct = decide(&acl.triples, &owner, &acl.governed_iri, acl.inherited);
        assert!(direct.allows(Mode::Read));
        assert!(direct.allows(Mode::Write));
        assert!(direct.allows(Mode::Control));
    }

    // acl:default is what makes the root ACL the fallback for the whole pod.
    #[tokio::test]
    async fn provisioned_root_acl_is_inherited_by_descendants() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER).await.unwrap();

        let acl = effective_acl(&store, &sp(), "/a/b/c").await.unwrap().expect("inherited");
        assert!(acl.inherited);
        let m = decide(&acl.triples, &Agent::WebId(OWNER.to_string()), &acl.governed_iri, true);
        assert!(m.allows(Mode::Write));
    }

    #[tokio::test]
    async fn nobody_else_gets_anything_from_the_default_root_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER).await.unwrap();

        let acl = effective_acl(&store, &sp(), "/foo").await.unwrap().expect("inherited");
        let stranger = Agent::WebId("https://bob.example/card#me".to_string());
        assert!(!decide(&acl.triples, &stranger, &acl.governed_iri, true).allows(Mode::Read));
        assert!(!decide(&acl.triples, &Agent::Public, &acl.governed_iri, true).allows(Mode::Read));
    }

    // Restarting the server must never roll back shares the owner made.
    #[tokio::test]
    async fn existing_root_acl_is_never_overwritten() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER).await.unwrap();
        // simulate the owner editing their ACL: grant the public read
        let g = sp().graph_iri("/.acl").unwrap();
        store.update(&format!(
            "INSERT DATA {{ GRAPH <{g}> {{ <{g}#public> \
             <{ACL_AGENT_CLASS}> <{FOAF_AGENT}> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> }} }}"
        )).await.unwrap();

        provision_root_acl(&store, &sp(), OWNER).await.unwrap(); // restart

        let acl = effective_acl(&store, &sp(), "/foo").await.unwrap().expect("acl");
        assert!(decide(&acl.triples, &Agent::Public, &acl.governed_iri, true).allows(Mode::Read),
            "the owner's edit must survive re-provisioning");
    }

    // The WebID is interpolated into SPARQL; an unvalidated one would be an
    // injection vector (the Plan-1 lesson).
    #[tokio::test]
    async fn non_iri_owner_is_rejected_not_interpolated() {
        let store = OxigraphStore::in_memory().unwrap();
        let err = provision_root_acl(&store, &sp(), "not an iri> } ; DROP ALL ; #").await;
        assert!(matches!(err, Err(ResourceError::InvalidIri)));
        assert!(effective_acl(&store, &sp(), "/").await.unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test wac::provision`
Expected: FAIL — `cannot find function provision_root_acl`.

- [ ] **Step 3: Implement**

Prepend to `src/wac/provision.rs`:

```rust
//! Bootstrap of the root ACL.
//!
//! WAC has no implicit grants: with no ACL anywhere, the PRP walk terminates
//! empty and every request is denied — including the owner's, which would
//! make a fresh pod unusable. Provisioning writes the one authorization that
//! makes the pod owner's own pod reachable.
//!
//! There is deliberately no owner bypass in `super::guard`: after this runs,
//! the ACL alone decides. An owner who deletes their own `acl:Control` rule
//! locks themselves out, exactly as on CSS/ESS.

use oxigraph::model::NamedNode;

use crate::{
    container::RDF_TYPE,
    resource::{get_rdf, ResourceError},
    space::StorageSpace,
    store::SparqlStore,
};

use super::pdp::{
    ACL_ACCESS_TO, ACL_AGENT, ACL_AUTHORIZATION, ACL_CONTROL, ACL_DEFAULT, ACL_MODE, ACL_READ,
    ACL_WRITE,
};

/// Write the root ACL granting `owner_webid` Read/Write/Control over the
/// whole pod, unless `/.acl` already has content. Idempotent, and safe to
/// call on every start.
pub async fn provision_root_acl(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    owner_webid: &str,
) -> Result<(), ResourceError> {
    // Validated because it is interpolated into SPARQL below.
    NamedNode::new(owner_webid).map_err(|_| ResourceError::InvalidIri)?;

    if get_rdf(store, space, "/.acl").await?.is_some() {
        return Ok(());
    }
    let acl_graph = space.graph_iri("/.acl")?;
    let root = space.graph_iri("/")?;
    let subject = format!("{acl_graph}#owner");
    NamedNode::new(&subject).map_err(|_| ResourceError::InvalidIri)?;

    store
        .update(&format!(
            "INSERT DATA {{ GRAPH <{acl_graph}> {{ \
             <{subject}> <{RDF_TYPE}> <{ACL_AUTHORIZATION}> . \
             <{subject}> <{ACL_AGENT}> <{owner_webid}> . \
             <{subject}> <{ACL_ACCESS_TO}> <{root}> . \
             <{subject}> <{ACL_DEFAULT}> <{root}> . \
             <{subject}> <{ACL_MODE}> <{ACL_READ}> . \
             <{subject}> <{ACL_MODE}> <{ACL_WRITE}> . \
             <{subject}> <{ACL_MODE}> <{ACL_CONTROL}> }} }}"
        ))
        .await?;
    Ok(())
}
```

Add `pub mod provision;` to `src/wac/mod.rs`.

In `src/main.rs`, after the existing `provision_root(...)` call:

```rust
    let owner = cfg.validated_owner_webid().expect("owner WebID validated above");
    sparql_pod::wac::provision::provision_root_acl(state.store.as_ref(), &state.space, &owner)
        .await.expect("provision root ACL");
```

- [ ] **Step 4: Run to verify pass**

Run: `nix develop -c cargo test wac::provision` then `nix develop -c cargo test`
Expected: PASS. Clippy clean, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/wac/provision.rs src/wac/mod.rs src/main.rs
git commit -m "feat: provision root ACL for the configured owner (idempotent)"
```

---

### Task 5: `wac/guard.rs` and enforcement in every handler

The task that actually closes the pod. Until now nothing reads the `Agent`.

**Files:**
- Create: `src/wac/guard.rs`
- Modify: `src/wac/mod.rs` (add `pub mod guard;`)
- Modify: `src/http.rs:32-239` (all four `*_impl` functions and their eight handler wrappers)
- Test: inline in `src/wac/guard.rs` (unit) and `src/http.rs` (integration)

**Interfaces:**
- Produces:
  - `wac::guard::authorize(store: &dyn SparqlStore, space: &StorageSpace, agent: &Agent, request_path: &str, mode: Mode) -> Result<(), Response>` — `Ok(())` means allowed. `Err` carries the response to return verbatim: 401 (+ `WWW-Authenticate: DPoP algs="ES256"`) for `Agent::Public`, 403 for a verified WebID, 500 on a store error, 400 on an unroutable path.
  - **ACL rewrite:** when `request_path` is an ACL path, `authorize` ignores the requested `mode` and instead requires `Control` on the governed resource. Handlers therefore need no special casing for `.acl` beyond skipping the *parent-container* check (an ACL is not a container member).
- Consumes: `prp::{effective_acl, is_acl_path, acl_subject_path}`, `pdp::decide`, `Mode`, `AccessModes`.

- [ ] **Step 1: Write the failing unit tests**

Create `src/wac/guard.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{ACL_ACCESS_TO, ACL_AGENT, ACL_CONTROL, ACL_MODE, ACL_READ};
    use crate::{rdf, resource::put_rdf, store::OxigraphStore};
    use oxigraph::io::RdfFormat;

    const ALICE: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }
    fn alice() -> Agent { Agent::WebId(ALICE.to_string()) }

    async fn write_acl(store: &OxigraphStore, path: &str, turtle: &str) {
        let base = sp().graph_iri(path).unwrap();
        let t = rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, &base).unwrap();
        put_rdf(store, &sp(), path, &t).await.unwrap();
    }

    fn status(r: Result<(), Response>) -> Option<StatusCode> {
        r.err().map(|res| res.status())
    }

    #[tokio::test]
    async fn granted_mode_is_allowed() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        assert!(authorize(&store, &sp(), &alice(), "/foo", Mode::Read).await.is_ok());
    }

    #[tokio::test]
    async fn missing_mode_denies_authenticated_agent_with_403() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        assert_eq!(
            status(authorize(&store, &sp(), &alice(), "/foo", Mode::Write).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn public_denial_is_401_with_a_challenge() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let res = authorize(&store, &sp(), &Agent::Public, "/foo", Mode::Read).await
            .expect_err("denied");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(header::WWW_AUTHENTICATE).is_some());
    }

    // No ACL anywhere = no grant. WAC has no implicit allow.
    #[tokio::test]
    async fn no_acl_anywhere_denies() {
        let store = OxigraphStore::in_memory().unwrap();
        assert_eq!(
            status(authorize(&store, &sp(), &alice(), "/foo", Mode::Read).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    // Reading an ACL needs Control on the governed resource — Read on the
    // resource is explicitly NOT enough, or every reader could see who else
    // has access.
    #[tokio::test]
    async fn acl_access_requires_control_not_read() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        assert_eq!(
            status(authorize(&store, &sp(), &alice(), "/foo.acl", Mode::Read).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn control_grants_acl_access() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        assert!(authorize(&store, &sp(), &alice(), "/foo.acl", Mode::Read).await.is_ok());
        assert!(authorize(&store, &sp(), &alice(), "/foo.acl", Mode::Write).await.is_ok());
    }

    // Write subsumes Append, so a writer may POST into a container.
    #[tokio::test]
    async fn write_satisfies_an_append_requirement() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/box/.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <http://www.w3.org/ns/auth/acl#Write> ."
        )).await;
        assert!(authorize(&store, &sp(), &alice(), "/box/", Mode::Append).await.is_ok());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test wac::guard`
Expected: FAIL — `cannot find function authorize`.

- [ ] **Step 3: Implement the guard**

Prepend to `src/wac/guard.rs`:

```rust
//! The enforcement point: one call handlers make before touching the store.
//!
//! Fails closed in every direction — a missing ACL, a store error, or an
//! unroutable path all deny. The only path to `Ok(())` is an ACL that
//! explicitly grants the requested mode to this agent.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::{auth::Agent, space::StorageSpace, store::SparqlStore};

use super::{pdp, prp, Mode};

/// The challenge sent with a 401, telling a client which credential the pod
/// accepts. `Bearer` is deliberately absent: Plan 4 verifies DPoP-bound
/// tokens only.
const DPOP_CHALLENGE: &str = "DPoP algs=\"ES256\"";

/// Deny in the way that tells the caller the truth without leaking anything:
/// an anonymous caller learns that credentials would help (401), a verified
/// one that theirs are insufficient (403). Neither learns whether the
/// resource exists — `authorize` runs before any existence check.
fn deny(agent: &Agent) -> Response {
    match agent {
        Agent::Public => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, DPOP_CHALLENGE)],
        )
            .into_response(),
        Agent::WebId(_) => StatusCode::FORBIDDEN.into_response(),
    }
}

/// May `agent` perform `mode` on `request_path`?
///
/// A request for an ACL resource (`<res>.acl`) is rewritten: the decision is
/// made against `<res>` and always requires `acl:Control`, whatever `mode`
/// the handler asked for. That rewrite lives here rather than in the
/// handlers so no handler can forget it.
pub async fn authorize(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    agent: &Agent,
    request_path: &str,
    mode: Mode,
) -> Result<(), Response> {
    let (target, required) = if prp::is_acl_path(request_path) {
        (prp::acl_subject_path(request_path), Mode::Control)
    } else {
        (request_path.to_string(), mode)
    };

    let acl = match prp::effective_acl(store, space, &target).await {
        Ok(Some(acl)) => acl,
        Ok(None) => return Err(deny(agent)),
        Err(crate::resource::ResourceError::InvalidIri) => {
            return Err(StatusCode::BAD_REQUEST.into_response())
        }
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    };

    if pdp::decide(&acl.triples, agent, &acl.governed_iri, acl.inherited).allows(required) {
        Ok(())
    } else {
        Err(deny(agent))
    }
}
```

Add `pub mod guard;` to `src/wac/mod.rs`.

- [ ] **Step 4: Wire the guard into every handler**

In `src/http.rs`, add to the imports:

```rust
use axum::Extension;
use crate::{auth::Agent, wac::{guard::authorize, prp, Mode}};
```

Every handler wrapper gains an `Extension<Agent>` parameter (before any body-consuming extractor, which axum requires) and passes it to its `*_impl`. For example:

```rust
async fn handle_put(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap, body: Bytes,
) -> Response {
    put_impl(st, agent, format!("/{path}"), headers, body).await
}

async fn handle_put_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>, headers: HeaderMap, body: Bytes,
) -> Response {
    put_impl(st, agent, "/".to_string(), headers, body).await
}
```

Do the same for `handle_get`/`handle_get_root`, `handle_post`/`handle_post_root`, `handle_delete`/`handle_delete_root`. `Extension<Agent>` is infallible in practice — `auth_layer` inserts it on every request that reaches a handler — and a missing extension yields a 500, which is the fail-closed direction.

`get_impl` — first statement after the signature change:

```rust
async fn get_impl(st: AppState, agent: Agent, req_path: String, headers: HeaderMap) -> Response {
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &req_path, Mode::Read).await {
        return res;
    }
    // ... existing body unchanged
```

`post_impl` — after the existing `is_container_path` check (POSTing to a non-container is a 409 regardless of who asks):

```rust
async fn post_impl(st: AppState, agent: Agent, container_path: String, headers: HeaderMap, body: Bytes) -> Response {
    if !container::is_container_path(&container_path) {
        return StatusCode::CONFLICT.into_response();
    }
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &container_path, Mode::Append).await {
        return res;
    }
    // ... existing body unchanged
```

`put_impl` — the authorization goes first, before the content-type check and before any store access:

```rust
async fn put_impl(st: AppState, agent: Agent, req_path: String, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &req_path, Mode::Write).await {
        return res;
    }
    // Creating a resource changes its parent container's containment triples,
    // so it additionally needs Append there. Existence is only consulted
    // AFTER Write on the target was granted, so it can never become an
    // existence oracle for an unauthorized caller. ACLs are not container
    // members (see wac::prp), so they skip this check.
    if !prp::is_acl_path(&req_path) {
        let exists = matches!(get_rdf(st.store.as_ref(), &st.space, &req_path).await, Ok(Some(_)));
        if !exists {
            if let Some(parent) = container::parent_container(&req_path) {
                if let Err(res) =
                    authorize(st.store.as_ref(), &st.space, &agent, &parent, Mode::Append).await
                {
                    return res;
                }
            }
        }
    }
    // ... existing body unchanged
```

`delete_impl` — Write on the target, plus Write on the parent whose containment changes:

```rust
async fn delete_impl(st: AppState, agent: Agent, req_path: String) -> Response {
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &req_path, Mode::Write).await {
        return res;
    }
    if !prp::is_acl_path(&req_path) {
        if let Some(parent) = container::parent_container(&req_path) {
            if let Err(res) =
                authorize(st.store.as_ref(), &st.space, &agent, &parent, Mode::Write).await
            {
                return res;
            }
        }
    }
    // ... existing body unchanged
```

- [ ] **Step 5: Update the existing handler tests to authenticate**

Every test in `src/http.rs`'s test module currently sends no credentials and expects success — after this task they would all get 401, correctly. Give the test app a provisioned owner and send owner credentials.

Replace the `app()` helper and add fixtures:

```rust
    use crate::auth::testsupport::{TestClient, TestIdp};
    use crate::auth::StaticWebIdIssuers;
    use std::time::{SystemTime, UNIX_EPOCH};

    const OWNER: &str = "https://alice.example/card#me";
    const ISSUER: &str = "https://idp.example/";

    /// An app whose root ACL grants OWNER full control, plus the IdP and
    /// client needed to mint credentials for them.
    struct Fixture {
        app: axum::Router,
        idp: TestIdp,
        client: TestClient,
    }

    async fn fixture() -> Fixture {
        let store = Arc::new(OxigraphStore::in_memory().unwrap());
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        crate::container::provision_root(store.as_ref(), &space).await.unwrap();
        crate::wac::provision::provision_root_acl(store.as_ref(), &space, OWNER).await.unwrap();

        let idp = TestIdp::new();
        let client = TestClient::new();
        let mut issuers = StaticWebIdIssuers::new();
        issuers.allow(OWNER, ISSUER);

        let state = AppState {
            store,
            space,
            resolver: Arc::new(StaticJwksResolver::new(ISSUER, idp.jwks())),
            webid_verifier: Arc::new(issuers),
            auth_config: Arc::new(crate::auth::AuthConfig::default()),
        };
        Fixture { app: router(state), idp, client }
    }

    fn now_unix() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    impl Fixture {
        /// Add credentials for `webid` to a request builder. The DPoP proof's
        /// `htu` must be the CONFIGURED base plus the path (never the socket),
        /// and its `jti` must be unique — the replay store rejects reuse.
        fn sign(
            &self,
            builder: axum::http::request::Builder,
            webid: &str,
            method: &str,
            path: &str,
        ) -> axum::http::request::Builder {
            let at = self.idp.mint_access_token(webid, &self.client.jkt(), now_unix() + 3600);
            let htu = format!("https://pod.toph.so{path}");
            let jti = uuid::Uuid::new_v4().to_string();
            let proof = self.client.mint_dpop(&htu, method, now_unix(), &jti);
            builder
                .header(header::AUTHORIZATION, format!("DPoP {at}"))
                .header("dpop", proof)
        }

        /// A request authenticated as the pod owner.
        fn owner_request(&self, method: &str, path: &str) -> axum::http::request::Builder {
            let b = Request::builder().method(method).uri(path);
            self.sign(b, OWNER, method, path)
        }
    }
```

Then rewrite each existing test to build its requests through `owner_request(...)`. For example, `put_turtle_then_get_jsonld_negotiates` becomes:

```rust
    #[tokio::test]
    async fn put_turtle_then_get_jsonld_negotiates() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        let put_res = f.app.clone().oneshot(put).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::CREATED);
        assert_eq!(put_res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/foo");

        let get = f.owner_request("GET", "/foo")
            .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/ld+json");
        assert!(body_string(res).await.contains("schema.org/name"));
    }
```

Apply the same mechanical change to every other test in the module. The assertions stay as they are — only the credentials are added. Any test whose assertion *changes* is a finding, not a fixup: report it rather than adjusting the expectation.

Delete the now-unused `app()`, `unused_resolver()` and `unused_webid_verifier()` helpers.

- [ ] **Step 6: Add the enforcement integration tests**

Append to `src/http.rs`'s test module:

```rust
    #[tokio::test]
    async fn anonymous_get_is_401_with_a_challenge() {
        let f = fixture().await;
        let res = f.app.oneshot(
            Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(header::WWW_AUTHENTICATE).is_some());
    }

    #[tokio::test]
    async fn authenticated_stranger_is_403() {
        let f = fixture().await;
        // A verified WebID the root ACL says nothing about. It must be
        // allowed through authentication (the issuer vouches for it) and
        // stopped by authorization.
        let stranger = "https://bob.example/card#me";
        let mut issuers = StaticWebIdIssuers::new();
        issuers.allow(OWNER, ISSUER);
        issuers.allow(stranger, ISSUER);
        let store = Arc::new(OxigraphStore::in_memory().unwrap());
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        crate::container::provision_root(store.as_ref(), &space).await.unwrap();
        crate::wac::provision::provision_root_acl(store.as_ref(), &space, OWNER).await.unwrap();
        let f2 = Fixture {
            app: router(AppState {
                store, space,
                resolver: Arc::new(StaticJwksResolver::new(ISSUER, f.idp.jwks())),
                webid_verifier: Arc::new(issuers),
                auth_config: Arc::new(crate::auth::AuthConfig::default()),
            }),
            idp: f.idp,
            client: f.client,
        };
        let req = f2.sign(Request::builder().method("GET").uri("/foo"), stranger, "GET", "/foo")
            .body(Body::empty()).unwrap();
        assert_eq!(f2.app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
    }

    // The denial must not depend on whether the resource exists — otherwise
    // the status code is an existence oracle for the whole namespace.
    #[tokio::test]
    async fn denial_does_not_reveal_existence() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/secret")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"s\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        let existing = f.app.clone().oneshot(
            Request::builder().method("GET").uri("/secret").body(Body::empty()).unwrap()
        ).await.unwrap().status();
        let absent = f.app.oneshot(
            Request::builder().method("GET").uri("/does-not-exist").body(Body::empty()).unwrap()
        ).await.unwrap().status();
        assert_eq!(existing, absent);
        assert_eq!(existing, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn owner_can_grant_another_agent_read_via_an_acl() {
        let f = fixture().await;
        let bob = "https://bob.example/card#me";
        let put = f.owner_request("PUT", "/shared")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"shared\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        let acl_body = format!(
            "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/shared> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."
        );
        let put_acl = f.owner_request("PUT", "/shared.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl_body)).unwrap();
        assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

        // Bob (a verified WebID) may now read it, but still may not write it.
        let mut issuers = StaticWebIdIssuers::new();
        issuers.allow(bob, ISSUER);
        // Rebuild the app around the SAME store so the writes above are visible.
        // (Fixture keeps its store inside AppState; capture it in `fixture()`
        // if this proves awkward — see Step 7.)
    }

    #[tokio::test]
    async fn acl_is_not_listed_as_a_container_child() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/item")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"i\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();
        let put_acl = f.owner_request("PUT", "/item.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(format!(
                "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/item> ; \
                 <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
            ))).unwrap();
        f.app.clone().oneshot(put_acl).await.unwrap();

        let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
        let listing = body_string(f.app.oneshot(get).await.unwrap()).await;
        assert!(listing.contains("https://pod.toph.so/item"));
        assert!(!listing.contains("item.acl"));
    }
```

- [ ] **Step 7: Make the fixture reusable across identities**

`owner_can_grant_another_agent_read_via_an_acl` needs a second app over the *same* store. Change `Fixture` to keep its parts so a second router can be built:

```rust
    struct Fixture {
        app: axum::Router,
        store: Arc<dyn crate::store::SparqlStore>,
        space: StorageSpace,
        idp: TestIdp,
        client: TestClient,
    }

    impl Fixture {
        /// A second app over the same store, authenticating `webid` as well.
        fn app_also_trusting(&self, webid: &str) -> axum::Router {
            let mut issuers = StaticWebIdIssuers::new();
            issuers.allow(OWNER, ISSUER);
            issuers.allow(webid, ISSUER);
            router(AppState {
                store: self.store.clone(),
                space: self.space.clone(),
                resolver: Arc::new(StaticJwksResolver::new(ISSUER, self.idp.jwks())),
                webid_verifier: Arc::new(issuers),
                auth_config: Arc::new(crate::auth::AuthConfig::default()),
            })
        }
    }
```

Then finish the two tests that need a second identity:

```rust
        let bob_app = f.app_also_trusting(bob);
        let read = f.sign(Request::builder().method("GET").uri("/shared"), bob, "GET", "/shared")
            .body(Body::empty()).unwrap();
        assert_eq!(bob_app.clone().oneshot(read).await.unwrap().status(), StatusCode::OK);

        let write = f.sign(Request::builder().method("PUT").uri("/shared"), bob, "PUT", "/shared")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"hijacked\" .")).unwrap();
        assert_eq!(bob_app.clone().oneshot(write).await.unwrap().status(), StatusCode::FORBIDDEN);

        // Bob has Read on the resource but no Control, so its ACL stays hidden.
        let read_acl = f.sign(Request::builder().method("GET").uri("/shared.acl"), bob, "GET", "/shared.acl")
            .body(Body::empty()).unwrap();
        assert_eq!(bob_app.oneshot(read_acl).await.unwrap().status(), StatusCode::FORBIDDEN);
```

Rewrite `authenticated_stranger_is_403` to use `app_also_trusting` instead of building a second `AppState` by hand.

- [ ] **Step 8: Run the full suite**

Run: `nix develop -c cargo test`
Expected: PASS — every pre-existing test still asserts what it asserted before, only with credentials attached. Then `nix develop -c cargo clippy --all-targets` (clean) and `nix develop -c cargo build 2>&1 | grep -i warning` (empty).

- [ ] **Step 9: Commit**

```bash
git add src/wac/guard.rs src/wac/mod.rs src/http.rs
git commit -m "feat: enforce WAC in every LDP handler (401/403, no existence leak)"
```

---

### Task 6: `Link: rel="acl"` discovery header

A Solid client cannot find a resource's ACL without this header. Small, but it is what makes ACLs usable by third-party apps rather than only by someone who knows our naming convention.

**Files:**
- Modify: `src/http.rs` (`get_impl`, `put_impl`, `post_impl` responses)
- Test: inline in `src/http.rs`

**Interfaces:**
- Produces: `fn acl_link(space: &StorageSpace, request_path: &str) -> Option<(header::HeaderName, String)>` in `src/http.rs` — the `Link: <acl-iri>; rel="acl"` header value, or `None` when the path itself is an ACL (an ACL has no ACL of its own; it is governed by its subject resource).
- Consumes: `prp::{acl_path, is_acl_path}`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn get_advertises_the_acl_location() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();

        let res = f.app.oneshot(f.owner_request("GET", "/foo").body(Body::empty()).unwrap())
            .await.unwrap();
        let link = res.headers().get(header::LINK).expect("Link header").to_str().unwrap().to_string();
        assert!(link.contains("https://pod.toph.so/foo.acl"));
        assert!(link.contains("rel=\"acl\""));
    }

    #[tokio::test]
    async fn created_resource_advertises_the_acl_location() {
        let f = fixture().await;
        let res = f.app.oneshot(f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        assert!(res.headers().get(header::LINK).unwrap().to_str().unwrap()
            .contains("https://pod.toph.so/foo.acl"));
    }

    // An ACL resource does not advertise an ACL of its own — it is governed
    // by acl:Control on its subject resource, and /foo.acl.acl never exists.
    #[tokio::test]
    async fn acl_resource_advertises_no_further_acl() {
        let f = fixture().await;
        let acl_body = format!(
            "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/foo> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
        );
        f.app.clone().oneshot(f.owner_request("PUT", "/foo.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl_body)).unwrap()).await.unwrap();

        let res = f.app.oneshot(f.owner_request("GET", "/foo.acl").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().get(header::LINK).is_none());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test http::tests::get_advertises`
Expected: FAIL — no `Link` header present.

- [ ] **Step 3: Implement**

Add to `src/http.rs`:

```rust
/// The `Link: <…>; rel="acl"` header a Solid client uses to discover where a
/// resource's ACL lives. `None` for ACL resources themselves — an ACL is
/// governed by `acl:Control` on its subject, not by an ACL of its own.
fn acl_link(space: &StorageSpace, request_path: &str) -> Option<(header::HeaderName, String)> {
    if prp::is_acl_path(request_path) {
        return None;
    }
    let iri = space.graph_iri(&prp::acl_path(request_path)).ok()?;
    Some((header::LINK, format!("<{iri}>; rel=\"acl\"")))
}
```

Attach it in `get_impl`'s success arm and in the three `CREATED` responses (`put_impl`'s container branch, `put_impl`'s resource branch, `post_impl`). Since `axum`'s array-of-headers form needs a fixed shape, build the response with a `HeaderMap` where a header is conditional, e.g.:

```rust
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, fmt.media_type().parse().expect("static media type"));
            headers.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
            if let Some((name, value)) = acl_link(&st.space, &req_path) {
                headers.insert(name, value.parse().expect("acl link is header-safe"));
            }
            (headers, bytes).into_response()
```

- [ ] **Step 4: Run to verify pass**

Run: `nix develop -c cargo test` — PASS. Clippy clean, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src/http.rs
git commit -m "feat: advertise ACL location via Link rel=\"acl\""
```

---

### Task 7: Route-coverage test and adversarial review

The structural safeguard for the per-handler-guard design: a test that no route can be reached unauthorized, so a future handler added without a guard fails the suite instead of shipping a hole.

**Files:**
- Create: `tests/route_coverage.rs`
- Test: that file
- Modify: `src/http.rs` — only if the test finds an unguarded path

**Interfaces:**
- Consumes: `sparql_pod::{http::{router, AppState}, space::StorageSpace, store::OxigraphStore, container, wac}`. Note this is an *integration* test (`tests/`), so it may only use the public API — `auth::testsupport` is `#[cfg(test)]`-gated and therefore unavailable. That is fine: this test sends no credentials at all.

- [ ] **Step 1: Write the test**

Create `tests/route_coverage.rs`:

```rust
//! Every route, every verb, no credentials: the answer must always be a
//! refusal. This is the structural safeguard for Plan 6's per-handler guard
//! design — a handler added later without an `authorize` call fails here
//! rather than silently exposing the store.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sparql_pod::{
    auth::AuthConfig,
    auth::{StaticJwksResolver, StaticWebIdIssuers, Jwks},
    container,
    http::{router, AppState},
    space::StorageSpace,
    store::OxigraphStore,
    wac,
};
use tower::ServiceExt;

const OWNER: &str = "https://alice.example/card#me";

async fn app() -> axum::Router {
    let store = Arc::new(OxigraphStore::in_memory().unwrap());
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    container::provision_root(store.as_ref(), &space).await.unwrap();
    wac::provision::provision_root_acl(store.as_ref(), &space, OWNER).await.unwrap();
    // Seed content so that "not found" can never be the reason for a refusal.
    let t = sparql_pod::rdf::parse(
        b"<#it> <http://schema.org/name> \"seed\" .",
        oxigraph::io::RdfFormat::Turtle,
        "https://pod.toph.so/seeded",
    ).unwrap();
    sparql_pod::resource::put_rdf(store.as_ref(), &space, "/seeded", &t).await.unwrap();

    router(AppState {
        store,
        space,
        resolver: Arc::new(StaticJwksResolver::new("https://idp.example/", Jwks { keys: vec![] })),
        webid_verifier: Arc::new(StaticWebIdIssuers::new()),
        auth_config: Arc::new(AuthConfig::default()),
    })
}

#[tokio::test]
async fn no_route_serves_an_unauthenticated_request() {
    let paths = [
        "/", "/seeded", "/seeded.acl", "/.acl", "/box/", "/box/child",
        "/does-not-exist", "/a/b/c",
    ];
    let methods = ["GET", "PUT", "POST", "DELETE"];

    for path in paths {
        for method in methods {
            let app = app().await;
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#it> <http://schema.org/name> \"x\" ."))
                .unwrap();
            let status = app.oneshot(req).await.unwrap().status();
            assert!(
                status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
                "{method} {path} returned {status}, expected 401/403 — is a guard missing?"
            );
        }
    }
}
```

- [ ] **Step 2: Run it**

Run: `nix develop -c cargo test --test route_coverage`
Expected: PASS. **Any** other status is a genuine finding — fix the handler, do not relax the assertion. Two shapes to watch for:
- A 409/405/415 returned *before* the guard runs. `POST` to a non-container and `DELETE /` legitimately answer before authorization today. If the test reports one of these, decide deliberately: either move the guard above that check (preferred — it leaks the least) or narrow the path list and record why in this plan.
- A 500, which means `Extension<Agent>` was missing — the middleware ordering broke.

- [ ] **Step 3: Commit**

```bash
git add tests/route_coverage.rs
git commit -m "test: no route serves an unauthenticated request"
```

- [ ] **Step 4: Whole-branch adversarial security review**

Use `superpowers:requesting-code-review` against the full branch diff, with an explicitly adversarial brief. The reviewer's job is to find a way in, specifically:

- A path to the store that bypasses `authorize` (any handler, any early return, any helper that reaches `store` directly).
- An ACL reachable without `Control` — including via the `Link` header, a container listing, or a conneg variant.
- An existence oracle: any response that differs between "exists but forbidden" and "does not exist".
- Scope confusion: an `acl:accessTo` rule taking effect through inheritance, or an `acl:default` rule taking effect directly.
- Injection through the owner WebID, an ACL path, or a `Slug` into the provisioning `INSERT DATA`.
- Regression against Plans 4/5: is any identity check weakened, skipped, or reordered?
- The `.acl` suffix as a namespace collision: what happens to a user resource legitimately named `notes.acl`? (It is treated as the ACL of `notes` — document this as a known naming reservation if the review confirms it.)

- [ ] **Step 5: Fix findings and re-verify**

Apply fixes, then: `nix develop -c cargo test` (all pass), `nix develop -c cargo clippy --all-targets` (clean), `nix develop -c cargo build 2>&1 | grep -i warning` (empty).

- [ ] **Step 6: Commit and finish the branch**

```bash
git add -A
git commit -m "fix: address WAC adversarial review findings"
```

Then use `superpowers:finishing-a-development-branch`.

---

## Verification Summary

Run after every task:

```bash
nix develop -c cargo test
nix develop -c cargo clippy --all-targets
nix develop -c cargo build 2>&1 | grep -i warning   # must print nothing
```

The 100 tests inherited from Plan 5 must stay green throughout. In Task 5 they gain credentials but not new expectations — an assertion that has to change there is a finding to report, not a fixup to apply.
