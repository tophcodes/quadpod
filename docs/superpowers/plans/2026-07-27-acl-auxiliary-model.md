# SPARQL Solid Pod — Plan 7: The ACL Auxiliary Model

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `<res>.acl` sibling convention with a typed auxiliary-resource model — reserved `/.aux/` namespace, lifecycle bound to the subject, stored existence, one traversal — so that six of Plan 6's seven defect classes become unrepresentable rather than guarded against.

**Architecture:** A typed URL model in `src/space.rs` (`ResourceUrl`, `ContainerUrl`, `AuxUrl`, `Target`) whose constructors are private, so every path enters the system through `StorageSpace::resolve` exactly once. Storage operations take `&impl GraphName` instead of a path plus a space. Resource existence becomes a stored marker in `urn:pod:sys:<res>`. Auxiliary create/delete is one store operation that cannot forget the cascade. Ancestor authorization and materialization share a single traversal.

**Tech Stack:** Rust, axum 0.8.9, oxigraph 0.5.9 (`Triple { subject: NamedOrBlankNode, predicate: NamedNode, object: Term }`), clap, existing auth stack.

**Builds on:** Plans 1–6, all merged to `main` (171 unit + 1 integration test green). Design spec: `docs/superpowers/specs/2026-07-27-acl-auxiliary-model-design.md`. Client contract: `docs/uri-space.md`. Evidence: `.superpowers/sdd/architecture-postmortem.md`, `.superpowers/sdd/acl-url-interop.md`.

## Global Constraints

- **Build/test ONLY via the flake dev shell.** Bare `cargo` fails (oxigraph → bindgen → libclang). Every command: `nix develop -c cargo test`, `nix develop -c cargo clippy --all-targets`, `nix develop -c cargo build 2>&1 | grep -i warning` (must print nothing).
- **NO `#[allow(...)]`.** No deprecated APIs. Clippy clean, zero build warnings.
- **This is the authorization boundary.** Fail closed everywhere. A missing ACL, a store error, an unroutable path all deny.
- **Do not weaken Plans 4/5.** `src/auth/**` is out of scope for behaviour changes; the identity boundary (ES256 pin, `cnf.jkt`, SSRF block, WebID-issuer binding, replay rejection) stays byte-equivalent except where a call site's types change.
- **Never interpolate unvalidated strings into SPARQL.** Every IRI reaching an update string comes from a typed URL whose constructor ran `NamedNode::new`.
- **Reserved namespace:** exactly `/.aux/` at the root. `/.aux/{kind}/{subject-path}`. `AuxKind::Acl` → segment `acl`, link relation `acl`, requires `Control` on the subject.
- **`Link` headers are unconditional** — emitted for every `AuxKind` on every response for a resource path, including 404 and denials.
- **Existing assertions must survive.** The 171 tests are the safety net; only setup changes where a URL shape appears. A changed *expectation* is a finding to report, not a fixup.
- Conventional commits. TDD: failing test first, minimal implementation, one commit per task.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/space.rs` | URI topology: typed URLs, classification, ancestor derivation | rewritten and grown (this is where the rules move to) |
| `src/resource.rs` | graph-level storage ops over `GraphName`; stored existence | signatures retyped, presence marker added |
| `src/aux.rs` | auxiliary lifecycle: create-with-subject, delete-with-subject | **new** |
| `src/container.rs` | containment triples; ancestor materialization | traversal merged with authorization |
| `src/wac/prp.rs` | ACL resolution over `AuxUrl`, constant-round-trip walk | rewritten |
| `src/wac/guard.rs` | `authorize` over `Target`; the shared ancestor traversal | retyped, gains the traversal |
| `src/http.rs` | handlers dispatch on `Target`; `Link` headers from `AuxKind` | large deletion |
| `src/store.rs` | `SparqlStore` | one method added |

---

### Task 1: Typed URL model in `space.rs`

The whole plan rests on this file. Nothing else changes yet — this task adds types and leaves the existing `graph_iri` in place so the tree keeps compiling.

**Files:**
- Modify: `src/space.rs`
- Test: inline in `src/space.rs`

**Interfaces:**
- Produces:
  - `pub trait GraphName { fn graph_iri(&self) -> &str; }`
  - `pub struct ResourceUrl` with `path() -> &str`, `aux(AuxKind) -> AuxUrl`, `parent() -> Option<ContainerUrl>`, `ancestors() -> Vec<ContainerUrl>` (nearest first, ending at the root container), `as_container() -> Option<ContainerUrl>`
  - `pub struct ContainerUrl` with `path() -> &str`, `as_resource() -> &ResourceUrl`
  - `pub enum AuxKind { Acl }` with `segment() -> &'static str`, `link_rel() -> &'static str`, `ALL: &[AuxKind]`
  - `pub struct AuxUrl` with `subject() -> &ResourceUrl`, `kind() -> AuxKind`
  - `pub enum Target { Resource(ResourceUrl), Container(ContainerUrl), Aux(AuxUrl) }`
  - `StorageSpace::resolve(&self, request_path: &str) -> Result<Target, SpaceError>`, `StorageSpace::root(&self) -> ContainerUrl`
  - `SpaceError::Reserved` added
  - `GraphName` implemented for all three URL types
- Consumes: nothing.

- [ ] **Step 1: Write the failing tests**

Append to `src/space.rs`'s test module:

```rust
    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    #[test]
    fn resolve_classifies_the_three_kinds() {
        let s = sp();
        assert!(matches!(s.resolve("/foo").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/box/").unwrap(), Target::Container(_)));
        assert!(matches!(s.resolve("/").unwrap(), Target::Container(_)));
        assert!(matches!(s.resolve("/.aux/acl/foo").unwrap(), Target::Aux(_)));
        assert!(matches!(s.resolve("/.aux/acl/").unwrap(), Target::Aux(_)));
    }

    // A dot is only special as the whole first segment `.aux`. Everything
    // else a user might name stays ordinary.
    #[test]
    fn only_the_aux_segment_is_reserved() {
        let s = sp();
        assert!(matches!(s.resolve("/.hidden").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/.config/x").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/box/.aux").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/box/.aux/acl").unwrap(), Target::Resource(_)));
    }

    #[test]
    fn unallocated_reserved_paths_are_refused() {
        let s = sp();
        assert_eq!(s.resolve("/.aux"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/bogus/x"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/acl"), Err(SpaceError::Reserved)); // no subject
    }

    #[test]
    fn aux_and_subject_are_mutual_inverses() {
        let s = sp();
        for path in ["/", "/foo", "/box/", "/a/b/c"] {
            let Target::Resource(r) | Target::Container(ContainerUrl(r)) = s.resolve(path).unwrap()
            else { panic!("{path} should be a resource or container") };
            let aux = r.aux(AuxKind::Acl);
            assert_eq!(aux.subject().path(), path, "round trip for {path}");
        }
    }

    #[test]
    fn aux_urls_have_the_documented_shape() {
        let s = sp();
        let acl_of = |p: &str| match s.resolve(p).unwrap() {
            Target::Resource(r) => r.aux(AuxKind::Acl),
            Target::Container(c) => c.as_resource().aux(AuxKind::Acl),
            Target::Aux(_) => panic!("not a subject"),
        };
        assert_eq!(acl_of("/").graph_iri(), "https://pod.toph.so/.aux/acl/");
        assert_eq!(acl_of("/foo").graph_iri(), "https://pod.toph.so/.aux/acl/foo");
        assert_eq!(acl_of("/box/").graph_iri(), "https://pod.toph.so/.aux/acl/box/");
        assert_eq!(acl_of("/a/b/c").graph_iri(), "https://pod.toph.so/.aux/acl/a/b/c");
    }

    // The chain a create actually mutates: nearest first, root last.
    #[test]
    fn ancestors_are_nearest_first_and_end_at_root() {
        let s = sp();
        let Target::Resource(r) = s.resolve("/a/b/c").unwrap() else { panic!() };
        let paths: Vec<_> = r.ancestors().iter().map(|c| c.path().to_string()).collect();
        assert_eq!(paths, vec!["/a/b/", "/a/", "/"]);

        let Target::Container(root) = s.resolve("/").unwrap() else { panic!() };
        assert!(root.as_resource().ancestors().is_empty(), "root has no ancestors");
    }

    #[test]
    fn graph_iri_still_rejects_iri_breaking_paths() {
        assert_eq!(sp().resolve("/foo> bar"), Err(SpaceError::InvalidResourceIri));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test space::`
Expected: FAIL — `cannot find type Target`, `cannot find type AuxKind`, etc.

- [ ] **Step 3: Implement**

Replace the body of `src/space.rs` above the test module with:

```rust
//! The pod's URI topology: which URLs exist, what they mean, and how they
//! relate. Every path enters the system through [`StorageSpace::resolve`],
//! which classifies it exactly once — the constructors below are private, so
//! no other module can mint a URL or re-derive what kind of thing it is.
//!
//! See `docs/uri-space.md` for the client-facing contract.

use oxigraph::model::NamedNode;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SpaceError {
    #[error("base URI must be absolute (http:// or https://)")]
    NotAbsolute,
    #[error("base URI must end with a trailing slash")]
    NoTrailingSlash,
    #[error("resource path does not form a valid IRI")]
    InvalidResourceIri,
    #[error("path is in the reserved namespace but names no auxiliary resource")]
    Reserved,
}

/// The reserved first segment. Everything under it is server-understood;
/// everything else is the user's.
const AUX_SEGMENT: &str = ".aux";

/// Anything addressable as a named graph.
pub trait GraphName {
    fn graph_iri(&self) -> &str;
}

/// A kind of auxiliary resource. Closed and server-defined: a kind exists
/// only if the server enforces its lifecycle, listing exclusion and
/// authorization derivation. This enum is the single source of truth for
/// both routing and the `Link` headers, so the two cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxKind {
    Acl,
}

impl AuxKind {
    pub const ALL: &'static [AuxKind] = &[AuxKind::Acl];

    /// The path segment under `/.aux/`.
    pub fn segment(self) -> &'static str {
        match self {
            AuxKind::Acl => "acl",
        }
    }

    /// The `Link` relation this kind is advertised with.
    pub fn link_rel(self) -> &'static str {
        match self {
            AuxKind::Acl => "acl",
        }
    }

    fn from_segment(segment: &str) -> Option<Self> {
        AuxKind::ALL.iter().copied().find(|k| k.segment() == segment)
    }
}

/// A URL in the resource space — the user's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceUrl {
    path: String,
    iri: String,
}

/// A [`ResourceUrl`] whose path ends in `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerUrl(pub(crate) ResourceUrl);

/// A URL in the reserved auxiliary space, carrying its subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxUrl {
    kind: AuxKind,
    subject: ResourceUrl,
    iri: String,
}

/// What a request addresses. Produced once, by [`StorageSpace::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Resource(ResourceUrl),
    Container(ContainerUrl),
    Aux(AuxUrl),
}

impl GraphName for ResourceUrl {
    fn graph_iri(&self) -> &str {
        &self.iri
    }
}
impl GraphName for ContainerUrl {
    fn graph_iri(&self) -> &str {
        self.0.graph_iri()
    }
}
impl GraphName for AuxUrl {
    fn graph_iri(&self) -> &str {
        &self.iri
    }
}
impl GraphName for Target {
    fn graph_iri(&self) -> &str {
        match self {
            Target::Resource(r) => r.graph_iri(),
            Target::Container(c) => c.graph_iri(),
            Target::Aux(a) => a.graph_iri(),
        }
    }
}

impl ResourceUrl {
    pub fn path(&self) -> &str {
        &self.path
    }

    /// This resource's auxiliary of the given kind. Total: every resource has
    /// an auxiliary URL whether or not that auxiliary has a representation.
    pub fn aux(&self, kind: AuxKind) -> AuxUrl {
        let base = self.iri.strip_suffix(&self.path).expect("iri ends with path");
        let iri = format!("{base}/{AUX_SEGMENT}/{}{}", kind.segment(), self.path);
        AuxUrl { kind, subject: self.clone(), iri }
    }

    pub fn as_container(&self) -> Option<ContainerUrl> {
        self.path.ends_with('/').then(|| ContainerUrl(self.clone()))
    }

    /// The immediate parent container, or `None` for the root.
    pub fn parent(&self) -> Option<ContainerUrl> {
        if self.path == "/" {
            return None;
        }
        let trimmed = self.path.strip_suffix('/').unwrap_or(&self.path);
        let idx = trimmed.rfind('/')?;
        let parent_path = trimmed[..=idx].to_string();
        let base = self.iri.strip_suffix(&self.path).expect("iri ends with path");
        Some(ContainerUrl(ResourceUrl {
            iri: format!("{base}{parent_path}"),
            path: parent_path,
        }))
    }

    /// Every container between this resource and the root, nearest first.
    /// This is the chain a create may materialize, and the same chain the
    /// guard authorizes — one derivation, used by both.
    pub fn ancestors(&self) -> Vec<ContainerUrl> {
        let mut out = Vec::new();
        let mut current = self.clone();
        while let Some(parent) = current.parent() {
            current = parent.0.clone();
            out.push(parent);
        }
        out
    }
}

impl ContainerUrl {
    pub fn path(&self) -> &str {
        self.0.path()
    }
    pub fn as_resource(&self) -> &ResourceUrl {
        &self.0
    }
}

impl AuxUrl {
    pub fn subject(&self) -> &ResourceUrl {
        &self.subject
    }
    pub fn kind(&self) -> AuxKind {
        self.kind
    }
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

    /// Classify a raw request path. This is the only way a URL enters the
    /// system, and the only place the reserved namespace is recognized.
    ///
    /// The IRI is validated here, once, because it is later interpolated
    /// verbatim into SPARQL as `<{iri}>`.
    pub fn resolve(&self, request_path: &str) -> Result<Target, SpaceError> {
        if let Some(rest) = request_path.strip_prefix(&format!("/{AUX_SEGMENT}")) {
            let Some(rest) = rest.strip_prefix('/') else {
                return Err(SpaceError::Reserved); // "/.aux"
            };
            let Some((segment, subject_rest)) = rest.split_once('/') else {
                return Err(SpaceError::Reserved); // "/.aux/" or "/.aux/acl"
            };
            let kind = AuxKind::from_segment(segment).ok_or(SpaceError::Reserved)?;
            let subject = self.resource(&format!("/{subject_rest}"))?;
            let aux = subject.aux(kind);
            NamedNode::new(&aux.iri).map_err(|_| SpaceError::InvalidResourceIri)?;
            return Ok(Target::Aux(aux));
        }
        let resource = self.resource(request_path)?;
        Ok(match resource.as_container() {
            Some(container) => Target::Container(container),
            None => Target::Resource(resource),
        })
    }

    /// The root container. Provisioning needs it before any request exists.
    pub fn root(&self) -> ContainerUrl {
        match self.resolve("/").expect("the root path is always valid") {
            Target::Container(c) => c,
            _ => unreachable!("\"/\" resolves to a container"),
        }
    }

    fn resource(&self, request_path: &str) -> Result<ResourceUrl, SpaceError> {
        let trimmed = request_path.strip_prefix('/').unwrap_or(request_path);
        let iri = format!("{}{}", self.base, trimmed);
        NamedNode::new(&iri).map_err(|_| SpaceError::InvalidResourceIri)?;
        Ok(ResourceUrl { path: request_path.to_string(), iri })
    }
}
```

Delete the old `graph_iri` method and its two tests (`graph_iri_uses_config_base_not_request_host`, `graph_iri_rejects_iri_breaking_chars`) — `resolve` replaces both, and the second is re-covered by `graph_iri_still_rejects_iri_breaking_paths` above. The tree will not compile yet; that is expected and fixed in Task 2.

- [ ] **Step 4: Run the space tests only**

Run: `nix develop -c cargo test --lib space:: 2>&1 | tail -20`
Expected: the `space::` tests pass. Other modules fail to compile — that is this task's known state, because `graph_iri` had callers. If you prefer a compiling tree at every commit, keep `graph_iri` as a deprecated-free thin wrapper (`pub fn graph_iri(&self, p: &str) -> Result<String, SpaceError> { Ok(self.resolve(p)?.graph_iri().to_string()) }`) and delete it in Task 2 — either is acceptable, say which you chose in your report.

- [ ] **Step 5: Commit**

```bash
git add src/space.rs
git commit -m "feat: typed URL model with a reserved auxiliary namespace"
```

---

### Task 2: Storage over `GraphName`, existence as a stored fact

**Files:**
- Modify: `src/resource.rs`, `src/store.rs`
- Test: inline in `src/resource.rs`

**Interfaces:**
- Consumes: `space::{GraphName, ResourceUrl, StorageSpace, Target}`.
- Produces:
  - `resource::put_rdf(store: &dyn SparqlStore, g: &impl GraphName, triples: &[Triple]) -> Result<(), ResourceError>` — replaces the graph *and* records presence, in one update.
  - `resource::get_rdf(store, g) -> Result<Option<Vec<Triple>>, ResourceError>` — `Some(vec![])` for a present-but-empty graph, `None` only when absent.
  - `resource::exists(store, g) -> Result<bool, ResourceError>`
  - `resource::delete_rdf(store, g) -> Result<bool, ResourceError>` — drops content and presence; returns whether it existed.
  - `resource::sys_graph_iri(g: &impl GraphName) -> String` — `urn:pod:sys:<iri>`
  - `store::SparqlStore::ask(&self, sparql: &str) -> Result<bool, StoreError>`
- Note: `space` is no longer a parameter — the typed URL carries its IRI.

- [ ] **Step 1: Write the failing tests**

Replace `src/resource.rs`'s test module with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rdf, space::{StorageSpace, Target}, store::OxigraphStore};
    use oxigraph::io::RdfFormat;

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn res(path: &str) -> crate::space::ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    fn triples(turtle: &str, base: &str) -> Vec<Triple> {
        rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, base).unwrap()
    }

    #[tokio::test]
    async fn put_then_get_roundtrips_triples() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        let t = triples("<#it> <http://schema.org/name> \"Toph\" .", foo.graph_iri());
        put_rdf(&store, &foo, &t).await.unwrap();
        let got = get_rdf(&store, &foo).await.unwrap().expect("exists");
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn put_replaces_not_appends() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        put_rdf(&store, &foo, &triples("<#it> <http://schema.org/name> \"A\" .", foo.graph_iri())).await.unwrap();
        put_rdf(&store, &foo, &triples("<#it> <http://schema.org/name> \"B\" .", foo.graph_iri())).await.unwrap();
        let got = get_rdf(&store, &foo).await.unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert!(matches!(&got[0].object, oxigraph::model::Term::Literal(l) if l.value() == "B"));
    }

    // The whole point of the presence marker: an empty resource is a resource.
    // Before this, "no triples" and "does not exist" were the same state, which
    // made an empty ACL silently widen access instead of locking a subtree down.
    #[tokio::test]
    async fn an_empty_resource_exists_and_is_distinguishable_from_an_absent_one() {
        let store = OxigraphStore::in_memory().unwrap();
        let empty = res("/empty");
        let absent = res("/absent");

        put_rdf(&store, &empty, &[]).await.unwrap();

        assert!(exists(&store, &empty).await.unwrap());
        assert_eq!(get_rdf(&store, &empty).await.unwrap(), Some(Vec::new()));

        assert!(!exists(&store, &absent).await.unwrap());
        assert_eq!(get_rdf(&store, &absent).await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_removes_content_and_presence() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        put_rdf(&store, &foo, &triples("<#it> <http://schema.org/name> \"x\" .", foo.graph_iri())).await.unwrap();

        assert!(delete_rdf(&store, &foo).await.unwrap());
        assert!(!exists(&store, &foo).await.unwrap());
        assert_eq!(get_rdf(&store, &foo).await.unwrap(), None);
        assert!(!delete_rdf(&store, &foo).await.unwrap(), "already gone");
    }

    // An empty resource must be deletable too — otherwise it would be
    // unreachable state: exists, but no way to remove it.
    #[tokio::test]
    async fn an_empty_resource_can_be_deleted() {
        let store = OxigraphStore::in_memory().unwrap();
        let empty = res("/empty");
        put_rdf(&store, &empty, &[]).await.unwrap();
        assert!(delete_rdf(&store, &empty).await.unwrap());
        assert!(!exists(&store, &empty).await.unwrap());
    }

    #[tokio::test]
    async fn presence_lives_in_the_system_graph_not_the_user_graph() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        put_rdf(&store, &foo, &triples("<#it> <http://schema.org/name> \"x\" .", foo.graph_iri())).await.unwrap();
        // the user sees exactly what they wrote
        assert_eq!(get_rdf(&store, &foo).await.unwrap().unwrap().len(), 1);
        // and the marker is elsewhere
        assert!(sys_graph_iri(&foo).starts_with("urn:pod:sys:"));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test --lib resource::`
Expected: FAIL — `exists` and `sys_graph_iri` do not exist; `put_rdf` takes the wrong argument count.

- [ ] **Step 3: Add `ask` to the store trait**

In `src/store.rs`, add to `trait SparqlStore`:

```rust
    async fn ask(&self, sparql: &str) -> Result<bool, StoreError>;
```

and to `impl SparqlStore for OxigraphStore`:

```rust
    async fn ask(&self, sparql: &str) -> Result<bool, StoreError> {
        let results = SparqlEvaluator::new()
            .parse_query(sparql)
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .on_store(&self.inner)
            .execute()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        match results {
            QueryResults::Boolean(b) => Ok(b),
            _ => Err(StoreError::Backend("expected ASK/boolean results".into())),
        }
    }
```

- [ ] **Step 4: Implement the resource layer**

Replace `src/resource.rs` above its test module with:

```rust
//! Graph-level storage operations.
//!
//! Existence is a **stored fact**, not an inference from triple count: an RDF
//! store cannot distinguish an empty named graph from an absent one, and
//! treating "no triples" as "absent" made an empty ACL mean the opposite of
//! what its author intended (it fell back to the ancestor's rules instead of
//! denying). A presence marker in `urn:pod:sys:<iri>` removes the ambiguity.

use crate::{
    rdf::RdfError,
    space::{GraphName, SpaceError},
    store::{SparqlStore, StoreError},
};
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
    fn from(_: SpaceError) -> Self {
        ResourceError::InvalidIri
    }
}

/// Predicate asserting that a resource exists. Server-asserted, and therefore
/// in the reserved system namespace rather than the user's graph.
pub const SYS_PRESENT: &str = "urn:pod:sys#present";

/// The system graph holding server-asserted facts about `g`.
pub fn sys_graph_iri(g: &impl GraphName) -> String {
    format!("urn:pod:sys:{}", g.graph_iri())
}

/// Replace a graph's contents and mark it present, in one update.
pub async fn put_rdf(
    store: &dyn SparqlStore,
    g: &impl GraphName,
    triples: &[Triple],
) -> Result<(), ResourceError> {
    let iri = g.graph_iri();
    let sys = sys_graph_iri(g);
    let mut body = String::new();
    for t in triples {
        body.push_str(&format!("{} {} {} .\n", t.subject, t.predicate, t.object));
    }
    store
        .update(&format!(
            "DROP SILENT GRAPH <{iri}>; \
             INSERT DATA {{ GRAPH <{iri}> {{ {body} }} }}; \
             INSERT DATA {{ GRAPH <{sys}> {{ <{iri}> <{SYS_PRESENT}> true }} }}"
        ))
        .await?;
    Ok(())
}

/// A graph's contents, or `None` if it does not exist. An existing graph with
/// no triples yields `Some(vec![])`.
pub async fn get_rdf(
    store: &dyn SparqlStore,
    g: &impl GraphName,
) -> Result<Option<Vec<Triple>>, ResourceError> {
    if !exists(store, g).await? {
        return Ok(None);
    }
    let iri = g.graph_iri();
    let triples = store
        .query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{iri}> {{ ?s ?p ?o }} }}"
        ))
        .await?;
    Ok(Some(triples))
}

pub async fn exists(store: &dyn SparqlStore, g: &impl GraphName) -> Result<bool, ResourceError> {
    let iri = g.graph_iri();
    let sys = sys_graph_iri(g);
    Ok(store
        .ask(&format!(
            "ASK {{ GRAPH <{sys}> {{ <{iri}> <{SYS_PRESENT}> true }} }}"
        ))
        .await?)
}

/// Delete a graph and its presence marker. Returns whether it existed.
pub async fn delete_rdf(store: &dyn SparqlStore, g: &impl GraphName) -> Result<bool, ResourceError> {
    let existed = exists(store, g).await?;
    if existed {
        let iri = g.graph_iri();
        let sys = sys_graph_iri(g);
        store
            .update(&format!("DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>"))
            .await?;
    }
    Ok(existed)
}
```

- [ ] **Step 5: Run to verify pass**

Run: `nix develop -c cargo test --lib resource:: store::`
Expected: PASS. Other modules still fail to compile — Tasks 3–7 retype them.

- [ ] **Step 6: Commit**

```bash
git add src/resource.rs src/store.rs
git commit -m "feat: store existence as a fact; storage ops over typed graph names"
```

---

### Task 3: `src/aux.rs` — the auxiliary lifecycle

The rules that were three separate runtime checks across two handlers become the only way to write or delete an auxiliary.

**Files:**
- Create: `src/aux.rs`
- Modify: `src/lib.rs` (add `pub mod aux;`)
- Test: inline in `src/aux.rs`

**Interfaces:**
- Consumes: `space::{AuxKind, AuxUrl, GraphName, ResourceUrl}`, `resource::{delete_rdf, exists, get_rdf, put_rdf, sys_graph_iri, ResourceError}`.
- Produces:
  - `aux::AuxError` — `SubjectMissing`, `Resource(ResourceError)`
  - `aux::put(store, aux: &AuxUrl, triples: &[Triple]) -> Result<(), AuxError>` — refuses when the subject does not exist
  - `aux::delete_subject(store, subject: &ResourceUrl) -> Result<bool, ResourceError>` — deletes the resource and **every** auxiliary kind in one store update; returns whether the subject existed

- [ ] **Step 1: Write the failing tests**

Create `src/aux.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{resource::{exists, get_rdf, put_rdf}, space::{AuxKind, StorageSpace, Target}, store::OxigraphStore};

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn res(path: &str) -> crate::space::ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    #[tokio::test]
    async fn an_auxiliary_needs_an_existing_subject() {
        let store = OxigraphStore::in_memory().unwrap();
        let ghost = res("/ghost");
        assert!(matches!(
            put(&store, &ghost.aux(AuxKind::Acl), &[]).await,
            Err(AuxError::SubjectMissing)
        ));
        assert!(!exists(&store, &ghost.aux(AuxKind::Acl)).await.unwrap());
    }

    #[tokio::test]
    async fn an_auxiliary_can_be_written_for_an_existing_subject() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        put_rdf(&store, &foo, &[]).await.unwrap();
        put(&store, &foo.aux(AuxKind::Acl), &[]).await.unwrap();
        assert!(exists(&store, &foo.aux(AuxKind::Acl)).await.unwrap());
    }

    // The cascade is definitional, not a step someone remembers: deleting a
    // subject removes every auxiliary kind with it, so no orphan can outlive
    // it and be resurrected with stale grants when the path is recreated.
    #[tokio::test]
    async fn deleting_a_subject_deletes_every_auxiliary_kind() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        put_rdf(&store, &foo, &[]).await.unwrap();
        for kind in AuxKind::ALL {
            put(&store, &foo.aux(*kind), &[]).await.unwrap();
        }

        assert!(delete_subject(&store, &foo).await.unwrap());

        assert!(!exists(&store, &foo).await.unwrap());
        for kind in AuxKind::ALL {
            assert!(
                !exists(&store, &foo.aux(*kind)).await.unwrap(),
                "auxiliary {kind:?} outlived its subject"
            );
            assert_eq!(get_rdf(&store, &foo.aux(*kind)).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn deleting_an_absent_subject_reports_absence() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(!delete_subject(&store, &res("/nope")).await.unwrap());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test --lib aux::`
Expected: FAIL — `cannot find function put`, `cannot find type AuxError`.

- [ ] **Step 3: Implement**

Prepend to `src/aux.rs`:

```rust
//! Auxiliary-resource lifecycle.
//!
//! An auxiliary is not an independently creatable object: it exists only for
//! an existing subject, and it dies with that subject. Both rules live here,
//! in the only functions that can write or delete one, so no handler can
//! implement half of them.

use oxigraph::model::Triple;
use thiserror::Error;

use crate::{
    resource::{exists, put_rdf, sys_graph_iri, ResourceError},
    space::{AuxKind, AuxUrl, GraphName, ResourceUrl},
    store::SparqlStore,
};

#[derive(Debug, Error)]
pub enum AuxError {
    #[error("the auxiliary's subject resource does not exist")]
    SubjectMissing,
    #[error(transparent)]
    Resource(#[from] ResourceError),
}

/// Write an auxiliary resource. Fails when its subject does not exist —
/// otherwise a policy document could be planted on a path that was never
/// created, where nearest-ACL-wins would make it permanent and unremovable.
pub async fn put(
    store: &dyn SparqlStore,
    aux: &AuxUrl,
    triples: &[Triple],
) -> Result<(), AuxError> {
    if !exists(store, aux.subject()).await? {
        return Err(AuxError::SubjectMissing);
    }
    put_rdf(store, aux, triples).await?;
    Ok(())
}

/// Delete a subject resource together with every auxiliary it may have, in a
/// single store update. Returns whether the subject existed.
pub async fn delete_subject(
    store: &dyn SparqlStore,
    subject: &ResourceUrl,
) -> Result<bool, ResourceError> {
    if !exists(store, subject).await? {
        return Ok(false);
    }
    let mut drops = vec![
        format!("DROP SILENT GRAPH <{}>", subject.graph_iri()),
        format!("DROP SILENT GRAPH <{}>", sys_graph_iri(subject)),
    ];
    for kind in AuxKind::ALL {
        let aux = subject.aux(*kind);
        drops.push(format!("DROP SILENT GRAPH <{}>", aux.graph_iri()));
        drops.push(format!("DROP SILENT GRAPH <{}>", sys_graph_iri(&aux)));
    }
    store.update(&drops.join("; ")).await?;
    Ok(true)
}
```

Add `pub mod aux;` to `src/lib.rs`.

- [ ] **Step 4: Run to verify pass**

Run: `nix develop -c cargo test --lib aux::`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/aux.rs src/lib.rs
git commit -m "feat: auxiliary lifecycle bound to its subject by construction"
```

---

### Task 4: `wac/prp.rs` — ACL resolution over `AuxUrl`

**Files:**
- Modify: `src/wac/prp.rs` (rewrite), `src/container.rs` (delete the ACL-containment exclusion)
- Test: inline in `src/wac/prp.rs`

**Interfaces:**
- Consumes: `space::{AuxKind, GraphName, ResourceUrl}`, `resource::{exists, get_rdf}`.
- Produces: `prp::effective_acl(store, subject: &ResourceUrl) -> Result<Option<EffectiveAcl>, ResourceError>`, `EffectiveAcl { triples, governed_iri, inherited }` (unchanged shape).
- Removed: `acl_path`, `is_acl_path`, `acl_subject_path` — the suffix predicates cease to exist. Any remaining caller is a compile error, which is the point.

- [ ] **Step 1: Write the failing tests**

Replace `src/wac/prp.rs`'s test module with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{ACL_ACCESS_TO, ACL_AGENT, ACL_DEFAULT, ACL_MODE, ACL_READ};
    use crate::{rdf, resource::put_rdf, space::{AuxKind, StorageSpace, Target}, store::OxigraphStore};
    use oxigraph::io::RdfFormat;

    const ALICE: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn res(path: &str) -> ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    async fn write_acl(store: &OxigraphStore, subject_path: &str, turtle: &str) {
        let subject = res(subject_path);
        put_rdf(store, &subject, &[]).await.unwrap();
        let aux = subject.aux(AuxKind::Acl);
        let t = rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, aux.graph_iri()).unwrap();
        put_rdf(store, &aux, &t).await.unwrap();
    }

    #[tokio::test]
    async fn direct_acl_is_found_and_not_marked_inherited() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &res("/foo")).await.unwrap().expect("found");
        assert!(!acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/foo");
        assert!(acl.triples.iter().any(|t| t.predicate.as_str() == ACL_MODE));
    }

    #[tokio::test]
    async fn missing_direct_acl_inherits_from_the_nearest_container() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/box/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &res("/box/item")).await.unwrap().expect("found");
        assert!(acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/box/");
    }

    #[tokio::test]
    async fn walk_ascends_all_the_way_to_the_root_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &res("/a/b/c")).await.unwrap().expect("found");
        assert!(acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/");
    }

    #[tokio::test]
    async fn nearest_acl_wins_entirely_over_ancestors() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/", &format!(
            "<#root> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        write_acl(&store, "/box/", &format!(
            "<#box> <{ACL_AGENT}> <https://bob.example/card#me> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &res("/box/item")).await.unwrap().expect("found");
        assert_eq!(acl.governed_iri, "https://pod.toph.so/box/");
        assert!(!acl.triples.iter().any(|t| matches!(&t.object,
            oxigraph::model::Term::NamedNode(n) if n.as_str() == ALICE)));
    }

    // The reason existence became a stored fact: an empty ACL is a policy
    // ("nothing is granted here"), not an absence that falls back to ancestors.
    #[tokio::test]
    async fn an_empty_acl_is_found_and_stops_the_walk() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/", &format!(
            "<#root> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        write_acl(&store, "/locked/", "").await;
        let acl = effective_acl(&store, &res("/locked/x")).await.unwrap().expect("found");
        assert_eq!(acl.governed_iri, "https://pod.toph.so/locked/");
        assert!(acl.triples.is_empty(), "an empty ACL grants nothing");
    }

    #[tokio::test]
    async fn no_acl_anywhere_is_none() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(effective_acl(&store, &res("/foo")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn resource_data_is_not_mistaken_for_its_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        let t = rdf::parse(b"<#it> <http://schema.org/name> \"Toph\" .", RdfFormat::Turtle, foo.graph_iri()).unwrap();
        put_rdf(&store, &foo, &t).await.unwrap();
        assert!(effective_acl(&store, &foo).await.unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test --lib wac::prp`
Expected: FAIL to compile — `effective_acl` still takes a space and a `&str`.

- [ ] **Step 3: Implement**

Replace `src/wac/prp.rs` above its test module with:

```rust
//! The WAC policy retrieval point: find the ACL that governs a resource.
//!
//! The ACL of `<res>` is `<res>`'s auxiliary of kind [`AuxKind::Acl`]. If it
//! has no representation, WAC inheritance applies: walk up the container
//! chain and use the first ACL found there, evaluated through `acl:default`.
//! The first ACL found wins completely — ancestor rules are never merged in,
//! because merging would make revoking access on a subtree impossible.
//!
//! The candidate chain comes from [`ResourceUrl::ancestors`], the same
//! derivation the guard authorizes against. There is deliberately no second
//! way to compute it.

use oxigraph::model::Triple;

use crate::{
    resource::{exists, get_rdf, ResourceError},
    space::{AuxKind, GraphName, ResourceUrl},
    store::SparqlStore,
};

/// The ACL that governs a resource, plus the context needed to evaluate it.
#[derive(Debug)]
pub struct EffectiveAcl {
    pub triples: Vec<Triple>,
    /// IRI of the resource this ACL belongs to — what `acl:accessTo` or
    /// `acl:default` must name for an authorization to apply.
    pub governed_iri: String,
    /// True when reached by walking up, so `acl:default` applies rather than
    /// `acl:accessTo`.
    pub inherited: bool,
}

/// Resolve the ACL governing `subject`, or `None` — which the guard turns
/// into a denial, because WAC has no implicit grant.
pub async fn effective_acl(
    store: &dyn SparqlStore,
    subject: &ResourceUrl,
) -> Result<Option<EffectiveAcl>, ResourceError> {
    let direct = subject.aux(AuxKind::Acl);
    if exists(store, &direct).await? {
        return Ok(Some(EffectiveAcl {
            triples: get_rdf(store, &direct).await?.unwrap_or_default(),
            governed_iri: subject.graph_iri().to_string(),
            inherited: false,
        }));
    }
    for ancestor in subject.ancestors() {
        let acl = ancestor.as_resource().aux(AuxKind::Acl);
        if exists(store, &acl).await? {
            return Ok(Some(EffectiveAcl {
                triples: get_rdf(store, &acl).await?.unwrap_or_default(),
                governed_iri: ancestor.graph_iri().to_string(),
                inherited: true,
            }));
        }
    }
    Ok(None)
}
```

In `src/container.rs`, delete the `is_acl_path` early return from `add_containment` and `remove_containment` (and the `acl_children_are_not_recorded_as_containment` test's reliance on it — rewrite that test in Task 5, where containment moves). Auxiliaries are no longer in the resource space, so a container can never be asked to contain one: the exclusion rule disappears rather than being enforced.

- [ ] **Step 4: Run to verify pass**

Run: `nix develop -c cargo test --lib wac::prp`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add src/wac/prp.rs src/container.rs
git commit -m "feat: resolve ACLs through typed auxiliary URLs; drop the suffix predicates"
```

---

### Task 5: One traversal — `wac/guard.rs` and `container.rs`

The mirror pair (`http::authorize_ancestors` and `container::ensure_ancestors`) becomes a single function. Drift between them was defects 3 and 5.

**Files:**
- Modify: `src/wac/guard.rs`, `src/container.rs`
- Test: inline in both

**Interfaces:**
- Consumes: `space::{AuxKind, ContainerUrl, GraphName, ResourceUrl, Target}`, `prp::effective_acl`, `pdp::decide`, `resource::{exists, put_rdf}`.
- Produces:
  - `guard::authorize(store, agent: &Agent, target: &Target, mode: Mode) -> Result<(), Response>` — an `Aux` target is decided against its subject and always requires `Control`.
  - `guard::authorize_and_materialize(store, agent: &Agent, target: &Target) -> Result<(), Response>` — walks `ancestors()` once: authorizes `Append` on each level that will change, creates the container, records containment, and stops after the first ancestor that already existed. The single traversal.
  - `container::ensure_container(store, c: &ContainerUrl) -> Result<(), ResourceError>`, `container::add_containment(store, parent: &ContainerUrl, child: &impl GraphName) -> Result<(), ResourceError>`, `container::remove_containment(...)`, `container::container_is_empty(store, c) -> Result<bool, ResourceError>` — all retyped; `ensure_ancestors` is **deleted**.

- [ ] **Step 1: Write the failing tests**

Add to `src/wac/guard.rs`'s test module (keep the existing ones, retyped to `Target`):

```rust
    // One traversal: every level the materialization would write is a level
    // the walk authorized, and it stops where writing stops. Neither half can
    // drift from the other, because there is only one half.
    #[tokio::test]
    async fn materialization_is_authorized_at_every_level_it_writes() {
        let store = OxigraphStore::in_memory().unwrap();
        // Bob may write below /box/ but holds nothing on /box/ itself.
        seed_acl(&store, "/box/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let target = sp().resolve("/box/sub/file").unwrap();
        let res = authorize_and_materialize(&store, &bob(), &target).await;
        assert!(res.is_err(), "creating /box/sub/ mutates /box/, which Bob cannot append to");
        assert!(!crate::resource::exists(&store, &container("/box/sub/")).await.unwrap(),
            "nothing may be materialized when the walk denies");
    }

    #[tokio::test]
    async fn an_existing_parent_costs_exactly_one_check() {
        let store = OxigraphStore::in_memory().unwrap();
        // Bob has Append on /inbox/ itself — the append-only inbox pattern.
        seed_container(&store, "/inbox/").await;
        seed_acl(&store, "/inbox/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/inbox/> ; \
             <{ACL_MODE}> <{ACL_APPEND}> ."
        )).await;
        let target = sp().resolve("/inbox/note").unwrap();
        assert!(authorize_and_materialize(&store, &bob(), &target).await.is_ok(),
            "an append-only agent must not need rights on the root");
    }

    // An auxiliary is not a container member, so writing one materializes
    // nothing at its parent — but any container it would create still counts.
    #[tokio::test]
    async fn writing_an_auxiliary_under_an_existing_container_needs_nothing_extra() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_container(&store, "/box/").await;
        crate::resource::put_rdf(&store, &resource("/box/doc"), &[]).await.unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        let target = sp().resolve("/.aux/acl/box/doc").unwrap();
        assert!(authorize_and_materialize(&store, &bob(), &target).await.is_ok(),
            "Control alone must suffice when nothing is materialized");
    }
```

Write the `sp()`, `bob()`, `resource()`, `container()`, `seed_acl()` and `seed_container()` helpers in that module following the shapes used in Task 4's tests; `seed_container` calls `container::ensure_container`, `seed_acl` writes the subject then `aux::put`.

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test --lib wac::guard`
Expected: FAIL — `authorize_and_materialize` does not exist.

- [ ] **Step 3: Retype `container.rs`**

Replace the operation signatures (keeping the SPARQL bodies, with `graph_iri()` in place of `space.graph_iri(path)?`):

```rust
pub async fn ensure_container(store: &dyn SparqlStore, c: &ContainerUrl) -> Result<(), ResourceError>
pub async fn add_containment(store: &dyn SparqlStore, parent: &ContainerUrl, child_iri: &str) -> Result<(), ResourceError>
pub async fn remove_containment(store: &dyn SparqlStore, parent: &ContainerUrl, child_iri: &str) -> Result<(), ResourceError>
pub async fn container_is_empty(store: &dyn SparqlStore, c: &ContainerUrl) -> Result<bool, ResourceError>
```

`ensure_container` must also mark presence, so an empty container exists: after its `INSERT DATA`, call `resource::put_rdf`-equivalent marking, or simply write the type triples through `put_rdf` when the container is absent and leave existing containers untouched. Delete `ensure_ancestors` and `parent_container` — `ResourceUrl::ancestors`/`parent` replace them. Delete `is_container_path` and `body_sets_containment`'s path handling is unchanged.

- [ ] **Step 4: Implement the shared traversal**

Add to `src/wac/guard.rs`:

```rust
/// Authorize and perform the container materialization a write implies —
/// in one traversal.
///
/// A level is written iff it is created, or it is the first already-existing
/// ancestor (which gains a containment triple). Those are exactly the levels
/// this walk authorizes `Append` on, and it stops there: above that point the
/// inserts are no-ops, and demanding rights there would break the
/// append-only inbox pattern. An auxiliary is never a container member, so a
/// write to one adds no containment — only the containers it would create
/// count.
pub async fn authorize_and_materialize(
    store: &dyn SparqlStore,
    agent: &Agent,
    target: &Target,
) -> Result<(), Response> {
    let (subject, is_member): (&ResourceUrl, bool) = match target {
        Target::Resource(r) => (r, true),
        Target::Container(c) => (c.as_resource(), true),
        Target::Aux(a) => (a.subject(), false),
    };

    // The IRI to record as a member at the next level up. It starts as the
    // target and becomes each container this walk creates.
    let mut child_iri = target.graph_iri().to_string();
    let mut record_child = is_member;
    for ancestor in subject.ancestors() {
        let existed = resource::exists(store, &ancestor)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        if existed && !record_child {
            return Ok(()); // nothing observable changes at or above this level
        }
        authorize(store, agent, &Target::Container(ancestor.clone()), Mode::Append).await?;
        container::ensure_container(store, &ancestor)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        if record_child {
            container::add_containment(store, &ancestor, &child_iri)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        }
        if existed {
            return Ok(());
        }
        child_iri = ancestor.graph_iri().to_string();
        record_child = true;
    }
    Ok(())
}
```

Retype `authorize` to take `&Target`:

```rust
pub async fn authorize(
    store: &dyn SparqlStore,
    agent: &Agent,
    target: &Target,
    mode: Mode,
) -> Result<(), Response> {
    let (subject, required) = match target {
        Target::Aux(a) => (a.subject().clone(), Mode::Control),
        Target::Resource(r) => (r.clone(), mode),
        Target::Container(c) => (c.as_resource().clone(), mode),
    };
    let acl = match prp::effective_acl(store, &subject).await {
        Ok(Some(acl)) => acl,
        Ok(None) => return Err(deny(agent)),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    };
    if pdp::decide(&acl.triples, agent, &acl.governed_iri, acl.inherited).allows(required) {
        Ok(())
    } else {
        Err(deny(agent))
    }
}
```

The `InvalidIri` arm is gone: a `Target` cannot carry an invalid IRI, because `resolve` validated it. That is the type doing the work the comment used to do.

- [ ] **Step 5: Run to verify pass**

Run: `nix develop -c cargo test --lib wac:: container::`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/wac/guard.rs src/container.rs
git commit -m "feat: single traversal authorizes exactly what it materializes"
```

---

### Task 6: Provisioning over typed URLs

**Files:**
- Modify: `src/wac/provision.rs`, `src/main.rs`
- Test: inline in `src/wac/provision.rs`

**Interfaces:**
- Consumes: `space::{AuxKind, GraphName, StorageSpace}`, `aux::put`, `resource::put_rdf`, `container::ensure_container`.
- Produces: `provision::provision_root_acl(store, space: &StorageSpace, owner_webid: &str) -> Result<(), ResourceError>` — unchanged name and semantics (idempotent, never overwrites), now writing to `space.root().as_resource().aux(AuxKind::Acl)`.
- Also: `container::provision_root(store, space)` becomes `ensure_container(store, &space.root())`.

- [ ] **Step 1: Adapt the existing tests**

Keep all five tests in `src/wac/provision.rs` with their assertions unchanged. Only their plumbing changes: `sp().graph_iri("/.acl")` becomes `sp().root().as_resource().aux(AuxKind::Acl).graph_iri()`, and `effective_acl(&store, &sp(), "/")` becomes `effective_acl(&store, sp().root().as_resource())`.

An assertion that must change is a finding — report it rather than editing it.

- [ ] **Step 2: Run to verify failure**

Run: `nix develop -c cargo test --lib wac::provision`
Expected: FAIL to compile against the new signatures.

- [ ] **Step 3: Implement**

Rewrite the body of `provision_root_acl` to derive the ACL URL from the space and write through `aux::put` (which now enforces that the root container exists — so `ensure_container(&space.root())` must run first; `main.rs` already calls `provision_root` before it). The existence check that prevents overwriting stays exactly as it is:

```rust
    let root = space.root();
    let acl = root.as_resource().aux(AuxKind::Acl);
    if exists(store, &acl).await? {
        return Ok(());
    }
```

and the `INSERT DATA` becomes a `put_rdf(store, &acl, &triples)` built from parsed Turtle rather than a hand-built update string — the owner WebID still passes `NamedNode::new` first.

- [ ] **Step 4: Run the full library suite**

Run: `nix develop -c cargo test --lib`
Expected: everything except `http::` passes (the handlers are Task 7).

- [ ] **Step 5: Commit**

```bash
git add src/wac/provision.rs src/main.rs src/container.rs
git commit -m "feat: provision the root ACL through the typed auxiliary model"
```

---

### Task 7: Handlers dispatch on `Target`

The largest deletion in the plan. Every `is_acl_path`, every empty-body rule, every remembered lifecycle step goes.

**Files:**
- Modify: `src/http.rs`
- Test: inline in `src/http.rs`, plus `tests/route_coverage.rs`

**Interfaces:**
- Consumes: everything above.
- Produces: handlers that resolve once and match. `acl_link` becomes `aux_links(space, &ResourceUrl) -> HeaderValue` covering every `AuxKind`.

- [ ] **Step 1: Resolve once, at the entry**

Each `handle_*` resolves the path and dispatches:

```rust
async fn handle_put(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap, body: Bytes,
) -> Response {
    match st.space.resolve(&format!("/{path}")) {
        Ok(target) => put_impl(st, agent, target, headers, body).await,
        Err(SpaceError::Reserved) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}
```

An unallocated reserved path is a 404: it is not data, and it never will be.

- [ ] **Step 2: `put_impl` over `Target`**

```rust
async fn put_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(res) = authorize(st.store.as_ref(), &agent, &target, Mode::Write).await {
        return res;
    }
    if let Err(res) = authorize_and_materialize(st.store.as_ref(), &agent, &target).await {
        return res;
    }
    let Some(fmt) = format_for_content_type(header_str(&headers, header::CONTENT_TYPE)) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let triples = match parse(&body, fmt, target.graph_iri()) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // conditional-request handling unchanged, using `get_rdf(store, &target)`
    match &target {
        Target::Aux(aux) => match crate::aux::put(st.store.as_ref(), aux, &triples).await {
            Ok(()) => created(&st.space, &target),
            Err(crate::aux::AuxError::SubjectMissing) => (
                StatusCode::NOT_FOUND,
                "an auxiliary resource cannot be created for a resource that does not exist",
            ).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        Target::Container(_) => { /* merge kept containment, then put_rdf; unchanged logic */ }
        Target::Resource(_) => match put_rdf(st.store.as_ref(), &target, &triples).await {
            Ok(()) => created(&st.space, &target),
            Err(e) => (put_status(&e), e.to_string()).into_response(),
        },
    }
}
```

The empty-body rejections at both handlers are **deleted**: with stored existence, an empty body creates an empty resource, which is exactly what it says.

- [ ] **Step 3: `delete_impl` over `Target`**

`Write` on the target; `Write` on the parent when the target is a container member; then `aux::delete_subject` for a resource or container (which cascades every auxiliary), or `delete_rdf` for an auxiliary. The `is_acl_path`-guarded cascade and the separate ACL-authorization block both disappear — deleting a subject removes its auxiliaries by construction, and the caller already needed `Write` on the subject.

Keep the container rules: 409 when non-empty, 405 on the root, both after authorization.

- [ ] **Step 4: `Link` headers from `AuxKind`**

```rust
/// Every auxiliary this resource has, advertised whether or not it exists —
/// a client must not derive these URLs, so it can only learn them here, and
/// it needs them precisely in order to create the first one.
fn aux_links(target: &Target) -> Option<(header::HeaderName, String)> {
    let subject = match target {
        Target::Resource(r) => r,
        Target::Container(c) => c.as_resource(),
        Target::Aux(_) => return None, // an auxiliary has none of its own
    };
    let value = AuxKind::ALL
        .iter()
        .map(|k| format!("<{}>; rel=\"{}\"", subject.aux(*k).graph_iri(), k.link_rel()))
        .collect::<Vec<_>>()
        .join(", ");
    Some((header::LINK, value))
}
```

Attach it to the GET success arm, the `CREATED` responses, **and** the 404 and denial paths for resource targets. The denial path means threading it through `authorize`'s error response at the handler, not inside the guard.

- [ ] **Step 5: Update the tests**

Every handler test's URL changes from `/foo.acl` to `/.aux/acl/foo`; assertions stay. Add:

```rust
    #[tokio::test]
    async fn the_acl_link_is_advertised_even_when_the_acl_does_not_exist() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo").header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();
        let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        let link = res.headers().get(header::LINK).unwrap().to_str().unwrap().to_string();
        assert!(link.contains("/.aux/acl/foo"), "{link}");
    }

    #[tokio::test]
    async fn the_acl_link_is_advertised_on_404() {
        let f = fixture().await;
        let get = f.owner_request("GET", "/nothing").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().get(header::LINK).is_some(),
            "SolidOS string-derives the ACL URL when this header is missing");
    }

    #[tokio::test]
    async fn an_empty_acl_denies_instead_of_inheriting() {
        let f = fixture().await;
        let mk = f.owner_request("PUT", "/locked/").header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("")).unwrap();
        f.app.clone().oneshot(mk).await.unwrap();
        let acl = f.owner_request("PUT", "/.aux/acl/locked/")
            .header(header::CONTENT_TYPE, "text/turtle").body(Body::from("")).unwrap();
        assert_eq!(f.app.clone().oneshot(acl).await.unwrap().status(), StatusCode::CREATED);
        // the owner locked themselves out of the subtree, which is what an
        // empty ACL means
        let get = f.owner_request("GET", "/locked/").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(get).await.unwrap().status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_reserved_namespace_is_not_storage() {
        let f = fixture().await;
        for path in ["/.aux", "/.aux/", "/.aux/bogus/x"] {
            let put = f.owner_request("PUT", path).header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
            assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(),
                StatusCode::NOT_FOUND, "{path} must not be storage");
        }
    }
```

In `tests/route_coverage.rs`, change the seeded ACL paths to the `/.aux/acl/` form and add `/.aux/acl/seeded`, `/.aux/bogus/x` to the path list.

- [ ] **Step 6: Verify and commit**

Run: `nix develop -c cargo test`, then clippy and the warning check.
Expected: the full suite green. Report any pre-existing test whose *expectation* had to change.

```bash
git add src/http.rs tests/route_coverage.rs
git commit -m "feat: handlers dispatch on a resolved Target; drop the suffix rules"
```

---

### Task 8: Prove the defects are unrepresentable, then review

**Files:**
- Create: `tests/unrepresentable.rs`
- Modify: `docs/superpowers/specs/2026-07-26-wac-enforcement-design.md` (mark superseded sections)

- [ ] **Step 1: Compile-fail evidence**

The design's success criterion is that six defect classes are *unrepresentable*, not merely tested. Record that as prose in `tests/unrepresentable.rs`'s module doc — naming, for each defect, the expression that no longer type-checks (`AuxUrl` has no `.aux()`; no constructor from a `Slug`; `ancestors()` is the only chain) — and add the runtime cases that remain meaningful:

```rust
//! Why six of Plan 6's seven defect classes cannot recur.
//!
//! Four are gone at the type level and have no runtime test, because the
//! expression that would exercise them does not compile:
//!
//! * **Slug escalation.** `AuxUrl`'s only constructors are
//!   `ResourceUrl::aux` and `StorageSpace::resolve` on a `/.aux/` path. A
//!   `Slug` produces a child name, and no child name is a `Target::Aux`.
//! * **Auxiliary-of-an-auxiliary.** `AuxUrl` has no `aux()` method.
//! * **Twin traversals.** `ResourceUrl::ancestors` is the only chain, and
//!   `authorize_and_materialize` is its only consumer.
//! * **Orphaned auxiliary.** `aux::delete_subject` drops every kind in one
//!   update; there is no code path that deletes a subject alone.
//!
//! The two that remain observable are tested below.

use std::sync::Arc;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sparql_pod::{aux, container, http::{router, AppState}, resource,
    space::{AuxKind, StorageSpace, Target}, store::OxigraphStore, wac};
use tower::ServiceExt;

const OWNER: &str = "https://alice.example/card#me";

// A Slug names a child in the resource space; nothing it can contain routes
// into `/.aux/`, because that classification happens on the request path.
#[tokio::test]
async fn a_slug_cannot_reach_the_auxiliary_space() {
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    for slug in [".aux", "..aux", "acl", ".aux.acl"] {
        let child = format!("/box/{slug}");
        assert!(
            matches!(space.resolve(&child).unwrap(), Target::Resource(_)),
            "{child} must stay an ordinary resource"
        );
    }
}

// Recreating a path must not restore the policy of the resource that used to
// live there. The cascade makes that structural rather than remembered.
#[tokio::test]
async fn an_auxiliary_never_outlives_its_subject() {
    let store = OxigraphStore::in_memory().unwrap();
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    let Target::Resource(doc) = space.resolve("/doc").unwrap() else { panic!() };

    resource::put_rdf(&store, &doc, &[]).await.unwrap();
    aux::put(&store, &doc.aux(AuxKind::Acl), &[]).await.unwrap();
    assert!(resource::exists(&store, &doc.aux(AuxKind::Acl)).await.unwrap());

    assert!(aux::delete_subject(&store, &doc).await.unwrap());
    assert!(!resource::exists(&store, &doc.aux(AuxKind::Acl)).await.unwrap());

    // recreate the same path: it inherits, it does not resurrect
    resource::put_rdf(&store, &doc, &[]).await.unwrap();
    assert!(
        wac::prp::effective_acl(&store, &doc).await.unwrap().is_none(),
        "the recreated resource must not pick up the deleted one's ACL"
    );
}
```

- [ ] **Step 2: Mark the superseded spec sections**

Add a note at the top of `2026-07-26-wac-enforcement-design.md` pointing at the new spec, and strike the `<res>.acl` location paragraph and the empty-body rules in §4, which no longer describe the system.

- [ ] **Step 3: Whole-branch adversarial review**

Dispatch a review of the full branch diff with the same brief as Plan 6's final review, plus these specific questions: can any path reach the store without passing through `resolve`? Can a `Target` be constructed outside `space`? Does `authorize_and_materialize` still write exactly the levels it authorizes, for all three `Target` variants? Does stored existence introduce a state where a resource exists but is unreachable, or is deletable by someone who could not create it?

- [ ] **Step 4: Fix findings, re-verify, commit**

## Verification Summary

After every task:

```bash
nix develop -c cargo test
nix develop -c cargo clippy --all-targets
nix develop -c cargo build 2>&1 | grep -i warning   # must print nothing
```

Tasks 1–6 leave `http.rs` uncompilable by design; run `nix develop -c cargo test --lib <module>::` for the module under test and note it in the report. From Task 7 the whole suite must be green.

## Known deviation from the spec

The spec (§8) claims the ACL walk becomes **one** store round trip. With existence stored as a marker, the honest cost is **two constant round trips** — one `ASK` per candidate until the nearest hit, then one `CONSTRUCT` for its content — which is still independent of the old depth+1 behaviour only in the second half. If the `ASK` loop shows up in profiling, the fix is a single `SELECT` over `VALUES ?g { … }` against the presence markers, which needs a `query_solutions` method on `SparqlStore`. Not built now: there is no measurement justifying it, and the interface change is larger than the win.
