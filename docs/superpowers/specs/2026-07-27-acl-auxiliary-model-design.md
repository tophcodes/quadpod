# ACL as an Auxiliary Resource — Design

**Date:** 2026-07-27
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Supersedes parts of:** [2026-07-26-wac-enforcement-design.md](2026-07-26-wac-enforcement-design.md) §3 (ACL location, containment) and §4 (enforcement matrix refinements)
**Evidence:** `.superpowers/sdd/architecture-postmortem.md`, `.superpowers/sdd/acl-url-interop.md`

## 1. Why

Plan 6 shipped WAC enforcement. Seven authorization defects were found during it — every one by adversarial review, and each one inside the fix for the previous one. The post-mortem identified a single common denominator, and it is not carelessness:

- **What does this request write?** The handler predicted the storage layer's effects in `authorize_ancestors`, a hand-maintained twin of `container::ensure_ancestors`. Drift between the twins is privilege escalation. Defects 3 and 5.
- **Is this path policy?** `is_acl_path` is `ends_with(".acl")`, re-evaluated at 13 production sites. Each of defects 1, 5, 6 and 7 is one missing evaluation.

Both questions have exactly one right answer per request, and neither had a canonical place to live. Notably, `wac/pdp.rs` and `wac/prp.rs` — the parts built from a spike with table tests — produced zero defects. Every fix landed in `src/http.rs`.

The deeper cause: **an ACL was modelled as an ordinary sibling resource that happens to have different rules.** Different containment, different lifecycle, different authorization, different existence contract — each rule re-derived at a call site, one review round at a time. The Solid Protocol already defines the class we were reinventing.

> "Solid has the notion of auxiliary resources to provide supplementary information such as descriptive metadata, **authorization conditions**, data shape constraints […] about a given resource."
> "Servers MUST support auxiliary resources […] and **manage the association** […]. **When a subject resource is deleted its auxiliary resources are also deleted by the server.**"
> — Solid Protocol, §Auxiliary Resources

This design adopts that class, and makes both questions answerable in one place each — the type system where possible, one function where not.

## 2. Goals

- The ACL's identity, lifecycle and containment behaviour follow from **types and construction**, not from remembered rules at call sites.
- Exactly **one** traversal derives the ancestor chain, and the same chain authorizes and materializes.
- **One** place answers "what kind of thing does this request address", resolved per request.
- Existence becomes a stored fact, so an empty resource — in particular an empty ACL, meaning *deny everything below* — is representable and truthful.
- Conformance improves, not just internals: the current `<res>.acl` convention invites exactly the client-side string derivation WAC forbids.

## 3. Non-Goals

- No change to the PDP (`wac/pdp.rs`) — it produced no defects and its interface is unaffected.
- No storage-boundary capability system (post-mortem alternative B in full). The typed store wrapper here is its cheap half; the rest waits for the `/sparql` read proxy, when a second door actually exists.
- No fix for defect 2 (a `Write`-holder destroying a narrowing ACL by delete-and-recreate). It is inherent to path-anchored policy; CSS and ESS behave identically. See §11.
- No data migration. This pod has never been deployed; `pod.toph.so` is the separate file-based pod and is untouched.

## 4. The ACL namespace

The ACL of a resource lives under a **reserved root prefix**, not as a sibling:

| Subject | ACL URL |
|---|---|
| `/` | `/.acl/` |
| `/foo` | `/.acl/foo` |
| `/box/` | `/.acl/box/` |
| `/a/b/c` | `/.acl/a/b/c` |

Both directions are total and mutually inverse: strip or prepend the one prefix segment.

**Why a prefix rather than a suffix.** A reserved prefix is a total function over the path space, evaluated once by the router. A reserved suffix is a partial predicate that must be re-evaluated wherever a path is constructed — which is precisely how defects 1, 5, 6 and 7 arose. `/.acl` without a trailing slash is reserved as well (404), so the space is unambiguous.

**Conformance.** WAC constrains discovery, not URL shape: servers MUST advertise the ACL via `Link: rel="acl"`, clients MUST discover it that way, and clients **MUST NOT** derive it by string operations — WAC even permits the ACL to live on a different origin. The official conformance harness contains no `.acl` string in its sources; it reads the `Link` header and fails loudly when absent. CSS treats its `.acl` suffix as a swappable config value behind a pluggable strategy and ships `.acr` and `.meta` alongside; Trellis uses `?ext=acl`; Manas uses `<res>._aux/acl`; ESS hosts ACRs on a different service entirely. Four implementations, four shapes.

**Interop obligations** (from `acl-url-interop.md`, all mandatory):

1. Emit `Link: <acl-url>; rel="acl"` on **every** response for a resource path, **including 404 and denial responses**. SolidOS's `solid-logic` falls back to string-deriving `<url>.acl` exactly when the header is absent, mid-create-flow. A regression test must cover the 404 case, because the failure is silent.
2. Serve ACLs with `Content-Type: text/turtle` (or the negotiated RDF type). rdflib guesses content type by extension when no real header arrives.
3. We write our own conformance-suite runner; the WAC test suite's CSS bootstrap script PUTs to `<root>/.acl`, which is CSS-specific plumbing, not interop.

## 5. Type model

The rules become types. All constructors are private to `space`; a URL enters the system only through `StorageSpace::resolve`.

```rust
pub struct ResourceUrl(String);   // in the resource space
pub struct ContainerUrl(String);  // a ResourceUrl ending in '/'
pub struct AclUrl(String);        // in the reserved ACL space

pub enum Target {
    Resource(ResourceUrl),
    Container(ContainerUrl),
    Acl(AclUrl),
}

impl StorageSpace {
    /// The single entry point from a raw request path. Rejects paths that
    /// form no valid IRI, and classifies the ACL space by prefix.
    pub fn resolve(&self, request_path: &str) -> Result<Target, SpaceError>;
}

impl ResourceUrl {
    pub fn acl(&self) -> AclUrl;                                // total
    pub fn ancestors(&self) -> impl Iterator<Item = ContainerUrl>;
    pub fn parent(&self) -> Option<ContainerUrl>;
}

impl AclUrl {
    pub fn subject(&self) -> ResourceUrl;                       // total inverse
}

pub trait GraphName { fn graph_iri(&self) -> &str; }            // all three
```

What becomes **unrepresentable**, rather than merely checked:

- `AclUrl` has no `.acl()`. The ACL-of-an-ACL chain (defect 7) cannot be written down.
- `AclUrl`'s only sources are `ResourceUrl::acl()` and the ACL route. No `Slug`, no concatenated string, can produce one — defect 1 has no path to the type.
- `ancestors()` yields `ContainerUrl`, and the same iterator feeds authorization and materialization — defects 3 and 5 lose their second source of truth.
- Store operations take `&impl GraphName`, so a write cannot address a graph the caller did not name.

`Target` is resolved once, in the handler entry, and passed down. The handlers stop asking `is_container_path` / `is_acl_path`; they match.

**Deliberately not in the type system:** existence. "No ACL without a subject" (defect 6) stays a runtime check, in one place — the typed store wrapper — rather than a witness token threaded through every call site. See §12 for the alternative, if you want the ceremony.

## 6. Lifecycle: the ACL is an auxiliary, not an object

- An ACL is **never independently created**. `PUT` to an ACL URL whose subject does not exist is a 404 by construction of the write path, not by a rule at two handlers.
- Deleting a resource deletes its ACL **in the same store operation**. Not a cascade someone remembered to add — the delete op takes the subject and drops both graphs plus the system graph.
- ACLs are never `ldp:contains` members. They are not in the resource space at all, so the question does not arise at `add_containment`; the exclusion rule disappears rather than being enforced.
- Consequently there is no orphaned-ACL state to reason about: defect 5's precondition cannot be constructed.

## 7. Existence as a stored fact

Resource existence moves out of "the user graph has at least one triple" into the reserved system graph the parent spec already defines (`urn:pod:sys:<res>`, parent design §5).

Why this belongs in *this* change rather than a later one: defect 4 was filed as a data-integrity defect at the end of Plan 3 and became a **security** defect the moment WAC shipped, because "resource absent" now means "ancestor policy applies". An empty ACL — the natural way to express *deny everything below here* — was answered with `201 Created` while in fact widening access. The 400-on-empty-body rules currently in `put_impl`/`post_impl` are a workaround that makes a legitimate Solid operation impossible; they are removed here.

With a presence marker: an empty resource exists, `GET` returns 200 with an empty representation, an empty ACL matches zero authorizations and therefore denies, and `DELETE` on it reaches `remove_containment` normally.

Touches: `resource::{put_rdf, get_rdf, delete_rdf}`, `container::container_is_empty`, the POST collision check, and ETag derivation for the empty case.

## 8. One traversal, one query

**Materialization and authorization share a traversal.** A single function walks `ancestors()`, authorizing `Append` and creating containers as it goes, stopping at the first ancestor that already exists — because above that level nothing observable changes. The mirror pair `authorize_ancestors` / `ensure_ancestors` collapses into it. This is the post-mortem's B-lite, and it is mostly deletion.

**The ACL walk is one query.** The candidate ACL graphs for `/a/b/c` are derivable from the path — `/.acl/a/b/c`, `/.acl/a/b/`, `/.acl/a/`, `/.acl/` — so the PRP asks for all of them in a single SPARQL query (`VALUES ?g { … } GRAPH ?g { … }`), ordered by depth, and takes the nearest non-empty one. One round trip instead of depth+1.

One ACL is one named graph, as today. A single shared ACL graph was considered and rejected: it turns `DROP GRAPH` into a subject-scoped `DELETE WHERE` (unsound for blank-node authorizations, and a bug there deletes other people's policy), turns `PUT` into a non-atomic diff on shared structure, and removes the isolation that makes the lifecycle binding in §6 a one-liner. Graph count is not a concern: only resources with an *own* policy have an ACL graph at all, and in a quad store a graph name is just the fourth term.

**Deriving the chain from the path is legitimate here** — and the distinction matters. Inside our own storage space the path hierarchy is not an assumption about URLs; it is an invariant this server establishes and maintains, and LDP defines containment in exactly those terms. For anything foreign — WebIDs, issuer URLs, another server's ACL URL — nothing is parsed or assumed; we compare, or we follow a `Link` header. The derivation lives on `StorageSpace`, which the parent design (§9) already names as the owner of URI topology.

## 9. What this buys, defect by defect

| Defect | After |
|---|---|
| 1 — `Slug: .acl` escalation | **unrepresentable** (no path from `Slug` to `AclUrl`) |
| 3 — unauthorized ancestor mutation | **unrepresentable** (one traversal, one chain) |
| 4 — empty-body PUT reports success while widening access | **unrepresentable** (existence is stored) |
| 5 — orphaned ACL re-materializes containers | **unrepresentable** (no orphan state) |
| 6 — ACL for a nonexistent subject | one check, one place (was: two rules, four sites) |
| 7 — `.acl.acl` chain | **unrepresentable** (`AclUrl` has no `.acl()`) |
| 2 — narrowing ACL destroyed by delete+recreate | unchanged; inherent, see §11 |

## 10. Migration

Nothing is deployed, so there is no data migration and no compatibility window. The work is a refactor of `src/http.rs`, `src/wac/prp.rs`, `src/space.rs`, `src/container.rs` and `src/resource.rs`, and it is **net-negative in lines**: three lifecycle rules, the `is_acl_path` predicate at 13 sites, the mirror-pair guard and the two empty-body rules all leave.

The existing 171 tests are the safety net for the refactor. Their assertions must survive; only setup changes where a URL shape appears.

## 11. What this does not fix

Defect 2: Bob holds `Write` on `/box/doc`, whose ACL narrows him; he deletes it (the ACL dies with it, by design), recreates it, and the wider inherited policy applies. This is path-anchored policy plus destroy-and-recreate, and no shape here prevents it. It is also, per the reviews, exactly how CSS and ESS behave.

Related and already documented in the current spec: `acl:default acl:Control` on a container is an irrevocable handover of everything below it, not a bounded "manage access here" grant.

## 12. Open questions

1. **Existence witness.** `AclUrl` could be constructible only from a proof that the subject exists (`fn acl_of(subject: &Existing<ResourceUrl>) -> AclUrl`), moving defect 6 into the type system too. Cost: an `Existing<T>` token threaded through call sites that currently take a URL. **Recommendation: no** — one check in the typed store wrapper, with a test, is the better trade at this size.
2. **How far `Target` travels.** It could stop at the guard, with handlers taking the unwrapped URL types, or be matched on inside each handler. **Recommendation: into the handlers** — the match is what replaces the scattered predicates, and a handler that receives `AclUrl` cannot accidentally treat it as a container.
3. **`HEAD` and `Link` on denials.** Obligation 1 in §4 says the header goes on 404s. Does it also go on 401/403? Emitting it discloses only a URL the client could not use anyway, and SolidOS's fallback path can be reached from a denial too. **Recommendation: yes, emit it always.**

## 13. Success criteria

- Every defect marked *unrepresentable* in §9 has a corresponding test that no longer compiles, or a construction that no longer exists — not merely a passing negative test.
- The full existing suite passes with assertions unchanged.
- `Link: rel="acl"` is present on 200, 404 and denial responses, with a regression test for the 404 case specifically.
- `is_acl_path`-style suffix predicates appear **zero** times outside `space`.
- The ancestor chain is derived in exactly one function, used by both authorization and materialization.
- The PRP resolves an ACL in one store round trip regardless of depth.
