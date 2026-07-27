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

## 4. Auxiliaries in general, ACL in particular

The ACL is one auxiliary kind, not a special case. The machinery below is parameterized by
kind from the start — one reserved prefix per kind, one lifecycle rule, one router
classification — because the defect history is a history of second implementations of
rules that already existed.

| Kind | Path | Written by | Authorized by |
|---|---|---|---|
| `Acl` | `/.aux/{subject}.acl` | client | `Control` on the subject |
| `Description` (candidate) | `/.aux/{subject}.meta` | client | `Write` on the subject |
| system projection (later) | — | server only | read-only, see §12.4 |

The auxiliary's **content is the user's data**; what the server contributes is the
association, the lifecycle, the exclusion from listings and the authorization derivation.
"Reserved" here means the server understands these paths, not that it owns what is in them.

**Exactly one segment is reserved, once and for all: `/.aux/`.** Every auxiliary kind is a
subdirectory inside it, so adding a kind later takes nothing further away from users. Any
other dot-prefixed name stays ordinary — `/.hidden`, `/.config` and `/notes/.env` are
normal resources. An unallocated path under `/.aux/` is refused rather than treated as data.

`/.well-known/` is a separate matter and not an auxiliary: RFC 8615 assigns it to the
*origin*, so the pod stores nothing there and refuses writes, and serving it is the reverse
proxy's job. It only arises at all when the pod's base URI is the origin root; under a
path-based topology it sits above the base URI entirely.

The client-facing statement of this contract is [`docs/uri-space.md`](../../uri-space.md);
it is normative and must be kept in step with the table above.

**Built now: `Acl` only, and `Description` is not promised.** For an RDF resource a
description resource is largely redundant — statements about a graph can live in that graph.
Its real justification arrives with **blobs**: a PNG cannot carry triples, so user-asserted
metadata (licence, caption, creator) needs a sidecar, while server-asserted facts (size,
hash, content-type) go to the system graph. Both halves appear for the first time together
there, split by authority. The blob plan decides whether that sidecar is a description
resource; until then the `.meta` name is reserved space, not a commitment.

What is built now is the *shape*: `AuxKind`, one path table, one lifecycle. A second kind is
then a variant plus one row in the authorization table, not a parallel subsystem — it
inherits conneg, ETags, conditional requests, authorization, cascade and discovery
unchanged.

**The set of kinds is closed and server-defined.** A user cannot introduce an auxiliary
kind, because what makes something auxiliary is semantics the *server* enforces: lifecycle
binding, exclusion from listings, authorization derived from the subject. A kind the server
does not understand has none of that, so it is an ordinary resource — and nothing is lost:
anyone can create `/notes/foo-annotations` and link it from their own data with
`rdfs:seeAlso`. It simply gets its own ACL and its own lifecycle, like any resource.
Consequently `AuxKind` is the single source of truth for both the routing table and the set
of `Link` headers, so the two cannot drift.

**Server-asserted facts are deliberately not auxiliaries.** Creation and modification
times, size, hash, the `object_store` key: these stay in the reserved `urn:pod:sys:<res>`
graph (parent design §5), exposed through HTTP headers (`Last-Modified`, `ETag`,
`Content-Length`) rather than as an addressable RDF resource. The split is by **authority,
not by aboutness** — the moment a server-asserted fact has a writable URL, a client can
dictate its own creation timestamp and the value is worthless for audit or ordering. None
of these fields exist in the code today; they arrive with blobs, which need `size`, `hash`
and `content-type` in the system graph anyway.

### The ACL namespace

> **Revised 2026-07-27, after the first conformance run.** The original shape put the kind
> in a leading segment (`/.aux/acl/box/`), which inherited the subject's trailing slash. Two
> things came out of running the harness against it, and the second is the one that matters.
>
> First, the harness could not write such a URL: Jersey's `UriTemplate.normalize()` — a
> broken reimplementation of RFC 3986's `remove_dot_segments`, three layers below the
> harness's own code — drops the trailing empty segment when the path also contains a
> dot-prefixed segment. That is a client bug (WAC forbids deriving the ACL URI by string
> operations), and `@inrupt/solid-client` and `rdflib.js` both preserve the URL correctly.
> On its own it would not justify a redesign.
>
> Second, and decisively: **the collision this shape was designed to avoid does not exist in
> Solid.** Protocol §3.1 says *"If two URIs differ only in the trailing slash […] the other
> URI MUST NOT correspond to another resource."* `/box` and `/box/` being distinct is LDP,
> not Solid; CSS rejects the pair with a 409 and `specification-tests` ships
> `slash-semantics-exclude.feature` for exactly this. So there was never a pair of ACLs to
> keep apart, and the shape paid a real interop cost for a distinction the specification
> forbids. No shipping server produces a slash-terminated ACL URL — the shape was
> unexercised anywhere.

The ACL of a resource lives under the reserved auxiliary prefix, with the kind as a
**suffix**, so an auxiliary URL never ends in a slash:

| Subject | ACL URL |
|---|---|
| `/` | `/.aux/.acl` |
| `/foo` | `/.aux/foo.acl` |
| `/box/` | `/.aux/box/.acl` |
| `/a/b/c` | `/.aux/a/b/c.acl` |

The rule is `/.aux` + the subject's path + `.` + the kind's name. Both directions stay total
and mutually inverse: strip the prefix and the suffix, or prepend and append them.

**The classification is still by prefix, and that is what matters.** The router decides
"resource space or auxiliary space" from the first segment alone — one total function,
evaluated once, which is the property the whole model rests on. The suffix only names the
*kind* inside a space this server already owns entirely, so it is not the re-derived
predicate the old `<res>.acl` design died of. It also matches how every other server ends an
auxiliary URL (`.acl`, `.acr`, `.meta`), which is why no client normalization trips over it.

**Trailing-slash pairs are refused.** Creating `/box` while `/box/` exists — or the reverse —
answers `409`, per Protocol §3.1 and matching CSS. This is a rule about the resource space;
the auxiliary space inherits it for free, because an auxiliary's identity now follows from
its subject's.

**Why a prefix rather than a suffix.** A reserved prefix is a total function over the path space, evaluated once by the router. A reserved suffix is a partial predicate that must be re-evaluated wherever a path is constructed — which is precisely how defects 1, 5, 6 and 7 arose. `/.aux`, `/.aux/` and any path under it ending in no kind's name are reserved as well (404), so the space is unambiguous. The kind's name is a suffix *inside* that prefix (see "The ACL namespace"), which changes nothing about the classification: it is read once, by the router, from the leading segment.

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

#[derive(Clone, Copy)]
pub enum AuxKind { Acl }          // + Description later; each owns one prefix
pub struct AuxUrl { kind: AuxKind, subject: ResourceUrl }

pub enum Target {
    Resource(ResourceUrl),
    Container(ContainerUrl),
    Aux(AuxUrl),
}

impl StorageSpace {
    /// The single entry point from a raw request path. Rejects paths that
    /// form no valid IRI, and classifies the auxiliary space by prefix.
    pub fn resolve(&self, request_path: &str) -> Result<Target, SpaceError>;
}

impl ResourceUrl {
    pub fn aux(&self, kind: AuxKind) -> AuxUrl;                 // total
    pub fn ancestors(&self) -> impl Iterator<Item = ContainerUrl>;
    pub fn parent(&self) -> Option<ContainerUrl>;
}

impl AuxUrl {
    pub fn subject(&self) -> &ResourceUrl;                      // total inverse
    pub fn kind(&self) -> AuxKind;
}

pub trait GraphName { fn graph_iri(&self) -> &str; }            // all of them
```

What becomes **unrepresentable**, rather than merely checked:

- `AuxUrl` has no `.aux()`. The auxiliary-of-an-auxiliary chain (defect 7) cannot be written down — for every kind, not just ACLs.
- `AuxUrl` holds its subject as a `ResourceUrl` rather than a string, so `subject()` cannot fail or disagree with the URL it came from.
- `AuxUrl`'s only sources are `ResourceUrl::aux()` and the auxiliary routes. No `Slug`, no concatenated string, can produce one — defect 1 has no path to the type.
- `ancestors()` yields `ContainerUrl`, and the same iterator feeds authorization and materialization — defects 3 and 5 lose their second source of truth.
- Store operations take `&impl GraphName`, so a write cannot address a graph the caller did not name.

`Target` is resolved once, in the handler entry, and passed down. The handlers stop asking `is_container_path` / `is_acl_path`; they match.

**Deliberately not in the type system:** existence. "No ACL without a subject" (defect 6) stays a runtime check, in one place — the typed store wrapper — rather than a witness token threaded through every call site. See §12 for the alternative, if you want the ceremony.

## 6. Lifecycle: the ACL is an auxiliary, not an object

- An ACL is **never independently created**. `PUT` to an ACL URL whose subject does not exist is a 404 by construction of the write path, not by a rule at two handlers.
- Deleting a resource deletes its ACL **in the same store operation**. Not a cascade someone remembered to add — the delete op takes the subject and drops both graphs plus the system graph.
- ACLs are never `ldp:contains` members. They are not in the resource space at all, so the question does not arise at `add_containment`; the exclusion rule disappears rather than being enforced.
- Consequently there is no orphaned-ACL state to reason about: defect 5's precondition cannot be constructed.

## 6a. Association, discovery, and what we do not support

**The `Link` header is unconditional and costs no lookup.** Every response for a resource
path carries a `Link` header for every implemented auxiliary kind, whether or not that
auxiliary has a representation — one header field, comma-separated:

```
Link: <https://pod.toph.so/.aux/foo.acl>; rel="acl"
```

Emitting it only when the auxiliary exists would be a chicken-and-egg trap: a client must
not derive the URL (WAC MUST NOT), so it learns it only from the header — and it needs it
precisely in order to *create* the first ACL. WAC anticipates the case explicitly, noting
that an associated ACL resource may have no representation, in which case a container's ACL
applies. Following the link and receiving 404 is the correct answer: *no own policy here,
you inherit, and this is where to change that.*

The URL is a pure function of the request path, so this is a string construction and zero
store access. **There is deliberately no index of which auxiliaries exist.** It would help
nowhere — the header needs no lookup, the PRP needs the nearest ACL's *content* rather than
its existence and gets it in one query, and the delete cascade is idempotent via
`DROP SILENT GRAPH`. It would only add a second source for a fact already stored elsewhere,
which is the exact construction behind defects 3 and 5.

The principle, stated once: **store what cannot be derived; derive what can.** Resource
existence is stored (§7) because "empty graph" and "absent graph" are indistinguishable in
the store. An auxiliary URL is derived, because it is a total function of the path.

We also do not write `rdfs:seeAlso` or similar association triples into the subject's graph:
those would be server-asserted statements inside user data (which parent design §5 rules
out) and a second description to keep in step. The header is the interface, and `HEAD`
delivers it without a body.

**Cascade applies only within this pod's storage space.** Deleting a resource deletes its
local auxiliaries; nothing foreign is touched, because nothing foreign can be.

**Remote auxiliaries are a non-goal.** WAC permits a server to associate an ACL on another
origin; we do not. The association here is server-managed and always resolves locally, so a
client cannot redirect it (it cannot set response headers, and a body triple is not a WAC
discovery mechanism). Supporting it would make every authorization decision depend on a
third-party fetch on the hot path: SSRF surface, availability coupling to a foreign host,
and cache/TTL questions with no good answer — we already paid for a hardened fetcher with IP
filtering, redirect refusal and a negative cache to make WebID and JWKS lookups safe. WAC's
own issue #90 leaves four cross-origin security questions unresolved. Not a trade worth
making for an authorization decision.

**Base IRI when parsing an auxiliary document.** An auxiliary is parsed with *its own* URL as
base, like any other resource — so `<>` inside `/.aux/foo.acl` denotes the ACL document, not
`/foo`. Statements about the subject name it explicitly (`</foo>` or the absolute IRI). This
matches CSS and is the least surprising rule, but it is a genuine trip hazard and belongs in
the client-facing documentation.

**There is no atomic create-with-policy, and that is a known window.** Creating a resource
and then setting its ACL is two requests; in between, the inherited policy applies. A
resource created in a public container is briefly public. This is inherent to Solid — no
server offers an atomic form — and the practical answer is to keep the window *empty*:
create the container first, set its ACL, then write content into it. An empty container
discloses nothing. Closing the window properly would mean allowing an ACL to precede its
subject, which is exactly what enables the squat defect (6) unless `Control` over an
auxiliary is also derivable from the inherited chain — a deliberate deviation from
nearest-ACL-wins that deserves its own design and its own adversarial review, not a
smuggled-in clause here.

## 7. Existence as a stored fact

Resource existence moves out of "the user graph has at least one triple" into the reserved system graph the parent spec already defines (`urn:pod:sys:<res>`, parent design §5).

Why this belongs in *this* change rather than a later one: defect 4 was filed as a data-integrity defect at the end of Plan 3 and became a **security** defect the moment WAC shipped, because "resource absent" now means "ancestor policy applies". An empty ACL — the natural way to express *deny everything below here* — was answered with `201 Created` while in fact widening access. The 400-on-empty-body rules currently in `put_impl`/`post_impl` are a workaround that makes a legitimate Solid operation impossible; they are removed here.

With a presence marker: an empty resource exists, `GET` returns 200 with an empty representation, an empty ACL matches zero authorizations and therefore denies, and `DELETE` on it reaches `remove_containment` normally.

Touches: `resource::{put_rdf, get_rdf, delete_rdf}`, `container::container_is_empty`, the POST collision check, and ETag derivation for the empty case.

## 8. One traversal, one query

**Materialization and authorization share a traversal.** A single function walks `ancestors()`, authorizing `Append` and creating containers as it goes, stopping at the first ancestor that already exists — because above that level nothing observable changes. The mirror pair `authorize_ancestors` / `ensure_ancestors` collapses into it. This is the post-mortem's B-lite, and it is mostly deletion.

**The ACL walk is one query.** The candidate ACL graphs for `/a/b/c` are derivable from the path — `/.aux/a/b/c.acl`, `/.aux/a/b/.acl`, `/.aux/a/.acl`, `/.aux/.acl` — so the PRP asks for all of them in a single SPARQL query (`VALUES ?g { … } GRAPH ?g { … }`), ordered by depth, and takes the nearest non-empty one. One round trip instead of depth+1.

One ACL is one named graph, as today. A single shared ACL graph was considered and rejected: it turns `DROP GRAPH` into a subject-scoped `DELETE WHERE` (unsound for blank-node authorizations, and a bug there deletes other people's policy), turns `PUT` into a non-atomic diff on shared structure, and removes the isolation that makes the lifecycle binding in §6 a one-liner. Graph count is not a concern: only resources with an *own* policy have an ACL graph at all, and in a quad store a graph name is just the fourth term.

**Deriving the chain from the path is legitimate here** — and the distinction matters. Inside our own storage space the path hierarchy is not an assumption about URLs; it is an invariant this server establishes and maintains, and LDP defines containment in exactly those terms. For anything foreign — WebIDs, issuer URLs, another server's ACL URL — nothing is parsed or assumed; we compare, or we follow a `Link` header. The derivation lives on `StorageSpace`, which the parent design (§9) already names as the owner of URI topology.

## 9. What this buys, defect by defect

| Defect | After |
|---|---|
| 1 — `Slug: .acl` escalation | **unrepresentable** (no path from `Slug` to `AuxUrl`) |
| 3 — unauthorized ancestor mutation | **unrepresentable** (one traversal, one chain) |
| 4 — empty-body PUT reports success while widening access | **unrepresentable** (existence is stored) |
| 5 — orphaned ACL re-materializes containers | **unrepresentable** (no orphan state) |
| 6 — ACL for a nonexistent subject | one check, one place (was: two rules, four sites) |
| 7 — `.acl.acl` chain | **unrepresentable** (`AuxUrl` has no `.aux()`) |
| 2 — narrowing ACL destroyed by delete+recreate | unchanged; inherent, see §11 |

## 10. Migration

Nothing is deployed, so there is no data migration and no compatibility window. The work is a refactor of `src/http.rs`, `src/wac/prp.rs`, `src/space.rs`, `src/container.rs` and `src/resource.rs`, and it is **net-negative in lines**: three lifecycle rules, the `is_acl_path` predicate at 13 sites, the mirror-pair guard and the two empty-body rules all leave.

The existing 171 tests are the safety net for the refactor. Their assertions must survive; only setup changes where a URL shape appears.

## 11. What this does not fix

Defect 2: Bob holds `Write` on `/box/doc`, whose ACL narrows him; he deletes it (the ACL dies with it, by design), recreates it, and the wider inherited policy applies. This is path-anchored policy plus destroy-and-recreate, and no shape here prevents it. It is also, per the reviews, exactly how CSS and ESS behave.

Related and already documented in the current spec: `acl:default acl:Control` on a container is an irrevocable handover of everything below it, not a bounded "manage access here" grant.

## 12. Open questions

1. **Existence witness.** `AuxUrl` could be constructible only from a proof that the subject exists (`fn aux_of(subject: &Existing<ResourceUrl>, kind: AuxKind) -> AuxUrl`), moving defect 6 into the type system too. Cost: an `Existing<T>` token threaded through call sites that currently take a URL. **Recommendation: no** — one check in the typed store wrapper, with a test, is the better trade at this size.
2. **How far `Target` travels.** It could stop at the guard, with handlers taking the unwrapped URL types, or be matched on inside each handler. **Recommendation: into the handlers** — the match is what replaces the scattered predicates, and a handler that receives `AuxUrl` cannot accidentally treat it as a container.
3. **`HEAD` and `Link` on denials.** Obligation 1 in §4 says the header goes on 404s. Does it also go on 401/403? Emitting it discloses only a URL the client could not use anyway, and SolidOS's fallback path can be reached from a denial too. **Recommendation: yes, emit it always.**
4. **The system-graph read projection.** Server-asserted facts are not writable, but they should be *readable* — for clients and for the deferred `/sparql` proxy. The natural shape is a GET-only URL serving `urn:pod:sys:<res>` as Turtle, answering 405 on write. Two things need verifying against the spec text before building it, the same way the ACL-URL risk was verified: whether Solid's description resource is required to be writable (which would make `rel="describedby"` the wrong relation for a read-only server projection); what relation a read-only projection should carry instead; and — a distinction this design has so far treated loosely — whether `rel="describedby"` denotes a per-resource metadata sidecar, the *storage description resource* the Protocol defines at a storage root, or both. Those are not the same thing and must not be conflated before either is built. **Recommendation: named follow-up, not this change** — it has no caller until blobs land.

## 13. Success criteria

- Every defect marked *unrepresentable* in §9 has a corresponding test that no longer compiles, or a construction that no longer exists — not merely a passing negative test.
- The full existing suite passes with assertions unchanged.
- `Link: rel="acl"` is present on 200, 404 and denial responses, with a regression test for the 404 case specifically.
- `is_acl_path`-style suffix predicates appear **zero** times outside `space`.
- The ancestor chain is derived in exactly one function, used by both authorization and materialization.
- The PRP resolves an ACL in one store round trip regardless of depth.
