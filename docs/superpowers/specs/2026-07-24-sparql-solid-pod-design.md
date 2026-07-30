# SPARQL-Authoritative Solid Pod — Design

**Date:** 2026-07-24
**Status:** Approved design (pre-implementation)
**Author:** Christopher Mühl (with Claude)

## 1. Context & Motivation

Today: a file-based Solid pod (`pod.toph.so`) is the source of truth, and data is
**synced into Oxigraph** so SPARQL queries can run over it. This means two copies of
every triple, sync machinery to maintain, and staleness between them.

The pain is not an acute bug — it is architectural: keeping two stores in sync offends
correctness and adds moving parts. The goal is to **collapse to a single store where a
SPARQL/quad store is authoritative**, blobs live in files, and the Solid/LDP surface is a
live projection over that store — no sync, no second copy.

A previous attempt (Oxigraph-backed storage) was abandoned; this design is the considered
second pass, built from existing, non-rotting components plus a thin custom core.

## 2. Goals

- **One authoritative store.** A SPARQL 1.1 quad store holds all RDF; no mirror, no sync.
- **Blobs in files**, not in the triple store.
- **Real Solid pod**: LDP + WAC + Solid-OIDC, usable by third-party Solid apps.
- **Not Node/CSS**: lighter runtime, and not bound to CSS's RDF-1.1 parser stack.
- **Reuse spec-stable components; own only the glue.** Rent the frozen-spec parts (auth
  formats, RDF syntaxes, access-control decision logic, SHACL); build the part nobody
  ships (LDP ↔ quad-store mapping).
- **Pluggable seams** for store backend, blob backend, and optional features.
- **Config-driven URI topology** (single/multi user/pod) without a rewrite.

## 3. Non-Goals (v1)

- **Not** an Identity Provider. Auth is **verify-only** against an external Solid-OIDC IdP.
- **No RDF-star / RDF 1.2 on the wire** — Solid is RDF-1.1-anchored (see §5).
- **No SPARQL UPDATE** write path (writes go through LDP, which already enforces WAC+SHACL).
- **No Solid Notifications Protocol.**
- **No multi-tenant registry / provisioning** — the *seam* exists (§9), the machinery is deferred.
- **No in-place migration** of the existing pod; v1 runs in parallel, data migration later.
- **No TLS in the server** — terminate at a reverse proxy (§10).

## 4. Key Decisions & Rationale

| Decision | Rationale |
|---|---|
| **Rust** | Not perf-bound (personal scale) but *plumbing*-bound; Rust has the best non-JS RDF tooling and Oxigraph is a Rust project. Live ecosystem, static binary → fits Fleet/Nomad. |
| **Build thin server, don't fork one** | Forking any server (CSS, Melvin's, DreamLab, jeswr's) means inheriting conventions/off-spec choices we'd fight. jeswr's `solid-server-rs` is explicitly "not a foundation." Manas-the-server is **dormant** (last commit 2024-07). |
| **Reuse Manas *leaf crates*, not its `Repo` trait** | The leaf crates are published, downloaded in the wild, and encode frozen specs → low rot. The `manas_repo` storage trait is heavy typestate + an 80-file reference backend → high effort, high coupling. Deep-reuse rejected; shallow-reuse chosen. |
| **Oxigraph default, behind a `SparqlStore` trait** | Target SPARQL 1.1 Protocol only (no vendor extensions) → Fuseki/GraphDB swappable. HTTP endpoint (not embedded) keeps multi-writer (Windmill pipelines) and avoids the single-writer RocksDB constraint. |
| **Strict RDF 1.1 everywhere; provenance is app data** | Solid mandates Turtle + JSON-LD (RDF 1.1). Backend-pluggability and RDF-star are mutually exclusive (not all stores support RDF-star). Provenance/PROV-O is **not** a server concern — pipelines write it as ordinary triples. |
| **WAC only (v1), ACP-ready by architecture** | Solid CG consensus recommends WAC; community adoption favors it. The standalone `acp` crate makes ACP a near-zero-cost future plug behind the same PDP seam. |
| **Verify-only auth, external IdP** | Running an IdP is a whole subsystem. Verify-only is far less surface; WebID profile docs can still live in the pod. |
| **URI-template config for topology** | One declarative knob (§9) expresses single/multi user/pod and subdomain-vs-path, instead of ad-hoc flags. Realizes the `StorageSpace` abstraction from day one. |
| **Reverse-proxy TLS; server is public-URL-aware via config** | Removes cert/ACME/wildcard burden from the server. In Solid, URL = identity and DPoP binds to URL, so the server must mint from configured public base-URI, never the socket. |
| **Fresh build, not a fork of jeswr's `solid-server-rs`** | The architecture is convergent (SPARQL-authoritative + `object_store` blobs + verify-only DPoP + axum LDP) — validating, not a reason to fork. But jeswr's is an explicit throwaway research spike (WAC absent, in-memory doubles, "do not deploy"), so there is nothing production-shaped to adopt. We build fresh — same idea, new mind — reusing Manas leaf crates for the stubbed parts (esp. WAC), with jeswr as an optional sounding board. |

## 5. Data Model

**Core mapping: resource URL = named graph name, 1:1.**
`PUT <base>/foo` (Content-Type `text/turtle`) parses the body and stores the triples in
named graph `<base>/foo`. This 1:1 mapping is what makes WAC and the SPARQL proxy tractable
(a resource is a graph is a WAC unit).

**URL is identity; the extension is just a name, not a format selector.**
- `<base>/foo`, `<base>/foo.ttl`, `<base>/foo.jsonld` are **three different resources /
  three different graphs**. The suffix is not stripped.
- **Format on write** = `Content-Type` header; **format on read** = `Accept` (conneg).
  A `.ttl` URL can legally be written as JSON-LD and read back as Turtle.
- **Recommendation baked into docs/tooling: extensionless RDF resource URLs.** Serialization
  does not belong in the path.

**RDF resources are stored as parsed triples, not bytes.** Round-trip is triple-preserving,
not byte-preserving (prefixes/comments/whitespace are not retained). Blobs are byte-preserving.

**RDF vs blob routing is by `Content-Type`, not extension:**
- `text/turtle`, `application/ld+json`, … → parse into a named graph (RDF source).
- anything else (`image/png`, `application/pdf`, …) → blob in `BlobStore`, plus a system
  metadata graph describing it (§7).

**Containers vs resources: trailing slash.** `<base>/foo/` = `ldp:Container`,
`<base>/foo` = resource. The apex (`pod.toph.so` ≡ `pod.toph.so/`) is **always** the root
storage container (`ldp:Container` + `pim:Storage`); HTTP normalizes the empty path to `/`.

**Per-resource graph layout (Option A — separated graphs):**

| Graph | Holds | Visibility |
|---|---|---|
| `<res>` | User data triples (for a container: user triples **+** server-managed `ldp:contains`) | Served as the resource representation (conneg) |
| `<res>.acl` | The ACL for `<res>` — a **first-class Solid resource** with its own URL, discoverable via `Link: rel="acl"`, GET/PUT-able, itself WAC-controlled (`acl:Control`) | User-addressable resource |
| `urn:quadpod:sys:<res>` | Server-asserted bookkeeping: for blobs the `object_store` key, size, hash, content-type; ETag; timestamps | **Server-only**, never conneg'd, never in user namespace |

Rationale for the split: ACL is *not* internal metadata — it is a real resource a user can
query — so it gets its own URL/graph. Purely-internal, server-asserted triples must **not**
be written into the user's namespace, so they live in a reserved `urn:` system graph.

**Root anchors WAC.** The root container must have `/.acl`; it is the mandatory fallback at
which the PRP container-walk terminates. Root ACL is the first thing provisioning creates.

## 6. Architecture

Request flows top→down; three front doors share one authorization core.

```
                 HTTP request (plain HTTP, behind reverse proxy)
                              │
                    ┌─────────▼─────────┐
                    │ axum HTTP server  │  BUILD (thin skeleton)
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │ Auth: verify      │  GLUE: dpop · solid_oidc_types · webid
                    │ DPoP / Solid-OIDC │        (htu reconstructed from configured base-URI)
                    └─────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────────┐
        │ (front door 1)      │ (2, optional)            │ (3, optional)
 ┌──────▼───────┐   ┌─────────▼──────────┐      ┌────────▼────────┐
 │ LDP layer    │   │ /sparql read proxy │      │ HTML view shell │
 │ CRUD, conneg,│   │ (WAC-projected)    │      │ (Accept: html)  │
 │ ETags, N3-   │   └─────────┬──────────┘      └────────┬────────┘
 │ patch        │             │                          │
 └──────┬───────┘             │                    external SolidOS /
        │  GLUE: rdf_dynsyn    │                    Data-Kitchen bundle
        │                      │
        └──────────┬───────────┘
                   │
        ┌──────────▼────────────┐
        │ WAC authorization core│   ← shared by all doors
        │  PRP: fetch ACL graph │   BUILD (SPARQL query + container walk)
        │  PDP: decide          │   BUILD (pure fn over ACL triples — see §16, ADR-1)
        └──────────┬────────────┘
                   │
        ┌──────────▼──────────┐
        │ SHACL validate      │   GLUE: rudof  (OPTIONAL, per-container, off by default)
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │ Storage router      │   BUILD (RDF vs blob)
        └────┬───────────┬────┘
      ┌──────▼─────┐ ┌───▼───────┐
      │ SparqlStore│ │ BlobStore │   BUILD traits
      │ → Oxigraph │ │ → object_ │   GLUE: oxigraph (default) · object_store (local/S3/…)
      │  (default) │ │   store   │
      └────────────┘ └───────────┘
```

## 7. Components: Build vs Reuse

**Build ourselves (the spine — the reason the project exists):**
- axum skeleton + config wiring
- **LDP semantics** — verb handlers (GET/HEAD/PUT/POST/DELETE/PATCH), container membership,
  conneg wiring, ETags/conditional requests, **N3-Patch** application
- **SPARQL storage mapping** — resource ↔ named graph, container ↔ `ldp:contains`, LDP ops →
  atomic SPARQL 1.1 Update; the `SparqlStore` trait + Oxigraph impl
- **Blob handling** — `BlobStore` trait, `object_store` impl, RDF-vs-blob router, system
  metadata graph (`urn:quadpod:sys:<res>`)
- **PRP** — fetch a resource's `.acl` graph + walk the container hierarchy to the root
  fallback (both are SPARQL queries)
- **StorageSpace + URI-template matcher** (§9), threaded through everything (no hardcoded root/base-URI/owner)
- **Public-URL derivation** for all minted URLs and DPoP `htu` (from config, not socket)
- Optional glue: per-container SHACL binding, `/sparql` read proxy, HTML-shell handler

**Reuse (published, spec-stable, low-rot):**

| Crate | Provides | Integration |
|---|---|---|
| `dpop`, `solid_oidc_types`, `webid` | token/identity verification | auth middleware; reconstruct `htu` from config |
| `rdf_dynsyn` | Turtle/JSON-LD/… parse + serialize | conneg on read & write |
| ~~`manas_access_control` (`WacDecisionPoint`) + `manas_space`~~ | ~~WAC decision engine~~ | **Not used.** The Plan 6 spike reversed this; the PDP is ours. See §16, ADR-1 |
| `acp` (later) | ACP decision | same `PolicyDecisionPoint` seam, near-zero cost |
| `object_store` | local/S3/GCS/… blob backends | `BlobStore` impl |
| `rudof_lib` 0.3.7 | SHACL/ShEx validation | optional per-container 422 |
| `oxigraph` | the store | behind `SparqlStore`, over SPARQL 1.1 Protocol |

**Mental model:** we build *how Solid maps onto a quad store*; we rent every *frozen spec*
(crypto/auth formats, RDF syntaxes, WAC/ACP decision math, SHACL).

## 8. Access Control (WAC)

- **PDP consumes policies as input, not storage.** `wac::pdp::decide` is a pure function of
  ours: ACL triples plus the request context in, access modes out. No I/O, no ancestry walking,
  no `async`. The original plan was to rent `manas_access_control`'s `WacDecisionPoint`; that
  was reversed by the Plan 6 spike for a decisive reason — `resolve_grants` never takes an ACL
  graph, it takes a slot chain and walks the ancestry *itself*, which inverts the PRP below.
  See §16, ADR-1.
- **PRP is ours.** Because resource = named graph, "fetch the ACL for `<res>`, else walk up
  containers to the root `.acl`" is a **SPARQL query** against the same store. WAC over named
  graphs stops being a slogan.
- **One core, many doors.** The function "which graphs may agent X read/write?" is factored
  once and reused by the LDP layer and the SPARQL proxy. Nobody reaches the raw store.
- **ACP-ready:** the `PolicyDecisionPoint` abstraction lets the standalone `acp` engine slot in
  later without touching callers.

## 9. URI Topology — `StorageSpace` + Template

A single config template expresses the whole topology:

- `https://pod.toph.so/` (no vars) → single-user / single-pod (**v1**)
- `https://{user}.toph.so/` → multi-user, one pod per subdomain
- `https://toph.so/{user}/{pod}/` → path-based multi-user / multi-pod

Matching an incoming URL against the template yields the `StorageSpace` (base-URI + owner
WebID + root ACL) and any `{user}`/`{pod}` bindings. v1 runs one space (a zero-variable
template); the matcher is still built so the seam exists.

**Caveats (explicit, so they are conscious choices):**

1. **RFC 6570 is expansion, not matching.** Reverse-matching a concrete URL to variables is
   not defined by 6570 and is ambiguous in general. We support a **constrained, deterministic
   subset**: literal segments + simple `{var}` host/path segments, no operators. Documented as
   "6570-*inspired*," not "RFC 6570 support."
2. **Subdomain vs path is also an isolation choice.** `{user}.host` ⇒ wildcard TLS+DNS (handled
   by the proxy) and **origin-per-pod** (stronger Solid isolation, `acl:origin`, cleaner app
   trust — Solid-preferred). `host/{user}` ⇒ one origin, simpler infra, **weaker** isolation.
3. **Template routes; it does not own.** Multi-user additionally needs a registry
   (`{user}` → owner WebID → root ACL) + provisioning (bootstrap root container + root `.acl`
   per space). **Deferred with multi-tenant.** v1: one owner in config.

## 10. Deployment

- **TLS terminates at a reverse proxy** (Caddy/Traefik/nginx); the server speaks **plain HTTP**.
  Wildcard certs (for subdomain topologies) are the proxy's job (declarative ACME).
- **Server is public-URL-aware via config.** All minted URLs (graph names, `Location`,
  `Link: rel="acl"`, containment, WebID) and DPoP `htu` verification derive from the configured
  base-URI/template — **never** from the request socket. `X-Forwarded-*` headers are not trusted
  for identity (spoofable); config is authoritative. (Multi-tenant subdomain mode will need the
  forwarded Host for space-routing — v1 n/a.)
- **Bind to localhost / private interface.** Plain HTTP must never be exposed directly; only the
  proxy reaches it. Tune proxy buffering for large blob transfers.

## 11. Optional Modules (seams present in v1, bodies deferred)

- **`/sparql` read proxy** — auth + WAC-projected, read-only. Enforcement = scope the query to
  the agent's readable graph set (default graph = union of readable graphs). Writes stay on LDP.
  Semantic consequence (accepted): the endpoint is a **policy-projected** view, not a raw store
  view; results are per-agent. Scale escape hatch (deferred): push WAC into the query as a
  security-filter join if graph counts explode.
- **HTML view** — on `Accept: text/html`, return a small configurable HTML shell that boots an
  external Solid viewer (SolidOS / Data Kitchen) pointed at the resource; the viewer bundle is
  static (proxy/CDN), not in the binary. Off by default (Solid mandates only Turtle + JSON-LD).
- **Per-container SHACL/ShEx** — attach a shape to specific containers via `ldp:constrainedBy`;
  violating writes get 422. Off unless a container binds a shape (mandatory validation would
  break generic Solid-app interop). Backed by `rudof`.

## 12. v1 Scope

**In:** core LDP CRUD, containers, conneg (Turtle/JSON-LD), ETags/conditional requests,
N3-Patch, WAC (PRP+PDP), verify-only Solid-OIDC/DPoP auth, blob storage via `object_store`,
`SparqlStore` over Oxigraph, `StorageSpace`/template matcher (single zero-var space),
public-URL-aware minting, CORS for browser Solid apps, SHACL validation.

**Deferred (seams only):** `/sparql` read proxy, HTML view, ACP, multi-tenant
registry/provisioning, Notifications, SPARQL UPDATE, data migration from the existing pod.

## 13. Success Criteria

- Passes the **Solid Protocol** and **WAC** conformance test suites for the implemented surface.
- A third-party Solid app can authenticate (external IdP), read/write RDF resources and blobs,
  and be correctly allowed/denied by WAC.
- Every triple lives in exactly **one** authoritative store; there is no sync process.
- Swapping Oxigraph for another SPARQL-1.1 store requires only config, no code change.

## 14. Risks & Spikes (validate before/early in implementation)

1. **Manas dormancy / compile.** Do `manas_access_control`, `manas_space`, `rdf_dynsyn`, `dpop`,
   `solid_oidc_types`, `webid`, `acp` build on current stable Rust? Confirm versions + licenses
   (MIT/Apache). If badly bit-rotted, fork the specific crate (small blast radius) or fall back
   to writing that piece.

   **Spike Results (2026-07-24):**
   All seven crates compile cleanly on Rust 1.95.0 (cargo). No bit-rot detected.

   | Crate | Version | License |
   |---|---|---|
   | `rdf_dynsyn` | 0.3.1 | MIT OR Apache-2.0 |
   | `dpop` | 0.1.1 | MIT OR Apache-2.0 |
   | `solid_oidc_types` | 0.1.0 | MIT OR Apache-2.0 |
   | `webid` | 0.1.0 | MIT OR Apache-2.0 |
   | `acp` | 0.1.0 | MIT OR Apache-2.0 |
   | `manas_access_control` | 0.1.0 | MIT OR Apache-2.0 |
   | `manas_space` | 0.1.0 | MIT OR Apache-2.0 |

   **Implication:** Risk de-risked. Proceed with shallow reuse of these leaf crates as planned. No forking required.
2. **WAC engine usability.** Confirm `WacDecisionPoint` + `manas_space::SolidStorageSpace` are
   usable with our own PRP (we supply the ACL chain), without dragging in `manas_repo`.

   **Outcome: answered no, and the design changed.** `resolve_grants` walks the ancestry
   itself, so it cannot be fed an ACL chain — it inverts our PRP. See §16, ADR-1.
3. **Atomicity.** A PUT touches the data graph + container `ldp:contains` + system graph; verify
   these compose into **one atomic** SPARQL 1.1 Update on Oxigraph (and on Fuseki).

   **Outcome: holds for Oxigraph, and is an implementor's obligation rather than a SPARQL
   guarantee.** See §16, ADR-2.
4. **Constrained-template matcher.** Confirm the chosen subset reverse-matches deterministically
   for the intended topologies.

## 15. Open Questions

None material. Minor items intentionally deferred: exact `rudof` API surface, the specific
external IdP to authenticate against (verify-only works against any Solid-OIDC issuer),
provisioning UX for multi-tenant.

## 16. What changed, and why

Decisions that were made after this document was written, that reverse or qualify something
it says, and that had no home of their own. They are recorded here rather than in a separate
decision directory because this is the document they correct — a second home would give the
contradiction a third place to live. Checkable rules go to `docs/constraints.md`; the
reasoning stays here.

### ADR-1 — Build our own WAC PDP; do not rent `manas_access_control`

**Decision.** `wac::pdp::decide` is a pure function of ours, taking ACL triples plus the
request context. `manas_access_control` and `manas_space` are not dependencies.

**Alternatives considered** (Plan 6 Task 0 spike, four pre-declared criteria; verdict in
`docs/superpowers/plans/2026-07-26-wac-enforcement.md` under "Spike Results"):

- **Rent `manas_access_control`.** Rejected on the decisive criterion:
  `WacDecisionPoint::resolve_grants` never takes an ACL graph. It takes a `SlotAcrChain` — a
  `BoxStream` of manas `SolidResourceSlot`s — and walks the ancestry itself, which inverts the
  PRP design and forces `decide()` to be `async` and fallible. Three of the four criteria
  favoured renting: it compiles, `manas_repo` is behind an off-by-default feature, and the
  oxigraph→sophia conversion is 27 lines. The fourth decided it.
- Recorded at the time as additional cost: manas requires an explicit `a acl:Authorization`
  (which ADR-5 deliberately does not), +80 crates including a parallel EOL http 0.2 / hyper
  0.14 / tower 0.4 stack, a `sophia_api` 0.8-vs-0.10 trap, and a namespace bug (`acl:agent`
  vs `acp:agent`).

**What would reopen it.** manas exposing a decision entry point that takes an ACL graph rather
than a slot chain; or ACP arriving, since the standalone `acp` crate was the original argument
for keeping the seam.

### ADR-2 — `SparqlStore` is dyn-dispatched, and `;`-sequence atomicity is an implementor's obligation

**Decision.** `AppState` holds `Arc<dyn SparqlStore>`, object-safe via `async_trait`. Every
write path assumes a `;`-separated update runs in one transaction.

**Alternatives considered** (Plan 1 issue I3, escalated to and decided by the user;
`2026-07-28-jsonld-datasets-design.md` §5.2 for the atomicity half):

- **Generic `AppState<S>`** with static dispatch. Rejected: RPITIT is not object-safe, and
  pinning `OxigraphStore` into `AppState` conflicts with §13's success criterion that the
  backend be config-swappable.
- **"SPARQL guarantees the sequence is atomic."** False, and worth recording as false. What
  holds is that `BoundPreparedSparqlUpdate::execute` evaluates every operation before calling
  `transaction.commit()`, so a runtime failure part-way through commits nothing — measured in
  both review rounds of the dataset spec. That is a property of `OxigraphStore`.

**What would reopen it.** A second `SparqlStore` implementor. `docs/constraints.md` carries
the tripwire, and `store.rs` now states the obligation on the trait.

### ADR-3 — Accept RS256 DPoP proofs; the ES256-only pin was stricter than RFC 9449

**Decision.** Proofs signed RS256 are verified through a pod-owned path dispatched on the
header `alg`, with an RFC 7638 RSA thumbprint for `cnf.jkt`. ES256 still goes to
`dpop-verifier` untouched; `none` and HS\* stay rejected; both paths meet at `VerifiedDpop`,
so `htu`, freshness, `cnf.jkt` and jti-last stay single-copy.

**Alternatives considered** (Plan 8 Task 2; `.superpowers/sdd/rs256-support.md`):

- **Keep ES256-only and skip the conformance run.** Rejected by the user: RFC 9449 permits any
  asymmetric alg except `none`/symmetric, so the pin was stricter than the spec — and the
  conformance harness signs RS256 unconditionally (`JwsUtils.java`, the ES256 line commented
  out, no config switch), so the run aborted before any test executed.
- **Configure `dpop-verifier` for RS256.** Impossible at 4.4.0, verified in source: a fixed
  match on `(alg, jwk)` and a closed untagged `Jwk` enum with only EC-P-256 and OKP-Ed25519,
  so an RSA JWK fails to deserialize before `alg` is read. No RSA thumbprint either.

**The non-obvious part.** `cnf.jkt` used `thumbprint_ec_p256`, which is EC-specific. Widening
the algorithms without widening the thumbprint would have silently broken proof-of-possession
for RSA keys — worse than rejecting them.

**What would reopen it.** `dpop-verifier` gaining RSA support (delete our path), or a decision
to advertise a narrower `algs` list in the `WWW-Authenticate` challenge, which
`wac::guard::DPOP_CHALLENGE` would then have to track.

### ADR-5 — An ACL rule does not need an explicit `a acl:Authorization`

**Decision.** `wac::pdp::decide` treats every subject in an ACL graph as a candidate
authorization. The type triple is not required.

**Alternatives considered** (Plan 6 Task 0, which flagged it for the Task 7 review as "MORE
permissive than a real WAC engine — sanity-check it"; the review upheld it):

- **Require the type triple**, as `manas_access_control` does. Rejected because real-world
  ACLs frequently omit it and CSS accepts them without it: requiring it would reject policy
  documents that every other Solid client produces, and a rejected ACL is an ACL that silently
  does not apply.

**Why it is recorded here.** It is the single most permissive choice the PDP makes, and in the
WAC spec it sits inside a section whose surrounding model — the `<res>.acl` sibling suffix —
has since been superseded. It reads as if it were part of the dead text. It is not.

**What would reopen it.** ACP, or a conformance scenario that requires the type triple. The
current run does not exercise one: roughly 370 WAC rows are unmeasured behind the `text/plain`
gap.
