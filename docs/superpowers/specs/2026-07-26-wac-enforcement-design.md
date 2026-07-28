# WAC Enforcement (Plan 6) — Design

**Date:** 2026-07-26
**Status:** Approved design (pre-implementation) — **partially superseded, see below**
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §8 (Access Control)

> **Superseded by [2026-07-27-acl-auxiliary-model-design.md](2026-07-27-acl-auxiliary-model-design.md).**
> This plan's `.acl` sibling layout and empty-body rules were replaced after seven
> authorization defects, each found inside the fix for the previous one, traced to
> one cause: the ACL was an ordinary resource distinguished by an `ends_with(".acl")`
> predicate, so every call site had to re-derive the rules that made it special. The
> auxiliary-model spec replaces that with a typed auxiliary URL (`AuxUrl`) under a
> reserved `/.aux/` prefix. The specific passages this made stale are marked in place
> below rather than deleted, so the reasoning that led here stays readable as history.

## 1. Context

Plans 1–5 built the LDP surface (CRUD, containers, conneg, ETags) and verify-only
Solid-OIDC/DPoP authentication. The auth middleware **attaches** an `Agent` to each
request; nothing reads it. Every request is therefore fully authorized: the pod is open.

Plan 6 closes that. It implements WAC — the PRP (find the applicable ACL) and the PDP
(decide from it) — and enforces the decision in every LDP handler. It resolves open
risk #2 of the parent spec (is `manas_access_control` usable with our own PRP?) via a
spike, and it decides the question Plan 3 deferred (does `.acl` show up in container
listings?).

## 2. Scope

**In:**

- WAC core without remote fetches: `acl:accessTo`, `acl:default` (inheritance),
  `acl:agent`, `acl:agentClass` (`foaf:Agent`, `acl:AuthenticatedAgent`), modes
  `acl:Read`/`acl:Write`/`acl:Append`/`acl:Control`.
- PRP: ACL resolution with an upward container walk to the root fallback.
- Enforcement in all existing LDP handlers, with WAC-correct status codes.
- `.acl` as an addressable Solid resource, gated by `acl:Control`, excluded from
  containment.
- Root ACL provisioning from a configured owner WebID.
- A `clap` command-line config layer (replacing ad-hoc `std::env::var` reads).

**Out (deliberately):**

- `acl:agentGroup` — resolving a group listing means fetching a (possibly remote)
  document, i.e. new SSRF surface. Deferred until there is a use case.
- `acl:origin` — only meaningful once CORS exists for browser apps; CORS is not yet
  planned.
- ACP. The PDP seam makes it a later plug-in, per parent spec §8.
- `/sparql` read proxy enforcement — the endpoint does not exist yet.
- N3-Patch — no PATCH handler exists yet; see §4.

## 3. Modules & Data Model

New module `src/wac/`, one responsibility per file:

| File | Responsibility | Depends on |
|---|---|---|
| `wac/prp.rs` | ACL resolution: `effective_acl(store, space, path) -> Option<EffectiveAcl>` | store, space, container |
| `wac/pdp.rs` | pure decision: `(ACL triples, agent, target, inherited?) -> AccessModes` | RDF types only |
| `wac/provision.rs` | root ACL bootstrap for the configured owner (idempotent) | store, space |
| `wac/guard.rs` | `authorize(store, space, agent, path, mode) -> Result<(), Response>` | prp + pdp |
| `wac/mod.rs` | re-exports, `Mode` enum, `AccessModes` bitset | — |

The PDP is a pure function with no store access. That makes it exhaustively
table-testable, and it hides the spike outcome (rented `manas_access_control` vs. our
own implementation) behind a single signature — see §7.

> **Superseded.** The paragraph below describes the `<res>.acl` sibling layout,
> distinguished by an `ends_with(".acl")` check at every call site. That is not how
> the system works now: the ACL is `<res>`'s auxiliary of kind `AuxKind::Acl`, a
> distinct typed URL under the reserved `/.aux/` prefix, produced only by
> `ResourceUrl::aux`/`StorageSpace::resolve` — see
> [2026-07-27-acl-auxiliary-model-design.md](2026-07-27-acl-auxiliary-model-design.md).
> Left in place as the record of what was tried first and why it didn't hold up.
>
> **ACL location** (parent spec §5): the ACL for `<res>` lives in graph `<res>.acl`.
> So `/foo` → `/foo.acl`, container `/box/` → `/box/.acl`, root `/` → `/.acl`. It is a
> real Solid resource: addressable via GET/PUT, but access to it is decided by
> `acl:Control` on `<res>`, not by Read/Write on the ACL itself.

**`.acl` is a reserved suffix, pod-wide.** *(Superseded — the ACL is an auxiliary under
`/.aux`, see the blockquote above. The first and third bullets below describe the dead suffix
model; the second one does not and is still current.)* Any request path ending in `.acl` is an
access-control document, decided by `Control` on the path with the suffix stripped. Three
consequences, all deliberate:

- A user cannot create an ordinary resource named `notes.acl` without `acl:Control` on
  `notes` — full `Read`+`Write` on the subtree is not enough. The suffix is server
  namespace, not user namespace.
- **Still current, and independent of the suffix model:** `wac::pdp::decide` deliberately
  does not require an explicit `a acl:Authorization` type triple (real-world ACLs frequently
  omit it, and CSS accepts them without it). Every subject in an ACL graph is therefore a
  candidate authorization. Recorded as ADR-5 in
  [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §16, because
  it is the most permissive choice the PDP makes and it must not be read as part of the
  superseded text around it.
- **Migration note.** Plans 1–5 shipped an open pod with no enforcement. Any resource
  named `*.acl` written during that period becomes live policy the moment this plan lands:
  one containing unrelated data shadows the inherited ACL for its subject and denies
  everyone including the owner; one that happens to carry `acl:` vocabulary grants for
  real. Audit for `*.acl` resources before enabling enforcement on an existing pod.

**PRP walk** (WAC semantics, no blending): check `<res>.acl` for `acl:accessTo`
authorizations first. If that graph does not exist, ascend to the parent container and
evaluate its `.acl` for `acl:default` authorizations; continue up to `/.acl`.
**The first ACL document found wins completely** — ancestor rules are not merged in.
If no ACL document exists anywhere (not even `/.acl`): deny.

**Containment:** `.acl` graphs are never recorded as `ldp:contains` children
(excluded in `add_containment`/`remove_containment`), so they do not appear in
container listings. This settles the question Plan 3 deferred.

**Lifecycle consequence:** because containment no longer ties an ACL to its subject,
deleting a resource must explicitly delete its ACL. Otherwise `DELETE /foo` orphans
`/foo.acl`, a container holding only its own ACL counts as empty and can be deleted out
from under it, and recreating either path resurrects the old authorizations — including
`acl:Control` for an agent who should no longer hold it. CSS and ESS cascade the same
way.

## 4. Enforcement Matrix & Status Codes

One `authorize(...)` call at the top of each `*_impl` in `src/http.rs`, before any
store access:

| Verb | Target | Required modes |
|---|---|---|
| GET `<res>` | `<res>` | `Read` |
| PUT `<res>` (exists) | `<res>` | `Write` |
| PUT `<res>` (new) | `<res>` + parent container | `Write` on `<res>`, `Append` on parent |
| POST `<container>/` | container | `Append` |
| DELETE `<res>` | `<res>` + parent container | `Write` on both |
| GET/PUT/DELETE `<res>.acl` | `<res>` | `Control` |

`Write` subsumes `Append`. Create and delete mutate the parent container's containment
triples, hence the check there too — without it, someone holding `Write` on a child
could manipulate the container's listing.

Three refinements the implementation reviews forced, which the bare matrix above does not
convey:

- **The parent check is a chain, not a single level.** Creating a resource may materialize
  several containers, and each one that is created — plus the first already-existing
  ancestor, which gains a containment triple — needs `Append`. The walk stops there:
  above that level the inserts are no-ops, so demanding rights there would break the
  append-only inbox pattern (an agent with `Append` on `/inbox/` must not need anything
  on `/`). This applies to ACL writes too, since `PUT /a/b/c.acl` can materialize `/a/`
  and `/a/b/`.
- **Deleting a resource that has its own ACL additionally requires `Control` on it**,
  because the delete cascades to that ACL. Consequence, deliberate: an agent holding
  `Write` but not `Control` cannot delete such a resource at all. Without the check, a
  narrowing ACL would be removable by exactly the agent it was written to constrain.
- **Superseded.** The rule below predates the presence marker (`urn:pod:sys:<iri>`,
  see [2026-07-27-acl-auxiliary-model-design.md](2026-07-27-acl-auxiliary-model-design.md)
  §7 "Existence as a stored fact"): existence is no longer inferred from triple count,
  so an empty body creates a real, empty, present resource — including an empty ACL,
  which now correctly means "grant nothing" rather than "absent, fall back to the
  ancestor" — instead of being refused with 400. Left in place as the record of the
  problem the presence marker was built to solve.
  **An empty RDF body is rejected with 400 on non-container paths.** Storing zero triples
  would drop the graph while answering `201 Created` — for an ACL that reads as "lock this
  subtree down" but in fact restores the ancestor's wider `acl:default` rules. Container
  paths keep the empty-body create, where the server supplies the type triples itself.

**An ACL can only be created for a subject that already exists** (`404` otherwise, checked
after authorization so it is never an existence oracle). Without this, an agent holding
`acl:Control` through an ancestor's `acl:default` could write `/box/ghost.acl` for a
`/box/ghost` that never existed, naming only themselves. Nearest-ACL-wins would make that
document govern the path permanently: the owner could not delete it (needs `Control`),
rewrite it (needs `Control`), or create the resource (needs `Write`), and revoking the
delegation would not help. Updating an ACL that already exists stays possible regardless,
so a stale one can always be repaired or removed.

**An ACL cannot have an ACL of its own.** `<res>.acl.acl` is refused outright. Otherwise the
subject-existence rule would be satisfiable one level up — `/box/.acl` does exist — and
since `authorize("/box/.acl.acl")` resolves through `effective_acl("/box/.acl")` to that
very document, its author would own it permanently: unremovable, uncascaded, invisible in
listings, and extensible without limit (`.acl.acl.acl`, …). That would hand an agent
holding no `Write` or `Append` anywhere an unbounded write primitive.

Consequences, accepted:

- Rights can no longer be pre-granted on a path before the resource exists by writing its
  ACL first. Use `acl:default` on an existing ancestor instead.
- `PUT /box/sub/.acl` for a container that does not exist yet is a `404`; it no longer
  materializes `/box/sub/` as a side effect. Create the container first.
- The `404` is a subject-existence oracle for an agent holding `Control` but not `Read`
  under the delegated subtree. Inherent to the rule and strictly weaker than what
  `Control` already permits — that agent can grant itself `Read` and look.

None of this makes `acl:Control` a bounded grant. Granting `acl:default acl:Control` on a
container is an **irrevocable handover of every resource below it**: the delegate can write
a direct ACL naming only themselves, nearest-ACL-wins then displaces the owner's inherited
rules, and revoking the delegation afterwards changes nothing — the owner can no longer
read, rewrite or delete that resource, nor delete the container above it while the resource
is still a member. This is WAC `Control` semantics, and CSS and ESS behave identically.
Delegate `Control` the way you would hand over a key, not the way you would share a folder.

**Status codes:**

- `Agent::Public` denied → **401** with `WWW-Authenticate: DPoP algs="ES256"`.
  Tells the client that authenticating would help.
- Authenticated agent denied → **403**.
- **No 404 leak:** authorization runs before the existence check. Without read access
  the response is 401/403 regardless of whether the resource exists — otherwise the
  status code is an existence oracle for the whole namespace.

The exists-vs-new distinction for PUT requires one store lookup. It runs **after**
`Write` on the target has been granted, so it can never be an oracle: only a caller who
may already write the resource learns whether it exists. The parent's `Append` check
then follows, and only in the create case — demanding it for plain updates would be
stricter than WAC.

**PATCH** is absent from the matrix: N3-Patch does not exist yet. Whoever adds it must
bring a guard; the route-coverage test (§6) fails if they forget.

## 5. Configuration & Bootstrap

**Config layer.** Configuration moves from scattered `std::env::var` calls to a `clap`
derive struct. Each option is a flag with an environment-variable fallback
(`#[arg(long, env = "POD_…")]`) — clap's built-in precedence (flag > env > default),
no hand-written precedence logic:

| Flag | Env fallback | Notes |
|---|---|---|
| `--base-uri` | `POD_BASE_URI` | absolute, trailing slash; validated at startup |
| `--owner-webid` | `POD_OWNER_WEBID` | **required**, see below |
| `--trusted-issuer` | `POD_TRUSTED_ISSUERS` | repeatable flag; replaces the comma-splitting in `auth/config.rs` |
| `--expected-audience` | `POD_EXPECTED_AUDIENCE` | optional |
| `--listen` | `POD_LISTEN` | socket address, default `127.0.0.1:3000` |

Nothing in this config is a secret (base URI, owner WebID, issuer list, audience are
all public information), so the "flags are visible in `ps`" objection does not apply.
Flags buy startup validation, `--help` as documentation, and repeatable list values —
a silently-ignored typo'd env var (`POD_BASE_URl`) becomes an explicit startup error.

**Owner is required.** Without `--owner-webid` the server refuses to start. A pod with
no known owner could only be all-open or all-closed after enforcement is switched on;
both are wrong, so the process exits with a clear message instead.

**Root provisioning.** `provision_root()` additionally creates `/.acl` when that graph
is empty:

```turtle
<#owner> a acl:Authorization ;
    acl:agent <OWNER_WEBID> ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Read, acl:Write, acl:Control .
```

`acl:default` makes this the fallback policy for the entire pod. An existing `/.acl`
is **never** overwritten — otherwise every restart would roll back the owner's shares.

**No owner bypass.** After provisioning, the ACL alone decides; the configured owner
has no path around WAC. Deleting their own Control rule locks them out, exactly as in
CSS/ESS. Two parallel authorization sources would be worse: contradictions between
them stay invisible.

## 6. Testing

1. **PDP table** (pure function, no store): agent type × authorization triples ×
   requested mode. Covers `acl:agent` match, `acl:AuthenticatedAgent` (matches
   `Agent::WebId`, not `Public`), `foaf:Agent` (matches both), `Write` ⊃ `Append`,
   `Control` in isolation, and the negatives: `acl:accessTo` naming a *different*
   resource, `acl:default` without an inheritance context, an authorization with no
   `acl:mode`.
2. **PRP walk** (in-memory store): direct ACL beats ancestor; missing direct ACL
   inherits from the nearest container; multi-level ascent `/a/b/c` → `/.acl`; the
   first ACL found wins *completely* (ancestor rules do not add in); no ACL anywhere →
   deny.
3. **HTTP integration per verb:** for every row of §4, one allowed and one forbidden
   case, plus the 401-vs-403 distinction, plus the no-404-leak property (a forbidden
   request against an existing and a non-existent resource return the same code).
4. **Route-coverage test:** iterate every registered method/path combination and send
   each unauthorized. Anything other than 401/403 fails. This is the countermeasure to
   the known weakness of per-handler guards — a future handler without a guard shows up
   here, not in production.
5. **`.acl` specifics:** `.acl` does not appear in `ldp:contains`; reading/writing an
   ACL requires `Control`, not `Read`/`Write`; DELETE of `/.acl` is permitted
   (WAC-conformant) and locks the pod down afterwards.

## 7. Task Breakdown

| Task | Content |
|---|---|
| 0 | **PDP spike:** call `manas_access_control::WacDecisionPoint` + `manas_space::SolidStorageSpace` for real, with our `StorageSpace`, a hand-built ACL graph and a WebID agent. Record exact API calls as a "Spike Results" section in the plan, as in Plan 4. |
| 1 | `clap` config layer + `--owner-webid`, startup validation |
| 2 | `wac/pdp.rs` — decision function (rented or own, per Task 0) + table tests |
| 3 | `wac/prp.rs` — ACL path derivation, upward walk, `.acl` containment exclusion |
| 4 | Root ACL provisioning |
| 5 | `wac/guard.rs` + wiring into all handlers, status-code semantics |
| 6 | `.acl` as an addressable resource (`Control` gate) + `Link: rel="acl"` header |
| 7 | Route-coverage test + adversarial final review |

**Spike fallback:** if Task 0 shows `manas_space` drags in `manas_repo` or forces its
own URI/slot model onto our `StorageSpace`, the same decision logic goes into
`pdp.rs` as a pure function — WAC core without agentGroup/origin is roughly 150–200
lines. The signature of `pdp.rs` is identical either way, so no other task is affected.
This keeps the blast radius of risk #2 inside a single file.

As in Plans 4 and 5, the branch ends with an **adversarial whole-branch security
review**, because this is a security boundary.

## 8. Success Criteria

- Under the default root ACL (owner-only), an agent with no credentials gets 401 on
  every route and an authenticated non-owner gets 403. Granting `foaf:Agent` read
  access in an ACL makes exactly that subtree publicly readable, and nothing else.
- The owner can read/write every resource in the pod and can grant another WebID
  read access to a subtree by writing one `.acl` — verified end-to-end over HTTP.
- The first ACL found in the walk is authoritative; ancestor authorizations do not
  leak in.
- `.acl` resources are invisible in container listings and reachable only with
  `acl:Control`.
- The route-coverage test passes, i.e. no handler reaches the store unauthorized.
- Existing tests (100 at the end of Plan 5) still pass, unchanged in meaning: the
  auth boundary from Plans 4/5 is not weakened.

## 9. Deferred / Follow-ups

- `acl:agentGroup`, `acl:origin` (see §2).
- Carried over from Plan 5: shared/Redis DPoP replay store, per-request-client
  performance, `safe_fetch.rs` `.expect()` → `?`, negative-cache TTL-recovery test.
- Carried over from Plan 2: RFC 7232 conformance gaps (`If-Match: *` on an existing
  resource, `If-None-Match: *` on GET → 304, comma-separated ETag lists).
- Carried over from Plan 3: POST to a non-container should arguably be 405 with an
  `Allow` header rather than 409; empty-body PUT creates a dangling containment link
  (symptom of the "empty graph = absent" model, needs a `urn:pod:sys:` presence
  marker, due with blobs).
