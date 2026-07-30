# Shape Validation on Write — SHACL First — Design

**Date:** 2026-07-30
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §11, §12
**Origin:** the root spec lists per-container SHACL/ShEx as a deferred optional feature with a
seam and no machinery. This is the machinery, for SHACL only.

## 1. What is missing today

Nothing in `src/` mentions SHACL, ShEx or `ldp:constrainedBy`. A write is checked for media
type, for the reserved namespace, for client-set containment, for named graphs a serialization
cannot carry, and for conditional-request preconditions — and then it is stored, whatever it
says. Authoring integrity currently lives in the pipelines that write into this pod, which
means every writer re-implements it and a writer that forgets simply succeeds.

## 2. What is rented and what is built

`rudof_lib` 0.3.7 is the SHACL engine. Verified before this spec, not assumed:

- Builds on the pinned toolchain (Rust 1.95.0), `--no-default-features`, ~27 s cold.
- Its RDF layer (`rudof_rdf` 0.3.7) sits on **oxigraph 0.5.9** and `oxrdf` 0.3.3 — the same
  versions this crate already depends on. Terms cross the boundary as themselves; there is no
  serialize-and-reparse bridge and no second `oxrdf` in the tree.
- `InputSpec::Str(String)` accepts an in-memory document, so nothing touches the filesystem.
- `ValidationReport` exposes `conforms()`, `results()`, `get_count_of(&Severity)` and
  `to_rdf(writer)` — the report is RDF without us formatting it.

Two version traps, both avoided by depending on `rudof_lib` alone:

- `shacl_validation` 0.2.12 hangs off `rudof_rdf` 0.2.20. Adding it *beside* `rudof_lib` puts
  two `rudof_rdf` versions in the tree. `rudof_lib` already re-exports what is needed.
- `rudof` 0.1.12 is an abandoned earlier line, and upstream warns that 0.2.19–0.3.0 shipped
  broken. 0.3.7 is the floor.

The default feature is `sparql`, which pulls `sparql_service`. It is off: validation runs in
the engine's native mode against triples we hand it, not against a remote endpoint.

Built here: the binding lookup, the choice of data graph, the placement in the write path, the
severity-to-status mapping, and the read view.

## 3. The binding

### 3.1 `ldp:constrainedBy`, on the container, in its own graph

A container declares a constraint the way it declares anything else — as a triple in its own
graph, written through the ordinary LDP write path:

```turtle
</notes/> ldp:constrainedBy </shapes/note> .
```

Nothing about this is server-minted. A client with `acl:Write` on the container sets it, any
client with `acl:Read` sees it, and if this pod never validated anything the statement would
still be true and still be actionable by clients. That is the property that makes
`constrainedBy` the right binding and Shape Trees the wrong one for a first cut: the Shape
Trees association (`Link: rel="…shapetrees#managedBy"`) is server-emitted, so it does not
exist at all until a server implements it.

Both readings of LDP §4.2.1.6 are served by one mechanism. Fedora uses `constrainedBy` on a
failure response to point at the document explaining the refusal; CSS's design proposal uses
it to name the shape to validate against. Here the shape *is* the document that explains the
refusal, so a `422` carries `Link: <shape>; rel="…ldp#constrainedBy"` and satisfies both.

### 3.2 The binding does not inherit

A binding on `/notes/` constrains writes to `/notes/foo`. It does **not** constrain
`/notes/2026/foo` — that resource's container is `/notes/2026/`, which carries its own binding
or none.

This is the LDP reading, and it is also the cheap one: the lookup is a single graph read at a
known IRI, not a walk. Nearest-binding-wins would need `ResourceUrl::ancestors` on the hot
write path and would let a constraint set far away silently govern a subtree the author of the
write never looked at. Inheritance remains addable later as an explicit opt-in predicate
without invalidating a single binding written under this rule; the reverse is not true.

### 3.3 The shape language is read, not guessed

The constraint document is an ordinary resource. Which language it is in comes from the media
type this pod already stores for it (`resource::stored_media_type`), never from sniffing:

| stored media type | treated as |
|---|---|
| `text/turtle`, `application/ld+json`, and the rest of `Format` | SHACL |
| anything else | **unsupported** — see §7 |

ShEx would slot in here as two more rows (`text/shex`, `application/shex+json`), which is why
the dispatch is a table rather than an `if`. It is not in this design; see §8.

### 3.4 The data graph is the written document, and nothing else

SHACL cannot express which data graph it is validating. `sh:targetClass`, `sh:targetNode` and
friends select *focus nodes within* a data graph; choosing the graph is the caller's job and
lies outside SHACL's model. `sh:shapesGraph` points the other way — from data to shapes — and
is declared inside the data, which makes it a per-write client choice rather than a container
policy. The choice is therefore the server's, and this design makes it once: **the data graph
is the body being written, alone.**

Precisely: the body's **default graph**. SHACL Core validates one graph, and a dataset-valued
body (§6.2 of the datasets design) has several. Unioning them would validate a document the
author never wrote and would make a shape's meaning depend on how many graphs a client
happened to send; the default graph is the one every serialization can carry and the one
`Dataset::default_graph_only` already names.

That is the common denominator of the shape languages. A ShEx schema checks a node against a
shape through a ShapeMap and has no notion of a container's aggregate state at all, so a
document-scoped binding is the only one both languages can mean the same thing by. Widening
the scope is a SHACL-only idea and would have to be a term ShEx ignores.

It also means this design mints **no vocabulary**. `ldp:constrainedBy` says which shape,
`sh:severity` says how hard (§4), and there is nothing left to express. The provisional
namespace of `docs/uri-space.md` — the one that owes a permanent identifier before 1.0 — keeps
its single existing term instead of gaining three more ahead of the move.

Container-scoped validation is deferred, not rejected; §8 states what it would buy, what it
would cost, and why adding it later invalidates no binding written under this rule.

## 4. Severity is the enforcement dial

SHACL already carries the reject-or-warn distinction per constraint, and rudof models it
(`Severity::{Trace, Debug, Info, Warning, Violation, Generic}`, defaulting to `Violation`).
The server needs no mode of its own:

- any result at `sh:Violation` → the write is refused
- otherwise → the write proceeds, and the findings are readable (§6)

A shapes graph whose every constraint declares `sh:Warning` therefore never refuses anything.
The mode is a property of the shape, chosen by whoever authored it, rather than a second
switch on the container that could disagree with it. `sh:deactivated` turns a shape off
entirely and needs no handling here — the engine honours it.

No other implementation does this. RDF4J's `ShaclSail` and GraphDB (which uses it) abort the
transaction on any violation and hand the report back inside the exception; Fuseki validates
only on demand and never on write. Severity-driven enforcement has no interop precedent, which
is one more reason the whole feature is off unless a container opts in.

## 5. Write path

### 5.1 Placement

In both `put_impl` and `post_impl`, validation goes **after** `check_conditionals` and
**before** the ancestor-materializing walk.

After the conditionals, because a request that fails `If-Match` is answered `412` and never
needed validating.

Before the walk, because that is what makes a refusal free. `put_impl` already states the
principle for the checks above it:

> Deliberately after the body checks: a 415 or an unparseable body must not leave containers
> behind for a resource that was never created.

A `422` is a body check in exactly that sense. What a refused write would leave behind is not
a container, though — because the binding does not inherit (§3.2), the container that refuses
is the target's direct parent, which had to exist in order to hold the binding, so there were
no missing ancestors to materialize. It is the **containment triple**: the same traversal adds
`<container> ldp:contains <target>` for a target that does not exist yet. Placed after the
walk, every refused write would leave that triple pointing at a resource that was never
created — and "just try the write and read the report", the reason this design has no dry-run
endpoint, would quietly mutate the pod.

### 5.2 There is no dry-run

A refused write stores nothing and returns the report in its `422` body. One request already
answers "would this be accepted?", so a second endpoint answering the same question in advance
would be a second code path with no additional answer. The case it would appear to cover — a
write that succeeds despite findings — is a shape that chose `sh:Warning`, and a client that
wants refusal there should say `sh:Violation`.

### 5.3 What is not validated

- **Auxiliary writes.** An ACL is server-understood data with its own rules; a user shape has
  no business refusing one, and a shape that could would be a way to lock an ACL.
- **Blob bodies.** There are no triples to validate. A blob write into a constrained container
  therefore always succeeds, which is a hole only for constraints about the container — and
  those are out of scope (§3.4, §8).

## 6. Read path — `GET /path?validate`

The report is not stored. It is computed when asked for:

```
GET /notes/2026-07-30?validate
→ 200, text/turtle, a sh:ValidationReport over what is stored right now
```

Three consequences, all of them the point:

- **Nothing can go stale.** Edit a shape and every subsequent report reflects it. No
  invalidation, no crawl, no background job.
- **Nothing accumulates.** There is no location for reports to pile up in, so no changelog can
  form by accident.
- **The URI is stable and means one thing** — the current conformance of this resource.

`?validate` rather than an auxiliary URL, for a reason `docs/uri-space.md` states normatively:
`/.aux/…` is *"auxiliary resources — your data, with a meaning the server has to understand"*,
and a validation report is not the client's data but a server assertion about it. That
document's own section on server-asserted facts anticipates this shape exactly — *"A read-only
projection of these facts may be offered later; it will never be writable."*

The query string also keeps the URL space untouched. Axum's `Path` extractor sees the path
only, so `/notes/foo?validate` resolves to the same `Target` as `/notes/foo` and inherits its
authorization with no decision to make: no `AuxKind`, no arm in `required_mode_for_aux`, no
`PUT`/`DELETE` refusals for a resource that is not writable. This does not weaken the
reserved-prefix rule from the ACL design — that rule is about paths that must be recognised
everywhere a path is constructed, and a query parameter constructs no path.

The known cost: a misspelled `?validat` is ignored and the resource is returned instead. The
report is self-identifying (`a sh:ValidationReport`), but the status code is `200` either way.
Rejecting unknown query parameters outright would break every client that appends a
cache-buster, so this is accepted rather than solved.

Serialization goes through the existing `negotiate` path, honouring `Accept` across the RDF
formats this pod writes, defaulting to Turtle. Adding a second format selector is forbidden by
`docs/constraints.md` ("There is one content-negotiation path, one parser and one ETag") and
is not needed.

`?validate` on a resource whose container has no binding is a `404`: there is no report where
there is no constraint.

## 7. Status codes

| situation | answer |
|---|---|
| any `sh:Violation` result | `422`, body is the report, `Link: <shape>; rel="…ldp#constrainedBy"` |
| findings below `sh:Violation` only | the write's ordinary `201`/`204`, plus `Link: </path?validate>; rel="describedby"` |
| no findings | the write's ordinary response, no extra header |
| binding names a resource that does not exist, is a blob of an unsupported type, or does not parse as SHACL | `409`, naming the unusable constraint document |
| `?validate` on an unconstrained or absent resource | `404` |

The `409` fails closed. A container whose constraint document is broken refuses every write
until it is fixed — see §10.

## 8. What this design does not do

- **ShEx.** ShExC and ShExJ work in rudof and would be blob-stored constraint documents;
  ShExR does not — `ShExFormat::RDFFormat(_) => todo!()` in both `shex_ast` and
  `shex_validation` 0.3.7, which is a panic rather than an error and must therefore never be
  reachable from a request. ShEx also needs a ShapeMap to say which node is checked against
  which shape, where SHACL brings its own targets; that is a vocabulary decision this design
  does not make.
- **Shape Trees.** The specification repository has not moved since 2021, though its
  vocabulary was given a `w3id.org` redirect on 2026-07-29. It is a layer *above* shape
  languages — hierarchy and containment expectations, delegating node-level checking to
  ShEx/SHACL via `st:shape` and `st:usesLanguage` — and it would reuse the validation function
  written here with a different binding lookup. Keeping lookup and validation separate
  functions is what keeps that a second lookup rather than a rewrite.
- **Container-scoped validation** — a data graph wider than the written document. Two variants
  were weighed. The cheap one adds the container's own graph, where `ldp:contains` is already
  materialized, and buys cardinality and membership typing for one store read. The expensive
  one adds every member's content and buys constraints across member bodies for one read per
  member per write.

  Both are deferred for the same reason: the constraints they buy are exactly the ones whose
  failure modes are worst. The cheap variant must validate against the container's graph
  **projected** to include the containment triple the write would add — validation runs before
  the write (§5.1), so against the stored graph a rule of "at most five members" counts the
  pre-write state and admits the sixth, silently. The expensive variant additionally lets a
  write to X be refused because an unreadable Y is malformed, and lets a container that already
  violates its shape refuse the very write that would repair it.

  Adding either later invalidates no binding written under §3.4: absence of a scope statement
  means document scope, so a scope vocabulary is purely additive. Should one be minted, it
  belongs in the `https://quadpod.toph.so/ns#` namespace and deliberately **not** under
  `urn:quadpod:` — that prefix is reserved (`dataset::RESERVED_PREFIX`) and
  `Dataset::uses_reserved_namespace` answers `400` for any client body mentioning it, so a
  term there would be a term no client could write.
- **Ad-hoc validation** (`?validate=<shapeIri>`). It would need the shape IRI restricted to
  pod-local resources resolved through the store — never dereferenced, or it is an SSRF vector
  the `auth::safe_fetch` policy exists to prevent — and `acl:Read` on the shape.

## 9. Testing

Properties, each of which must be shown to fail before the code that makes it hold:

1. A body violating a bound shape is refused `422`, and a subsequent `GET` shows the *old*
   representation — the refusal stored nothing.
2. A refused `PUT` leaves the container's `ldp:contains` unchanged. This is the §5.1 ordering,
   and it fails loudly if validation moves after the walk. Asserting "no ancestor container
   was created" instead would hold no matter where validation sits — see §5.1 for why.
3. A shape whose constraints are all `sh:Warning` admits the write and the response carries
   the `describedby` link.
4. A shape whose focus nodes exist only in *other* members of the container finds nothing —
   the data graph is the written document alone (§3.4), and a test that passes here only
   because the container happened to be empty is not this test.
5. A blob write into a constrained container succeeds and is not validated.
6. An ACL write is never validated, even under a shape that would refuse it.
7. `GET /x?validate` reflects a shape edited after `/x` was written, with no write to `/x`.
8. `GET /x?validate` requires `acl:Read` on `/x` and is `404` where no binding exists.
9. A binding on `/notes/` does not constrain `/notes/2026/foo` (§3.2).
10. A constraint document that does not parse yields `409`, not a silently unvalidated write.

## 10. Documented limits

- **A broken constraint document bricks its container** until the binding is fixed or removed.
  Deliberate: failing open would disable a policy silently, which is the failure mode a
  validation feature exists to prevent.
- **Validation cost is paid per write.** It is bounded by the size of the written body; no
  store read is added to the write path.
- **Nothing constrains a container's shape as a whole** — not its member count, not its member
  types. `ldp:contains` is never in a data graph here (§3.4, §8).
- **Named graphs in a body are never validated** (§3.4). A dataset-valued resource is checked
  on its default graph only, so a shape cannot reach what a client put in a named graph.
- **`?validate` is reachable by any agent with `acl:Read`**, and repeated calls are repeated
  validation work. There is no rate limit in this pod.
- **The report describes now, not then.** A report fetched after a later write describes the
  later state. Preserving write-time state is versioning, which this pod does not do.
- **Severity-driven enforcement is unique to this pod** (§4). A client that assumes
  SHACL-conformant servers always refuse violations will be surprised by a warn-only shape.
- **Whoever can write a container can constrain it.** Under the single-user v1 topology this
  is the owner; it is an access-control property to revisit before multi-tenant.

## 11. Deltas against documents already in force

- `docs/uri-space.md` — one new section for the `?validate` view, the first query parameter
  this pod gives meaning to. *The vocabulary this pod mints* is **unchanged**: this design adds
  no term, so the provisional-IRI warning still covers exactly one.
- `docs/superpowers/specs/2026-07-24-sparql-solid-pod-design.md` §11/§12 — SHACL moves from
  "deferred, seam only" to implemented-and-optional. §7's rented-crate table gains
  `rudof_lib`, replacing the `rudof (shacl_validation)` row with the crate that actually
  resolves.
- `docs/constraints.md` — two candidate rules, each to be demonstrated red before it is added:
  the binding is read in exactly one module, and the query string is read in exactly one
  module. The second is what keeps `?validate` from becoming a general pattern of hiding
  behaviour in query parameters.
- `Cargo.toml` — `rudof_lib = { version = "0.3.7", default-features = false }`.
