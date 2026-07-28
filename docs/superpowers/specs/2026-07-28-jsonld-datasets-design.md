# Dataset-Valued Resources — Full JSON-LD Support — Design

**Date:** 2026-07-28
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md)
**Origin:** `docs/conformance-findings.md` — defect D3, deliberately deferred out of Plan 8
Task 4 because it is a data-model decision, not a forgotten line.

## 1. What is wrong today

`rdf::parse` iterates the parser's quads and copies three of their four fields:

```rust
out.push(Triple { subject: q.subject, predicate: q.predicate, object: q.object });
```

`q.graph_name` is dropped. A client that `PUT`s a JSON-LD document containing named graphs
gets `201`, and on `GET` the graph names are gone — the dataset comes back flattened into its
merged triples. No error, no warning. `content-negotiation-named-graphs:16` fails on exactly
this.

The silent part is the harm. Supporting a format means supporting what the format can
express; JSON-LD can express an RDF dataset, so a pod that accepts `application/ld+json`
and keeps only one graph of it is not supporting JSON-LD.

## 2. What the specifications actually require

Neither RDF nor Solid forces the answer, so this design picks one of several defensible
readings and says which.

**RDF declines to answer.** The W3C Note *On Semantics of RDF Datasets* catalogues eight
competing semantics for named graphs and records that no consensus exists; a graph name is
not even required to denote the graph it names. On the question this design must settle —
what it means for two *different* datasets to contain a graph of the same name — the Note is
silent. It treats semantics within a single dataset only.

**The Graph Store Protocol models a document as one graph.** `PUT` is `DROP; INSERT`,
`POST` is `INSERT`. It has no notion of a multi-graph payload at all: one request, one graph
IRI.

**Quad stores merge, structurally.** A store is a single global quad space keyed by graph
name, so loading two documents that name the same graph merges them. Not a decision — the
absence of a document boundary at which anything could stay separate.

**Trellis LDP** — the closest prior art, an LDP server on a triplestore — stores each
resource as exactly one named graph and puts bookkeeping in derived graph names
(`<iri>?ext=acl`, `<iri>?ext=audit`). Same family as this pod's system graph, but derived by
string construction, and Trellis issue #559 is that derivation breaking against remote
SPARQL endpoints. Dataset-valued resources do not exist there either.

**Solid leans dataset.** The Protocol's own N3 Patch text says to *"start from the RDF
dataset in the target document"*. The document model of the specification is a dataset, not
a graph.

### 2.1 Decision: graph names are document-local

Two documents that both name `urn:example:g1` have two independent graphs that happen to
share a name — exactly as two documents containing triples about the same subject are still
two documents.

The alternative (store-global names) is not merely risky, it contradicts what a resource
means in HTTP. A `PUT` on one resource would delete triples belonging to another resource's
content, and WAC — which authorizes resources — could never see it. A `GET` would return data
the resource's own writer never wrote.

Sharing data across documents is expressed in Solid by a resource and a reference, not by a
shared graph name.

## 3. Storage model

A resource is an **RDF dataset**. Three kinds of store graph exist:

| Store graph | Holds |
|---|---|
| `<resource-iri>` | the resource's default graph — unchanged from today |
| `urn:pod:subgraph:<hex>` | one named graph of one resource |
| `urn:pod:sys:<resource-iri>` | bookkeeping: presence marker and registry |

`<hex>` is SHA-256 over the resource IRI, a separator byte, and the graph name (for a blank
node graph name, its canonical label — see §4). **The resource IRI is part of the key**, which
is what makes the same graph name in two resources land in two different shelves.

The registry lives beside the presence marker that already exists:

```
<resource>              sys:present    true .
<resource>              sys:hasSubgraph <urn:pod:subgraph:8f2a…> .
<urn:pod:subgraph:8f2a…> sys:graphName  <urn:example:g1> .      # IRI-named
<urn:pod:subgraph:1c07…> sys:graphBlank true .                  # was a blank node
```

Three invariants carry the design:

1. **The key is server-minted only**, from values the server already holds. A document
   containing a graph literally named `urn:pod:subgraph:8f2a…` or `urn:pod:sys:…` lands in
   its own hashed shelf like any other — the reserved namespace is unreachable rather than
   merely undocumented.
2. **Content and bookkeeping appear and disappear in the same update.** No subgraph without a
   registry entry, no registry entry without a subgraph. The same invariant the presence
   marker already has.
3. **The system graph is not addressable.** No URL path resolves to it. This is the existing
   argument for why `urn:pod:sys:` is safe today; the registry inherits it.

### 3.1 Naming

`urn:pod:` is not a registered URN namespace (RFC 8141 requires registration). This is a
**deliberate deviation**: these IRIs never leave the server, are never resolved, and never
appear in a response, and readability while debugging a bookkeeping structure is worth more
than formal correctness nobody checks. `tag:` URIs (RFC 4151) are the named escape hatch if
these IRIs ever become externally visible — that is the condition under which this decision
should be revisited.

`subgraph` rather than `graph` because everything in a quad store is a graph; the word has to
carry "part of something else" or it distinguishes nothing.

### 3.2 What may be a dataset

Ordinary resources only. Containers and auxiliaries reject named graphs with `400`:

- A **container**'s graph carries server-managed containment triples that are merged on write.
  Named subgraphs beside them would be a second mechanism in the same place.
- An **auxiliary**'s rules would be invisible to WAC if they sat in a subgraph — an ACL that
  is silently ineffective, the most dangerous failure this codebase has.

### 3.3 The internal vocabulary is documented, not folklore

`sys:present`, `sys:hasSubgraph`, `sys:graphName`, `sys:graphBlank` are a named, stable part
of the design. No HTTP client ever needs them. They matter only to a future SPARQL endpoint.

## 4. Blank nodes

A blank node has no stable identity across two parses: `_:b0` today may be `_:b7` tomorrow and
mean the same thing. A hash over that label would look deterministic and be arbitrary.

**RDFC-1.0** (RDF Dataset Canonicalization, W3C Rec 2024) solves it, and it is already
available: oxigraph 0.5.9 depends on `oxrdf` with the `rdfc-10` feature and re-exports it, so
`Dataset::canonicalize` and `canonicalize_blank_nodes` need no new dependency and no feature
change.

Every document is canonicalized on write. Blank nodes — in triples and as graph names — then
carry structure-derived, reproducible labels. A blank-node-named graph is keyed from its
canonical label and marked `sys:graphBlank`; on read it becomes a *fresh* blank node again.

The returned dataset is therefore isomorphic to the one written: the blank node stays a blank
node, and may be labelled differently, which it is entitled to be. Skolemization — replacing
it with a minted IRI — was rejected: it would return the client a document in which a blank
node became an IRI, a visible rewrite of their data.

**This also closes a known crack.** `rdf.rs` says of `etag`:

> assumes stable blank-node labeling from the store (fine for ground graphs; revisit when
> bnode-bearing graphs arrive)

Canonicalization is that revisit. After it, the same statement produces the same ETag.

Two constraints follow, and both belong in the implementation:

- Canonical labels depend on the shape of the **whole** dataset; one added quad can relabel
  many. Harmless here because `PUT` replaces the whole resource — it would matter the day
  `PATCH` arrives.
- RDFC-1.0 has exponential worst-case complexity ("dataset poisoning" in its own spec text).
  A **cap of 1000 blank nodes per document**, checked *before* canonicalization, rejects with
  `400`. Checked after, the guard would be worthless — the expensive computation has already
  run. Every writer is authenticated and WAC-authorized, but that is not a promise of good
  behaviour.

## 5. Write path

`PUT`, and identically for the child a `POST` creates:

1. Parse the body into a **dataset**, base IRI = the resource IRI.
2. **Blank-node cap** — over the limit, `400`, before canonicalization.
3. **Canonicalize** (RDFC-1.0, SHA-256).
4. **Split.** Default-graph quads to `<resource-iri>`; each named graph to its keyed shelf plus
   a registry entry.
5. **Target checks.** Named graphs on a container or auxiliary: `400`. Client-set containment
   in a container body: `409`, as today.
6. **One SPARQL update.** Drop the resource graph, drop every *currently registered* subgraph,
   drop the registry, insert the new content, insert registry and presence marker.

Step 6's drop must run **through the registry, not through the new keys**. A graph that is
absent from the new document has no new key by which it could be found; that is precisely
where orphans are created.

### 5.1 Atomicity is a precondition, not an assumption

The whole write path rests on `store.update` executing a `;`-separated sequence atomically.
Today's code already relies on this (`DROP; INSERT; INSERT`) without ever saying so. **This
must be measured before implementation.** If it does not hold, the write path changes — the
ordering must then be one whose interruption leaves a harmless state — and that is a design
change, not a test failure.

## 6. Read path

1. Presence marker, else `404` as today.
2. Collect the resource graph, the registry, and each shelf; rebuild the dataset with the
   **original** names. Graphs marked blank get a fresh blank node.
3. Serialize according to `Accept`.

### 6.1 Negotiation moves after the read

`get_impl` currently picks a format before it knows what the resource holds. Whether
`text/turtle` is answerable depends on whether the resource has named graphs, so the read must
come first.

| `Accept` | no named graphs | with named graphs |
|---|---|---|
| `text/turtle`, `application/n-triples` | as today | `406` |
| `application/ld+json`, `application/trig`, `application/n-quads` | as today | full |
| `*/*` | Turtle, as today | JSON-LD |

`application/trig` and `application/n-quads` are new, for reading and writing. Without them
JSON-LD would be the only lossless text form.

`*/*` falling to JSON-LD matters: answering `406` to a client that said "anything" would be
absurd, and Turtle cannot represent the resource. oxigraph refuses this outright —
`serialize_quad` on a graph format returns *"Only quads in the default graph can be serialized
to a RDF graph format"* — so the choice is explicit or a runtime error.

Merging all graphs into the Turtle response was rejected on semantics, not convenience: a
statement in a named graph is not asserted in the default graph, so merging would manufacture
assertions the document never made. Returning only the default graph was rejected as the same
silent truncation this work exists to remove.

**Measured, not assumed:** CSS answers `Accept: text/turtle` on such a resource with
`Content-Type: text/turtle` and a body in **TriG** syntax (`<g1> { … }`), which no strict
Turtle parser accepts. It is not a model to copy.

## 7. Delete

Resource graph, every registered shelf, and the system graph — in one update, for the reason
in §5.1.

## 8. What does not change

WAC, containment, the ancestor walk, the §3.1 slash-pair rule, aux links, `If-Match` /
`If-None-Match`. All of it is keyed on the resource IRI, which is untouched.

Subgraphs need no authorization of their own: no URL resolves to one and no client can name
one, so their content is covered by the resource's ACL by construction. There is no second
rule here that could drift from the first.

Resources without named graphs are stored exactly as they are today. **No migration**, and
none would be needed anyway — the pod is pre-1.0 with an in-memory store and no deployed data.

## 9. Documented limits

**An empty named graph does not survive.** `{"@id": "urn:g", "@graph": []}` produces no quads,
so a quad-based parser never sees it. It will not come back. This is a real gap against byte
fidelity and is not closable within this model.

**A graph named like the resource itself** is an ordinary named graph and gets its own shelf.
It round-trips unchanged. Folding it into the resource's default graph would be a document
rewrite — moving statements out of a named graph changes what the document asserts — and it is
the obvious accidental implementation, so it is pinned by a test.

**Byte fidelity was never offered.** Formatting, `@context`, key order and blank node labels
are not preserved; they are not today either. What this design adds to the preserved set is
which graph a statement belongs to.

## 10. Testing

**Canonicalization is an isomorphism oracle** and the round-trip assertion is exact, not
approximate:

```rust
canonicalize(sent) == canonicalize(read_back)
```

One assertion covering graph names, blank nodes, and the assignment of triples to graphs.

- **Unit (`rdf.rs`)** — parsing preserves graph names; canonicalization is reproducible; key
  derivation is injective in both directions that matter (same name in two resources → two
  keys; two names in one resource → two keys); the ETag changes when *only* a graph name
  changes, which is the `304` trap.
- **Storage** — the invariant of §3 checked after every write and delete, including the case
  most easily forgotten: a `PUT` replacing a document with one containing *fewer* graphs must
  leave no orphaned shelves.
- **HTTP** — JSON-LD with a named graph in and out; `406` on Turtle; `*/*` yields JSON-LD;
  TriG and N-Quads both directions; `400` for container, auxiliary and the blank-node cap; the
  graph named like its resource.
- **Conformance** — `content-negotiation-named-graphs:16` passes, and the full run does not
  regress against the counts recorded in `docs/conformance-findings.md`.

Two rules carried over from earlier rounds, both of which found real defects every time:

**Every test must fail against a mutant.** The "graph named like the resource" test is
worthless if it stays green when someone folds the two together. The aux-URL work produced
exactly this failure: a test asking for the property in a form where it held trivially.

**A documented limit gets a test too.** The empty named graph is pinned so that it stays a
decision rather than resurfacing as a surprising bug.

## 11. Follow-ups this design deliberately does not do

- **Non-RDF resources (blobs).** 540 of the 615 conformance failures. Its own plan.
- **RDFa extraction**, which only becomes honest once blobs exist: the HTML would be the
  content, with extracted triples in a derived graph marked as derived — never the source.
  oxigraph has no RDFa parser; this needs one.
- **A public SPARQL endpoint.** The registry is visible as-is for now; rewriting constant graph
  names is straightforward later (`?g sys:graphName <name>`), rewriting variable ones is a
  query rewriter. Neither is this design's problem, and authorizing WAC over arbitrary SPARQL
  patterns is the harder half of that endpoint anyway.
- **Stored representation variants** (several files negotiated per resource). Explicitly not
  wanted: representations here are generated from one state, so they cannot drift. Two
  documents are two resources, linked by `rel="alternate"`.
- **`application/rdf+xml`**, which oxigraph already supports and this pod does not offer. A
  line in the format table, on the day that table is touched for another reason.
- **Replacing the presence marker with `CREATE GRAPH`.** An empty named graph is
  indistinguishable from an absent one when querying, which is why the marker exists; whether
  oxigraph tracks empty named graphs well enough to carry that meaning is unmeasured. Moot
  here, because the registry has to record more than existence anyway.
