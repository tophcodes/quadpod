# Dataset-Valued Resources — Full JSON-LD Support — Design

**Date:** 2026-07-28
**Status:** Proposed (pre-implementation), revision 2
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md)
**Origin:** `docs/conformance-findings.md` — defect D3, deliberately deferred out of Plan 8
Task 4 because it is a data-model decision, not a forgotten line.
**Reviews:** `.superpowers/sdd/spec-review-dev.md` (implementability),
`.superpowers/sdd/spec-review-domain.md` (Solid/RDF domain, adversarial). Revision 2 exists
because those reviews falsified four load-bearing claims of revision 1; §4 is a different
mechanism now, not a rewording. What changed and why is recorded in §12.

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

**The Graph Store Protocol is silent, not supporting.** GSP defines `PUT` as
`DROP; INSERT` and `POST` as `INSERT` against one graph IRI per request. It says nothing
about payloads that themselves contain quads, and nothing about whether a request-URL graph
IRI overrides payload graph names. Revision 1 cited it as evidence for a document-is-a-graph
model; it is evidence for neither position.

**Quad stores merge, structurally.** A store is a single global quad space keyed by graph
name, so loading two documents that name the same graph merges them. Not a decision — the
absence of a document boundary at which anything could stay separate.

**No shipping implementation merges graph names across documents.** Surveyed: CSS (both
backends), NSS, Inrupt ESS via `solid-client-js`, Trellis, Fedora 6, Marmotta, Virtuoso LDP,
Carbon LDP. Every one of them scopes graph names to the document or drops them. What differs
is only *how*: flatten silently (NSS on conversion, Fedora), lie about the content type (CSS
file backend), or refuse the write (CSS SPARQL backend, Virtuoso, Trellis). §2.1 is the
industry-wide answer, not a bold call.

**Trellis is the closest prior art, and it projects rather than embeds.** A resource there
really is multi-graph in a triplestore: `TriplestoreResourceService` writes `GRAPH <iri>`,
`GRAPH <iri?ext=acl>`, `GRAPH <iri?ext=audit>` and a server-wide `trellis:PreferServerManaged`
graph holding LDP type, `dc:modified` and containment for every resource. But the extra
graphs are exposed as **separate URLs** (`?ext=` is a live query parameter), never as quads
in a body — its `IOService` is structurally triple-only (`Stream<Triple>`), which is what
issue **#592** is open about. The relevant lesson is that one, not issue #559, which revision
1 cited as a derivation breaking against remote endpoints: #559 was a user pointing Trellis
at Blazegraph in *triples* mode, closed the next day as misconfiguration.

**CSS's SPARQL backend refuses outright**, which matters because it is this pod's closest
architectural twin — Solid server, triplestore behind it. `SparqlDataAccessor` (v7.2.0):

```ts
if (triples.some((triple): boolean => !def.equals(triple.graph))) {
  throw new NotImplementedHttpError('Only triples in the default graph are supported.');
}
```

Its metadata graph is `namedNode(\`meta:${name.value}\`)` — a scheme-prefix mangle, and direct
prior art for §3's shelf pattern.

**Solid leans dataset.** The Protocol's own N3 Patch text says to *"start from the RDF
dataset in the target document"*. The document model of the specification is a dataset, not
a graph.

**`solid/specification#804` is compatible, and was misread in revision 1.** jeswr's
Access-Controlled Query draft (2026-07-13) mandates flattening inner named graphs — but
explicitly only in the *query projection*: *"Flattening affects only what a SPARQL query can
see. The stored representation is untouched: a GET on the resource returns the original
document, inner graphs and all."* That is what this design does. Its rejection of
"namespaced first-class graphs" rests on that route needing "name-rewriting or provenance
table"; for a quadstore-backed pod the table falls out of the write path anyway (§5), which
is the one substantive difference of opinion and is recorded in the issue thread.

**Hashing graph names has no prior art** in W3C, LDP or Solid discussion. The nearest system
is the Trusty URIs module RA (nanopublications), which hashes a dataset per document and
states *"Blank nodes are not supported and have to be skolemized"* — the same escape hatch §4
takes. The W3C RDF WG's 2011 `RDF-Datasets-Proposal` lists under Cons: *"There are use cases
that would benefit from 'nesting' … these are not well handled."* This design is in new
territory, which is a stronger claim than revision 1 made.

### 2.1 Decision: graph names are document-local

Two documents that both name `urn:example:g1` have two independent graphs that happen to
share a name — exactly as two documents containing triples about the same subject are still
two documents.

In the order that matters:

1. **The parse base IRI is the resource IRI, so naming another resource's graph costs eleven
   characters.** A document `PUT` to `/attacker/doc` containing
   `{"@graph":[{"@id":"../victim","@graph":[…]}]}` yields the graph name
   `https://pod.toph.so/victim` (verified). Under store-global names that write would land in
   `/victim`'s graph with no ACL check anywhere in the path.
2. **WAC authorizes URLs.** A store-global graph has no URL, so every store-global write
   would be, by construction, an unauthorized one.
3. **HTTP resource semantics.** `PUT /a` must not change `GET /b`.

The counter-position deserves stating: store-global names are the natural reading of a quad
store, they are what an unmodified SPARQL Update endpoint gives you, there are real use cases
(many documents contributing to one shared index graph), and RDF licenses it — *"the graph
name is not required to denote the graph. It is merely syntactically paired with the graph."*
It loses on point 1 alone.

Sharing data across documents is expressed in Solid by a resource and a reference, not by a
shared graph name.

## 3. Storage model

A resource is an **RDF dataset**. Three kinds of store graph exist:

| Store graph | Holds |
|---|---|
| `<resource-iri>` | the resource's default graph — unchanged from today |
| `urn:pod:subgraph:<hex>` | one named graph of one resource |
| `urn:pod:sys:<resource-iri>` | bookkeeping: presence marker and registry |

The registry lives beside the presence marker that already exists. `sys:` expands to
`urn:pod:sys#`, matching `resource::SYS_PRESENT` (`urn:pod:sys#present`) — note the `#`,
which is what keeps predicate IRIs from colliding syntactically with the system-*graph*
naming scheme `urn:pod:sys:<resource-iri>`:

```
<resource>              sys:present     true .
<resource>              sys:hasSubgraph <urn:pod:subgraph:8f2a…> .
<urn:pod:subgraph:8f2a…> sys:graphName  <urn:example:g1> .      # IRI-named
<urn:pod:subgraph:1c07…> sys:graphSkolem <urn:pod:bnode:…> .    # was a blank node (§4)
```

### 3.1 Key derivation

`<hex>` is the full 64-character lowercase hex SHA-256 of

```
resource-iri  ‖  0x00  ‖  graph-name
```

both parts as UTF-8. **The separator is `0x00` because RFC 3987 excludes control characters
from IRIs**, so it cannot occur in either part and the pair cannot be re-read as a different
pair. Revision 1 said "a separator byte" without fixing it; with a printable separator two
distinct (resource, graph name) pairs can collide, which is a cross-resource read/write. The
domain review could not construct a working exploit against `/`-as-separator only because
Protocol §3.1's slash-pair rule happens to forbid the resources it would need — an accidental
defence, and not one to rely on.

**The resource IRI is part of the key**, which is what makes the same graph name in two
resources land in two different shelves.

### 3.2 Invariants

1. **The key is server-minted only**, from values the server already holds. No client can
   name the shelf space.
2. **The reserved namespace is refused at the door.** Any IRI in `urn:pod:` appearing in a
   request body — as subject, predicate, object or graph name — is rejected with `400`. This
   is a single check in one place, and it removes a family of questions rather than answering
   them one at a time (§4 needs it for de-skolemization; §3 would otherwise need to argue
   that a graph named `urn:pod:subgraph:…` is harmless).
3. **Content and bookkeeping appear and disappear in the same update.** No subgraph without a
   registry entry, no registry entry without a subgraph.
4. **An orphaned shelf is a correctness hazard, not litter.** Because the key is a pure
   function of (resource IRI, graph name), it is stable across delete and recreate. A shelf
   the registry does not list is content that a future write to the same pair would
   `INSERT DATA` *into*, and the resource would then return triples nobody wrote. §5 and §7
   drop both by registry and by new key for this reason; that redundancy is what makes the
   invariant self-healing rather than merely asserted, and it must not be optimised away.
5. **The system graph is not addressable.** No URL path resolves to it, which is the existing
   argument for why `urn:pod:sys:` is safe today. The registry inherits it.

### 3.3 Naming

`urn:pod:` is not a registered URN namespace (RFC 8141 requires registration). This is a
**deliberate deviation**: these IRIs never leave the server, are never resolved, and never
appear in a response, and readability while debugging a bookkeeping structure is worth more
than formal correctness nobody checks. `tag:` URIs (RFC 4151) are the named escape hatch if
these IRIs ever become externally visible — that is the condition under which this decision
should be revisited.

`subgraph` rather than `graph` because everything in a quad store is a graph.

### 3.4 What may be a dataset

Ordinary resources only. Containers and auxiliaries reject named graphs with `400`:

- A **container**'s graph carries server-managed containment triples that are merged on write.
  Named subgraphs beside them would be a second mechanism in the same place.
- An **auxiliary**'s rules would be invisible to WAC if they sat in a subgraph — an ACL that
  is silently ineffective, the most dangerous failure this codebase has. Verified: `wac::prp`
  reads ACL content through `resource::get_rdf` on the auxiliary's graph IRI, which returns
  the default graph only.

### 3.5 The internal vocabulary is documented, not folklore

`sys:present`, `sys:hasSubgraph`, `sys:graphName`, `sys:graphSkolem` are a named, stable part
of the design under the `urn:pod:sys#` prefix. No HTTP client ever needs them.

### 3.6 The sealed-trait invariant needs replacing

`space::GraphName` is sealed, and its comment says why: *"every implementor's `graph_iri` is
interpolated verbatim into SPARQL, so only types minted through `StorageSpace::resolve` … may
implement it."* `<shelf> sys:graphName <user-supplied-iri>` is the first place a
client-supplied IRI is interpolated into SPARQL outside that discipline.

The domain review probed it and could not break it — `oxjsonld` drops node objects whose
`@id` is not a valid IRI rather than passing them through, and the Turtle/TriG/N-Quads
parsers reject them outright. It is hardening, not a live hole. Every graph name is
nonetheless re-validated through `NamedNode::new` immediately before interpolation, so the
property the sealed trait guaranteed is restored explicitly rather than inherited by luck.

## 4. Blank nodes: internal skolemization

**Revision 1 got this wrong in three ways at once, and the fix is one mechanism.**

Every blank node in a `PUT` body — in triples and as a graph name — is replaced on write by a
server-minted IRI in the reserved namespace, `urn:pod:bnode:<uuid>`. Each occurrence of the
same blank node within one document gets the same skolem IRI. Nothing else in the store is a
blank node. On read, every `urn:pod:bnode:` IRI is turned back into a blank node, one fresh
blank node per distinct skolem IRI, before serialization.

RDF 1.1 §3.5 blesses skolemization explicitly. The returned dataset is isomorphic to the one
written: same structure, same co-reference, labels not preserved — which they need not be,
and are not today either.

What this buys, in the order the reviews falsified revision 1:

- **The ETag becomes meaningful.** SPARQL Update inserts blank nodes in `INSERT DATA` as
  *fresh* blank nodes by definition — measured: three identical `PUT`s produce three different
  stored labels. Canonicalizing on write, as revision 1 proposed, could not survive that; the
  store discards the labels. With no blank nodes in the store, what is stored is stable, and
  `etag()` over it means something.
- **Co-reference survives.** A blank node can be a graph name *and* a term — routine in
  JSON-LD, and the deployed Verifiable Credentials `proof` pattern, which is the case raised
  in `solid/specification#291`: *"the server may not modify those graph names, nor may it move
  those `proof` triples into the default graph."* Revision 1's "graphs marked blank get a
  fresh blank node on read" broke exactly that: the shelf came back under one node while
  `<top> :points _:x` came back under another. One skolem IRI used everywhere makes the
  problem disappear rather than requiring bookkeeping to repair it.
- **The `INSERT DATA` block problem disappears.** `INSERT DATA { GRAPH <a> { _:b0 … } };
  INSERT DATA { GRAPH <b> { _:b0 … } }` is a hard error in oxigraph — *"The blank node _:b0
  cannot be shared by multiple blocks"*. With no blank nodes reaching SPARQL, no write can
  ever hit it.
- **`GRAPH _:g { … }` is not expressible in SPARQL at all** (verified: syntax error). A
  blank-node-named graph cannot be stored as one, so skolemization is not merely convenient
  here, it is the only representation available.
- **The denial-of-service vanishes rather than being mitigated.** Revision 1 defended
  RDFC-1.0's exponential worst case with a cap of 1000 blank nodes. The W3C's own poison
  test, `rdfc10/test074`, is **10 blank nodes in 3400 bytes**; measured against oxrdf 0.3.3:
  8 nodes = 2.45 s, 10 nodes = **375 s**, 12 = unfinished after 60 s. RDFC-1.0 says to bound
  *calls to Hash N-Degree Quads*, not input size, and oxrdf implements no bound at all — it
  does not meet that MUST, so the defence could not be delegated to it either. Skolemization
  needs no canonicalization, so none of this applies.

**What is given up.** Two `PUT`s of the same document produce different skolem IRIs, hence
different keys for blank-node-named graphs and a different ETag. Revision 1 promised
cross-write determinism; this does not. It is invisible from outside — within a single stored
state everything is stable, which is what `If-None-Match` needs — and it applies only to
blank-node-named graphs. IRI-named graphs keep stable keys.

**What it costs.** Invariant 3.2.2: a document may not contain `urn:pod:` IRIs. Without that,
a client could write a real IRI in the skolem namespace and get a blank node back — a visible
rewrite of their data. The check is one predicate over the parsed quads and it is cheaper than
the alternative (recording per-resource which IRIs are skolems).

**A note on `PATCH`.** The day N3 Patch arrives, skolemization needs a rule for what a patch
means against a skolemized store. Not in scope here, but it is the place this decision will
next be felt.

## 5. Write path

`PUT`, and identically for the child a `POST` creates. **Both handlers need the same
sequence**; `put_impl` and `post_impl` run their analogous checks in different relative orders
today, so this is two call sites, not one.

1. Parse the body into a **dataset**, base IRI = the resource IRI.
2. **Cheap rejections, immediately** — before anything expensive, because a request that
   cannot succeed must not pay for work first:
   - any `urn:pod:` IRI anywhere in the dataset → `400` (§3.2.2);
   - named graphs on a container or auxiliary → `400` (§3.4);
   - client-set containment in a container body → `409`, as today. **This check must run over
     the whole dataset, not the default graph only** — `container::body_sets_containment`
     takes `&[Triple]`; fed only the default graph, the `409` is bypassed by putting
     `ldp:contains` in a named graph. The `400` above makes it moot for containers, which is
     why the order is stated rather than left to chance.
3. **Skolemize** every blank node (§4).
4. **Split.** Default-graph quads to `<resource-iri>`; each named graph to its keyed shelf
   (§3.1) plus a registry entry.
5. **Read the registry** for the resource's current shelf keys.
6. **One update**, `;`-chained:
   - `DROP SILENT GRAPH <k>` for every key from step 5 — *literal* IRIs, one statement each;
   - `DROP SILENT GRAPH <k>` for every key from step 4 (invariant 3.2.4);
   - drop the resource graph and the system graph;
   - one `INSERT DATA` carrying the default-graph block and one `GRAPH` block per shelf;
   - the registry and presence marker.

### 5.1 Why step 5 is a separate read

`DROP GRAPH` takes a literal IRI; SPARQL has no syntax for dropping the graph a pattern binds
to. The variable-bound alternative, `DELETE { GRAPH ?g { ?s ?p ?o } } WHERE { … }`, was built
and run against a live store during review: it empties the graphs but **does not remove them**
— `store.named_graphs()` still lists them afterwards. Only a literal `DROP GRAPH` frees the
entity. Emptied-but-present graphs would accumulate for the life of every resource that is
ever rewritten, which for the in-memory backend this pod actually runs is unbounded memory.

This is the same distinction the presence marker exists for — an RDF store cannot tell an
empty named graph from an absent one — arriving one level down, where no marker catches it.

The cost is a read-then-write window: a concurrent write landing between step 5 and step 6
could have its shelves dropped, or leave shelves the registry no longer lists. **Accepted for
single-user v1**, consistent with the same window `put_impl`'s container merge and
`resource::delete_rdf` already document and accept. Invariant 3.2.4's second drop is what
keeps the *consequence* bounded: a stale shelf cannot silently supply triples to a later
write.

### 5.2 Atomicity: verified, with a caveat

Revision 1 listed `;`-sequence atomicity as an unmeasured precondition. Both reviews settled
it independently — by reading `BoundPreparedSparqlUpdate::execute` (every operation is
evaluated before `transaction.commit()` is called, so an error partway through returns without
committing) and by measurement: a runtime failure in the last operation of a sequence rolled
the first two back.

**The caveat is new and belongs in the design.** This is a property of `OxigraphStore`, not of
SPARQL. `SparqlStore` is a trait; the day a remote endpoint implements it, `;`-sequence
atomicity is gone and this write path is unsound with no compile error to say so — the same
class of portability constraint Trellis hit with quad-shaped storage. The guarantee is stated
on the trait as a documented obligation of any implementor.

## 6. Read path

1. Presence marker, else `404` as today.
2. Read the resource graph, the registry, and **one `CONSTRUCT` per shelf** — `query_triples`
   returns `Vec<Triple>` with no graph field, so a single query cannot recover which shelf a
   triple came from. For a resource with N named graphs that is 2+N in-process queries. No
   store-trait change is needed; blank-node identity across separate `CONSTRUCT`s was measured
   to survive, and after §4 there are no blank nodes in the store anyway.
3. Compute the **ETag from the stored quads**, before de-skolemization, over graph names as
   well as triples.
4. De-skolemize, then serialize.

### 6.1 The ETag order is normative

Step 3 before step 4, and the reason is not stylistic. If the ETag were computed after
de-skolemization — the natural code order, since one would build "the dataset to serialize"
once and use it for both body and header — every `GET` would mint fresh blank node labels,
`etag()` renders terms via `Display`, and every response would carry a different validator.
`If-None-Match` would never match and `304` would never fire.

`rdf::etag(&[Triple])` must become dataset-aware: graph names participate in the hash, or two
datasets differing only in which graph a statement sits in share a validator.

### 6.2 Negotiation is a property, not a table

**The server selects the highest-ranked acceptable media range it can serve, and answers
`406` only when no acceptable range can represent the resource.**

That is a bigger change than revision 1's "negotiation moves after the read".
`format_for_accept` returns the first supported type in the list and ignores q-values
entirely; it needs to become a capability-aware resolver over the whole `Accept` list, where
"can this format carry a dataset" filters the candidate set instead of being checked on the
winner. `Accept: text/turtle, application/ld+json` against a dataset-valued resource must
return JSON-LD, not `406` — the client explicitly offered a format that works.

Capabilities:

| Format | Carries a dataset |
|---|---|
| `application/ld+json`, `application/trig`, `application/n-quads` | yes |
| `text/turtle`, `application/n-triples` | no |

Wildcards are scoped by their type: `*/*` admits every format, so a dataset-valued resource
answers it with JSON-LD (and a graph-valued one with Turtle, as today); `text/*` admits only
`text/turtle`, so it behaves like `text/turtle`. `application/*` admits the dataset formats.

`application/trig` and `application/n-quads` are new, for reading and writing. Without them
JSON-LD would be the only lossless text form. Both are also unadvertised — the pod emits no
`Accept-Put`/`Accept-Post` and has no `OPTIONS` route, so a client that gets a `406` has no
way to learn that TriG would work. **That is a named follow-up (§11), not solved here**, and
it is the reason the `406` body names the acceptable types and the response carries
`Link: <…>; rel="alternate"; type="application/trig"`.

`Vary: Accept` is emitted on every negotiated response, and the selected format participates
in the ETag. Today neither is true: one strong validator is shared by every representation,
which RFC 9110 §8.8.1 forbids, and `*/*` now makes the selected format *state-dependent* —
the same URL under identical request headers answers Turtle or JSON-LD depending on whether
anyone has written a named graph into it since. That is precisely what `Vary` exists for.

### 6.3 Owning the Solid §5.5 violation

Solid Protocol §5.5: *"the server MUST satisfy `GET` requests on this resource when the field
value of the `Accept` header field requests a representation in `text/turtle` or
`application/ld+json`."* A `406` does not satisfy it for `text/turtle`, and this design
knowingly fails that MUST for dataset-valued resources.

The position it is chosen against is not hypothetical. **RDF 1.1 Concepts §4.2**
(non-normative) says: *"If an RDF dataset is returned and the consumer is expecting an RDF
graph, the consumer is expected to use the RDF dataset's default graph."* The LDP WG ran the
same argument and reversed itself — ISSUE-90 ("An LDPC/LDPR is a Named Graph") was resolved in
favour in December 2013, landed in the March 2014 LC draft, and was removed six weeks later.
And the Solid conformance suite records the expectation in a **disabled** scenario of the very
feature this design fixes:

```gherkin
  @ignore
  Scenario: Alice can GET the JSON-LD with named graph as TTL
    # The expected response is disputed - since TTL doesn't support Quads, the RDF spec suggests:
    # "If an RDF dataset is returned and the consumer is expecting an RDF graph, the consumer is
    #  expected to use the RDF dataset's default graph."
```

`406` is chosen anyway, because a lossy `200` is indistinguishable from a correct one: a
client asking for Turtle and receiving the default graph alone has no way to learn that
anything was withheld. Merging all graphs into the response was rejected on semantics — a
statement in a named graph is not asserted in the default graph, so merging manufactures
assertions the document never made.

Two things worth being honest about: the conformance target is the JSON-LD scenario alone, so
**passing `content-negotiation-named-graphs:16` does not require the `406`** — it is a free
choice, which is a reason to make it deliberately, not a reason to make it. And the
alternative that ships is worse: CSS's file backend answers `Accept: text/turtle` with
`Content-Type: text/turtle` and a **TriG** body (measured, CSS 7.2.0; `CSS#1327`, open since
2022), which no strict Turtle parser accepts. Its SPARQL backend answers `501` instead.

## 7. Delete

Read the registry, then one update dropping the resource graph, every registered shelf as a
literal `DROP SILENT GRAPH`, and the system graph. Same shape and same caveat as §5.1.

Note that `aux::delete_subject` today drops the subject graph and its system graph — the
registry — and each auxiliary, without reading what the registry pointed at. Under this design
that ordering destroys the only record of the shelves before they are dropped, which is
invariant 3.2.4's failure mode exactly.

## 8. What does not change

WAC, containment, the ancestor walk, the §3.1 slash-pair rule, aux links.

Subgraphs need no authorization of their own: no URL resolves to one and no client can name
one, so their content is covered by the resource's ACL by construction.

**Conditional requests do change** and were wrongly listed here in revision 1 — see §6.1 and
§6.2: the ETag becomes dataset-aware and format-aware, and `Vary` is new.

**Storage changes for every resource containing a blank node**, not only for dataset-valued
ones: §4 skolemizes unconditionally, so a plain Turtle `PUT` with an anonymous node now stores
an IRI where it previously stored whatever label the parser assigned. That is deliberate — it
is what makes the ETag meaningful at all — but "unchanged for resources without named graphs"
is false and revision 1 said it.

No migration is needed regardless: the pod is pre-1.0, the store is in-memory only
(`OxigraphStore::in_memory` is the sole constructor), and there is no deployed data.

## 9. Documented limits

1. **An empty named graph does not survive.** `{"@id": "urn:g", "@graph": []}` produces no
   quads, so a quad-based parser never sees it. Not closable within this model.
2. **`urn:pod:` IRIs are refused in request bodies** (§3.2.2). A document that legitimately
   wants to talk about such an IRI cannot be stored.
3. **Blank node labels are not preserved**, only their structure and co-reference. True today
   as well.
4. **Byte fidelity was never offered.** Formatting, `@context`, key order.
5. **A graph named like the resource itself** is an ordinary named graph with its own shelf,
   and round-trips unchanged. Folding it into the resource's default graph would be a document
   rewrite — moving statements out of a named graph changes what the document asserts — and it
   is the obvious accidental implementation, so it is pinned by a test.
6. **A graph named like *another* resource's URL** is likewise ordinary and lands in this
   resource's shelf. This is the case §2.1 exists for, it is reachable with an eleven-character
   relative IRI, and it gets a test: writing that document must not change `GET /victim` by one
   triple.

## 10. Testing

- **Round-trip** — the oracle is dataset isomorphism: read back, de-skolemized, must be
  isomorphic to what was sent. `Dataset` comparison after `canonicalize` is the cheapest exact
  form of that assertion, and using RDFC *in tests* is safe in a way using it on request bodies
  is not: test inputs are not attacker-controlled. The blank-node-as-graph-name-and-term case
  (§4) is a required fixture, not an edge case.
- **Unit** — key derivation: the same graph name in two resources yields two keys; two names
  in one resource yield two keys; and the encoding property itself, that no two distinct pairs
  can produce one key, which is what the `0x00` separator buys and what revision 1's two
  example pairs did not pin. Skolemization round-trips co-reference. The ETag changes when only
  a graph name changes, and does not change between two `GET`s of the same stored state.
- **Storage** — invariant 3.2.3 after every write and delete; a `PUT` replacing a document with
  one containing *fewer* graphs leaves no shelf behind, checked through `named_graphs()` rather
  than by querying for triples, because an emptied graph still answers empty (§5.1); and the
  resurrection case: delete a resource, recreate it with the same inner graph name, and the old
  triples must not reappear.
- **HTTP** — JSON-LD with a named graph in and out; TriG and N-Quads both directions;
  `Accept: text/turtle, application/ld+json` yields JSON-LD; `text/*` yields `406`; `*/*`
  yields JSON-LD; `Vary: Accept` present; `400` for container, auxiliary, and a `urn:pod:` IRI
  in the body; the two graph-naming cases from §9.
- **Conformance** — `content-negotiation-named-graphs:16` passes, and the full run does not
  regress against the counts in `docs/conformance-findings.md`.

Two rules carried over, both of which found real defects every previous round:

**Every test must fail against a mutant.** The "graph named like the resource" test is
worthless if it stays green when someone folds the two together — the aux-URL work produced
exactly this failure, a test asking for a property in a form where it held trivially.

**A documented limit gets a test too** — with an assertion that can actually fail. The empty
named graph cannot use the isomorphism oracle: zero quads on both sides pass it vacuously. It
needs a direct assertion on the response instead.

## 11. Follow-ups this design deliberately does not do

- **Non-RDF resources (blobs).** 540 of the 615 conformance failures. Its own plan.
- **`OPTIONS`, `Accept-Put`, `Accept-Post`.** TriG and N-Quads are undiscoverable without
  them, and `solid/specification#610` makes discoverability the thing that makes optional quad
  support interoperable. Directly adjacent to §6.2 and worth doing next.
- **RDFa extraction**, which only becomes honest once blobs exist: the HTML would be the
  content, with extracted triples in a derived graph marked as derived. oxigraph has no RDFa
  parser.
- **A public SPARQL endpoint.** `solid/specification#804` is the live proposal, and uvdsl's
  suggestion in that thread — reuse the Graph Store Protocol's resource↔graph mapping,
  invert it, put access control on top — is the shape to build against. Flattening the query
  view (§2) is compatible with storing datasets faithfully, so this design does not constrain
  that choice. Authorizing WAC over arbitrary SPARQL patterns is the harder half.
- **Stored representation variants** (several files negotiated per resource). Explicitly not
  wanted: representations here are generated from one state, so they cannot drift.
- **`application/rdf+xml`**, which oxigraph already supports and this pod does not offer.
- **Replacing the presence marker with `CREATE GRAPH`.** Moot here, since the registry records
  more than existence anyway.

## 12. What changed in revision 2, and why

| § | Revision 1 said | Why it was wrong |
|---|---|---|
| 4 | Canonicalize (RDFC-1.0) on write; cap blank nodes at 1000 | The W3C poison test is 10 blank nodes and takes 375 s against oxrdf; the cap guarded nothing and rejected legitimate documents. Replaced by skolemization, which needs no canonicalization at all. |
| 4 | Canonicalization stabilises the ETag | `INSERT DATA` mints fresh blank nodes by definition; the store discards canonical labels. Measured. |
| 4, 6 | The returned dataset is isomorphic | Not when a blank node is both graph name and term — the VC `proof` shape. One skolem IRI everywhere fixes it. |
| 5 | Drop through the registry, **not** through the new keys | False dichotomy: stable keys make an orphaned shelf into content a later write inherits. Both drops are needed. |
| 5 | "One SPARQL update" | Also needs to be one `INSERT DATA` *operation*, and needs a prior registry read, because `DROP GRAPH` cannot take a variable and `DELETE WHERE` leaves the graph entity behind. |
| 5.1 | Atomicity must be measured | It was, twice, by both reviews. It holds for `OxigraphStore` and not for the trait. |
| 6.1 | A table keyed on one media type | `Accept` is a list with q-values; the table `406`s requests that offered a workable format. |
| 8 | Conditional requests unchanged; storage unchanged without named graphs | Both false: the ETag becomes dataset- and format-aware, and skolemization touches every blank-node-bearing resource. |
| 2 | Trellis stores one graph per resource; #559 shows the derivation breaking | Four graph kinds, one of them server-wide; `?ext=` is client-visible; #559 was a misconfiguration closed the next day. #592 is the relevant issue. |
| 2 | `#804` mandates the opposite | It mandates flattening of the *query view* only and explicitly leaves stored representations untouched. Compatible. |
| 3 | "SHA-256 over the IRI, a separator byte, and the graph name" | Unspecified separator; a printable one admits collisions. Fixed to `0x00`, which IRIs cannot contain. |
