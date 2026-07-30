# N3 Patch — Changing Part of a Resource — Design

**Date:** 2026-07-30
**Status:** Proposed (pre-implementation), revision 1
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md)
**Origin:** `docs/conformance-findings.md` rank 6 — the last unclaimed rank on that list, and
the only Solid MUST this pod answers with `405`.

## 1. What is wrong today

`rg -n 'patch' src/` finds nothing. No route, no handler, no `Accept-Patch`. Axum answers
`405` for every `PATCH`, which costs two measured scenarios and a MUST:

- `protocol/writing-resource/containment:38` — a patch expected to succeed.
- `protocol/authentication/header:40` — an **anonymous** patch expected to be refused with
  `401`. It gets `405`, because the method check fires before authentication. The other five
  anonymous rows in that feature pass, `WWW-Authenticate` included; this one fails only
  because the method does not exist.

The cost is larger than two rows. Within the 491 `protected-operation` scenarios that the
non-RDF work unblocks, a share exercises `PATCH`; those rows have never been evaluated
against this pod, and they will fail on `405` the moment the `415` clears. The same findings
entry named `OPTIONS` alongside `PATCH`, and `OPTIONS` has since landed.

A pod that cannot change one triple of a document without rewriting the whole document is
also, separately, a bad pod. `PUT` is the only editing primitive this server offers today.

## 2. What the specifications actually require

Solid Protocol §5.3.1, verbatim where it matters:

> Servers MUST accept a `PATCH` request with an *N3 Patch* body when the target of the
> request is an *RDF document*.

> Servers MUST process a patch resource against the target document as follows: … Start from
> the RDF dataset in the target document, **or an empty RDF dataset if the target resource
> does not exist yet**.

> If no such mapping exists, or if multiple mappings exist, the server MUST respond with a
> `409` status code.

> If the set of triples resulting from `?deletions` is non-empty and the dataset does not
> contain *all* of these triples, the server MUST respond with a `409` status code.

> Servers MUST respond with a `422` status code if a patch document does not satisfy all of
> the above constraints.

And on access control: a request is treated as a Read operation when the conditions are
non-empty, an Append operation when there are insertions, and both Read and Write when there
are deletions.

Three findings from reading the document rather than assuming it:

**`application/sparql-update` does not appear in the Solid Protocol at all.** Not as a MUST,
not as a MAY, not as a mention. It is what the early servers did before N3 Patch was
specified. `containment:38` sends it anyway — the bundled `specification-tests` v0.0.19
encodes some ecosystem behaviour beside the specification text. This design implements the
specification and not the test; §15 records the consequence.

**The Protocol says nothing about atomicity.** The words *atomic*, *atomically*, *partial*,
*concurrent* and *simultaneous* do not occur in it. There is no requirement this design could
violate by choosing where the patch is computed, and none it can satisfy by choosing
differently.

**Lost updates are handled as a conditional-request problem, not a server guarantee.** §5.3:

> Clients are encouraged to use the HTTP `If-None-Match` header field with a value of `"*"`
> to prevent an unsafe request method, e.g., `PUT`, `PATCH`, from inadvertently modifying an
> existing representation …

> Servers MAY use the HTTP `ETag` header field with a strong validator … in order to
> encourage clients to opt-in to using the `If-Match` header field in their requests.

This pod already emits strong ETags and already honours `If-Match`/`If-None-Match` in
`put_impl`. `PATCH` inherits that machinery and thereby lands exactly where the specification
puts the problem. §11 records what it does not cover.

## 3. One media type: `text/n3`

`Accept-Patch: text/n3`, and `415` for anything else.

The alternative considered and rejected was accepting `application/sparql-update` as well, to
turn `containment:38` green. It is rejected because of what it would be: `sparql-update` means
executing a **client-authored database command** against a store that holds every resource,
every ACL and the server's own system graphs. A patch to `/notes` and a `DROP ALL` are the
same kind of object at the point of execution, and the only thing separating them would be a
rejection list — a list that must stay exhaustive against a `spargebra` AST that may gain a
variant in any minor release. The guard and the guarded would sit on opposite sides of a
dependency bump.

This project has already made this choice once, in the other direction: `MediaType` refuses
quoted-string parameters instead of escaping them, so the safety is a property of the alphabet
rather than of a correct escape at every site. N3 Patch is the same shape of answer. It is a
**document made of triples**, not a command; the server parses it to terms and builds every
query it issues from those terms itself. There is no client SPARQL text anywhere in this
design, so there is nothing to sandbox and no list to keep exhaustive.

Adding `sparql-update` later remains possible and would be its own design, with its own
containment argument. It is not required by anything, which is what makes deferring it cheap.

**`Format` gains no `text/n3` variant, and `text/n3` is never accepted on `PUT` or `POST`.** N3
Patch is an instruction, not a representation: nothing is ever stored as N3, served as N3, or
negotiated into N3. Adding it to `Format` would make `text/n3` a media type a client could `PUT`
a resource as, and would put an instruction format inside the type whose whole job is answering
*"can I parse this as a stored representation?"* — the distinction the constraint *"There is one
content-negotiation path, one parser and one ETag"* exists to keep sharp.

## 4. Parsing: measured, not assumed

`oxttl` is already in the tree transitively (0.2.3, via oxigraph) and becomes a direct
dependency. Its `n3` module parses N3, including the `{ }` formulae that N3 Patch is built
from and that Turtle cannot express.

`N3Term` has no formula variant — the variants are `NamedNode`, `BlankNode`, `Literal`,
`Triple` and `Variable`. Formulae are carried on the quad instead: `N3Quad::graph_name` is an
`oxrdf::GraphName`, and the crate documents that *"the `graph_name` is used to encode the
formula where the triple is in. In this case the formula is encoded by a blank node."*

Measured against the parser rather than read off the documentation. Parsing the worked example
of §5 yields, in order:

| `graph_name` | subject | predicate | object |
|---|---|---|---|
| `DefaultGraph` | `_:patch` | `rdf:type` | `solid:InsertDeletePatch` |
| `_:b0` | `?person` | `ex:email` | `"alt@example.org"` |
| `DefaultGraph` | `_:patch` | `solid:where` | `_:b0` |
| `_:b1` | `?person` | `ex:email` | `"alt@example.org"` |
| `DefaultGraph` | `_:patch` | `solid:deletes` | `_:b1` |
| `_:b2` | `?person` | `ex:email` | `"neu@example.org"` |
| `DefaultGraph` | `_:patch` | `solid:inserts` | `_:b2` |

Three properties this pins, all of which the implementation depends on:

1. The patch resource's own triples arrive in the default graph.
2. Each formula's contents arrive as quads whose `graph_name` is a fresh anonymous blank node.
3. That same blank node is the **object** of the corresponding `solid:where` / `solid:deletes`
   / `solid:inserts` triple, so linking a formula to its contents is a blank-node comparison
   and nothing more.

Variables survive as `N3Term::Variable`. The two formulae with identical contents (`where` and
`deletes` above) receive **different** blank nodes, which is what makes them distinguishable at
all — §14 turns that into a test.

## 5. The patch document

The worked example, against a `/profile` holding
`<#me> ex:email "alt@example.org" ; ex:name "Toph" .`:

```
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix ex:    <http://example.org/> .

_:patch a solid:InsertDeletePatch ;
  solid:where   { ?person ex:email "alt@example.org" . } ;
  solid:deletes { ?person ex:email "alt@example.org" . } ;
  solid:inserts { ?person ex:email "neu@example.org" . } .
```

### 5.1 Shape validation — `422`

Checked against the parsed quads, before anything touches the store:

- Exactly one subject carries `rdf:type solid:InsertDeletePatch`.
- At most one `solid:where`, at most one `solid:deletes`, at most one `solid:inserts` on it.
- The object of each is a blank node that occurs as a `graph_name` in the same document.
- Neither `?insertions` nor `?deletions` contains a blank node.
- Every variable in `?insertions` or `?deletions` also occurs in `?conditions`.
- No quad in the document belongs to anything but the patch resource and its three formulae.

The last one is this design's addition rather than the specification's. A document carrying
a second patch resource, or triples on an unrelated subject, is a document whose author
believed something the server is not going to do. Refusing beats silently applying the part
the server recognised — the same fail-closed reading `kind_of` already takes for a binary
resource with no stored media type.

**A patch with neither `solid:inserts` nor `solid:deletes` is `422`.** The specification
permits both to be absent, which describes a request that changes nothing. No client means it,
and admitting it would put a request that needs no access mode at all into a path whose first
gate is an access-mode check (§9).

## 6. Applying the patch

Every step below issues SPARQL that the **server** builds from parsed terms. Nothing the
client wrote is concatenated into a query as text.

1. **Scope.** All queries are scoped to `GRAPH <resource-iri>`. The client's pattern selects
   within that graph; it does not choose it. This is the whole containment argument, and it is
   one line rather than a rejection list.
2. **Conditions → `SELECT`.** The condition formula becomes a graph pattern. Run it with
   `LIMIT 2`.
3. **Count.** Zero rows or two rows → `409`. Exactly one row is the mapping. `LIMIT 2` is
   sufficient to distinguish the three cases and is what stops a broad pattern from
   materialising a large result set purely to be counted.
4. **Bind.** Substitute the mapping into the deletion and insertion formulae. Both are now
   **concrete triples** — no variables, and no blank nodes by §5.1.
5. **Check deletions.** If the deletion set is non-empty and the stored graph does not contain
   all of it → `409`, nothing written.
6. **Write.** One update: `DELETE DATA { GRAPH <iri> { … } } ; INSERT DATA { GRAPH <iri> { … } }`.
   Delete before insert, per the specification's step order — a patch that deletes and
   re-inserts the same triple must end with it present.

### 6.1 Variables are renumbered, not passed through

A variable name comes from the client. `?person` is fine; a name chosen to close the query and
open another one is the injection this design must not have.

Client variables are therefore **mapped to server-generated names** — `?v0`, `?v1`, … in order
of first occurrence — and the client's spelling never reaches the query text. This is not a
validation of the client's name against SPARQL's alphabet; it is a design in which the client's
name is not used. The mapping is also needed anyway, to substitute the binding back into the
formulae.

IRIs are rendered through `NamedNode`, literals through `sparql::Literal` — the two types this
codebase already established for exactly this, and the constraint check that forbids a
hand-written `"{}"` covers the new call sites without amendment.

### 6.2 The default graph only

A resource in this pod may hold a dataset with named graphs (shelves). N3 Patch has no syntax
for naming a graph, so a patch applies to the resource's **default graph** and nothing else:
conditions match only there, deletions remove only from there, insertions land only there. A
triple in a shelf cannot be reached by any patch a client can write.

This is a limit rather than a defect — the format has no way to express the operation — and it
is recorded in §11. It matches the line §6.2 of the non-RDF design already draws between what
a graph format can carry and what the resource holds.

### 6.3 What a patch means against a skolemized store

`2026-07-28-jsonld-datasets-design.md` §4 left this open in as many words — *"The day N3 Patch
arrives, skolemization needs a rule for what a patch means against a skolemized store."* This
is that rule.

Stored blank nodes are skolem IRIs; served ones are blank nodes again, de-skolemized at the two
sites that serialize (`get_impl` and `legacy_graph_read`). A patch document may contain no blank
nodes at all (§5.1), so **a client can never name one**. It can only reach a blank-node subject
through a variable in `solid:where` that pins it by its other properties.

**A variable may bind to a skolem IRI, and the binding is substituted verbatim.** The
`urn:quadpod:` refusal applies to IRIs written **literally in the patch document**, never to a
binding the server itself produced. Ordering matters and is the whole content of this rule: run
the reserved-namespace check on the *parsed document*, before substitution. Run it after, and
every patch touching blank-node data is refused with a message about a namespace the client has
never seen.

The check itself is `dataset::uses_reserved_namespace`, called rather than reimplemented — the
constraint *"Only `dataset` mints or recognises a skolem IRI"* is enforced by
`! rg -q "urn:quadpod:bnode" src --glob '!src/dataset.rs'`, so the patch module must not contain
that string at all.

De-skolemizing the resource, applying the patch to the visible form and re-skolemizing was
considered and rejected. `Dataset::skolemize` mints a fresh UUID per blank node per call, so a
round trip renames **every** blank node in the resource, including those the patch never
mentioned. That renames blank-node-named graphs, hence their `ShelfKey`s, so a patch scoped to
the default graph would rewrite shelves it never touched — and it reintroduces the
read-modify-write window §6 exists to avoid, now spanning the whole resource. It buys nothing
in exchange: a variable binds to a skolem IRI exactly as readily as to a derived blank-node
label, so which triples match is identical either way.

### 6.4 Error bodies name conditions, not values

A `409` says which rule failed. It does **not** echo the bound triples, because a binding may
be a skolem IRI and that IRI is the server's, not the client's to see.

`put_impl` already draws this line: its named-graph `409` lists the IRI-named graphs and merely
*counts* the blank-named ones, so the refusal accounts for everything it refuses without naming
what the client never wrote. The patch path inherits the rule rather than rediscovering it.

## 7. Creation

A `PATCH` whose target does not exist starts from an empty dataset, as §2 quotes. In practice
that means only an insert-only patch can create: a patch with a non-empty `solid:where` finds
zero mappings against an empty dataset and gets `409` by §6, which is the correct answer and
needs no special case.

When the resource is created, the request goes through the **existing** creation path — the
same ancestor materialization, containment linking and `201` that `PUT` uses. There is no
second creation path. The stored media type for a resource created this way is `text/turtle`:
a patch declares no representation format, and Turtle is what the negotiation fallback already
prefers.

## 8. Targets

`PATCH` is accepted wherever the target is an RDF document: `Target::Resource`,
`Target::Container` and `Target::Aux`.

- **Container.** Containment is server-managed. A patch whose insertions or deletions touch
  `ldp:contains` is `409`, reusing `container::body_sets_containment` — the same refusal
  `put_impl` already makes, at the same point in the sequence, so a rejected patch cannot
  leave a containment triple behind.
- **Aux.** `authorize` already ignores the caller's mode for an `Aux` target and substitutes
  `required_mode_for_aux`, so patching an ACL requires `Control` without this design saying
  anything. §9's tiering applies to resources and containers only.
- **A binary resource is `409`.** `text/n3` is a perfectly acceptable request body, so `415`
  would be a claim about the wrong thing; the conflict is with the state of the target, which
  is bytes and has no triples to patch. The message says so.

## 9. Access control

The required modes depend on the patch's contents, and the contents are only known after
parsing. The pod's standing rule is that no handler branch answers before `authorize` runs, so
an unauthorized caller learns nothing — including whether the target exists.

Both hold at once, because `authorize` returns a `Decision` carrying the agent's **full**
`AccessModes`, resolved from the ACL it already walked:

1. Call `authorize(…, Mode::Append)` first. Every patch that §5.1 admits inserts or deletes,
   and `AccessModes::allows` makes `Write` subsume `Append`, so this gate refuses exactly
   those callers who could do nothing anyway.
2. Parse and validate the patch.
3. Check the required set against the `AccessModes` already in hand: conditions non-empty →
   `read`; insertions → `append`; deletions → `read` **and** `write`.

No second ACL resolution. That is the reason `authorize`'s doc comment gives for returning the
decision at all: a second lookup repeats the ancestor walk on the hot path, and an ACL written
between the two would let the answer describe access other than the access granted.

An agent holding only Append can therefore run an insert-only patch and is refused one that
deletes — which is the behaviour the `protected-operation` features test, and which a single
`Mode::Write` gate would get wrong in the permissive direction for the first case and the
restrictive direction for the second.

## 10. The HTTP edge

### 10.1 Status codes in one place

| Code | Cause |
|---|---|
| `415` | `Content-Type` is not `text/n3` |
| `400` | The body is not parseable N3, or names the reserved `urn:quadpod:` namespace |
| `422` | The patch document violates §5.1 |
| `409` | Zero or multiple mappings; a deletion triple is absent; the target is a binary resource; the patch touches `ldp:contains` on a container |
| `412` | `If-Match` or `If-None-Match: *` failed |
| `401`/`403` | §9 |
| `201` | The patch created the resource |
| `204` | The patch changed an existing resource |

`201` goes through the existing `created` helper, so `Location` and the auxiliary-URL `Link`
headers come with it exactly as they do for `PUT`. `204` for a modification matches what
`DELETE` already answers; `205` is what some other Solid servers send, and adopting it would
introduce a third success shape this codebase has no other use for.

`400` for the reserved namespace rather than `422` keeps it identical to `put_impl`'s answer
for the same body content. The namespace rule is about what a client may write anywhere, not
about the shape of a patch document.

### 10.2 Advertisement

- `allowed_methods` gains `PATCH` for every target it already lists, which feeds both the
  `Allow` header on `GET`/`HEAD` and the `Allow`/`Access-Control-Allow-Methods` pair on
  `OPTIONS`.
- `Accept-Patch: text/n3` is emitted where §5.3 requires it, and joins the CORS
  exposed-headers list beside `Accept-Put`'s eventual home.

### 10.3 Conditional requests

The `If-Match` / `If-None-Match` block from `put_impl` moves to a shared helper and is used
unchanged. `PATCH` evaluates it after authorization and before any write, in the same position
`PUT` does.

## 11. Documented limits

- **`If-Match` is the client's choice.** Two patches racing on one resource are serialized by
  the store, but a client that sends no validator can still overwrite a change it never saw.
  The specification treats this as a client opt-in (§2) and this design does not exceed it.
- **A condition pattern is client-controlled compute.** `LIMIT 2` bounds the result set, not
  the join cost. A deliberately expensive pattern against a large resource is a load a client
  can impose.
- **The default graph only** (§6.2). Triples in shelves are unreachable by patch.
- **No `application/sparql-update`** (§3).
- **The body is buffered whole**, under the existing request body limit.
- **A patch cannot change a resource's stored media type.** It is not a representation.

## 12. What does not change

Routing a patch onto the existing `Target` and the existing writer means `authorize`,
`authorize_and_materialize`, ancestor materialization, `refuse_slash_pair`, containment,
auxiliary-URL advertisement, blob teardown and `name_is_taken` all apply unaltered. No new
`DirectlyWritable` implementor appears; a patch is a way of writing a resource, not a new kind
of thing in the URL space.

**The targeted update of §6 step 6 is not a third teardown site.** `2026-07-29-non-rdf-resources-design.md`
§7 fixes the rule that wherever a resource's RDF state is torn down, its blob is torn down in
the same operation, and names the two sites that do it: `put_dataset`'s replace and
`delete_subject`'s cascade. `e31c88b` removed a second, weaker delete cascade once already, so
this is a boundary with a history.

A patch tears nothing down. It never changes a resource's kind — a patch at a binary resource
is `409` (§8) — so there is never a blob to remove, no registry entry to drop and no shelf to
reap. It removes and adds triples inside a graph that continues to exist, which is why it is a
mutation beside those two sites rather than a third instance of them. Should a later change give
`PATCH` the power to change a kind, that is the moment this paragraph stops being true and §7's
rule applies to it.

The `;`-sequenced update it issues is atomic in `OxigraphStore` and not in the `SparqlStore`
trait — the same footing every existing write path stands on, recorded in the constraint
*"`SparqlStore` has exactly one implementor"*. This design adds no new reliance there.

## 13. Testing

Each test names the mutant it kills.

1. **Formula linking.** A patch whose `where` and `deletes` formulae contain *identical*
   triples, and whose `inserts` differs. Kills an implementation that collects quads without
   regard to `graph_name` — which would still pass every patch where the three formulae happen
   to differ, and that is most of them.
2. **Variable renumbering.** A variable whose name is chosen to close the query and open
   another (`?x } INSERT DATA { GRAPH <urn:evil> …`). The injected graph must not exist
   afterwards. Demonstrated red against a version that interpolates the client's name.
3. **Mapping count.** Zero matches → `409`; two matches → `409`; one match → applied. Kills the
   obvious implementation as a single `DELETE … INSERT … WHERE`, which applies to *all*
   matches and would pass a one-match test perfectly.
4. **Missing deletion.** A deletion set the graph does not fully contain → `409`, **and the
   insertions did not happen**. Asserted on the stored graph, not on the status code alone.
5. **Creation.** An insert-only patch on an absent resource creates it, materializes ancestors
   and links containment, answering `201`. A patch with a `where` on an absent resource →
   `409`.
6. **Access tiering.** An Append-only agent: insert-only patch succeeds, a patch with
   deletions is refused. Kills a single `Mode::Write` gate, in both directions.
7. **Binary target.** `PATCH text/n3` at a blob → `409`, and the bytes are still there
   afterwards, queried through the `BlobStore` directly.
8. **Containment.** A patch inserting `ldp:contains` on a container → `409`, and no ancestor
   was materialized by the attempt.
9. **Conditional.** A stale `If-Match` → `412`, and the graph is unchanged.
10. **Shape.** Blank node in insertions; a variable in deletions absent from conditions; two
    `solid:inserts`; a stray triple on an unrelated subject; neither inserts nor deletes. Each
    `422`.
11. **Anonymous.** `PATCH` without credentials → `401` with `WWW-Authenticate`, not `405`.
    This is `authentication/header:40` as a unit test.
12. **Skolem binding.** `PUT` a document containing a blank node, then patch that blank node's
    triples through a `solid:where` that pins it by another property. Must succeed. Kills the
    ordering mistake §6.3 exists to prevent — running the reserved-namespace check after
    substitution rather than before, which refuses this patch with a message naming an IRI the
    client never saw. That mutant passes every other test here, because every other test's
    fixture has no blank nodes.
13. **No skolem IRI in an error body.** Provoke each `409` against a resource holding blank
    nodes and assert the response body contains no `urn:quadpod:`. Kills the natural
    implementation of §6 step 5's message, which would echo the bound triples to be helpful.

## 14. Conformance: what this moves

- `protocol/authentication/header:40` — **green.** The method exists, so the auth middleware
  answers before the method check.
- `protocol/writing-resource/containment:38` — **stays red**, and moves into Bucket 1 with the
  reason from §3: it sends `application/sparql-update`, which the Protocol does not define.
- The `PATCH` share of the `protected-operation` scenarios becomes **measured** for the first
  time.

No test is disabled. The findings document attributes every failure to a named cause, and the
reconciliation across runs only works while nothing is switched off.

## 15. Follow-ups this design deliberately does not do

- **`application/sparql-update`.** §3. Its own design, with its own containment argument, if
  a caller ever needs it.
- **Patching a named graph inside a resource.** §6.2. Needs a format that can name one; the
  per-subgraph-URL follow-up in `2026-07-28-jsonld-datasets-design.md` §11 is where that
  conversation already lives.
- **`Accept-Put`.** Adjacent to §10.2 and named in the JSON-LD design's follow-ups; it belongs
  with the discoverability work, not here.
- **Server-side conflict merging.** Rejected by omission: the specification's answer to a
  concurrent change is `412`, and a server that merges instead is a server whose clients
  cannot predict what they wrote.

## 16. Deltas against documents already in force

No decision recorded elsewhere is reversed or narrowed. `docs/uri-space.md` is unaffected: a
patch addresses a URL that already exists in the space and creates nothing new in it.

One open question recorded elsewhere is **closed** rather than changed:
`2026-07-28-jsonld-datasets-design.md` §4's *"A note on `PATCH`"* deferred the meaning of a patch
against a skolemized store to the day N3 Patch arrived. §6.3 is the answer, and that note should
now read as settled rather than pending.
