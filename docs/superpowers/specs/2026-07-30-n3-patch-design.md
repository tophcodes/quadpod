# N3 Patch — Changing Part of a Resource — Design

**Date:** 2026-07-30
**Status:** Proposed (pre-implementation), revision 1
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md)
**Origin:** `docs/conformance-findings.md`, fifth run — **rank 1 of the residual failures, 66
scenarios, 78% of everything still red**, and the only Solid MUST this pod answers with `405`.

## 1. What is wrong today

`rg -n 'PATCH' src/` finds nothing but an RFC 9110 citation in a comment. No route, no handler,
no `Accept-Patch`. Axum's method dispatch answers `405` before authentication, before
`Content-Type`, before anything about the request is inspected.

This was rank 6 while non-RDF resources blocked 540 scenarios. That work has landed and the
fifth run measures 567 passed against 85 failed, which leaves `PATCH` as **the largest single
gap in the suite**:

| Feature | Failures |
|---|---|
| `wac/protected-operation/read-access-{agent,bob,public}` | 10 each |
| `wac/protected-operation/write-access-{agent,bob}` | 12 each |
| `wac/protected-operation/write-access-public` | 9 |
| `protocol/writing-resource/containment:38` | 1 |
| `protocol/authentication/header:40` | 1 |
| `protocol/writing-resource/content-type-reject:19` | 1 |

`10×3 + 12×2 + 9 + 1 + 1 + 1 = 66`.

The 63 `protected-operation` rows are `retry until <expected-status>` steps that never
converge: `405` is never one of the awaited statuses (`403`, `401`, or
`[200, 201, 204, 205]` depending on the row), so karate gives up after three attempts. They
read differently in `harness.log` than an ordinary assertion mismatch and have the identical
root cause.

The remaining three are individually informative. `containment:38` sends
`application/sparql-update`. `authentication/header:40` is an **anonymous** patch that must be
refused with `401` — the other five anonymous rows in that feature pass, `WWW-Authenticate`
included, and this one fails only because the method does not exist. `content-type-reject:19`
is a patch with no `Content-Type` at all, which cannot reach the `Content-Type` gate that
already answers it correctly for `PUT` and `POST`.

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

The cost is one scenario, and that is measured rather than hoped. Of the 66 `PATCH` failures,
**63 send `text/n3`** — the `protected-operation` fixture quoted in §9 — and one sends no
`Content-Type` at all. `containment:38` is the only row in the entire suite that uses
`application/sparql-update`. The format this design implements is the format the tests
overwhelmingly speak.

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
- Every variable in `?insertions` or `?deletions` also occurs in `?conditions`. Note the
  narrowness: only *variables* are constrained this way. `solid:deletes { ?p ex:phone "123" }`
  is legal with `?p` bound by the conditions and the phone triple mentioned nowhere else — a
  deletion whose triple is absent is answered by §6's `409`, not by a shape violation.
- **Exactly one** subject carries the type. Two patch resources in one document make "the
  patch" ambiguous, and picking the first would be arbitrary. `422` — *unprocessable* is
  literally what it is.

**Triples outside the patch resource and its formulae are ignored, not refused.** The
specification constrains the patch resource; it does not forbid a document from carrying
anything else, and reading a lenient silence as a `422` would refuse documents no rule condemns.
The ambiguity worth failing on is two patches, not one patch beside some noise.

**A patch with neither `solid:inserts` nor `solid:deletes` succeeds as a no-op**, answering
`204`. The specification says both are "at most one", so absent is legal, and its processing
steps then yield no change — a literal reading requires success, and this design follows it
rather than inventing a refusal.

One consequence, recorded because it is a real if harmless deviation: such a patch still passes
§9's `Append` pre-gate, so a caller holding only `Read` receives `403` for a request that would
have changed nothing. The mode mapping says a patch with no insertions and no deletions needs
no write mode at all. Keeping the gate is the trade for authorizing before parsing, and no
client sends this request.

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
5. **Check and write, as one operation.** The deletion-presence check is the `WHERE` clause of
   the write, not a query before it:

   ```sparql
   WITH <resource-iri>
   DELETE { <ground deletions> }
   INSERT { <ground insertions> }
   WHERE  { <ground deletions> }
   ```

   Every term is ground, so the pattern matches at most once. If any deletion triple is absent
   the pattern does not match and **nothing happens** — which is the `409`, decided by the store
   rather than by a prior read. An empty deletion set leaves `WHERE { }`, which matches once, so
   the insert-only shape needs no separate branch. Delete before insert, per the specification's
   step order: a patch that deletes and re-inserts the same triple must end with it present.

   Measured against `OxigraphStore`: a `WHERE` naming two triples of which one is absent leaves
   the graph byte-identical; the satisfiable version applies; `WHERE { }` inserts. Folding the
   check in this way is what closes the window a separate check leaves open — between reading
   "all present" and writing, a concurrent writer can remove one, and `DELETE DATA` would then
   silently skip it while `INSERT DATA` still ran, reporting success for a patch whose `409`
   condition held at the moment of writing.

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

**A `sparql!` macro would not cover this query, and that is worth writing down before anyone
builds one.** `2026-07-29-non-rdf-resources-design.md` §13 proposes a `sqlx::query!`-style
proc-macro that parses each query at build time with `spargebra`, and states the condition that
makes it safe: *"the SPARQL text must stay a source literal."*

Every query this pod issues today satisfies that — a fixed skeleton with values interpolated
into it. The patch `SELECT` is the first that does not. Its **graph pattern** comes from the
client's `solid:where` formula, so the query's shape exists only at runtime and no build-time
parse can reach it, by construction rather than by omission. A macro adopted later must leave
this one call site outside itself, and the danger is precisely that it would then look
covered.

What stands in for it here is the same thing that stands in for it everywhere else in this
codebase: every term is rendered through a type whose alphabet is established, every variable
name is the server's own, and §13's tests name the mutants. The failure a build-time parse
catches is a query that does not parse; the failure that matters on this path is a query that
parses and means something else, which the macro would not have caught either.

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

### 6.4 Error bodies speak the client's vocabulary

A `409` may name the triples it is about — that is most of its diagnostic value — but it names
them **de-skolemized**, through the same conversion the read path uses. A skolem IRI never
appears in a response body.

The cheapest way to get there is not to convert anything: **a message names the patch's own
patterns, not the bindings computed from them.** The client wrote `?p ex:phone "123"`, and
echoing that back says exactly which rule failed on exactly which triple, in the client's own
words. No skolem IRI can appear, because a patch document containing one was already refused
by §6.3 — so the property holds by construction rather than by remembering to convert.

Where a bound term genuinely must be shown, `Dataset::deskolemize` is the conversion: it derives
the blank node's label from the skolem IRI rather than generating one, precisely so that *"two
reads of one stored state must produce identical bytes"*, and the label it prints is therefore
the label the client already saw in its `GET` — `_:b9f3c…`, not `<urn:quadpod:bnode:9f3c…>`.

What stays forbidden is the raw form. A message assembled from the *bound* triples without that
conversion prints an IRI the server minted and the client has never seen, which is the leak
`put_impl` avoids when it counts blank-named graphs rather than naming them.

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
deletes. This is not an inference about what the suite probably wants — the fixture is
`specification-tests` v0.0.19 `web-access-control/protected-operation/write-access-bob.feature`,
and its `Examples` table says so directly:

| caller's access to the resource | awaited status |
|---|---|
| `W` | `[200, 201, 204, 205]` |
| **`A`** | **`[200, 201, 204, 205]`** |
| `C` | `[403]` |
| Public | `[401]` |

The patch those rows send is insert-only:

```
Content-Type: text/n3

@prefix solid: <http://www.w3.org/ns/solid/terms#>.
_:insert a solid:InsertDeletePatch; solid:inserts { <> a <http://example.org#Foo> . }.
```

So the `A` rows are exactly this section's tiering, and a single `Mode::Write` gate loses them.
The `C` rows are the other half: `AccessModes::allows` already grants nothing from `Control`
except ACL access, so they need no new logic — only that the patch path asks the same question
every other handler asks.

Two further things that table settles. The rows target `fictive` resources — names the suite
reserved and never created — and await `2xx`, which is §7's creation path under test rather
than under discussion. And `201`/`204` from §10.1 are both inside the awaited set, so the
success-code choice needs no revisiting.

## 10. The HTTP edge

### 10.1 Status codes in one place

| Code | Cause |
|---|---|
| `400` | No `Content-Type` at all, on a non-empty body |
| `415` | A `Content-Type` that is not `text/n3`; or no `Content-Type` on an empty body |
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

The missing-`Content-Type` split mirrors `classify_body` exactly — `400 "Content-Type is
required"` for a body with no type, `415` for an empty one. That distinction is not decorative:
`content-type-reject:19` is a patch with no `Content-Type`, and the gate that already answers
its `PUT` and `POST` siblings correctly has simply never been reachable by a patch.

### 10.2 Advertisement

- `allowed_methods` gains `PATCH` for every target it already lists, which feeds both the
  `Allow` header on `GET`/`HEAD` and the `Allow`/`Access-Control-Allow-Methods` pair on
  `OPTIONS`.
- `Accept-Patch: text/n3` is emitted where §5.3 requires it, and joins the CORS
  exposed-headers list beside `Accept-Put`'s eventual home.

### 10.3 Conditional requests

`check_conditionals` — *"RFC 9110 §13.1.1 preconditions, shared by both kinds of write"* —
already exists and is already shared. `PATCH` becomes its third caller and needs no extraction
and no new interface. It is evaluated after authorization and before any write, in the same
position `PUT` uses it.

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

**The targeted update of §6 step 5 is not a third teardown site.** `2026-07-29-non-rdf-resources-design.md`
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
   insertions did not happen**. Asserted on the stored graph, not on the status code alone —
   this is the half a status-code assertion cannot see, and it is the half §6 step 5's folded
   `WHERE` exists to guarantee. Kills a version that checks presence in a query and then writes
   with `DELETE DATA`/`INSERT DATA`, which inserts even when a deletion has gone missing in
   between.
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
    `solid:inserts`; **two patch resources** — each `422`. And the two lenient cases, which are
    the ones a fail-closed implementation gets wrong: a stray triple on an unrelated subject is
    **ignored** and the patch applies; a patch with neither insertions nor deletions succeeds
    with `204`.
11. **Anonymous.** `PATCH` without credentials → `401` with `WWW-Authenticate`, not `405`.
    This is `authentication/header:40` as a unit test.
12. **Skolem binding.** `PUT` a document containing a blank node, then patch that blank node's
    triples through a `solid:where` that pins it by another property. Must succeed. Kills the
    ordering mistake §6.3 exists to prevent — running the reserved-namespace check after
    substitution rather than before, which refuses this patch with a message naming an IRI the
    client never saw. That mutant passes every other test here, because every other test's
    fixture has no blank nodes.
13. **Error bodies name the client's own words.** Provoke a `409` against a resource holding
    blank nodes, with a patch whose deletion set is not fully present. Assert the body contains
    no `urn:quadpod:` **and** that it does name the predicate the client wrote. Both halves are
    needed: the first alone is satisfied by a message that names nothing, which §6.4 does not
    want, and the second alone is satisfied by a message that also prints the binding.

## 14. Conformance: what this moves

Against the fifth run's 66, this design accounts for every one:

| Scenarios | Expectation |
|---|---|
| 63 `protected-operation` rows | **Become reachable.** They are `retry until <expected-status>` steps awaiting `403`, `401` or `[200, 201, 204, 205]`; each of those is now a status the pod can produce. Whether they go green is what §9's tiering decides, and finding that out is the point. |
| `authentication/header:40` | **Green.** The method exists, so the auth middleware answers `401` before the method check. |
| `content-type-reject:19` | **Green.** A patch with no `Content-Type` now reaches the gate that already answers `400` for `PUT` and `POST` (§10.1). |
| `containment:38` | **Stays red**, and moves into Bucket 1 with the reason from §3: it sends `application/sparql-update`, which the Protocol does not define. |

`63 + 1 + 1 + 1 = 66`.

The 63 split by what they await, which is worth separating because the two halves test
different things:

- **The 30 `read-access-*` rows await only refusal** (`403` for a named agent, `401` for
  Public). They need the route to exist and `authorize` to run; the parse and apply machinery
  is never reached. If `PATCH` denies as `PUT` and `DELETE` already do, they pass.
- **The 33 `write-access-*` rows are mixed** — `write-access-bob` splits 6 awaiting `2xx`,
  3 awaiting `403` (`Control`), 3 awaiting `401` (Public). Only the `2xx` half exercises
  parsing, mapping and writing end to end.

The honest form of the claim: **65 of the 66 become reachable, 2 are certainly green, the
denial rows turn on `authorize` alone, and the success rows are a measurement rather than a
prediction.** They have never run against this pod, so asserting a number for them would be
inventing one — the same mistake the third run's write-up avoided when it declined to call the
unblocked WAC rows a free 540.

No test is disabled. The findings document attributes every failure to a named cause, and the
reconciliation across runs only works while nothing is switched off.

## 15. Follow-ups this design deliberately does not do

- **Patching a named graph inside a resource.** §6.2, and the sharpest consequence of this
  design: a resource `PUT` as JSON-LD with named graphs has parts no patch can reach, and the
  only repair is a whole-resource `PUT`. This is a property of N3 Patch rather than of this pod
  — no Solid server patches inside a named graph over `text/n3`, CSS included, because the
  format has no syntax for naming one.

  Two recorded routes out, neither taken here. `2026-07-28-jsonld-datasets-design.md` §11's
  per-subgraph URLs are the mechanism, and that design fixes them as *"a **view**, not a
  resource — read-only"*, so making them writable is a reopening rather than an extension. And
  `application/sparql-update` **can** name a graph, which is the one capability it offers beyond
  `containment:38` — the strongest argument on its side, and it belongs in that decision rather
  than in this one.
- **`application/sparql-update`.** §3. Its own design, with its own containment argument, if
  a caller ever needs it. See the graph-targeting point immediately above for what it would buy.
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
