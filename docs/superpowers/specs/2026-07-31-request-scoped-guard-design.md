# One probe per request — the guard as a stateful enforcement point

**Date:** 2026-07-31
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §6, §8, §16 ADR-1, ADR-2
**Origin:** [2026-07-26-wac-enforcement-design.md](2026-07-26-wac-enforcement-design.md) fixed *what* the
guard decides and in *what order* it may disclose. It said nothing about how many times it asks
the store, and the answer turns out to be quadratic in path depth.

## 1. What is decided

The LDP door's WAC enforcement point becomes a value. `wac::Guard` is constructed once per request from
the store, the agent and the target; it resolves every existence fact the request needs in
**one** store query and the chain's ACLs in one more; and `authorize` becomes a synchronous
method on it that cannot reach the store at all.

Four properties are decided beyond "it is faster":

- **One probe, one derivation.** The set of facts a request needs is a pure function of its
  target. It is computed once, in one place, and answered in one round trip.
- **`authorize` loses its store parameter.** After construction there is no `&dyn SparqlStore`
  in scope for the decision path, so a second resolution is not something a future edit has to
  remember not to write — it is something it cannot write.
- **`materialize` consumes the guard.** The probe describes the store *before* the request
  writes to it. Taking `self` makes the stale window uninhabitable rather than commented.
- **The cost is pinned by a test, not by intent.** A counting store and per-method call budgets
  land *before* the refactor, so the improvement is measured rather than asserted, and the
  regression is caught by CI rather than by a later reader counting `format!` calls.

**The guard is the LDP door's enforcement point, not the only one there will be.** Root spec §8
requires one authorization core shared by every front door, and §11 keeps a `/sparql` read proxy
as a seam whose enforcement is *"scope the query to the agent's readable graph set"* — a
set-valued question that no single-target API can answer. The core §8 shares is one layer below
this type: `pdp::decide` and the ACL resolution, both of which the guard *uses* rather than
replaces. A second door builds its own projection on the same two pieces. Nothing here forecloses
it, and nothing here should be stretched to serve it.

Explicitly **not** decided here: any cache that outlives a request, and any change to
`SparqlStore`. Both are §10.

## 2. The shape of the waste

Let the target sit at depth *d* and let the governing ACL sit *k* levels above it (*k* = 0 when
the resource has its own).

`prp::effective_acl` costs *k* + 1 `ASK`s to find the ACL, then `resource::get_rdf` costs two
more — one `ASK` for the presence marker and one `CONSTRUCT` for the triples — because
`get_rdf` re-runs the existence check its caller has just run (`resource.rs:620`). So a single
`authorize` is *k* + 3 queries, of which exactly one carries data.

`guard::authorize_and_materialize` then calls `authorize` once per level it walks
(`guard.rs:248`), and each of those calls starts its own walk from that level. The chains are
nested — the ACL candidates for `/a/b/` are a suffix of those for `/a/b/c` — so every level
re-asks a question an earlier level already answered. Around that sit `resource::exists` for
the target, one per ancestor, one per created URL for the trailing-slash rule
(`guard::refuse_slash_pair`), and one more for an auxiliary's subject.

A `PUT /a/b/c` into an empty pod governed by `/.acl` spends roughly *d²*/2 queries before it
writes anything, and every one of them is a fresh `format!`ed string the store parses from
scratch. On the read path the same shape appears smaller but not differently: a `GET` pays
*k* + 3 for the decision and then `get_rdf` pays the duplicate existence check a second time
for the content itself.

None of this is wrong. It is the cost of deriving the same nested chain repeatedly, from a
layer that has no memory.

## 3. Every request is one chain

The premise the whole design rests on: a request touches exactly one path chain, and that chain
is derivable from the target before anything else happens.

LDP gives each request exactly one target URL. Everything the guard consults is derived from
it — never chosen:

| Consulted | Derived from |
|---|---|
| the containers above the target | `ResourceUrl::ancestors` |
| the ACL of each of those, and of the target | `ResourceUrl::aux(AuxKind::Acl)` |
| the trailing-slash counterpart of each URL a write would create | `ResourceUrl::slash_counterpart` |
| an auxiliary's subject | `AuxUrl::subject` |

The three handlers that look like exceptions are not. `DELETE` additionally authorizes the
parent container (`http.rs:1928`) and every existing auxiliary of the subject
(`http.rs:1950`) — both inside the chain. `POST` authorizes the container and then the child
(`http.rs:1382`, `http.rs:1434`); the child is one level below the container, and its name is
server-minted, so its non-existence is known without asking. A `PUT` to an auxiliary computes
from its subject.

**`POST` is the one method that builds two guards, and it has to.** Its second target does not
exist until its first authorization has passed: the container is authorized before the child's
name is minted, precisely so that nothing — not even the name-collision check — answers ahead of
the guard (`http.rs:1337`'s comment). So `post_impl` probes the container, authorizes `Append`,
settles the name, then probes the child. The child's chain is the container's chain plus one
element, so the second probe is one more query, not another ladder. Two guards, still one chain.

The child probe also absorbs `name_is_taken`: "is this name free" is the presence question the
probe already answers, and reading it from the guard removes two store calls rather than adding
one. A collision costs a third probe, which is what a collision is worth.

That question is **one** method, `is_taken`, and not two accessors the caller composes. The
answer turns on two probed facts — the URL itself, and the trailing-slash counterpart Protocol
§3.1 forbids from coexisting with it — and a guard that handed both out separately would put the
§3.1 rule in the handler, where `http.rs` would then carry a piece of LDP semantics that
`name_is_taken` used to own. The guard answers questions; it does not publish facts for callers
to reassemble into rules.

The name is deliberately present-tense. An earlier draft called the own-existence half `existed`,
past tense, to mark that it describes the store before the request wrote to it — but that is true
of *every* answer this type gives, which is what consuming `self` in `materialize` enforces. A
tense that belongs to the type reads as noise on one method and is missed on all the others.

This is what makes a single probe complete rather than merely helpful. It is not an
optimization that happens to work today: it is a consequence of LDP addressing one resource per
request, and a handler that broke it would have no way to express itself through the API in §5.

## 4. The probe

`resource` gains one function:

```rust
pub async fn exists_many(
    store: &dyn SparqlStore,
    graphs: &[&dyn GraphName],
) -> Result<HashSet<String>, ResourceError>
```

It renders one `SELECT` over a `VALUES` block pairing each candidate's system graph with its
own IRI, and returns the subset that carries a presence marker:

```sparql
SELECT ?g WHERE {
  VALUES (?sys ?g) { (<urn:quadpod:sys:https://pod.toph.so/a/b/c> <https://pod.toph.so/a/b/c>) … }
  GRAPH ?sys { ?g <urn:quadpod:sys#present> true }
}
```

It lives in `resource` because the system-graph IRI is `resource`'s to build and nobody else's
(`constraints.md`, *"Only `resource` builds a system-graph IRI"*). `exists` stays, expressed as
the one-element case, so the two cannot answer differently.

`GraphName` is object-safe — one `&self` method returning `&str` — so the slice takes `&dyn
GraphName` and the seal keeps its meaning: only types minted through `StorageSpace::resolve`
reach the interpolation site.

**The probe set is unconditional.** It covers the target, its ancestors, the ACL of each, and
the slash counterpart of each, whether or not this particular method will consult all of them.
A read path does not need the counterparts. Asking for them anyway costs bytes in one query
rather than a round trip, and a probe set that varies by method is a second derivation of §3's
table — the exact thing this design exists to remove.

## 5. `Guard`

```rust
impl Guard {
    async fn probe(store: &dyn SparqlStore, agent: Agent, target: Target) -> Result<Self, Response>;

    fn authorize(&self, mode: Mode) -> Result<Decision, Response>;
    fn authorize_parent(&self, mode: Mode) -> Result<Decision, Response>;
    fn authorize_aux(&self, kind: AuxKind) -> Result<Decision, Response>;

    fn is_taken(&self) -> bool;
    fn deny(&self) -> Response;
    async fn materialize(self) -> Result<(), Response>;
}
```

`authorize` takes no target. There is one per request and the guard owns it; the two variants
name the only other things §3 permits a handler to ask about. A handler cannot construct a
`Target` of its own and have it authorized, because no method accepts one.

**The three decision methods are synchronous and take no store.** They read the probed presence
set and the ACL triples the guard already holds, and hand them to `pdp::decide`, which is a pure
function over ACL triples (ADR-1). The claim in `guard::authorize`'s current doc comment — that
resolving the ACL twice would repeat the ancestor walk and could straddle a concurrent
write — stops being a warning and becomes a property of the signatures.

**The guard holds only what the target implies:** store, agent, target, the probed presence set,
and the ACL triples it loaded. Not `AppState`, not the blob store, not headers, not the request
body. Without that line it becomes the place everything per-request accumulates, and an
enforcement point that holds the request body is no longer an enforcement point.

**The chain's ACL triples are read eagerly, in one query.** `prp::load_chain_acls` takes the
probe's presence set and fetches every ACL the chain actually has, keyed by the IRI it governs;
choosing which one governs a given level is then a lookup in that map.

Eager rather than lazy, and the skeleton is what settled it: a lazy per-level fetch needs an
`await` at the moment a level is decided, and there is none left — `authorize` is synchronous,
which is the property the whole design is for. Laziness and a store-free decision cannot both
hold, and the decision is the one worth keeping.

What eagerness costs is reading an ACL that no level ends up consulting. That is bounded by the
chain, it is one query either way, and in the ordinary case the chain holds exactly one ACL
document. It buys back the memo, the interior mutability a memo behind `&self` would need, and
the ordering question of which level warms it.

Total for the authorization of a deep create: **two queries** — the presence probe and the ACL
read — against roughly *d*²/2 today.

## 6. Before and after the write

The probe describes the store as it was when the guard was built. `materialize` is the moment
that stops being true, so it takes `self`:

```rust
async fn materialize(self) -> Result<(), Response>;
```

After it returns, the guard does not exist, and nothing can read a stale answer from it because
there is nothing left to read from. Any pre-write fact a handler still wants is read from
`existed()` **before** the call — which is a borrow the compiler orders, not a rule anyone has
to remember.

An earlier draft had `materialize` return a `Created { target_existed }`, on the belief that
`put_impl` chose `201` over `204` by reading the same snapshot a second time. It does not:
`created()` (`http.rs:405`) answers `201` unconditionally on every successful `PUT`, so there is
no such choice and no consumer for the value. The type is dropped rather than kept for a caller
that does not exist. Whether that unconditional `201` is itself correct is a separate question
and deliberately not this design's — see §10.

The internal ordering of `materialize` is unchanged. It still decides the whole plan before
writing any of it, for the reason `authorize_and_materialize`'s doc comment gives: a denial
halfway up must leave the store as it found it. What changes is that the decision half no longer
touches the store, so "decide everything, then write" is now visible in the types rather than
maintained by two loops that happen to agree.

Handlers that ask the store *after* the write — container emptiness, ETag re-reads, the shelf
list — ask it directly, as they do now. The guard is not a general request cache and answers no
question it did not probe for.

## 7. Knowing early is not answering early

`2026-07-26-wac-enforcement-design.md` requires the `PUT` exists-vs-new distinction to run
*after* authorization, so that no refusal reveals whether a resource exists. `guard.rs` applies
the same rule twice more: `refuse_slash_pair` and the auxiliary-subject check are both
deliberately ordered after the whole chain is authorized.

The probe inverts the acquisition order — the guard learns all of it before deciding anything.
That is safe, and the reason is worth stating precisely, because it is the one place this design
could go quietly wrong: **disclosure is a property of the response, not of the query.** A fact
the pod holds in memory discloses nothing; a status code that varies with it discloses
everything.

So the rule the implementation carries is a rule about ordering *refusals*, unchanged in
substance:

- Every refusal that reads a probed existence fact — `409` for a slash pair, `404` for a missing
  auxiliary subject — is produced after the corresponding `authorize` has returned `Ok`.
- `Guard::probe` itself refuses nothing. Its only failure is a store error, which is a `500`
  regardless of what exists.
- `is_taken()` refuses nothing on its own — it answers from probed facts, and its one caller
  reads it after `authorize` has returned `Ok`. That ordering is a discipline, exactly as it is
  today for the `name_is_taken` lookup it replaces; what changes is that the answer is free, not
  that the rule is new.

The existing tests that pin this ordering (`materialization_is_authorized_at_every_level_it_writes`,
the ACL-oracle tests in `http.rs`) are the regression check, and they must pass unchanged. Any
edit that makes them pass only after being rewritten is the failure mode this section names.

## 8. Measuring

A counting store lands **first**, in `tests/`:

```rust
struct CountingStore { inner: Arc<dyn SparqlStore>, counts: Mutex<Counts> }
```

It delegates every method and tallies calls by kind. It lives in `tests/` rather than `src/`
because `constraints.md` pins `SparqlStore` to exactly one implementor by counting `impl`
blocks under `src/`, and that rule is about backends carrying ADR-2's atomicity obligation — a
decorator that forwards is not a second backend, but the check cannot tell, and weakening it to
allow `#[cfg(test)]` would weaken it against a real second backend too. `AppState` and `router`
are already `pub`, so an integration test builds the app around the decorator without any new
seam in `src/`.

A new `tests/call_budget.rs` then drives the router over the authorized happy paths and asserts
an upper bound per method — `GET`, `PUT` over an existing resource, `PUT` creating a chain three
deep, `POST`, `DELETE`, `PATCH`. The assertions are `<=`, not `==`: a budget that fails when
the count drops is a budget that punishes improvement.

Order matters. The budgets are committed against **today's** counts, then tightened in the same
commit that makes them true. That way the numbers in this document are measured rather than
estimated, and the diff shows the improvement instead of claiming it.

## 9. What is checked

`docs/constraints.md` gains one rule:

> The guard names the store exactly twice: the field it holds and the probe that fills it.
>     check: `[ "$(rg -o 'dyn SparqlStore' src/wac/guard.rs | wc -l)" = 2 ]`

Restoring a store parameter to any of the three decision methods makes it three, and that is the
failure this whole design is built to prevent. Anchoring on the count rather than on a regex over
one signature is the shape *"`space::GraphName` stays sealed"* already uses: it pins the
declaration, so it cannot be satisfied by a method spelled differently. It must be demonstrated
red against a real edit before the rule is added, per the file's own standard.

The tests inside `guard.rs` construct `OxigraphStore` by its concrete type and so do not
contribute to the count — which is also why the rule reads `src/wac/guard.rs` rather than `src`.

The call budgets in §8 are the second check, and they are ordinary tests rather than a
`constraints.md` rule: they are about a quantity that is expected to keep improving, not about a
property that must stay exactly true.

No existing rule changes. The `SparqlStore`-has-one-implementor check stays as it is, which is
§8's reason for putting the decorator in `tests/`.

## 10. Out of scope

- **Any cache outliving a request.** An ACL decision cache is the largest remaining win and the
  one with a correctness failure mode: a stale grant is an authorization defect, not a slow
  response. It needs invalidation designed against the write paths, and it needs the call
  budgets from §8 to show it is worth the risk. Separate spec.
- **Prepared statements.** Every query is still a `format!`ed string the store re-parses. Fixing
  that means adding a shape to `SparqlStore`, which ADR-2 makes a load-bearing contract, and §5
  removes so many calls that the per-call parse cost is a different question afterwards than it
  is now. Revisit against measurements, not before.
- **`get_rdf`'s duplicate existence check** (`resource.rs:620`). It asks the store whether the
  graph is present and then reads it, which is one call more than a caller who already knows.
  Removing it means either a second entry point that skips the check — a way to read a graph
  without establishing it exists, which is the shape this codebase spent Plan 7 making
  unrepresentable — or folding presence and content into one query, which is its own design. An
  earlier draft of this section claimed it disappeared for free as a consequence of §4. It does
  not: §4 batches the *guard's* existence questions and never touches `get_rdf`.
- **`PUT` answering `201` unconditionally.** `created()` (`http.rs:405`) never answers `204` for
  an overwrite. That is a protocol question, not a cost one, and fixing it here would smuggle a
  behaviour change into a refactor whose whole claim is that behaviour is unchanged.
- **The read path's remaining queries.** Content, shelves and conditional requests are work, not
  overhead.
- **`ensure_container` / `add_containment` as separate updates.** Two updates per created level
  where one `;`-sequence would do. Real, small, and independent of everything above — an issue,
  not part of this.

## 11. Deltas against documents already in force

**§4 is a restoration, not a change.** Root spec §8 describes the PRP as *"a **SPARQL query**
against the same store"*, singular, and §6's box reads *"PRP: fetch ACL graph — BUILD (SPARQL
query + container walk)"*. The implementation turned that one query into one `ASK` per level and
then repeated the whole ladder per level. `exists_many` is what §8 already said. No record needs
amending; the code was the thing that had drifted.

`2026-07-26-wac-enforcement-design.md` states that the exists-vs-new distinction for `PUT`
"requires one store lookup" running after authorization. After §6 it requires none: the fact is
already probed, and the ordering requirement it was protecting is restated in §7 as a rule about
refusals rather than about lookups. The clause is corrected in place.

The doc comment on `guard::authorize` justifies returning `Decision` from the same resolution
rather than a second lookup. That reasoning is unchanged and now enforced by §9's check rather
than by the comment.

No decision recorded elsewhere is reversed or narrowed.
