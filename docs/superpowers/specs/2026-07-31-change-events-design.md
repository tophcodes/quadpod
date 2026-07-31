# Change Events on the LDP Write Path — Design

**Date:** 2026-07-31
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §41 listed
the Solid Notifications Protocol as deferred, not rejected; §257 named it as future work. This
reopens the first half of it.
**Origin:** [issue #17](https://github.com/tophcodes/sparql-pod/issues/17), under epic
[#20](https://github.com/tophcodes/sparql-pod/issues/20). What drains this bus is the subscription
API and `WebSocketChannel2023` ([#18](https://github.com/tophcodes/sparql-pod/issues/18)), then
`WebhookChannel2023` ([#19](https://github.com/tophcodes/sparql-pod/issues/19)).

## 1. What is decided

Every successful mutation on the LDP write path emits one or more change events onto an
in-process bus. An event names a topic, an ActivityStreams activity, the object the activity
concerns, an optional target, and the topic's state after the write.

Four properties are decided beyond "events exist":

- **The bus is a per-topic registry, not one broadcast channel.** A subscriber to one resource
  must not make every write anywhere in the pod compute a validator.
- **Nothing is computed for a topic nobody is listening to.** The `state` of an event is read
  only after the registry has confirmed a live channel for its topic. With no subscribers the
  write path does no extra I/O at all: every pre-write fact the mapping needs is already in
  `Guard`'s one probe (§4.3).
- **`state` is the ETag of the N-Quads representation at the held RDF version**, or the blob
  ETag for a binary resource, and it always describes the *topic* — never the `object`.
- **Emission is synchronous with the request.** The state a notification reports must be the
  state that write produced, and no other.

The bus is complete by construction: the SPARQL endpoint is internal-only (decided 2026-07-31),
so `src/http.rs` sees every change there is. No store-level change feed is needed, and none is
built.

## 2. The bus is a topic registry

The issue proposed a bare `tokio::sync::broadcast`. That is the wrong shape, for a reason that
only appears once the cost gate is written down: with one channel for the whole pod, a single
subscriber anywhere makes *every* write a candidate for state computation, and the filtering
that sorts it out happens after the cost has been paid. It is also not the shape the protocol
asks for — a notification channel has exactly one `notify:topic`, so a single firehose would
have to be re-split per channel in #18.

```rust
pub struct Bus { channels: RwLock<HashMap<Topic, broadcast::Sender<Event>>> }
```

### 2.1 `Topic` is constructible only from a `Target`

```rust
pub struct Topic(String);
impl From<&Target> for Topic { … }
```

No `From<String>`, no public field. The registry is otherwise the one place in the pod where
raw client-supplied paths live as keys, and #18 will authorize subscriptions on exactly these
keys (`acl:Read` on the topic, through the existing PDP). This is the same construction that
`space::GraphName`, `shelf::ShelfKey` and `blob::BlobKey` already use: the value is guaranteed by
how it is built rather than by a rule each call site has to remember.

`From` rather than an inherent `of`, because the conversion is total and takes one value —
which is what `From` is for. `ShelfKey::of` takes two arguments and stays as it is; a
tuple-`From` would be a constructor wearing a conversion's clothes.

### 2.2 `live` is the cost gate

```rust
impl Bus { pub fn live(&self, topics: &[Topic]) -> Vec<Topic> }
```

The emit path asks which of the topics a request touched have a live channel, and computes
`state` only for those. A `Sender` whose `receiver_count()` has fallen to zero is evicted
during that lookup; the `Receiver` `Bus::subscribe` hands out also removes its own entry when
the last one drops. Without the eviction the map grows without bound over client-chosen paths.

`Receiver` is a reader of one topic's channel and nothing else. The Solid *notification channel*
— a channel type, a `receiveFrom` or `sendTo`, an `accept`, the optional
`startAt`/`endAt`/`rate` features, and for webhooks a lifetime longer than the process — is #18's
and #19's object, and each of those holds a `Receiver` to get its events. None of that protocol
state belongs on this type, which is why it is not called `Subscription`.

Expressing the gate as "which topics are live" rather than "is anyone listening" is what makes
it checkable: `state` is computed in one place, behind one call, instead of at four sites that
each have to remember the check.

The gate is racy in one direction — a subscriber arriving between the `live` call and the
`send` misses that one event. That gap is what `notify:state` in a `SubscriptionRequest`
exists to close, and closing it is #18's business.

### 2.3 Capacity

64 events per channel. A receiver that falls behind gets `RecvError::Lagged`, which is a
receiver-side concern and therefore belongs to the channel types (#18, #19).

## 3. The event

```rust
pub enum Activity { Create, Update, Delete, Add, Remove }

pub struct Event {
    pub topic: Topic,
    pub activity: Activity,
    pub object: String,
    pub target: Option<String>,
    pub state: Option<String>,
}
```

### 3.1 No `id`, no `published`

Both are properties of a *notification*, not of a change. One bus event fans out to however
many channels are subscribed to its topic, each notification needs its own `id`, and the
protocol defines `published` as "the date and time of the notification". Both are minted when
#18 serializes. The useful side effect is that `Event` contains no clock and is comparable in a
test without a time stub.

### 3.2 `object` is not always the topic

The protocol's prose says `object` is "One `object` property to identify the (topic) resource
that the notification is about". Its own example contradicts that:

```json
{ "type": "Add",
  "object": "https://example.org/container/new-resource",
  "target": "https://example.org/container/",
  "published": "…", "state": "…" }
```

The example wins. It is the ActivityStreams semantics of `as:Add` — the actor adds the object
to the target collection — and under the prose reading `target` would have no purpose at all.

So on a container's channel, `object` is the child and `target` is the container. `state` is
unaffected by this and always describes the topic (§5.1).

A consequence worth stating plainly, because it is the thing a reader will get wrong: **the
creation of a child is not delivered to the parent's subscribers as `Create`.** They get `Add`.
`as:Create` exists only on the new resource's own channel — which, for a container this write
materialized on the way down, is a channel nobody was subscribed to unless they had subscribed
to a URL that did not exist yet. That is legitimate and is the "tell me when this appears" case.

## 4. The mapping

| Request | Events |
|---|---|
| `PUT`/`PATCH` on an existing resource | `r` → `Update` |
| `PUT`/`POST`/`PATCH` that creates | `r` → `Create`; parent `p` → `Add`(object=`r`, target=`p`) |
| containers materialized on the way | each `c` → `Create`; its parent → `Add` |
| `PUT` on an existing container | `c` → `Update` |
| `DELETE` of a resource or container | `r` → `Delete`; parent `p` → `Remove`(object=`r`, target=`p`) |
| the auxiliaries that delete took with it | each `a` → `Delete` on its own topic |
| `PUT` on an auxiliary | `a` → `Create` or `Update`, no parent event |
| `DELETE` of an auxiliary | `a` → `Delete`, no parent event |

`PATCH` appears in the creating row because `create_by_patch` exists.

A `PUT /a/b/c.ttl` onto an empty path is therefore six events: three `Create`, three `Add`.

### 4.1 A containment change is `Add`/`Remove` alone, not `Update` beside it

The issue's text gave the parent `as:Update` *plus* `as:Add`/`as:Remove`. That is one event too
many. `Add` already says the container changed, the container's new `state` rides on that same
event, and the Community Solid Server — the only Solid implementation whose behaviour can be
read — sends only the one:

```typescript
private addContainerActivity(map: ChangeMap, id: ResourceIdentifier, add: boolean, object: ResourceIdentifier): void {
  const metadata = new RepresentationMetadata({
    [SOLID_AS.activity]: add ? AS.terms.Add : AS.terms.Remove,
    [AS.object]: namedNode(object.path),
  });
  map.set(id, metadata);
}
```

Its `ChangeMap` is keyed by identifier, so it *cannot* carry two activities for one resource.
Every client written against CSS therefore already copes with `Add` alone, and none expects the
pair. That also independently confirms §3.2: the parent's `AS.object` is the child.

`Update` stays where a container's representation changes without containment changing — a `PUT`
on an existing container.

**One deliberate divergence.** A container that is created *and* gains a child in the same
request sends both `Create` and `Add`, as two events. CSS collapses them only because a map
keyed by identifier cannot hold two activities; that is an artifact of the data structure, not a
decision. This bus is keyed by (topic, activity) and has no such limit, and the two facts are
genuinely different — a "tell me when this appears" subscriber wants the `Create`.

The same source confirms the fan-out itself. `DataAccessorBasedStore::createRecursiveContainers`
accumulates every intermediate container it creates into the returned `ChangeMap`, and
`MonitoringStore` emits one event per entry over `[ AS.terms.Add, AS.terms.Create,
AS.terms.Delete, AS.terms.Remove, AS.terms.Update ]`. Reporting only the immediate parent would
have been the deviation.

### 4.2 An auxiliary has no containment to report

Not an exception to remember — `delete_impl` already states the rule it follows from: "an
auxiliary is never a container member […] so there is no containment to repair". No
containment, no `Add`/`Remove`, and no `Update` on a parent that did not change.

The cascade in the other direction is real: `aux::delete_subject` takes every auxiliary of a
deleted subject with it, so each of those is a `Delete` on its own topic. Which ones were there
needs no read: `delete_impl` already calls `Guard::authorize_aux` for every `AuxKind`, and that
method answers `Ok(None)` for an auxiliary the probe did not find.

### 4.3 Telling `Create` from `Update`

Requires knowing whether the target existed *before* the write, and that answer is already
public and already free: `Guard::target_exists()`, which reads the presence set `Guard::probe`
resolved once for the whole request. `patch_impl` uses it for its own create-vs-update branch
already.

It covers auxiliaries too, which is not obvious and is worth pinning: `probe` builds its
candidate set as every chain member, *every `AuxKind` of every chain member*, and every
slash counterpart. An `Aux` target's own presence is therefore in the set, so the mapping needs
nothing from `aux::put` — whose own `exists` call runs after the update and answers "did my
write land", not "was it there before". An auxiliary `PATCH` never creates (`aux::patch` refuses
an absent auxiliary), so it is always `Update`.

The read has to happen before `Guard::materialize`, which consumes the guard. The borrow checker
enforces that ordering rather than a rule in this document — which is the point `materialize`'s
own doc comment makes about pre-write facts.

## 5. `state`

### 5.1 The rule

`state` is the ETag of the topic's **N-Quads representation at the RDF version the stored state
holds** — `Skolemized::etag(Format::NQuads, held)`. For a binary resource it is
`blob_etag(bytes)`, the only validator such a resource has. A `Delete` carries no `state`; the
protocol makes it "zero or one".

Epic #20 already records that `state` reuses the one existing ETag rather than inventing a
second validator. This spec settles *which* of the existing tags, since a resource has one per
(format, version) pair and the protocol has room for exactly one `state`.

It always describes the topic of the channel the event runs on, never the event's `object`. The
vocabulary defines it as "The last known state of a resource (topic)", and a subscriber has to
be able to hand the value back as `notify:state` in the next `SubscriptionRequest`. A value
describing something other than the topic cannot be used that way.

### 5.2 Why a real ETag, and why that one

The protocol defines `state` only as an opaque `xsd:string` and never says it is an ETag. A
format-independent token would satisfy it. A real ETag satisfies it *and* is usable as an
`If-Match` value, because `check_conditionals` matches `If-Match` against every current
representation rather than against one selected tag (RFC 9110 §13.1.1). A subscriber that
received an N-Quads tag can therefore use it to guard a Turtle write. The format-independent
token buys nothing in exchange for giving that up.

That the guard is currently racy — the precondition read and the write are two store calls — is
#10, and it is not made better or worse here. The claim is only that a `state` value is accepted
where an `If-Match` value is accepted.

It does not cause the mirror-image problem on reads: `get_impl` compares `If-None-Match` against
the *served* tag only, so an N-Quads tag presented on a Turtle `GET` does not produce a spurious
`304`.

**The format has to carry datasets.** `Skolemized::etag` hashes every stored quad, named graphs
included, but a Turtle or N-Triples representation cannot show them — so a graph format's tag
changes on changes its own representation does not have. RFC 9110 §8.8.1 permits that ("A strong
validator might change for reasons other than a change to the representation data") while asking
a server not to do it. N-Quads, TriG and JSON-LD all carry datasets and are exact here.

**The format has to have an RDF 1.2 syntax**, which is what rules JSON-LD out. The RDF & SPARQL
WG's deliverables cover Turtle, TriG, N-Triples, N-Quads and XML; JSON-LD belongs to a different
group, and JSON-LD 1.1 (2020) has no syntax for triple terms. `Skolemized::etag(Format::JsonLd,
Rdf12)` would name a representation that cannot exist — the same defect this section rejects the
1.1 tag for one paragraph down.

**N-Quads over TriG**, because it is the format the hash already agrees with. `Skolemized::etag`
does not serialize: it renders each stored quad through oxigraph's `Display`, which is N-Quads,
sorts the lines and hashes them. The format argument is a keying line, not a serializer. Naming
N-Quads makes the label describe what is underneath it rather than merely distinguishing it.
Nothing a human reads is affected either way — `state` is an opaque hash, and no document in
either syntax is ever produced because of this choice.

**The version has to be the held one, not 1.1.** `etag_candidates` produces a tag per (format,
version) pair, and two RDF 1.2 states differing only in triple terms share a 1.1 projection and
therefore a 1.1 tag. With 1.1 as `state`, a real change would report no change — in the one
field a subscriber uses to detect change.

The cost of that is worth naming: on a resource holding 1.2 content, `state` is *not* the tag an
ordinary `GET` returns. `negotiate` reads an `Accept` without a `version` parameter as `Rdf11`
and `get_impl` serves `requested.min(held)`, so a plain N-Quads read of a 1.2 resource is
answered at 1.1, with a different tag. Only `Accept: application/n-quads;version=1.2` returns
the value `state` carries. Both tags are in `etag_candidates`, so `If-Match` takes either.

### 5.3 One tag per representation is not reopened

Sharing a single ETag across formats and leaning on `Vary: Accept` was considered and refused.
RFC 9110 §8.8.1 defines a strong validator as metadata that "changes value whenever a change
occurs to the representation data that would be observable in the content of a 200 (OK) response
to GET", and permits two representations to share one only "if they differ only in the
representation metadata […] the same representation data". Turtle bytes and JSON-LD bytes are
not the same representation data. A shared tag would have to be marked weak, and `If-Match`
requires strong comparison — the pod's lost-update protection would go with it.

`Vary: Accept` does not rescue it. Vary tells a cache how to key its stored variants; it does
not stop a validator obtained from one variant being presented on a request for another. In this
code that is concrete: `GET` as Turtle yields `"abc"`, then `GET` with
`Accept: application/ld+json` and `If-None-Match: "abc"` is compared against the served JSON-LD
tag, and a shared value answers `304` for a variant the client does not hold.

This was already decided in [2026-07-28-jsonld-datasets-design.md](2026-07-28-jsonld-datasets-design.md) §6.4
and is recorded here only so the question is not asked a third time.

### 5.4 Computed from the stored state, after the write

Never from the request body. The container `PUT` path merges existing `ldp:contains` back in and
`ensure_container` re-asserts the type triples afterwards (`put_impl`'s `Target::Container` arm),
so what is stored is not what was sent; a tag derived from the body would name a representation
that never existed.
Reading it back is also unavoidable for two cases regardless: after `add_containment` the handler
does not hold the parent's full triple set, and the graph a `PATCH` produces "never exists as a
`Dataset` in this process" (`patch_shape_conflict`).

## 6. Where it is emitted

### 6.1 `Guard::materialize` stops discarding its plan

Its signature becomes `Result<Materialized, Response>`. `Materialized` carries the two lists the
method already builds and drops on the floor — `creations` (what this write brings into
existence) and `plan` (which container is ensured, and which child is linked into it).

The existence answer is *not* part of it: `Guard::target_exists()` already gives that, and
`materialize` takes `self`, so a caller has to read it beforehand anyway. Folding it into the
return value would be a second way to ask one question.

Nothing new is derived. Reconstructing the ancestor set at the HTTP layer would be a second
multi-hop walk, which the constraint "`ResourceUrl::ancestors` is the only multi-hop walk up the
container chain" exists to prevent; this is the same walk, no longer thrown away.

`Materialized` holds URLs and IRIs, no store, so the WAC rule "the guard names the store exactly
twice" is untouched.

### 6.2 One call per handler

`notify::emit_put`, `emit_post`, `emit_patch`, `emit_delete`, each called exactly once at the
tail of the corresponding `*_impl`, each returning immediately unless `res.status().is_success()`.
That is the cut `put_impl`'s tail already makes for the shape report
(`if findings.is_some() && res.status().is_success()`), not a new pattern.

Emitting at each success site instead would be fifteen places to forget, in a file of nearly
seven thousand lines, where a future write path compiles silently without an event.

### 6.3 The blob arm has to stop returning early

`put_impl`'s `Repr::Blob` branch is a `return match put_blob(…)` — a *successful*
early exit that bypasses the tail. It becomes a value flowing into `res`, or every binary write
emits nothing. This is the only place #17 changes existing control flow.

## 7. Synchronous by design

`broadcast::Sender::send` is not an `async fn`: it writes into a ring buffer and wakes receivers
without yielding, and overwrites the oldest entry when full rather than applying backpressure. A
slow subscriber cannot stall the write path. The registry lookup takes an uncontended read lock
for nanoseconds and nothing is held across an await.

The one real cost is the `state` read-back, and it is not moved off the request path. Under two
rapid writes to one resource, two spawned emit tasks would both read after the second write and
report the same newest `state`; the first event would then claim a state that never existed at
its own moment — in the one field subscribers use to detect change. Slow beats wrong. Spawning
would not remove the read-back either, only misplace it: §5.4 shows it is unavoidable for
`PATCH` and for parent containers.

Nor does the read-back occupy a Tokio worker. `OxigraphStore::blocking` already offloads every
evaluation to the blocking pool, so the cost is a round-trip on that pool and a delayed response
for the writing client — not a stall of requests that never touched this topic.

The asynchronous boundary is at the receiver, which is where the expensive work of the channel
types lives — WebSocket frames in #18, webhook `POST`s and retries in #19 — behind `recv()` in
its own task.

If a hot watched resource ever makes the read-back measurable, the resource `PUT` path holds the
written state as `skolemized` and `Skolemized::etag` is a pure function over it, so that case can
be made I/O-free. It is not done now: it would be a second way to derive `state`, which is what
the one-ETag constraint exists against, and there is no measurement asking for it.

## 8. Errors and known limits

- A `send` with no receivers is the normal case, not an error.
- If the `state` read-back fails, the event goes out with `state: None`. A successful write must
  not become a `500` because a notification could not be decorated, and the protocol makes
  `state` optional.
- `std::sync::RwLock`, with no `.await` under the lock.
- The container `PUT` path writes `put_rdf` and `ensure_container` as two operations; if the
  second fails there is a partial write and no event. That is the non-atomicity already
  documented in `put_impl`'s `Target::Container` arm, not something introduced here.

## 9. Tests

One per method: subscribe to the topic, issue the request, assert `activity`, `object`, `target`
and `state`. Beyond those, four that can actually fail:

- The `state` in the event is byte-identical to the `ETag` of an immediately following `GET` with
  `Accept: application/n-quads;version=1.2`. Written against a resource that actually holds 1.2
  content, with a sibling asserting that the same read *without* the `version` parameter returns
  a **different** tag. Without that pair the test passes trivially on a 1.1 resource, where the
  two are the same value, and the version half of §5.2 goes unchecked.
- Fan-out: `PUT /a/b/c.ttl` onto an empty path; a subscriber on `/` receives exactly one event,
  `Add`(object=`/a/`) — no `Update` beside it (§4.1) and no `Create` for `/a/b/` (§3.2).
- No subscriber ⇒ no `state`: demonstrated with a query counter, not with "it did not crash". A
  test that cannot go red is the mistake `docs/constraints.md` opens by warning about.

  The harness already exists. `tests/call_budget.rs` holds `CountingStore`, a decorator that
  forwards every `SparqlStore` call and tallies it, and its own header states why it lives in
  `tests/`: `docs/constraints.md` pins `SparqlStore` to one implementor *under `src/`*, and that
  rule is about a backend carrying ADR-2's atomicity obligation rather than about a decorator.
  Its fixture needs no authentication either — the root ACL there grants `foaf:Agent` everything.

  Better still, the budgets in that file are the test. They are upper bounds on the store calls
  one request costs, asserted with no subscriber present. Any unconditional I/O this feature adds
  to the write path breaks `a_put_on_an_existing_resource_stays_within_budget` or
  `PUT_DEEP_BUDGET` without a line being written for it. The change events add one case: subscribe
  to a topic, repeat the same request, and assert the count *rises* — which is what proves the
  gate is a gate rather than a dead branch.
- A binary `PUT` emits — the regression test for §6.3.

## 10. Out of scope

No persistence, no delivery guarantees, no `Lagged` handling, no subscription endpoint, no
ActivityStreams JSON-LD serialization, no authorization of subscriptions. All of that is #18;
`Topic` is only the place where #18 can attach it. Persistence and outbound delivery are #19's.

`ETag` on write responses is not part of this. RFC 9110 §9.3.4 forbids a validator on a
successful `PUT` "unless the request's representation data was saved without any transformation
applied to the content", which the container `PUT` path violates by design, so it is a decision
of its own rather than a line added here.

## 11. Deltas against documents already in force

- **[2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §41** listed the
  Solid Notifications Protocol as out of scope. This lifts that for the change-event layer only;
  the protocol surface stays out until #18.
- **`wac::guard::Guard::materialize`** changes signature from `Result<(), Response>` to
  `Result<Materialized, Response>`. No behavioural change; the value returned is what the method
  already computed and discarded. `Materialized` holds no store, so the WAC rule "the guard names
  the store exactly twice" stays green.
- **`src/http.rs`** gains one emit call per write handler and loses one early `return` (§6.3).
- **`AppState`** gains `pub events: Arc<Bus>`.
- **`tests/call_budget.rs`** gains the no-subscriber and one-subscriber cases (§9). Its existing
  budgets already assert the no-cost property; nothing in `src/` changes for it.
- **`docs/constraints.md`** gains three rules, each demonstrated red against a real violation
  before being added:
  1. Every write-path `*_impl` has exactly one `notify::emit_*` call.
  2. `Format::NQuads` appears as an ETag argument only in `notify.rs`, so the `state` rule cannot
     acquire a second deriver.
  3. `Topic` is built only through `From<&Target>`.
