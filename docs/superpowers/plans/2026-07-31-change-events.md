# Change Events on the LDP Write Path — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every successful mutation on the LDP write path publishes ActivityStreams change events onto an in-process, per-topic bus, so the channel types in #18 and #19 have something to drain.

**Architecture:** `src/notify.rs` holds a registry of `broadcast::Sender`s keyed by `Topic`. Four `emit_*` functions, one per write method, are called once each at the tail of the corresponding `*_impl` in `src/http.rs`. Nothing computes a `state` for a topic with no live channel, so a pod with no subscribers does exactly the I/O it does today.

**Tech Stack:** Rust 2021, axum 0.8, tokio 1.53 (`sync::broadcast`), oxigraph 0.5.9.

**Spec:** [`docs/superpowers/specs/2026-07-31-change-events-design.md`](../specs/2026-07-31-change-events-design.md). Issue [#17](https://github.com/tophcodes/sparql-pod/issues/17), under epic #20.

## Global Constraints

- **The skeleton's signatures are given.** `src/notify.rs` and `wac::guard::Materialized` already exist with their public API fixed (commits `4415225`, `afebaf9`). Tasks fill bodies. **No new public functions, no new modules, no changed public signatures.** Two visibility widenings are explicitly permitted and named in Task 3.
- **Build and test through the flake:** `nix develop -c cargo build`, `nix develop -c cargo test`. A bare `cargo` fails on `openssl-sys`.
- **`arch-check` must be green after every task.** Run it; 25 rules today, 0 violated, 0 broken.
- **No `#[allow]` attributes anywhere in `src/`** — pinned by `docs/constraints.md`. If a lint fires, fix the code.
- **`state` is `Skolemized::etag(Format::NQuads, held)`**, or `blob_etag(bytes)` for a binary resource, and it always describes the event's **topic**, never its `object`. `Delete` carries no `state`.
- **A containment change is `Add`/`Remove` alone** — never an `Update` beside it.
- **Done means no `todo!("skeleton")` and no `// skeleton:` left in `src/`.** Task 8 asserts it.
- Commit after every task. Conventional commits, concise subject.

---

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `src/notify.rs` | The registry, the event type, the four emit functions, and their unit tests | 1, 3, 4, 5, 6, 7 |
| `src/wac/guard.rs` | `Guard::materialize` hands back what it built instead of discarding it | 2 |
| `src/http.rs` | One `emit_*` call per write handler; two helpers widened to `pub(crate)`; `Fixture` keeps the bus | 3, 4, 5, 6, 7 |
| `tests/call_budget.rs` | The no-subscriber / one-subscriber cost cases | 8 |
| `docs/constraints.md` | Three new rules, each demonstrated red first | 8 |

---

### Task 1: The registry — `Topic`, `Bus`, `Receiver`

**Files:**
- Modify: `src/notify.rs` (fill `Topic::from`, `Topic::as_str`, `Bus::live`, `Bus::publish`, `Bus::subscribe`, `Receiver::recv`, `Drop for Receiver`; add a `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `crate::space::{StorageSpace, Target}`, `Target::graph_iri()`.
- Produces: `Topic: From<&Target> + Clone + Eq + Hash`; `Bus::live(&self, &[Topic]) -> Vec<Topic>`; `Bus::publish(&self, Event)`; `Bus::subscribe(self: &Arc<Bus>, Topic) -> Receiver`; `Receiver::recv(&mut self) -> Result<Event, broadcast::error::RecvError>`. Tasks 4–7 use `live` and `publish`; Task 8 uses `subscribe`.

- [ ] **Step 1: Write the failing tests**

Append to `src/notify.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::StorageSpace;

    fn target(path: &str) -> Target {
        StorageSpace::new("https://pod.toph.so/").unwrap().resolve(path).unwrap()
    }

    #[test]
    fn a_topic_is_the_targets_graph_iri() {
        let t = target("/notes");
        assert_eq!(Topic::from(&t).as_str(), t.graph_iri());
    }

    #[test]
    fn an_unwatched_topic_is_not_live() {
        let bus = Arc::new(Bus::new());
        assert!(bus.live(&[Topic::from(&target("/notes"))]).is_empty());
    }

    #[test]
    fn a_watched_topic_is_live_and_only_that_one() {
        let bus = Arc::new(Bus::new());
        let watched = Topic::from(&target("/notes"));
        let other = Topic::from(&target("/other"));
        let _rx = bus.subscribe(watched.clone());
        assert_eq!(bus.live(&[watched.clone(), other]), vec![watched]);
    }

    #[test]
    fn dropping_the_last_receiver_unregisters_the_channel() {
        let bus = Arc::new(Bus::new());
        let topic = Topic::from(&target("/notes"));
        drop(bus.subscribe(topic.clone()));
        assert!(bus.live(&[topic]).is_empty(), "a dropped receiver must leave no entry behind");
        assert_eq!(bus.channels.read().unwrap().len(), 0, "and no empty sender either");
    }

    #[tokio::test]
    async fn publish_reaches_the_receiver_of_that_topic() {
        let bus = Arc::new(Bus::new());
        let topic = Topic::from(&target("/notes"));
        let mut rx = bus.subscribe(topic.clone());
        bus.publish(Event {
            topic: topic.clone(),
            activity: Activity::Update,
            object: topic.as_str().to_owned(),
            target: None,
            state: Some("\"abc\"".to_owned()),
        });
        let got = rx.recv().await.unwrap();
        assert_eq!(got.activity, Activity::Update);
        assert_eq!(got.state.as_deref(), Some("\"abc\""));
    }

    /// Publishing must not be what creates a channel — otherwise the registry
    /// fills up with every topic ever written to, which is the unbounded growth
    /// `live`'s eviction exists to prevent.
    #[tokio::test]
    async fn publishing_to_an_unwatched_topic_creates_no_channel() {
        let bus = Arc::new(Bus::new());
        let topic = Topic::from(&target("/notes"));
        bus.publish(Event {
            topic: topic.clone(), activity: Activity::Delete,
            object: "x".to_owned(), target: None, state: None,
        });
        assert_eq!(bus.channels.read().unwrap().len(), 0,
            "publish must not register a topic nobody asked for");
        assert!(bus.live(&[topic]).is_empty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib notify::`
Expected: FAIL — every test panics at `not yet implemented: skeleton`.

- [ ] **Step 3: Fill the bodies**

In `src/notify.rs`, replace the seven `todo!("skeleton")` bodies:

```rust
impl From<&Target> for Topic {
    fn from(target: &Target) -> Self {
        Self(target.graph_iri().to_owned())
    }
}

impl Topic {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

```rust
    pub fn live(&self, topics: &[Topic]) -> Vec<Topic> {
        let mut channels = self.channels.write().expect("the bus lock is never held across a panic");
        topics.iter().filter(|t| {
            match channels.get(*t) {
                // A sender whose last receiver went away is evicted here rather
                // than left to accumulate: the key space is client-chosen.
                Some(tx) if tx.receiver_count() == 0 => { channels.remove(*t); false }
                Some(_) => true,
                None => false,
            }
        }).cloned().collect()
    }

    pub fn publish(&self, event: Event) {
        let channels = self.channels.read().expect("the bus lock is never held across a panic");
        if let Some(tx) = channels.get(&event.topic) {
            // `send` fails only when there is no receiver left, which is the
            // normal case rather than an error.
            let _ = tx.send(event);
        }
    }

    pub fn subscribe(self: &Arc<Self>, topic: Topic) -> Receiver {
        let mut channels = self.channels.write().expect("the bus lock is never held across a panic");
        let tx = channels
            .entry(topic.clone())
            .or_insert_with(|| broadcast::channel(CAPACITY).0);
        Receiver { rx: tx.subscribe(), bus: Arc::clone(self), topic }
    }
```

Add above `impl Bus`:

```rust
/// Events buffered per channel before a slow reader starts losing them to
/// `RecvError::Lagged`. Handling that loss is the channel type's business
/// (#18, #19), not this bus's.
const CAPACITY: usize = 64;
```

Rename `Receiver`'s fields from `_bus`/`_topic`/`_rx` to `bus`/`topic`/`rx`, and:

```rust
impl Receiver {
    pub async fn recv(&mut self) -> Result<Event, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let mut channels = self.bus.channels.write().expect("the bus lock is never held across a panic");
        // `self.rx` is still alive here, so the count includes it: 1 means this
        // was the last reader.
        if channels.get(&self.topic).is_some_and(|tx| tx.receiver_count() <= 1) {
            channels.remove(&self.topic);
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib notify::`
Expected: PASS, 6 tests.

- [ ] **Step 5: Run the whole suite and the constraints**

Run: `nix develop -c cargo test && arch-check`
Expected: all green; `arch-check` reports 25 checked, 0 violated, 0 broken.

- [ ] **Step 6: Commit**

```bash
git add src/notify.rs
git commit -m "feat(notify): the per-topic registry and its cost gate"
```

---

### Task 2: `Guard::materialize` hands back what it built

**Files:**
- Modify: `src/wac/guard.rs` (the tail of `materialize`, and the `// skeleton:` line)
- Test: `src/wac/guard.rs`'s existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Materialized { created: Vec<ResourceUrl>, linked: Vec<(ContainerUrl, String)> }`, actually populated. Tasks 4–6 read both fields.

- [ ] **Step 1: Write the failing test**

Add to `src/wac/guard.rs`'s `mod tests`. The helpers already there are `sp()`, `alice()`, `seed_acl(&store, path, triples)` and `guard_for(&store, agent, path)`; use them.

```rust
    /// A deep create reports every container it made and every link it added,
    /// so the change events can be derived from one walk rather than a second.
    #[tokio::test]
    async fn materialize_reports_the_containers_it_created_and_the_links_it_added() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}>, <{ACL_WRITE}>, <{ACL_APPEND}> ."
        )).await;
        let m = guard_for(&store, alice(), "/a/b/c.ttl").await.materialize().await.unwrap();

        let created: Vec<&str> = m.created.iter().map(|r| r.graph_iri()).collect();
        assert_eq!(created, vec![
            "https://pod.toph.so/a/b/c.ttl",
            "https://pod.toph.so/a/b/",
            "https://pod.toph.so/a/",
        ], "nearest first, and the target itself is among them");

        let linked: Vec<(&str, &str)> = m.linked.iter()
            .map(|(c, child)| (c.graph_iri(), child.as_str())).collect();
        assert_eq!(linked, vec![
            ("https://pod.toph.so/a/b/", "https://pod.toph.so/a/b/c.ttl"),
            ("https://pod.toph.so/a/", "https://pod.toph.so/a/b/"),
            ("https://pod.toph.so/", "https://pod.toph.so/a/"),
        ]);
    }

    /// An overwrite creates nothing and links nothing: the parent already
    /// records this child, so re-inserting the triple changes no state.
    #[tokio::test]
    async fn materialize_reports_nothing_for_an_overwrite() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}>, <{ACL_WRITE}>, <{ACL_APPEND}> ."
        )).await;
        guard_for(&store, alice(), "/a.ttl").await.materialize().await.unwrap();
        crate::resource::put_rdf(&store, &resource("/a.ttl"), &[]).await.unwrap();

        let m = guard_for(&store, alice(), "/a.ttl").await.materialize().await.unwrap();
        assert!(m.created.is_empty(), "nothing was created: {:?}", m.created);
        assert!(m.linked.is_empty(), "nothing was linked: {:?}", m.linked);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib wac::guard::tests::materialize`
Expected: FAIL — both `created` and `linked` are empty because `materialize` returns `Materialized::default()`.

(The second test fails on the *first* assertion only after the first test fails; that is fine — the first is the one that pins the behaviour.)

- [ ] **Step 3: Fill the body**

In `materialize`, `creations` is `Vec<&ResourceUrl>` and `plan` is `Vec<(ContainerUrl, Option<String>)>`. `plan` is consumed by the loop that applies it, so collect `linked` inside that loop, and clone `creations` into owned URLs — `Materialized` outlives the guard the references borrow from.

Replace the applying loop and the tail:

```rust
        let created: Vec<ResourceUrl> = creations.into_iter().cloned().collect();
        let mut linked: Vec<(ContainerUrl, String)> = Vec::new();
        for (ancestor, child_iri) in plan {
            container::ensure_container(self.store, &ancestor)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
            if let Some(child_iri) = child_iri {
                container::add_containment(self.store, &ancestor, &child_iri)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
                linked.push((ancestor, child_iri));
            }
        }
        Ok(Materialized { created, linked })
```

Delete the `// skeleton:` comment line above the old `Ok(Materialized::default())`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib wac::guard::`
Expected: PASS, including every pre-existing guard test.

- [ ] **Step 5: Commit**

```bash
git add src/wac/guard.rs
git commit -m "feat(wac): materialize reports what it created and linked"
```

---

### Task 3: `state` — the one read-back

**Files:**
- Modify: `src/http.rs` (widen `blob_etag` and `ground_dataset` to `pub(crate)`)
- Modify: `src/notify.rs` (add the private `state_of` helper and its tests)

**Interfaces:**
- Consumes: `crate::http::{blob_etag, ground_dataset}` (widened here), `resource::{kind_of, get_dataset, get_rdf, Kind}`, `blob::BlobKey`, `Skolemized::{etag, deskolemize}`, `Dataset::rdf_version`.
- Produces: `async fn state_of(st: &AppState, target: &Target) -> Option<String>` — **private to `src/notify.rs`**. Tasks 4–7 call it, and only for a topic `Bus::live` returned.

**Why the widening is allowed:** both helpers already compute exactly the value this needs, and re-deriving either would be the second ETag deriver `docs/constraints.md` exists to prevent. Neither becomes `pub`; both stay crate-internal.

- [ ] **Step 1: Widen the two helpers**

In `src/http.rs`:

```rust
pub(crate) fn blob_etag(bytes: &[u8]) -> String {
```

```rust
pub(crate) fn ground_dataset(triples: Vec<Triple>) -> Skolemized {
```

- [ ] **Step 2: Write the failing test**

Add to `src/notify.rs`'s `mod tests`. It needs a store, so it belongs with the other store-backed tests — build one the way `wac::guard`'s tests do.

```rust
    /// The value a subscriber receives is the validator the pod would hand out
    /// for the same state, in the format §5.1 fixes.
    #[tokio::test]
    async fn state_is_the_n_quads_etag_at_the_held_version() {
        let (st, target) = state_fixture("/notes", b"<#it> <http://schema.org/name> \"x\" .").await;
        let stored = crate::resource::get_dataset(st.store.as_ref(), match &target {
            Target::Resource(r) => r, _ => unreachable!(),
        }).await.unwrap().unwrap();
        let held = stored.deskolemize().rdf_version();
        let expected = stored.etag(crate::rdf::Format::from_content_type("application/n-quads").unwrap(), held);

        assert_eq!(state_of(&st, &target).await.as_deref(), Some(expected.as_str()));
    }

    /// A binary resource has one representation and one validator.
    #[tokio::test]
    async fn state_of_a_binary_resource_is_its_blob_etag() {
        let (st, target) = binary_fixture("/photo.png", b"\x89PNG\r\n\x1a\n").await;
        assert_eq!(
            state_of(&st, &target).await.as_deref(),
            Some(crate::http::blob_etag(b"\x89PNG\r\n\x1a\n").as_str()),
        );
    }

    /// An absent target has no state, which is what a `Delete` reports.
    #[tokio::test]
    async fn state_of_an_absent_target_is_none() {
        let (st, _) = state_fixture("/notes", b"<#it> <http://schema.org/name> \"x\" .").await;
        let gone = st.space.resolve("/never-existed").unwrap();
        assert_eq!(state_of(&st, &gone).await, None);
    }
```

Write `state_fixture` and `binary_fixture` as `#[cfg(test)]` helpers in the same module: build an `OxigraphStore::in_memory()` and an `ObjectStoreBlobs::in_memory()`, `provision_root`, `put_rdf` / `put_blob` the content, and assemble an `AppState` exactly as `tests/call_budget.rs`'s `app()` does. Return `(AppState, Target)`.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib notify::tests::state`
Expected: FAIL — `state_of` does not exist, so this is a compile error naming it.

- [ ] **Step 4: Write the helper**

In `src/notify.rs`:

```rust
/// The topic's validator after the write — §5.1.
///
/// Called only for a topic [`Bus::live`] returned, which is what keeps a pod
/// with no subscribers doing no extra I/O. `None` where there is no state to
/// report: the target is gone (a `Delete`), or the read-back failed, which
/// must not turn a successful write into a `500` — the protocol makes `state`
/// optional precisely so this case has an answer.
async fn state_of(st: &AppState, target: &Target) -> Option<String> {
    let store = st.store.as_ref();
    if let Target::Resource(r) = target {
        if let Ok(Some(crate::resource::Kind::Binary(_))) = crate::resource::kind_of(store, r).await {
            let key = crate::blob::BlobKey::of(r)?;
            return st.blobs.get(&key).await.ok().flatten().map(|b| crate::http::blob_etag(&b));
        }
        let stored = crate::resource::get_dataset(store, r).await.ok().flatten()?;
        return Some(etag_of(&stored));
    }
    // A container or an auxiliary is always ground and always default-graph,
    // so it reaches the same `etag` through the same lift the read path uses.
    let triples = crate::resource::get_rdf(store, target).await.ok().flatten()?;
    Some(etag_of(&crate::http::ground_dataset(triples)))
}

/// §5.1: N-Quads at the version the stored state holds. N-Quads because
/// `Skolemized::etag` renders each quad through oxigraph's `Display`, which is
/// N-Quads — so the media type keying the hash describes what is under it. The
/// held version rather than 1.1, or two RDF 1.2 states differing only in triple
/// terms would share a validator and a real change would report none.
fn etag_of(stored: &Skolemized) -> String {
    let held = stored.deskolemize().rdf_version();
    stored.etag(nquads(), held)
}
```

Add the imports at the top of `src/notify.rs`:

```rust
use crate::dataset::Skolemized;
use crate::rdf::Format;
```

and the format beside `etag_of`:

```rust
/// The one format `state` is expressed in. Named once, so `docs/constraints.md`
/// can pin it to this module.
fn nquads() -> Format {
    Format::from_content_type("application/n-quads").expect("a static, supported media type")
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib notify::`
Expected: PASS, 9 tests.

- [ ] **Step 6: Commit**

```bash
git add src/notify.rs src/http.rs
git commit -m "feat(notify): compute a topic's state from the stored state"
```

---

### Task 4: `emit_put` and the `PUT` handler

**Files:**
- Modify: `src/notify.rs` (`emit_put`, plus the shared mapping helper it introduces)
- Modify: `src/http.rs` (`put_impl`: the `Repr::Blob` early return, and the tail; `Fixture` keeps the bus)

**Interfaces:**
- Consumes: `Bus::live`, `Bus::publish`, `state_of` (Task 3), `Materialized` (Task 2), `Guard::target_exists`.
- Produces: `emit_put(&AppState, &Target, Existence, &Materialized, &Response)`, plus two private helpers Tasks 5–7 reuse: `publish_own(&AppState, &Target, Activity)` and `publish_containment(&AppState, target_iri: &str, &Materialized, Activity)`.

- [ ] **Step 1: Give the test fixture access to the bus**

In `src/http.rs`'s `mod tests`, add a field to `Fixture` and populate it:

```rust
    struct Fixture {
        app: axum::Router,
        events: Arc<crate::notify::Bus>,
        store: Arc<dyn crate::store::SparqlStore>,
        // … the rest unchanged
```

In the fixture builder, bind the bus before the `AppState` literal and hand the same `Arc` to both:

```rust
        let events = Arc::new(crate::notify::Bus::new());
        let state = AppState {
            store: store.clone(),
            events: events.clone(),
            // … the rest unchanged
        };
        Fixture {
            app: router(state), events, store, blobs, space, max_body_bytes, idp, client,
            _replay_guard, _reentrancy: ReentrancyGuard,
        }
```

- [ ] **Step 2: Write the failing tests**

Add to `src/http.rs`'s `mod tests`:

```rust
    /// A create is reported on the resource's own channel, and on its parent's
    /// as `Add` — not as a second `Create` (§3.2).
    #[tokio::test]
    async fn a_put_that_creates_emits_create_on_the_target_and_add_on_the_parent() {
        let f = fixture().await;
        let target = f.space.resolve("/c/notes").unwrap();
        let parent = f.space.resolve("/c/").unwrap();
        let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
        let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let e = on_target.recv().await.unwrap();
        assert_eq!(e.activity, crate::notify::Activity::Create);
        assert_eq!(e.object, target.graph_iri());
        assert_eq!(e.target, None);
        assert!(e.state.is_some(), "a create reports the state it produced");

        let p = on_parent.recv().await.unwrap();
        assert_eq!(p.activity, crate::notify::Activity::Add);
        assert_eq!(p.object, target.graph_iri(), "the object of an Add is the child");
        assert_eq!(p.target.as_deref(), Some(parent.graph_iri()));
    }

    /// An overwrite changes no containment, so the parent hears nothing at all.
    #[tokio::test]
    async fn a_put_that_overwrites_emits_update_and_nothing_on_the_parent() {
        let f = fixture().await;
        let target = f.space.resolve("/c/notes").unwrap();
        let put = |body: &'static str| f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle").body(Body::from(body)).unwrap();
        f.app.clone().oneshot(put("<#it> <http://schema.org/name> \"one\" .")).await.unwrap();

        let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
        let mut on_parent = f.events.subscribe(
            crate::notify::Topic::from(&f.space.resolve("/c/").unwrap()));
        f.app.clone().oneshot(put("<#it> <http://schema.org/name> \"two\" .")).await.unwrap();

        assert_eq!(on_target.recv().await.unwrap().activity, crate::notify::Activity::Update);
        assert!(on_parent.try_recv().is_err(), "containment did not change, so the parent is silent");
    }

    /// The regression test for the `Repr::Blob` arm's early return: a binary
    /// write must not bypass the tail where emission happens.
    #[tokio::test]
    async fn a_binary_put_emits() {
        let f = fixture().await;
        let target = f.space.resolve("/c/photo.png").unwrap();
        let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/c/photo.png")
            .header(header::CONTENT_TYPE, "image/png")
            .body(Body::from(&b"\x89PNG\r\n\x1a\n"[..])).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let e = on_target.recv().await.unwrap();
        assert_eq!(e.activity, crate::notify::Activity::Create);
        assert_eq!(e.state.as_deref(), Some(blob_etag(b"\x89PNG\r\n\x1a\n").as_str()));
    }

    /// A refused write emits nothing: the tail returns before touching the bus.
    #[tokio::test]
    async fn a_refused_put_emits_nothing() {
        let f = fixture().await;
        let target = f.space.resolve("/c/notes").unwrap();
        let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("this is not turtle {{{")).unwrap()).await.unwrap();
        assert!(!res.status().is_success(), "the fixture's premise: {}", res.status());
        assert!(on_target.try_recv().is_err());
    }
```

`try_recv` is `broadcast::Receiver::try_recv`; expose it on `Receiver` only if these tests need it — otherwise assert with `tokio::time::timeout` on `recv`. Prefer adding nothing: use

```rust
    use tokio::time::{timeout, Duration};
    assert!(timeout(Duration::from_millis(50), on_parent.recv()).await.is_err(),
        "containment did not change, so the parent is silent");
```

and drop the `try_recv` calls.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::a_put_that a_binary_put a_refused_put`
Expected: FAIL — the first three time out or panic at `not yet implemented: skeleton`; nothing is published yet.

- [ ] **Step 4: Fill `emit_put`**

In `src/notify.rs`:

```rust
pub async fn emit_put(
    st: &AppState,
    target: &Target,
    existence: Existence,
    materialized: &Materialized,
    res: &Response,
) {
    if !res.status().is_success() {
        return;
    }
    let activity = match existence {
        Existence::Existed => Activity::Update,
        Existence::Absent => Activity::Create,
    };
    publish_own(st, target, activity).await;
    publish_containment(st, target.graph_iri(), materialized, Activity::Add).await;
}

/// `Create`, `Update` or `Delete` on the topic's own channel, where `object`
/// is the topic itself and there is no `target`.
async fn publish_own(st: &AppState, target: &Target, activity: Activity) {
    let topic = Topic::from(target);
    if st.events.live(std::slice::from_ref(&topic)).is_empty() {
        return;
    }
    let state = match activity {
        Activity::Delete => None,
        _ => state_of(st, target).await,
    };
    let object = topic.as_str().to_owned();
    st.events.publish(Event { topic, activity, object, target: None, state });
}

/// A `Create` for every container this write brought into existence, and one
/// `Add` or `Remove` for every container whose membership changed.
///
/// No `Update` beside the `Add`: it says nothing the `Add` does not, and the
/// container's new state rides on the same event (design §4.1). A container
/// that was both created and gained a child gets both events — they are two
/// facts, and this bus is keyed by (topic, activity).
async fn publish_containment(
    st: &AppState,
    target_iri: &str,
    materialized: &Materialized,
    activity: Activity,
) {
    for created in &materialized.created {
        if created.graph_iri() == target_iri {
            continue; // the request's own target — `publish_own` already did it
        }
        let Some(container) = created.as_container() else {
            continue; // only containers are materialized on the way down
        };
        publish_own(st, &Target::Container(container), Activity::Create).await;
    }
    for (container, child) in &materialized.linked {
        let container_target = Target::Container(container.clone());
        let topic = Topic::from(&container_target);
        if st.events.live(std::slice::from_ref(&topic)).is_empty() {
            continue;
        }
        let state = state_of(st, &container_target).await;
        st.events.publish(Event {
            topic,
            activity,
            object: child.clone(),
            target: Some(container.graph_iri().to_owned()),
            state,
        });
    }
}
```

- [ ] **Step 5: Wire `put_impl`**

`put_impl`'s `Repr::Blob` arm ends in `return match put_blob(…)` — a *successful* early exit past the tail. Emitting in both places would make two emit calls in one handler, which §6.2 rejects and Task 8's constraint counts against. So `put_impl` splits: a wrapper that emits once, and the current body under a new name that reports what the emit needs.

Rename the existing `async fn put_impl(...) -> Response` to:

```rust
async fn put_write(
    st: &AppState, agent: Agent, target: &Target, headers: HeaderMap, body: Bytes,
) -> (Response, crate::notify::Existence, Materialized) {
```

and add the wrapper above it:

```rust
async fn put_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap, body: Bytes) -> Response {
    let (res, existence, materialized) = put_write(&st, agent, &target, headers, body).await;
    crate::notify::emit_put(&st, &target, existence, &materialized, &res).await;
    res
}
```

Inside `put_write`:

- Bind the pre-write fact right after the guard is probed and authorized, before anything can consume it:

  ```rust
      let existence = if guard.target_exists() {
          crate::notify::Existence::Existed
      } else {
          crate::notify::Existence::Absent
      };
  ```

- Every early `return X;` becomes `return (X, existence, Materialized::default());`. The ones *above* the `existence` binding — the guard probe and the `authorize` refusal — use `crate::notify::Existence::Absent` literally. All of these are failure responses, so what they report is never read: `emit_put` returns on `!res.status().is_success()` before touching either value.

- Both `guard.materialize()` call sites now yield a value. Bind it:

  ```rust
      let materialized = match guard.materialize().await {
          Ok(m) => m,
          Err(res) => return (with_aux_links(res, target), existence, Materialized::default()),
      };
  ```

- The blob arm's `return match put_blob(…)` becomes a normal return carrying the same three values:

  ```rust
          return (match put_blob(store, st.blobs.as_ref(), r, bytes, &mt).await {
              Ok(()) => created(target),
              Err(ResourceError::KeyTooLong) => StatusCode::URI_TOO_LONG.into_response(),
              Err(e) => (put_status(&e), e.to_string()).into_response(),
          }, existence, materialized);
  ```

  It still returns early — but it now returns the `Materialized` its own `guard.materialize()` produced, so the wrapper emits for the blob path exactly as it does for the RDF path. §6.3 is satisfied by the value reaching the emit, not by the control flow being straightened.

- The final tail becomes:

  ```rust
      let res = if findings.is_some() && res.status().is_success() {
          report_link(target, res)
      } else {
          res
      };
      (res, existence, materialized)
  ```

Import `crate::wac::guard::Materialized` at the top of `src/http.rs`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib http::`
Expected: PASS, including every pre-existing `http` test.

- [ ] **Step 7: Run the whole suite and the constraints**

Run: `nix develop -c cargo test && arch-check`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add src/notify.rs src/http.rs
git commit -m "feat(http): emit change events on PUT"
```

---

### Task 5: `emit_post` and the `POST` handler

**Files:**
- Modify: `src/notify.rs` (`emit_post`)
- Modify: `src/http.rs` (`post_impl` tail)

**Interfaces:**
- Consumes: `publish_own`, `publish_containment` (Task 4).
- Produces: `emit_post(&AppState, &Target, &Materialized, &Response)`.

- [ ] **Step 1: Write the failing test**

Add to `src/http.rs`'s `mod tests`:

```rust
    /// The allocated child is always new, so `POST` is always a `Create` — and
    /// the container that received it hears `Add`, with the child as `object`.
    #[tokio::test]
    async fn a_post_emits_create_on_the_child_and_add_on_the_container() {
        let f = fixture().await;
        let container = f.space.resolve("/c/").unwrap();
        let mut on_container = f.events.subscribe(crate::notify::Topic::from(&container));

        let res = f.app.clone().oneshot(f.owner_request("POST", "/c/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", "child")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let location = res.headers()[header::LOCATION].to_str().unwrap().to_owned();

        let e = on_container.recv().await.unwrap();
        assert_eq!(e.activity, crate::notify::Activity::Add);
        assert_eq!(e.object, location, "the object of an Add is the allocated child");
        assert_eq!(e.target.as_deref(), Some(container.graph_iri()));
        assert!(e.state.is_some(), "the container's own new state rides on the Add");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `nix develop -c cargo test --lib http::tests::a_post_emits`
Expected: FAIL — panics at `not yet implemented: skeleton`.

- [ ] **Step 3: Fill `emit_post`**

```rust
pub async fn emit_post(
    st: &AppState,
    child: &Target,
    materialized: &Materialized,
    res: &Response,
) {
    if !res.status().is_success() {
        return;
    }
    // No `Existence` parameter: `post_impl` allocates an unused name, so the
    // child is new by construction.
    publish_own(st, child, Activity::Create).await;
    publish_containment(st, child.graph_iri(), materialized, Activity::Add).await;
}
```

- [ ] **Step 4: Wire `post_impl`**

At the tail of `post_impl`, after the `report_link` decision and before the value is returned, using the `Materialized` returned by `child_guard.materialize()`:

```rust
    crate::notify::emit_post(&st, &child, &materialized, &res).await;
    res
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test && arch-check`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/notify.rs src/http.rs
git commit -m "feat(http): emit change events on POST"
```

---

### Task 6: `emit_patch` and the `PATCH` handler

**Files:**
- Modify: `src/notify.rs` (`emit_patch`)
- Modify: `src/http.rs` (`patch_impl` tail)

**Interfaces:**
- Consumes: `publish_own`, `publish_containment` (Task 4), `Guard::target_exists`.
- Produces: `emit_patch(&AppState, &Target, Existence, &Materialized, &Response)`.

- [ ] **Step 1: Write the failing tests**

```rust
    /// The ordinary patch: the resource was there, so it is an `Update`.
    #[tokio::test]
    async fn a_patch_on_an_existing_resource_emits_update() {
        let f = fixture().await;
        let target = f.space.resolve("/c/notes").unwrap();
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"one\" .")).unwrap())
            .await.unwrap();

        let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
        let res = f.app.clone().oneshot(f.owner_request("PATCH", "/c/notes")
            .header(header::CONTENT_TYPE, "text/n3")
            .body(Body::from(
                "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
                 <> a solid:InsertDeletePatch ; solid:inserts \
                 { <#it> <http://schema.org/keywords> \"k\" . } .\n")).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let e = on_target.recv().await.unwrap();
        assert_eq!(e.activity, crate::notify::Activity::Update);
        assert!(e.state.is_some());
    }

    /// `create_by_patch`: a patch on an absent resource creates it, so it is a
    /// `Create` and its parent hears `Add`.
    #[tokio::test]
    async fn a_patch_that_creates_emits_create_and_add() {
        let f = fixture().await;
        let target = f.space.resolve("/c/fresh").unwrap();
        let parent = f.space.resolve("/c/").unwrap();
        let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
        let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));

        let res = f.app.clone().oneshot(f.owner_request("PATCH", "/c/fresh")
            .header(header::CONTENT_TYPE, "text/n3")
            .body(Body::from(
                "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
                 <> a solid:InsertDeletePatch ; solid:inserts \
                 { <#it> <http://schema.org/name> \"x\" . } .\n")).unwrap())
            .await.unwrap();
        assert!(res.status().is_success(), "create-by-patch: {}", res.status());

        assert_eq!(on_target.recv().await.unwrap().activity, crate::notify::Activity::Create);
        let p = on_parent.recv().await.unwrap();
        assert_eq!(p.activity, crate::notify::Activity::Add);
        assert_eq!(p.object, target.graph_iri());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::a_patch_`
Expected: FAIL — panics at `not yet implemented: skeleton`.

- [ ] **Step 3: Fill `emit_patch`**

```rust
pub async fn emit_patch(
    st: &AppState,
    target: &Target,
    existence: Existence,
    materialized: &Materialized,
    res: &Response,
) {
    if !res.status().is_success() {
        return;
    }
    let activity = match existence {
        Existence::Existed => Activity::Update,
        Existence::Absent => Activity::Create,
    };
    publish_own(st, target, activity).await;
    publish_containment(st, target.graph_iri(), materialized, Activity::Add).await;
}
```

- [ ] **Step 4: Wire `patch_impl`**

`patch_impl` already reads `guard.target_exists()` for its own create-vs-update branch. Reuse that value — do not call it twice — and emit at the tail:

```rust
    crate::notify::emit_patch(&st, &target, existence, &materialized, &res).await;
    res
```

On the path where no materialization happened, pass `&Materialized::default()`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test && arch-check`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/notify.rs src/http.rs
git commit -m "feat(http): emit change events on PATCH"
```

---

### Task 7: `emit_delete` and the `DELETE` handler

**Files:**
- Modify: `src/notify.rs` (`emit_delete`)
- Modify: `src/http.rs` (`delete_impl`: collect the present auxiliaries, and the tail)

**Interfaces:**
- Consumes: `publish_own` (Task 4), `Guard::authorize_aux`.
- Produces: `emit_delete(&AppState, &Target, &[AuxUrl], &Response)`.

- [ ] **Step 1: Write the failing tests**

```rust
    /// The resource, and its parent losing a member. `Remove` carries the child
    /// as `object`, exactly as `Add` does.
    #[tokio::test]
    async fn a_delete_emits_delete_on_the_target_and_remove_on_the_parent() {
        let f = fixture().await;
        let target = f.space.resolve("/c/notes").unwrap();
        let parent = f.space.resolve("/c/").unwrap();
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
            .await.unwrap();

        let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
        let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));
        let res = f.app.clone().oneshot(
            f.owner_request("DELETE", "/c/notes").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let e = on_target.recv().await.unwrap();
        assert_eq!(e.activity, crate::notify::Activity::Delete);
        assert_eq!(e.state, None, "a deleted resource has no state to report");

        let p = on_parent.recv().await.unwrap();
        assert_eq!(p.activity, crate::notify::Activity::Remove);
        assert_eq!(p.object, target.graph_iri());
        assert_eq!(p.target.as_deref(), Some(parent.graph_iri()));
        assert!(p.state.is_some(), "the parent still exists and reports its new state");
    }

    /// `aux::delete_subject` takes the ACL with the subject, and its own topic
    /// hears about it.
    #[tokio::test]
    async fn deleting_a_subject_emits_delete_for_the_auxiliaries_it_cascades() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
            .await.unwrap();
        f.app.clone().oneshot(f.owner_request("PUT", "/.aux/acl/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(format!(
                "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/c/notes> ; \
                 <http://www.w3.org/ns/auth/acl#mode> \
                 <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write>, \
                 <http://www.w3.org/ns/auth/acl#Control> ."))).unwrap())
            .await.unwrap();

        let acl = f.space.resolve("/.aux/acl/c/notes").unwrap();
        let mut on_acl = f.events.subscribe(crate::notify::Topic::from(&acl));
        f.app.clone().oneshot(
            f.owner_request("DELETE", "/c/notes").body(Body::empty()).unwrap()).await.unwrap();

        let e = on_acl.recv().await.unwrap();
        assert_eq!(e.activity, crate::notify::Activity::Delete);
    }

    /// An auxiliary is never a container member, so its removal is not a
    /// containment change and the parent hears nothing (design §4.2).
    #[tokio::test]
    async fn deleting_an_auxiliary_emits_no_parent_event() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
            .await.unwrap();
        f.app.clone().oneshot(f.owner_request("PUT", "/.aux/acl/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(format!(
                "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/c/notes> ; \
                 <http://www.w3.org/ns/auth/acl#mode> \
                 <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write>, \
                 <http://www.w3.org/ns/auth/acl#Control> ."))).unwrap())
            .await.unwrap();

        let mut on_parent = f.events.subscribe(
            crate::notify::Topic::from(&f.space.resolve("/c/").unwrap()));
        let res = f.app.clone().oneshot(
            f.owner_request("DELETE", "/.aux/acl/c/notes").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        use tokio::time::{timeout, Duration};
        assert!(timeout(Duration::from_millis(50), on_parent.recv()).await.is_err(),
            "an auxiliary is not a member, so nothing about containment changed");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::a_delete_ deleting_a deleting_an`
Expected: FAIL — panics at `not yet implemented: skeleton`.

- [ ] **Step 3: Fill `emit_delete`**

```rust
pub async fn emit_delete(
    st: &AppState,
    target: &Target,
    auxiliaries: &[AuxUrl],
    res: &Response,
) {
    if !res.status().is_success() {
        return;
    }
    publish_own(st, target, Activity::Delete).await;
    for aux in auxiliaries {
        publish_own(st, &Target::Aux(aux.clone()), Activity::Delete).await;
    }
    // An auxiliary is never a container member, so its removal changes no
    // containment and its parent hears nothing (design §4.2).
    let Some(parent) = (match target {
        Target::Resource(r) => r.parent(),
        Target::Container(c) => c.as_resource().parent(),
        Target::Aux(_) => None,
    }) else {
        return;
    };
    let parent_target = Target::Container(parent.clone());
    let topic = Topic::from(&parent_target);
    if st.events.live(std::slice::from_ref(&topic)).is_empty() {
        return;
    }
    let state = state_of(st, &parent_target).await;
    st.events.publish(Event {
        topic,
        activity: Activity::Remove,
        object: target.graph_iri().to_owned(),
        target: Some(parent.graph_iri().to_owned()),
        state,
    });
}
```

- [ ] **Step 4: Wire `delete_impl`**

`delete_impl` already loops `AuxKind::ALL` calling `guard.authorize_aux(*kind)`. That call answers `Ok(Some(_))` exactly for an auxiliary the probe found present, so collect them in the same loop rather than probing again:

```rust
    let mut present_auxes: Vec<AuxUrl> = Vec::new();
    for kind in AuxKind::ALL {
        match guard.authorize_aux(*kind) {
            Err(res) => return with_aux_links(res, &target),
            Ok(Some(_)) => present_auxes.push(subject.aux(*kind)),
            Ok(None) => {}
        }
    }
```

Then bind the response instead of returning it directly from the final `match`, and emit at the tail:

```rust
    crate::notify::emit_delete(&st, &target, &present_auxes, &res).await;
    res
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test && arch-check`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/notify.rs src/http.rs
git commit -m "feat(http): emit change events on DELETE"
```

---

### Task 8: The properties, the budgets, and the constraints

**Files:**
- Modify: `src/http.rs` (the fan-out test)
- Modify: `tests/call_budget.rs` (the no-subscriber and one-subscriber cases)
- Modify: `docs/constraints.md` (three rules)

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces: nothing further; this task closes the feature.

- [ ] **Step 1: Write the fan-out test**

The one that pins §3.2's most misreadable consequence. Add to `src/http.rs`'s `mod tests`:

```rust
    /// A deep create is six events, and the root hears exactly one of them:
    /// `Add` naming the container directly beneath it. Not `Create` for the
    /// grandchild — `as:Create` only ever runs on the new resource's own
    /// channel (design §3.2).
    #[tokio::test]
    async fn a_deep_create_tells_the_root_only_about_its_own_child() {
        let f = fixture().await;
        let root = f.space.resolve("/").unwrap();
        let a = f.space.resolve("/a/").unwrap();
        let mut on_root = f.events.subscribe(crate::notify::Topic::from(&root));

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/a/b/c.ttl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let e = on_root.recv().await.unwrap();
        assert_eq!(e.activity, crate::notify::Activity::Add);
        assert_eq!(e.object, a.graph_iri(), "the root's own child, not the grandchild");
        assert_eq!(e.target.as_deref(), Some(root.graph_iri()));

        use tokio::time::{timeout, Duration};
        assert!(timeout(Duration::from_millis(50), on_root.recv()).await.is_err(),
            "one event on the root, not one per level below it");
    }
```

- [ ] **Step 2: Write the cost cases**

In `tests/call_budget.rs`. The existing budgets already fail on any unconditional I/O; these two make the gate's *presence* observable rather than implied. Follow the file's own shape — `app()`, `counts.take()`, `oneshot`.

First widen `app()`'s return type so the test can reach the bus the router is holding. In `app()`, bind it before the `AppState` literal and hand the same `Arc` to both:

```rust
async fn app() -> (axum::Router, Arc<CountingStore>, Arc<sparql_pod::notify::Bus>) {
    // … unchanged up to the AppState literal …
    let events = Arc::new(sparql_pod::notify::Bus::new());
    let app = router(AppState {
        store,
        events: events.clone(),
        // … the rest unchanged …
    });
    (app, counting, events)
}
```

Update the three existing tests' `let (app, counts) = app().await;` to `let (app, counts, _events) = app().await;`, and add the shared request builder:

```rust
fn put_request(path: &str, object: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!("<#it> <http://schema.org/name> {object} .")))
        .unwrap()
}
```

Then the new case:

```rust
/// The gate is a gate: with a subscriber on the topic, the same request costs
/// strictly more, because `state` is read back. Asserted as an inequality
/// rather than a number, so it survives an unrelated change to the write path.
#[tokio::test]
async fn a_subscriber_makes_a_put_cost_more_than_it_does_without_one() {
    let (app, counts, events) = app().await;

    counts.take();
    app.clone().oneshot(put_request("/seeded", "\"one\"")).await.unwrap();
    let without = counts.take().total();

    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    let _rx = events.subscribe(sparql_pod::notify::Topic::from(&space.resolve("/seeded").unwrap()));
    app.oneshot(put_request("/seeded", "\"two\"")).await.unwrap();
    let with = counts.take().total();

    assert!(with > without, "a watched topic reads its state back: {without} without, {with} with");
}
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `nix develop -c cargo test`
Expected: all green.

- [ ] **Step 4: Demonstrate each constraint red, then add it**

For each rule below: make the violation, run the check, watch it fail, revert, then add the rule to `docs/constraints.md` in the section named. `docs/constraints.md` says in its own header that a check which cannot fail is worse than no check — so this step is not optional and its evidence goes in the commit message.

Under a new `## Notifications` section:

```
Every write handler emits exactly once.
    → 2026-07-31-change-events-design.md §6.2. Emission at each success site
    instead would be fifteen places to forget in `http.rs`, where a new write
    path compiles silently without an event and no test names the omission.
    Counts calls rather than the functions' existence: a handler that stops
    calling its emit keeps compiling.
    check: [ "$(rg -o 'crate::notify::emit_(put|post|patch|delete)\(' src/http.rs | wc -l)" = 4 ]

Only `notify` fixes a format for `state`.
    → 2026-07-31-change-events-design.md §5.1, §5.2. `state` is the N-Quads
    validator at the held version; a second site choosing a format is a second
    answer to "which of this resource's ETags is its state", and the two would
    drift silently because both would keep producing a plausible tag.
    Anchored on the *fixed* format rather than on the media type: `rdf.rs`
    names `application/n-quads` in `Format::media_type` and `http.rs` in
    `SERVABLE`, both legitimately, so a literal-based check is red on arrival.
    What distinguishes this call is that every other `.etag(` site passes a
    negotiated format — `etag_candidates`, `get_impl` and `legacy_graph_read`
    all pass a variable — and only `state` pins one. Narrower than its
    sentence: it catches the copy-paste, not a second site that re-derives
    N-Quads under another name.
    check: ! rg -q 'etag\(nquads\(\)' src --glob '!src/notify.rs'

`Topic` is built only from a `Target`.
    → §2.1. The registry is where #18 authorizes subscriptions, so a key that
    did not pass `StorageSpace::resolve` is a subscription to a path the space
    never admitted. `From<&Target>` is the only constructor today; nothing but
    this stops a `From<String>` being added beside it.
    check: ! rg -q 'Topic\(' src --glob '!src/notify.rs'
```

- [ ] **Step 5: Verify the skeleton is gone**

Run:

```bash
rg -n 'todo!\("skeleton"\)|// skeleton:' src/ ; echo "exit=$?"
```

Expected: no matches, `exit=1`.

- [ ] **Step 6: Full verification**

Run: `nix develop -c cargo test && arch-check`
Expected: all tests green; `arch-check` reports 28 checked, 0 violated, 0 broken.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs tests/call_budget.rs docs/constraints.md
git commit -m "test(notify): pin the fan-out, the cost gate and three constraints"
```

---

## What this plan does not do

Out of scope, per spec §10: persistence, delivery guarantees, `Lagged` handling, the subscription endpoint, ActivityStreams JSON-LD serialization, and authorization of subscriptions — all #18 and #19. `ETag` on write responses is #28. Advertising `version=1.2` only for formats that have an RDF 1.2 syntax is #32.
