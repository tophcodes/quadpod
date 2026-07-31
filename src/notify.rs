//! Change events for the Solid Notifications Protocol, produced by the LDP
//! write path and drained by whatever channel type is subscribed.
//!
//! The bus is a registry keyed by topic rather than one broadcast channel: a
//! notification channel has exactly one `notify:topic`, and a single firehose
//! would make one subscriber anywhere in the pod the reason every write
//! computes a validator. [`Bus::live`] is where that cost is gated — nothing
//! reads a `state` for a topic with no live channel.
//!
//! Every write goes through LDP (the SPARQL endpoint is internal-only), so
//! this bus is complete by construction and no store-level change feed exists.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::response::Response;
use tokio::sync::broadcast;

use crate::dataset::Skolemized;
use crate::http::AppState;
use crate::rdf::Format;
use crate::space::{AuxUrl, GraphName, Target};
use crate::wac::guard::Materialized;

/// The channel key: a resource's graph IRI, and the unit #18 authorizes a
/// subscription against.
///
/// Constructible only from a [`Target`], so a request path cannot become a key
/// without passing `StorageSpace::resolve` first — the same guarantee
/// `space::GraphName`, `shelf::ShelfKey` and `blob::BlobKey` are built with.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Topic(String);

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

/// The ActivityStreams activity an event reports.
///
/// A containment change is `Add` or `Remove` alone: it already says the
/// container changed, and the container's new state rides on the same event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Activity {
    Create,
    Update,
    Delete,
    Add,
    Remove,
}

/// One change, on one topic.
///
/// Carries no `id` and no `published`: both belong to a *notification* rather
/// than to the change, one event fans out to however many channels are
/// subscribed, and each notification needs its own `id`. #18 mints them when
/// it serializes, which also keeps this type free of a clock.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Event {
    /// The channel this event runs on.
    pub topic: Topic,
    pub activity: Activity,
    /// The topic itself, except on `Add`/`Remove`, where it is the child.
    pub object: String,
    /// The container, on `Add`/`Remove` only.
    pub target: Option<String>,
    /// The **topic's** validator after the write — never the `object`'s, or a
    /// subscriber could not hand it back as `notify:state`. `None` on
    /// `Delete`, and when the read-back failed.
    pub state: Option<String>,
}

/// Events buffered per channel before a slow reader starts losing them to
/// `RecvError::Lagged`. Handling that loss is the channel type's business
/// (#18, #19), not this bus's.
const CAPACITY: usize = 64;

/// The per-topic registry.
pub struct Bus {
    channels: RwLock<HashMap<Topic, broadcast::Sender<Event>>>,
}

impl Bus {
    pub fn new() -> Self {
        Self { channels: RwLock::new(HashMap::new()) }
    }

    /// Which of `topics` have a live channel — the one gate every `state`
    /// computation sits behind.
    ///
    /// Evicts any sender whose receiver count has fallen to zero, which is
    /// what keeps the map from growing without bound over client-chosen paths.
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

    /// Deliver `event` to `event.topic`'s channel, if it still has one.
    ///
    /// A send with no receivers is the normal case, not an error.
    pub fn publish(&self, event: Event) {
        let channels = self.channels.read().expect("the bus lock is never held across a panic");
        if let Some(tx) = channels.get(&event.topic) {
            // `send` fails only when there is no receiver left, which is the
            // normal case rather than an error.
            let _ = tx.send(event);
        }
    }

    /// Take `topic`'s channel, creating it if this is its first receiver.
    ///
    /// Takes `&Arc<Self>` because the returned [`Receiver`] unregisters itself
    /// when the last one drops.
    pub fn subscribe(self: &Arc<Self>, topic: Topic) -> Receiver {
        let mut channels = self.channels.write().expect("the bus lock is never held across a panic");
        let tx = channels
            .entry(topic.clone())
            .or_insert_with(|| broadcast::channel(CAPACITY).0);
        Receiver { rx: tx.subscribe(), bus: Arc::clone(self), topic }
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

/// A live reader of one topic's channel. Unregisters that channel on drop when
/// no other reader is left.
///
/// Not a Solid notification channel and deliberately not named one. A
/// `WebSocketChannel2023` or `WebhookChannel2023` is #18's and #19's object —
/// it carries a channel type, a `receiveFrom` or `sendTo`, an `accept`, the
/// optional `startAt`/`endAt`/`rate` features, and for webhooks it outlives the
/// process. Each of those *holds* one of these to get its events. Nothing about
/// the protocol belongs on this type.
pub struct Receiver {
    bus: Arc<Bus>,
    topic: Topic,
    rx: broadcast::Receiver<Event>,
}

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

/// Whether the target was there before the write — what decides `Create` from
/// `Update`.
///
/// A `bool`, for the reason [`crate::rdf::Shape`] is not one:
/// `emit_put(&st, &target, true, …)` says nothing at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existence {
    Existed,
    Absent,
}

/// `PUT`: `Create` or `Update` on the target, and `Add` on each container that
/// gained a child. `existence` comes from
/// [`crate::wac::guard::Guard::target_exists`], read before the guard was
/// consumed.
pub async fn emit_put(
    _st: &AppState,
    _target: &Target,
    _existence: Existence,
    _materialized: &Materialized,
    _res: &Response,
) {
    todo!("skeleton")
}

/// `POST`: as [`emit_put`], on the allocated child rather than the request
/// target, and always a `Create` — the name is fresh by construction.
pub async fn emit_post(
    _st: &AppState,
    _child: &Target,
    _materialized: &Materialized,
    _res: &Response,
) {
    todo!("skeleton")
}

/// `PATCH`: `Update`, or the `Create` shape when `create_by_patch` ran.
pub async fn emit_patch(
    _st: &AppState,
    _target: &Target,
    _existence: Existence,
    _materialized: &Materialized,
    _res: &Response,
) {
    todo!("skeleton")
}

/// `DELETE`: `Delete` on the target, `Remove` on its parent, and a `Delete` on
/// each auxiliary the cascade took with it. `auxiliaries` are the ones
/// `Guard::authorize_aux` found present, collected before the write.
pub async fn emit_delete(
    _st: &AppState,
    _target: &Target,
    _auxiliaries: &[AuxUrl],
    _res: &Response,
) {
    todo!("skeleton")
}

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

/// The one format `state` is expressed in. Named once, so `docs/constraints.md`
/// can pin it to this module.
fn nquads() -> Format {
    Format::from_content_type("application/n-quads").expect("a static, supported media type")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthConfig, Jwks, StaticJwksResolver, StaticWebIdIssuers};
    use crate::blob::ObjectStoreBlobs;
    use crate::container;
    use crate::rdf::{MediaType, RdfVersion};
    use crate::resource;
    use crate::space::StorageSpace;
    use crate::store::OxigraphStore;
    use bytes::Bytes;
    use oxigraph::model::Triple;

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

    /// `Drop` is what unregisters, not `live`. Asserted on the map directly and
    /// *before* any `live` call, because `live` evicts a zero-receiver sender
    /// itself and would satisfy this assertion on its own.
    #[test]
    fn dropping_the_last_receiver_unregisters_the_channel() {
        let bus = Arc::new(Bus::new());
        let topic = Topic::from(&target("/notes"));
        drop(bus.subscribe(topic.clone()));
        assert_eq!(bus.channels.read().unwrap().len(), 0,
            "the last receiver's Drop must remove the entry, without help from live()");
    }

    /// And only the *last* one: an unconditional eviction would cut off every
    /// other reader of the same topic.
    #[test]
    fn dropping_one_of_two_receivers_leaves_the_channel_alone() {
        let bus = Arc::new(Bus::new());
        let topic = Topic::from(&target("/notes"));
        let keep = bus.subscribe(topic.clone());
        drop(bus.subscribe(topic.clone()));
        assert_eq!(bus.channels.read().unwrap().len(), 1,
            "a second reader is still there, so the channel must survive");
        assert_eq!(bus.live(&[topic]), vec![Topic::from(&target("/notes"))]);
        drop(keep);
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

    /// The pieces every `state_of` fixture shares: a full `AppState` over an
    /// in-memory store and blob store, exactly as `tests/call_budget.rs`'s
    /// `app()` assembles one, minus the router — `state_of` is called
    /// directly, not through a request.
    fn assemble_state(
        store: OxigraphStore, blobs: ObjectStoreBlobs, space: StorageSpace,
    ) -> AppState {
        AppState {
            store: Arc::new(store),
            events: Arc::new(Bus::new()),
            blobs: Arc::new(blobs),
            space,
            resolver: Arc::new(StaticJwksResolver::new("https://idp.example/", Jwks { keys: vec![] })),
            webid_verifier: Arc::new(StaticWebIdIssuers::new()),
            auth_config: Arc::new(AuthConfig::default()),
            max_body_bytes: 64 * 1024 * 1024,
        }
    }

    /// An `AppState` whose store holds `turtle` (RDF 1.1) at `path`, and the
    /// `Target` that resolves to.
    async fn state_fixture(path: &str, turtle: &[u8]) -> (AppState, Target) {
        let store = OxigraphStore::in_memory().unwrap();
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        container::provision_root(&store, &space.root()).await.unwrap();

        let target = space.resolve(path).unwrap();
        let Target::Resource(r) = &target else {
            unreachable!("state_fixture is only called with a resource path")
        };
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let triples: Vec<Triple> = ttl
            .parse(turtle, r.graph_iri(), RdfVersion::Rdf11)
            .unwrap()
            .quads().iter().cloned().map(Triple::from).collect();
        resource::put_rdf(&store, r, &triples).await.unwrap();

        let st = assemble_state(store, ObjectStoreBlobs::in_memory(), space);
        (st, target)
    }

    /// An `AppState` whose store holds `bytes` as a binary resource at `path`.
    async fn binary_fixture(path: &str, bytes: &'static [u8]) -> (AppState, Target) {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = ObjectStoreBlobs::in_memory();
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        container::provision_root(&store, &space.root()).await.unwrap();

        let target = space.resolve(path).unwrap();
        let Target::Resource(r) = &target else {
            unreachable!("binary_fixture is only called with a resource path")
        };
        let mt = MediaType::parse("image/png").unwrap();
        resource::put_blob(&store, &blobs, r, Bytes::from_static(bytes), &mt).await.unwrap();

        let st = assemble_state(store, blobs, space);
        (st, target)
    }

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

    /// `state_is_the_n_quads_etag_at_the_held_version` fixes the format and
    /// the version by recomputing both independently — but its fixture is
    /// pure RDF 1.1, so a broken `state_of` that hashed at a hard-coded
    /// `RdfVersion::Rdf11` instead of the stored state's own held version
    /// would pass that test too. This one holds an RDF 1.2-basic directional
    /// literal, where the two versions provably diverge, so it fails if
    /// `state_of` ever collapses a 1.2 state to its 1.1 projection's
    /// validator — the exact failure the module doc comment on `etag_of`
    /// warns about.
    #[tokio::test]
    async fn state_of_a_1_2_basic_state_is_not_its_1_1_projections_etag() {
        let store = OxigraphStore::in_memory().unwrap();
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        container::provision_root(&store, &space.root()).await.unwrap();

        let target = space.resolve("/notes").unwrap();
        let Target::Resource(r) = &target else { unreachable!() };
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let triples: Vec<Triple> = ttl
            .parse(b"<#it> <http://e/p> \"hi\"@en--ltr .", r.graph_iri(), RdfVersion::Rdf12Basic)
            .unwrap()
            .quads().iter().cloned().map(Triple::from).collect();
        resource::put_rdf(&store, r, &triples).await.unwrap();

        let stored = crate::resource::get_dataset(&store, r).await.unwrap().unwrap();
        let held = stored.deskolemize().rdf_version();
        assert_eq!(held, RdfVersion::Rdf12Basic, "fixture must actually hold a 1.2-basic term");
        let one_one_etag = stored.etag(nquads(), RdfVersion::Rdf11);

        let st = assemble_state(store, ObjectStoreBlobs::in_memory(), space);
        assert_ne!(
            state_of(&st, &target).await.as_deref(),
            Some(one_one_etag.as_str()),
            "state_of must hash at the state's held version, not silently at 1.1",
        );
    }
}
