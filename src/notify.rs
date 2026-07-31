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

use crate::http::AppState;
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
}
