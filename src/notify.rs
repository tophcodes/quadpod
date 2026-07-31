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
use crate::space::{AuxUrl, Target};
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
    fn from(_target: &Target) -> Self {
        todo!("skeleton")
    }
}

impl Topic {
    pub fn as_str(&self) -> &str {
        todo!("skeleton")
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
    pub fn live(&self, _topics: &[Topic]) -> Vec<Topic> {
        todo!("skeleton")
    }

    /// Deliver `event` to `event.topic`'s channel, if it still has one.
    ///
    /// A send with no receivers is the normal case, not an error.
    pub fn publish(&self, _event: Event) {
        todo!("skeleton")
    }

    /// Take `topic`'s channel, creating it if this is its first subscriber.
    ///
    /// Takes `&Arc<Self>` because the returned [`Subscription`] unregisters
    /// itself when the last receiver drops.
    pub fn subscribe(self: &Arc<Self>, _topic: Topic) -> Subscription {
        todo!("skeleton")
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

/// A live subscription to one topic. Unregisters its channel on drop when no
/// other receiver is left.
pub struct Subscription {
    _bus: Arc<Bus>,
    _topic: Topic,
    _rx: broadcast::Receiver<Event>,
}

impl Subscription {
    pub async fn recv(&mut self) -> Result<Event, broadcast::error::RecvError> {
        todo!("skeleton")
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        todo!("skeleton")
    }
}

/// `PUT`: `Create` or `Update` on the target, and `Add` on each container that
/// gained a child. `existed` is [`crate::wac::guard::Guard::target_exists`],
/// read before the guard was consumed.
pub async fn emit_put(
    _st: &AppState,
    _target: &Target,
    _existed: bool,
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
    _existed: bool,
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
