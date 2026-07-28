//! Where one named graph of one resource is stored, and the bookkeeping that
//! names it back.
//!
//! Skeleton for the storage model of §3. The key is server-minted from values
//! the server already holds, which is what makes the same graph name in two
//! resources land in two different shelves — §2.1's decision expressed as an
//! address rather than as a rule someone has to remember.

use crate::space::ResourceUrl;
use oxigraph::model::NamedNodeRef;

/// The bookkeeping vocabulary, under `urn:pod:sys#` — the same prefix
/// `resource::SYS_PRESENT` already uses. The `#` is what keeps these
/// predicate IRIs from colliding with the system-*graph* naming scheme
/// `urn:pod:sys:<resource-iri>`.
pub const SYS_HAS_SUBGRAPH: &str = "urn:pod:sys#hasSubgraph";
pub const SYS_GRAPH_NAME: &str = "urn:pod:sys#graphName";
pub const SYS_MEDIA_TYPE: &str = "urn:pod:sys#mediaType";

/// A store graph holding one named graph of one resource.
///
/// Opaque by construction: nothing reads it back, the registry holds the
/// original name. Constructible only through [`ShelfKey::of`], so a key can
/// never be built from a client-supplied string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShelfKey(String);

impl ShelfKey {
    /// SHA-256 over `resource-iri ‖ 0x00 ‖ graph-name`, rendered as 64 lowercase
    /// hex characters and prefixed `urn:pod:subgraph:`.
    ///
    /// The separator is `0x00` because RFC 3987 excludes control characters
    /// from IRIs, so it cannot occur in either part and one pair can never be
    /// read back as a different pair. A printable separator admits collisions
    /// across resources, which is a cross-resource read and write.
    // skeleton: the attribute goes when the body lands
    #[allow(unused_variables)]
    pub fn of(resource: &ResourceUrl, graph_name: NamedNodeRef<'_>) -> Self {
        todo!("skeleton")
    }

    /// The store graph IRI. Interpolated into SPARQL, so it must be the only
    /// way a shelf is ever addressed.
    pub fn graph_iri(&self) -> &str {
        &self.0
    }

    /// Reconstruct a key the registry already holds. Not a parse — the caller
    /// asserts this came out of `sys:hasSubgraph`, never off the wire.
    pub fn from_registry(iri: &str) -> Self {
        Self(iri.to_owned())
    }
}
