//! Where one named graph of one resource is stored, and the bookkeeping that
//! names it back.
//!
//! The storage model of §3. The key is server-minted from values the server
//! already holds, so the same graph name in two resources
//! lands in two different shelves, §2.1's decision expressed as an address
//! rather than as a rule someone has to remember.

use crate::space::{GraphName, ResourceUrl};
use oxigraph::model::NamedNodeRef;
use sha2::{Digest, Sha256};

/// The bookkeeping vocabulary, under `urn:quadpod:sys#`, the same prefix
/// `resource::SYS_PRESENT` already uses. The `#` is what keeps these
/// predicate IRIs from colliding with the system-*graph* naming scheme
/// `urn:quadpod:sys:<resource-iri>`.
pub const SYS_HAS_SUBGRAPH: &str = "urn:quadpod:sys#hasSubgraph";
pub const SYS_GRAPH_NAME: &str = "urn:quadpod:sys#graphName";
pub const SYS_MEDIA_TYPE: &str = "urn:quadpod:sys#mediaType";

/// A store graph holding one named graph of one resource.
///
/// Opaque by construction: nothing reads it back, the registry holds the
/// original name. Constructible only through [`ShelfKey::of`], so a key can
/// never be built from a client-supplied string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShelfKey(String);

impl ShelfKey {
    /// SHA-256 over `resource-iri ‖ 0x00 ‖ graph-name`, rendered as 64 lowercase
    /// hex characters and prefixed `urn:quadpod:subgraph:`.
    ///
    /// The separator is `0x00` because RFC 3987 excludes control characters
    /// from IRIs, so it cannot occur in either part and one pair can never be
    /// read back as a different pair. A printable separator admits collisions
    /// across resources, which is a cross-resource read and write.
    pub fn of(resource: &ResourceUrl, graph_name: NamedNodeRef<'_>) -> Self {
        // 0x00 as the separator because RFC 3987 excludes control characters
        // from IRIs: it cannot occur in either part, so one pair can never be
        // read back as a different pair.
        let mut h = Sha256::new();
        h.update(resource.graph_iri().as_bytes());
        h.update([0x00]);
        h.update(graph_name.as_str().as_bytes());
        Self(format!("urn:quadpod:subgraph:{}", hex::encode(h.finalize())))
    }

    /// The store graph IRI. Interpolated into SPARQL, so it must be the only
    /// way a shelf is ever addressed.
    pub fn graph_iri(&self) -> &str {
        &self.0
    }

    /// Reconstruct a key the registry already holds. Not a parse, the caller
    /// asserts this came out of `sys:hasSubgraph`, never off the wire.
    pub fn from_registry(iri: &str) -> Self {
        Self(iri.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::{StorageSpace, Target};
    use oxigraph::model::NamedNode;

    fn res(path: &str) -> ResourceUrl {
        match StorageSpace::new("https://pod.toph.so/").unwrap().resolve(path).unwrap() {
            Target::Resource(r) => r,
            other => panic!("{path} is not a resource: {other:?}"),
        }
    }

    #[test]
    fn the_key_separates_pairs_a_printable_separator_would_merge() {
        // The collision a `:` separator admits: the resource IRI may contain a
        // colon in a path segment, and every absolute IRI has one after its
        // scheme, so `<resource>:<graph>` cannot be split back apart.
        let a = ShelfKey::of(&res("/a"), NamedNode::new("urn:x:b").unwrap().as_ref());
        let b = ShelfKey::of(&res("/a:urn"), NamedNode::new("x:b").unwrap().as_ref());
        assert_ne!(a.graph_iri(), b.graph_iri());

        // Same graph name, two resources, the case §2.1 exists for.
        let g = NamedNode::new("urn:example:g1").unwrap();
        assert_ne!(
            ShelfKey::of(&res("/one"), g.as_ref()).graph_iri(),
            ShelfKey::of(&res("/two"), g.as_ref()).graph_iri(),
        );

        // Two names in one resource.
        assert_ne!(
            ShelfKey::of(&res("/one"), NamedNode::new("urn:example:g1").unwrap().as_ref()).graph_iri(),
            ShelfKey::of(&res("/one"), NamedNode::new("urn:example:g2").unwrap().as_ref()).graph_iri(),
        );

        // Deterministic, and shaped as the spec says.
        let k = ShelfKey::of(&res("/one"), g.as_ref());
        assert_eq!(k.graph_iri(), ShelfKey::of(&res("/one"), g.as_ref()).graph_iri());
        let hex = k.graph_iri().strip_prefix("urn:quadpod:subgraph:").expect("prefix");
        assert_eq!(hex.len(), 64, "full sha256, lowercase hex");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // The collision no separator at all admits: with nothing between the two
    // parts, `<resource><graph>` cannot be split back apart, so the byte
    // split can move from the resource/graph boundary to anywhere inside the
    // concatenation, including right before a scheme, since a graph name
    // must be an absolute IRI. Both pairs below concatenate to
    // `https://pod.toph.so/ax:urn:1:2`.
    #[test]
    fn the_key_separates_pairs_no_separator_would_merge() {
        let a = ShelfKey::of(&res("/a"), NamedNode::new("x:urn:1:2").unwrap().as_ref());
        let b = ShelfKey::of(&res("/ax:"), NamedNode::new("urn:1:2").unwrap().as_ref());
        assert_ne!(
            a.graph_iri(),
            b.graph_iri(),
            "no separator between resource and graph name would let (/a, x:urn:1:2) and \
             (/ax:, urn:1:2) hash to the same key"
        );
    }
}
