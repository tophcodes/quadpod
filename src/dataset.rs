//! What a resource *is*, and the one place blank nodes are dealt with.
//!
//! Skeleton for `docs/superpowers/specs/2026-07-28-jsonld-datasets-design.md`
//! (revision 3). Signatures are fixed here so the plan's tasks fill bodies
//! rather than deciding boundaries one file path at a time.
//!
//! The load-bearing distinction is between the two types below, and it is a
//! type distinction rather than a convention because §4's invariant — *no
//! blank node ever reaches the store* — is otherwise asserted globally and
//! enforced locally, which is what the review found wrong in revision 2.
//! [`Skolemized`] is the only thing the write path accepts, so "forgot to
//! skolemize" is a compile error and not a leak.

use crate::rdf::Format;
use oxigraph::model::{NamedNode, Quad};

/// The reserved namespace. Every server-minted IRI lives under it, and §3.2.2
/// refuses it in request bodies — RDF 1.1 §3.5 preserves meaning only
/// "provided that the Skolem IRIs do not occur anywhere else".
pub const RESERVED_PREFIX: &str = "urn:quadpod:";

/// A dataset as a client wrote it or will read it: blank nodes intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset(Vec<Quad>);

/// A dataset as the store holds it: every blank node replaced by a
/// `urn:quadpod:bnode:<uuid>` IRI, in triples and as graph names alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skolemized(Vec<Quad>);

impl Dataset {
    pub fn new(quads: Vec<Quad>) -> Self {
        Self(quads)
    }

    pub fn quads(&self) -> &[Quad] {
        &self.0
    }

    /// The graph names this dataset carries, in no particular order. Drives
    /// §6.2's `containsGraph` links and §6.3's "can this format serve it".
    pub fn named_graphs(&self) -> Vec<NamedNode> {
        let mut seen: Vec<NamedNode> = Vec::new();
        for q in &self.0 {
            if let oxigraph::model::GraphName::NamedNode(n) = &q.graph_name {
                if !seen.contains(n) {
                    seen.push(n.clone());
                }
            }
        }
        seen
    }

    pub fn has_named_graphs(&self) -> bool {
        !self.named_graphs().is_empty()
    }

    /// §3.2.2: any `urn:quadpod:` IRI anywhere — subject, predicate, object or
    /// graph name — is a `400`. Case-insensitive over scheme and NID, because
    /// RFC 8141 makes both case-insensitive and `URN:QUADPOD:` denotes the same
    /// namespace.
    pub fn uses_reserved_namespace(&self) -> bool {
        fn reserved(iri: &str) -> bool {
            // `urn:quadpod:` — scheme and NID are case-insensitive (RFC 8141), the
            // rest of the NSS is not, and only the prefix is ours.
            iri.len() > RESERVED_PREFIX.len()
                && iri[..RESERVED_PREFIX.len()].eq_ignore_ascii_case(RESERVED_PREFIX)
        }
        self.0.iter().any(|q| {
            let subject = match &q.subject {
                oxigraph::model::NamedOrBlankNode::NamedNode(n) => reserved(n.as_str()),
                _ => false,
            };
            let object = match &q.object {
                oxigraph::model::Term::NamedNode(n) => reserved(n.as_str()),
                _ => false,
            };
            let graph = match &q.graph_name {
                oxigraph::model::GraphName::NamedNode(n) => reserved(n.as_str()),
                _ => false,
            };
            subject || object || graph || reserved(q.predicate.as_str())
        })
    }

    /// The default graph alone, for the graph-format answer of §6.2.
    pub fn default_graph_only(&self) -> Dataset {
        Dataset::new(
            self.0.iter()
                .filter(|q| q.graph_name == oxigraph::model::GraphName::DefaultGraph)
                .cloned()
                .collect(),
        )
    }
}

impl Skolemized {
    /// §4: replace every blank node with a minted IRI, one per distinct blank
    /// node within this document, so co-reference survives — including the
    /// case where a blank node is both a graph name and a term.
    // skeleton: the attribute goes when the body lands
    #[allow(unused_variables)]
    pub fn skolemize(dataset: &Dataset) -> Self {
        todo!("skeleton")
    }

    /// Server-built content that is already ground. `None` if it is not, which
    /// is the choke point replacing revision 2's per-handler enforcement:
    /// `container::ensure_container`, `add_containment` and auxiliary
    /// provisioning all come through here.
    // skeleton: the attribute goes when the body lands
    #[allow(unused_variables)]
    pub fn ground(quads: Vec<Quad>) -> Option<Self> {
        todo!("skeleton")
    }

    pub fn quads(&self) -> &[Quad] {
        &self.0
    }

    /// §4: back to blank nodes, one per distinct skolem IRI, **with a label
    /// derived from the skolem IRI** — a fresh label per read would break
    /// §6.4's byte-identical guarantee.
    pub fn deskolemize(&self) -> Dataset {
        todo!("skeleton")
    }

    /// §6.1: the validator, over the stored quads *before* de-skolemization and
    /// over the selected format. Graph names participate, or two datasets
    /// differing only in which graph a statement sits in share a validator.
    ///
    /// A method rather than a free function because the thing it identifies is
    /// this value: hashing something else, or hashing after the blank nodes
    /// come back, is the mistake — and both are harder to write by accident
    /// when the hash belongs to the stored form.
    // skeleton: the attribute goes when the body lands
    #[allow(unused_variables)]
    pub fn etag(&self, fmt: Format) -> String {
        todo!("skeleton")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxigraph::model::{Literal, NamedNode, Quad};

    fn q(s: &str, o: &str, g: oxigraph::model::GraphName) -> Quad {
        Quad::new(
            NamedNode::new(s).unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal(o),
            g,
        )
    }

    #[test]
    fn named_graphs_are_listed_once_and_the_default_graph_is_not_one() {
        let g1 = NamedNode::new("http://example.org/g1").unwrap();
        let ds = Dataset::new(vec![
            q("http://example.org/a", "A", g1.clone().into()),
            q("http://example.org/b", "B", g1.into()),
            q("http://example.org/c", "C", oxigraph::model::GraphName::DefaultGraph),
        ]);
        assert_eq!(ds.named_graphs().len(), 1, "two quads, one graph name");
        assert!(ds.has_named_graphs());
        assert_eq!(ds.default_graph_only().quads().len(), 1);
    }

    // §3.2.2. RFC 8141 makes the URN scheme and NID case-insensitive, so a
    // literal prefix comparison lets `URN:QUADPOD:` through — and a document that
    // gets through here comes back with its IRI rewritten into a blank node.
    #[test]
    fn the_reserved_namespace_is_refused_in_any_position_and_any_case() {
        let reserved = "urn:quadpod:bnode:1234";
        let subject = Dataset::new(vec![q(reserved, "x", oxigraph::model::GraphName::DefaultGraph)]);
        assert!(subject.uses_reserved_namespace(), "as a subject");

        let object = Dataset::new(vec![Quad::new(
            NamedNode::new("http://example.org/a").unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            NamedNode::new(reserved).unwrap(),
            oxigraph::model::GraphName::DefaultGraph,
        )]);
        assert!(object.uses_reserved_namespace(), "as an object");

        let graph = Dataset::new(vec![q(
            "http://example.org/a", "x",
            NamedNode::new("URN:QUADPOD:subgraph:dead").unwrap().into())]);
        assert!(graph.uses_reserved_namespace(), "as a graph name, upper-case");

        let clean = Dataset::new(vec![q(
            "http://example.org/a", "x",
            NamedNode::new("urn:podcast:1").unwrap().into())]);
        assert!(!clean.uses_reserved_namespace(), "a longer NID is a different namespace");
    }
}
