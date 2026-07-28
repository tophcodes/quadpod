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

/// The skolem namespace. Only this module writes or matches it — see
/// `docs/constraints.md`.
const SKOLEM_PREFIX: &str = "urn:quadpod:bnode:";

impl Skolemized {
    /// §4: replace every blank node with a minted IRI, one per distinct blank
    /// node within this document, so co-reference survives — including the
    /// case where a blank node is both a graph name and a term.
    pub fn skolemize(dataset: &Dataset) -> Self {
        use oxigraph::model::{GraphName, NamedOrBlankNode, Term};
        let mut minted: std::collections::HashMap<String, NamedNode> = std::collections::HashMap::new();
        let mut iri_for = |b: &oxigraph::model::BlankNode| -> NamedNode {
            minted.entry(b.as_str().to_owned())
                .or_insert_with(|| {
                    NamedNode::new(format!("{SKOLEM_PREFIX}{}", uuid::Uuid::new_v4()))
                        .expect("a uuid is IRI-safe")
                })
                .clone()
        };
        let quads = dataset.quads().iter().map(|q| {
            let subject = match &q.subject {
                NamedOrBlankNode::BlankNode(b) => NamedOrBlankNode::NamedNode(iri_for(b)),
                other => other.clone(),
            };
            let object = match &q.object {
                Term::BlankNode(b) => Term::NamedNode(iri_for(b)),
                other => other.clone(),
            };
            let graph_name = match &q.graph_name {
                GraphName::BlankNode(b) => GraphName::NamedNode(iri_for(b)),
                other => other.clone(),
            };
            Quad { subject, predicate: q.predicate.clone(), object, graph_name }
        }).collect();
        Self(quads)
    }

    /// Server-built content that is already ground. `None` if it is not, which
    /// is the choke point replacing revision 2's per-handler enforcement:
    /// `container::ensure_container`, `add_containment` and auxiliary
    /// provisioning all come through here.
    pub fn ground(quads: Vec<Quad>) -> Option<Self> {
        use oxigraph::model::{GraphName, NamedOrBlankNode, Term};
        let blank = quads.iter().any(|q| {
            matches!(q.subject, NamedOrBlankNode::BlankNode(_))
                || matches!(q.object, Term::BlankNode(_))
                || matches!(q.graph_name, GraphName::BlankNode(_))
        });
        (!blank).then_some(Self(quads))
    }

    pub fn quads(&self) -> &[Quad] {
        &self.0
    }

    /// §4: back to blank nodes, one per distinct skolem IRI, **with a label
    /// derived from the skolem IRI** — a fresh label per read would break
    /// §6.4's byte-identical guarantee.
    pub fn deskolemize(&self) -> Dataset {
        use oxigraph::model::{BlankNode, GraphName, NamedOrBlankNode, Term};
        // The label is derived from the IRI, not generated: two reads of one
        // stored state must produce identical bytes (§6.4).
        fn blank_for(n: &NamedNode) -> Option<BlankNode> {
            let suffix = n.as_str().strip_prefix(SKOLEM_PREFIX)?;
            let label: String = suffix.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            BlankNode::new(format!("b{label}")).ok()
        }
        let quads = self.0.iter().map(|q| {
            let subject = match &q.subject {
                NamedOrBlankNode::NamedNode(n) => match blank_for(n) {
                    Some(b) => NamedOrBlankNode::BlankNode(b),
                    None => q.subject.clone(),
                },
                other => other.clone(),
            };
            let object = match &q.object {
                Term::NamedNode(n) => match blank_for(n) {
                    Some(b) => Term::BlankNode(b),
                    None => q.object.clone(),
                },
                other => other.clone(),
            };
            let graph_name = match &q.graph_name {
                GraphName::NamedNode(n) => match blank_for(n) {
                    Some(b) => GraphName::BlankNode(b),
                    None => q.graph_name.clone(),
                },
                other => other.clone(),
            };
            Quad { subject, predicate: q.predicate.clone(), object, graph_name }
        }).collect();
        Dataset::new(quads)
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
    use oxigraph::model::{BlankNode, Literal, NamedNode, Quad};

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

        let predicate = Dataset::new(vec![Quad::new(
            NamedNode::new("http://example.org/a").unwrap(),
            NamedNode::new(reserved).unwrap(),
            Literal::new_simple_literal("x"),
            oxigraph::model::GraphName::DefaultGraph,
        )]);
        assert!(predicate.uses_reserved_namespace(), "as a predicate");

        let graph = Dataset::new(vec![q(
            "http://example.org/a", "x",
            NamedNode::new("URN:QUADPOD:subgraph:dead").unwrap().into())]);
        assert!(graph.uses_reserved_namespace(), "as a graph name, upper-case");

        let clean = Dataset::new(vec![q(
            "http://example.org/a", "x",
            NamedNode::new("urn:podcast:1").unwrap().into())]);
        assert!(!clean.uses_reserved_namespace(), "a longer NID is a different namespace");
    }

    // The case revision 2 got wrong: a blank node that is both a graph name and
    // a term. This is the Verifiable Credentials `proof` shape, and
    // solid/specification#291 says a server may not modify those graph names.
    #[test]
    fn a_blank_node_that_is_both_graph_name_and_term_keeps_its_identity() {
        let b = BlankNode::default();
        let ds = Dataset::new(vec![
            // <top> :points _:b
            Quad::new(
                NamedNode::new("http://example.org/top").unwrap(),
                NamedNode::new("http://example.org/points").unwrap(),
                b.clone(),
                oxigraph::model::GraphName::DefaultGraph,
            ),
            // GRAPH _:b { <s> :name "inside" }
            q("http://example.org/s", "inside", b.clone().into()),
        ]);

        let stored = Skolemized::skolemize(&ds);
        assert!(
            stored.quads().iter().all(|q| !matches!(
                q.graph_name, oxigraph::model::GraphName::BlankNode(_))),
            "no blank node reaches the store, not even as a graph name"
        );

        let back = stored.deskolemize();
        let graph_node = back.quads().iter()
            .find_map(|q| match &q.graph_name {
                oxigraph::model::GraphName::BlankNode(n) => Some(n.clone()),
                _ => None,
            })
            .expect("the named graph came back blank");
        let object_node = back.quads().iter()
            .find_map(|q| match &q.object {
                oxigraph::model::Term::BlankNode(n) => Some(n.clone()),
                _ => None,
            })
            .expect("the object came back blank");
        assert_eq!(graph_node, object_node, "co-reference survived the round trip");
    }

    #[test]
    fn deskolemization_is_stable_across_reads() {
        let b = BlankNode::default();
        let stored = Skolemized::skolemize(&Dataset::new(vec![q(
            "http://example.org/s", "x", b.into())]));
        assert_eq!(stored.deskolemize(), stored.deskolemize(),
            "a fresh label per read would break the byte-identical guarantee");
    }

    #[test]
    fn ground_refuses_content_that_still_has_a_blank_node() {
        let ok = vec![q("http://example.org/s", "x", oxigraph::model::GraphName::DefaultGraph)];
        assert!(Skolemized::ground(ok).is_some());

        let not_ok = vec![Quad::new(
            BlankNode::default(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("x"),
            oxigraph::model::GraphName::DefaultGraph,
        )];
        assert!(Skolemized::ground(not_ok).is_none());
    }

    #[test]
    fn distinct_blank_nodes_stay_distinct() {
        let b1 = BlankNode::new("b1").unwrap();
        let b2 = BlankNode::new("b2").unwrap();

        let ds = Dataset::new(vec![
            Quad::new(
                NamedNode::new("http://example.org/a").unwrap(),
                NamedNode::new("http://example.org/links").unwrap(),
                b1.clone(),
                oxigraph::model::GraphName::DefaultGraph,
            ),
            Quad::new(
                NamedNode::new("http://example.org/c").unwrap(),
                NamedNode::new("http://example.org/links").unwrap(),
                b2.clone(),
                oxigraph::model::GraphName::DefaultGraph,
            ),
        ]);

        let stored = Skolemized::skolemize(&ds);

        // Collect all skolem IRIs in the stored dataset
        let skolem_iris: Vec<String> = stored.quads().iter()
            .filter_map(|q| match &q.object {
                oxigraph::model::Term::NamedNode(n) => {
                    if n.as_str().starts_with("urn:quadpod:bnode:") {
                        Some(n.as_str().to_string())
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();
        assert_eq!(skolem_iris.len(), 2, "two distinct blank nodes should get two distinct skolem IRIs");
        assert_ne!(skolem_iris[0], skolem_iris[1], "each blank node gets its own skolem IRI");

        // Verify the round trip preserves distinctness
        let back = stored.deskolemize();
        let blank_nodes: Vec<oxigraph::model::BlankNode> = back.quads().iter()
            .filter_map(|q| match &q.object {
                oxigraph::model::Term::BlankNode(b) => Some(b.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(blank_nodes.len(), 2, "deskolemization should restore both blank nodes");
        assert_ne!(blank_nodes[0], blank_nodes[1], "the two blank nodes should remain distinct");
    }
}
