//! What a resource *is*, and the one place blank nodes are dealt with.
//!
//! The load-bearing distinction is between the two types below, and it is a
//! type distinction rather than a convention: §4's invariant — *no blank
//! node ever reaches the store* — must hold everywhere, and a rule enforced
//! locally, one call site at a time, is exactly the shape that misses one
//! (design spec §4). [`Skolemized`] is the only thing the write path
//! accepts, so "forgot to skolemize" is a compile error and not a leak.
//!
//! It carries [`GroundQuad`], not `Quad`: the invariant is the *shape* of the
//! term types, so a blank node in a stored quad is unwritable rather than
//! merely unwritten. That is what makes [`skolemize`](Skolemized::skolemize)
//! total — it cannot leak a blank node it forgot, because the target has no
//! variant to put one in — and it is why the only fallible construction left,
//! [`from_store`](Skolemized::from_store), sits at the store boundary, where
//! the quads come from outside this type system and refusing them is a parse
//! and not a self-check.

use crate::rdf::{Format, RdfVersion};
use oxigraph::model::{Literal, NamedNode, Quad, Term, Triple};
use sha2::{Digest, Sha256};
use std::fmt;

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
pub struct Skolemized(Vec<GroundQuad>);

/// A quad with no blank node in any position — the store's currency.
///
/// `Quad`'s subject, object and graph name each admit a `BlankNode`, so the
/// stored invariant could only ever be asserted about a `Quad`, and asserted
/// facts rot. Here it is the type: there is no variant to hold a blank node,
/// so the mistakes this replaces (skolemizing and then dropping the result,
/// weakening the check that used to guard the constructor) stop compiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundQuad {
    pub subject: NamedNode,
    pub predicate: NamedNode,
    pub object: GroundTerm,
    pub graph_name: GroundGraphName,
}

/// `Term` minus its blank node — the object position of a [`GroundQuad`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroundTerm {
    NamedNode(NamedNode),
    Literal(Literal),
}

/// `GraphName` minus its blank node. Every graph a stored quad names is
/// named by an IRI, which is what makes
/// [`Skolemized::named_graphs`] exhaustive where [`Dataset::named_graphs`]
/// cannot be (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroundGraphName {
    DefaultGraph,
    NamedNode(NamedNode),
}

impl GroundQuad {
    pub fn new(
        subject: NamedNode,
        predicate: NamedNode,
        object: impl Into<GroundTerm>,
        graph_name: impl Into<GroundGraphName>,
    ) -> Self {
        Self { subject, predicate, object: object.into(), graph_name: graph_name.into() }
    }
}

impl From<NamedNode> for GroundTerm {
    fn from(n: NamedNode) -> Self {
        GroundTerm::NamedNode(n)
    }
}

impl From<Literal> for GroundTerm {
    fn from(l: Literal) -> Self {
        GroundTerm::Literal(l)
    }
}

impl From<NamedNode> for GroundGraphName {
    fn from(n: NamedNode) -> Self {
        GroundGraphName::NamedNode(n)
    }
}

impl From<GroundGraphName> for oxigraph::model::GraphName {
    fn from(g: GroundGraphName) -> Self {
        match g {
            GroundGraphName::DefaultGraph => oxigraph::model::GraphName::DefaultGraph,
            GroundGraphName::NamedNode(n) => oxigraph::model::GraphName::NamedNode(n),
        }
    }
}

impl From<&GroundQuad> for Quad {
    fn from(q: &GroundQuad) -> Self {
        Quad::new(
            q.subject.clone(),
            q.predicate.clone(),
            match &q.object {
                GroundTerm::NamedNode(n) => oxigraph::model::Term::NamedNode(n.clone()),
                GroundTerm::Literal(l) => oxigraph::model::Term::Literal(l.clone()),
            },
            q.graph_name.clone(),
        )
    }
}

/// N-Triples term syntax, as `Term`'s own `Display` writes it — the escaping
/// of quotes, newlines, language tags and datatypes that
/// `resource::serialize_for_insert` interpolates into a SPARQL body.
impl fmt::Display for GroundTerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroundTerm::NamedNode(n) => n.fmt(f),
            GroundTerm::Literal(l) => l.fmt(f),
        }
    }
}

impl Dataset {
    pub fn new(quads: Vec<Quad>) -> Self {
        Self(quads)
    }

    /// The least [`RdfVersion`] under which every term here is expressible.
    ///
    /// **The only place a dataset's version is classified** — see
    /// `docs/constraints.md`. Two classifiers is how the write-side check and
    /// the read-side projection drift apart, and the drift is silent: both
    /// answer, one answers wrong. The check that this replaced saw only
    /// triple terms, and every directional literal walked past it.
    ///
    /// Only the object position can hold a triple term — subjects are
    /// `NamedOrBlankNode` — and only a literal can carry a base direction, so
    /// one pass over the objects decides it.
    pub fn rdf_version(&self) -> RdfVersion {
        let mut found = RdfVersion::Rdf11;
        for q in &self.0 {
            let here = match &q.object {
                Term::Triple(_) => RdfVersion::Rdf12,
                Term::Literal(l) if l.direction().is_some() => RdfVersion::Rdf12Basic,
                _ => continue,
            };
            found = found.max(here);
            if found == RdfVersion::Rdf12 {
                break;
            }
        }
        found
    }

    pub fn quads(&self) -> &[Quad] {
        &self.0
    }

    /// The **IRI-named** graphs this dataset carries, in no particular order.
    /// Drives §6.2's `containsGraph` links, and only those: a `Link` header can
    /// name a graph by IRI and by nothing else, so a graph whose name is a
    /// blank node is deliberately absent from this list.
    ///
    /// It is therefore not the predicate for "is this a dataset" —
    /// [`has_named_graphs`](Self::has_named_graphs) is.
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

    /// Whether any quad sits outside the default graph — a blank-node graph
    /// name counts, which is why this reads the quads rather than asking
    /// [`named_graphs`](Self::named_graphs), whose list is narrower on purpose.
    ///
    /// This is what §3.4 refuses on containers and auxiliaries, asked of a
    /// body on its way in. Defining it as "`named_graphs` is non-empty" makes
    /// `GRAPH _:g { … }` invisible to that decision, and that shape — a blank
    /// node that is both graph name and term — is the deployed Verifiable
    /// Credentials `proof` pattern §4 exists for. On the way back out the
    /// question is asked of [`Skolemized`], where it cannot come apart from
    /// the list at all.
    pub fn has_named_graphs(&self) -> bool {
        self.0.iter().any(|q| q.graph_name != oxigraph::model::GraphName::DefaultGraph)
    }

    /// §3.2.2: any `urn:quadpod:` IRI anywhere — subject, predicate, object or
    /// graph name — is a `400`. Case-insensitive over scheme and NID, because
    /// RFC 8141 makes both case-insensitive and `URN:QUADPOD:` denotes the same
    /// namespace.
    pub fn uses_reserved_namespace(&self) -> bool {
        fn reserved(iri: &str) -> bool {
            // `urn:quadpod:` — scheme and NID are case-insensitive (RFC 8141), the
            // rest of the NSS is not, and only the prefix is ours. `get` returns
            // `None` rather than panicking when byte 12 is not a char boundary —
            // `<urn:quadpodé:x>` is a legal IRI whose 13th byte (the 2-byte `é`
            // starts at byte 11) lands mid-character — which also folds in the
            // length check.
            iri.get(..RESERVED_PREFIX.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(RESERVED_PREFIX))
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

/// A dataset's quads as triples, graph name dropped. Used only where the
/// caller has already established there is no graph name worth keeping —
/// either every quad is already in the default graph, or (the containment
/// check) the graph name is exactly what must not hide anything from it.
pub(crate) fn triples_of(dataset: &Dataset) -> Vec<Triple> {
    dataset.quads().iter().cloned().map(Triple::from).collect()
}

/// The skolem namespace. Only this module writes or matches it — see
/// `docs/constraints.md`.
const SKOLEM_PREFIX: &str = "urn:quadpod:bnode:";

impl Skolemized {
    /// Quads the caller already holds in ground form — server-built content
    /// (`container::ensure_container`, `add_containment`) and the buckets
    /// `resource::put_dataset` splits a stored dataset into. Total, because
    /// [`GroundQuad`] can carry nothing this type would have to refuse.
    pub fn new(quads: Vec<GroundQuad>) -> Self {
        Self(quads)
    }

    /// §4: replace every blank node with a minted IRI, one per distinct blank
    /// node within this document, so co-reference survives — including the
    /// case where a blank node is both a graph name and a term.
    ///
    /// The only conversion from client data, and it is total in both
    /// directions of the word: every input maps, and no input can map to
    /// something that still holds a blank node.
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
        let quads = dataset.quads().iter().map(|q| GroundQuad {
            subject: match &q.subject {
                NamedOrBlankNode::NamedNode(n) => n.clone(),
                NamedOrBlankNode::BlankNode(b) => iri_for(b),
            },
            predicate: q.predicate.clone(),
            object: match &q.object {
                Term::NamedNode(n) => GroundTerm::NamedNode(n.clone()),
                Term::BlankNode(b) => GroundTerm::NamedNode(iri_for(b)),
                Term::Literal(l) => GroundTerm::Literal(l.clone()),
                Term::Triple(_) => unreachable!(
                    "Format::parse refuses RDF 1.2 triple terms, and every Dataset \
                     skolemized here came from it"
                ),
            },
            graph_name: match &q.graph_name {
                GraphName::DefaultGraph => GroundGraphName::DefaultGraph,
                GraphName::NamedNode(n) => GroundGraphName::NamedNode(n.clone()),
                GraphName::BlankNode(b) => GroundGraphName::NamedNode(iri_for(b)),
            },
        }).collect();
        Self(quads)
    }

    /// Quads read back out of the store. `None` when one of them is not
    /// ground, which is the store disagreeing with §4 — corruption, not a
    /// caller mistake, and the callers say so with `expect`.
    ///
    /// This is the only fallible way into the type, and it is a **parse**:
    /// `query_triples` hands back oxigraph's `Term`, outside this module's
    /// type system, and something has to decide what it is. Nothing on the
    /// write path may call it — client data goes through
    /// [`skolemize`](Self::skolemize), server-built data through
    /// [`new`](Self::new) — because a check that runs on our own values is
    /// the check that quietly stops running.
    pub fn from_store(quads: Vec<Quad>) -> Option<Self> {
        use oxigraph::model::{GraphName, NamedOrBlankNode, Term};
        quads.into_iter().map(|q| {
            Some(GroundQuad {
                subject: match q.subject {
                    NamedOrBlankNode::NamedNode(n) => n,
                    NamedOrBlankNode::BlankNode(_) => return None,
                },
                predicate: q.predicate,
                object: match q.object {
                    Term::NamedNode(n) => GroundTerm::NamedNode(n),
                    Term::Literal(l) => GroundTerm::Literal(l),
                    Term::BlankNode(_) => return None,
                    Term::Triple(_) => return None,
                },
                graph_name: match q.graph_name {
                    GraphName::DefaultGraph => GroundGraphName::DefaultGraph,
                    GraphName::NamedNode(n) => GroundGraphName::NamedNode(n),
                    GraphName::BlankNode(_) => return None,
                },
            })
        }).collect::<Option<Vec<_>>>().map(Self)
    }

    pub fn quads(&self) -> &[GroundQuad] {
        &self.0
    }

    /// The graphs this dataset names, in no particular order — **all** of
    /// them, unlike [`Dataset::named_graphs`], because a stored graph name is
    /// an IRI by construction. Every dataset decision the read and write paths
    /// make (§6.2's shape, §6.2.1's refusal, the `containsGraph` count) is
    /// taken over this list rather than the visible one, where a graph the
    /// client named with a blank node would be missing from it.
    pub fn named_graphs(&self) -> Vec<NamedNode> {
        let mut seen: Vec<NamedNode> = Vec::new();
        for q in &self.0 {
            if let GroundGraphName::NamedNode(n) = &q.graph_name {
                if !seen.contains(n) {
                    seen.push(n.clone());
                }
            }
        }
        seen
    }

    /// Whether this is a dataset rather than a lone default graph. Cannot
    /// disagree with [`named_graphs`](Self::named_graphs), which is the whole
    /// point: on the visible side the two questions come apart.
    pub fn has_named_graphs(&self) -> bool {
        self.0.iter().any(|q| q.graph_name != GroundGraphName::DefaultGraph)
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
            let subject = match blank_for(&q.subject) {
                Some(b) => NamedOrBlankNode::BlankNode(b),
                None => NamedOrBlankNode::NamedNode(q.subject.clone()),
            };
            let object = match &q.object {
                GroundTerm::NamedNode(n) => match blank_for(n) {
                    Some(b) => Term::BlankNode(b),
                    None => Term::NamedNode(n.clone()),
                },
                GroundTerm::Literal(l) => Term::Literal(l.clone()),
            };
            let graph_name = match &q.graph_name {
                GroundGraphName::NamedNode(n) => match blank_for(n) {
                    Some(b) => GraphName::BlankNode(b),
                    None => GraphName::NamedNode(n.clone()),
                },
                GroundGraphName::DefaultGraph => GraphName::DefaultGraph,
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
    pub fn etag(&self, fmt: Format) -> String {
        let mut lines: Vec<String> = self.0.iter().map(|q| Quad::from(q).to_string()).collect();
        lines.sort();
        let mut h = Sha256::new();
        h.update(fmt.media_type().as_bytes());
        h.update(b"\n");
        for l in &lines {
            h.update(l.as_bytes());
            h.update(b"\n");
        }
        format!("\"{}\"", hex::encode(h.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxigraph::model::{BlankNode, Literal, NamedNode, Quad};

    /// A quad whose object is an RDF 1.2 triple term.
    fn q_triple_term(s: &str, g: oxigraph::model::GraphName) -> Quad {
        use oxigraph::model::{Term, Triple};
        Quad::new(
            NamedNode::new(s).unwrap(),
            NamedNode::new("http://e/p").unwrap(),
            Term::Triple(Box::new(Triple::new(
                NamedNode::new("http://e/a").unwrap(),
                NamedNode::new("http://e/b").unwrap(),
                NamedNode::new("http://e/c").unwrap(),
            ))),
            g,
        )
    }

    /// A quad whose object is a directional language-tagged string — the
    /// RDF 1.2 addition that is *not* a triple term (§2).
    fn q_directional(s: &str, g: oxigraph::model::GraphName) -> Quad {
        use oxigraph::model::BaseDirection;
        Quad::new(
            NamedNode::new(s).unwrap(),
            NamedNode::new("http://e/p").unwrap(),
            Literal::new_directional_language_tagged_literal("hi", "en", BaseDirection::Ltr)
                .unwrap(),
            g,
        )
    }

    /// §3.1: the least label under which every term is expressible.
    #[test]
    fn a_plain_dataset_classifies_as_1_1() {
        let ds = Dataset::new(vec![q("http://e/s", "v", oxigraph::model::GraphName::DefaultGraph)]);
        assert_eq!(ds.rdf_version(), RdfVersion::Rdf11);
    }

    /// The term kind today's refusal cannot see. §2.
    #[test]
    fn a_directional_literal_classifies_as_1_2_basic() {
        let ds = Dataset::new(vec![q_directional(
            "http://e/s",
            oxigraph::model::GraphName::DefaultGraph,
        )]);
        assert_eq!(ds.rdf_version(), RdfVersion::Rdf12Basic);
    }

    #[test]
    fn a_triple_term_classifies_as_1_2() {
        let ds = Dataset::new(vec![q_triple_term(
            "http://e/s",
            oxigraph::model::GraphName::DefaultGraph,
        )]);
        assert_eq!(ds.rdf_version(), RdfVersion::Rdf12);
    }

    /// The classification is over the whole dataset, so one 1.2 term among
    /// many 1.1 quads still classifies 1.2.
    #[test]
    fn the_classification_is_the_maximum_over_all_terms() {
        use oxigraph::model::GraphName;
        let ds = Dataset::new(vec![
            q("http://e/s", "v", GraphName::DefaultGraph),
            q_directional("http://e/s2", GraphName::DefaultGraph),
            q_triple_term("http://e/s3", GraphName::DefaultGraph),
        ]);
        assert_eq!(ds.rdf_version(), RdfVersion::Rdf12);
    }

    fn q(s: &str, o: &str, g: oxigraph::model::GraphName) -> Quad {
        Quad::new(
            NamedNode::new(s).unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal(o),
            g,
        )
    }

    /// The same quad in stored form.
    fn gq(s: &str, o: &str, g: GroundGraphName) -> GroundQuad {
        GroundQuad::new(
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

    // A `Link` header can name a graph by IRI and by nothing else, so
    // `named_graphs` lists only those — but a blank-named graph is still a
    // graph, and every dataset decision (§3.4's refusal, §6.2's shape,
    // §6.2.1's refusal) hangs off `has_named_graphs`. Defining the predicate
    // as "the list is non-empty" makes `GRAPH _:g { … }` invisible to all
    // three at once.
    #[test]
    fn a_blank_named_graph_is_a_dataset_even_though_it_cannot_be_linked() {
        let ds = Dataset::new(vec![q(
            "http://example.org/s", "inside", BlankNode::default().into())]);
        assert!(ds.named_graphs().is_empty(), "no IRI to put in a Link header");
        assert!(ds.has_named_graphs(), "and yet the quad is not in the default graph");
        assert!(ds.default_graph_only().quads().is_empty(),
            "so a graph format would serve nothing at all");
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

        // §3.2.2 says *any* IRI in the namespace, and the exact prefix IRI is
        // in it — a `>` comparison let it through as neither longer nor shorter.
        let exact = Dataset::new(vec![q(
            "http://example.org/a", "x",
            NamedNode::new(RESERVED_PREFIX).unwrap().into())]);
        assert!(exact.uses_reserved_namespace(), "the exact namespace IRI, with nothing after it");
    }

    // Whole-branch review: `iri[..RESERVED_PREFIX.len()]` slices at byte 12
    // with no char-boundary check. `<urn:quadpodé:x>` is a legal IRI oxrdf
    // accepts, and its `é` (bytes 11-12) puts that cut point mid-character —
    // a panic, not a `400`. Checked in all four quad positions because the
    // guard in `reserved` is applied separately to each one.
    #[test]
    fn a_multi_byte_character_straddling_the_prefix_boundary_does_not_panic() {
        let straddling = "urn:quadpodé:x";

        let subject = Dataset::new(vec![Quad::new(
            NamedNode::new(straddling).unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("x"),
            oxigraph::model::GraphName::DefaultGraph,
        )]);
        assert!(!subject.uses_reserved_namespace(), "as a subject");

        let predicate = Dataset::new(vec![Quad::new(
            NamedNode::new("http://example.org/a").unwrap(),
            NamedNode::new(straddling).unwrap(),
            Literal::new_simple_literal("x"),
            oxigraph::model::GraphName::DefaultGraph,
        )]);
        assert!(!predicate.uses_reserved_namespace(), "as a predicate");

        let object = Dataset::new(vec![Quad::new(
            NamedNode::new("http://example.org/a").unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            NamedNode::new(straddling).unwrap(),
            oxigraph::model::GraphName::DefaultGraph,
        )]);
        assert!(!object.uses_reserved_namespace(), "as an object");

        let graph = Dataset::new(vec![Quad::new(
            NamedNode::new("http://example.org/a").unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("x"),
            NamedNode::new(straddling).unwrap(),
        )]);
        assert!(!graph.uses_reserved_namespace(), "as a graph name");
    }

    // A blank node that is both a graph name and a term. This is the
    // Verifiable Credentials `proof` shape, and solid/specification#291 says
    // a server may not modify those graph names.
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

        // That no blank node reaches the store, not even as a graph name, is
        // no longer assertable here: `GroundGraphName` has no variant to
        // compare against. What is still worth pinning is that the identity
        // survives the round trip — see `tests/unrepresentable.rs`.
        let stored = Skolemized::skolemize(&ds);
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

    // The store is the one source of quads this module cannot type-check on
    // the way in, so `from_store` is a parse: a blank node coming back out is
    // §4 broken underneath us, and reading it as an ordinary quad would put
    // it back on the read path as if it had always been there.
    #[test]
    fn from_store_refuses_content_that_still_has_a_blank_node() {
        let ok = vec![q("http://example.org/s", "x", oxigraph::model::GraphName::DefaultGraph)];
        assert!(Skolemized::from_store(ok).is_some());

        let not_ok = vec![Quad::new(
            BlankNode::default(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("x"),
            oxigraph::model::GraphName::DefaultGraph,
        )];
        assert!(Skolemized::from_store(not_ok).is_none());
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
                GroundTerm::NamedNode(n) => {
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

    #[test]
    fn the_etag_covers_graph_names_and_the_selected_format() {
        let jsonld = Format::from_content_type("application/ld+json").unwrap();
        let trig = Format::from_content_type("application/trig").unwrap();
        let g1 = NamedNode::new("http://example.org/g1").unwrap();
        let g2 = NamedNode::new("http://example.org/g2").unwrap();

        let in_g1 = Skolemized::new(vec![gq("http://example.org/s", "x", g1.into())]);
        let in_g2 = Skolemized::new(vec![gq("http://example.org/s", "x", g2.into())]);

        assert_ne!(in_g1.etag(jsonld), in_g2.etag(jsonld),
            "same triple, different graph — a shared validator would serve the wrong one");
        assert_ne!(in_g1.etag(jsonld), in_g1.etag(trig),
            "different representations are different entities (RFC 9110 §8.8.1)");
        assert_eq!(in_g1.etag(jsonld), in_g1.etag(jsonld), "stable between reads");
    }

    // Every other etag test uses a single-quad dataset, so it can't tell
    // `lines.sort()` apart from no sort at all. This one builds the same two
    // quads in two different orders — mirroring rdf.rs's
    // `serialization_is_canonical_not_merely_repeatable` — so a missing sort
    // fails it.
    #[test]
    fn the_etag_is_order_independent() {
        let jsonld = Format::from_content_type("application/ld+json").unwrap();
        let q1 = gq("http://example.org/a", "A", GroundGraphName::DefaultGraph);
        let q2 = gq("http://example.org/b", "B", GroundGraphName::DefaultGraph);

        let forward = Skolemized::new(vec![q1.clone(), q2.clone()]);
        let backward = Skolemized::new(vec![q2, q1]);

        assert_eq!(forward.etag(jsonld), backward.etag(jsonld),
            "same quads in a different order must share a validator");
    }
}
