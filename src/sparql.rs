//! Values that may be interpolated into a SPARQL update or query.
//!
//! The store is written by string concatenation, so a value whose alphabet is
//! not established is a value that can leave its delimiter and continue the
//! update as syntax. This module holds the types that make that
//! unrepresentable for the one shape where the delimiter is a quote.
//!
//! IRIs need no type here: every `<...>` interpolation in this crate is fed by
//! `space::GraphName` (sealed), by `shelf::ShelfKey`, or by a name already
//! validated through `NamedNode::new`.

use std::fmt;

/// A literal, rendered with its quotes and escapes.
///
/// The escaping is oxrdf's: `oxigraph::model::Literal`'s `Display` already
/// produces the quoted, escaped N-Triples form — the quotes are not added
/// here — which is what `resource::serialize_for_insert` already relies on
/// for every triple this pod writes. Rendering through it rather than beside
/// it is the point — a second escaper is a second thing to get right, and the
/// two would drift silently because both would still produce output.
pub struct Literal(String);

impl Literal {
    pub fn new(value: &oxigraph::model::Literal) -> Self {
        Self(value.to_string())
    }
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxigraph::model::Literal as OxLiteral;

    // The escaping is oxrdf's, not ours — this pins that we render through it
    // rather than beside it. A second escaper is how two write paths come to
    // disagree about one backslash.
    #[test]
    fn a_literal_renders_quoted_and_escaped() {
        assert_eq!(Literal::new(&OxLiteral::new_simple_literal("plain")).to_string(), "\"plain\"");

        for raw in ["has \" quote", "has \\ backslash", "has \n newline", "has \r return"] {
            let rendered = Literal::new(&OxLiteral::new_simple_literal(raw)).to_string();
            let inner = &rendered[1..rendered.len() - 1];
            assert!(
                !inner.contains('"') || inner.contains("\\\""),
                "{raw:?} rendered as {rendered:?}: a bare quote would close the literal"
            );
            assert!(!inner.contains('\n') && !inner.contains('\r'),
                "{raw:?} rendered as {rendered:?}: a raw newline is not legal in STRING_LITERAL2");
        }
    }

    // The whole point: what comes out can be concatenated into an update and
    // still parse. Asserted by round-tripping through the store, not by
    // eyeballing the string — a rendering that merely *looks* escaped but is
    // not would pass a string comparison against a hand-written expectation.
    #[tokio::test]
    async fn a_rendered_literal_survives_an_actual_insert() {
        use crate::store::{OxigraphStore, SparqlStore};
        let store = OxigraphStore::in_memory().unwrap();
        let nasty = "x\" . } DROP ALL ; INSERT DATA { GRAPH <urn:evil> { <urn:a> <urn:b> \"pwned";
        let lit = Literal::new(&OxLiteral::new_simple_literal(nasty));

        store.update(&format!(
            "INSERT DATA {{ GRAPH <urn:test:g> {{ <urn:test:s> <urn:test:p> {lit} }} }}"
        )).await.unwrap();

        let back = store.query_triples(
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <urn:test:g> { ?s ?p ?o } }"
        ).await.unwrap();
        assert_eq!(back.len(), 1);
        assert!(
            matches!(&back[0].object, oxigraph::model::Term::Literal(l) if l.value() == nasty),
            "the value must come back exactly, not truncated at the quote"
        );
        // The injected DROP ALL must not have run.
        assert!(!store.ask("ASK { GRAPH <urn:evil> { ?s ?p ?o } }").await.unwrap(),
            "the payload was executed as syntax rather than stored as data");
    }
}
