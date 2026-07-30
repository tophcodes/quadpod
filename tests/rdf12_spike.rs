//! Task 0 of the RDF 1.2 plan: the two measurements the design rests on.
//! Delete this file once Task 7 lands — its properties are covered there by
//! tests that go through the HTTP surface instead of around it.

use sparql_pod::store::{OxigraphStore, SparqlStore};

/// The store must accept SPARQL 1.2 syntax in an update and hand the term
/// back through a CONSTRUCT. If this fails, the design is not implementable:
/// the pod talks to the store only in SPARQL strings.
#[tokio::test]
async fn store_round_trips_a_triple_term() {
    let store = OxigraphStore::in_memory().expect("in-memory store");
    store
        .update(
            "INSERT DATA { GRAPH <http://e/g> { \
             <http://e/s> <http://e/p> <<( <http://e/a> <http://e/b> <http://e/c> )>> } }",
        )
        .await
        .expect("INSERT DATA with a triple term must be accepted");

    let triples = store
        .query_triples("CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <http://e/g> { ?s ?p ?o } }")
        .await
        .expect("CONSTRUCT must succeed");

    assert_eq!(triples.len(), 1, "one triple back");
    assert!(
        matches!(triples[0].object, oxigraph::model::Term::Triple(_)),
        "the object must come back as a triple term, got {:?}",
        triples[0].object
    );
}

/// The Turtle parser must produce a directional language-tagged string.
/// This is the term kind today's refusal does not see (design §2): it is a
/// `Term::Literal`, so the `Term::Triple` check never looks at it.
#[test]
fn turtle_parses_a_directional_literal() {
    use sparql_pod::rdf::Format;
    let fmt = Format::from_content_type("text/turtle").expect("turtle is supported");
    let ttl = br#"<http://e/s> <http://e/p> "hello"@en--ltr ."#;
    let ds = fmt
        .parse(ttl, "http://e/")
        .expect("a directional literal must parse — it is not a triple term");
    let oxigraph::model::Term::Literal(l) = &ds.quads()[0].object else {
        panic!("expected a literal, got {:?}", ds.quads()[0].object);
    };
    assert!(l.direction().is_some(), "the base direction must survive parsing");
}
