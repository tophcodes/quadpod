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

// The second measurement — that `oxttl` produces a directional
// language-tagged string — now lives in `rdf::tests`, as
// `a_directional_literal_is_refused_too`. It measures the same fact from the
// other side: the refusal reports `Rdf12Basic`, which is only reachable if
// the parser built such a literal in the first place.
