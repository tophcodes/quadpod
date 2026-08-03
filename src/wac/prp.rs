//! The WAC policy retrieval point: find the ACL that governs a resource.
//!
//! The ACL of `<res>` is `<res>`'s auxiliary of kind [`AuxKind::Acl`]. If it
//! has no representation, WAC inheritance applies: walk up the container
//! chain and use the first ACL found there, evaluated through `acl:default`.
//! The first ACL found wins completely — ancestor rules are never merged in,
//! because merging would make revoking access on a subtree impossible.
//!
//! The candidate chain comes from [`ResourceUrl::ancestors`], the same
//! derivation the guard authorizes against. There is deliberately no second
//! way to compute it.

use oxigraph::model::Triple;

use crate::{
    resource::ResourceError,
    space::{AuxKind, GraphName, ResourceUrl},
    store::SparqlStore,
};

/// The triples of every ACL in `chain` that exists, keyed by the IRI of the
/// resource it governs.
///
/// `present` is the probe's answer (`resource::exists_many`), so this asks the
/// store nothing about existence — it reads the set it was handed and fetches
/// only the graphs already known to be there, in one query.
///
/// Eager rather than lazy, and that is forced: `Guard::authorize` is
/// synchronous, so there is no `await` left at the point a level's ACL is
/// chosen. Loading the whole chain's ACLs costs one query for a set bounded by
/// the chain, and is usually one document — a lazy per-level fetch would cost
/// the synchronous decision instead.
pub async fn load_chain_acls(
    store: &dyn SparqlStore,
    chain: &[ResourceUrl],
    present: &std::collections::HashSet<String>,
) -> Result<std::collections::HashMap<String, Vec<Triple>>, ResourceError> {
    // ACL graph IRI -> the IRI of the resource it governs.
    let mut governed: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut values = String::new();
    for element in chain {
        let acl = element.aux(AuxKind::Acl);
        let acl_iri = acl.graph_iri();
        if !present.contains(acl_iri) {
            continue;
        }
        values.push_str(&format!("<{acl_iri}> "));
        governed.insert(acl_iri.to_owned(), element.graph_iri().to_owned());
    }
    // Seeded with an empty vector per existing ACL *before* the query: an ACL
    // that holds no triples yields no solutions, and it must still be found —
    // an empty ACL grants nothing, which is the opposite of falling through to
    // an ancestor.
    let mut out: std::collections::HashMap<String, Vec<Triple>> =
        governed.values().map(|g| (g.clone(), Vec::new())).collect();
    if governed.is_empty() {
        return Ok(out);
    }

    let rows = store
        .query_solutions(&format!(
            "SELECT ?g ?s ?p ?o WHERE {{ VALUES ?g {{ {values} }} \
             GRAPH ?g {{ ?s ?p ?o }} }}"
        ))
        .await?;
    for row in &rows {
        let (Some(oxigraph::model::Term::NamedNode(g)), Some(s), Some(p), Some(o)) =
            (row.get("g"), row.get("s"), row.get("p"), row.get("o"))
        else {
            continue;
        };
        let subject = match s {
            oxigraph::model::Term::NamedNode(n) => oxigraph::model::NamedOrBlankNode::NamedNode(n.clone()),
            oxigraph::model::Term::BlankNode(b) => oxigraph::model::NamedOrBlankNode::BlankNode(b.clone()),
            _ => continue,
        };
        let (Some(key), oxigraph::model::Term::NamedNode(predicate)) =
            (governed.get(g.as_str()), p.clone())
        else {
            continue;
        };
        out.entry(key.clone())
            .or_default()
            .push(Triple::new(subject, predicate, o.clone()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{ACL_AGENT, ACL_DEFAULT, ACL_MODE, ACL_READ};
    use crate::{rdf::Format, resource::put_rdf, space::{AuxKind, StorageSpace, Target}, store::OxigraphStore};

    const ALICE: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn res(path: &str) -> ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    async fn write_acl(store: &OxigraphStore, subject_path: &str, turtle: &str) {
        let subject = res(subject_path);
        put_rdf(store, &subject, &[]).await.unwrap();
        let aux = subject.aux(AuxKind::Acl);
        let t: Vec<Triple> = Format::from_content_type("text/turtle").unwrap()
            .parse(turtle.as_bytes(), aux.graph_iri(), crate::rdf::RdfVersion::Rdf11).unwrap()
            .quads().iter().cloned().map(Triple::from).collect();
        crate::aux::put(store, &aux, &t).await.unwrap();
    }

    use std::collections::HashSet;

    /// The probe's answer for a chain, computed the honest way so these tests
    /// exercise `load_chain_acls` rather than a hand-built fixture.
    async fn probe(store: &OxigraphStore, chain: &[ResourceUrl]) -> HashSet<String> {
        let auxes: Vec<_> = chain.iter().map(|r| r.aux(AuxKind::Acl)).collect();
        let refs: Vec<&dyn crate::space::GraphName> =
            auxes.iter().map(|a| a as &dyn crate::space::GraphName).collect();
        crate::resource::exists_many(store, &refs).await.unwrap()
    }

    #[tokio::test]
    async fn load_chain_acls_keys_by_governed_iri() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/box/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let chain = vec![res("/box/item"), res("/box/"), res("/")];
        let present = probe(&store, &chain).await;

        let acls = load_chain_acls(&store, &chain, &present).await.unwrap();
        assert_eq!(acls.len(), 1, "only /box/ has an ACL");
        let triples = acls.get("https://pod.toph.so/box/").expect("keyed by what it governs");
        assert!(triples.iter().any(|t| t.predicate.as_str() == ACL_MODE));
    }

    // The fixture that makes empty ACLs work: an ACL that exists but holds no
    // triples is a policy ("nothing is granted here") and must appear in the
    // map, or the guard walks past it to an ancestor grant it was written to
    // override.
    #[tokio::test]
    async fn an_existing_but_empty_acl_gets_an_entry() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/locked/", "").await;
        let chain = vec![res("/locked/x"), res("/locked/"), res("/")];
        let present = probe(&store, &chain).await;

        let acls = load_chain_acls(&store, &chain, &present).await.unwrap();
        let triples = acls.get("https://pod.toph.so/locked/").expect("an empty ACL is still an ACL");
        assert!(triples.is_empty());
    }

    #[tokio::test]
    async fn two_acls_in_one_chain_both_load() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/", &format!(
            "<#root> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        write_acl(&store, "/box/", &format!(
            "<#box> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let chain = vec![res("/box/item"), res("/box/"), res("/")];
        let present = probe(&store, &chain).await;

        let acls = load_chain_acls(&store, &chain, &present).await.unwrap();
        assert_eq!(acls.len(), 2);
        assert!(acls.contains_key("https://pod.toph.so/"));
        assert!(acls.contains_key("https://pod.toph.so/box/"));
    }

    #[tokio::test]
    async fn a_chain_with_no_acls_loads_nothing() {
        let store = OxigraphStore::in_memory().unwrap();
        let chain = vec![res("/foo")];
        let acls = load_chain_acls(&store, &chain, &HashSet::new()).await.unwrap();
        assert!(acls.is_empty());
    }
}
