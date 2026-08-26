//! Named graphs, blank graph names, and the dataset formats.

use super::fixture::*;

#[tokio::test]
async fn a_jsonld_dataset_round_trips_over_http() {
    let f = fixture().await;
    let body = r#"{"@context":{"name":"http://schema.org/name"},
      "@graph":[{"@id":"urn:example:g1","@graph":[{"@id":"http://example.org/alice","name":"Alice"}]},
                {"@id":"http://example.org/bob","name":"Bob"}]}"#;
    let put = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/ld+json")
        .body(Body::from(body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_string(res).await.contains("urn:example:g1"), "the graph name survived");
}

#[tokio::test]
async fn turtle_gets_the_default_graph_and_is_told_what_it_is_missing() {
    let f = fixture().await;
    let body = r#"{"@graph":[{"@id":"urn:example:g1",
      "@graph":[{"@id":"http://example.org/alice","http://schema.org/name":"Alice"}]}]}"#;
    let put = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/ld+json")
        .body(Body::from(body)).unwrap();
    f.app.clone().oneshot(put).await.unwrap();

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "§6.2: not a 406");
    assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
    let links: Vec<_> = res.headers().get_all(header::LINK).iter()
        .map(|v| v.to_str().unwrap().to_owned()).collect();
    assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains("urn:example:g1")),
        "the client learns which graphs it did not get: {links:?}");
    assert!(links.iter().any(|l| l.contains("alternate") && l.contains("application/trig")));
}

// §6.2.1: GET as Turtle, edit, PUT back would otherwise destroy every named
// graph with a 2xx and no warning.
#[tokio::test]
async fn a_graph_format_write_over_named_graphs_is_refused() {
    let f = fixture().await;
    let body = r#"{"@graph":[{"@id":"urn:example:g1",
      "@graph":[{"@id":"http://example.org/alice","http://schema.org/name":"Alice"}]}]}"#;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/ld+json")
        .body(Body::from(body)).unwrap()).await.unwrap();

    let overwrite = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(overwrite).await.unwrap().status(), StatusCode::CONFLICT);

    // and nothing changed
    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
    assert!(body_string(f.app.clone().oneshot(get).await.unwrap()).await.contains("urn:example:g1"));
}

#[tokio::test]
async fn the_reserved_namespace_and_container_datasets_are_refused() {
    let f = fixture().await;
    // Any IRI under the reserved prefix triggers the refusal, this one
    // avoids the skolem sub-namespace that only `dataset` may write or
    // match (`docs/constraints.md`).
    let reserved = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<urn:quadpod:evil:x> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(reserved).await.unwrap().status(), StatusCode::BAD_REQUEST);

    let container = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from("<urn:example:g1> { <http://example.org/a> <http://schema.org/name> \"x\" }")).unwrap();
    assert_eq!(f.app.oneshot(container).await.unwrap().status(), StatusCode::BAD_REQUEST);
}

// Containers and auxiliaries are skolemized on the way in like everything
// else; without the matching step out, a client's blank node comes back as
// an IRI it never wrote.
#[tokio::test]
async fn an_acl_containing_a_blank_node_round_trips_as_a_blank_node() {
    let f = fixture().await;
    // A second, named authorization keeps OWNER's Control over /c/notes,
    // without it this ACL would deny even its own author the Control
    // needed to read it back, which is a real (and separately tested) WAC
    // rule, not what this test is about.
    let acl = format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         <#owner> a acl:Authorization ; acl:agent <{OWNER}> ; \
            acl:mode acl:Control, acl:Read, acl:Write ; acl:accessTo </c/notes> .\n\
         [] a acl:Authorization ; acl:mode acl:Read ; \
            acl:agentClass <http://xmlns.com/foaf/0.1/Agent> ; \
            acl:accessTo </c/notes> ."
    );
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
    let put = f.owner_request("PUT", "/.aux/c/notes.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl)).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    let get = f.owner_request("GET", "/.aux/c/notes.acl")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let out = body_string(f.app.oneshot(get).await.unwrap()).await;
    // The constant, not a hardcoded literal: only `dataset` may write or
    // match the skolem sub-namespace it lives under (`docs/constraints.md`).
    assert!(!out.contains(crate::dataset::RESERVED_PREFIX),
        "the server's internal IRI must not reach a client: {out}");
    assert!(out.contains("acl:Authorization") || out.contains("auth/acl#Authorization"),
        "and the rule itself survived: {out}");
}

/// A resource whose only content sits in a graph the client named with a
/// blank node. TriG is the only way to write one over HTTP, and the shape
/// is the deployed Verifiable Credentials `proof` pattern (§4).
const BLANK_NAMED_GRAPH_TRIG: &str =
    "_:g { <http://example.org/alice> <http://schema.org/name> \"Alice\" }";

// §6.2, on the input that used to be invisible to every dataset decision:
// a blank-node graph name is not an IRI, so nothing a `Link` header can
// name, but the resource is still a dataset, and a graph format still
// serves only part of it. Before, this answered `200` with an empty body
// and no indication anything existed at all, which is the exact silent
// loss §6.2 exists to prevent.
#[tokio::test]
async fn a_blank_named_graph_is_a_dataset_and_a_graph_format_is_told_so() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let links: Vec<String> = res.headers().get_all(header::LINK).iter()
        .map(|v| v.to_str().unwrap().to_owned()).collect();
    assert!(links.iter().any(|l| l.contains("alternate") && l.contains("application/trig")),
        "the client must be told the whole thing is available elsewhere: {links:?}");
    assert!(!links.iter().any(|l| l.contains("containsGraph")),
        "and not under a name it never wrote: {links:?}");
    assert!(!body_string(res).await.contains("Alice"),
        "the withheld graph is withheld, not merged into the default graph");
}

// §6.3 on the same input: the client offered a format that carries the
// whole resource, so preferring the lossy one it happened to list first is
// the wrong answer, and it is what a shape read off the de-skolemized view
// produces, since the graph name is a blank node again there.
#[tokio::test]
async fn a_blank_named_graph_makes_negotiation_prefer_a_dataset_format() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap()).await.unwrap();

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "text/turtle, application/trig").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/trig");
    let out = body_string(res).await;
    assert!(out.contains("Alice"), "and it carries the graph: {out}");
    assert!(!out.contains(crate::dataset::RESERVED_PREFIX),
        "under a blank node, not the server's internal IRI: {out}");
}

// §6.2.1 on the same input. The refusal cannot name the graph (the client
// never wrote a name for it), but it must still refuse, or a Turtle write
// destroys it with a `201` and no warning.
#[tokio::test]
async fn a_graph_format_write_over_a_blank_named_graph_is_refused() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap()).await.unwrap();

    let overwrite = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    let res = f.app.clone().oneshot(overwrite).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let body = body_string(res).await;
    assert!(body.contains("named by a blank node"),
        "the refusal accounts for what it is refusing to destroy: {body}");
    assert!(!body.contains(crate::dataset::RESERVED_PREFIX),
        "without leaking the server's internal IRI: {body}");

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
    assert!(body_string(f.app.oneshot(get).await.unwrap()).await.contains("Alice"),
        "and nothing was destroyed");
}

// §3.4, which runs on the parsed dataset before skolemization. A container
// that accepts this stores nothing and says `201`; for an ACL it tells an
// author a rule was created when it was not.
#[tokio::test]
async fn a_blank_named_graph_is_refused_on_a_container_and_an_auxiliary() {
    let f = fixture().await;
    let container = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap();
    assert_eq!(f.app.clone().oneshot(container).await.unwrap().status(),
        StatusCode::BAD_REQUEST, "a container's graph carries containment");

    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
    let acl = f.owner_request("PUT", "/.aux/c/notes.acl")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap();
    assert_eq!(f.app.clone().oneshot(acl).await.unwrap().status(),
        StatusCode::BAD_REQUEST, "an ACL's rules would be invisible to WAC in a subgraph");
    assert!(f.stored("/.aux/c/notes.acl").await.is_none(),
        "and the refusal wrote nothing");
}

// Every other `containsGraph` assertion uses one named graph, where
// `insert` and `append` are indistinguishable. Two of them tell them
// apart, `insert` would replace the first `Link` with the second, and the
// client would be told about half of what it did not get.
#[tokio::test]
async fn every_withheld_graph_is_named_not_just_the_last() {
    let f = fixture().await;
    let body = "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }\n\
                <urn:example:g2> { <http://example.org/bob> <http://schema.org/name> \"Bob\" }";
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(body)).unwrap()).await.unwrap();

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let links: Vec<String> = f.app.oneshot(get).await.unwrap()
        .headers().get_all(header::LINK).iter()
        .map(|v| v.to_str().unwrap().to_owned()).collect();
    for g in ["urn:example:g1", "urn:example:g2"] {
        assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains(g)),
            "{g} is missing from {links:?}");
    }
}

// §6.2.1's body is the whole remedy: a `409` that does not say which
// graphs are in the way is a refusal the client cannot act on.
#[tokio::test]
async fn the_refusal_names_the_graphs_it_is_protecting() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(
            "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }"
        )).unwrap()).await.unwrap();

    let overwrite = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    let res = f.app.oneshot(overwrite).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let body = body_string(res).await;
    assert!(body.contains("urn:example:g1"), "which graph is in the way: {body}");
    assert!(body.contains("application/trig"), "and how to write it anyway: {body}");
}

// §4 on the ordinary resource path. Only the auxiliary path was pinned,
// so a read that skipped de-skolemization returned the server's internal
// IRI to the client for every resource that ever held a blank node.
#[tokio::test]
async fn a_resource_containing_a_blank_node_round_trips_as_a_blank_node() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/knows> [ <http://schema.org/name> \"Alice\" ] ."))
        .unwrap()).await.unwrap();

    let get = f.owner_request("GET", "/foo")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let out = body_string(f.app.oneshot(get).await.unwrap()).await;
    // The constant, not a literal: only `dataset` may write or match the
    // skolem sub-namespace (`docs/constraints.md`).
    assert!(!out.contains(crate::dataset::RESERVED_PREFIX),
        "the server's internal IRI must not reach a client: {out}");
    assert!(out.contains("Alice"), "and the statement itself survived: {out}");
}

// §6.3, against a resource that is dataset-shaped: the client
// offered a format carrying everything, so the lossy one it listed first
// is the wrong answer. A shape hardcoded to `Graph` answers Turtle here.
#[tokio::test]
async fn a_dataset_shaped_resource_negotiates_away_from_a_lossy_format() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(
            "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }"
        )).unwrap()).await.unwrap();

    for accept in ["text/turtle, application/trig", "text/turtle, application/ld+json"] {
        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, accept).body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_ne!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle",
            "{accept}: a format that carries the whole resource was offered");
    }

    // §6.3: `text/*` admits Turtle, and Turtle can serve the default
    // graph: that is a `200` with `Link`s, never a `406`.
    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "text/*").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle");
}

// §9.5. Folding this into the default graph would be a document rewrite
// (a statement in a named graph is not asserted in the default graph),
// and it is the obvious accidental implementation of the split.
#[tokio::test]
async fn a_graph_named_like_its_own_resource_stays_a_named_graph() {
    let f = fixture().await;
    let body = r#"{"@graph":[
        {"@id":"https://pod.toph.so/c/notes",
         "@graph":[{"@id":"http://example.org/a","http://schema.org/name":"inside"}]},
        {"@id":"http://example.org/b","http://schema.org/name":"outside"}]}"#;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/ld+json")
        .body(Body::from(body)).unwrap()).await.unwrap();

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap();
    let out = body_string(f.app.clone().oneshot(get).await.unwrap()).await;
    assert!(out.contains("\"inside\" <https://pod.toph.so/c/notes>"),
        "still in its named graph, not merged into the default one: {out}");
    assert!(out.lines().any(|l| l.contains("\"outside\"") && l.trim_end().ends_with("\" .")),
        "and the default-graph statement is still in the default graph: {out}");
}

// §9.6 / §2.1. Eleven characters of relative IRI name another resource's
// URL. Under store-global graph names this write would land in /victim
// with no ACL check anywhere in the path.
#[tokio::test]
async fn naming_another_resources_url_as_a_graph_touches_nothing() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/victim")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"mine\" .")).unwrap()).await.unwrap();

    let before = body_string(f.app.clone().oneshot(f.owner_request("GET", "/victim")
        .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap())
        .await.unwrap()).await;

    let attack = r#"{"@graph":[{"@id":"../victim",
        "@graph":[{"@id":"http://example.org/x","http://schema.org/name":"theirs"}]}]}"#;
    f.app.clone().oneshot(f.owner_request("PUT", "/attacker/doc")
        .header(header::CONTENT_TYPE, "application/ld+json")
        .body(Body::from(attack)).unwrap()).await.unwrap();

    let after = body_string(f.app.clone().oneshot(f.owner_request("GET", "/victim")
        .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap())
        .await.unwrap()).await;
    assert_eq!(before, after, "/victim changed by a write to /attacker/doc");
    assert!(!after.contains("theirs"));
}

// §9.1: an empty named graph produces no quads, so it cannot survive. The
// isomorphism oracle passes vacuously here: this needs a direct assertion
// on the response instead, or the limit stops being a decision and becomes
// a surprise.
#[tokio::test]
async fn an_empty_named_graph_is_documented_as_lost() {
    let f = fixture().await;
    let body = r#"{"@graph":[{"@id":"urn:example:empty","@graph":[]},
        {"@id":"http://example.org/b","http://schema.org/name":"kept"}]}"#;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/ld+json")
        .body(Body::from(body)).unwrap()).await.unwrap();

    let out = body_string(f.app.clone().oneshot(f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap())
        .await.unwrap()).await;
    assert!(out.contains("kept"));
    assert!(!out.contains("urn:example:empty"),
        "documented limit (§9.1): a graph with no quads does not round-trip");
}

// §6.2.1's check reads `get_dataset` to decide whether an existing resource
// has named graphs a graph-format write would destroy. If the registry is
// corrupt, a shelf `sys:hasSubgraph` lists with no `sys:graphName`, the
// state §3.2.3 says should never occur, `get_dataset` fails closed with
// `InvalidIri` (pinned directly against the store in `resource.rs`). This
// pins that `put_impl` propagates the refusal instead of reading the store
// error as "no named graphs" and proceeding with exactly the overwrite the
// check exists to refuse.
#[tokio::test]
async fn a_corrupt_registry_refuses_the_write_instead_of_overwriting() {
    let f = fixture().await;
    let body = r#"{"@graph":[
        {"@id":"https://pod.toph.so/c/notes","http://schema.org/name":"kept"},
        {"@id":"urn:example:g1","@graph":[{"@id":"http://example.org/a","http://schema.org/name":"Alice"}]}]}"#;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/ld+json")
        .body(Body::from(body)).unwrap()).await.unwrap();
    let before = f.stored("/c/notes").await;

    let r = match f.url("/c/notes") {
        Target::Resource(r) => r,
        other => panic!("/c/notes is not a resource: {other:?}"),
    };
    let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
    let key = crate::shelf::ShelfKey::of(&r, g.as_ref());
    let sys = crate::resource::sys_graph_iri(&r);
    f.store.update(&format!(
        "DELETE DATA {{ GRAPH <{sys}> {{ <{}> <{}> <{}> }} }}",
        key.graph_iri(), crate::shelf::SYS_GRAPH_NAME, g.as_str()
    )).await.unwrap();

    let overwrite = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    let res = f.app.clone().oneshot(overwrite).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST,
        "a store error must refuse, not read as \"no named graphs\"");
    assert_eq!(f.stored("/c/notes").await, before, "the refused write changed nothing");
}

// Every other `containsGraph` assertion covers only the Link headers.
// This one also checks that both graphs' actual content survives a
// dataset-format read, not merely that their names are mentioned.
#[tokio::test]
async fn two_named_graphs_both_round_trip_and_are_both_named() {
    let f = fixture().await;
    let body = "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }\n\
                <urn:example:g2> { <http://example.org/bob> <http://schema.org/name> \"Bob\" }";
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(body)).unwrap()).await.unwrap();

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap();
    let out = body_string(f.app.clone().oneshot(get).await.unwrap()).await;
    assert!(out.contains("\"Alice\" <urn:example:g1>"), "graph g1's content survived: {out}");
    assert!(out.contains("\"Bob\" <urn:example:g2>"), "graph g2's content survived: {out}");

    let turtle_get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let links: Vec<String> = f.app.oneshot(turtle_get).await.unwrap()
        .headers().get_all(header::LINK).iter()
        .map(|v| v.to_str().unwrap().to_owned()).collect();
    for g in ["urn:example:g1", "urn:example:g2"] {
        assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains(g)),
            "{g} is missing from {links:?}");
    }
}

// `has_named_graphs` counts a blank-named graph; `named_graphs` cannot
// name one. Only a document mixing both kinds exercises the split: the
// resource must still be treated as a dataset (blank-named graph withheld
// from a graph-format read too), but `containsGraph` can name only the
// IRI-named one, and a dataset format must still carry both.
#[tokio::test]
async fn a_blank_named_graph_and_an_iri_named_graph_together() {
    let f = fixture().await;
    let body = "_:g { <http://example.org/alice> <http://schema.org/name> \"Alice\" }\n\
                <urn:example:g1> { <http://example.org/bob> <http://schema.org/name> \"Bob\" }";
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .body(Body::from(body)).unwrap()).await.unwrap();

    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let links: Vec<String> = res.headers().get_all(header::LINK).iter()
        .map(|v| v.to_str().unwrap().to_owned()).collect();
    assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains("urn:example:g1")),
        "the IRI-named graph is nameable: {links:?}");
    assert_eq!(links.iter().filter(|l| l.contains("containsGraph")).count(), 1,
        "the blank-named graph has no IRI a Link header can name: {links:?}");
    assert!(!body_string(res).await.contains("Alice"),
        "neither named graph leaked into the default graph");

    let dataset_get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
    let out = body_string(f.app.oneshot(dataset_get).await.unwrap()).await;
    assert!(out.contains("Alice"), "the blank-named graph's content still round-trips: {out}");
    assert!(out.contains("Bob"), "and the IRI-named graph's content: {out}");
}
