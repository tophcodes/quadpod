//! RDF 1.2: version negotiation, triple terms, directional literals.

use super::fixture::*;

/// §4: silence means 1.1, so an undeclared body carrying a triple term
/// contradicts its own declaration. Deliberately stricter than RDF 1.2
/// Concepts, which reads a missing parameter as 1.2.
#[tokio::test]
async fn an_undeclared_triple_term_is_a_400() {
    let f = fixture().await;
    let res = put_versioned(&f, "/foo", "text/turtle", TRIPLE_TERM_TTL).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// The same body, declared, is stored.
#[tokio::test]
async fn a_declared_triple_term_is_accepted() {
    let f = fixture().await;
    let res = put_versioned(&f, "/foo", "text/turtle;version=1.2", TRIPLE_TERM_TTL).await;
    assert_eq!(res.status(), StatusCode::CREATED, "{}", res.status());
}

/// The gap the old refusal had, now on the wire: a directional
/// language-tagged string is RDF 1.2 too, and needs declaring.
#[tokio::test]
async fn a_directional_literal_needs_a_declaration() {
    let f = fixture().await;
    let undeclared = put_versioned(&f, "/a", "text/turtle", DIRECTIONAL_TTL).await;
    assert_eq!(undeclared.status(), StatusCode::BAD_REQUEST);

    let declared =
        put_versioned(&f, "/b", "text/turtle;version=1.2-basic", DIRECTIONAL_TTL).await;
    assert_eq!(declared.status(), StatusCode::CREATED, "{}", declared.status());
}

/// §6: an unrecognised label is not a silent fallback to 1.1, a client
/// that named a version this server does not know must not be quietly
/// served a different one.
#[tokio::test]
async fn an_unknown_version_label_is_a_415() {
    let f = fixture().await;
    let res = put_versioned(
        &f, "/foo", "text/turtle;version=1.3",
        "<#it> <http://schema.org/name> \"Toph\" .",
    ).await;
    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// §6, the conflict that protects §5's read. Without it, GET as 1.1,
/// edit, PUT back deletes every triple term with a 2xx and no warning:
/// the read-side projection must not become the template for its own
/// destruction. Mirrors §6.2.1's named-graph refusal exactly.
#[tokio::test]
async fn writing_below_a_resources_version_is_a_409() {
    let f = fixture().await;
    let created =
        put_versioned(&f, "/foo", "text/turtle;version=1.2", TRIPLE_TERM_TTL).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let clobber = put_versioned(
        &f, "/foo", "text/turtle", "<#it> <http://schema.org/name> \"Toph\" .",
    ).await;
    assert_eq!(clobber.status(), StatusCode::CONFLICT);
}

fn links_of(res: &axum::response::Response) -> String {
    res.headers().get_all(header::LINK).iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect::<Vec<_>>().join(", ")
}

/// §5: a 1.1 client gets the projection, a `200`, and is told both what
/// it got and where the whole thing is.
#[tokio::test]
async fn a_1_1_read_of_a_1_2_resource_says_what_it_served() {
    let f = fixture().await;
    assert_eq!(
        put_versioned(&f, "/foo", "text/turtle;version=1.2", TRIPLE_TERM_TTL).await.status(),
        StatusCode::CREATED,
    );

    let res = get_accepting(&f, "/foo", "text/turtle").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/turtle;version=1.1");
    let link = links_of(&res);
    assert!(
        link.contains("rel=\"alternate\"") && link.contains("version=1.2"),
        "an alternate link must name the fuller representation, got {link}"
    );
    assert!(
        !body_string(res).await.contains("<<("),
        "the triple term must not be in a 1.1 body"
    );
}

/// The `alternate` link names the resource's *own* classification, so a
/// resource whose only excess is a directional literal advertises
/// `1.2-basic` rather than promising triple terms it does not have.
#[tokio::test]
async fn the_alternate_link_names_the_resources_own_version() {
    let f = fixture().await;
    put_versioned(&f, "/foo", "text/turtle;version=1.2-basic", DIRECTIONAL_TTL).await;

    let res = get_accepting(&f, "/foo", "text/turtle").await;
    let link = links_of(&res);
    assert!(link.contains("version=1.2-basic"), "got {link}");
}

/// Asking for 1.2 explicitly gets the whole thing, undegraded.
#[tokio::test]
async fn asking_for_1_2_gets_the_triple_term() {
    let f = fixture().await;
    put_versioned(&f, "/foo", "text/turtle;version=1.2", TRIPLE_TERM_TTL).await;

    let res = get_accepting(&f, "/foo", "text/turtle;version=1.2").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/turtle;version=1.2");
    assert!(body_string(res).await.contains("<<("), "the triple term must be present");
}

/// A plain RDF 1.1 resource is byte-identical to what it was before this
/// feature: no `version` parameter at all. RDF 1.2 Concepts encourages
/// announcing a version only for documents using 1.2 functionality, and
/// every deployed client compares `Content-Type` for equality.
#[tokio::test]
async fn an_ordinary_resource_carries_no_version_parameter() {
    let f = fixture().await;
    f.put_turtle("/foo", "<#it> <http://schema.org/name> \"Toph\" .").await;

    let res = get_accepting(&f, "/foo", "text/turtle").await;
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/turtle");
    assert!(!links_of(&res).contains("version="), "nothing to advertise");
}

/// §9: the two representations of one state must not share a strong
/// validator (RFC 9110 §8.8.1).
#[tokio::test]
async fn the_two_versions_do_not_share_an_etag() {
    let f = fixture().await;
    put_versioned(&f, "/foo", "text/turtle;version=1.2", TRIPLE_TERM_TTL).await;

    let at_11 = get_accepting(&f, "/foo", "text/turtle").await;
    let at_12 = get_accepting(&f, "/foo", "text/turtle;version=1.2").await;
    assert_ne!(at_11.headers()[header::ETAG], at_12.headers()[header::ETAG]);
}

#[tokio::test]
async fn a_put_carrying_a_triple_term_is_a_400() {
    let f = fixture().await;
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(
            "<http://e/s> <http://e/p> <<( <http://e/a> <http://e/b> <http://e/c> )>> ."
        )).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// §2.1's refusal has to hold in both parsers that can build a `Dataset`:
// `Format::parse` above, and here `patch::Patch::parse`, the only other
// way a triple term could reach the store, since a patch body never goes
// through `Format::parse` at all.
#[tokio::test]
async fn a_patch_carrying_a_triple_term_is_a_400() {
    let f = fixture().await;
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

    let res = patch_n3(&f, "/profile",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:x <<( <http://e/a> <http://e/b> <http://e/c> )>> . } .\n").await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
