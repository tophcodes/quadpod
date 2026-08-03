//! `ETag`, `If-Match`/`If-None-Match`, `304`, and what `Vary` promises.

use super::fixture::*;

#[tokio::test]
async fn get_emits_etag_and_304_on_if_none_match() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();

    let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    let cond = f.owner_request("GET", "/foo")
        .header(header::IF_NONE_MATCH, &etag).body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(cond).await.unwrap().status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn put_if_match_mismatch_is_412() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();

    let stale = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_MATCH, "\"deadbeef\"")
        .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
    assert_eq!(f.app.oneshot(stale).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn put_if_none_match_star_on_existing_is_412() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();

    let create_only = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_NONE_MATCH, "*")
        .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
    assert_eq!(f.app.oneshot(create_only).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn put_if_match_matching_succeeds() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();
    // read current etag
    let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    // conditional update with matching If-Match must succeed
    let upd = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_MATCH, &etag)
        .body(Body::from("<#it> <http://schema.org/name> \"New\" .")).unwrap();
    assert_eq!(f.app.oneshot(upd).await.unwrap().status(), StatusCode::CREATED);
}

#[tokio::test]
async fn put_if_none_match_star_on_absent_creates() {
    let f = fixture().await;
    let req = f.owner_request("PUT", "/brand-new")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_NONE_MATCH, "*")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::CREATED);
}

// RFC 9110 §13.1.1 matches `If-Match` against any current representation.
// A resource's validator embeds its format (§6.4), so comparing against
// one server-chosen representation makes `GET` as TriG followed by a
// conditional `PUT` fail with `412` permanently.
#[tokio::test]
async fn a_validator_from_any_format_satisfies_a_conditional_write() {
    let f = fixture().await;

    // A graph-shaped resource stored as Turtle, fetched as JSON-LD: the
    // two representations have different validators, and only one of them
    // is what an `Accept`-less `GET` would have returned.
    f.app.clone().oneshot(f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap()).await.unwrap();
    let get = f.owner_request("GET", "/foo")
        .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/ld+json");
    let json_tag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    let plain = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let plain_tag = f.app.clone().oneshot(plain).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_ne!(json_tag, plain_tag,
        "different representations are different entities (RFC 9110 §8.8.1)");

    let conditional = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_MATCH, &json_tag)
        .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(conditional).await.unwrap().status(),
        StatusCode::CREATED, "the tag the client was just handed must be accepted");

    // And the same for a dataset-shaped resource, whose stored type is
    // JSON-LD while the client fetched it as TriG.
    let body = "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }";
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/ld+json")
        .body(Body::from(r#"{"@graph":[{"@id":"urn:example:g1","@graph":[
            {"@id":"http://example.org/alice","http://schema.org/name":"Alice"}]}]}"#))
        .unwrap()).await.unwrap();
    let get = f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
    let trig_tag = f.app.clone().oneshot(get).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    let conditional = f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "application/trig")
        .header(header::IF_MATCH, &trig_tag)
        .body(Body::from(body)).unwrap();
    assert_eq!(f.app.clone().oneshot(conditional).await.unwrap().status(),
        StatusCode::CREATED);

    // A validator of no representation at all is still refused.
    let stale = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_MATCH, "\"deadbeef\"")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.oneshot(stale).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
}

// RFC 9110 §15.4.5: a `304` carries the `ETag` it was matched on, or the
// client cannot refresh its cache entry. `Vary` for the same reason it is
// on the `200` (§6.3) — the answer depended on `Accept`.
#[tokio::test]
async fn a_304_still_carries_its_validator_and_vary() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap()).await.unwrap();

    let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let tag = f.app.clone().oneshot(get).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    let cond = f.owner_request("GET", "/foo")
        .header(header::IF_NONE_MATCH, &tag).body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(cond).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(res.headers().get(header::ETAG).unwrap(), tag.as_str());
    assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
}

// §6.3: `Vary: Accept` on every negotiated response. The container and
// auxiliary path negotiates as much as the resource path does.
#[tokio::test]
async fn a_container_read_varies_on_accept_including_its_304() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
    let tag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    let cond = f.owner_request("GET", "/")
        .header(header::IF_NONE_MATCH, &tag).body(Body::empty()).unwrap();
    let res = f.app.oneshot(cond).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
    assert_eq!(res.headers().get(header::ETAG).unwrap(), tag.as_str());
}

// `current_tags` contributes no validator for a container or an
// auxiliary in any existing test, and nothing exercised `If-Match` on an
// ACL — exactly the read-modify-write pattern SolidOS uses on every
// write: `GET`, keep the `ETag`, `PUT` back conditionally.
#[tokio::test]
async fn if_match_on_an_acl_succeeds_with_the_right_tag_and_412s_with_the_wrong_one() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
    let acl = format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         <#owner> a acl:Authorization ; acl:agent <{OWNER}> ; \
            acl:mode acl:Control, acl:Read, acl:Write ; acl:accessTo </c/notes> ."
    );
    f.app.clone().oneshot(f.owner_request("PUT", "/.aux/c/notes.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl.clone())).unwrap()).await.unwrap();

    let get = f.owner_request("GET", "/.aux/c/notes.acl")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    // Read-modify-write: the ETag just fetched is handed back unchanged,
    // and must be accepted.
    let put_back = f.owner_request("PUT", "/.aux/c/notes.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_MATCH, &etag)
        .body(Body::from(acl)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_back).await.unwrap().status(), StatusCode::CREATED,
        "a conditional write carrying the ETag just read must succeed");

    // A stale or wrong tag must not be accepted.
    let wrong = f.owner_request("PUT", "/.aux/c/notes.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_MATCH, "\"deadbeef\"")
        .body(Body::from(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
             <#owner> a acl:Authorization ; acl:agent <https://mallory.example/card#me> ; \
                acl:mode acl:Control ; acl:accessTo </c/notes> ."
        )).unwrap();
    assert_eq!(f.app.oneshot(wrong).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
}

// Unifying container and auxiliary ETags onto `Skolemized::etag` made
// them format-aware (RFC 9110 §8.8.1): Turtle and JSON-LD renderings of
// the same container are different representations, so they must not
// share a validator — and the same representation, fetched twice, must.
#[tokio::test]
async fn a_containers_etag_tracks_the_selected_format() {
    let f = fixture().await;

    let turtle = f.app.clone().oneshot(f.owner_request("GET", "/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap())
        .await.unwrap();
    let turtle_tag = turtle.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    let jsonld = f.app.clone().oneshot(f.owner_request("GET", "/")
        .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap())
        .await.unwrap();
    let jsonld_tag = jsonld.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    assert_ne!(turtle_tag, jsonld_tag,
        "Turtle and JSON-LD are different representations (RFC 9110 §8.8.1) and must not share an ETag");

    let turtle_again = f.app.clone().oneshot(f.owner_request("GET", "/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap())
        .await.unwrap();
    let turtle_again_tag = turtle_again.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_eq!(turtle_tag, turtle_again_tag, "same format, same content → same ETag");

    // RFC 9110 §13.1.1: `If-Match` matches *any* current representation,
    // not just the one the server would negotiate by default — so a
    // write carrying the JSON-LD-negotiated tag must be accepted too.
    let put = f.app.clone().oneshot(f.owner_request("PUT", "/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header(header::IF_MATCH, &jsonld_tag)
        .body(Body::from(
            "<https://pod.toph.so/> <http://purl.org/dc/terms/title> \"root\" .",
        )).unwrap()).await.unwrap();
    assert_eq!(put.status(), StatusCode::CREATED,
        "If-Match must accept a tag negotiated for any servable format, not only the default");
}
