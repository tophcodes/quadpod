//! Media types, content negotiation, and the RDF-versus-blob classification of a body.

use super::fixture::*;

#[tokio::test]
async fn put_turtle_then_get_jsonld_negotiates() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    let put_res = f.app.clone().oneshot(put).await.unwrap();
    assert_eq!(put_res.status(), StatusCode::CREATED);
    assert_eq!(put_res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/foo");

    let get = f.owner_request("GET", "/foo")
        .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/ld+json");
    assert!(body_string(res).await.contains("schema.org/name"));
}

// Solid Protocol §2.2 names the status code in its normative text:
// "Server MUST reject PUT, POST, and PATCH requests that contain content
// but lack the Content-Type header field, with a status code of 400."
#[tokio::test]
async fn a_write_with_content_and_no_content_type_is_a_400() {
    let f = fixture().await;
    for (method, path) in [("PUT", "/x"), ("POST", "/")] {
        let res = f.app.clone().oneshot(f.owner_request(method, path)
            .body(Body::from("hello")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{method} {path}");
    }
}

// The live injection vector: a legal HTTP header value that is not a legal
// media type, whose quote would close the SPARQL literal it is
// interpolated into. A CRLF payload would NOT do here — hyper rejects it
// before any handler runs, so that test would pin hyper and pass no matter
// what MediaType::parse does.
#[tokio::test]
async fn a_content_type_that_is_not_a_media_type_is_a_415_and_stores_nothing() {
    let f = fixture().await;
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/evil")
        .header(header::CONTENT_TYPE, r#"text/plain;x=""#)
        .body(Body::from("x")).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let res = f.app.clone().oneshot(f.owner_request("GET", "/evil")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "nothing may have been stored");
}

// §8.5: an ACL the PDP cannot parse is not an ACL.
#[tokio::test]
async fn a_non_rdf_body_on_an_auxiliary_is_a_415() {
    let f = fixture().await;
    f.put_turtle("/subject", "").await;
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/.aux/subject.acl")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("x")).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// §8.5: a container's representation is RDF, so the two asks contradict.
#[tokio::test]
async fn posting_a_non_rdf_body_as_a_container_is_a_400() {
    let f = fixture().await;
    let res = f.app.clone().oneshot(f.owner_request("POST", "/")
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
        .body(Body::from("x")).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_default_accept_is_turtle() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();
    let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle");
}

#[tokio::test]
async fn get_unsupported_accept_is_406() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();
    let get = f.owner_request("GET", "/foo")
        .header(header::ACCEPT, "image/png").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
}

// `application/json` is a syntactically valid media type that `Format`
// does not parse as RDF, so `classify_body` routes it to the blob path
// rather than refusing it.
#[tokio::test]
async fn put_of_a_valid_but_unrecognised_media_type_stores_it_as_a_blob() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "application/json").body(Body::from("{}")).unwrap();
    let res = f.app.oneshot(put).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn get_missing_is_404() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/nope").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
