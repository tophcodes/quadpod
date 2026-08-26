//! Containment over PUT, POST and DELETE, and `Slug` allocation.

use super::fixture::*;

#[tokio::test]
async fn delete_existing_is_204_then_404() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();
    let del = f.owner_request("DELETE", "/foo").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
    let del2 = f.owner_request("DELETE", "/foo").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(del2).await.unwrap().status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_deep_resource_creates_ancestor_containment() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/a/b/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    // GET the parent container /a/b/. It must list the doc via ldp:contains
    let get = f.owner_request("GET", "/a/b/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(body.contains("ldp#contains"));
    assert!(body.contains("https://pod.toph.so/a/b/doc"));
}

#[tokio::test]
async fn delete_resource_removes_containment() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/a/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();
    let del = f.owner_request("DELETE", "/a/doc").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);

    let get = f.owner_request("GET", "/a/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert!(!body_string(res).await.contains("https://pod.toph.so/a/doc"));
}

#[tokio::test]
async fn get_root_container_is_200() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_string(res).await.contains("ldp#BasicContainer"));
}

#[tokio::test]
async fn put_container_rejecting_client_containment_is_409() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(
            "<https://pod.toph.so/box/> <http://www.w3.org/ns/ldp#contains> <https://pod.toph.so/box/x> .",
        )).unwrap();
    assert_eq!(f.app.oneshot(put).await.unwrap().status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn put_container_stores_user_triples_and_keeps_type() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<https://pod.toph.so/box/> <http://purl.org/dc/terms/title> \"My Box\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
    let get = f.owner_request("GET", "/box/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    let body = body_string(res).await;
    assert!(body.contains("My Box"));                 // user triple kept
    assert!(body.contains("ldp#BasicContainer"));     // server type re-asserted
}

#[tokio::test]
async fn delete_nonempty_container_is_409_empty_is_204() {
    let f = fixture().await;
    // create a child → parent /box/ becomes non-empty
    let put = f.owner_request("PUT", "/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();
    let del_full = f.owner_request("DELETE", "/box/").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(del_full).await.unwrap().status(), StatusCode::CONFLICT);
    // remove child, then container is deletable
    let del_child = f.owner_request("DELETE", "/box/doc").body(Body::empty()).unwrap();
    f.app.clone().oneshot(del_child).await.unwrap();
    let del_empty = f.owner_request("DELETE", "/box/").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(del_empty).await.unwrap().status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_root_container_is_405() {
    let f = fixture().await;
    let del = f.owner_request("DELETE", "/").body(Body::empty()).unwrap();
    let res = f.app.oneshot(del).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn post_with_slug_creates_named_child() {
    let f = fixture().await;
    let post = f.owner_request("POST", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    let res = f.app.clone().oneshot(post).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/box/note");
    // the child is retrievable and the container lists it
    let get = f.owner_request("GET", "/box/note").body(Body::empty()).unwrap();
    let got = f.app.oneshot(get).await.unwrap();
    assert_eq!(got.status(), StatusCode::OK);
}

// A `Slug` names a child of the container POSTed to, so at the root it can
// aim straight at a reserved segment. `classify` refuses both names, so the
// POST answers `404` and allocates nothing, including with the `Link:
// rel="type"` container form, which is the shape `/.well-known/` itself
// would take. Without the space-level reservation the `.well-known` row
// would be a `201` for a resource the `/.well-known/` routes shadow on GET
// and no method can delete.
#[tokio::test]
async fn a_slug_cannot_allocate_a_reserved_segment_at_the_root() {
    let f = fixture().await;
    for slug in [".aux", ".well-known"] {
        for type_link in [None, Some("<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")] {
            let mut post = f.owner_request("POST", "/")
                .header(header::CONTENT_TYPE, "text/turtle")
                .header("slug", slug);
            if let Some(link) = type_link {
                post = post.header(header::LINK, link);
            }
            let req = post.body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
            let res = f.app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "Slug: {slug}, link: {type_link:?}");
            assert!(res.headers().get(header::LOCATION).is_none(), "Slug: {slug} allocated a URL");
        }
    }
}

#[tokio::test]
async fn post_slug_collision_gets_distinct_url() {
    let f = fixture().await;
    let mk = || f.owner_request("POST", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle").header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    let loc1 = f.app.clone().oneshot(mk()).await.unwrap().headers().get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
    let loc2 = f.app.clone().oneshot(mk()).await.unwrap().headers().get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
    assert_ne!(loc1, loc2);
}

// LDP §5.2.3.4: a POST whose `Link: rel="type"` names a container asks for
// a container, and Solid §3.1 makes the trailing slash the only thing that
// distinguishes the two, so the allocated name must carry it.
#[tokio::test]
async fn post_with_container_type_link_creates_a_container() {
    let f = fixture().await;
    let post = f.owner_request("POST", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "sub")
        .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
        .body(Body::from("")).unwrap();
    let res = f.app.clone().oneshot(post).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/box/sub/");

    // It is a real container: typed, readable, and POSTable into.
    let get = f.owner_request("GET", "/box/sub/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let got = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert!(body_string(got).await.contains(container::LDP_BASIC_CONTAINER));

    // And the parent lists it under its slash-terminated URL.
    let list = f.owner_request("GET", "/box/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    assert!(body_string(f.app.oneshot(list).await.unwrap()).await
        .contains("https://pod.toph.so/box/sub/"));
}

// A `Slug` is a hint, and §3.1 makes the other half of a slash pair as
// unavailable as the name itself, so a POSTed container whose name is
// held by an existing *resource* gets another name, not the `409` a
// client-named PUT would get. Same rule `Guard::is_taken` already applies
// in the other direction.
#[tokio::test]
async fn posted_container_avoids_a_name_its_slash_counterpart_holds() {
    let f = fixture().await;
    let mk_resource = f.owner_request("POST", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle").header("slug", "sub")
        .body(Body::from("")).unwrap();
    let res = f.app.clone().oneshot(mk_resource).await.unwrap();
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/box/sub");

    let post = f.owner_request("POST", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle").header("slug", "sub")
        .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
        .body(Body::from("")).unwrap();
    let res = f.app.oneshot(post).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let loc = res.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert_ne!(loc, "https://pod.toph.so/box/sub/", "the counterpart is taken");
    assert!(loc.ends_with('/'), "it is still a container: {loc}");
}

// Containment is server-managed on a POSTed container for the same reason
// it is on a PUT one.
#[tokio::test]
async fn posted_container_may_not_set_containment() {
    let f = fixture().await;
    let post = f.owner_request("POST", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle").header("slug", "sub")
        .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
        .body(Body::from(
            "<https://pod.toph.so/box/sub/> \
             <http://www.w3.org/ns/ldp#contains> <https://pod.toph.so/elsewhere> .",
        )).unwrap();
    let res = f.app.clone().oneshot(post).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    // and nothing was left behind
    let get = f.owner_request("GET", "/box/sub/").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(get).await.unwrap().status(), StatusCode::NOT_FOUND);
}

// This test used to assert a 400 with the reasoning that an empty body left
// the container linking a child that did not exist, the child 404d forever
// and a later DELETE never reached the containment removal. Existence is a
// stored fact now, so the created child exists, is listed, is readable and is
// deletable; the dangling-link hazard the 400 defended against is gone, and
// what remains is a resource with no triples, which is exactly what an empty
// body says.
#[tokio::test]
async fn post_empty_body_creates_an_empty_child_that_is_really_there() {
    let f = fixture().await;
    let mk = f.owner_request("PUT", "/inbox/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    let post = f.owner_request("POST", "/inbox/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "note")
        .body(Body::from("")).unwrap();
    let res = f.app.clone().oneshot(post).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/inbox/note");
    assert_eq!(f.stored("/inbox/note").await, Some(Vec::new()), "an empty child exists");

    // It is listed, readable, and, the part that used to be impossible,
    // removable, which leaves the container deletable again.
    let get = f.owner_request("GET", "/inbox/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let body = body_string(f.app.clone().oneshot(get).await.unwrap()).await;
    assert!(body.contains("https://pod.toph.so/inbox/note"), "the child must be listed");

    let read = f.owner_request("GET", "/inbox/note").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(read).await.unwrap().status(), StatusCode::OK);

    let del_child = f.owner_request("DELETE", "/inbox/note").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(del_child).await.unwrap().status(), StatusCode::NO_CONTENT);
    let del = f.owner_request("DELETE", "/inbox/").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn post_to_non_container_is_conflict() {
    let f = fixture().await;
    // /doc is a resource path (no trailing slash) → POST not allowed there
    let post = f.owner_request("POST", "/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.oneshot(post).await.unwrap().status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn put_container_preserves_existing_containment() {
    let f = fixture().await;
    // create a child so /box/ is non-empty
    let child = f.owner_request("PUT", "/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    f.app.clone().oneshot(child).await.unwrap();
    // PUT the container itself with only user triples (no ldp:contains)
    let put = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<https://pod.toph.so/box/> <http://purl.org/dc/terms/title> \"Box\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
    // the child's containment link must survive
    let get = f.owner_request("GET", "/box/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    let body = body_string(res).await;
    assert!(body.contains("https://pod.toph.so/box/doc"));  // containment preserved
    assert!(body.contains("Box"));                           // user triple stored
}
