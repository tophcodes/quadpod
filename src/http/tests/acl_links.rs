//! Where the `acl` link is advertised, and what an empty ACL means.

use super::fixture::*;

#[tokio::test]
async fn get_advertises_the_acl_location() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();

    let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    let link = res.headers().get(header::LINK).expect("Link header").to_str().unwrap().to_string();
    assert!(link.contains("https://pod.toph.so/.aux/foo.acl"));
    assert!(link.contains("rel=\"acl\""));
}

#[tokio::test]
async fn created_resource_advertises_the_acl_location() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    let res = f.app.oneshot(put).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(res.headers().get(header::LINK).unwrap().to_str().unwrap()
        .contains("https://pod.toph.so/.aux/foo.acl"));
}

// An ACL resource does not advertise an ACL of its own — it is governed
// by acl:Control on its subject resource, and /.aux/.aux/foo.acl.acl
// never exists.
#[tokio::test]
async fn acl_resource_advertises_no_further_acl() {
    let f = fixture().await;
    // The subject must exist: an ACL is only creatable for a resource
    // that does (see `acl_for_a_resource_that_does_not_exist_is_refused`).
    let put_foo = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put_foo).await.unwrap().status(), StatusCode::CREATED);
    let acl_body = format!(
        "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/foo> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/foo.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    f.app.clone().oneshot(put_acl).await.unwrap();

    let get = f.owner_request("GET", "/.aux/foo.acl").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().get(header::LINK).is_none());
}

// A client must not string-derive an auxiliary URL, so the advertisement
// has to arrive before the auxiliary exists — that is exactly the moment
// it needs it, to create the first one.
#[tokio::test]
async fn the_acl_link_is_advertised_even_when_the_acl_does_not_exist() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo").header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
    assert!(f.stored("/.aux/foo.acl").await.is_none(), "no ACL of its own yet");

    let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    let link = res.headers().get(header::LINK).unwrap().to_str().unwrap().to_string();
    assert!(link.contains("/.aux/foo.acl"), "{link}");
}

// SolidOS string-derives `<url>.acl` when this header is missing, and in
// this pod's URI space that path is ordinary data, not a policy. A
// create flow starts with a 404, so the 404 has to carry it.
#[tokio::test]
async fn the_acl_link_is_advertised_on_404_and_on_a_refusal() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/nothing").body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::LINK).is_some(),
        "SolidOS string-derives the ACL URL when this header is missing");

    let anon = Request::builder().method("GET").uri("/nothing").body(Body::empty()).unwrap();
    let res = f.app.oneshot(anon).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(res.headers().get(header::LINK).is_some(),
        "a refusal must advertise it too — it is derived from the path, not the store");
}

// An empty ACL is a policy ("nothing is granted here"), not an absence
// that falls back to the ancestor's wider rules. The owner locking
// themselves out of a subtree is the honest consequence.
#[tokio::test]
async fn an_empty_acl_denies_instead_of_inheriting() {
    let f = fixture().await;
    let mk = f.owner_request("PUT", "/locked/").header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);
    let acl = f.owner_request("PUT", "/.aux/locked/.acl")
        .header(header::CONTENT_TYPE, "text/turtle").body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(acl).await.unwrap().status(), StatusCode::CREATED);

    let get = f.owner_request("GET", "/locked/").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(get).await.unwrap().status(), StatusCode::FORBIDDEN);
}
