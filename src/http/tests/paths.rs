//! Path normalization and encoding, IRI breakage, over-long segments.

use super::fixture::*;

// §3.2, §11: a legal URL this pod cannot store.
#[tokio::test]
async fn an_over_long_path_segment_is_a_414() {
    let f = fixture().await;
    let long = "a".repeat(300);
    let res = f.app.clone().oneshot(f.owner_request("PUT", &format!("/{long}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("x")).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::URI_TOO_LONG);
}

// Whole-branch review: `uses_reserved_namespace` sliced an IRI at a fixed
// byte offset with no char-boundary check, so this body — legal Turtle,
// and `<urn:quadpodé:x>` is a legal IRI oxrdf accepts — panicked the
// handler and aborted the connection with no response at all. The
// response's exact status is not the point; that one comes back at all,
// instead of the connection dying, is.
#[tokio::test]
async fn a_multi_byte_iri_in_the_body_does_not_abort_the_connection() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<urn:quadpodé:x> <http://schema.org/name> \"x\" .")).unwrap();
    let res = f.app.oneshot(put).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn iri_breaking_path_is_400() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/foo%3E%20bar").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_iri_breaking_path_is_400() {
    let f = fixture().await;
    let req = f.owner_request("PUT", "/foo%3E%20bar")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
}

// Each shape here is one `dpop-verifier::normalize_htu` would silently
// change (drop an empty segment, resolve a dot-segment, or strip
// whatever follows a fragment marker) while this pod would otherwise
// treat it as naming a distinct resource. `resolve`'s `NotNormalized`
// check refuses them all at the HTTP layer, through `classify`, before
// any of them can reach the store or the WAC guard.
#[tokio::test]
async fn paths_normalization_would_alias_are_400() {
    let f = fixture().await;
    // `owner_request` signs the raw path, which is exactly what
    // `derive_htu` derives the `htu` from, so every shape here
    // authenticates and is then refused by `classify`, not by the
    // credential check.
    for path in ["/a//b", "/a/b//", "/a/./b", "/a/../b"] {
        let get = f.owner_request("GET", path).body(Body::empty()).unwrap();
        assert_eq!(
            f.app.clone().oneshot(get).await.unwrap().status(),
            StatusCode::BAD_REQUEST,
            "GET {path} should be refused as not normalization-stable"
        );
        let put = f.owner_request("PUT", path)
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(
            f.app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::BAD_REQUEST,
            "PUT {path} should be refused as not normalization-stable"
        );
    }
}

// A raw request path of `/a%23b` decodes (the way `classify` decodes it)
// to `/a#b`, which `resolve` refuses as `NotNormalized` — a `400`, and it
// must stay a `400` rather than becoming a misleading `401`. The `htu` a
// client signs is the WIRE form, `%23` and all (see `derive_htu`), which
// is exactly what `owner_request` builds; before the wire-form fix this
// test had to craft a proof over the decoded `https://pod.toph.so/a#b`
// instead, and `owner_request` could not express it.
#[tokio::test]
async fn hash_in_the_decoded_path_is_400_not_401() {
    let f = fixture().await;
    let req = f.owner_request("GET", "/a%23b").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
}

// This pins the property `HTU_DECODE_FAILURE_SENTINEL` used to guarantee
// before it was deleted as unreachable: a request whose path does not
// percent-decode to valid UTF-8 must fail closed, never reach a handler,
// and never be mistaken for an authentication failure. `derive_htu` signs
// and compares the wire form (see its doc comment), so this request
// authenticates just fine; it is axum's own `Path<String>` extractor that
// now rejects the invalid UTF-8 with a `400` before `handle_get`'s body
// ever runs. If this ever regresses to a `401` or a `200`, the sentinel's
// guarantee is gone and nothing else in this suite would catch it.
#[tokio::test]
async fn an_undecodable_path_is_400_even_when_authenticated() {
    let f = fixture().await;
    let req = f.owner_request("GET", "/%ff%fe").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
}

// The trailing slash is not a segment normalization would remove — it is
// what distinguishes a container from a resource — so it must keep
// working exactly as it did before the `NotNormalized` rule existed.
#[tokio::test]
async fn trailing_slash_container_still_resolves() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
    let get = f.owner_request("GET", "/box/")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_string(res).await.contains("ldp#BasicContainer"));
}

// The trailing slash is exactly what `dpop-verifier`'s `normalize_htu`
// erases, so without `verify_dpop`'s own exact `htu` comparison this
// request would authenticate: the owner signs `PUT /foo` and an on-path
// adversary re-delivers the identical bytes as `PUT /foo/`, installing
// the body as the *container* of the same name — a different resource
// from the one the client addressed and authorized. It must be a 401,
// from the middleware, before any handler sees it.
//
// This used to be pinned against an auxiliary pair
// (`PUT /.aux/foo.acl` re-delivered as `PUT /.aux/foo/.acl`), but the
// auxiliary URL shape changed: the kind is now a suffix, so those two
// paths' segment lists (`[".aux","foo.acl"]` vs `[".aux","foo",".acl"]`)
// differ in a non-empty segment, not an empty one — `normalize_htu`
// never treats them as equal, so an ordinary `htu` mismatch already
// answers 401 without this tightening. Worse, appending the slash
// directly (`/.aux/foo.acl` -> `/.aux/foo.acl/`) *does* still collapse
// under `normalize_htu`, but `/.aux/foo.acl/` ends in no kind's suffix,
// so it resolves to `Reserved` -> 404 regardless of what `verify_dpop`
// decides. Both are a real improvement, and both are why this
// regression now has to live in the resource space instead.
#[tokio::test]
async fn a_proof_for_a_resource_cannot_write_its_container_counterpart() {
    let f = fixture().await;
    let at = f.idp.mint_access_token(OWNER, &f.client.jkt(), now_unix() + 3600);
    let proof = f.client.mint_dpop(
        "https://pod.toph.so/foo",
        "PUT",
        now_unix(),
        "jti-resource-trailing-slash",
    );
    let req = Request::builder()
        .method("PUT")
        .uri("/foo/")
        .header(header::AUTHORIZATION, format!("DPoP {at}"))
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("dpop", proof)
        .body(Body::from(""))
        .unwrap();
    assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

// The same re-targeting, through a percent-escape instead of a trailing
// slash. The owner signs `PUT /.aux/a%41.acl` — whose subject the handlers
// read as `/aA` — and an on-path adversary re-delivers the identical bytes
// as `PUT /.aux/a%2541.acl`, whose subject is `/a%41`, a DIFFERENT
// resource. While `htu` was the percent-DECODED graph IRI and the exact
// comparison decoded both sides, the two collapsed to the same string and
// this authenticated. It must be a 401, from the middleware.
#[tokio::test]
async fn a_proof_for_one_acl_cannot_be_redirected_by_a_double_escape() {
    let f = fixture().await;
    let at = f.idp.mint_access_token(OWNER, &f.client.jkt(), now_unix() + 3600);
    let proof = f.client.mint_dpop(
        "https://pod.toph.so/.aux/a%41.acl",
        "PUT",
        now_unix(),
        "jti-acl-double-escape",
    );
    let req = Request::builder()
        .method("PUT")
        .uri("/.aux/a%2541.acl")
        .header(header::AUTHORIZATION, format!("DPoP {at}"))
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("dpop", proof)
        .body(Body::from(
            "<#r> a <http://www.w3.org/ns/auth/acl#Authorization> ;\
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/aA> .",
        ))
        .unwrap();
    assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

// The other half: a client that signs the wire form it actually requests
// must get through, end to end. `%41` is a plain `A`, so this once failed
// with a `401` even for the honest client — `dpop-verifier` compared the
// still-encoded proof against a `derive_htu` that had already decoded it.
#[tokio::test]
async fn a_percent_encoded_path_authenticates_for_its_own_request() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/a%41")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    let res = f.app.clone().oneshot(put).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    // The handler decoded the path, so the resource is `/aA` — the `htu`
    // being the wire form changed the credential check, not the storage.
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/aA");

    let get = f.owner_request("GET", "/aA").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_string(res).await.contains("schema.org/name"));
}

// The reserved namespace is server-understood, not storage: a path in it
// that names no auxiliary names nothing at all, and no method may make
// one exist there.
#[tokio::test]
async fn the_reserved_namespace_is_not_storage() {
    let f = fixture().await;
    for path in ["/.aux", "/.aux/", "/.aux/bogus/x"] {
        let put = f.owner_request("PUT", path).header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::NOT_FOUND, "PUT {path} must not be storage");
        let get = f.owner_request("GET", path).body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(get).await.unwrap().status(),
            StatusCode::NOT_FOUND, "GET {path}");
        let del = f.owner_request("DELETE", path).body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(),
            StatusCode::NOT_FOUND, "DELETE {path}");
    }
    // ...while a name that merely starts with the reserved one is the
    // user's, like any other.
    let put = f.owner_request("PUT", "/.auxiliary").header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.oneshot(put).await.unwrap().status(), StatusCode::CREATED);
}
