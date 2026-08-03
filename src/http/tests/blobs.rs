//! Blob roundtrip, backend failure, and the body limit.

use super::fixture::*;

#[tokio::test]
async fn a_text_file_can_be_put_and_read_back_byte_for_byte() {
    let f = fixture().await;
    let body: &[u8] = &[0x00, 0xff, 0xfe, b'\r', b'\n', b'A'];

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(body.to_vec())).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let res = f.app.clone().oneshot(f.owner_request("GET", "/notes.txt")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/plain");
    let got = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
    assert_eq!(&got[..], body, "bytes survive exactly");
}

// A blob is a container member exactly as an RDF resource is.
#[tokio::test]
async fn a_posted_blob_joins_and_leaves_its_container() {
    let f = fixture().await;
    let res = f.app.clone().oneshot(f.owner_request("POST", "/box/")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("x")).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let loc = res.headers()[header::LOCATION].to_str().unwrap().to_owned();
    let child_path = loc.strip_prefix("https://pod.toph.so").unwrap().to_owned();

    let listing = f.get_turtle("/box/").await;
    assert!(listing.contains(&loc), "the blob is a member");

    let res = f.app.clone().oneshot(f.owner_request("DELETE", &child_path)
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let listing = f.get_turtle("/box/").await;
    assert!(!listing.contains(&loc), "and it leaves again");
}

// §8.4: axum's own 2 MiB default already applied here. This pins that the
// configured number is the one in force — a body over it is refused, and
// one under it is not.
//
// The under-limit body must be a format `put_impl` accepts today (only an
// RDF `Content-Type`, so `text/turtle` rather than `text/plain`) to reach
// `201` at all. The oversized body's `Content-Type` is irrelevant: axum's
// `Bytes` extractor rejects it for size before `put_impl` reads any
// header.
#[tokio::test]
async fn a_body_over_the_configured_limit_is_a_413() {
    let f = fixture_with_body_limit(64).await;

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/small.txt")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/big.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(vec![b'x'; 4096])).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// §3.4: the validator is computed from the served bytes, so the same bytes
// give the same tag and one byte's difference gives a different one.
#[tokio::test]
async fn a_blob_carries_a_strong_validator_and_answers_conditionally() {
    let f = fixture().await;
    f.put_blob("/a.txt", "text/plain", b"hello").await;
    f.put_blob("/b.txt", "text/plain", b"hello").await;
    f.put_blob("/c.txt", "text/plain", b"hellp").await;

    let ta = f.etag_of("/a.txt").await;
    assert_eq!(ta, f.etag_of("/b.txt").await, "same bytes, same tag");
    assert_ne!(ta, f.etag_of("/c.txt").await, "one byte apart, different tag");

    let res = f.app.clone().oneshot(f.owner_request("GET", "/a.txt")
        .header(header::IF_NONE_MATCH, &ta)
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);

    // A stale If-Match must refuse the write rather than overwrite it.
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/a.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::IF_MATCH, "\"0000000000000000000000000000000000000000000000000000000000000000\"")
        .body(Body::from("new")).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
}

// §6.1. Both halves matter: without the admitting cases an accept_allows
// that always refuses would pass.
#[tokio::test]
async fn accept_decides_whether_a_blob_is_servable() {
    let f = fixture().await;
    f.put_blob("/pic.png", "image/png", b"png").await;

    for accept in ["*/*", "image/*", "image/png", "text/turtle, image/png"] {
        let res = f.app.clone().oneshot(f.owner_request("GET", "/pic.png")
            .header(header::ACCEPT, accept).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Accept: {accept}");
    }
    for accept in ["text/turtle", "text/*", "image/png;q=0", "*/*, image/png;q=0"] {
        let res = f.app.clone().oneshot(f.owner_request("GET", "/pic.png")
            .header(header::ACCEPT, accept).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE, "Accept: {accept}");
    }
}

// §6.2: the pod's namespace still says the resource exists, but there is
// nothing to serve. 500 would read as "my fault, retry".
#[tokio::test]
async fn a_blob_whose_object_vanished_is_a_404_with_a_warning() {
    let f = fixture().await;
    f.put_blob("/gone.txt", "text/plain", b"x").await;

    // Emptied from underneath, exactly as an operator or another writer
    // on a shared bucket would.
    let r = match f.space.resolve("/gone.txt").unwrap() {
        crate::space::Target::Resource(r) => r,
        _ => panic!("resource"),
    };
    let key = crate::blob::BlobKey::of(&r).unwrap();
    f.blobs.delete(&key).await.unwrap();

    let res = f.app.clone().oneshot(f.owner_request("GET", "/gone.txt")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().contains_key(header::WARNING));
}

// §10: the claim the whole plan exists to make testable.
#[tokio::test]
async fn wac_governs_a_blob_exactly_as_it_governs_a_graph() {
    let f = fixture().await;
    f.put_blob("/secret.txt", "text/plain", b"s3cret").await;
    f.put_turtle("/.aux/secret.txt.acl", &format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> . \
         <#owner> a acl:Authorization ; \
           acl:agent <{OWNER}> ; \
           acl:accessTo <https://pod.toph.so/secret.txt> ; \
           acl:mode acl:Read, acl:Write, acl:Control ."
    )).await;

    // Anonymous: the ACL names only the owner.
    let res = f.app.clone().oneshot(Request::builder()
        .method("GET").uri("/secret.txt").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = f.app.clone().oneshot(f.owner_request("GET", "/secret.txt")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// Whole-branch review, Important 1: `put_status` mapped `ResourceError::Blob`
// through its `_` arm to `400`, telling a client a server-side outage was
// their malformed request. `resource::`'s own `FailingBlobs` never caught
// this because it never goes through a handler — this one does.
#[tokio::test]
async fn a_blob_backend_outage_answers_500_not_400() {
    let f = fixture_with_blobs(Arc::new(FailingBlobs), 64 * 1024 * 1024).await;

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/photo.png")
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(&b"x"[..])).unwrap()).await.unwrap();

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// The backend's own words are for the log, not for the client: the body
/// says the same thing whatever failed underneath. `tests/observability.rs`
/// holds the other half — that the words really are in the log.
#[tokio::test]
async fn a_500_says_nothing_about_the_backend_that_failed() {
    let f = fixture_with_blobs(Arc::new(FailingBlobs), 64 * 1024 * 1024).await;

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/photo.png")
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(&b"x"[..])).unwrap()).await.unwrap();

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body_string(res).await, INTERNAL_ERROR_BODY);
}
