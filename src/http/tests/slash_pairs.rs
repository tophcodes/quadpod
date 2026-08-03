//! `/x` and `/x/` as a conflicting pair.

use super::fixture::*;

/// `PUT path` as the owner, with a body that suits a container or a
/// resource alike.
async fn owner_put(f: &Fixture, path: &str) -> StatusCode {
    let req = f.owner_request("PUT", path)
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    f.app.clone().oneshot(req).await.unwrap().status()
}

// Solid Protocol §3.1: "If two URIs differ only in the trailing slash […]
// the other URI MUST NOT correspond to another resource." Both orders,
// because neither half of the pair is privileged — a container may not
// appear beside a resource any more than the reverse.
#[tokio::test]
async fn a_trailing_slash_pair_is_refused_in_both_orders() {
    let f = fixture().await;
    assert_eq!(owner_put(&f, "/box/").await, StatusCode::CREATED);
    assert_eq!(owner_put(&f, "/box").await, StatusCode::CONFLICT,
        "a resource must not appear beside the container of the same name");

    assert_eq!(owner_put(&f, "/doc").await, StatusCode::CREATED);
    assert_eq!(owner_put(&f, "/doc/").await, StatusCode::CONFLICT,
        "a container must not appear beside the resource of the same name");

    // The refusal is a refusal: nothing was written either way.
    assert!(f.stored("/box").await.is_none());
    assert!(f.stored("/doc/").await.is_none());
}

// The counterweight: the rule forbids the PAIR, not either half of it. A
// container and a resource of the same name each remain perfectly ordinary
// on their own, and overwriting one is not "creating its counterpart".
#[tokio::test]
async fn either_half_alone_still_creates_and_is_still_writable() {
    let f = fixture().await;
    assert_eq!(owner_put(&f, "/box/").await, StatusCode::CREATED);
    assert_eq!(owner_put(&f, "/box/").await, StatusCode::CREATED, "overwrite");
    assert_eq!(owner_put(&f, "/plain").await, StatusCode::CREATED);
    assert_eq!(owner_put(&f, "/plain").await, StatusCode::CREATED, "overwrite");

    // ...and once the counterpart is gone, the name is free again.
    let del = f.owner_request("DELETE", "/plain").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(owner_put(&f, "/plain/").await, StatusCode::CREATED);
}

// The 409 depends on whether some OTHER resource exists, so answering it
// before the denial would turn it into an existence oracle for the whole
// namespace — the same trap `denial_does_not_reveal_existence` pins for
// the target itself. Authorization runs first; the pair check never does.
#[tokio::test]
async fn the_slash_pair_conflict_is_not_an_existence_oracle() {
    let f = fixture().await;
    assert_eq!(owner_put(&f, "/box/").await, StatusCode::CREATED);

    // Anonymous: 401, exactly as for a path where no pair exists at all.
    let anon = |path: &'static str| Request::builder().method("PUT").uri(path)
        .header(header::CONTENT_TYPE, "text/turtle").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(anon("/box")).await.unwrap().status(),
        StatusCode::UNAUTHORIZED);
    assert_eq!(f.app.clone().oneshot(anon("/no-pair-here")).await.unwrap().status(),
        StatusCode::UNAUTHORIZED);

    // A verified stranger: 403, and again indistinguishable.
    let bob = "https://bob.example/card#me";
    let bob_app = f.app_also_trusting(bob);
    let signed = |path: &'static str| f
        .sign(Request::builder().method("PUT").uri(path), bob, "PUT", path)
        .header(header::CONTENT_TYPE, "text/turtle").body(Body::empty()).unwrap();
    assert_eq!(bob_app.clone().oneshot(signed("/box")).await.unwrap().status(),
        StatusCode::FORBIDDEN);
    assert_eq!(bob_app.oneshot(signed("/no-pair-here")).await.unwrap().status(),
        StatusCode::FORBIDDEN);
}

// The other way the forbidden pair could be built: not by naming the
// counterpart, but by making the ancestor walk materialize it. `/a` is an
// ordinary resource; `PUT /a/b` would create the container `/a/` beside
// it. The refusal has to come from the walk, since no handler-level check
// on the target would see this at all.
#[tokio::test]
async fn materializing_an_ancestor_cannot_build_the_pair_either() {
    let f = fixture().await;
    assert_eq!(owner_put(&f, "/a").await, StatusCode::CREATED);
    assert_eq!(owner_put(&f, "/a/b").await, StatusCode::CONFLICT);
    assert!(f.stored("/a/").await.is_none(),
        "the refused create must not have materialized the container");
    assert!(f.stored("/a/b").await.is_none());
}

// A `Slug` is a hint, so a name whose counterpart is taken is treated the
// way a taken name always has been — the server picks another — rather
// than failing a request that never named that URL in the first place.
#[tokio::test]
async fn post_allocates_around_a_taken_counterpart() {
    let f = fixture().await;
    assert_eq!(owner_put(&f, "/inbox/").await, StatusCode::CREATED);
    assert_eq!(owner_put(&f, "/inbox/note/").await, StatusCode::CREATED);

    let post = f.owner_request("POST", "/inbox/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    let res = f.app.clone().oneshot(post).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let location = res.headers().get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
    assert_ne!(location, "https://pod.toph.so/inbox/note",
        "the container /inbox/note/ already owns that name");
    assert!(location.starts_with("https://pod.toph.so/inbox/note-"), "{location}");
}
