//! Refusals, and the permissions a write needs on a target and its ancestors.

use super::fixture::*;

// The whole mapping in one table: the guard decides a kind and this layer
// decides what it costs, so no test on the decision side can see a wrong
// status, a missing challenge or a body that leaks. Every [`Denial`] there
// is today is listed here; what makes a *new* one impossible to forget is
// `impl IntoResponse for Denial`'s exhaustive match, not this list.
#[tokio::test]
async fn every_denial_renders_as_the_answer_its_kind_earns() {
    let store_failed =
        ResourceError::Store(crate::store::StoreError::Backend("oxigraph exploded".into()));
    let cases = [
        (Denial::Unauthenticated, StatusCode::UNAUTHORIZED, "", true),
        (Denial::Forbidden, StatusCode::FORBIDDEN, "", false),
        (
            Denial::AuxSubjectMissing,
            StatusCode::NOT_FOUND,
            AUX_SUBJECT_MISSING_MESSAGE,
            false,
        ),
        (Denial::SlashPair, StatusCode::CONFLICT, SLASH_PAIR_MESSAGE, false),
        // The literal, not the constant: what a client is told when the
        // store fails is the contract `tests/observability.rs` pins from
        // the outside, and it must not name the cause.
        (Denial::Store(store_failed), StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error", false),
    ];
    for (denial, status, body, challenge) in cases {
        let what = format!("{denial:?}");
        let res = denial.into_response();
        assert_eq!(res.status(), status, "{what}");
        assert_eq!(
            res.headers().get(header::WWW_AUTHENTICATE).map(|v| v.to_str().unwrap()),
            challenge.then_some(DPOP_CHALLENGE),
            "only an unauthenticated caller is told which credential would help: {what}"
        );
        assert_eq!(body_string(res).await, body, "{what}");
    }
}

#[tokio::test]
async fn anonymous_get_is_401_with_a_challenge() {
    let f = fixture().await;
    let res = f.app.oneshot(
        Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(res.headers().get(header::WWW_AUTHENTICATE).is_some());
}

#[tokio::test]
async fn authenticated_stranger_is_403() {
    let f = fixture().await;
    // A verified WebID the root ACL says nothing about. It must be
    // allowed through authentication (the issuer vouches for it) and
    // stopped by authorization.
    let stranger = "https://bob.example/card#me";
    let stranger_app = f.app_also_trusting(stranger);
    let req = f.sign(Request::builder().method("GET").uri("/foo"), stranger, "GET", "/foo")
        .body(Body::empty()).unwrap();
    assert_eq!(stranger_app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// The denial must not depend on whether the resource exists — otherwise
// the status code is an existence oracle for the whole namespace.
#[tokio::test]
async fn denial_does_not_reveal_existence() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/secret")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"s\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    let existing = f.app.clone().oneshot(
        Request::builder().method("GET").uri("/secret").body(Body::empty()).unwrap()
    ).await.unwrap().status();
    let absent = f.app.oneshot(
        Request::builder().method("GET").uri("/does-not-exist").body(Body::empty()).unwrap()
    ).await.unwrap().status();
    assert_eq!(existing, absent);
    assert_eq!(existing, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn owner_can_grant_another_agent_read_via_an_acl() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let put = f.owner_request("PUT", "/shared")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"shared\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    let acl_body = format!(
        "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/shared> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/shared.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    // Bob (a verified WebID) may now read it, but still may not write it.
    let bob_app = f.app_also_trusting(bob);
    let read = f.sign(Request::builder().method("GET").uri("/shared"), bob, "GET", "/shared")
        .body(Body::empty()).unwrap();
    assert_eq!(bob_app.clone().oneshot(read).await.unwrap().status(), StatusCode::OK);

    let write = f.sign(Request::builder().method("PUT").uri("/shared"), bob, "PUT", "/shared")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"hijacked\" .")).unwrap();
    assert_eq!(bob_app.clone().oneshot(write).await.unwrap().status(), StatusCode::FORBIDDEN);

    // Bob has Read on the resource but no Control, so its ACL stays hidden.
    let read_acl = f.sign(Request::builder().method("GET").uri("/.aux/shared.acl"), bob, "GET", "/.aux/shared.acl")
        .body(Body::empty()).unwrap();
    assert_eq!(bob_app.oneshot(read_acl).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// Most of this suite authenticates as OWNER, who holds every
// mode through the root ACL — so a test suite built only from those
// could never notice if put_impl's parent-Append check were deleted.
// Bob here holds Write on the (not yet existing) target resource
// directly, but nothing at all on its parent container, so creation
// must still be refused.
#[tokio::test]
async fn creating_a_resource_needs_append_on_the_parent_not_just_write_on_the_target() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    // Grant Bob Write on /newfile before it exists. That grant has to
    // come from the ROOT ACL's `acl:default` — a direct /.aux/newfile.acl
    // cannot be created for a resource that does not exist yet (see
    // `acl_for_a_resource_that_does_not_exist_is_refused`). It also has
    // to be `acl:default` only: Bob must end up with Write on the child
    // and nothing whatsoever on `/` itself, which is exactly what
    // omitting an `acl:accessTo </>` rule for him achieves.
    let acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);
    let create = f.sign(Request::builder().method("PUT").uri("/newfile"), bob, "PUT", "/newfile")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(bob_app.oneshot(create).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// Mirrors the put_impl case above: Bob holds Write directly on an
// EXISTING resource but nothing on its parent container, so deleting it
// (which rewrites the parent's containment triples) must still be
// refused.
#[tokio::test]
async fn deleting_a_resource_needs_write_on_the_parent_not_just_the_target() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let put = f.owner_request("PUT", "/target")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    let acl_body = format!(
        "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/target> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/target.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);
    let del = f.sign(Request::builder().method("DELETE").uri("/target"), bob, "DELETE", "/target")
        .body(Body::empty()).unwrap();
    assert_eq!(bob_app.oneshot(del).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// post_impl's container-level check requires Mode::Append specifically
// — Read must not be enough to POST. Bob is granted Read directly on the
// container (via acl:accessTo) and, separately, Append inherited BY ITS
// CHILDREN (via acl:default) so that if the container-level Append
// requirement were weakened to Read, the request would sail through
// this test's own child-level check too and the mutation would be
// caught turning FORBIDDEN into CREATED.
#[tokio::test]
async fn posting_into_a_container_needs_append_not_just_read() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/mailroom/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    let acl_body = format!(
        "<#bob-read> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/mailroom/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> . \
         <#bob-append-children> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/mailroom/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Append> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/mailroom/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);
    let post = f.sign(Request::builder().method("POST").uri("/mailroom/"), bob, "POST", "/mailroom/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(bob_app.oneshot(post).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// This test used to assert a 400: an empty body meant DROP-and-insert-
// nothing, so "revoke everything" left no ACL behind and the walk resumed
// at the root — a revoke that WIDENED access. Existence is a stored fact
// now, so the same request means what it says: an ACL that grants
// nothing, which no ancestor can override. The property under test is
// unchanged — an empty ACL must never widen access — only the mechanism
// that delivers it.
#[tokio::test]
async fn an_emptied_acl_revokes_rather_than_falling_back_to_the_ancestor() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    let acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/box/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let wipe = f.owner_request("PUT", "/.aux/box/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(wipe).await.unwrap().status(), StatusCode::CREATED);

    // The ACL still exists — it is now the policy "nothing is granted
    // here" — so the walk stops at it and the root's acl:default rules
    // never come back into play.
    assert_eq!(
        f.stored("/.aux/box/.acl").await,
        Some(Vec::new()),
        "the emptied ACL must exist and grant nothing"
    );
    let bob_app = f.app_also_trusting(bob);
    let read = f.sign(Request::builder().method("GET").uri("/box/"), bob, "GET", "/box/")
        .body(Body::empty()).unwrap();
    assert_eq!(bob_app.clone().oneshot(read).await.unwrap().status(), StatusCode::FORBIDDEN);
    let write = f.sign(Request::builder().method("PUT").uri("/box/note"), bob, "PUT", "/box/note")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(bob_app.oneshot(write).await.unwrap().status(), StatusCode::FORBIDDEN);

    // ...and the owner locked themselves out of the subtree too, which is
    // what an empty ACL means — including of DELETE, which needs Control
    // here and this ACL grants that to nobody, not even the owner. There
    // is no HTTP route back for a subtree ACL emptied this way; only the
    // root has an operator-level escape hatch (`--reset-root-acl`, see
    // `wac::provision::provision_root_acl`).
    let owner_read = f.owner_request("GET", "/box/").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(owner_read).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// The exception that keeps LDP working: a container's type triples come
// from the server, so PUTting one with an empty body is legitimate.
#[tokio::test]
async fn empty_body_put_on_a_container_still_creates_it() {
    let f = fixture().await;
    let mk = f.owner_request("PUT", "/somecontainer/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);
    let get = f.owner_request("GET", "/somecontainer/").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_string(res).await.contains("ldp#BasicContainer"));
}

// Creating /box/sub/file also CREATES /box/sub/ and writes a containment
// triple into /box/ — a container Bob holds nothing on. Bob's grant here
// is acl:default only, i.e. "everything below /box/", deliberately
// without acl:accessTo </box/>. Checking only the immediate parent lets
// him mutate /box/ anyway: its content and ETag change and it stops being
// empty, so the owner's DELETE /box/ returns 409 from then on.
#[tokio::test]
async fn creating_a_deep_resource_needs_append_on_every_ancestor_it_materializes() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    let acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/box/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/box/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Append> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/box/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);
    let deep = || f.sign(Request::builder().method("PUT").uri("/box/sub/file"), bob, "PUT", "/box/sub/file")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();

    // /box/sub/ does not exist yet, so serving this would create it and
    // link it into /box/.
    assert_eq!(bob_app.clone().oneshot(deep()).await.unwrap().status(), StatusCode::FORBIDDEN);
    assert!(
        f.stored("/box/sub/").await.is_none(),
        "the refused request must not have materialized the intermediate container"
    );

    // Sanity, and the proof that the refusal was about mutating /box/ and
    // nothing else: once the owner has created /box/sub/ himself, the very
    // same request from Bob succeeds — his Write on the target and Append
    // on /box/sub/ were never in doubt, and /box/ is no longer touched.
    let mk_sub = f.owner_request("PUT", "/box/sub/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk_sub).await.unwrap().status(), StatusCode::CREATED);
    assert_eq!(bob_app.oneshot(deep()).await.unwrap().status(), StatusCode::CREATED);
}

// The other half of `Guard::materialize`'s exemption, and the one
// that makes calling it unconditionally safe: overwriting a resource that
// already exists adds no containment triple its parent does not already
// hold, so it must NOT start demanding `Append` there. Bob here holds
// Read+Write on one document and deliberately nothing on the container
// around it — the ordinary "you may edit this file" grant. Without the
// `is_member` half of the exemption (false whenever the target already
// exists) every such edit would 403.
#[tokio::test]
async fn overwriting_an_existing_resource_needs_no_append_on_its_container() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);
    let doc = f.owner_request("PUT", "/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"v1\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(doc).await.unwrap().status(), StatusCode::CREATED);

    let doc_acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/doc> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/doc> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write> ."
    );
    let put_doc_acl = f.owner_request("PUT", "/.aux/box/doc.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(doc_acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_doc_acl).await.unwrap().status(), StatusCode::CREATED);

    // Sanity: Bob genuinely has no Append on /box/, so the CREATED below
    // really is the exemption doing the work.
    let bob_app = f.app_also_trusting(bob);
    let sanity = f.sign(Request::builder().method("POST").uri("/box/"), bob, "POST", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(bob_app.clone().oneshot(sanity).await.unwrap().status(), StatusCode::FORBIDDEN);

    let edit = f.sign(Request::builder().method("PUT").uri("/box/doc"), bob, "PUT", "/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"v2\" .")).unwrap();
    assert_eq!(bob_app.oneshot(edit).await.unwrap().status(), StatusCode::CREATED);
}

// An auxiliary is never a containment member, so it can OUTLIVE the
// container it sits in. A PUT to such an orphan re-runs the ancestor
// walk, which materializes that container again and writes a fresh
// `ldp:contains` triple into ITS parent — here the root. The write must
// still be authorized level by level, even though the caller passed the
// check on the target itself.
//
// The orphan is `/box/doc`'s ACL. It is the shape that keeps Bob
// authorized on the target after his delegation is revoked: the guard's
// nearest-ACL search finds that ACL directly — the document Bob wrote
// about himself — with no ancestor ever consulted. That is precisely the
// case that matters — Bob
// passes the target check on his own say-so and must still be stopped
// from touching `/`.
//
// No HTTP route produces this orphan: `aux::delete_subject` takes every
// auxiliary with its subject, by construction. It is fabricated at the
// store level below, and the guard this test pins stays load-bearing
// defence-in-depth regardless — it must refuse to serve a write into this
// state however the store ends up in it.
#[tokio::test]
async fn put_to_an_orphaned_auxiliary_still_needs_append_on_what_it_materializes() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";

    for path in ["/box/", "/box/doc"] {
        let mk = f.owner_request("PUT", path)
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("")).unwrap();
        assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);
    }

    // The delegation: Bob may manage access below /box/ and nothing else
    // — no Append on /box/, nothing at all on /.
    let box_acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/box/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/box/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_box_acl = f.owner_request("PUT", "/.aux/box/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(box_acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_box_acl).await.unwrap().status(), StatusCode::CREATED);

    // Bob exercises his delegation: a policy for /box/doc naming only
    // himself. Entirely legitimate at this point.
    let bob_app = f.app_also_trusting(bob);
    let squat_body = format!(
        "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/doc> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_doc_acl = f.sign(
            Request::builder().method("PUT").uri("/.aux/box/doc.acl"), bob, "PUT", "/.aux/box/doc.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(squat_body.clone())).unwrap();
    assert_eq!(bob_app.clone().oneshot(put_doc_acl).await.unwrap().status(), StatusCode::CREATED);

    // The orphan, fabricated at the store level: /box/doc's graphs vanish
    // without the cascade ever running, and its containment triple with
    // them so the container becomes deletable.
    let doc = f.url("/box/doc");
    f.store.update(&format!(
        "DROP SILENT GRAPH <{}>; DROP SILENT GRAPH <{}>",
        doc.graph_iri(), crate::resource::sys_graph_iri(&doc),
    )).await.unwrap();
    f.store.update(
        &container::containment_removal(&f.container("/box/"), doc.graph_iri()).unwrap(),
    ).await.unwrap();

    // The owner tidies up, which revokes Bob's delegation by cascading
    // /box/'s own ACL. /box/doc's ACL is a different subject's auxiliary,
    // so nothing reclaims it.
    let del = f.owner_request("DELETE", "/box/").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert!(
        f.stored("/.aux/box/.acl").await.is_none(),
        "deleting the container must have revoked the delegation"
    );
    assert!(
        f.stored("/.aux/box/doc.acl").await.is_some(),
        "the orphaned auxiliary survives — that is the premise of this test"
    );
    assert!(
        container::container_is_empty(f.store.as_ref(), &f.container("/")).await.unwrap(),
        "the root must be empty again before the attack"
    );

    // Sanity: Bob's own document still grants him Control over its
    // subject, so he really does pass the check on the target itself. A
    // FORBIDDEN below would otherwise prove nothing.
    let read = f.sign(
            Request::builder().method("GET").uri("/.aux/box/doc.acl"), bob, "GET", "/.aux/box/doc.acl")
        .body(Body::empty()).unwrap();
    assert_eq!(bob_app.clone().oneshot(read).await.unwrap().status(), StatusCode::OK);

    // The attack: Bob holds nothing on / or /box/ any more. Serving this
    // would recreate /box/ and write </> ldp:contains </box/>.
    let attack = f.sign(
            Request::builder().method("PUT").uri("/.aux/box/doc.acl"), bob, "PUT", "/.aux/box/doc.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(squat_body)).unwrap();
    assert_eq!(bob_app.oneshot(attack).await.unwrap().status(), StatusCode::FORBIDDEN);
    assert!(
        container::container_is_empty(f.store.as_ref(), &f.container("/")).await.unwrap(),
        "a refused PUT must not have written a containment triple into the root"
    );
    assert!(
        f.stored("/box/").await.is_none(),
        "a refused PUT must not have re-materialized the deleted container"
    );
}

// The counterweight to the test above: an agent holding Append on one
// container and NOTHING anywhere else — in particular nothing on `/` —
// must still be able to POST into it. If the ancestor walk did not stop
// at the first existing container, this is the flow it would break.
#[tokio::test]
async fn append_only_agent_can_still_post_into_its_inbox() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/inbox/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    // Append on the container itself (acl:accessTo) plus Append for the
    // children it will hold (acl:default) — post_impl checks both.
    let acl_body = format!(
        "<#bob-here> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/inbox/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Append> . \
         <#bob-below> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/inbox/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Append> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/inbox/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);
    let post = f.sign(Request::builder().method("POST").uri("/inbox/"), bob, "POST", "/inbox/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(bob_app.oneshot(post).await.unwrap().status(), StatusCode::CREATED);
}

// A narrowing ACL is WAC's ONLY mechanism for revoking rights that an
// ancestor hands down through acl:default. If deleting the resource also
// deleted that ACL, an agent holding merely Write could remove the
// narrowing, recreate the resource, and have the guard's nearest-ACL
// search walk back up to the wider ancestor grant — escalating themselves
// to Control without
// ever being allowed to touch the ACL directly.
#[tokio::test]
async fn deleting_a_resource_needs_control_over_the_acl_it_would_cascade_into() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let put = f.owner_request("PUT", "/projects/audit-log")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"log\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    // /projects/ hands Bob Read+Write+CONTROL down to its children, and
    // Read+Write on the container itself (so the parent-Write check on a
    // DELETE below is satisfied and cannot be what refuses him).
    let projects_acl = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/projects/> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/projects/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob-here> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/projects/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write> . \
         <#bob-below> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/projects/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_projects_acl = f.owner_request("PUT", "/.aux/projects/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(projects_acl)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_projects_acl).await.unwrap().status(), StatusCode::CREATED);

    // The narrowing ACL: on the log itself Bob may read and write, but
    // NOT control. The nearest ACL wins completely, so this replaces the
    // Control he would otherwise inherit from /.aux/projects/.acl.
    let log_acl = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/projects/audit-log> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/projects/audit-log> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write> ."
    );
    let put_log_acl = f.owner_request("PUT", "/.aux/projects/audit-log.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(log_acl)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_log_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);

    // Sanity: Bob really does hold Write on the log — he may edit it. A
    // FORBIDDEN below would otherwise prove nothing.
    let edit = f.sign(Request::builder().method("PUT").uri("/projects/audit-log"), bob, "PUT", "/projects/audit-log")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"edited\" .")).unwrap();
    assert_eq!(bob_app.clone().oneshot(edit).await.unwrap().status(), StatusCode::CREATED);
    // ...and that he cannot reach the narrowing ACL directly.
    let touch_acl = f.sign(Request::builder().method("DELETE").uri("/.aux/projects/audit-log.acl"), bob, "DELETE", "/.aux/projects/audit-log.acl")
        .body(Body::empty()).unwrap();
    assert_eq!(bob_app.clone().oneshot(touch_acl).await.unwrap().status(), StatusCode::FORBIDDEN);

    // The attack: delete the resource so the cascade takes the ACL with it.
    let del = f.sign(Request::builder().method("DELETE").uri("/projects/audit-log"), bob, "DELETE", "/projects/audit-log")
        .body(Body::empty()).unwrap();
    assert_eq!(bob_app.oneshot(del).await.unwrap().status(), StatusCode::FORBIDDEN);
    assert!(
        f.stored("/.aux/projects/audit-log.acl").await.is_some(),
        "the narrowing ACL must survive a refused delete"
    );

    // The owner, who does hold Control there, is unaffected.
    let owner_del = f.owner_request("DELETE", "/projects/audit-log").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(owner_del).await.unwrap().status(), StatusCode::NO_CONTENT);
}
