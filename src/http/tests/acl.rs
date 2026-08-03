//! The ACL document itself: creation rules, warnings, and the delete cascade.

use super::fixture::*;

/// The `Warning` header on a response, if it carries one.
fn warning_of(res: &axum::response::Response) -> Option<String> {
    res.headers()
        .get(header::WARNING)
        .map(|v| v.to_str().unwrap().to_owned())
}

// The empty body: the obvious way to write an ACL that denies its whole
// subtree, including the Control that removing it would need. It is
// accepted — that is a legitimate thing to want — but never silently.
#[tokio::test]
async fn an_empty_acl_is_created_and_warned_about() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/locked")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();

    let res = put_acl(&f, "/locked", "").await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let expected = acl_grants_nothing_message(
        "https://pod.toph.so/.aux/locked.acl",
        "https://pod.toph.so/locked",
        false, // "/locked" is a resource, not a container: no subtree to mention
        false,
    );
    assert_eq!(warning_of(&res), Some(format!("199 - \"{expected}\"")));
    assert!(expected.contains("grants no access to anyone"));
    assert!(!expected.contains("--reset-root-acl"), "only the root can be reset");
}

// The case that actually happens: a document full of triples that grant
// nothing, because `acl:accessTo` names the wrong resource. Identical
// effect to the empty body, so it must get identical treatment — an
// emptiness check on the body would have missed this entirely.
#[tokio::test]
async fn an_acl_whose_triples_grant_nothing_is_warned_about_too() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/typo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();

    // Every predicate is right; the `accessTo` names a DIFFERENT resource.
    let body = format!(
        "<#o> a <http://www.w3.org/ns/auth/acl#Authorization> ; \
         <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/somewhere-else> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
         <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let res = put_acl(&f, "/typo", &body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(res.headers().contains_key(header::WARNING), "a non-empty body can grant nothing");
    assert!(warning_of(&res).unwrap().contains("https://pod.toph.so/typo"));
}

// The counterweight: an ACL that does grant something must be silent, or
// the warning is noise nobody reads.
#[tokio::test]
async fn an_acl_that_grants_something_is_not_warned_about() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/kept")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();

    let body = format!(
        "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/kept> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let res = put_acl(&f, "/kept", &body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(warning_of(&res), None, "a real grant must not be warned about");
}

// The root is the one subject with a way back, and the warning is the only
// place a client learns what it is: `--reset-root-acl`, out of band,
// because the HTTP route needs the Control this ACL just revoked.
#[tokio::test]
async fn an_empty_root_acl_warning_names_the_recovery_flag() {
    let f = fixture().await;
    let res = put_acl(&f, "/", "").await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let warning = warning_of(&res).expect("the root lockout must be warned about");
    assert!(warning.contains("--reset-root-acl"), "{warning}");
    assert!(warning.contains("https://pod.toph.so/.aux/.acl"), "{warning}");

    // And it is really locked: the owner can no longer read their own pod.
    let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(get).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// An orphaned ACL would outlive its resource and be resurrected — with
// its old grants — the moment anyone recreates that path.
#[tokio::test]
async fn deleting_a_resource_deletes_its_acl() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/gone")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"g\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();
    // Write is listed alongside Control deliberately: this direct ACL
    // replaces the inherited root one entirely (nearest ACL wins), and
    // Control alone would leave the owner unable to DELETE /gone at all.
    let acl_body = format!(
        "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/gone> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write>, \
         <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/gone.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    f.app.clone().oneshot(put_acl).await.unwrap();

    let del = f.owner_request("DELETE", "/gone").body(Body::empty()).unwrap();
    assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);

    // The ACL graph must be gone from the store, not merely unreachable.
    assert!(
        f.stored("/.aux/gone.acl").await.is_none(),
        "the deleted resource's ACL must not survive it"
    );
}

#[tokio::test]
async fn acl_is_not_listed_as_a_container_child() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/item")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"i\" .")).unwrap();
    f.app.clone().oneshot(put).await.unwrap();
    let put_acl = f.owner_request("PUT", "/.aux/item.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/item> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
        ))).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
    let listing = body_string(f.app.oneshot(get).await.unwrap()).await;
    assert!(listing.contains("https://pod.toph.so/item"));
    assert!(!listing.contains("/.aux/"));
}

// The suffix rule is gone: `.acl` is an ordinary name, and a `Slug` can no
// longer name an access-control document at all — every auxiliary lives
// in the reserved namespace, which `container::child_name` cannot reach
// (its output is one segment, appended to the container's own path).
//
// This replaces two tests that pinned the old escalation (an append-only
// agent POSTing `Slug: .acl`, or `Slug: note.acl`, to write a policy
// document). That attack is no longer refused — it is no longer
// expressible, which is the stronger property, so what is pinned here is
// that the created child is ordinary data and changes no policy anywhere.
#[tokio::test]
async fn a_slug_can_no_longer_name_an_access_control_document() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/inbox/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    // Bob holds Append below `/` and nothing else — in particular no
    // Control anywhere.
    let root_acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Append> ."
    );
    let put_root_acl = f.owner_request("PUT", "/.aux/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(root_acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_root_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);
    let post = |slug: &'static str| f.sign(
            Request::builder().method("POST").uri("/inbox/"), bob, "POST", "/inbox/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", slug)
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();

    for slug in [".acl", "note.acl", ".aux"] {
        let res = bob_app.clone().oneshot(post(slug)).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "Slug: {slug} is an ordinary child");
        assert_eq!(
            res.headers().get(header::LOCATION).unwrap(),
            &format!("https://pod.toph.so/inbox/{slug}")[..],
        );
    }

    // The container's real access-control document was never touched: it
    // still does not exist, and Bob — who now owns a child literally
    // named `.acl` — still holds no Control over `/inbox/`.
    assert!(f.stored("/.aux/inbox/.acl").await.is_none(),
        "a Slug must not have been able to reach the reserved namespace");
    let hijack = f.sign(
            Request::builder().method("PUT").uri("/.aux/inbox/.acl"), bob, "PUT", "/.aux/inbox/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "<#pwn> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/inbox/> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
        ))).unwrap();
    assert_eq!(bob_app.oneshot(hijack).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// The residual from the previous round: an ACL is exempt from containment
// (it is never listed via `ldp:contains`), but `Guard::materialize`
// still materializes any missing ancestor containers for
// `PUT /.aux/a/b/c.acl` exactly as it would for `PUT /a/b/c`. Bob's grant
// here is `acl:Control` via the ROOT ACL's `acl:default` — inherited onto
// every descendant, `/a/`, `/a/b/`, and `/a/b/c` alike — and deliberately
// nothing else, so he has no `acl:Append` anywhere. That is enough to
// authorize writing `/a/b/c`'s ACL (the guard rewrites an ACL PUT to
// require Control on the subject, which Bob holds), but must NOT be
// enough to let his request silently create `/a/` and `/a/b/` and link
// them together — containers he holds no Append on.
#[tokio::test]
async fn deep_acl_put_needs_append_on_ancestors_it_materializes() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let root_acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
           <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
         <http://www.w3.org/ns/auth/acl#default> <https://pod.toph.so/> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_root_acl = f.owner_request("PUT", "/.aux/.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(root_acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_root_acl).await.unwrap().status(), StatusCode::CREATED);

    // Neither ancestor exists yet: this is the case that matters, since
    // an already-existing ancestor needs no fresh authorization.
    assert!(
        f.stored("/a/").await.is_none()
    );

    let bob_app = f.app_also_trusting(bob);
    let put_acl = f.sign(Request::builder().method("PUT").uri("/.aux/a/b/c.acl"), bob, "PUT", "/.aux/a/b/c.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(
            "<#x> <http://www.w3.org/ns/auth/acl#agent> <https://someone.example/#me> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/a/b/c> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .",
        )).unwrap();
    assert_eq!(bob_app.oneshot(put_acl).await.unwrap().status(), StatusCode::FORBIDDEN);

    assert!(
        f.stored("/a/").await.is_none(),
        "a refused PUT of a deep .acl must not have materialized the ancestor container it has no Append on"
    );
}

// The counterweight to THIS test above's counterweight: when the ACL's
// immediate parent already exists, creating the ACL is a zero-mutation
// event — an `Aux` target is never a containment member (that's
// `Guard::materialize`'s `may_be_member` match on the `Target`
// variant, a property of the type rather than something `add_containment`
// has to notice at runtime), and `ensure_container` is a no-op on a
// container that already has its type triples. So an agent holding
// `acl:Control` on the ACL's subject (here, via `/.aux/box/.acl`'s own
// `acl:default`) and NOTHING else — in particular no `acl:Append` on
// `/box/` — must still be able to write
// that subject's ACL. Requiring `Append` here would refuse a legitimate
// "you may manage access below here" delegation for a request that
// never touches `/box/`'s containment triples at all.
#[tokio::test]
async fn acl_put_under_an_existing_container_needs_no_append_on_it() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

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

    // Sanity: Bob genuinely has no Append on /box/ — an ordinary POST
    // must fail. Otherwise a CREATED below would prove nothing about the
    // exemption this test targets.
    let bob_app = f.app_also_trusting(bob);
    let sanity = f.sign(Request::builder().method("POST").uri("/box/"), bob, "POST", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "note")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(bob_app.clone().oneshot(sanity).await.unwrap().status(), StatusCode::FORBIDDEN);

    // The subject has to exist before its ACL can be created; the owner
    // makes it, which is the ordinary division of labour for a "you may
    // manage access below here" delegation.
    let mk_doc = f.owner_request("PUT", "/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"doc\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk_doc).await.unwrap().status(), StatusCode::CREATED);

    // /box/ already exists (created above), so writing /.aux/box/doc.acl is
    // a zero-mutation event at the container level: Control on the subject
    // (inherited via /.aux/box/.acl's acl:default) must be enough.
    let put_doc_acl = f.sign(Request::builder().method("PUT").uri("/.aux/box/doc.acl"), bob, "PUT", "/.aux/box/doc.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(
            "<#x> <http://www.w3.org/ns/auth/acl#agent> <https://someone.example/#me> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/doc> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .",
        )).unwrap();
    assert_eq!(bob_app.oneshot(put_doc_acl).await.unwrap().status(), StatusCode::CREATED);
}

// ACL squatting: a `Control`-only delegate writes an ACL for a path that
// does not exist and never did, naming only themselves. Nearest-ACL-wins
// makes that document govern the ghost path permanently — the owner can
// no longer create it (no Write), rewrite or delete the ACL (no Control),
// and deleting the container above does not reclaim it, because an ACL is
// not a containment member. Revoking the delegation changes nothing. The
// path would be bricked for everyone with no HTTP route to repair it.
#[tokio::test]
async fn acl_for_a_resource_that_does_not_exist_is_refused() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

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

    // Bob's Control over /box/ghost is genuine (inherited via acl:default)
    // — the refusal below is about the subject's absence, not about him.
    let bob_app = f.app_also_trusting(bob);
    let squat = f.sign(Request::builder().method("PUT").uri("/.aux/box/ghost.acl"), bob, "PUT", "/.aux/box/ghost.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/ghost> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
        ))).unwrap();
    let res = bob_app.oneshot(squat).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(body_string(res).await.contains("does not exist"));
    assert!(
        f.stored("/.aux/box/ghost.acl").await.is_none(),
        "the squatted ACL must not have been stored"
    );

    // ...and the path is still the owner's to use.
    let owner_create = f.owner_request("PUT", "/box/ghost")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"mine\" .")).unwrap();
    assert_eq!(f.app.oneshot(owner_create).await.unwrap().status(), StatusCode::CREATED);
}

// Finding 2: the same refusal, but for a subject whose ancestors don't
// exist either. `Guard::materialize`'s existence check (see its doc
// comment) is what refuses this before anything is created: without it,
// `aux::put` would be the only thing that ever said no here, and by the
// time it ran, `materialize` would already have created and linked `/a/`
// and `/a/b/` for a write that was always going to be refused. A 404 that
// mutates the store either way, but silently so: the caller is told
// nothing happened.
#[tokio::test]
async fn acl_for_a_deep_resource_that_does_not_exist_creates_no_ancestors() {
    let f = fixture().await;
    let put_acl = f.owner_request("PUT", "/.aux/a/b/c.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "<#x> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/a/b/c> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."
        ))).unwrap();
    let res = f.app.clone().oneshot(put_acl).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    assert!(f.stored("/a/").await.is_none(),
        "the 404 must not have materialized /a/");
    assert!(f.stored("/a/b/").await.is_none(),
        "the 404 must not have materialized /a/b/");
}

// The counterweight: authoring an ACL the ordinary way — for a resource
// that exists — must keep working, or the check above would have simply
// switched ACL authoring off.
#[tokio::test]
async fn acl_for_an_existing_resource_is_created() {
    let f = fixture().await;
    let mk = f.owner_request("PUT", "/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"doc\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    let put_acl = f.owner_request("PUT", "/.aux/box/doc.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/doc> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
               <http://www.w3.org/ns/auth/acl#Write>, \
               <http://www.w3.org/ns/auth/acl#Control> ."
        ))).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    // An auxiliary that outlives its subject must still be removable, or
    // its grants would be permanent: nearest-ACL-wins would keep handing
    // them to whoever recreates the path. No HTTP route produces that
    // state any more — DELETE cascades into every auxiliary by
    // construction — so the subject is dropped at the store level here,
    // and the guarantee has to hold regardless.
    //
    // This test used to assert that such a stale ACL also stays
    // REWRITABLE (the old subject-exists rule applied only to creation).
    // `aux::put` now carries the rule inside its update and applies it
    // always, so that half is gone; DELETE is the repair route.
    let doc = f.url("/box/doc");
    f.store.update(&format!(
        "DROP SILENT GRAPH <{}>; DROP SILENT GRAPH <{}>",
        doc.graph_iri(), crate::resource::sys_graph_iri(&doc),
    )).await.unwrap();

    let del_acl = f.owner_request("DELETE", "/.aux/box/doc.acl").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(del_acl).await.unwrap().status(), StatusCode::NO_CONTENT);
}

// An ACL over `aux::MAX_AUX_TRIPLES` is refused with a `413`, and refused
// whole: nothing of it is stored, so the resource keeps being governed by
// whatever governed it before. The body here is tens of kilobytes against
// a 64 MiB limit, so the status can only have come from the triple cap —
// axum's own limit never sees a body this small.
#[tokio::test]
async fn an_acl_over_the_triple_cap_is_refused_with_413() {
    let f = fixture().await;
    f.put_turtle("/box/doc", "<#it> <http://schema.org/name> \"doc\" .").await;

    let mut body = String::new();
    for i in 0..=crate::aux::MAX_AUX_TRIPLES {
        body.push_str(&format!(
            "<#a{i}> <http://www.w3.org/ns/auth/acl#agent> <https://webid.example/{i}> .\n"
        ));
    }
    let put_acl = f.owner_request("PUT", "/.aux/box/doc.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(body)).unwrap();
    let res = f.app.clone().oneshot(put_acl).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body_string(res).await.contains("at most"));

    assert!(
        f.stored("/.aux/box/doc.acl").await.is_none(),
        "the refused ACL must not have been stored"
    );
}

// ACL-of-an-ACL. A document that governs itself is permanent: whoever
// names only themselves in it keeps Control over it forever, and no
// cascade reaches it. The refusal is now structural — `resolve` will not
// classify a path whose auxiliary subject is itself in the reserved
// namespace — so it arrives before any handler logic runs, which is why
// the body no longer carries an explanation. Bob's grant is left in place
// so the refusal cannot be mistaken for an authorization failure: he does
// hold `acl:Control` below `/box/`.
#[tokio::test]
async fn acl_of_an_acl_is_refused_over_put() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    let mk = f.owner_request("PUT", "/box/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    // Bob gets Control on /.aux/box/.acl itself, delegated via that same
    // document's own acl:default — i.e. exactly the ancestor route the
    // finding used.
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

    let bob_app = f.app_also_trusting(bob);
    let squat = f.sign(Request::builder().method("PUT").uri("/.aux/.aux/box/.acl.acl"), bob, "PUT", "/.aux/.aux/box/.acl.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/.aux/box/.acl> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
        ))).unwrap();
    let res = bob_app.oneshot(squat).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    // Not addressable at all, so there is nothing to read back either.
    assert!(f.space.resolve("/.aux/.aux/box/.acl.acl").is_err(),
        "an auxiliary must never be the subject of an auxiliary");
    let read = f.owner_request("GET", "/.aux/.aux/box/.acl.acl").body(Body::empty()).unwrap();
    assert_eq!(f.app.oneshot(read).await.unwrap().status(), StatusCode::NOT_FOUND);
}

// Three tests lived here, all pinning that a `Slug` could not smuggle an
// access-control document past a container's Append check: `ghost.acl`
// for a subject that never existed, `.acl.acl`, and the legitimate
// `doc.acl` counterweight. None of those requests can name an auxiliary
// any more — a slug is one segment appended to the container's own path,
// and every auxiliary lives in the reserved namespace. What remains worth
// pinning is that POST cannot reach one by addressing it directly either:
// an auxiliary is not a container, so there is nothing to POST into, and
// the refusal comes after authorization like every other branch.
#[tokio::test]
async fn an_auxiliary_cannot_be_created_over_post() {
    let f = fixture().await;
    let mk = f.owner_request("PUT", "/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"doc\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

    // The owner holds Control on every subject here, so these are
    // authorized requests that are refused on their shape alone.
    for path in ["/.aux/.acl", "/.aux/box/.acl"] {
        let post = f.owner_request("POST", path)
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", "doc")
            .body(Body::from(format!(
                "<#x> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/doc> ; \
                 <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
            ))).unwrap();
        assert_eq!(f.app.clone().oneshot(post).await.unwrap().status(),
            StatusCode::CONFLICT, "POST {path}");
    }
    // The unallocated part of the reserved namespace is not addressable
    // at all, so it is not a container either.
    let post = f.owner_request("POST", "/.aux/bogus/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(post).await.unwrap().status(), StatusCode::NOT_FOUND);

    assert!(f.stored("/.aux/box/doc.acl").await.is_none(),
        "no auxiliary may have been created");
}
