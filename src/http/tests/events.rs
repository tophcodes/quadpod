//! The change events a write emits, on its own topic and its parent's.

use super::fixture::*;

/// The next event on a topic, or a failure, never a hang. A
/// `broadcast::Receiver` whose sender is still alive blocks forever when
/// nothing is published, and libtest has no per-test timeout: an
/// unbounded `recv` turns "no event was emitted" into a suite that never
/// finishes rather than into a red test.
async fn next_event(rx: &mut crate::notify::Receiver) -> crate::notify::Event {
    timeout(Duration::from_secs(5), rx.recv())
        .await.expect("expected an event on this topic, none arrived within 5s").unwrap()
}

/// That a topic stays silent. The write is over before this is called, so
/// anything the topic was going to hear is already buffered: this waits on
/// a silence that has already been decided, not on one still being made.
async fn stays_silent(rx: &mut crate::notify::Receiver, why: &str) {
    assert!(timeout(Duration::from_millis(50), rx.recv()).await.is_err(), "{why}");
}

/// A create is reported on the resource's own channel, and on its parent's
/// as `Add`, not as a second `Create` (§3.2).
#[tokio::test]
async fn a_put_that_creates_emits_create_on_the_target_and_add_on_the_parent() {
    let f = fixture().await;
    // `/c/` is made to exist first, so this write's only containment
    // change there is the `Add`; the container's own `Create` is the
    // subject of the next test.
    f.put_turtle("/c/other", "<#it> <http://schema.org/name> \"y\" .").await;
    let target = f.space.resolve("/c/notes").unwrap();
    let parent = f.space.resolve("/c/").unwrap();
    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
    let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let e = next_event(&mut on_target).await;
    assert_eq!(e.activity, crate::notify::Activity::Create);
    assert_eq!(e.object, target.graph_iri());
    assert_eq!(e.target, None);
    assert!(e.state.is_some(), "a create reports the state it produced");

    let p = next_event(&mut on_parent).await;
    assert_eq!(p.activity, crate::notify::Activity::Add);
    assert_eq!(p.object, target.graph_iri(), "the object of an Add is the child");
    assert_eq!(p.target.as_deref(), Some(parent.graph_iri()));
    // Independent of `state_of`: a GET on the container itself, at the
    // same media type and version §5.1 fixes, is the validator the pod
    // would hand a client for the same state. Catches an Add reporting
    // back the child's state instead of the topic's, the one place the
    // "state describes the topic, not the object" rule can break.
    let container_etag = f.app.clone().oneshot(f.owner_request("GET", "/c/")
        .header(header::ACCEPT, "application/n-quads")
        .body(Body::empty()).unwrap()).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_eq!(p.state.as_deref(), Some(container_etag.as_str()),
        "the Add's state must be the container's own validator, not the child's");
}

/// `/c/` did not exist either, so the same write created it, and a
/// container's own creation is its own fact, reported beside the `Add`
/// that filled it.
#[tokio::test]
async fn a_put_that_materializes_a_container_emits_its_create_too() {
    let f = fixture().await;
    let parent = f.space.resolve("/c/").unwrap();
    let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));

    f.put_turtle("/c/notes", "<#it> <http://schema.org/name> \"x\" .").await;

    let first = next_event(&mut on_parent).await;
    assert_eq!(first.activity, crate::notify::Activity::Create,
        "the container came into existence, which the Add alone does not say");
    assert_eq!(first.object, parent.graph_iri());
    assert_eq!(first.target, None);
    let second = next_event(&mut on_parent).await;
    assert_eq!(second.activity, crate::notify::Activity::Add);
    assert_eq!(second.target.as_deref(), Some(parent.graph_iri()));
}

/// `Materialized::created` always includes the request's own target, and
/// for a container target `as_container` does not screen it back out, so a
/// fresh container's own channel must hear its `Create` exactly once, not
/// once from `publish_own` and again from `publish_containment`.
#[tokio::test]
async fn a_put_that_creates_a_container_emits_exactly_one_create_on_its_own_topic() {
    let f = fixture().await;
    let target = f.space.resolve("/fresh/").unwrap();
    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/fresh/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("")).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let e = next_event(&mut on_target).await;
    assert_eq!(e.activity, crate::notify::Activity::Create);
    assert_eq!(e.object, target.graph_iri());
    assert_eq!(e.target, None);
    stays_silent(&mut on_target,
        "the container's own topic must hear one Create, not a second one for the same target").await;
}

/// An overwrite changes no containment, so the parent hears nothing at all.
#[tokio::test]
async fn a_put_that_overwrites_emits_update_and_nothing_on_the_parent() {
    let f = fixture().await;
    let target = f.space.resolve("/c/notes").unwrap();
    let put = |body: &'static str| f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle").body(Body::from(body)).unwrap();
    f.app.clone().oneshot(put("<#it> <http://schema.org/name> \"one\" .")).await.unwrap();

    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
    let mut on_parent = f.events.subscribe(
        crate::notify::Topic::from(&f.space.resolve("/c/").unwrap()));
    f.app.clone().oneshot(put("<#it> <http://schema.org/name> \"two\" .")).await.unwrap();

    assert_eq!(next_event(&mut on_target).await.activity, crate::notify::Activity::Update);
    stays_silent(&mut on_parent, "containment did not change, so the parent is silent").await;
}

/// The blob arm's early return carries `existence` and `materialized` out
/// alongside the response (§6.3), so a binary `PUT` emits every field a
/// graph `PUT` does.
#[tokio::test]
async fn a_binary_put_emits() {
    let f = fixture().await;
    let target = f.space.resolve("/c/photo.png").unwrap();
    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/c/photo.png")
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(&b"\x89PNG\r\n\x1a\n"[..])).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let e = next_event(&mut on_target).await;
    assert_eq!(e.activity, crate::notify::Activity::Create);
    assert_eq!(e.object, target.graph_iri());
    assert_eq!(e.target, None);
    assert_eq!(e.state.as_deref(), Some(blob_etag(b"\x89PNG\r\n\x1a\n").as_str()));
}

/// And the containment half of the same early return: the blob path walks
/// the same ancestors, so it reports the same `Add`.
#[tokio::test]
async fn a_binary_put_emits_the_add_on_its_parent() {
    let f = fixture().await;
    let parent = f.space.resolve("/c/").unwrap();
    let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));

    f.put_blob("/c/photo.png", "image/png", b"\x89PNG\r\n\x1a\n").await;

    // `/c/` is created by this same write, so its own `Create` comes first;
    // the `Add` is the fact under test.
    assert_eq!(next_event(&mut on_parent).await.activity, crate::notify::Activity::Create);
    let add = next_event(&mut on_parent).await;
    assert_eq!(add.activity, crate::notify::Activity::Add,
        "the blob path must report the containment it added");
    assert_eq!(add.object, f.space.resolve("/c/photo.png").unwrap().graph_iri());
    assert_eq!(add.target.as_deref(), Some(parent.graph_iri()));
}

/// A refused write emits nothing: the tail returns before touching the bus.
/// The unparseable body is refused at `classify_body`, before
/// `Guard::materialize` ever runs, so `materialized` is empty and the parent
/// assertion below is vacuous on its own. It would pass whether or not
/// `emit_put`'s status gate exists (issue #41).
///
/// The second half is the case that discriminates: `/d/` does not exist yet,
/// so `PUT`ting a blob under it materializes the container and
/// links it into its parent before the blob write, the only step that can
/// still fail, fails. `FailingBlobs`, not `FailingStore`: a failing
/// `SparqlStore` takes its `500` inside `materialize` itself and never
/// reaches the tail (see `a_post_whose_write_fails_emits_nothing`).
#[tokio::test]
async fn a_refused_put_emits_nothing() {
    let f = fixture_with_blobs(Arc::new(FailingBlobs), 64 * 1024 * 1024).await;

    let target = f.space.resolve("/c/notes").unwrap();
    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
    let mut on_parent = f.events.subscribe(
        crate::notify::Topic::from(&f.space.resolve("/c/").unwrap()));

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("this is not turtle {{{")).unwrap()).await.unwrap();
    assert!(!res.status().is_success(), "the fixture's premise: {}", res.status());
    stays_silent(&mut on_target, "a refused write is not a change").await;
    stays_silent(&mut on_parent, "a refused write materialized nothing to report either").await;

    let child = f.space.resolve("/d/photo.png").unwrap();
    let container = f.space.resolve("/d/").unwrap();
    let mut on_child = f.events.subscribe(crate::notify::Topic::from(&child));
    let mut on_container = f.events.subscribe(crate::notify::Topic::from(&container));

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/d/photo.png")
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(&b"\x89PNG\r\n\x1a\n"[..])).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR, "the fixture's premise");

    // `/d/` was materialized: `Guard::materialize` commits its
    // container and containment writes to the real store before
    // `put_blob` ever runs, so the 500 above leaves it behind.
    let d = f.app.clone().oneshot(f.owner_request("GET", "/d/")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(d.status(), StatusCode::OK,
        "materialize must have created /d/ before put_blob failed");

    stays_silent(&mut on_child, "no bytes were stored, so no child was created").await;
    stays_silent(&mut on_container,
        "the container was materialized, but the write still failed").await;
}

/// The allocated child is always new, so `POST` is always a `Create`, and
/// the container that received it hears `Add`, with the child as `object`.
/// `/c/` is made to exist first (as
/// `a_put_that_creates_emits_create_on_the_target_and_add_on_the_parent`
/// does), so this write's only containment change there is the `Add`.
#[tokio::test]
async fn a_post_emits_create_on_the_child_and_add_on_the_container() {
    let f = fixture().await;
    f.put_turtle("/c/other", "<#it> <http://schema.org/name> \"y\" .").await;
    let container = f.space.resolve("/c/").unwrap();
    let child = f.space.resolve("/c/child").unwrap();
    let mut on_container = f.events.subscribe(crate::notify::Topic::from(&container));
    // Subscribed up front, alongside the container: a broken `emit_post`
    // that only ran `publish_containment` and never `publish_own` on the
    // child would still satisfy an assertion made solely on the
    // container's channel, so the child's own `Create` is checked too.
    let mut on_child = f.events.subscribe(crate::notify::Topic::from(&child));

    let res = f.app.clone().oneshot(f.owner_request("POST", "/c/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "child")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let location = res.headers()[header::LOCATION].to_str().unwrap().to_owned();
    assert_eq!(location, child.graph_iri(), "the fixture's premise: no slug collision");

    let created = next_event(&mut on_child).await;
    assert_eq!(created.activity, crate::notify::Activity::Create);
    assert_eq!(created.object, child.graph_iri());
    assert_eq!(created.target, None);
    assert!(created.state.is_some(), "a create reports the state it produced");

    let e = next_event(&mut on_container).await;
    assert_eq!(e.activity, crate::notify::Activity::Add);
    assert_eq!(e.object, location, "the object of an Add is the allocated child");
    assert_eq!(e.target.as_deref(), Some(container.graph_iri()));
    // Independent of `state_of`: a GET on the container itself, at the
    // same media type and version §5.1 fixes, is the validator the pod
    // would hand a client for the same state. Catches an Add reporting
    // back the child's state instead of the topic's.
    let container_etag = f.app.clone().oneshot(f.owner_request("GET", "/c/")
        .header(header::ACCEPT, "application/n-quads")
        .body(Body::empty()).unwrap()).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_eq!(e.state.as_deref(), Some(container_etag.as_str()),
        "the Add's state must be the container's own validator, not the child's");
}

/// Every other refusal in `post_impl` returns before the tail, so a
/// storage failure is the only way a non-2xx reaches `emit_post`, and its
/// success guard is all that stands between that and a `Create` for a
/// child that was never written, plus an `Add` naming it.
///
/// The blob backend is what fails, not the store: `Guard::materialize`
/// runs before the write and takes its own `500` out of `post_impl` past
/// the tail, so a failing `SparqlStore` never gets a request as far as the
/// emit.
#[tokio::test]
async fn a_post_whose_write_fails_emits_nothing() {
    let f = fixture_with_blobs(Arc::new(FailingBlobs), 64 * 1024 * 1024).await;
    let container = f.space.resolve("/c/").unwrap();
    let child = f.space.resolve("/c/photo.png").unwrap();
    let mut on_container = f.events.subscribe(crate::notify::Topic::from(&container));
    let mut on_child = f.events.subscribe(crate::notify::Topic::from(&child));

    let res = f.app.clone().oneshot(f.owner_request("POST", "/c/")
        .header(header::CONTENT_TYPE, "image/png")
        .header("slug", "photo.png")
        .body(Body::from(&b"\x89PNG\r\n\x1a\n"[..])).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR, "the fixture's premise");

    stays_silent(&mut on_child, "no bytes were stored, so no child was created").await;
    stays_silent(&mut on_container, "and nothing is there for an Add to name").await;
}

/// The ordinary patch: the resource was there, so it is an `Update`.
#[tokio::test]
async fn a_patch_on_an_existing_resource_emits_update() {
    let f = fixture().await;
    let target = f.space.resolve("/c/notes").unwrap();
    f.put_turtle("/c/notes", "<#it> <http://schema.org/name> \"one\" .").await;

    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
    let res = f.app.clone().oneshot(f.owner_request("PATCH", "/c/notes")
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
             <> a solid:InsertDeletePatch ; solid:inserts \
             { <#it> <http://schema.org/keywords> \"k\" . } .\n")).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let e = next_event(&mut on_target).await;
    assert_eq!(e.activity, crate::notify::Activity::Update);
    // Independent of `state_of`: a GET at the same media type and version
    // §5.1 fixes is the validator the pod would hand a client for the
    // post-patch state. A bare `is_some()` would pass a read-back of the
    // wrong resource; this pins the exact value.
    let etag = f.app.clone().oneshot(f.owner_request("GET", "/c/notes")
        .header(header::ACCEPT, "application/n-quads")
        .body(Body::empty()).unwrap()).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_eq!(e.state.as_deref(), Some(etag.as_str()));
}

/// `create_by_patch`: a patch on an absent resource creates it, so it is a
/// `Create` and its parent hears `Add`.
#[tokio::test]
async fn a_patch_that_creates_emits_create_and_add() {
    let f = fixture().await;
    f.put_turtle("/c/other", "<#it> <http://schema.org/name> \"y\" .").await;
    let target = f.space.resolve("/c/fresh").unwrap();
    let parent = f.space.resolve("/c/").unwrap();
    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
    let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));

    let res = f.app.clone().oneshot(f.owner_request("PATCH", "/c/fresh")
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
             <> a solid:InsertDeletePatch ; solid:inserts \
             { <#it> <http://schema.org/name> \"x\" . } .\n")).unwrap())
        .await.unwrap();
    assert!(res.status().is_success(), "create-by-patch: {}", res.status());

    assert_eq!(next_event(&mut on_target).await.activity, crate::notify::Activity::Create);
    let p = next_event(&mut on_parent).await;
    assert_eq!(p.activity, crate::notify::Activity::Add);
    assert_eq!(p.object, target.graph_iri());
    // Independent of `state_of`: a GET on the container itself, at the
    // same media type and version §5.1 fixes, is the validator the pod
    // would hand a client for the same state.
    let container_etag = f.app.clone().oneshot(f.owner_request("GET", "/c/")
        .header(header::ACCEPT, "application/n-quads")
        .body(Body::empty()).unwrap()).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_eq!(p.state.as_deref(), Some(container_etag.as_str()),
        "the Add's state must be the container's own validator, not the child's");
}

/// §6.3: a `PUT` on an auxiliary reaches `put_impl`'s tail and emits, and
/// that is the whole argument for the aux `PATCH` fix, the two verbs must
/// agree about the same topic. First write creates it, the second updates
/// it, and its subject's container hears neither: an auxiliary is never a
/// member (§4.2).
#[tokio::test]
async fn a_put_on_an_auxiliary_emits_create_then_update() {
    let f = fixture().await;
    f.put_turtle("/c/notes", "<#it> <http://schema.org/name> \"one\" .").await;
    let aux = f.space.resolve("/.aux/c/notes.acl").unwrap();
    let mut on_aux = f.events.subscribe(crate::notify::Topic::from(&aux));
    let mut on_parent = f.events.subscribe(
        crate::notify::Topic::from(&f.space.resolve("/c/").unwrap()));

    // Control on every write, or the second `PUT` would be refused by the
    // policy the first one installed.
    let acl = |title: &str| format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/c/notes> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ; \
         <http://purl.org/dc/terms/title> \"{title}\" ."
    );
    assert_eq!(put_acl(&f, "/c/notes", &acl("first")).await.status(), StatusCode::CREATED);

    let created = next_event(&mut on_aux).await;
    assert_eq!(created.activity, crate::notify::Activity::Create);
    assert_eq!(created.object, aux.graph_iri());
    assert_eq!(created.target, None);

    let second = put_acl(&f, "/c/notes", &acl("second")).await;
    assert!(second.status().is_success(), "overwriting the acl: {}", second.status());

    let updated = next_event(&mut on_aux).await;
    assert_eq!(updated.activity, crate::notify::Activity::Update,
        "the auxiliary was there, so the second write is not another Create");
    // Independent of `state_of`: a GET on the auxiliary itself, at the
    // media type and version §5.1 fixes, is the validator the pod would
    // hand a client for the same state.
    let aux_etag = f.app.clone().oneshot(f.owner_request("GET", "/.aux/c/notes.acl")
        .header(header::ACCEPT, "application/n-quads")
        .body(Body::empty()).unwrap()).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_eq!(updated.state.as_deref(), Some(aux_etag.as_str()));

    stays_silent(&mut on_parent,
        "an auxiliary is never a container member, so containment did not change").await;
}

/// Design §4.3: an auxiliary `PATCH` never creates (`aux::patch` refuses
/// an absent one), so it is always an `Update`, reported on the
/// auxiliary's own topic. An auxiliary is never a container member, so
/// its parent's containment does not change either.
#[tokio::test]
async fn a_patch_on_an_auxiliary_emits_update() {
    let f = fixture().await;
    f.put_turtle("/c/notes", "<#it> <http://schema.org/name> \"one\" .").await;
    let acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/c/notes> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
    );
    assert_eq!(put_acl(&f, "/c/notes", &acl_body).await.status(), StatusCode::CREATED);

    let aux = f.space.resolve("/.aux/c/notes.acl").unwrap();
    let parent = f.space.resolve("/c/").unwrap();
    let mut on_aux = f.events.subscribe(crate::notify::Topic::from(&aux));
    let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));

    let res = patch_n3(&f, "/.aux/c/notes.acl",
        "<> a solid:InsertDeletePatch ; solid:inserts \
         { <#owner> <http://purl.org/dc/terms/title> \"updated\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let e = next_event(&mut on_aux).await;
    assert_eq!(e.activity, crate::notify::Activity::Update);
    assert_eq!(e.object, aux.graph_iri());
    assert_eq!(e.target, None);
    // Independent of `state_of`: a GET on the auxiliary itself, at the
    // same media type and version §5.1 fixes, is the validator the pod
    // would hand a client for the same state.
    let aux_etag = f.app.clone().oneshot(f.owner_request("GET", "/.aux/c/notes.acl")
        .header(header::ACCEPT, "application/n-quads")
        .body(Body::empty()).unwrap()).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_eq!(e.state.as_deref(), Some(aux_etag.as_str()));
    stays_silent(&mut on_parent,
        "an auxiliary is never a container member, so containment did not change").await;
}

/// Deleting `emit_patch`'s `!status.is_success()` guard would let this
/// through with a bogus `Update`, the tail is reached, patch or no.
#[tokio::test]
async fn a_refused_patch_emits_nothing() {
    let f = fixture().await;
    f.put_turtle("/c/notes", "<#it> <http://schema.org/name> \"one\" .").await;
    let target = f.space.resolve("/c/notes").unwrap();
    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));

    // `solid:deletes` names a triple that is not there, the simplest 409.
    let res = patch_n3(&f, "/c/notes",
        "<> a solid:InsertDeletePatch ; solid:deletes \
         { <#it> <http://schema.org/name> \"absent\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT, "the fixture's premise");
    stays_silent(&mut on_target, "a refused patch is not a change").await;
}

/// The resource, and its parent losing a member. `Remove` carries the child
/// as `object`, exactly as `Add` does.
#[tokio::test]
async fn a_delete_emits_delete_on_the_target_and_remove_on_the_parent() {
    let f = fixture().await;
    let target = f.space.resolve("/c/notes").unwrap();
    let parent = f.space.resolve("/c/").unwrap();
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
        .await.unwrap();

    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
    let mut on_parent = f.events.subscribe(crate::notify::Topic::from(&parent));
    let res = f.app.clone().oneshot(
        f.owner_request("DELETE", "/c/notes").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let e = next_event(&mut on_target).await;
    assert_eq!(e.activity, crate::notify::Activity::Delete);
    assert_eq!(e.state, None, "a deleted resource has no state to report");

    let p = next_event(&mut on_parent).await;
    assert_eq!(p.activity, crate::notify::Activity::Remove);
    assert_eq!(p.object, target.graph_iri());
    assert_eq!(p.target.as_deref(), Some(parent.graph_iri()));
    // Independent of `state_of`: a GET on the container itself, at the
    // same media type and version §5.1 fixes, is the validator the pod
    // would hand a client for the same state. Catches a Remove reporting
    // back the child's (nonexistent) state instead of the parent's.
    let parent_etag = f.app.clone().oneshot(f.owner_request("GET", "/c/")
        .header(header::ACCEPT, "application/n-quads")
        .body(Body::empty()).unwrap()).await.unwrap()
        .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
    assert_eq!(p.state.as_deref(), Some(parent_etag.as_str()),
        "the parent still exists and reports its new state");
}

/// `aux::delete_subject` takes the ACL with the subject, and its own topic
/// hears about it.
#[tokio::test]
async fn deleting_a_subject_emits_delete_for_the_auxiliaries_it_cascades() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
        .await.unwrap();
    f.app.clone().oneshot(f.owner_request("PUT", "/.aux/c/notes.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/c/notes> ; \
             <http://www.w3.org/ns/auth/acl#mode> \
             <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write>, \
             <http://www.w3.org/ns/auth/acl#Control> ."))).unwrap())
        .await.unwrap();

    let acl = f.space.resolve("/.aux/c/notes.acl").unwrap();
    let mut on_acl = f.events.subscribe(crate::notify::Topic::from(&acl));
    f.app.clone().oneshot(
        f.owner_request("DELETE", "/c/notes").body(Body::empty()).unwrap()).await.unwrap();

    let e = next_event(&mut on_acl).await;
    assert_eq!(e.activity, crate::notify::Activity::Delete);
}

/// A direct auxiliary `DELETE` reaches the tail's single `emit_delete`
/// rather than returning early past it, so it is reported on the
/// auxiliary's own topic. An auxiliary is never a container member, so
/// its removal is not a containment change and the parent hears nothing
/// (design §4.2).
#[tokio::test]
async fn deleting_an_auxiliary_emits_no_parent_event() {
    let f = fixture().await;
    f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
        .await.unwrap();
    f.app.clone().oneshot(f.owner_request("PUT", "/.aux/c/notes.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/c/notes> ; \
             <http://www.w3.org/ns/auth/acl#mode> \
             <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write>, \
             <http://www.w3.org/ns/auth/acl#Control> ."))).unwrap())
        .await.unwrap();

    let acl = f.space.resolve("/.aux/c/notes.acl").unwrap();
    let mut on_parent = f.events.subscribe(
        crate::notify::Topic::from(&f.space.resolve("/c/").unwrap()));
    let mut on_acl = f.events.subscribe(crate::notify::Topic::from(&acl));
    let res = f.app.clone().oneshot(
        f.owner_request("DELETE", "/.aux/c/notes.acl").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let e = next_event(&mut on_acl).await;
    assert_eq!(e.activity, crate::notify::Activity::Delete);
    assert_eq!(e.object, acl.graph_iri());
    assert_eq!(e.target, None);
    assert_eq!(e.state, None);
    stays_silent(&mut on_acl, "the aux arm reaches the tail's one emit, not two").await;

    stays_silent(&mut on_parent,
        "an auxiliary is not a member, so nothing about containment changed").await;
}

/// `delete_impl` collects only the auxiliaries `authorize_aux` reported
/// present. One it found absent must not reach `emit_delete`, or a `DELETE`
/// would announce the removal of an auxiliary that never was, on the topic
/// of every kind in `AuxKind::ALL`, as each new kind is added.
#[tokio::test]
async fn a_delete_says_nothing_about_an_auxiliary_that_was_not_there() {
    let f = fixture().await;
    f.put_turtle("/c/notes", "<#it> <http://schema.org/name> \"x\" .").await;
    let target = f.space.resolve("/c/notes").unwrap();
    let acl = f.space.resolve("/.aux/c/notes.acl").unwrap();
    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));
    let mut on_acl = f.events.subscribe(crate::notify::Topic::from(&acl));

    let res = f.app.clone().oneshot(
        f.owner_request("DELETE", "/c/notes").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    assert_eq!(next_event(&mut on_target).await.activity, crate::notify::Activity::Delete);
    stays_silent(&mut on_acl,
        "the resource had no acl, so the cascade took none with it").await;
}

/// A refused delete emits nothing: the tail returns before touching the bus.
#[tokio::test]
async fn a_refused_delete_emits_nothing() {
    let f = fixture().await;
    let mut on_target = f.events.subscribe(
        crate::notify::Topic::from(&f.space.resolve("/never-existed").unwrap()));

    let res = f.app.clone().oneshot(
        f.owner_request("DELETE", "/never-existed").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "the fixture's premise");
    stays_silent(&mut on_target, "a refused delete is not a change").await;
}

/// §9's first mandated test, on the wire: `state` is byte-identical to the
/// `ETag` of an immediately following `GET` at the media type and version
/// §5.1 fixes. Against a resource that holds RDF 1.2, with the
/// unversioned read of the same state asserted to differ, on a 1.1 fixture
/// the two reads return the same tag and the version half of §5.2 goes
/// unchecked.
#[tokio::test]
async fn the_state_is_the_versioned_n_quads_etag_of_a_1_2_resource() {
    let f = fixture().await;
    let target = f.space.resolve("/foo").unwrap();
    let mut on_target = f.events.subscribe(crate::notify::Topic::from(&target));

    assert_eq!(
        put_versioned(&f, "/foo", "text/turtle;version=1.2", TRIPLE_TERM_TTL).await.status(),
        StatusCode::CREATED,
        "the fixture's premise: the stored state holds a triple term",
    );
    let e = next_event(&mut on_target).await;

    let versioned = get_accepting(&f, "/foo", "application/n-quads;version=1.2").await;
    assert_eq!(versioned.status(), StatusCode::OK);
    let versioned_etag = versioned.headers()[header::ETAG].to_str().unwrap().to_owned();
    let unversioned = get_accepting(&f, "/foo", "application/n-quads").await;
    assert_eq!(unversioned.status(), StatusCode::OK);
    let unversioned_etag = unversioned.headers()[header::ETAG].to_str().unwrap().to_owned();

    assert_ne!(versioned_etag, unversioned_etag,
        "the two reads must differ, or this test cannot tell the versions apart");
    assert_eq!(e.state.as_deref(), Some(versioned_etag.as_str()),
        "state is the validator of the state as held, not of its 1.1 projection");
}

/// A deep create is six events, and the root hears exactly one of them:
/// `Add` naming the container directly beneath it. Not `Create` for the
/// grandchild, `as:Create` only ever runs on the new resource's own
/// channel (design §3.2).
#[tokio::test]
async fn a_deep_create_tells_the_root_only_about_its_own_child() {
    let f = fixture().await;
    let root = f.space.resolve("/").unwrap();
    let a = f.space.resolve("/a/").unwrap();
    let mut on_root = f.events.subscribe(crate::notify::Topic::from(&root));

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/a/b/c.ttl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap())
        .await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let e = next_event(&mut on_root).await;
    assert_eq!(e.activity, crate::notify::Activity::Add);
    assert_eq!(e.object, a.graph_iri(), "the root's own child, not the grandchild");
    assert_eq!(e.target.as_deref(), Some(root.graph_iri()));

    stays_silent(&mut on_root, "one event on the root, not one per level below it").await;
}
