//! SHACL: refusal, warning, and the `?validate` view.

use super::fixture::*;

/// The shapes document, and a container bound to it. Returns nothing;
/// both are ordinary resources afterwards. Binds `shape_ttl`, stored at
/// `shape_path`, to `container_path`, the one place this file spells
/// `ldp:constrainedBy` to set a binding up (data, not a read; see
/// `docs/constraints.md`).
async fn bind_shape(f: &Fixture, container_path: &str, shape_path: &str, shape_ttl: &str) {
    f.put_turtle(shape_path, shape_ttl).await;
    f.put_turtle(container_path, &format!(
        "<> <http://www.w3.org/ns/ldp#constrainedBy> <https://pod.toph.so{shape_path}> ."
    )).await;
}

pub(super) async fn bind_note_shape(f: &Fixture) {
    bind_shape(f, "/notes/", "/shapes/note", r#"
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix schema: <http://schema.org/> .
        <http://example.org/NoteShape> a sh:NodeShape ;
          sh:targetClass schema:NoteDigitalDocument ;
          sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Violation ] .
    "#).await;
}

#[tokio::test]
async fn a_violating_write_is_refused_and_stores_nothing() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"first\" .").await;

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle");
    let body = body_string(res).await;
    assert!(body.contains("ValidationReport"), "the report is the body: {body}");

    assert!(f.get_turtle("/notes/n1").await.contains("first"),
        "the refused write must not have replaced the stored representation");
}

/// §3.1: a `422` names the shape that explains the refusal, so a client
/// can fetch it rather than being told only that something failed.
#[tokio::test]
async fn a_refused_write_names_the_shape_in_a_link_header() {
    let f = fixture().await;
    bind_note_shape(&f).await;

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let link = res.headers().get(header::LINK).expect("a Link header naming the shape")
        .to_str().unwrap().to_owned();
    assert!(link.contains("/shapes/note"), "expected the shape's own IRI: {link}");
    assert!(link.contains("constrainedBy"), "expected the constrainedBy relation: {link}");
}

/// §5.1: validation runs before the traversal that adds the containment
/// triple, so a refusal leaves the container exactly as it was, no
/// `ldp:contains` pointing at a resource that was never created.
#[tokio::test]
async fn a_refused_write_adds_no_containment() {
    let f = fixture().await;
    bind_note_shape(&f).await;

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let listing = f.get_turtle("/notes/").await;
    assert!(!listing.contains("/notes/n1"),
        "the refused write left a containment triple behind: {listing}");
}

#[tokio::test]
async fn a_warning_admits_the_write_and_links_the_report() {
    let f = fixture().await;
    f.put_turtle("/shapes/note", r#"
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix schema: <http://schema.org/> .
        <http://example.org/NoteShape> a sh:NodeShape ;
          sh:targetClass schema:NoteDigitalDocument ;
          sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Warning ] .
    "#).await;
    f.put_turtle("/notes/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
        <https://pod.toph.so/shapes/note> .").await;

    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let link = res.headers().get_all(header::LINK).iter()
        .map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>().join(", ");
    assert!(link.contains("/notes/n1?validate") && link.contains("describedby"),
        "expected a describedby link to the report, got: {link}");
}

#[tokio::test]
async fn a_conforming_write_carries_no_report_link() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ; \
            <http://schema.org/name> \"ok\" ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let link = res.headers().get_all(header::LINK).iter()
        .map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>().join(", ");
    assert!(!link.contains("validate"), "nothing to describe: {link}");
}

/// The `describedby` link falls out of a tail that `Target::Resource`'s
/// `Err` arm shares with its `Ok` arm, so a warning-only validation
/// followed by a `put_dataset` failure must not still advertise a report
/// for a write that never persisted.
///
/// The resource is pre-created so the failing write adds no containment
/// triple, `store.update` runs exactly once for it, inside `put_dataset`
/// itself, which is the call `FailingStore` is armed to fail.
#[tokio::test]
async fn a_failed_write_after_a_warning_carries_no_report_link() {
    let store = Arc::new(FailingStore::new(OxigraphStore::in_memory().unwrap()));
    let f = fixture_with_store_and_blobs(
        store.clone(),
        Arc::new(crate::blob::ObjectStoreBlobs::in_memory()),
        64 * 1024 * 1024,
    ).await;
    f.put_turtle("/shapes/note", r#"
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix schema: <http://schema.org/> .
        <http://example.org/NoteShape> a sh:NodeShape ;
          sh:targetClass schema:NoteDigitalDocument ;
          sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Warning ] .
    "#).await;
    f.put_turtle("/notes/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
        <https://pod.toph.so/shapes/note> .").await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"first\" .").await;

    store.arm();
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
        .unwrap()).await.unwrap();

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(res.headers().get(header::LINK).is_none(),
        "a write that did not persist has nothing for describedby to describe");
}

/// An ACL is server-understood data; a user shape may not refuse one (§5.3).
#[tokio::test]
async fn an_acl_write_is_never_validated() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"ok\" .").await;

    // Alongside the authorization the ACL needs, a subject typed
    // `schema:NoteDigitalDocument` with no `schema:name`, a triple
    // `NoteShape` would refuse if this write were validated like any
    // other resource. Without it, this test would still pass `201` even
    // if the `Target::Aux(_)` exemption in `enforce_shape` were deleted.
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/.aux/notes/n1.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(format!(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> . \
             @prefix schema: <http://schema.org/> . \
             <#a> a acl:Authorization ; acl:agent <{OWNER}> ; \
             acl:accessTo <https://pod.toph.so/notes/n1> ; acl:mode acl:Read, acl:Write, acl:Control . \
             <#note> a schema:NoteDigitalDocument ."
        ))).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// A blob has no triples, so nothing constrains it (§5.3).
#[tokio::test]
async fn a_blob_write_is_never_validated() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/pic.png")
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(&b"\x89PNG"[..])).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// Failing closed: an unusable constraint document refuses the write
/// rather than letting it through unvalidated (§7, §10).
#[tokio::test]
async fn a_broken_constraint_document_is_a_conflict() {
    let f = fixture().await;
    f.put_turtle("/notes/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
        <https://pod.toph.so/shapes/gone> .").await;
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

/// §3.2: the binding does not inherit.
#[tokio::test]
async fn a_binding_does_not_reach_a_grandchild() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/2026/n1")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED,
        "/notes/2026/ carries no binding of its own");
}

/// The child a `POST` allocates is validated against the binding on the
/// container it lands in, and a refusal leaves that child unallocated.
#[tokio::test]
async fn a_violating_post_is_refused_and_creates_nothing() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    let res = f.app.clone().oneshot(f.owner_request("POST", "/notes/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "n1")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let res = f.app.clone().oneshot(f.owner_request("GET", "/notes/n1")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_conforming_post_is_created() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    let res = f.app.clone().oneshot(f.owner_request("POST", "/notes/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .header("slug", "n1")
        .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ; \
            <http://schema.org/name> \"ok\" ."))
        .unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn validate_view_reports_the_current_state() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"ok\" .").await;

    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/n1", "validate")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(body.contains("ValidationReport"));
    assert!(!body.contains("resultSeverity"), "conforming, so no results: {body}");
}

/// The report is computed, not stored: editing the shape changes it with
/// no write to the resource.
#[tokio::test]
async fn validate_view_follows_a_later_shape_edit() {
    let f = fixture().await;
    f.put_turtle("/shapes/note", "@prefix sh: <http://www.w3.org/ns/shacl#> . \
        <http://example.org/S> a sh:NodeShape .").await;
    f.put_turtle("/notes/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
        <https://pod.toph.so/shapes/note> .").await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> .").await;

    f.put_turtle("/shapes/note", r#"
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix schema: <http://schema.org/> .
        <http://example.org/NoteShape> a sh:NodeShape ;
          sh:targetClass schema:NoteDigitalDocument ;
          sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Warning ] .
    "#).await;

    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/n1", "validate")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_string(res).await.contains("Warning"),
        "the report must reflect the shape as it is now");
}

#[tokio::test]
async fn validate_view_is_404_without_a_binding() {
    let f = fixture().await;
    f.put_turtle("/plain", "<> <http://schema.org/name> \"x\" .").await;
    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/plain", "validate")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn validate_view_needs_read_on_the_subject() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"ok\" .").await;

    let bob = "https://bob.example/card#me";
    let bob_app = f.app_also_trusting(bob);
    let req = f.sign(
        Request::builder().method("GET").uri("/notes/n1?validate"),
        bob, "GET", "/notes/n1",
    ).body(Body::empty()).unwrap();
    assert_eq!(bob_app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// An unknown query parameter is ignored, as everywhere else.
#[tokio::test]
async fn a_misspelled_parameter_returns_the_resource() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"ok\" .").await;
    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/n1", "validat")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_string(res).await.contains("schema.org/name"));
}

#[tokio::test]
async fn validate_view_response_varies_on_accept() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"ok\" .").await;

    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/n1", "validate")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
}

/// A container's shape lookup uses its own parent, exactly as a PUT to
/// the container does, here the root, which binds the shape that
/// `/notes/` itself is validated against.
#[tokio::test]
async fn validate_view_on_a_container_uses_its_own_parent() {
    let f = fixture().await;
    f.put_turtle("/shapes/any", "@prefix sh: <http://www.w3.org/ns/shacl#> . \
        <http://example.org/S> a sh:NodeShape .").await;
    f.put_turtle("/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
        <https://pod.toph.so/shapes/any> .").await;
    f.put_turtle("/notes/", "<> <http://purl.org/dc/terms/title> \"notes\" .").await;

    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/", "validate")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(body.contains("ValidationReport"));
    assert!(!body.contains("resultSeverity"), "the shape has no target, so nothing is flagged: {body}");
}

/// §3.4/§10: `ldp:contains` is never in a data graph, so a container that
/// was accepted at write time, its own body carried no members, must
/// still conform at `?validate` after the ancestor walk adds one. A shape
/// targeting `ldp:contains` directly on the container's own IRI is what
/// would trip if the read path validated the full stored graph instead of
/// what the write path checked.
#[tokio::test]
async fn validate_view_on_a_container_matches_what_its_write_was_validated_against() {
    let f = fixture().await;
    bind_shape(&f, "/", "/shapes/no-members", r#"
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix ldp: <http://www.w3.org/ns/ldp#> .
        <http://example.org/NoMembersShape> a sh:NodeShape ;
          sh:targetNode <https://pod.toph.so/notes/> ;
          sh:property [ sh:path ldp:contains ; sh:maxCount 0 ; sh:severity sh:Violation ] .
    "#).await;
    f.put_turtle("/notes/", "<> <http://purl.org/dc/terms/title> \"notes\" .").await;
    f.put_turtle("/notes/n1", "<> <http://schema.org/name> \"x\" .").await;

    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/", "validate")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(!body.contains("resultSeverity"),
        "the write into /notes/ was accepted, so ?validate must agree: {body}");
}

/// `without_server_managed` used to strip `rdf:type ldp:Container`/
/// `ldp:BasicContainer` on *any* subject, but `ensure_container` only ever
/// asserts that pair on the container's own IRI. A client-authored type
/// triple about a subject the server never touches, `<#x>` here, must
/// therefore survive into the `?validate` view exactly as the write path
/// validated it.
///
/// The container's own subject is a different story: `ensure_container`
/// re-asserts the same pair there on every write, so a client-authored `<>
/// a ldp:Container` and the server's own assertion collapse into one
/// stored triple with no way to tell which wrote it, that focus node keeps
/// reporting `sh:Violation` for `sh:hasValue ldp:Container` even though
/// the write that produced it was accepted. Narrowing the strip to the
/// container's own subject cannot recover that; it only stops the filter
/// from reaching past it onto `<#x>`.
#[tokio::test]
async fn without_server_managed_only_strips_the_containers_own_type_pair() {
    let f = fixture().await;
    bind_shape(&f, "/", "/shapes/requires-container-type", r#"
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix ldp: <http://www.w3.org/ns/ldp#> .
        @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
        <http://example.org/S> a sh:NodeShape ;
          sh:targetNode <https://pod.toph.so/notes/>, <https://pod.toph.so/notes/#x> ;
          sh:property [ sh:path rdf:type ; sh:hasValue ldp:Container ; sh:severity sh:Violation ] .
    "#).await;
    let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<> a <http://www.w3.org/ns/ldp#Container> . \
            <#x> a <http://www.w3.org/ns/ldp#Container> .")).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/", "validate")
        .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(!body.contains("notes/#x>"),
        "the write into /notes/ accepted <#x> a ldp:Container, so ?validate must not \
         report a violation for it: {body}");
}

/// §5.3: a blob is never validated, `?validate` on one answers `404`, the
/// same "no report here" a resource never validated at all gets, not a
/// vacuous `200, sh:conforms true` for a representation SHACL never saw.
#[tokio::test]
async fn validate_view_on_a_blob_is_404() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_blob("/notes/pic.png", "image/png", &b"\x89PNG"[..]).await;

    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/pic.png", "validate")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// An auxiliary is never validated, whatever its subject's shape says,
/// both the ACL and the subject it governs exist here, so the 404 proves
/// the rule rather than an absent resource answering incidentally.
#[tokio::test]
async fn validate_view_on_an_auxiliary_is_404() {
    let f = fixture().await;
    f.put_turtle("/notes/n1", "<> <http://schema.org/name> \"x\" .").await;
    let body = format!(
        "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
         <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/notes/n1> ; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put = put_acl(&f, "/notes/n1", &body).await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let res = f.app.clone().oneshot(f.owner_request_query("GET", "/.aux/notes/n1.acl", "validate")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
