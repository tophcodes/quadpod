//! N3 Patch.

use super::fixture::*;
use super::shapes::bind_note_shape;

async fn body_bytes(res: axum::response::Response) -> Vec<u8> {
    http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes().to_vec()
}

#[tokio::test]
async fn a_patch_changes_one_triple_and_answers_204() {
    let f = fixture().await;
    f.put_turtle("/profile",
        "<#me> <http://example.org/email> \"old\" ; <http://example.org/name> \"Toph\" .").await;

    let res = patch_n3(&f, "/profile",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:where   { ?p ex:email \"old\" . } ;\n\
           solid:deletes { ?p ex:email \"old\" . } ;\n\
           solid:inserts { ?p ex:email \"new\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let ttl = f.get_turtle("/profile").await;
    assert!(ttl.contains("\"new\""), "{ttl}");
    assert!(!ttl.contains("\"old\""), "{ttl}");
    assert!(ttl.contains("\"Toph\""), "an untouched triple must survive: {ttl}");
}

// §8: `text/n3` is a perfectly good body, so `415` would be a claim about
// the wrong thing — the conflict is with a target that has no triples.
// The byte assertion is the half a status check cannot see: a `409` that
// also destroyed the object passes a status-only test.
#[tokio::test]
async fn a_patch_at_a_blob_is_409_and_the_bytes_survive() {
    let f = fixture().await;
    f.put_blob("/notes.txt", "text/plain", b"hello \x00\xff bytes").await;

    let res = patch_n3(&f, "/notes.txt",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:x \"1\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    let got = f.app.clone().oneshot(f.owner_request("GET", "/notes.txt")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert_eq!(body_bytes(got).await, b"hello \x00\xff bytes");
}

#[tokio::test]
async fn a_patch_setting_containment_on_a_container_is_409() {
    let f = fixture().await;
    f.put_turtle("/c/thing", "<#a> <http://example.org/b> \"c\" .").await;

    let res = patch_n3(&f, "/c/",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> <http://www.w3.org/ns/ldp#contains> \
                           <https://pod.toph.so/c/forged> . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    let ttl = f.get_turtle("/c/").await;
    assert!(!ttl.contains("forged"), "containment is server-managed: {ttl}");
}

// A container's LDP type lives only in its body — the pod emits no
// `Link: rel="type"` — so a patch that deletes it would leave the container
// untyped to every client. `put_impl` re-asserts the server's type triples
// after writing a container body; a patch is answered the same way, which
// keeps the client free to patch the container's other triples.
#[tokio::test]
async fn a_patch_cannot_strip_a_containers_ldp_type() {
    let f = fixture().await;
    f.put_turtle("/c/thing", "<#a> <http://example.org/b> \"c\" .").await;

    let res = patch_n3(&f, "/c/",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:deletes { <> a <http://www.w3.org/ns/ldp#BasicContainer> . } .\n").await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let ttl = f.get_turtle("/c/").await;
    assert!(ttl.contains("BasicContainer"), "a container must stay typed: {ttl}");
    assert!(ttl.contains("thing"), "its members must survive the re-assertion: {ttl}");
}

#[tokio::test]
async fn a_patch_deleting_through_a_variable_predicate_on_a_container_is_409() {
    let f = fixture().await;
    f.put_turtle("/c/thing", "<#a> <http://example.org/b> \"c\" .").await;
    f.put_turtle("/c/", "<> <http://example.org/marker> <http://example.org/target> .").await;

    let res = patch_n3(&f, "/c/",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:where   { <> ?p <http://example.org/target> . } ;\n\
           solid:deletes { <> ?p <http://example.org/target> . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_stale_if_match_refuses_the_patch_with_412() {
    let f = fixture().await;
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

    let res = f.app.clone().oneshot(f.owner_request("PATCH", "/profile")
        .header(header::CONTENT_TYPE, "text/n3")
        .header(header::IF_MATCH, "\"deadbeef\"")
        .body(Body::from(patch_body(
            "_:patch a solid:InsertDeletePatch ;\n\
               solid:inserts { <> ex:x \"1\" . } .\n"))).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);

    let ttl = f.get_turtle("/profile").await;
    assert!(!ttl.contains("\"1\""), "nothing may have been written: {ttl}");
}

#[tokio::test]
async fn a_malformed_patch_document_is_422_and_a_bad_body_is_400() {
    let f = fixture().await;
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

    let two_inserts = patch_n3(&f, "/profile",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:x \"1\" . } ;\n\
           solid:inserts { <> ex:y \"2\" . } .\n").await;
    assert_eq!(two_inserts.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let junk = f.app.clone().oneshot(f.owner_request("PATCH", "/profile")
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from("this is not N3 {{{")).unwrap()).await.unwrap();
    assert_eq!(junk.status(), StatusCode::BAD_REQUEST);
}

// The middle row is `content-type-reject:19`, which has never been
// reachable because there was no `PATCH` route to reach the gate with.
#[tokio::test]
async fn the_content_type_gate_matches_classify_body() {
    let f = fixture().await;
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;
    let body = patch_body(
        "_:patch a solid:InsertDeletePatch ; solid:inserts { <> ex:x \"1\" . } .\n");

    let wrong = f.app.clone().oneshot(f.owner_request("PATCH", "/profile")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(body.clone())).unwrap()).await.unwrap();
    assert_eq!(wrong.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let untyped = f.app.clone().oneshot(f.owner_request("PATCH", "/profile")
        .body(Body::from(body)).unwrap()).await.unwrap();
    assert_eq!(untyped.status(), StatusCode::BAD_REQUEST);

    let empty = f.app.clone().oneshot(f.owner_request("PATCH", "/profile")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(empty.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// `authentication/header:40` as a unit test. It fails today only because
// axum answers `405` before the auth layer ever runs.
#[tokio::test]
async fn an_anonymous_patch_is_401_not_405() {
    let f = fixture().await;
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

    let res = f.app.clone().oneshot(Request::builder()
        .method("PATCH").uri("/profile")
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(patch_body(
            "_:patch a solid:InsertDeletePatch ; solid:inserts { <> ex:x \"1\" . } .\n")))
        .unwrap()).await.unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(res.headers().contains_key(header::WWW_AUTHENTICATE));
}

// §6.4. Both halves matter: the first alone is satisfied by a message that
// names nothing, the second alone by one that also prints the binding —
// which for a blank-node subject is a skolem IRI the client has never seen.
#[tokio::test]
async fn a_409_names_the_patch_and_never_a_skolem_iri() {
    let f = fixture().await;
    f.put_turtle("/profile", "[] <http://example.org/email> \"old\" .").await;

    let res = patch_n3(&f, "/profile",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:where   { ?p ex:email \"old\" . } ;\n\
           solid:deletes { ?p ex:email \"old\" . ?p ex:phone \"123\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    let body = String::from_utf8(body_bytes(res).await).unwrap();
    assert!(!body.contains("urn:quadpod:"), "a minted IRI must not leak: {body}");
    assert!(body.contains("phone"), "the message must say what failed: {body}");
}

// §9, and the `write-access-*` fixture's `A` row in both directions. A
// single `Mode::Write` gate refuses the first; a gate that only ever asks
// for `Append` admits the second.
#[tokio::test]
async fn an_append_only_agent_may_insert_but_not_delete() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

    let acl = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
           <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/profile> ; \
           <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
             <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
           <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/profile> ; \
           <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Append> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/profile.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);

    let insert = f.sign(Request::builder().method("PATCH").uri("/profile"), bob, "PATCH", "/profile")
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(patch_body(
            "_:patch a solid:InsertDeletePatch ; solid:inserts { <> ex:x \"1\" . } .\n")))
        .unwrap();
    assert_eq!(bob_app.clone().oneshot(insert).await.unwrap().status(), StatusCode::NO_CONTENT,
        "an insert-only patch needs Append, not Write");

    let delete = f.sign(Request::builder().method("PATCH").uri("/profile"), bob, "PATCH", "/profile")
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(patch_body(
            "_:patch a solid:InsertDeletePatch ;\n\
               solid:where   { ?p ex:email \"old\" . } ;\n\
               solid:deletes { ?p ex:email \"old\" . } .\n")))
        .unwrap();
    assert_eq!(bob_app.oneshot(delete).await.unwrap().status(), StatusCode::FORBIDDEN,
        "deleting needs Write");
}

/// An ACL granting the owner every mode over `/profile`, plus whatever
/// `extra` the test needs. The owner's own grant is repeated because this
/// ACL replaces the root's for its subject.
fn profile_acl(extra: &str) -> String {
    format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
           <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/profile> ; \
           <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
             <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         {extra}"
    )
}

#[tokio::test]
async fn an_acl_url_accepts_a_patch() {
    let f = fixture().await;
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;
    let put_acl = f.owner_request("PUT", "/.aux/profile.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(profile_acl(""))).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let res = patch_n3(&f, "/.aux/profile.acl",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <#owner> <http://www.w3.org/ns/auth/acl#mode> \
                           <http://www.w3.org/ns/auth/acl#Append> . } .\n").await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let ttl = f.get_turtle("/.aux/profile.acl").await;
    assert!(ttl.contains("#Append"), "the patch's triple must be there: {ttl}");
    assert!(ttl.contains("#Control"), "the grants it did not name must survive: {ttl}");
}

// §8: `authorize` substitutes Control for an Aux target regardless of the
// mode the handler asks for, so §9's tiering does not apply here. An agent
// holding Write on the subject but not Control must be refused — otherwise
// anyone who may edit a resource may rewrite the policy over it.
#[tokio::test]
async fn patching_an_acl_needs_control_not_write() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

    let acl = profile_acl(&format!(
        "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
           <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/profile> ; \
           <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
             <http://www.w3.org/ns/auth/acl#Write> ."
    ));
    let put_acl = f.owner_request("PUT", "/.aux/profile.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let bob_app = f.app_also_trusting(bob);
    let req = f.sign(
        Request::builder().method("PATCH").uri("/.aux/profile.acl"),
        bob, "PATCH", "/.aux/profile.acl",
    )
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(patch_body(
            "_:patch a solid:InsertDeletePatch ;\n\
               solid:inserts { <#bob> <http://www.w3.org/ns/auth/acl#mode> \
                               <http://www.w3.org/ns/auth/acl#Control> . } .\n")))
        .unwrap();
    assert_eq!(bob_app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let stored = f.stored("/.aux/profile.acl").await.expect("the ACL exists");
    assert!(
        !stored.iter().any(|t| t.to_string().contains("#bob") && t.to_string().ends_with("#Control>")),
        "a refused patch must not have granted anything: {stored:?}"
    );
}

// The converse of the test above, and the only one that pins §8's skip of
// the §9 mode check: `authorize` substituted Control for the auxiliary, so
// an agent holding Control and nothing else is exactly who may rewrite the
// policy. Asking §9's question again would demand Append on top of
// Control — which Control does not subsume — and refuse them. The owner's
// own ACL grants Read, Write and Control together, so no test using it can
// tell the skip from its absence.
#[tokio::test]
async fn control_alone_may_patch_an_acl() {
    let f = fixture().await;
    let carol = "https://carol.example/card#me";
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

    let acl = profile_acl(&format!(
        "<#carol> <http://www.w3.org/ns/auth/acl#agent> <{carol}> ; \
           <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/profile> ; \
           <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
    ));
    let put_acl = f.owner_request("PUT", "/.aux/profile.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let carol_app = f.app_also_trusting(carol);
    let req = f.sign(
        Request::builder().method("PATCH").uri("/.aux/profile.acl"),
        carol, "PATCH", "/.aux/profile.acl",
    )
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(patch_body(
            "_:patch a solid:InsertDeletePatch ;\n\
               solid:inserts { <#carol> <http://www.w3.org/ns/auth/acl#mode> \
                               <http://www.w3.org/ns/auth/acl#Append> . } .\n")))
        .unwrap();
    assert_eq!(carol_app.oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    let stored = f.stored("/.aux/profile.acl").await.expect("the ACL exists");
    assert!(
        stored.iter().any(|t| t.to_string().ends_with("#Append>")),
        "the patch an agent with Control may make must land: {stored:?}"
    );
}

// A patch does not create an auxiliary. The subject is present here, so
// the subject-missing `404` would be a false statement about the store —
// and an insert-only patch, whose `WHERE` the subject guard satisfies,
// would otherwise leave its triples in a graph nothing marks present.
#[tokio::test]
async fn patching_an_absent_acl_whose_subject_exists_is_404_and_writes_nothing() {
    let f = fixture().await;
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

    let res = patch_n3(&f, "/.aux/profile.acl",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <#owner> <http://www.w3.org/ns/auth/acl#mode> \
                           <http://www.w3.org/ns/auth/acl#Control> . } .\n").await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_string(res).await, AuxError::Missing.to_string(),
        "the subject exists, so the subject-missing body would be untrue");

    assert!(f.stored("/.aux/profile.acl").await.is_none());
    // Not just unmarked: `stored` gates on the presence marker, so it
    // reports `None` for a graph full of triples nobody ever made present.
    let iri = f.url("/.aux/profile.acl").graph_iri().to_string();
    let leftover = f.store
        .query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{iri}> {{ ?s ?p ?o }} }}"
        ))
        .await
        .unwrap();
    assert!(leftover.is_empty(), "the refused patch wrote into the ACL graph: {leftover:?}");
}

// The other face of the same defect: a patch whose conditions match
// nothing returns before touching the store, and an existence question
// asked afterwards would turn that `409` into a `404` about a resource
// that is right there.
#[tokio::test]
async fn a_patch_matching_nothing_at_an_acl_is_409_not_404() {
    let f = fixture().await;
    f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;
    let put_acl = f.owner_request("PUT", "/.aux/profile.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(profile_acl(""))).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let res = patch_n3(&f, "/.aux/profile.acl",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:where   { ?a <http://www.w3.org/ns/auth/acl#mode> \
                           <http://www.w3.org/ns/auth/acl#Append> . } ;\n\
           solid:inserts { ?a <http://www.w3.org/ns/auth/acl#mode> \
                           <http://www.w3.org/ns/auth/acl#Write> . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn patching_an_acl_whose_subject_is_absent_is_404() {
    let f = fixture().await;

    let res = patch_n3(&f, "/.aux/never-existed.acl",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <#owner> <http://www.w3.org/ns/auth/acl#mode> \
                           <http://www.w3.org/ns/auth/acl#Control> . } .\n").await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_string(res).await, AUX_SUBJECT_MISSING_MESSAGE,
        "the same answer PUT already gives for the same reason");

    assert!(f.stored("/.aux/never-existed.acl").await.is_none());
}

#[tokio::test]
async fn an_insert_only_patch_creates_the_resource() {
    let f = fixture().await;

    let res = patch_n3(&f, "/fresh",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:nickname \"Charlie\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(
        res.headers()[header::LOCATION].to_str().unwrap(),
        "https://pod.toph.so/fresh"
    );

    let ttl = f.get_turtle("/fresh").await;
    assert!(ttl.contains("Charlie"), "{ttl}");
}

// §7: the same ancestor materialization and containment linking `PUT`
// uses, not a second creation path. Asserted on the parent's containment
// rather than on the child's existence — a creation that skipped the
// ancestor walk still produces a readable child.
#[tokio::test]
async fn creating_by_patch_materializes_ancestors_and_containment() {
    let f = fixture().await;

    let res = patch_n3(&f, "/deep/er/thing",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:nickname \"Charlie\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CREATED);

    let root = f.get_turtle("/").await;
    assert!(root.contains("https://pod.toph.so/deep/"),
        "the root must contain deep/: {root}");
    let deep = f.get_turtle("/deep/").await;
    assert!(deep.contains("https://pod.toph.so/deep/er/"),
        "deep/ must contain er/: {deep}");
    let er = f.get_turtle("/deep/er/").await;
    assert!(er.contains("https://pod.toph.so/deep/er/thing"),
        "er/ must contain thing: {er}");
}

// A container's type triples are the server's, so a container a patch
// creates carries them exactly as one `PUT` creates does — otherwise the
// creation answers `201` for something no client can read as a container.
#[tokio::test]
async fn an_insert_only_patch_creates_a_container_with_its_type() {
    let f = fixture().await;

    let res = patch_n3(&f, "/box/",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:label \"things\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CREATED);

    let ttl = f.get_turtle("/box/").await;
    assert!(ttl.contains("things"), "{ttl}");
    assert!(ttl.contains("ldp#BasicContainer"), "{ttl}");
}

// The two cases cannot overlap: a condition against an empty dataset finds
// zero mappings, which is a 409 and not a creation.
#[tokio::test]
async fn a_patch_with_conditions_on_an_absent_resource_is_409() {
    let f = fixture().await;

    let res = patch_n3(&f, "/fresh",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:where   { ?p ex:email \"old\" . } ;\n\
           solid:inserts { ?p ex:email \"new\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    let get = f.app.clone().oneshot(f.owner_request("GET", "/fresh")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(get.status(), StatusCode::NOT_FOUND,
        "a refused patch must not have created anything");
}

// §7: the empty dataset an absent target is patched against holds no triple
// for a deletion to find, so the answer is the same `409` the identical
// patch gets on an existing target. The `GET` is the assertion that bites:
// a creation branch taken on the strength of the conditions alone answers
// `201` for a patch that asks only to remove something.
#[tokio::test]
async fn a_deletions_only_patch_on_an_absent_resource_is_409() {
    let f = fixture().await;

    let res = patch_n3(&f, "/gone",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:deletes { <> ex:nickname \"Charlie\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert!(body_string(res).await.contains("a triple this patch deletes is not there"),
        "the same body the existing-target path gives for the same patch");

    let get = f.app.clone().oneshot(f.owner_request("GET", "/gone")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(get.status(), StatusCode::NOT_FOUND,
        "a refused patch must not have created anything");
}

// `patch_shape_conflict`: a patch's effect never exists as a `Dataset` in
// this process, so a shape-constrained container refuses the write
// outright rather than attempt to validate it. The inserted triple is
// one `NoteShape` would happily admit — proving the refusal fires on the
// binding alone, not on anything the patch's content would have failed.
#[tokio::test]
async fn a_patch_into_a_shape_constrained_container_is_409() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"first\" .").await;

    let res = patch_n3(&f, "/notes/n1",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:x \"1\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let body = body_string(res).await;
    assert!(body.contains("shape-constrained"), "{body}");
    assert!(body.contains("PUT"), "{body}");

    let ttl = f.get_turtle("/notes/n1").await;
    assert!(!ttl.contains("\"1\""), "a refused patch must not have written: {ttl}");
}

// The converse: an ordinary container with no binding is unaffected by
// the refusal above.
#[tokio::test]
async fn a_patch_into_an_unconstrained_container_still_succeeds() {
    let f = fixture().await;
    f.put_turtle("/notes/n1", "<#me> <http://example.org/email> \"old\" .").await;

    let res = patch_n3(&f, "/notes/n1",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:x \"1\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
}

// An ACL is never validated (§5.3 of the shape-validation design), and
// `patch_shape_conflict` must not lock one either: the subject's
// container binds a shape here, and the patch still lands.
#[tokio::test]
async fn a_patch_to_an_acl_under_a_shape_constrained_container_still_succeeds() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"first\" .").await;
    let acl_body = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
           <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/notes/n1> ; \
           <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
             <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/notes/n1.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl_body)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    let res = patch_n3(&f, "/.aux/notes/n1.acl",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <#owner> <http://www.w3.org/ns/auth/acl#mode> \
                           <http://www.w3.org/ns/auth/acl#Append> . } .\n").await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let ttl = f.get_turtle("/.aux/notes/n1.acl").await;
    assert!(ttl.contains("#Append"), "the patch's triple must be there: {ttl}");
}

// `authorize`'s own comment says it "runs before the body is looked at so
// an unauthorized caller learns nothing" — `patch_shape_conflict` runs
// after the §9 mode check for the same property: a caller who was always
// going to be denied must be denied on that ground, not told first that
// the container happens to be shape-constrained.
#[tokio::test]
async fn a_denied_patch_is_403_not_the_shape_409() {
    let f = fixture().await;
    let bob = "https://bob.example/card#me";
    bind_note_shape(&f).await;
    f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
        <http://schema.org/name> \"first\" .").await;

    let acl = format!(
        "<#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
           <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/notes/n1> ; \
           <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
             <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> . \
         <#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
           <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/notes/n1> ; \
           <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Append> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/notes/n1.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl)).unwrap();
    assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

    // Bob holds only Append on /notes/n1, whose container binds a shape.
    // A deletion needs Write, which he does not have — §9 must deny this
    // before `patch_shape_conflict` ever runs.
    let bob_app = f.app_also_trusting(bob);
    let delete = f.sign(Request::builder().method("PATCH").uri("/notes/n1"), bob, "PATCH", "/notes/n1")
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(patch_body(
            "_:patch a solid:InsertDeletePatch ;\n\
               solid:where   { <> <http://schema.org/name> \"first\" . } ;\n\
               solid:deletes { <> <http://schema.org/name> \"first\" . } .\n")))
        .unwrap();
    assert_eq!(bob_app.oneshot(delete).await.unwrap().status(), StatusCode::FORBIDDEN,
        "the mode denial must win over the shape refusal");
}

// The same ordering argument from the other side: a `PATCH` at a blob is
// refused for being a blob, not for its container's shape — even when
// the container has one.
#[tokio::test]
async fn a_patch_at_a_blob_in_a_shape_constrained_container_is_the_binary_refusal() {
    let f = fixture().await;
    bind_note_shape(&f).await;
    f.put_blob("/notes/pic.png", "image/png", b"\x89PNG").await;

    let res = patch_n3(&f, "/notes/pic.png",
        "_:patch a solid:InsertDeletePatch ;\n\
           solid:inserts { <> ex:x \"1\" . } .\n").await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert_eq!(body_string(res).await, BINARY_TARGET_MESSAGE,
        "the blob refusal must win over the shape one");
}
