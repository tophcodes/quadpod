//! CORS, `Allow`, the `Accept-Put`/`Post`/`Patch` advertisements and `WAC-Allow`.

use super::fixture::*;

#[tokio::test]
async fn no_origin_means_no_cors_headers() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    assert!(res.headers().get(header::ACCESS_CONTROL_EXPOSE_HEADERS).is_none());
}

#[tokio::test]
async fn an_origin_is_reflected_and_vary_keeps_accept() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/")
        .header(header::ORIGIN, "https://app.example")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://app.example"
    );
    // One field line carrying both, not one line each. RFC 9110 §5.3 lets a
    // list-valued field repeat, but a client that reads only the first line
    // then sees half the list — and that is what the conformance harness
    // does. Asserting over `get_all` would pass either way, which is why
    // this asserts the line count first.
    let vary: Vec<&str> = res.headers().get_all(header::VARY)
        .iter().map(|v| v.to_str().unwrap()).collect();
    assert_eq!(vary.len(), 1, "Vary must be one field line: {vary:?}");
    // `Origin` with a capital O: the suite compares the field value as a
    // case-sensitive string.
    assert!(vary[0].contains("Accept"), "{vary:?}");
    assert!(vary[0].contains("Origin"), "{vary:?}");
}

#[tokio::test]
async fn expose_headers_is_enumerated_and_not_a_wildcard() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/")
        .header(header::ORIGIN, "https://app.example")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    let exposed = res.headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS).unwrap().to_str().unwrap();
    assert_ne!(exposed, "*");
    assert!(exposed.contains("ETag"), "{exposed}");
    assert!(exposed.contains("WAC-Allow"), "{exposed}");
}

#[tokio::test]
async fn allow_and_accept_patch_advertise_the_method() {
    let f = fixture().await;
    f.put_turtle("/c/thing", "<#a> <http://example.org/b> \"c\" .").await;

    // Every target shape, because `allowed_methods` has three arms and a
    // fix to one of them is not a fix to the others.
    for path in ["/c/thing", "/c/", "/"] {
        let get = f.app.clone().oneshot(f.owner_request("GET", path)
            .header(header::ACCEPT, "text/turtle")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(get.status(), StatusCode::OK, "GET {path}");
        let allow = get.headers()[header::ALLOW].to_str().unwrap();
        assert!(allow.contains("PATCH"), "GET {path} Allow: {allow}");
        assert_eq!(
            get.headers()["accept-patch"].to_str().unwrap(), "text/n3",
            "GET {path}"
        );

        let opt = f.app.clone().oneshot(Request::builder()
            .method("OPTIONS").uri(path).body(Body::empty()).unwrap()).await.unwrap();
        let allow = opt.headers()[header::ALLOW].to_str().unwrap();
        assert!(allow.contains("PATCH"), "OPTIONS {path} Allow: {allow}");
        let acam = opt.headers()[header::ACCESS_CONTROL_ALLOW_METHODS].to_str().unwrap();
        assert!(acam.contains("PATCH"), "OPTIONS {path} ACAM: {acam}");
        assert_eq!(opt.headers()["accept-patch"].to_str().unwrap(), "text/n3");
    }
}

/// Protocol §5.3: the three `Accept-*` headers are one MUST, and the two
/// new ones are checked on every target shape for the reason the test
/// above gives — `allowed_methods` has three arms.
#[tokio::test]
async fn accept_put_advertises_every_writable_format_and_version() {
    let f = fixture().await;
    f.put_turtle("/c/thing", "<#a> <http://example.org/b> \"c\" .").await;

    for path in ["/c/thing", "/c/", "/"] {
        let get = f.app.clone().oneshot(f.owner_request("GET", path)
            .header(header::ACCEPT, "text/turtle")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(get.status(), StatusCode::OK, "GET {path}");
        let put = get.headers()["accept-put"].to_str().unwrap().to_string();

        let opt = f.app.clone().oneshot(Request::builder()
            .method("OPTIONS").uri(path).body(Body::empty()).unwrap()).await.unwrap();
        let opt_put = opt.headers()["accept-put"].to_str().unwrap().to_string();
        assert_eq!(put, opt_put, "GET and OPTIONS must advertise the same thing at {path}");

        for fmt in Format::ALL {
            let mt = fmt.media_type();
            assert!(put.contains(mt), "{path} Accept-Put lacks {mt}: {put}");
            // Both halves are true: an absent `version` parameter *is*
            // 1.1 (`RdfVersion::from_media_type`), so the bare type and
            // the versioned type are two acceptable representations.
            assert!(
                put.contains(&format!("{mt};version=1.2")),
                "{path} Accept-Put lacks {mt};version=1.2: {put}"
            );
        }
    }
}

/// Each header reaches exactly as far as `Allow` does, and `*/*` appears
/// exactly where `classify_body` admits a blob. A container's own
/// representation must be RDF; an auxiliary's must be too.
#[tokio::test]
async fn the_write_advertisement_is_scoped_to_what_the_target_allows() {
    let f = fixture().await;
    f.put_turtle("/c/thing", "<#a> <http://example.org/b> \"c\" .").await;

    let container = f.app.clone().oneshot(Request::builder()
        .method("OPTIONS").uri("/c/").body(Body::empty()).unwrap()).await.unwrap();
    let post = container.headers()["accept-post"].to_str().unwrap();
    assert!(post.contains("*/*"), "a POSTed child may be a blob: {post}");
    assert!(post.contains("text/turtle"), "{post}");
    let put = container.headers()["accept-put"].to_str().unwrap();
    assert!(!put.contains("*/*"), "a container's own representation must be RDF: {put}");

    let resource = f.app.clone().oneshot(Request::builder()
        .method("OPTIONS").uri("/c/thing").body(Body::empty()).unwrap()).await.unwrap();
    assert!(resource.headers()["accept-put"].to_str().unwrap().contains("*/*"));
    assert!(
        resource.headers().get("accept-post").is_none(),
        "POST is not in a resource's Allow, so it must not be advertised"
    );

    let aux = f.app.clone().oneshot(Request::builder()
        .method("OPTIONS").uri("/.aux/thing.acl").body(Body::empty()).unwrap()).await.unwrap();
    let aux_put = aux.headers()["accept-put"].to_str().unwrap();
    assert!(aux_put.contains("text/turtle"), "{aux_put}");
    assert!(!aux_put.contains("*/*"), "an auxiliary is a policy document, never a blob: {aux_put}");
    assert!(aux.headers().get("accept-post").is_none());
}

#[tokio::test]
async fn accept_patch_is_exposed_to_cross_origin_readers() {
    let f = fixture().await;
    f.put_turtle("/thing", "<#a> <http://example.org/b> \"c\" .").await;

    let res = f.app.clone().oneshot(f.owner_request("GET", "/thing")
        .header(header::ORIGIN, "https://app.example")
        .header(header::ACCEPT, "text/turtle")
        .body(Body::empty()).unwrap()).await.unwrap();
    let exposed = res.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS].to_str().unwrap();
    assert!(exposed.contains("Accept-Patch"), "{exposed}");
}

/// A browser cannot read a response header that is not enumerated here, so
/// an advertisement missing from this list is invisible to exactly the
/// clients that most need to discover what they may write.
#[tokio::test]
async fn the_write_advertisement_is_exposed_to_cross_origin_readers() {
    let f = fixture().await;
    f.put_turtle("/thing", "<#a> <http://example.org/b> \"c\" .").await;

    let res = f.app.clone().oneshot(f.owner_request("GET", "/thing")
        .header(header::ORIGIN, "https://app.example")
        .header(header::ACCEPT, "text/turtle")
        .body(Body::empty()).unwrap()).await.unwrap();
    let exposed = res.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS].to_str().unwrap();
    assert!(exposed.contains("Accept-Put"), "{exposed}");
    assert!(exposed.contains("Accept-Post"), "{exposed}");
}

// The reason the middleware wraps `auth_layer` instead of sitting inside
// it: `protocol/cors/simple-requests` asserts the CORS fields on an
// anonymous request, which this pod answers 401.
#[tokio::test]
async fn cors_headers_survive_a_401() {
    let f = fixture().await;
    let get = Request::builder().method("GET").uri("/")
        .header(header::ORIGIN, "https://app.example")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://app.example"
    );
    assert!(res.headers().get(header::ACCESS_CONTROL_EXPOSE_HEADERS).is_some());
}

// A preflight carries no credentials by construction — the browser sends
// it before, and without, the credentialed request.
#[tokio::test]
async fn options_answers_without_credentials() {
    let f = fixture().await;
    let req = Request::builder().method("OPTIONS").uri("/")
        .header(header::ORIGIN, "https://app.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(body_string(res).await, "");
}

#[tokio::test]
async fn options_mirrors_exactly_the_requested_headers() {
    let f = fixture().await;
    let req = Request::builder().method("OPTIONS").uri("/")
        .header(header::ORIGIN, "https://app.example")
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "X-CUSTOM, Content-Type")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(req).await.unwrap();
    let allowed = res.headers()
        .get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap().to_str().unwrap();
    assert!(allowed.contains("X-CUSTOM"), "{allowed}");
    assert!(allowed.contains("Content-Type"), "{allowed}");
    // The negative half: `accept-acah` asserts Accept is ABSENT when it was
    // not requested, in an otherwise identical request. A fixed list fails
    // one of the two.
    assert!(!allowed.contains("Accept"), "{allowed}");
}

#[tokio::test]
async fn options_omits_allow_headers_when_none_were_requested() {
    let f = fixture().await;
    let req = Request::builder().method("OPTIONS").uri("/")
        .header(header::ORIGIN, "https://app.example")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(res.headers().get(header::ACCESS_CONTROL_ALLOW_HEADERS).is_none());
}

#[tokio::test]
async fn options_advertises_the_methods_the_target_accepts() {
    let f = fixture().await;

    let on_container = Request::builder().method("OPTIONS").uri("/box/")
        .body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(on_container).await.unwrap();
    let allow = res.headers().get(header::ALLOW).unwrap().to_str().unwrap().to_string();
    let acam = res.headers()
        .get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap().to_str().unwrap();
    assert!(allow.contains("POST"), "{allow}");
    assert!(allow.contains("OPTIONS"), "{allow}");
    assert_eq!(allow, acam, "Allow and Access-Control-Allow-Methods must agree");

    let on_resource = Request::builder().method("OPTIONS").uri("/foo")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(on_resource).await.unwrap();
    let allow = res.headers().get(header::ALLOW).unwrap().to_str().unwrap();
    assert!(!allow.contains("POST"), "{allow}");
    assert!(allow.contains("OPTIONS"), "{allow}");
}

// `classify` still decides what a path means: the reserved namespace is not
// storage, and OPTIONS does not get to pretend otherwise.
#[tokio::test]
async fn options_on_the_unallocated_reserved_namespace_is_404() {
    let f = fixture().await;
    let req = Request::builder().method("OPTIONS").uri("/.aux/bogus/x")
        .body(Body::empty()).unwrap();
    let res = f.app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

// The root ACL grants the owner Read/Write/Control and nobody else
// anything, so this pins three things at once: both groups are always
// present, an empty group is `""` rather than omitted, and `write` reports
// `append` alongside it.
#[tokio::test]
async fn wac_allow_reports_both_groups_and_appends_with_write() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("wac-allow").unwrap().to_str().unwrap(),
        "user=\"read write append control\",public=\"\""
    );
}

// A resource's own ACL replaces inheritance entirely, which is why the
// owner's group here is the narrower set this document grants and not the
// root ACL's.
#[tokio::test]
async fn wac_allow_reports_public_read_when_the_acl_grants_it() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/foo")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    let acl = format!(
        "<#public> <http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent> ; \
                   <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/foo> ; \
                   <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> . \
         <#owner> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                  <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/foo> ; \
                  <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
                                                       <http://www.w3.org/ns/auth/acl#Control> ."
    );
    let put_acl = f.owner_request("PUT", "/.aux/foo.acl")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(acl)).unwrap();
    let status = f.app.clone().oneshot(put_acl).await.unwrap().status();
    assert!(status.is_success(), "writing the ACL returned {status}");

    let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("wac-allow").unwrap().to_str().unwrap(),
        "user=\"read control\",public=\"read\""
    );
}

// Solid Protocol §4.1: a successful GET/HEAD MUST advertise the methods
// its target supports.
#[tokio::test]
async fn reads_advertise_the_methods_the_target_supports() {
    let f = fixture().await;
    let put = f.owner_request("PUT", "/box/doc")
        .header(header::CONTENT_TYPE, "text/turtle").body(Body::from("")).unwrap();
    assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

    for (method, path, expected) in [
        ("GET", "/box/", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"),
        ("HEAD", "/box/", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"),
        ("GET", "/box/doc", "GET, HEAD, PUT, PATCH, DELETE, OPTIONS"),
        ("HEAD", "/box/doc", "GET, HEAD, PUT, PATCH, DELETE, OPTIONS"),
    ] {
        let req = f.owner_request(method, path).body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{method} {path}");
        assert_eq!(res.headers().get(header::ALLOW).unwrap(), expected, "{method} {path}");
    }
}

// The root is the one container DELETE refuses, and `Allow` has to say so
// rather than repeat a generic list.
#[tokio::test]
async fn the_root_does_not_advertise_delete() {
    let f = fixture().await;
    let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
    let res = f.app.oneshot(get).await.unwrap();
    assert_eq!(res.headers().get(header::ALLOW).unwrap(), "GET, HEAD, POST, PUT, PATCH, OPTIONS");
}
