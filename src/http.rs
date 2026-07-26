use std::sync::Arc;
use axum::{Router, routing::get, extract::{State, Path}, body::Bytes, Extension,
    http::{StatusCode, HeaderMap, header, header::{IF_MATCH, IF_NONE_MATCH}}, response::{IntoResponse, Response}};
use crate::{space::StorageSpace, store::SparqlStore, container, resource::{put_rdf, get_rdf, delete_rdf, ResourceError},
    rdf::{format_for_content_type, format_for_accept, parse, serialize, etag}, auth::{Agent, AuthConfig, JwksResolver, WebIdIssuerVerifier, auth_layer},
    wac::{guard::authorize, prp, Mode}};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn SparqlStore>,
    pub space: StorageSpace,
    pub resolver: Arc<dyn JwksResolver>,
    pub webid_verifier: Arc<dyn WebIdIssuerVerifier>,
    pub auth_config: Arc<AuthConfig>,
}

pub fn router(state: AppState) -> Router {
    // axum 0.8 wildcard capture syntax: "/{*path}" (NOT the old "/*path").
    Router::new()
        .route("/", get(handle_get_root).put(handle_put_root).post(handle_post_root).delete(handle_delete_root))
        .route("/{*path}", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_layer))
        .with_state(state)
}

/// The `Link: <…>; rel="acl"` header a Solid client uses to discover where a
/// resource's ACL lives. `None` for ACL resources themselves — an ACL is
/// governed by `acl:Control` on its subject, not by an ACL of its own.
fn acl_link(space: &StorageSpace, request_path: &str) -> Option<(header::HeaderName, String)> {
    if prp::is_acl_path(request_path) {
        return None;
    }
    let iri = space.graph_iri(&prp::acl_path(request_path)).ok()?;
    Some((header::LINK, format!("<{iri}>; rel=\"acl\"")))
}

fn put_status(e: &ResourceError) -> StatusCode {
    match e {
        ResourceError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

async fn handle_put(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap, body: Bytes,
) -> Response {
    put_impl(st, agent, format!("/{path}"), headers, body).await
}

async fn handle_put_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>, headers: HeaderMap, body: Bytes,
) -> Response {
    put_impl(st, agent, "/".to_string(), headers, body).await
}

async fn put_impl(st: AppState, agent: Agent, req_path: String, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &req_path, Mode::Write).await {
        return res;
    }
    // Creating a resource changes its parent container's containment triples,
    // so it additionally needs Append there. Existence is only consulted
    // AFTER Write on the target was granted, so it can never become an
    // existence oracle for an unauthorized caller. ACLs are not container
    // members (see wac::prp), so they skip this check.
    if !prp::is_acl_path(&req_path) {
        let exists = matches!(get_rdf(st.store.as_ref(), &st.space, &req_path).await, Ok(Some(_)));
        if !exists {
            if let Some(parent) = container::parent_container(&req_path) {
                if let Err(res) =
                    authorize(st.store.as_ref(), &st.space, &agent, &parent, Mode::Append).await
                {
                    return res;
                }
            }
        }
    }
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_content_type(ct) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let g = match st.space.graph_iri(&req_path) {
        Ok(g) => g,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if headers.contains_key(IF_MATCH) || headers.contains_key(IF_NONE_MATCH) {
        let current_tag = match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
            Ok(Some(tr)) => Some(etag(&tr)),
            Ok(None) => None,
            Err(e) => return (put_status(&e), e.to_string()).into_response(),
        };
        if let Some(im) = headers.get(IF_MATCH).and_then(|v| v.to_str().ok()) {
            if Some(im) != current_tag.as_deref() {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
        }
        if headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some("*")
            && current_tag.is_some()
        {
            return StatusCode::PRECONDITION_FAILED.into_response();
        }
    }
    let triples = match parse(&body, fmt, &g) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if container::is_container_path(&req_path) {
        if container::body_sets_containment(&triples) {
            return StatusCode::CONFLICT.into_response();
        }
        if let Err(e) = container::ensure_ancestors(st.store.as_ref(), &st.space, &req_path).await {
            return (put_status(&e), e.to_string()).into_response();
        }
        // preserve existing containment, re-assert type, add user triples (minus any type/contains the server owns)
        // Note: this read-then-write (get_rdf here, then DROP+INSERT in put_rdf) is not
        // transactional across the two graph operations; a concurrent child add landing
        // between the read and the write could be lost. Accepted for single-user v1
        // per the plan's cross-graph-atomicity note.
        let existing = match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
            Ok(v) => v.unwrap_or_default(),
            Err(e) => return (put_status(&e), e.to_string()).into_response(),
        };
        let kept_containment: Vec<_> = existing.into_iter()
            .filter(|t| t.predicate.as_str() == container::LDP_CONTAINS)
            .collect();
        let mut merged = triples;
        merged.extend(kept_containment);
        if let Err(e) = put_rdf(st.store.as_ref(), &st.space, &req_path, &merged).await {
            return (put_status(&e), e.to_string()).into_response();
        }
        if let Err(e) = container::ensure_container(st.store.as_ref(), &st.space, &req_path).await {
            return (put_status(&e), e.to_string()).into_response();
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::LOCATION, g.parse().expect("graph iri is header-safe"));
        if let Some((name, value)) = acl_link(&st.space, &req_path) {
            headers.insert(name, value.parse().expect("acl link is header-safe"));
        }
        return (StatusCode::CREATED, headers).into_response();
    }
    // Note: ensure_ancestors and subsequent put_rdf are separate store updates and not transactional.
    // Accepted for single-user v1 per the plan's cross-graph-atomicity note.
    if let Err(e) = container::ensure_ancestors(st.store.as_ref(), &st.space, &req_path).await {
        return (put_status(&e), e.to_string()).into_response();
    }
    match put_rdf(st.store.as_ref(), &st.space, &req_path, &triples).await {
        Ok(()) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::LOCATION, g.parse().expect("graph iri is header-safe"));
            if let Some((name, value)) = acl_link(&st.space, &req_path) {
                headers.insert(name, value.parse().expect("acl link is header-safe"));
            }
            (StatusCode::CREATED, headers).into_response()
        }
        Err(e) => (put_status(&e), e.to_string()).into_response(),
    }
}

async fn handle_post(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap, body: Bytes,
) -> Response {
    post_impl(st, agent, format!("/{path}"), headers, body).await
}

async fn handle_post_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>, headers: HeaderMap, body: Bytes,
) -> Response {
    post_impl(st, agent, "/".to_string(), headers, body).await
}

async fn post_impl(st: AppState, agent: Agent, container_path: String, headers: HeaderMap, body: Bytes) -> Response {
    // Authorize the target path FIRST, even though Append on a non-container
    // is a meaningless grant in practice: the 409 below is derived from the
    // request path alone, but no handler branch may answer before
    // `authorize` runs, so an unauthorized caller never learns even that
    // much about the path they probed.
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &container_path, Mode::Append).await {
        return res;
    }
    if !container::is_container_path(&container_path) {
        return StatusCode::CONFLICT.into_response(); // POST target must be a container
    }
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_content_type(ct) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let slug = headers.get("slug").and_then(|v| v.to_str().ok());
    // unique child path
    let mut name = container::child_name(slug);
    let mut child_path = format!("{container_path}{name}");
    // Note: this existence check (get_rdf) followed by write (put_rdf below) is not transactional;
    // a concurrent write landing between these operations could be missed. Accepted for single-user v1.
    if matches!(get_rdf(st.store.as_ref(), &st.space, &child_path).await, Ok(Some(_))) {
        name = format!("{name}-{}", uuid::Uuid::new_v4());
        child_path = format!("{container_path}{name}");
    }
    // The container's Append is not enough to authorize the CHILD: a `Slug`
    // of `.acl` would otherwise let an append-only agent write the
    // container's own access-control document and escalate to Control.
    // Routing the settled child path through `authorize` also picks up the
    // guard's `.acl` -> Control rewrite, so this cannot be forgotten again.
    // Mode::Append (not Write) here: for an ordinary (non-.acl) child this
    // must stay consistent with the container-level check above, or the
    // append-only inbox pattern this design targets would break — every
    // legitimate append-only POST would suddenly need Write on the child it
    // creates. For a `.acl` child the guard ignores this argument entirely
    // and substitutes Control, so the escalation is still blocked.
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &child_path, Mode::Append).await {
        return res;
    }
    let g = match st.space.graph_iri(&child_path) {
        Ok(g) => g,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let triples = match parse(&body, fmt, &g) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if let Err(e) = container::ensure_ancestors(st.store.as_ref(), &st.space, &child_path).await {
        return (put_status(&e), e.to_string()).into_response();
    }
    match put_rdf(st.store.as_ref(), &st.space, &child_path, &triples).await {
        Ok(()) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::LOCATION, g.parse().expect("graph iri is header-safe"));
            if let Some((name, value)) = acl_link(&st.space, &child_path) {
                headers.insert(name, value.parse().expect("acl link is header-safe"));
            }
            (StatusCode::CREATED, headers).into_response()
        }
        Err(e) => (put_status(&e), e.to_string()).into_response(),
    }
}

async fn handle_get(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap,
) -> Response {
    get_impl(st, agent, format!("/{path}"), headers).await
}

async fn handle_get_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>, headers: HeaderMap,
) -> Response {
    get_impl(st, agent, "/".to_string(), headers).await
}

async fn get_impl(st: AppState, agent: Agent, req_path: String, headers: HeaderMap) -> Response {
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &req_path, Mode::Read).await {
        return res;
    }
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_accept(accept) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(Some(triples)) => {
            let tag = etag(&triples);
            if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
                return (StatusCode::NOT_MODIFIED, [(header::ETAG, tag)]).into_response();
            }
            match serialize(&triples, fmt) {
                Ok(bytes) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, fmt.media_type().parse().expect("static media type"));
                    headers.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
                    if let Some((name, value)) = acl_link(&st.space, &req_path) {
                        headers.insert(name, value.parse().expect("acl link is header-safe"));
                    }
                    (headers, bytes).into_response()
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(ResourceError::InvalidIri) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn handle_delete(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
) -> Response {
    delete_impl(st, agent, format!("/{path}")).await
}

async fn handle_delete_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>,
) -> Response {
    delete_impl(st, agent, "/".to_string()).await
}

async fn delete_impl(st: AppState, agent: Agent, req_path: String) -> Response {
    if let Err(res) = authorize(st.store.as_ref(), &st.space, &agent, &req_path, Mode::Write).await {
        return res;
    }
    if !prp::is_acl_path(&req_path) {
        if let Some(parent) = container::parent_container(&req_path) {
            if let Err(res) =
                authorize(st.store.as_ref(), &st.space, &agent, &parent, Mode::Write).await
            {
                return res;
            }
        }
    }
    if container::is_container_path(&req_path) {
        if req_path == "/" {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        match container::container_is_empty(st.store.as_ref(), &st.space, &req_path).await {
            Ok(false) => return StatusCode::CONFLICT.into_response(),
            Ok(true) => {}
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
        // is the container present at all? (root always is)
        let present = matches!(get_rdf(st.store.as_ref(), &st.space, &req_path).await, Ok(Some(_)));
        if !present {
            return StatusCode::NOT_FOUND.into_response();
        }
        if let Err(e) = delete_rdf(st.store.as_ref(), &st.space, &req_path).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        if let Some(parent) = container::parent_container(&req_path) {
            if let Err(e) = container::remove_containment(st.store.as_ref(), &st.space, &parent, &req_path).await {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        }
        // The ACL is not a container member (wac::prp), so nothing else would
        // ever reclaim it — and a resurrected resource must not inherit the
        // authorizations of the one that was deleted.
        if !prp::is_acl_path(&req_path) {
            if let Err(e) = delete_rdf(st.store.as_ref(), &st.space, &prp::acl_path(&req_path)).await {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        }
        return StatusCode::NO_CONTENT.into_response();
    }
    match delete_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(true) => {
            if let Some(parent) = container::parent_container(&req_path) {
                if let Err(e) = container::remove_containment(st.store.as_ref(), &st.space, &parent, &req_path).await {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            }
            // The ACL is not a container member (wac::prp), so nothing else
            // would ever reclaim it — and a resurrected resource must not
            // inherit the authorizations of the one that was deleted.
            if !prp::is_acl_path(&req_path) {
                if let Err(e) = delete_rdf(st.store.as_ref(), &st.space, &prp::acl_path(&req_path)).await {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(ResourceError::InvalidIri) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use crate::{space::StorageSpace, store::OxigraphStore, auth::StaticJwksResolver};
    use crate::auth::testsupport::{TestClient, TestIdp};
    use crate::auth::StaticWebIdIssuers;

    const OWNER: &str = "https://alice.example/card#me";
    const ISSUER: &str = "https://idp.example/";

    /// An app whose root ACL grants OWNER full control, plus the IdP and
    /// client needed to mint credentials for them. The store and space are
    /// kept so a second app can be built over the SAME data (see
    /// [`Fixture::app_also_trusting`]) and so tests can inspect the store
    /// directly.
    struct Fixture {
        app: axum::Router,
        store: Arc<dyn crate::store::SparqlStore>,
        space: StorageSpace,
        idp: TestIdp,
        client: TestClient,
        /// Held for the test's whole lifetime: these tests authenticate
        /// through `auth_layer`, which records DPoP `jti`s into the
        /// process-wide replay store using the REAL wall clock. That would
        /// otherwise evict the still-fresh entries of `auth::dpop`'s
        /// concurrently-running replay tests, which simulate `now_unix`
        /// near the epoch (see `auth::dpop::test_replay_lock`).
        _replay_guard: tokio::sync::MutexGuard<'static, ()>,
    }

    async fn fixture() -> Fixture {
        let _replay_guard = crate::auth::dpop::test_replay_lock().lock().await;
        let store: Arc<dyn crate::store::SparqlStore> =
            Arc::new(OxigraphStore::in_memory().unwrap());
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        crate::container::provision_root(store.as_ref(), &space).await.unwrap();
        crate::wac::provision::provision_root_acl(store.as_ref(), &space, OWNER).await.unwrap();

        let idp = TestIdp::new();
        let client = TestClient::new();
        let mut issuers = StaticWebIdIssuers::new();
        issuers.allow(OWNER, ISSUER);

        let state = AppState {
            store: store.clone(),
            space: space.clone(),
            resolver: Arc::new(StaticJwksResolver::new(ISSUER, idp.jwks())),
            webid_verifier: Arc::new(issuers),
            auth_config: Arc::new(crate::auth::AuthConfig::default()),
        };
        Fixture { app: router(state), store, space, idp, client, _replay_guard }
    }

    fn now_unix() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    impl Fixture {
        /// Add credentials for `webid` to a request builder. The DPoP proof's
        /// `htu` must be the CONFIGURED base plus the path (never the socket),
        /// and its `jti` must be unique — the replay store rejects reuse.
        fn sign(
            &self,
            builder: axum::http::request::Builder,
            webid: &str,
            method: &str,
            path: &str,
        ) -> axum::http::request::Builder {
            let at = self.idp.mint_access_token(webid, &self.client.jkt(), now_unix() + 3600);
            let htu = format!("https://pod.toph.so{path}");
            let jti = uuid::Uuid::new_v4().to_string();
            let proof = self.client.mint_dpop(&htu, method, now_unix(), &jti);
            builder
                .header(header::AUTHORIZATION, format!("DPoP {at}"))
                .header("dpop", proof)
        }

        /// A request authenticated as the pod owner.
        fn owner_request(&self, method: &str, path: &str) -> axum::http::request::Builder {
            let b = Request::builder().method(method).uri(path);
            self.sign(b, OWNER, method, path)
        }

        /// A second app over the same store, authenticating `webid` as well.
        fn app_also_trusting(&self, webid: &str) -> axum::Router {
            let mut issuers = StaticWebIdIssuers::new();
            issuers.allow(OWNER, ISSUER);
            issuers.allow(webid, ISSUER);
            router(AppState {
                store: self.store.clone(),
                space: self.space.clone(),
                resolver: Arc::new(StaticJwksResolver::new(ISSUER, self.idp.jwks())),
                webid_verifier: Arc::new(issuers),
                auth_config: Arc::new(crate::auth::AuthConfig::default()),
            })
        }
    }

    async fn body_string(res: axum::response::Response) -> String {
        let b = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        String::from_utf8_lossy(&b).into_owned()
    }

    #[tokio::test]
    async fn put_turtle_then_get_jsonld_negotiates() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        let put_res = f.app.clone().oneshot(put).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::CREATED);
        assert_eq!(put_res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/foo");

        let get = f.owner_request("GET", "/foo")
            .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/ld+json");
        assert!(body_string(res).await.contains("schema.org/name"));
    }

    #[tokio::test]
    async fn get_default_accept_is_turtle() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();
        let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle");
    }

    #[tokio::test]
    async fn get_unsupported_accept_is_406() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();
        let get = f.owner_request("GET", "/foo")
            .header(header::ACCEPT, "image/png").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn put_unsupported_content_type_is_415() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "application/json").body(Body::from("{}")).unwrap();
        let res = f.app.oneshot(put).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn get_missing_is_404() {
        let f = fixture().await;
        let get = f.owner_request("GET", "/nope").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
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

    #[tokio::test]
    async fn get_emits_etag_and_304_on_if_none_match() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();

        let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

        let cond = f.owner_request("GET", "/foo")
            .header(header::IF_NONE_MATCH, &etag).body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(cond).await.unwrap().status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn put_if_match_mismatch_is_412() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();

        let stale = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, "\"deadbeef\"")
            .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
        assert_eq!(f.app.oneshot(stale).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn put_if_none_match_star_on_existing_is_412() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();

        let create_only = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_NONE_MATCH, "*")
            .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
        assert_eq!(f.app.oneshot(create_only).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn put_if_match_matching_succeeds() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();
        // read current etag
        let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
        // conditional update with matching If-Match must succeed
        let upd = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, &etag)
            .body(Body::from("<#it> <http://schema.org/name> \"New\" .")).unwrap();
        assert_eq!(f.app.oneshot(upd).await.unwrap().status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn put_if_none_match_star_on_absent_creates() {
        let f = fixture().await;
        let req = f.owner_request("PUT", "/brand-new")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_NONE_MATCH, "*")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn delete_existing_is_204_then_404() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();
        let del = f.owner_request("DELETE", "/foo").body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
        let del2 = f.owner_request("DELETE", "/foo").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(del2).await.unwrap().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_deep_resource_creates_ancestor_containment() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/a/b/doc")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        // GET the parent container /a/b/ — it must list the doc via ldp:contains
        let get = f.owner_request("GET", "/a/b/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_string(res).await;
        assert!(body.contains("ldp#contains"));
        assert!(body.contains("https://pod.toph.so/a/b/doc"));
    }

    #[tokio::test]
    async fn delete_resource_removes_containment() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/a/doc")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();
        let del = f.owner_request("DELETE", "/a/doc").body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);

        let get = f.owner_request("GET", "/a/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert!(!body_string(res).await.contains("https://pod.toph.so/a/doc"));
    }

    #[tokio::test]
    async fn get_root_container_is_200() {
        let f = fixture().await;
        let get = f.owner_request("GET", "/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body_string(res).await.contains("ldp#BasicContainer"));
    }

    #[tokio::test]
    async fn put_container_rejecting_client_containment_is_409() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(
                "<https://pod.toph.so/box/> <http://www.w3.org/ns/ldp#contains> <https://pod.toph.so/box/x> .",
            )).unwrap();
        assert_eq!(f.app.oneshot(put).await.unwrap().status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn put_container_stores_user_triples_and_keeps_type() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<https://pod.toph.so/box/> <http://purl.org/dc/terms/title> \"My Box\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
        let get = f.owner_request("GET", "/box/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        let body = body_string(res).await;
        assert!(body.contains("My Box"));                 // user triple kept
        assert!(body.contains("ldp#BasicContainer"));     // server type re-asserted
    }

    #[tokio::test]
    async fn delete_nonempty_container_is_409_empty_is_204() {
        let f = fixture().await;
        // create a child → parent /box/ becomes non-empty
        let put = f.owner_request("PUT", "/box/doc")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        f.app.clone().oneshot(put).await.unwrap();
        let del_full = f.owner_request("DELETE", "/box/").body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(del_full).await.unwrap().status(), StatusCode::CONFLICT);
        // remove child, then container is deletable
        let del_child = f.owner_request("DELETE", "/box/doc").body(Body::empty()).unwrap();
        f.app.clone().oneshot(del_child).await.unwrap();
        let del_empty = f.owner_request("DELETE", "/box/").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(del_empty).await.unwrap().status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_root_container_is_405() {
        let f = fixture().await;
        let del = f.owner_request("DELETE", "/").body(Body::empty()).unwrap();
        let res = f.app.oneshot(del).await.unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn post_with_slug_creates_named_child() {
        let f = fixture().await;
        let post = f.owner_request("POST", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", "note")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        let res = f.app.clone().oneshot(post).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/box/note");
        // the child is retrievable and the container lists it
        let get = f.owner_request("GET", "/box/note").body(Body::empty()).unwrap();
        let got = f.app.oneshot(get).await.unwrap();
        assert_eq!(got.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_slug_collision_gets_distinct_url() {
        let f = fixture().await;
        let mk = || f.owner_request("POST", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle").header("slug", "note")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        let loc1 = f.app.clone().oneshot(mk()).await.unwrap().headers().get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
        let loc2 = f.app.clone().oneshot(mk()).await.unwrap().headers().get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
        assert_ne!(loc1, loc2);
    }

    #[tokio::test]
    async fn post_to_non_container_is_conflict() {
        let f = fixture().await;
        // /doc is a resource path (no trailing slash) → POST not allowed there
        let post = f.owner_request("POST", "/doc")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.oneshot(post).await.unwrap().status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn put_container_preserves_existing_containment() {
        let f = fixture().await;
        // create a child so /box/ is non-empty
        let child = f.owner_request("PUT", "/box/doc")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        f.app.clone().oneshot(child).await.unwrap();
        // PUT the container itself with only user triples (no ldp:contains)
        let put = f.owner_request("PUT", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<https://pod.toph.so/box/> <http://purl.org/dc/terms/title> \"Box\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
        // the child's containment link must survive
        let get = f.owner_request("GET", "/box/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        let body = body_string(res).await;
        assert!(body.contains("https://pod.toph.so/box/doc"));  // containment preserved
        assert!(body.contains("Box"));                           // user triple stored
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
        let put_acl = f.owner_request("PUT", "/shared.acl")
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
        let read_acl = f.sign(Request::builder().method("GET").uri("/shared.acl"), bob, "GET", "/shared.acl")
            .body(Body::empty()).unwrap();
        assert_eq!(bob_app.oneshot(read_acl).await.unwrap().status(), StatusCode::FORBIDDEN);
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
        let put_acl = f.owner_request("PUT", "/gone.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl_body)).unwrap();
        f.app.clone().oneshot(put_acl).await.unwrap();

        let del = f.owner_request("DELETE", "/gone").body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);

        // The ACL graph must be gone from the store, not merely unreachable.
        assert!(
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/gone.acl").await.unwrap().is_none(),
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
        let put_acl = f.owner_request("PUT", "/item.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(format!(
                "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/item> ; \
                 <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
            ))).unwrap();
        f.app.clone().oneshot(put_acl).await.unwrap();

        let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
        let listing = body_string(f.app.oneshot(get).await.unwrap()).await;
        assert!(listing.contains("https://pod.toph.so/item"));
        assert!(!listing.contains("item.acl"));
    }

    // An agent with Append on a container must not be able to write that
    // container's ACL by naming the child `.acl` — that would escalate
    // append-only access to Control over the whole subtree.
    #[tokio::test]
    async fn append_only_agent_cannot_post_a_container_acl() {
        let f = fixture().await;
        let bob = "https://bob.example/card#me";
        // owner creates /inbox/, which starts with NO direct ACL of its own
        // — it inherits from the root ACL. That inheritance matters: if
        // Bob's grant lived directly at /inbox/.acl, that path would already
        // exist and the Slug: .acl attack below would be deflected onto a
        // uuid-suffixed name by the ordinary collision-avoidance branch,
        // proving nothing. Granting Bob Append through the root ACL (via
        // acl:default) keeps /inbox/.acl genuinely absent beforehand, so the
        // hijack really does create — and thereby replace — the ACL that
        // (until that moment) was inherited from the root.
        let mk = f.owner_request("PUT", "/inbox/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("")).unwrap();
        assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);
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
        let put_root_acl = f.owner_request("PUT", "/.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(root_acl_body)).unwrap();
        assert_eq!(f.app.clone().oneshot(put_root_acl).await.unwrap().status(), StatusCode::CREATED);

        let bob_app = f.app_also_trusting(bob);

        // Sanity check: Bob genuinely has (inherited) Append on the
        // container — an innocuous POST must succeed. Otherwise a FORBIDDEN
        // below would prove nothing about the escalation this test targets.
        let sanity = f.sign(Request::builder().method("POST").uri("/inbox/"), bob, "POST", "/inbox/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", "note")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(bob_app.clone().oneshot(sanity).await.unwrap().status(), StatusCode::CREATED);

        // The attack: POST with Slug: .acl makes child_path == /inbox/.acl,
        // exactly the ACL that governs /inbox/ itself. If unauthorized, Bob
        // would gain Control over the container (and, via acl:default, its
        // whole subtree) using only his Append grant.
        let hijack = f.sign(Request::builder().method("POST").uri("/inbox/"), bob, "POST", "/inbox/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", ".acl")
            .body(Body::from(format!(
                "<#pwn> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/inbox/> ; \
                 <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
            ))).unwrap();
        assert_eq!(bob_app.oneshot(hijack).await.unwrap().status(), StatusCode::FORBIDDEN);
    }

    // Every other test in this file authenticates as OWNER, who holds every
    // mode through the root ACL — so a test suite built only from those
    // could never notice if put_impl's parent-Append check were deleted.
    // Bob here holds Write on the (not yet existing) target resource
    // directly, but nothing at all on its parent container, so creation
    // must still be refused.
    #[tokio::test]
    async fn creating_a_resource_needs_append_on_the_parent_not_just_write_on_the_target() {
        let f = fixture().await;
        let bob = "https://bob.example/card#me";
        // Grant Bob Write on /newfile before it exists — an ACL resource is
        // independent of whether its subject resource has been created yet.
        let acl_body = format!(
            "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/newfile> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> ."
        );
        let put_acl = f.owner_request("PUT", "/newfile.acl")
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
        let put_acl = f.owner_request("PUT", "/target.acl")
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
        let put_acl = f.owner_request("PUT", "/mailroom/.acl")
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
        assert!(link.contains("https://pod.toph.so/foo.acl"));
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
            .contains("https://pod.toph.so/foo.acl"));
    }

    // An ACL resource does not advertise an ACL of its own — it is governed
    // by acl:Control on its subject resource, and /foo.acl.acl never exists.
    #[tokio::test]
    async fn acl_resource_advertises_no_further_acl() {
        let f = fixture().await;
        let acl_body = format!(
            "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/foo> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
        );
        let put_acl = f.owner_request("PUT", "/foo.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl_body)).unwrap();
        f.app.clone().oneshot(put_acl).await.unwrap();

        let get = f.owner_request("GET", "/foo.acl").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().get(header::LINK).is_none());
    }
}
