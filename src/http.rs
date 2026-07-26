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

/// Authorize `Append` on every ancestor container that creating `req_path`
/// would observably change.
///
/// Creating a resource does not touch only its immediate parent:
/// `container::ensure_ancestors` materializes every missing container above
/// it, and each one it creates — plus the first ancestor that already exists,
/// which gains a containment triple — is a real mutation of a resource the
/// caller may hold nothing on. So the walk authorizes each of those, and
/// stops after the first existing one (inclusive), exactly where
/// `ensure_ancestors` stops writing. Going further would demand rights the
/// request never exercises and would break the append-only inbox pattern:
/// an agent with `Append` on `/inbox/` alone would be refused because the
/// walk also reached `/`. When the parent already exists — the common case —
/// this is a single check, i.e. the original behaviour.
///
/// Existence is only ever consulted AFTER `Append` on that same container was
/// granted, so it can never become an existence oracle.
///
/// One exception, checked up front: the immediate parent already exists AND
/// nothing would be added to it. Two ways that happens, and they are the same
/// rule seen from two sides — the parent gains a containment triple it does
/// not already have:
///
///   * the target is an ACL. `add_containment` never records an ACL as a
///     container member, so no containment triple is ever produced for it.
///   * the target already exists. Its containment triple is already in the
///     parent, so re-inserting it is a no-op.
///
/// In both cases `ensure_container` is the only other write, and it is a
/// no-op on a container that already carries its `ldp:Container` /
/// `ldp:BasicContainer` type triples. That invariant is load-bearing: it
/// holds by construction because every route that materializes a container
/// (`container::ensure_ancestors`, `provision_root`, and `put_impl`'s
/// container branch) calls `ensure_container`. It is not, however,
/// transactionally guaranteed — `put_impl` runs `put_rdf` and then
/// `ensure_container` as two separate store updates, so a store error landing
/// between them would leave a typeless container graph, and for that graph
/// this exemption would be skipping a real (if cosmetic) write. If that ever
/// stops being merely theoretical, this exemption is where it bites.
///
/// The two halves must be checked TOGETHER. Splitting them — exempting ACLs
/// here and existing targets at the call site — is what let a revoked
/// `Control`-only delegate force a write into the root container: an ACL is
/// not a containment member, so a container can be deleted while an `.acl`
/// below it survives, and a PUT to that orphan then ran `ensure_ancestors`
/// with no ancestor authorization at all.
///
/// Existence is peeked before any `authorize` call only in this exemption;
/// that is safe because both callers have already authorized the target
/// itself (`put_impl` requires `Write`, rewritten to `Control` on the
/// subject for an `.acl` path; `post_impl` requires `Append` on the container
/// and then on the settled `child_path`, which picks up the same `.acl` ->
/// `Control` rewrite). So it is not a fresh oracle for an agent who holds
/// nothing here. When the parent does NOT exist, this falls through to the
/// ordinary walk below, which authorizes and materializes it exactly as for
/// any other path.
async fn authorize_ancestors(
    st: &AppState, agent: &Agent, req_path: &str,
) -> Result<(), Response> {
    if let Some(parent) = container::parent_container(req_path) {
        let parent_exists =
            matches!(get_rdf(st.store.as_ref(), &st.space, &parent).await, Ok(Some(_)));
        let target_exists =
            matches!(get_rdf(st.store.as_ref(), &st.space, req_path).await, Ok(Some(_)));
        if parent_exists && (prp::is_acl_path(req_path) || target_exists) {
            return Ok(());
        }
    }
    let mut child = req_path.to_string();
    while let Some(parent) = container::parent_container(&child) {
        authorize(st.store.as_ref(), &st.space, agent, &parent, Mode::Append).await?;
        if matches!(get_rdf(st.store.as_ref(), &st.space, &parent).await, Ok(Some(_))) {
            return Ok(());
        }
        child = parent;
    }
    Ok(())
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
    // Creating a resource changes its parent container's containment triples
    // — and, when the parent is missing too, every ancestor up to the first
    // one that already exists — so it additionally needs Append on each of
    // those (see `authorize_ancestors`). Existence is only consulted AFTER
    // Write (or, for an ACL path, Control on its subject) on the target was
    // granted, so it can never become an existence oracle for an unauthorized
    // caller. This runs for ACL paths too: an ACL is not itself a container
    // member (see `wac::prp` / `container::add_containment`), but
    // `container::ensure_ancestors` still materializes the SAME missing
    // ancestor containers for `PUT /a/b/c.acl` as it would for
    // `PUT /a/b/c` — Control on `c` says nothing about `a` or `a/b/`.
    //
    // Called unconditionally, including when the target already exists: for
    // an ordinary resource an existing target implies an existing parent that
    // already contains it, which `authorize_ancestors` recognizes itself, but
    // an ACL is not a containment member and so CAN outlive the container it
    // sits in. Skipping the walk here on existence alone let a PUT to such an
    // orphan re-materialize that container unauthorized.
    if let Err(res) = authorize_ancestors(&st, &agent, &req_path).await {
        return res;
    }
    // An ACL may only be CREATED for a subject that exists. Otherwise anyone
    // holding `acl:Control` below a container can squat on a path that does
    // not exist and never did: `<ghost>.acl` naming only themselves becomes,
    // by nearest-ACL-wins, the document governing `<ghost>` — so the owner
    // can no longer create it (no Write), rewrite that ACL or delete it (no
    // Control), and deleting the container above does not reclaim it either,
    // because an ACL is not a containment member. Revoking the squatter's
    // delegation changes nothing. The path is bricked for everyone with no
    // HTTP route left to repair it. `Control` over a resource that does not
    // exist is not a grant anyone can meaningfully exercise, and requiring
    // the subject matches how auxiliary resources behave elsewhere in Solid.
    //
    // Scoped to creation deliberately: an ACL whose graph already exists must
    // stay writable even if its subject has since gone, or a stale ACL could
    // never be repaired or replaced by the owner.
    //
    // Placed AFTER every `authorize` call above, so an unauthorized caller is
    // still answered 401/403 and never learns whether the subject exists.
    if prp::is_acl_path(&req_path)
        && !matches!(get_rdf(st.store.as_ref(), &st.space, &req_path).await, Ok(Some(_)))
    {
        let subject = prp::acl_subject_path(&req_path);
        if !matches!(get_rdf(st.store.as_ref(), &st.space, &subject).await, Ok(Some(_))) {
            return (
                StatusCode::NOT_FOUND,
                "an ACL cannot be created for a resource that does not exist",
            ).into_response();
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
    // `resource::put_rdf` drops the graph and inserts nothing in its place, so
    // an empty body would answer 201 Created for a resource that does not
    // exist. On an ACL that inverts its meaning: an owner PUTting an empty
    // `<res>.acl` to revoke everything inherited below it gets a positive
    // confirmation while `effective_acl` keeps walking up to the ancestor's
    // acl:default rules — access WIDENED, not revoked. Containers are exempt:
    // the server supplies their type triples itself, so an empty body is the
    // ordinary way to create one.
    if triples.is_empty() && !container::is_container_path(&req_path) {
        return (
            StatusCode::BAD_REQUEST,
            "an empty RDF document cannot be stored: it would leave no resource behind. \
             Use DELETE to remove a resource.",
        ).into_response();
    }
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
    // POSTing into a container that does not exist yet materializes it and
    // its missing ancestors, so those need authorizing too. The walk starts
    // at `container_path` — already checked above, and where it stops in the
    // ordinary case of an existing container, so this adds nothing for a
    // plain append-only POST.
    if let Err(res) = authorize_ancestors(&st, &agent, &child_path).await {
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
    // `resource::put_rdf` drops the graph and inserts nothing in its place, so
    // an empty body would answer 201 Created for a child that does not
    // exist — while the container's new `ldp:contains` link to it (added by
    // `ensure_ancestors` below) survives, dangling forever: the child 404s,
    // so a later DELETE never reaches `remove_containment`. Unlike
    // `put_impl`, no container-path exemption applies here: `child_path` is
    // always `container_path + name`, which never ends in `/`.
    if triples.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "an empty RDF document cannot be stored: it would leave no resource behind. \
             Use DELETE to remove a resource.",
        ).into_response();
    }
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
    // Deleting a resource cascades to its ACL (below), so the caller must be
    // allowed to delete that ACL too — otherwise a narrowing ACL could be
    // removed by someone holding only Write, and recreating the resource
    // would restore the wider inherited rights it was written to revoke.
    // `authorize` rewrites an .acl path to Control on its subject. The
    // residual signal ("this resource has its own ACL") is only ever
    // observable to a caller who already holds Write on it — strictly less
    // than the Control the unguarded cascade used to hand them.
    if !prp::is_acl_path(&req_path) {
        let acl = prp::acl_path(&req_path);
        if matches!(get_rdf(st.store.as_ref(), &st.space, &acl).await, Ok(Some(_))) {
            if let Err(res) =
                authorize(st.store.as_ref(), &st.space, &agent, &acl, Mode::Write).await
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

    // True while this thread's test is holding a live `Fixture`.
    //
    // The replay lock a `Fixture` takes is process-wide and NOT reentrant, so
    // a second `fixture()` call inside one test would await a guard its own
    // caller still holds — a silent hang rather than a failure. A bare
    // `try_lock` cannot detect that: `cargo test` runs these tests in
    // parallel, so the lock is legitimately contended almost all the time and
    // `try_lock` fails for the innocent reason far more often than the guilty
    // one. Re-entrancy is therefore tracked per test thread, where the two
    // cases are distinguishable, and the mistake panics at once.
    thread_local! {
        static FIXTURE_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Clears [`FIXTURE_HELD`] when the fixture goes away. A field rather than
    /// a `Drop` impl on `Fixture` itself, because tests move `f.app` out of
    /// the fixture and that partial move is only legal while `Fixture` has no
    /// `Drop` of its own.
    struct ReentrancyGuard;

    impl Drop for ReentrancyGuard {
        fn drop(&mut self) {
            FIXTURE_HELD.with(|f| f.set(false));
        }
    }

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
        /// Releases this thread's re-entrancy flag (see [`FIXTURE_HELD`]).
        _reentrancy: ReentrancyGuard,
    }

    async fn fixture() -> Fixture {
        assert!(
            !FIXTURE_HELD.with(|f| f.replace(true)),
            "call fixture() once per test: it holds the process-wide DPoP replay lock \
             for the fixture's lifetime, so a second call would deadlock"
        );
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
        Fixture {
            app: router(state), store, space, idp, client, _replay_guard,
            _reentrancy: ReentrancyGuard,
        }
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

    // The failure mode the re-entrancy flag exists to prevent: before it, a
    // second fixture() in one test awaited the process-wide replay lock its
    // own caller was still holding and wedged CI with no output at all. The
    // panic must arrive BEFORE that await, which is what this pins.
    #[tokio::test]
    #[should_panic(expected = "call fixture() once per test")]
    async fn calling_fixture_twice_panics_instead_of_hanging() {
        let _first = fixture().await;
        let _second = fixture().await;
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

    // `resource::put_rdf` drops the graph and inserts nothing in its place,
    // so an empty body would answer 201 Created for a child that has no
    // content at all — while the container's ldp:contains link to it
    // survives, dangling: the child 404s forever, so a later DELETE never
    // reaches remove_containment. Confirms the listing is unaffected too.
    #[tokio::test]
    async fn post_empty_body_is_400_and_does_not_link_a_dangling_child() {
        let f = fixture().await;
        let mk = f.owner_request("PUT", "/inbox/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("")).unwrap();
        assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

        let post = f.owner_request("POST", "/inbox/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", "note")
            .body(Body::from("")).unwrap();
        let res = f.app.clone().oneshot(post).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(res).await.contains("empty RDF document"));

        let get = f.owner_request("GET", "/inbox/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        let body = body_string(res).await;
        assert!(!body.contains("ldp#contains"), "a rejected POST must not have linked a child");

        // The container the rejected POST would have targeted must remain
        // deletable — a dangling containment link would make it 409 forever.
        let del = f.owner_request("DELETE", "/inbox/").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
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
        // Grant Bob Write on /newfile before it exists. That grant has to
        // come from the ROOT ACL's `acl:default` — a direct /newfile.acl
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
        let put_acl = f.owner_request("PUT", "/.acl")
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

    // An empty body means DROP-and-insert-nothing (resource::put_rdf), so a
    // 201 would confirm a resource that isn't there. For an ACL that is the
    // opposite of what the caller asked for: with /box/.acl gone, the walk
    // resumes at the root ACL and its acl:default rules apply to the whole
    // subtree again — a "revoke everything" that WIDENS access.
    #[tokio::test]
    async fn empty_body_put_on_a_resource_is_400_and_does_not_erase_an_acl() {
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
        let put_acl = f.owner_request("PUT", "/box/.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl_body)).unwrap();
        assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

        let wipe = f.owner_request("PUT", "/box/.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("")).unwrap();
        let res = f.app.clone().oneshot(wipe).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(res).await.contains("empty RDF document"));

        // The ACL that was in force must still be in force, byte for byte in
        // effect: Bob keeps exactly the Read it granted him.
        assert!(
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/box/.acl").await.unwrap().is_some(),
            "a rejected PUT must not have dropped the ACL graph"
        );
        let bob_app = f.app_also_trusting(bob);
        let read = f.sign(Request::builder().method("GET").uri("/box/"), bob, "GET", "/box/")
            .body(Body::empty()).unwrap();
        assert_eq!(bob_app.clone().oneshot(read).await.unwrap().status(), StatusCode::OK);
        let write = f.sign(Request::builder().method("PUT").uri("/box/note"), bob, "PUT", "/box/note")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(bob_app.oneshot(write).await.unwrap().status(), StatusCode::FORBIDDEN);
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
        let put_acl = f.owner_request("PUT", "/box/.acl")
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
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/box/sub/").await.unwrap().is_none(),
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

    // The residual from the previous round: an ACL path is exempt from
    // containment (an `.acl` is never listed via `ldp:contains`), but
    // `ensure_ancestors` still materializes any missing ancestor containers
    // for `PUT /a/b/c.acl` exactly as it would for `PUT /a/b/c`. Bob's grant
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
        let put_root_acl = f.owner_request("PUT", "/.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(root_acl_body)).unwrap();
        assert_eq!(f.app.clone().oneshot(put_root_acl).await.unwrap().status(), StatusCode::CREATED);

        // Neither ancestor exists yet: this is the case that matters, since
        // an already-existing ancestor needs no fresh authorization.
        assert!(
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/a/").await.unwrap().is_none()
        );

        let bob_app = f.app_also_trusting(bob);
        let put_acl = f.sign(Request::builder().method("PUT").uri("/a/b/c.acl"), bob, "PUT", "/a/b/c.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(
                "<#x> <http://www.w3.org/ns/auth/acl#agent> <https://someone.example/#me> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/a/b/c> ; \
                 <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .",
            )).unwrap();
        assert_eq!(bob_app.oneshot(put_acl).await.unwrap().status(), StatusCode::FORBIDDEN);

        assert!(
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/a/").await.unwrap().is_none(),
            "a refused PUT of a deep .acl must not have materialized the ancestor container it has no Append on"
        );
    }

    // The counterweight to THIS test above's counterweight: when the ACL's
    // immediate parent already exists, creating the ACL is a zero-mutation
    // event — `add_containment` never records an ACL as a container member,
    // and `ensure_container` is a no-op on a container that already has its
    // type triples. So an agent holding `acl:Control` on the ACL's subject
    // (here, via `/box/.acl`'s own `acl:default`) and NOTHING else — in
    // particular no `acl:Append` on `/box/` — must still be able to write
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
        let put_box_acl = f.owner_request("PUT", "/box/.acl")
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

        // /box/ already exists (created above), so writing /box/doc.acl is a
        // zero-mutation event at the container level: Control on the subject
        // (inherited via /box/.acl's acl:default) must be enough.
        let put_doc_acl = f.sign(Request::builder().method("PUT").uri("/box/doc.acl"), bob, "PUT", "/box/doc.acl")
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
        let put_box_acl = f.owner_request("PUT", "/box/.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(box_acl_body)).unwrap();
        assert_eq!(f.app.clone().oneshot(put_box_acl).await.unwrap().status(), StatusCode::CREATED);

        // Bob's Control over /box/ghost is genuine (inherited via acl:default)
        // — the refusal below is about the subject's absence, not about him.
        let bob_app = f.app_also_trusting(bob);
        let squat = f.sign(Request::builder().method("PUT").uri("/box/ghost.acl"), bob, "PUT", "/box/ghost.acl")
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
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/box/ghost.acl").await.unwrap().is_none(),
            "the squatted ACL must not have been stored"
        );

        // ...and the path is still the owner's to use.
        let owner_create = f.owner_request("PUT", "/box/ghost")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"mine\" .")).unwrap();
        assert_eq!(f.app.oneshot(owner_create).await.unwrap().status(), StatusCode::CREATED);
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

        let put_acl = f.owner_request("PUT", "/box/doc.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(format!(
                "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/doc> ; \
                 <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
                   <http://www.w3.org/ns/auth/acl#Write>, \
                   <http://www.w3.org/ns/auth/acl#Control> ."
            ))).unwrap();
        assert_eq!(f.app.clone().oneshot(put_acl).await.unwrap().status(), StatusCode::CREATED);

        // The check is creation-only, so a STALE ACL stays repairable: an
        // owner must always be able to rewrite (or delete) one whose subject
        // has gone, whatever left it that way. The subject is removed at the
        // store level here precisely because no HTTP route produces that
        // state — DELETE cascades into the ACL — and the guarantee has to
        // hold regardless.
        delete_rdf(f.store.as_ref(), &f.space, "/box/doc").await.unwrap();
        let rewrite = f.owner_request("PUT", "/box/doc.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(format!(
                "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/doc> ; \
                 <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
            ))).unwrap();
        assert_eq!(f.app.clone().oneshot(rewrite).await.unwrap().status(), StatusCode::CREATED);

        let del_acl = f.owner_request("DELETE", "/box/doc.acl").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(del_acl).await.unwrap().status(), StatusCode::NO_CONTENT);
    }

    // The other half of `authorize_ancestors`' exemption, and the one that
    // makes calling it unconditionally safe: overwriting a resource that
    // already exists adds no containment triple its parent does not already
    // hold, so it must NOT start demanding `Append` there. Bob here holds
    // Read+Write on one document and deliberately nothing on the container
    // around it — the ordinary "you may edit this file" grant. Without the
    // `target_exists` half of the exemption every such edit would 403.
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
        let put_doc_acl = f.owner_request("PUT", "/box/doc.acl")
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

    // An ACL is never a containment member, so it can OUTLIVE the container
    // it sits in: deleting an "empty" container takes its own `.acl` with it
    // but leaves any `.acl` addressed below it in the store. A PUT to such an
    // orphan re-runs `ensure_ancestors`, which materializes the container
    // again and writes a fresh `ldp:contains` triple into ITS parent — here
    // the root. While the target's own graph existed, `put_impl` skipped the
    // ancestor walk entirely, so that write happened with no authorization on
    // any container in the chain.
    //
    // The orphan used here is `/box/.acl.acl`: an ACL is an addressable
    // resource governed by `Control` on its subject, so `/box/.acl` has an
    // ACL of its own, and that one is NOT cascaded when `/box/` is deleted
    // (the cascade removes `prp::acl_path("/box/")` and nothing else). It is
    // also the shape that keeps Bob authorized on the target after his
    // delegation is revoked: `effective_acl("/box/.acl")` finds
    // `/box/.acl.acl` directly, i.e. the document Bob wrote about himself.
    // That is precisely the case that matters — Bob passes the target check
    // on his own say-so and must still be stopped from touching `/`.
    #[tokio::test]
    async fn put_to_an_orphaned_acl_still_needs_append_on_what_it_materializes() {
        let f = fixture().await;
        let bob = "https://bob.example/card#me";

        let mk = f.owner_request("PUT", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("")).unwrap();
        assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);

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
        let put_box_acl = f.owner_request("PUT", "/box/.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(box_acl_body)).unwrap();
        assert_eq!(f.app.clone().oneshot(put_box_acl).await.unwrap().status(), StatusCode::CREATED);

        // Bob exercises the delegation while it is live. Legitimate: /box/
        // exists, so this writes nothing at the container level.
        let bob_app = f.app_also_trusting(bob);
        let squat_body = format!(
            "<#bob> <http://www.w3.org/ns/auth/acl#agent> <{bob}> ; \
             <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/box/.acl> ; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
        );
        let squat = f.sign(Request::builder().method("PUT").uri("/box/.acl.acl"), bob, "PUT", "/box/.acl.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(squat_body.clone())).unwrap();
        assert_eq!(bob_app.clone().oneshot(squat).await.unwrap().status(), StatusCode::CREATED);

        // The owner tidies up. /box/ holds no ldp:contains members (ACLs
        // never are), so it is deleteable — and the delete revokes Bob's
        // delegation by cascading /box/.acl.
        let del = f.owner_request("DELETE", "/box/").body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
        assert!(
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/box/.acl").await.unwrap().is_none(),
            "deleting the container must have revoked the delegation"
        );
        assert!(
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/box/.acl.acl").await.unwrap().is_some(),
            "the orphaned ACL survives — that is the premise of this test"
        );
        assert!(
            container::container_is_empty(f.store.as_ref(), &f.space, "/").await.unwrap(),
            "the root must be empty again before the attack"
        );

        // The attack: Bob holds nothing on / or /box/ any more, but his own
        // squatted document still grants him Control over the target. Serving
        // this would recreate /box/ and write </> ldp:contains </box/>.
        let attack = f.sign(Request::builder().method("PUT").uri("/box/.acl.acl"), bob, "PUT", "/box/.acl.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(squat_body)).unwrap();
        assert_eq!(bob_app.oneshot(attack).await.unwrap().status(), StatusCode::FORBIDDEN);
        assert!(
            container::container_is_empty(f.store.as_ref(), &f.space, "/").await.unwrap(),
            "a refused PUT must not have written a containment triple into the root"
        );
        assert!(
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/box/").await.unwrap().is_none(),
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
        let put_acl = f.owner_request("PUT", "/inbox/.acl")
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
    // narrowing, recreate the resource, and have `effective_acl` walk back up
    // to the wider ancestor grant — escalating themselves to Control without
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
        let put_projects_acl = f.owner_request("PUT", "/projects/.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(projects_acl)).unwrap();
        assert_eq!(f.app.clone().oneshot(put_projects_acl).await.unwrap().status(), StatusCode::CREATED);

        // The narrowing ACL: on the log itself Bob may read and write, but
        // NOT control. The nearest ACL wins completely, so this replaces the
        // Control he would otherwise inherit from /projects/.acl.
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
        let put_log_acl = f.owner_request("PUT", "/projects/audit-log.acl")
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
        let touch_acl = f.sign(Request::builder().method("DELETE").uri("/projects/audit-log.acl"), bob, "DELETE", "/projects/audit-log.acl")
            .body(Body::empty()).unwrap();
        assert_eq!(bob_app.clone().oneshot(touch_acl).await.unwrap().status(), StatusCode::FORBIDDEN);

        // The attack: delete the resource so the cascade takes the ACL with it.
        let del = f.sign(Request::builder().method("DELETE").uri("/projects/audit-log"), bob, "DELETE", "/projects/audit-log")
            .body(Body::empty()).unwrap();
        assert_eq!(bob_app.oneshot(del).await.unwrap().status(), StatusCode::FORBIDDEN);
        assert!(
            crate::resource::get_rdf(f.store.as_ref(), &f.space, "/projects/audit-log.acl").await.unwrap().is_some(),
            "the narrowing ACL must survive a refused delete"
        );

        // The owner, who does hold Control there, is unaffected.
        let owner_del = f.owner_request("DELETE", "/projects/audit-log").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(owner_del).await.unwrap().status(), StatusCode::NO_CONTENT);
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
        // The subject must exist: an ACL is only creatable for a resource
        // that does (see `acl_for_a_resource_that_does_not_exist_is_refused`).
        let put_foo = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(put_foo).await.unwrap().status(), StatusCode::CREATED);
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
