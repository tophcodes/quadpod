//! The HTTP edge: every request path is classified once, by
//! [`StorageSpace::resolve`], and every handler dispatches on the [`Target`]
//! that comes back. No handler re-derives what kind of thing a URL names, and
//! none of them can: the lifecycle rules live in the types (`resource::` for
//! a subject, `aux::` for an auxiliary) rather than in a predicate each
//! handler has to remember to evaluate.

use std::sync::Arc;
use axum::{Router, routing::get, extract::{State, Path}, body::Bytes, Extension,
    http::{StatusCode, HeaderMap, header, header::{IF_MATCH, IF_NONE_MATCH}}, response::{IntoResponse, Response}};
use crate::{aux::{self, AuxError, AUX_SUBJECT_MISSING_MESSAGE}, container,
    resource::{put_rdf, get_rdf, delete_rdf, exists, ResourceError},
    rdf::{format_for_content_type, format_for_accept, parse, serialize, etag},
    auth::{Agent, AuthConfig, JwksResolver, WebIdIssuerVerifier, auth_layer},
    space::{AuxKind, AuxUrl, GraphName, SpaceError, StorageSpace, Target},
    store::SparqlStore,
    wac::{guard::{authorize, authorize_and_materialize}, pdp, Mode}};

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

/// Classify a request path, or answer it outright.
///
/// A path in the reserved namespace that names no auxiliary resource is a
/// `404`: it is not data, and it never will be — no representation can be
/// stored there and none can be read from there. Anything else `resolve`
/// refuses is a malformed request URL.
fn classify(space: &StorageSpace, request_path: &str) -> Result<Target, StatusCode> {
    space.resolve(request_path).map_err(|e| match e {
        SpaceError::Reserved => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_REQUEST,
    })
}

/// Every auxiliary this resource has, advertised whether or not it exists.
///
/// A client must not derive these URLs — in this pod's URI space `<url>.acl`
/// is an ordinary resource, not a policy document — so this header is the
/// only place it can learn them, and it needs them precisely in order to
/// create the first one. Built from [`AuxKind::ALL`], so a new kind is
/// advertised the moment it exists.
///
/// `None` for an auxiliary: it has no auxiliaries of its own, being governed
/// by `acl:Control` on its subject.
fn aux_links(target: &Target) -> Option<String> {
    let subject = match target {
        Target::Resource(r) => r,
        Target::Container(c) => c.as_resource(),
        Target::Aux(_) => return None,
    };
    Some(
        AuxKind::ALL
            .iter()
            .map(|k| format!("<{}>; rel=\"{}\"", subject.aux(*k).graph_iri(), k.link_rel()))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// Attach [`aux_links`] to a response — including refusals and `404`s, which
/// is where a client mid-create-flow needs them most: SolidOS string-derives
/// `<url>.acl` exactly when this header is absent, and would then write its
/// policy to a path this pod treats as ordinary data.
fn with_aux_links(mut res: Response, target: &Target) -> Response {
    if let Some(value) = aux_links(target) {
        res.headers_mut().insert(
            header::LINK,
            value.parse().expect("aux link value is header-safe"),
        );
    }
    res
}

/// The one sentence a self-denying ACL is reported with, in both places it is
/// reported — [`warn_if_acl_grants_nothing`] logs this string and puts this
/// same string on the response, so the two can never drift.
///
/// `acl_iri` is where the document now lives, `subject_iri` the resource it
/// governs. `is_container` decides whether the message claims a subtree: a
/// container's ACL is inherited by everything under it, but a plain
/// resource's ancestor chain never contains the resource itself, so its ACL
/// governs exactly that one resource and nothing "below" it. `is_root` adds
/// the recovery instruction, which only applies to the root: for any other
/// subtree there is genuinely no way back, since removing the ACL needs the
/// `Control` it just revoked from everyone.
fn acl_grants_nothing_message(
    acl_iri: &str,
    subject_iri: &str,
    is_container: bool,
    is_root: bool,
) -> String {
    let scope = if is_container { " and everything below it" } else { "" };
    let mut m = format!(
        "The ACL at {acl_iri} grants no access to anyone, so every request for \
         {subject_iri}{scope} is now denied, including the Control needed to \
         remove this ACL."
    );
    if is_root {
        m.push_str(" Recovery requires restarting the server with --reset-root-acl.");
    }
    m
}

/// A `Warning` header carrying `message`, if it can be expressed as one.
///
/// `Warning` is obsolete — RFC 9111 §5.5 retired it along with the cache
/// semantics it was invented for — and it is still the right field here. It
/// was never reassigned, `199` is precisely its "miscellaneous warning, text
/// MAY be presented to a human" code, and a `curl -i` user reads it as a
/// warning without being told anything about this pod, which no bespoke
/// `X-`-prefixed name achieves. The response is a `201` to a `PUT`, never
/// cached, so the caching rules that obsoleted the field cannot apply to it.
/// The authoritative channel is the log; this is the convenience copy, so an
/// intermediary that strips it costs nothing.
///
/// [`acl_grants_nothing_message`] interpolates IRIs, and RFC 3987 permits
/// non-ASCII IRI characters, so the message is not guaranteed to be pure
/// ASCII — only guaranteed to contain no `"` or `\`, which is what actually
/// keeps the `quoted-string` this builds well-formed. `HeaderValue::from_str`
/// accepts any byte `>= 32` except `127`, so a non-ASCII subject IRI becomes
/// obs-text in the header value rather than being rejected: legal, if not
/// always readable by a client that assumes ASCII. The `Option` return is for
/// what actually can make `from_str` fail — a `"` or `\` that somehow reached
/// this point despite the guard below, or a control byte below `32`. Should
/// that ever happen, the header is dropped rather than a malformed one sent —
/// the log still carries the whole story.
fn warning_header(message: &str) -> Option<header::HeaderValue> {
    if message.contains(['"', '\\']) {
        return None;
    }
    header::HeaderValue::from_str(&format!("199 - \"{message}\"")).ok()
}

/// Say so, twice, when a just-written ACL grants nobody anything.
///
/// This pod treats an empty ACL as "nothing is granted here" rather than
/// "absent" — existence is a stored marker, not a triple count — so such a
/// document wins over every ancestor and denies its whole subtree, including
/// the `Control` that removing it would need. At the root that means the pod
/// is locked out of itself and only `--reset-root-acl` gets back in; anywhere
/// else there is no route back at all. Neither the empty body nor the far more
/// likely near-miss (the wrong predicate, an `acl:accessTo` naming something
/// else) was signalled before this — a typo in a WebID is not among the
/// near-misses this catches: see [`pdp::grants_anything`]'s doc comment for
/// why.
///
/// The write is not refused. An ACL that locks its own subtree is a legitimate
/// thing to want, and second-guessing a `PUT` that `aux::put` already accepted
/// would be the handler overruling the policy layer. It is reported instead:
/// once to the log, which is authoritative, and once on the response, so a
/// `curl` user sees it without reading server logs. Both carry the identical
/// sentence from [`acl_grants_nothing_message`].
///
/// The question itself is [`pdp::grants_anything`]'s — the layer that owns
/// what a grant *is*. Asking it here, by re-reading the triples, is exactly
/// the duplication this codebase has spent its ACL defects unlearning.
/// `triples` is what `aux::put` just stored, so no second round-trip is
/// needed to know the document's contents.
fn warn_if_acl_grants_nothing(
    space: &StorageSpace,
    aux: &AuxUrl,
    triples: &[oxigraph::model::Triple],
    mut res: Response,
) -> Response {
    if aux.kind() != AuxKind::Acl {
        return res;
    }
    let subject_iri = aux.subject().graph_iri();
    if pdp::grants_anything(triples, subject_iri) {
        return res;
    }
    let is_root = subject_iri == space.root().graph_iri();
    let is_container = aux.subject().as_container().is_some();
    let message = acl_grants_nothing_message(aux.graph_iri(), subject_iri, is_container, is_root);
    tracing::warn!("{message}");
    if let Some(value) = warning_header(&message) {
        res.headers_mut().insert(header::WARNING, value);
    }
    res
}

/// The `201` every create answers with: where the thing now lives, and where
/// its auxiliaries would live.
fn created(target: &Target) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        target.graph_iri().parse().expect("graph iri is header-safe"),
    );
    with_aux_links((StatusCode::CREATED, headers).into_response(), target)
}

fn put_status(e: &ResourceError) -> StatusCode {
    match e {
        ResourceError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> &str {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

async fn handle_put(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap, body: Bytes,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) => put_impl(st, agent, target, headers, body).await,
        Err(status) => status.into_response(),
    }
}

async fn handle_put_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>, headers: HeaderMap, body: Bytes,
) -> Response {
    match classify(&st.space, "/") {
        Ok(target) => put_impl(st, agent, target, headers, body).await,
        Err(status) => status.into_response(),
    }
}

async fn put_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap, body: Bytes) -> Response {
    let store = st.store.as_ref();
    if let Err(res) = authorize(store, &agent, &target, Mode::Write).await {
        return with_aux_links(res, &target);
    }
    let Some(fmt) = format_for_content_type(header_str(&headers, header::CONTENT_TYPE)) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let triples = match parse(&body, fmt, target.graph_iri()) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // Containment is server-managed. Refused here, before the ancestor walk
    // below writes anything, so a rejected PUT cannot leave a containment
    // triple pointing at a container it never created.
    if matches!(target, Target::Container(_)) && container::body_sets_containment(&triples) {
        return StatusCode::CONFLICT.into_response();
    }
    if headers.contains_key(IF_MATCH) || headers.contains_key(IF_NONE_MATCH) {
        let current_tag = match get_rdf(store, &target).await {
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
    // Creating a resource materializes every missing ancestor container and
    // links it into the first one that already exists — real mutations of
    // resources the caller may hold nothing on. One traversal authorizes
    // exactly the levels it writes (see `wac::guard`), so there is no second
    // rule here that could drift from it.
    //
    // Deliberately after the body checks: a 415 or an unparseable body must
    // not leave containers behind for a resource that was never created.
    //
    // This is also where a create that Solid Protocol §3.1 forbids is refused
    // with a `409` — `PUT /box` while `/box/` exists, or the reverse. That
    // rule belongs to the same one traversal, because the set of URLs it
    // applies to is the set of URLs this call would create; there is no
    // separate check here that could drift from it.
    if let Err(res) = authorize_and_materialize(store, &agent, &target).await {
        return with_aux_links(res, &target);
    }
    match &target {
        // An auxiliary exists only for an existing subject, and that rule is
        // inside `aux::put`'s update rather than a check here — a check and a
        // write are two round-trips, and an interleaved DELETE between them
        // would plant a policy document on a path that no longer exists.
        Target::Aux(a) => match aux::put(store, a, &triples).await {
            Ok(()) => warn_if_acl_grants_nothing(&st.space, a, &triples, created(&target)),
            Err(AuxError::SubjectMissing) =>
                (StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response(),
            Err(AuxError::Resource(e)) => (put_status(&e), e.to_string()).into_response(),
        },
        Target::Container(c) => {
            // Preserve existing containment, then re-assert the server's type
            // triples. Note: this read-then-write (get_rdf here, then
            // DROP+INSERT in put_rdf) is not transactional across the two
            // graph operations; a concurrent child add landing between the
            // read and the write could be lost. Accepted for single-user v1
            // per the plan's cross-graph-atomicity note.
            let existing = match get_rdf(store, c).await {
                Ok(v) => v.unwrap_or_default(),
                Err(e) => return (put_status(&e), e.to_string()).into_response(),
            };
            let mut merged = triples;
            merged.extend(
                existing.into_iter().filter(|t| t.predicate.as_str() == container::LDP_CONTAINS),
            );
            if let Err(e) = put_rdf(store, c, &merged).await {
                return (put_status(&e), e.to_string()).into_response();
            }
            if let Err(e) = container::ensure_container(store, c).await {
                return (put_status(&e), e.to_string()).into_response();
            }
            created(&target)
        }
        Target::Resource(r) => match put_rdf(store, r, &triples).await {
            Ok(()) => created(&target),
            Err(e) => (put_status(&e), e.to_string()).into_response(),
        },
    }
}

async fn handle_post(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap, body: Bytes,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) => post_impl(st, agent, target, headers, body).await,
        Err(status) => status.into_response(),
    }
}

async fn handle_post_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>, headers: HeaderMap, body: Bytes,
) -> Response {
    match classify(&st.space, "/") {
        Ok(target) => post_impl(st, agent, target, headers, body).await,
        Err(status) => status.into_response(),
    }
}

/// Whether a name a `POST` would allocate is already spoken for — by a
/// resource of its own, or by the other half of its trailing-slash pair,
/// which Protocol §3.1 forbids it from coming to exist beside.
///
/// A `Slug` is a hint, so a taken name is answered by picking another rather
/// than by the `409` a client-named `PUT` gets: the counterpart is exactly as
/// unavailable as the name itself, and for the same reason. Store errors read
/// as "not taken" here, as the direct existence check always has — the write
/// that follows is what reports them.
async fn name_is_taken(store: &dyn SparqlStore, child: &Target) -> bool {
    if matches!(exists(store, child).await, Ok(true)) {
        return true;
    }
    let Target::Resource(r) = child else { return false };
    match r.slash_counterpart() {
        Some(counterpart) => matches!(exists(store, &counterpart).await, Ok(true)),
        None => false,
    }
}

async fn post_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap, body: Bytes) -> Response {
    let store = st.store.as_ref();
    // Authorize the target FIRST, even though Append on a non-container is a
    // meaningless grant in practice: the 409 below is derived from the
    // request path alone, but no handler branch may answer before `authorize`
    // runs, so an unauthorized caller never learns even that much about the
    // path they probed. An auxiliary lands here too — POST is how one would
    // try to create one, and it is refused as "not a container".
    if let Err(res) = authorize(store, &agent, &target, Mode::Append).await {
        return with_aux_links(res, &target);
    }
    let Target::Container(parent) = &target else {
        return StatusCode::CONFLICT.into_response(); // POST target must be a container
    };
    let Some(fmt) = format_for_content_type(header_str(&headers, header::CONTENT_TYPE)) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let slug = headers.get("slug").and_then(|v| v.to_str().ok());
    // A settled child name contains no `/`, so the child of a container is
    // always an ordinary resource — unless the server would have to allocate
    // it inside the reserved namespace (`Slug: .aux` at the root), which
    // `classify` refuses. A `Slug` can therefore never name an auxiliary.
    let name = container::child_name(slug);
    let mut child = match classify(&st.space, &format!("{}{name}", parent.path())) {
        Ok(t) => t,
        Err(status) => return status.into_response(),
    };
    // Note: this existence check followed by the write below is not
    // transactional; a concurrent write landing between them could be missed.
    // Accepted for single-user v1.
    if name_is_taken(store, &child).await {
        let unique = format!("{name}-{}", uuid::Uuid::new_v4());
        child = match classify(&st.space, &format!("{}{unique}", parent.path())) {
            Ok(t) => t,
            Err(status) => return status.into_response(),
        };
    }
    // The container's Append is not enough to authorize the CHILD: it may
    // carry an ACL of its own that grants less than the container does.
    // Mode::Append (not Write) to stay consistent with the container-level
    // check above, or the append-only inbox pattern this design targets would
    // break — every legitimate append-only POST would suddenly need Write on
    // the child it creates.
    if let Err(res) = authorize(store, &agent, &child, Mode::Append).await {
        return with_aux_links(res, &child);
    }
    let triples = match parse(&body, fmt, child.graph_iri()) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // POSTing into a container that does not exist yet materializes it and
    // its missing ancestors, so those need authorizing too — the same single
    // traversal `put_impl` uses.
    if let Err(res) = authorize_and_materialize(store, &agent, &child).await {
        return with_aux_links(res, &child);
    }
    match &child {
        Target::Resource(r) => match put_rdf(store, r, &triples).await {
            Ok(()) => created(&child),
            Err(e) => (put_status(&e), e.to_string()).into_response(),
        },
        // Unreachable: see the `child_name` comment above.
        Target::Container(_) | Target::Aux(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn handle_get(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) => get_impl(st, agent, target, headers).await,
        Err(status) => status.into_response(),
    }
}

async fn handle_get_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>, headers: HeaderMap,
) -> Response {
    match classify(&st.space, "/") {
        Ok(target) => get_impl(st, agent, target, headers).await,
        Err(status) => status.into_response(),
    }
}

async fn get_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap) -> Response {
    let store = st.store.as_ref();
    if let Err(res) = authorize(store, &agent, &target, Mode::Read).await {
        return with_aux_links(res, &target);
    }
    let Some(fmt) = format_for_accept(header_str(&headers, header::ACCEPT)) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    match get_rdf(store, &target).await {
        Ok(Some(triples)) => {
            let tag = etag(&triples);
            if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
                return with_aux_links(
                    (StatusCode::NOT_MODIFIED, [(header::ETAG, tag)]).into_response(),
                    &target,
                );
            }
            match serialize(&triples, fmt) {
                Ok(bytes) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, fmt.media_type().parse().expect("static media type"));
                    headers.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
                    with_aux_links((headers, bytes).into_response(), &target)
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        // The advertisement matters most here: a client creating a resource
        // learns where its ACL goes from the 404 it got when it looked.
        Ok(None) => with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Err(ResourceError::InvalidIri) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn handle_delete(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) => delete_impl(st, agent, target).await,
        Err(status) => status.into_response(),
    }
}

async fn handle_delete_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>,
) -> Response {
    match classify(&st.space, "/") {
        Ok(target) => delete_impl(st, agent, target).await,
        Err(status) => status.into_response(),
    }
}

async fn delete_impl(st: AppState, agent: Agent, target: Target) -> Response {
    let store = st.store.as_ref();
    if let Err(res) = authorize(store, &agent, &target, Mode::Write).await {
        return with_aux_links(res, &target);
    }
    let subject = match &target {
        // Removing an auxiliary is a complete operation on its own: the path
        // falls back to inherited policy, which is exactly what its absence
        // means. Nothing else refers to it — an auxiliary is never a
        // container member — so there is no containment to repair.
        Target::Aux(a) => {
            return match delete_rdf(store, a).await {
                Ok(true) => StatusCode::NO_CONTENT.into_response(),
                Ok(false) => StatusCode::NOT_FOUND.into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            };
        }
        Target::Resource(r) => r,
        Target::Container(c) => c.as_resource(),
    };
    // Removing a member rewrites the parent's containment triples.
    if let Some(parent) = subject.parent() {
        if let Err(res) = authorize(store, &agent, &Target::Container(parent), Mode::Write).await {
            return with_aux_links(res, &target);
        }
    }
    // Deleting a subject takes every auxiliary it has with it (that cascade
    // is `aux::delete_subject`'s definition, not a step remembered here), so
    // the caller must be allowed to remove each one that exists. Without
    // this, a narrowing ACL — WAC's only mechanism for revoking what an
    // ancestor hands down through `acl:default` — could be erased by someone
    // holding merely Write: delete the resource, recreate it, and the wider
    // ancestor grant applies again. The residual signal ("this resource has
    // an auxiliary of kind k") is only ever observable to a caller who
    // already holds Write on it.
    for kind in AuxKind::ALL {
        let aux = subject.aux(*kind);
        match exists(store, &aux).await {
            Ok(false) => {}
            Ok(true) => {
                // `authorize` ignores this `Mode::Write` for an `Aux` target
                // and requires `Control` instead — passed here only to match
                // every other call site's shape, not because the mode itself
                // matters.
                if let Err(res) = authorize(store, &agent, &Target::Aux(aux), Mode::Write).await {
                    return with_aux_links(res, &target);
                }
            }
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
    if let Target::Container(c) = &target {
        if subject.parent().is_none() {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        match container::container_is_empty(store, c).await {
            Ok(false) => return StatusCode::CONFLICT.into_response(),
            Ok(true) => {}
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
    match aux::delete_subject(store, subject).await {
        Ok(true) => {
            if let Some(parent) = subject.parent() {
                if let Err(e) =
                    container::remove_containment(store, &parent, subject.graph_iri()).await
                {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
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
    use crate::{space::{ContainerUrl, StorageSpace}, store::OxigraphStore, auth::StaticJwksResolver};
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
        crate::container::provision_root(store.as_ref(), &space.root()).await.unwrap();
        crate::wac::provision::provision_root_acl(store.as_ref(), &space, OWNER, false).await.unwrap();

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

        /// The typed URL a request path names, for tests that inspect the
        /// store directly rather than through HTTP.
        fn url(&self, path: &str) -> Target {
            self.space.resolve(path).expect("test path resolves")
        }

        fn container(&self, path: &str) -> ContainerUrl {
            match self.url(path) {
                Target::Container(c) => c,
                _ => panic!("{path} is not a container path"),
            }
        }

        /// What is stored at `path`, straight from the store.
        async fn stored(&self, path: &str) -> Option<Vec<oxigraph::model::Triple>> {
            crate::resource::get_rdf(self.store.as_ref(), &self.url(path)).await.unwrap()
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

    // Each shape here is one `dpop-verifier::normalize_htu` would silently
    // change (drop an empty segment, resolve a dot-segment, or strip
    // whatever follows a fragment marker) while this pod would otherwise
    // treat it as naming a distinct resource. `resolve`'s `NotNormalized`
    // check refuses them all at the HTTP layer, through `classify`, before
    // any of them can reach the store or the WAC guard.
    #[tokio::test]
    async fn paths_normalization_would_alias_are_400() {
        let f = fixture().await;
        // `owner_request` signs the raw path, which is exactly what
        // `derive_htu` derives the `htu` from, so every shape here
        // authenticates and is then refused by `classify`, not by the
        // credential check.
        for path in ["/a//b", "/a/b//", "/a/./b", "/a/../b"] {
            let get = f.owner_request("GET", path).body(Body::empty()).unwrap();
            assert_eq!(
                f.app.clone().oneshot(get).await.unwrap().status(),
                StatusCode::BAD_REQUEST,
                "GET {path} should be refused as not normalization-stable"
            );
            let put = f.owner_request("PUT", path)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
            assert_eq!(
                f.app.clone().oneshot(put).await.unwrap().status(),
                StatusCode::BAD_REQUEST,
                "PUT {path} should be refused as not normalization-stable"
            );
        }
    }

    // A raw request path of `/a%23b` decodes (the way `classify` decodes it)
    // to `/a#b`, which `resolve` refuses as `NotNormalized` — a `400`, and it
    // must stay a `400` rather than becoming a misleading `401`. The `htu` a
    // client signs is the WIRE form, `%23` and all (see `derive_htu`), which
    // is exactly what `owner_request` builds; before the wire-form fix this
    // test had to craft a proof over the decoded `https://pod.toph.so/a#b`
    // instead, and `owner_request` could not express it.
    #[tokio::test]
    async fn hash_in_the_decoded_path_is_400_not_401() {
        let f = fixture().await;
        let req = f.owner_request("GET", "/a%23b").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    // This pins the property `HTU_DECODE_FAILURE_SENTINEL` used to guarantee
    // before it was deleted as unreachable: a request whose path does not
    // percent-decode to valid UTF-8 must fail closed, never reach a handler,
    // and never be mistaken for an authentication failure. `derive_htu` signs
    // and compares the wire form (see its doc comment), so this request
    // authenticates just fine; it is axum's own `Path<String>` extractor that
    // now rejects the invalid UTF-8 with a `400` before `handle_get`'s body
    // ever runs. If this ever regresses to a `401` or a `200`, the sentinel's
    // guarantee is gone and nothing else in this suite would catch it.
    #[tokio::test]
    async fn an_undecodable_path_is_400_even_when_authenticated() {
        let f = fixture().await;
        let req = f.owner_request("GET", "/%ff%fe").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    // The trailing slash is not a segment normalization would remove — it is
    // what distinguishes a container from a resource — so it must keep
    // working exactly as it did before the `NotNormalized` rule existed.
    #[tokio::test]
    async fn trailing_slash_container_still_resolves() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("")).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
        let get = f.owner_request("GET", "/box/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body_string(res).await.contains("ldp#BasicContainer"));
    }

    // The trailing slash is exactly what `dpop-verifier`'s `normalize_htu`
    // erases, so without `verify_dpop`'s own exact `htu` comparison this
    // request would authenticate: the owner signs `PUT /foo` and an on-path
    // adversary re-delivers the identical bytes as `PUT /foo/`, installing
    // the body as the *container* of the same name — a different resource
    // from the one the client addressed and authorized. It must be a 401,
    // from the middleware, before any handler sees it.
    //
    // This used to be pinned against an auxiliary pair
    // (`PUT /.aux/foo.acl` re-delivered as `PUT /.aux/foo/.acl`), but the
    // auxiliary URL shape changed: the kind is now a suffix, so those two
    // paths' segment lists (`[".aux","foo.acl"]` vs `[".aux","foo",".acl"]`)
    // differ in a non-empty segment, not an empty one — `normalize_htu`
    // never treats them as equal, so an ordinary `htu` mismatch already
    // answers 401 without this tightening. Worse, appending the slash
    // directly (`/.aux/foo.acl` -> `/.aux/foo.acl/`) *does* still collapse
    // under `normalize_htu`, but `/.aux/foo.acl/` ends in no kind's suffix,
    // so it resolves to `Reserved` -> 404 regardless of what `verify_dpop`
    // decides. Both are a real improvement, and both are why this
    // regression now has to live in the resource space instead.
    #[tokio::test]
    async fn a_proof_for_a_resource_cannot_write_its_container_counterpart() {
        let f = fixture().await;
        let at = f.idp.mint_access_token(OWNER, &f.client.jkt(), now_unix() + 3600);
        let proof = f.client.mint_dpop(
            "https://pod.toph.so/foo",
            "PUT",
            now_unix(),
            "jti-resource-trailing-slash",
        );
        let req = Request::builder()
            .method("PUT")
            .uri("/foo/")
            .header(header::AUTHORIZATION, format!("DPoP {at}"))
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("dpop", proof)
            .body(Body::from(""))
            .unwrap();
        assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    // The same re-targeting, through a percent-escape instead of a trailing
    // slash. The owner signs `PUT /.aux/a%41.acl` — whose subject the handlers
    // read as `/aA` — and an on-path adversary re-delivers the identical bytes
    // as `PUT /.aux/a%2541.acl`, whose subject is `/a%41`, a DIFFERENT
    // resource. While `htu` was the percent-DECODED graph IRI and the exact
    // comparison decoded both sides, the two collapsed to the same string and
    // this authenticated. It must be a 401, from the middleware.
    #[tokio::test]
    async fn a_proof_for_one_acl_cannot_be_redirected_by_a_double_escape() {
        let f = fixture().await;
        let at = f.idp.mint_access_token(OWNER, &f.client.jkt(), now_unix() + 3600);
        let proof = f.client.mint_dpop(
            "https://pod.toph.so/.aux/a%41.acl",
            "PUT",
            now_unix(),
            "jti-acl-double-escape",
        );
        let req = Request::builder()
            .method("PUT")
            .uri("/.aux/a%2541.acl")
            .header(header::AUTHORIZATION, format!("DPoP {at}"))
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("dpop", proof)
            .body(Body::from(
                "<#r> a <http://www.w3.org/ns/auth/acl#Authorization> ;\
                 <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.toph.so/aA> .",
            ))
            .unwrap();
        assert_eq!(f.app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    // The other half: a client that signs the wire form it actually requests
    // must get through, end to end. `%41` is a plain `A`, so this once failed
    // with a `401` even for the honest client — `dpop-verifier` compared the
    // still-encoded proof against a `derive_htu` that had already decoded it.
    #[tokio::test]
    async fn a_percent_encoded_path_authenticates_for_its_own_request() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/a%41")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        let res = f.app.clone().oneshot(put).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        // The handler decoded the path, so the resource is `/aA` — the `htu`
        // being the wire form changed the credential check, not the storage.
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/aA");

        let get = f.owner_request("GET", "/aA").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body_string(res).await.contains("schema.org/name"));
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

    // This test used to assert a 400 with the reasoning that an empty body
    // left the container linking a child that did not exist — the child 404d
    // forever and a later DELETE never reached `remove_containment`. Existence
    // is a stored fact now, so the created child exists, is listed, is
    // readable and is deletable; the dangling-link hazard the 400 defended
    // against is gone, and what remains is a resource with no triples, which
    // is exactly what an empty body says.
    #[tokio::test]
    async fn post_empty_body_creates_an_empty_child_that_is_really_there() {
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
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/inbox/note");
        assert_eq!(f.stored("/inbox/note").await, Some(Vec::new()), "an empty child exists");

        // It is listed, readable, and — the part that used to be impossible —
        // removable, which leaves the container deletable again.
        let get = f.owner_request("GET", "/inbox/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let body = body_string(f.app.clone().oneshot(get).await.unwrap()).await;
        assert!(body.contains("https://pod.toph.so/inbox/note"), "the child must be listed");

        let read = f.owner_request("GET", "/inbox/note").body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(read).await.unwrap().status(), StatusCode::OK);

        let del_child = f.owner_request("DELETE", "/inbox/note").body(Body::empty()).unwrap();
        assert_eq!(f.app.clone().oneshot(del_child).await.unwrap().status(), StatusCode::NO_CONTENT);
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

    /// The `Warning` header on a response, if it carries one.
    fn warning_of(res: &axum::response::Response) -> Option<String> {
        res.headers()
            .get(header::WARNING)
            .map(|v| v.to_str().unwrap().to_owned())
    }

    /// Write `body` as the ACL of `subject_path` and return the response.
    async fn put_acl(f: &Fixture, subject_path: &str, body: &str) -> axum::response::Response {
        let path = format!("/.aux{subject_path}.acl");
        let req = f.owner_request("PUT", &path)
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(body.to_owned())).unwrap();
        f.app.clone().oneshot(req).await.unwrap()
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

    // The residual from the previous round: an ACL is exempt from containment
    // (it is never listed via `ldp:contains`), but `authorize_and_materialize`
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
    // `authorize_and_materialize`'s `may_be_member` match on the `Target`
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
    // exist either. Before the existence check inside
    // `authorize_and_materialize` (see its doc comment), `aux::put` was the
    // only thing that ever said no here — and by the time it ran,
    // `authorize_and_materialize` had already created and linked `/a/` and
    // `/a/b/` for a write that was always going to be refused. A 404 that
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
        // document's own
        // acl:default — i.e. exactly the ancestor route the finding used.
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

    // The other half of `authorize_and_materialize`'s exemption, and the one
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
    // authorized on the target after his delegation is revoked:
    // `effective_acl("/box/doc")` finds that ACL directly, i.e. the document
    // Bob wrote about himself. That is precisely the case that matters — Bob
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
        container::remove_containment(f.store.as_ref(), &f.container("/box/"), doc.graph_iri())
            .await.unwrap();

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
        assert!(link.contains("https://pod.toph.so/.aux/foo.acl"));
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
            .contains("https://pod.toph.so/.aux/foo.acl"));
    }

    // An ACL resource does not advertise an ACL of its own — it is governed
    // by acl:Control on its subject resource, and /.aux/.aux/foo.acl.acl
    // never exists.
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
        let put_acl = f.owner_request("PUT", "/.aux/foo.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl_body)).unwrap();
        f.app.clone().oneshot(put_acl).await.unwrap();

        let get = f.owner_request("GET", "/.aux/foo.acl").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().get(header::LINK).is_none());
    }

    // A client must not string-derive an auxiliary URL, so the advertisement
    // has to arrive before the auxiliary exists — that is exactly the moment
    // it needs it, to create the first one.
    #[tokio::test]
    async fn the_acl_link_is_advertised_even_when_the_acl_does_not_exist() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo").header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);
        assert!(f.stored("/.aux/foo.acl").await.is_none(), "no ACL of its own yet");

        let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        let link = res.headers().get(header::LINK).unwrap().to_str().unwrap().to_string();
        assert!(link.contains("/.aux/foo.acl"), "{link}");
    }

    // SolidOS string-derives `<url>.acl` when this header is missing, and in
    // this pod's URI space that path is ordinary data, not a policy. A
    // create flow starts with a 404, so the 404 has to carry it.
    #[tokio::test]
    async fn the_acl_link_is_advertised_on_404_and_on_a_refusal() {
        let f = fixture().await;
        let get = f.owner_request("GET", "/nothing").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().get(header::LINK).is_some(),
            "SolidOS string-derives the ACL URL when this header is missing");

        let anon = Request::builder().method("GET").uri("/nothing").body(Body::empty()).unwrap();
        let res = f.app.oneshot(anon).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(header::LINK).is_some(),
            "a refusal must advertise it too — it is derived from the path, not the store");
    }

    // An empty ACL is a policy ("nothing is granted here"), not an absence
    // that falls back to the ancestor's wider rules. The owner locking
    // themselves out of a subtree is the honest consequence.
    #[tokio::test]
    async fn an_empty_acl_denies_instead_of_inheriting() {
        let f = fixture().await;
        let mk = f.owner_request("PUT", "/locked/").header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("")).unwrap();
        assert_eq!(f.app.clone().oneshot(mk).await.unwrap().status(), StatusCode::CREATED);
        let acl = f.owner_request("PUT", "/.aux/locked/.acl")
            .header(header::CONTENT_TYPE, "text/turtle").body(Body::from("")).unwrap();
        assert_eq!(f.app.clone().oneshot(acl).await.unwrap().status(), StatusCode::CREATED);

        let get = f.owner_request("GET", "/locked/").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(get).await.unwrap().status(), StatusCode::FORBIDDEN);
    }

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

    // The reserved namespace is server-understood, not storage: a path in it
    // that names no auxiliary names nothing at all, and no method may make
    // one exist there.
    #[tokio::test]
    async fn the_reserved_namespace_is_not_storage() {
        let f = fixture().await;
        for path in ["/.aux", "/.aux/", "/.aux/bogus/x"] {
            let put = f.owner_request("PUT", path).header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
            assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(),
                StatusCode::NOT_FOUND, "PUT {path} must not be storage");
            let get = f.owner_request("GET", path).body(Body::empty()).unwrap();
            assert_eq!(f.app.clone().oneshot(get).await.unwrap().status(),
                StatusCode::NOT_FOUND, "GET {path}");
            let del = f.owner_request("DELETE", path).body(Body::empty()).unwrap();
            assert_eq!(f.app.clone().oneshot(del).await.unwrap().status(),
                StatusCode::NOT_FOUND, "DELETE {path}");
        }
        // ...while a name that merely starts with the reserved one is the
        // user's, like any other.
        let put = f.owner_request("PUT", "/.auxiliary").header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.oneshot(put).await.unwrap().status(), StatusCode::CREATED);
    }
}
