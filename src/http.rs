//! The HTTP edge: every request path is classified once, by
//! [`StorageSpace::resolve`], and every handler dispatches on the [`Target`]
//! that comes back. No handler re-derives what kind of thing a URL names, and
//! none of them can: the lifecycle rules live in the types (`resource::` for
//! a subject, `aux::` for an auxiliary) rather than in a predicate each
//! handler has to remember to evaluate.

use std::sync::Arc;
use axum::{Router, routing::get, extract::{State, Path, RawQuery}, body::Bytes, Extension,
    http::{StatusCode, HeaderMap, HeaderValue, header, header::{IF_MATCH, IF_NONE_MATCH}}, response::{IntoResponse, Response}};
use oxigraph::model::{NamedNode, Quad, Triple};
use crate::{aux::{self, AuxError, AUX_SUBJECT_MISSING_MESSAGE}, container,
    dataset::{triples_of, Dataset, Skolemized},
    resource::{put_rdf, get_rdf, delete_rdf, exists, patch_dataset, put_dataset, put_blob, get_dataset, stored_media_type, kind_of, Kind, PatchResult, ResourceError},
    rdf::{Format, MediaType, Shape, negotiate, accept_allows},
    auth::{Agent, AuthConfig, JwksResolver, WebIdIssuerVerifier, auth_layer},
    space::{AuxKind, AuxUrl, ContainerUrl, GraphName, SpaceError, StorageSpace, Target},
    store::SparqlStore,
    wac::{guard::{authorize, authorize_and_materialize, deny}, pdp, AccessModes, Decision, Mode}};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn SparqlStore>,
    pub blobs: Arc<dyn crate::blob::BlobStore>,
    pub space: StorageSpace,
    pub resolver: Arc<dyn JwksResolver>,
    pub webid_verifier: Arc<dyn WebIdIssuerVerifier>,
    pub auth_config: Arc<AuthConfig>,
    pub max_body_bytes: usize,
}

pub fn router(state: AppState) -> Router {
    let max_body_bytes = state.max_body_bytes;
    // axum 0.8 wildcard capture syntax: "/{*path}" (NOT the old "/*path").
    //
    // `Router::layer` wraps everything built so far, so the LAST call is the
    // outermost: `cors_layer` sees the `401` that `auth_layer` produces, which
    // is where the CORS fields are required.
    Router::new()
        .route("/", get(handle_get_root).put(handle_put_root).post(handle_post_root).delete(handle_delete_root).patch(handle_patch_root).options(handle_options_root))
        .route("/{*path}", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete).patch(handle_patch).options(handle_options))
        .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_layer))
        .layer(axum::middleware::from_fn(cors_layer))
        .with_state(state)
}

/// The response headers a browser may read off a cross-origin response.
///
/// Enumerated rather than `*` because a wildcard names nothing a client can act
/// on, and because every field here is one some handler on this pod actually
/// emits. Both properties are asserted: `protocol/cors/enumerate-headers`
/// requires the header to be present and to differ from `*`.
const EXPOSED_HEADERS: &str =
    "Accept-Patch, Allow, Content-Type, ETag, Link, Location, Vary, WAC-Allow, Warning, WWW-Authenticate";

/// Reflect a request's `Origin` onto its response.
///
/// Wraps `auth_layer` rather than sitting inside it: the CORS fields are
/// required on the `401` that layer produces for an anonymous request
/// (`protocol/cors/simple-requests`), and a layer inside it never sees that
/// response.
///
/// No `Access-Control-Allow-Credentials`. This pod authenticates from an
/// `Authorization` header, which CORS treats as a request header to allow, not
/// as a credential to flag; the flag exists for cookies and TLS client
/// certificates, neither of which this pod accepts. That is what makes
/// reflecting an arbitrary origin safe here — the browser attaches no
/// credential of its own, so a foreign page can only send a token it already
/// holds, and a page holding the token never needed CORS to use it. Setting the
/// flag is the change that would make ambient authority usable against this
/// pod.
pub async fn cors_layer(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).cloned();
    let mut res = next.run(req).await;
    let Some(origin) = origin else { return res };
    let h = res.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    // `Origin` joins whatever `Vary` the handler already set — typically
    // `Accept` from a negotiated read — as **one field line**, not a second
    // one. Appending would be legal (RFC 9110 §5.3 lets a list-valued field
    // repeat) and still wrong in practice: a client that reads the first line
    // and stops sees half the list, and the conformance harness is such a
    // client. Replacing outright would be worse — a cache would then serve one
    // representation for every `Accept`.
    //
    // The spelling matters: the suite compares this field value as a
    // case-sensitive string, and `header::ORIGIN` is lowercase.
    let mut parts: Vec<String> = h
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    if !parts.iter().any(|p| p.eq_ignore_ascii_case("origin")) {
        parts.push("Origin".to_owned());
    }
    if let Ok(v) = HeaderValue::from_str(&parts.join(", ")) {
        h.insert(header::VARY, v);
    }
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSED_HEADERS),
    );
    res
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
        // `append`, not `insert`: a dataset-shaped resource read (§6.2)
        // already carries its own `Link` headers for `containsGraph` and
        // `alternate`, and `insert` would silently discard them.
        res.headers_mut().append(
            header::LINK,
            value.parse().expect("aux link value is header-safe"),
        );
    }
    res
}

/// The methods a target actually accepts, as an `Allow` field value.
///
/// Derived from the router's own shape rather than a fixed list: a container
/// is the only thing `POST` may address, and the root is the only container
/// `DELETE` refuses (`delete_impl`). `OPTIONS` is accepted everywhere — it
/// answers from the request URL alone and needs no representation to describe.
fn allowed_methods(target: &Target) -> &'static str {
    match target {
        Target::Container(c) if c.as_resource().parent().is_none() => "GET, HEAD, POST, PUT, PATCH, OPTIONS",
        Target::Container(_) => "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
        Target::Resource(_) | Target::Aux(_) => "GET, HEAD, PUT, PATCH, DELETE, OPTIONS",
    }
}

/// The one patch format this pod accepts. Protocol §5.3 makes advertising it a
/// MUST, and it travels with `Allow` because both answer "what may I do here?".
const ACCEPT_PATCH: &str = "text/n3";

/// Attach [`allowed_methods`] to a read that succeeded — Protocol §4.1 makes
/// it a MUST on `GET`/`HEAD` — alongside `Accept-Patch`.
fn with_allow(mut res: Response, target: &Target) -> Response {
    res.headers_mut().insert(
        header::ALLOW,
        allowed_methods(target).parse().expect("method list is header-safe"),
    );
    res.headers_mut().insert("accept-patch", HeaderValue::from_static(ACCEPT_PATCH));
    res
}

/// `WAC-Allow` as WAC defines it: what the requester may do on this resource,
/// and what an anonymous caller may do.
///
/// Both groups always appear. An empty group is `public=""` and not an omitted
/// group — the field parses into a list per group, and an absent group does not
/// yield the empty list a client (or the conformance suite) reads it as.
///
/// Modes are read through [`AccessModes::allows`], so a grant of `acl:Write`
/// reports `append` beside `write`. That is WAC's own subsumption rule, and the
/// suite pins it: its `read/write/append` case is checked for set equality, so
/// an answer missing `append` fails it.
fn wac_allow_value(decision: &Decision) -> String {
    fn group(m: AccessModes) -> String {
        [(Mode::Read, "read"), (Mode::Write, "write"),
         (Mode::Append, "append"), (Mode::Control, "control")]
            .iter()
            .filter(|(mode, _)| m.allows(*mode))
            .map(|(_, name)| *name)
            .collect::<Vec<_>>()
            .join(" ")
    }
    format!("user=\"{}\",public=\"{}\"", group(decision.user), group(decision.public))
}

/// The headers every successful read carries: the auxiliary advertisements,
/// the `Allow` Protocol §4.1 makes a MUST on `GET`/`HEAD`, and `WAC-Allow`.
///
/// One helper rather than three nested calls at four sites, so a read path
/// added later cannot pick up two of the three and still look right.
fn with_read_headers(res: Response, target: &Target, decision: &Decision) -> Response {
    let mut res = with_allow(with_aux_links(res, target), target);
    res.headers_mut().insert(
        "wac-allow",
        wac_allow_value(decision).parse().expect("mode names are header-safe"),
    );
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
        ResourceError::Store(_) | ResourceError::Blob(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> &str {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// Every `ETag` `target` currently answers with, one per representation —
/// what `If-Match`/`If-None-Match` compare against, since neither header
/// carries a format the way `Accept` does. `None` means the target does not
/// exist, which is what `If-None-Match: *` tests.
///
/// A [`Target::Resource`]'s validator embeds the format it labels (§6.4, RFC
/// 9110 §8.8.1: different representations are different entities), so there is
/// no single "the" tag to compare against. RFC 9110 §13.1.1 matches `If-Match`
/// against *any* current representation of the resource, so every format the
/// resource can be served as contributes one: a client that fetched it as
/// TriG and conditionally writes it back must not be told `412` forever
/// because the server compared against the Turtle tag instead.
///
/// Containers and auxiliaries never carry a named graph (§3.4 refuses that at
/// write time), but a client can still fetch them as any of the [`SERVABLE`]
/// formats, so they get the same treatment: one tag per format.
///
/// A binary resource has a single representation and therefore a single tag,
/// computed by [`blob_etag`] rather than drawn from this list.
const SERVABLE: [&str; 5] = [
    "text/turtle", "application/n-triples", "application/ld+json",
    "application/trig", "application/n-quads",
];

async fn current_tags(
    store: &dyn SparqlStore,
    blobs: &dyn crate::blob::BlobStore,
    target: &Target,
) -> Result<Option<Vec<String>>, ResourceError> {
    if let Target::Resource(r) = target {
        if let Some(Kind::Binary(_)) = kind_of(store, r).await? {
            let Some(key) = crate::blob::BlobKey::of(r) else {
                return Ok(None);
            };
            return Ok(blobs.get(&key).await?.map(|b| vec![blob_etag(&b)]));
        }
        let Some(stored) = get_dataset(store, r).await? else {
            return Ok(None);
        };
        // A format missing from `SERVABLE` can still be served but its
        // validator would never match, which is a legitimate conditional
        // write refused forever.
        return Ok(Some(
            SERVABLE.iter()
                .filter_map(|ct| Format::from_content_type(ct))
                .map(|f| stored.etag(f))
                .collect(),
        ));
    }
    let Some(triples) = get_rdf(store, target).await? else {
        return Ok(None);
    };
    let ground = ground_dataset(triples);
    Ok(Some(
        SERVABLE.iter()
            .filter_map(|ct| Format::from_content_type(ct))
            .map(|f| ground.etag(f))
            .collect(),
    ))
}

/// Lifts a container's or auxiliary's raw triples (always default-graph,
/// always ground — §3.4 and skolemization at the write path guarantee both)
/// into the same [`Skolemized`] type a resource's dataset is held as, so the
/// two paths share one `etag`/`deskolemize` implementation.
fn ground_dataset(triples: Vec<Triple>) -> Skolemized {
    let quads: Vec<Quad> = triples.into_iter()
        .map(|t| Quad::new(t.subject, t.predicate, t.object, oxigraph::model::GraphName::DefaultGraph))
        .collect();
    Skolemized::from_store(quads).expect("store content is ground by construction")
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

/// `PATCH` (`2026-07-30-n3-patch-design.md`). The sequence, which the plan fills
/// in this order and no other:
///
/// 1. `authorize(…, Mode::Append)` — before anything is parsed, so an
///    unauthorized caller learns nothing, and the returned `Decision` carries
///    the full mode set §9 needs.
/// 2. The `Content-Type` gate: `text/n3`, with `classify_body`'s split for a
///    missing type — `400` on a non-empty body, `415` on an empty one.
/// 3. `patch::Patch::parse` — `400` for unparseable N3 or a reserved IRI, `422`
///    for a shape violation.
/// 4. `RequiredModes::satisfied_by` against the decision already in hand. No
///    second ACL resolution.
/// 5. `kind_of` — a binary resource is `409`; the bytes are not triples.
/// 6. On a container, refuse a patch touching `ldp:contains` with `409`, through
///    the same `container::body_sets_containment` `put_impl` uses.
/// 7. `check_conditionals` — `412`.
/// 8. An absent target is patched against an empty dataset (§7): a patch that
///    asks nothing of the prior state — no conditions and no deletions — is a
///    creation through the `PUT` path, `create_by_patch` → `201`. A patch that
///    asks anything of it gets from the empty dataset the same `409` a target
///    without those triples gives, and no write. An existing target goes to
///    `resource::patch_dataset` → `204`, or the `409` its `PatchResult` names.
/// 9. On a container, `container::ensure_container` afterwards, exactly as
///    `put_impl` does — the server's type triples are its own, and a patch
///    that deleted them would otherwise leave the container untyped.
async fn patch_impl(
    st: AppState,
    agent: Agent,
    target: Target,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let store = st.store.as_ref();
    // Append is the weakest mode any patch §5.1 admits can need, and
    // `AccessModes::allows` makes Write subsume it — so this refuses exactly
    // those callers who could do nothing anyway, and it runs before the body
    // is looked at so an unauthorized caller learns nothing.
    let decision = match authorize(store, &agent, &target, Mode::Append).await {
        Ok(d) => d,
        Err(res) => return with_aux_links(res, &target),
    };

    let ct = header_str(&headers, header::CONTENT_TYPE).trim();
    if ct.is_empty() {
        return if body.is_empty() {
            StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
        } else {
            (StatusCode::BAD_REQUEST, "Content-Type is required").into_response()
        };
    }
    if MediaType::parse(ct).map(|m| m.essence()).as_deref() != Some("text/n3") {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }

    let patch = match crate::patch::Patch::parse(&body, target.graph_iri()) {
        Ok(p) => p,
        Err(e @ crate::patch::PatchError::Shape(_)) => {
            return (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response()
        }
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    // A shape-constrained container refuses every PATCH outright — see
    // `patch_shape_conflict` for why validating one is not an option. Checked
    // after the patch parses, so a malformed document still gets its own
    // answer, and after `authorize` above ran, so an unauthorized caller
    // learns nothing more than it already has.
    if let Err(res) = patch_shape_conflict(&st, &target).await {
        return res;
    }

    // §9: the modes this particular patch needs, against the set `authorize`
    // already resolved. `deny` rather than a second `authorize` — the answer
    // is in hand, and re-resolving would walk the ancestor chain again and
    // could read an ACL written in between.
    //
    // §8: not for an auxiliary. `authorize` substituted `Control` for it
    // regardless of the mode asked for, so asking again with modes derived
    // from the patch's parts would demand `Read` or `Write` on top of
    // `Control` — refusing an ACL patch from an agent WAC says may make it.
    if !matches!(target, Target::Aux(_)) && !patch.required_modes().satisfied_by(decision.user) {
        return with_aux_links(deny(&agent), &target);
    }

    // §8: `text/n3` is a perfectly good request body, so the conflict is with
    // the state of the target — bytes, which have no triples to patch.
    if let Target::Resource(r) = &target {
        match kind_of(store, r).await {
            Ok(Some(Kind::Binary(_))) => {
                return (StatusCode::CONFLICT, BINARY_TARGET_MESSAGE).into_response()
            }
            Ok(_) => {}
            Err(e) => return (put_status(&e), e.to_string()).into_response(),
        }
    }
    // Containment is server-managed, refused before anything is written for
    // the same reason `put_impl` refuses it there.
    if let Target::Container(c) = &target {
        if let Some(conflict) = patch_sets_containment(&patch, c) {
            return (StatusCode::CONFLICT, conflict.message()).into_response();
        }
    }
    if let Err(res) = check_conditionals(store, st.blobs.as_ref(), &headers, &target).await {
        return res;
    }
    // An auxiliary is written through `aux`, whose subject-existence guard is
    // what keeps a policy document off a path that names nothing, and it
    // answers the same `404` `put_impl` does when the subject is gone. It
    // takes its own branch here because the `exists` check below is not the
    // one it needs: §7's creation path is closed for an auxiliary as well, and
    // `aux::patch` refuses an absent one itself, with a body that says which
    // of the two is missing.
    let r = match &target {
        Target::Resource(r) => r,
        Target::Container(c) => c.as_resource(),
        Target::Aux(a) => {
            return match aux::patch(store, a, &patch).await {
                Ok(result) => patch_response(result, &patch),
                Err(AuxError::SubjectMissing) => {
                    (StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response()
                }
                Err(e @ AuxError::Missing) => {
                    (StatusCode::NOT_FOUND, e.to_string()).into_response()
                }
                Err(AuxError::Resource(e)) => (put_status(&e), e.to_string()).into_response(),
            }
        }
    };
    match exists(store, &target).await {
        Ok(true) => {}
        Ok(false) => return create_by_patch(&st, &agent, &target, &patch).await,
        Err(e) => return (put_status(&e), e.to_string()).into_response(),
    }
    match patch_dataset(store, r, &patch).await {
        // A container's type triples are the server's, and a patch names its
        // own triples — including them. Re-asserting them here is what
        // `put_impl` does after writing a container body, and it is why a
        // container patch is not refused outright: the client stays free to
        // patch everything else the container's graph holds.
        Ok(result) => match &target {
            Target::Container(c) => match container::ensure_container(store, c).await {
                Ok(()) => patch_response(result, &patch),
                Err(e) => (put_status(&e), e.to_string()).into_response(),
            },
            _ => patch_response(result, &patch),
        },
        Err(e) => (put_status(&e), e.to_string()).into_response(),
    }
}

/// §7: a target that does not exist is patched against an empty RDF dataset,
/// so a patch that asks nothing of the prior state creates it — through the
/// same [`authorize_and_materialize`] walk, the same containment linking and
/// the same [`created`] response `PUT` uses. There is no second creation path.
///
/// A patch creates only when the empty dataset answers everything it asks:
/// [`crate::patch::Patch::ground_insertions`] is `Some` exactly when it has no
/// conditions, and it must delete nothing. Either part unmet is §6's `409` and
/// touches nothing — a condition finds no mapping in an empty dataset, and a
/// triple to delete is not in one either.
///
/// The media type recorded for a resource created this way is `text/turtle`:
/// a patch declares no representation format, and Turtle is what negotiation
/// falls back to.
///
/// Only a resource or a container reaches here. An auxiliary is answered by
/// `aux::patch`, which refuses an absent one itself.
async fn create_by_patch(
    st: &AppState,
    agent: &Agent,
    target: &Target,
    patch: &crate::patch::Patch,
) -> Response {
    let store = st.store.as_ref();
    let Some(triples) = patch.ground_insertions() else {
        return patch_response(PatchResult::NoMapping, patch);
    };
    if !patch.deletions().is_empty() {
        return patch_response(PatchResult::DeletionMissing, patch);
    }
    if let Err(res) = authorize_and_materialize(store, agent, target).await {
        return with_aux_links(res, target);
    }
    let written = match target {
        Target::Resource(r) => {
            let turtle =
                Format::from_content_type("text/turtle").expect("text/turtle is an RDF format");
            put_dataset(store, st.blobs.as_ref(), r, &ground_dataset(triples), turtle).await
        }
        // A container's graph carries the server's own type triples, so it is
        // written the way `put_impl` writes one rather than through
        // `put_dataset`, which §3.4 keeps containers off. There is no existing
        // containment to preserve: nothing was there to contain anything.
        Target::Container(c) => match put_rdf(store, c, &triples).await {
            Ok(()) => container::ensure_container(store, c).await,
            Err(e) => Err(e),
        },
        Target::Aux(_) => unreachable!("an auxiliary never reaches the creation branch"),
    };
    match written {
        Ok(()) => created(target),
        Err(e) => (put_status(&e), e.to_string()).into_response(),
    }
}

/// §6's outcomes as HTTP: applied is `204`, and each refusal is the `409` that
/// names the part of the patch it was about. One function, because a target
/// whose patch is refused for a reason the other target reports differently is
/// a difference no client could explain.
fn patch_response(result: PatchResult, patch: &crate::patch::Patch) -> Response {
    match result {
        PatchResult::Applied => StatusCode::NO_CONTENT.into_response(),
        PatchResult::NoMapping => {
            patch_conflict("nothing matches the conditions", patch.conditions())
        }
        PatchResult::SeveralMappings => {
            patch_conflict("more than one mapping satisfies the conditions", patch.conditions())
        }
        PatchResult::DeletionMissing => {
            patch_conflict("a triple this patch deletes is not there", patch.deletions())
        }
    }
}

const BINARY_TARGET_MESSAGE: &str =
    "this resource holds bytes rather than triples, so there is nothing to patch";

const CONTAINMENT_MESSAGE: &str = "ldp:contains is server-managed";

const CONTAINMENT_VARIABLE_PREDICATE_MESSAGE: &str =
    "a variable predicate on a container may bind ldp:contains, which is server-managed";

/// Why a patch on a container is refused for touching containment.
enum ContainmentConflict {
    /// The patch names `ldp:contains` as a ground predicate.
    Ground,
    /// A pattern's predicate is a variable, which could bind `ldp:contains`
    /// even though nothing in the patch names it.
    VariablePredicate,
}

impl ContainmentConflict {
    fn message(&self) -> &'static str {
        match self {
            Self::Ground => CONTAINMENT_MESSAGE,
            Self::VariablePredicate => CONTAINMENT_VARIABLE_PREDICATE_MESSAGE,
        }
    }
}

/// Whether a patch would write the containment triples the server manages,
/// and why.
///
/// Over the insertions and the deletions both — unlinking a member forges the
/// container's contents exactly as inserting one does — and over the patterns
/// rather than over what they would bind to, because the refusal has to land
/// before the write.
///
/// [`container::body_sets_containment`] reads the predicate and nothing else,
/// so each pattern is offered to it as a triple whose subject and object are
/// the container itself: positions that check never looks at. A pattern whose
/// predicate is not an IRI has no triple form at all and can still bind to
/// `ldp:contains`, so it is refused without asking.
fn patch_sets_containment(patch: &crate::patch::Patch, c: &ContainerUrl) -> Option<ContainmentConflict> {
    let iri = NamedNode::new(c.graph_iri()).expect("a container's IRI is valid");
    let mut written = Vec::new();
    for p in patch.insertions().iter().chain(patch.deletions()) {
        let crate::patch::PatternTerm::Named(predicate) = &p.predicate else {
            return Some(ContainmentConflict::VariablePredicate);
        };
        written.push(Triple::new(iri.clone(), predicate.clone(), iri.clone()));
    }
    container::body_sets_containment(&written).then_some(ContainmentConflict::Ground)
}

/// A `409` that names the patterns it is about (§6.4).
///
/// The patterns are the client's own words, and they are all a message ever
/// carries: a *binding* may be a skolem IRI the client has never seen, while a
/// pattern cannot be one — `Patch::parse` refuses any document that names the
/// reserved namespace.
fn patch_conflict(reason: &str, patterns: &[crate::patch::Pattern]) -> Response {
    (StatusCode::CONFLICT, format!("{reason}: {}", show_patterns(patterns))).into_response()
}

/// Triple patterns as message text — never as SPARQL, which
/// `resource::patch_dataset` builds for itself. A variable prints by its
/// index: the name the client chose does not leave `patch` (§6.1).
fn show_patterns(patterns: &[crate::patch::Pattern]) -> String {
    patterns
        .iter()
        .map(|p| {
            format!(
                "{} {} {} .",
                show_term(&p.subject), show_term(&p.predicate), show_term(&p.object)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn show_term(t: &crate::patch::PatternTerm) -> String {
    match t {
        crate::patch::PatternTerm::Named(n) => n.to_string(),
        crate::patch::PatternTerm::Literal(l) => l.to_string(),
        crate::patch::PatternTerm::Var(i) => format!("?v{i}"),
    }
}

async fn handle_patch(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    headers: HeaderMap, body: Bytes,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) => patch_impl(st, agent, target, headers, body).await,
        Err(status) => status.into_response(),
    }
}

async fn handle_patch_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>, headers: HeaderMap, body: Bytes,
) -> Response {
    match classify(&st.space, "/") {
        Ok(target) => patch_impl(st, agent, target, headers, body).await,
        Err(status) => status.into_response(),
    }
}

/// What a request body is, once its `Content-Type` has been read.
enum Repr {
    Rdf(Dataset, Format),
    Blob(Bytes, MediaType),
}

/// §8.1: the three-way gate. `Err` is the response to send.
///
/// The order matters. A missing `Content-Type` on a request with content is
/// Solid Protocol §2.2's `400` and is answered before anything else, because
/// it is a different failure from a type this pod cannot use — a distinction
/// that only exists now that an unrecognised type is a blob rather than a
/// refusal.
///
/// The error is boxed for `clippy::result_large_err`, which measures the
/// `Err` type: `Response` is large, and boxing it keeps `Result<Repr, _>`
/// from being sized by it.
fn classify_body(headers: &HeaderMap, body: &Bytes, target: &Target) -> Result<Repr, Box<Response>> {
    let ct = header_str(headers, header::CONTENT_TYPE).trim();
    if ct.is_empty() {
        if !body.is_empty() {
            return Err(Box::new((StatusCode::BAD_REQUEST, "Content-Type is required").into_response()));
        }
        return Err(Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()));
    }
    if let Some(fmt) = Format::from_content_type(ct) {
        return match fmt.parse(body, target.graph_iri()) {
            Ok(d) => Ok(Repr::Rdf(d, fmt)),
            Err(e) => Err(Box::new((StatusCode::BAD_REQUEST, e.to_string()).into_response())),
        };
    }
    let Some(mt) = MediaType::parse(ct) else {
        return Err(Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()));
    };
    match target {
        // §8.5: an auxiliary is a policy document the PDP has to read, and a
        // container's representation carries server-managed containment.
        Target::Aux(_) => Err(Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response())),
        Target::Container(_) => Err(Box::new((
            StatusCode::BAD_REQUEST,
            "a container's representation must be RDF",
        ).into_response())),
        Target::Resource(_) => Ok(Repr::Blob(body.clone(), mt)),
    }
}

/// RFC 9110 §13.1.1 preconditions, shared by both kinds of write.
async fn check_conditionals(
    store: &dyn SparqlStore,
    blobs: &dyn crate::blob::BlobStore,
    headers: &HeaderMap,
    target: &Target,
) -> Result<(), Response> {
    if !headers.contains_key(IF_MATCH) && !headers.contains_key(IF_NONE_MATCH) {
        return Ok(());
    }
    let current_tags = match current_tags(store, blobs, target).await {
        Ok(t) => t,
        Err(e) => return Err((put_status(&e), e.to_string()).into_response()),
    };
    if let Some(im) = headers.get(IF_MATCH).and_then(|v| v.to_str().ok()) {
        // RFC 9110 §13.1.1: `If-Match` matches *any* current representation,
        // not the one the server would have picked.
        if !current_tags.as_ref().is_some_and(|ts| ts.iter().any(|t| t == im)) {
            return Err(StatusCode::PRECONDITION_FAILED.into_response());
        }
    }
    if headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some("*")
        && current_tags.is_some()
    {
        return Err(StatusCode::PRECONDITION_FAILED.into_response());
    }
    Ok(())
}

/// Validate a body against the shape its container binds, if any.
///
/// `Err` is the response to send; `Ok(Some(report))` is a write that may
/// proceed but has findings to advertise; `Ok(None)` is an unconstrained
/// write. Auxiliaries are never validated — an ACL is server-understood data
/// with its own rules.
async fn enforce_shape(
    st: &AppState,
    target: &Target,
    dataset: &crate::dataset::Dataset,
) -> Result<Option<crate::shapes::Report>, Response> {
    let container = match target {
        Target::Aux(_) => return Ok(None),
        Target::Resource(r) => r.parent(),
        Target::Container(c) => c.as_resource().parent(),
    };
    let Some(container) = container else {
        return Ok(None); // the root container has no parent to constrain it
    };
    let shapes = match crate::shapes::load(st.store.as_ref(), &st.space, &container).await {
        Ok(None) => return Ok(None),
        Ok(Some(s)) => s,
        Err(e) => return Err(shape_status(e)),
    };
    let report = match crate::shapes::validate(&shapes.turtle, dataset) {
        Ok(r) => r,
        Err(e) => return Err(shape_status(e)),
    };
    if report.refuses() {
        let body = turtle_bytes(&report.into_dataset());
        let mut res = (
            StatusCode::UNPROCESSABLE_ENTITY,
            [(header::CONTENT_TYPE, "text/turtle")],
            body,
        )
            .into_response();
        // §3.1: the shape is the document that explains the refusal, so the
        // refusal names it.
        if let Ok(v) = HeaderValue::from_str(&format!(
            "<{}>; rel=\"http://www.w3.org/ns/ldp#constrainedBy\"", shapes.iri
        )) {
            res.headers_mut().append(header::LINK, v);
        }
        return Err(res);
    }
    Ok(if report.is_empty() { None } else { Some(report) })
}

/// Whether `target`'s parent container binds a shape — and if it does, the
/// `409` that refuses a `PATCH` outright, without attempting to validate it.
///
/// A patch is applied as one SPARQL update whose `WHERE` clause carries the
/// deletion-presence check, so the graph a patch produces never exists as a
/// [`crate::dataset::Dataset`] in this process — there is nothing for
/// [`crate::shapes::validate`] to run against. Checking only the insertions
/// would be cheap, but wrong: a `sh:Violation` can be produced by a deletion
/// as readily as by an insertion (removing the one triple that satisfied an
/// `sh:minCount`, say), so a check that saw only what was added would pass
/// patches it should refuse. Refusing the whole request is the answer that
/// stays honest; `PUT` is how a shape-constrained container gets a validated
/// write.
///
/// An auxiliary's own container is never asked, mirroring `enforce_shape` for
/// the same reason: an ACL is never validated, and a shape must not be able
/// to lock one.
async fn patch_shape_conflict(st: &AppState, target: &Target) -> Result<(), Response> {
    let container = match target {
        Target::Aux(_) => return Ok(()),
        Target::Resource(r) => r.parent(),
        Target::Container(c) => c.as_resource().parent(),
    };
    let Some(container) = container else {
        return Ok(()); // the root container has no parent to constrain it
    };
    match crate::shapes::load(st.store.as_ref(), &st.space, &container).await {
        Ok(None) => Ok(()),
        Ok(Some(shape)) => Err((
            StatusCode::CONFLICT,
            format!(
                "{} is shape-constrained (by {}); a PATCH cannot be validated against a \
                 shape, so it is refused rather than risk writing a state the shape does \
                 not allow — PUT a full representation to write a validated one",
                container.graph_iri(),
                shape.iri,
            ),
        )
            .into_response()),
        Err(e) => Err(shape_status(e)),
    }
}

/// The response a shape lookup or validation failure earns.
///
/// The split is whose fault it is. Only parsing the constraint document reads
/// something an author wrote, so only that is a `409` telling them to fix it;
/// the engine failing, or this pod failing to serialize or re-read its own
/// output, is a `500`. One function, so the two cannot drift apart.
fn shape_status(e: crate::shapes::ShapeError) -> Response {
    use crate::shapes::ShapeError;
    let message = e.to_string();
    let status = match &e {
        ShapeError::Resource(r) => put_status(r),
        ShapeError::Engine(_) => StatusCode::INTERNAL_SERVER_ERROR,
        ShapeError::Unparsable(_) | ShapeError::Unsupported(_) | ShapeError::Missing => {
            StatusCode::CONFLICT
        }
    };
    (status, message).into_response()
}

/// A dataset as Turtle, for an error body. Not negotiated: `Accept` describes
/// the target's representation, and this is not that.
fn turtle_bytes(dataset: &crate::dataset::Dataset) -> Vec<u8> {
    crate::rdf::Format::from_content_type("text/turtle")
        .expect("text/turtle is one of the five formats")
        .serialize(dataset)
        .unwrap_or_default()
}

/// A `describedby` link to the resource's validation report.
fn report_link(target: &Target, mut res: Response) -> Response {
    let path = match target {
        Target::Resource(r) => r.path().to_owned(),
        Target::Container(c) => c.path().to_owned(),
        Target::Aux(_) => return res,
    };
    if let Ok(v) = HeaderValue::from_str(&format!("<{path}?validate>; rel=\"describedby\"")) {
        res.headers_mut().append(header::LINK, v);
    }
    res
}

async fn put_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap, body: Bytes) -> Response {
    let store = st.store.as_ref();
    if let Err(res) = authorize(store, &agent, &target, Mode::Write).await {
        return with_aux_links(res, &target);
    }
    let repr = match classify_body(&headers, &body, &target) {
        Ok(r) => r,
        Err(res) => return *res,
    };
    let (dataset, fmt) = match repr {
        Repr::Rdf(d, f) => (d, f),
        Repr::Blob(bytes, mt) => {
            // A blob has none of the dataset checks below to run: no named
            // graphs, no reserved namespace, no containment triples. It does
            // share the conditional-request block and the ancestor walk, so
            // it runs them itself rather than falling through to where the
            // RDF path runs them.
            let Target::Resource(r) = &target else {
                unreachable!("classify_body refuses a blob for any other target")
            };
            if crate::blob::BlobKey::of(r).is_none() {
                return StatusCode::URI_TOO_LONG.into_response();
            }
            if let Err(res) = check_conditionals(store, st.blobs.as_ref(), &headers, &target).await {
                return res;
            }
            if let Err(res) = authorize_and_materialize(store, &agent, &target).await {
                return with_aux_links(res, &target);
            }
            return match put_blob(store, st.blobs.as_ref(), r, bytes, &mt).await {
                Ok(()) => created(&target),
                Err(ResourceError::KeyTooLong) => StatusCode::URI_TOO_LONG.into_response(),
                Err(e) => (put_status(&e), e.to_string()).into_response(),
            };
        }
    };
    // §3.2.2 — the skolem namespace is the server's.
    if dataset.uses_reserved_namespace() {
        return (StatusCode::BAD_REQUEST, "the urn:quadpod: namespace is reserved").into_response();
    }
    // §3.4 — a container's graph carries containment; an auxiliary's rules
    // would be invisible to WAC inside a subgraph.
    if dataset.has_named_graphs() && !matches!(target, Target::Resource(_)) {
        return (StatusCode::BAD_REQUEST, "named graphs are only allowed on resources").into_response();
    }
    // Containment is server-managed. Refused here, before the ancestor walk
    // below writes anything, so a rejected PUT cannot leave a containment
    // triple pointing at a container it never created. Over the whole
    // dataset, not the default graph: otherwise the 409 is bypassed by
    // putting ldp:contains in a named graph.
    if matches!(target, Target::Container(_)) && container::body_sets_containment(&triples_of(&dataset)) {
        return StatusCode::CONFLICT.into_response();
    }
    // §6.2.1 — a graph-format write must not silently discard what a graph
    // format could not have shown the client in the first place.
    if let Target::Resource(r) = &target {
        if !fmt.carries_dataset() {
            // A store error is not "no named graphs": reading it that way lets
            // the overwrite this check exists to refuse proceed on exactly the
            // request the check could not evaluate.
            let existing = match get_dataset(store, r).await {
                Ok(v) => v,
                Err(e) => return (put_status(&e), e.to_string()).into_response(),
            };
            if let Some(existing) = existing {
                // Over the stored quads, where every graph name is an IRI. A
                // graph the client named with a blank node is destroyed by
                // this write just as surely, and the de-skolemized view shows
                // it as a blank node again — invisible to `Dataset::named_graphs`.
                if existing.has_named_graphs() {
                    // Only IRI names go in the message: a blank-named graph
                    // has no name the client ever wrote, and the IRI the
                    // server minted for it is not the client's to see
                    // (§3.2.2). It is still counted, so the refusal accounts
                    // for everything it is refusing to destroy.
                    let named = existing.deskolemize().named_graphs();
                    let mut parts: Vec<String> =
                        named.iter().map(|n| n.as_str().to_owned()).collect();
                    let blank_named = existing.named_graphs().len() - parts.len();
                    if blank_named > 0 {
                        parts.push(format!("{blank_named} named by a blank node"));
                    }
                    let list = parts.join(", ");
                    return (StatusCode::CONFLICT, format!(
                        "this resource has named graphs ({list}) that {} cannot carry; \
                         write it as application/trig or application/ld+json, or DELETE it first",
                        fmt.media_type()
                    )).into_response();
                }
            }
        }
    }
    let skolemized = Skolemized::skolemize(&dataset);
    if let Err(res) = check_conditionals(store, st.blobs.as_ref(), &headers, &target).await {
        return res;
    }
    let findings = match enforce_shape(&st, &target, &dataset).await {
        Ok(f) => f,
        Err(res) => return res,
    };
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
    let res = match &target {
        // An auxiliary exists only for an existing subject, and that rule is
        // inside `aux::put`'s update rather than a check here — a check and a
        // write are two round-trips, and an interleaved DELETE between them
        // would plant a policy document on a path that no longer exists.
        Target::Aux(a) => {
            let triples = triples_of(&dataset.default_graph_only());
            match aux::put(store, a, &triples).await {
                Ok(()) => warn_if_acl_grants_nothing(&st.space, a, &triples, created(&target)),
                Err(AuxError::SubjectMissing) =>
                    (StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response(),
                // Unreachable: `put` writes the auxiliary, so it never asks
                // for one that is already there.
                Err(AuxError::Missing) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                Err(AuxError::Resource(e)) => (put_status(&e), e.to_string()).into_response(),
            }
        }
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
            let mut merged = triples_of(&dataset.default_graph_only());
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
        Target::Resource(r) => match put_dataset(store, st.blobs.as_ref(), r, &skolemized, fmt).await {
            Ok(()) => created(&target),
            Err(e) => (put_status(&e), e.to_string()).into_response(),
        },
    };
    // The link describes the stored representation. `Target::Resource`'s
    // `Err` arm above is a tail expression flowing into `res` exactly like
    // its `Ok` arm, so findings alone cannot gate the link: a body that only
    // warned, followed by a `put_dataset` failure, would otherwise still
    // advertise a report for a write that stored nothing.
    if findings.is_some() && res.status().is_success() { report_link(&target, res) } else { res }
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
    let subject = match child {
        Target::Resource(r) => r,
        // A `Link: rel="type"` can make the allocated child a container, and
        // the pair rule reads the same from that side.
        Target::Container(c) => c.as_resource(),
        Target::Aux(_) => return false,
    };
    match subject.slash_counterpart() {
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
    let slug = headers.get("slug").and_then(|v| v.to_str().ok());
    // A settled child name contains no `/`, so the child of a container is
    // always an ordinary resource — unless the server would have to allocate
    // it inside the reserved namespace (`Slug: .aux` at the root), which
    // `classify` refuses. A `Slug` can therefore never name an auxiliary.
    //
    // A `Link: rel="type"` naming a container asks for one, and under Solid
    // §3.1 the trailing slash is the *only* thing that tells the two apart —
    // so it is appended as a separate `suffix`, and the name it decorates
    // stays a bare segment. Anything that has to vary the name varies that
    // segment and re-applies the suffix; folding the slash into the name would
    // put the retry *inside* the container instead of beside it.
    let wants_container =
        container::type_link_requests_container(header_str(&headers, header::LINK));
    let suffix = if wants_container { "/" } else { "" };
    let name = container::child_name(slug);
    let mut child = match classify(&st.space, &format!("{}{name}{suffix}", parent.path())) {
        Ok(t) => t,
        Err(status) => return status.into_response(),
    };
    // Note: this existence check followed by the write below is not
    // transactional; a concurrent write landing between them could be missed.
    // Accepted for single-user v1.
    if name_is_taken(store, &child).await {
        let unique = format!("{name}-{}{suffix}", uuid::Uuid::new_v4());
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
    let repr = match classify_body(&headers, &body, &child) {
        Ok(r) => r,
        Err(res) => return *res,
    };
    // The dataset checks below have no meaning for a blob: no named graphs,
    // no reserved namespace, no containment triples. It gets its own
    // over-long-key check instead, run here for the same reason the dataset
    // checks are — before the ancestor walk below writes anything.
    let mut findings = None;
    let skolemized = match &repr {
        Repr::Rdf(dataset, _) => {
            // §3.2.2 — the skolem namespace is the server's.
            if dataset.uses_reserved_namespace() {
                return (StatusCode::BAD_REQUEST, "the urn:quadpod: namespace is reserved").into_response();
            }
            // §3.4 — the allocated child is always a resource or a container
            // (never an auxiliary, see above), so this is exactly `put_impl`'s check.
            if dataset.has_named_graphs() && !matches!(child, Target::Resource(_)) {
                return (StatusCode::BAD_REQUEST, "named graphs are only allowed on resources").into_response();
            }
            // Containment is server-managed, for a container POST asks for
            // exactly as much as for one a PUT names — and refused before
            // anything is written, for the same reason.
            if matches!(child, Target::Container(_)) && container::body_sets_containment(&triples_of(dataset)) {
                return StatusCode::CONFLICT.into_response();
            }
            // Against the settled child, not the requested slug: the binding
            // lives on the child's parent, which for a POST is the container
            // this request targets, and refusing here — before the ancestor
            // walk below creates anything — leaves nothing behind to clean up.
            findings = match enforce_shape(&st, &child, dataset).await {
                Ok(f) => f,
                Err(res) => return res,
            };
            Some(Skolemized::skolemize(dataset))
        }
        Repr::Blob(..) => {
            let Target::Resource(r) = &child else {
                unreachable!("classify_body refuses a blob for a non-resource target")
            };
            if crate::blob::BlobKey::of(r).is_none() {
                return StatusCode::URI_TOO_LONG.into_response();
            }
            None
        }
    };
    // POSTing into a container that does not exist yet materializes it and
    // its missing ancestors, so those need authorizing too — the same single
    // traversal `put_impl` uses.
    if let Err(res) = authorize_and_materialize(store, &agent, &child).await {
        return with_aux_links(res, &child);
    }
    let res = match &child {
        Target::Resource(r) => match repr {
            Repr::Blob(bytes, mt) => match put_blob(store, st.blobs.as_ref(), r, bytes, &mt).await {
                Ok(()) => created(&child),
                Err(ResourceError::KeyTooLong) => StatusCode::URI_TOO_LONG.into_response(),
                Err(e) => (put_status(&e), e.to_string()).into_response(),
            },
            Repr::Rdf(_, fmt) => {
                let skolemized = skolemized.expect("Repr::Rdf produced a skolemized dataset above");
                match put_dataset(store, st.blobs.as_ref(), r, &skolemized, fmt).await {
                    Ok(()) => created(&child),
                    Err(e) => (put_status(&e), e.to_string()).into_response(),
                }
            }
        },
        // A freshly allocated name, so there are no members to preserve — the
        // read-then-merge `put_impl` does for an existing container has
        // nothing to read here.
        Target::Container(c) => {
            let Repr::Rdf(dataset, _) = &repr else {
                unreachable!("classify_body refuses a blob for Target::Container")
            };
            let triples = triples_of(&dataset.default_graph_only());
            match put_rdf(store, c, &triples).await {
                Ok(()) => match container::ensure_container(store, c).await {
                    Ok(()) => created(&child),
                    Err(e) => (put_status(&e), e.to_string()).into_response(),
                },
                Err(e) => (put_status(&e), e.to_string()).into_response(),
            }
        }
        // Unreachable: a `Slug` can never name an auxiliary (see above), and
        // the only other shape `classify` can return for a child path is the
        // container the `Link` header asks for.
        Target::Aux(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    // Mirrors `put_impl`'s tail: findings alone cannot gate the link, or a
    // body that only warned, followed by a storage failure, would advertise a
    // report for a child that was never created.
    if findings.is_some() && res.status().is_success() { report_link(&child, res) } else { res }
}

/// Answer a CORS preflight — and a bare `OPTIONS`, which the suite also sends
/// (`protocol/cors/acao-vary` omits `Access-Control-Request-Method`).
///
/// Deliberately unauthorized. A preflight arrives without credentials by
/// construction, so demanding them makes a pod unusable from a browser; and
/// the answer is derived entirely from the request URL's shape —
/// [`allowed_methods`] takes a [`Target`] and never reaches the store — so it
/// discloses nothing about what exists. That is the line `post_impl` already
/// draws when it answers `409` from the path shape rather than let `POST`
/// become an existence oracle.
///
/// `Access-Control-Allow-Headers` mirrors what was asked for rather than
/// naming a fixed set: `protocol/cors/accept-acah` sends two otherwise
/// identical preflights and requires `Accept` to be absent from the answer to
/// the one that did not request it.
fn options_impl(target: &Target, headers: &HeaderMap) -> Response {
    let mut out = HeaderMap::new();
    let methods = allowed_methods(target);
    out.insert(header::ALLOW, HeaderValue::from_static(methods));
    out.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(methods));
    out.insert("accept-patch", HeaderValue::from_static(ACCEPT_PATCH));
    if let Some(requested) = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
    }
    (StatusCode::NO_CONTENT, out).into_response()
}

async fn handle_options(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) => options_impl(&target, &headers),
        Err(status) => status.into_response(),
    }
}

async fn handle_options_root(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match classify(&st.space, "/") {
        Ok(target) => options_impl(&target, &headers),
        Err(status) => status.into_response(),
    }
}

async fn handle_get(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    RawQuery(query): RawQuery, headers: HeaderMap,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) if wants_validation(query.as_deref()) =>
            validate_view(st, agent, target, headers).await,
        Ok(target) => get_impl(st, agent, target, headers).await,
        Err(status) => status.into_response(),
    }
}

async fn handle_get_root(
    State(st): State<AppState>, Extension(agent): Extension<Agent>,
    RawQuery(query): RawQuery, headers: HeaderMap,
) -> Response {
    match classify(&st.space, "/") {
        Ok(target) if wants_validation(query.as_deref()) =>
            validate_view(st, agent, target, headers).await,
        Ok(target) => get_impl(st, agent, target, headers).await,
        Err(status) => status.into_response(),
    }
}

/// Whether this request asks for the validation report rather than the
/// resource. The only query parameter this pod gives meaning to; every other
/// parameter — including a near-miss like `?validat` — is ignored and the
/// resource itself is served, exactly as before this parameter existed.
fn wants_validation(query: Option<&str>) -> bool {
    query.is_some_and(|q| q.split('&').any(|p| p == "validate"))
}

/// The current validation report for `target`, computed now and never
/// stored: nothing here can go stale, because the report always describes
/// the representation and the shape exactly as they are at the moment of the
/// request.
async fn validate_view(
    st: AppState, agent: Agent, target: Target, headers: HeaderMap,
) -> Response {
    let store = st.store.as_ref();
    if let Err(res) = authorize(store, &agent, &target, Mode::Read).await {
        return with_aux_links(res, &target);
    }
    // The container whose `ldp:constrainedBy` binds a shape to `target` —
    // its parent, the same lookup a write validates against (§3.2).
    let container = match &target {
        Target::Aux(_) => return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Target::Resource(r) => r.parent(),
        Target::Container(c) => c.as_resource().parent(),
    };
    let Some(container) = container else {
        return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target);
    };
    let shapes = match crate::shapes::load(store, &st.space, &container).await {
        Ok(None) => return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Ok(Some(s)) => s,
        Err(e) => return shape_status(e),
    };
    // `target`'s own content — what the shape is validated against.
    let dataset = match &target {
        // §5.3: a blob has no triples, so it is never validated — the same
        // "no report here" answer as an unconstrained resource, not a
        // vacuous `sh:conforms true` for a representation SHACL never saw.
        Target::Resource(r) if matches!(kind_of(store, r).await, Ok(Some(Kind::Binary(_)))) =>
            return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Target::Resource(r) => match get_dataset(store, r).await {
            Ok(Some(d)) => d.deskolemize(),
            Ok(None) => return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
            Err(e) => return (put_status(&e), e.to_string()).into_response(),
        },
        Target::Container(c) => match get_rdf(store, c).await {
            // Minus what this pod adds on write — `ldp:contains` and the
            // type triples `ensure_container` asserts — so this is exactly
            // the graph a write into `c` was validated against (§3.4). The
            // full stored graph would let a shape targeting those
            // server-managed triples report `Violation` here while every
            // write into `c` keeps succeeding, which is a contradiction no
            // client can act on (§10: `ldp:contains` is never in a data
            // graph here).
            Ok(Some(t)) =>
                ground_dataset(container::without_server_managed(t, c.graph_iri())).deskolemize(),
            Ok(None) => return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
            Err(e) => return (put_status(&e), e.to_string()).into_response(),
        },
        Target::Aux(_) => unreachable!("an auxiliary already returned above"),
    };
    let report = match crate::shapes::validate(&shapes.turtle, &dataset) {
        Ok(r) => r,
        Err(e) => return shape_status(e),
    };
    let accept = header_str(&headers, header::ACCEPT);
    let Some(fmt) = negotiate(accept, Shape::Graph, None) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    match fmt.serialize(&report.into_dataset()) {
        Ok(bytes) => {
            let mut out = HeaderMap::new();
            out.insert(header::CONTENT_TYPE, fmt.media_type().parse().expect("static media type"));
            out.insert(header::VARY, "Accept".parse().expect("static"));
            (out, bytes).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// §3.4: the validator for a blob, computed from the bytes about to be served.
///
/// Not `ObjectMeta::e_tag`: it is optional, its meaning differs per backend,
/// and it changes under a backend migration although the content did not. This
/// is the same rule and the same shape as
/// [`Skolemized::etag`](crate::dataset::Skolemized::etag).
fn blob_etag(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("\"{}\"", hex::encode(h.finalize()))
}

/// §6: a blob's representation. `Accept` is an acceptability test rather than
/// a negotiation, because there is only one representation to offer.
async fn blob_read(st: AppState, target: Target, headers: HeaderMap, mt: MediaType) -> Response {
    let Target::Resource(r) = &target else {
        unreachable!("only a resource can be binary")
    };
    if !accept_allows(header_str(&headers, header::ACCEPT), &mt) {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    let Some(key) = crate::blob::BlobKey::of(r) else {
        return StatusCode::URI_TOO_LONG.into_response();
    };
    let bytes = match st.blobs.get(&key).await {
        Ok(Some(b)) => b,
        // §6.2: the pod's namespace still says this exists; the backend has
        // nothing to hand over. A `500` would read as "my fault, retry".
        Ok(None) => {
            let mut out = HeaderMap::new();
            if let Some(w) = warning_header("the storage backend has no object for this resource") {
                out.insert(header::WARNING, w);
            }
            return with_aux_links((StatusCode::NOT_FOUND, out).into_response(), &target);
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let tag = blob_etag(&bytes);
    let mut out = HeaderMap::new();
    out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
    out.insert(header::VARY, "Accept".parse().expect("static"));
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
        return with_allow(with_aux_links((StatusCode::NOT_MODIFIED, out).into_response(), &target), &target);
    }
    // `MediaType` carries the `HeaderValue` its constructor validated, so
    // there is nothing here to assert.
    out.insert(header::CONTENT_TYPE, mt.header_value());
    with_allow(with_aux_links((out, bytes).into_response(), &target), &target)
}

async fn get_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap) -> Response {
    let store = st.store.as_ref();
    let decision = match authorize(store, &agent, &target, Mode::Read).await {
        Ok(d) => d,
        Err(res) => return with_aux_links(res, &target),
    };
    let Target::Resource(r) = &target else {
        return legacy_graph_read(st, &decision, target, headers).await; // containers, auxiliaries
    };
    // §6: which kind this is, then the matching read. Both kinds share
    // authorization, the auxiliary advertisement and the `Allow` header above
    // and below; only the representation differs.
    match kind_of(store, r).await {
        // `st.clone()` rather than a move: `store` above borrows `st.store`,
        // and `AppState` is `Clone` over `Arc`s, so this costs two refcounts.
        Ok(Some(Kind::Binary(mt))) => return blob_read(st.clone(), target.clone(), headers, mt).await,
        Ok(Some(Kind::Rdf)) => {}
        Ok(None) => return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Err(ResourceError::InvalidIri) => return StatusCode::BAD_REQUEST.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    // §6.1: read everything first — the ETag covers the resource, not the
    // body, so the shelves are read even when only the default graph will be
    // served.
    let stored = match get_dataset(store, r).await {
        Ok(Some(d)) => d,
        // The advertisement matters most here: a client creating a resource
        // learns where its ACL goes from the 404 it got when it looked.
        Ok(None) => return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Err(ResourceError::InvalidIri) => return StatusCode::BAD_REQUEST.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let visible = stored.deskolemize();
    // What is withheld is decided on the **stored** quads, where every graph
    // name is an IRI (§4) and no graph is invisible; what can be *named* comes
    // from the visible view, further down. The de-skolemized view shows a
    // blank-node graph name as a blank node again, which `Dataset::named_graphs`
    // cannot list, so deriving the shape from it would leave that decision
    // resting on the narrower of the two questions. §6.1 puts the ETag before
    // de-skolemization for the same reason.
    let shape = if stored.has_named_graphs() { Shape::Dataset } else { Shape::Graph };
    let stored_type = stored_media_type(store, r)
        .await
        .ok()
        .flatten()
        .and_then(|m| Format::from_content_type(m.as_str()));
    let Some(fmt) = negotiate(header_str(&headers, header::ACCEPT), shape, stored_type) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    let tag = stored.etag(fmt);
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
        let mut out = HeaderMap::new();
        out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
        out.insert(header::VARY, "Accept".parse().expect("static"));
        return with_read_headers(
            (StatusCode::NOT_MODIFIED, out).into_response(), &target, &decision);
    }
    // §6.2: a graph format gets the default graph, and is told what it missed.
    let served = if fmt.carries_dataset() { visible.clone() } else { visible.default_graph_only() };
    let bytes = match fmt.serialize(&served) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut out = HeaderMap::new();
    out.insert(header::CONTENT_TYPE, fmt.media_type().parse().expect("static media type"));
    out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
    out.insert(header::VARY, "Accept".parse().expect("static"));
    // Only when something was actually left out — an ordinary graph-shaped
    // resource served as Turtle has nothing to point `alternate` at, and
    // must not carry these headers just because Turtle itself is lossy.
    if !fmt.carries_dataset() && stored.has_named_graphs() {
        // `containsGraph` names what a client would recognise, so it is drawn
        // from the visible view: a graph the client named with a blank node
        // has no IRI it ever wrote, and the IRI the server minted for it is
        // reserved (§3.2.2), so there is nothing this header could name it
        // with. The `alternate` links below are emitted for either kind, so a
        // resource whose only withheld graph is blank-named still tells the
        // client that something was withheld and where to get it whole.
        for name in visible.named_graphs() {
            out.append(header::LINK, format!(
                "<{}>; rel=\"https://quadpod.toph.so/ns#containsGraph\"", name.as_str()
            ).parse().expect("graph name is header-safe"));
        }
        for alt in ["application/trig", "application/ld+json"] {
            out.append(header::LINK, format!(
                "<{}>; rel=\"alternate\"; type=\"{alt}\"", r.graph_iri()
            ).parse().expect("static"));
        }
    }
    with_read_headers((out, bytes).into_response(), &target, &decision)
}

/// The pre-dataset read path: containers and auxiliaries, whose graph never
/// carries a name (§3.4 refuses that at write time), so there is nothing here
/// [`get_impl`]'s dataset machinery would add.
///
/// Containers and auxiliaries are skolemized on the way in through `put_rdf`
/// and `aux::put` — an ACL may legitimately contain `[]` — so the matching
/// step out belongs here, the one place this shared path serializes, rather
/// than inside a resource-shaped branch (design spec §4).
async fn legacy_graph_read(
    st: AppState, decision: &Decision, target: Target, headers: HeaderMap,
) -> Response {
    let store = st.store.as_ref();
    let Some(fmt) = negotiate(header_str(&headers, header::ACCEPT), Shape::Graph, None) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    match get_rdf(store, &target).await {
        Ok(Some(triples)) => {
            let ground = ground_dataset(triples);
            let tag = ground.etag(fmt);
            if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
                // `Vary: Accept` on every negotiated response (§6.3), and this
                // path negotiates as much as the resource path does.
                let mut out = HeaderMap::new();
                out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
                out.insert(header::VARY, "Accept".parse().expect("static"));
                return with_read_headers(
                    (StatusCode::NOT_MODIFIED, out).into_response(), &target, decision,
                );
            }
            let visible = ground.deskolemize();
            match fmt.serialize(&visible) {
                Ok(bytes) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, fmt.media_type().parse().expect("static media type"));
                    headers.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
                    headers.insert(header::VARY, "Accept".parse().expect("static"));
                    with_read_headers((headers, bytes).into_response(), &target, decision)
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
    match aux::delete_subject(store, st.blobs.as_ref(), subject).await {
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
        blobs: Arc<dyn crate::blob::BlobStore>,
        space: StorageSpace,
        max_body_bytes: usize,
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
        fixture_with_body_limit(64 * 1024 * 1024).await
    }

    async fn fixture_with_body_limit(max_body_bytes: usize) -> Fixture {
        fixture_with_blobs(Arc::new(crate::blob::ObjectStoreBlobs::in_memory()), max_body_bytes).await
    }

    /// Like [`fixture`], but with a caller-chosen `BlobStore` — for a fixture
    /// whose blob backend is failing (see `a_blob_backend_outage_answers_500_not_400`).
    async fn fixture_with_blobs(blobs: Arc<dyn crate::blob::BlobStore>, max_body_bytes: usize) -> Fixture {
        fixture_with_store_and_blobs(
            Arc::new(OxigraphStore::in_memory().unwrap()), blobs, max_body_bytes,
        ).await
    }

    /// Like [`fixture_with_blobs`], but with a caller-chosen `SparqlStore` too
    /// — for a fixture whose store backend starts failing partway through a
    /// test (see `a_failed_write_after_a_warning_carries_no_report_link`).
    async fn fixture_with_store_and_blobs(
        store: Arc<dyn crate::store::SparqlStore>,
        blobs: Arc<dyn crate::blob::BlobStore>,
        max_body_bytes: usize,
    ) -> Fixture {
        assert!(
            !FIXTURE_HELD.with(|f| f.replace(true)),
            "call fixture() once per test: it holds the process-wide DPoP replay lock \
             for the fixture's lifetime, so a second call would deadlock"
        );
        let _replay_guard = crate::auth::dpop::test_replay_lock().lock().await;
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        crate::container::provision_root(store.as_ref(), &space.root()).await.unwrap();
        crate::wac::provision::provision_root_acl(store.as_ref(), &space, OWNER, false).await.unwrap();

        let idp = TestIdp::new();
        let client = TestClient::new();
        let mut issuers = StaticWebIdIssuers::new();
        issuers.allow(OWNER, ISSUER);

        let state = AppState {
            store: store.clone(),
            blobs: blobs.clone(),
            space: space.clone(),
            resolver: Arc::new(StaticJwksResolver::new(ISSUER, idp.jwks())),
            webid_verifier: Arc::new(issuers),
            auth_config: Arc::new(crate::auth::AuthConfig::default()),
            max_body_bytes,
        };
        Fixture {
            app: router(state), store, blobs, space, max_body_bytes, idp, client, _replay_guard,
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

        /// A request whose URI carries a query string. The DPoP proof is
        /// signed for the bare path, because `htu` excludes the query.
        fn owner_request_query(&self, method: &str, path: &str, query: &str)
            -> axum::http::request::Builder
        {
            let b = Request::builder().method(method).uri(format!("{path}?{query}"));
            self.sign(b, OWNER, method, path)
        }

        async fn put_turtle(&self, path: &str, ttl: &str) {
            let res = self.app.clone().oneshot(self.owner_request("PUT", path)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(ttl.to_owned())).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::CREATED, "PUT {path}");
        }

        async fn get_turtle(&self, path: &str) -> String {
            let res = self.app.clone().oneshot(self.owner_request("GET", path)
                .header(header::ACCEPT, "text/turtle")
                .body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "GET {path}");
            let b = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
            String::from_utf8(b.to_vec()).unwrap()
        }

        async fn put_blob(&self, path: &str, ct: &str, body: &'static [u8]) {
            let res = self.app.clone().oneshot(self.owner_request("PUT", path)
                .header(header::CONTENT_TYPE, ct)
                .body(Body::from(body)).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::CREATED, "PUT {path}");
        }

        async fn etag_of(&self, path: &str) -> String {
            let res = self.app.clone().oneshot(self.owner_request("GET", path)
                .body(Body::empty()).unwrap()).await.unwrap();
            res.headers()[header::ETAG].to_str().unwrap().to_owned()
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
                blobs: self.blobs.clone(),
                space: self.space.clone(),
                resolver: Arc::new(StaticJwksResolver::new(ISSUER, self.idp.jwks())),
                webid_verifier: Arc::new(issuers),
                auth_config: Arc::new(crate::auth::AuthConfig::default()),
                max_body_bytes: self.max_body_bytes,
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
    async fn a_text_file_can_be_put_and_read_back_byte_for_byte() {
        let f = fixture().await;
        let body: &[u8] = &[0x00, 0xff, 0xfe, b'\r', b'\n', b'A'];

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(body.to_vec())).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let res = f.app.clone().oneshot(f.owner_request("GET", "/notes.txt")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CONTENT_TYPE], "text/plain");
        let got = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        assert_eq!(&got[..], body, "bytes survive exactly");
    }

    // Solid Protocol §2.2 names the status code in its normative text:
    // "Server MUST reject PUT, POST, and PATCH requests that contain content
    // but lack the Content-Type header field, with a status code of 400."
    #[tokio::test]
    async fn a_write_with_content_and_no_content_type_is_a_400() {
        let f = fixture().await;
        for (method, path) in [("PUT", "/x"), ("POST", "/")] {
            let res = f.app.clone().oneshot(f.owner_request(method, path)
                .body(Body::from("hello")).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{method} {path}");
        }
    }

    // The live injection vector: a legal HTTP header value that is not a legal
    // media type, whose quote would close the SPARQL literal it is
    // interpolated into. A CRLF payload would NOT do here — hyper rejects it
    // before any handler runs, so that test would pin hyper and pass no matter
    // what MediaType::parse does.
    #[tokio::test]
    async fn a_content_type_that_is_not_a_media_type_is_a_415_and_stores_nothing() {
        let f = fixture().await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/evil")
            .header(header::CONTENT_TYPE, r#"text/plain;x=""#)
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let res = f.app.clone().oneshot(f.owner_request("GET", "/evil")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "nothing may have been stored");
    }

    // §3.2, §11: a legal URL this pod cannot store.
    #[tokio::test]
    async fn an_over_long_path_segment_is_a_414() {
        let f = fixture().await;
        let long = "a".repeat(300);
        let res = f.app.clone().oneshot(f.owner_request("PUT", &format!("/{long}"))
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::URI_TOO_LONG);
    }

    // §8.5: an ACL the PDP cannot parse is not an ACL.
    #[tokio::test]
    async fn a_non_rdf_body_on_an_auxiliary_is_a_415() {
        let f = fixture().await;
        f.put_turtle("/subject", "").await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/.aux/subject.acl")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // §8.5: a container's representation is RDF, so the two asks contradict.
    #[tokio::test]
    async fn posting_a_non_rdf_body_as_a_container_is_a_400() {
        let f = fixture().await;
        let res = f.app.clone().oneshot(f.owner_request("POST", "/")
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    // A blob is a container member exactly as an RDF resource is.
    #[tokio::test]
    async fn a_posted_blob_joins_and_leaves_its_container() {
        let f = fixture().await;
        let res = f.app.clone().oneshot(f.owner_request("POST", "/box/")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let loc = res.headers()[header::LOCATION].to_str().unwrap().to_owned();
        let child_path = loc.strip_prefix("https://pod.toph.so").unwrap().to_owned();

        let listing = f.get_turtle("/box/").await;
        assert!(listing.contains(&loc), "the blob is a member");

        let res = f.app.clone().oneshot(f.owner_request("DELETE", &child_path)
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let listing = f.get_turtle("/box/").await;
        assert!(!listing.contains(&loc), "and it leaves again");
    }

    // Whole-branch review: `uses_reserved_namespace` sliced an IRI at a fixed
    // byte offset with no char-boundary check, so this body — legal Turtle,
    // and `<urn:quadpodé:x>` is a legal IRI oxrdf accepts — panicked the
    // handler and aborted the connection with no response at all. The
    // response's exact status is not the point; that one comes back at all,
    // instead of the connection dying, is.
    #[tokio::test]
    async fn a_multi_byte_iri_in_the_body_does_not_abort_the_connection() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<urn:quadpodé:x> <http://schema.org/name> \"x\" .")).unwrap();
        let res = f.app.oneshot(put).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
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

    // `application/json` is a syntactically valid media type that `Format`
    // does not parse as RDF, so `classify_body` routes it to the blob path
    // rather than refusing it.
    #[tokio::test]
    async fn put_of_a_valid_but_unrecognised_media_type_stores_it_as_a_blob() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "application/json").body(Body::from("{}")).unwrap();
        let res = f.app.oneshot(put).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
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

    // LDP §5.2.3.4: a POST whose `Link: rel="type"` names a container asks for
    // a container, and Solid §3.1 makes the trailing slash the only thing that
    // distinguishes the two — so the allocated name must carry it.
    #[tokio::test]
    async fn post_with_container_type_link_creates_a_container() {
        let f = fixture().await;
        let post = f.owner_request("POST", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", "sub")
            .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
            .body(Body::from("")).unwrap();
        let res = f.app.clone().oneshot(post).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/box/sub/");

        // It is a real container: typed, readable, and POSTable into.
        let get = f.owner_request("GET", "/box/sub/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let got = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(got.status(), StatusCode::OK);
        assert!(body_string(got).await.contains(container::LDP_BASIC_CONTAINER));

        // And the parent lists it under its slash-terminated URL.
        let list = f.owner_request("GET", "/box/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        assert!(body_string(f.app.oneshot(list).await.unwrap()).await
            .contains("https://pod.toph.so/box/sub/"));
    }

    // A `Slug` is a hint, and §3.1 makes the other half of a slash pair as
    // unavailable as the name itself — so a POSTed container whose name is
    // held by an existing *resource* gets another name, not the `409` a
    // client-named PUT would get. Same rule `name_is_taken` already applied in
    // the other direction.
    #[tokio::test]
    async fn posted_container_avoids_a_name_its_slash_counterpart_holds() {
        let f = fixture().await;
        let mk_resource = f.owner_request("POST", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle").header("slug", "sub")
            .body(Body::from("")).unwrap();
        let res = f.app.clone().oneshot(mk_resource).await.unwrap();
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/box/sub");

        let post = f.owner_request("POST", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle").header("slug", "sub")
            .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
            .body(Body::from("")).unwrap();
        let res = f.app.oneshot(post).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let loc = res.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        assert_ne!(loc, "https://pod.toph.so/box/sub/", "the counterpart is taken");
        assert!(loc.ends_with('/'), "it is still a container: {loc}");
    }

    // Containment is server-managed on a POSTed container for the same reason
    // it is on a PUT one.
    #[tokio::test]
    async fn posted_container_may_not_set_containment() {
        let f = fixture().await;
        let post = f.owner_request("POST", "/box/")
            .header(header::CONTENT_TYPE, "text/turtle").header("slug", "sub")
            .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
            .body(Body::from(
                "<https://pod.toph.so/box/sub/> \
                 <http://www.w3.org/ns/ldp#contains> <https://pod.toph.so/elsewhere> .",
            )).unwrap();
        let res = f.app.clone().oneshot(post).await.unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
        // and nothing was left behind
        let get = f.owner_request("GET", "/box/sub/").body(Body::empty()).unwrap();
        assert_eq!(f.app.oneshot(get).await.unwrap().status(), StatusCode::NOT_FOUND);
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

    #[tokio::test]
    async fn a_jsonld_dataset_round_trips_over_http() {
        let f = fixture().await;
        let body = r#"{"@context":{"name":"http://schema.org/name"},
          "@graph":[{"@id":"urn:example:g1","@graph":[{"@id":"http://example.org/alice","name":"Alice"}]},
                    {"@id":"http://example.org/bob","name":"Bob"}]}"#;
        let put = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body_string(res).await.contains("urn:example:g1"), "the graph name survived");
    }

    #[tokio::test]
    async fn turtle_gets_the_default_graph_and_is_told_what_it_is_missing() {
        let f = fixture().await;
        let body = r#"{"@graph":[{"@id":"urn:example:g1",
          "@graph":[{"@id":"http://example.org/alice","http://schema.org/name":"Alice"}]}]}"#;
        let put = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap();
        f.app.clone().oneshot(put).await.unwrap();

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "§6.2: not a 406");
        assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
        let links: Vec<_> = res.headers().get_all(header::LINK).iter()
            .map(|v| v.to_str().unwrap().to_owned()).collect();
        assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains("urn:example:g1")),
            "the client learns which graphs it did not get: {links:?}");
        assert!(links.iter().any(|l| l.contains("alternate") && l.contains("application/trig")));
    }

    // §6.2.1: GET as Turtle, edit, PUT back would otherwise destroy every named
    // graph with a 2xx and no warning.
    #[tokio::test]
    async fn a_graph_format_write_over_named_graphs_is_refused() {
        let f = fixture().await;
        let body = r#"{"@graph":[{"@id":"urn:example:g1",
          "@graph":[{"@id":"http://example.org/alice","http://schema.org/name":"Alice"}]}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let overwrite = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(overwrite).await.unwrap().status(), StatusCode::CONFLICT);

        // and nothing changed
        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
        assert!(body_string(f.app.clone().oneshot(get).await.unwrap()).await.contains("urn:example:g1"));
    }

    #[tokio::test]
    async fn the_reserved_namespace_and_container_datasets_are_refused() {
        let f = fixture().await;
        // Any IRI under the reserved prefix triggers the refusal — this one
        // avoids the skolem sub-namespace that only `dataset` may write or
        // match (`docs/constraints.md`).
        let reserved = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<urn:quadpod:evil:x> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(reserved).await.unwrap().status(), StatusCode::BAD_REQUEST);

        let container = f.owner_request("PUT", "/box/")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from("<urn:example:g1> { <http://example.org/a> <http://schema.org/name> \"x\" }")).unwrap();
        assert_eq!(f.app.oneshot(container).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    // Containers and auxiliaries are skolemized on the way in like everything
    // else; without the matching step out, a client's blank node comes back as
    // an IRI it never wrote.
    #[tokio::test]
    async fn an_acl_containing_a_blank_node_round_trips_as_a_blank_node() {
        let f = fixture().await;
        // A second, named authorization keeps OWNER's Control over /c/notes —
        // without it this ACL would deny even its own author the Control
        // needed to read it back, which is a real (and separately tested)
        // WAC rule, not what this test is about.
        let acl = format!(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
             <#owner> a acl:Authorization ; acl:agent <{OWNER}> ; \
                acl:mode acl:Control, acl:Read, acl:Write ; acl:accessTo </c/notes> .\n\
             [] a acl:Authorization ; acl:mode acl:Read ; \
                acl:agentClass <http://xmlns.com/foaf/0.1/Agent> ; \
                acl:accessTo </c/notes> ."
        );
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
        let put = f.owner_request("PUT", "/.aux/c/notes.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl)).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        let get = f.owner_request("GET", "/.aux/c/notes.acl")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let out = body_string(f.app.oneshot(get).await.unwrap()).await;
        // The constant, not a hardcoded literal: only `dataset` may write or
        // match the skolem sub-namespace it lives under (`docs/constraints.md`).
        assert!(!out.contains(crate::dataset::RESERVED_PREFIX),
            "the server's internal IRI must not reach a client: {out}");
        assert!(out.contains("acl:Authorization") || out.contains("auth/acl#Authorization"),
            "and the rule itself survived: {out}");
    }

    /// A resource whose only content sits in a graph the client named with a
    /// blank node. TriG is the only way to write one over HTTP, and the shape
    /// is the deployed Verifiable Credentials `proof` pattern (§4).
    const BLANK_NAMED_GRAPH_TRIG: &str =
        "_:g { <http://example.org/alice> <http://schema.org/name> \"Alice\" }";

    // §6.2, on the input that used to be invisible to every dataset decision:
    // a blank-node graph name is not an IRI, so nothing a `Link` header can
    // name — but the resource is still a dataset, and a graph format still
    // serves only part of it. Before, this answered `200` with an empty body
    // and no indication anything existed at all, which is the exact silent
    // loss §6.2 exists to prevent.
    #[tokio::test]
    async fn a_blank_named_graph_is_a_dataset_and_a_graph_format_is_told_so() {
        let f = fixture().await;
        let put = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let links: Vec<String> = res.headers().get_all(header::LINK).iter()
            .map(|v| v.to_str().unwrap().to_owned()).collect();
        assert!(links.iter().any(|l| l.contains("alternate") && l.contains("application/trig")),
            "the client must be told the whole thing is available elsewhere: {links:?}");
        assert!(!links.iter().any(|l| l.contains("containsGraph")),
            "and not under a name it never wrote: {links:?}");
        assert!(!body_string(res).await.contains("Alice"),
            "the withheld graph is withheld, not merged into the default graph");
    }

    // §6.3 on the same input: the client offered a format that carries the
    // whole resource, so preferring the lossy one it happened to list first is
    // the wrong answer — and it is what a shape read off the de-skolemized
    // view produces, since the graph name is a blank node again there.
    #[tokio::test]
    async fn a_blank_named_graph_makes_negotiation_prefer_a_dataset_format() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "text/turtle, application/trig").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/trig");
        let out = body_string(res).await;
        assert!(out.contains("Alice"), "and it carries the graph: {out}");
        assert!(!out.contains(crate::dataset::RESERVED_PREFIX),
            "under a blank node, not the server's internal IRI: {out}");
    }

    // §6.2.1 on the same input. The refusal cannot name the graph — the client
    // never wrote a name for it — but it must still refuse, or a Turtle write
    // destroys it with a `201` and no warning.
    #[tokio::test]
    async fn a_graph_format_write_over_a_blank_named_graph_is_refused() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap()).await.unwrap();

        let overwrite = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        let res = f.app.clone().oneshot(overwrite).await.unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let body = body_string(res).await;
        assert!(body.contains("named by a blank node"),
            "the refusal accounts for what it is refusing to destroy: {body}");
        assert!(!body.contains(crate::dataset::RESERVED_PREFIX),
            "without leaking the server's internal IRI: {body}");

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
        assert!(body_string(f.app.oneshot(get).await.unwrap()).await.contains("Alice"),
            "and nothing was destroyed");
    }

    // §3.4, which runs on the parsed dataset before skolemization. A container
    // that accepts this stores nothing and says `201`; for an ACL it tells an
    // author a rule was created when it was not.
    #[tokio::test]
    async fn a_blank_named_graph_is_refused_on_a_container_and_an_auxiliary() {
        let f = fixture().await;
        let container = f.owner_request("PUT", "/box/")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap();
        assert_eq!(f.app.clone().oneshot(container).await.unwrap().status(),
            StatusCode::BAD_REQUEST, "a container's graph carries containment");

        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
        let acl = f.owner_request("PUT", "/.aux/c/notes.acl")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(BLANK_NAMED_GRAPH_TRIG)).unwrap();
        assert_eq!(f.app.clone().oneshot(acl).await.unwrap().status(),
            StatusCode::BAD_REQUEST, "an ACL's rules would be invisible to WAC in a subgraph");
        assert!(f.stored("/.aux/c/notes.acl").await.is_none(),
            "and the refusal wrote nothing");
    }

    // Every other `containsGraph` assertion uses one named graph, where
    // `insert` and `append` are indistinguishable. Two of them tell them
    // apart — `insert` would replace the first `Link` with the second, and the
    // client would be told about half of what it did not get.
    #[tokio::test]
    async fn every_withheld_graph_is_named_not_just_the_last() {
        let f = fixture().await;
        let body = "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }\n\
                    <urn:example:g2> { <http://example.org/bob> <http://schema.org/name> \"Bob\" }";
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let links: Vec<String> = f.app.oneshot(get).await.unwrap()
            .headers().get_all(header::LINK).iter()
            .map(|v| v.to_str().unwrap().to_owned()).collect();
        for g in ["urn:example:g1", "urn:example:g2"] {
            assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains(g)),
                "{g} is missing from {links:?}");
        }
    }

    // §6.2.1's body is the whole remedy: a `409` that does not say which
    // graphs are in the way is a refusal the client cannot act on.
    #[tokio::test]
    async fn the_refusal_names_the_graphs_it_is_protecting() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(
                "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }"
            )).unwrap()).await.unwrap();

        let overwrite = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        let res = f.app.oneshot(overwrite).await.unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let body = body_string(res).await;
        assert!(body.contains("urn:example:g1"), "which graph is in the way: {body}");
        assert!(body.contains("application/trig"), "and how to write it anyway: {body}");
    }

    // RFC 9110 §13.1.1 matches `If-Match` against any current representation.
    // A resource's validator embeds its format (§6.4), so comparing against
    // one server-chosen representation makes `GET` as TriG followed by a
    // conditional `PUT` fail with `412` permanently.
    #[tokio::test]
    async fn a_validator_from_any_format_satisfies_a_conditional_write() {
        let f = fixture().await;

        // A graph-shaped resource stored as Turtle, fetched as JSON-LD: the
        // two representations have different validators, and only one of them
        // is what an `Accept`-less `GET` would have returned.
        f.app.clone().oneshot(f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap()).await.unwrap();
        let get = f.owner_request("GET", "/foo")
            .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/ld+json");
        let json_tag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

        let plain = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
        let plain_tag = f.app.clone().oneshot(plain).await.unwrap()
            .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
        assert_ne!(json_tag, plain_tag,
            "different representations are different entities (RFC 9110 §8.8.1)");

        let conditional = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, &json_tag)
            .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(conditional).await.unwrap().status(),
            StatusCode::CREATED, "the tag the client was just handed must be accepted");

        // And the same for a dataset-shaped resource, whose stored type is
        // JSON-LD while the client fetched it as TriG.
        let body = "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }";
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(r#"{"@graph":[{"@id":"urn:example:g1","@graph":[
                {"@id":"http://example.org/alice","http://schema.org/name":"Alice"}]}]}"#))
            .unwrap()).await.unwrap();
        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
        let trig_tag = f.app.clone().oneshot(get).await.unwrap()
            .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
        let conditional = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .header(header::IF_MATCH, &trig_tag)
            .body(Body::from(body)).unwrap();
        assert_eq!(f.app.clone().oneshot(conditional).await.unwrap().status(),
            StatusCode::CREATED);

        // A validator of no representation at all is still refused.
        let stale = f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, "\"deadbeef\"")
            .body(Body::from("")).unwrap();
        assert_eq!(f.app.oneshot(stale).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
    }

    // RFC 9110 §15.4.5: a `304` carries the `ETag` it was matched on, or the
    // client cannot refresh its cache entry. `Vary` for the same reason it is
    // on the `200` (§6.3) — the answer depended on `Accept`.
    #[tokio::test]
    async fn a_304_still_carries_its_validator_and_vary() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/foo").body(Body::empty()).unwrap();
        let tag = f.app.clone().oneshot(get).await.unwrap()
            .headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

        let cond = f.owner_request("GET", "/foo")
            .header(header::IF_NONE_MATCH, &tag).body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(cond).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(res.headers().get(header::ETAG).unwrap(), tag.as_str());
        assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
    }

    // §6.3: `Vary: Accept` on every negotiated response. The container and
    // auxiliary path negotiates as much as the resource path does.
    #[tokio::test]
    async fn a_container_read_varies_on_accept_including_its_304() {
        let f = fixture().await;
        let get = f.owner_request("GET", "/").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
        let tag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

        let cond = f.owner_request("GET", "/")
            .header(header::IF_NONE_MATCH, &tag).body(Body::empty()).unwrap();
        let res = f.app.oneshot(cond).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
        assert_eq!(res.headers().get(header::ETAG).unwrap(), tag.as_str());
    }

    // §4 on the ordinary resource path. Only the auxiliary path was pinned,
    // so a read that skipped de-skolemization returned the server's internal
    // IRI to the client for every resource that ever held a blank node.
    #[tokio::test]
    async fn a_resource_containing_a_blank_node_round_trips_as_a_blank_node() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/knows> [ <http://schema.org/name> \"Alice\" ] ."))
            .unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/foo")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let out = body_string(f.app.oneshot(get).await.unwrap()).await;
        // The constant, not a literal: only `dataset` may write or match the
        // skolem sub-namespace (`docs/constraints.md`).
        assert!(!out.contains(crate::dataset::RESERVED_PREFIX),
            "the server's internal IRI must not reach a client: {out}");
        assert!(out.contains("Alice"), "and the statement itself survived: {out}");
    }

    // §6.3, against a resource that is genuinely dataset-shaped: the client
    // offered a format carrying everything, so the lossy one it listed first
    // is the wrong answer. A shape hardcoded to `Graph` answers Turtle here.
    #[tokio::test]
    async fn a_dataset_shaped_resource_negotiates_away_from_a_lossy_format() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(
                "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }"
            )).unwrap()).await.unwrap();

        for accept in ["text/turtle, application/trig", "text/turtle, application/ld+json"] {
            let get = f.owner_request("GET", "/c/notes")
                .header(header::ACCEPT, accept).body(Body::empty()).unwrap();
            let res = f.app.clone().oneshot(get).await.unwrap();
            assert_ne!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle",
                "{accept}: a format that carries the whole resource was offered");
        }

        // §6.3: `text/*` admits Turtle, and Turtle can serve the default
        // graph — that is a `200` with `Link`s, never a `406`.
        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "text/*").body(Body::empty()).unwrap();
        let res = f.app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle");
    }

    // §9.5. Folding this into the default graph would be a document rewrite —
    // a statement in a named graph is not asserted in the default graph — and
    // it is the obvious accidental implementation of the split.
    #[tokio::test]
    async fn a_graph_named_like_its_own_resource_stays_a_named_graph() {
        let f = fixture().await;
        let body = r#"{"@graph":[
            {"@id":"https://pod.toph.so/c/notes",
             "@graph":[{"@id":"http://example.org/a","http://schema.org/name":"inside"}]},
            {"@id":"http://example.org/b","http://schema.org/name":"outside"}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap();
        let out = body_string(f.app.clone().oneshot(get).await.unwrap()).await;
        assert!(out.contains("\"inside\" <https://pod.toph.so/c/notes>"),
            "still in its named graph, not merged into the default one: {out}");
        assert!(out.lines().any(|l| l.contains("\"outside\"") && l.trim_end().ends_with("\" .")),
            "and the default-graph statement is still in the default graph: {out}");
    }

    // §9.6 / §2.1. Eleven characters of relative IRI name another resource's
    // URL. Under store-global graph names this write would land in /victim
    // with no ACL check anywhere in the path.
    #[tokio::test]
    async fn naming_another_resources_url_as_a_graph_touches_nothing() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/victim")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"mine\" .")).unwrap()).await.unwrap();

        let before = body_string(f.app.clone().oneshot(f.owner_request("GET", "/victim")
            .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap())
            .await.unwrap()).await;

        let attack = r#"{"@graph":[{"@id":"../victim",
            "@graph":[{"@id":"http://example.org/x","http://schema.org/name":"theirs"}]}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/attacker/doc")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(attack)).unwrap()).await.unwrap();

        let after = body_string(f.app.clone().oneshot(f.owner_request("GET", "/victim")
            .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap())
            .await.unwrap()).await;
        assert_eq!(before, after, "/victim changed by a write to /attacker/doc");
        assert!(!after.contains("theirs"));
    }

    // §9.1: an empty named graph produces no quads, so it cannot survive. The
    // isomorphism oracle passes vacuously here — this needs a direct assertion
    // on the response instead, or the limit stops being a decision and becomes
    // a surprise.
    #[tokio::test]
    async fn an_empty_named_graph_is_documented_as_lost() {
        let f = fixture().await;
        let body = r#"{"@graph":[{"@id":"urn:example:empty","@graph":[]},
            {"@id":"http://example.org/b","http://schema.org/name":"kept"}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let out = body_string(f.app.clone().oneshot(f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap())
            .await.unwrap()).await;
        assert!(out.contains("kept"));
        assert!(!out.contains("urn:example:empty"),
            "documented limit (§9.1): a graph with no quads does not round-trip");
    }

    // `current_tags` contributes no validator for a container or an
    // auxiliary in any existing test, and nothing exercised `If-Match` on an
    // ACL — exactly the read-modify-write pattern SolidOS uses on every
    // write: `GET`, keep the `ETag`, `PUT` back conditionally.
    #[tokio::test]
    async fn if_match_on_an_acl_succeeds_with_the_right_tag_and_412s_with_the_wrong_one() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
        let acl = format!(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
             <#owner> a acl:Authorization ; acl:agent <{OWNER}> ; \
                acl:mode acl:Control, acl:Read, acl:Write ; acl:accessTo </c/notes> ."
        );
        f.app.clone().oneshot(f.owner_request("PUT", "/.aux/c/notes.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl.clone())).unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/.aux/c/notes.acl")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

        // Read-modify-write: the ETag just fetched is handed back unchanged,
        // and must be accepted.
        let put_back = f.owner_request("PUT", "/.aux/c/notes.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, &etag)
            .body(Body::from(acl)).unwrap();
        assert_eq!(f.app.clone().oneshot(put_back).await.unwrap().status(), StatusCode::CREATED,
            "a conditional write carrying the ETag just read must succeed");

        // A stale or wrong tag must not be accepted.
        let wrong = f.owner_request("PUT", "/.aux/c/notes.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, "\"deadbeef\"")
            .body(Body::from(
                "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                 <#owner> a acl:Authorization ; acl:agent <https://mallory.example/card#me> ; \
                    acl:mode acl:Control ; acl:accessTo </c/notes> ."
            )).unwrap();
        assert_eq!(f.app.oneshot(wrong).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
    }

    // Unifying container and auxiliary ETags onto `Skolemized::etag` made
    // them format-aware (RFC 9110 §8.8.1): Turtle and JSON-LD renderings of
    // the same container are different representations, so they must not
    // share a validator — and the same representation, fetched twice, must.
    #[tokio::test]
    async fn a_containers_etag_tracks_the_selected_format() {
        let f = fixture().await;

        let turtle = f.app.clone().oneshot(f.owner_request("GET", "/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap())
            .await.unwrap();
        let turtle_tag = turtle.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

        let jsonld = f.app.clone().oneshot(f.owner_request("GET", "/")
            .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap())
            .await.unwrap();
        let jsonld_tag = jsonld.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

        assert_ne!(turtle_tag, jsonld_tag,
            "Turtle and JSON-LD are different representations (RFC 9110 §8.8.1) and must not share an ETag");

        let turtle_again = f.app.clone().oneshot(f.owner_request("GET", "/")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap())
            .await.unwrap();
        let turtle_again_tag = turtle_again.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
        assert_eq!(turtle_tag, turtle_again_tag, "same format, same content → same ETag");

        // RFC 9110 §13.1.1: `If-Match` matches *any* current representation,
        // not just the one the server would negotiate by default — so a
        // write carrying the JSON-LD-negotiated tag must be accepted too.
        let put = f.app.clone().oneshot(f.owner_request("PUT", "/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, &jsonld_tag)
            .body(Body::from(
                "<https://pod.toph.so/> <http://purl.org/dc/terms/title> \"root\" .",
            )).unwrap()).await.unwrap();
        assert_eq!(put.status(), StatusCode::CREATED,
            "If-Match must accept a tag negotiated for any servable format, not only the default");
    }

    // §6.2.1's check reads `get_dataset` to decide whether an existing
    // resource has named graphs a graph-format write would destroy. If the
    // registry is corrupt — a shelf `sys:hasSubgraph` lists with no
    // `sys:graphName`, the state §3.2.3 says should never occur — `get_dataset`
    // fails closed with `InvalidIri` (pinned directly against the store in
    // `resource.rs`). This pins that `put_impl` propagates the refusal instead
    // of reading the store error as "no named graphs" and proceeding with
    // exactly the overwrite the check exists to refuse.
    #[tokio::test]
    async fn a_corrupt_registry_refuses_the_write_instead_of_overwriting() {
        let f = fixture().await;
        let body = r#"{"@graph":[
            {"@id":"https://pod.toph.so/c/notes","http://schema.org/name":"kept"},
            {"@id":"urn:example:g1","@graph":[{"@id":"http://example.org/a","http://schema.org/name":"Alice"}]}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap()).await.unwrap();
        let before = f.stored("/c/notes").await;

        let r = match f.url("/c/notes") {
            Target::Resource(r) => r,
            other => panic!("/c/notes is not a resource: {other:?}"),
        };
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let key = crate::shelf::ShelfKey::of(&r, g.as_ref());
        let sys = crate::resource::sys_graph_iri(&r);
        f.store.update(&format!(
            "DELETE DATA {{ GRAPH <{sys}> {{ <{}> <{}> <{}> }} }}",
            key.graph_iri(), crate::shelf::SYS_GRAPH_NAME, g.as_str()
        )).await.unwrap();

        let overwrite = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        let res = f.app.clone().oneshot(overwrite).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST,
            "a store error must refuse, not read as \"no named graphs\"");
        assert_eq!(f.stored("/c/notes").await, before, "the refused write changed nothing");
    }

    // Every other `containsGraph` assertion covers only the Link headers.
    // This one also checks that both graphs' actual content survives a
    // dataset-format read, not merely that their names are mentioned.
    #[tokio::test]
    async fn two_named_graphs_both_round_trip_and_are_both_named() {
        let f = fixture().await;
        let body = "<urn:example:g1> { <http://example.org/alice> <http://schema.org/name> \"Alice\" }\n\
                    <urn:example:g2> { <http://example.org/bob> <http://schema.org/name> \"Bob\" }";
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap();
        let out = body_string(f.app.clone().oneshot(get).await.unwrap()).await;
        assert!(out.contains("\"Alice\" <urn:example:g1>"), "graph g1's content survived: {out}");
        assert!(out.contains("\"Bob\" <urn:example:g2>"), "graph g2's content survived: {out}");

        let turtle_get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let links: Vec<String> = f.app.oneshot(turtle_get).await.unwrap()
            .headers().get_all(header::LINK).iter()
            .map(|v| v.to_str().unwrap().to_owned()).collect();
        for g in ["urn:example:g1", "urn:example:g2"] {
            assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains(g)),
                "{g} is missing from {links:?}");
        }
    }

    // `has_named_graphs` counts a blank-named graph; `named_graphs` cannot
    // name one. Only a document mixing both kinds exercises the split: the
    // resource must still be treated as a dataset (blank-named graph withheld
    // from a graph-format read too), but `containsGraph` can name only the
    // IRI-named one, and a dataset format must still carry both.
    #[tokio::test]
    async fn a_blank_named_graph_and_an_iri_named_graph_together() {
        let f = fixture().await;
        let body = "_:g { <http://example.org/alice> <http://schema.org/name> \"Alice\" }\n\
                    <urn:example:g1> { <http://example.org/bob> <http://schema.org/name> \"Bob\" }";
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let links: Vec<String> = res.headers().get_all(header::LINK).iter()
            .map(|v| v.to_str().unwrap().to_owned()).collect();
        assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains("urn:example:g1")),
            "the IRI-named graph is nameable: {links:?}");
        assert_eq!(links.iter().filter(|l| l.contains("containsGraph")).count(), 1,
            "the blank-named graph has no IRI a Link header can name: {links:?}");
        assert!(!body_string(res).await.contains("Alice"),
            "neither named graph leaked into the default graph");

        let dataset_get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
        let out = body_string(f.app.oneshot(dataset_get).await.unwrap()).await;
        assert!(out.contains("Alice"), "the blank-named graph's content still round-trips: {out}");
        assert!(out.contains("Bob"), "and the IRI-named graph's content: {out}");
    }

    // §8.4: axum's own 2 MiB default already applied here. This pins that the
    // configured number is the one in force — a body over it is refused, and
    // one under it is not.
    //
    // The under-limit body must be a format `put_impl` accepts today (only an
    // RDF `Content-Type`, so `text/turtle` rather than `text/plain`) to reach
    // `201` at all. The oversized body's `Content-Type` is irrelevant: axum's
    // `Bytes` extractor rejects it for size before `put_impl` reads any
    // header.
    #[tokio::test]
    async fn a_body_over_the_configured_limit_is_a_413() {
        let f = fixture_with_body_limit(64).await;

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/small.txt")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/big.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(vec![b'x'; 4096])).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // §3.4: the validator is computed from the served bytes, so the same bytes
    // give the same tag and one byte's difference gives a different one.
    #[tokio::test]
    async fn a_blob_carries_a_strong_validator_and_answers_conditionally() {
        let f = fixture().await;
        f.put_blob("/a.txt", "text/plain", b"hello").await;
        f.put_blob("/b.txt", "text/plain", b"hello").await;
        f.put_blob("/c.txt", "text/plain", b"hellp").await;

        let ta = f.etag_of("/a.txt").await;
        assert_eq!(ta, f.etag_of("/b.txt").await, "same bytes, same tag");
        assert_ne!(ta, f.etag_of("/c.txt").await, "one byte apart, different tag");

        let res = f.app.clone().oneshot(f.owner_request("GET", "/a.txt")
            .header(header::IF_NONE_MATCH, &ta)
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);

        // A stale If-Match must refuse the write rather than overwrite it.
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/a.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::IF_MATCH, "\"0000000000000000000000000000000000000000000000000000000000000000\"")
            .body(Body::from("new")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
    }

    // §6.1. Both halves matter: without the admitting cases an accept_allows
    // that always refuses would pass.
    #[tokio::test]
    async fn accept_decides_whether_a_blob_is_servable() {
        let f = fixture().await;
        f.put_blob("/pic.png", "image/png", b"png").await;

        for accept in ["*/*", "image/*", "image/png", "text/turtle, image/png"] {
            let res = f.app.clone().oneshot(f.owner_request("GET", "/pic.png")
                .header(header::ACCEPT, accept).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "Accept: {accept}");
        }
        for accept in ["text/turtle", "text/*", "image/png;q=0", "*/*, image/png;q=0"] {
            let res = f.app.clone().oneshot(f.owner_request("GET", "/pic.png")
                .header(header::ACCEPT, accept).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE, "Accept: {accept}");
        }
    }

    // §6.2: the pod's namespace still says the resource exists, but there is
    // nothing to serve. 500 would read as "my fault, retry".
    #[tokio::test]
    async fn a_blob_whose_object_vanished_is_a_404_with_a_warning() {
        let f = fixture().await;
        f.put_blob("/gone.txt", "text/plain", b"x").await;

        // Emptied from underneath, exactly as an operator or another writer
        // on a shared bucket would.
        let r = match f.space.resolve("/gone.txt").unwrap() {
            crate::space::Target::Resource(r) => r,
            _ => panic!("resource"),
        };
        let key = crate::blob::BlobKey::of(&r).unwrap();
        f.blobs.delete(&key).await.unwrap();

        let res = f.app.clone().oneshot(f.owner_request("GET", "/gone.txt")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().contains_key(header::WARNING));
    }

    // §10: the claim the whole plan exists to make testable.
    #[tokio::test]
    async fn wac_governs_a_blob_exactly_as_it_governs_a_graph() {
        let f = fixture().await;
        f.put_blob("/secret.txt", "text/plain", b"s3cret").await;
        f.put_turtle("/.aux/secret.txt.acl", &format!(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> . \
             <#owner> a acl:Authorization ; \
               acl:agent <{OWNER}> ; \
               acl:accessTo <https://pod.toph.so/secret.txt> ; \
               acl:mode acl:Read, acl:Write, acl:Control ."
        )).await;

        // Anonymous: the ACL names only the owner.
        let res = f.app.clone().oneshot(Request::builder()
            .method("GET").uri("/secret.txt").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = f.app.clone().oneshot(f.owner_request("GET", "/secret.txt")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// A `BlobStore` whose `put` always fails, standing in for a backend
    /// outage — disk full, bucket unreachable. Reached only through the HTTP
    /// handlers here, unlike `resource::`'s own `FailingBlobs`: that one
    /// pins `put_dataset`'s write order, but nothing at that level ever
    /// passes through `put_status`, which is the function this test exists
    /// to cover.
    struct FailingBlobs;

    #[async_trait::async_trait]
    impl crate::blob::BlobStore for FailingBlobs {
        async fn put(&self, _: &crate::blob::BlobKey, _: bytes::Bytes)
            -> Result<(), crate::blob::BlobError> {
            Err(crate::blob::BlobError::Backend("disk on fire".into()))
        }
        async fn get(&self, _: &crate::blob::BlobKey)
            -> Result<Option<bytes::Bytes>, crate::blob::BlobError> {
            Err(crate::blob::BlobError::Backend("disk on fire".into()))
        }
        async fn delete(&self, _: &crate::blob::BlobKey)
            -> Result<(), crate::blob::BlobError> { Ok(()) }
    }

    // Whole-branch review, Important 1: `put_status` mapped `ResourceError::Blob`
    // through its `_` arm to `400`, telling a client a server-side outage was
    // their malformed request. `resource::`'s own `FailingBlobs` never caught
    // this because it never goes through a handler — this one does.
    #[tokio::test]
    async fn a_blob_backend_outage_answers_500_not_400() {
        let f = fixture_with_blobs(Arc::new(FailingBlobs), 64 * 1024 * 1024).await;

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/photo.png")
            .header(header::CONTENT_TYPE, "image/png")
            .body(Body::from(&b"x"[..])).unwrap()).await.unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_put_carrying_a_triple_term_is_a_400() {
        let f = fixture().await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(
                "<http://e/s> <http://e/p> <<( <http://e/a> <http://e/b> <http://e/c> )>> ."
            )).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    // §2.1's refusal has to hold in both parsers that can build a `Dataset`:
    // `Format::parse` above, and here `patch::Patch::parse` — the only other
    // way a triple term could reach the store, since a patch body never goes
    // through `Format::parse` at all.
    #[tokio::test]
    async fn a_patch_carrying_a_triple_term_is_a_400() {
        let f = fixture().await;
        f.put_turtle("/profile", "<#me> <http://example.org/email> \"old\" .").await;

        let res = patch_n3(&f, "/profile",
            "_:patch a solid:InsertDeletePatch ;\n\
               solid:inserts { <> ex:x <<( <http://e/a> <http://e/b> <http://e/c> )>> . } .\n").await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    /// The shapes document, and a container bound to it. Returns nothing;
    /// both are ordinary resources afterwards.
    /// Binds `shape_ttl`, stored at `shape_path`, to `container_path` — the
    /// one place this file spells `ldp:constrainedBy` to set a binding up
    /// (data, not a read; see `docs/constraints.md`).
    async fn bind_shape(f: &Fixture, container_path: &str, shape_path: &str, shape_ttl: &str) {
        f.put_turtle(shape_path, shape_ttl).await;
        f.put_turtle(container_path, &format!(
            "<> <http://www.w3.org/ns/ldp#constrainedBy> <https://pod.toph.so{shape_path}> ."
        )).await;
    }

    async fn bind_note_shape(f: &Fixture) {
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
    /// triple, so a refusal leaves the container exactly as it was — no
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

    /// A `SparqlStore` that delegates to a real in-memory store until
    /// [`FailingStore::arm`] is called, after which every `update` fails —
    /// standing in for a backend outage that starts partway through a test.
    /// Reads (`query_triples`, `ask`) always delegate, so shape lookup and
    /// validation, which never write, are unaffected.
    struct FailingStore {
        inner: OxigraphStore,
        armed: std::sync::atomic::AtomicBool,
    }

    impl FailingStore {
        fn new(inner: OxigraphStore) -> Self {
            Self { inner, armed: std::sync::atomic::AtomicBool::new(false) }
        }
        fn arm(&self) {
            self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl crate::store::SparqlStore for FailingStore {
        async fn update(&self, sparql: &str) -> Result<(), crate::store::StoreError> {
            if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(crate::store::StoreError::Backend("store backend outage".into()));
            }
            self.inner.update(sparql).await
        }
        async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, crate::store::StoreError> {
            self.inner.query_triples(sparql).await
        }
        async fn ask(&self, sparql: &str) -> Result<bool, crate::store::StoreError> {
            self.inner.ask(sparql).await
        }
        async fn query_solutions(&self, sparql: &str)
            -> Result<Vec<oxigraph::sparql::QuerySolution>, crate::store::StoreError>
        {
            self.inner.query_solutions(sparql).await
        }
    }

    /// The `describedby` link falls out of a tail that `Target::Resource`'s
    /// `Err` arm shares with its `Ok` arm, so a warning-only validation
    /// followed by a `put_dataset` failure must not still advertise a report
    /// for a write that never persisted.
    ///
    /// The resource is pre-created so the failing write adds no containment
    /// triple — `store.update` runs exactly once for it, inside `put_dataset`
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

        // Alongside the authorization the ACL actually needs, a subject typed
        // `schema:NoteDigitalDocument` with no `schema:name` — a triple
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
    /// the container does — here the root, which binds the shape that
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
    /// was accepted at write time — its own body carried no members — must
    /// still conform at `?validate` after the ancestor walk adds one. A
    /// shape targeting `ldp:contains` directly on the container's own IRI is
    /// what would trip if the read path validated the full stored graph
    /// instead of what the write path actually checked.
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
    /// triple about a subject the server never touches — `<#x>` here — must
    /// therefore survive into the `?validate` view exactly as the write path
    /// validated it.
    ///
    /// The container's own subject is a different story: `ensure_container`
    /// re-asserts the same pair there on every write, so a client-authored
    /// `<> a ldp:Container` and the server's own assertion collapse into one
    /// stored triple with no way to tell which wrote it — that focus node
    /// keeps reporting `sh:Violation` for `sh:hasValue ldp:Container` even
    /// though the write that produced it was accepted. Narrowing the strip to
    /// the container's own subject cannot recover that; it only stops the
    /// filter from reaching past it onto `<#x>`.
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

    /// §5.3: a blob is never validated — `?validate` on one answers `404`,
    /// the same "no report here" a resource never validated at all gets, not
    /// a vacuous `200, sh:conforms true` for a representation SHACL never saw.
    #[tokio::test]
    async fn validate_view_on_a_blob_is_404() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        f.put_blob("/notes/pic.png", "image/png", &b"\x89PNG"[..]).await;

        let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/pic.png", "validate")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// An auxiliary is never validated, whatever its subject's shape says —
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

    fn patch_body(inner: &str) -> String {
        format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
             @prefix ex: <http://example.org/> .\n{inner}"
        )
    }

    async fn patch_n3(f: &Fixture, path: &str, inner: &str) -> axum::response::Response {
        f.app.clone().oneshot(f.owner_request("PATCH", path)
            .header(header::CONTENT_TYPE, "text/n3")
            .body(Body::from(patch_body(inner))).unwrap()).await.unwrap()
    }

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
}
