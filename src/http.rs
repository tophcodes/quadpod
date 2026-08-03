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
    resource::{put_rdf, get_rdf, delete_rdf, patch_dataset, put_dataset, put_blob, get_dataset, stored_media_type, kind_of, Kind, PatchResult, ResourceError},
    rdf::{Format, MediaType, RdfVersion, Shape, negotiate, accept_allows},
    auth::{Agent, AuthConfig, JtiReplayStore, JwksResolver, WebIdIssuerVerifier, auth_layer},
    space::{AuxKind, AuxUrl, ContainerUrl, GraphName, SpaceError, StorageSpace, Target},
    store::SparqlStore,
    wac::{guard::{Denial, Guard, Materialized}, pdp, AccessModes, Decision, Mode}};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn SparqlStore>,
    pub events: Arc<crate::notify::Bus>,
    pub blobs: Arc<dyn crate::blob::BlobStore>,
    pub space: StorageSpace,
    pub resolver: Arc<dyn JwksResolver>,
    pub webid_verifier: Arc<dyn WebIdIssuerVerifier>,
    pub auth_config: Arc<AuthConfig>,
    /// The `jti`s of the DPoP proofs this pod has accepted, so a second
    /// sighting of one is refused. Per pod, like every other collaborator
    /// here: two pods in one process each reject their own replays.
    pub replay: Arc<dyn JtiReplayStore>,
    pub max_body_bytes: usize,
}

pub fn router(state: AppState) -> Router {
    let max_body_bytes = state.max_body_bytes;
    // axum 0.8 wildcard capture syntax: "/{*path}" (NOT the old "/*path").
    //
    // `Router::layer` wraps everything built so far, so the LAST call is the
    // outermost: `cors_layer` sees the `401` that `auth_layer` produces, which
    // is where the CORS fields are required, and the trace layer outside both
    // sees every response this pod emits — including the ones no handler ever
    // ran for.
    Router::new()
        .route("/", get(handle_get_root).put(handle_put_root).post(handle_post_root).delete(handle_delete_root).patch(handle_patch_root).options(handle_options_root))
        .route("/{*path}", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete).patch(handle_patch).options(handle_options))
        .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_layer))
        .layer(axum::middleware::from_fn(cors_layer))
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(|req: &axum::extract::Request| {
                    // The id is minted here rather than read off a header: an
                    // inbound `X-Request-Id` is client-controlled, so trusting
                    // it lets one caller file its requests under another's id.
                    // Every event a request produces — the `error!` at each
                    // `500` included — inherits this span, so a log line always
                    // says which request it belongs to.
                    tracing::info_span!(
                        "request",
                        id = %uuid::Uuid::new_v4(),
                        method = %req.method(),
                        path = %req.uri().path(),
                    )
                })
                // At `INFO`, because the access log is the record of what the
                // pod did and a default-level subscriber must see it. The
                // status and the latency are `DefaultOnResponse`'s own fields.
                .on_response(
                    tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
                ),
        )
        .with_state(state)
}

/// The response headers a browser may read off a cross-origin response.
///
/// Enumerated rather than `*` because a wildcard names nothing a client can act
/// on, and because every field here is one some handler on this pod actually
/// emits. Both properties are asserted: `protocol/cors/enumerate-headers`
/// requires the header to be present and to differ from `*`.
const EXPOSED_HEADERS: &str =
    "Accept-Patch, Accept-Post, Accept-Put, Allow, Content-Type, ETag, Link, Location, Vary, WAC-Allow, Warning, WWW-Authenticate";

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
///
/// A constant rather than a lookup, unlike [`accept_write`]: `text/n3` is not
/// a [`Format`] — nothing in `rdf.rs` parses it, `patch.rs` owns it end to end
/// — so there is no list here for a second one to drift from.
const ACCEPT_PATCH: &str = "text/n3";

/// Which write method an advertisement describes. A two-arm enum rather than a
/// `bool`, for the reason [`Shape`] is one: `accept_write(&target, true, v)`
/// says nothing at the call site.
#[derive(Debug, Clone, Copy)]
enum Write {
    Put,
    Post,
}

/// What may be written here, as an `Accept-Put`/`Accept-Post` field value.
///
/// `None` where [`allowed_methods`] does not permit the method: `POST`
/// addresses containers alone, and a header naming a method the same response
/// refuses in `Allow` is worse than an absent one.
///
/// Every RDF format appears twice — bare, and with the store's own `version`
/// label. Both are true: [`RdfVersion::from_media_type`] reads an *absent*
/// parameter as `Rdf11`, so the two spellings are two acceptable
/// representations. The versioned twin is dropped on an `Rdf11` store, where
/// it would be a second spelling of the first entry. Only the store's maximum
/// is named; a lower `version` is accepted — [`classify_body`] refuses only
/// `declared > store_version` — and is what the bare entry already covers.
///
/// `*/*` is [LDP §4.5.2][ldp]'s "any media type", and it is [`classify_body`]'s
/// blob arm read back out: a `POST`ed child and a `PUT` resource may be blobs;
/// a container's own representation and an auxiliary may not.
///
/// [ldp]: https://www.w3.org/TR/ldp/#ldpc-post-acceptposthdr
fn accept_write(target: &Target, method: Write, version: RdfVersion) -> Option<String> {
    let blobs = match (target, method) {
        (Target::Container(_), Write::Post) | (Target::Resource(_), Write::Put) => true,
        (Target::Container(_) | Target::Aux(_), Write::Put) => false,
        (Target::Resource(_) | Target::Aux(_), Write::Post) => return None,
    };
    let mut types = Vec::new();
    for f in Format::ALL {
        types.push(f.media_type().to_string());
        if version > RdfVersion::Rdf11 {
            types.push(format!("{};version={}", f.media_type(), version.label()));
        }
    }
    if blobs {
        types.push("*/*".to_string());
    }
    Some(types.join(", "))
}

/// Attach [`allowed_methods`] to a read that succeeded — Protocol §4.1 makes
/// it a MUST on `GET`/`HEAD` — alongside the three `Accept-*` headers §5.3
/// makes a MUST beside it.
fn with_allow(mut res: Response, target: &Target, version: RdfVersion) -> Response {
    res.headers_mut().insert(
        header::ALLOW,
        allowed_methods(target).parse().expect("method list is header-safe"),
    );
    res.headers_mut().insert("accept-patch", HeaderValue::from_static(ACCEPT_PATCH));
    for (name, method) in [("accept-put", Write::Put), ("accept-post", Write::Post)] {
        if let Some(value) = accept_write(target, method, version) {
            res.headers_mut().insert(
                name,
                value.parse().expect("media types and version labels are header-safe"),
            );
        }
    }
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
fn with_read_headers(
    res: Response, target: &Target, decision: &Decision, version: RdfVersion,
) -> Response {
    let mut res = with_allow(with_aux_links(res, target), target, version);
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

/// The body every `500` carries, whatever failed underneath.
///
/// A store or blob failure names this pod's internals — an Oxigraph message, a
/// bucket, a path — and none of that is something the client can act on. The
/// detail is not lost, it is moved: [`internal_error`] logs the cause with the
/// request's own span around it. A `4xx` keeps its text, because there the text
/// describes what the caller sent.
const INTERNAL_ERROR_BODY: &str = "internal server error";

/// The `500` for a failure the client did not cause: logged with its cause,
/// answered with [`INTERNAL_ERROR_BODY`].
///
/// Every `500` this crate builds goes through here, so a failure that reaches a
/// client is a failure the operator can read about.
pub(crate) fn internal_error(cause: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %cause, "request failed");
    (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_ERROR_BODY).into_response()
}

/// The challenge sent with a 401, telling a client which credential the pod
/// accepts. `Bearer` is deliberately absent: Plan 4 verifies DPoP-bound
/// tokens only.
///
/// `algs` is RFC 9449 §5.1's space-delimited list of the JWS algorithms the
/// pod will verify a proof under, and it must stay an accurate description of
/// [`crate::auth::dpop::verify_dpop`]: a client that reads this header picks
/// its proof algorithm from it, so advertising one the pod rejects sends
/// honest clients into a 401 loop, and omitting one it accepts turns away
/// clients that could have authenticated. ES256 comes from `dpop-verifier`,
/// RS256 from the pod's own path; EdDSA is absent because `dpop-verifier`'s
/// `eddsa` feature is not enabled here.
const DPOP_CHALLENGE: &str = "DPoP algs=\"ES256 RS256\"";

/// The `409` body a create is refused with when it would produce the other
/// half of a trailing-slash pair.
const SLASH_PAIR_MESSAGE: &str =
    "another resource already exists whose URI differs from this one only in the trailing slash";

/// What each refusal the guard reaches costs a client.
///
/// The guard decides *that* a request is refused and on which ground; the
/// status codes, the bodies and the challenge header are this layer's, and
/// this is the only place they are chosen. A store failure keeps the road
/// every other `500` takes — [`internal_error`], which logs the cause and
/// answers [`INTERNAL_ERROR_BODY`] — so the detail the guard carried out
/// reaches the operator and nothing of it reaches the client.
impl IntoResponse for Denial {
    fn into_response(self) -> Response {
        match self {
            Denial::Unauthenticated => {
                (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, DPOP_CHALLENGE)])
                    .into_response()
            }
            Denial::Forbidden => StatusCode::FORBIDDEN.into_response(),
            Denial::AuxSubjectMissing => {
                (StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response()
            }
            Denial::SlashPair => (StatusCode::CONFLICT, SLASH_PAIR_MESSAGE).into_response(),
            Denial::Store(e) => internal_error(&e),
        }
    }
}

/// The response a write-path [`ResourceError`] earns: [`put_status`]'s status,
/// with the cause going to whichever of the two audiences it belongs to.
fn put_error(e: &ResourceError) -> Response {
    let status = put_status(e);
    if status.is_server_error() {
        return internal_error(e);
    }
    (status, e.to_string()).into_response()
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
        // write refused forever. The same holds one axis over: a resource has
        // one validator per *(format, served version)*, so a 1.2 client's
        // `If-Match` needs its pair listed here too.
        return Ok(Some(etag_candidates(&stored)));
    }
    let Some(triples) = get_rdf(store, target).await? else {
        return Ok(None);
    };
    let ground = ground_dataset(triples);
    Ok(Some(etag_candidates(&ground)))
}

/// Every validator this stored state could legitimately have been served
/// with: each servable format, at RDF 1.1 and at the state's own version.
///
/// The version comes from [`Dataset::rdf_version`] via de-skolemization
/// rather than from a second classifier over the stored quads — one
/// classifier is a rule (`docs/constraints.md`), and this is the caller that
/// would most naturally have broken it.
fn etag_candidates(stored: &Skolemized) -> Vec<String> {
    let held = stored.deskolemize().rdf_version();
    let versions = if held == RdfVersion::Rdf11 {
        vec![RdfVersion::Rdf11]
    } else {
        vec![RdfVersion::Rdf11, held]
    };
    SERVABLE.iter()
        .filter_map(|ct| Format::from_content_type(ct))
        .flat_map(|f| versions.iter().map(move |v| stored.etag(f, *v)))
        .collect()
}

/// Lifts a container's or auxiliary's raw triples (always default-graph,
/// always ground — §3.4 and skolemization at the write path guarantee both)
/// into the same [`Skolemized`] type a resource's dataset is held as, so the
/// two paths share one `etag`/`deskolemize` implementation.
pub(crate) fn ground_dataset(triples: Vec<Triple>) -> Skolemized {
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
    let guard = match Guard::probe(store, agent.clone(), target.clone()).await {
        Ok(g) => g,
        Err(d) => return with_aux_links(d.into_response(), &target),
    };
    // Append is the weakest mode any patch §5.1 admits can need, and
    // `AccessModes::allows` makes Write subsume it — so this refuses exactly
    // those callers who could do nothing anyway, and it runs before the body
    // is looked at so an unauthorized caller learns nothing.
    let decision = match guard.authorize(Mode::Append) {
        Ok(dec) => dec,
        Err(d) => return with_aux_links(d.into_response(), &target),
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
        return with_aux_links(guard.deny().into_response(), &target);
    }

    // §8: `text/n3` is a perfectly good request body, so the conflict is with
    // the state of the target — bytes, which have no triples to patch.
    if let Target::Resource(r) = &target {
        match kind_of(store, r).await {
            Ok(Some(Kind::Binary(_))) => {
                return (StatusCode::CONFLICT, BINARY_TARGET_MESSAGE).into_response()
            }
            Ok(_) => {}
            Err(e) => return put_error(&e),
        }
    }
    // A shape-constrained container refuses every PATCH outright — see
    // `patch_shape_conflict` for why validating one is not an option. Checked
    // after the two refusals above, which are about the caller and the
    // target's own state and must win first: `authorize`'s own comment says
    // it "runs before the body is looked at so an unauthorized caller learns
    // nothing", and a caller the §9 mode check would deny must not learn a
    // container is shape-constrained on the way to that denial, nor must a
    // `PATCH` at a blob be told about a shape instead of about the blob.
    if let Err(res) = patch_shape_conflict(&st, &target).await {
        return res;
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
    // takes its own branch here because the `target_exists` check below is not
    // the one it needs: §7's creation path is closed for an auxiliary as well, and
    // `aux::patch` refuses an absent one itself, with a body that says which
    // of the two is missing. That refusal also means this arm never creates —
    // it is always an `Update` (§4.3), the same activity `put_write`'s `Aux`
    // arm reports on the same topic.
    let (res, existence, materialized) = if let Target::Aux(a) = &target {
        let res = match aux::patch(store, a, &patch).await {
            Ok(result) => patch_response(result, &patch),
            Err(AuxError::SubjectMissing) => {
                (StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response()
            }
            Err(e @ AuxError::Missing) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
            // Unreachable: the triple cap is counted over a whole document,
            // which only `aux::put` is given.
            Err(e @ AuxError::TooLarge(_)) => internal_error(&e),
            Err(AuxError::Resource(e)) => put_error(&e),
        };
        (res, crate::notify::Existence::Existed, Materialized::default())
    } else {
        let r = match &target {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource(),
            Target::Aux(_) => unreachable!("matched above"),
        };
        // Read before `materialize` consumes `guard` below (in either
        // branch): it takes `self`, so this is the only chance to ask.
        let existence = if guard.target_exists() {
            crate::notify::Existence::Existed
        } else {
            crate::notify::Existence::Absent
        };
        let (res, materialized) = if matches!(existence, crate::notify::Existence::Absent) {
            create_by_patch(&st, guard, &target, &patch).await
        } else {
            let res = match patch_dataset(store, r, &patch).await {
                // A container's type triples are the server's, and a patch names
                // its own triples — including them. Re-asserting them here is
                // what `put_impl` does after writing a container body, and it is
                // why a container patch is not refused outright: the client
                // stays free to patch everything else the container's graph
                // holds.
                Ok(result) => match &target {
                    Target::Container(c) => match container::ensure_container(store, c).await {
                        Ok(()) => patch_response(result, &patch),
                        Err(e) => put_error(&e),
                    },
                    _ => patch_response(result, &patch),
                },
                Err(e) => put_error(&e),
            };
            // An update materializes nothing: the target already existed, so
            // there is no ancestor to walk.
            (res, Materialized::default())
        };
        (res, existence, materialized)
    };
    crate::notify::emit_patch(&st, &target, existence, &materialized, res.status()).await;
    res
}

/// §7: a target that does not exist is patched against an empty RDF dataset,
/// so a patch that asks nothing of the prior state creates it — through the
/// same [`crate::wac::guard::Guard::materialize`] walk, the same containment linking and
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
///
/// The second element of the pair is what the ancestor walk materialized —
/// what `emit_patch` needs and cannot re-derive. A failing exit's is never
/// read: `emit_patch` gates emission on `status` alone, before it looks at it.
async fn create_by_patch(
    st: &AppState,
    guard: Guard<'_>,
    target: &Target,
    patch: &crate::patch::Patch,
) -> (Response, Materialized) {
    let store = st.store.as_ref();
    let Some(triples) = patch.ground_insertions() else {
        return (patch_response(PatchResult::NoMapping, patch), Materialized::default());
    };
    if !patch.deletions().is_empty() {
        return (patch_response(PatchResult::DeletionMissing, patch), Materialized::default());
    }
    let materialized = match guard.materialize().await {
        Ok(m) => m,
        Err(d) => return (with_aux_links(d.into_response(), target), Materialized::default()),
    };
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
        Ok(()) => (created(target), materialized),
        Err(e) => (put_error(&e), Materialized::default()),
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
    /// The declared [`RdfVersion`] travels with the parsed body because the
    /// write path needs it after `classify_body` has returned, and re-reading
    /// it from the header there would be a second reader of the `version`
    /// parameter — which `docs/constraints.md` forbids.
    Rdf(Dataset, Format, RdfVersion),
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
fn classify_body(
    headers: &HeaderMap,
    body: &Bytes,
    target: &Target,
    store_version: RdfVersion,
) -> Result<Repr, Box<Response>> {
    let ct = header_str(headers, header::CONTENT_TYPE).trim();
    if ct.is_empty() {
        if !body.is_empty() {
            return Err(Box::new((StatusCode::BAD_REQUEST, "Content-Type is required").into_response()));
        }
        return Err(Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()));
    }
    if let Some(fmt) = Format::from_content_type(ct) {
        // §4/§6, all three refusals in the one funnel the write path already
        // has. `None` is an unrecognised label rather than an absent one, and
        // a `415` for the same reason the next check is one: `version` is a
        // media-type parameter, so "I do not accept this media type" is
        // literally what the status says.
        let Some(declared) = RdfVersion::from_media_type(ct) else {
            return Err(Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()));
        };
        if declared > store_version {
            return Err(Box::new((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!(
                    "this pod's store holds RDF {} at most",
                    store_version.label()
                ),
            ).into_response()));
        }
        return match fmt.parse(body, target.graph_iri(), declared) {
            Ok(d) => Ok(Repr::Rdf(d, fmt, declared)),
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
        Err(e) => return Err(put_error(&e)),
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
    let status = match &e {
        ShapeError::Resource(r) => put_status(r),
        ShapeError::Engine(_) => StatusCode::INTERNAL_SERVER_ERROR,
        ShapeError::Unparsable(_) | ShapeError::Unsupported(_) | ShapeError::Missing => {
            StatusCode::CONFLICT
        }
    };
    if status.is_server_error() {
        return internal_error(&e);
    }
    (status, e.to_string()).into_response()
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

/// The single place a `PUT` reports what it changed.
///
/// A wrapper rather than an emit at each success site, because the write below
/// has one successful early exit of its own (the blob arm) and design §6.2
/// fixes exactly one emit call per handler: the two facts the emit needs are
/// carried out of [`put_write`] as values instead of the emit being repeated
/// wherever control leaves.
async fn put_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap, body: Bytes) -> Response {
    let (res, existence, materialized) = put_write(&st, agent, &target, headers, body).await;
    crate::notify::emit_put(&st, &target, existence, &materialized, res.status()).await;
    res
}

/// The write itself, reporting what the emit above cannot re-derive: whether
/// the target was there beforehand, and what the ancestor walk materialized.
///
/// A failing exit's `existence` and `materialized` are never read: `emit_put`
/// gates emission on `status` alone, before it looks at either value.
async fn put_write(
    st: &AppState, agent: Agent, target: &Target, headers: HeaderMap, body: Bytes,
) -> (Response, crate::notify::Existence, Materialized) {
    let store = st.store.as_ref();
    let absent = crate::notify::Existence::Absent;
    let guard = match Guard::probe(store, agent, target.clone()).await {
        Ok(g) => g,
        Err(d) => return (with_aux_links(d.into_response(), target), absent, Materialized::default()),
    };
    if let Err(d) = guard.authorize(Mode::Write) {
        return (with_aux_links(d.into_response(), target), absent, Materialized::default());
    }
    let existence = if guard.target_exists() {
        crate::notify::Existence::Existed
    } else {
        crate::notify::Existence::Absent
    };
    let repr = match classify_body(&headers, &body, target, st.store.rdf_version()) {
        Ok(r) => r,
        Err(res) => return (*res, existence, Materialized::default()),
    };
    let (dataset, fmt, declared) = match repr {
        Repr::Rdf(d, f, v) => (d, f, v),
        Repr::Blob(bytes, mt) => {
            // A blob has none of the dataset checks below to run: no named
            // graphs, no reserved namespace, no containment triples. It does
            // share the conditional-request block and the ancestor walk, so
            // it runs them itself rather than falling through to where the
            // RDF path runs them.
            let Target::Resource(r) = target else {
                unreachable!("classify_body refuses a blob for any other target")
            };
            if crate::blob::BlobKey::of(r).is_none() {
                return (StatusCode::URI_TOO_LONG.into_response(), existence, Materialized::default());
            }
            if let Err(res) = check_conditionals(store, st.blobs.as_ref(), &headers, target).await {
                return (res, existence, Materialized::default());
            }
            let materialized = match guard.materialize().await {
                Ok(m) => m,
                Err(d) => return (with_aux_links(d.into_response(), target), existence, Materialized::default()),
            };
            // An early exit that carries what `emit_put` needs out alongside
            // the response (§6.3).
            return (match put_blob(store, st.blobs.as_ref(), r, bytes, &mt).await {
                Ok(()) => created(target),
                Err(ResourceError::KeyTooLong) => StatusCode::URI_TOO_LONG.into_response(),
                Err(e) => put_error(&e),
            }, existence, materialized);
        }
    };
    // §3.2.2 — the skolem namespace is the server's.
    if dataset.uses_reserved_namespace() {
        return ((StatusCode::BAD_REQUEST, "the urn:quadpod: namespace is reserved").into_response(),
            existence, Materialized::default());
    }
    // §3.4 — a container's graph carries containment; an auxiliary's rules
    // would be invisible to WAC inside a subgraph.
    if dataset.has_named_graphs() && !matches!(target, Target::Resource(_)) {
        return ((StatusCode::BAD_REQUEST, "named graphs are only allowed on resources").into_response(),
            existence, Materialized::default());
    }
    // Containment is server-managed. Refused here, before the ancestor walk
    // below writes anything, so a rejected PUT cannot leave a containment
    // triple pointing at a container it never created. Over the whole
    // dataset, not the default graph: otherwise the 409 is bypassed by
    // putting ldp:contains in a named graph.
    if matches!(target, Target::Container(_)) && container::body_sets_containment(&triples_of(&dataset)) {
        return (StatusCode::CONFLICT.into_response(), existence, Materialized::default());
    }
    // The version half of the same argument, and it applies to every format
    // rather than only the graph-shaped ones: a client that declared 1.1 was
    // served the 1.1 projection, so replacing from it would delete exactly
    // the terms that projection hid. The read must not become the template
    // for its own destruction.
    //
    // Compared against what the *client declared*, not against what its body
    // classifies as: declaring 1.2 and sending 1.1 content is a deliberate
    // replacement by a client that can see the whole resource, and refusing
    // that would make the higher version a trap rather than a capability.
    if let Target::Resource(r) = target {
        let existing = match get_dataset(store, r).await {
            Ok(v) => v,
            Err(e) => return (put_error(&e), existence, Materialized::default()),
        };
        if let Some(existing) = existing {
            let held = existing.deskolemize().rdf_version();
            if declared < held {
                return ((StatusCode::CONFLICT, format!(
                    "this resource holds RDF {} terms that {} cannot carry; \
                     send Content-Type with version={}, or DELETE it first",
                    held.label(), declared.label(), held.label()
                )).into_response(), existence, Materialized::default());
            }
        }
    }
    // §6.2.1 — a graph-format write must not silently discard what a graph
    // format could not have shown the client in the first place.
    if let Target::Resource(r) = target {
        if !fmt.carries_dataset() {
            // A store error is not "no named graphs": reading it that way lets
            // the overwrite this check exists to refuse proceed on exactly the
            // request the check could not evaluate.
            let existing = match get_dataset(store, r).await {
                Ok(v) => v,
                Err(e) => return (put_error(&e), existence, Materialized::default()),
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
                    return ((StatusCode::CONFLICT, format!(
                        "this resource has named graphs ({list}) that {} cannot carry; \
                         write it as application/trig or application/ld+json, or DELETE it first",
                        fmt.media_type()
                    )).into_response(), existence, Materialized::default());
                }
            }
        }
    }
    let skolemized = Skolemized::skolemize(&dataset);
    if let Err(res) = check_conditionals(store, st.blobs.as_ref(), &headers, target).await {
        return (res, existence, Materialized::default());
    }
    let findings = match enforce_shape(st, target, &dataset).await {
        Ok(f) => f,
        Err(res) => return (res, existence, Materialized::default()),
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
    let materialized = match guard.materialize().await {
        Ok(m) => m,
        Err(d) => return (with_aux_links(d.into_response(), target), existence, Materialized::default()),
    };
    let res = match target {
        // An auxiliary exists only for an existing subject, and that rule is
        // inside `aux::put`'s update rather than a check here — a check and a
        // write are two round-trips, and an interleaved DELETE between them
        // would plant a policy document on a path that no longer exists.
        Target::Aux(a) => {
            let triples = triples_of(&dataset.default_graph_only());
            match aux::put(store, a, &triples).await {
                Ok(()) => warn_if_acl_grants_nothing(&st.space, a, &triples, created(target)),
                Err(AuxError::SubjectMissing) =>
                    (StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response(),
                // RFC 9110 §15.5.14: the content is larger than this server is
                // willing to process. The document is well-formed RDF and its
                // meaning is understood — nothing about it is a client
                // mistake a `400` would describe — so what is refused is its
                // size, which is also what tells the caller a smaller
                // document would be accepted. Same answer the configured
                // `max_body_bytes` gives one layer out, for the same reason.
                Err(e @ AuxError::TooLarge(_)) =>
                    (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response(),
                // Unreachable: `put` writes the auxiliary, so it never asks
                // for one that is already there.
                Err(e @ AuxError::Missing) => internal_error(&e),
                Err(AuxError::Resource(e)) => put_error(&e),
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
                Err(e) => return (put_error(&e), existence, materialized),
            };
            let mut merged = triples_of(&dataset.default_graph_only());
            merged.extend(
                existing.into_iter().filter(|t| t.predicate.as_str() == container::LDP_CONTAINS),
            );
            if let Err(e) = put_rdf(store, c, &merged).await {
                return (put_error(&e), existence, materialized);
            }
            if let Err(e) = container::ensure_container(store, c).await {
                return (put_error(&e), existence, materialized);
            }
            created(target)
        }
        Target::Resource(r) => match put_dataset(store, st.blobs.as_ref(), r, &skolemized, fmt).await {
            Ok(()) => created(target),
            Err(e) => put_error(&e),
        },
    };
    // The link describes the stored representation. `Target::Resource`'s
    // `Err` arm above is a tail expression flowing into `res` exactly like
    // its `Ok` arm, so findings alone cannot gate the link: a body that only
    // warned, followed by a `put_dataset` failure, would otherwise still
    // advertise a report for a write that stored nothing.
    let res =
        if findings.is_some() && res.status().is_success() { report_link(target, res) } else { res };
    (res, existence, materialized)
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

async fn post_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap, body: Bytes) -> Response {
    let store = st.store.as_ref();
    // Authorize the target FIRST, even though Append on a non-container is a
    // meaningless grant in practice: the 409 below is derived from the
    // request path alone, but no handler branch may answer before `authorize`
    // runs, so an unauthorized caller never learns even that much about the
    // path they probed. An auxiliary lands here too — POST is how one would
    // try to create one, and it is refused as "not a container".
    let parent_guard = match Guard::probe(store, agent.clone(), target.clone()).await {
        Ok(g) => g,
        Err(d) => return with_aux_links(d.into_response(), &target),
    };
    if let Err(d) = parent_guard.authorize(Mode::Append) {
        return with_aux_links(d.into_response(), &target);
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
    // Note: this probe followed by the write below is not transactional; a
    // concurrent write landing between them could be missed. Accepted for
    // single-user v1.
    let mut child_guard = match Guard::probe(store, agent.clone(), child.clone()).await {
        Ok(g) => g,
        Err(d) => return with_aux_links(d.into_response(), &child),
    };
    if child_guard.is_taken() {
        let unique = format!("{name}-{}{suffix}", uuid::Uuid::new_v4());
        child = match classify(&st.space, &format!("{}{unique}", parent.path())) {
            Ok(t) => t,
            Err(status) => return status.into_response(),
        };
        child_guard = match Guard::probe(store, agent.clone(), child.clone()).await {
            Ok(g) => g,
            Err(d) => return with_aux_links(d.into_response(), &child),
        };
    }
    // The container's Append is not enough to authorize the CHILD: it may
    // carry an ACL of its own that grants less than the container does.
    // Mode::Append (not Write) to stay consistent with the container-level
    // check above, or the append-only inbox pattern this design targets would
    // break — every legitimate append-only POST would suddenly need Write on
    // the child it creates.
    if let Err(d) = child_guard.authorize(Mode::Append) {
        return with_aux_links(d.into_response(), &child);
    }
    let repr = match classify_body(&headers, &body, &child, st.store.rdf_version()) {
        Ok(r) => r,
        Err(res) => return *res,
    };
    // The dataset checks below have no meaning for a blob: no named graphs,
    // no reserved namespace, no containment triples. It gets its own
    // over-long-key check instead, run here for the same reason the dataset
    // checks are — before the ancestor walk below writes anything.
    let mut findings = None;
    let skolemized = match &repr {
        Repr::Rdf(dataset, _, _) => {
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
    let materialized = match child_guard.materialize().await {
        Ok(m) => m,
        Err(d) => return with_aux_links(d.into_response(), &child),
    };
    let res = match &child {
        Target::Resource(r) => match repr {
            Repr::Blob(bytes, mt) => match put_blob(store, st.blobs.as_ref(), r, bytes, &mt).await {
                Ok(()) => created(&child),
                Err(ResourceError::KeyTooLong) => StatusCode::URI_TOO_LONG.into_response(),
                Err(e) => put_error(&e),
            },
            Repr::Rdf(_, fmt, _) => {
                let skolemized = skolemized.expect("Repr::Rdf produced a skolemized dataset above");
                match put_dataset(store, st.blobs.as_ref(), r, &skolemized, fmt).await {
                    Ok(()) => created(&child),
                    Err(e) => put_error(&e),
                }
            }
        },
        // A freshly allocated name, so there are no members to preserve — the
        // read-then-merge `put_impl` does for an existing container has
        // nothing to read here.
        Target::Container(c) => {
            let Repr::Rdf(dataset, _, _) = &repr else {
                unreachable!("classify_body refuses a blob for Target::Container")
            };
            let triples = triples_of(&dataset.default_graph_only());
            match put_rdf(store, c, &triples).await {
                Ok(()) => match container::ensure_container(store, c).await {
                    Ok(()) => created(&child),
                    Err(e) => put_error(&e),
                },
                Err(e) => put_error(&e),
            }
        }
        // Unreachable: a `Slug` can never name an auxiliary (see above), and
        // the only other shape `classify` can return for a child path is the
        // container the `Link` header asks for.
        Target::Aux(_) => internal_error(&"a POST allocated a child path that names an auxiliary"),
    };
    // Mirrors `put_impl`'s tail: findings alone cannot gate the link, or a
    // body that only warned, followed by a storage failure, would advertise a
    // report for a child that was never created.
    let res = if findings.is_some() && res.status().is_success() { report_link(&child, res) } else { res };
    crate::notify::emit_post(&st, &child, &materialized, res.status()).await;
    res
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
/// become an existence oracle. The [`RdfVersion`] this also takes is a
/// deployment constant ([`SparqlStore::rdf_version`]) rather than a lookup, so
/// that argument survives it intact.
///
/// `Access-Control-Allow-Headers` mirrors what was asked for rather than
/// naming a fixed set: `protocol/cors/accept-acah` sends two otherwise
/// identical preflights and requires `Accept` to be absent from the answer to
/// the one that did not request it.
fn options_impl(target: &Target, headers: &HeaderMap, version: RdfVersion) -> Response {
    let mut out = HeaderMap::new();
    let methods = allowed_methods(target);
    out.insert(header::ALLOW, HeaderValue::from_static(methods));
    out.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(methods));
    out.insert("accept-patch", HeaderValue::from_static(ACCEPT_PATCH));
    for (name, method) in [("accept-put", Write::Put), ("accept-post", Write::Post)] {
        if let Some(value) = accept_write(target, method, version) {
            out.insert(name, value.parse().expect("media types and version labels are header-safe"));
        }
    }
    if let Some(requested) = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
    }
    (StatusCode::NO_CONTENT, out).into_response()
}

async fn handle_options(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) => options_impl(&target, &headers, st.store.rdf_version()),
        Err(status) => status.into_response(),
    }
}

async fn handle_options_root(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match classify(&st.space, "/") {
        Ok(target) => options_impl(&target, &headers, st.store.rdf_version()),
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
    let guard = match Guard::probe(store, agent, target.clone()).await {
        Ok(g) => g,
        Err(d) => return with_aux_links(d.into_response(), &target),
    };
    if let Err(d) = guard.authorize(Mode::Read) {
        return with_aux_links(d.into_response(), &target);
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
            Err(e) => return put_error(&e),
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
            Err(e) => return put_error(&e),
        },
        Target::Aux(_) => unreachable!("an auxiliary already returned above"),
    };
    let report = match crate::shapes::validate(&shapes.turtle, &dataset) {
        Ok(r) => r,
        Err(e) => return shape_status(e),
    };
    let accept = header_str(&headers, header::ACCEPT);
    // The report is this pod's own RDF; there is no stored version to
    // project, so the negotiated version is not carried further.
    let Some((fmt, _)) = negotiate(accept, Shape::Graph, None) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    match fmt.serialize(&report.into_dataset()) {
        Ok(bytes) => {
            let mut out = HeaderMap::new();
            out.insert(header::CONTENT_TYPE, fmt.media_type().parse().expect("static media type"));
            out.insert(header::VARY, "Accept".parse().expect("static"));
            (out, bytes).into_response()
        }
        Err(e) => internal_error(&e),
    }
}

/// §3.4: the validator for a blob, computed from the bytes about to be served.
///
/// Not `ObjectMeta::e_tag`: it is optional, its meaning differs per backend,
/// and it changes under a backend migration although the content did not. This
/// is the same rule and the same shape as
/// [`Skolemized::etag`](crate::dataset::Skolemized::etag).
pub(crate) fn blob_etag(bytes: &[u8]) -> String {
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
        Err(e) => return internal_error(&e),
    };
    let tag = blob_etag(&bytes);
    let mut out = HeaderMap::new();
    out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
    out.insert(header::VARY, "Accept".parse().expect("static"));
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
        return with_allow(
            with_aux_links((StatusCode::NOT_MODIFIED, out).into_response(), &target),
            &target, st.store.rdf_version());
    }
    // `MediaType` carries the `HeaderValue` its constructor validated, so
    // there is nothing here to assert.
    out.insert(header::CONTENT_TYPE, mt.header_value());
    with_allow(with_aux_links((out, bytes).into_response(), &target), &target, st.store.rdf_version())
}

async fn get_impl(st: AppState, agent: Agent, target: Target, headers: HeaderMap) -> Response {
    let store = st.store.as_ref();
    let guard = match Guard::probe(store, agent, target.clone()).await {
        Ok(g) => g,
        Err(d) => return with_aux_links(d.into_response(), &target),
    };
    let decision = match guard.authorize(Mode::Read) {
        Ok(dec) => dec,
        Err(d) => return with_aux_links(d.into_response(), &target),
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
        Err(e) => return internal_error(&e),
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
        Err(e) => return internal_error(&e),
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
    let Some((fmt, requested)) = negotiate(header_str(&headers, header::ACCEPT), shape, stored_type) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    // §5: what is actually served is the lower of what the client asked for
    // and what the resource is — asking for 1.2 of a plain 1.1 resource is
    // answered, and advertised, as 1.1.
    let held = visible.rdf_version();
    let served_version = requested.min(held);
    let tag = stored.etag(fmt, served_version);
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
        let mut out = HeaderMap::new();
        out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
        out.insert(header::VARY, "Accept".parse().expect("static"));
        return with_read_headers(
            (StatusCode::NOT_MODIFIED, out).into_response(), &target, &decision,
            store.rdf_version());
    }
    // §6.2: a graph format gets the default graph, and is told what it missed.
    let served = if fmt.carries_dataset() { visible.clone() } else { visible.default_graph_only() };
    let served = served.project_to(served_version);
    let bytes = match fmt.serialize(&served) {
        Ok(b) => b,
        Err(e) => return internal_error(&e),
    };
    let mut out = HeaderMap::new();
    // §5: the response states the version it carries — but only where a
    // version is in play at all. RDF 1.2 Concepts encourages announcing a
    // version for "documents that make use of RDF 1.2-specific
    // functionality"; stamping `version=1.1` on every plain Turtle response
    // would contradict that, and would break every client comparing
    // `Content-Type` for equality, the conformance harness included.
    //
    // On a resource that *is* 1.2, the parameter carries real information in
    // both directions: `version=1.2` says the triple terms are here, and
    // `version=1.1` says they were left out — which, with the `alternate`
    // link below, is the whole loss signal. No minted vocabulary, because a
    // version is a property of the representation as a whole and has no
    // parts to enumerate.
    out.insert(
        header::CONTENT_TYPE,
        if held > RdfVersion::Rdf11 {
            format!("{};version={}", fmt.media_type(), served_version.label())
                .parse().expect("media type and version label are token-safe")
        } else {
            fmt.media_type().parse().expect("static media type")
        },
    );
    out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
    out.insert(header::VARY, "Accept".parse().expect("static"));
    // §5: only when the version actually cost something. The link names the
    // resource's *own* classification, not a blanket 1.2 — promising triple
    // terms a `1.2-basic` resource does not have would be a worse answer than
    // saying nothing.
    if served_version < held {
        out.append(header::LINK, format!(
            "<{}>; rel=\"alternate\"; type=\"{};version={}\"",
            r.graph_iri(), fmt.media_type(), held.label()
        ).parse().expect("media type and version label are token-safe"));
    }
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
    with_read_headers((out, bytes).into_response(), &target, &decision, store.rdf_version())
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
    let Some((fmt, requested)) = negotiate(header_str(&headers, header::ACCEPT), Shape::Graph, None) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    match get_rdf(store, &target).await {
        Ok(Some(triples)) => {
            let ground = ground_dataset(triples);
            // De-skolemized first, because the served version is a property
            // of what the client would see and the ETag has to cover it.
            let visible = ground.deskolemize();
            let held = visible.rdf_version();
            let served_version = requested.min(held);
            let tag = ground.etag(fmt, served_version);
            if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
                // `Vary: Accept` on every negotiated response (§6.3), and this
                // path negotiates as much as the resource path does.
                let mut out = HeaderMap::new();
                out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
                out.insert(header::VARY, "Accept".parse().expect("static"));
                return with_read_headers(
                    (StatusCode::NOT_MODIFIED, out).into_response(), &target, decision,
                    store.rdf_version(),
                );
            }
            match fmt.serialize(&visible.project_to(served_version)) {
                Ok(bytes) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::CONTENT_TYPE,
                        if held > RdfVersion::Rdf11 {
                            format!("{};version={}", fmt.media_type(), served_version.label())
                                .parse().expect("media type and version label are token-safe")
                        } else {
                            fmt.media_type().parse().expect("static media type")
                        },
                    );
                    headers.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
                    headers.insert(header::VARY, "Accept".parse().expect("static"));
                    if served_version < held {
                        headers.append(header::LINK, format!(
                            "<{}>; rel=\"alternate\"; type=\"{};version={}\"",
                            target.graph_iri(), fmt.media_type(), held.label()
                        ).parse().expect("media type and version label are token-safe"));
                    }
                    with_read_headers(
                        (headers, bytes).into_response(), &target, decision, store.rdf_version())
                }
                Err(e) => internal_error(&e),
            }
        }
        // The advertisement matters most here: a client creating a resource
        // learns where its ACL goes from the 404 it got when it looked.
        Ok(None) => with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Err(ResourceError::InvalidIri) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => internal_error(&e),
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
    let guard = match Guard::probe(store, agent, target.clone()).await {
        Ok(g) => g,
        Err(d) => return with_aux_links(d.into_response(), &target),
    };
    if let Err(d) = guard.authorize(Mode::Write) {
        return with_aux_links(d.into_response(), &target);
    }
    // The auxiliary arm's response carries no `present_auxes` of its own — an
    // auxiliary cascades no others — so both arms reach the single emit below
    // through the same pair.
    let (res, present_auxes): (Response, Vec<AuxUrl>) = if let Target::Aux(a) = &target {
        // Removing an auxiliary is a complete operation on its own: the path
        // falls back to inherited policy, which is exactly what its absence
        // means. Nothing else refers to it — an auxiliary is never a
        // container member — so there is no containment to repair.
        let res = match delete_rdf(store, a).await {
            Ok(true) => StatusCode::NO_CONTENT.into_response(),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(e) => internal_error(&e),
        };
        (res, Vec::new())
    } else {
        let subject = match &target {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource(),
            Target::Aux(_) => unreachable!("matched above"),
        };
        // Removing a member rewrites the parent's containment triples.
        if let Err(d) = guard.authorize_parent(Mode::Write) {
            return with_aux_links(d.into_response(), &target);
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
        //
        // `authorize_aux` answers `Ok(Some(_))` exactly for a kind the probe
        // found present, so that same call collects `present_auxes` — the set
        // `emit_delete` reports — without a second probe.
        let mut present_auxes: Vec<AuxUrl> = Vec::new();
        for kind in AuxKind::ALL {
            match guard.authorize_aux(*kind) {
                Err(d) => return with_aux_links(d.into_response(), &target),
                Ok(Some(_)) => present_auxes.push(subject.aux(*kind)),
                Ok(None) => {}
            }
        }
        if let Target::Container(c) = &target {
            if subject.parent().is_none() {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            match container::container_is_empty(store, c).await {
                Ok(false) => return StatusCode::CONFLICT.into_response(),
                Ok(true) => {}
                Err(e) => return internal_error(&e),
            }
        }
        // The parent's containment triple goes with the subject, inside
        // `delete_subject`'s own update — this handler cannot leave the two
        // half-applied because it never holds them apart.
        let res = match aux::delete_subject(store, st.blobs.as_ref(), subject).await {
            Ok(true) => StatusCode::NO_CONTENT.into_response(),
            Ok(false) => with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
            Err(e) => internal_error(&e),
        };
        (res, present_auxes)
    };
    crate::notify::emit_delete(&st, &target, &present_auxes, res.status()).await;
    res
}

#[cfg(test)]
mod tests;
