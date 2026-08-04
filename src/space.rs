//! The pod's URI topology: which URLs exist, what they mean, and how they
//! relate. Every path enters the system through [`StorageSpace::resolve`],
//! which classifies it exactly once — the constructors below are private, so
//! no other module can mint a URL or re-derive what kind of thing it is.
//!
//! See `docs/uri-space.md` for the client-facing contract.

use oxigraph::model::NamedNode;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SpaceError {
    #[error("base URI must be absolute (http:// or https://)")]
    NotAbsolute,
    #[error("base URI must end with a trailing slash")]
    NoTrailingSlash,
    #[error("base URI does not form a valid IRI")]
    InvalidBaseIri,
    #[error("resource path does not form a valid IRI")]
    InvalidResourceIri,
    #[error("path is in a reserved namespace and names nothing addressable there")]
    Reserved,
    #[error("request path must start with '/'")]
    NotRooted,
    #[error("request path contains a segment that URI/htu normalization would remove or resolve")]
    NotNormalized,
}

/// The reserved first segments. Everything under one of them is
/// server-understood; everything else is the user's.
///
/// `.aux` holds auxiliary resources, which [`StorageSpace::resolve`] decodes
/// into an [`AuxUrl`]. `.well-known` is origin infrastructure (RFC 8615),
/// answered by routes of its own in `crate::http`: nothing under it is
/// storage, so no path there resolves to anything at all.
const AUX_SEGMENT: &str = ".aux";
const WELL_KNOWN_SEGMENT: &str = ".well-known";
const RESERVED_SEGMENTS: &[&str] = &[AUX_SEGMENT, WELL_KNOWN_SEGMENT];

mod sealed {
    pub trait Sealed {}
}

/// Anything addressable as a named graph. Sealed: every implementor's
/// `graph_iri` is interpolated verbatim into SPARQL, so only types minted
/// through `StorageSpace::resolve` (and its `root`/`parent`/`ancestors`/
/// `as_container` derivatives) may implement it.
pub trait GraphName: sealed::Sealed + Sync {
    fn graph_iri(&self) -> &str;
}

/// A graph that may be written straight to the store, because nothing has to
/// be true of anything else first. Sealed through [`GraphName`].
///
/// Not [`AuxUrl`]: an auxiliary may only be written for a subject that
/// exists, and that condition is part of the write itself — see `aux::put`,
/// which carries it inside the update. A direct `resource::put_rdf` would
/// plant a policy document on a path that was never created, and
/// nearest-ACL-wins would then make it permanent and unremovable. That is the
/// defect this bound exists to make uncompilable; `aux::` being a convention
/// was not enough.
///
/// Not [`Target`]: a `Target` has not yet been decided into resource-or-
/// auxiliary, so it cannot say which lifecycle rule applies. Match on it
/// first — the arm you land in carries the right bound.
pub trait DirectlyWritable: GraphName {}

/// A graph that may be deleted on its own, taking nothing else with it.
/// Sealed through [`GraphName`].
///
/// Only [`AuxUrl`]: removing an auxiliary is a complete operation — the path
/// falls back to inherited policy, which is exactly what its absence means.
///
/// Not [`ResourceUrl`]/[`ContainerUrl`]: deleting a subject must take every
/// auxiliary with it, or a recreated path resurrects the old grants. The
/// cascade is `aux::delete_subject`, and this bound is what stops a caller
/// from reaching past it with `resource::delete_rdf`.
///
/// Not [`Target`]: same reason as [`DirectlyWritable`].
pub trait DirectlyDeletable: GraphName {}

/// A kind of auxiliary resource. Closed and server-defined: a kind exists
/// only if the server enforces its lifecycle, listing exclusion and
/// authorization derivation. This enum is the single source of truth for
/// both routing and the `Link` headers, so the two cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxKind {
    Acl,
}

impl AuxKind {
    pub const ALL: &'static [AuxKind] = &[AuxKind::Acl];

    /// This kind's name, which an auxiliary URL carries as its suffix.
    pub fn name(self) -> &'static str {
        match self {
            AuxKind::Acl => "acl",
        }
    }

    /// The `Link` relation this kind is advertised with.
    pub fn link_rel(self) -> &'static str {
        match self {
            AuxKind::Acl => "acl",
        }
    }

    /// What an auxiliary URL of this kind ends in: `.` plus the kind's name.
    fn suffix(self) -> String {
        format!(".{}", self.name())
    }

    /// Split a path inside the reserved namespace into the kind it names and
    /// the subject path that remains. The inverse of appending [`suffix`].
    ///
    /// No two kinds' suffixes may be suffixes of one another, or this split
    /// would be ambiguous. Guaranteed by `aux_kind_names_are_well_formed`'s
    /// no-dot rule on every name — see its doc comment for why that alone
    /// is enough.
    fn split_suffix(rest: &str) -> Option<(Self, &str)> {
        AuxKind::ALL
            .iter()
            .copied()
            .find_map(|k| rest.strip_suffix(&k.suffix()).map(|subject| (k, subject)))
    }
}

/// A URL in the resource space — the user's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceUrl {
    path: String,
    iri: String,
}

/// A [`ResourceUrl`] whose path ends in `/`. The field is private, not
/// `pub(crate)`: the only checked constructor is [`ResourceUrl::as_container`],
/// so a `ContainerUrl` cannot be minted around a resource that isn't one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerUrl(ResourceUrl);

/// A URL in the reserved auxiliary space, carrying its subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxUrl {
    kind: AuxKind,
    subject: ResourceUrl,
    iri: String,
}

/// What a request addresses. Produced once, by [`StorageSpace::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Resource(ResourceUrl),
    Container(ContainerUrl),
    Aux(AuxUrl),
}

impl sealed::Sealed for ResourceUrl {}
impl sealed::Sealed for ContainerUrl {}
impl sealed::Sealed for AuxUrl {}
impl sealed::Sealed for Target {}

impl GraphName for ResourceUrl {
    fn graph_iri(&self) -> &str {
        &self.iri
    }
}
impl GraphName for ContainerUrl {
    fn graph_iri(&self) -> &str {
        self.0.graph_iri()
    }
}
impl GraphName for AuxUrl {
    fn graph_iri(&self) -> &str {
        &self.iri
    }
}
impl GraphName for Target {
    fn graph_iri(&self) -> &str {
        match self {
            Target::Resource(r) => r.graph_iri(),
            Target::Container(c) => c.graph_iri(),
            Target::Aux(a) => a.graph_iri(),
        }
    }
}

impl DirectlyWritable for ResourceUrl {}
impl DirectlyWritable for ContainerUrl {}

impl DirectlyDeletable for AuxUrl {}

impl ResourceUrl {
    pub fn path(&self) -> &str {
        &self.path
    }

    /// This resource's auxiliary of the given kind: `/.aux`, this resource's
    /// own path, and the kind's name as a suffix. Total — every resource has
    /// an auxiliary URL whether or not that auxiliary has a representation —
    /// and inverted by [`AuxUrl::subject`].
    ///
    /// The kind is a suffix rather than a leading segment so that an auxiliary
    /// URL never ends in `/`, which is the shape every other Solid server
    /// produces (`.acl`, `.acr`, `.meta`) and the one clients normalize
    /// without damage. Classification is unaffected: the router still decides
    /// resource-space-or-auxiliary-space from the first segment alone.
    pub fn aux(&self, kind: AuxKind) -> AuxUrl {
        let base = self.iri.strip_suffix(&self.path).expect("iri ends with path");
        let iri = format!("{base}/{AUX_SEGMENT}{}{}", self.path, kind.suffix());
        AuxUrl { kind, subject: self.clone(), iri }
    }

    /// The other half of this URL's trailing-slash pair — `/box/` for `/box`,
    /// `/box` for `/box/` — or `None` for the root, whose counterpart would be
    /// the empty path and is no URL in this space at all.
    ///
    /// Solid Protocol §3.1: "If two URIs differ only in the trailing slash,
    /// and the server has associated a resource with one of them, then the
    /// other URI MUST NOT correspond to another resource." The pair stays
    /// *addressable* — `/box` and `/box/` are still two names, one of which
    /// may exist — so this derivation is what a create consults, not a
    /// canonicalization of one onto the other.
    ///
    /// Unlike `resource()`, this mints the `ResourceUrl` directly rather than
    /// re-running `NamedNode::new` on the result — which is exactly what the
    /// module header says the private constructors exist to prevent going
    /// unexamined. It is safe here: `self.iri` was already validated by
    /// whichever constructor produced `self`, and adding or removing a
    /// single trailing `/` is the only byte-level change made to it — it
    /// cannot turn a valid IRI into an invalid one (and the root, the one
    /// path whose counterpart would be the empty string, is handled above by
    /// returning `None` before an IRI is built at all). The `debug_assert!`
    /// pins that argument rather than leaving it asserted only in prose.
    pub fn slash_counterpart(&self) -> Option<ResourceUrl> {
        let path = match self.path.strip_suffix('/') {
            Some("") => return None, // the root
            Some(stripped) => stripped.to_string(),
            None => format!("{}/", self.path),
        };
        let base = self.iri.strip_suffix(&self.path).expect("iri ends with path");
        let iri = format!("{base}{path}");
        debug_assert!(
            NamedNode::new(&iri).is_ok(),
            "slash_counterpart must preserve IRI validity: {iri}"
        );
        Some(ResourceUrl { iri, path })
    }

    pub fn as_container(&self) -> Option<ContainerUrl> {
        self.path.ends_with('/').then(|| ContainerUrl(self.clone()))
    }

    /// The immediate parent container, or `None` for the root.
    pub fn parent(&self) -> Option<ContainerUrl> {
        if self.path == "/" {
            return None;
        }
        let trimmed = self.path.strip_suffix('/').unwrap_or(&self.path);
        let idx = trimmed.rfind('/')?;
        let parent_path = trimmed[..=idx].to_string();
        let base = self.iri.strip_suffix(&self.path).expect("iri ends with path");
        Some(ContainerUrl(ResourceUrl {
            iri: format!("{base}{parent_path}"),
            path: parent_path,
        }))
    }

    /// Every container between this resource and the root, nearest first.
    /// This is the chain a create may materialize, and the same chain the
    /// guard authorizes — one derivation, used by both.
    pub fn ancestors(&self) -> Vec<ContainerUrl> {
        let mut out = Vec::new();
        let mut current = self.clone();
        while let Some(parent) = current.parent() {
            current = parent.0.clone();
            out.push(parent);
        }
        out
    }
}

impl ContainerUrl {
    pub fn path(&self) -> &str {
        self.0.path()
    }
    pub fn as_resource(&self) -> &ResourceUrl {
        &self.0
    }
}

impl AuxUrl {
    pub fn subject(&self) -> &ResourceUrl {
        &self.subject
    }
    pub fn kind(&self) -> AuxKind {
        self.kind
    }
}

#[derive(Debug, Clone)]
pub struct StorageSpace {
    base: String,
}

impl StorageSpace {
    pub fn new(base: impl Into<String>) -> Result<Self, SpaceError> {
        let base = base.into();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(SpaceError::NotAbsolute);
        }
        if !base.ends_with('/') {
            return Err(SpaceError::NoTrailingSlash);
        }
        NamedNode::new(&base).map_err(|_| SpaceError::InvalidBaseIri)?;
        Ok(Self { base })
    }

    /// Classify a raw request path. This is the only way a URL enters the
    /// system, and the only place the reserved namespaces are recognized.
    ///
    /// The IRI is validated here, once, because it is later interpolated
    /// verbatim into SPARQL as `<{iri}>`.
    pub fn resolve(&self, request_path: &str) -> Result<Target, SpaceError> {
        if !request_path.starts_with('/') {
            return Err(SpaceError::NotRooted);
        }
        // `dpop-verifier`'s `htu` comparison (see `auth::middleware`) drops
        // empty path segments, resolves `.`/`..`, and strips fragments before
        // comparing. A path that normalization would change names one
        // resource here but a DIFFERENT, canonicalized one to that
        // comparison — so two distinct named graphs with independent ACLs
        // (e.g. `/box` and `/box//`, or `/a/b` and `/a/%23/../b`) would look
        // like the same `htu` to a replayed or re-routed request. Refusing
        // the non-stable shape outright is cheaper and safer than trying to
        // canonicalize it, which would silently change which resource a
        // request names. The trailing slash itself is exempt: it is what
        // distinguishes a container and is not a segment normalization would
        // remove.
        if !Self::is_normalization_stable(request_path) {
            return Err(SpaceError::NotNormalized);
        }
        // `/.well-known/` is the origin's own space (RFC 8615), answered by
        // routes of its own in `crate::http`, and it names no storage at any
        // depth — the bare forms included. Refusing it here, not only in the
        // router, is what stops a write from allocating inside it: a
        // resource placed there — by `Slug: .well-known` at the root, say —
        // would be shadowed by those routes on GET and undeletable, since
        // they route no write method at all.
        if Self::segment_remainder(request_path, WELL_KNOWN_SEGMENT).is_some() {
            return Err(SpaceError::Reserved);
        }
        if let Some(rest) = Self::segment_remainder(request_path, AUX_SEGMENT) {
            // `rest` is everything after `/.aux`: "" for `/.aux` itself,
            // otherwise a path starting with `/`. Stripping the kind's suffix
            // inverts `ResourceUrl::aux` exactly — `/.aux/box/.acl` yields
            // `/box/`, `/.aux/.acl` yields `/`. A path under `/.aux` that ends
            // in no kind's suffix (including `/.aux` and `/.aux/` themselves)
            // names no auxiliary and is reserved, not data.
            let Some((kind, subject_path)) = AuxKind::split_suffix(rest) else {
                return Err(SpaceError::Reserved);
            };
            // An auxiliary has no auxiliary — `AuxUrl` cannot build one, and the
            // path space must not name one either. Without this, the subject of
            // `/.aux/.aux/foo.acl.acl` would be a plain resource whose IRI is the
            // ACL graph of `/foo`, and authorization would derive from it. The
            // check is on the *decoded subject*, so it refuses every nesting
            // depth: each strip peels one suffix, and the subject that remains
            // still begins with the reserved segment. It is every reserved
            // segment, not just `.aux`: a subject the resource space itself
            // refuses may not be reached through an auxiliary either.
            if Self::reserved_segment(subject_path).is_some() {
                return Err(SpaceError::Reserved);
            }
            // The subject is derived by removing a suffix, so — unlike the old
            // shape, where it was a suffix of the request path — it can be a
            // path this pod would refuse in its own right: `/.aux/..acl` names
            // the subject `/.`, which `dpop-verifier`'s `htu` normalization
            // would resolve to something else entirely. An auxiliary may only
            // name a subject the resource space itself accepts.
            if !Self::is_normalization_stable(subject_path) {
                return Err(SpaceError::NotNormalized);
            }
            let subject = self.resource(subject_path)?;
            let aux = subject.aux(kind);
            NamedNode::new(&aux.iri).map_err(|_| SpaceError::InvalidResourceIri)?;
            return Ok(Target::Aux(aux));
        }
        let resource = self.resource(request_path)?;
        Ok(match resource.as_container() {
            Some(container) => Target::Container(container),
            None => Target::Resource(resource),
        })
    }

    /// The root container. Provisioning needs it before any request exists.
    pub fn root(&self) -> ContainerUrl {
        match self.resolve("/").expect("the root path is always valid") {
            Target::Container(c) => c,
            _ => unreachable!("\"/\" resolves to a container"),
        }
    }

    /// True iff normalizing `request_path` the way DPoP's `htu` comparison
    /// does (dropping empty segments, resolving `.`/`..`, stripping
    /// fragments) would leave it unchanged. Callers only pass paths already
    /// validated to start with `/`.
    ///
    /// The single trailing slash is deliberately not a segment: `/box` and
    /// `/box/` are different resources here (a resource and a container) and
    /// both must stay stable. It is any OTHER empty segment — `//` anywhere,
    /// including a doubled trailing slash — that normalization would remove.
    fn is_normalization_stable(request_path: &str) -> bool {
        if request_path.contains('#') {
            return false;
        }
        let rest = &request_path[1..]; // strip the leading '/' callers guarantee
        if rest.is_empty() {
            return true; // "/" itself — the root, nothing to check
        }
        let segments: Vec<&str> = rest.split('/').collect();
        // Every segment but the last must be non-empty and not a dot-segment
        // — an empty or dot segment there is exactly what normalization would
        // drop or resolve. The last segment is different: empty is how a
        // legitimate single trailing slash appears here (the container
        // marker, not a removable segment), so it is allowed to be empty,
        // but if it is NOT empty it is an ordinary segment and must pass the
        // same check as any other.
        let (init, last) = segments.split_at(segments.len() - 1);
        let init_ok = init.iter().all(|seg| !seg.is_empty() && *seg != "." && *seg != "..");
        let last_ok = last[0].is_empty() || (last[0] != "." && last[0] != "..");
        init_ok && last_ok
    }

    /// What follows `/{segment}` when the path's *whole* first segment is
    /// `segment`. `/.auxiliary` and `/.well-known-x` are ordinary resources:
    /// a reservation costs exactly its own name, never a prefix of a longer
    /// name.
    fn segment_remainder<'p>(request_path: &'p str, segment: &str) -> Option<&'p str> {
        let rest = request_path.strip_prefix('/')?.strip_prefix(segment)?;
        (rest.is_empty() || rest.starts_with('/')).then_some(rest)
    }

    /// Which of [`RESERVED_SEGMENTS`] the path's first segment is, if any.
    fn reserved_segment(request_path: &str) -> Option<&'static str> {
        RESERVED_SEGMENTS
            .iter()
            .copied()
            .find(|segment| Self::segment_remainder(request_path, segment).is_some())
    }

    fn resource(&self, request_path: &str) -> Result<ResourceUrl, SpaceError> {
        let trimmed = request_path
            .strip_prefix('/')
            .expect("callers only pass paths validated to start with '/'");
        let iri = format!("{}{}", self.base, trimmed);
        NamedNode::new(&iri).map_err(|_| SpaceError::InvalidResourceIri)?;
        Ok(ResourceUrl { path: request_path.to_string(), iri })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_base_without_trailing_slash() {
        assert!(matches!(StorageSpace::new("https://pod.toph.so"),
            Err(SpaceError::NoTrailingSlash)));
    }

    #[test]
    fn rejects_non_absolute_base() {
        assert!(matches!(StorageSpace::new("pod.toph.so/"),
            Err(SpaceError::NotAbsolute)));
    }

    // Passes the scheme/trailing-slash checks but is not a valid IRI (the
    // space), so without this check `root()`'s `.expect(...)` would panic.
    #[test]
    fn rejects_a_base_that_is_not_a_valid_iri() {
        assert!(matches!(StorageSpace::new("https://pod .toph.so/"),
            Err(SpaceError::InvalidBaseIri)));
    }

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    #[test]
    fn resolve_classifies_the_three_kinds() {
        let s = sp();
        assert!(matches!(s.resolve("/foo").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/box/").unwrap(), Target::Container(_)));
        assert!(matches!(s.resolve("/").unwrap(), Target::Container(_)));
        assert!(matches!(s.resolve("/.aux/foo.acl").unwrap(), Target::Aux(_)));
        assert!(matches!(s.resolve("/.aux/.acl").unwrap(), Target::Aux(_)));
    }

    // A dot is only special as the whole first segment `.aux` or
    // `.well-known`. Everything else a user might name stays ordinary.
    #[test]
    fn only_the_two_reserved_segments_are_special() {
        let s = sp();
        assert!(matches!(s.resolve("/.hidden").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/.config/x").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/box/.aux").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/box/.aux/x.acl").unwrap(), Target::Resource(_)));
        // The reserved name is the whole segment, never a prefix of a longer one.
        assert!(matches!(s.resolve("/.auxiliary").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/.auxiliary/x").unwrap(), Target::Resource(_)));
    }

    // `/.well-known/` is the origin's, at every depth and in both bare
    // forms: it names no storage, so nothing there resolves and nothing can
    // be allocated there.
    #[test]
    fn the_well_known_segment_is_reserved_at_every_depth() {
        let s = sp();
        for path in [
            "/.well-known",
            "/.well-known/",
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
            "/.well-known/oauth-authorization-server",
            "/.well-known/a/b/c",
        ] {
            assert_eq!(s.resolve(path), Err(SpaceError::Reserved), "{path} must be reserved");
        }
        // ...and it is no subject either: an auxiliary may not reach a path
        // the resource space itself refuses.
        assert_eq!(s.resolve("/.well-known/x.acl"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/.well-known.acl"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/.well-known/x.acl"), Err(SpaceError::Reserved));
    }

    // The reservation costs exactly the name `.well-known` at the root — the
    // same bound `/.auxiliary` pins for `.aux`.
    #[test]
    fn a_well_known_near_miss_is_an_ordinary_resource() {
        let s = sp();
        assert!(matches!(s.resolve("/.well-known-x").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/.well-knownish/x").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/x/.well-known/y").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/x/.well-known/").unwrap(), Target::Container(_)));
        // ...and such a resource has an ACL like any other.
        assert!(matches!(s.resolve("/.aux/.well-known-x.acl").unwrap(), Target::Aux(_)));
        assert!(matches!(s.resolve("/.aux/x/.well-known/y.acl").unwrap(), Target::Aux(_)));
    }

    // The IRI comes from the configured base; the request host is ignored.
    #[test]
    fn resolve_builds_iris_from_the_configured_base() {
        let s = sp();
        assert_eq!(s.resolve("/foo").unwrap().graph_iri(), "https://pod.toph.so/foo");
        assert_eq!(s.resolve("/a/b").unwrap().graph_iri(), "https://pod.toph.so/a/b");
        assert_eq!(s.resolve("/").unwrap().graph_iri(), "https://pod.toph.so/");
    }

    // Every URL enters through `resolve`, so a slashless path must be
    // refused here rather than silently aliasing another resource's IRI.
    #[test]
    fn resolve_rejects_a_path_without_a_leading_slash() {
        let s = sp();
        assert_eq!(s.resolve(""), Err(SpaceError::NotRooted));
        assert_eq!(s.resolve("foo"), Err(SpaceError::NotRooted));
        assert_eq!(s.resolve("a/b/c"), Err(SpaceError::NotRooted));
    }

    #[test]
    fn unallocated_reserved_paths_are_refused() {
        let s = sp();
        assert_eq!(s.resolve("/.aux"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/bogus/x"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/acl"), Err(SpaceError::Reserved)); // no `.` before it
        assert_eq!(s.resolve("/.aux/foo"), Err(SpaceError::Reserved)); // no kind named
        assert_eq!(s.resolve("/.aux/foo.bogus"), Err(SpaceError::Reserved));
    }

    // The subject is what remains after the suffix comes off, so it can be a
    // path the resource space would refuse in its own right. `/.aux/..acl`
    // would name the subject `/.`, and `/.aux/...acl` the subject `/..` —
    // both shapes `dpop-verifier`'s `htu` normalization resolves elsewhere,
    // and both are refused for the auxiliary exactly as they are for the
    // resource.
    #[test]
    fn an_auxiliary_may_not_name_a_subject_normalization_would_alias() {
        let s = sp();
        assert_eq!(s.resolve("/.aux/..acl"), Err(SpaceError::NotNormalized));
        assert_eq!(s.resolve("/.aux/...acl"), Err(SpaceError::NotNormalized));
        assert_eq!(s.resolve("/.aux/box/..acl"), Err(SpaceError::NotNormalized));
        // ...while a dot-prefixed name that is not a dot-segment is ordinary,
        // and so is its ACL.
        assert!(matches!(s.resolve("/.aux/.hidden.acl").unwrap(), Target::Aux(_)));
    }

    // `AuxUrl` has no `aux()`, so no auxiliary-of-an-auxiliary can be built.
    // The path space must not offer one either — at any nesting depth.
    #[test]
    fn an_auxiliary_is_never_the_subject_of_an_auxiliary() {
        let s = sp();
        // The exact URL `foo`'s ACL's ACL would have, and every deeper nesting.
        assert_eq!(s.resolve("/.aux/.aux/foo.acl.acl"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/.aux/.aux/foo.acl.acl.acl"), Err(SpaceError::Reserved));
        assert_eq!(
            s.resolve("/.aux/.aux/.aux/.aux/foo.acl.acl.acl.acl"),
            Err(SpaceError::Reserved)
        );
        // The container root's, and the ones an attacker would reach for by
        // pasting the old shape or half of it.
        assert_eq!(s.resolve("/.aux/.aux/box/.acl.acl"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/.aux/.acl.acl"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/.aux/foo.acl"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/.aux.acl"), Err(SpaceError::Reserved));
        // A `.aux` segment that is not the subject's first is ordinary, so it
        // has an ACL like any other resource.
        assert!(matches!(s.resolve("/.aux/box/.aux.acl").unwrap(), Target::Aux(_)));
    }

    // Both directions are total and mutually inverse: a subject's auxiliary
    // URL resolves back to that same subject, and to the same `AuxUrl`.
    #[test]
    fn aux_and_subject_are_mutual_inverses() {
        let s = sp();
        for path in ["/", "/foo", "/box/", "/a/b/c", "/foo.acl", "/.hidden", "/.auxiliary"] {
            let (Target::Resource(r) | Target::Container(ContainerUrl(r))) = s.resolve(path).unwrap()
            else { panic!("{path} should be a resource or container") };
            for kind in AuxKind::ALL {
                let aux = r.aux(*kind);
                assert_eq!(aux.subject().path(), path, "round trip for {path}");
                let request_path =
                    aux.graph_iri().strip_prefix("https://pod.toph.so").expect("built from base");
                let Target::Aux(decoded) = s.resolve(request_path).unwrap() else {
                    panic!("{request_path} should resolve back to an auxiliary")
                };
                assert_eq!(decoded, aux, "resolve must invert aux() for {path}");
            }
        }
    }

    // The documented table, and the property that matters about it: no
    // auxiliary URL ends in a slash, whatever its subject looks like.
    #[test]
    fn aux_urls_have_the_documented_shape() {
        let s = sp();
        let acl_of = |p: &str| match s.resolve(p).unwrap() {
            Target::Resource(r) => r.aux(AuxKind::Acl),
            Target::Container(c) => c.as_resource().aux(AuxKind::Acl),
            Target::Aux(_) => panic!("not a subject"),
        };
        assert_eq!(acl_of("/").graph_iri(), "https://pod.toph.so/.aux/.acl");
        assert_eq!(acl_of("/foo").graph_iri(), "https://pod.toph.so/.aux/foo.acl");
        assert_eq!(acl_of("/box/").graph_iri(), "https://pod.toph.so/.aux/box/.acl");
        assert_eq!(acl_of("/a/b/c").graph_iri(), "https://pod.toph.so/.aux/a/b/c.acl");
        for path in ["/", "/foo", "/box/", "/a/b/c", "/a/b/c/"] {
            for kind in AuxKind::ALL {
                let iri = match s.resolve(path).unwrap() {
                    Target::Resource(r) => r.aux(*kind),
                    Target::Container(c) => c.as_resource().aux(*kind),
                    Target::Aux(_) => panic!("not a subject"),
                }
                .graph_iri()
                .to_string();
                assert!(!iri.ends_with('/'), "{iri} ends in a slash");
            }
        }
    }

    // The direction an attacker controls: decode an `AuxUrl` from a request
    // path, rather than building one from a subject via `aux()`. Every row of
    // the table above, read back.
    #[test]
    fn resolve_decodes_aux_urls_from_the_request_path() {
        let s = sp();
        for (path, subject) in [
            ("/.aux/.acl", "/"),
            ("/.aux/foo.acl", "/foo"),
            ("/.aux/box/.acl", "/box/"),
            ("/.aux/a/b/c.acl", "/a/b/c"),
            // A subject whose own name ends in `.acl` is ordinary data, and
            // its ACL is a different URL again.
            ("/.aux/foo.acl.acl", "/foo.acl"),
        ] {
            let Target::Aux(aux) = s.resolve(path).unwrap() else {
                panic!("{path} should be an auxiliary")
            };
            assert_eq!(aux.subject().path(), subject, "subject of {path}");
            assert_eq!(aux.kind(), AuxKind::Acl);
            assert_eq!(
                aux.graph_iri(),
                format!("https://pod.toph.so{path}"),
                "the decoded URL must be the one requested"
            );
        }
    }

    // The chain a create actually mutates: nearest first, root last.
    #[test]
    fn ancestors_are_nearest_first_and_end_at_root() {
        let s = sp();
        let Target::Resource(r) = s.resolve("/a/b/c").unwrap() else { panic!() };
        let paths: Vec<_> = r.ancestors().iter().map(|c| c.path().to_string()).collect();
        assert_eq!(paths, vec!["/a/b/", "/a/", "/"]);

        let Target::Container(root) = s.resolve("/").unwrap() else { panic!() };
        assert!(root.as_resource().ancestors().is_empty(), "root has no ancestors");
    }

    #[test]
    fn graph_iri_still_rejects_iri_breaking_paths() {
        assert_eq!(sp().resolve("/foo> bar"), Err(SpaceError::InvalidResourceIri));
    }

    // Pins `AuxKind`'s invariants so a new variant can't silently misbehave:
    // the `match` is exhaustive over the enum, so forgetting to add the
    // variant here — and to `ALL` — is a compile error, not a silent gap in
    // routing or `Link` headers. Each kind's name must also be non-empty and
    // slash-free (a `/` would make the suffix span segments and the split
    // ambiguous) and IRI-safe (it is interpolated into a graph IRI).
    //
    // The no-dot rule is also what keeps `split_suffix` unambiguous as more
    // kinds are added, with no separate test needed for it: every suffix is
    // `"." + name`, and a name here contains no `.`, so the only `.` in a
    // suffix is its own leading one. One suffix can therefore never be a
    // suffix of a different one — that would require the shorter suffix's
    // leading `.` to land on some OTHER `.` inside the longer one, and there
    // is no such character to land on.
    #[test]
    fn aux_kind_names_are_well_formed() {
        for kind in AuxKind::ALL {
            match kind {
                AuxKind::Acl => {}
            }
            let name = kind.name();
            assert!(!name.is_empty(), "{kind:?} has an empty name");
            assert!(!name.contains('/'), "{kind:?}'s name contains '/'");
            assert!(!name.contains('.'), "{kind:?}'s name contains '.'");
            let iri = format!("https://pod.toph.so/.aux/x{}", kind.suffix());
            assert!(NamedNode::new(&iri).is_ok(), "{kind:?}'s name is not IRI-safe");
        }
    }

    // The pair Protocol §3.1 forbids from co-existing. Both directions, and
    // the root — whose counterpart would be the empty path, which is no URL.
    #[test]
    fn slash_counterpart_is_the_other_half_of_the_pair() {
        let s = sp();
        let res = |p: &str| match s.resolve(p).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        };
        for (path, other) in [("/foo", "/foo/"), ("/box/", "/box"), ("/a/b/c", "/a/b/c/")] {
            let counterpart = res(path).slash_counterpart().expect("has a counterpart");
            assert_eq!(counterpart.path(), other);
            assert_eq!(counterpart.graph_iri(), format!("https://pod.toph.so{other}"));
            // ...and it is an involution: the counterpart's counterpart is
            // the original, so neither half is privileged.
            assert_eq!(counterpart.slash_counterpart().as_ref(), Some(&res(path)));
        }
        assert_eq!(res("/").slash_counterpart(), None, "the root has no counterpart");
    }

    // The aliasing `dpop-verifier::normalize_htu` performs (drop empty
    // segments, resolve dot-segments, strip fragments) must never let two
    // paths this pod treats as distinct named graphs compare equal as `htu`.
    // `resolve` closes that gap by refusing every shape normalization would
    // change, rather than by canonicalizing it — see the doc comment on
    // `is_normalization_stable`.
    #[test]
    fn resolve_rejects_paths_normalization_would_alias() {
        let s = sp();
        for path in [
            "/a//b",        // empty segment in the middle
            "/a/b//",       // doubled trailing slash — not the one legitimate slash
            "//",           // an empty segment followed by the trailing slash
            "/a/./b",       // a `.` segment
            "/a/../b",      // a `..` segment
            "/a/..",        // trailing `..`
            "/./",          // `.` as the only segment
            // A literal `#`. `resolve` always receives an already
            // percent-DECODED path (see `auth::middleware::derive_htu` and
            // `http::classify`'s callers), so `%23` in a raw request path
            // arrives here as this literal character, not as the three
            // characters `%23`.
            "/a#b",
        ] {
            assert_eq!(s.resolve(path), Err(SpaceError::NotNormalized), "{path} must be refused");
        }
    }

    // The trailing slash is NOT a segment normalization would remove — it is
    // what distinguishes a container from a resource, and it must keep
    // resolving exactly as before this rule existed.
    #[test]
    fn resolve_still_accepts_the_legitimate_trailing_slash() {
        let s = sp();
        assert!(matches!(s.resolve("/box/").unwrap(), Target::Container(_)));
        assert!(matches!(s.resolve("/box").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/").unwrap(), Target::Container(_)));
        assert!(matches!(s.resolve("/a/b/c/").unwrap(), Target::Container(_)));
    }
}
