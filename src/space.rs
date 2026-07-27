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
    #[error("path is in the reserved namespace but names no auxiliary resource")]
    Reserved,
    #[error("request path must start with '/'")]
    NotRooted,
}

/// The reserved first segment. Everything under it is server-understood;
/// everything else is the user's.
const AUX_SEGMENT: &str = ".aux";

mod sealed {
    pub trait Sealed {}
}

/// Anything addressable as a named graph. Sealed: every implementor's
/// `graph_iri` is interpolated verbatim into SPARQL, so only types minted
/// through `StorageSpace::resolve` (and its `root`/`parent`/`ancestors`/
/// `as_container` derivatives) may implement it.
pub trait GraphName: sealed::Sealed {
    fn graph_iri(&self) -> &str;
}

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

    /// The path segment under `/.aux/`.
    pub fn segment(self) -> &'static str {
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

    fn from_segment(segment: &str) -> Option<Self> {
        AuxKind::ALL.iter().copied().find(|k| k.segment() == segment)
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

impl ResourceUrl {
    pub fn path(&self) -> &str {
        &self.path
    }

    /// This resource's auxiliary of the given kind. Total: every resource has
    /// an auxiliary URL whether or not that auxiliary has a representation.
    pub fn aux(&self, kind: AuxKind) -> AuxUrl {
        let base = self.iri.strip_suffix(&self.path).expect("iri ends with path");
        let iri = format!("{base}/{AUX_SEGMENT}/{}{}", kind.segment(), self.path);
        AuxUrl { kind, subject: self.clone(), iri }
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
    /// system, and the only place the reserved namespace is recognized.
    ///
    /// The IRI is validated here, once, because it is later interpolated
    /// verbatim into SPARQL as `<{iri}>`.
    pub fn resolve(&self, request_path: &str) -> Result<Target, SpaceError> {
        if !request_path.starts_with('/') {
            return Err(SpaceError::NotRooted);
        }
        if let Some(rest) = self.reserved_remainder(request_path) {
            let Some(rest) = rest.strip_prefix('/') else {
                return Err(SpaceError::Reserved); // "/.aux"
            };
            let Some((segment, subject_rest)) = rest.split_once('/') else {
                return Err(SpaceError::Reserved); // "/.aux/" or "/.aux/acl"
            };
            let kind = AuxKind::from_segment(segment).ok_or(SpaceError::Reserved)?;
            let subject_path = format!("/{subject_rest}");
            // An auxiliary has no auxiliary — `AuxUrl` cannot build one, and the
            // path space must not name one either. Without this, the subject of
            // `/.aux/acl/.aux/acl/foo` would be a plain resource whose IRI is the
            // ACL graph of `/foo`, and authorization would derive from it.
            if self.reserved_remainder(&subject_path).is_some() {
                return Err(SpaceError::Reserved);
            }
            let subject = self.resource(&subject_path)?;
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

    /// What follows `/.aux` when the path's *whole* first segment is the
    /// reserved one. `/.auxiliary` is an ordinary resource: the reservation
    /// costs exactly the name `.aux`, never a prefix of a longer name.
    fn reserved_remainder<'p>(&self, request_path: &'p str) -> Option<&'p str> {
        let rest = request_path.strip_prefix('/')?.strip_prefix(AUX_SEGMENT)?;
        (rest.is_empty() || rest.starts_with('/')).then_some(rest)
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
        assert!(matches!(s.resolve("/.aux/acl/foo").unwrap(), Target::Aux(_)));
        assert!(matches!(s.resolve("/.aux/acl/").unwrap(), Target::Aux(_)));
    }

    // A dot is only special as the whole first segment `.aux`. Everything
    // else a user might name stays ordinary.
    #[test]
    fn only_the_aux_segment_is_reserved() {
        let s = sp();
        assert!(matches!(s.resolve("/.hidden").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/.config/x").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/box/.aux").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/box/.aux/acl").unwrap(), Target::Resource(_)));
        // The reserved name is the whole segment, never a prefix of a longer one.
        assert!(matches!(s.resolve("/.auxiliary").unwrap(), Target::Resource(_)));
        assert!(matches!(s.resolve("/.auxiliary/x").unwrap(), Target::Resource(_)));
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
        assert_eq!(s.resolve("/.aux/acl"), Err(SpaceError::Reserved)); // no subject
    }

    // `AuxUrl` has no `aux()`, so no auxiliary-of-an-auxiliary can be built.
    // The path space must not offer one either.
    #[test]
    fn an_auxiliary_is_never_the_subject_of_an_auxiliary() {
        let s = sp();
        assert_eq!(s.resolve("/.aux/acl/.aux/acl/foo"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/acl/.aux/"), Err(SpaceError::Reserved));
        assert_eq!(s.resolve("/.aux/acl/.aux"), Err(SpaceError::Reserved));
        // A `.aux` segment that is not the subject's first is ordinary, so it
        // has an ACL like any other resource.
        assert!(matches!(s.resolve("/.aux/acl/box/.aux").unwrap(), Target::Aux(_)));
    }

    #[test]
    fn aux_and_subject_are_mutual_inverses() {
        let s = sp();
        for path in ["/", "/foo", "/box/", "/a/b/c"] {
            let (Target::Resource(r) | Target::Container(ContainerUrl(r))) = s.resolve(path).unwrap()
            else { panic!("{path} should be a resource or container") };
            let aux = r.aux(AuxKind::Acl);
            assert_eq!(aux.subject().path(), path, "round trip for {path}");
        }
    }

    #[test]
    fn aux_urls_have_the_documented_shape() {
        let s = sp();
        let acl_of = |p: &str| match s.resolve(p).unwrap() {
            Target::Resource(r) => r.aux(AuxKind::Acl),
            Target::Container(c) => c.as_resource().aux(AuxKind::Acl),
            Target::Aux(_) => panic!("not a subject"),
        };
        assert_eq!(acl_of("/").graph_iri(), "https://pod.toph.so/.aux/acl/");
        assert_eq!(acl_of("/foo").graph_iri(), "https://pod.toph.so/.aux/acl/foo");
        assert_eq!(acl_of("/box/").graph_iri(), "https://pod.toph.so/.aux/acl/box/");
        assert_eq!(acl_of("/a/b/c").graph_iri(), "https://pod.toph.so/.aux/acl/a/b/c");
    }

    // The direction an attacker controls: decode an `AuxUrl` from a request
    // path, rather than building one from a subject via `aux()`.
    #[test]
    fn resolve_decodes_aux_urls_from_the_request_path() {
        let s = sp();
        let Target::Aux(aux) = s.resolve("/.aux/acl/box/").unwrap() else { panic!() };
        assert_eq!(aux.subject().path(), "/box/");
        assert_eq!(aux.graph_iri(), "https://pod.toph.so/.aux/acl/box/");
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
    // routing or `Link` headers. Each kind's segment must also be non-empty
    // and slash-free (`resolve` splits on the first `/`, so two kinds could
    // otherwise collide) and IRI-safe (it is interpolated into a graph IRI).
    #[test]
    fn aux_kind_segments_are_well_formed() {
        for kind in AuxKind::ALL {
            match kind {
                AuxKind::Acl => {}
            }
            let segment = kind.segment();
            assert!(!segment.is_empty(), "{kind:?} has an empty segment");
            assert!(!segment.contains('/'), "{kind:?}'s segment contains '/'");
            let iri = format!("https://pod.toph.so/.aux/{segment}/x");
            assert!(NamedNode::new(&iri).is_ok(), "{kind:?}'s segment is not IRI-safe");
        }
    }
}
