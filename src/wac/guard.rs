//! The enforcement point: one call handlers make before touching the store.
//!
//! Fails closed in every direction — a missing ACL, a store error, or an
//! unroutable path all deny. The only path to `Ok(())` is an ACL that
//! explicitly grants the requested mode to this agent.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::{
    auth::Agent,
    aux::AUX_SUBJECT_MISSING_MESSAGE,
    container,
    resource,
    space::{AuxKind, ContainerUrl, GraphName, ResourceUrl, Target},
    store::SparqlStore,
};

use super::{pdp, prp, Decision, Mode};

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

/// Deny in the way that tells the caller the truth without leaking anything:
/// an anonymous caller learns that credentials would help (401), a verified
/// one that theirs are insufficient (403). Neither learns whether the
/// resource exists — `authorize` runs before any existence check.
///
/// Public to the crate for the one refusal this module cannot make itself:
/// a patch's required modes are known only after the body is parsed, and
/// re-running [`authorize`] to say no would resolve the ACL a second time.
/// It stays the single place the `401`/`403` split and [`DPOP_CHALLENGE`] are
/// decided, which is what a handler-side refusal would break.
pub(crate) fn deny(agent: &Agent) -> Response {
    match agent {
        Agent::Public => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, DPOP_CHALLENGE)],
        )
            .into_response(),
        Agent::WebId(_) => StatusCode::FORBIDDEN.into_response(),
    }
}

/// The `409` body a create is refused with when it would produce the other
/// half of a trailing-slash pair.
const SLASH_PAIR_MESSAGE: &str =
    "another resource already exists whose URI differs from this one only in the trailing slash";

/// The mode required to access an auxiliary of this kind, whatever `mode` the
/// handler asked for. Exhaustive over [`AuxKind`]: a new kind is a compile
/// error here until this match says what it requires, rather than silently
/// inheriting `Control` (over-restrictive) or `mode` (potentially
/// under-restrictive) from a fallback arm.
fn required_mode_for_aux(kind: AuxKind) -> Mode {
    match kind {
        AuxKind::Acl => Mode::Control,
    }
}

/// The LDP door's enforcement point, for one request.
///
/// Built once from the target, it resolves every existence fact the request
/// needs in one query and reads the governing ACLs in one more. The three
/// decision methods are then synchronous and hold no store parameter, so a
/// second resolution of the same ACL — which would repeat the walk and could
/// straddle a concurrent write — is not something a later edit has to
/// remember not to write.
///
/// **Not** the enforcement point for the `/sparql` read proxy the root spec
/// §11 keeps as a seam: that door asks a set-valued question ("which graphs
/// may this agent read"), which no single-target API answers. The core root
/// spec §8 shares across doors is `pdp::decide` and the ACL resolution below
/// this type, both of which this uses rather than replaces.
///
/// The lifetime is deliberate: a guard borrows the store for the request it
/// was probed in, so it cannot be stashed in anything that outlives the
/// snapshot it describes.
pub struct Guard<'a> {
    store: &'a dyn SparqlStore,
    agent: Agent,
    target: Target,
    /// The subject and every container above it, nearest first — the one
    /// chain a request touches (design §3).
    chain: Vec<ResourceUrl>,
    /// Graph IRIs the probe found present.
    present: std::collections::HashSet<String>,
    /// ACL triples by governed IRI, for every ACL in the chain that exists.
    acls: std::collections::HashMap<String, Vec<oxigraph::model::Triple>>,
}

impl<'a> Guard<'a> {
    /// Resolve everything this request's authorization depends on.
    ///
    /// Refuses nothing: its only failure is a store error, which is a `500`
    /// whatever exists. Every refusal that reads a probed fact is produced by
    /// a method below, after the corresponding [`Guard::authorize`] returned
    /// `Ok` — design §7's rule, which is about the ordering of *answers*, not
    /// of queries.
    pub async fn probe(
        store: &'a dyn SparqlStore,
        agent: Agent,
        target: Target,
    ) -> Result<Self, Response> {
        let subject: ResourceUrl = match &target {
            Target::Resource(r) => r.clone(),
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(a) => a.subject().clone(),
        };
        // Nearest first, ending at the root: the one chain this request touches
        // (design §3). `ResourceUrl::ancestors` is the only derivation of it.
        let mut chain = vec![subject.clone()];
        chain.extend(subject.ancestors().iter().map(|c| c.as_resource().clone()));

        // Everything anyone in this request may ask about, unconditionally —
        // a probe set that varied by method would be a second derivation of the
        // same table (design §4).
        let auxes: Vec<_> = chain
            .iter()
            .flat_map(|r| AuxKind::ALL.iter().map(move |k| r.aux(*k)))
            .collect();
        let counterparts: Vec<_> = chain.iter().filter_map(|r| r.slash_counterpart()).collect();
        let mut candidates: Vec<&dyn GraphName> = Vec::new();
        candidates.extend(chain.iter().map(|r| r as &dyn GraphName));
        candidates.extend(auxes.iter().map(|a| a as &dyn GraphName));
        candidates.extend(counterparts.iter().map(|r| r as &dyn GraphName));

        let present = resource::exists_many(store, &candidates)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        let acls = prp::load_chain_acls(store, &chain, &present)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

        Ok(Self { store, agent, target, chain, present, acls })
    }

    /// Decide `required` against the nearest ACL at or above `chain[start]`.
    ///
    /// Nearest wins entirely: ancestor rules are never merged in, because
    /// merging would make revoking access on a subtree impossible. `inherited`
    /// is true for anything above `start`, which is what makes `acl:default`
    /// apply rather than `acl:accessTo`.
    fn decide_from(&self, start: usize, required: Mode) -> Result<Decision, Response> {
        let found = self.chain[start..]
            .iter()
            .enumerate()
            .find_map(|(offset, element)| {
                self.acls.get(element.graph_iri()).map(|t| (element, t, offset > 0))
            });
        let Some((element, triples, inherited)) = found else {
            return Err(deny(&self.agent)); // WAC has no implicit grant
        };
        let governed = element.graph_iri();
        let user = pdp::decide(triples, &self.agent, governed, inherited);
        let public = match self.agent {
            Agent::Public => user,
            Agent::WebId(_) => pdp::decide(triples, &Agent::Public, governed, inherited),
        };
        if user.allows(required) {
            Ok(Decision { user, public })
        } else {
            Err(deny(&self.agent))
        }
    }

    /// May this agent perform `mode` on the target?
    ///
    /// Takes no target: there is one per request and this owns it. An
    /// auxiliary is decided against its subject and requires the mode its
    /// [`AuxKind`] demands, exactly as the free function it replaces.
    pub fn authorize(&self, mode: Mode) -> Result<Decision, Response> {
        let required = match &self.target {
            Target::Aux(a) => required_mode_for_aux(a.kind()),
            _ => mode,
        };
        self.decide_from(0, required)
    }

    /// The same question for the container above the target — `None` at the
    /// root, which has none. `DELETE` needs it because removing a member
    /// rewrites the parent's containment triples.
    pub fn authorize_parent(&self, mode: Mode) -> Result<Option<Decision>, Response> {
        // chain[0] is the subject, so chain[1] is its parent — absent only at
        // the root, whose `ancestors()` is empty.
        if self.chain.len() < 2 {
            return Ok(None);
        }
        self.decide_from(1, mode).map(Some)
    }

    /// The same question for the target's auxiliary of `kind` — `None` when
    /// no such auxiliary exists, so there is nothing to authorize.
    ///
    /// `DELETE` needs it for every kind: deleting a subject takes its
    /// auxiliaries with it, and a narrowing ACL must not be removable by
    /// someone holding merely `Write`.
    pub fn authorize_aux(&self, kind: AuxKind) -> Result<Option<Decision>, Response> {
        let aux = self.chain[0].aux(kind);
        if !self.present.contains(aux.graph_iri()) {
            return Ok(None); // nothing there to authorize
        }
        // An auxiliary is decided against its subject, which is chain[0].
        self.decide_from(0, required_mode_for_aux(kind)).map(Some)
    }

    /// Refuse, in the way that tells this agent the truth without leaking
    /// anything — the `401`/`403` split of the free [`deny`].
    ///
    /// For the one refusal the decision methods cannot make: a patch's
    /// required modes are known only after its body is parsed, and re-running
    /// [`Guard::authorize`] to say no would decide against a mode the handler
    /// has already established is the wrong one. The guard owns the agent, so
    /// this is where that refusal now comes from.
    pub fn deny(&self) -> Response {
        deny(&self.agent)
    }

    /// Whether this URL is already spoken for — either it names a resource, or
    /// its trailing-slash counterpart does, which Solid Protocol §3.1 forbids
    /// from coexisting with it.
    ///
    /// `false` for an `Aux` target's counterpart half: an auxiliary never has
    /// one ([`ResourceUrl::slash_counterpart`] is a resource-space concept
    /// only), though the target itself can of course still be taken outright.
    /// For a `Container`, the counterpart checked is its own resource URL's —
    /// a `Link: rel="type"` can make an allocated child a container, and the
    /// pair rule reads the same from that side.
    ///
    /// Reads only the probe's already-resolved presence set — this is the
    /// question `name_is_taken` used to answer with its own two queries, now
    /// read from [`Guard::probe`]'s single one. Refuses nothing on its own;
    /// callers read it after [`Guard::authorize`] returned `Ok`, which is the
    /// ordering the store lookup it replaces already obeyed (design §7).
    pub fn is_taken(&self) -> bool {
        if self.present.contains(self.target.graph_iri()) {
            return true;
        }
        let subject: &ResourceUrl = match &self.target {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource(),
            Target::Aux(_) => return false,
        };
        subject.slash_counterpart().is_some_and(|c| self.present.contains(c.graph_iri()))
    }

    /// Authorize and perform the container materialization this write implies,
    /// then give up the guard.
    ///
    /// Takes `self` because the probe describes the store *before* these
    /// writes: after this returns there is no guard left to read a stale
    /// answer from. A pre-write fact a caller still wants is read from
    /// [`Guard::is_taken`] beforehand, which the borrow checker orders for it.
    pub async fn materialize(self) -> Result<(), Response> {
        let subject = &self.chain[0];
        // Target-existence only, never the counterpart: materializing a target
        // whose counterpart merely exists is not "already there" — it is the
        // slash-pair conflict [`Guard::materialize`] refuses further down.
        let target_existed = self.present.contains(self.target.graph_iri());
        let may_be_member = !matches!(self.target, Target::Aux(_));
        // An auxiliary is never a container member, and neither is a target that
        // already exists: re-inserting the containment triple changes nothing, so
        // demanding Append for it would refuse the ordinary "you may edit this
        // file" grant.
        let is_member = may_be_member && !target_existed;

        let mut creations: Vec<&ResourceUrl> = Vec::new();
        if is_member {
            creations.push(subject);
        }
        let mut child_iri = self.target.graph_iri().to_string();
        let mut record_child = is_member;
        let mut plan: Vec<(ContainerUrl, Option<String>)> = Vec::new();
        for (i, ancestor) in subject.ancestors().into_iter().enumerate() {
            let existed = self.present.contains(ancestor.graph_iri());
            if existed && !record_child {
                break; // nothing observable changes at or above this level
            }
            self.decide_from(i + 1, Mode::Append)?;
            plan.push((ancestor.clone(), record_child.then(|| child_iri.clone())));
            if existed {
                break;
            }
            creations.push(&self.chain[i + 1]);
            child_iri = ancestor.graph_iri().to_string();
            record_child = true;
        }

        // Every ancestor is authorized by here, so a missing subject may finally
        // be reported — before the plan below materializes anything for a write
        // that could never succeed.
        if matches!(self.target, Target::Aux(_)) && !self.present.contains(subject.graph_iri()) {
            return Err((StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response());
        }

        // Protocol §3.1, over everything this write would create. Deliberately
        // after the whole chain is authorized: a caller about to be refused for an
        // ancestor must be refused without learning what else exists.
        for created in &creations {
            if let Some(counterpart) = created.slash_counterpart() {
                if self.present.contains(counterpart.graph_iri()) {
                    return Err((StatusCode::CONFLICT, SLASH_PAIR_MESSAGE).into_response());
                }
            }
        }

        for (ancestor, child_iri) in plan {
            container::ensure_container(self.store, &ancestor)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
            if let Some(child_iri) = child_iri {
                container::add_containment(self.store, &ancestor, &child_iri)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{
        ACL_ACCESS_TO, ACL_AGENT, ACL_APPEND, ACL_CONTROL, ACL_DEFAULT, ACL_MODE, ACL_READ,
        ACL_WRITE,
    };
    use crate::{
        rdf::Format,
        space::{AuxKind, StorageSpace},
        store::OxigraphStore,
    };
    use oxigraph::model::Triple;

    const ALICE: &str = "https://alice.example/card#me";
    const BOB: &str = "https://bob.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }
    fn alice() -> Agent { Agent::WebId(ALICE.to_string()) }
    fn bob() -> Agent { Agent::WebId(BOB.to_string()) }

    fn resource(path: &str) -> ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    fn container(path: &str) -> ContainerUrl {
        match sp().resolve(path).unwrap() {
            Target::Container(c) => c,
            _ => panic!("not a container path"),
        }
    }

    async fn seed_container(store: &OxigraphStore, path: &str) {
        crate::container::ensure_container(store, &container(path)).await.unwrap();
    }

    /// Mark the subject present, then write its ACL. The presence marker goes
    /// in additively: `aux::put` refuses an auxiliary whose subject does not
    /// exist, and seeding a policy must not erase whatever the subject
    /// already holds.
    async fn seed_acl(store: &OxigraphStore, subject_path: &str, turtle: &str) {
        let subject = resource(subject_path);
        crate::resource::insert_marked(store, &subject, &[]).await.unwrap();
        let aux = subject.aux(AuxKind::Acl);
        let t: Vec<Triple> = Format::from_content_type("text/turtle").unwrap()
            .parse(turtle.as_bytes(), aux.graph_iri(), crate::rdf::RdfVersion::Rdf11).unwrap()
            .quads().iter().cloned().map(Triple::from).collect();
        crate::aux::put(store, &aux, &t).await.unwrap();
    }

    /// Generic in the success type because it never looks at one: every
    /// caller below asks a [`Guard`] decision method the same question, and
    /// only its refusal is under test.
    fn status<T>(r: Result<T, Response>) -> Option<StatusCode> {
        r.err().map(|res| res.status())
    }

    /// Whether `parent`'s containment graph records `child_iri` as a member —
    /// the direct triple check, stronger than merely asking if the container
    /// holds *some* member.
    async fn contains(store: &OxigraphStore, parent: &ContainerUrl, child_iri: &str) -> bool {
        let p = parent.graph_iri();
        store
            .ask(&format!(
                "ASK {{ GRAPH <{p}> {{ <{p}> <{}> <{child_iri}> }} }}",
                crate::container::LDP_CONTAINS
            ))
            .await
            .unwrap()
    }

    /// Probe a guard for `path` as `agent`, panicking on a store failure.
    async fn guard_for<'a>(store: &'a OxigraphStore, agent: Agent, path: &str) -> Guard<'a> {
        Guard::probe(store, agent, sp().resolve(path).unwrap()).await.expect("probe")
    }

    #[tokio::test]
    async fn a_probed_guard_grants_and_denies_by_mode() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let g = guard_for(&store, alice(), "/foo").await;
        assert!(g.authorize(Mode::Read).is_ok());
        assert_eq!(status(g.authorize(Mode::Write)), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn a_guard_denies_an_anonymous_caller_with_a_challenge() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let g = guard_for(&store, Agent::Public, "/foo").await;
        let res = g.authorize(Mode::Read).expect_err("denied");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(header::WWW_AUTHENTICATE).is_some());
        // `deny` is the same refusal, for the caller that has to make it itself.
        assert_eq!(g.deny().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_guard_inherits_from_the_nearest_ancestor_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let g = guard_for(&store, alice(), "/box/item").await;
        assert!(g.authorize(Mode::Read).is_ok());
    }

    // The resource's own empty ACL wins over the ancestor grant it was written to
    // override — the fixture that fails if the chain is searched in the wrong
    // direction, or if an empty ACL is treated as an absent one.
    #[tokio::test]
    async fn a_guard_lets_an_own_empty_acl_win() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/", &format!(
            "<#root> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        seed_acl(&store, "/foo", "").await;
        let g = guard_for(&store, alice(), "/foo").await;
        assert_eq!(status(g.authorize(Mode::Read)), Some(StatusCode::FORBIDDEN));
    }

    // An auxiliary is decided against its subject and requires Control, whatever
    // mode the caller names.
    #[tokio::test]
    async fn a_guard_requires_control_for_an_acl_target() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let g = guard_for(&store, alice(), "/.aux/foo.acl").await;
        assert_eq!(status(g.authorize(Mode::Read)), Some(StatusCode::FORBIDDEN));
    }

    // A target that is itself present is taken, regardless of its counterpart.
    #[tokio::test]
    async fn is_taken_is_true_for_a_present_target() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        assert!(guard_for(&store, alice(), "/foo").await.is_taken());
        assert!(!guard_for(&store, alice(), "/nothing").await.is_taken());
    }

    // Neither half exists: /box/ is free.
    #[tokio::test]
    async fn is_taken_is_false_when_neither_half_exists() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(!guard_for(&store, alice(), "/box/").await.is_taken());
    }

    // /box does not exist itself, but its trailing-slash counterpart /box/
    // does — the Protocol §3.1 half `existed` alone never answered.
    #[tokio::test]
    async fn is_taken_is_true_when_only_the_counterpart_exists() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_container(&store, "/box/").await;
        assert!(guard_for(&store, alice(), "/box").await.is_taken());
    }

    // A `Link: rel="type"` can make an allocated child a container, so the
    // counterpart checked for a `Container` target must be its own resource
    // URL's counterpart — the case `name_is_taken`'s `Target::Container` arm
    // singled out.
    #[tokio::test]
    async fn is_taken_checks_the_containers_own_resource_counterpart() {
        let store = OxigraphStore::in_memory().unwrap();
        crate::resource::put_rdf(&store, &resource("/box"), &[]).await.unwrap();
        assert!(guard_for(&store, alice(), "/box/").await.is_taken());
    }

    // An `Aux` target has no counterpart concept at all — `is_taken` must
    // answer only from the aux's own presence, never fall through to a
    // counterpart lookup that `ResourceUrl::slash_counterpart` cannot even
    // form for it.
    #[tokio::test]
    async fn is_taken_ignores_the_counterpart_for_an_aux_target() {
        let store = OxigraphStore::in_memory().unwrap();
        crate::resource::put_rdf(&store, &resource("/box/doc"), &[]).await.unwrap();
        assert!(!guard_for(&store, alice(), "/.aux/box/doc.acl").await.is_taken());
    }

    // No ACL anywhere = no grant. WAC has no implicit allow.
    #[tokio::test]
    async fn no_acl_anywhere_denies() {
        let store = OxigraphStore::in_memory().unwrap();
        let g = guard_for(&store, alice(), "/foo").await;
        assert_eq!(status(g.authorize(Mode::Read)), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn authorize_parent_decides_one_level_up_and_is_none_at_the_root() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_container(&store, "/box/").await;
        // Only acl:accessTo: decide_from(1, ...) reaches /box/ at offset 0
        // (inherited = false), so this is the predicate a correct index needs.
        // A wrongly-indexed decide_from(0, ...) would see /box/ at offset 1
        // (inherited = true) and require acl:default, which is absent here —
        // so only the correct index finds a match.
        seed_acl(&store, "/box/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let g = guard_for(&store, alice(), "/box/item").await;
        assert!(g.authorize_parent(Mode::Write).unwrap().is_some());

        let root = guard_for(&store, alice(), "/").await;
        assert!(root.authorize_parent(Mode::Write).unwrap().is_none(), "the root has no parent");
    }

    #[tokio::test]
    async fn authorize_aux_is_none_when_the_auxiliary_does_not_exist() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        crate::resource::put_rdf(&store, &resource("/box/doc"), &[]).await.unwrap();
        let g = guard_for(&store, alice(), "/box/doc").await;
        assert!(g.authorize_aux(AuxKind::Acl).unwrap().is_none());
    }

    // Control on the subject is what an ACL auxiliary requires — Write is not
    // enough, or a narrowing ACL could be erased by someone holding merely
    // Write. The auxiliary under test here is /box/doc's own .acl, which is
    // also the ACL that governs /box/doc at chain[0] — so its own grant to
    // Alice is what decide_from(0, ...) resolves against, deliberately Write
    // only rather than empty, so the denial comes from the mode requirement.
    #[tokio::test]
    async fn authorize_aux_requires_control_over_the_subject() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/box/doc", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/doc> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let g = guard_for(&store, alice(), "/box/doc").await;
        assert_eq!(status(g.authorize_aux(AuxKind::Acl)), Some(StatusCode::FORBIDDEN));
    }

    // An existing target gains no containment triple — its parent already records
    // it — so materializing over one must not demand Append at the level above.
    // This is the "you may edit this file" grant, where an agent holds Write on
    // one document and nothing on the container around it.
    #[tokio::test]
    async fn materializing_over_an_existing_target_needs_nothing_above_it() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_container(&store, "/box/").await;
        crate::resource::put_rdf(&store, &resource("/box/doc"), &[]).await.unwrap();
        seed_acl(&store, "/box/doc", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/doc> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let g = guard_for(&store, alice(), "/box/doc").await;
        assert!(g.materialize().await.is_ok(), "an overwrite adds no containment");
    }

    #[tokio::test]
    async fn a_guarded_deep_create_materializes_and_links_the_whole_chain() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/> ; <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        guard_for(&store, alice(), "/a/b/c").await.materialize().await.unwrap();

        for path in ["/a/b/", "/a/", "/"] {
            assert!(resource::exists(&store, &container(path)).await.unwrap(), "{path} must exist");
        }
        assert!(contains(&store, &container("/a/b/"), "https://pod.toph.so/a/b/c").await);
    }

    #[tokio::test]
    async fn a_guarded_walk_writes_nothing_when_a_level_denies() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let g = guard_for(&store, bob(), "/box/sub/file").await;
        assert!(g.materialize().await.is_err(), "creating /box/sub/ mutates /box/");
        assert!(!resource::exists(&store, &container("/box/sub/")).await.unwrap(),
            "nothing may be materialized when the walk denies");
    }

    #[tokio::test]
    async fn a_guarded_walk_stops_at_the_first_existing_ancestor() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_container(&store, "/inbox/").await;
        seed_acl(&store, "/inbox/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/inbox/> ; \
             <{ACL_MODE}> <{ACL_APPEND}> ."
        )).await;
        guard_for(&store, bob(), "/inbox/note").await.materialize().await.unwrap();
        assert!(contains(&store, &container("/inbox/"), "https://pod.toph.so/inbox/note").await);
        assert!(!resource::exists(&store, &container("/")).await.unwrap(),
            "the walk must never touch the root");
    }

    // Alice holds only `acl:default` at /box/ — enough to Append one level
    // *below* /box/ by inheritance, but decide_from(1) evaluates /box/
    // itself directly (offset 0, not inherited), which needs `acl:accessTo`
    // and finds none: denied. That denial must win over the slash-pair
    // check even though /box/sub (no trailing slash) already exists and
    // /box/sub/ is exactly the target — if the check ran before the walk,
    // it would answer 409 and reveal /box/sub's existence to an agent who
    // is about to be refused for /box/ anyway. Asserting 403 is what makes
    // this fixture fail loudly if that check is ever hoisted above the loop
    // (see `materialize`'s doc comment): a hoist here would flip 403 to 409.
    #[tokio::test]
    async fn a_guarded_write_denied_on_an_ancestor_never_reaches_the_slash_pair_check() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        crate::resource::put_rdf(&store, &resource("/box/sub"), &[]).await.unwrap();
        let g = guard_for(&store, alice(), "/box/sub/").await;
        assert_eq!(status(g.materialize().await), Some(StatusCode::FORBIDDEN),
            "denied on /box/ (accessTo required, only default granted) must win over \
             the 409 for /box/sub's slash counterpart, or the ordering leaks it");
    }

    // Alice holds only `acl:accessTo` at the root — a direct grant that does
    // not inherit. /box/ does not exist yet, so the walk does not break
    // immediately (unlike the aux case where the nearest ancestor already
    // exists and record_child is false); it reaches decide_from(1), which
    // resolves against the root ACL from an inherited position (offset > 0)
    // and needs `acl:default`, absent here: denied. That denial must win
    // over the aux-subject-exists check even though /box/ghost does not
    // exist either — if the check ran before the walk, it would answer 404
    // and confirm the subject's absence to an agent who is about to be
    // refused for /box/ anyway. Asserting 403 is what makes this fixture
    // fail loudly if that check is ever hoisted above the loop: a hoist
    // here would flip 403 to 404.
    #[tokio::test]
    async fn a_guarded_aux_write_denied_on_an_ancestor_never_reaches_the_subject_check() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let g = guard_for(&store, alice(), "/.aux/box/ghost.acl").await;
        assert_eq!(status(g.materialize().await), Some(StatusCode::FORBIDDEN),
            "denied while walking to /box/ (root's accessTo grant doesn't inherit) must \
             win over the 404 for ghost's own non-existence, or the ordering leaks it");
    }
}
