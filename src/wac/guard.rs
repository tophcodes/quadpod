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

/// Solid Protocol §3.1: "If two URIs differ only in the trailing slash, and
/// the server has associated a resource with one of them, then the other URI
/// MUST NOT correspond to another resource."
///
/// So every create asks whether its counterpart is already taken and refuses
/// rather than producing the pair. The pair stays *addressable* — `/box` and
/// `/box/` remain two names this pod resolves and distinguishes — but only one
/// of them may exist at a time. Nothing merges: the rule forbids the pair, it
/// does not make one URI mean the other.
///
/// Callers run this only after authorizing every level of the write (see
/// [`authorize_and_materialize`], its only caller): a caller denied on the
/// target itself, or on any ancestor the write would touch, never reaches
/// this check and so learns nothing about the counterpart from it — the
/// mistake `put_impl`'s conditional-request branch already avoids by sitting
/// after `authorize`.
///
/// That does not close the oracle for the counterpart's *own* ACL, which
/// this check never consults: a caller authorized to write `/box` by some
/// unrelated, inherited rule, but who holds no access at all under `/box/`'s
/// own, narrower ACL, still learns from a `409` that `/box/` exists — where a
/// direct request to `/box/` would have answered `403` without confirming
/// anything. That residual is inherent to enforcing Protocol §3.1 at all:
/// the rule turns on whether the *other* URI names a resource, so answering
/// it has to consult that resource's existence, not its ACL. Community Solid
/// Server discloses the same way, for the same reason.
async fn refuse_slash_pair(
    store: &dyn SparqlStore,
    created: &ResourceUrl,
) -> Result<(), Response> {
    let Some(counterpart) = created.slash_counterpart() else {
        return Ok(()); // the root: its counterpart is the empty path, no URL
    };
    let taken = resource::exists(store, &counterpart)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    if taken {
        return Err((StatusCode::CONFLICT, SLASH_PAIR_MESSAGE).into_response());
    }
    Ok(())
}

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

/// May `agent` perform `mode` on `target` — and what else may they, and the
/// public, do there?
///
/// An auxiliary is decided against its subject and requires the mode its
/// [`AuxKind`] demands ([`required_mode_for_aux`]), not necessarily `mode`
/// itself. That rewrite lives here rather than in the handlers so no handler
/// can forget it — and it is now the type that carries the subject, so there
/// is nothing left to derive from a string.
///
/// The returned [`Decision`] is what `WAC-Allow` is rendered from. It is
/// produced here, from the ACL this call already resolved, rather than by a
/// second lookup in the caller: a second resolution would repeat the ancestor
/// walk on the pod's hottest path, and an ACL written between the two would
/// let the header describe access other than the access just granted.
pub async fn authorize(
    store: &dyn SparqlStore,
    agent: &Agent,
    target: &Target,
    mode: Mode,
) -> Result<Decision, Response> {
    let (subject, required) = match target {
        Target::Aux(a) => (a.subject().clone(), required_mode_for_aux(a.kind())),
        Target::Resource(r) => (r.clone(), mode),
        Target::Container(c) => (c.as_resource().clone(), mode),
    };

    let acl = match prp::effective_acl(store, &subject).await {
        Ok(Some(acl)) => acl,
        Ok(None) => return Err(deny(agent)),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    };

    let user = pdp::decide(&acl.triples, agent, &acl.governed_iri, acl.inherited);
    // An anonymous request has already computed the public answer; asking the
    // same question twice would double the cost of the one case that gains
    // nothing from a second evaluation.
    let public = match agent {
        Agent::Public => user,
        Agent::WebId(_) => {
            pdp::decide(&acl.triples, &Agent::Public, &acl.governed_iri, acl.inherited)
        }
    };

    if user.allows(required) {
        Ok(Decision { user, public })
    } else {
        Err(deny(agent))
    }
}

/// Authorize and perform the container materialization a write implies —
/// from one traversal.
///
/// A level is written iff it is created, or it is the first already-existing
/// ancestor (which gains a containment triple). Those are exactly the levels
/// this walk authorizes `Append` on, and it stops there: above that point the
/// inserts are no-ops, and demanding rights there would break the
/// append-only inbox pattern. An auxiliary is never a container member, so a
/// write to one adds no containment — only the containers it would create
/// count.
///
/// The walk decides the whole chain before it writes any of it. A denial
/// halfway up must leave the store exactly as it found it: interleaving the
/// two would let an agent authorized only *below* a container create a fresh
/// subtree there and then be refused, leaving containers they were never
/// allowed to make. Two loops, one derivation — the plan the second loop
/// applies is the plan the first one authorized, level for level.
///
/// For an `Aux` target there is a third possibility besides "authorized" and
/// "refused for an ancestor": every ancestor authorizes fine, yet the target
/// is still doomed, because this walk never creates the aux's own subject
/// (only the ancestor *containers* count as `may_be_member`, never the
/// subject itself) — and `aux::put` refuses to write an auxiliary for a
/// subject that does not exist. Left unchecked, that refusal would arrive
/// only after the plan below had already materialized every ancestor for a
/// write that could never succeed. The check runs after the decide loop, not
/// before it: an ancestor-Append denial must still win and answer `Forbidden`
/// without ever revealing whether the subject exists, exactly as it does
/// today — only a caller who clears every ancestor gets as far as learning
/// that the subject itself does not.
///
/// This is also where Solid Protocol §3.1 is enforced ([`refuse_slash_pair`]):
/// the set of URLs a write brings into existence is decided here and nowhere
/// else, so this is the only place that can refuse to create either half of a
/// trailing-slash pair without a second, driftable derivation of the same set.
pub async fn authorize_and_materialize(
    store: &dyn SparqlStore,
    agent: &Agent,
    target: &Target,
) -> Result<(), Response> {
    let (subject, may_be_member): (&ResourceUrl, bool) = match target {
        Target::Resource(r) => (r, true),
        Target::Container(c) => (c.as_resource(), true),
        Target::Aux(a) => (a.subject(), false),
    };
    // Whether this write adds a containment triple at the level above. An
    // auxiliary is never a container member — and neither is a target that
    // already exists, whose parent already records it: re-inserting that
    // triple changes nothing, so demanding `Append` for it would refuse the
    // ordinary "you may edit this file" grant, where an agent holds Write on
    // one document and nothing on the container around it.
    //
    // Existence is consulted before any `authorize` call here, which is safe
    // because every caller has already authorized the target itself — so it
    // is not a fresh oracle for an agent who holds nothing.
    let is_member = if may_be_member {
        !resource::exists(store, target)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
    } else {
        false
    };

    // Every URL this write would bring into existence — the target, when it is
    // not there yet, and each container the walk below would materialize. It
    // is what Protocol §3.1 is checked against, once the whole chain has been
    // authorized.
    let mut creations: Vec<ResourceUrl> = Vec::new();
    if is_member {
        creations.push(subject.clone());
    }

    // The IRI to record as a member at the next level up. It starts as the
    // target and becomes each container this walk creates.
    let mut child_iri = target.graph_iri().to_string();
    let mut record_child = is_member;
    let mut plan: Vec<(ContainerUrl, Option<String>)> = Vec::new();
    for ancestor in subject.ancestors() {
        let existed = resource::exists(store, &ancestor)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        if existed && !record_child {
            break; // nothing observable changes at or above this level
        }
        authorize(store, agent, &Target::Container(ancestor.clone()), Mode::Append).await?;
        plan.push((ancestor.clone(), record_child.then(|| child_iri.clone())));
        if existed {
            break;
        }
        creations.push(ancestor.as_resource().clone());
        child_iri = ancestor.graph_iri().to_string();
        record_child = true;
    }

    // See the doc comment above: every ancestor is authorized at this point,
    // but an `Aux` target's own subject was never among them, so a missing
    // subject is caught here — before the plan below materializes anything —
    // rather than later inside `aux::put`, after the ancestors it would have
    // no further use for are already created and linked.
    if matches!(target, Target::Aux(_))
        && !resource::exists(store, subject)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
    {
        return Err((StatusCode::NOT_FOUND, AUX_SUBJECT_MISSING_MESSAGE).into_response());
    }

    // Protocol §3.1, applied to everything this write would create — the
    // target and the containers above it alike, since a deep create is the
    // other way the forbidden pair could come into being (`PUT /a/b` beside an
    // existing resource `/a` would otherwise materialize the container `/a/`
    // next to it). Deliberately after the whole chain is authorized, for the
    // same reason as the check above: a caller who is going to be refused for
    // an ancestor must be refused without learning what else exists.
    for created in &creations {
        refuse_slash_pair(store, created).await?;
    }

    for (ancestor, child_iri) in plan {
        container::ensure_container(store, &ancestor)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        if let Some(child_iri) = child_iri {
            container::add_containment(store, &ancestor, &child_iri)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        }
    }
    Ok(())
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

    /// Whether the target was present when this guard was probed.
    ///
    /// Refuses nothing on its own. Callers read it after [`Guard::authorize`]
    /// returned `Ok`, which is the ordering the store lookup it replaces
    /// already obeyed (design §7).
    pub fn existed(&self) -> bool {
        self.present.contains(self.target.graph_iri())
    }

    /// Authorize and perform the container materialization this write implies,
    /// then give up the guard.
    ///
    /// Takes `self` because the probe describes the store *before* these
    /// writes: after this returns there is no guard left to read a stale
    /// answer from. A pre-write fact a caller still wants is read from
    /// [`Guard::existed`] beforehand, which the borrow checker orders for it.
    pub async fn materialize(self) -> Result<(), Response> {
        let subject = &self.chain[0];
        let target_existed = self.existed();
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

    /// Generic in the success type because it never looks at one: both
    /// [`authorize`] and [`authorize_and_materialize`] are asked the same
    /// question here, and only their refusal is under test.
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
    async fn a_probed_guard_grants_what_the_free_function_grants() {
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

    #[tokio::test]
    async fn existed_reports_the_pre_request_state() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        assert!(guard_for(&store, alice(), "/foo").await.existed());
        assert!(!guard_for(&store, alice(), "/nothing").await.existed());
    }

    #[tokio::test]
    async fn granted_mode_is_allowed() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let target = sp().resolve("/foo").unwrap();
        assert!(authorize(&store, &alice(), &target, Mode::Read).await.is_ok());
    }

    #[tokio::test]
    async fn missing_mode_denies_authenticated_agent_with_403() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let target = sp().resolve("/foo").unwrap();
        assert_eq!(
            status(authorize(&store, &alice(), &target, Mode::Write).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn public_denial_is_401_with_a_challenge() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let target = sp().resolve("/foo").unwrap();
        let res = authorize(&store, &Agent::Public, &target, Mode::Read).await
            .expect_err("denied");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(header::WWW_AUTHENTICATE).is_some());
    }

    // No ACL anywhere = no grant. WAC has no implicit allow.
    #[tokio::test]
    async fn no_acl_anywhere_denies() {
        let store = OxigraphStore::in_memory().unwrap();
        let target = sp().resolve("/foo").unwrap();
        assert_eq!(
            status(authorize(&store, &alice(), &target, Mode::Read).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    // Reading an ACL needs Control on the governed resource — Read on the
    // resource is explicitly NOT enough, or every reader could see who else
    // has access.
    #[tokio::test]
    async fn acl_access_requires_control_not_read() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let target = sp().resolve("/.aux/foo.acl").unwrap();
        assert_eq!(
            status(authorize(&store, &alice(), &target, Mode::Read).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn control_grants_acl_access() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        let target = sp().resolve("/.aux/foo.acl").unwrap();
        assert!(authorize(&store, &alice(), &target, Mode::Read).await.is_ok());
        assert!(authorize(&store, &alice(), &target, Mode::Write).await.is_ok());
    }

    // Write subsumes Append, so a writer may POST into a container.
    #[tokio::test]
    async fn write_satisfies_an_append_requirement() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let target = sp().resolve("/box/").unwrap();
        assert!(authorize(&store, &alice(), &target, Mode::Append).await.is_ok());
    }

    // One traversal: every level the materialization would write is a level
    // the walk authorized, and it stops where writing stops. Neither half can
    // drift from the other, because there is only one half.
    #[tokio::test]
    async fn materialization_is_authorized_at_every_level_it_writes() {
        let store = OxigraphStore::in_memory().unwrap();
        // Bob may write below /box/ but holds nothing on /box/ itself.
        seed_acl(&store, "/box/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let target = sp().resolve("/box/sub/file").unwrap();
        let res = authorize_and_materialize(&store, &bob(), &target).await;
        assert!(res.is_err(), "creating /box/sub/ mutates /box/, which Bob cannot append to");
        assert!(!crate::resource::exists(&store, &container("/box/sub/")).await.unwrap(),
            "nothing may be materialized when the walk denies");
    }

    #[tokio::test]
    async fn an_existing_parent_costs_exactly_one_check() {
        let store = OxigraphStore::in_memory().unwrap();
        // Bob has Append on /inbox/ itself — the append-only inbox pattern.
        seed_container(&store, "/inbox/").await;
        seed_acl(&store, "/inbox/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/inbox/> ; \
             <{ACL_MODE}> <{ACL_APPEND}> ."
        )).await;
        let target = sp().resolve("/inbox/note").unwrap();
        assert!(authorize_and_materialize(&store, &bob(), &target).await.is_ok(),
            "an append-only agent must not need rights on the root");
        assert!(contains(&store, &container("/inbox/"), "https://pod.toph.so/inbox/note").await,
            "the walk must actually record /inbox/note as a member of /inbox/");
        assert!(!resource::exists(&store, &container("/")).await.unwrap(),
            "the walk must stop at the first existing ancestor and never touch the root");
    }

    // A fresh store, nothing materialized yet: every ancestor of a deep
    // create must be built and linked to its parent, not merely authorized.
    #[tokio::test]
    async fn a_deep_create_materializes_and_links_the_whole_chain() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/> ; <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let target = sp().resolve("/a/b/c").unwrap();
        assert!(authorize_and_materialize(&store, &alice(), &target).await.is_ok(),
            "a root grant with acl:default must authorize the whole chain");

        for path in ["/a/b/", "/a/", "/"] {
            assert!(resource::exists(&store, &container(path)).await.unwrap(),
                "{path} must be materialized");
        }
        assert!(contains(&store, &container("/"), "https://pod.toph.so/a/").await,
            "/ must contain /a/");
        assert!(contains(&store, &container("/a/"), "https://pod.toph.so/a/b/").await,
            "/a/ must contain /a/b/");
        assert!(contains(&store, &container("/a/b/"), "https://pod.toph.so/a/b/c").await,
            "/a/b/ must contain /a/b/c");
    }

    // An auxiliary is not a container member, so writing one materializes
    // nothing at its parent — but any container it would create still counts.
    #[tokio::test]
    async fn writing_an_auxiliary_under_an_existing_container_needs_nothing_extra() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_container(&store, "/box/").await;
        crate::resource::put_rdf(&store, &resource("/box/doc"), &[]).await.unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        let target = sp().resolve("/.aux/box/doc.acl").unwrap();
        assert!(authorize_and_materialize(&store, &bob(), &target).await.is_ok(),
            "Control alone must suffice when nothing is materialized");
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

    #[tokio::test]
    async fn a_guarded_write_refuses_the_other_half_of_a_slash_pair() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/> ; <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        crate::resource::put_rdf(&store, &resource("/box"), &[]).await.unwrap();
        let g = guard_for(&store, alice(), "/box/").await;
        assert_eq!(status(g.materialize().await), Some(StatusCode::CONFLICT));
    }

    #[tokio::test]
    async fn a_guarded_aux_write_still_needs_its_subject_to_exist() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/> ; <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        let g = guard_for(&store, alice(), "/.aux/ghost.acl").await;
        assert_eq!(status(g.materialize().await), Some(StatusCode::NOT_FOUND));
    }
}
