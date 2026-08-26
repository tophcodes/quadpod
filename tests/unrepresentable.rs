//! Why six of Plan 6's seven defect classes cannot recur, and what else the
//! type system decides here.
//!
//! Six are gone at the type level and have no runtime test, because the
//! expression that would exercise them does not compile:
//!
//! * **Slug escalation.** The only struct literal that produces an `AuxUrl`
//!   is `ResourceUrl::aux` (`src/space.rs:198-202`); `StorageSpace::resolve`'s
//!   auxiliary branch (`src/space.rs:317-349`) does not construct one
//!   independently: it decodes a kind and a subject from the request path
//!   and then calls that same `subject.aux(kind)`, so both routes into an
//!   `AuxUrl` funnel through one constructor. A `Slug` is sanitized by
//!   `container::child_name` (`src/container.rs:91-100`), whose character
//!   filter admits only `[A-Za-z0-9._-]`, with no `/`. `Target::Aux` requires a
//!   request path whose FIRST segment is the reserved `.aux` and which still
//!   has a subject path after it (`src/space.rs:317-322`); a child name is one
//!   segment appended to its container's own path, so it can supply one or the
//!   other, never both. The deepest a slug-derived path can reach is the
//!   single reserved segment `/.aux` with no remainder, which `resolve`
//!   refuses as `SpaceError::Reserved` (a 404, see `src/http.rs`'s
//!   `classify`), never a `Target::Aux`.
//! * **Auxiliary-of-an-auxiliary.** `AuxUrl`'s impl block (`src/space.rs:266-273`)
//!   offers only `subject()` and `kind()`; there is no method that returns
//!   another `AuxUrl`. The path space offers none either: `resolve` refuses a
//!   decoded subject that itself re-enters the reserved namespace
//!   (`src/space.rs:330-332`), at every nesting depth.
//! * **Twin traversals.** `ResourceUrl::ancestors` (`src/space.rs:264-272`) is
//!   the only function that walks more than one `.parent()` hop, so it is the
//!   sole derivation of the container chain. `Guard::probe` (`src/wac/guard.rs:124`)
//!   calls it once per request to build the chain that both authorization and
//!   `prp::load_chain_acls`'s ACL inheritance read from: one call feeding two
//!   questions, not two derivations of the chain. `Guard::materialize`
//!   (`src/wac/guard.rs:285`) walks `ancestors` a second time to derive its
//!   containment plan, but from the same `subject` the probe used, so it
//!   recomputes the identical, deterministic chain rather than risking a
//!   second one that could diverge, as Plan 6's separate walks did.
//! * **A blank node in the store.** `dataset::Skolemized` wraps
//!   `dataset::GroundQuad`, whose subject is a `NamedNode`, object a
//!   `GroundTerm` (`NamedNode | Literal`) and graph name a `GroundGraphName`
//!   (`NamedNode | DefaultGraph`), so no position has a variant that holds one.
//!   Every write path takes that type: `resource::serialize_for_insert` is the
//!   only renderer of an `INSERT` body and `resource::insert_marked` the only
//!   additive writer, and neither accepts a `Quad`. So the three ways §4 used
//!   to be breakable, skolemizing and discarding the result, weakening the
//!   groundness check that guarded the constructor, or a new writer never
//!   calling it, are now a type error rather than a silent leak.
//!
//!   Two things this does *not* make impossible, and both stay tested.
//!   `Skolemized::from_store` parses quads coming back out of the store, which
//!   is the one source outside this type system; it answers `None` on a blank
//!   node (`dataset.rs`'s `from_store_refuses_content_that_still_has_a_blank_node`).
//!   And a caller may still choose the wrong conversion for client data:
//!   dropping a body instead of skolemizing it is a decision rather than a
//!   broken invariant, so `http.rs` tests what a `PUT` with a blank node
//!   stores.
//! * **An unvalidated owner WebID in the root ACL.** `provision_root_acl`
//!   (`src/wac/provision.rs`) interpolates the owner's WebID into a Turtle
//!   string, so an unvalidated one closes the IRI and continues as syntax,
//!   the Plan-1 lesson. Its parameter is `&NamedNode`, and `NamedNode::new`
//!   is the only way to make one, so the check happens where the value is
//!   parsed: `Config::owner_webid` carries the type, not a `String`. The
//!   runtime test that used to feed it `"not an iri> } ; DROP ALL ; #"` is
//!   gone because that expression no longer compiles. What this does *not*
//!   cover: the graph IRIs interpolated beside it come from `GraphName`,
//!   which is sealed by its own rule in `docs/constraints.md`.
//! * **Orphaned auxiliary.** `resource::delete_rdf` is bounded to
//!   `impl DirectlyDeletable` (`src/resource.rs:141-144`), and
//!   `DirectlyDeletable` is implemented only for `AuxUrl` (`src/space.rs:181`),
//!   so `delete_rdf` cannot be called with a `ResourceUrl`/`ContainerUrl` at
//!   all; the compiler refuses it. The only function that deletes a subject
//!   is `aux::delete_subject` (`src/aux.rs:97-113`), whose single
//!   `store.update` call (`src/aux.rs:102-111`) drops the subject's own
//!   graphs plus, via `for kind in AuxKind::ALL`, every auxiliary kind in one
//!   update, so no partial cascade can be observed.
//!
//! The two that remain observable are tested below.

use quadpod::{
    aux, resource,
    space::{AuxKind, StorageSpace, Target},
    store::OxigraphStore,
};

// A Slug names a child in the resource space; nothing it can contain routes
// into `/.aux/`, because that classification happens on the request path.
#[tokio::test]
async fn a_slug_cannot_reach_the_auxiliary_space() {
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    for slug in [".aux", "..aux", "acl", ".aux.acl", ".acl", "note.acl"] {
        let child = format!("/box/{slug}");
        assert!(
            matches!(space.resolve(&child).unwrap(), Target::Resource(_)),
            "{child} must stay an ordinary resource"
        );
    }
    // At the root a slug is the whole first segment, which is the only place
    // it could name the reserved one, and even there it names no auxiliary,
    // because nothing follows it to be a subject.
    assert!(space.resolve("/.aux").is_err(), "a root slug cannot reach the reserved segment");
    assert!(
        matches!(space.resolve("/.acl").unwrap(), Target::Resource(_)),
        "the kind's suffix alone is an ordinary name outside /.aux"
    );
}

// Recreating a path must not restore the policy of the resource that used to
// live there. The cascade makes that structural rather than remembered.
#[tokio::test]
async fn an_auxiliary_never_outlives_its_subject() {
    let store = OxigraphStore::in_memory().unwrap();
    let blobs = quadpod::blob::ObjectStoreBlobs::in_memory();
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    let Target::Resource(doc) = space.resolve("/doc").unwrap() else { panic!() };

    resource::put_rdf(&store, &doc, &[]).await.unwrap();
    aux::put(&store, &doc.aux(AuxKind::Acl), &[]).await.unwrap();
    assert!(resource::exists(&store, &doc.aux(AuxKind::Acl)).await.unwrap());

    assert!(aux::delete_subject(&store, &blobs, &doc).await.unwrap());
    assert!(!resource::exists(&store, &doc.aux(AuxKind::Acl)).await.unwrap());

    // recreate the same path: it inherits, it does not resurrect
    resource::put_rdf(&store, &doc, &[]).await.unwrap();
    assert!(
        !resource::exists(&store, &doc.aux(AuxKind::Acl)).await.unwrap(),
        "the recreated resource must not pick up the deleted one's ACL"
    );
    for ancestor in doc.ancestors() {
        assert!(
            !resource::exists(&store, &ancestor.as_resource().aux(AuxKind::Acl)).await.unwrap(),
            "nor may an ancestor's ACL have been left governing it"
        );
    }
}
