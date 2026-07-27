//! Why six of Plan 6's seven defect classes cannot recur.
//!
//! Four are gone at the type level and have no runtime test, because the
//! expression that would exercise them does not compile:
//!
//! * **Slug escalation.** The only struct literal that produces an `AuxUrl`
//!   is `ResourceUrl::aux` (`src/space.rs:198-202`); `StorageSpace::resolve`'s
//!   auxiliary branch (`src/space.rs:317-349`) does not construct one
//!   independently — it decodes a kind and a subject from the request path
//!   and then calls that same `subject.aux(kind)`, so both routes into an
//!   `AuxUrl` funnel through one constructor. A `Slug` is sanitized by
//!   `container::child_name` (`src/container.rs:91-100`), whose character
//!   filter admits only `[A-Za-z0-9._-]` — no `/`. `Target::Aux` requires a
//!   request path whose FIRST segment is the reserved `.aux` and which still
//!   has a subject path after it (`src/space.rs:317-322`); a child name is one
//!   segment appended to its container's own path, so it can supply one or the
//!   other, never both. The deepest a slug-derived path can reach is the
//!   single reserved segment `/.aux` with no remainder, which `resolve`
//!   refuses as `SpaceError::Reserved` (a 404 — see `src/http.rs`'s
//!   `classify`) — never a `Target::Aux`.
//! * **Auxiliary-of-an-auxiliary.** `AuxUrl`'s impl block (`src/space.rs:266-273`)
//!   offers only `subject()` and `kind()`; there is no method that returns
//!   another `AuxUrl`. The path space offers none either: `resolve` refuses a
//!   decoded subject that itself re-enters the reserved namespace
//!   (`src/space.rs:330-332`), at every nesting depth.
//! * **Twin traversals.** `ResourceUrl::ancestors` (`src/space.rs:246-254`) is
//!   the only function that walks more than one `.parent()` hop, so it is the
//!   sole derivation of the container chain. `wac::guard::authorize_and_materialize`
//!   builds both its authorization loop and its materialization plan from one
//!   call to it (`src/wac/guard.rs:156`), which is what stops the two from
//!   diverging into different chains, as Plan 6's separate walks could.
//!   `ancestors` has one other caller, `wac::prp::effective_acl`'s
//!   ACL-inheritance walk (`src/wac/prp.rs:47`) — a different question (which
//!   ACL governs a path) sharing the same chain, not a second derivation of
//!   it. (The brief for this task described `authorize_and_materialize` as
//!   the *only* consumer of `ancestors`; that overstates it, so this doc
//!   states the weaker, true claim instead.)
//! * **Orphaned auxiliary.** `resource::delete_rdf` is bounded to
//!   `impl DirectlyDeletable` (`src/resource.rs:141-144`), and
//!   `DirectlyDeletable` is implemented only for `AuxUrl` (`src/space.rs:181`)
//!   — so `delete_rdf` cannot be called with a `ResourceUrl`/`ContainerUrl` at
//!   all; the compiler refuses it. The only function that deletes a subject
//!   is `aux::delete_subject` (`src/aux.rs:97-113`), whose single
//!   `store.update` call (`src/aux.rs:102-111`) drops the subject's own
//!   graphs plus, via `for kind in AuxKind::ALL`, every auxiliary kind — one
//!   update, so no partial cascade can be observed.
//!
//! The two that remain observable are tested below.

use sparql_pod::{
    aux, resource,
    space::{AuxKind, StorageSpace, Target},
    store::OxigraphStore,
    wac,
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
    // it could name the reserved one — and even there it names no auxiliary,
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
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    let Target::Resource(doc) = space.resolve("/doc").unwrap() else { panic!() };

    resource::put_rdf(&store, &doc, &[]).await.unwrap();
    aux::put(&store, &doc.aux(AuxKind::Acl), &[]).await.unwrap();
    assert!(resource::exists(&store, &doc.aux(AuxKind::Acl)).await.unwrap());

    assert!(aux::delete_subject(&store, &doc).await.unwrap());
    assert!(!resource::exists(&store, &doc.aux(AuxKind::Acl)).await.unwrap());

    // recreate the same path: it inherits, it does not resurrect
    resource::put_rdf(&store, &doc, &[]).await.unwrap();
    assert!(
        wac::prp::effective_acl(&store, &doc).await.unwrap().is_none(),
        "the recreated resource must not pick up the deleted one's ACL"
    );
}
