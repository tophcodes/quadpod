//! N3 Patch: the document a `PATCH` body carries, and nothing about applying it.
//!
//! The design of `2026-07-30-n3-patch-design.md`. This module parses, validates
//! the shape §5.1 fixes, and answers which access modes the patch needs. It
//! reaches no store and builds no SPARQL, which is what keeps the question
//! "is this document acceptable?" separable from "what does it do to this
//! resource?".
//!
//! **A `Patch` that exists is shape-valid.** [`Patch::parse`] is the only
//! constructor and the fields are private, so no later caller can assemble one
//! that skips a §5.1 check.
//!
//! **No client-chosen name leaves this module.** Variables arrive named by the
//! client and leave as indices (§6.1), so the string a client wrote can never
//! reach a query.

use crate::wac::AccessModes;
use oxigraph::model::{Literal, NamedNode, Triple};

/// Why a patch document is not one.
#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    /// Not parseable as N3 at all — `400`.
    #[error("invalid N3: {0}")]
    Syntax(String),
    /// Parsed, but violates §5.1 — `422`.
    #[error("not a valid N3 Patch: {0}")]
    Shape(&'static str),
    /// Names the reserved namespace literally — `400`, and checked here rather
    /// than after substitution, because a binding may legitimately be a skolem
    /// IRI (§6.3).
    #[error("the urn:quadpod: namespace is reserved")]
    Reserved,
}

/// One position of a triple pattern: ground, or the `n`th variable.
///
/// A blank node in `solid:where` becomes a [`PatternTerm::Var`] — it matches
/// like SPARQL's pattern blank node and is unreachable from the insertion and
/// deletion formulae, which may contain no blank nodes at all (§5.1). So there
/// is no blank-node variant, and there is nothing for a later caller to
/// mishandle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternTerm {
    Named(NamedNode),
    Literal(Literal),
    Var(usize),
}

/// A triple pattern from one of the three formulae.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub subject: PatternTerm,
    pub predicate: PatternTerm,
    pub object: PatternTerm,
}

/// The access modes a patch needs, per §5.3.1's operation mapping: conditions
/// are a Read, insertions an Append, deletions a Read and a Write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredModes {
    pub read: bool,
    pub append: bool,
    pub write: bool,
}

impl RequiredModes {
    /// Whether modes already resolved by `wac::guard::authorize` cover this.
    ///
    /// Takes the held set rather than the store: §9's whole point is that the
    /// one `authorize` call already answered this, and a second ACL resolution
    /// would repeat the ancestor walk and could read a different ACL.
    pub fn satisfied_by(self, _held: AccessModes) -> bool {
        todo!()
    }
}

/// A shape-valid N3 Patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    conditions: Vec<Pattern>,
    deletions: Vec<Pattern>,
    insertions: Vec<Pattern>,
    variables: usize,
}

impl Patch {
    /// Parse a `text/n3` body and enforce §5.1.
    ///
    /// Formulae arrive from `oxttl` as quads whose `graph_name` is a blank node
    /// that is also the object of the `solid:where` / `solid:deletes` /
    /// `solid:inserts` triple, so linking one to its contents is a blank-node
    /// comparison (§4).
    ///
    /// Refuses: no patch resource, more than one, more than one of any formula
    /// predicate, a blank node in the insertions or deletions, a variable in
    /// them that no condition binds. Ignores triples belonging to neither the
    /// patch resource nor its formulae — the specification constrains the patch
    /// resource and does not forbid a document from carrying anything else.
    pub fn parse(_body: &[u8], _base: &str) -> Result<Self, PatchError> {
        todo!()
    }

    pub fn conditions(&self) -> &[Pattern] {
        todo!()
    }

    pub fn deletions(&self) -> &[Pattern] {
        todo!()
    }

    pub fn insertions(&self) -> &[Pattern] {
        todo!()
    }

    /// How many distinct variables the patterns use, so a consumer can name
    /// them `?v0`..`?v{n-1}` without inventing its own numbering.
    pub fn variables(&self) -> usize {
        todo!()
    }

    pub fn required_modes(&self) -> RequiredModes {
        todo!()
    }

    /// The insertions as ground triples, when there is nothing to match.
    ///
    /// `Some` exactly when the conditions are empty: §5.1 admits a variable in
    /// the insertions only if a condition binds it, so no conditions means no
    /// variables. This is the only shape that can create a resource (§7) —
    /// against an absent resource any non-empty condition finds zero mappings
    /// and is a `409`, so the two cases do not overlap.
    pub fn ground_insertions(&self) -> Option<Vec<Triple>> {
        todo!()
    }
}
