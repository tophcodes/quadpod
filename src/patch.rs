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
use oxigraph::model::{BlankNode, GraphName, Literal, NamedNode, Triple};
use oxttl::n3::{N3Parser, N3Quad, N3Term};
use std::collections::HashMap;

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

const SOLID_INSERT_DELETE_PATCH: &str = "http://www.w3.org/ns/solid/terms#InsertDeletePatch";
const SOLID_WHERE: &str = "http://www.w3.org/ns/solid/terms#where";
const SOLID_DELETES: &str = "http://www.w3.org/ns/solid/terms#deletes";
const SOLID_INSERTS: &str = "http://www.w3.org/ns/solid/terms#inserts";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// Assigns each distinct client name — variable or condition blank node — the
/// next free index, so §6.1's renumbering happens in exactly one place.
///
/// Conditions are walked first and are the only formula allowed to *create* an
/// index. A lookup that misses in the insertions or deletions is §5.1's
/// unbound variable, which is why `bind` and `lookup` are separate.
///
/// Variables and condition blank nodes share this map, so a blank-node key is
/// prefixed (`_:`) to keep it distinct from a variable of the same spelling —
/// `?x` and `_:x` are different names.
#[derive(Default)]
struct Renumber(HashMap<String, usize>);

impl Renumber {
    fn bind(&mut self, name: &str) -> usize {
        let next = self.0.len();
        *self.0.entry(name.to_owned()).or_insert(next)
    }

    fn lookup(&self, name: &str) -> Option<usize> {
        self.0.get(name).copied()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
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
    pub fn parse(body: &[u8], base: &str) -> Result<Self, PatchError> {
        let parser = N3Parser::new()
            .with_base_iri(base)
            .map_err(|e| PatchError::Syntax(e.to_string()))?;
        let mut quads: Vec<N3Quad> = Vec::new();
        for quad in parser.for_slice(body) {
            quads.push(quad.map_err(|e| PatchError::Syntax(e.to_string()))?);
        }

        let subject = patch_subject(&quads)?;
        let conditions_formula = formula(&quads, &subject, SOLID_WHERE)?;
        let deletions_formula = formula(&quads, &subject, SOLID_DELETES)?;
        let insertions_formula = formula(&quads, &subject, SOLID_INSERTS)?;

        // Conditions first: they are the only formula that may introduce a
        // name, so walking them first is what makes an unbound variable in the
        // other two detectable rather than silently fresh.
        let mut names = Renumber::default();
        let conditions = patterns(&quads, conditions_formula.as_ref(), &mut names, Binding::Bind)?;
        let deletions = patterns(&quads, deletions_formula.as_ref(), &mut names, Binding::Lookup)?;
        let insertions = patterns(&quads, insertions_formula.as_ref(), &mut names, Binding::Lookup)?;

        Ok(Self { conditions, deletions, insertions, variables: names.len() })
    }

    pub fn conditions(&self) -> &[Pattern] {
        &self.conditions
    }

    pub fn deletions(&self) -> &[Pattern] {
        &self.deletions
    }

    pub fn insertions(&self) -> &[Pattern] {
        &self.insertions
    }

    /// How many distinct variables the patterns use, so a consumer can name
    /// them `?v0`..`?v{n-1}` without inventing its own numbering.
    pub fn variables(&self) -> usize {
        self.variables
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

/// The one subject typed `solid:InsertDeletePatch`.
fn patch_subject(quads: &[N3Quad]) -> Result<N3Term, PatchError> {
    let mut found: Vec<&N3Term> = Vec::new();
    for q in quads {
        let is_type_triple = q.graph_name == GraphName::DefaultGraph
            && matches!(&q.predicate, N3Term::NamedNode(n) if n.as_str() == RDF_TYPE)
            && matches!(&q.object, N3Term::NamedNode(n) if n.as_str() == SOLID_INSERT_DELETE_PATCH);
        if is_type_triple && !found.contains(&&q.subject) {
            found.push(&q.subject);
        }
    }
    match found.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(PatchError::Shape("no solid:InsertDeletePatch resource")),
        _ => Err(PatchError::Shape("more than one solid:InsertDeletePatch resource")),
    }
}

/// The blank node naming one formula of the patch resource, if it has one.
fn formula(
    quads: &[N3Quad],
    subject: &N3Term,
    predicate: &str,
) -> Result<Option<BlankNode>, PatchError> {
    let mut found: Vec<&N3Term> = Vec::new();
    for q in quads {
        if q.graph_name == GraphName::DefaultGraph
            && &q.subject == subject
            && matches!(&q.predicate, N3Term::NamedNode(n) if n.as_str() == predicate)
        {
            found.push(&q.object);
        }
    }
    match found.as_slice() {
        [] => Ok(None),
        [N3Term::BlankNode(b)] => Ok(Some(b.clone())),
        [_] => Err(PatchError::Shape("a formula predicate whose object is not a formula")),
        _ => Err(PatchError::Shape("more than one of a formula predicate")),
    }
}

/// Whether a formula may introduce names (`solid:where`) or only use them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Binding {
    Bind,
    Lookup,
}

fn patterns(
    quads: &[N3Quad],
    formula: Option<&BlankNode>,
    names: &mut Renumber,
    binding: Binding,
) -> Result<Vec<Pattern>, PatchError> {
    let Some(formula) = formula else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for q in quads {
        if q.graph_name != GraphName::BlankNode(formula.clone()) {
            continue;
        }
        out.push(Pattern {
            subject: term(&q.subject, names, binding)?,
            predicate: term(&q.predicate, names, binding)?,
            object: term(&q.object, names, binding)?,
        });
    }
    Ok(out)
}

fn term(t: &N3Term, names: &mut Renumber, binding: Binding) -> Result<PatternTerm, PatchError> {
    match t {
        N3Term::NamedNode(n) => Ok(PatternTerm::Named(n.clone())),
        N3Term::Literal(l) => Ok(PatternTerm::Literal(l.clone())),
        N3Term::Variable(v) => match binding {
            Binding::Bind => Ok(PatternTerm::Var(names.bind(v.as_str()))),
            Binding::Lookup => names
                .lookup(v.as_str())
                .map(PatternTerm::Var)
                .ok_or(PatchError::Shape("a variable no condition binds")),
        },
        // A blank node in `solid:where` matches like SPARQL's pattern blank
        // node; in the other two formulae it is §5.1's refusal.
        N3Term::BlankNode(b) => match binding {
            Binding::Bind => Ok(PatternTerm::Var(names.bind(&format!("_:{}", b.as_str())))),
            Binding::Lookup => Err(PatchError::Shape("a blank node in insertions or deletions")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://pod.toph.so/profile";

    fn p(body: &str) -> Result<Patch, PatchError> {
        Patch::parse(body.as_bytes(), BASE)
    }

    fn named(iri: &str) -> PatternTerm {
        PatternTerm::Named(NamedNode::new(iri).unwrap())
    }

    fn lit(v: &str) -> PatternTerm {
        PatternTerm::Literal(Literal::new_simple_literal(v))
    }

    const PREFIXES: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
                            @prefix ex: <http://example.org/> .\n";

    // §4: a formula's contents arrive as quads whose graph_name is a blank
    // node that is ALSO the object of the solid:where / solid:deletes /
    // solid:inserts triple. The `where` and `deletes` formulae here hold
    // IDENTICAL triples, which is what kills the implementation that collects
    // quads without regard to graph_name — that one would put all three
    // formulae into all three fields and still pass any patch whose formulae
    // happen to differ, which is most of them.
    #[test]
    fn each_formula_keeps_its_own_contents() {
        let patch = p(&format!(
            "{PREFIXES}\
             _:patch a solid:InsertDeletePatch ;\n\
               solid:where   {{ ?person ex:email \"old\" . }} ;\n\
               solid:deletes {{ ?person ex:email \"old\" . }} ;\n\
               solid:inserts {{ ?person ex:email \"new\" . }} .\n"
        ))
        .unwrap();

        assert_eq!(patch.conditions().len(), 1);
        assert_eq!(patch.deletions().len(), 1);
        assert_eq!(patch.insertions().len(), 1);
        assert_eq!(patch.conditions()[0].object, lit("old"));
        assert_eq!(patch.deletions()[0].object, lit("old"));
        assert_eq!(
            patch.insertions()[0].object,
            lit("new"),
            "the inserts formula must not have been merged with the others"
        );
        assert_eq!(patch.insertions()[0].predicate, named("http://example.org/email"));
    }

    // §6.1: the client's spelling never leaves this module. Asserted on the
    // parsed term rather than on a rendered query, because the type is what
    // enforces it — PatternTerm has no String-carrying variable variant.
    #[test]
    fn variables_become_indices_in_first_occurrence_order() {
        let patch = p(&format!(
            "{PREFIXES}\
             _:patch a solid:InsertDeletePatch ;\n\
               solid:where   {{ ?first ex:knows ?second . }} ;\n\
               solid:inserts {{ ?second ex:knownBy ?first . }} .\n"
        ))
        .unwrap();

        assert_eq!(patch.variables(), 2);
        assert_eq!(patch.conditions()[0].subject, PatternTerm::Var(0));
        assert_eq!(patch.conditions()[0].object, PatternTerm::Var(1));
        // The same name resolves to the same index across formulae — this is
        // what makes a binding substitutable at all.
        assert_eq!(patch.insertions()[0].subject, PatternTerm::Var(1));
        assert_eq!(patch.insertions()[0].object, PatternTerm::Var(0));
    }

    // `<>` is the resource itself. The conformance fixture uses exactly this
    // shape, so a parser that does not resolve against the base IRI fails 63
    // scenarios while passing every test above.
    #[test]
    fn the_empty_iri_resolves_against_the_base() {
        let patch = p(&format!(
            "{PREFIXES}\
             _:patch a solid:InsertDeletePatch ;\n\
               solid:inserts {{ <> a <http://example.org#Foo> . }} .\n"
        ))
        .unwrap();

        assert_eq!(patch.insertions()[0].subject, named(BASE));
    }

    // A patch with no conditions is legal and common — it is the shape the
    // whole `protected-operation` fixture sends.
    #[test]
    fn a_patch_may_have_only_insertions() {
        let patch = p(&format!(
            "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
               solid:inserts {{ <> ex:nickname \"Charlie\" . }} .\n"
        ))
        .unwrap();

        assert!(patch.conditions().is_empty());
        assert!(patch.deletions().is_empty());
        assert_eq!(patch.insertions().len(), 1);
        assert_eq!(patch.variables(), 0);
    }

    #[test]
    fn a_body_that_is_not_n3_is_a_syntax_error() {
        assert!(matches!(p("this is not N3 {{{"), Err(PatchError::Syntax(_))));
    }

    // §5.1's refusals, each `422`.
    #[test]
    fn the_shape_rules_refuse_what_they_say_they_refuse() {
        // No patch resource at all.
        assert!(matches!(
            p(&format!("{PREFIXES}<#me> ex:name \"Toph\" .\n")),
            Err(PatchError::Shape(_))
        ));

        // Two patch resources: "the patch" is ambiguous and picking one would
        // be arbitrary.
        assert!(matches!(
            p(&format!(
                "{PREFIXES}\
                 _:a a solid:InsertDeletePatch ; solid:inserts {{ <> ex:x \"1\" . }} .\n\
                 _:b a solid:InsertDeletePatch ; solid:inserts {{ <> ex:y \"2\" . }} .\n"
            )),
            Err(PatchError::Shape(_))
        ));

        // Two of one formula predicate.
        assert!(matches!(
            p(&format!(
                "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                   solid:inserts {{ <> ex:x \"1\" . }} ;\n\
                   solid:inserts {{ <> ex:y \"2\" . }} .\n"
            )),
            Err(PatchError::Shape(_))
        ));

        // A blank node in the insertions.
        assert!(matches!(
            p(&format!(
                "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                   solid:inserts {{ <> ex:knows _:someone . }} .\n"
            )),
            Err(PatchError::Shape(_))
        ));

        // A variable in the deletions that no condition binds.
        assert!(matches!(
            p(&format!(
                "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                   solid:where   {{ <> ex:email \"old\" . }} ;\n\
                   solid:deletes {{ ?unbound ex:email \"old\" . }} .\n"
            )),
            Err(PatchError::Shape(_))
        ));
    }

    // The two LENIENT cases. A fail-closed implementation gets both wrong,
    // and no refusal test can catch that — only these can.
    #[test]
    fn what_the_shape_rules_deliberately_allow() {
        // Triples belonging to neither the patch resource nor its formulae are
        // ignored: the specification constrains the patch resource and does not
        // forbid a document from carrying anything else.
        let patch = p(&format!(
            "{PREFIXES}\
             _:patch a solid:InsertDeletePatch ;\n\
               solid:inserts {{ <> ex:nickname \"Charlie\" . }} .\n\
             <#unrelated> ex:name \"noise\" .\n"
        ))
        .unwrap();
        assert_eq!(patch.insertions().len(), 1);

        // Neither insertions nor deletions: "at most one" makes both absent
        // legal, and the processing steps then yield no change. §5.1 follows
        // that literally rather than inventing a refusal.
        let empty = p(&format!("{PREFIXES}_:patch a solid:InsertDeletePatch .\n")).unwrap();
        assert!(empty.insertions().is_empty());
        assert!(empty.deletions().is_empty());

        // A blank node in the CONDITIONS is fine — it matches like SPARQL's
        // pattern blank node and becomes a variable no formula can name.
        let bnode_condition = p(&format!(
            "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
               solid:where   {{ _:x ex:email \"old\" . }} ;\n\
               solid:inserts {{ <> ex:seen \"yes\" . }} .\n"
        ))
        .unwrap();
        assert_eq!(bnode_condition.conditions().len(), 1);
        assert_eq!(bnode_condition.conditions()[0].subject, PatternTerm::Var(0));
    }
}
