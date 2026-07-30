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

use crate::wac::{AccessModes, Mode};
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
    /// Carries an RDF 1.2 term — `400`, the same answer
    /// [`crate::rdf::Format::parse`] gives a body richer than it declared.
    ///
    /// **Both** of RDF 1.2's additions, not only triple terms: a directional
    /// language-tagged string is an ordinary `Literal`, so a refusal that
    /// matches on `N3Term::Triple` alone lets it through into the store —
    /// which is exactly the half-check `Format::parse` used to have
    /// (`2026-07-30-rdf12-design.md` §2).
    ///
    /// A patch is always read at RDF 1.1. `text/n3` is not one of the five
    /// negotiated formats and carries no `version` parameter here, and §4
    /// reads silence as 1.1. Writing RDF 1.2 through a patch is therefore not
    /// possible today; it needs a version parameter on `text/n3` first.
    #[error("RDF 1.2 terms are not accepted in a patch; a patch is read as RDF 1.1")]
    Rdf12Term,
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
    pub fn satisfied_by(self, held: AccessModes) -> bool {
        (!self.read || held.allows(Mode::Read))
            && (!self.append || held.allows(Mode::Append))
            && (!self.write || held.allows(Mode::Write))
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
        RequiredModes {
            read: !self.conditions.is_empty() || !self.deletions.is_empty(),
            append: !self.insertions.is_empty(),
            write: !self.deletions.is_empty(),
        }
    }

    /// The insertions as ground triples, when there is nothing to match.
    ///
    /// `Some` exactly when the conditions are empty: §5.1 admits a variable in
    /// the insertions only if a condition binds it, so no conditions means no
    /// variables, and the other positions are ground already — a literal
    /// subject or predicate is refused by [`Patch::parse`]. The remaining
    /// `None` arms are therefore unreachable, and stay so that this is a total
    /// function rather than one with a panic in it.
    ///
    /// Ground insertions are what §7 needs to create a resource, but they are
    /// not the whole test: a patch that also deletes asks something of the
    /// prior state, which an absent resource does not have.
    pub fn ground_insertions(&self) -> Option<Vec<Triple>> {
        if !self.conditions.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(self.insertions.len());
        for p in &self.insertions {
            let (PatternTerm::Named(s), PatternTerm::Named(pr)) = (&p.subject, &p.predicate) else {
                return None;
            };
            let object = match &p.object {
                PatternTerm::Named(n) => oxigraph::model::Term::NamedNode(n.clone()),
                PatternTerm::Literal(l) => oxigraph::model::Term::Literal(l.clone()),
                PatternTerm::Var(_) => return None,
            };
            out.push(Triple::new(s.clone(), pr.clone(), object));
        }
        Some(out)
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
///
/// §5.1 asks for two things of the object, and both are checked here: it is a
/// blank node, and that blank node *occurs as a `graph_name` in the same
/// document*. Without the second, `solid:inserts _:nope` reads as a formula
/// with no contents and the patch answers `204` for having done nothing.
///
/// An empty formula — `solid:inserts { }` — reaches this function in exactly
/// that shape: `oxttl` gives it a blank-node object and emits no quad naming
/// it, so the two documents are indistinguishable here and get the same
/// refusal. Omitting the predicate is how a patch says it inserts nothing;
/// §5.1 makes that legal and this leaves it untouched.
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
        [N3Term::BlankNode(b)] if names_a_formula(quads, b) => Ok(Some(b.clone())),
        [_] => Err(PatchError::Shape("a formula predicate whose object is not a formula")),
        _ => Err(PatchError::Shape("more than one of a formula predicate")),
    }
}

/// Whether `b` is the `graph_name` of anything in the document — which is what
/// makes it a formula rather than a blank node that merely sits where one
/// belongs.
fn names_a_formula(quads: &[N3Quad], b: &BlankNode) -> bool {
    let name = GraphName::BlankNode(b.clone());
    quads.iter().any(|q| q.graph_name == name)
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
            subject: non_literal(term(&q.subject, names, binding)?, LITERAL_SUBJECT)?,
            predicate: non_literal(term(&q.predicate, names, binding)?, LITERAL_PREDICATE)?,
            object: term(&q.object, names, binding)?,
        });
    }
    Ok(out)
}

const LITERAL_SUBJECT: &str = "a literal in subject position";
const LITERAL_PREDICATE: &str = "a literal in predicate position";

/// §5.1: only the object position admits a literal. N3 is wider than RDF here —
/// `oxttl` parses a literal subject or predicate inside a formula — so the two
/// positions that RDF forbids are refused as a shape violation, and every later
/// stage may take a subject and a predicate to be a name or a variable.
fn non_literal(t: PatternTerm, violation: &'static str) -> Result<PatternTerm, PatchError> {
    match t {
        PatternTerm::Literal(_) => Err(PatchError::Shape(violation)),
        other => Ok(other),
    }
}

fn term(t: &N3Term, names: &mut Renumber, binding: Binding) -> Result<PatternTerm, PatchError> {
    match t {
        N3Term::NamedNode(n) => {
            if crate::dataset::is_reserved_iri(n.as_str()) {
                return Err(PatchError::Reserved);
            }
            Ok(PatternTerm::Named(n.clone()))
        }
        // A directional language-tagged string is RDF 1.2, and it is a
        // `Literal` — so it reaches this arm and not the one below.
        N3Term::Literal(l) if l.direction().is_some() => Err(PatchError::Rdf12Term),
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
        // A patch is the only way into the store that does not go through
        // `Format::parse`, so the version refusal has to be repeated here.
        // It builds no `Dataset`, which is why it cannot ask
        // `Dataset::rdf_version` — the one classifier — and why this arm and
        // the literal arm above are pinned by their own rule in
        // `docs/constraints.md`.
        N3Term::Triple(_) => Err(PatchError::Rdf12Term),
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

    /// A patch is read as RDF 1.1, and neither of RDF 1.2's additions gets
    /// in. **Measured: `oxttl`'s N3 parser refuses both before this module
    /// sees a term at all** — `<<( … )>>` is "not a valid RDF value" and
    /// `@en--ltr` is "rdf:dirLangString is not supported in N3". So these
    /// assert the refusal, not its route: the `N3Term::Triple` and
    /// directional-`Literal` arms in `term` are depth behind the parser, and
    /// would become the live refusal only if `oxttl` gained RDF 1.2 syntax
    /// for N3.
    ///
    /// That is also why `docs/constraints.md` pins those arms with prose
    /// saying they are currently unreachable: a check whose property holds
    /// trivially is worse than no check when nobody records which one it is.
    #[test]
    fn a_triple_term_in_a_patch_does_not_get_in() {
        let body = format!(
            "{PREFIXES}<> a solid:InsertDeletePatch ; solid:inserts {{ \
             ex:s ex:p <<( ex:a ex:b ex:c )>> . }} ."
        );
        assert!(p(&body).is_err(), "{:?}", p(&body));
    }

    #[test]
    fn a_directional_literal_in_a_patch_does_not_get_in() {
        let body = format!(
            "{PREFIXES}<> a solid:InsertDeletePatch ; solid:inserts {{ \
             ex:s ex:p \"hi\"@en--ltr . }} ."
        );
        assert!(p(&body).is_err(), "{:?}", p(&body));
    }

    /// The refusal is about the version, not about literals: an ordinary
    /// language-tagged string still goes through.
    #[test]
    fn a_plain_language_tagged_literal_still_parses() {
        let body = format!(
            "{PREFIXES}<> a solid:InsertDeletePatch ; solid:inserts {{ \
             ex:s ex:p \"hi\"@en . }} ."
        );
        assert!(p(&body).is_ok(), "{:?}", p(&body));
    }

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

    // `?x` and `_:x` are two names, which is what the `_:` key prefix in
    // `Renumber` buys. Without it both bind index 0, and the conditions
    // silently become `?x ex:knows ?x` — a pattern that matches a different
    // set of triples than the one the client wrote, with no error anywhere.
    #[test]
    fn a_variable_and_a_blank_node_spelled_alike_are_different_names() {
        let patch = p(&format!(
            "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
               solid:where   {{ ?x ex:knows _:x . }} ;\n\
               solid:inserts {{ ?x ex:seen \"yes\" . }} .\n"
        ))
        .unwrap();

        assert_eq!(patch.variables(), 2, "?x and _:x must get an index each");
        assert_eq!(patch.conditions()[0].subject, PatternTerm::Var(0));
        assert_eq!(
            patch.conditions()[0].object,
            PatternTerm::Var(1),
            "the blank node must not collapse onto the variable of the same spelling"
        );
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

    // §5.1: the object of a formula predicate is a blank node that occurs as a
    // `graph_name` in the same document. A blank node that names no formula is
    // not an empty one — nothing in the document says what to insert — and
    // reading it as empty answers `204` for a patch that did nothing.
    #[test]
    fn a_formula_predicate_whose_object_names_no_formula_is_refused() {
        for body in [
            format!(
                "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                   solid:inserts _:nope .\n"
            ),
            format!(
                "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                   solid:where   _:nope ;\n\
                   solid:inserts {{ <> ex:x \"1\" . }} .\n"
            ),
            format!(
                "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                   solid:deletes _:nope .\n"
            ),
            // An empty formula reaches this module in exactly the same shape:
            // `oxttl` gives it a blank-node object and emits no quad naming it.
            // The two are the same document here, so they get the same answer.
            format!("{PREFIXES}_:patch a solid:InsertDeletePatch ; solid:inserts {{ }} .\n"),
        ] {
            assert!(
                matches!(p(&body), Err(PatchError::Shape(_))),
                "must refuse: {body}"
            );
        }
    }

    // §5.1: only the object position admits a literal. oxttl's N3 parser
    // accepts one in subject and in predicate position inside a formula, so
    // this is a document that reaches here and must be refused rather than
    // left for a later stage to notice it cannot build a triple from it.
    #[test]
    fn a_literal_in_subject_or_predicate_position_is_refused() {
        assert!(
            matches!(
                p(&format!(
                    "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                       solid:inserts {{ \"s\" ex:p \"o\" . }} .\n"
                )),
                Err(PatchError::Shape(_))
            ),
            "a literal subject"
        );
        assert!(
            matches!(
                p(&format!(
                    "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                       solid:inserts {{ <> \"p\" \"o\" . }} .\n"
                )),
                Err(PatchError::Shape(_))
            ),
            "a literal predicate"
        );
        // The conditions are held to the same rule: a pattern whose subject is
        // a literal matches nothing an RDF graph can hold.
        assert!(
            matches!(
                p(&format!(
                    "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                       solid:where   {{ \"s\" ex:p ?o . }} ;\n\
                       solid:inserts {{ <> ex:seen ?o . }} .\n"
                )),
                Err(PatchError::Shape(_))
            ),
            "a literal subject in the conditions"
        );
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

    // §3.2.2: the skolem namespace is the server's, and a document naming it
    // literally is a 400 exactly as it is for PUT.
    #[test]
    fn a_literal_reserved_iri_is_refused() {
        for body in [
            format!("{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                       solid:inserts {{ <urn:quadpod:res:1> ex:x \"1\" . }} .\n"),
            format!("{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                       solid:inserts {{ <> ex:x <urn:quadpod:sys:evil> . }} .\n"),
            format!("{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                       solid:where {{ <URN:QUADPOD:res:1> ex:x \"1\" . }} ;\n\
                       solid:inserts {{ <> ex:y \"2\" . }} .\n"),
        ] {
            assert!(
                matches!(Patch::parse(body.as_bytes(), BASE), Err(PatchError::Reserved)),
                "must refuse: {body}"
            );
        }
    }

    // The other half, and the one a fail-closed implementation gets wrong: an
    // ordinary patch must not be refused just because it CAN bind to a skolem
    // IRI later. Nothing here names the namespace, so nothing here is refused.
    #[test]
    fn a_patch_that_may_bind_to_a_skolem_iri_parses_fine() {
        let patch = Patch::parse(
            format!(
                "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
                   solid:where   {{ ?p ex:email \"old\" . }} ;\n\
                   solid:deletes {{ ?p ex:email \"old\" . }} ;\n\
                   solid:inserts {{ ?p ex:email \"new\" . }} .\n"
            )
            .as_bytes(),
            BASE,
        )
        .unwrap();
        assert_eq!(patch.variables(), 1);
    }

    // §7: the only shape that can create a resource. `Some` exactly when the
    // conditions are empty — §5.1 admits a variable in the insertions only if
    // a condition binds it, so no conditions means no variables to leave in.
    #[test]
    fn ground_insertions_exist_exactly_when_nothing_is_matched() {
        let creatable = p(&format!(
            "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
               solid:inserts {{ <> ex:nickname \"Charlie\" . }} .\n"
        ))
        .unwrap();
        let triples = creatable.ground_insertions().expect("no conditions, so ground");
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].subject, NamedNode::new(BASE).unwrap().into());
        assert_eq!(triples[0].object, Literal::new_simple_literal("Charlie").into());

        // A condition means a match is required, and against an absent
        // resource that is a 409 rather than a creation.
        let matching = p(&format!(
            "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
               solid:where   {{ ?p ex:email \"old\" . }} ;\n\
               solid:inserts {{ ?p ex:email \"new\" . }} .\n"
        ))
        .unwrap();
        assert!(matching.ground_insertions().is_none());

        // Empty patch: ground, and empty.
        let empty = p(&format!("{PREFIXES}_:patch a solid:InsertDeletePatch .\n")).unwrap();
        assert_eq!(empty.ground_insertions().map(|t| t.len()), Some(0));
    }

    use crate::wac::AccessModes;

    fn modes(read: bool, write: bool, append: bool) -> AccessModes {
        AccessModes { read, write, append, control: false }
    }

    // §5.3.1's operation mapping. The insert-only row is the one the whole
    // `protected-operation` fixture sends, and it must NOT require Write.
    #[test]
    fn required_modes_follow_the_operation_mapping() {
        let insert_only = p(&format!(
            "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
               solid:inserts {{ <> ex:x \"1\" . }} .\n"
        ))
        .unwrap()
        .required_modes();
        assert_eq!(insert_only, RequiredModes { read: false, append: true, write: false });

        let with_conditions = p(&format!(
            "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
               solid:where   {{ ?p ex:email \"old\" . }} ;\n\
               solid:inserts {{ ?p ex:x \"1\" . }} .\n"
        ))
        .unwrap()
        .required_modes();
        assert_eq!(with_conditions, RequiredModes { read: true, append: true, write: false });

        let with_deletions = p(&format!(
            "{PREFIXES}_:patch a solid:InsertDeletePatch ;\n\
               solid:where   {{ ?p ex:email \"old\" . }} ;\n\
               solid:deletes {{ ?p ex:email \"old\" . }} .\n"
        ))
        .unwrap()
        .required_modes();
        assert_eq!(with_deletions, RequiredModes { read: true, append: false, write: true });
    }

    // The conformance table in §9: a caller holding Append alone may run an
    // insert-only patch, and a caller holding Control alone may not run
    // anything. Both directions, because a gate that always says yes and a
    // gate that always says no each pass one half.
    #[test]
    fn satisfied_by_reads_the_held_modes_exactly() {
        let insert_only = RequiredModes { read: false, append: true, write: false };
        assert!(insert_only.satisfied_by(modes(false, false, true)), "Append alone suffices");
        assert!(insert_only.satisfied_by(modes(false, true, false)), "Write subsumes Append");
        assert!(!insert_only.satisfied_by(modes(true, false, false)), "Read alone does not");
        assert!(
            !insert_only.satisfied_by(AccessModes { read: false, write: false, append: false, control: true }),
            "Control grants ACL access and nothing else"
        );

        let deleting = RequiredModes { read: true, append: false, write: true };
        assert!(deleting.satisfied_by(modes(true, true, false)));
        assert!(!deleting.satisfied_by(modes(false, true, false)), "Write without Read is not enough");
        assert!(!deleting.satisfied_by(modes(true, false, true)), "Append is not Write");
    }
}
