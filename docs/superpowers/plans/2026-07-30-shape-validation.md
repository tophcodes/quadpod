# Shape Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A container may name a SHACL shape with `ldp:constrainedBy`; writes into that container are validated against it, and `GET <resource>?validate` returns the current report.

**Architecture:** One new module, `src/shapes.rs`, holding two separable halves — *which shape applies here* (a store read) and *does this body satisfy it* (a pure function over rudof). `put_impl` and `post_impl` call both between `check_conditionals` and the ancestor-materializing walk, so a refusal writes nothing. The read view is a query parameter on the resource itself, which keeps the URL space and the WAC target unchanged.

**Tech Stack:** Rust 1.95.0, axum 0.8, oxigraph 0.5.9, `rudof_lib` 0.3.7.

**Spec:** [`docs/superpowers/specs/2026-07-30-shape-validation-design.md`](../specs/2026-07-30-shape-validation-design.md). Section references below (§3.2, §5.1, …) are to that document.

## Global Constraints

- Dependency is exactly `rudof_lib = { version = "0.3.7", default-features = false }`. Never add `shacl_validation` beside it — that pulls a second `rudof_rdf` (0.2.20 against 0.3.7). Never `rudof` 0.1.x.
- **Refusal is "some result carries `sh:resultSeverity sh:Violation`", never `sh:conforms`.** Verified against rudof 0.3.7: a shape whose only constraint is `sh:severity sh:Warning` still reports `sh:conforms false`. Using `conforms` would make every warn-only shape refuse every write.
- The data graph is the written body's **default graph**, alone (§3.4). No store read enters the write path.
- This feature mints no vocabulary. `ldp:constrainedBy` and `sh:severity` are the whole interface.
- A constraint document outside this pod's storage space is unsupported — shapes are never fetched over the network (§8).
- After every task: `nix develop -c cargo test` passes and `arch-check` reports 0 violated, 0 broken.
- Commit at the end of every task. Conventional commits.

---

### Task 0: Refuse RDF 1.2 triple terms at the parser

**Why this task exists:** `rudof_lib` transitively enables oxigraph's `rdf-12` feature — unconditionally, through `rudof_rdf` and `sparql_service`, confirmed with `cargo tree -e features -i oxrdf`. Cargo unifies features project-wide, so adding the dependency (Task 1 Step 1) does two things beyond adding SHACL: `oxrdf::Term` gains a `Triple(_)` variant, and **the Turtle parser starts accepting RDF 1.2 syntax**. Measured, not assumed:

```
Input:  <http://e/s> <http://e/p> <<( <http://e/a> <http://e/b> <http://e/c> )>> .
Output: ACCEPTED 1 quad(s)
```

The root spec's §3 non-goal — *"No RDF-star / RDF 1.2 on the wire — Solid is RDF-1.1-anchored"* — would otherwise stop holding silently. This task makes it hold because it is checked. `oxttl` 0.2.3 has no version switch, so the check is ours and it goes after parsing.

**Files:**
- Modify: `src/rdf.rs` (`RdfError`, `Format::parse`), `src/dataset.rs` (two exhaustive matches)
- Test: `src/rdf.rs` and `src/http.rs`, each in its own `mod tests`

**Interfaces:**
- Consumes: nothing from earlier tasks — this is the first task
- Produces: `RdfError::Rdf12TripleTerm`, and the invariant that **a `Dataset` built by `Format::parse` never holds a `Term::Triple`**. Tasks 1–5 rely on that invariant and never re-check it.

- [ ] **Step 1: Write the failing tests**

In `src/rdf.rs`'s `mod tests`:

```rust
    /// RDF 1.2 triple terms are refused, so the wire contract stays RDF 1.1
    /// even though the linked parser understands more (root spec §3).
    #[test]
    fn a_triple_term_is_refused() {
        let fmt = Format::from_content_type("text/turtle").unwrap();
        let ttl = b"<http://e/s> <http://e/p> <<( <http://e/a> <http://e/b> <http://e/c> )>> .";
        assert!(matches!(
            fmt.parse(ttl, "http://e/"),
            Err(RdfError::Rdf12TripleTerm)
        ));
    }

    /// The refusal is about triple terms, not about the syntax being new:
    /// ordinary RDF 1.1 still parses.
    #[test]
    fn an_ordinary_triple_still_parses() {
        let fmt = Format::from_content_type("text/turtle").unwrap();
        let ttl = b"<http://e/s> <http://e/p> <http://e/o> .";
        assert_eq!(fmt.parse(ttl, "http://e/").unwrap().quads().len(), 1);
    }
```

In `src/http.rs`'s `mod tests`:

```rust
    #[tokio::test]
    async fn a_put_carrying_a_triple_term_is_a_400() {
        let f = fixture().await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(
                "<http://e/s> <http://e/p> <<( <http://e/a> <http://e/b> <http://e/c> )>> ."
            )).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib rdf::tests::a_triple_term_is_refused`
Expected: FAIL — at this point the crate does not compile at all, because Task 1's dependency is already in `Cargo.toml` and `src/dataset.rs` has two non-exhaustive matches (`E0004`). That compile error **is** the first failure; fix it in Step 3 and the test failure appears underneath it.

- [ ] **Step 3: Close the two matches in `src/dataset.rs`**

In `Skolemized::skolemize`, the object match gains:

```rust
                Term::Triple(_) => unreachable!(
                    "Format::parse refuses RDF 1.2 triple terms, and every Dataset \
                     skolemized here came from it"
                ),
```

In `Skolemized::from_store`, the object match gains an arm consistent with its neighbours, which already decline what they cannot represent:

```rust
                    Term::Triple(_) => return None,
```

`unreachable!` with a justifying message is house style here (`src/rdf.rs:62`). The two arms differ on purpose: `skolemize` sees only client bodies, which Step 4 filters; `from_store` sees whatever the store holds, which this pod does not control on its own.

- [ ] **Step 4: Refuse triple terms in `Format::parse`**

Add the variant to `RdfError`:

```rust
    #[error("RDF 1.2 triple terms are not accepted; this pod stores RDF 1.1")]
    Rdf12TripleTerm,
```

and the check in `Format::parse`, after the parse loop and before `Ok(Dataset::new(out))`:

```rust
        // The linked oxigraph has `rdf-12` on — a transitive dependency turns
        // it on and Cargo unifies features crate-wide — so the parser accepts
        // RDF 1.2. The wire contract is RDF 1.1 (root spec §3), and this is
        // what keeps that true rather than incidental. Only the object can be
        // a triple term; subjects are `NamedOrBlankNode`.
        if out.iter().any(|q| matches!(q.object, Term::Triple(_))) {
            return Err(RdfError::Rdf12TripleTerm);
        }
```

Map `Rdf12TripleTerm` to the same status the existing parse failure produces (`400`) — find that mapping rather than adding a second one.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib rdf::tests` then `nix develop -c cargo test --lib http::tests::a_put_carrying_a_triple_term_is_a_400`
Expected: PASS.

- [ ] **Step 6: Add the constraint**

In `docs/constraints.md`, under a new `## RDF version` heading:

```markdown
The wire contract is RDF 1.1, and it is checked rather than assumed.
    → 2026-07-24-sparql-solid-pod-design.md §3; 2026-07-30-shape-validation-design.md §2.1.
    `rudof_lib` turns on oxigraph's `rdf-12` feature transitively, and Cargo
    unifies features crate-wide, so the linked parser accepts RDF 1.2 whether
    this pod wants it or not. Before that dependency the non-goal held because
    nothing had enabled the feature — an accident, not a property. `oxttl` has
    no version switch, so the refusal is ours and lives in the one parser.
    check: rg -q 'Term::Triple\(_\)' src/rdf.rs
```

- [ ] **Step 7: Run the whole suite and the checks**

Run: `nix develop -c cargo test && arch-check`
Expected: suite green, `14 checked, 0 violated, 0 broken`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/rdf.rs src/dataset.rs src/http.rs docs/constraints.md
git commit -m "feat: refuse RDF 1.2 triple terms, so the RDF 1.1 contract is checked"
```

The commit includes `Cargo.toml`, `Cargo.lock` and `src/lib.rs` because Task 1's dependency line is what makes this task necessary and what makes the tree compile again; `src/shapes.rs` stays uncommitted for Task 1.

---

### Task 1: The validation function

**Files:**
- Create: `src/shapes.rs`
- Modify: `Cargo.toml` (add the dependency), `src/lib.rs` (declare the module)
- Test: `src/shapes.rs`, in its own `mod tests` — this repo puts unit tests in the file under test

**Interfaces:**
- Consumes: `crate::dataset::Dataset`, `crate::rdf::Format`
- Produces:
  - `pub enum ShapeError { Unparsable(String), Unsupported(String), Missing, Resource(crate::resource::ResourceError) }`
  - `pub struct Report` with `pub fn refuses(&self) -> bool`, `pub fn is_empty(&self) -> bool`, `pub fn into_dataset(self) -> Dataset`
  - `pub fn validate(shapes_turtle: &str, body: &Dataset) -> Result<Report, ShapeError>`

- [ ] **Step 1: Add the dependency**

In `Cargo.toml`, in `[dependencies]`, keeping the list alphabetical (it currently runs `reqwest`, `serde_json`, `sha2`, …):

```toml
rudof_lib = { version = "0.3.7", default-features = false }
```

- [ ] **Step 2: Declare the module**

In `src/lib.rs`, beside the other `pub mod` lines:

```rust
pub mod shapes;
```

- [ ] **Step 3: Write the failing tests**

Create `src/shapes.rs` containing only the test module for now:

```rust
//! Shape validation: which shape applies, and whether a body satisfies it.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdf::Format;

    const NOTE_SHAPE_VIOLATION: &str = r#"
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix schema: <http://schema.org/> .
        <http://example.org/NoteShape> a sh:NodeShape ;
          sh:targetClass schema:NoteDigitalDocument ;
          sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Violation ] .
    "#;

    const NOTE_SHAPE_WARNING: &str = r#"
        @prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix schema: <http://schema.org/> .
        <http://example.org/NoteShape> a sh:NodeShape ;
          sh:targetClass schema:NoteDigitalDocument ;
          sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Warning ] .
    "#;

    fn turtle(ttl: &str) -> Dataset {
        Format::from_content_type("text/turtle")
            .expect("turtle is a supported format")
            .parse(ttl.as_bytes(), "https://pod.toph.so/n1")
            .expect("parses")
    }

    /// A body missing a required property is refused.
    #[test]
    fn a_violation_refuses() {
        let body = turtle("<> a <http://schema.org/NoteDigitalDocument> .");
        let report = validate(NOTE_SHAPE_VIOLATION, &body).expect("validates");
        assert!(report.refuses());
        assert!(!report.is_empty());
    }

    /// The trap this pod's whole warn/reject split rests on: rudof reports
    /// `sh:conforms false` for a warning too, so refusal must be read off
    /// `sh:resultSeverity`, never off `sh:conforms`.
    #[test]
    fn a_warning_reports_but_does_not_refuse() {
        let body = turtle("<> a <http://schema.org/NoteDigitalDocument> .");
        let report = validate(NOTE_SHAPE_WARNING, &body).expect("validates");
        assert!(!report.refuses(), "a warning must not refuse the write");
        assert!(!report.is_empty(), "but it is still reported");
    }

    /// A conforming body produces a report with no results at all.
    #[test]
    fn a_conforming_body_reports_nothing() {
        let body = turtle(
            "<> a <http://schema.org/NoteDigitalDocument> ; \
             <http://schema.org/name> \"Note\" .",
        );
        let report = validate(NOTE_SHAPE_VIOLATION, &body).expect("validates");
        assert!(!report.refuses());
        assert!(report.is_empty());
    }

    /// Named graphs in the body are not the data graph (§3.4).
    #[test]
    fn only_the_default_graph_is_validated() {
        let body = Format::from_content_type("application/trig")
            .expect("trig is a supported format")
            .parse(
                b"<urn:example:g> { <https://pod.toph.so/n1> a <http://schema.org/NoteDigitalDocument> . }",
                "https://pod.toph.so/n1",
            )
            .expect("parses");
        let report = validate(NOTE_SHAPE_VIOLATION, &body).expect("validates");
        assert!(report.is_empty(), "a named graph holds no focus node");
    }

    /// A shapes document that is not SHACL at all is an error, not a panic
    /// and not a silent pass.
    #[test]
    fn an_unparsable_shapes_document_is_an_error() {
        let body = turtle("<> a <http://schema.org/NoteDigitalDocument> .");
        assert!(matches!(
            validate("this is not turtle {{{", &body),
            Err(ShapeError::Unparsable(_))
        ));
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib shapes::`
Expected: FAIL — `cannot find function validate in this scope`, `cannot find type ShapeError`.

- [ ] **Step 5: Write the implementation**

Put this above the `mod tests` block in `src/shapes.rs`:

```rust
use rudof_lib::{
    formats::{
        DataFormat, InputSpec, ResultShaclValidationFormat, ShaclFormat, ShaclValidationMode,
    },
    Rudof, RudofConfig,
};
use thiserror::Error;

use crate::{dataset::Dataset, rdf::Format, resource::ResourceError};

/// `sh:resultSeverity`, and the one severity that refuses a write.
const SH_RESULT_SEVERITY: &str = "http://www.w3.org/ns/shacl#resultSeverity";
const SH_VIOLATION: &str = "http://www.w3.org/ns/shacl#Violation";

#[derive(Debug, Error)]
pub enum ShapeError {
    #[error("the constraint document could not be read as SHACL: {0}")]
    Unparsable(String),
    #[error("the constraint document is not an RDF resource in this pod: {0}")]
    Unsupported(String),
    #[error("the constraint document does not exist")]
    Missing,
    #[error(transparent)]
    Resource(#[from] ResourceError),
}

/// A SHACL validation report, as RDF.
///
/// Held as a [`Dataset`] rather than as rudof's own type because the same
/// value is both the thing decisions are read off and the thing served to a
/// client — and serving it goes through this pod's one serializer.
pub struct Report(Dataset);

impl Report {
    /// Whether this report refuses the write.
    ///
    /// Read off `sh:resultSeverity`, **not** `sh:conforms`: rudof reports
    /// `sh:conforms false` for a `sh:Warning` result too, so `conforms` would
    /// turn every advisory shape into a refusing one.
    pub fn refuses(&self) -> bool {
        self.0.quads().iter().any(|q| {
            q.predicate.as_str() == SH_RESULT_SEVERITY
                && matches!(&q.object, oxigraph::model::Term::NamedNode(n) if n.as_str() == SH_VIOLATION)
        })
    }

    /// Whether the report carries no results at all.
    pub fn is_empty(&self) -> bool {
        !self
            .0
            .quads()
            .iter()
            .any(|q| q.predicate.as_str() == SH_RESULT_SEVERITY)
    }

    pub fn into_dataset(self) -> Dataset {
        self.0
    }
}

/// This pod's Turtle handle, for the two hops in and out of rudof.
fn turtle() -> Format {
    Format::from_content_type("text/turtle").expect("text/turtle is one of the five formats")
}

/// Validate `body`'s default graph against `shapes_turtle`.
///
/// Both documents cross the boundary as Turtle text. rudof reads and writes
/// its own serializations, and going through text keeps this pod's parser the
/// only thing that ever builds a [`Dataset`] — including the one built from
/// the report.
pub fn validate(shapes_turtle: &str, body: &Dataset) -> Result<Report, ShapeError> {
    let data = turtle()
        .serialize(&body.default_graph_only())
        .map_err(|e| ShapeError::Unparsable(e.to_string()))?;
    let data = String::from_utf8(data).expect("the serializer emits UTF-8");

    let mut rudof = Rudof::new(RudofConfig::default());
    rudof
        .load_data()
        .with_data(&[InputSpec::Str(data)])
        .with_data_format(&DataFormat::Turtle)
        .execute()
        .map_err(|e| ShapeError::Unparsable(e.to_string()))?;
    rudof
        .load_shacl_shapes()
        .with_shacl_schema(&InputSpec::Str(shapes_turtle.to_owned()))
        .with_shacl_schema_format(&ShaclFormat::Turtle)
        .execute()
        .map_err(|e| ShapeError::Unparsable(e.to_string()))?;
    rudof
        .validate_shacl()
        .with_shacl_validation_mode(&ShaclValidationMode::Native)
        .execute()
        .map_err(|e| ShapeError::Unparsable(e.to_string()))?;

    let mut out: Vec<u8> = Vec::new();
    rudof
        .serialize_shacl_validation_results(&mut out)
        .with_result_shacl_validation_format(&ResultShaclValidationFormat::Turtle)
        .execute()
        .map_err(|e| ShapeError::Unparsable(e.to_string()))?;

    let report = turtle()
        .parse(&out, "urn:quadpod:report")
        .map_err(|e| ShapeError::Unparsable(e.to_string()))?;
    Ok(Report(report))
}
```

If `Dataset` exposes its quads under a different accessor than `quads()`, use that one — check `src/dataset.rs` rather than adding a second accessor.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib shapes::`
Expected: PASS, 5 tests.

- [ ] **Step 7: Run the whole suite and the checks**

Run: `nix develop -c cargo test && arch-check`
Expected: all green, `13 checked, 0 violated, 0 broken`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/shapes.rs
git commit -m "feat: validate a body against a SHACL shape"
```

---

### Task 2: Which shape applies

**Files:**
- Modify: `src/shapes.rs`
- Test: `src/shapes.rs`, `mod tests`

**Interfaces:**
- Consumes: `Task 1`'s `ShapeError`; `crate::resource::{get_rdf, kind_of, Kind}`; `crate::space::{StorageSpace, ContainerUrl, Target}`; `crate::store::SparqlStore`
- Produces: `pub async fn load(store: &dyn SparqlStore, space: &StorageSpace, container: &ContainerUrl) -> Result<Option<String>, ShapeError>` — the constraint document as Turtle text, or `None` when the container names none

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `src/shapes.rs`:

```rust
    use crate::{
        resource::put_rdf,
        space::{StorageSpace, Target},
        store::OxigraphStore,
    };

    fn space() -> StorageSpace {
        StorageSpace::new("https://pod.toph.so/").unwrap()
    }

    fn container(space: &StorageSpace, path: &str) -> ContainerUrl {
        match space.resolve(path).expect("resolves") {
            Target::Container(c) => c,
            _ => panic!("{path} is not a container"),
        }
    }

    fn resource(space: &StorageSpace, path: &str) -> crate::space::ResourceUrl {
        match space.resolve(path).expect("resolves") {
            Target::Resource(r) => r,
            _ => panic!("{path} is not a resource"),
        }
    }

    #[tokio::test]
    async fn a_container_without_a_binding_has_no_shape() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        let c = container(&sp, "/notes/");
        put_rdf(&store, &c, &[]).await.unwrap();
        assert!(load(&store, &sp, &c).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_binding_yields_the_constraint_document() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        let shape = resource(&sp, "/shapes/note");
        let shape_triples = Format::from_content_type("text/turtle")
            .unwrap()
            .parse(NOTE_SHAPE_VIOLATION.as_bytes(), "https://pod.toph.so/shapes/note")
            .unwrap();
        put_rdf(&store, &shape, &crate::dataset::triples_of(&shape_triples)).await.unwrap();

        let c = container(&sp, "/notes/");
        let binding = Format::from_content_type("text/turtle")
            .unwrap()
            .parse(
                b"<> <http://www.w3.org/ns/ldp#constrainedBy> <https://pod.toph.so/shapes/note> .",
                "https://pod.toph.so/notes/",
            )
            .unwrap();
        put_rdf(&store, &c, &crate::dataset::triples_of(&binding)).await.unwrap();

        let doc = load(&store, &sp, &c).await.unwrap().expect("a shape");
        assert!(doc.contains("NodeShape"));
    }

    #[tokio::test]
    async fn a_binding_to_a_missing_document_is_missing() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        let c = container(&sp, "/notes/");
        let binding = Format::from_content_type("text/turtle")
            .unwrap()
            .parse(
                b"<> <http://www.w3.org/ns/ldp#constrainedBy> <https://pod.toph.so/shapes/gone> .",
                "https://pod.toph.so/notes/",
            )
            .unwrap();
        put_rdf(&store, &c, &crate::dataset::triples_of(&binding)).await.unwrap();
        assert!(matches!(load(&store, &sp, &c).await, Err(ShapeError::Missing)));
    }

    /// A shape is never fetched over the network (§8), so a foreign IRI is
    /// refused rather than resolved.
    #[tokio::test]
    async fn a_foreign_constraint_document_is_unsupported() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        let c = container(&sp, "/notes/");
        let binding = Format::from_content_type("text/turtle")
            .unwrap()
            .parse(
                b"<> <http://www.w3.org/ns/ldp#constrainedBy> <https://elsewhere.example/s> .",
                "https://pod.toph.so/notes/",
            )
            .unwrap();
        put_rdf(&store, &c, &crate::dataset::triples_of(&binding)).await.unwrap();
        assert!(matches!(load(&store, &sp, &c).await, Err(ShapeError::Unsupported(_))));
    }
```

If `triples_of` is private to `http.rs`, move it to `dataset.rs` as `pub(crate) fn triples_of(&Dataset) -> Vec<Triple>` and update `http.rs`'s call sites — one helper, one home.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib shapes::`
Expected: FAIL — `cannot find function load in this scope`.

- [ ] **Step 3: Write the implementation**

Add to `src/shapes.rs`:

```rust
use crate::{
    resource::{get_rdf, kind_of, Kind},
    space::{ContainerUrl, StorageSpace, Target},
    store::SparqlStore,
};

/// `ldp:constrainedBy`, the only binding this pod reads.
const LDP_CONSTRAINED_BY: &str = "http://www.w3.org/ns/ldp#constrainedBy";

/// The constraint document bound to `container`, serialized as Turtle.
///
/// The binding does not inherit (§3.2): this reads `container`'s own graph and
/// walks nowhere. A document outside this pod's space is refused rather than
/// fetched — shapes are data here, not links.
pub async fn load(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    container: &ContainerUrl,
) -> Result<Option<String>, ShapeError> {
    let Some(triples) = get_rdf(store, container).await? else {
        return Ok(None);
    };
    let Some(iri) = triples.iter().find_map(|t| match &t.object {
        oxigraph::model::Term::NamedNode(n) if t.predicate.as_str() == LDP_CONSTRAINED_BY => {
            Some(n.as_str().to_owned())
        }
        _ => None,
    }) else {
        return Ok(None);
    };

    let base = space.root().graph_iri();
    let Some(rest) = iri.strip_prefix(base.trim_end_matches('/')) else {
        return Err(ShapeError::Unsupported(iri));
    };
    let Ok(Target::Resource(r)) = space.resolve(rest) else {
        return Err(ShapeError::Unsupported(iri));
    };

    match kind_of(store, &r).await? {
        None => Err(ShapeError::Missing),
        Some(Kind::Binary(mt)) => Err(ShapeError::Unsupported(mt.as_str().to_owned())),
        Some(Kind::Rdf) => {
            let triples = get_rdf(store, &r).await?.unwrap_or_default();
            let dataset = Dataset::from_triples(&triples);
            let bytes = turtle()
                .serialize(&dataset)
                .map_err(|e| ShapeError::Unparsable(e.to_string()))?;
            Ok(Some(
                String::from_utf8(bytes).expect("the serializer emits UTF-8"),
            ))
        }
    }
}
```

`Dataset::from_triples` may not exist; if not, build the dataset the way `resource::as_quads` already does — one `Quad` per triple in the default graph — and reuse that helper rather than writing a second one.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib shapes::`
Expected: PASS, 9 tests.

- [ ] **Step 5: Run the whole suite and the checks**

Run: `nix develop -c cargo test && arch-check`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/shapes.rs src/dataset.rs src/http.rs
git commit -m "feat: read the shape a container binds with ldp:constrainedBy"
```

---

### Task 3: Refuse a violating PUT

**Files:**
- Modify: `src/http.rs` (`put_impl`, between `check_conditionals` and `authorize_and_materialize`)
- Test: `src/http.rs`, `mod tests`

**Interfaces:**
- Consumes: `shapes::{load, validate, Report, ShapeError}`
- Produces: `async fn enforce_shape(st: &AppState, target: &Target, dataset: &Dataset) -> Result<Option<Report>, Response>` — `Ok(None)` when no shape is bound, `Ok(Some(report))` when the write may proceed, `Err(response)` when it may not

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `src/http.rs`:

```rust
    /// The shapes document, and a container bound to it. Returns nothing;
    /// both are ordinary resources afterwards.
    async fn bind_note_shape(f: &Fixture) {
        f.put_turtle("/shapes/note", r#"
            @prefix sh: <http://www.w3.org/ns/shacl#> .
            @prefix schema: <http://schema.org/> .
            <http://example.org/NoteShape> a sh:NodeShape ;
              sh:targetClass schema:NoteDigitalDocument ;
              sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Violation ] .
        "#).await;
        f.put_turtle("/notes/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
            <https://pod.toph.so/shapes/note> .").await;
    }

    #[tokio::test]
    async fn a_violating_write_is_refused_and_stores_nothing() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
            <http://schema.org/name> \"first\" .").await;

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
            .unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle");
        let body = body_string(res).await;
        assert!(body.contains("ValidationReport"), "the report is the body: {body}");

        assert!(f.get_turtle("/notes/n1").await.contains("first"),
            "the refused write must not have replaced the stored representation");
    }

    /// §5.1: validation runs before the traversal that adds the containment
    /// triple, so a refusal leaves the container exactly as it was — no
    /// `ldp:contains` pointing at a resource that was never created.
    #[tokio::test]
    async fn a_refused_write_adds_no_containment() {
        let f = fixture().await;
        bind_note_shape(&f).await;

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
            .unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let listing = f.get_turtle("/notes/").await;
        assert!(!listing.contains("/notes/n1"),
            "the refused write left a containment triple behind: {listing}");
    }

    #[tokio::test]
    async fn a_warning_admits_the_write_and_links_the_report() {
        let f = fixture().await;
        f.put_turtle("/shapes/note", r#"
            @prefix sh: <http://www.w3.org/ns/shacl#> .
            @prefix schema: <http://schema.org/> .
            <http://example.org/NoteShape> a sh:NodeShape ;
              sh:targetClass schema:NoteDigitalDocument ;
              sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Warning ] .
        "#).await;
        f.put_turtle("/notes/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
            <https://pod.toph.so/shapes/note> .").await;

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
            .unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let link = res.headers().get_all(header::LINK).iter()
            .map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>().join(", ");
        assert!(link.contains("/notes/n1?validate") && link.contains("describedby"),
            "expected a describedby link to the report, got: {link}");
    }

    #[tokio::test]
    async fn a_conforming_write_carries_no_report_link() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ; \
                <http://schema.org/name> \"ok\" ."))
            .unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let link = res.headers().get_all(header::LINK).iter()
            .map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>().join(", ");
        assert!(!link.contains("validate"), "nothing to describe: {link}");
    }

    /// An ACL is server-understood data; a user shape may not refuse one (§5.3).
    #[tokio::test]
    async fn an_acl_write_is_never_validated() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
            <http://schema.org/name> \"ok\" .").await;

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/.aux/notes/n1.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(format!(
                "@prefix acl: <http://www.w3.org/ns/auth/acl#> . \
                 <#a> a acl:Authorization ; acl:agent <{OWNER}> ; \
                 acl:accessTo <https://pod.toph.so/notes/n1> ; acl:mode acl:Read, acl:Write, acl:Control ."
            ))).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    /// A blob has no triples, so nothing constrains it (§5.3).
    #[tokio::test]
    async fn a_blob_write_is_never_validated() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/pic.png")
            .header(header::CONTENT_TYPE, "image/png")
            .body(Body::from(&b"\x89PNG"[..])).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    /// Failing closed: an unusable constraint document refuses the write
    /// rather than letting it through unvalidated (§7, §10).
    #[tokio::test]
    async fn a_broken_constraint_document_is_a_conflict() {
        let f = fixture().await;
        f.put_turtle("/notes/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
            <https://pod.toph.so/shapes/gone> .").await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/n1")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
            .unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    /// §3.2: the binding does not inherit.
    #[tokio::test]
    async fn a_binding_does_not_reach_a_grandchild() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes/2026/n1")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
            .unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED,
            "/notes/2026/ carries no binding of its own");
    }
```

A note on what §5.1 is observable *through*, because it is easy to test the wrong thing. Because the binding does not inherit (§3.2), the container that refuses a write is always the target's direct parent — which must exist to hold the binding. A refused write therefore never had missing ancestors to materialize, and a test that asserts "no ancestor container was created" would pass no matter where validation sits. What `authorize_and_materialize` *does* add for a target that does not exist yet is the containment triple at the level above (`wac::guard`, the `is_member` branch). That triple is the observable: place validation after the walk and a `422` leaves `<container> ldp:contains <target>` pointing at a resource that was never created. `a_refused_write_adds_no_containment` is the test that fails when the ordering is wrong.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests`
Expected: FAIL — the violating write returns `201`, not `422`.

- [ ] **Step 3: Write the enforcement helper**

Add to `src/http.rs`, near `check_conditionals`:

```rust
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
        Err(crate::shapes::ShapeError::Resource(e)) => {
            return Err((put_status(&e), e.to_string()).into_response())
        }
        Err(e) => return Err((StatusCode::CONFLICT, e.to_string()).into_response()),
    };
    let report = match crate::shapes::validate(&shapes, dataset) {
        Ok(r) => r,
        Err(e) => return Err((StatusCode::CONFLICT, e.to_string()).into_response()),
    };
    if report.refuses() {
        let body = turtle_bytes(&report.into_dataset());
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            [(header::CONTENT_TYPE, "text/turtle")],
            body,
        )
            .into_response());
    }
    Ok(if report.is_empty() { None } else { Some(report) })
}

/// A dataset as Turtle, for an error body. Not negotiated: `Accept` describes
/// the target's representation, and this is not that.
fn turtle_bytes(dataset: &crate::dataset::Dataset) -> Vec<u8> {
    crate::rdf::Format::from_content_type("text/turtle")
        .expect("text/turtle is one of the five formats")
        .serialize(dataset)
        .unwrap_or_default()
}
```

- [ ] **Step 4: Call it from `put_impl`**

In `put_impl`, immediately after the `check_conditionals` block and before the comment block introducing `authorize_and_materialize`:

```rust
    let findings = match enforce_shape(&st, &target, &dataset).await {
        Ok(f) => f,
        Err(res) => return res,
    };
```

Then, where `put_impl` builds its success response, add the report link when `findings.is_some()`. The response is built by `created(&target)` and the container/resource arms below it; add the header at the single point where the successful response leaves `put_impl`, so both arms get it:

```rust
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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib http::tests`
Expected: PASS.

- [ ] **Step 6: Run the whole suite and the checks**

Run: `nix develop -c cargo test && arch-check`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs
git commit -m "feat: refuse a PUT that violates its container's shape"
```

---

### Task 4: The same for POST

**Files:**
- Modify: `src/http.rs` (`post_impl`)
- Test: `src/http.rs`, `mod tests`

**Interfaces:**
- Consumes: `enforce_shape` and `report_link` from Task 3, unchanged
- Produces: nothing new

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn a_violating_post_is_refused_and_creates_nothing() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        let res = f.app.clone().oneshot(f.owner_request("POST", "/notes/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", "n1")
            .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ."))
            .unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let res = f.app.clone().oneshot(f.owner_request("GET", "/notes/n1")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_conforming_post_is_created() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        let res = f.app.clone().oneshot(f.owner_request("POST", "/notes/")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header("slug", "n1")
            .body(Body::from("<> a <http://schema.org/NoteDigitalDocument> ; \
                <http://schema.org/name> \"ok\" ."))
            .unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::a_violating_post_is_refused_and_creates_nothing`
Expected: FAIL — status is `201`.

- [ ] **Step 3: Call `enforce_shape` from `post_impl`**

In `post_impl`, after the child's `authorize` and after `classify_body` produced `Repr::Rdf(dataset, _)`, and before the ancestor walk. The target passed is the **child** (`&child`), not the parent — the child's parent container is where the binding lives, which for a POST is the container being posted to.

```rust
    let findings = match enforce_shape(&st, &child, &dataset).await {
        Ok(f) => f,
        Err(res) => return res,
    };
```

Blob branches skip it exactly as in `put_impl`: the `Repr::Blob` arm never reaches this line.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib http::tests`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and the checks**

Run: `nix develop -c cargo test && arch-check`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/http.rs
git commit -m "feat: refuse a POST that violates its container's shape"
```

---

### Task 5: `GET <resource>?validate`

**Files:**
- Modify: `src/http.rs` (`handle_get`, `handle_get_root`, `get_impl`)
- Test: `src/http.rs`, `mod tests`

**Interfaces:**
- Consumes: `shapes::{load, validate}`
- Produces: `async fn validate_view(st: AppState, agent: Agent, target: Target, headers: HeaderMap) -> Response`

**Note on the test credentials:** DPoP's `htu` is derived from `req.uri().path()` (`auth::middleware::auth_layer`), which excludes the query string. A request to `/notes/n1?validate` must therefore be **signed for `/notes/n1`** and **sent to `/notes/n1?validate`**. `owner_request` signs whatever string it is given, so it cannot be used directly.

- [ ] **Step 1: Write the failing tests**

```rust
    impl Fixture {
        /// A request whose URI carries a query string. The DPoP proof is
        /// signed for the bare path, because `htu` excludes the query.
        fn owner_request_query(&self, method: &str, path: &str, query: &str)
            -> axum::http::request::Builder
        {
            let b = Request::builder().method(method).uri(format!("{path}?{query}"));
            self.sign(b, OWNER, method, path)
        }
    }

    #[tokio::test]
    async fn validate_view_reports_the_current_state() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
            <http://schema.org/name> \"ok\" .").await;

        let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/n1", "validate")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_string(res).await;
        assert!(body.contains("ValidationReport"));
        assert!(!body.contains("resultSeverity"), "conforming, so no results: {body}");
    }

    /// The report is computed, not stored: editing the shape changes it with
    /// no write to the resource.
    #[tokio::test]
    async fn validate_view_follows_a_later_shape_edit() {
        let f = fixture().await;
        f.put_turtle("/shapes/note", "@prefix sh: <http://www.w3.org/ns/shacl#> . \
            <http://example.org/S> a sh:NodeShape .").await;
        f.put_turtle("/notes/", "<> <http://www.w3.org/ns/ldp#constrainedBy> \
            <https://pod.toph.so/shapes/note> .").await;
        f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> .").await;

        f.put_turtle("/shapes/note", r#"
            @prefix sh: <http://www.w3.org/ns/shacl#> .
            @prefix schema: <http://schema.org/> .
            <http://example.org/NoteShape> a sh:NodeShape ;
              sh:targetClass schema:NoteDigitalDocument ;
              sh:property [ sh:path schema:name ; sh:minCount 1 ; sh:severity sh:Warning ] .
        "#).await;

        let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/n1", "validate")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body_string(res).await.contains("Warning"),
            "the report must reflect the shape as it is now");
    }

    #[tokio::test]
    async fn validate_view_is_404_without_a_binding() {
        let f = fixture().await;
        f.put_turtle("/plain", "<> <http://schema.org/name> \"x\" .").await;
        let res = f.app.clone().oneshot(f.owner_request_query("GET", "/plain", "validate")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn validate_view_needs_read_on_the_subject() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
            <http://schema.org/name> \"ok\" .").await;

        let bob_app = f.app.clone();
        let req = f.sign(
            Request::builder().method("GET").uri("/notes/n1?validate"),
            BOB, "GET", "/notes/n1",
        ).body(Body::empty()).unwrap();
        assert_eq!(bob_app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
    }

    /// An unknown query parameter is ignored, as everywhere else.
    #[tokio::test]
    async fn a_misspelled_parameter_returns_the_resource() {
        let f = fixture().await;
        bind_note_shape(&f).await;
        f.put_turtle("/notes/n1", "<> a <http://schema.org/NoteDigitalDocument> ; \
            <http://schema.org/name> \"ok\" .").await;
        let res = f.app.clone().oneshot(f.owner_request_query("GET", "/notes/n1", "validat")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body_string(res).await.contains("schema.org/name"));
    }
```

Replace `BOB` with whatever the existing tests call the non-owner WebID — grep `mod tests` for the constant beside `OWNER`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::validate_view`
Expected: FAIL — the resource's own representation comes back instead of a report.

- [ ] **Step 3: Route the query parameter**

Change `handle_get` and `handle_get_root` to read the raw query and dispatch. `RawQuery` is axum's extractor for the unparsed query string; it never fails.

```rust
async fn handle_get(
    State(st): State<AppState>, Path(path): Path<String>, Extension(agent): Extension<Agent>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    headers: HeaderMap,
) -> Response {
    match classify(&st.space, &format!("/{path}")) {
        Ok(target) if wants_validation(query.as_deref()) =>
            validate_view(st, agent, target, headers).await,
        Ok(target) => get_impl(st, agent, target, headers).await,
        Err(status) => status.into_response(),
    }
}

/// Whether this request asks for the validation report rather than the
/// resource. The only query parameter this pod gives meaning to; anything
/// else is ignored, as it always has been.
fn wants_validation(query: Option<&str>) -> bool {
    query.is_some_and(|q| q.split('&').any(|p| p == "validate"))
}
```

Apply the same two changes to `handle_get_root`.

- [ ] **Step 4: Write the view**

```rust
/// The current validation report for `target`, computed now.
///
/// Nothing is stored, so nothing can go stale: the report always describes
/// the representation and the shape as they are at this moment.
async fn validate_view(
    st: AppState, agent: Agent, target: Target, headers: HeaderMap,
) -> Response {
    let store = st.store.as_ref();
    if let Err(res) = authorize(store, &agent, &target, Mode::Read).await {
        return with_aux_links(res, &target);
    }
    let container = match &target {
        Target::Aux(_) => return StatusCode::NOT_FOUND.into_response(),
        Target::Resource(r) => r.parent(),
        Target::Container(c) => c.as_resource().parent(),
    };
    let Some(container) = container else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let shapes = match crate::shapes::load(store, &st.space, &container).await {
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Some(s)) => s,
        Err(e) => return (StatusCode::CONFLICT, e.to_string()).into_response(),
    };
    let dataset = match &target {
        Target::Resource(r) => match get_dataset(store, r).await {
            Ok(Some(d)) => d.deskolemize(),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => return (put_status(&e), e.to_string()).into_response(),
        },
        _ => match get_rdf(store, &target_graph(&target)).await {
            Ok(Some(t)) => crate::dataset::Dataset::from_triples(&t),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => return (put_status(&e), e.to_string()).into_response(),
        },
    };
    let report = match crate::shapes::validate(&shapes, &dataset) {
        Ok(r) => r,
        Err(e) => return (StatusCode::CONFLICT, e.to_string()).into_response(),
    };
    let accept = header_str(&headers, header::ACCEPT);
    let Some(fmt) = crate::rdf::negotiate(accept, crate::rdf::Shape::Graph, None) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    match fmt.serialize(&report.into_dataset()) {
        Ok(bytes) => ([(header::CONTENT_TYPE, fmt.media_type())], bytes).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
```

`target_graph` stands for whatever `get_impl` already uses to read a container's triples; reuse that rather than adding a branch. If `get_impl` reads containers through `get_rdf(store, c)` directly, do the same here.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test --lib http::tests`
Expected: PASS.

- [ ] **Step 6: Run the whole suite and the checks**

Run: `nix develop -c cargo test && arch-check`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs
git commit -m "feat: serve the validation report at ?validate"
```

---

### Task 6: The rules that keep it in one place

**Files:**
- Modify: `docs/constraints.md`, `docs/uri-space.md`
- Test: `arch-check`, plus a deliberate temporary violation to prove each rule can fail

**Interfaces:**
- Consumes: the module layout from Tasks 1–5
- Produces: two entries in `docs/constraints.md`

- [ ] **Step 1: Prove the first rule can go red**

Temporarily add a second reader of the binding — in `src/http.rs`, a line mentioning `ldp#constrainedBy` — then run the check you are about to add:

```bash
! rg -q 'ldp#constrainedBy' src --glob '!src/shapes.rs'
```

Expected: exit status 1 (the rule is violated). Revert the temporary line and re-run; expected exit status 0.

- [ ] **Step 2: Prove the second rule can go red**

Temporarily add a second reader of the query string — in `src/get_impl`, a `RawQuery` extractor — then run:

```bash
[ "$(rg -o 'RawQuery' src | wc -l)" -le 3 ]
```

Count the occurrences the real implementation needs first (`handle_get`, `handle_get_root`, and the `wants_validation` doc reference if any), set the bound to exactly that, and confirm one more occurrence breaks it. Revert.

- [ ] **Step 3: Add both rules**

In `docs/constraints.md`, under a new `## Shape validation` heading, following the file's existing shape — rule, reasoning, `check:`:

```markdown
## Shape validation

Only `shapes` reads the constraint binding.
    → 2026-07-30-shape-validation-design.md §3.1, §3.2. The binding is what
    decides whether a write is checked at all; a second reader is a second
    answer to "is this container constrained", and the one that says no wins
    silently. The lookup is also the seam a shape-tree binding would replace
    (§8), which only stays a second lookup while there is exactly one.
    check: ! rg -q 'ldp#constrainedBy' src --glob '!src/shapes.rs'

The query string is read in exactly one place.
    → §6. `?validate` is the only query parameter this pod gives meaning to,
    and the reason it is safe is that it changes no path and therefore no WAC
    target. A second reader elsewhere is behaviour hidden behind a parameter
    that no URL shows and no ACL names.
    check: [ "$(rg -o 'RawQuery' src | wc -l)" = N ]
```

Replace `N` with the count established in Step 2.

- [ ] **Step 4: Document the view in the normative URI-space document**

In `docs/uri-space.md`, after *Server-asserted facts are not auxiliary resources*, add:

```markdown
## One query parameter, and what it means

`GET <resource>?validate` returns the resource's current SHACL validation
report — a `sh:ValidationReport`, in the negotiated RDF format — instead of the
resource's own representation. It is a computed view: nothing is stored, so it
always describes the representation and the shape as they are now.

It is a query parameter rather than an auxiliary because a report is a
server-asserted fact about your data, not your data, and this document reserves
`/.aux/` for the latter. The parameter changes no path, so the URL's WAC target
is the resource itself and `acl:Read` on the resource is what it takes.

`?validate` on a resource whose container binds no shape is a `404`. Every other
query parameter is ignored, as it always has been.
```

- [ ] **Step 5: Verify**

Run: `arch-check`
Expected: `15 checked, 0 violated, 0 broken`.

- [ ] **Step 6: Commit**

```bash
git add docs/constraints.md docs/uri-space.md
git commit -m "docs: constrain the shape binding and the query string to one reader each"
```

---

## Self-Review

**Spec coverage.** §2 (rented crate, versions, features) → Task 1 Step 1 and the global constraints. §3.1/§3.2 (binding, no inheritance) → Task 2, and the grandchild test in Task 3. §3.3 (language read from the stored media type) → Task 2's `kind_of` dispatch; the ShEx rows are absent by design. §3.4 (document scope, default graph) → Task 1's `default_graph_only` and the named-graph test. §4 (severity) → Task 1's `refuses`, and the warn tests in Tasks 1 and 3. §5.1 (placement) → Task 3 Step 4 and the deep-write test. §5.2 (no dry-run) → nothing to build. §5.3 (aux, blobs) → Task 3's two tests. §6 (the view) → Task 5. §7 (status codes) → the 422, 409 and 404 tests across Tasks 3 and 5. §11 (deltas) → Task 6, plus the parent-spec edit noted below.

**Gap found and closed:** the spec's §11 lists a `docs/superpowers/specs/2026-07-24-sparql-solid-pod-design.md` edit (§7's rented-crate row, §11/§12's deferred status). No task covered it. It belongs with the change that makes it true, so do it in **Task 6 Step 4**, in the same commit: replace §7's `rudof (shacl_validation)` row with `rudof_lib`, and move SHACL out of §12's deferred list.

**Placeholder scan:** none. Three places name a fallback explicitly rather than leaving a blank — `Dataset::from_triples`/`as_quads` (Task 2 Step 3), `triples_of`'s home (Task 2 Step 1), `target_graph` (Task 5 Step 4), and the `BOB` constant (Task 5 Step 1). Each says what to check and what to do either way.

**Type consistency:** `ShapeError`, `Report`, `validate`, `load`, `enforce_shape`, `report_link`, `wants_validation`, `validate_view` are spelled identically everywhere they appear. `Report::refuses`/`is_empty`/`into_dataset` are the only three methods used.
