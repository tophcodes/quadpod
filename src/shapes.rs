//! Shape validation: which shape applies, and whether a body satisfies it.

use rudof_lib::{
    formats::{
        DataFormat, InputSpec, ResultShaclValidationFormat, ShaclFormat, ShaclValidationMode,
    },
    Rudof, RudofConfig,
};
use thiserror::Error;

use crate::{
    dataset::Dataset,
    rdf::Format,
    resource::{as_quads, get_rdf, kind_of, Kind, ResourceError},
    space::{ContainerUrl, GraphName, StorageSpace, Target},
    store::SparqlStore,
};

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
    #[error("the validation engine failed: {0}")]
    Engine(String),
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
        .map_err(|e| ShapeError::Engine(e.to_string()))?;
    let data = String::from_utf8(data).expect("the serializer emits UTF-8");

    let mut rudof = Rudof::new(RudofConfig::default());
    rudof
        .load_data()
        .with_data(&[InputSpec::Str(data)])
        .with_data_format(&DataFormat::Turtle)
        .execute()
        .map_err(|e| ShapeError::Engine(e.to_string()))?;
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
        .map_err(|e| ShapeError::Engine(e.to_string()))?;

    let mut out: Vec<u8> = Vec::new();
    rudof
        .serialize_shacl_validation_results(&mut out)
        .with_result_shacl_validation_format(&ResultShaclValidationFormat::Turtle)
        .execute()
        .map_err(|e| ShapeError::Engine(e.to_string()))?;

    let report = turtle()
        .parse(&out, "urn:quadpod:report")
        .map_err(|e| ShapeError::Engine(e.to_string()))?;
    Ok(Report(report))
}

/// `ldp:constrainedBy`, the only binding this pod reads.
const LDP_CONSTRAINED_BY: &str = "http://www.w3.org/ns/ldp#constrainedBy";

/// The constraint document bound to `container`, serialized as Turtle.
///
/// The binding does not inherit: this reads `container`'s own graph and
/// walks nowhere. A document outside this pod's space is refused rather than
/// fetched — shapes are data here, not links.
pub async fn load(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    container: &ContainerUrl,
) -> Result<Option<String>, ShapeError> {
    // `Ok(None)` covers two different states of `container` — one that
    // exists but carries no binding, and one that does not exist at all —
    // because both mean the same thing to a caller: nothing constrains
    // writes here.
    let Some(triples) = get_rdf(store, container).await? else {
        return Ok(None);
    };
    let bindings: Vec<String> = triples
        .iter()
        .filter_map(|t| match &t.object {
            oxigraph::model::Term::NamedNode(n) if t.predicate.as_str() == LDP_CONSTRAINED_BY => {
                Some(n.as_str().to_owned())
            }
            _ => None,
        })
        .collect();
    // Exactly one binding, or none — never a pick among several. The
    // triples come back from a `CONSTRUCT` with no `ORDER BY`, so "the
    // first one" would be an artefact of the store's term ordering rather
    // than anything the author expressed. Two bindings mean the author
    // stated two policies and the server cannot know which; that is the
    // same not-knowing that makes a broken document fail closed (§3.1).
    let iri = match bindings.as_slice() {
        [] => return Ok(None),
        [iri] => iri.clone(),
        _ => {
            return Err(ShapeError::Unsupported(format!(
                "{} carries {} ldp:constrainedBy bindings ({}), not one",
                container.graph_iri(),
                bindings.len(),
                bindings.join(", "),
            )))
        }
    };

    // `strip_prefix` alone confuses `https://pod.toph.so/x` with
    // `https://pod.toph.so.evil.example/x` — the latter also starts with the
    // trimmed base as a byte string. The remainder must begin with `/`, the
    // boundary a same-origin path always has, or the IRI names a different
    // origin entirely.
    let base = space.root().graph_iri().trim_end_matches('/').to_owned();
    let Some(rest) = iri.strip_prefix(&base).filter(|r| r.starts_with('/')) else {
        return Err(ShapeError::Unsupported(iri));
    };
    // `resolve` documents that it always receives an already
    // percent-decoded path from the HTTP layer; `rest` is a raw,
    // never-decoded substring of a client-authored IRI that was stored
    // verbatim in this container's graph. That mismatch is sound here
    // because nothing downstream decodes `rest` either: the resource it
    // resolves to has a graph IRI built byte-for-byte from `rest`, so it is
    // byte-identical to the IRI the client wrote. Two distinct stored IRIs
    // therefore always resolve to two distinct graphs — no percent-encoding
    // variant can alias one stored binding onto a graph a different IRI
    // names.
    let Ok(Target::Resource(r)) = space.resolve(rest) else {
        return Err(ShapeError::Unsupported(iri));
    };

    match kind_of(store, &r).await? {
        None => Err(ShapeError::Missing),
        Some(Kind::Binary(mt)) => Err(ShapeError::Unsupported(mt.as_str().to_owned())),
        Some(Kind::Rdf) => {
            // `kind_of` and this read are two separate store reads, so the
            // document can be deleted in between. Falling back to an empty
            // shapes graph here would make the write it was meant to
            // constrain pass trivially — an empty SHACL graph conforms
            // unconditionally — turning a fail-closed feature fail-open.
            // Report the same `Missing` a document that was never there
            // reports, rather than tolerate the race.
            let triples = get_rdf(store, &r).await?.ok_or(ShapeError::Missing)?;
            let dataset = Dataset::new(as_quads(&triples));
            let bytes = turtle()
                .serialize(&dataset)
                .map_err(|e| ShapeError::Unparsable(e.to_string()))?;
            Ok(Some(
                String::from_utf8(bytes).expect("the serializer emits UTF-8"),
            ))
        }
    }
}

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

    /// A shapes document that is not SHACL is the author's problem; nothing
    /// else in this function is.
    #[test]
    fn an_engine_failure_is_not_reported_as_an_unreadable_document() {
        let body = turtle("<> a <http://schema.org/NoteDigitalDocument> .");
        assert!(matches!(
            validate("this is not turtle {{{", &body),
            Err(ShapeError::Unparsable(_))
        ));
    }

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

    /// Two bindings on one container state two policies, and the server has
    /// no honest way to choose between them (§3.1) — refused, not resolved
    /// by whichever triple the store happens to return first.
    #[tokio::test]
    async fn two_bindings_on_one_container_are_unsupported() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        let c = container(&sp, "/notes/");
        let binding = Format::from_content_type("text/turtle")
            .unwrap()
            .parse(
                b"<> <http://www.w3.org/ns/ldp#constrainedBy> <https://pod.toph.so/shapes/a>, <https://pod.toph.so/shapes/b> .",
                "https://pod.toph.so/notes/",
            )
            .unwrap();
        put_rdf(&store, &c, &crate::dataset::triples_of(&binding)).await.unwrap();
        assert!(matches!(load(&store, &sp, &c).await, Err(ShapeError::Unsupported(_))));
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

    /// The classic prefix-confusion bug: `https://pod.toph.so.evil.example/x`
    /// starts with `https://pod.toph.so` as a byte string, but is a different
    /// origin entirely. Without the `starts_with('/')` guard, the stripped
    /// remainder — `.evil.example/x` — happens to still get refused, by
    /// `StorageSpace::resolve`'s unrelated rooted-path check. The guard
    /// exists so the origin boundary is stated here, at the point it
    /// matters, rather than relying on that incidental rejection elsewhere.
    #[tokio::test]
    async fn a_domain_confusable_constraint_document_is_unsupported() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        let c = container(&sp, "/notes/");
        let binding = Format::from_content_type("text/turtle")
            .unwrap()
            .parse(
                b"<> <http://www.w3.org/ns/ldp#constrainedBy> <https://pod.toph.so.evil.example/x> .",
                "https://pod.toph.so/notes/",
            )
            .unwrap();
        put_rdf(&store, &c, &crate::dataset::triples_of(&binding)).await.unwrap();
        assert!(matches!(load(&store, &sp, &c).await, Err(ShapeError::Unsupported(_))));
    }
}
