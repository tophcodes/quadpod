//! Shape validation: which shape applies, and whether a body satisfies it.

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
