use oxigraph::io::{RdfFormat, RdfParser, RdfSerializer};
use oxigraph::model::Triple;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RdfError {
    #[error("rdf parse error: {0}")]
    Parse(String),
    #[error("rdf serialize error: {0}")]
    Serialize(String),
    #[error("unsupported media type")]
    UnsupportedType,
}

fn turtle() -> RdfFormat {
    RdfFormat::Turtle
}
fn ntriples() -> RdfFormat {
    RdfFormat::NTriples
}
fn jsonld() -> RdfFormat {
    RdfFormat::JsonLd {
        profile: oxigraph::io::JsonLdProfileSet::empty(),
    }
}

fn media_type(ct: &str) -> &str {
    ct.split(';').next().unwrap_or("").trim()
}

pub fn format_for_content_type(ct: &str) -> Option<RdfFormat> {
    match media_type(ct) {
        "text/turtle" => Some(turtle()),
        "application/ld+json" => Some(jsonld()),
        "application/n-triples" => Some(ntriples()),
        _ => None,
    }
}

pub fn format_for_accept(accept: &str) -> Option<RdfFormat> {
    let a = accept.trim();
    if a.is_empty() {
        return Some(turtle());
    }
    let mut saw_type = false;
    for part in a.split(',') {
        let mt = media_type(part);
        if mt == "*/*" || mt == "text/*" {
            return Some(turtle());
        }
        saw_type = true;
        if let Some(f) = format_for_content_type(mt) {
            return Some(f);
        }
    }
    if saw_type {
        None
    } else {
        Some(turtle())
    }
}

pub fn parse(bytes: &[u8], fmt: RdfFormat, base_iri: &str) -> Result<Vec<Triple>, RdfError> {
    let parser = RdfParser::from_format(fmt)
        .with_base_iri(base_iri)
        .map_err(|e| RdfError::Parse(e.to_string()))?;
    let mut out = Vec::new();
    for quad in parser.for_slice(bytes) {
        let q = quad.map_err(|e| RdfError::Parse(e.to_string()))?;
        out.push(Triple {
            subject: q.subject,
            predicate: q.predicate,
            object: q.object,
        });
    }
    Ok(out)
}

/// Renders terms via `Display`, so this assumes stable blank-node labeling from the store
/// (fine for ground graphs; revisit when bnode-bearing graphs arrive).
pub fn etag(triples: &[Triple]) -> String {
    let mut lines: Vec<String> = triples
        .iter()
        .map(|t| format!("{} {} {} .", t.subject, t.predicate, t.object))
        .collect();
    lines.sort();
    let mut h = Sha256::new();
    for l in &lines {
        h.update(l.as_bytes());
        h.update(b"\n");
    }
    format!("\"{}\"", hex::encode(h.finalize()))
}

pub fn serialize(triples: &[Triple], fmt: RdfFormat) -> Result<Vec<u8>, RdfError> {
    let mut ser = RdfSerializer::from_format(fmt).for_writer(Vec::new());
    for t in triples {
        ser.serialize_triple(t)
            .map_err(|e| RdfError::Serialize(e.to_string()))?;
    }
    ser.finish().map_err(|e| RdfError::Serialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxigraph::model::{Literal, NamedNode, Triple};

    fn sample() -> Vec<Triple> {
        vec![Triple::new(
            NamedNode::new("https://pod.toph.so/foo#it").unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("Toph"),
        )]
    }

    #[test]
    fn content_type_mapping() {
        assert!(format_for_content_type("text/turtle").is_some());
        assert!(format_for_content_type("text/turtle; charset=utf-8").is_some());
        assert!(format_for_content_type("application/ld+json").is_some());
        assert!(format_for_content_type("application/n-triples").is_some());
        assert!(format_for_content_type("application/json").is_none());
    }

    #[test]
    fn accept_defaults_to_turtle_and_picks_supported() {
        assert!(format_for_accept("*/*").is_some());
        assert!(format_for_accept("").is_some());
        assert!(format_for_accept("application/ld+json").is_some());
        assert!(format_for_accept("application/xhtml+xml, application/ld+json").is_some());
        assert!(format_for_accept("image/png").is_none());
    }

    #[test]
    fn etag_is_order_independent_and_changes_with_content() {
        use oxigraph::model::{Triple, NamedNode, Literal};
        let s = NamedNode::new("https://pod.toph.so/foo#it").unwrap();
        let p1 = NamedNode::new("http://schema.org/name").unwrap();
        let p2 = NamedNode::new("http://schema.org/age").unwrap();
        let t1 = Triple::new(s.clone(), p1, Literal::new_simple_literal("Toph"));
        let t2 = Triple::new(s, p2, Literal::new_simple_literal("40"));
        let ab = etag(&[t1.clone(), t2.clone()]);
        let ba = etag(&[t2, t1.clone()]);
        assert_eq!(ab, ba);                       // order-independent
        assert_ne!(ab, etag(&[t1]));              // content-sensitive
        assert!(ab.starts_with('"') && ab.ends_with('"'));
    }

    #[test]
    fn turtle_to_jsonld_roundtrip_preserves_triples() {
        let ttl = serialize(&sample(), format_for_content_type("text/turtle").unwrap()).unwrap();
        let via_ttl = parse(
            &ttl,
            format_for_content_type("text/turtle").unwrap(),
            "https://pod.toph.so/foo",
        )
        .unwrap();
        let jsonld = serialize(&via_ttl, format_for_content_type("application/ld+json").unwrap())
            .unwrap();
        let via_json = parse(
            &jsonld,
            format_for_content_type("application/ld+json").unwrap(),
            "https://pod.toph.so/foo",
        )
        .unwrap();
        assert_eq!(via_json.len(), 1);
        assert_eq!(via_json[0].predicate.as_str(), "http://schema.org/name");
        assert!(String::from_utf8_lossy(&jsonld).contains("schema.org/name"));
    }
}
