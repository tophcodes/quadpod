use crate::dataset::Dataset;
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
    // Media-type tokens are case-insensitive per RFC 9110 §8.3.1, so
    // `Application/LD+JSON` or `TEXT/TURTLE` must match too.
    match media_type(ct).to_ascii_lowercase().as_str() {
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

/// A media type this pod can read and write, and what it is capable of.
///
/// The point of the newtype is that "Turtle cannot carry named graphs" is
/// stated **once**, here, instead of living in a predicate every caller has to
/// remember to consult. It also keeps oxigraph's `RdfFormat` — an enum with
/// variants we deliberately do not support — out of our own signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format(RdfFormat);

/// What a resource turned out to be, once read. Replaces a bare `bool`
/// parameter that read as `negotiate(accept, true, …)` at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// A default graph and nothing else — every supported format can serve it.
    Graph,
    /// Carries named graphs, so a graph format serves only part of it (§6.2).
    Dataset,
}

impl Format {
    /// The formats this pod accepts on write, from a `Content-Type`.
    /// Media-type tokens are case-insensitive per RFC 9110 §8.3.1.
    pub fn from_content_type(ct: &str) -> Option<Self> {
        match media_type(ct).to_ascii_lowercase().as_str() {
            "text/turtle" => Some(Self(RdfFormat::Turtle)),
            "application/n-triples" => Some(Self(RdfFormat::NTriples)),
            "application/ld+json" => Some(Self(RdfFormat::JsonLd {
                profile: oxigraph::io::JsonLdProfileSet::empty(),
            })),
            "application/trig" => Some(Self(RdfFormat::TriG)),
            "application/n-quads" => Some(Self(RdfFormat::NQuads)),
            _ => None,
        }
    }

    /// What goes in the `Content-Type` of a response.
    pub fn media_type(&self) -> &'static str {
        match self.0 {
            RdfFormat::Turtle => "text/turtle",
            RdfFormat::NTriples => "application/n-triples",
            RdfFormat::JsonLd { .. } => "application/ld+json",
            RdfFormat::TriG => "application/trig",
            RdfFormat::NQuads => "application/n-quads",
            _ => unreachable!("Format is only constructed from the five arms above"),
        }
    }

    /// §6.3: whether named graphs survive this format. `text/turtle` and
    /// `application/n-triples` cannot carry them — oxigraph refuses such a
    /// write outright rather than dropping the graph name, so this is the
    /// difference between a designed answer and a runtime error.
    pub fn carries_dataset(&self) -> bool {
        self.0.supports_datasets()
    }

    pub fn parse(&self, bytes: &[u8], base_iri: &str) -> Result<Dataset, RdfError> {
        let parser = RdfParser::from_format(self.0)
            .with_base_iri(base_iri)
            .map_err(|e| RdfError::Parse(e.to_string()))?;
        let mut out = Vec::new();
        for quad in parser.for_slice(bytes) {
            out.push(quad.map_err(|e| RdfError::Parse(e.to_string()))?);
        }
        Ok(Dataset::new(out))
    }

    /// §6.4: a deterministic function of its input. Quads are sorted before
    /// serialization, exactly as [`etag`] sorts before hashing — one canonical
    /// order for both, so two states that share a validator serialize
    /// identically. Repeatability alone is not enough: oxigraph returns
    /// `CONSTRUCT` results in insertion order.
    pub fn serialize(&self, dataset: &Dataset) -> Result<Vec<u8>, RdfError> {
        // Sorted for the same reason `etag` sorts: oxigraph returns CONSTRUCT
        // results in insertion order, so without this two states that share a
        // validator serialize differently.
        let mut quads: Vec<_> = dataset.quads().to_vec();
        quads.sort_by_key(|q| q.to_string());
        let mut ser = RdfSerializer::from_format(self.0).for_writer(Vec::new());
        for q in &quads {
            ser.serialize_quad(q).map_err(|e| RdfError::Serialize(e.to_string()))?;
        }
        ser.finish().map_err(|e| RdfError::Serialize(e.to_string()))
    }
}

/// §6.3: select the highest-ranked acceptable media range the server can
/// serve, over the whole `Accept` list with q-values — not the first
/// recognised entry, which is what [`format_for_accept`] does today and which
/// answers `text/turtle, application/ld+json` with the lossy one.
///
/// `stored` is what the representation arrived as (§6.4); `*/*` resolves to
/// it. `None` means nothing acceptable is supported at all, which is the only
/// remaining `406`.
pub(crate) fn negotiate(accept: &str, shape: Shape, stored: Option<Format>) -> Option<Format> {
    let usable = |f: Format| shape == Shape::Graph || f.carries_dataset();
    let fallback = || {
        [ "text/turtle", "application/ld+json" ].iter()
            .filter_map(|ct| Format::from_content_type(ct))
            .find(|f| usable(*f))
    };
    let accept = accept.trim();
    if accept.is_empty() {
        return stored.filter(|f| usable(*f)).or_else(fallback);
    }

    // (quality, order) — highest quality wins, earlier entry breaks a tie.
    let mut ranked: Vec<(f32, usize, &str)> = Vec::new();
    for (i, part) in accept.split(',').enumerate() {
        let mut bits = part.split(';');
        let mt = bits.next().unwrap_or("").trim();
        let q = bits
            .filter_map(|p| p.trim().strip_prefix("q=").and_then(|v| v.parse::<f32>().ok()))
            .next()
            .unwrap_or(1.0);
        ranked.push((q, i, mt));
    }
    ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));

    // RFC 9110 §12.5.1: q=0 means the client explicitly rejects that media
    // range, not merely ranks it last. A named type at q=0 must also be
    // excluded from what a wildcard elsewhere in the list resolves to —
    // `*/*, text/turtle;q=0` means "anything but Turtle".
    let rejected: Vec<String> = ranked.iter()
        .filter(|(q, _, mt)| *q == 0.0 && !mt.ends_with("/*"))
        .map(|(_, _, mt)| mt.to_ascii_lowercase())
        .collect();
    let not_rejected = |f: Format| !rejected.iter().any(|r| r == f.media_type());
    let fallback_avoiding_rejected = || {
        [ "text/turtle", "application/ld+json" ].iter()
            .filter_map(|ct| Format::from_content_type(ct))
            .find(|f| usable(*f) && not_rejected(*f))
    };

    for &(q, _, mt) in &ranked {
        if q == 0.0 {
            continue;
        }
        // Media-type tokens are case-insensitive per RFC 9110 §8.3.1, so
        // `Text/*` must match the wildcard arms too.
        let candidate = match mt.to_ascii_lowercase().as_str() {
            "*/*" => stored.filter(|f| usable(*f) && not_rejected(*f)).or_else(fallback_avoiding_rejected),
            "text/*" => Format::from_content_type("text/turtle").filter(|f| usable(*f) && not_rejected(*f)),
            "application/*" => fallback_avoiding_rejected(),
            other => Format::from_content_type(other).filter(|f| usable(*f)),
        };
        if candidate.is_some() {
            return candidate;
        }
    }
    // Nothing offered can serve the resource fully — the first pass only
    // accepts a format that can. §6.2: a graph format against a Shape::Dataset
    // resource still answers with what it can carry (the default graph, plus
    // Link headers naming what it left out), so a second pass repeats the
    // resolution with the `usable` filter dropped. Wildcards are resolved here
    // too, and scoped by their type exactly as above: `text/*` admits only
    // `text/turtle`, and skipping it would answer `406` to a client that named
    // a range this server can serve. Only a media type this server never
    // recognises at all falls through to the `None` below — the one remaining
    // `406`.
    let lax_fallback = || {
        [ "text/turtle", "application/ld+json" ].iter()
            .filter_map(|ct| Format::from_content_type(ct))
            .find(|f| not_rejected(*f))
    };
    for &(q, _, mt) in &ranked {
        if q == 0.0 {
            continue;
        }
        let candidate = match mt.to_ascii_lowercase().as_str() {
            "*/*" => stored.filter(|f| not_rejected(*f)).or_else(lax_fallback),
            "text/*" => Format::from_content_type("text/turtle").filter(|f| not_rejected(*f)),
            "application/*" => lax_fallback(),
            other => Format::from_content_type(other).filter(|f| not_rejected(*f)),
        };
        if candidate.is_some() {
            return candidate;
        }
    }
    None
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
    fn content_type_matching_is_case_insensitive() {
        assert!(format_for_content_type("Application/LD+JSON").is_some());
        assert!(format_for_content_type("TEXT/TURTLE; charset=utf-8").is_some());
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

    #[test]
    fn format_knows_which_media_types_carry_a_dataset() {
        let turtle = Format::from_content_type("text/turtle").unwrap();
        let jsonld = Format::from_content_type("application/ld+json").unwrap();
        let trig = Format::from_content_type("application/trig").unwrap();
        let nquads = Format::from_content_type("application/n-quads").unwrap();
        let ntriples = Format::from_content_type("application/n-triples").unwrap();

        assert!(!turtle.carries_dataset(), "Turtle has no syntax for named graphs");
        assert!(!ntriples.carries_dataset());
        assert!(jsonld.carries_dataset());
        assert!(trig.carries_dataset());
        assert!(nquads.carries_dataset());

        // The media type comes back out for the Content-Type header.
        assert_eq!(turtle.media_type(), "text/turtle");
        assert_eq!(trig.media_type(), "application/trig");

        // Parameters and case are per RFC 9110 §8.3.1.
        assert_eq!(Format::from_content_type("TEXT/TURTLE; charset=utf-8"), Some(turtle));
        assert_eq!(Format::from_content_type("application/json"), None);
    }

    const NAMED_GRAPH_JSONLD: &str = r#"{
      "@context": {"name": "http://schema.org/name"},
      "@graph": [
        {"@id": "http://example.org/g1",
         "@graph": [{"@id": "http://example.org/alice", "name": "Alice"}]},
        {"@id": "http://example.org/bob", "name": "Bob"}
      ]
    }"#;

    #[test]
    fn parse_keeps_the_graph_name() {
        let jsonld = Format::from_content_type("application/ld+json").unwrap();
        let ds = jsonld.parse(NAMED_GRAPH_JSONLD.as_bytes(), "https://pod.toph.so/c/notes").unwrap();

        assert_eq!(ds.quads().len(), 2);
        let named: Vec<_> = ds.quads().iter()
            .filter(|q| q.graph_name != oxigraph::model::GraphName::DefaultGraph)
            .collect();
        assert_eq!(named.len(), 1, "one quad sits in a named graph");
        assert_eq!(
            named[0].graph_name.to_string(),
            "<http://example.org/g1>",
            "the graph name is the client's, unchanged"
        );
    }

    // §6.4: equal meaning must give equal bytes, or a cached validator and a
    // Range request splice mismatched content. Repeatability alone passes even
    // on the broken version, so the two datasets here are built in opposite
    // orders on purpose.
    #[test]
    fn serialization_is_canonical_not_merely_repeatable() {
        use oxigraph::model::{Literal, NamedNode, Quad};
        let g = NamedNode::new("http://example.org/g1").unwrap();
        let p = NamedNode::new("http://schema.org/name").unwrap();
        let q1 = Quad::new(
            NamedNode::new("http://example.org/alice").unwrap(),
            p.clone(), Literal::new_simple_literal("Alice"), g.clone());
        let q2 = Quad::new(
            NamedNode::new("http://example.org/bob").unwrap(),
            p, Literal::new_simple_literal("Bob"), g);

        let forward = Dataset::new(vec![q1.clone(), q2.clone()]);
        let backward = Dataset::new(vec![q2, q1]);

        for ct in ["application/trig", "application/n-quads", "application/ld+json"] {
            let f = Format::from_content_type(ct).unwrap();
            assert_eq!(
                f.serialize(&forward).unwrap(),
                f.serialize(&backward).unwrap(),
                "{ct}: same quads in a different order must serialize identically"
            );
        }
    }

    #[test]
    fn negotiation_prefers_a_format_that_can_carry_the_resource() {
        let jsonld = Format::from_content_type("application/ld+json").unwrap();
        let turtle = Format::from_content_type("text/turtle").unwrap();

        // The case the old first-match resolver gets wrong: Turtle is listed
        // first, but the client also offered a format that carries everything.
        assert_eq!(
            negotiate("text/turtle, application/ld+json", Shape::Dataset, None),
            Some(jsonld));
        // On a graph-shaped resource the same header takes the first match.
        assert_eq!(
            negotiate("text/turtle, application/ld+json", Shape::Graph, None),
            Some(turtle));
        // q-values outrank order.
        assert_eq!(
            negotiate("application/ld+json;q=0.2, text/turtle;q=0.9", Shape::Graph, None),
            Some(turtle));
        // `*/*` resolves to what the resource arrived as (§6.4).
        assert_eq!(negotiate("*/*", Shape::Graph, Some(turtle)), Some(turtle));
        assert_eq!(negotiate("*/*", Shape::Dataset, Some(turtle)), Some(jsonld),
            "stored format cannot serve it, so fall to one that can");
        // text/* is scoped by its type.
        assert_eq!(negotiate("text/*", Shape::Graph, None), Some(turtle));
        // Nothing supported at all is the only remaining 406.
        assert_eq!(negotiate("image/png", Shape::Graph, None), None);
        // `*/*` with nothing stored falls back to Turtle first (§6.4) — only
        // when Turtle cannot carry the resource does JSON-LD win.
        assert_eq!(negotiate("*/*", Shape::Graph, None), Some(turtle));
        assert_eq!(negotiate("*/*", Shape::Dataset, None), Some(jsonld));
        // application/* must resolve to something that can serve the resource.
        assert_eq!(negotiate("application/*", Shape::Graph, None), Some(turtle));
        assert_eq!(negotiate("application/*", Shape::Dataset, None), Some(jsonld));
    }

    // RFC 9110 §12.5.1: q=0 is a refusal, not a low rank.
    #[test]
    fn q_zero_is_a_refusal_not_a_low_rank() {
        let jsonld = Format::from_content_type("application/ld+json").unwrap();

        assert_eq!(negotiate("text/turtle;q=0", Shape::Graph, None), None);
        // The only nominally-acceptable entry is refused, and the other is
        // unsupported outright — nothing left to serve.
        assert_eq!(negotiate("image/png, text/turtle;q=0", Shape::Graph, None), None);
        // `*/*` must not resolve to a type excluded elsewhere in the list.
        assert_ne!(negotiate("*/*, text/turtle;q=0", Shape::Graph, None), Some(Format::from_content_type("text/turtle").unwrap()));
        assert_eq!(negotiate("*/*, text/turtle;q=0", Shape::Graph, None), Some(jsonld));
    }

    #[test]
    fn wildcard_matching_is_case_insensitive() {
        let turtle = Format::from_content_type("text/turtle").unwrap();
        assert_eq!(negotiate("Text/*", Shape::Graph, None), Some(turtle));
    }

    // §6.2: a client that names only a graph format still gets an answer —
    // the default graph — rather than a 406. The earlier test above only
    // covers the *preference* for a fuller format when one is also offered;
    // this is the case where a graph format is all there is.
    #[test]
    fn a_lone_graph_format_still_serves_a_dataset_shaped_resource() {
        let turtle = Format::from_content_type("text/turtle").unwrap();
        assert_eq!(negotiate("text/turtle", Shape::Dataset, None), Some(turtle));
        // q=0 still refuses it outright — this is a fallback, not an override.
        assert_eq!(negotiate("text/turtle;q=0", Shape::Dataset, None), None);
        // A genuinely unsupported type gets no such fallback.
        assert_eq!(negotiate("image/png", Shape::Dataset, None), None);
    }

    // §6.3: `text/*` admits `text/turtle`, and `406` is for when *nothing*
    // acceptable is supported at all. A range that resolves to a format this
    // server serves is not that case — even when the format can only carry
    // part of the resource, which is precisely what §6.2 answers with the
    // default graph. `*/*` and `application/*` reach a dataset-capable format
    // in the first pass, so `text/*` is the range where the second pass is
    // the only thing standing between the client and a wrong `406`.
    #[test]
    fn a_wildcard_range_still_serves_a_dataset_shaped_resource() {
        let turtle = Format::from_content_type("text/turtle").unwrap();
        assert_eq!(negotiate("text/*", Shape::Dataset, None), Some(turtle));
        assert_eq!(negotiate("Text/*", Shape::Dataset, None), Some(turtle),
            "media ranges are case-insensitive here too (RFC 9110 §8.3.1)");
        // Still scoped by its type, and still refusable.
        assert_eq!(negotiate("text/*, text/turtle;q=0", Shape::Dataset, None), None);
        assert_eq!(negotiate("image/*", Shape::Dataset, None), None);
    }
}
