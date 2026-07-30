use crate::dataset::Dataset;
use oxigraph::io::{RdfFormat, RdfParser, RdfSerializer};
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

fn media_type(ct: &str) -> &str {
    ct.split(';').next().unwrap_or("").trim()
}

/// A media type this pod stores and echoes back.
///
/// [`Format`] answers "can I parse this as RDF?" and its `media_type` is a
/// `&'static str`, so every `Content-Type` the RDF path emits is safe by
/// construction. A non-RDF resource's type comes from the client and reaches
/// two interpolation sites — a SPARQL literal and a response header — so it
/// needs a constructor that can refuse.
///
/// RFC 9110 §5.6.2: `token "/" token`, optionally followed by `; token=token`
/// parameters. Every byte of the trimmed input is checked against tchar plus
/// `/`, `;`, `=`, and space before the `type/subtype` shape is parsed, so the
/// stored string can never contain a byte outside that alphabet — not even
/// one sitting at a boundary a structural parse would trim away first.
/// Quoted-string parameter values are refused rather than escaped: the
/// alphabet contains neither `"` nor `\`, so a value that passes here cannot
/// leave the SPARQL literal it is interpolated into, and that safety is a
/// property of the alphabet the stored string is drawn from, not of a
/// correct escape at every site. The cost is that `multipart/...;
/// boundary="--x"` is rejected, which is acceptable because multipart is a
/// request encoding rather than a stored representation.
///
/// Carries its `http::HeaderValue` alongside the raw string, both built by
/// the one constructor. `#[derive(PartialEq, Eq)]` compares both fields
/// rather than `raw` alone, which is fine: the two are always built together
/// by `parse`, so they never disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType {
    raw: String,
    header: http::HeaderValue,
}

/// RFC 9110 §5.6.2 tchar.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
                | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

fn is_token(t: &str) -> bool {
    !t.is_empty() && t.bytes().all(is_tchar)
}

/// tchar plus the `/`, `;`, `=`, and space bytes the grammar uses to
/// delimit tokens from one another.
fn is_media_type_byte(b: u8) -> bool {
    is_tchar(b) || matches!(b, b'/' | b';' | b'=' | b' ')
}

impl MediaType {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        // Every byte of the input must be in the media-type alphabet before
        // it is parsed structurally. This is what makes the alphabet claim
        // literally true: the structural parse below trims each segment
        // before validating it, so a stray whitespace or control byte sitting
        // right at a `;` or `=` boundary would otherwise be trimmed away
        // before `is_token` ever sees it, yet still survive into the stored
        // string. Neither check subsumes the other — this one catches a rogue
        // byte hiding at a trimmed boundary, the structural parse below
        // catches a malformed `type/subtype` or a valueless parameter.
        if !s.bytes().all(is_media_type_byte) {
            return None;
        }
        let mut parts = s.split(';');
        let (ty, sub) = parts.next()?.trim().split_once('/')?;
        if !is_token(ty) || !is_token(sub) {
            return None;
        }
        for p in parts {
            let (name, value) = p.trim().split_once('=')?;
            if !is_token(name) || !is_token(value) {
                return None;
            }
        }
        let header = http::HeaderValue::from_str(s).ok()?;
        Some(Self { raw: s.to_owned(), header })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The `Content-Type` header for this media type. Infallible: the value
    /// was built and checked by the only constructor, so no call site has to
    /// assert it.
    pub fn header_value(&self) -> http::HeaderValue {
        self.header.clone()
    }

    /// `type/subtype`, lowercased, parameters dropped — what an `Accept`
    /// comparison is made against, since media-type tokens are
    /// case-insensitive (RFC 9110 §8.3.1) but parameter values need not be.
    pub fn essence(&self) -> String {
        media_type(&self.raw).to_ascii_lowercase()
    }
}

impl From<Format> for MediaType {
    fn from(f: Format) -> Self {
        MediaType::parse(f.media_type())
            .expect("a Format's media type is a valid media type")
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
    /// serialization, exactly as [`Skolemized::etag`](crate::dataset::Skolemized::etag)
    /// sorts before hashing — one canonical order for both, so two states
    /// that share a validator serialize identically. Repeatability alone is
    /// not enough: oxigraph returns `CONSTRUCT` results in insertion order.
    pub fn serialize(&self, dataset: &Dataset) -> Result<Vec<u8>, RdfError> {
        // Sorted for the same reason Skolemized::etag sorts: oxigraph
        // returns CONSTRUCT results in insertion order, so without this two
        // states that share a validator serialize differently.
        let mut quads: Vec<_> = dataset.quads().to_vec();
        quads.sort_by_key(|q| q.to_string());
        let mut ser = RdfSerializer::from_format(self.0).for_writer(Vec::new());
        for q in &quads {
            ser.serialize_quad(q).map_err(|e| RdfError::Serialize(e.to_string()))?;
        }
        ser.finish().map_err(|e| RdfError::Serialize(e.to_string()))
    }
}

/// The `Accept` list, highest quality first with earlier entries breaking a
/// tie, as `(q, position, media range)`.
///
/// **The only place this header is parsed.** [`negotiate`] and
/// [`accept_allows`] ask different questions of it — which format to render
/// into, and whether one fixed type is admissible — but a second copy of the
/// q-value parse is how the two come to disagree about `q=0`.
fn ranked_accept(accept: &str) -> Vec<(f32, usize, &str)> {
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
    ranked.sort_by(|a, b| {
        b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1))
    });
    ranked
}

/// §6.1: whether `accept` admits a resource whose only representation is `mt`.
///
/// Not negotiation — there is nothing to choose between. RFC 9110 §12.5.1
/// makes a more specific media range override a less specific one, so the
/// decision is by specificity rather than by order or by the highest q.
pub(crate) fn accept_allows(accept: &str, mt: &MediaType) -> bool {
    let accept = accept.trim();
    if accept.is_empty() {
        return true;
    }
    let essence = mt.essence();
    let ty = essence.split('/').next().unwrap_or("");
    let type_wildcard = format!("{ty}/*");
    let mut best: Option<(u8, f32)> = None;
    for (q, _, range) in ranked_accept(accept) {
        let range = range.to_ascii_lowercase();
        let specificity = if range == essence {
            3
        } else if range == type_wildcard {
            2
        } else if range == "*/*" {
            1
        } else {
            continue;
        };
        if best.is_none_or(|(s, _)| specificity > s) {
            best = Some((specificity, q));
        }
    }
    matches!(best, Some((_, q)) if q > 0.0)
}

/// §6.3: select the highest-ranked acceptable media range the server can
/// serve, over the whole `Accept` list with q-values, rather than the first
/// recognised entry — which would answer `text/turtle, application/ld+json`
/// with the lossy one.
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

    let ranked = ranked_accept(accept);

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

#[cfg(test)]
mod tests {
    use super::*;
    use oxigraph::model::{GraphName, Literal, NamedNode, Quad};

    // Not superseded by the JSON-LD-named-graph tests below: this pins that
    // a plain, default-graph dataset still round-trips through both formats.
    #[test]
    fn turtle_to_jsonld_roundtrip_preserves_triples() {
        let turtle = Format::from_content_type("text/turtle").unwrap();
        let jsonld = Format::from_content_type("application/ld+json").unwrap();
        let ds = Dataset::new(vec![Quad::new(
            NamedNode::new("https://pod.toph.so/foo#it").unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("Toph"),
            GraphName::DefaultGraph,
        )]);

        let ttl = turtle.serialize(&ds).unwrap();
        let via_ttl = turtle.parse(&ttl, "https://pod.toph.so/foo").unwrap();
        let jsonld_bytes = jsonld.serialize(&via_ttl).unwrap();
        let via_json = jsonld.parse(&jsonld_bytes, "https://pod.toph.so/foo").unwrap();

        assert_eq!(via_json.quads().len(), 1);
        assert_eq!(via_json.quads()[0].predicate.as_str(), "http://schema.org/name");
        assert!(String::from_utf8_lossy(&jsonld_bytes).contains("schema.org/name"));
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

    #[test]
    fn media_type_accepts_what_rfc_9110_calls_a_media_type() {
        assert_eq!(MediaType::parse("text/plain").unwrap().as_str(), "text/plain");
        assert_eq!(
            MediaType::parse("text/plain; charset=utf-8").unwrap().as_str(),
            "text/plain; charset=utf-8",
            "a token parameter is kept verbatim — it is what the client declared"
        );
        assert_eq!(MediaType::parse("  image/png  ").unwrap().as_str(), "image/png");
        // Tokens are case-insensitive, so comparison uses the lowercased
        // essence while the stored form keeps the client's spelling.
        assert_eq!(MediaType::parse("Image/PNG").unwrap().essence(), "image/png");
        assert_eq!(
            MediaType::parse("text/plain; charset=utf-8").unwrap().essence(),
            "text/plain",
            "essence drops parameters"
        );
    }

    // The reason this type exists. The stored form is interpolated into a
    // `"`-delimited SPARQL literal, so a value that cannot contain `"` or `\`
    // is safe by its alphabet rather than by a correct escape at every site.
    // RFC 9110 §5.6.2's tchar set contains neither, so refusing everything
    // outside it is the whole defence.
    #[test]
    fn media_type_refuses_anything_that_could_leave_a_sparql_literal() {
        for bad in [
            r#"text/plain; boundary="x""#,   // quoted-string parameter
            r#"text/plain"; x="#,            // a bare quote
            r"text/plain\",                  // a backslash
            "text/plain\u{7f}",              // DEL, a CTL
            "text/plain\nX-Evil: 1",         // LF, if it ever reached us
            "textplain",                     // no slash
            "/plain",                        // empty type
            "text/",                         // empty subtype
            "",                              // nothing at all
            "text/plain; charset",           // parameter with no value
            "text/plain;\ncharset=utf8",     // LF hiding at a segment boundary
            "text/plain;\rcharset=utf8",     // CR hiding at a segment boundary
            "text/plain;\tcharset=utf8",     // tab hiding at a segment boundary
            "text/plain; charset =\tutf8",   // whitespace straddling `=`
        ] {
            assert!(MediaType::parse(bad).is_none(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn every_format_is_also_a_media_type() {
        let ttl = Format::from_content_type("text/turtle").unwrap();
        assert_eq!(MediaType::from(ttl).as_str(), "text/turtle");
    }

    // A MediaType that parsed is a header value that exists. No call site
    // should have to assert that with an `.expect`.
    #[test]
    fn a_media_type_carries_its_header_value() {
        let mt = MediaType::parse("text/plain; charset=utf-8").unwrap();
        assert_eq!(mt.header_value().to_str().unwrap(), "text/plain; charset=utf-8");
        assert_eq!(mt.header_value().to_str().unwrap(), mt.as_str());
    }

    // §6.1: a blob has one representation, so this is an acceptability test
    // and not a resolver. The cases are the ones `negotiate` already handles,
    // which is precisely why they must not be answered by a second parse.
    #[test]
    fn accept_allows_admits_or_refuses_a_single_representation() {
        let png = MediaType::parse("image/png").unwrap();
        let txt = MediaType::parse("text/plain; charset=utf-8").unwrap();

        assert!(accept_allows("", &png), "no Accept header means no constraint");
        assert!(accept_allows("*/*", &png));
        assert!(accept_allows("image/*", &png));
        assert!(accept_allows("image/png", &png));
        assert!(accept_allows("Image/PNG", &png), "ranges are case-insensitive");
        assert!(accept_allows("text/turtle, image/png;q=0.1", &png));
        // Parameters do not take part in the match; the essence does.
        assert!(accept_allows("text/plain", &txt));

        assert!(!accept_allows("text/turtle", &png));
        assert!(!accept_allows("text/*", &png));
    }

    // RFC 9110 §12.5.1: q=0 is a refusal, and a more specific media range
    // overrides a less specific one — so the answer cannot be derived from
    // order or from the highest q alone.
    #[test]
    fn accept_allows_honours_q_zero_and_specificity() {
        let png = MediaType::parse("image/png").unwrap();

        assert!(!accept_allows("image/png;q=0", &png));
        assert!(!accept_allows("*/*, image/png;q=0", &png), "specific overrides */*");
        assert!(!accept_allows("image/png;q=0, */*", &png), "and order does not matter");
        assert!(accept_allows("*/*;q=0, image/png", &png), "and it works the other way");
        assert!(!accept_allows("image/*;q=0, */*", &png), "type/* overrides */*");
    }
}
