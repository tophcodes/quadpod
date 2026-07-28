# Dataset-Valued Resources (Full JSON-LD) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A resource may be an RDF dataset — a JSON-LD document with named graphs round-trips through the pod instead of being silently flattened.

**Architecture:** A resource's default graph stays in the store graph named by its IRI, exactly as today. Each inner named graph goes to a server-minted shelf (`urn:quadpod:subgraph:<sha256>`), with a registry in the existing system graph mapping shelf → original name. Blank nodes are skolemized on write so the store holds no blank node at all, which is what makes the ETag and co-reference work. Auxiliaries and containers keep their existing graph-shaped paths.

**Tech Stack:** Rust, axum 0.8, oxigraph 0.5.9 (oxrdf 0.3.3), sha2, uuid v4, tokio.

**Spec:** `docs/superpowers/specs/2026-07-28-jsonld-datasets-design.md` (revision 3). Section references below (§4, §6.2 …) point there. Read §12 first: three earlier revisions were wrong in ways that look reasonable, and the table says which.

**Skeleton:** `src/dataset.rs`, `src/shelf.rs`, and the new items in `src/rdf.rs` / `src/resource.rs` already exist as signatures with `todo!("skeleton")` bodies (commits `c7522e8`, `3577a8c`).

> **The signatures in the skeleton are given. Tasks fill bodies only. No new public functions, no new modules.** If a task seems to need one, that is a finding — stop and report it rather than adding it.

## Global Constraints

- Build and test only through `nix develop -c cargo …`. Bare `cargo` fails on libclang.
- `nix develop -c cargo clippy --all-targets` must be clean, and **no `#[allow]` attributes in `src/`** at the end of the plan. The skeleton's `#[allow(unused_variables, dead_code)]` markers come off as each body lands; Task 10 pins that with a constraint.
- `nix develop -c cargo build 2>&1 | grep -i warning` must print nothing.
- `arch-check` must stay at `0/8 rot` after every task.
- Every test must fail against a mutant. If a test passes with the implementation deliberately broken, the test is wrong — fix the test before the code.
- Commit after every task. Conventional commits, no verbose bodies.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/dataset.rs` | `Dataset` / `Skolemized`, skolemization, the reserved-namespace check, the ETag | fill bodies |
| `src/shelf.rs` | shelf key derivation and the registry vocabulary | fill body |
| `src/rdf.rs` | `Format` (what each media type can do), parse, serialize, negotiation | fill bodies; old `parse`/`serialize`/`etag` stay until Task 9 |
| `src/resource.rs` | the dataset write/read/delete paths and the registry queries | fill bodies |
| `src/http.rs` | wiring: negotiation order, headers, the new refusals | modify handlers |
| `src/container.rs`, `src/aux.rs` | callers of `serialize_for_insert` | adapt to `Skolemized` in Task 8 |

---

### Task 1: `Format` — which media types this pod supports, and what each can do

**Files:**
- Modify: `src/rdf.rs` (fill `Format::from_content_type`, `media_type`, `carries_dataset`)
- Test: `src/rdf.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: nothing.
- Produces: `rdf::Format` with `from_content_type(&str) -> Option<Format>`, `media_type(&self) -> &'static str`, `carries_dataset(&self) -> bool`. `Format` is `Copy + PartialEq`.

- [ ] **Step 1: Write the failing test**

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c cargo test --lib format_knows_which`
Expected: panic at `todo!("skeleton")`.

- [ ] **Step 3: Write minimal implementation**

```rust
impl Format {
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

    pub fn carries_dataset(&self) -> bool {
        self.0.supports_datasets()
    }
}
```

Note `carries_dataset` delegates to oxigraph rather than re-listing the formats: the property being asked about is exactly the one its serializer enforces, and a second list is a second thing to get wrong.

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib rdf::`
Expected: all pass, including the pre-existing `content_type_mapping` tests.

- [ ] **Step 5: Commit**

```bash
git add src/rdf.rs
git commit -m "feat: Format knows which media types carry a dataset"
```

---

### Task 2: parse and serialize a dataset, deterministically

**Files:**
- Modify: `src/rdf.rs` (fill `Format::parse`, `Format::serialize`)
- Test: `src/rdf.rs` tests

**Interfaces:**
- Consumes: `Format` (Task 1), `dataset::Dataset::{new, quads}`.
- Produces: `Format::parse(&self, bytes: &[u8], base_iri: &str) -> Result<Dataset, RdfError>`, `Format::serialize(&self, dataset: &Dataset) -> Result<Vec<u8>, RdfError>`.

- [ ] **Step 1: Write the failing tests**

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib "rdf::tests::parse_keeps or rdf::tests::serialization_is"`
Expected: both panic at `todo!("skeleton")`.

- [ ] **Step 3: Write minimal implementation**

```rust
impl Format {
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib rdf::`
Expected: all pass.

- [ ] **Step 5: Verify the canonical-order test bites**

Temporarily delete the two `sort_by_key` lines and re-run `serialization_is_canonical_not_merely_repeatable`. Expected: FAIL for at least TriG and N-Quads. Restore the sort.

- [ ] **Step 6: Commit**

```bash
git add src/rdf.rs
git commit -m "feat: parse and serialize datasets, in canonical order"
```

---

### Task 3: what a `Dataset` can answer about itself

**Files:**
- Modify: `src/dataset.rs` (fill `named_graphs`, `uses_reserved_namespace`, `default_graph_only`)
- Test: new `#[cfg(test)] mod tests` in `src/dataset.rs`

**Interfaces:**
- Consumes: `Dataset::{new, quads}`.
- Produces: `named_graphs(&self) -> Vec<NamedNode>`, `has_named_graphs(&self) -> bool` (already written in terms of `named_graphs`), `uses_reserved_namespace(&self) -> bool`, `default_graph_only(&self) -> Dataset`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use oxigraph::model::{BlankNode, Literal, NamedNode, Quad};

    fn q(s: &str, o: &str, g: oxigraph::model::GraphName) -> Quad {
        Quad::new(
            NamedNode::new(s).unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal(o),
            g,
        )
    }

    #[test]
    fn named_graphs_are_listed_once_and_the_default_graph_is_not_one() {
        let g1 = NamedNode::new("http://example.org/g1").unwrap();
        let ds = Dataset::new(vec![
            q("http://example.org/a", "A", g1.clone().into()),
            q("http://example.org/b", "B", g1.into()),
            q("http://example.org/c", "C", oxigraph::model::GraphName::DefaultGraph),
        ]);
        assert_eq!(ds.named_graphs().len(), 1, "two quads, one graph name");
        assert!(ds.has_named_graphs());
        assert_eq!(ds.default_graph_only().quads().len(), 1);
    }

    // §3.2.2. RFC 8141 makes the URN scheme and NID case-insensitive, so a
    // literal prefix comparison lets `URN:QUADPOD:` through — and a document that
    // gets through here comes back with its IRI rewritten into a blank node.
    #[test]
    fn the_reserved_namespace_is_refused_in_any_position_and_any_case() {
        let reserved = "urn:quadpod:bnode:1234";
        let subject = Dataset::new(vec![q(reserved, "x", oxigraph::model::GraphName::DefaultGraph)]);
        assert!(subject.uses_reserved_namespace(), "as a subject");

        let object = Dataset::new(vec![Quad::new(
            NamedNode::new("http://example.org/a").unwrap(),
            NamedNode::new("http://schema.org/name").unwrap(),
            NamedNode::new(reserved).unwrap(),
            oxigraph::model::GraphName::DefaultGraph,
        )]);
        assert!(object.uses_reserved_namespace(), "as an object");

        let graph = Dataset::new(vec![q(
            "http://example.org/a", "x",
            NamedNode::new("URN:QUADPOD:subgraph:dead").unwrap().into())]);
        assert!(graph.uses_reserved_namespace(), "as a graph name, upper-case");

        let clean = Dataset::new(vec![q(
            "http://example.org/a", "x",
            NamedNode::new("urn:podcast:1").unwrap().into())]);
        assert!(!clean.uses_reserved_namespace(), "a longer NID is a different namespace");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib dataset::`
Expected: both panic at `todo!("skeleton")`.

- [ ] **Step 3: Write minimal implementation**

```rust
impl Dataset {
    pub fn named_graphs(&self) -> Vec<NamedNode> {
        let mut seen: Vec<NamedNode> = Vec::new();
        for q in &self.0 {
            if let oxigraph::model::GraphName::NamedNode(n) = &q.graph_name {
                if !seen.contains(n) {
                    seen.push(n.clone());
                }
            }
        }
        seen
    }

    pub fn uses_reserved_namespace(&self) -> bool {
        fn reserved(iri: &str) -> bool {
            // `urn:quadpod:` — scheme and NID are case-insensitive (RFC 8141), the
            // rest of the NSS is not, and only the prefix is ours.
            iri.len() > RESERVED_PREFIX.len()
                && iri[..RESERVED_PREFIX.len()].eq_ignore_ascii_case(RESERVED_PREFIX)
        }
        self.0.iter().any(|q| {
            let subject = match &q.subject {
                oxigraph::model::NamedOrBlankNode::NamedNode(n) => reserved(n.as_str()),
                _ => false,
            };
            let object = match &q.object {
                oxigraph::model::Term::NamedNode(n) => reserved(n.as_str()),
                _ => false,
            };
            let graph = match &q.graph_name {
                oxigraph::model::GraphName::NamedNode(n) => reserved(n.as_str()),
                _ => false,
            };
            subject || object || graph || reserved(q.predicate.as_str())
        })
    }

    pub fn default_graph_only(&self) -> Dataset {
        Dataset::new(
            self.0.iter()
                .filter(|q| q.graph_name == oxigraph::model::GraphName::DefaultGraph)
                .cloned()
                .collect(),
        )
    }
}
```

Remove the `#[allow]` markers from the three functions you just filled.

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib dataset::`
Expected: PASS. Then `nix develop -c cargo clippy --all-targets` — clean.

- [ ] **Step 5: Commit**

```bash
git add src/dataset.rs
git commit -m "feat: dataset shape queries and the reserved-namespace refusal"
```

---

### Task 4: skolemization

**Files:**
- Modify: `src/dataset.rs` (fill `Skolemized::{skolemize, ground, deskolemize}`)
- Test: `src/dataset.rs` tests

**Interfaces:**
- Consumes: `Dataset`.
- Produces: `Skolemized::skolemize(&Dataset) -> Skolemized`, `Skolemized::ground(Vec<Quad>) -> Option<Skolemized>`, `Skolemized::deskolemize(&self) -> Dataset`, `Skolemized::quads(&self) -> &[Quad]`.

**Background:** §4. Blank nodes become `urn:quadpod:bnode:<uuid>` IRIs — one IRI per distinct blank node *within one document*, used in every position that node occupied. On the way back, one blank node per distinct skolem IRI, **labelled from the IRI** rather than freshly generated (§6.4 needs byte-identical reads).

- [ ] **Step 1: Write the failing tests**

```rust
    // The case revision 2 got wrong: a blank node that is both a graph name and
    // a term. This is the Verifiable Credentials `proof` shape, and
    // solid/specification#291 says a server may not modify those graph names.
    #[test]
    fn a_blank_node_that_is_both_graph_name_and_term_keeps_its_identity() {
        let b = BlankNode::default();
        let ds = Dataset::new(vec![
            // <top> :points _:b
            Quad::new(
                NamedNode::new("http://example.org/top").unwrap(),
                NamedNode::new("http://example.org/points").unwrap(),
                b.clone(),
                oxigraph::model::GraphName::DefaultGraph,
            ),
            // GRAPH _:b { <s> :name "inside" }
            q("http://example.org/s", "inside", b.clone().into()),
        ]);

        let stored = Skolemized::skolemize(&ds);
        assert!(
            stored.quads().iter().all(|q| !matches!(
                q.graph_name, oxigraph::model::GraphName::BlankNode(_))),
            "no blank node reaches the store, not even as a graph name"
        );

        let back = stored.deskolemize();
        let graph_node = back.quads().iter()
            .find_map(|q| match &q.graph_name {
                oxigraph::model::GraphName::BlankNode(n) => Some(n.clone()),
                _ => None,
            })
            .expect("the named graph came back blank");
        let object_node = back.quads().iter()
            .find_map(|q| match &q.object {
                oxigraph::model::Term::BlankNode(n) => Some(n.clone()),
                _ => None,
            })
            .expect("the object came back blank");
        assert_eq!(graph_node, object_node, "co-reference survived the round trip");
    }

    #[test]
    fn deskolemization_is_stable_across_reads() {
        let b = BlankNode::default();
        let stored = Skolemized::skolemize(&Dataset::new(vec![q(
            "http://example.org/s", "x", b.into())]));
        assert_eq!(stored.deskolemize(), stored.deskolemize(),
            "a fresh label per read would break the byte-identical guarantee");
    }

    #[test]
    fn ground_refuses_content_that_still_has_a_blank_node() {
        let ok = vec![q("http://example.org/s", "x", oxigraph::model::GraphName::DefaultGraph)];
        assert!(Skolemized::ground(ok).is_some());

        let not_ok = vec![Quad::new(
            BlankNode::default(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("x"),
            oxigraph::model::GraphName::DefaultGraph,
        )];
        assert!(Skolemized::ground(not_ok).is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib dataset::tests::a_blank_node`
Expected: panic at `todo!("skeleton")`.

- [ ] **Step 3: Write minimal implementation**

```rust
/// The skolem namespace. Only this module writes or matches it — see
/// `docs/constraints.md`.
const SKOLEM_PREFIX: &str = "urn:quadpod:bnode:";

impl Skolemized {
    pub fn skolemize(dataset: &Dataset) -> Self {
        use oxigraph::model::{GraphName, NamedOrBlankNode, Term};
        let mut minted: std::collections::HashMap<String, NamedNode> = std::collections::HashMap::new();
        let mut iri_for = |b: &oxigraph::model::BlankNode| -> NamedNode {
            minted.entry(b.as_str().to_owned())
                .or_insert_with(|| {
                    NamedNode::new(format!("{SKOLEM_PREFIX}{}", uuid::Uuid::new_v4()))
                        .expect("a uuid is IRI-safe")
                })
                .clone()
        };
        let quads = dataset.quads().iter().map(|q| {
            let subject = match &q.subject {
                NamedOrBlankNode::BlankNode(b) => NamedOrBlankNode::NamedNode(iri_for(b)),
                other => other.clone(),
            };
            let object = match &q.object {
                Term::BlankNode(b) => Term::NamedNode(iri_for(b)),
                other => other.clone(),
            };
            let graph_name = match &q.graph_name {
                GraphName::BlankNode(b) => GraphName::NamedNode(iri_for(b)),
                other => other.clone(),
            };
            Quad { subject, predicate: q.predicate.clone(), object, graph_name }
        }).collect();
        Self(quads)
    }

    pub fn ground(quads: Vec<Quad>) -> Option<Self> {
        use oxigraph::model::{GraphName, NamedOrBlankNode, Term};
        let blank = quads.iter().any(|q| {
            matches!(q.subject, NamedOrBlankNode::BlankNode(_))
                || matches!(q.object, Term::BlankNode(_))
                || matches!(q.graph_name, GraphName::BlankNode(_))
        });
        (!blank).then_some(Self(quads))
    }

    pub fn deskolemize(&self) -> Dataset {
        use oxigraph::model::{BlankNode, GraphName, NamedOrBlankNode, Term};
        // The label is derived from the IRI, not generated: two reads of one
        // stored state must produce identical bytes (§6.4).
        fn blank_for(n: &NamedNode) -> Option<BlankNode> {
            let suffix = n.as_str().strip_prefix(SKOLEM_PREFIX)?;
            let label: String = suffix.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            BlankNode::new(format!("b{label}")).ok()
        }
        let quads = self.0.iter().map(|q| {
            let subject = match &q.subject {
                NamedOrBlankNode::NamedNode(n) => match blank_for(n) {
                    Some(b) => NamedOrBlankNode::BlankNode(b),
                    None => q.subject.clone(),
                },
                other => other.clone(),
            };
            let object = match &q.object {
                Term::NamedNode(n) => match blank_for(n) {
                    Some(b) => Term::BlankNode(b),
                    None => q.object.clone(),
                },
                other => other.clone(),
            };
            let graph_name = match &q.graph_name {
                GraphName::NamedNode(n) => match blank_for(n) {
                    Some(b) => GraphName::BlankNode(b),
                    None => q.graph_name.clone(),
                },
                other => other.clone(),
            };
            Quad { subject, predicate: q.predicate.clone(), object, graph_name }
        }).collect();
        Dataset::new(quads)
    }
}
```

Remove the `#[allow]` markers from the three functions.

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib dataset::`
Expected: PASS.

- [ ] **Step 5: Verify the co-reference test bites**

Temporarily change `skolemize` to mint a fresh IRI per *occurrence* (move the `or_insert_with` out of the map so every call generates one). Re-run: `a_blank_node_that_is_both_graph_name_and_term_keeps_its_identity` must FAIL. Restore.

- [ ] **Step 6: Commit**

```bash
git add src/dataset.rs
git commit -m "feat: skolemize blank nodes on the way in, restore them on the way out"
```

---

### Task 5: the shelf key

**Files:**
- Modify: `src/shelf.rs` (fill `ShelfKey::of`)
- Test: new `#[cfg(test)] mod tests` in `src/shelf.rs`

**Interfaces:**
- Consumes: `space::{ResourceUrl, StorageSpace, Target}`.
- Produces: `ShelfKey::of(&ResourceUrl, NamedNodeRef) -> ShelfKey`, `ShelfKey::graph_iri(&self) -> &str`, `ShelfKey::from_registry(&str) -> ShelfKey`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::{StorageSpace, Target};
    use oxigraph::model::NamedNode;

    fn res(path: &str) -> ResourceUrl {
        match StorageSpace::new("https://pod.toph.so/").unwrap().resolve(path).unwrap() {
            Target::Resource(r) => r,
            other => panic!("{path} is not a resource: {other:?}"),
        }
    }

    #[test]
    fn the_key_separates_pairs_a_printable_separator_would_merge() {
        // The collision a `:` separator admits: the resource IRI may contain a
        // colon in a path segment, and every absolute IRI has one after its
        // scheme, so `<resource>:<graph>` cannot be split back apart.
        let a = ShelfKey::of(&res("/a"), NamedNode::new("urn:x:b").unwrap().as_ref());
        let b = ShelfKey::of(&res("/a:urn"), NamedNode::new("x:b").unwrap().as_ref());
        assert_ne!(a.graph_iri(), b.graph_iri());

        // Same graph name, two resources — the case §2.1 exists for.
        let g = NamedNode::new("urn:example:g1").unwrap();
        assert_ne!(
            ShelfKey::of(&res("/one"), g.as_ref()).graph_iri(),
            ShelfKey::of(&res("/two"), g.as_ref()).graph_iri(),
        );

        // Two names in one resource.
        assert_ne!(
            ShelfKey::of(&res("/one"), NamedNode::new("urn:example:g1").unwrap().as_ref()).graph_iri(),
            ShelfKey::of(&res("/one"), NamedNode::new("urn:example:g2").unwrap().as_ref()).graph_iri(),
        );

        // Deterministic, and shaped as the spec says.
        let k = ShelfKey::of(&res("/one"), g.as_ref());
        assert_eq!(k.graph_iri(), ShelfKey::of(&res("/one"), g.as_ref()).graph_iri());
        let hex = k.graph_iri().strip_prefix("urn:quadpod:subgraph:").expect("prefix");
        assert_eq!(hex.len(), 64, "full sha256, lowercase hex");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c cargo test --lib shelf::`
Expected: panic at `todo!("skeleton")`.

- [ ] **Step 3: Write minimal implementation**

```rust
use sha2::{Digest, Sha256};

impl ShelfKey {
    pub fn of(resource: &ResourceUrl, graph_name: NamedNodeRef<'_>) -> Self {
        // 0x00 as the separator because RFC 3987 excludes control characters
        // from IRIs: it cannot occur in either part, so one pair can never be
        // read back as a different pair.
        let mut h = Sha256::new();
        h.update(resource.graph_iri().as_bytes());
        h.update([0x00]);
        h.update(graph_name.as_str().as_bytes());
        Self(format!("urn:quadpod:subgraph:{}", hex::encode(h.finalize())))
    }
}
```

`ResourceUrl::graph_iri` comes from the `GraphName` trait, so `use crate::space::GraphName;` is needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop -c cargo test --lib shelf::`
Expected: PASS. Then `arch-check` — still `0/8 rot`.

- [ ] **Step 5: Commit**

```bash
git add src/shelf.rs
git commit -m "feat: derive the shelf key from the resource and the graph name"
```

---

### Task 6: the ETag, and negotiation

**Files:**
- Modify: `src/dataset.rs` (fill `Skolemized::etag`), `src/rdf.rs` (fill `negotiate`)
- Test: `src/dataset.rs` tests, `src/rdf.rs` tests

**Interfaces:**
- Consumes: `Format`, `Shape`, `Skolemized`.
- Produces: `Skolemized::etag(&self, Format) -> String`, `rdf::negotiate(&str, Shape, Option<Format>) -> Option<Format>` (crate-visible).

- [ ] **Step 1: Write the failing tests**

In `src/dataset.rs`:

```rust
    #[test]
    fn the_etag_covers_graph_names_and_the_selected_format() {
        let jsonld = Format::from_content_type("application/ld+json").unwrap();
        let trig = Format::from_content_type("application/trig").unwrap();
        let g1 = NamedNode::new("http://example.org/g1").unwrap();
        let g2 = NamedNode::new("http://example.org/g2").unwrap();

        let in_g1 = Skolemized::ground(vec![q("http://example.org/s", "x", g1.into())]).unwrap();
        let in_g2 = Skolemized::ground(vec![q("http://example.org/s", "x", g2.into())]).unwrap();

        assert_ne!(in_g1.etag(jsonld), in_g2.etag(jsonld),
            "same triple, different graph — a shared validator would serve the wrong one");
        assert_ne!(in_g1.etag(jsonld), in_g1.etag(trig),
            "different representations are different entities (RFC 9110 §8.8.1)");
        assert_eq!(in_g1.etag(jsonld), in_g1.etag(jsonld), "stable between reads");
    }
```

In `src/rdf.rs`:

```rust
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
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib "the_etag_covers or negotiation_prefers"`
Expected: both panic at `todo!("skeleton")`.

- [ ] **Step 3: Write minimal implementation**

`Skolemized::etag`:

```rust
    pub fn etag(&self, fmt: Format) -> String {
        let mut lines: Vec<String> = self.0.iter().map(|q| q.to_string()).collect();
        lines.sort();
        let mut h = Sha256::new();
        h.update(fmt.media_type().as_bytes());
        h.update(b"\n");
        for l in &lines {
            h.update(l.as_bytes());
            h.update(b"\n");
        }
        format!("\"{}\"", hex::encode(h.finalize()))
    }
```

`rdf::negotiate`:

```rust
pub(crate) fn negotiate(accept: &str, shape: Shape, stored: Option<Format>) -> Option<Format> {
    let usable = |f: Format| shape == Shape::Graph || f.carries_dataset();
    let fallback = || {
        [ "application/ld+json", "text/turtle" ].iter()
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

    for (_, _, mt) in ranked {
        let candidate = match mt {
            "*/*" => stored.filter(|f| usable(*f)).or_else(fallback),
            "text/*" => Format::from_content_type("text/turtle").filter(|f| usable(*f)),
            "application/*" => fallback(),
            other => Format::from_content_type(other).filter(|f| usable(*f)),
        };
        if candidate.is_some() {
            return candidate;
        }
    }
    None
}
```

Remove the `#[allow]` markers from both.

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/dataset.rs src/rdf.rs
git commit -m "feat: dataset-aware ETag and capability-aware negotiation"
```

---

### Task 7: the storage paths

**Files:**
- Modify: `src/resource.rs` (fill `put_dataset`, `get_dataset`, `delete_dataset`, `stored_media_type`, `registered_shelves`)
- Test: `src/resource.rs` tests

**Interfaces:**
- Consumes: `Skolemized`, `ShelfKey`, `Format`, `SparqlStore`, `sys_graph_iri`, `SYS_PRESENT`.
- Produces: the five functions as declared in the skeleton.

**Background:** §5, §5.1, §7. The write is a registry read followed by **one** update; the drops must be literal `DROP SILENT GRAPH <iri>` statements, both for the shelves the registry lists *and* for the keys about to be written (§3.2 invariant 4). A `DELETE WHERE` empties a graph without removing it — the leak the review measured.

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn a_dataset_round_trips_through_the_store() {
        let store = OxigraphStore::in_memory().unwrap();
        let r = res("/c/notes");
        let jsonld = crate::rdf::Format::from_content_type("application/ld+json").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let ds = Skolemized::ground(vec![
            oxigraph::model::Quad::new(
                oxigraph::model::NamedNode::new("https://pod.toph.so/c/notes#it").unwrap(),
                oxigraph::model::NamedNode::new("http://schema.org/name").unwrap(),
                oxigraph::model::Literal::new_simple_literal("Toph"),
                oxigraph::model::GraphName::DefaultGraph),
            oxigraph::model::Quad::new(
                oxigraph::model::NamedNode::new("http://example.org/alice").unwrap(),
                oxigraph::model::NamedNode::new("http://schema.org/name").unwrap(),
                oxigraph::model::Literal::new_simple_literal("Alice"),
                g.clone()),
        ]).unwrap();

        put_dataset(&store, &r, &ds, jsonld).await.unwrap();

        let back = get_dataset(&store, &r).await.unwrap().expect("present");
        assert_eq!(back.quads().len(), 2);
        assert!(back.quads().iter().any(|q| q.graph_name == g.clone().into()),
            "the graph name came back");
        assert_eq!(stored_media_type(&store, &r).await.unwrap(), Some(jsonld));
    }

    // §3.2 invariant 4: a shelf the registry no longer lists is not litter, it
    // is content the next write to the same (resource, graph name) pair would
    // INSERT INTO — so the resource would return triples nobody wrote.
    #[tokio::test]
    async fn a_replacing_write_leaves_no_shelf_behind() {
        let store = OxigraphStore::in_memory().unwrap();
        let r = res("/c/notes");
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let with_graph = Skolemized::ground(vec![oxigraph::model::Quad::new(
            oxigraph::model::NamedNode::new("http://example.org/alice").unwrap(),
            oxigraph::model::NamedNode::new("http://schema.org/name").unwrap(),
            oxigraph::model::Literal::new_simple_literal("Alice"),
            g.clone())]).unwrap();

        put_dataset(&store, &r, &with_graph, ttl).await.unwrap();
        assert_eq!(registered_shelves(&store, &r).await.unwrap().len(), 1);

        // Replace with a document that has no named graph at all.
        put_dataset(&store, &r, &Skolemized::ground(vec![]).unwrap(), ttl).await.unwrap();
        assert!(registered_shelves(&store, &r).await.unwrap().is_empty());

        // And the shelf is gone, not merely emptied: write the same graph name
        // again and it must not inherit the old triples.
        put_dataset(&store, &r, &with_graph, ttl).await.unwrap();
        let back = get_dataset(&store, &r).await.unwrap().unwrap();
        assert_eq!(back.quads().len(), 1, "no resurrected content");
    }

    #[tokio::test]
    async fn delete_removes_the_shelves_too() {
        let store = OxigraphStore::in_memory().unwrap();
        let r = res("/c/notes");
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let ds = Skolemized::ground(vec![oxigraph::model::Quad::new(
            oxigraph::model::NamedNode::new("http://example.org/alice").unwrap(),
            oxigraph::model::NamedNode::new("http://schema.org/name").unwrap(),
            oxigraph::model::Literal::new_simple_literal("Alice"),
            g)]).unwrap();

        put_dataset(&store, &r, &ds, ttl).await.unwrap();
        assert!(delete_dataset(&store, &r).await.unwrap(), "existed");
        assert!(get_dataset(&store, &r).await.unwrap().is_none());
        assert!(registered_shelves(&store, &r).await.unwrap().is_empty());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib resource::tests::a_dataset_round_trips`
Expected: panic at `todo!("skeleton")`.

- [ ] **Step 3: Write minimal implementation**

```rust
use crate::shelf::{SYS_GRAPH_NAME, SYS_HAS_SUBGRAPH, SYS_MEDIA_TYPE};

pub async fn registered_shelves(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Vec<ShelfKey>, ResourceError> {
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let triples = store.query_triples(&format!(
        "CONSTRUCT {{ <{iri}> <{SYS_HAS_SUBGRAPH}> ?g }} \
         WHERE {{ GRAPH <{sys}> {{ <{iri}> <{SYS_HAS_SUBGRAPH}> ?g }} }}"
    )).await?;
    Ok(triples.iter().filter_map(|t| match &t.object {
        oxigraph::model::Term::NamedNode(n) => Some(ShelfKey::from_registry(n.as_str())),
        _ => None,
    }).collect())
}

pub async fn put_dataset(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
    dataset: &Skolemized,
    media_type: Format,
) -> Result<(), ResourceError> {
    use oxigraph::model::GraphName;
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);

    // Split by graph name; the key is minted only here, from the pair.
    let mut default_graph: Vec<Triple> = Vec::new();
    let mut shelves: Vec<(ShelfKey, String, Vec<Triple>)> = Vec::new();
    for q in dataset.quads() {
        let t = Triple { subject: q.subject.clone(), predicate: q.predicate.clone(), object: q.object.clone() };
        match &q.graph_name {
            GraphName::DefaultGraph => default_graph.push(t),
            GraphName::NamedNode(n) => {
                let key = ShelfKey::of(r, n.as_ref());
                match shelves.iter_mut().find(|(k, _, _)| k == &key) {
                    Some((_, _, ts)) => ts.push(t),
                    None => shelves.push((key, n.as_str().to_owned(), vec![t])),
                }
            }
            // Unreachable: Skolemized carries no blank node (§4).
            GraphName::BlankNode(_) => return Err(ResourceError::InvalidIri),
        }
    }

    // Both drops (§3.2 invariant 4): what the registry lists, and what we are
    // about to write. Literal IRIs — DROP takes no variable, and DELETE WHERE
    // empties a graph without removing it.
    let mut update = String::new();
    for key in registered_shelves(store, r).await? {
        update.push_str(&format!("DROP SILENT GRAPH <{}>; ", key.graph_iri()));
    }
    for (key, _, _) in &shelves {
        update.push_str(&format!("DROP SILENT GRAPH <{}>; ", key.graph_iri()));
    }
    update.push_str(&format!("DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>; "));

    // One INSERT DATA: blank nodes cannot be shared across operations, and
    // although Skolemized has none today, splitting would make that a latent
    // trap for the first caller who changes it.
    update.push_str("INSERT DATA { ");
    update.push_str(&format!("GRAPH <{iri}> {{ {} }} ", serialize_for_insert(&default_graph)));
    for (key, _, ts) in &shelves {
        update.push_str(&format!("GRAPH <{}> {{ {} }} ", key.graph_iri(), serialize_for_insert(ts)));
    }
    update.push_str("}; ");

    let mut registry = format!(
        "<{iri}> <{SYS_PRESENT}> true . <{iri}> <{SYS_MEDIA_TYPE}> \"{}\" . ",
        media_type.media_type()
    );
    for (key, name, _) in &shelves {
        registry.push_str(&format!(
            "<{iri}> <{SYS_HAS_SUBGRAPH}> <{k}> . <{k}> <{SYS_GRAPH_NAME}> <{name}> . ",
            k = key.graph_iri()
        ));
    }
    update.push_str(&format!("INSERT DATA {{ GRAPH <{sys}> {{ {registry} }} }}"));

    store.update(&update).await?;
    Ok(())
}
```

And the three readers:

```rust
pub async fn get_dataset(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Option<Skolemized>, ResourceError> {
    use oxigraph::model::{GraphName, NamedNode, Quad};
    if !exists(store, r).await? {
        return Ok(None);
    }
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);

    let mut quads: Vec<Quad> = store
        .query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{iri}> {{ ?s ?p ?o }} }}"
        ))
        .await?
        .into_iter()
        .map(|t| Quad::new(t.subject, t.predicate, t.object, GraphName::DefaultGraph))
        .collect();

    // One CONSTRUCT per shelf: query_triples has no graph field, so a single
    // query cannot recover which shelf a triple came from. The graph name comes
    // from the registry, not from the key — the key is not reversible.
    for key in registered_shelves(store, r).await? {
        let k = key.graph_iri();
        let names = store.query_triples(&format!(
            "CONSTRUCT {{ <{k}> <{SYS_GRAPH_NAME}> ?n }} \
             WHERE {{ GRAPH <{sys}> {{ <{k}> <{SYS_GRAPH_NAME}> ?n }} }}"
        )).await?;
        let Some(name) = names.iter().find_map(|t| match &t.object {
            oxigraph::model::Term::NamedNode(n) => NamedNode::new(n.as_str()).ok(),
            _ => None,
        }) else {
            // A shelf with no name is the invariant of §3.2.3 broken; refusing
            // is better than serving content under a name we invented.
            return Err(ResourceError::InvalidIri);
        };
        for t in store.query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{k}> {{ ?s ?p ?o }} }}"
        )).await? {
            quads.push(Quad::new(t.subject, t.predicate, t.object, name.clone()));
        }
    }

    Ok(Some(Skolemized::ground(quads).expect("the store holds no blank node")))
}

pub async fn delete_dataset(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<bool, ResourceError> {
    let existed = exists(store, r).await?;
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let mut update = String::new();
    for key in registered_shelves(store, r).await? {
        update.push_str(&format!("DROP SILENT GRAPH <{}>; ", key.graph_iri()));
    }
    update.push_str(&format!("DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>"));
    store.update(&update).await?;
    Ok(existed)
}

pub async fn stored_media_type(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Option<Format>, ResourceError> {
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let triples = store.query_triples(&format!(
        "CONSTRUCT {{ <{iri}> <{SYS_MEDIA_TYPE}> ?m }} \
         WHERE {{ GRAPH <{sys}> {{ <{iri}> <{SYS_MEDIA_TYPE}> ?m }} }}"
    )).await?;
    Ok(triples.iter().find_map(|t| match &t.object {
        oxigraph::model::Term::Literal(l) => Format::from_content_type(l.value()),
        _ => None,
    }))
}
```

Note `delete_dataset` reads the registry before dropping it — the ordering `aux::delete_subject` gets wrong today, where the system graph goes first and takes the only record of the shelves with it (§7).

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib resource::`
Expected: PASS.

- [ ] **Step 5: Verify the orphan test bites**

Temporarily drop only the registry-listed shelves (delete the second loop). Re-run `a_replacing_write_leaves_no_shelf_behind` — it must still pass. Then instead delete the *first* loop (registry-driven) and re-run: it must FAIL, because the graph that vanished from the document is no longer dropped. Restore both.

- [ ] **Step 6: Commit**

```bash
git add src/resource.rs
git commit -m "feat: dataset write, read and delete paths with the shelf registry"
```

---

### Task 8: `serialize_for_insert` becomes the choke point

**Files:**
- Modify: `src/resource.rs` (`serialize_for_insert` signature), `src/container.rs`, `src/aux.rs`, `src/wac/provision.rs` (callers)
- Test: `src/resource.rs` tests

**Interfaces:**
- Consumes: `Skolemized::ground`.
- Produces: `pub(crate) fn serialize_for_insert(quads: &Skolemized) -> String` — every write path renders through it, so the "no blank node in the store" invariant is enforced in one place instead of asserted globally (§4).

- [ ] **Step 1: Write the failing test**

```rust
    // §4: the invariant was asserted globally and enforced in two handlers.
    // Three other writers pass arbitrary triples, and it held only because
    // provision_root_acl happens to write <#owner> rather than [] a
    // acl:Authorization.
    #[test]
    fn server_built_content_goes_through_the_ground_constructor() {
        use oxigraph::model::{BlankNode, Literal, NamedNode, Quad, GraphName};
        let blank = vec![Quad::new(
            BlankNode::default(),
            NamedNode::new("http://schema.org/name").unwrap(),
            Literal::new_simple_literal("x"),
            GraphName::DefaultGraph)];
        assert!(Skolemized::ground(blank).is_none(),
            "a writer cannot smuggle a blank node past the constructor");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c cargo test --lib server_built_content`
Expected: FAIL — `ground` is `todo!()` if Task 4 is not yet merged; otherwise this passes and the real change is Step 3's signature migration, which the compiler drives.

- [ ] **Step 3: Change the signature and follow the compiler**

Change `serialize_for_insert(triples: &[Triple])` to take `&Skolemized`, and at each call site wrap the server-built triples:

```rust
// container.rs, in ensure_container / add_containment:
let quads: Vec<Quad> = triples.iter().map(|t| Quad::new(
    t.subject.clone(), t.predicate.clone(), t.object.clone(),
    oxigraph::model::GraphName::DefaultGraph)).collect();
let ground = Skolemized::ground(quads).expect("server-built container triples are ground");
```

`put_rdf` and `insert_marked` keep their `&[Triple]` parameters and do the wrapping internally, so their callers do not change.

- [ ] **Step 4: Run the full suite**

Run: `nix develop -c cargo test`
Expected: all pass. `nix develop -c cargo clippy --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add src/resource.rs src/container.rs src/aux.rs src/wac/provision.rs
git commit -m "refactor: enforce the no-blank-node invariant at serialize_for_insert"
```

---

### Task 9: wire the HTTP layer

**Files:**
- Modify: `src/http.rs` (`put_impl`, `post_impl`, `get_impl`)
- Test: `src/http.rs` tests

**Interfaces:**
- Consumes: everything above.
- Produces: no new public functions.

**Background:** §5 (check order), §6 (read order), §6.2, §6.2.1, §6.3.

Read order (§6.1) is normative: read the whole dataset → negotiate → ETag → de-skolemize and serialize. Write order (§5) is: parse → cheap refusals → skolemize → split → registry read → one update.

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn a_jsonld_dataset_round_trips_over_http() {
        let f = fixture().await;
        let body = r#"{"@context":{"name":"http://schema.org/name"},
          "@graph":[{"@id":"urn:example:g1","@graph":[{"@id":"http://example.org/alice","name":"Alice"}]},
                    {"@id":"http://example.org/bob","name":"Bob"}]}"#;
        let put = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body_string(res).await.contains("urn:example:g1"), "the graph name survived");
    }

    #[tokio::test]
    async fn turtle_gets_the_default_graph_and_is_told_what_it_is_missing() {
        let f = fixture().await;
        let body = r#"{"@graph":[{"@id":"urn:example:g1",
          "@graph":[{"@id":"http://example.org/alice","http://schema.org/name":"Alice"}]}]}"#;
        let put = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap();
        f.app.clone().oneshot(put).await.unwrap();

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let res = f.app.clone().oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "§6.2: not a 406");
        assert_eq!(res.headers().get(header::VARY).unwrap(), "Accept");
        let links: Vec<_> = res.headers().get_all(header::LINK).iter()
            .map(|v| v.to_str().unwrap().to_owned()).collect();
        assert!(links.iter().any(|l| l.contains("containsGraph") && l.contains("urn:example:g1")),
            "the client learns which graphs it did not get: {links:?}");
        assert!(links.iter().any(|l| l.contains("alternate") && l.contains("application/trig")));
    }

    // §6.2.1: GET as Turtle, edit, PUT back would otherwise destroy every named
    // graph with a 2xx and no warning.
    #[tokio::test]
    async fn a_graph_format_write_over_named_graphs_is_refused() {
        let f = fixture().await;
        let body = r#"{"@graph":[{"@id":"urn:example:g1",
          "@graph":[{"@id":"http://example.org/alice","http://schema.org/name":"Alice"}]}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let overwrite = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(overwrite).await.unwrap().status(), StatusCode::CONFLICT);

        // and nothing changed
        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap();
        assert!(body_string(f.app.clone().oneshot(get).await.unwrap()).await.contains("urn:example:g1"));
    }

    #[tokio::test]
    async fn the_reserved_namespace_and_container_datasets_are_refused() {
        let f = fixture().await;
        let reserved = f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<urn:quadpod:bnode:x> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(f.app.clone().oneshot(reserved).await.unwrap().status(), StatusCode::BAD_REQUEST);

        let container = f.owner_request("PUT", "/box/")
            .header(header::CONTENT_TYPE, "application/trig")
            .body(Body::from("<urn:example:g1> { <http://example.org/a> <http://schema.org/name> \"x\" }")).unwrap();
        assert_eq!(f.app.oneshot(container).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib http::tests::a_jsonld_dataset`
Expected: FAIL — the graph name is dropped today.

- [ ] **Step 3: Rewrite the checks in `put_impl`**

Replacing the current `parse` + containment block, in this order (§5 step 2: the cheap
refusals come before anything expensive, and both `put_impl` and `post_impl` need them):

```rust
    let Some(fmt) = Format::from_content_type(header_str(&headers, header::CONTENT_TYPE)) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let dataset = match fmt.parse(&body, target.graph_iri()) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // §3.2.2 — the skolem namespace is the server's.
    if dataset.uses_reserved_namespace() {
        return (StatusCode::BAD_REQUEST, "the urn:quadpod: namespace is reserved").into_response();
    }
    // §3.4 — a container's graph carries containment; an auxiliary's rules
    // would be invisible to WAC inside a subgraph.
    if dataset.has_named_graphs() && !matches!(target, Target::Resource(_)) {
        return (StatusCode::BAD_REQUEST, "named graphs are only allowed on resources").into_response();
    }
    // Over the whole dataset, not the default graph: otherwise the 409 is
    // bypassed by putting ldp:contains in a named graph.
    if matches!(target, Target::Container(_)) && container::body_sets_containment(dataset.quads()) {
        return StatusCode::CONFLICT.into_response();
    }
    // §6.2.1 — a graph-format write must not silently discard what a graph
    // format could not have shown the client in the first place.
    if let Target::Resource(r) = &target {
        if !fmt.carries_dataset() {
            if let Ok(Some(existing)) = get_dataset(store, r).await {
                let names = existing.deskolemize().named_graphs();
                if !names.is_empty() {
                    let list = names.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(", ");
                    return (StatusCode::CONFLICT, format!(
                        "this resource has named graphs ({list}) that {} cannot carry; \
                         write it as application/trig or application/ld+json, or DELETE it first",
                        fmt.media_type()
                    )).into_response();
                }
            }
        }
    }
```

Then the write itself: `Skolemized::skolemize(&dataset)` → the existing `If-Match`/`If-None-Match`
block → `authorize_and_materialize` → `put_dataset(store, r, &stored, fmt)` for a
`Target::Resource`. `Target::Container` and `Target::Aux` keep `put_rdf` / `aux::put`,
fed `dataset.default_graph_only().quads()` mapped to triples — they have no named graphs by
the check above.

- [ ] **Step 4: Rewrite `get_impl`'s body**

```rust
    if let Err(res) = authorize(store, &agent, &target, Mode::Read).await {
        return with_aux_links(res, &target);
    }
    let Target::Resource(r) = &target else {
        return legacy_graph_read(st, agent, target, headers).await; // containers, auxiliaries
    };
    // §6.1: read everything first — the ETag covers the resource, not the body.
    let stored = match get_dataset(store, r).await {
        Ok(Some(d)) => d,
        Ok(None) => return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Err(ResourceError::InvalidIri) => return StatusCode::BAD_REQUEST.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let visible = stored.deskolemize();
    let shape = if visible.has_named_graphs() { Shape::Dataset } else { Shape::Graph };
    let stored_type = stored_media_type(store, r).await.ok().flatten();
    let Some(fmt) = rdf::negotiate(header_str(&headers, header::ACCEPT), shape, stored_type) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    let tag = stored.etag(fmt);
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
        return with_allow(with_aux_links(
            (StatusCode::NOT_MODIFIED, [(header::ETAG, tag)]).into_response(), &target), &target);
    }
    // §6.2: a graph format gets the default graph, and is told what it missed.
    let served = if fmt.carries_dataset() { visible.clone() } else { visible.default_graph_only() };
    let bytes = match fmt.serialize(&served) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut out = HeaderMap::new();
    out.insert(header::CONTENT_TYPE, fmt.media_type().parse().expect("static media type"));
    out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
    out.insert(header::VARY, "Accept".parse().expect("static"));
    if !fmt.carries_dataset() {
        for name in visible.named_graphs() {
            out.append(header::LINK, format!(
                "<{}>; rel=\"https://quadpod.toph.so/ns#containsGraph\"", name.as_str()
            ).parse().expect("graph name is header-safe"));
        }
        for alt in ["application/trig", "application/ld+json"] {
            out.append(header::LINK, format!(
                "<{}>; rel=\"alternate\"; type=\"{alt}\"", r.graph_iri()
            ).parse().expect("static"));
        }
    }
    with_allow(with_aux_links((out, bytes).into_response(), &target), &target)
```

`with_aux_links` inserts its own `Link`, so it must use `append` rather than `insert` after
this change — check it, or the `containsGraph` links are silently dropped.

`legacy_graph_read` is not a new function: it is the existing `get_rdf`-based body, kept for
containers and auxiliaries. Move it into the `else` arm rather than extracting it, so no new
public surface appears.

**It must de-skolemize before serializing.** Containers and auxiliaries take raw client bodies,
so `put_rdf` and `aux::put` skolemize on the way in — an ACL may legitimately contain `[]`.
Without the matching step on the way out, `GET /.aux/notes.acl` returns
`<urn:quadpod:bnode:…>` where the client wrote a blank node. The design spec §4 states this
directly: de-skolemization belongs where the shared path serializes, not inside a
resource-shaped branch.

Concretely: wrap the triples from `get_rdf` as default-graph quads, put them through
`Skolemized::ground(…)` (they come from the store, so they are ground by construction),
`deskolemize()`, and serialize with `Format::serialize`. This also retires
`rdf::serialize` for these callers ahead of Task 11.

- [ ] **Step 4b: Pin the auxiliary round trip**

```rust
    // Containers and auxiliaries are skolemized on the way in like everything
    // else; without the matching step out, a client's blank node comes back as
    // an IRI it never wrote.
    #[tokio::test]
    async fn an_acl_containing_a_blank_node_round_trips_as_a_blank_node() {
        let f = fixture().await;
        let acl = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                   [] a acl:Authorization ; acl:mode acl:Read ; \
                      acl:agentClass <http://xmlns.com/foaf/0.1/Agent> ; \
                      acl:accessTo </c/notes> .";
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap()).await.unwrap();
        let put = f.owner_request("PUT", "/.aux/c/notes.acl")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(acl)).unwrap();
        assert_eq!(f.app.clone().oneshot(put).await.unwrap().status(), StatusCode::CREATED);

        let get = f.owner_request("GET", "/.aux/c/notes.acl")
            .header(header::ACCEPT, "text/turtle").body(Body::empty()).unwrap();
        let out = body_string(f.app.oneshot(get).await.unwrap()).await;
        assert!(!out.contains("urn:quadpod:bnode"),
            "the server's internal IRI must not reach a client: {out}");
        assert!(out.contains("acl:Authorization") || out.contains("auth/acl#Authorization"),
            "and the rule itself survived: {out}");
    }
```

- [ ] **Step 5: Run the full suite**

Run: `nix develop -c cargo test`
Expected: all pass, including the 296 pre-existing tests. Any pre-existing test that now fails is a finding — report it rather than editing the test.

- [ ] **Step 6: Commit**

```bash
git add src/http.rs
git commit -m "feat: serve and accept dataset-valued resources over HTTP"
```

---

### Task 10: the documented limits, and the two graph-naming cases

**Files:**
- Test only: `src/http.rs` tests

**Background:** §9 and §10. A documented limit gets a test *with an assertion that can fail* —
the isomorphism oracle passes vacuously on the empty-named-graph case (zero quads on both
sides), which is exactly the "test that holds trivially" failure this project has shipped
before.

- [ ] **Step 1: Write the tests**

```rust
    // §9.5. Folding this into the default graph would be a document rewrite —
    // a statement in a named graph is not asserted in the default graph — and
    // it is the obvious accidental implementation of the split.
    #[tokio::test]
    async fn a_graph_named_like_its_own_resource_stays_a_named_graph() {
        let f = fixture().await;
        let body = r#"{"@graph":[
            {"@id":"https://pod.toph.so/c/notes",
             "@graph":[{"@id":"http://example.org/a","http://schema.org/name":"inside"}]},
            {"@id":"http://example.org/b","http://schema.org/name":"outside"}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let get = f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap();
        let out = body_string(f.app.clone().oneshot(get).await.unwrap()).await;
        assert!(out.contains("\"inside\" <https://pod.toph.so/c/notes>"),
            "still in its named graph, not merged into the default one: {out}");
        assert!(out.lines().any(|l| l.contains("\"outside\"") && l.trim_end().ends_with("\" .")),
            "and the default-graph statement is still in the default graph: {out}");
    }

    // §9.6 / §2.1. Eleven characters of relative IRI name another resource's
    // URL. Under store-global graph names this write would land in /victim
    // with no ACL check anywhere in the path.
    #[tokio::test]
    async fn naming_another_resources_url_as_a_graph_touches_nothing() {
        let f = fixture().await;
        f.app.clone().oneshot(f.owner_request("PUT", "/victim")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"mine\" .")).unwrap()).await.unwrap();

        let before = body_string(f.app.clone().oneshot(f.owner_request("GET", "/victim")
            .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap())
            .await.unwrap()).await;

        let attack = r#"{"@graph":[{"@id":"../victim",
            "@graph":[{"@id":"http://example.org/x","http://schema.org/name":"theirs"}]}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/attacker/doc")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(attack)).unwrap()).await.unwrap();

        let after = body_string(f.app.clone().oneshot(f.owner_request("GET", "/victim")
            .header(header::ACCEPT, "application/n-quads").body(Body::empty()).unwrap())
            .await.unwrap()).await;
        assert_eq!(before, after, "/victim changed by a write to /attacker/doc");
        assert!(!after.contains("theirs"));
    }

    // §9.1: an empty named graph produces no quads, so it cannot survive. The
    // isomorphism oracle passes vacuously here — this needs a direct assertion
    // on the response instead, or the limit stops being a decision and becomes
    // a surprise.
    #[tokio::test]
    async fn an_empty_named_graph_is_documented_as_lost() {
        let f = fixture().await;
        let body = r#"{"@graph":[{"@id":"urn:example:empty","@graph":[]},
            {"@id":"http://example.org/b","http://schema.org/name":"kept"}]}"#;
        f.app.clone().oneshot(f.owner_request("PUT", "/c/notes")
            .header(header::CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body)).unwrap()).await.unwrap();

        let out = body_string(f.app.clone().oneshot(f.owner_request("GET", "/c/notes")
            .header(header::ACCEPT, "application/trig").body(Body::empty()).unwrap())
            .await.unwrap()).await;
        assert!(out.contains("kept"));
        assert!(!out.contains("urn:example:empty"),
            "documented limit (§9.1): a graph with no quads does not round-trip");
    }
```

- [ ] **Step 2: Run them**

Run: `nix develop -c cargo test --lib "a_graph_named_like or naming_another or an_empty_named"`
Expected: PASS, given Tasks 1–9. If `a_graph_named_like_its_own_resource_stays_a_named_graph`
fails, the split in `put_dataset` has a special case for the resource's own IRI — remove the
special case, not the test.

- [ ] **Step 3: Verify the first two bite**

Add a special case to `put_dataset` that routes a graph named like the resource into the
default graph. `a_graph_named_like_its_own_resource_stays_a_named_graph` must FAIL. Remove it.

Then change `ShelfKey::of` to hash only the graph name, dropping the resource IRI.
`naming_another_resources_url_as_a_graph_touches_nothing` must FAIL. Restore.

- [ ] **Step 4: Commit**

```bash
git add src/http.rs
git commit -m "test: pin the documented limits and the two graph-naming cases"
```

---

### Task 11: conformance, cleanup, and the last constraint

**Files:**
- Modify: `docs/conformance-findings.md`, `docs/constraints.md`, `.superpowers/sdd/progress.md`
- Remove: every remaining `#[allow]` in `src/`

- [ ] **Step 1: Delete the superseded paths**

There must be one negotiation, one parser, one serializer, one ETag. After Task 9 the crate
has two of each, and "a second derivation of a truth that already has an authority" is the
defect class this project has hit most often — it is why `docs/constraints.md` exists.

Delete `rdf::format_for_content_type`, `rdf::format_for_accept`, `rdf::parse`,
`rdf::serialize` and `rdf::etag`. The container and auxiliary paths that still call them move
to `Format::parse` / `Format::serialize` with a dataset that has no named graphs (the §3.4
check guarantees that), and to `Skolemized::etag`. `tests/route_coverage.rs` calls
`sparql_pod::rdf::parse` and moves with them.

Expected: the compiler lists every call site. If one cannot move, that is a finding — report
it rather than keeping the old function alive for it.

- [ ] **Step 2: Remove the skeleton markers and the process artefacts in comments**

Two sweeps, both mechanical.

`rg -n '#\[allow' src` — every hit should now be a filled body. Delete the attribute and its
comment. Re-run `nix develop -c cargo clippy --all-targets`; if a warning appears, fix the code
rather than restoring the attribute.

Then `rg -n 'skeleton|Task [0-9]|revision [0-9]|Plan [0-9]|the plan' src` — a doc comment states
the contract in the present tense and never how the code came to be. Process artefacts (task
numbers, plan filenames, revision numbers, "what the review found") are the journal-comment
antipattern: they rot on the next edit and mean nothing to a reader who never saw the change.
Reword them into present facts, or delete them where the fact is already obvious. A pointer to
a durable document — a spec section, an issue number — stays.

Known hits at the time of writing: `src/rdf.rs` (the `negotiate` marker's comment),
`src/dataset.rs` (module header, and three comments citing revisions). `src/config.rs:163` and
`src/http.rs:332` predate this plan; reword them too if you are touching that region, otherwise
leave them.

Run: `rg -n '#\[allow' src` — every hit should now be a filled body. Delete the attribute and its `// skeleton:` comment. Re-run `nix develop -c cargo clippy --all-targets`; if a warning appears, fix the code rather than restoring the attribute.

- [ ] **Step 3: Adopt the constraints that keep both out**

Append to `docs/constraints.md`:

```
There is one content-negotiation path, one parser and one ETag.
    → 2026-07-28-jsonld-datasets-design.md §6.3, §6.1. `Format` and
    `negotiate` replaced `format_for_content_type` / `format_for_accept` /
    `rdf::parse` / `rdf::serialize` / `rdf::etag`. Two of each is how the
    Turtle path and the dataset path drift apart, and drift here is silent:
    both answer, one answers wrong.
    check: ! rg -q 'fn (format_for_accept|format_for_content_type)\b' src
```

and

```
No `#[allow]` attributes in `src/`.
    → Plan 6 Task 1 recorded this as a global constraint, and it was
    load-bearing once already: it forced a plan-mandated `Result<String, ()>`
    (which trips `clippy::result_unit_err`) to become a named error type. The
    dataset skeleton suspended it deliberately, with `// skeleton:` comments;
    this rule is what removes them.
    check: ! rg -q '#\[allow' src
```

Run `arch-check` — expected `0/10 rot`.

- [ ] **Step 4: Run the conformance suite**

Run: `conformance/run.sh` (see `conformance/README.md`; needs the harness image and a local CSS).
Expected: `content-negotiation-named-graphs:16` passes. Compare the totals against the recorded 41 features / 652 scenarios / 37 passed. **A drop anywhere is a finding**, not a number to update.

- [ ] **Step 5: Update the findings document**

In `docs/conformance-findings.md`, move D3 out of the defect bucket with the new scenario count, and re-check the bucket sums — they are stated as summing to 615, and the sum is the point.

- [ ] **Step 6: Record it in progress.md**

Append a Plan 9 section: what landed, what the reviews found across three revisions, and the two open follow-ups (per-subgraph URLs; `OPTIONS`/`Accept-Put` so TriG is discoverable).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: dataset-valued resources pass content-negotiation-named-graphs"
```

---

## Verification Summary

```bash
nix develop -c cargo test                      # 296 + new, all green
nix develop -c cargo clippy --all-targets      # clean
nix develop -c cargo build 2>&1 | grep -i warning   # prints nothing
arch-check                                     # 0/10 rot
rg -n '#\[allow' src                           # no hits
```

## What this plan does not do

- Non-RDF resources. 540 of the 615 conformance failures, its own plan, and the decision it must make is already recorded (spec §11): RDF stays triples-first, bytes get a second path.
- Per-subgraph URLs, `OPTIONS`, `Accept-Put`/`Accept-Post`. All three are projections of the dataset outward and should be designed together, not bolted on one at a time.
- `PATCH`. Skolemization needs a rule for what a patch means against a skolemized store (§4).
