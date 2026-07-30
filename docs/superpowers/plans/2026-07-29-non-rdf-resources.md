# Non-RDF Resources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store and serve non-RDF resources as bytes in a swappable `BlobStore`, so the 540 conformance scenarios blocked by one `415` become runnable and the ~370 unmeasured WAC access-mode rows can finally be evaluated.

**Architecture:** A resource is RDF or binary, decided by `Content-Type` on write. RDF keeps the existing triples-first path untouched. Binary bytes go to a `BlobStore` at a key that mirrors the URL path, with three triples in `urn:quadpod:sys:<iri>` — presence, kind, media type — and nothing about the bytes themselves. Both kinds are `ResourceUrl`s, so WAC, containment, ancestor materialization and auxiliary URLs apply unchanged.

**Tech Stack:** Rust 1.97 stable, axum 0.8, oxigraph 0.5, `object_store` 0.14 (`InMemory` + `LocalFileSystem`), `sha2`, `async-trait`, `thiserror`, `clap`.

**Spec:** `docs/superpowers/specs/2026-07-29-non-rdf-resources-design.md` (revision 2). Section references below (§3.1, §5.1, …) point into it.

## Global Constraints

- **No `#[allow]` attributes anywhere in `src/`.** A clippy lint is fixed, never suppressed. Verified by `arch-check`.
- **`nix develop -c cargo clippy --all-targets` must be clean** at every commit, and `nix develop -c cargo build` must print no warnings.
- **`arch-check` must be 0 rot** at every commit. Two new rules land in this plan (Task 10).
- **Every test must be demonstrated to fail before its implementation exists.** `docs/constraints.md`: *"A check that cannot fail is worse than no check: this project has already shipped a test that asked for its property in a form where it held trivially."* Where a test could pass for the wrong reason, the plan says so and says what to do about it.
- **No journal comments.** Doc comments state the present contract. No "moved from", "used to be", "Task 6", plan filenames, or commit SHAs in source. Rationale that reads as history gets reworded, not deleted.
- **Conventional commits**, concise subject, body only where the *why* is not obvious.
- Run every cargo command through `nix develop -c`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/blob.rs` | `BlobKey` (the only place an object key is built), the `BlobStore` trait and its `object_store` implementation | **new** |
| `src/rdf.rs` | `MediaType`, `sparql::Literal`'s one caller, `ranked_accept` (the only `Accept` parser), later `accept_allows` alongside `negotiate` | modify |
| `src/resource.rs` | `put_blob`, `kind_of`, `stored_media_type` returning `MediaType`, blob teardown inside `put_dataset` | modify |
| `src/aux.rs` | blob teardown inside the one delete cascade | modify |
| `src/config.rs` | `--blob-store`, `--max-body-bytes` | modify |
| `src/http.rs` | three-way `Content-Type` gate, blob read path, `current_tags` blob branch, body limit layer | modify |
| `src/lib.rs` | register `blob` | modify |
| `src/main.rs` | build the `BlobStore` from config | modify |
| `docs/constraints.md` | two new rules | modify |
| `docs/uri-space.md` | the normative sentence §14 contradicts | modify |
| `docs/conformance-findings.md` | third run, `content-type-reject` reclassified | modify |

---

### Task 1: `MediaType`

A validating newtype for a media type the pod will store and echo. Today `Format::media_type()` returns `&'static str`, so every `Content-Type` the pod emits is safe by construction; a blob's type comes from the client and reaches both a SPARQL literal and a response header.

**Files:**
- Modify: `src/rdf.rs` (add above `Format`)
- Test: `src/rdf.rs` `mod tests`

**Interfaces:**
- Produces: `pub struct MediaType`; `MediaType::parse(&str) -> Option<MediaType>`; `MediaType::as_str(&self) -> &str`; `MediaType::essence(&self) -> String`; `impl From<Format> for MediaType`.

- [ ] **Step 1: Write the failing tests**

Add to `src/rdf.rs`'s `mod tests`:

```rust
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
        ] {
            assert!(MediaType::parse(bad).is_none(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn every_format_is_also_a_media_type() {
        let ttl = Format::from_content_type("text/turtle").unwrap();
        assert_eq!(MediaType::from(ttl).as_str(), "text/turtle");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib rdf::tests::media_type 2>&1 | tail -20`
Expected: FAIL — `cannot find type MediaType in this scope`.

- [ ] **Step 3: Write minimal implementation**

Insert into `src/rdf.rs`, immediately after the `media_type` helper function near the top:

```rust
/// A media type this pod stores and echoes back.
///
/// [`Format`] answers "can I parse this as RDF?" and its `media_type` is a
/// `&'static str`, so every `Content-Type` the RDF path emits is safe by
/// construction. A non-RDF resource's type comes from the client and reaches
/// two interpolation sites — a SPARQL literal and a response header — so it
/// needs a constructor that can refuse.
///
/// RFC 9110 §5.6.2: `token "/" token`, optionally followed by `; token=token`
/// parameters. Quoted-string parameter values are refused rather than escaped:
/// the tchar set contains neither `"` nor `\`, so a value that passes here
/// cannot leave the SPARQL literal it is interpolated into, and that safety is
/// a property of the alphabet rather than of a correct escape at every site.
/// The cost is that `multipart/...; boundary="--x"` is rejected, which is
/// acceptable because multipart is a request encoding rather than a stored
/// representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType(String);

/// RFC 9110 §5.6.2 tchar.
fn is_token(t: &str) -> bool {
    !t.is_empty()
        && t.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
                        | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
}

impl MediaType {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
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
        Some(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `type/subtype`, lowercased, parameters dropped — what an `Accept`
    /// comparison is made against, since media-type tokens are
    /// case-insensitive (RFC 9110 §8.3.1) but parameter values need not be.
    pub fn essence(&self) -> String {
        media_type(&self.0).to_ascii_lowercase()
    }
}

impl From<Format> for MediaType {
    fn from(f: Format) -> Self {
        Self(f.media_type().to_owned())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib rdf::tests 2>&1 | tail -5`
Expected: PASS, and every pre-existing `rdf::tests` test still passes.

- [ ] **Step 5: Verify the refusal test bites**

Temporarily change `parse` to `Some(Self(s.trim().to_owned()))` as its whole body. Run
`nix develop -c cargo test --lib rdf::tests::media_type_refuses`. Expected: FAIL on the first
entry. Revert.

This step exists because a validator that accepts everything is the exact mutant the test
must catch, and nothing else in the suite would notice it.

- [ ] **Step 6: Commit**

```bash
git add src/rdf.rs
git commit -m "feat: a validating MediaType newtype

A blob's Content-Type comes from the client and is interpolated into a
SPARQL literal. Restricting it to RFC 9110 §5.6.2 tchars makes the stored
form incapable of containing a quote or a backslash, so the safety is a
property of the alphabet rather than of an escape at every call site."
```

---

### Task 1b: make an unescaped SPARQL literal and an unsafe header value unrepresentable

Inserted after Task 1, before Task 2. Two small newtypes closing two classes of "a raw string
reaches a place where its alphabet matters", so later tasks cannot reopen them.

**Files:**
- Create: `src/sparql.rs`
- Modify: `src/rdf.rs` (`MediaType`), `src/resource.rs:126-136` (`put_dataset`'s registry
  string), `src/lib.rs`, `docs/constraints.md`
- Test: `src/sparql.rs` `mod tests`, `src/rdf.rs` `mod tests`

**Interfaces:**
- Produces: `pub struct sparql::Literal` with `sparql::Literal::new(&oxigraph::model::Literal)
  -> Literal` and `impl std::fmt::Display`; `MediaType::header_value(&self) ->
  http::HeaderValue` (infallible).

## Why, before what

Scoping check run before writing this task: `rg -n '\\"\{' src` finds **exactly one**
quote-delimited SPARQL literal interpolation in the whole codebase — `src/resource.rs:134`,
the media type. Every other SPARQL interpolation is `<{iri}>`, where the IRI comes from the
sealed `space::GraphName` trait (a constraint already guards that), from `shelf::ShelfKey`, or
is validated through `NamedNode::new` at `src/resource.rs:144`. Literals inside user data go
through oxrdf's `Display` in `serialize_for_insert`, which is the escaper this project already
trusts.

So this task builds a newtype for one call site today and one more that Task 4 adds — and
**deliberately builds nothing else**. A general "SPARQL fragment" layer would be machinery for
two callers, which this project's own rules forbid. What makes the rule stick is not the type
but the constraint check in step 6: a type does not stop anyone writing
`format!("\"{}\"", s)`, and the check does.

The second half is smaller and has a named victim: the plan's Task 8 contains
`mt.as_str().parse().expect("a MediaType is header-safe")` — a `.expect` asserting an
invariant that a *different* type is supposed to guarantee. If `MediaType` carries the
`HeaderValue` it validated, that `.expect` has nothing to assert and disappears.

## Step 1: Write the failing tests

Create `src/sparql.rs` with only this test module (implementation comes in step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use oxigraph::model::Literal as OxLiteral;

    // The escaping is oxrdf's, not ours — this pins that we render through it
    // rather than beside it. A second escaper is how two write paths come to
    // disagree about one backslash.
    #[test]
    fn a_literal_renders_quoted_and_escaped() {
        assert_eq!(Literal::new(&OxLiteral::new_simple_literal("plain")).to_string(), "\"plain\"");

        for raw in ["has \" quote", "has \\ backslash", "has \n newline", "has \r return"] {
            let rendered = Literal::new(&OxLiteral::new_simple_literal(raw)).to_string();
            let inner = &rendered[1..rendered.len() - 1];
            assert!(
                !inner.contains('"') || inner.contains("\\\""),
                "{raw:?} rendered as {rendered:?}: a bare quote would close the literal"
            );
            assert!(!inner.contains('\n') && !inner.contains('\r'),
                "{raw:?} rendered as {rendered:?}: a raw newline is not legal in STRING_LITERAL2");
        }
    }

    // The whole point: what comes out can be concatenated into an update and
    // still parse. Asserted by round-tripping through the store, not by
    // eyeballing the string — a rendering that merely *looks* escaped but is
    // not would pass a string comparison against a hand-written expectation.
    #[tokio::test]
    async fn a_rendered_literal_survives_an_actual_insert() {
        use crate::store::{OxigraphStore, SparqlStore};
        let store = OxigraphStore::in_memory().unwrap();
        let nasty = "x\" . } DROP ALL ; INSERT DATA { GRAPH <urn:evil> { <urn:a> <urn:b> \"pwned";
        let lit = Literal::new(&OxLiteral::new_simple_literal(nasty));

        store.update(&format!(
            "INSERT DATA {{ GRAPH <urn:test:g> {{ <urn:test:s> <urn:test:p> {lit} }} }}"
        )).await.unwrap();

        let back = store.query_triples(
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <urn:test:g> { ?s ?p ?o } }"
        ).await.unwrap();
        assert_eq!(back.len(), 1);
        assert!(
            matches!(&back[0].object, oxigraph::model::Term::Literal(l) if l.value() == nasty),
            "the value must come back exactly, not truncated at the quote"
        );
        // The injected DROP ALL must not have run.
        assert!(store.ask("ASK { GRAPH <urn:evil> { ?s ?p ?o } }").await.unwrap() == false,
            "the payload was executed as syntax rather than stored as data");
    }
}
```

Add to `src/rdf.rs`'s `mod tests`:

```rust
    // A MediaType that parsed is a header value that exists. No call site
    // should have to assert that with an `.expect`.
    #[test]
    fn a_media_type_carries_its_header_value() {
        let mt = MediaType::parse("text/plain; charset=utf-8").unwrap();
        assert_eq!(mt.header_value().to_str().unwrap(), "text/plain; charset=utf-8");
        assert_eq!(mt.header_value().to_str().unwrap(), mt.as_str());
    }
```

## Step 2: Run tests to verify they fail

Run: `nix develop -c cargo test --lib sparql 2>&1 | tail -20` and
`nix develop -c cargo test --lib rdf::tests::a_media_type_carries 2>&1 | tail -20`

Expected: FAIL — `sparql` is not a module; `header_value` does not exist.

## Step 3: Write `src/sparql.rs`

Add `pub mod sparql;` to `src/lib.rs` (alphabetical).

```rust
//! Values that may be interpolated into a SPARQL update or query.
//!
//! The store is written by string concatenation, so a value whose alphabet is
//! not established is a value that can leave its delimiter and continue the
//! update as syntax. This module holds the types that make that
//! unrepresentable for the one shape where the delimiter is a quote.
//!
//! IRIs need no type here: every `<...>` interpolation in this crate is fed by
//! `space::GraphName` (sealed), by `shelf::ShelfKey`, or by a name already
//! validated through `NamedNode::new`.

use std::fmt;

/// A literal, rendered with its quotes and escapes.
///
/// The escaping is oxrdf's: `oxigraph::model::Literal`'s `Display` produces the
/// N-Triples form, which is what `resource::serialize_for_insert` already
/// relies on for every triple this pod writes. Rendering through it rather than
/// beside it is the point — a second escaper is a second thing to get right,
/// and the two would drift silently because both would still produce output.
pub struct Literal(String);

impl Literal {
    pub fn new(value: &oxigraph::model::Literal) -> Self {
        Self(value.to_string())
    }
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
```

Check what `oxigraph::model::Literal`'s `Display` actually emits for a simple literal — if it
already includes the surrounding quotes, `Literal::new` stores it as-is and `Display` writes
it through, as above. If it does **not**, add the quotes in `new` and say so in the doc
comment. Let the tests tell you; do not assume.

## Step 4: Give `MediaType` its header value

In `src/rdf.rs`, change `MediaType` to carry both forms, built by the one constructor:

```rust
pub struct MediaType {
    raw: String,
    header: http::HeaderValue,
}
```

`parse` builds the `HeaderValue` after the alphabet check and returns `None` if it fails.
Given the alphabet (tchars plus `/`, `;`, `=`, space — all visible ASCII) it cannot fail, but
handling it is what removes the `.expect`, and a `None` here is the correct answer anyway.

```rust
    /// The `Content-Type` header for this media type. Infallible: the value was
    /// built and checked by the only constructor, so no call site has to assert
    /// it.
    pub fn header_value(&self) -> http::HeaderValue {
        self.header.clone()
    }
```

`as_str` returns `&self.raw`. `essence` is unchanged. `From<Format>` must go through `parse`
rather than constructing the struct directly, so there is still exactly one path in — if
`parse` on a `Format`'s own media type could ever fail, that is a bug worth panicking on, so
`.expect("a Format's media type is a valid media type")` is correct there and is not the kind
of `.expect` this task removes.

Derive `PartialEq`/`Eq` on the field that carries identity (`raw`) — if `#[derive]` on the
struct compares both fields that is fine too, since they are built together; state which you
chose and why in one line.

`http` is already in the dependency tree via axum. If it is not a direct dependency, add
`http = "1"` to `Cargo.toml` — check `Cargo.lock` for the version axum resolved and match it.

## Step 5: Use the type at the one call site

`src/resource.rs:126-136`, `put_dataset`'s registry string, currently:

```rust
    let mut registry = format!(
        "<{iri}> <{SYS_PRESENT}> true . <{iri}> <{SYS_MEDIA_TYPE}> \"{}\" . ",
        media_type.media_type()
    );
```

becomes a `crate::sparql::Literal` built from an `oxigraph::model::Literal` over
`media_type.media_type()`, interpolated **without** hand-written quotes.

## Step 6: Add the constraint that makes the rule stick

A type does not stop anyone writing `format!("\"{}\"", s)`. The check does. Append to
`docs/constraints.md` under "Storage addressing":

```markdown
A SPARQL literal is never interpolated by hand.
    → 2026-07-29-non-rdf-resources-design.md §8.2; `sparql::Literal`. Every
    `<...>` interpolation in this crate is fed by a sealed or validated type, so
    the IRI half needs no rule; the quote half had exactly one site and no rule
    at all. A hand-written `"{}"` is a value that can close its own literal and
    continue the update as syntax, and it fails by executing rather than by
    erroring.
    check: ! rg -q '\\"\{' src --glob '!src/sparql.rs' --glob '!src/http.rs'
```

`src/http.rs` is excluded because its `\"{` matches are HTTP `Link` and `Warning` header
construction, not SPARQL — verify that is still true when you add the rule
(`rg -n '\\"\{' src/http.rs`) and, if any SPARQL has appeared there, narrow the check instead
of widening the exclusion.

**Demonstrate it goes red:** add `let _ = format!("\"{}\"", "x");` to `src/resource.rs`, run
`arch-check --only 'SPARQL literal'`, confirm a non-zero exit, then remove it. `docs/constraints.md`
requires this of every rule it carries.

## Step 7: Full verification and commit

```bash
nix develop -c cargo test          # all green, output pristine
nix develop -c cargo clippy --all-targets   # clean
nix develop -c cargo build 2>&1 | grep -i warning   # nothing
arch-check                         # 0 rot, now including the new rule
rg -n '#\[allow' src               # no hits
```

```bash
git add src/sparql.rs src/rdf.rs src/resource.rs src/lib.rs docs/constraints.md Cargo.toml Cargo.lock
git commit -m "feat: make an unescaped SPARQL literal unrepresentable

The store is written by string concatenation, so a literal whose alphabet is
not established can close its own quote and continue the update as syntax —
failing by executing rather than by erroring. sparql::Literal renders through
oxrdf's escaper, the one this pod already trusts for every triple it writes,
rather than beside it.

MediaType now carries the HeaderValue its constructor validated, so no call
site has to assert header-safety with an .expect on another type's invariant."
```

## Out of scope

- Any general "SPARQL fragment" or IRI newtype. The IRI half is already covered by the sealed
  `GraphName` trait and its existing constraint; building a type for it would be a second
  guard over the same property.
- Touching `serialize_for_insert`. It already renders through oxrdf's `Display`; wrapping that
  in a newtype would add a layer without adding a guarantee.


---

### Task 2: one `Accept` parser, two consumers

`negotiate` parses the `Accept` list inline. A blob needs the same parse to answer a different question, and writing it twice is the drift `docs/constraints.md` names. The ranking moves out; both become consumers (§6.1).

**Files:**
- Modify: `src/rdf.rs:112-198` (`negotiate`)
- Test: `src/rdf.rs` `mod tests`

**Interfaces:**
- Consumes: `MediaType` from Task 1.
- Produces: `fn ranked_accept(accept: &str) -> Vec<(f32, usize, &str)>` — private to `rdf.rs`,
  consumed by `negotiate` here and by `accept_allows` in Task 8.

`accept_allows` itself lands in Task 8, with the read path that calls it. A `pub(crate)`
function with no production caller is a `dead_code` warning, and this build is warning-free
by rule — so the acceptability test cannot ship six tasks ahead of its consumer.

- [ ] **Step 1: Write the failing tests**

```rust
There is no new test to write here. The extraction is behaviour-preserving, and
`negotiate`'s existing suite — `q=0` as a refusal, wildcard scoping, case-insensitivity, the
two-pass dataset fallback — is exactly what says so. Adding a test for `ranked_accept` itself
would assert the shape of a private helper rather than any behaviour a caller can observe.

- [ ] **Step 2: Confirm the existing suite is green before you touch anything**

Run: `nix develop -c cargo test --lib rdf 2>&1 | tail -5`
Expected: PASS. This is the baseline the extraction must not move.

- [ ] **Step 3: Write minimal implementation**

In `src/rdf.rs`, add before `negotiate`:

```rust
/// The `Accept` list, highest quality first with earlier entries breaking a
/// tie, as `(q, position, media range)`.
///
/// **The only place this header is parsed.** [`negotiate`] asks it which
/// format to render into; a resource with a single representation asks it
/// whether that one type is admissible. Those are different questions, but a
/// second copy of the q-value parse is how the two come to disagree about
/// `q=0`.
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

```

Then replace the inline ranking inside `negotiate` — the block from
`// (quality, order) — highest quality wins, earlier entry breaks a tie.` through the
`ranked.sort_by(...)` line — with:

```rust
    let ranked = ranked_accept(accept);
```

Leave the rest of `negotiate` unchanged; it already iterates `&ranked`.

- [ ] **Step 4: Run the whole suite**

Run: `nix develop -c cargo test --lib rdf 2>&1 | tail -5`
Expected: PASS. Every pre-existing negotiation test must still pass — the extraction is
behaviour-preserving, and those tests are what says so.

- [ ] **Step 5: Commit**

```bash
git add src/rdf.rs
git commit -m "refactor: one Accept parser, one consumer so far

A blob has a single representation, so 'does the client accept it?' is a
different question from 'which format do I render into?'. Both parse the
same header, and two q-value parses is how they come to disagree about q=0
— which docs/constraints.md already names as the failure mode. ranked_accept
is the one parser; the second consumer arrives with the blob read path."
```

---

### Task 3: `blob.rs` — the key and the store

**Files:**
- Create: `src/blob.rs`
- Modify: `src/lib.rs`, `Cargo.toml`
- Test: `src/blob.rs` `mod tests`

**Interfaces:**
- Consumes: `crate::space::ResourceUrl`.
- Produces: `pub struct BlobKey`; `BlobKey::of(&ResourceUrl) -> Option<BlobKey>`; `BlobKey::as_str(&self) -> &str`; `pub trait BlobStore` with `put(&self, &BlobKey, Bytes) -> Result<(), BlobError>`, `get(&self, &BlobKey) -> Result<Option<Bytes>, BlobError>`, `delete(&self, &BlobKey) -> Result<(), BlobError>`; `pub struct ObjectStoreBlobs` with `in_memory()` and `local(&std::path::Path) -> Result<Self, BlobError>`; `pub enum BlobError { Backend(String) }`.

- [ ] **Step 1: Add the dependency**

In `Cargo.toml` `[dependencies]`, keeping the list alphabetical:

```toml
bytes = "1.12.1"
object_store = "0.14.1"
```

`bytes` is already in the lockfile transitively; naming it directly is what lets a public
trait signature mention `Bytes` without borrowing axum's re-export.

Run: `nix develop -c cargo build 2>&1 | tail -5` — expected: builds, no warnings.

- [ ] **Step 2: Write the failing tests**

Create `src/blob.rs` with only this test module plus `use` lines (the implementation comes in
step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::{StorageSpace, Target};

    fn res(path: &str) -> crate::space::ResourceUrl {
        match StorageSpace::new("https://pod.toph.so/").unwrap().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    // §3.2: the key mirrors the URL. Asserted on the key itself and not on a
    // round trip, because a round trip passes under ANY injective key
    // function — a hash included — and mirroring is the whole property.
    #[test]
    fn the_key_mirrors_the_resource_path() {
        assert_eq!(BlobKey::of(&res("/photos/cat.png")).unwrap().as_str(), "photos/cat.png");
        assert_eq!(BlobKey::of(&res("/notes")).unwrap().as_str(), "notes");
    }

    // Also asserted on the key: a `400` from somewhere upstream would make a
    // status-code assertion pass while proving nothing about BlobKey.
    #[test]
    fn a_relative_segment_never_reaches_the_backend_as_an_ascent() {
        // Whatever `resolve` admits, the key must not contain a `..` segment.
        for path in ["/a/b/c.txt", "/a/x.txt"] {
            let key = BlobKey::of(&res(path)).unwrap();
            assert!(
                !key.as_str().split('/').any(|s| s == ".." || s == "."),
                "{path} produced {}", key.as_str()
            );
            assert!(!key.as_str().starts_with('/'), "keys carry no leading slash");
        }
    }

    // §3.2: with a hash key every legal URL had a legal key. With a mirrored
    // one some do not, and the pod must say so rather than hand the backend a
    // name it will reject.
    #[test]
    fn an_over_long_segment_or_path_has_no_key() {
        let long_segment = "a".repeat(256);
        assert!(BlobKey::of(&res(&format!("/{long_segment}"))).is_none());

        let deep: String = std::iter::repeat_n("seg/", 300).collect();
        assert!(BlobKey::of(&res(&format!("/{deep}leaf"))).is_none());

        // The boundary itself is storable — an off-by-one here would refuse
        // legal URLs, which is the mirror-image bug.
        let at_limit = "a".repeat(255);
        assert!(BlobKey::of(&res(&format!("/{at_limit}"))).is_some());
    }

    #[tokio::test]
    async fn put_get_delete_round_trip() {
        let blobs = ObjectStoreBlobs::in_memory();
        let key = BlobKey::of(&res("/photos/cat.png")).unwrap();

        assert!(blobs.get(&key).await.unwrap().is_none(), "absent is None, not an error");

        // Bytes, not text: a NUL and invalid UTF-8 are what tell a byte path
        // apart from one that routes through String somewhere.
        let payload = bytes::Bytes::from_static(&[0x00, 0xff, 0xfe, b'\r', b'\n', 0x41]);
        blobs.put(&key, payload.clone()).await.unwrap();
        assert_eq!(blobs.get(&key).await.unwrap().unwrap(), payload);

        blobs.delete(&key).await.unwrap();
        assert!(blobs.get(&key).await.unwrap().is_none());

        // §4: deleting an absent object succeeds. The delete path in §7 has no
        // prior read, so this is load-bearing rather than tidy.
        blobs.delete(&key).await.unwrap();
    }

    #[tokio::test]
    async fn local_backend_writes_the_mirrored_tree_to_disk() {
        let dir = std::env::temp_dir().join(format!("sparql-pod-blob-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let blobs = ObjectStoreBlobs::local(&dir).unwrap();
        let key = BlobKey::of(&res("/photos/cat.png")).unwrap();

        blobs.put(&key, bytes::Bytes::from_static(b"png")).await.unwrap();

        // The point of mirroring: the file is where its URL says it is.
        assert_eq!(std::fs::read(dir.join("photos").join("cat.png")).unwrap(), b"png");
        std::fs::remove_dir_all(&dir).ok();
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib blob 2>&1 | tail -20`
Expected: FAIL — `blob` is not a module yet, then once registered, `BlobKey` undefined.

- [ ] **Step 4: Write minimal implementation**

Add `pub mod blob;` to `src/lib.rs` (alphabetical, before `pub mod config;`).

Prepend to `src/blob.rs`, above the test module:

```rust
//! Bytes for non-RDF resources, and the key that addresses them.
//!
//! The storage model of design spec §3.2. The key is the resource's own path,
//! so the backing store mirrors the URL tree and can be read with ordinary
//! tools; it is derived rather than recorded, which is what makes an
//! interrupted write or delete heal on the next write to the same URL instead
//! of leaking an object nobody can find.

use crate::space::ResourceUrl;
use bytes::Bytes;
use object_store::{path::Path, ObjectStore};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("blob backend error: {0}")]
    Backend(String),
}

/// Longest path segment most filesystems accept, and longest whole path most
/// object stores accept — `object_store`'s own documented wording. Checked at
/// key construction so an over-long URL is refused with `414` before anything
/// is written, rather than failing inside a backend that phrases it
/// differently.
const MAX_SEGMENT_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 1024;

/// Where one resource's bytes live: its path with the leading `/` removed, so
/// `/photos/cat.png` is stored at `photos/cat.png`.
///
/// Constructible only through [`BlobKey::of`], which is what keeps the
/// derivation in one place — a second site building a key by hand is how two
/// resources come to share one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobKey(Path);

impl BlobKey {
    /// `None` when the mirrored key would exceed a segment or path length
    /// limit: a legal URL this pod cannot store (§3.2, §11).
    ///
    /// `Path::from` percent-encodes segments the backends treat as
    /// problematic, so a relative segment never reaches the backend as a
    /// directory ascent.
    pub fn of(r: &ResourceUrl) -> Option<Self> {
        let rel = r.path().trim_start_matches('/');
        if rel.len() > MAX_PATH_BYTES {
            return None;
        }
        if rel.split('/').any(|s| s.len() > MAX_SEGMENT_BYTES) {
            return None;
        }
        Some(Self(Path::from(rel)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

/// Byte storage for non-RDF resources.
///
/// **Obligation on every implementor:** `put` writes the whole payload or
/// writes nothing; `delete` on an absent key succeeds; `get` distinguishes an
/// absent object from a backend it could not reach. The write order in design
/// spec §5.1 and the delete order in §7 rest on the first two, and neither can
/// check them.
///
/// Deliberately narrower than `object_store::ObjectStore`, whose multipart,
/// listing, copy and rename surface this pod does not use — and narrower on
/// purpose in the other direction too, since a remote Solid pod is a plausible
/// future implementor and is not an `ObjectStore`.
#[async_trait::async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, key: &BlobKey, bytes: Bytes) -> Result<(), BlobError>;
    async fn get(&self, key: &BlobKey) -> Result<Option<Bytes>, BlobError>;
    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError>;
}

/// The `object_store`-backed implementation: in-process, local filesystem, or
/// anything else `object_store` reaches.
pub struct ObjectStoreBlobs(Arc<dyn ObjectStore>);

impl ObjectStoreBlobs {
    /// Bytes live for the process, matching `OxigraphStore::in_memory` — the
    /// pod stays uniformly ephemeral rather than making blobs outlive the
    /// triples that describe them.
    pub fn in_memory() -> Self {
        Self(Arc::new(object_store::memory::InMemory::new()))
    }

    /// A directory mirroring the URL tree (§3.2).
    pub fn local(root: &std::path::Path) -> Result<Self, BlobError> {
        object_store::local::LocalFileSystem::new_with_prefix(root)
            .map(|fs| Self(Arc::new(fs)))
            .map_err(|e| BlobError::Backend(e.to_string()))
    }
}

#[async_trait::async_trait]
impl BlobStore for ObjectStoreBlobs {
    async fn put(&self, key: &BlobKey, bytes: Bytes) -> Result<(), BlobError> {
        self.0
            .put(&key.0, bytes.into())
            .await
            .map(|_| ())
            .map_err(|e| BlobError::Backend(e.to_string()))
    }

    async fn get(&self, key: &BlobKey) -> Result<Option<Bytes>, BlobError> {
        match self.0.get(&key.0).await {
            Ok(r) => r
                .bytes()
                .await
                .map(Some)
                .map_err(|e| BlobError::Backend(e.to_string())),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(BlobError::Backend(e.to_string())),
        }
    }

    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError> {
        match self.0.delete(&key.0).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(BlobError::Backend(e.to_string())),
        }
    }
}
```

- [ ] **Step 4b: Reconcile with the real `object_store` API**

The three call sites above (`put`, `get`, `delete`, `r.bytes()`, `bytes.into()`) are written
against `object_store` 0.14.1's documented surface. If any fails to compile, fix the call —
do not change the trait. `nix develop -c cargo doc --open -p object_store` has the answer.
The trait's shape is a design decision (§4); the glue underneath is not.

- [ ] **Step 5: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib blob 2>&1 | tail -10`
Expected: PASS, all six tests.

- [ ] **Step 6: Verify the mirroring test bites**

Temporarily change `BlobKey::of`'s final line to
`Some(Self(Path::from(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(rel.as_bytes())))))`.
Run `nix develop -c cargo test --lib blob`. Expected: `the_key_mirrors_the_resource_path` and
`local_backend_writes_the_mirrored_tree_to_disk` FAIL, while `put_get_delete_round_trip`
still PASSES — which is exactly why the round trip is not the test for this property.
Revert.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/blob.rs src/lib.rs
git commit -m "feat: BlobKey and the BlobStore seam

The key is the resource path, so the backing store mirrors the URL tree and
ls works. Derived rather than recorded: an interrupted write leaves an object
the next write to the same URL overwrites, so nothing needs a sweep. Over-long
segments and paths have no key at all, which is a 414 rather than a backend
error phrased in the backend's words."
```

---

### Task 4: storing and recognising a binary resource

**Files:**
- Modify: `src/resource.rs`
- Test: `src/resource.rs` `mod tests`

**Interfaces:**
- Consumes: `BlobKey`, `BlobStore`, `BlobError` (Task 3); `MediaType` (Task 1).
- Produces: `pub const SYS_BINARY_RESOURCE: &str`; `pub enum Kind { Rdf, Binary(MediaType) }`; `pub async fn put_blob(&dyn SparqlStore, &dyn BlobStore, &ResourceUrl, Bytes, &MediaType) -> Result<(), ResourceError>`; `pub async fn kind_of(&dyn SparqlStore, &ResourceUrl) -> Result<Option<Kind>, ResourceError>`; `stored_media_type` now returns `Result<Option<MediaType>, ResourceError>`; new `ResourceError` variants `Blob(BlobError)` and `KeyTooLong` and `BinaryWithoutMediaType`.

- [ ] **Step 1: Write the failing tests**

Add to `src/resource.rs`'s `mod tests`:

```rust
    /// A `BlobStore` whose `put` always fails, for the write-order test.
    struct FailingBlobs;

    #[async_trait::async_trait]
    impl crate::blob::BlobStore for FailingBlobs {
        async fn put(&self, _: &crate::blob::BlobKey, _: bytes::Bytes)
            -> Result<(), crate::blob::BlobError> {
            Err(crate::blob::BlobError::Backend("disk on fire".into()))
        }
        async fn get(&self, _: &crate::blob::BlobKey)
            -> Result<Option<bytes::Bytes>, crate::blob::BlobError> { Ok(None) }
        async fn delete(&self, _: &crate::blob::BlobKey)
            -> Result<(), crate::blob::BlobError> { Ok(()) }
    }

    #[tokio::test]
    async fn a_blob_round_trips_with_its_declared_media_type() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/photos/cat.png");
        let mt = crate::rdf::MediaType::parse("image/png").unwrap();
        let payload = bytes::Bytes::from_static(&[0x00, 0xff, 0xfe, b'\r', b'\n', 0x41]);

        put_blob(&store, &blobs, &r, payload.clone(), &mt).await.unwrap();

        assert!(exists(&store, &r).await.unwrap());
        assert_eq!(kind_of(&store, &r).await.unwrap(), Some(Kind::Binary(mt)));
        let key = crate::blob::BlobKey::of(&r).unwrap();
        assert_eq!(
            crate::blob::BlobStore::get(&blobs, &key).await.unwrap().unwrap(),
            payload,
            "bytes survive exactly — a NUL and invalid UTF-8 are in there on purpose"
        );
    }

    // §5.1: bytes first, marker second. The reverse order leaves a resource
    // that exists and cannot be served, and nothing but this test says which
    // way round the two statements go.
    #[tokio::test]
    async fn a_failed_object_write_leaves_no_resource_behind() {
        let store = OxigraphStore::in_memory().unwrap();
        let r = res("/photos/cat.png");
        let mt = crate::rdf::MediaType::parse("image/png").unwrap();

        let err = put_blob(&store, &FailingBlobs, &r, bytes::Bytes::from_static(b"x"), &mt)
            .await
            .unwrap_err();

        assert!(matches!(err, ResourceError::Blob(_)));
        assert!(!exists(&store, &r).await.unwrap(), "the marker must not have been written");
        assert_eq!(kind_of(&store, &r).await.unwrap(), None);
    }

    // §3.3: the kind is a stored triple, not an inference from the media type.
    // Deriving it would silently re-interpret every stored RDF/XML blob on the
    // day `Format` learns application/rdf+xml.
    #[tokio::test]
    async fn an_rdf_resource_and_a_blob_are_distinguishable_by_a_stored_fact() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let rdf = res("/notes");
        let blob = res("/photo");

        // `put_rdf`, not `put_dataset`: this task must not depend on Task 6's
        // signature change, and it writes the same presence marker.
        put_rdf(&store, &rdf, &[]).await.unwrap();
        put_blob(&store, &blobs, &blob, bytes::Bytes::from_static(b"x"),
                 &crate::rdf::MediaType::parse("text/plain").unwrap()).await.unwrap();

        assert_eq!(kind_of(&store, &rdf).await.unwrap(), Some(Kind::Rdf));
        assert!(matches!(kind_of(&store, &blob).await.unwrap(), Some(Kind::Binary(_))));
        assert_eq!(kind_of(&store, &res("/absent")).await.unwrap(), None);
    }

    // §3.1's invariant: a binary resource always has a stored media type.
    // This state should not occur — one INSERT DATA writes both — so the test
    // pins the fail-closed answer for when it somehow does.
    #[tokio::test]
    async fn a_binary_resource_without_a_media_type_fails_closed() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/photo");
        put_blob(&store, &blobs, &r, bytes::Bytes::from_static(b"x"),
                 &crate::rdf::MediaType::parse("text/plain").unwrap()).await.unwrap();

        let sys = sys_graph_iri(&r);
        store.update(&format!(
            "DELETE WHERE {{ GRAPH <{sys}> {{ <{}> <{SYS_MEDIA_TYPE}> ?m }} }}", r.graph_iri()
        )).await.unwrap();

        assert!(matches!(
            kind_of(&store, &r).await,
            Err(ResourceError::BinaryWithoutMediaType)
        ));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib resource 2>&1 | tail -20`
Expected: FAIL — `put_blob`, `kind_of`, `Kind` undefined.

- [ ] **Step 3: Write minimal implementation**

In `src/resource.rs`, extend the error type:

```rust
    #[error(transparent)]
    Blob(#[from] crate::blob::BlobError),
    #[error("the storage key for this URL is too long")]
    KeyTooLong,
    #[error("a binary resource has no stored media type")]
    BinaryWithoutMediaType,
```

Add near `SYS_PRESENT`:

```rust
/// Marks a resource whose representation is bytes rather than triples.
///
/// Stored rather than inferred from the media type: inferring it would make
/// every blob stored under a type `Format` later learns re-interpret as an
/// empty RDF resource, and `application/rdf+xml` is already on the follow-up
/// list (`2026-07-28-jsonld-datasets-design.md` §11).
pub const SYS_BINARY_RESOURCE: &str = "urn:quadpod:sys#BinaryResource";

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// What a resource's representation is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Rdf,
    Binary(crate::rdf::MediaType),
}
```

Add the write path:

```rust
/// §5: replace a resource with bytes, and record what they arrived as.
///
/// The object is written **before** the marker, and that order is the design
/// (§5.1): an interrupted marker write leaves an object no read path can see
/// and the next write to the same URL overwrites, whereas the reverse order
/// would leave a resource that exists and cannot be served. The registry read
/// happens before the drops for the same reason it does in [`put_dataset`] —
/// it lives in the graph being dropped.
pub async fn put_blob(
    store: &dyn SparqlStore,
    blobs: &dyn crate::blob::BlobStore,
    r: &ResourceUrl,
    bytes: bytes::Bytes,
    media_type: &crate::rdf::MediaType,
) -> Result<(), ResourceError> {
    let key = crate::blob::BlobKey::of(r).ok_or(ResourceError::KeyTooLong)?;
    let shelves = registered_shelves(store, r).await?;
    blobs.put(&key, bytes).await?;

    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let mut update = String::new();
    for shelf in shelves {
        update.push_str(&format!("DROP SILENT GRAPH <{}>; ", shelf.graph_iri()));
    }
    update.push_str(&format!(
        "DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>; \
         INSERT DATA {{ GRAPH <{sys}> {{ \
           <{iri}> <{SYS_PRESENT}> true . \
           <{iri}> <{RDF_TYPE}> <{SYS_BINARY_RESOURCE}> . \
           <{iri}> <{SYS_MEDIA_TYPE}> \"{}\" \
         }} }}",
        media_type.as_str()
    ));
    store.update(&update).await?;
    Ok(())
}

/// Which kind of representation `r` holds, or `None` if it is absent.
pub async fn kind_of(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Option<Kind>, ResourceError> {
    if !exists(store, r).await? {
        return Ok(None);
    }
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let binary = store
        .ask(&format!(
            "ASK {{ GRAPH <{sys}> {{ <{iri}> <{RDF_TYPE}> <{SYS_BINARY_RESOURCE}> }} }}"
        ))
        .await?;
    if !binary {
        return Ok(Some(Kind::Rdf));
    }
    // §3.1 writes both in one INSERT DATA, so a binary resource without a
    // media type is that invariant broken. Refusing beats serving bytes under
    // a type the server invented.
    let mt = stored_media_type(store, r).await?.ok_or(ResourceError::BinaryWithoutMediaType)?;
    Ok(Some(Kind::Binary(mt)))
}
```

Change `stored_media_type`'s return type from `Option<Format>` to
`Option<crate::rdf::MediaType>` and its body's `find_map` arm from
`Format::from_content_type(l.value())` to `crate::rdf::MediaType::parse(l.value())`. Update
its doc comment: it is no longer "returned as the type" but "returned as the media type; the
RDF path narrows it to a `Format`".

Fix the one caller inside this module's own tests
(`assert_eq!(stored_media_type(&store, &r).await.unwrap(), Some(jsonld))`) to compare against
`Some(crate::rdf::MediaType::from(jsonld))`.

Fix the one production caller, `get_impl` (`src/http.rs:683`). It feeds `negotiate`, which
still takes an `Option<Format>` because the RDF read path still chooses between five
renderings; narrowing happens at the call site:

```rust
    let stored_type = stored_media_type(store, r)
        .await
        .ok()
        .flatten()
        .and_then(|m| Format::from_content_type(m.as_str()));
```

- [ ] **Step 4: Run the whole suite**

Run: `nix develop -c cargo test 2>&1 | tail -10`
Expected: PASS. The crate must build at the end of this task — a task that leaves `src/`
uncompilable has no testable deliverable.

- [ ] **Step 5: Verify the write-order test bites**

Temporarily move `blobs.put(&key, bytes).await?;` to *after* `store.update(&update).await?;`.
Run `nix develop -c cargo test --lib resource::tests::a_failed_object_write`. Expected: FAIL —
`exists` returns true. Revert.

- [ ] **Step 6: Commit**

```bash
git add src/resource.rs
git commit -m "feat: store a resource as bytes, and record which kind it is

The system graph gets three triples and nothing about the bytes: the pod does
not own them, and a stored size or hash goes silently false when a swappable
backend is written to from elsewhere. The kind is a stored triple rather than
an inference from the media type, so adding application/rdf+xml to Format
later cannot re-interpret stored blobs as empty RDF resources."
```

---

### Task 5: the two teardown sites

Wherever a resource's RDF state is torn down, its blob goes with it. There are exactly two such places, and neither gets a parallel blob-delete entry point — `e31c88b` removed a second delete cascade once already (§7).

**Files:**
- Modify: `src/resource.rs` (`put_dataset`), `src/aux.rs` (`delete_subject`)
- Test: `src/resource.rs`, `src/aux.rs`

**Interfaces:**
- Produces: `put_dataset(&dyn SparqlStore, &dyn BlobStore, &ResourceUrl, &Skolemized, Format)`; `aux::delete_subject(&dyn SparqlStore, &dyn BlobStore, &ResourceUrl)`. Both gain `blobs` as their second parameter.

- [ ] **Step 1: Write the failing tests**

In `src/resource.rs`'s `mod tests`:

```rust
    // §5.2: PUT replaces the representation including its kind. The assertion
    // is against the BlobStore directly, not through the marker — reading back
    // through the registry is how `b4d2346` found orphans invisible.
    #[tokio::test]
    async fn writing_rdf_over_a_blob_removes_the_object() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/thing");
        let key = crate::blob::BlobKey::of(&r).unwrap();
        let ttl = Format::from_content_type("text/turtle").unwrap();

        put_blob(&store, &blobs, &r, bytes::Bytes::from_static(b"x"),
                 &crate::rdf::MediaType::parse("text/plain").unwrap()).await.unwrap();
        assert!(crate::blob::BlobStore::get(&blobs, &key).await.unwrap().is_some());

        put_dataset(&store, &blobs, &r, &Skolemized::new(vec![]), ttl).await.unwrap();

        assert_eq!(kind_of(&store, &r).await.unwrap(), Some(Kind::Rdf));
        assert!(
            crate::blob::BlobStore::get(&blobs, &key).await.unwrap().is_none(),
            "the superseded object must be gone, not merely unreachable"
        );
    }

    #[tokio::test]
    async fn writing_a_blob_over_rdf_removes_the_graph_and_its_shelves() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/thing");
        let ttl = Format::from_content_type("text/turtle").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let ds = Skolemized::new(vec![gq("http://example.org/alice", "Alice", g.clone().into())]);

        put_dataset(&store, &blobs, &r, &ds, ttl).await.unwrap();
        let shelf = ShelfKey::of(&r, g.as_ref());

        put_blob(&store, &blobs, &r, bytes::Bytes::from_static(b"x"),
                 &crate::rdf::MediaType::parse("text/plain").unwrap()).await.unwrap();

        assert!(matches!(kind_of(&store, &r).await.unwrap(), Some(Kind::Binary(_))));
        assert!(registered_shelves(&store, &r).await.unwrap().is_empty());
        // Probed directly: an emptied-but-present shelf is content the next
        // write to the same graph name would inherit.
        let leftover = store.query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{}> {{ ?s ?p ?o }} }}", shelf.graph_iri()
        )).await.unwrap();
        assert!(leftover.is_empty());
    }
```

In `src/aux.rs`'s `mod tests`:

```rust
    // §7: there is one delete cascade, and the blob goes with it. Asserted
    // against the BlobStore, not against a 404 from a read path.
    #[tokio::test]
    async fn the_delete_cascade_takes_the_blob_with_it() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/photo");
        let key = crate::blob::BlobKey::of(&r).unwrap();

        crate::resource::put_blob(
            &store, &blobs, &r, bytes::Bytes::from_static(b"x"),
            &crate::rdf::MediaType::parse("image/png").unwrap(),
        ).await.unwrap();

        assert!(delete_subject(&store, &blobs, &r).await.unwrap());
        assert!(!crate::resource::exists(&store, &r).await.unwrap());
        assert!(crate::blob::BlobStore::get(&blobs, &key).await.unwrap().is_none());
    }

    // The cascade is correct for a resource that never had a blob, and it
    // must not report failure for one — `delete` on an absent key succeeds.
    #[tokio::test]
    async fn the_cascade_still_works_for_an_rdf_resource() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/notes");
        crate::resource::put_rdf(&store, &r, &[]).await.unwrap();
        assert!(delete_subject(&store, &blobs, &r).await.unwrap());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib 2>&1 | tail -20`
Expected: FAIL — arity mismatch on `put_dataset` / `delete_subject`.

- [ ] **Step 3: Write minimal implementation**

In `src/resource.rs`, add `blobs: &dyn crate::blob::BlobStore` as `put_dataset`'s second
parameter, and immediately before the `DROP` loop:

```rust
    // §5.2: this write replaces the representation including its kind, so a
    // blob that was here is superseded. Unconditional — deleting an absent
    // object succeeds, and a check plus a delete is two round-trips with a
    // window between them. Over-long keys have no object to remove.
    if let Some(key) = crate::blob::BlobKey::of(r) {
        blobs.delete(&key).await?;
    }
```

Extend `put_dataset`'s doc comment with one sentence naming this as one of the two teardown
sites §7 describes.

In `src/aux.rs`, add `blobs: &dyn crate::blob::BlobStore` as `delete_subject`'s second
parameter, and after `store.update(&drops.join("; ")).await?;`:

```rust
    // §7: graphs and marker first, then the object. An interrupted second half
    // leaves an object no marker points at, which the next write to the same
    // URL overwrites; the reverse order would leave a resource that exists and
    // cannot be served.
    if let Some(key) = crate::blob::BlobKey::of(subject) {
        blobs.delete(&key).await?;
    }
```

Extend `delete_subject`'s doc comment: it is no longer "graphs only". State that it is the
one cascade and that the blob is part of it.

`src/http.rs` calls both functions and must compile at the end of this task, so it needs the
handle now. Add the field to `AppState` (`src/http.rs:21-28`):

```rust
    pub blobs: Arc<dyn crate::blob::BlobStore>,
```

then pass `st.blobs.as_ref()` at every `put_dataset` and `delete_subject` call site the
compiler names. `src/main.rs` gets `blobs: Arc::new(sparql_pod::blob::ObjectStoreBlobs::in_memory()),`
in its `AppState` literal — Task 6 replaces that with the configured backend.

In `src/http.rs`'s test `fixture()`, keep the handle so later tests can probe the object store
directly rather than through a read path:

```rust
    struct Fixture {
        app: axum::Router,
        store: Arc<dyn crate::store::SparqlStore>,
        blobs: Arc<dyn crate::blob::BlobStore>,
        // … unchanged fields …
    }
```

```rust
        let blobs: Arc<dyn crate::blob::BlobStore> =
            Arc::new(crate::blob::ObjectStoreBlobs::in_memory());
        let state = AppState {
            store: store.clone(),
            blobs: blobs.clone(),
            // … unchanged fields …
        };
        Fixture { app: router(state), store, blobs, space, idp, client, _replay_guard,
                  _reentrancy: ReentrancyGuard }
```

Update the remaining `src/resource.rs` and `src/aux.rs` test call sites the compiler names.

- [ ] **Step 4: Run the whole suite**

Run: `nix develop -c cargo test 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 5: Verify the teardown tests bite**

Comment out the `blobs.delete` line in `put_dataset`. Run
`nix develop -c cargo test --lib resource::tests::writing_rdf_over_a_blob`. Expected: FAIL.
Restore, then do the same for `delete_subject` against
`aux::tests::the_delete_cascade_takes_the_blob`. Expected: FAIL. Restore.

- [ ] **Step 6: Commit**

```bash
git add src/resource.rs src/aux.rs
git commit -m "feat: tear the blob down wherever the RDF state is torn down

Two sites, both unconditional: put_dataset's replace and delete_subject's
cascade. Not a blob::delete entry point beside them — e31c88b removed a
second, weaker delete cascade once already, and aux::delete_subject is the
one that does it completely."
```

---

### Task 6: config, `AppState`, and an explicit body limit

**Files:**
- Modify: `src/config.rs`, `src/http.rs:21-37`, `src/main.rs`
- Test: `src/config.rs` `mod tests`

**Interfaces:**
- Produces: `Config::blob_store: String`; `Config::max_body_bytes: usize`; `Config::blobs(&self) -> Result<Arc<dyn BlobStore>, String>`; `AppState::blobs: Arc<dyn BlobStore>`; `AppState::max_body_bytes: usize`.

- [ ] **Step 1: Write the failing tests**

In `src/config.rs`'s `mod tests`:

```rust
    #[test]
    fn blob_store_selects_a_backend_and_refuses_an_unknown_one() {
        let mut cfg = Config::parse_from(["sparql-pod", "--owner-webid", "https://a.example/#me"]);
        assert_eq!(cfg.blob_store, "memory", "the default matches the in-memory triple store");
        assert!(cfg.blobs().is_ok());

        let dir = std::env::temp_dir().join(format!("sparql-pod-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        cfg.blob_store = format!("local:{}", dir.display());
        assert!(cfg.blobs().is_ok());
        std::fs::remove_dir_all(&dir).ok();

        cfg.blob_store = "s3:bucket".into();
        assert!(cfg.blobs().is_err(), "an unimplemented backend must refuse to start");
        cfg.blob_store = "nonsense".into();
        assert!(cfg.blobs().is_err());
    }

    // axum's own default is 2 MiB and already applies to every write path.
    // Making it a flag is what turns a 413 into a decision.
    #[test]
    fn max_body_bytes_has_an_explicit_default() {
        let cfg = Config::parse_from(["sparql-pod", "--owner-webid", "https://a.example/#me"]);
        assert_eq!(cfg.max_body_bytes, 64 * 1024 * 1024);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib config 2>&1 | tail -20`
Expected: FAIL — no field `blob_store`.

- [ ] **Step 3: Write minimal implementation**

Add to `Config`:

```rust
    /// Where non-RDF resource bytes live. `memory` keeps them in process,
    /// matching the triple store, so the pod is uniformly ephemeral rather
    /// than making blobs outlive the triples describing them.
    /// `local:<dir>` mirrors the URL tree under `<dir>`, so it can be read and
    /// backed up with ordinary tools.
    #[arg(long, env = "POD_BLOB_STORE", default_value = "memory")]
    pub blob_store: String,

    /// Largest request body accepted, in bytes, for every write path. axum
    /// applies a 2 MiB default of its own when nothing is set; naming it here
    /// makes a `413` a statement about this pod rather than a framework
    /// artefact. The body is buffered whole in memory, which is the real
    /// ceiling behind this number.
    #[arg(long, env = "POD_MAX_BODY_BYTES", default_value_t = 64 * 1024 * 1024)]
    pub max_body_bytes: usize,
```

And the constructor:

```rust
    /// The blob backend this process will use, or the operator-facing reason
    /// it cannot be built. Refusing to start beats starting with a backend
    /// that silently differs from the one configured.
    pub fn blobs(&self) -> Result<std::sync::Arc<dyn crate::blob::BlobStore>, String> {
        let spec = self.blob_store.trim();
        if spec == "memory" {
            return Ok(std::sync::Arc::new(crate::blob::ObjectStoreBlobs::in_memory()));
        }
        if let Some(dir) = spec.strip_prefix("local:") {
            return crate::blob::ObjectStoreBlobs::local(std::path::Path::new(dir))
                .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn crate::blob::BlobStore>)
                .map_err(|e| format!("--blob-store local: {e}"));
        }
        Err(format!(
            "--blob-store: expected `memory` or `local:<dir>`, got `{spec}`"
        ))
    }
```

In `src/http.rs`, extend `AppState` — `blobs` arrived in Task 5, so only the limit is new:

```rust
    pub max_body_bytes: usize,
```

and `router`:

```rust
pub fn router(state: AppState) -> Router {
    let max_body_bytes = state.max_body_bytes;
    // axum 0.8 wildcard capture syntax: "/{*path}" (NOT the old "/*path").
    Router::new()
        .route("/", get(handle_get_root).put(handle_put_root).post(handle_post_root).delete(handle_delete_root))
        .route("/{*path}", get(handle_get).put(handle_put).post(handle_post).delete(handle_delete))
        .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_layer))
        .with_state(state)
}
```

In `src/main.rs`, before building `state`:

```rust
    let blobs = match cfg.blobs() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
```

and add `blobs,` plus `max_body_bytes: cfg.max_body_bytes,` to the `AppState` literal.

In `src/http.rs`'s test `fixture()`, add `max_body_bytes: 64 * 1024 * 1024,` to the
`AppState` literal. Replace `src/main.rs`'s hardcoded `ObjectStoreBlobs::in_memory()` from
Task 5 with the `blobs` value built above.

- [ ] **Step 4: Pin that the limit is enforced**

Add to `src/http.rs`'s `mod tests`. The limit is a decision now, so something has to fail
when it is crossed; without this the flag could be read, stored and never applied.

```rust
    // §8.4: axum's own 2 MiB default already applied here. This pins that the
    // configured number is the one in force — a body over it is refused, and
    // one under it is not.
    #[tokio::test]
    async fn a_body_over_the_configured_limit_is_a_413() {
        let f = fixture_with_body_limit(64).await;

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/small.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(vec![b'x'; 32])).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/big.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(vec![b'x'; 4096])).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
```

Give `fixture()` a `max_body_bytes` parameter by extracting its body into
`fixture_with_body_limit(max_body_bytes: usize) -> Fixture` and making
`fixture()` call it with `64 * 1024 * 1024`. Do not copy the body: the re-entrancy assertion
and the replay-lock acquisition must happen exactly once per fixture, and a second copy is
where that stops being true.

- [ ] **Step 5: Run the whole suite**

Run: `nix develop -c cargo test 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/config.rs src/http.rs src/main.rs
git commit -m "feat: configurable blob backend and an explicit body limit

router() set no DefaultBodyLimit, so axum's 2 MiB default already applied to
every write path — an accidental limit rather than a decided one. It is now
--max-body-bytes, default 64 MiB. --blob-store picks memory (default, matching
the in-memory triple store) or local:<dir>; an unrecognised value refuses to
start rather than silently falling back."
```

---

### Task 7: the three-way `Content-Type` gate on write

**Files:**
- Modify: `src/http.rs:335-482` (`put_impl`), `src/http.rs:529-634` (`post_impl`)
- Test: `src/http.rs` `mod tests`

**Interfaces:**
- Consumes: `MediaType`, `put_blob`, `kind_of`, `BlobKey`.
- Produces: `enum Repr { Rdf(Dataset, Format), Blob(Bytes, MediaType) }` and
  `fn classify_body(&HeaderMap, &Bytes, &Target) -> Result<Repr, Response>` in `src/http.rs`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn a_text_file_can_be_put_and_read_back_byte_for_byte() {
        let f = fixture().await;
        let body: &[u8] = &[0x00, 0xff, 0xfe, b'\r', b'\n', b'A'];

        let res = f.app.clone().oneshot(f.owner_request("PUT", "/notes.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(body.to_vec())).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let res = f.app.clone().oneshot(f.owner_request("GET", "/notes.txt")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CONTENT_TYPE], "text/plain");
        let got = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        assert_eq!(&got[..], body, "bytes survive exactly");
    }

    // Solid Protocol §2.2 names the status code in its normative text:
    // "Server MUST reject PUT, POST, and PATCH requests that contain content
    // but lack the Content-Type header field, with a status code of 400."
    #[tokio::test]
    async fn a_write_with_content_and_no_content_type_is_a_400() {
        let f = fixture().await;
        for (method, path) in [("PUT", "/x"), ("POST", "/")] {
            let res = f.app.clone().oneshot(f.owner_request(method, path)
                .body(Body::from("hello")).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{method} {path}");
        }
    }

    // The live injection vector: a legal HTTP header value that is not a legal
    // media type, whose quote would close the SPARQL literal it is
    // interpolated into. A CRLF payload would NOT do here — hyper rejects it
    // before any handler runs, so that test would pin hyper and pass no matter
    // what MediaType::parse does.
    #[tokio::test]
    async fn a_content_type_that_is_not_a_media_type_is_a_415_and_stores_nothing() {
        let f = fixture().await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/evil")
            .header(header::CONTENT_TYPE, r#"text/plain;x=""#)
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let res = f.app.clone().oneshot(f.owner_request("GET", "/evil")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "nothing may have been stored");
    }

    // §3.2, §11: a legal URL this pod cannot store.
    #[tokio::test]
    async fn an_over_long_path_segment_is_a_414() {
        let f = fixture().await;
        let long = "a".repeat(300);
        let res = f.app.clone().oneshot(f.owner_request("PUT", &format!("/{long}"))
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::URI_TOO_LONG);
    }

    // §8.5: an ACL the PDP cannot parse is not an ACL.
    #[tokio::test]
    async fn a_non_rdf_body_on_an_auxiliary_is_a_415() {
        let f = fixture().await;
        f.put_turtle("/subject", "").await;
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/.aux/acl/subject")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // §8.5: a container's representation is RDF, so the two asks contradict.
    #[tokio::test]
    async fn posting_a_non_rdf_body_as_a_container_is_a_400() {
        let f = fixture().await;
        let res = f.app.clone().oneshot(f.owner_request("POST", "/")
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::LINK, "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    // A blob is a container member exactly as an RDF resource is.
    #[tokio::test]
    async fn a_posted_blob_joins_and_leaves_its_container() {
        let f = fixture().await;
        let res = f.app.clone().oneshot(f.owner_request("POST", "/box/")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let loc = res.headers()[header::LOCATION].to_str().unwrap().to_owned();
        let child_path = loc.strip_prefix("https://pod.toph.so").unwrap().to_owned();

        let listing = f.get_turtle("/box/").await;
        assert!(listing.contains(&loc), "the blob is a member");

        let res = f.app.clone().oneshot(f.owner_request("DELETE", &child_path)
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let listing = f.get_turtle("/box/").await;
        assert!(!listing.contains(&loc), "and it leaves again");
    }
```

`owner_request` already exists (`src/http.rs:992`). `put_turtle` and `get_turtle` do not — add
them to the `impl Fixture` block beside it:

```rust
        async fn put_turtle(&self, path: &str, ttl: &str) {
            let res = self.app.clone().oneshot(self.owner_request("PUT", path)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(ttl.to_owned())).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::CREATED, "PUT {path}");
        }

        async fn get_turtle(&self, path: &str) -> String {
            let res = self.app.clone().oneshot(self.owner_request("GET", path)
                .header(header::ACCEPT, "text/turtle")
                .body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "GET {path}");
            let b = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
            String::from_utf8(b.to_vec()).unwrap()
        }
```

If an equivalent helper turns out to exist under another name, use that one rather than
adding a near-duplicate.

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib http 2>&1 | tail -30`
Expected: FAIL — the `text/plain` writes answer `415`.

- [ ] **Step 3: Write the classifier**

Add to `src/http.rs`, above `put_impl`:

```rust
/// What a request body is, once its `Content-Type` has been read.
enum Repr {
    Rdf(Dataset, Format),
    Blob(Bytes, MediaType),
}

/// §8.1: the three-way gate. `Err` is the response to send.
///
/// The order matters. A missing `Content-Type` on a request with content is
/// Solid Protocol §2.2's `400` and is answered before anything else, because
/// it is a different failure from a type this pod cannot use — a distinction
/// that only exists now that an unrecognised type is a blob rather than a
/// refusal.
fn classify_body(headers: &HeaderMap, body: &Bytes, target: &Target) -> Result<Repr, Response> {
    let ct = header_str(headers, header::CONTENT_TYPE).trim();
    if ct.is_empty() {
        if !body.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "Content-Type is required").into_response());
        }
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
    }
    if let Some(fmt) = Format::from_content_type(ct) {
        return match fmt.parse(body, target.graph_iri()) {
            Ok(d) => Ok(Repr::Rdf(d, fmt)),
            Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string()).into_response()),
        };
    }
    let Some(mt) = MediaType::parse(ct) else {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
    };
    match target {
        // §8.5: an auxiliary is a policy document the PDP has to read, and a
        // container's representation carries server-managed containment.
        Target::Aux(_) => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()),
        Target::Container(_) => Err((
            StatusCode::BAD_REQUEST,
            "a container's representation must be RDF",
        ).into_response()),
        Target::Resource(_) => Ok(Repr::Blob(body.clone(), mt)),
    }
}
```

Add `use crate::rdf::{Format, MediaType, Shape, negotiate};` to the imports and
`use crate::resource::{… , put_blob, kind_of, Kind};`.

- [ ] **Step 4: Rewire `put_impl`**

Replace `put_impl`'s `Format::from_content_type` gate and the `fmt.parse` block
(`src/http.rs:340-346`) with:

```rust
    let repr = match classify_body(&headers, &body, &target) {
        Ok(r) => r,
        Err(res) => return res,
    };
    let (dataset, fmt) = match &repr {
        Repr::Rdf(d, f) => (d.clone(), *f),
        Repr::Blob(bytes, mt) => {
            // A blob has none of the dataset checks below to run: no named
            // graphs, no reserved namespace, no containment triples. It does
            // share the conditional-request block and the ancestor walk, so it
            // rejoins the flow there rather than returning here.
            let Target::Resource(r) = &target else {
                unreachable!("classify_body refuses a blob for any other target")
            };
            if crate::blob::BlobKey::of(r).is_none() {
                return StatusCode::URI_TOO_LONG.into_response();
            }
            if let Err(res) = check_conditionals(store, &headers, &target).await {
                return res;
            }
            if let Err(res) = authorize_and_materialize(store, &agent, &target).await {
                return with_aux_links(res, &target);
            }
            return match put_blob(store, st.blobs.as_ref(), r, bytes.clone(), mt).await {
                Ok(()) => created(&target),
                Err(ResourceError::KeyTooLong) => StatusCode::URI_TOO_LONG.into_response(),
                Err(e) => (put_status(&e), e.to_string()).into_response(),
            };
        }
    };
```

Extract the existing `If-Match`/`If-None-Match` block (`src/http.rs:404-422`) into a helper
so both kinds share one implementation:

```rust
/// RFC 9110 §13.1.1 preconditions, shared by both kinds of write.
async fn check_conditionals(
    store: &dyn SparqlStore,
    headers: &HeaderMap,
    target: &Target,
) -> Result<(), Response> {
    if !headers.contains_key(IF_MATCH) && !headers.contains_key(IF_NONE_MATCH) {
        return Ok(());
    }
    let current_tags = match current_tags(store, target).await {
        Ok(t) => t,
        Err(e) => return Err((put_status(&e), e.to_string()).into_response()),
    };
    if let Some(im) = headers.get(IF_MATCH).and_then(|v| v.to_str().ok()) {
        // `If-Match` matches *any* current representation, not the one the
        // server would have picked.
        if !current_tags.as_ref().is_some_and(|ts| ts.iter().any(|t| t == im)) {
            return Err(StatusCode::PRECONDITION_FAILED.into_response());
        }
    }
    if headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some("*")
        && current_tags.is_some()
    {
        return Err(StatusCode::PRECONDITION_FAILED.into_response());
    }
    Ok(())
}
```

`current_tags` needs `blobs` to answer for a binary resource; that is Task 8. Until then it
compiles unchanged and answers with the RDF tags, which is wrong only for blobs and is fixed
there.

Replace the RDF path's inline conditional block with `check_conditionals(...)`, and add
`blobs` to the `put_dataset` call.

- [ ] **Step 5: Rewire `post_impl`**

Same gate, after the child name is settled so `classify_body` sees the child target:

```rust
    let repr = match classify_body(&headers, &body, &child) {
        Ok(r) => r,
        Err(res) => return res,
    };
```

Then in the dispatch at the end, add the blob arm:

```rust
        Target::Resource(r) => match repr {
            Repr::Blob(bytes, mt) => {
                match put_blob(store, st.blobs.as_ref(), r, bytes, &mt).await {
                    Ok(()) => created(&child),
                    Err(ResourceError::KeyTooLong) => StatusCode::URI_TOO_LONG.into_response(),
                    Err(e) => (put_status(&e), e.to_string()).into_response(),
                }
            }
            Repr::Rdf(..) => match put_dataset(store, st.blobs.as_ref(), r, &skolemized, fmt).await {
                Ok(()) => created(&child),
                Err(e) => (put_status(&e), e.to_string()).into_response(),
            },
        },
```

The dataset checks between the gate and the dispatch (`uses_reserved_namespace`,
`has_named_graphs`, `body_sets_containment`, `Skolemized::skolemize`) run only on the
`Repr::Rdf` arm; guard them with a `if let Repr::Rdf(dataset, fmt) = &repr` block rather than
duplicating the dispatch.

- [ ] **Step 6: Run tests to verify they pass**

Run: `nix develop -c cargo test --lib http 2>&1 | tail -20`
Expected: PASS for the write-side tests. The read-side ones
(`a_text_file_can_be_put_and_read_back_byte_for_byte`) still FAIL — that is Task 8.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs
git commit -m "feat: route non-RDF writes to the blob path

The Content-Type gate becomes three-way: a recognised RDF type parses, a
valid media type Format does not know is a blob, and a syntactically invalid
one is still 415. Separating those makes 'Content-Type absent' its own case,
so it answers 400 as Solid §2.2's normative text requires instead of being
conflated with 'unsupported'."
```

---

### Task 8: reading a blob

**Files:**
- Modify: `src/http.rs` (`get_impl`, `current_tags`, `SERVABLE` neighbourhood)
- Test: `src/http.rs` `mod tests`

**Interfaces:**
- Consumes: `kind_of`, `Kind`, `BlobStore::get`, `ranked_accept` (Task 2), `MediaType`.
- Produces: `pub(crate) fn accept_allows(accept: &str, mt: &MediaType) -> bool` in
  `src/rdf.rs`; `fn blob_etag(&[u8]) -> String` in `src/http.rs`.

`accept_allows` lands here rather than in Task 2 because this is the task that gives it a
production caller. Shipping it earlier would be a `dead_code` warning in a build that is
warning-free by rule.

- [ ] **Step 1: Write the failing tests**

In `src/rdf.rs`'s `mod tests`:

```rust
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
```
```

In `src/http.rs`'s `mod tests`:

```rust
    // §3.4: the validator is computed from the served bytes, so the same bytes
    // give the same tag and one byte's difference gives a different one.
    #[tokio::test]
    async fn a_blob_carries_a_strong_validator_and_answers_conditionally() {
        let f = fixture().await;
        f.put_blob("/a.txt", "text/plain", b"hello").await;
        f.put_blob("/b.txt", "text/plain", b"hello").await;
        f.put_blob("/c.txt", "text/plain", b"hellp").await;

        let ta = f.etag_of("/a.txt").await;
        assert_eq!(ta, f.etag_of("/b.txt").await, "same bytes, same tag");
        assert_ne!(ta, f.etag_of("/c.txt").await, "one byte apart, different tag");

        let res = f.app.clone().oneshot(f.owner_request("GET", "/a.txt")
            .header(header::IF_NONE_MATCH, &ta)
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);

        // A stale If-Match must refuse the write rather than overwrite it.
        let res = f.app.clone().oneshot(f.owner_request("PUT", "/a.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::IF_MATCH, "\"0000000000000000000000000000000000000000000000000000000000000000\"")
            .body(Body::from("new")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
    }

    // §6.1. Both halves matter: without the admitting cases an accept_allows
    // that always refuses would pass.
    #[tokio::test]
    async fn accept_decides_whether_a_blob_is_servable() {
        let f = fixture().await;
        f.put_blob("/pic.png", "image/png", b"png").await;

        for accept in ["*/*", "image/*", "image/png", "text/turtle, image/png"] {
            let res = f.app.clone().oneshot(f.owner_request("GET", "/pic.png")
                .header(header::ACCEPT, accept).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "Accept: {accept}");
        }
        for accept in ["text/turtle", "text/*", "image/png;q=0", "*/*, image/png;q=0"] {
            let res = f.app.clone().oneshot(f.owner_request("GET", "/pic.png")
                .header(header::ACCEPT, accept).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE, "Accept: {accept}");
        }
    }

    // §6.2: the pod's namespace still says the resource exists, but there is
    // nothing to serve. 500 would read as "my fault, retry".
    #[tokio::test]
    async fn a_blob_whose_object_vanished_is_a_404_with_a_warning() {
        let f = fixture().await;
        f.put_blob("/gone.txt", "text/plain", b"x").await;

        // Emptied from underneath, exactly as an operator or another writer
        // on a shared bucket would.
        let r = match f.space.resolve("/gone.txt").unwrap() {
            crate::space::Target::Resource(r) => r,
            _ => panic!("resource"),
        };
        let key = crate::blob::BlobKey::of(&r).unwrap();
        f.blobs.delete(&key).await.unwrap();

        let res = f.app.clone().oneshot(f.owner_request("GET", "/gone.txt")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().contains_key(header::WARNING));
    }

    // §10: the claim the whole plan exists to make testable.
    #[tokio::test]
    async fn wac_governs_a_blob_exactly_as_it_governs_a_graph() {
        let f = fixture().await;
        f.put_blob("/secret.txt", "text/plain", b"s3cret").await;
        f.put_turtle("/.aux/acl/secret.txt", &format!(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> . \
             <#owner> a acl:Authorization ; \
               acl:agent <{OWNER}> ; \
               acl:accessTo <https://pod.toph.so/secret.txt> ; \
               acl:mode acl:Read, acl:Write, acl:Control ."
        )).await;

        // Anonymous: the ACL names only the owner.
        let res = f.app.clone().oneshot(Request::builder()
            .method("GET").uri("/secret.txt").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = f.app.clone().oneshot(f.owner_request("GET", "/secret.txt")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
```

Add these `Fixture` helpers next to the existing ones:

```rust
        async fn put_blob(&self, path: &str, ct: &str, body: &'static [u8]) {
            let res = self.app.clone().oneshot(self.owner_request("PUT", path)
                .header(header::CONTENT_TYPE, ct)
                .body(Body::from(body)).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::CREATED, "PUT {path}");
        }

        async fn etag_of(&self, path: &str) -> String {
            let res = self.app.clone().oneshot(self.owner_request("GET", path)
                .body(Body::empty()).unwrap()).await.unwrap();
            res.headers()[header::ETAG].to_str().unwrap().to_owned()
        }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `nix develop -c cargo test --lib http 2>&1 | tail -30`
Expected: FAIL — `get_impl` runs the dataset path and answers `404` or `500` for a blob.

- [ ] **Step 3: Write `accept_allows`**

In `src/rdf.rs`, directly after `ranked_accept`:

```rust
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
```

- [ ] **Step 3b: Write the read path**

Add above `get_impl`:

```rust
/// §3.4: the validator for a blob, computed from the bytes about to be served.
///
/// Not `ObjectMeta::e_tag`: it is optional, its meaning differs per backend,
/// and it changes under a backend migration although the content did not. This
/// is the same rule and the same shape as
/// [`Skolemized::etag`](crate::dataset::Skolemized::etag).
fn blob_etag(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("\"{}\"", hex::encode(h.finalize()))
}
```

At the top of `get_impl`, after the `Target::Resource` destructure and before the
`get_dataset` call:

```rust
    // §6: which kind this is, then the matching read. Both kinds share
    // authorization, the auxiliary advertisement and the `Allow` header above
    // and below; only the representation differs.
    match kind_of(store, r).await {
        // `st.clone()` rather than a move: `store` above borrows `st.store`,
        // and `AppState` is `Clone` over `Arc`s, so this costs two refcounts.
        Ok(Some(Kind::Binary(mt))) => return blob_read(st.clone(), target.clone(), headers, mt).await,
        Ok(Some(Kind::Rdf)) => {}
        Ok(None) => return with_aux_links(StatusCode::NOT_FOUND.into_response(), &target),
        Err(ResourceError::InvalidIri) => return StatusCode::BAD_REQUEST.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
```

And the read itself:

```rust
/// §6: a blob's representation. `Accept` is an acceptability test rather than
/// a negotiation, because there is only one representation to offer.
async fn blob_read(st: AppState, target: Target, headers: HeaderMap, mt: MediaType) -> Response {
    let Target::Resource(r) = &target else {
        unreachable!("only a resource can be binary")
    };
    if !accept_allows(header_str(&headers, header::ACCEPT), &mt) {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    let Some(key) = crate::blob::BlobKey::of(r) else {
        return StatusCode::URI_TOO_LONG.into_response();
    };
    let bytes = match st.blobs.get(&key).await {
        Ok(Some(b)) => b,
        // §6.2: the pod's namespace still says this exists; the backend has
        // nothing to hand over. A `500` would read as "my fault, retry".
        Ok(None) => {
            let mut out = HeaderMap::new();
            if let Some(w) = warning_header("the storage backend has no object for this resource") {
                out.insert(header::WARNING, w);
            }
            return with_aux_links((StatusCode::NOT_FOUND, out).into_response(), &target);
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let tag = blob_etag(&bytes);
    let mut out = HeaderMap::new();
    out.insert(header::ETAG, tag.parse().expect("etag is header-safe"));
    out.insert(header::VARY, "Accept".parse().expect("static"));
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
        return with_allow(with_aux_links((StatusCode::NOT_MODIFIED, out).into_response(), &target), &target);
    }
    out.insert(
        header::CONTENT_TYPE,
        // Every byte came through `MediaType::parse`, which admits only RFC
        // 9110 tchars plus `/`, `;`, `=` and space.
        mt.as_str().parse().expect("a MediaType is header-safe"),
    );
    with_allow(with_aux_links((out, bytes).into_response(), &target), &target)
}
```

- [ ] **Step 4: Give `current_tags` a blob branch**

`current_tags` builds one validator per `SERVABLE` format because an RDF resource has five
representations. A blob has one. Add `blobs: &dyn crate::blob::BlobStore` as its second
parameter, and at the top of the `Target::Resource` arm:

```rust
        if let Some(Kind::Binary(_)) = kind_of(store, r).await? {
            let Some(key) = crate::blob::BlobKey::of(r) else {
                return Ok(None);
            };
            return Ok(blobs.get(&key).await?.map(|b| vec![blob_etag(&b)]));
        }
```

Thread `blobs` through `check_conditionals` from Task 7 and its two call sites.

Update the doc comment above `SERVABLE`: it explains why a *resource* gets one tag per
format; add that a binary resource has a single representation and therefore a single tag.

- [ ] **Step 5: Run the whole suite**

Run: `nix develop -c cargo test 2>&1 | tail -10`
Expected: PASS, including Task 7's byte-fidelity test.

- [ ] **Step 6: Verify the Accept tests bite, both of them**

Specificity first — this is the one most likely to be wrong. Temporarily replace
`accept_allows`'s body with
`ranked_accept(accept).iter().any(|(q, _, r)| *q > 0.0 && (*r == "*/*" || *r == essence))`.
Run `nix develop -c cargo test --lib rdf::tests::accept_allows_honours`. Expected: FAIL on
`"*/*, image/png;q=0"` — RFC 9110 §12.5.1 makes a more specific range override a less
specific one, so neither order nor highest-q gives the right answer. Revert.

Then the wiring. Temporarily make `blob_read` skip the `accept_allows` check. Run
`nix develop -c cargo test --lib http::tests::accept_decides`. Expected: FAIL on the
refusing half. Then make it `return NOT_ACCEPTABLE` unconditionally: expected FAIL on the
admitting half. Revert.

- [ ] **Step 7: Commit**

```bash
git add src/http.rs
git commit -m "feat: serve non-RDF resources

The validator is sha256 over the served bytes rather than the backend's own
ETag: that one is optional, means different things per backend, and changes
under a migration although the content did not. An object missing while its
marker is present answers 404 with a Warning — the namespace still says the
resource exists, and 500 would read as a retryable server fault."
```

---

### Task 9: `content-type-reject` in the findings, and the conformance run

**Files:**
- Modify: `docs/conformance-findings.md`, `conformance/README.md`
- Test: the suite itself

- [ ] **Step 1: Run the suite**

Run: `./conformance/run.sh` (~4 min including the build)

- [ ] **Step 2: Regenerate the per-feature table**

```bash
jq -r '.featureSummary[] | "\(.passedCount)/\(.scenarioCount)\t\(.relativePath)"' \
  conformance/.run/karate/karate-reports/karate-summary-json.txt | sort
```

- [ ] **Step 3: Write the third run into the findings**

Add a "Third run — after Plan 10" section beside the existing two, with the same table shape
(date, pod commit, features / scenarios / passed / failed). Then:

- Reconcile the delta explicitly, feature by feature, the way the second run does. A bare
  aggregate is not a reconciliation.
- Move `content-type-reject` out of Bucket 2 into Bucket 3 as a resolved defect, with the
  reasoning from spec §9: the conflation argument does not survive the three-way gate, the
  RFC 9110 citation was half-read, and Solid Protocol §2.2 names `400` in its normative
  text.
- Rewrite the "One gap accounts for almost everything" section. Rank 1 is gone; whatever the
  run shows is the new ranking, and the ~81 rows the second run projected would fall through
  to `OPTIONS`/`PATCH` now have a measured number instead of an estimate.
- Any newly-failing scenario that was previously blocked is a **new finding**, not a
  regression, and belongs in a bucket with a named cause. Bucket 4 must end at 0.

- [ ] **Step 4: Commit**

```bash
git add docs/conformance-findings.md conformance/README.md
git commit -m "docs: third conformance run — non-RDF resources"
```

---

### Task 10: constraints, the normative doc, and the final sweep

**Files:**
- Modify: `docs/constraints.md`, `docs/uri-space.md`

- [ ] **Step 1: Add the two constraints**

Append to `docs/constraints.md` under "Storage addressing":

```markdown
Only `blob::BlobKey` builds an object key.
    → 2026-07-29-non-rdf-resources-design.md §3.2. The key is the resource's
    own path, so two resources sharing one object is a cross-resource read and
    write — the same failure `ShelfKey` guards against one layer up. It is also
    what the derived-key argument rests on: an interrupted write heals only
    because every writer computes the same key from the same URL.
    check: ! rg -q 'Path::(from|parse)' src --glob '!src/blob.rs'
```

and under "Boundaries that have no compiler behind them":

```markdown
The `Accept` header is parsed in exactly one place.
    → 2026-07-29-non-rdf-resources-design.md §6.1. `negotiate` and
    `accept_allows` ask different questions of the same header. The existing
    negotiation rule pins that two *named* functions do not return; this pins
    the property those names stood for. The q-value parse is what a second
    reader cannot avoid rewriting, which is what makes this fail against a real
    violation rather than against a naming convention.
    check: [ "$(rg -o 'strip_prefix\("q="\)' src | wc -l)" = 1 ]
```

- [ ] **Step 2: Demonstrate both go red**

For the first: add `let _ = object_store::path::Path::from("x");` to `src/resource.rs`. Run
`arch-check --only 'object key'`. Expected: non-zero exit. Remove it.

For the second: copy the `strip_prefix("q=")` line into a second function in `src/rdf.rs`.
Run `arch-check --only 'Accept header'`. Expected: non-zero exit. Remove it.

`docs/constraints.md` requires this: *"Every rule here was demonstrated to go red against a
real violation before it was added."*

- [ ] **Step 3: Correct the normative doc**

In `docs/uri-space.md`, "Server-asserted facts are not auxiliary resources", replace the
first sentence. It currently reads:

> Creation and modification times, byte size, content hash and storage keys are **not**
> addressable and not writable. They live in an internal graph (`urn:quadpod:sys:<res>`) and
> are exposed through the HTTP headers that already exist for them — `Last-Modified`,
> `ETag`, `Content-Length`.

Rewrite it in the present tense, keeping the part that carries the meaning (these are the
server's assertions, never addressable, never writable, surfaced through headers) and
dropping the claim that byte size and content hash are kept anywhere. State positively what
the internal graph does hold — existence, the kind of representation, and the media type it
arrived as — and why the rest is not stored: the pod does not exclusively own the bytes
behind a swappable backend, so a stored size or hash goes silently false when something else
writes to the same bucket. The storage key is derived from the resource's own URL rather than
recorded.

Do not add a changelog line. This document is overwritten in place; the *why* goes in the
commit message.

- [ ] **Step 4: Full verification**

```bash
nix develop -c cargo clippy --all-targets   # clean
nix develop -c cargo build 2>&1 | grep -i warning   # prints nothing
nix develop -c cargo test                   # all green
arch-check                                  # 0/12 rot
rg -n '#\[allow' src                        # no hits
```

- [ ] **Step 5: Commit**

```bash
git add docs/constraints.md docs/uri-space.md
git commit -m "docs: constrain the object key and the Accept parser

uri-space.md promised byte size, content hash and storage keys live in
urn:quadpod:sys:<res>. None of them do, and the reason is not tidiness: with
a swappable backend the pod does not exclusively own the bytes, so a stored
size or hash goes silently false the moment anything else writes to the
bucket. The key is derived from the URL instead of recorded."
```

---

## Verification Summary

```bash
nix develop -c cargo test                    # every test above
nix develop -c cargo clippy --all-targets    # clean
nix develop -c cargo build 2>&1 | grep -i warning   # nothing
arch-check                                   # 0/12 rot
rg -n '#\[allow' src                         # no hits
./conformance/run.sh                         # numbers into the findings doc
```

**What is not promised:** that the 540 blocked scenarios turn green. They become *runnable*.
The findings project ~81 falling straight through to `OPTIONS`/`PATCH`, both separate plans.
The honest number is knowable only after Task 9's run.

## What this plan does not do

- **`Range` and streaming.** `object_store`'s `get_opts` already carries range and ETag
  matching, so it is an extension rather than a rebuild — and the point at which computing
  the validator from the whole object is worth re-litigating.
- **S3 / Ceph backends.** `ObjectStoreBlobs` holds an `Arc<dyn ObjectStore>`, so this is a
  Cargo feature flag plus one `--blob-store` arm, not a design change. Left out because it
  cannot be tested without a live endpoint, and untested backend glue is worse than an
  honest `Err` from `Config::blobs`.
- **Serving a pod over an existing directory.** Spec §13, with the three decisions it must
  reopen already written down.
- **`OPTIONS`, `WAC-Allow`, CORS, `PATCH`.** Ranks 2–6 of the findings; several become
  measurable only once this lands.
- **Orphan collection**, **persistence for the SPARQL store**, **`Last-Modified`**.
