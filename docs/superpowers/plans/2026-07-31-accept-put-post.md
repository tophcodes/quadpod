# `Accept-Put` / `Accept-Post` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit `Accept-Put` and `Accept-Post` wherever the pod already emits `Allow` and
`Accept-Patch`, with values derived from `Format` and carrying the `version` parameter.

**Architecture:** `Format` gains `ALL`, and `from_content_type` searches it instead of matching
five literals — the same shape `AuxKind::ALL` already has in `aux_links`. `http.rs` builds the
field value from that array plus `*/*` where `classify_body` admits a blob, and inserts it at
the two sites that already produce `Allow`: `with_allow` and `options_impl`. Both take
`RdfVersion` as a value; neither reaches the store.

**Tech Stack:** Rust, axum, oxigraph. Tests are `#[tokio::test]` inside `src/http.rs`'s and
`src/rdf.rs`'s own `mod tests`, run with `cargo test`.

**Spec:** [`docs/superpowers/specs/2026-07-31-accept-put-post-design.md`](../specs/2026-07-31-accept-put-post-design.md)

## Global Constraints

- `arch-check` must stay green — 21 rules today, 22 after Task 4. Run it before every commit.
- No `#[allow]` attributes anywhere in `src/` (`constraints.md`).
- `cargo clippy --all-targets -- -D warnings` is the bar, not `cargo build`.
- The advertised version label is `SparqlStore::rdf_version().label()`, which is `1.2` for the
  only implementor. Tests may spell `1.2` literally; production code may not.
- Conventional commits. Commit at the end of every task.

## File structure

| File | Responsibility | Change |
|---|---|---|
| `src/rdf.rs` | owns which media types parse | `Format::ALL`; `from_content_type` searches it |
| `src/http.rs` | owns what the wire says | value builder, two insert sites, threading, CORS |
| `docs/constraints.md` | the checks | one new rule |
| `docs/superpowers/specs/2026-07-28-jsonld-datasets-design.md` | historical design | one stale clause |
| `docs/superpowers/specs/2026-07-31-accept-put-post-design.md` | this design | §6's check, corrected |

---

### Task 1: `Format::ALL` becomes the one list

**Files:**
- Modify: `src/rdf.rs:207-233` (`impl Format`: `from_content_type`, `media_type`)
- Test: `src/rdf.rs` `mod tests`

**Interfaces:**
- Consumes: nothing.
- Produces: `Format::ALL: [Format; 5]` — public, `Copy`, order is Turtle, N-Triples, JSON-LD,
  TriG, N-Quads. `Format::media_type(&self) -> &'static str` is unchanged and stays total.

- [ ] **Step 1: Write the failing test**

In `src/rdf.rs`, inside `mod tests`:

```rust
/// `ALL` is what `Accept-Put` is built from, and `from_content_type` is what
/// the write path admits. A format in one and not the other is either an
/// advertisement for a type that is refused, or a type that works and cannot
/// be discovered — so the two are one array, and this is that array's test.
#[test]
fn every_advertised_format_is_a_format_the_write_path_parses() {
    for f in Format::ALL {
        assert_eq!(
            Format::from_content_type(f.media_type()),
            Some(f),
            "{} is advertised but not parsed",
            f.media_type()
        );
    }
    let mut seen: Vec<&str> = Format::ALL.iter().map(|f| f.media_type()).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), Format::ALL.len(), "two entries share a media type");
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test --lib rdf::tests::every_advertised_format`
Expected: FAIL — `error[E0599]: no associated item named 'ALL' found for struct 'Format'`.

- [ ] **Step 3: Add `ALL` and rewrite `from_content_type` to search it**

In `src/rdf.rs`, replace the body of `from_content_type` and add `ALL` above it:

```rust
impl Format {
    /// Every format the write path parses, and therefore every format
    /// `Accept-Put` and `Accept-Post` name. One array rather than a second
    /// literal list beside the parser: `aux_links` builds from `AuxKind::ALL`
    /// for the same reason, and for the same failure — an advertisement and a
    /// gate that disagree are both individually plausible.
    pub const ALL: [Self; 5] = [
        Self(RdfFormat::Turtle),
        Self(RdfFormat::NTriples),
        Self(RdfFormat::JsonLd { profile: JsonLdProfileSet::empty() }),
        Self(RdfFormat::TriG),
        Self(RdfFormat::NQuads),
    ];

    /// The formats this pod accepts on write, from a `Content-Type`.
    /// Media-type tokens are case-insensitive per RFC 9110 §8.3.1.
    pub fn from_content_type(ct: &str) -> Option<Self> {
        let mt = media_type(ct).to_ascii_lowercase();
        Self::ALL.into_iter().find(|f| f.media_type() == mt)
    }
```

`media_type` keeps its `match` untouched — it is the definition this search reads.

If `JsonLdProfileSet::empty()` is not a `const fn`, `ALL` cannot be a `const`. Then, and only
then, make it an associated function with the same name spelled `pub fn all() -> [Self; 5]` and
adjust the test and Task 2 to call it. Check first:
`rg -n 'pub const fn empty' ~/.cargo/registry/src/*/oxigraph-*/ 2>/dev/null` — or just compile.

- [ ] **Step 4: Import `JsonLdProfileSet` if it is not already in scope**

Run: `rg -n 'JsonLdProfileSet' src/rdf.rs`
If the only hit is inside `from_content_type`'s old body, the type is named through a path
(`oxigraph::io::JsonLdProfileSet`); keep that same path in `ALL` rather than adding an import.

- [ ] **Step 5: Run the test and the whole suite**

Run: `cargo test --lib rdf::` then `cargo test`
Expected: PASS. Every existing `from_content_type` caller keeps working — the function's
contract is unchanged, only its body is.

- [ ] **Step 6: Clippy and commit**

```bash
cargo clippy --all-targets -- -D warnings
git add src/rdf.rs
git commit -m "refactor(rdf): Format::ALL is the one list of writable media types"
```

---

### Task 2: the advertisement, built and emitted

**Files:**
- Modify: `src/http.rs:180-195` (`ACCEPT_PATCH`, `with_allow`), `src/http.rs:224-232`
  (`with_read_headers`), `src/http.rs:1432-1442` (`options_impl`), and the seven call sites
  listed in Step 5
- Test: `src/http.rs` `mod tests`

**Interfaces:**
- Consumes: `Format::ALL` (Task 1); `RdfVersion::label(self) -> &'static str`;
  `SparqlStore::rdf_version(&self) -> RdfVersion`.
- Produces:
  - `enum Write { Put, Post }` — private to `http.rs`.
  - `fn accept_write(target: &Target, method: Write, version: RdfVersion) -> Option<String>` —
    `None` where `allowed_methods` does not permit that method at that target.
  - `fn with_allow(res: Response, target: &Target, version: RdfVersion) -> Response`
  - `fn with_read_headers(res: Response, target: &Target, decision: &Decision, version: RdfVersion) -> Response`
  - `fn options_impl(target: &Target, headers: &HeaderMap, version: RdfVersion) -> Response`

- [ ] **Step 1: Write the failing tests**

In `src/http.rs`, inside `mod tests`, beside `allow_and_accept_patch_advertise_the_method`:

```rust
/// Protocol §5.3: the three `Accept-*` headers are one MUST, and the two new
/// ones are checked on every target shape for the reason the `Accept-Patch`
/// test above gives — `allowed_methods` has three arms.
#[tokio::test]
async fn accept_put_advertises_every_writable_format_and_version() {
    let f = fixture().await;
    f.put_turtle("/c/thing", "<#a> <http://example.org/b> \"c\" .").await;

    for path in ["/c/thing", "/c/", "/"] {
        let get = f.app.clone().oneshot(f.owner_request("GET", path)
            .header(header::ACCEPT, "text/turtle")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(get.status(), StatusCode::OK, "GET {path}");
        let put = get.headers()["accept-put"].to_str().unwrap().to_string();

        let opt = f.app.clone().oneshot(Request::builder()
            .method("OPTIONS").uri(path).body(Body::empty()).unwrap()).await.unwrap();
        let opt_put = opt.headers()["accept-put"].to_str().unwrap().to_string();
        assert_eq!(put, opt_put, "GET and OPTIONS must advertise the same thing at {path}");

        for fmt in Format::ALL {
            let mt = fmt.media_type();
            assert!(put.contains(mt), "{path} Accept-Put lacks {mt}: {put}");
            // Both halves are true: an absent `version` parameter *is* 1.1
            // (`RdfVersion::from_media_type`), so the bare type and the
            // versioned type are two acceptable representations, not one.
            assert!(
                put.contains(&format!("{mt};version=1.2")),
                "{path} Accept-Put lacks {mt};version=1.2: {put}"
            );
        }
    }
}

/// Each header reaches exactly as far as `Allow` does, and `*/*` appears
/// exactly where `classify_body` admits a blob. A container's own
/// representation must be RDF; an auxiliary's must be too.
#[tokio::test]
async fn the_write_advertisement_is_scoped_to_what_the_target_allows() {
    let f = fixture().await;
    f.put_turtle("/c/thing", "<#a> <http://example.org/b> \"c\" .").await;

    let container = f.app.clone().oneshot(Request::builder()
        .method("OPTIONS").uri("/c/").body(Body::empty()).unwrap()).await.unwrap();
    let post = container.headers()["accept-post"].to_str().unwrap();
    assert!(post.contains("*/*"), "a POSTed child may be a blob: {post}");
    assert!(post.contains("text/turtle"), "{post}");
    let put = container.headers()["accept-put"].to_str().unwrap();
    assert!(!put.contains("*/*"), "a container's own representation must be RDF: {put}");

    let resource = f.app.clone().oneshot(Request::builder()
        .method("OPTIONS").uri("/c/thing").body(Body::empty()).unwrap()).await.unwrap();
    assert!(resource.headers()["accept-put"].to_str().unwrap().contains("*/*"));
    assert!(
        resource.headers().get("accept-post").is_none(),
        "POST is not in a resource's Allow, so it must not be advertised"
    );

    let aux = f.app.clone().oneshot(Request::builder()
        .method("OPTIONS").uri("/.aux/thing.acl").body(Body::empty()).unwrap()).await.unwrap();
    let aux_put = aux.headers()["accept-put"].to_str().unwrap();
    assert!(aux_put.contains("text/turtle"), "{aux_put}");
    assert!(!aux_put.contains("*/*"), "an auxiliary is a policy document, never a blob: {aux_put}");
    assert!(aux.headers().get("accept-post").is_none());
}
```

`Format` may need importing in the test module — `mod tests` starts with `use super::*;` and
`http.rs` already imports `Format`, so no change is expected. If the compiler disagrees, add
`use crate::rdf::Format;` to the test module rather than widening the outer import.

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test --lib http::tests::accept_put http::tests::the_write_advertisement`
Expected: FAIL — both panic on the missing header (`accept-put` index panics with
`key not found`).

- [ ] **Step 3: Build the value**

In `src/http.rs`, directly below `ACCEPT_PATCH` (which stays exactly as it is — `text/n3` is not
a `Format`, so a constant is honest there and would be a second list here):

```rust
/// Which write method an advertisement describes. A two-arm enum rather than
/// a `bool`, for the reason `Shape` is one: `accept_write(&target, true, v)`
/// says nothing at the call site.
#[derive(Debug, Clone, Copy)]
enum Write {
    Put,
    Post,
}

/// What may be written here, as an `Accept-Put`/`Accept-Post` field value.
///
/// `None` where [`allowed_methods`] does not permit the method: `POST`
/// addresses containers alone, and a header naming a method the same response
/// refuses in `Allow` is worse than an absent one.
///
/// Every RDF format appears twice — bare, and with the store's own `version`
/// label. Both are true: [`RdfVersion::from_media_type`] reads an *absent*
/// parameter as `Rdf11`, so the two spellings are two acceptable
/// representations. The versioned twin is dropped on an `Rdf11` store, where
/// it would be a second spelling of the first entry. Only the store's maximum
/// is named; a lower `version` is accepted (`classify_body` refuses only
/// `declared > store_version`) and is what the bare entry already covers.
///
/// `*/*` is [LDP §4.5.2][ldp]'s "any media type", and it is `classify_body`'s
/// blob arm read back out: a `POST`ed child and a `PUT` resource may be
/// blobs; a container's own representation and an auxiliary may not.
///
/// [ldp]: https://www.w3.org/TR/ldp/#ldpc-post-acceptposthdr
fn accept_write(target: &Target, method: Write, version: RdfVersion) -> Option<String> {
    let blobs = match (target, method) {
        (Target::Container(_), Write::Post) | (Target::Resource(_), Write::Put) => true,
        (Target::Container(_) | Target::Aux(_), Write::Put) => false,
        (Target::Resource(_) | Target::Aux(_), Write::Post) => return None,
    };
    let mut types = Vec::new();
    for f in Format::ALL {
        types.push(f.media_type().to_string());
        if version > RdfVersion::Rdf11 {
            types.push(format!("{};version={}", f.media_type(), version.label()));
        }
    }
    if blobs {
        types.push("*/*".to_string());
    }
    Some(types.join(", "))
}
```

- [ ] **Step 4: Emit it at the two sites that already emit `Allow`**

Replace `with_allow` (`src/http.rs:186`):

```rust
/// Attach [`allowed_methods`] to a read that succeeded — Protocol §4.1 makes
/// it a MUST on `GET`/`HEAD` — alongside the three `Accept-*` headers §5.3
/// makes a MUST beside it.
fn with_allow(mut res: Response, target: &Target, version: RdfVersion) -> Response {
    res.headers_mut().insert(
        header::ALLOW,
        allowed_methods(target).parse().expect("method list is header-safe"),
    );
    res.headers_mut().insert("accept-patch", HeaderValue::from_static(ACCEPT_PATCH));
    for (name, method) in [("accept-put", Write::Put), ("accept-post", Write::Post)] {
        if let Some(value) = accept_write(target, method, version) {
            res.headers_mut().insert(
                name,
                value.parse().expect("media types and version labels are header-safe"),
            );
        }
    }
    res
}
```

And `options_impl` (`src/http.rs:1432`), adding the parameter and the same three lines:

```rust
fn options_impl(target: &Target, headers: &HeaderMap, version: RdfVersion) -> Response {
    let mut out = HeaderMap::new();
    let methods = allowed_methods(target);
    out.insert(header::ALLOW, HeaderValue::from_static(methods));
    out.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(methods));
    out.insert("accept-patch", HeaderValue::from_static(ACCEPT_PATCH));
    for (name, method) in [("accept-put", Write::Put), ("accept-post", Write::Post)] {
        if let Some(value) = accept_write(target, method, version) {
            out.insert(name, value.parse().expect("media types and version labels are header-safe"));
        }
    }
    if let Some(requested) = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
    }
    (StatusCode::NO_CONTENT, out).into_response()
}
```

Extend `options_impl`'s existing doc comment — the paragraph justifying an unauthorized answer
says *"`allowed_methods` takes a `Target` and never reaches the store"*. Append one sentence so
the claim stays exact:

> The `RdfVersion` this now also takes is a deployment constant
> (`SparqlStore::rdf_version`), not a lookup — the answer is still derived from the request
> URL's shape and discloses nothing about what exists.

- [ ] **Step 5: Thread `RdfVersion` through the seven call sites**

`with_read_headers` gains the parameter and forwards it:

```rust
fn with_read_headers(
    res: Response, target: &Target, decision: &Decision, version: RdfVersion,
) -> Response {
    let mut res = with_allow(with_aux_links(res, target), target, version);
```

Every caller already holds `st`. Pass `st.store.rdf_version()`:

| Line (pre-edit) | Function | Call |
|---|---|---|
| 1448 | `handle_options` | `options_impl(&target, &headers, st.store.rdf_version())` |
| 1455 | `handle_options_root` | `options_impl(&target, &headers, st.store.rdf_version())` |
| 1610 | `blob_read` | `with_allow(…, &target, st.store.rdf_version())` |
| 1615 | `blob_read` | `with_allow(…, &target, st.store.rdf_version())` |
| 1677 | `get_impl` | `with_read_headers(…, &decision, st.store.rdf_version())` |
| 1744 | `get_impl` | `with_read_headers(…, &decision, st.store.rdf_version())` |
| 1777, 1801 | `legacy_graph_read` | `with_read_headers(…, decision, st.store.rdf_version())` |

`get_impl` and `legacy_graph_read` bind `let store = st.store.as_ref();` at the top; either
`store.rdf_version()` or `st.store.rdf_version()` compiles. Use `store.rdf_version()` there so
the borrow already in scope is the one used.

Run: `cargo build 2>&1 | rg '^error' -A 3` and fix any call site the table missed — the compiler
enumerates them, so no site can be forgotten.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib http::`
Expected: PASS, including the two new tests and the untouched
`allow_and_accept_patch_advertise_the_method`.

- [ ] **Step 7: Clippy and commit**

```bash
cargo clippy --all-targets -- -D warnings
git add src/http.rs
git commit -m "feat(http): advertise Accept-Put and Accept-Post"
```

---

### Task 3: make both readable cross-origin

**Files:**
- Modify: `src/http.rs:54-55` (`EXPOSED_HEADERS`)
- Test: `src/http.rs` `mod tests`

**Interfaces:**
- Consumes: Task 2's headers.
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Beside `accept_patch_is_exposed_to_cross_origin_readers`:

```rust
/// A browser cannot read a response header that is not enumerated here, so
/// an advertisement missing from this list is invisible to exactly the
/// clients that most need to discover what they may write.
#[tokio::test]
async fn the_write_advertisement_is_exposed_to_cross_origin_readers() {
    let f = fixture().await;
    f.put_turtle("/thing", "<#a> <http://example.org/b> \"c\" .").await;

    let res = f.app.clone().oneshot(f.owner_request("GET", "/thing")
        .header(header::ORIGIN, "https://app.example")
        .header(header::ACCEPT, "text/turtle")
        .body(Body::empty()).unwrap()).await.unwrap();
    let exposed = res.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS].to_str().unwrap();
    assert!(exposed.contains("Accept-Put"), "{exposed}");
    assert!(exposed.contains("Accept-Post"), "{exposed}");
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test --lib http::tests::the_write_advertisement_is_exposed`
Expected: FAIL — `assertion failed` on `Accept-Put`, printing the current list.

- [ ] **Step 3: Extend the list**

```rust
const EXPOSED_HEADERS: &str =
    "Accept-Patch, Accept-Post, Accept-Put, Allow, Content-Type, ETag, Link, Location, Vary, WAC-Allow, Warning, WWW-Authenticate";
```

Alphabetical, as the list already is.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib http::`
Expected: PASS. `protocol/cors/enumerate-headers` requires the value to differ from `*`, which
it still does.

- [ ] **Step 5: Commit**

```bash
cargo clippy --all-targets -- -D warnings
git add src/http.rs
git commit -m "feat(http): expose the write advertisement to cross-origin readers"
```

---

### Task 4: pin it, and correct two documents

**Files:**
- Modify: `docs/constraints.md` (append to the section holding the negotiation rules)
- Modify: `docs/superpowers/specs/2026-07-28-jsonld-datasets-design.md:528`
- Modify: `docs/superpowers/specs/2026-07-31-accept-put-post-design.md` §6

**Interfaces:** none.

- [ ] **Step 1: Demonstrate the check goes red before adding it**

The rule anchors on the loop, the way `GraphName stays sealed` anchors on a signature. Prove it
fails against the violation it names — replace the loop head in `accept_write` with a literal
list, temporarily:

```bash
rg -q 'for f in Format::ALL' src/http.rs && echo GREEN || echo RED
```
Expected now: `GREEN`. Then check out a scratch edit that hand-writes
`for mt in ["text/turtle", "application/trig", …]` in place of the loop, re-run, expect `RED`,
and `git checkout src/http.rs`.

- [ ] **Step 2: Add the rule**

Append to `docs/constraints.md`, under the heading that already holds
*"There is one content-negotiation path, one parser and one ETag"*:

```markdown
The write advertisement is built from `Format::ALL`.
    → 2026-07-31-accept-put-post-design.md §2, §6. `Accept-Put` and
    `Accept-Post` name the media types `classify_body` admits, and a
    hand-maintained second list is how the header comes to advertise a type
    the parser refuses — a disagreement invisible from either side, because
    both halves keep looking plausible on their own. `aux_links` builds from
    `AuxKind::ALL` for the same reason. Anchored on the loop rather than on
    the absence of literals: `http.rs` legitimately names `application/trig`
    and `application/ld+json` in the `rel="alternate"` links of §6.2, and
    every format by name across its tests.
    check: rg -q 'for f in Format::ALL' src/http.rs
```

- [ ] **Step 3: Run all the checks**

Run: `arch-check`
Expected: 22 checked, 0 violated.

- [ ] **Step 4: Correct the two specs**

In `2026-07-28-jsonld-datasets-design.md`, the sentence at §6.3 reading *"Both are
undiscoverable: the pod emits no `Accept-Put`/`Accept-Post` and has no `OPTIONS` route."* Both
halves are now stale. Replace with:

> Both were undiscoverable when this was written: the pod emitted no
> `Accept-Put`/`Accept-Post` and had no `OPTIONS` route. **Named follow-up (§11)**, closed by
> [2026-07-31-accept-put-post-design.md](2026-07-31-accept-put-post-design.md).

Keep the following sentence about `rel="alternate"` as it is.

In `2026-07-31-accept-put-post-design.md` §6, replace the proposed check. The literal-absence
form it proposes goes red against the working tree for legitimate reasons — the `alternate`
links and the tests both name those media types. The rule as landed is the one in Step 2; copy
it into §6 verbatim, and replace the paragraph beginning *"It goes red against the violation it
names"* with:

> It goes red against the violation it names: a hand-written list in place of the loop deletes
> the anchor. A literal-absence check was considered first and rejected — `http.rs` names
> `application/trig` and `application/ld+json` legitimately in §6.2's `rel="alternate"` links,
> so that form is red against a correct tree.

- [ ] **Step 5: Commit**

```bash
arch-check
git add docs/
git commit -m "docs: pin the write advertisement to Format::ALL"
```

---

### Task 5: verify against the suite

**Files:** none — this task produces a report and a finding, not a diff.

- [ ] **Step 1: Full test suite and lints**

```bash
cargo test
cargo clippy --all-targets -- -D warnings
arch-check
```
Expected: all green, 22 rules checked.

- [ ] **Step 2: Conformance run**

Run: `./conformance/run.sh`
It needs Docker and takes several minutes; it starts a CSS as an identity provider, builds the
pod, and runs the official harness. Exit code is the harness's own — non-zero while any scenario
fails, which is the expected state (85 failures at last count, mostly `PATCH`-adjacent).

What matters is the delta, not the exit code: compare the new report under `conformance/reports/`
against the counts in `conformance/README.md` (41 features, 652 scenarios, 567 passed, 85
failed). A scenario that regressed is a bug in this branch; a scenario that newly passes belongs
in the summary.

If Docker is unavailable, say so plainly and stop — do not claim the suite passed.

- [ ] **Step 3: Record the outcome**

If the numbers moved, update `conformance/README.md`'s status paragraph and add the finding to
`docs/conformance-findings.md` in the shape the existing entries use. If they did not move,
change neither file and say so.

```bash
git add -u
git commit -m "docs: conformance run after the write advertisement"
```

## Self-review

- Spec §1 → Tasks 2 and 3. §2 → Task 1. §3 → Task 2 Steps 1 and 3. §4 → Task 2 Steps 1 and 3.
  §5 → Task 2 Steps 4–5 and Task 3. §6 → Task 4. §7 → Tasks 1, 2, 3 and 5. §9 → Task 4 Step 4.
- Names used in later tasks and defined earlier: `Format::ALL` (Task 1 → Task 2), `Write`,
  `accept_write`, `with_allow`, `with_read_headers`, `options_impl` (Task 2 → Tasks 3, 4).
- §6's check changed between spec and plan, and Task 4 Step 4 carries the correction back into
  the spec rather than leaving the two documents disagreeing.
