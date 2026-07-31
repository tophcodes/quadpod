# `Accept-Put` and `Accept-Post` — Design

**Date:** 2026-07-31
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §3, §4
**Origin:** [2026-07-28-jsonld-datasets-design.md](2026-07-28-jsonld-datasets-design.md) §6.3, §11
named the advertisement as the reason TriG and N-Quads are undiscoverable;
[2026-07-30-rdf12-design.md](2026-07-30-rdf12-design.md) §4 made a media-type parameter the
opt-in for writing triple terms and declared the advertisement out of scope. This is
[issue #3](https://github.com/tophcodes/sparql-pod/issues/3), and it closes both.

## 1. What is decided

The pod emits `Accept-Put` and `Accept-Post` wherever it already emits `Allow` and
`Accept-Patch`. Solid Protocol §5.3 makes all three a MUST; two of the three shipped with the
header slice and with N3 Patch, and this is the third.

Two properties are decided beyond "the header exists":

- **The value is derived from `Format`, not written beside it.** `rdf.rs` already owns which
  media types the write path parses. A hand-maintained header is how the two come to disagree,
  and that disagreement is unobservable from either side — the parser keeps working, the header
  keeps looking plausible.
- **The value carries the `version` parameter.** rdf12-design §4 requires a client to set
  `version=1.2` to write a triple term, and a client can only set a parameter it knows the
  server takes. Without this, §4's opt-in is discoverable only by provoking a `415`.

## 2. One list, not two

`Format::from_content_type` matches five literal arms; `Format::media_type` matches the same
five in the other direction. The advertisement needs that list a third time, which is one time
too many.

`Format` gains `ALL`, an array of the five formats, and `from_content_type` is rewritten to
search it:

```rust
Self::ALL.into_iter().find(|f| f.media_type() == media_type(ct).to_ascii_lowercase())
```

The parse list and the advertised list then coincide **by construction**. Adding a sixth format
is one edit in one place, and a format that parses but is not advertised stops being
expressible.

`media_type` keeps its `match` — it is the definition the search reads, and the direction that
has to stay total.

This is the shape `ACCEPT_PATCH` deliberately does **not** have. `text/n3` is not a `Format` —
nothing parses it through `rdf.rs`, `patch.rs` owns it end to end — so a `&'static str` constant
is honest there and would be a second list here.

## 3. What the value says

For each format in `Format::ALL`, in that order: the essence, then the same essence with
`;version=<label>` where `<label>` is `SparqlStore::rdf_version`'s label. `*/*` last, where a
blob is acceptable.

```
Accept-Put: text/turtle, text/turtle;version=1.2, application/n-triples,
  application/n-triples;version=1.2, application/ld+json, application/ld+json;version=1.2,
  application/trig, application/trig;version=1.2, application/n-quads,
  application/n-quads;version=1.2, */*
```

**Both halves of each pair are true.** `RdfVersion::from_media_type` reads an absent parameter
as `Rdf11` — deliberately, and that decision is rdf12-design's §4. So the bare type and the
versioned type are two genuinely different acceptable representations, and listing only one of
them would understate what the write path takes.

**The versioned twin is omitted when the store is `Rdf11`**, where `;version=1.1` would be a
second spelling of the bare entry and nothing more. A `Rdf12Basic` store advertises
`;version=1.2-basic`. One entry per format for the version the store actually holds — not the
containment chain below it, which the bare entry already covers.

Only the store's own maximum appears. A client that names a lower version is accepted (§6 of
rdf12-design refuses only `declared > store_version`), and a client that names a higher one gets
the `415` that header was there to prevent.

## 4. Scope per target

Each header reaches exactly as far as `allowed_methods` does at that target, and no further. A
header advertising a method the target does not allow is worse than an absent header: it is an
answer that contradicts `Allow` in the same response.

| Target | `Accept-Put` | `Accept-Post` |
|---|---|---|
| Container | RDF formats | RDF formats + `*/*` |
| Resource | RDF formats + `*/*` | — |
| Aux | RDF formats | — |

`Accept-Post` appears on containers alone, because a container is the only thing `POST` may
address. `Accept-Put` appears everywhere, because `PUT` is in every arm of `allowed_methods`.

The `*/*` column is `classify_body`'s three-way gate read back out:

- A **container's** own representation must be RDF (`400`, *"a container's representation must
  be RDF"*), so no `*/*` on its `Accept-Put`. Its `Accept-Post` does carry `*/*` — the child a
  `POST` creates is a resource, and `classify_body` classifies it as one.
- An **auxiliary** is a policy document the PDP has to read; a blob there is `415`.
- A **resource** accepts any parseable media type as a blob. LDP §4.5.2 defines `*/*` in
  `Accept-Post` as exactly this claim, and the same reading is the only sensible one for
  `Accept-Put`, which has no RFC of its own.

## 5. Where it is emitted

`with_allow` and `options_impl` — the two places `Allow` and `Accept-Patch` already come from.
No third emission site, so a read path added later cannot pick up two headers of the four.

Both take `RdfVersion` as a `Copy` parameter rather than `AppState`. `options_impl`'s doc
comment justifies answering an unauthorized `OPTIONS` with *"`allowed_methods` takes a `Target`
and never reaches the store — so it discloses nothing about what exists"*. That sentence must
stay literally true. `SparqlStore::rdf_version` is a constant per deployment and touches nothing
stored, but a handler holding `AppState` inside `options_impl` invites the next edit to ask it
something that does. The handlers read the version; the header builders receive it.

`EXPOSED_HEADERS` gains both names. A browser client cannot read a response header that is not
listed there, which would make the advertisement invisible to exactly the clients that need it
most — and `protocol/cors/enumerate-headers` requires the list to be enumerated rather than `*`.

## 6. What is checked

`docs/constraints.md` gains one rule:

> The write advertisement is built from `Format::ALL`.
>     check: `rg -q 'for f in Format::ALL' src/http.rs`

It goes red against the violation it names: a hand-written media-type list in place of the loop
deletes the anchor, which was checked against a real edit before the rule was added.

A literal-absence check was the first form considered — `! rg -q '"application/(trig|n-quads)"'
src/http.rs` — and it is rejected: `http.rs` names `application/trig` and `application/ld+json`
legitimately in §6.2's `rel="alternate"` links, and every format by name across its tests, so
that form is red against a correct tree. Anchoring on the loop is the same shape as
*"`space::GraphName` stays sealed"*, which pins a signature rather than an absence.

The `Format::ALL` search in §2 is not separately checked. It is the definition of
`from_content_type`, so it cannot drift without the parser drifting with it.

## 7. Tests

In `http.rs`, following the table shape the existing `Accept-Patch` test uses — every target
shape, on both `GET` and `OPTIONS`, because `allowed_methods` has three arms:

- Every format in `Format::ALL` appears in `Accept-Put`, bare **and** with `;version=1.2`.
- `Accept-Post` is present on a container and absent on a resource and on an auxiliary.
- `*/*` is in a resource's `Accept-Put` and in a container's `Accept-Post`, and **not** in a
  container's `Accept-Put` or an auxiliary's.
- `EXPOSED_HEADERS` names both.

One test in `rdf.rs`: every member of `Format::ALL` round-trips through `from_content_type` on
its own `media_type`, and the array has one entry per arm of `media_type`'s match.

Then the conformance run. The suite exercises these headers as part of the protocol manifest;
the report is the deliverable either way.

## 8. Out of scope

- **`Accept-Patch`'s shape.** `text/n3` stays a constant, for §2's reason.
- **The in-band `VERSION` directive.** rdf12-design §13, unchanged.
- **`Accept-Post` on a resource.** It would advertise a method `Allow` refuses.
- **Per-subgraph URLs** — [#4](https://github.com/tophcodes/sparql-pod/issues/4). The third of
  jsonld-datasets-design §11's discoverability items, and the one that needs its own design.

## 9. Deltas against documents already in force

`2026-07-28-jsonld-datasets-design.md` §6.3 states that the pod *"has no `OPTIONS` route"*. That
was true when written and has not been since the conformance-headers slice. The clause is
corrected in place; the rest of the sentence — that TriG and N-Quads are undiscoverable — is
what this design removes, and §11's follow-up is closed by it.

No decision recorded elsewhere is reversed or narrowed.
