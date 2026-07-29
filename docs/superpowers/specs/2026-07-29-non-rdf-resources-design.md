# Non-RDF Resources — Bytes Beside the Triples — Design

**Date:** 2026-07-29
**Status:** Proposed (pre-implementation), revision 1
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md)
**Origin:** `docs/conformance-findings.md` rank 1 — 540 of 609 conformance failures, named
there as the only way to find out whether WAC is correct at all.

## 1. What is wrong today

`put_impl` and `post_impl` both reach the same line:

```rust
let Some(fmt) = Format::from_content_type(header_str(&headers, header::CONTENT_TYPE)) else {
    return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
};
```

`Format` recognises five RDF media types. Everything else — `text/plain`, `image/png`,
`application/pdf` — is `415`. A Solid pod that cannot store a text file is not a storage
server.

The damage is larger than the missing feature, and it is measured. The conformance suite
builds `text/plain` fixtures inside `callonce` backgrounds, and a `callonce` that throws
takes its entire feature with it. Six WAC `protected-operation` features (491 scenarios),
five CORS features (30), all four `acl-object` features (12) and seven further scenarios
**never reach an assertion**. Roughly 370 rows of WAC access-mode assertions have never
been evaluated against this pod. The access-control engine is the part of this project with
the most safety weight and the least evidence behind it, and one `415` is why.

## 2. What the specifications actually require

**Solid Protocol §2.2** — a server MUST reject `PUT`, `POST` and `PATCH` requests that
contain content but lack `Content-Type`, **with a status code of 400**. The status code is
in the normative text, not inferred from it. See §9, which is where this pod is wrong today.

**Solid Protocol §5** — a resource is not required to be an RDF source. Non-RDF resources
are ordinary LDP resources: they live in containers, they carry auxiliary resources, they
are governed by WAC exactly as RDF resources are.

**RFC 9110 §8.3** — when `Content-Type` is absent, a recipient MAY assume
`application/octet-stream`. Solid's MUST overrides this MAY. Recording it because it is the
reflex a byte path invites: once the pod can store arbitrary bytes, "no type, so
octet-stream" becomes the natural-looking answer, and it is forbidden here.

**RFC 9110 §5.6.2** — `Content-Type` is `token "/" token` with optional parameters. This
matters because the value crosses from a client request into a server response header
(§8.2).

**LWS** — a data resource is content plus a stored media type, with `ETag` and `Range` as
MUSTs. `Range` is out of scope here (§13); the stored media type is not, and this pod
already records it (`sys:mediaType`, parent spec §5).

## 3. Storage model

A non-RDF resource is **bytes in a `BlobStore`, plus three triples in the system graph**.
Nothing else. The parent spec (§5) fixed the shape — `BlobStore` trait, `object_store`
implementation, `urn:quadpod:sys:<res>` for the server-asserted facts. This section fixes
what those facts are, and §14 records where it departs from the parent.

### 3.1 The system graph holds no fact about the bytes

```
GRAPH <urn:quadpod:sys:{iri}> {
  <{iri}> <urn:quadpod:sys#present>   true .
  <{iri}> a                           <urn:quadpod:sys#BinaryResource> .
  <{iri}> <urn:quadpod:sys#mediaType> "image/png" .
}
```

The governing rule, and the reason size, hash, `ETag` and timestamps are **not** here:

> The pod may store a derived fact only about content it owns exclusively.

For RDF triples that holds: the SPARQL store is the only writer, so `sys:present` is
legitimately a stored fact and the presence marker works. For blob bytes it does not. A
swappable backend means, by definition, that something else can write into the same bucket —
an operator, another pod, a migration job, `aws s3 cp`. A stored size or hash is then an
assertion about foreign state, and it goes wrong **silently**: the graph keeps claiming a
digest the object no longer has, and nothing in the system notices.

The three triples that remain survive that test:

- **`present`** — the pod owns its own namespace. That this URL exists is its decision, not
  the backend's. It stays a stored fact, and it is what makes an existence check one query
  rather than a backend round-trip.
- **`mediaType`** — not derivable from the bytes. It is the pod's record of what the client
  declared at write time. Swapping the object does not retroactively change what the client
  said, so the fact stays true.
- **the kind marker** — see §3.3.

A consequence worth stating, because it is the whole point of the rule: if the object is
replaced behind the pod's back, the pod serves the new bytes under a freshly computed,
correct `ETag`. Nothing in the graph has become false, because nothing in the graph talks
about the bytes.

### 3.2 The key is derived, and stored nowhere

`BlobKey::of(&ResourceUrl)` = `sha256(resource iri)`, hex, as an `object_store::Path`. A
pure function of the resource URL, in one place, exactly as `ShelfKey` is a pure function of
(resource IRI, graph name).

Deriving rather than minting is what makes the failure modes in §5.1 and §7 self-healing: an
interrupted write or an interrupted delete leaves an object at a key the *next* write to the
same URL computes again and overwrites. An opaque minted key — the parent spec's
`sys:storageKey` — would leak an object nobody can find, and would need a sweep to reclaim.
Nothing here needs one.

It also means the delete path computes the key without reading anything first, which removes
one read-then-write window from a layer that already carries several.

The cost, recorded rather than hidden: individual objects cannot be relocated within a
backend. A whole-backend migration (copy every key, repoint the config) still works, because
keys are stable across backends. Per-object relocation would need a recorded key, and that
is the trade §14 documents against the parent spec.

Guarded by a new constraint in the family that already holds `sys:`, `subgraph:` and
`bnode:`:

```
Only `blob::BlobKey` derives an object key.
```

### 3.3 The kind marker is explicit, not inferred

It is tempting to derive it: a resource is a blob exactly when
`Format::from_content_type(stored_media_type)` is `None`. One source of truth, no extra
triple.

It rots, and the rot is already scheduled. `2026-07-28-jsonld-datasets-design.md` §11 lists
`application/rdf+xml` as a follow-up — oxigraph supports it and this pod does not offer it
yet. On the day `Format` learns that type, every stored RDF/XML **blob** silently
re-interprets as an RDF resource whose graph is empty: `GET` returns an empty Turtle
document, `200`, no error. Any format added to `Format` later has the same effect on
whatever was stored as a blob under that type.

One triple is cheaper than that class of bug, and it makes the question answerable without
consulting a table that is designed to grow.

### 3.4 The ETag is computed from the served bytes

`"<sha256 hex>"` over the bytes the pod is about to serve — the same rule and the same shape
as `Skolemized::etag` on the RDF path.

Not `ObjectMeta::e_tag`, for three reasons. It is `Option<String>`, so a fallback would be
needed anyway and there would be two rules instead of one. Its semantics differ per backend:
S3 gives an MD5 or a multipart construct, `LocalFileSystem` derives one from
inode/mtime/size — the same bytes get different validators depending on where they sit. And
it changes under a backend migration although the content did not, which turns every cached
validator stale for no reason a client could understand.

The price, stated plainly: a conditional `GET` and a `HEAD` must read the whole object to
compute the validator. For the scope here that is acceptable. It is also the exact point
`Range` support would reopen — see §13.

## 4. The `BlobStore` seam

```rust
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, key: &BlobKey, bytes: Bytes) -> Result<(), BlobError>;
    async fn get(&self, key: &BlobKey) -> Result<Option<Bytes>, BlobError>;
    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError>;
}
```

- **`get` returns `Option`, not `Err(NotFound)`.** "Object gone, marker present" (§6.2) is a
  reachable state with a designed answer, not a failure. Folding it into the error type
  merges it with a genuine backend outage, and the two must produce different statuses.
- **`delete` is idempotent.** Deleting an absent object succeeds. This is what `DROP SILENT`
  already does one layer up, and it is what lets the delete path skip a prior read.
- **No `head`.** The `ETag` comes from the bytes (§3.4), so nothing would call it. It
  arrives with `Range`, which gives it a caller.

**The obligation on an implementor**, stated on the trait the way `store.rs` states the
`;`-sequence rule: `put` either writes the whole payload or writes nothing; `delete` on an
absent key succeeds; `get` distinguishes an absent object from a failure to reach the
backend. §5.1 and §7 rest on the first two and cannot check them.

Unlike `SparqlStore`, this trait gets **no one-implementor tripwire**. ADR-2's exists
because `;`-atomicity is a property of `OxigraphStore` rather than of SPARQL, so a second
implementor genuinely reopens the decision. Per-object atomicity here is a documented
property of `object_store`'s own contract, held by every backend behind it, so a second
implementor reopens nothing.

### 4.1 Why not `object_store::ObjectStore` directly

`ObjectStore` has seven required methods, including `put_multipart_opts`,
`list_with_delimiter`, `copy_opts` and `rename_opts`. Putting that surface into this pod's
signatures is the same mistake `Format` exists to avoid with oxigraph's `RdfFormat`: an
enum, or here a trait, with variants this project deliberately does not support.

The second reason is forward-looking and concrete: a remote Solid pod as a storage backend
is a plausible future implementor and is not an `ObjectStore`. The seam has to be ours for
that to be an implementation rather than a rewrite.

### 4.2 Backends

`ObjectStoreBlobs(Arc<dyn ObjectStore>)` is the only implementor in this plan. Config
selects:

| Config | `object_store` type | Notes |
|---|---|---|
| `memory` (default) | `InMemory` | Mirrors `OxigraphStore::in_memory()`. The pod stays uniformly ephemeral — blobs are exactly as durable as triples, which is to say not at all. |
| `local:<path>` | `LocalFileSystem` | |
| `s3:<bucket>` | `AmazonS3` | A custom endpoint is also the **Ceph RGW** case: RGW is S3-compatible, so it needs no backend code of its own. |

The default matters. Any durable blob backend beside an in-memory triple store would make
blobs outlive the RDF that describes them, which is a worse state than losing both.

## 5. Write path

`blob::put(store, blobs, r, bytes, media_type)`:

1. `blobs.put(&BlobKey::of(r), bytes)`. `object_store` documents `put_opts` as *"guaranteed
   to be atomic, it will either successfully write the entirety of `payload` to `location`,
   or fail"* — so a half-written object is not a state this design has to handle.
2. One SPARQL sequence: `DROP SILENT` the resource graph, `DROP SILENT` every shelf the
   registry lists, `DROP SILENT` the system graph, then `INSERT DATA` the three triples of
   §3.1.

Step 2 is literally `put_dataset`'s teardown. That is not a coincidence to be tidied away
later — it is why §5.2 needs no code.

### 5.1 The order is load-bearing

Bytes first, marker second.

| Interruption | Result |
|---|---|
| Step 1 fails | Nothing marked. `500`, no state change. |
| Step 2 fails | An object at a key no marker points to. Invisible to every read path, and overwritten by the next write to the same URL (§3.2). |

The reverse order produces a resource that exists and cannot be served — the difference
between litter and corruption. Since no compiler enforces a statement order, §12 pins it
with a `BlobStore` stub whose `put` fails.

### 5.2 Switching kinds costs nothing in one direction and one line in the other

The user-visible rule: `PUT` replaces the representation, including its kind. Solid and LDP
both read `PUT` that way, and it is what CSS does.

**RDF → blob** is free: step 2 above already drops the resource graph, the shelves and the
system graph, which is the entire RDF state.

**Blob → RDF** needs `put_dataset` to gain an unconditional `blobs.delete` before its own
teardown. Unconditional because deleting an absent object succeeds (§4), so no existence
check is needed and none is wanted — a check plus a delete is two round-trips with a window
between them. This is the only place the RDF path knows the blob path exists.

## 6. Read path

Read the system graph, branch on the kind marker, `blobs.get`. On `Some(bytes)`: `ETag` from
§3.4, `Content-Type` from `sys:mediaType`, `Content-Length` from the length, `Vary: Accept`
for the same reason the RDF path carries it.

### 6.1 `Accept` against a single representation

A blob has exactly one representation, so there is nothing to negotiate. The question is not
`negotiate`'s "which of my five formats do I render into?" but "does the client accept the
one type that exists?" — and if not, `406`.

These are different questions, but they parse the same header: q-values, `q=0` as a refusal
rather than a low rank (RFC 9110 §12.5.1), and type-scoped wildcards. Writing that parse
twice is exactly the drift `docs/constraints.md` names — *"two of each is how the Turtle path
and the dataset path drift apart, and drift here is silent: both answer, one answers wrong."*

So the ranking is lifted out of `negotiate` into `ranked_accept`, and `negotiate` and
`accept_allows` become two consumers of **one** parser. The constraint stays true in
substance and not merely in the letter of its `rg` check — and it gets a check that says so,
since the existing one only pins that two *named* functions do not return:

```
The `Accept` header is parsed in exactly one place.
    check: [ "$(rg -o 'strip_prefix\("q="\)' src | wc -l)" = 1 ]
```

The q-value parse is the part a second reader cannot avoid rewriting, which is what makes
this fail against a real violation rather than against a naming convention.

### 6.2 Object missing, marker present

`404`, with a `Warning` header naming the backend as the reason.

The pod does not claim the resource never existed — its own namespace still says it does —
but it has nothing to serve. `500` would read as "my fault, retry", which misdescribes a
backend that has been emptied out from underneath. This is the state §4's `Option` return
exists to express.

## 7. Delete

**There is no `blob::delete` entry point.** `aux::delete_subject` is the one delete cascade —
it reads the shelf registry and drops the shelves, the resource graph, the system graph and
every auxiliary in a single update — and it gains a `blobs` parameter and one call. A
parallel blob-delete function would be a second, weaker cascade beside it, which is exactly
what `e31c88b` removed once already:

> `resource::delete_dataset` was dead in production and a second, weaker implementation of
> the delete cascade with no auxiliary cascade; `aux::delete_subject` is the one that does it
> completely.

Within that cascade the order is graphs and marker first, then `blobs.delete`. If the second
half fails, an object is left at a derived key no marker points to: invisible, and reclaimed
by the next write to the same URL. The mirror image of §5.1, and the same preference — leave
litter, never corruption.

The rule generalises, and it is the reason this is not a second implementation of anything:
**wherever a resource's RDF state is torn down, the blob is torn down in the same
operation.** There are exactly two such sites — `put_dataset`'s replace (§5.2) and
`delete_subject`'s cascade — and both gain the same unconditional line. Deleting an absent
object succeeds (§4), so neither needs a prior existence check.

## 8. The HTTP edge

### 8.1 The `Content-Type` gate becomes three-way

| Header | Path |
|---|---|
| A recognised RDF type | RDF, unchanged |
| A valid media type `Format` does not know | blob |
| Syntactically invalid | `415` |
| Absent, with a body | `400` — §9 |

### 8.2 `MediaType` is a validating newtype

Today `Format::media_type()` returns `&'static str`, so **every `Content-Type` this pod
emits is safe by construction**. A blob's media type comes from the client and reaches two
interpolation sites: a SPARQL literal in `INSERT DATA`, and a response header value.
`MediaType::parse` (RFC 9110 §5.6.2 — `token "/" token`, parameters allowed, no CTL, no
CR/LF, no bare quote) becomes the only constructor.

The two sites are not equally exposed, and the difference decides what §12's test must send.
Hyper rejects CR and LF inside a request header value before any handler sees it, so
response-header splitting is not reachable from here; `MediaType::parse` refusing them is
defence in depth. **The live vector is the SPARQL literal**: `Content-Type: text/plain;x="`
is a perfectly legal HTTP header value, and interpolated unescaped it closes the literal and
continues the update as syntax. That is the case the validation exists for.

`stored_media_type` consequently returns `Option<MediaType>` rather than `Option<Format>`,
and the RDF path converts. One place knows what was stored.

### 8.3 Conditional requests

`current_tags` builds one validator per `SERVABLE` format because an RDF resource has five
representations. A blob has one, so the blob branch returns a one-element list. The
`If-Match`/`If-None-Match` logic above it — RFC 9110 §13.1.1, match against *any* current
representation — is untouched.

### 8.4 The body limit becomes explicit

`router()` sets no `DefaultBodyLimit`, so axum's 2 MiB default applies today, to RDF as much
as to anything else. The limit already exists; it is accidental rather than decided.

It becomes `--max-body-bytes` (with an environment variable, like the rest of the config),
default **64 MiB**, so a `413` is a statement instead of a framework artefact. One knob, not
one per kind: two limits would be a second place answering the same question.

The real ceiling behind it is that the body is buffered whole in memory. Raising it properly
means streaming — `put_multipart_opts` and a `BlobStore` that takes a stream. Out of scope,
and §13 says so.

### 8.5 Two edges closed

- `Target::Aux` with a non-RDF body → `415`. An ACL the PDP cannot parse is not an ACL.
- `POST` with `Link: rel="type"` naming a container **and** a non-RDF body → `400`. A
  container's representation is RDF; the two requests contradict each other.

### 8.6 Status codes in one place

Scattered across the sections above; collected here because a handler is where they have to
agree.

| Case | Answer | Where |
|---|---|---|
| Backend failure (bucket unreachable, disk full) | `500` | §5.1 |
| Object absent, marker present | `404` + `Warning` | §6.2 |
| `Content-Type` absent, request has a body | `400` | §9 |
| `Content-Type` syntactically invalid | `415` | §8.2 |
| Non-RDF body on `Target::Aux` | `415` | §8.5 |
| `Link: rel="type"` container + non-RDF body | `400` | §8.5 |
| Body exceeds `--max-body-bytes` | `413` | §8.4 |
| `Accept` excludes the stored media type | `406` | §6.1 |

`500` rather than `502` for a backend failure: `put_status` already maps
`ResourceError::Store(_)` to `500`, and a blob backend is exactly as far upstream as the
SPARQL store. Two different codes for two backends of the same pod would be arbitrary.

## 9. `content-type-reject` is a defect, not a pending decision

`docs/conformance-findings.md` files this in Bucket 2 ("Pending decision — do not change
these without a decision"). That classification is wrong, and this design corrects it.

The recorded rationale is that `format_for_content_type` is the single gate for "can I parse
this body?", so an absent type is answered like an unparseable one; that RFC 9110 supports
`415` for an unsupported or absent representation type; and that the suite reads Protocol's
"MUST reject" as `400`. All three parts fail:

1. **The conflation argument does not survive this design.** It held while both cases meant
   the same thing — no write. After §8.1, an unsupported type is not refused at all, it is a
   blob. What is left at the gate is "absent" and "malformed", which were never the same
   question.
2. **The RFC citation is half-read.** `415` covers an *unsupported* type. For an *absent*
   one, RFC 9110 §8.3 offers a different answer entirely (assume `application/octet-stream`,
   MAY) — a third option, not support for `415`.
3. **The suite is quoting, not interpreting.** Solid Protocol §2.2
   (`#server-content-type-missing`): *"Server MUST reject `PUT`, `POST`, and `PATCH` requests
   that contain content but lack the `Content-Type` header field, with a status code of
   `400`."* The status code is in the normative text. Solid's MUST also overrides RFC 9110's
   MAY, so assuming `octet-stream` is forbidden here rather than merely inelegant.

`PUT` and `POST` without `Content-Type` therefore answer `400`. `PATCH` stays `405` because
this pod has no `PATCH`; that is a different gap with its own plan.

It is folded into this design rather than deferred because §8.1 is the commit that first
separates "absent" from "unsupported". Re-opening that separation later to change one line
costs more than doing it here.

## 10. What does not change

The point of routing blobs onto `ResourceUrl` rather than a new target type: `authorize`,
`authorize_and_materialize`, the single-traversal ancestor materialization,
`refuse_slash_pair`, containment, auxiliary-URL advertisement, the `Allow` header and
`name_is_taken` all apply to a blob unaltered.

In particular the constraint *"only `ResourceUrl` and `ContainerUrl` may be written
directly"* stays green: no third `DirectlyWritable` implementor appears. A blob is a
resource whose representation happens to be bytes, not a fourth kind of thing in the URL
space.

## 11. Documented limits

- The body is buffered whole in memory, bounded by §8.4.
- `HEAD` and a conditional `GET` read the entire object to compute the validator (§3.4).
- No `Range`, so a client cannot resume or seek.
- An object orphaned by an interrupted write or delete is reclaimed only by a later write to
  the same URL. There is no sweep.
- Individual objects cannot be relocated within a backend (§3.2).

## 12. Testing

Every test below names the mutant it kills. `docs/constraints.md` records that this project
has already shipped a test asserting its property in a form where it held trivially; the
defence is to say in advance what each test would catch.

1. **Byte fidelity** — a body containing `\0`, invalid UTF-8 and CRLF round-trips exactly.
   Kills any implementation that routes the body through `String`. An ASCII fixture would be
   precisely the trivially-passing test.
2. **Kind switch, both directions** — and proof the old state is *gone*, not merely
   unreachable. For blob→RDF the `BlobStore` is queried **directly**, not through the marker;
   `b4d2346` is the precedent for why reading back through the registry hides orphans.
3. **Write order** — a `BlobStore` stub whose `put` fails. The resource must not exist
   afterwards. Without this, §5.1 is a comment.
4. **Media-type injection** — `Content-Type: text/plain;x="` (a legal HTTP header value that
   is not a legal media type) yields `415`, and the resource is not created. Demonstrated red
   against the unvalidated version. A CRLF payload would *not* do here: hyper rejects it
   before the handler runs, so that test would pin hyper's parser and pass no matter what
   `MediaType::parse` does — the trivially-passing shape §12 opens by warning about.
5. **Validators** — identical bytes give identical tags, one byte's difference gives a
   different tag, `If-None-Match` gives `304`, a stale `If-Match` gives `412`.
6. **`406`** on an `Accept` that excludes the stored type, **and** `*/*` and `image/*`
   serving it. Without the second half, an `accept_allows` that always refuses passes.
7. **WAC on a blob** — an ACL denying Read denies it for bytes too. This is the claim the
   whole plan exists to make testable; it belongs here and not only in the suite.
8. **Containment** — a blob `POST`ed into a container appears in `ldp:contains` and
   disappears on delete.
9. **`content-type-reject`** — `PUT` and `POST` with a body and no `Content-Type` give
   `400`.

Success criteria: `cargo clippy --all-targets` clean, `arch-check` 0 rot including the new
key constraint, and a conformance run with an updated findings document.

**What is not promised: that the 540 turn green.** They become *runnable*. The findings
already project that ~81 of them fall straight through to `OPTIONS`/`PATCH`, both of which
are separate plans. The honest number is knowable only after the run — which is the point,
since ~370 WAC rows are unmeasured today.

## 13. Follow-ups this design deliberately does not do

- **`Range` and streaming.** `object_store`'s `get_opts` already carries range and ETag
  matching, so this is an extension rather than a rebuild. It is also the point at which
  §3.4's "compute the validator from the bytes" is worth re-litigating, since serving a range
  should not require reading the whole object.
- **`OPTIONS`, `WAC-Allow`, CORS, `PATCH`.** Ranks 2–6 of the findings. Several become
  measurable only once this lands.
- **Orphan collection.** §3.2's derived key makes it unnecessary for correctness; a backend
  accumulating dead objects across many interrupted writes is an operational concern, not a
  correctness one.
- **Persistence for the SPARQL store.** Named here only because §4.2's default exists to
  avoid pre-empting it.
- **RDFa extraction**, which `2026-07-28-jsonld-datasets-design.md` §11 notes only becomes
  honest once blobs exist. It does not become honest automatically.

## 14. Deltas against documents already in force

| Document says | This design | Why |
|---|---|---|
| Parent spec §5: `urn:quadpod:sys:<res>` holds "the `object_store` key, size, hash, content-type; ETag; timestamps" | Only `present`, the kind marker and `mediaType` | §3.1 — the pod does not own the bytes, so a stored fact about them can go silently false. Size and hash come from the backend or the served bytes at request time. |
| Parent spec §5: the key is recorded | The key is derived and recorded nowhere | §3.2 — self-healing after an interrupted write, and no read before a delete. Costs per-object relocation, recorded there. |
| **`docs/uri-space.md`**, "Server-asserted facts are not auxiliary resources": "byte size, content hash and storage keys … live in an internal graph (`urn:quadpod:sys:<res>`)" | Byte size and content hash live nowhere; the storage key is derived | §3.1, §3.2 |

The first two are narrowings of the parent spec: the graph layout, the `BlobStore` seam, the
`object_store` implementation and Content-Type-based routing all stand as it fixed them.

The third is different in kind. `docs/uri-space.md` declares itself **normative** for the
contract between this pod and its clients, so it is not a document a spec may quietly depart
from — the sentence gets rewritten in the same change that implements this, not afterwards.
What survives it unchanged is the part that carries the meaning: these facts are the
*server's* assertions, they are never addressable or writable, and they are exposed through
the HTTP headers that already exist for them. Only the claim about *where they are kept*
becomes wrong, and it becomes wrong because §3.1 says the pod must not keep them at all.

Adjacent, and deliberately not folded in: that same passage promises exposure through
`Last-Modified` as well, which this pod emits nowhere today. `ObjectMeta::last_modified`
would supply it for a blob without storing anything — consistent with §3.1's rule — but it is
a separate gap that predates this design and applies to RDF resources too.
