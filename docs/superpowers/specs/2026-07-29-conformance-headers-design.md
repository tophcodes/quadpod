# Response Headers and `OPTIONS` — Design

**Date:** 2026-07-29
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §13 (Success Criteria)
**Evidence:** [`docs/conformance-findings.md`](../../conformance-findings.md), ranks 2, 4 and 5

## 1. Scope

Three of the six gaps the conformance triage names are pure response-shape work and depend on
nothing in the store:

| Rank | Gap | Scenarios today | After non-RDF resources land |
|---|---|---|---|
| 2 | `WAC-Allow` header | 50 | 50 |
| 4 | `OPTIONS` | 4 | more, bounded by 85 |
| 5 | CORS headers | 5 | 35 |

Rank 1 (non-RDF resources) is deliberately **not** in this design: it is the largest gap, it
is a storage question rather than a header question, and the two can be built in parallel
without touching the same code. Ranks 3 (`Allow` on GET/HEAD) and 6 (`PATCH`) are out of
scope — the first is already done in `3cb0723`, the second is not header work.

The `OPTIONS` column grows because 81 of the 491 blocked `wac/protected-operation` rows
exercise `OPTIONS` **or** `PATCH` — the triage counts the two together, so how many are
`OPTIONS` alone is not known until rank 1 clears the `415` and the rows run. 85 is the
ceiling, not the estimate. The CORS column grows because 30 of the 38 CORS scenarios are
blocked upstream by the same `415` rather than by CORS itself. Both figures are only realised
once rank 1 lands; nothing in this design depends on that happening first.

## 2. What the suite actually requires

Every requirement below was read out of the feature files bundled in
`solidproject/conformance-test-harness:latest` under `/data`, not inferred from the spec
prose. Where the two could differ, the feature file is what this design targets.

### 2.1 CORS

- **`Access-Control-Allow-Origin` echoes `Origin` verbatim.** `access-control-headers.feature`
  asserts `match header Access-Control-Allow-Origin == config.origin`, so a literal `*` fails.
- **The headers must be present on the anonymous `401`.** Three of the six scenarios in
  `access-control-headers.feature` and six of `simple-requests.feature` send no credentials
  and assert the CORS headers on the `401` response. This is the single fact that fixes the
  layering (§3.1).
- **`Vary` must contain `Origin` on GET and HEAD.** `acao-vary.feature` and
  `simple-requests.feature`. GET already sets `Vary: Accept`, so this is an append, never a
  replace.
- **`Access-Control-Expose-Headers` must be present and must not be `*`.**
  `enumerate-headers.feature` asserts both, explicitly rejecting the wildcard.

### 2.2 `OPTIONS`

- **Answered without credentials.** `preflight.feature` and `preflight-requests.feature` send
  `Origin` and `Access-Control-Request-*` but no `Authorization`. A `401` fails them.
- **Answered without a preflight too.** The `OPTIONS` rows of `acao-vary.feature` send neither
  `Access-Control-Request-Method` nor `Access-Control-Request-Headers`, and still expect
  `200`/`204` with the CORS headers. So `OPTIONS` is a route, not merely a preflight
  interception.
- **`200` or `204`, and the body must be empty.** `match response == ''` in every `OPTIONS`
  scenario.
- **`Access-Control-Allow-Methods` contains the requested method** — GET, HEAD and POST are
  each exercised.
- **`Access-Control-Allow-Headers` mirrors `Access-Control-Request-Headers`.** This is the
  requirement that rules out a fixed list. `accept-acah.feature` asserts
  `!contains 'Accept'` when `Accept` was not requested and `contains 'Accept'` when it was —
  in otherwise identical requests. Only echoing satisfies both.
- **`Access-Control-Expose-Headers` is asserted on the preflight response as well**
  (`preflight.feature`), so it is not GET-only.
- `read-method-support.feature` separately asserts `responseStatus != 405 && != 501` for
  `OPTIONS` on both a container and a resource.

### 2.3 `WAC-Allow`

- Emitted on GET **and** HEAD (`header-exists.feature`).
- Both groups always present. `user-access-direct.feature` asserts `result.public == []`,
  which the harness's `parseWacAllowHeader` produces from `public=""`. An omitted group is not
  an empty group.
- **`write` must be reported together with `append`.** The `read/write/append` row is checked
  with `contains only`, i.e. set equality, so the emitted set must not be missing `append`.
  The `read/write` row uses a plain `contains`, which a superset also satisfies. Emitting
  `append` whenever `write` is granted therefore satisfies every row, and matches WAC's own
  subsumption rule — already modelled by `AccessModes::allows`.
- `control` is reported in the `user` group; the feature asserts
  `result.user contains ['read', 'write', 'control']` for the resource owner.

## 3. Design

### 3.1 Layering

```
Router
 └─ cors_layer          (axum::middleware::from_fn — outermost)
     └─ auth_layer      (unchanged)
         └─ routes      (+ .options(...) on both)
```

The CORS middleware wraps the auth layer because §2.1 requires the CORS headers on the
anonymous `401`, which the auth layer produces. Inside that layer they could never reach it.

`OPTIONS` is routed *inside* the auth layer — the layer only attaches the `Agent` extension —
but its handler calls **no** `authorize`. Two reasons this is safe rather than an exception
carved out for convenience:

- A CORS preflight is unauthenticated by construction. The browser sends it before it sends
  the credentialed request, and it strips `Authorization` when it does. A pod that demands
  credentials on `OPTIONS` cannot be used from a browser at all.
- The response is derived **entirely from the shape of the request URL** — `allowed_methods`
  already takes a `Target` and never touches the store. It therefore discloses nothing about
  what exists. This is the same line `post_impl` draws when it answers `409` from the path
  shape alone rather than let POST become an existence oracle
  (`docs/conformance-findings.md`, Bucket 2).

`tests/route_coverage.rs` — "every route, every verb, no credentials: the answer must always
be a refusal" — must exempt `OPTIONS` explicitly, carrying the reasoning above in the test so
the exemption cannot later be mistaken for an oversight.

### 3.2 The CORS middleware

With no `Origin` in the request, add nothing: a non-CORS request gets a non-CORS response.
With an `Origin`, add three fields to whatever response came back:

| Header | Value |
|---|---|
| `Access-Control-Allow-Origin` | the request's `Origin`, verbatim |
| `Vary` | `Origin`, **appended** to any existing value |
| `Access-Control-Expose-Headers` | the fixed list below |

The expose list enumerates exactly what this pod emits, and nothing else — advertising a
header that never appears is noise a client cannot use:

```
Allow, Content-Type, ETag, Link, Location, Vary, WAC-Allow, Warning, WWW-Authenticate
```

`Vary` uses `HeaderMap::append`, not `insert`. `get_impl` already sets `Vary: Accept`, and
`insert` would silently drop it, breaking content negotiation for caches to fix a CORS test.

**No `Access-Control-Allow-Credentials`.** No scenario asks for it — the suite authenticates
with an `Authorization` header, which CORS treats as a request header to be allowed, not as a
credential to be flagged. The flag exists for cookies and TLS client certs, and this pod has
neither. Echoing an arbitrary origin without it grants a foreign page nothing: the browser
attaches no ambient authority, so the page can only send a token it already holds, and if it
holds the token it did not need CORS to use it. Adding the flag would be the one change that
makes cookie-based auth against this pod possible, which is not a door to open by accident.

**No `Access-Control-Max-Age`.** Nothing tests it and nothing needs it yet.

### 3.3 The `OPTIONS` handler

Always `204 No Content` with an empty body, for a resolvable target. Three headers:

| Header | Value |
|---|---|
| `Allow` | `allowed_methods(target)`, now including `OPTIONS` |
| `Access-Control-Allow-Methods` | the same value |
| `Access-Control-Allow-Headers` | `Access-Control-Request-Headers`, verbatim; omitted if absent |

Mirroring the requested headers is not laziness — §2.2 shows a fixed list cannot pass, because
two otherwise identical requests must produce an `Access-Control-Allow-Headers` that does and
does not contain `Accept`.

An unresolvable path keeps its existing meaning: `classify` answers `404` for the reserved
namespace and `400` for a malformed URL. Both are shape-derived, so `OPTIONS` discloses no
more than any other method already does.

`allowed_methods` gains `OPTIONS` in all three arms, and loses the clause in its doc comment
that says `OPTIONS` is absent because no route serves it — that sentence becomes false.

### 3.4 `WAC-Allow`

Emitted on successful GET and HEAD responses, in the form:

```
WAC-Allow: user="read write append control",public=""
```

Both groups always appear; an empty group is rendered as `""` rather than omitted (§2.3).
Modes are rendered through `AccessModes::allows`, not by reading the struct fields directly,
so `write` reports `append` with it — the subsumption rule the struct already documents.

**Where the decision comes from.** The pod today answers one question per request: may *this*
agent perform *this* mode? The header needs two more: the requester's full mode set, and the
public one. `pdp::decide` already returns a complete `AccessModes` and already takes the agent
as a parameter, and it is pure — no store access, no `await`. Calling it twice is free. The
expensive half is obtaining the ACL, which is `prp`'s ancestor walk and its store queries.

So `guard::authorize` returns its decision instead of discarding it:

```rust
pub struct Decision {
    pub user: AccessModes,
    pub public: AccessModes,
}

// guard::authorize(…) -> Result<Decision, Response>
```

One `prp` resolution, two `decide` calls. GET and HEAD render the header from it; every other
handler ignores the value. The cost is a mechanical signature change at the call sites, all of
which the compiler finds.

The alternative — leaving `authorize` alone and adding a separate `wac::modes_for` that GET and
HEAD call afterwards — was rejected on two grounds. It repeats the ancestor walk and its store
queries on the pod's hottest path to answer a question that was just answered from the same
data. And it splits authorization from the statement *about* that authorization across two
evaluations, so an ACL written between them would make the header describe access that was not
the access granted. One evaluation cannot disagree with itself.

## 4. Testing

Unit tests alongside the existing ones in `src/http.rs`:

**CORS**
- No `Origin` in the request → none of the three headers appear.
- With `Origin` → `Access-Control-Allow-Origin` matches it exactly.
- A GET carries `Vary` containing *both* `Accept` and `Origin` — the regression that `insert`
  would cause.
- An anonymous request that ends in `401` still carries the CORS headers.
- `Access-Control-Expose-Headers` is present and is not `*`.

**`OPTIONS`**
- Succeeds with no credentials, `204`, empty body.
- `Access-Control-Allow-Headers` mirrors exactly the requested set — including the negative
  case, where `Accept` was not requested and must not appear.
- `Access-Control-Allow-Methods` contains `POST` for a container and does not for a resource.
- `Allow` and `Access-Control-Allow-Methods` agree.

**`WAC-Allow`**
- Owner on their own resource → `user="read write append control"`, `public=""`.
- An agent with `acl:Read` only → `user="read"`.
- An ACL granting `foaf:Agent` read → `public="read"`.
- An ACL granting `acl:Write` renders `append` alongside `write`.

**Route coverage:** `tests/route_coverage.rs` exempts `OPTIONS`, with the §3.1 reasoning
recorded in the test.

**Conformance:** `./conformance/run.sh`, and a third run recorded in
`docs/conformance-findings.md` against the existing two.

## 5. What this is expected to move, and what it is not

Nominally 59 scenarios: 50 + 4 + 5. That number is **optimistic in the same way rank 1 is**,
and for the same reason. All 50 `wac-allow` failures are today the assertion
`match header WAC-Allow != null`. Karate stops a scenario at its first failed assertion, so
everything after that line — the `contains only` checks against real mode sets — has never
been evaluated against this pod. Whether the owner holds `control` on a resource whose ACL
names only Bob is a question the third run will answer, not this design.

The honest claim is narrower: these 59 scenarios stop failing for the reason they fail today.
Some will pass. Any that do not will fail on an assertion that has never run before, which is
new information rather than a regression.
