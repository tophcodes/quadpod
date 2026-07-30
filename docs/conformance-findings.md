# Conformance findings

| | |
|---|---|
| **Date** | 2026-07-27 |
| **Pod commit** | `ef49c5d` |
| **Harness** | `solidproject/conformance-test-harness:latest`, image `sha256:601457122b3f`, runner **1.2.2** (Quarkus 3.29.2, karate 1.5.1) |
| **Bundled tests** | `solid-contrib/specification-tests` **v0.0.19 (2024-03-21)** |
| **Manifests** | `protocol` + `web-access-control` (the two `application.yaml` links by default) |
| **Command** | `./conformance/run.sh` |

Two consecutive runs produced identical counts. The numbers below are reproducible.

## The numbers

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 37 | 615 |
| harness's MUST-linked subset | 38 | 649 | 33 | 608 |

## Second run — after Plan 9 (dataset-valued resources)

| | |
|---|---|
| **Date** | 2026-07-29 |
| **Pod commit** | `1fe4953` |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 43 | 609 |

Same 41 features, same 652 scenarios — nothing aborted or got skipped that used to run.
Passed rose by 6, not the 1 that Plan 9 alone accounts for. All three of Bucket 3's
defects are gone, not just D3:

- **D3** (named graphs dropped on write) is the one Plan 9 fixed:
  `content-negotiation-named-graphs` (its one active scenario, at line 16) now passes.
- **D1** (`POST` ignoring `Link: rel="type"`) and **D2** (no `Allow` on GET/HEAD) were
  already fixed, by `0336247` and `3cb0723` — both land after `ef49c5d`, the commit the
  first run measured, and neither run had re-measured the suite since. They are not part
  of this plan; they surface here because this is the first conformance run since they
  landed.

Bucket 3 is therefore **0 scenarios**, and the totals reconcile exactly:
`615 (bucket 1 + 2 + 3 + 4 at first run) − 1 (D3) − 1 (D1) − 4 (D2) = 609`, which is what
this run measured. No other feature's pass/fail count moved — checked against every row in
Buckets 1 and 2 individually, not just the aggregate.

The harness's own `ResultLogger` counts only scenarios attached to a MUST requirement; the
karate totals count every scenario in every feature that ran. Use the karate row — it is
what `reports/report.html` shows.

`PREPARE SERVER` succeeded. The harness logged *"The Pod is using [WAC] for access control"*
and *"Confirmed we can create a container … and set ACLs on it"*, so **nothing failed inside
the harness's own setup** and the run measured the pod, not the runner.

## Third run — after Plan 10 (non-RDF resources)

| | |
|---|---|
| **Date** | 2026-07-30 |
| **Pod commit** | `7debec9` (the last code commit measured; two docs-only commits follow it) |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 479 | 173 |

Of the 41 features, 18 pass every scenario and 23 have at least one failure. Same 41 features,
same 652 scenarios as every prior run. Passed rose from 43 to 479 — **+436** — and every one
of the 436 reconciles to a named cause, feature by feature, not merely in aggregate.

### Where the 436 came from

Two independent sources, and they add up exactly:

**1. Rank 1 shipped: the `text/plain`-fixture `callonce` abort that used to take out whole
features is gone.** 540 scenarios that never reached an assertion before now run to
completion. Of those 540:

- **434 now pass.** This is the headline number Plan 10 exists to produce: the vast majority
  of the ~370 previously-unmeasured WAC access-mode assertions the second run's document
  called "the real reason to do #1 first" turn out to be **correct**. `read-access-agent`,
  `read-access-bob` and `read-access-public` each go from `0/90` to `80/90`; `write-access-agent`
  and `write-access-bob` each go from `0/84` to `68/84`; `write-access-public` goes from `0/53`
  to `40/53`; all four `acl-object` features go `0/3` → `3/3`; all five `cors` features that
  were entirely blocked now pass everything except the CORS/`OPTIONS` assertions themselves
  (below).
- **106 still fail, for four named, pre-existing causes** — not new problems, just newly
  measurable instances of gaps and one defect-family already on this document before this run:
  63 more `PATCH` failures, 20 more CORS-header failures, 11 more `OPTIONS` failures, and 12
  genuinely new findings (6 `POST`, 6 `DELETE`) that this run is the first to surface. See
  Bucket 1 and the ranking below for the breakdown; see Bucket 2 and Bucket 3 for the 12 new
  ones.

**2. `content-type-reject` went from `0/3` to `2/3` independent of unblocking** — it was
never blocked, it was simply wrong, and design spec §9 says why (see Bucket 3): **+2**.

`434 + 2 = 436`, exactly the measured rise. No other feature's pass count moved outside these
two sources — checked against every row in every bucket, not just the aggregate.

### The 173 residual failures, all attributed

| Cause | Scenarios | Bucket | Status |
|---|---|---|---|
| No `PATCH` route | 66 | 1 | unchanged gap, now fully measured (was 2) |
| No `WAC-Allow` header | 50 | 1 | unchanged, was already fully measured |
| No CORS response headers | 25 | 1 | unchanged gap, now fully measured (was 5) |
| No `OPTIONS` route | 15 | 1 | unchanged gap, now fully measured (was 4) |
| `POST` into a container whose grant is `accessTo`-only | 6 | 3 | **new defect**, unblocked by Plan 10 |
| `DELETE` of a container/fictive resource via inherited-only access | 6 | 2 + 3 | **new finding** (3 defect, 3 pending-decision), unblocked by Plan 10 |
| `post-target-not-found` (ancestor materialization) | 4 | 2 | unchanged |
| `containment:122` (trailing-slash pair) | 1 | 2 | unchanged |
| **Total** | **173** | | |

`66 + 50 + 25 + 15 + 6 + 6 + 4 + 1 = 173`. Every failure in this run has one of these eight
names; none is left over — see Bucket 4.

A newly-failing scenario that was previously *blocked* (part of the 540) is a **new finding**,
not a regression: it was never measured before, so there is nothing for it to regress from.
The `POST`/`DELETE` rows above are exactly that — three genuinely new WAC-decision questions
this run is the first to answer, found only by reading the harness's own Java fixture-builder
(decompiled from the already-pulled `solidproject/conformance-test-harness` image, since the
suite's `.feature` files and their Java `AccessDatasetBuilder` are not otherwise inspectable
without running it) alongside every example row's pass/fail state.

### Did the second run's ~81 projection hold?

**Not as stated, and the miss is itself informative.** The second run projected that "within
the 491 `protected-operation` rows, … 81 exercise `OPTIONS` or `PATCH`", predicting that many
would fail on those two ranks the moment the `415` cleared. Measured: **`protected-operation`
has no `OPTIONS` scenarios at all** — `OPTIONS` is purely a `cors/*` and `read-method-support`
phenomenon, never tested inside the WAC access-mode features. The number the projection was
actually reaching for is `PATCH` alone within `protected-operation`: **63**, not 81 — close in
order of magnitude, wrong in composition (`OPTIONS` contributes 0 of it, not roughly half). Add
the 12 newly-discovered `POST`/`DELETE` findings — genuinely new, not what the projection was
naming — and 75 of the 540 unblocked scenarios still fail on a write method or a write
decision, against a projected 81. The estimate landed in the right neighborhood by magnitude
and for the wrong reason.

## One gap accounted for almost everything — until this run

Rank 1 from the first two runs — non-RDF resources, 540 of 609 (then) failures — is gone: it
shipped in Plan 10
(`docs/superpowers/specs/2026-07-29-non-rdf-resources-design.md`).
**No single remaining gap comes close to that share.** Ranked by scenarios still failing:

| Rank | Gap | Scenarios | Note |
|---|---|---|---|
| 1 | **`PATCH` not implemented** | **66** | was rank 6 at 2; the dominant residual cause now that WAC's `retry until` assertions expose it everywhere a write is tested |
| 2 | **`WAC-Allow` header** | **50** | unchanged since the first run — pure header work, the access decisions underneath already pass |
| 3 | **No CORS response headers** | **25** | was 5; the other 20 were blocked by rank 1 before, not by CORS |
| 4 | **`OPTIONS` not implemented** | **15** | was 4; likewise mostly newly measured |
| 5 | **`POST` into an `accessTo`-only container** | **6** | new defect, only measurable now — Bucket 3 |
| 6 | **`DELETE` via inherited-only access** | **6** | new finding, split 3 defect / 3 pending-decision — Buckets 2 and 3 |
| 7 | **`post-target-not-found`** | **4** | unchanged, Bucket 2 |
| 8 | **trailing-slash pair** | **1** | unchanged, Bucket 2 |

`66 + 50 + 25 + 15 + 6 + 6 + 4 + 1 = 173`.

Ranks 1–4 are not new problems — they are the same four gaps the first run already named
(`PATCH`, `WAC-Allow`, CORS headers, `OPTIONS`), now measured in full for the first time
because nothing aborts the features that carry them anymore. Ranks 5–6 are the payoff the
second run's document promised: *"the real reason to do #1 first: it is the only way to find
out whether WAC is correct."* It was, mostly — **434 of the 540 unblocked scenarios (80%)
pass outright**, meaning the WAC access-decision logic this pod already had was correct for
the overwhelming majority of cases nobody had been able to test. The 6 + 6 above are the
genuine exceptions: real, previously-invisible WAC decision-point gaps, not restatements of
`PATCH`/`OPTIONS`/CORS. See Buckets 2 and 3 for what each one actually is.

The work implied by this ranking, in order: `PATCH` is now the single biggest lever (66
scenarios, and it is one route, not sixty-six separate bugs); `WAC-Allow` is unchanged, cheap,
pure header work; CORS and `OPTIONS` are, between them, "the pod does not answer preflight
requests or emit CORS headers at all" — one feature, not two, once built. The `POST`/`DELETE`
findings are narrower and worth a real decision each, not a blanket fix.

---

## Bucket 1 — Expected gap (156 scenarios, as of the third run)

Features this pod deliberately does not have.

### Non-RDF resources — RESOLVED (Plan 10, `7debec9`)

The 540 scenarios this used to name (below, unchanged as a record of what was blocked) no
longer belong in this bucket: `PUT`/`POST` with a non-RDF `Content-Type` now stores the body
as a blob (parent spec §5, this design's §3–§8) instead of answering `415`. Every feature
this row used to abort now runs to completion — see the third run's reconciliation for where
its 540 scenarios landed.

<details>
<summary>What used to fail here (first and second run)</summary>

| Feature | Scenarios | How it failed |
|---|---|---|
| `wac/protected-operation/read-access-agent` | 90 | `callonce common.feature:122` — `Failed to create …/*.txt, response=415` |
| `wac/protected-operation/read-access-bob` | 90 | same |
| `wac/protected-operation/read-access-public` | 90 | same |
| `wac/protected-operation/write-access-agent` | 84 | same |
| `wac/protected-operation/write-access-bob` | 84 | same |
| `wac/protected-operation/write-access-public` | 53 | same |
| `protocol/cors/acao-vary` | 12 | Background `createResource('.txt', …, 'text/plain')` → 415 |
| `protocol/cors/simple-requests` | 10 | same |
| `protocol/cors/preflight-requests` | 4 | same |
| `protocol/cors/accept-acah` | 3 | same |
| `protocol/cors/enumerate-headers` | 1 | same |
| `wac/acl-object/container-none` | 3 | `callonce setup` → 415 |
| `wac/acl-object/container-access-to` | 3 | same |
| `wac/acl-object/container-default` | 3 | same |
| `wac/acl-object/container-access-to-default` | 3 | same |
| `protocol/cors/access-control-headers:31` | 1 | credentialed `POST text/plain` → 415 |
| `protocol/writing-resource/containment:14` | 1 | `PUT *.txt text/plain` → 415, expected 201 |
| `protocol/writing-resource/delete-protect-nonempty-container:23` | 1 | fixture `createResource('.txt')` → 415 |
| `protocol/writing-resource/delete-remove-containment:50` | 1 | same |
| `protocol/writing-resource/slash-semantics-exclude:40` | 1 | `PUT foo text/plain` → 415 |
| `protocol/writing-resource/slash-semantics-exclude:99` | 1 | `POST text/plain` → 415 |
| `wac/protected-operation/acl-propagation:32` | 1 | `PUT *.txt text/plain` → 415, expected 201 |

</details>

### `WAC-Allow` header — 50 scenarios (unchanged)

The pod still never emits `WAC-Allow`. Every one of these failures is the single assertion
`match header WAC-Allow != null`; **no access decision failed anywhere in these features.**
Identical count and identical breakdown to the first and second run — this gap was never
blocked by the `415`, so it was already fully measured before this run.

| Feature | Failed / total |
|---|---|
| `wac/wac-allow/header-exists` | 2 / 2 |
| `wac/wac-allow/user-access-direct` | 12 / 14 |
| `wac/wac-allow/user-access-indirect` | 12 / 14 |
| `wac/wac-allow/public-access-direct` | 12 / 14 |
| `wac/wac-allow/public-access-indirect` | 12 / 14 |

### `OPTIONS` — 15 scenarios (was 4)

No `OPTIONS` route exists (`rg OPTIONS src/` finds nothing), so axum answers `405`. The
original 4 were never blocked; the other 11 were, inside the CORS preflight features, which
build their fixtures from a `text/plain` resource:

- `protocol/read-write-resource/read-method-support:31` and `:36` — unchanged from run 1.
- `protocol/cors/preflight:12` and `:28` — unchanged.
- `protocol/cors/acao-vary:12`, `:27`, `:42`, `:57` (4, newly measured) — preflight-shaped requests inside a feature the `415` used to abort.
- `protocol/cors/accept-acah:15`, `:26`, `:37` (3, newly measured).
- `protocol/cors/preflight-requests:13` (×3) and `:51` (4, newly measured).

### No CORS response headers — 25 scenarios (was 5)

The pod emits no `Access-Control-*` or CORS-relevant `Vary` headers on any response. The
original 5 (`access-control-headers:17`×3, `:32`×2) were never blocked; `:32` now has a third
failure of the same shape — a `POST text/plain` scenario that used to be the `415` row itself,
now unblocked and failing on the same missing header instead. The other 19 were entirely
blocked before:

- `protocol/cors/access-control-headers:17` (×3), `:32` (×3) — 6, one newly unblocked.
- `protocol/cors/acao-vary:13`, `:43` (×2 each, `Access-Control-Allow-Origin` missing) and
  `:28`, `:58` (×2 each, `Vary` omits `Origin` — the pod's `Vary` says `Accept` only) — 8, all
  newly measured.
- `protocol/cors/simple-requests:17`, `:33`, `:49`, `:68` — 10, all newly measured.
- `protocol/cors/enumerate-headers:14` — 1, newly measured.

All 38 scenarios that fail across the seven `protocol/cors/*` features split cleanly between
the two gaps above: 13 of `OPTIONS`'s 15 live in `cors/*` (`preflight`, `acao-vary`,
`accept-acah`, `preflight-requests` — the other 2 are `read-method-support`, not a CORS
feature at all) plus all 25 CORS-header failures — `13 + 25 = 38`, matching the per-feature
table exactly. No CORS-feature scenario in this run fails for a third reason.

### `PATCH` — 66 scenarios (was 3)

This pod has no `PATCH` route at all (`rg PATCH src/` finds nothing); axum's method dispatch
answers `405` before authentication, `Content-Type`, or anything else about the request is
ever inspected. The original 3 were never blocked:

- `protocol/writing-resource/containment:38` — unchanged from run 1.
- `protocol/authentication/header:40` — unchanged. The other **five** anonymous rows in this
  feature still pass, `WWW-Authenticate` included.
- `protocol/writing-resource/content-type-reject:19` — the third of the three
  `content-type-reject` scenarios (see Bucket 3): `PATCH` with no `Content-Type` still answers
  `405`, not the `400` the other two now correctly get.

The other **63** were blocked by the `text/plain` `callonce` abort and are newly measured —
every `PATCH`-method row in every `wac/protected-operation/{read,write}-access-*` feature,
without exception:

| Feature | New `PATCH` failures |
|---|---|
| `read-access-agent` | 10 |
| `read-access-bob` | 10 |
| `read-access-public` | 10 |
| `write-access-agent` | 12 |
| `write-access-bob` | 12 |
| `write-access-public` | 9 |

Each is a `retry until <expected-status>` step that never converges, because `405` is never
one of the awaited statuses (`403`, `401`, or `[200, 201, 204, 205]` depending on the row) —
karate gives up after 3 attempts and reports `too many retry attempts: 3`, which reads
differently in `harness.log` than an ordinary assertion mismatch but has the identical root
cause. **This is now the largest single gap in the suite** — see the reconciliation below.

---

## Bucket 2 — Pending decision (8 scenarios)

The pod behaves deliberately and differently from the test. **Do not change these without a
decision.** `content-type-reject` left this bucket in the third run — see Bucket 3 — and
`DELETE` of a reserved-but-never-created resource (below) took its place; the count is 8
either way, coincidentally.

### `DELETE` of a reserved-but-never-created resource — 3 scenarios

| | |
|---|---|
| **Test wants** | `403` for `DELETE` of a `fictive` resource — one the suite reserved a name for but never created — authorized only through an ancestor's `acl:default` grant |
| **Pod does** | `404` |
| **Why** | `authorize` (`src/http.rs:993`) grants `Write` via the same inherited `acl:default` rule that lets the identical setup delete a `plain` or `rdf` resource correctly. With authorization settled, `aux::delete_subject` finds nothing to remove and returns `Ok(false)`, mapped to `404` (`src/http.rs:1052-1063`). The pod's stated policy is that `authorize` runs before any existence check so a caller *without* access learns nothing; here the caller *has* access, and what it learns (nothing exists at this name) is arguably correct, not a leak — 404 for "authorized, but not there" is a defensible answer the suite happens to score against 403. New this run: previously blocked by the `text/plain` `callonce` abort in the same feature. |

### `post-target-not-found` — 4 scenarios

| Line | Test wants | Pod does | Why |
|---|---|---|---|
| `:13` | `404` — POST to a container that does not exist | `201` | The pod materialises missing ancestors on write. A reserved-but-absent container is created rather than reported missing. |
| `:27`, `:41`, `:55` | `404` or `405` — POST to a non-container URL | `409` | `post_impl` answers `409` from the *request path shape* alone, before any existence check, so an unauthorized caller cannot use POST as an existence oracle (`src/http.rs:372-383`). `404` would require disclosing existence; `405` would be a method claim the pod does not want to make about resource URLs. |

### `containment:122` — 1 scenario

| | |
|---|---|
| **Test wants** | `404` for `POST …/dahut3/foo/` where `dahut3` exists as a *resource* |
| **Pod does** | `409` with body `another resource already exists whose URI differs from this one only in the trailing slash` |
| **Why** | Ancestor materialisation would have to create `dahut3/` beside the existing `dahut3`, which Protocol §3.1 forbids; `refuse_slash_pair` (`src/wac/guard.rs:81`) stops it. |

**This is the only failure the new trailing-slash-pair rule touches, and it did not create
it.** Without the rule the pod would have materialised `dahut3/` and answered `201` — still
not the `404` the test asserts. The rule changed the shape of an already-failing scenario, not
the count. It belongs with `post-target-not-found`: the same ancestor-materialisation decision,
surfacing as `409` instead of `201`.

---

## Bucket 3 — Defect (9 scenarios failing — 2 more resolved this run; D1–D3 were resolved before it)

### `content-type-reject` — RESOLVED (Plan 10, `7debec9`) — reclassified from Bucket 2, and fixed

Previously filed here as a pending decision (see the second run's document, now superseded):
"`format_for_content_type` is the single gate … RFC 9110 supports `415` … the suite reads
Protocol's 'MUST reject' as `400`." All three legs of that reasoning fail, and
[the design](../superpowers/specs/2026-07-29-non-rdf-resources-design.md) §9 is where the
correction was made before this run, not after it:

1. **The conflation argument does not survive the three-way gate.** It held only while
   "unsupported type" and "absent type" meant the same thing — no write. §8.1 of the design
   separates them: an unsupported type is now a blob, not a refusal. What is left at the gate
   is "absent" and "malformed", which were never the same question.
2. **The RFC 9110 citation was half-read.** §8.3 covers an *absent* type with a MAY
   (`application/octet-stream`), not a `415` — that status is for an *unsupported* one. Citing
   it for "absent" was reading the wrong paragraph.
3. **Solid Protocol §2.2 names `400` in its normative text**, not merely implies it: "Server
   MUST reject `PUT`, `POST`, and `PATCH` requests that contain content but lack the
   `Content-Type` header field, with a status code of `400`." The suite was quoting the spec,
   not interpreting around it.

`PUT` and `POST` without `Content-Type` now answer `400` — confirmed, `content-type-reject`
is `2/3`. The third case is `PATCH`, and it still answers `405`: this pod has no `PATCH`
route at all, so the method check fires before `Content-Type` is ever inspected — the same
cause as every other `PATCH` failure below, not a residual of this defect.

### D1 — RESOLVED (`0336247`) — `POST` ignored `Link: rel="type"`, so containers could not be created by POST

`slash-semantics-exclude:65` (1 scenario). `post_impl` never reads the `Link` header
(`src/http.rs:370-406`); `container::child_name` always yields a slash-free segment, so a POST
always creates a *resource* and `Location` never ends in `/`.

```
POST /c/  Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"  Content-Type: text/turtle
→ 201, Location: /c/<name>      # expected Location to end in "/"
```

The POST itself succeeds (line 63 passes); only `assert childContainerUrl.endsWith('/')` fails.
This also silently costs the two "POST with a Slug should conflict" halves of the same feature.

### D2 — RESOLVED (`3cb0723`) — no `Allow` header on GET/HEAD

`read-method-allow:12`, `:19`, `:26`, `:33` (4 scenarios). The spec makes this a MUST; the pod
emits no `Allow` header anywhere.

```
GET /c/   (authenticated)  → 200, no Allow header    # expected Allow to contain GET, HEAD
```

Cheapest item on the whole list. Filed as a defect rather than a gap because it was never a
deliberate omission — unlike `WAC-Allow`, which is a feature.

### D3 — RESOLVED (Plan 9) — JSON-LD named graphs were dropped on write

`content-negotiation-named-graphs:16` (1 scenario). `rdf::parse` used to iterate quads and
discard `q.graph_name`, flattening everything into the resource's single graph. Plan 9
replaced the graph-only parse/serialize/ETag path with `Format` and `Skolemized`, which
carry graph names through the whole round trip (design spec §3, §4, §6).

```
PUT /c/x.json  Content-Type: application/ld+json   (body contains an @graph with a named graph)
GET /c/x.json  Accept: application/ld+json
→ 200, and parse(response).contains(expected) is now true
```

`content-negotiation-turtle` (2/2) and `content-negotiation-jsonld` (2/2) both still pass, so
plain Turtle↔JSON-LD negotiation is unaffected.

### New — POST into a container whose own grant is `accessTo`-only (6 scenarios)

`wac/protected-operation/write-access-{agent,bob,public}`, the `POST … type: container`
rows, 2 per feature (`resource: W` and `resource: A`, `container: no`).

| | |
|---|---|
| **Test wants** | `POST` into an existing, empty *nested* container succeeds when that container holds a *direct* (`acl:accessTo`) Append/Write grant on itself |
| **Pod does** | Denies (retry against `[200, 201, 204, 205]` exhausts 3 attempts) |
| **Why** | `post_impl` authorizes twice: `Mode::Append` on the container being posted into (`src/http.rs:638`), then `Mode::Append` on the *newly-allocated child* (`src/http.rs:680`, via `authorize_and_materialize`, `src/wac/guard.rs:216-232`). The container check passes — it finds the container's own `accessTo` grant. The child check does not: the child has no ACL of its own, so it walks up to the container's ACL and is evaluated as *inherited*, which `pdp::decide` scores against `acl:default` only, never `acl:accessTo` (`src/wac/pdp.rs:54-55`, deliberately: "The two never cross over"). A grant written as `acl:accessTo` alone — exactly what the suite's fixture writes when the container itself, not its future children, is what's being tested — never satisfies the child gate. |

Verified by cross-referencing every example row against pass/fail: `container: W` / `resource:
inherited` (the container's grant *is* `acl:default`) passes; `container: no` / `resource: W`
(the same container, but the grant is `accessTo`-only) fails. Same target, same effective
modes by any reading of Solid Protocol's own text — POST authorization is a property of the
container being posted into — different result, because the pod additionally requires a
mode on the *child*, and that requirement can only be satisfied by inheritance. The two-gate
design is deliberate (`src/http.rs:674-679`'s comment: a child may carry an ACL that
grants *less* than the container), but nothing in that reasoning requires the *inheritance*
predicate specifically — an `accessTo` grant on the container is exactly as much "the
container's own ACL" as a `default` one, and Solid Protocol does not ask a POST to also hold
a mode on a resource that does not exist yet. Filed as a defect, not a pending decision: no
document records this as intended.

### New — DELETE of a container authorized only through inheritance (3 scenarios)

`wac/protected-operation/write-access-{agent,bob,public}`, the `DELETE … type: container`
row, `container: W` (direct + `acl:default`), `resource: inherited` (no ACL of its own).

| | |
|---|---|
| **Test wants** | `403` — deleting a container must not be authorized purely by an ancestor's `acl:default` grant |
| **Pod does** | `204` — deletes it |
| **Why** | `delete_impl`'s only authorization for the target (`src/http.rs:993`) is `authorize(target, Mode::Write)`, and `authorize` does not distinguish "Write reached via my own ACL" from "Write reached via an ancestor's `acl:default`" (`src/wac/pdp.rs:54`, by design, for ordinary resources). The identical setup deletes a `plain` or `rdf` resource correctly (those pass — see `write-access-agent`'s `DELETE … type: plain/rdf, container: W, resource: inherited` rows, both `[200, 202, 204, 205]`). Deleting a *container* is where the suite draws a line this pod does not: removing a whole subtree apparently needs more than the mode an ancestor happens to cascade down. |

The `fictive` counterpart of this test — same `container: W`/`resource: inherited` setup,
same inherited grant, `DELETE` of a resource that was never created rather than an existing
container — also fails, but for a different reason (`404` instead of `403`, not an incorrect
allow). It is filed in Bucket 2, not here — see `post-target-not-found`'s neighbour above.

---

## Bucket 4 — Unclassified (0 scenarios)

Every one of the first run's 615 failures was attributed to a named cause, verified against
either the harness log's response line or the pod's source. Nothing left over. As of the
second run, 609 remained, all attributed. As of the third, below, 173 remain, every one
attributed — the last twelve (nine newly-filed defects, three re-filed in Bucket 2) needed a
decompile of the harness's own Java fixture-builder, cross-referenced against every example
row's pass/fail state, to pin down; see the third run's section for how.

---

## What passed, and is therefore not on anyone's list

Unchanged from the second run — still fully passing, still worth stating:

| | |
|---|---|
| `if-none-match-asterisk` | 2 / 2 |
| `post-uri-assignment` | 1 / 1 |
| `post-uri-assignment-slug` | 1 / 1 |
| `uri-assignment` | 1 / 1 |
| `method-not-allowed` | 2 / 2 |
| `describedby-unique` | 2 / 2 |
| `content-negotiation-turtle` | 2 / 2 |
| `content-negotiation-jsonld` | 2 / 2 |
| `content-negotiation-named-graphs` | 1 / 1 |
| anonymous `401` rows in `authentication/header` | 5 / 6, `WWW-Authenticate` present |

**Two features that were reported `2/3` in the second run's document are now `3/3`:**
`delete-remove-containment` and `delete-protect-nonempty-container`. Both third scenarios
were the `text/plain`-fixture failure the old document flagged by name; both now pass
untouched, having needed nothing but Plan 10 itself.

**`slash-semantics-exclude` is `4/4`**, not just its first scenario — the other three build
`text/plain` fixtures that used to make the whole feature abort.

**All four `acl-object` features are `3/3`.** Every one of these builds a `text/plain`
resource in its `callonce` setup; every one now runs its ACL-object assertions to completion
and passes them.

**WAC access decisions are correct for the large majority of newly-measured cases.** This is
the finding Plan 10 existed to produce, not a side effect of it: 434 of the 540 scenarios this
run newly measures — 80% — pass outright. `read-access-{agent,bob,public}` each go from
untestable to `80/90`; `write-access-{agent,bob}` to `68/84`; `write-access-public` to `40/53`.
Every failure among those six features has a named cause above (`PATCH`, or one of the two
new `POST`/`DELETE` findings) — none is an ordinary Read/Write/Append/Control decision coming
out wrong. The ~370 rows the second run's document called "genuinely unmeasured" and "the real
reason to do #1 first" are measured now, and WAC held up.

**The new auxiliary URL shape still works, including for blobs.** The harness's
`PREPARE SERVER` step created a container and set an ACL on it through the
`Link`-advertised `/.aux/acl/{path}` URL, and the four `wac-allow` features exercise ACL
writes and reads repeatedly with every access decision correct. **No failure in this run
traces to the ACL URL shape or to the blob path specifically** — every blob-involving
failure traces to `PATCH`, `POST`, or `DELETE` gaps that apply identically to RDF resources.

**The trailing-slash-pair rule still costs nothing.** Exactly one scenario mentions it
(`containment:122`), and that scenario failed before the rule existed too — see Bucket 2.

---

## Reproducing

```bash
./conformance/run.sh                       # ~4 min including the build
```

Artifacts:

```
conformance/reports/report.html            human-readable, per-request
conformance/reports/report.ttl             EARL, for diffing against the next run
conformance/.run/harness.log               every failure with its response line
conformance/.run/karate/karate-reports/    karate's own summary + karate-summary-json.txt
```

`karate-summary-json.txt` is the fastest way to regenerate the per-feature table:

```bash
jq -r '.featureSummary[] | "\(.passedCount)/\(.scenarioCount)\t\(.relativePath)"' \
  conformance/.run/karate/karate-reports/karate-summary-json.txt | sort
```
