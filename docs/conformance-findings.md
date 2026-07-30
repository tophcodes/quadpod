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

## Two parallel measurements — not a sequence

After the second run, two feature slices were developed independently from the same base
(`1fe4953`): PR #1 on `main` added `WAC-Allow`, `OPTIONS`, and CORS response headers;
`feat/non-rdf-resources` added non-RDF (blob) resource storage. Each branch measured the
conformance suite against its own tree, without the other branch's work present. Neither
number below describes a tree anyone would ship — each is missing the other branch's
feature, and each one's document names the other's feature as its own rank-1 open gap.
Presenting them as a third and then a fourth run would imply a sequence that never
happened; they are two data points about two different trees, both superseded by the
merged measurement that follows.

### `main` alone — after PR #1 (`WAC-Allow`, `OPTIONS`, CORS headers)

| | |
|---|---|
| **Pod commit** | `143584d` |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 101 | 551 |

Passed rose by **58** over the second run, and all 58 land in a small set of features:

| Feature | Second run | This measurement | Δ |
|---|---|---|---|
| `wac/wac-allow/header-exists` | 0 / 2 | 2 / 2 | +2 |
| `wac/wac-allow/user-access-direct` | 2 / 14 | 14 / 14 | +12 |
| `wac/wac-allow/user-access-indirect` | 2 / 14 | 14 / 14 | +12 |
| `wac/wac-allow/public-access-direct` | 2 / 14 | 14 / 14 | +12 |
| `wac/wac-allow/public-access-indirect` | 2 / 14 | 14 / 14 | +12 |
| `protocol/read-write-resource/read-method-support` | 4 / 6 | 6 / 6 | +2 |
| `protocol/cors/preflight` | 0 / 2 | 1 / 2 | +1 |
| `protocol/cors/access-control-headers` | 0 / 6 | 5 / 6 | +5 |

All 50 `WAC-Allow` scenarios that were failing now pass, not merely the `!= null`
assertion that used to stop them — including the case the header's shape depends on,
where the owner reads a resource whose ACL names only Bob and the `user` group still
reports `control`. The five CORS features that did **not** move — `simple-requests`,
`acao-vary`, `preflight-requests`, `accept-acah`, `enumerate-headers` — all build a
`text/plain` fixture in their `Background` and abort there on this tree, because this
branch has no non-RDF support; their CORS assertions never ran here.

### `feat/non-rdf-resources` alone — after Plan 10 (non-RDF resources)

| | |
|---|---|
| **Pod commit** | `7debec9` |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 479 | 173 |

Passed rose by **436** over the second run. The `text/plain`-fixture abort that used to
take out whole features is gone on this tree, so 540 scenarios that never reached an
assertion before ran to completion: **434 of them passed outright** — the WAC
access-decision logic this pod already had turned out to be correct for the large
majority of the ~370 previously-unmeasured access-mode assertions. The other 106 failed
for four causes, none of them new in kind: 63 more `PATCH` failures (this branch has no
`PATCH` route), 20 more CORS-header failures and 11 more `OPTIONS` failures (this branch
has neither, `main`'s work being absent here), and 12 genuinely new findings — 6 `POST`
into an `accessTo`-only container, 6 `DELETE` via inherited-only access — that this
measurement was the first to surface, because they only exist once a resource can be
created to test them against. `content-type-reject` also went from `0/3` to `2/3`,
independent of unblocking: it was never blocked by the fixture abort, it was simply wrong
(design spec §9), and Plan 10 fixed it.

Both measurements are complete records of what each slice did alone; both are superseded
by the merge below wherever they disagree with it.

## Fourth run — merged (`main` + `feat/non-rdf-resources`)

| | |
|---|---|
| **Date** | 2026-07-30 |
| **Pod state** | merge in progress: `main` (`6654711`, PR #1) united with `feat/non-rdf-resources` (`a7f3627`), common ancestor `751f7bf` |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 557 | 95 |

Same 41 features, same 652 scenarios as every prior run. Of the 41, **27 pass every
scenario and 14 have at least one failure.** This is the current truth: the tree that
ships is neither branch alone, and its number is neither 101 nor 479.

**The gain is not a simple sum.** `557 − 43 (second run) − 58 (main alone) − 436 (blob
alone) = 20`. Those 20 scenarios needed *both* slices to pass and could not appear in
either isolated delta: a CORS-header or `OPTIONS`-preflight assertion on a `text/plain`
fixture fails on the missing fixture in `main` alone and on the missing header in
`feat/non-rdf-resources` alone, and only passes where both are present. `accept-acah`
(0 in both isolated measurements' passing counts for this feature) and
`enumerate-headers` are now `3/3` and `1/1` — fully passing only in the merge — which is
this effect directly, not a rounding artefact of the arithmetic.

### The 95 residual failures, reconciled feature by feature

| Cause | Scenarios | Bucket | Status |
|---|---|---|---|
| No `PATCH` route | 66 | 1 | unchanged gap, both slices left it alone |
| CORS `Vary` header ships as two separate header lines | 10 | 3 | **new defect**, measurable for the first time |
| `POST` into a container whose grant is `accessTo`-only | 6 | 3 | unchanged from the blob-alone measurement |
| `DELETE` of a container/fictive resource via inherited-only access | 6 | 2 + 3 | unchanged from the blob-alone measurement (3 defect, 3 pending-decision) |
| `post-target-not-found` (ancestor materialization) | 4 | 2 | unchanged since the first run |
| CORS/`OPTIONS` scheme-rewrite redirect, unreachable over `http` | 2 | 1 | unchanged in kind, now measured in a second feature |
| `containment:122` (trailing-slash pair) | 1 | 2 | unchanged since the first run |
| **Total** | **95** | | |

`66 + 10 + 6 + 6 + 4 + 2 + 1 = 95`. Every failure in this run has one of these seven
names; none is left over — see Bucket 4.

Two gaps that both isolated measurements called open are **fully resolved in the merge**
and do not appear above: `WAC-Allow` (58/58, every scenario in all five `wac-allow`
features) and non-RDF/blob resources (the fixture that used to abort 540 scenarios no
longer exists as a gap at all). `OPTIONS` and CORS response headers are resolved for
every case that does not also depend on the two findings below — see "Did `main`'s and
the blob branch's rankings hold?".

Verified against `conformance/.run/harness.log` and the per-scenario detail in
`conformance/.run/karate/karate-reports/*.html`, feature by feature:

- **`writing-resource/post-target-not-found` (0/4)** — all four failures are the
  unchanged ancestor-materialization behaviour from the first run (`:13` → `201` not
  `404`; `:27`, `:41`, `:55` → `409` not `404`/`405`). See Bucket 2.
- **`cors/preflight` (1/2)** — the one failure (`:28`) is the `@http-redirect` row:
  `[301, 308]` expected, `204` returned, because this pod is dialled over `http` in the
  harness and the scheme-rewrite this scenario relies on is a no-op. Unreachable without
  an `https` deployment.
- **`cors/preflight-requests` (1/4)** — `:36` (×2) fails on `Vary`; `:51` fails on the
  same `@http-redirect` shape as `preflight:28`, newly measured in this feature because
  it used to abort on the `text/plain` fixture.
- **`writing-resource/content-type-reject` (2/3)** — the third scenario is `PATCH` with
  no `Content-Type`: still `405`, because there is no `PATCH` route to reach the
  `Content-Type` gate. Same cause as every other `PATCH` failure, not a residual of the
  content-type-reject defect (which is otherwise fixed — see Bucket 3).
- **`writing-resource/containment` (3/5)** — `:38` is `PATCH` with
  `application/sparql-update`, unchanged from the first run; `:122` is the
  trailing-slash-pair rule, unchanged since the first run — see Bucket 2.
- **`authentication/header` (5/6)** — `:40` is the anonymous `PATCH` row, unchanged
  since the first run. The other five anonymous rows still pass, `WWW-Authenticate`
  included.
- **`cors/simple-requests` (6/10)** — all four failures (`:53` ×2, `:71` ×2) are the
  `Vary` defect below.
- **`cors/acao-vary` (8/12)** — all four failures (`:28` ×2, `:58` ×2) are the same
  `Vary` defect.
- **`wac/protected-operation/write-access-public` (40/53)**, **`write-access-agent`
  (68/84)**, **`write-access-bob` (68/84)** — each splits into exactly three shapes,
  confirmed against the per-scenario HTML report:
  - `POST` into an `accessTo`-only container, 2 scenarios each (`resource: W` and
    `resource: A`, `container: no`) — the `POST`-into-`accessTo`-only-container defect.
  - `PATCH` against a resource the caller is otherwise entitled to write, 12 / 12 / 9
    scenarios — the `PATCH` gap.
  - `DELETE`, 2 scenarios each, both `container: W` / `resource: inherited`: one
    `Bob cannot DELETE a fictive resource…` (never created — Bucket 2) and one
    `Bob cannot DELETE a container resource…` (exists — Bucket 3 defect).
  - `2 + 12 + 2 = 16` (`write-access-agent`, `write-access-bob`); `2 + 9 + 2 = 13`
    (`write-access-public`). `16 + 16 + 13 = 45`.
- **`wac/protected-operation/read-access-agent`, `read-access-bob`, `read-access-public`
  (80/90 each)** — every failure (10 per feature, 30 total) is `method PATCH` at the
  scenario's `retry until responseStatus == 403` step: `405` is never one of the awaited
  statuses, so karate exhausts its retries. No other cause appears in these three
  features.

`45 (write-access-*) + 30 (read-access-*) = 75` of the 95 sit inside
`wac/protected-operation`; the other 20 are the CORS/`OPTIONS`/`PATCH`/pending-decision
scenarios outside it (`post-target-not-found` 4, `preflight` 1, `preflight-requests` 3,
`content-type-reject` 1, `containment` 2, `header` 1, `simple-requests` 4, `acao-vary` 4
— `4+1+3+1+2+1+4+4 = 20`).

### Did `main`'s and the blob branch's rankings hold?

**Neither ranking describes the merged tree**, and each is wrong in a specific,
checkable way:

- **`main`'s ranking still lists non-RDF resources as rank 1, open.** It is not open —
  Plan 10 shipped it, in the other branch this document now merges.
- **The blob branch's ranking lists `WAC-Allow`, CORS headers, and `OPTIONS` as its
  ranks 2, 3, and 4, all open.** `WAC-Allow` is not open: `main`'s work resolves every
  one of its 58 scenarios once the fixture that used to block them exists, with no
  residual. `OPTIONS` is likewise resolved as a route — no scenario in this run fails
  because the pod answers `405` to `OPTIONS` — the only surviving `OPTIONS`-shaped
  failures are the two `@http-redirect` rows, which are an `http`-vs-`https` test
  environment limit, not a missing route. CORS response headers are resolved for three
  of seven `cors/*` features outright (`access-control-headers`, `accept-acah`,
  `enumerate-headers`, all passing every scenario) and for every
  `Access-Control-Allow-Origin` / `Access-Control-Expose-Headers` assertion in the other
  four; what remains in those four is the `Vary` defect below, a narrower and different
  claim than "no CORS response headers" (25 scenarios in the blob-alone count) ever was.

Ranked by scenarios still failing, the merged tree's gaps are:

| Rank | Gap | Scenarios | Bucket | Note |
|---|---|---|---|---|
| 1 | **`PATCH` not implemented** | **66** | 1 | unchanged since the second run; the dominant residual cause, same as the blob-alone measurement found |
| 2 | **CORS `Vary` header ships as two lines** | **10** | 3 | new — only measurable once both a non-RDF fixture and a CORS response existed together |
| 3 | **`DELETE` via inherited-only access** | **6** | 2 + 3 | unchanged from the blob-alone measurement (3 defect, 3 pending-decision) |
| 3 | **`POST` into an `accessTo`-only container** | **6** | 3 | unchanged from the blob-alone measurement |
| 5 | **`post-target-not-found`** | **4** | 2 | unchanged since the first run |
| 6 | **CORS/`OPTIONS` scheme-rewrite redirect (needs `https`)** | **2** | 1 | unchanged in kind; now measured in a second feature |
| 7 | **`containment:122`, trailing-slash pair** | **1** | 2 | unchanged since the first run |

`66 + 10 + 6 + 6 + 4 + 2 + 1 = 95`.

Resolved and off this list entirely: non-RDF resources (540 scenarios, Plan 10),
`WAC-Allow` (58 scenarios, PR #1), the `acl-object` family (12 scenarios, resolved by
Plan 10 alone — these scenarios never touch `WAC-Allow`, `OPTIONS`, or CORS headers, so
they needed only the fixture, not the interaction), `content-type-reject`'s `PUT`/`POST`
legs (Bucket 3), and `OPTIONS` as a route (only its `https`-only redirect edge case
remains, folded into rank 6 above). `accept-acah` and `enumerate-headers`, by contrast,
*are* the interaction: both build the same fixture but also assert CORS headers, so both
needed the merge specifically.

---

## Bucket 1 — Expected gap (68 scenarios, as of the merged run)

Features this pod deliberately does not have, or environment limits the harness cannot
clear.

### Non-RDF resources — RESOLVED (Plan 10, `feat/non-rdf-resources`)

`PUT`/`POST` with a non-RDF `Content-Type` stores the body as a blob (parent spec §5,
`docs/superpowers/specs/2026-07-29-non-rdf-resources-design.md` §3–§8) instead of
answering `415`. Every feature this used to abort now runs to completion.

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

### `WAC-Allow` header — RESOLVED (PR #1, `main`)

The pod emits `WAC-Allow` on every response the five `wac-allow` features check —
58 of 58 scenarios pass, not just the `!= null` assertion that used to stop most of them.
Includes the case the header's shape depends on: the owner reads a resource whose ACL
names only Bob, and the `user` group still reports `control`.

### `OPTIONS` — RESOLVED as a route; 2 scenarios remain, and they are an environment limit

`OPTIONS` answers correctly everywhere the suite checks it as a route:
`read-write-resource/read-method-support` is `6/6`, and no `cors/*` failure in this run
is a `405` on `OPTIONS`. The two that remain are the `@http-redirect` scenarios in
`cors/preflight:28` and `cors/preflight-requests:51`: both rewrite the target's scheme to
`http` and expect a `301`/`308` redirect to the `https` original. This pod is dialled
over `http` in the harness, so the rewrite is a no-op and the request is answered `204`.
Not reachable without an `https` deployment — unchanged in kind since the first run,
newly measured in the second feature because `preflight-requests` used to abort on its
`text/plain` fixture.

### CORS response headers — RESOLVED except one defect (see Bucket 3)

`access-control-headers`, `accept-acah`, and `enumerate-headers` — 10 of 38 `cors/*`
scenarios — pass every case, including `Access-Control-Allow-Origin`,
`Access-Control-Expose-Headers` (present and not `*`), and `Access-Control-Allow-Headers`
mirroring what was requested. Every `Access-Control-Allow-Origin` and
`Access-Control-Expose-Headers` assertion in the other four `cors/*` features also
passes. What remains — 10 scenarios across `simple-requests`, `preflight-requests`, and
`acao-vary` — is a single defect in how `Vary` is emitted, not a missing header; see
Bucket 3.

### `PATCH` — 66 scenarios (unchanged)

This pod has no `PATCH` route at all (`rg PATCH src/` finds nothing but the RFC 9110
citation in a comment); axum's method dispatch answers `405` before authentication,
`Content-Type`, or anything else about the request is ever inspected.

| Feature | `PATCH` failures |
|---|---|
| `wac/protected-operation/read-access-agent` | 10 |
| `wac/protected-operation/read-access-bob` | 10 |
| `wac/protected-operation/read-access-public` | 10 |
| `wac/protected-operation/write-access-agent` | 12 |
| `wac/protected-operation/write-access-bob` | 12 |
| `wac/protected-operation/write-access-public` | 9 |
| `protocol/writing-resource/containment:38` | 1 |
| `protocol/authentication/header:40` | 1 |
| `protocol/writing-resource/content-type-reject:19` | 1 |

`10×3 + 12×2 + 9 + 1 + 1 + 1 = 66`. Each `wac/protected-operation` row is a
`retry until <expected-status>` step that never converges, because `405` is never one of
the awaited statuses (`403`, `401`, or `[200, 201, 204, 205]` depending on the row) —
karate gives up after 3 attempts and reports `too many retry attempts: 3`, which reads
differently in `harness.log` than an ordinary assertion mismatch but has the identical
root cause. **This is the largest single gap in the suite.**

---

## Bucket 2 — Pending decision (8 scenarios)

The pod behaves deliberately and differently from the test. **Do not change these without
a decision.**

### `DELETE` of a reserved-but-never-created resource — 3 scenarios

| | |
|---|---|
| **Test wants** | `403` for `DELETE` of a `fictive` resource — one the suite reserved a name for but never created — authorized only through an ancestor's `acl:default` grant |
| **Pod does** | `404` |
| **Why** | `authorize` (`src/http.rs:993`) grants `Write` via the same inherited `acl:default` rule that lets the identical setup delete a `plain` or `rdf` resource correctly. With authorization settled, `aux::delete_subject` finds nothing to remove and returns `Ok(false)`, mapped to `404`. The pod's stated policy is that `authorize` runs before any existence check so a caller *without* access learns nothing; here the caller *has* access, and what it learns (nothing exists at this name) is arguably correct, not a leak — `404` for "authorized, but not there" is a defensible answer the suite happens to score against `403`. |

Confirmed still present, one instance per `write-access-{agent,bob,public}` feature — the
`DELETE … type: fictive, container: W, resource: inherited` row in each.

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

**This is the only failure the trailing-slash-pair rule touches, and it did not create
it.** Without the rule the pod would have materialised `dahut3/` and answered `201` —
still not the `404` the test asserts. The rule changed the shape of an already-failing
scenario, not the count. It belongs with `post-target-not-found`: the same
ancestor-materialisation decision, surfacing as `409` instead of `201`.

---

## Bucket 3 — Defect (19 scenarios failing)

### `content-type-reject` — RESOLVED (Plan 10) — reclassified from Bucket 2, and fixed

Previously filed here as a pending decision (see the second run's document, now
superseded): "`format_for_content_type` is the single gate … RFC 9110 supports `415` …
the suite reads Protocol's 'MUST reject' as `400`." All three legs of that reasoning
fail, and
[the design](../superpowers/specs/2026-07-29-non-rdf-resources-design.md) §9 is where the
correction was made:

1. **The conflation argument does not survive the three-way gate.** It held only while
   "unsupported type" and "absent type" meant the same thing — no write. §8.1 of the
   design separates them: an unsupported type is now a blob, not a refusal. What is left
   at the gate is "absent" and "malformed", which were never the same question.
2. **The RFC 9110 citation was half-read.** §8.3 covers an *absent* type with a MAY
   (`application/octet-stream`), not a `415` — that status is for an *unsupported* one.
   Citing it for "absent" was reading the wrong paragraph.
3. **Solid Protocol §2.2 names `400` in its normative text**, not merely implies it:
   "Server MUST reject `PUT`, `POST`, and `PATCH` requests that contain content but lack
   the `Content-Type` header field, with a status code of `400`."

`PUT` and `POST` without `Content-Type` answer `400` — confirmed, `content-type-reject`
is `2/3`. The third case is `PATCH`, and it still answers `405`: no `PATCH` route exists,
so the method check fires before `Content-Type` is ever inspected — the same cause as
every other `PATCH` failure, not a residual of this defect.

### D1 — RESOLVED (`0336247`) — `POST` ignored `Link: rel="type"`, so containers could not be created by POST

`slash-semantics-exclude:65` (1 scenario). `post_impl` never reads the `Link` header
(`src/http.rs:370-406`); `container::child_name` always yields a slash-free segment, so a
POST always creates a *resource* and `Location` never ends in `/`.

### D2 — RESOLVED (`3cb0723`) — no `Allow` header on GET/HEAD

`read-method-allow:12`, `:19`, `:26`, `:33` (4 scenarios). The spec makes this a MUST;
cheapest item on the whole list, filed as a defect rather than a gap because it was never
a deliberate omission — unlike `WAC-Allow`, which is a feature.

### D3 — RESOLVED (Plan 9) — JSON-LD named graphs were dropped on write

`content-negotiation-named-graphs:16` (1 scenario). `rdf::parse` used to iterate quads
and discard `q.graph_name`, flattening everything into the resource's single graph. Plan
9 replaced the graph-only parse/serialize/ETag path with `Format` and `Skolemized`, which
carry graph names through the whole round trip.

### `POST` into a container whose own grant is `accessTo`-only — 6 scenarios

`wac/protected-operation/write-access-{agent,bob,public}`, the `POST … type: container`
rows, 2 per feature (`resource: W` and `resource: A`, `container: no`).

| | |
|---|---|
| **Test wants** | `POST` into an existing, empty *nested* container succeeds when that container holds a *direct* (`acl:accessTo`) Append/Write grant on itself |
| **Pod does** | Denies (retry against `[200, 201, 204, 205]` exhausts 3 attempts) |
| **Why** | `post_impl` authorizes twice: `Mode::Append` on the container being posted into (`src/http.rs:638`), then `Mode::Append` on the *newly-allocated child* (`src/http.rs:680`, via `authorize_and_materialize`, `src/wac/guard.rs:216-232`). The container check passes — it finds the container's own `accessTo` grant. The child check does not: the child has no ACL of its own, so it walks up to the container's ACL and is evaluated as *inherited*, which `pdp::decide` scores against `acl:default` only, never `acl:accessTo` (`src/wac/pdp.rs:54-55`, deliberately: "The two never cross over"). A grant written as `acl:accessTo` alone — exactly what the suite's fixture writes when the container itself, not its future children, is what's being tested — never satisfies the child gate. |

Confirmed unchanged from the blob-alone measurement: `container: W` / `resource:
inherited` passes; `container: no` / `resource: W` fails, cross-checked against the
per-scenario report for all three `write-access-*` features. Filed as a defect, not a
pending decision: no document records this as intended.

### `DELETE` of a container authorized only through inheritance — 3 scenarios

`wac/protected-operation/write-access-{agent,bob,public}`, the `DELETE … type: container`
row, `container: W` (direct + `acl:default`), `resource: inherited` (no ACL of its own).

| | |
|---|---|
| **Test wants** | `403` — deleting a container must not be authorized purely by an ancestor's `acl:default` grant |
| **Pod does** | `204` — deletes it |
| **Why** | `delete_impl`'s only authorization for the target (`src/http.rs:993`) is `authorize(target, Mode::Write)`, and `authorize` does not distinguish "Write reached via my own ACL" from "Write reached via an ancestor's `acl:default`" (`src/wac/pdp.rs:54`, by design, for ordinary resources). The identical setup deletes a `plain` or `rdf` resource correctly. Deleting a *container* is where the suite draws a line this pod does not: removing a whole subtree apparently needs more than the mode an ancestor happens to cascade down. |

The `fictive` counterpart of this test — same setup, `DELETE` of a resource that was
never created rather than an existing container — fails for a different reason (`404`
instead of `403`, not an incorrect allow); it is filed in Bucket 2 above.

### CORS `Vary` header ships as two separate header lines — 10 scenarios, new this run

`protocol/cors/simple-requests:53` (×2), `:71` (×2); `protocol/cors/preflight-requests:36`
(×2); `protocol/cors/acao-vary:28` (×2), `:58` (×2).

| | |
|---|---|
| **Test wants** | On a CORS-eligible, content-negotiated `GET`/`HEAD`, one `Vary` header whose value contains `Origin` (alongside `Accept`) |
| **Pod does** | Sends `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers` correctly, but the response the harness reads back has `Vary: Accept` only |
| **Why** | `cors_layer` (`src/http.rs:73-90`) is deliberately the outermost layer so it can add CORS fields after the handler has already set `Vary: Accept` for content negotiation (§6.3). Its comment says why it uses `append` rather than `insert`: "a negotiated read has already set `Vary: Accept`, and replacing it would make a cache serve the wrong representation." But `HeaderMap::append` (`src/http.rs:84`) adds a *second, separate* `Vary` header line rather than combining the value into the existing one. RFC 9110 permits a recipient to treat repeated header fields as equivalent to one comma-joined field, but the harness's HTTP client reads only the first `Vary` line it receives — `Accept` — and never sees `Origin`. Confirmed by the per-scenario report for `cors/simple-requests:53`: the request does send `Origin`, and `Access-Control-Allow-Origin`/`Access-Control-Expose-Headers` both pass (proving `cors_layer` ran and reached the `Vary` line), yet the `Vary` assertion still fails on the split header. |

Genuinely new: previously unmeasurable in `main` alone (CORS features that reach this
code path build a `text/plain` fixture and aborted on `415`) and unmeasurable in
`feat/non-rdf-resources` alone (the CORS headers this defect concerns did not exist on
that tree at all). Explains why `access-control-headers`, `accept-acah`, and
`enumerate-headers` are fully passing while `simple-requests`, `preflight-requests`, and
`acao-vary` are not: only the latter three exercise a `GET`/`HEAD` where content
negotiation has already written a `Vary: Accept` before `cors_layer` appends `Origin`.
The fix is to combine the value into the existing `Vary` header rather than append a
second line — the intent the code comment already states, not met by the method it uses.

---

## Bucket 4 — Unclassified (0 scenarios)

Every one of the first run's 615 failures was attributed to a named cause, verified
against either the harness log's response line or the pod's source. As of the second run,
609 remained, all attributed. As of the merged run, all 95 remaining failures are
attributed above — cross-checked against `conformance/.run/harness.log`'s response lines
and the per-scenario detail in `conformance/.run/karate/karate-reports/*.html` for every
one of the 14 features with a failure, not sampled. `66 + 10 + 6 + 6 + 4 + 2 + 1 = 95`;
nothing left over.

---

## What passed, and is therefore not on anyone's list

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
| `read-method-allow` | 4 / 4 |
| `read-method-support` | 6 / 6 |
| `slash-semantics-exclude` | 4 / 4 |
| `delete-protect-nonempty-container` | 3 / 3 |
| `delete-remove-containment` | 3 / 3 |
| all five `wac-allow` features | 58 / 58 |
| all four `acl-object` features | 12 / 12 |
| `cors/access-control-headers` | 6 / 6 |
| `cors/accept-acah` | 3 / 3 |
| `cors/enumerate-headers` | 1 / 1 |
| anonymous `401` rows in `authentication/header` | 5 / 6, `WWW-Authenticate` present |

**The new auxiliary URL shape works, including for blobs.** The harness's
`PREPARE SERVER` step created a container and set an ACL on it through the
`Link`-advertised `/.aux/{path}.acl` URL, and the five `wac-allow` features exercise ACL
writes and reads repeatedly with every access decision correct. **No failure in this run
traces to the ACL URL shape or to the blob path specifically** — every blob-involving
failure traces to `PATCH`, `POST`, `DELETE`, or the `Vary` gaps above, which apply
identically to RDF resources.

**WAC access decisions are correct for the large majority of newly-measured cases.** 434
of the 540 scenarios the non-RDF work unblocked — 80% — pass outright.
`read-access-{agent,bob,public}` each reach `80/90`; `write-access-{agent,bob}` reach
`68/84`; `write-access-public` reaches `40/53`. Every failure among those six features has
a named cause above (`PATCH`, or one of the two `POST`/`DELETE` findings) — none is an
ordinary Read/Write/Append/Control decision coming out wrong.

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
