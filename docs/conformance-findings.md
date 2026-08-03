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

## Fifth run — after the `Vary` fix (`9d47b1a`)

| | |
|---|---|
| **Date** | 2026-07-30 |
| **Pod commit** | `9d47b1a` (the merged tree above plus this one fix) |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 567 | 85 |

Same 41 features, same 652 scenarios as every prior run. This is a re-measurement of the
merged tree above plus one commit, not a sixth parallel slice: `9d47b1a` fixed the `Vary`
defect the merged run filed (Bucket 3, now resolved below) — `cors_layer` now joins
`Origin` into the handler's existing `Vary` value as one field line instead of appending
a second line. 27 → 29 of 41 features now pass every scenario, 12 (was 14) have at least
one failure: `cors/simple-requests` and `cors/acao-vary` flip to fully green;
`cors/preflight-requests` gains two passes but still has one failure, so it stays in the
failing column. Exactly the 10 scenarios the finding predicted moved, and nothing else
did:

| Feature | Fourth run | Fifth run | Δ |
|---|---|---|---|
| `cors/simple-requests` | 6/10 | **10/10** | +4 |
| `cors/acao-vary` | 8/12 | **12/12** | +4 |
| `cors/preflight-requests` | 1/4 | **3/4** | +2 |

`557 + 10 = 567`. Verified against `conformance/.run/harness.log` and
`conformance/.run/karate/karate-reports/karate-summary-json.txt` for this run: every other
feature's pass/fail split — including both `write-access-*` and `read-access-*` line
numbers within `wac/protected-operation` — matches the fourth run exactly, not assumed
from the arithmetic.

### The 85 residual failures, reconciled feature by feature

| Cause | Scenarios | Bucket | Status |
|---|---|---|---|
| No `PATCH` route | 66 | 1 | unchanged gap |
| `DELETE` of a container/fictive resource via inherited-only access | 6 | 2 + 3 | unchanged (3 defect, 3 pending-decision) |
| `POST` into a container whose grant is `accessTo`-only | 6 | 3 | unchanged |
| `post-target-not-found` (ancestor materialization) | 4 | 2 | unchanged since the first run |
| CORS/`OPTIONS` scheme-rewrite redirect, unreachable over `http` | 2 | 1 | unchanged in kind |
| `containment:122` (trailing-slash pair) | 1 | 2 | unchanged since the first run |
| **Total** | **85** | | |

`66 + 6 + 6 + 4 + 2 + 1 = 85`. The `Vary` row that used to sit here is gone outright, not
folded into another cause — see Bucket 3. Every other row's count is identical to the
merged run's table above; only the `Vary` line was removed.

Feature-by-feature, only three rows changed from the merged run's list:

- **`cors/simple-requests` (10/10)** — the four `Vary` failures (`:53` ×2, `:71` ×2) are
  gone. Fully passing; moved to "What passed" below.
- **`cors/acao-vary` (12/12)** — the four `Vary` failures (`:28` ×2, `:58` ×2) are gone.
  Fully passing; moved to "What passed" below.
- **`cors/preflight-requests` (3/4)** — the two `Vary` failures at `:36` are gone; `:51`
  still fails, and it is the same `@http-redirect` shape as `cors/preflight:28`: `[301,
  308]` expected, `204` returned, because this pod is dialled over `http` in the harness
  and the scheme-rewrite the scenario relies on is a no-op. Confirmed directly in
  `harness.log` for this run — `:51` is the only `ERROR` line left under this feature.

Every other feature's failing lines are byte-for-byte the same as the merged run —
confirmed against `harness.log` line by line for `post-target-not-found`, `preflight`,
`content-type-reject`, `containment`, `authentication/header`, and all six
`wac/protected-operation` features, including the exact scenario-line numbers cited in
the merged run's reconciliation above. None of them touch `Vary`, so none of them had
anywhere to move.

`45 (write-access-*) + 30 (read-access-*) = 75` of the 85 still sit inside
`wac/protected-operation`, unchanged; the other 10 are `post-target-not-found` 4,
`preflight` 1, `preflight-requests` 1, `content-type-reject` 1, `containment` 2, `header`
1 (`4+1+1+1+2+1 = 10`). `75 + 10 = 85`.

### The ranking, rederived

With `Vary` resolved, `PATCH` is more dominant than ever — it is now **78% of every
remaining failure** (66 of 85), up from 69% in the merged run. What used to be rank 2
(`Vary`, 10) is gone outright rather than replaced; second and third place are now a
genuine tie, both inherited from the blob-alone measurement and both worth 6 scenarios:

| Rank | Gap | Scenarios | Bucket | Note |
|---|---|---|---|---|
| 1 | **`PATCH` not implemented** | **66** | 1 | dominant residual cause, more so now that `Vary` is gone |
| 2 | **`DELETE` via inherited-only access** | **6** | 2 + 3 | tied with rank 2 below (3 defect, 3 pending-decision) |
| 2 | **`POST` into an `accessTo`-only container** | **6** | 3 | tied with rank 2 above |
| 4 | **`post-target-not-found`** | **4** | 2 | unchanged since the first run |
| 5 | **CORS/`OPTIONS` scheme-rewrite redirect (needs `https`)** | **2** | 1 | unchanged in kind |
| 6 | **`containment:122`, trailing-slash pair** | **1** | 2 | unchanged since the first run |

`66 + 6 + 6 + 4 + 2 + 1 = 85`. Honestly: there is no second-place gap on its own anymore —
just two 6-scenario defects, neither larger than the other, both already filed in Bucket 3
and unrelated to this fix.

## Sixth run — after N3 Patch (`d485135`)

| | |
|---|---|
| **Date** | 2026-07-30 |
| **Pod commit** | `d485135976795d0f5a6029a8f69029462b1993dd` (the fifth run's tree plus the N3 Patch work), **re-measured at `83f270e`** |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 632 | 20 |
| harness's MUST-linked subset | 38 | 649 | 621 | 20 |

Four whole-branch review fixes landed after this run — a container's LDP type is re-asserted after a patch, a formula predicate whose object names no formula is refused, and two guards gained the tests that pin them. The suite was run again at `83f270e` and produced the identical **632 / 20**, with the same seven failing features at the same counts, so every number below holds for the branch as it merges rather than only for the commit it was first measured at.

Same 41 features, same 652 scenarios as every prior run. **34 of the 41 now pass every
scenario and 7 have at least one failure**, against 29 and 12 in the fifth run. 85 residual
failures fall to 20.

One deviation in method, stated up front: this run's `karate-reports/` directory holds only
the summary pages (`karate-summary.html`, `karate-summary-json.txt`, `karate-tags.html`,
`karate-timeline.html`) — no per-feature HTML, which earlier runs used for per-scenario
detail. `conformance/reports/report.html` carries the same detail as EARL/RDFa — every
scenario's title, every step, and each step's `earl#passed` / `earl#failed` — and is what the
per-scenario claims below are checked against, alongside `harness.log` for the response lines.

### Which rows moved, and which did not

Eight features gained; four features that still fail did not move at all. A feature that
gained has no `ERROR` line left under it in `harness.log` and its own `failed: 0` banner; a
feature that did not move carries the same `ERROR` lines, at the same scenario line numbers,
as the fifth run. Both were read out of the log, not inferred from the totals.

| Feature | Fifth run | Sixth run | Δ |
|---|---|---|---|
| `wac/protected-operation/read-access-agent` | 80/90 | **90/90** | +10 |
| `wac/protected-operation/read-access-bob` | 80/90 | **90/90** | +10 |
| `wac/protected-operation/read-access-public` | 80/90 | **90/90** | +10 |
| `wac/protected-operation/write-access-agent` | 68/84 | **80/84** | +12 |
| `wac/protected-operation/write-access-bob` | 68/84 | **80/84** | +12 |
| `wac/protected-operation/write-access-public` | 40/53 | **49/53** | +9 |
| `protocol/authentication/header` | 5/6 | **6/6** | +1 |
| `protocol/writing-resource/content-type-reject` | 2/3 | **3/3** | +1 |

`10 + 10 + 10 + 12 + 12 + 9 + 1 + 1 = 65`, and `567 + 65 = 632`. Every one of the 65 is a
`PATCH` row — accounted for individually in the next section.

Did not move. Named individually rather than left as a remainder:

| Feature | Fifth run | Sixth run | `ERROR` lines in `harness.log` |
|---|---|---|---|
| `protocol/writing-resource/post-target-not-found` | 0/4 | 0/4 | `:13`, `:27`, `:41`, `:55` |
| `protocol/writing-resource/containment` | 3/5 | 3/5 | `:38`, `:122` |
| `protocol/cors/preflight` | 1/2 | 1/2 | `:28` |
| `protocol/cors/preflight-requests` | 3/4 | 3/4 | `:51` |

The other 29 features were fully green in the fifth run and are fully green here — each one's
`passedCount` equals its `scenarioCount` in this run's `karate-summary-json.txt`, checked row
by row, and none of them appears in `harness.log`'s `>>> failed features:` block. `29 + 5
newly green + 4 unmoved + 3 write-access-* still partially red = 41`.

### The 66-scenario `PATCH` gap, accounted for

**65 of the 66 are green. One is not, and it is not a defect.** Every row the fifth run filed
under "No `PATCH` route" is named here:

| Rows | Where | Outcome |
|---|---|---|
| 30 | `read-access-{agent,bob,public}`, 10 each | **Green** |
| 33 | `write-access-{agent,bob}` 12 each, `write-access-public` 9 | **Green** |
| 1 | `protocol/authentication/header:40` | **Green** |
| 1 | `protocol/writing-resource/content-type-reject:19` | **Green** |
| 1 | `protocol/writing-resource/containment:38` | **Still red** — moved to Bucket 1 |

`30 + 33 + 1 + 1 + 1 = 66`.

- **The 30 `read-access-*` rows** are the `Bob cannot PATCH …` / `Public cannot PATCH …`
  outlines at `read-access-{agent,bob}` Examples rows `95`–`104` and `read-access-public`
  `99`–`108`. Each sends `Content-Type: text/n3` with a `solid:InsertDeletePatch` body and
  runs `retry until responseStatus == 403` (`401` for the Public subject). All 30 report
  `earl#passed` on that step, and all three features are `90/90` with no `ERROR` line.
  `authorize` runs before the body is parsed, which is all these rows ever needed.
- **The 33 `write-access-*` rows** are the Examples rows at `write-access-{agent,bob}`
  `109`–`120` and `write-access-public` `85`–`93`. They split three ways, and **all three
  parts are green, including the 18 that were a measurement rather than a prediction**:
  - **18 rows await `2xx`** — `… can PATCH to a rdf resource …` and `… can PATCH to a fictive
    resource …`, 6 per feature (`109`–`114`, `109`–`114`, `85`–`90`), under `W` and `A` grants
    both direct and inherited. These are the only rows in the suite that drive parse → mode
    check → apply → write end to end, and the `fictive` ones exercise creation through a patch
    against an absent target. The design (§14) declined to predict them; they pass.
  - **9 rows await `403`** — the `Control`-only grants (`115`–`117`, `115`–`117`, `91`–`93`).
  - **6 rows await `401`** — the Public subject against a non-public resource (`118`–`120`
    in `write-access-agent` and `write-access-bob`; `write-access-public` has no such row,
    which is why it contributes 9 and not 12).
- **`authentication/header:40`** — `Unauthenticated user gets an appropriate response on
  PATCH`, `Then status 401`, `earl#passed`. The route exists, so the auth layer answers
  before axum's method dispatch can say `405`.
- **`content-type-reject:19`** — `Server rejects PATCH requests without Content-Type`,
  `earl#passed`. The patch handler's `Content-Type` gate is now reachable and answers `400`
  for a non-empty body with no type, the same answer `PUT` and `POST` already gave.
- **`containment:38`** — `PATCH creates a grandchild resource and intermediate containers`,
  the only row in the suite that sends `application/sparql-update`. Still red; see Bucket 1.

**Neighbouring `PATCH` rows that were never part of the 66 did not regress.** Six rows per
`read-access-*` feature (Examples `122`–`124` and `131`–`133`; `126`–`128` and `135`–`137` for
`read-access-public`) send `Content-Type: text/plain` and accept
`[403, 405, 415]` — `[401, 405, 415]` for the Public subject. They passed on `405` when there
was no route; they pass now that there is one. That is 18 scenarios which could have gone red
on a careless gate and did not.

### The 20 residual failures, reconciled feature by feature

| Cause | Scenarios | Bucket | Status |
|---|---|---|---|
| `POST` into a container whose grant is `accessTo`-only | 6 | 3 | unchanged |
| `DELETE` of a container/fictive resource via inherited-only access | 6 | 2 + 3 | unchanged (3 defect, 3 pending-decision) |
| `post-target-not-found` (ancestor materialization) | 4 | 2 | unchanged since the first run |
| CORS/`OPTIONS` scheme-rewrite redirect, unreachable over `http` | 2 | 1 | unchanged in kind |
| `containment:122` (trailing-slash pair) | 1 | 2 | unchanged since the first run |
| `containment:38` (`application/sparql-update`) | 1 | 1 | **reclassified** — was "No `PATCH` route" |
| **Total** | **20** | | |

`6 + 6 + 4 + 2 + 1 + 1 = 20`. The `PATCH`-route row that dominated every table since the
second run is gone from this one; nothing was folded into another cause to make it disappear.

Verified line by line, feature by feature:

- **`writing-resource/post-target-not-found` (0/4)** — the same four responses as every run
  since the first: `:13` → `status code was: 201, expected: 404`; `:27` and `:41` → `409` not
  in `[404, 405]`; `:55` → `409` not in `[404, 405, 415]`. Bucket 2.
- **`writing-resource/containment` (3/5)** — `:122` → `status code was: 409, expected: 404,
  … response: another resource already exists whose URI differs from this one only in the
  trailing slash`, unchanged (Bucket 2). `:38` is the `application/sparql-update` row, now
  Bucket 1.
- **`cors/preflight` (1/2)** and **`cors/preflight-requests` (3/4)** — `:28` and `:51`, both
  `[301, 308] contains responseStatus` failing on `204`. The `@http-redirect` rows: this pod
  is dialled over `http` in the harness, so the scheme rewrite is a no-op. Bucket 1,
  unchanged.
- **`wac/protected-operation/write-access-{agent,bob,public}` (80/84, 80/84, 49/53)** — four
  failures each, and only two shapes remain now that the `PATCH` rows are green:
  - **`POST`, 2 per feature.** `harness.log`: `When method POST` / `too many retry
    attempts: 3` at `write-access-agent:62`, `write-access-bob:62`, `write-access-public:47`,
    twice each. The Examples rows are `78` and `80` (`agent`, `bob`) and `62` and `64`
    (`public`): `… can write a container resource (POST) and cannot read it, when … has no
    access to the container and W / A access to the resource`. The `accessTo`-only defect,
    Bucket 3.
  - **`DELETE`, 2 per feature.** `When method DELETE` / `too many retry attempts: 3` at
    `write-access-agent:128`, `write-access-bob:127`, `write-access-public:100`, twice each.
    Examples rows `147`/`151` (`agent`), `146`/`150` (`bob`), `119`/`123` (`public`): one
    `… cannot DELETE a fictive resource …` (Bucket 2) and one `… cannot DELETE a container
    resource …` (Bucket 3), both `W access to the container` / `inherited access to the
    resource`.
  - `2 + 2 = 4` per feature, `4 × 3 = 12`.

`12` of the 20 sit inside `wac/protected-operation`; the other 8 are `post-target-not-found`
4, `containment` 2, `preflight` 1, `preflight-requests` 1. `12 + 8 = 20`.

### The ranking, rederived

`PATCH` was 78% of the fifth run's residual. It is now one scenario, and that scenario is a
media type the Protocol never defined. The two 6-scenario findings that shared rank 2 are
promoted to a shared rank 1 unchanged — neither has been touched since the blob-alone
measurement first surfaced them:

| Rank | Gap | Scenarios | Bucket | Note |
|---|---|---|---|---|
| 1 | **`POST` into an `accessTo`-only container** | **6** | 3 | tied with rank 1 below |
| 1 | **`DELETE` via inherited-only access** | **6** | 2 + 3 | tied with rank 1 above (3 defect, 3 pending-decision) |
| 3 | **`post-target-not-found`** | **4** | 2 | unchanged since the first run |
| 4 | **CORS/`OPTIONS` scheme-rewrite redirect (needs `https`)** | **2** | 1 | unchanged in kind; needs an `https` deployment, not a code change |
| 5 | **`containment:122`, trailing-slash pair** | **1** | 2 | unchanged since the first run |
| 5 | **`containment:38`, `application/sparql-update`** | **1** | 1 | new to this list; refused by design |

`6 + 6 + 4 + 2 + 1 + 1 = 20`.

The shape of what is left has changed, not just its size. Of the 20, **9 are defects**
(Bucket 3), **8 are decisions this pod made deliberately and has written down** (Bucket 2),
and **3 are gaps it will not close** (Bucket 1: two need `https`, one needs a media type the
specification does not contain). There is no longer a single dominant cause, and no
unimplemented feature on the list at all.

---

## Seventh run — after RDF 1.2 support

| | |
|---|---|
| **Date** | 2026-07-30 |
| **Pod commit** | `35ee057` (RDF 1.2 on the wire, merged with `main`) |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 632 | 20 |
| harness's MUST-linked subset | 38 | 649 | 621 | 20 |

**Identical to the sixth run, and that is the result being reported.** RDF 1.2 support adds a
`version` media-type parameter to responses and three new refusals to the write path; the
question this run answers is whether any of it reached a scenario that was passing before.
None did — same 632 / 20, same seven failing features.

That outcome is designed rather than lucky. the pod emits the `version`
parameter **only** on resources that classify above RDF 1.1, and no conformance scenario creates
one, so every response the harness sees is byte-identical to the sixth run's — a strict
`Content-Type: text/turtle` comparison never meets a parameter it did not expect. The design's
first draft stamped the parameter on every RDF response; five of this repo's own tests caught
that before the harness could, and the rule was narrowed (design §5, §11 risk 3). The write-side
refusals — `400` for a body richer than it declared, `415` for an unknown version label or one
the store cannot hold, `409` for a write below a resource's own version — are all unreachable
from a 1.1 client, which is what the harness is.

An earlier measurement of this work reported 567 / 85. That number described the pre-merge
branch, which forked before N3 Patch and shape validation reached `main`; it is superseded by
this one rather than contradicted by it.

The 20 residual failures are unchanged and are the same ones reconciled below.

## Eighth run — regression check on six unmeasured slices

| | |
|---|---|
| **Date** | 2026-08-03 |
| **Pod commit** | `247d24f` |

| | Features | Scenarios | Passed | Failed |
|---|---|---|---|---|
| karate (everything that ran) | 41 | 652 | 632 | 20 |
| harness's MUST-linked subset | 38 | 649 | 621 | 20 |

**Identical to the seventh run, and that is the result being reported.** Six feature slices
landed on `main` between `35ee057` and this commit without the suite being run once:
shape validation, `Accept-Put`/`Accept-Post`, auth caching, CLI config and the
persistent store, the request-scoped guard, and change events. This run asks one
question — did any of them reach a scenario that was passing before — and the answer is no.
Nothing moved in either direction.

**Shape validation was the named risk, and it is the one worth stating the evidence for.** It
is the only slice of the six that can *refuse* a write, and the suite writes fixtures
constantly. A refusal inside a feature's `Background` does not fail one scenario; it aborts
the whole feature before any assertion runs — the mechanism that took out 540 scenarios at the
`text/plain` fixture through the first two runs. That did not happen: `harness.log` reports
`features: 41 | skipped: 0` and `scenarios: 652`, the same 41 and 652 as every run since the
first, so every feature reached its assertions. No feature aborted, and none was skipped.

The 20 failures are **line-identical to the sixth and seventh runs, not merely equal in
count** — every `ERROR` line in `harness.log` carries the same feature and scenario line
number as before:

| Feature | Scenario lines | Scenarios | Cause |
|---|---|---|---|
| `writing-resource/post-target-not-found` | `:13`, `:27`, `:41`, `:55` | 4 | ancestor materialization (Bucket 2) |
| `wac/protected-operation/write-access-{agent,bob,public}` | `:62`, `:62`, `:47`, ×2 each | 6 | `POST` into an `accessTo`-only container (Bucket 2 — **reclassified**, was Bucket 3) |
| `wac/protected-operation/write-access-{agent,bob,public}` | `:128`, `:127`, `:100`, ×2 each | 6 | `DELETE` via inherited-only access (3 Bucket 3, 3 Bucket 2) |
| `cors/preflight` | `:28` | 1 | `@http-redirect`, needs `https` (Bucket 1) |
| `cors/preflight-requests` | `:51` | 1 | same |
| `writing-resource/containment` | `:122` | 1 | trailing-slash pair (Bucket 2) |
| `writing-resource/containment` | `:38` | 1 | `application/sparql-update` (Bucket 1) |
| **Total** | | **20** | |

`4 + 6 + 6 + 1 + 1 + 1 + 1 = 20`. The response lines are unchanged too, quoted from this run's
own log rather than carried over: `post-target-not-found:13` → `status code was: 201,
expected: 404`; `containment:122` → `status code was: 409, expected: 404 … another resource
already exists whose URI differs from this one only in the trailing slash`; both
`@http-redirect` rows → `[301,308]` does not contain `204`; `containment:38` → `did not
evaluate to 'true': responseStatus >= 200 && responseStatus < 300`, still with no response
line, for the reason Bucket 1 names.

The per-feature counts behind those failures are unchanged as well —
`write-access-{agent,bob}` at `80/84` each and `write-access-public` at `49/53`, read out of
this run's `karate-summary-json.txt`. **34 of 41 features pass every scenario, 7 have at least
one failure**, the same 34 and 7 as the sixth and seventh runs.

One deviation in method, the same one the sixth run declared: this run's `karate-reports/`
directory holds only the summary pages, no per-feature HTML. The claims above come from
`harness.log`'s `ERROR` lines and its per-feature `failed:` banners, and from
`conformance/reports/report.html` for per-scenario detail.

The buckets below hold the same 20 scenarios, but **one row changed bucket after this
run** — not because the pod or the measurement moved, but because the specification was
looked up. The six `POST`-into-an-`accessTo`-only-container scenarios move from Bucket 3
(defect) to Bucket 2 (pending decision); the reasoning and its sources are in that entry.
The split is now **3 expected gap, 14 pending decision, 3 defect** — `3 + 14 + 3 = 20`,
against `3 + 8 + 9` before. Bucket 4 stays empty.

## Bucket 1 — Expected gap (3 scenarios, as of the sixth run)

Features this pod deliberately does not have, or environment limits the harness cannot
clear.

### Non-RDF resources — RESOLVED (Plan 10, `feat/non-rdf-resources`)

`PUT`/`POST` with a non-RDF `Content-Type` stores the body as a blob (`docs/architecture.md`, Storage model) instead of
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

### CORS response headers — RESOLVED, including `Vary` (see Bucket 3)

`access-control-headers`, `accept-acah`, and `enumerate-headers` — 10 of 38 `cors/*`
scenarios — pass every case, including `Access-Control-Allow-Origin`,
`Access-Control-Expose-Headers` (present and not `*`), and `Access-Control-Allow-Headers`
mirroring what was requested. Every `Access-Control-Allow-Origin` and
`Access-Control-Expose-Headers` assertion in the other four `cors/*` features also
passes. What remained after the merged run — 10 scenarios across `simple-requests`,
`preflight-requests`, and `acao-vary` — was a single defect in how `Vary` was emitted, not
a missing header; `9d47b1a` fixed it, and `simple-requests`/`acao-vary` are now fully
green (see Bucket 3 and the fifth run above). The only `cors/*` failures left are the two
`@http-redirect` scenarios noted above, unrelated to response headers.

### `PATCH` — RESOLVED as a route (N3 Patch); 1 scenario remains, and it is a media type this pod refuses by design

The pod implements N3 Patch: `PATCH` with a `text/n3` body against an RDF document, per
Solid Protocol §5.3.1. `patch_impl`
(`src/http.rs:484`) authorizes before it parses, gates on `Content-Type`, and applies the
patch — including against an absent target, which creates the resource. `Accept-Patch:
text/n3` travels with `Allow` on every `GET`/`HEAD`/`OPTIONS` (`src/http.rs:182`). 65 of the
66 scenarios this section used to list are green as of the sixth run.

What remains is `protocol/writing-resource/containment:38`, and it is a deliberate gap rather
than a defect:

| | |
|---|---|
| **Test sends** | `PATCH` with `Content-Type: application/sparql-update` and body `INSERT DATA { <#hello> <#linked> <#world> . }`, asserting `responseStatus >= 200 && responseStatus < 300` |
| **Pod does** | `415` — the `Content-Type` gate accepts `text/n3` and nothing else (`src/http.rs:509-511`) |
| **Why** | `application/sparql-update` does not appear in the Solid Protocol at all — not as a MUST, not as a MAY, not as a mention. It is pre-N3-Patch ecosystem behaviour that the bundled `specification-tests` v0.0.19 still encodes. Accepting it would mean executing a client-authored database command against a store holding every resource, every ACL, and the server's own system graphs, separated from a `DROP ALL` only by a rejection list that must stay exhaustive against a `spargebra` AST that may gain a variant in any minor release (`docs/decisions.md`, ADR-8). This is the only row in the whole suite that uses this media type. Adding it later remains possible and would be its own design. |

One honest note on the evidence: `harness.log` records this row as `did not evaluate to
'true': responseStatus >= 200 && responseStatus < 300` — karate prints a status only for
`status` and `match` steps, not for `assert` — so there is **no response line in the log for
this scenario**. The `415` is attributed from the request the per-scenario EARL detail in
`conformance/reports/report.html` shows being sent (`header Content-Type =
'application/sparql-update'`, `method PATCH`, both `earl#passed`) together with the gate at
`src/http.rs:509-511` and its unit test (`the_content_type_gate_matches_classify_body`,
`text/turtle` → `415`). That is a source attribution, not a measured response line, and it is
named as one.

<details>
<summary>What used to fail here (first through fifth run)</summary>

Before the route existed, axum's method dispatch answered `405` before authentication,
`Content-Type`, or anything else about the request was ever inspected:

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

`10×3 + 12×2 + 9 + 1 + 1 + 1 = 66`. Each `wac/protected-operation` row was a
`retry until <expected-status>` step that never converged, because `405` was never one of the
awaited statuses (`403`, `401`, or `[200, 201, 204, 205]` depending on the row) — karate gave
up after 3 attempts and reported `too many retry attempts: 3`. It was the largest single gap
in the suite for four consecutive runs.

</details>

---

## Bucket 2 — Pending decision (14 scenarios)

The pod behaves deliberately and differently from the test. **Do not change these without
a decision.**

### `POST` into a container whose own grant is `accessTo`-only — 6 scenarios

`wac/protected-operation/write-access-{agent,bob,public}`, the `POST … type: container`
rows, 2 per feature (`resource: W` and `resource: A`, `container: no`).

| | |
|---|---|
| **Test wants** | `POST` into an existing, empty *nested* container succeeds when that container holds a *direct* (`acl:accessTo`) Append/Write grant on itself |
| **Pod does** | Denies (retry against `[200, 201, 204, 205]` exhausts 3 attempts) |
| **Why** | `post_impl` authorizes twice: `Mode::Append` on the container (`src/http.rs:1540`), then `Mode::Append` on the newly-allocated child (`src/http.rs:1593`). The container check passes on its `accessTo` grant. The child check does not: the child has no ACL of its own, so `Guard::decide_from` walks up to the container's ACL and evaluates it as *inherited*, which `pdp::decide` scores against `acl:default` only (`src/wac/pdp.rs:61`). An `accessTo`-only grant never satisfies the child gate. |

**The pod's behaviour is what the specification says, and the test encodes what the
reference implementation does.** WAC's normative text makes the child the subject of the
check — "when an operation requests to create a resource as a member of a container
resource, the server MUST match an Authorization allowing the `acl:Append` or `acl:Write`
access privilege (as needed by the operation) *on the resource to be created*". The
resource to be created has no ACL, so its effective ACL is the container's (WAC's
effective-ACL algorithm: walk up to the first ACL with a representation), and within it
only `acl:default` reaches "a resource lower in the collection hierarchy" — the definition
of `acl:default` itself. An `accessTo`-only container therefore grants the new resource
nothing.

That reading is settled, not inferred: [solid/specification#186] asked whether an
`acl:accessTo` rule in a container's ACL can apply to a child that has no ACL of its own,
and the answer — closed by the editor as "consensus is deemed to be captured in WAC
Editor's Draft" — is that step 3 of the walk inherits *only* rules marked `acl:default`,
"therefore no rules grant access, therefore all access is denied".

CSS diverges, and the bundled suite follows CSS. `ParentContainerReader` translates a
`create` on the target into an `append` on the parent — `if
(modes.has(AccessMode.create)) { containerModes.add(AccessMode.append); }` — so the check
lands on the container itself, in `accessTo` scope. WAC has no `create` mode for this to
map onto; CSS mints one internally.

**Reclassified from Bucket 3 (defect) on 2026-08-03.** The sentence that filed it there —
"no document records this as intended" — was false: the specification's own text and
[solid/specification#186] both do. Nothing about the pod changed; what changed is that the
question was looked up rather than assumed. The divergence is open with the community, and
until it resolves this pod keeps the spec-literal behaviour. If the outcome is that the
spec text is too narrow, the fix is small and belongs in the creation path, not in
`pdp::decide` — the `accessTo`/`acl:default` separation is load-bearing everywhere else
(it is what lets an ACL grant read on a container's members without granting a listing of
the container).

[solid/specification#186]: https://github.com/solid/specification/issues/186

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
| **Why** | Ancestor materialisation would have to create `dahut3/` beside the existing `dahut3`, which Protocol §3.1 forbids; the slash-pair check in `Guard::materialize` (`src/wac/guard.rs:319-328`) stops it. |

**This is the only failure the trailing-slash-pair rule touches, and it did not create
it.** Without the rule the pod would have materialised `dahut3/` and answered `201` —
still not the `404` the test asserts. The rule changed the shape of an already-failing
scenario, not the count. It belongs with `post-target-not-found`: the same
ancestor-materialisation decision, surfacing as `409` instead of `201`.

---

## Bucket 3 — Defect (3 scenarios failing)

### `content-type-reject` — RESOLVED (Plan 10) — reclassified from Bucket 2, and fixed

Previously filed here as a pending decision (see the second run's document, now
superseded): "`format_for_content_type` is the single gate … RFC 9110 supports `415` …
the suite reads Protocol's 'MUST reject' as `400`." All three legs of that reasoning
fail, and the correction is:

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

`PUT`, `POST` and `PATCH` without `Content-Type` all answer `400` — `content-type-reject` is
`3/3` as of the sixth run. The `PATCH` leg was the last to arrive: until the route existed,
axum's method check fired before `Content-Type` was ever inspected and the answer was `405`,
which was a residual of the `PATCH` gap and not of this defect.

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

### CORS `Vary` header shipped as two separate lines — RESOLVED (`9d47b1a`) — was 10 scenarios

`protocol/cors/simple-requests:53` (×2), `:71` (×2); `protocol/cors/preflight-requests:36`
(×2); `protocol/cors/acao-vary:28` (×2), `:58` (×2).

| | |
|---|---|
| **Test wanted** | On a CORS-eligible, content-negotiated `GET`/`HEAD`, one `Vary` header whose value contains `Origin` (alongside `Accept`) |
| **Pod did** | Sent `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers` correctly, but the response the harness read back had `Vary: Accept` only |
| **Why** | `cors_layer` (`src/http.rs:73-90`) is deliberately the outermost layer so it can add CORS fields after the handler has already set `Vary: Accept` for content negotiation (§6.3). Its comment said why it used `append` rather than `insert`: "a negotiated read has already set `Vary: Accept`, and replacing it would make a cache serve the wrong representation." But `HeaderMap::append` added a *second, separate* `Vary` header line rather than combining the value into the existing one. RFC 9110 §5.3 permits a recipient to treat repeated header fields as equivalent to one comma-joined field, but the harness's HTTP client reads only the first `Vary` line it receives — `Accept` — and never sees `Origin`. Confirmed by the per-scenario report for `cors/simple-requests:53`: the request did send `Origin`, and `Access-Control-Allow-Origin`/`Access-Control-Expose-Headers` both passed (proving `cors_layer` ran and reached the `Vary` line), yet the `Vary` assertion still failed on the split header. This is the record of why a two-line `Vary` is a defect and not a legal-but-unusual choice: RFC 9110 permits repeating a list-valued field, but a client that reads the first line and stops sees half the list — and the conformance harness is exactly such a client. |

Genuinely new when first measured: previously unmeasurable in `main` alone (CORS features
that reach this code path build a `text/plain` fixture and aborted on `415`) and
unmeasurable in `feat/non-rdf-resources` alone (the CORS headers this defect concerns did
not exist on that tree at all). It explained why `access-control-headers`, `accept-acah`,
and `enumerate-headers` were fully passing while `simple-requests`, `preflight-requests`,
and `acao-vary` were not: only the latter three exercise a `GET`/`HEAD` where content
negotiation has already written a `Vary: Accept` before `cors_layer` appends `Origin`.

**Fixed by `9d47b1a`**: `cors_layer` now reads whatever `Vary` value is already present,
splits it on commas, adds `Origin` only if it is not already listed, and writes the whole
set back with a single `insert` — one field line, e.g. `Vary: Accept, Origin`, instead of
two. Re-run confirms all 10 scenarios now pass: `cors/simple-requests` and `cors/acao-vary`
are `10/10` and `12/12`; the two `Vary` failures at `preflight-requests:36` are gone (see
the fifth run above).

---

## Bucket 4 — Unclassified (0 scenarios)

Every one of the first run's 615 failures was attributed to a named cause, verified
against either the harness log's response line or the pod's source. As of the second run,
609 remained, all attributed. As of the merged run, all 95 remaining failures were
attributed — cross-checked against `conformance/.run/harness.log`'s response lines and the
per-scenario detail in `conformance/.run/karate/karate-reports/*.html` for every one of
the 14 features with a failure, not sampled. As of the fifth run, `9d47b1a` removed the
`Vary` cause outright (10 scenarios) rather than folding it into another one, leaving 85 —
`66 + 6 + 6 + 4 + 2 + 1 = 85` — re-verified the same way against this run's own
`harness.log` and `karate-summary-json.txt`, feature by feature, for all 12 features with
a failure. Nothing left over.

As of the sixth run, 20 remain — `6 + 6 + 4 + 2 + 1 + 1 = 20` — and every one is attributed
to a named cause: each of the 7 features with a failure was read out of `harness.log`'s
`ERROR` lines and cross-checked against the per-scenario EARL detail in
`conformance/reports/report.html`, which also supplied the Examples-row line numbers for the
`wac/protected-operation` outlines. The 65 scenarios that went green were checked the same
way rather than deduced from the totals: each was located by scenario title in
`report.html` with `earl#passed` on its asserting step, and each of the six features involved
carries a `failed: 0` banner in `harness.log`. One attribution is deliberately weaker than
the rest and says so — `containment:38`'s `415` comes from the source gate and its unit test,
because karate prints no status for a failed `assert` step. Bucket 4 stays empty, but that
row is the closest thing in this run to an inference.

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
| `cors/simple-requests` | 10 / 10 (as of the fifth run — `9d47b1a`) |
| `cors/acao-vary` | 12 / 12 (as of the fifth run — `9d47b1a`) |
| `authentication/header` | 6 / 6 (as of the sixth run — `d485135`; the anonymous `PATCH` row included, `WWW-Authenticate` present) |
| `content-type-reject` | 3 / 3 (as of the sixth run — `d485135`) |
| all three `read-access-*` features | 90 / 90 each (as of the sixth run — `d485135`) |

**The new auxiliary URL shape works, including for blobs.** The harness's
`PREPARE SERVER` step created a container and set an ACL on it through the
`Link`-advertised `/.aux/{path}.acl` URL, and the five `wac-allow` features exercise ACL
writes and reads repeatedly with every access decision correct. **No failure in this run
traces to the ACL URL shape or to the blob path specifically** — every blob-involving
failure traces to `PATCH`, `POST`, or `DELETE`, all of which apply identically to RDF
resources. `Vary` was the fourth such gap; `9d47b1a` fixed it (see Bucket 3).

**WAC access decisions are correct for the large majority of newly-measured cases.** 434
of the 540 scenarios the non-RDF work unblocked — 80% — passed outright at the merged run,
when `read-access-{agent,bob,public}` each reached `80/90`, `write-access-{agent,bob}`
`68/84`, and `write-access-public` `40/53`. As of the sixth run the three `read-access-*`
features are `90/90`, `write-access-{agent,bob}` are `80/84`, and `write-access-public` is
`49/53` — 12 failures across the six, all of them the `POST`/`DELETE` findings above. No
failure in these features has ever been an ordinary Read/Write/Append/Control decision coming
out wrong.

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
