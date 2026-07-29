# Conformance findings — first run

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

## One gap accounts for almost everything

**540 of the 615 failures — 88% — are one missing feature: non-RDF resources.**

`format_for_content_type` answers `None` for `text/plain`, so the pod returns `415`. The
suite builds `text/plain` fixtures in `callonce` backgrounds, and a `callonce` that throws
takes its whole feature with it. Six WAC `protected-operation` features (491 scenarios), five
CORS features (30), all four `acl-object` features (12), and seven more scenarios scattered
across `containment`, `delete-*`, `acl-propagation` and `slash-semantics-exclude` **never
reach an assertion at all**. Nothing downstream of that `415` has been measured.

Ranked by scenarios unblocked, the work is:

| Rank | Gap | Scenarios | Note |
|---|---|---|---|
| 1 | **non-RDF / blob resources** | **540** | 88% of all failures; unblocks, does not automatically pass |
| 2 | `WAC-Allow` header | 50 | pure header work; the access decisions underneath already pass |
| 3 | `Allow` header on GET/HEAD | 4 | classified as a defect below — a MUST, and cheap |
| 4 | `OPTIONS` | 4 | 2 of them are also CORS |
| 5 | CORS headers | 5 | the other 30 CORS scenarios are blocked by #1, not by CORS |
| 6 | `PATCH` | 2 | |

Rank 1 is not a free 540. Those scenarios become *runnable*, not green: within the 491
`protected-operation` rows, 124 target a `text/plain` resource and **81 exercise `OPTIONS` or
`PATCH`**, so expect roughly that many to fail on ranks 4 and 6 the moment the `415` clears.
The rest — ~370 rows of WAC access-mode assertions — are genuinely unmeasured today. That is
the real reason to do #1 first: it is the only way to find out whether WAC is correct.

---

## Bucket 1 — Expected gap (601 scenarios)

Features this pod deliberately does not have.

### Non-RDF resources — 540 scenarios

`PUT`/`POST` with `Content-Type: text/plain` (or any non-RDF type) → `415`.

| Feature | Scenarios | How it fails |
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

### `WAC-Allow` header — 50 scenarios

The pod never emits `WAC-Allow`. Every one of these failures is the single assertion
`match header WAC-Allow != null`; **no access decision failed anywhere in these features.**

| Feature | Failed / total |
|---|---|
| `wac/wac-allow/header-exists` | 2 / 2 |
| `wac/wac-allow/user-access-direct` | 12 / 14 |
| `wac/wac-allow/user-access-indirect` | 12 / 14 |
| `wac/wac-allow/public-access-direct` | 12 / 14 |
| `wac/wac-allow/public-access-indirect` | 12 / 14 |

### `OPTIONS` — 4 scenarios

No `OPTIONS` route exists (`rg OPTIONS src/` finds nothing), so axum answers `405`.

- `protocol/read-write-resource/read-method-support:31` and `:36` — `assert responseStatus != 405` on a container and a resource.
- `protocol/cors/preflight:12` and `:28` — expected `[200, 204]` / `[301, 308]`, got `405`.

### CORS — 5 scenarios

`protocol/cors/access-control-headers` at `:17` (×3, anonymous) and `:32` (×2, credentialed):
the status assertions pass, `match header Access-Control-Allow-Origin == config.origin` finds
`null`. **Only 5 of the 38 CORS scenarios actually fail on CORS** — the other 33 are blocked
upstream by `text/plain` (30) or `OPTIONS` (2) or are the 415 row above (1).

### `PATCH` — 2 scenarios

- `protocol/writing-resource/containment:38` — `PATCH` with `application/sparql-update`, expected 2xx.
- `protocol/authentication/header:40` — anonymous `PATCH` expected `401`, got `405`. The
  method check fires before authentication. Worth noting: the other **five** anonymous rows in
  this feature pass, `WWW-Authenticate` included — that predicted gap does not exist.

---

## Bucket 2 — Pending decision (8 scenarios)

The pod behaves deliberately and differently from the test. **Do not change these without a
decision.**

### `content-type-reject` — 3 scenarios

| | |
|---|---|
| **Test wants** | `400` for a write with no `Content-Type` at all (PUT, POST, PATCH) |
| **Pod does** | `415` (PUT/POST); PATCH is `405` |
| **Why** | `format_for_content_type` is the single gate for "can I parse this body?", and a missing type is answered the same way as an unparseable one. RFC 9110 supports `415` for an unsupported/absent representation type; the suite reads Protocol's "MUST reject" as `400`. |

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

## Bucket 3 — Defect (0 scenarios — all three resolved as of the second run, above)

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

---

## Bucket 4 — Unclassified (0 scenarios)

Every one of the first run's 615 failures was attributed to a named cause, verified against
either the harness log's response line or the pod's source. Nothing left over. As of the
second run, 609 remain — see the reconciliation above.

---

## What passed, and is therefore not on anyone's list

Worth stating, because several of these were flagged as suspects before the run:

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
| `delete-remove-containment` | 2 / 3 (the third is a `text/plain` fixture) |
| `delete-protect-nonempty-container` | 2 / 3 (same) |
| `slash-semantics-exclude` scenario 1 | PUT container then resource of the same name — passes |
| anonymous `401` rows in `authentication/header` | 5 / 6, `WWW-Authenticate` present |

**The new auxiliary URL shape works.** The harness's `PREPARE SERVER` step created a container
and set an ACL on it through the `Link`-advertised `/.aux/{path}.acl` URL, and the four
`wac-allow` features exercise ACL writes and reads repeatedly with every access decision
correct. **No failure in this run traces to the ACL URL shape.**

**The trailing-slash-pair rule cost nothing.** Exactly one scenario mentions it
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
