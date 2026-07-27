# Running the Solid Conformance Suite — Design

**Date:** 2026-07-27
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §13 (Success Criteria)
**Evidence:** `.superpowers/sdd/conformance-suite-research.md`

## 1. Why now

Conformance is a success criterion of the parent design, not a nicety: *"Passes the Solid
Protocol and WAC conformance test suites for the implemented surface."* Seven plans in, it
has never been run.

Two of this project's larger decisions — moving the ACL to a reserved `/.aux/` prefix, and
advertising it only through `Link: rel="acl"` — were justified by *reading* what the suite
does. That research was sound, but it is still research. And the last change before this one
found that percent-encoded paths had never authenticated at all, since Plan 4: `normalize_htu`
keeps escapes while `derive_htu` decoded them, so every such request was a 401. A conformance
run finds that class of thing in minutes; three plans of careful review did not.

## 2. What we run

`solid-contrib/conformance-test-harness` (the runner) against
`solid-contrib/specification-tests` (the tests), via the published
`solidproject/conformance-test-harness` image. Two manifests:

- **`protocol`** — 25 features: LDP CRUD, containment, content negotiation,
  `If-None-Match: *`, CORS, auth headers.
- **`web-access-control`** — 16 features: `acl:accessTo`/`acl:default` scoping, propagation,
  `WAC-Allow`.

The 12 `sparql-update` PATCH features live in `protocol/converted/` and are commented out of
the harness's own `application.yaml`, so having no PATCH costs almost nothing here.

**Not run:** `web-access-control-tests` (frozen 2022) and `solid-crud-tests` (2023) both
authenticate through an NSS-style login cookie via the deprecated `solid-auth-fetcher`, have
no client-credentials path, and test websockets and notifications. Skipping them is a
research finding, not laziness.

## 3. Credentials, and why a verify-only pod is testable

The harness's `AuthManager` supports session login, refresh token, client credentials, or
local registration — no static-token mode. Crucially the IdP and the server under test are
configured independently (`USERS_*_IDP` vs `TEST_CONTAINER`), and it presents tokens as
`Authorization: DPoP <token>` — exactly the path this pod verifies. So **client credentials
from an external IdP work**, and the pod never needs to issue anything.

Two configuration details that are not obvious:

- `TEST_CONTAINER` must be an **absolute pod URL**. That skips the harness's `findStorage()`,
  which would otherwise require `pim:storage` in the WebID *and* a `rel="type"` `pim:Storage`
  link this pod does not emit.
- `POD_BASE_URI` must be **byte-identical** to the origin the harness dials, or every DPoP
  `htu` comparison fails.

## 4. `--allow-insecure-host`

### The obstacle

The pod's outbound fetches — OIDC discovery, JWKS, and the WebID document that binds a WebID
to its issuer — go through an SSRF-hardened client that refuses loopback, RFC 1918,
link-local, CGNAT and IPv6 ULA, follows no redirects, pins the validated IP, and is
https-only. That hardening exists because the fetch happens **before any credential is
verified**: an attacker who can make the pod fetch an attacker-chosen URL has a
pre-authentication SSRF primitive.

The consequence is that a locally-run IdP and locally-hosted test WebIDs are unreachable by
construction. Note the trap for this project's own infrastructure: **Tailscale is `100.64/10`,
which the CGNAT rule blocks** — a CSS in the tailnet is as unreachable as one on `localhost`.

### The rule that actually matters

The distinction is not *private versus public*. It is **named by the operator versus chosen by
the attacker**. Plan 5 already built the first half of that: `--trusted-issuer` rejects a
token whose `iss` is not listed *before any fetch is attempted*.

So: a repeatable `--allow-insecure-host <host>`. For exactly the hosts listed there, and only
for them:

- the private/loopback/CGNAT IP filter does not apply;
- `http` is permitted (a local CSS usually is not behind TLS).

Everything else stays, for every host without exception: redirects are still refused, the
connection is still pinned to the validated IP against DNS rebinding, the body cap and the
timeout still apply.

### What this costs, stated plainly

For a host on that list the SSRF surface is open again — someone who can make the pod process
a token with `iss: http://localhost:3000/` reaches that one host. That is the price of local
operation working at all, it is bounded by exactly the entries the operator typed, and it is
what `--trusted-issuer` should be paired with in any deployment that uses it.

**Not built:** a global "allow private addresses" switch. It would make the pre-authentication
primitive reachable in a release binary with one flag, which is the opposite of what the
hardening was for.

**Also not built:** a separate test binary wiring the static resolvers. It would work, but it
would test a binary nobody deploys and would leave the real fetch path unexercised — which is
precisely the gap this plan exists to close.

## 5. The runner

`run-against-sparql-pod.sh`, modelled on the suite's `run-against-css.sh` but shorter,
because two things the CSS script does are unnecessary here:

- **No ACL bootstrap.** The CSS script does `curl -X PUT $SUT/.acl`. Here that would be an
  ordinary resource write that silently achieves nothing — ACLs live at `/.aux/{path}.acl` and
  are discovered through the `Link` header. The pod provisions its root ACL for
  `--owner-webid` at boot with the identical grant, so there is nothing to bootstrap.
- **No cookie harvesting or WebID seeding.** Client credentials replace both.

What it must do: start a local CSS as IdP, register the test users and mint client
credentials with the harness's own `createCredentials.js`, start the pod with
`--allow-insecure-host` and `--trusted-issuer` pointing at that CSS, run both manifests, and
collect the report. Cleanup between runs is a pod restart — the store is in-memory.

## 6. What we expect to fail

From the research, split by what a failure would mean:

**Expected gaps, not defects:** CORS (7 features), `WWW-Authenticate`/`Allow`/`WAC-Allow`
headers (7), `OPTIONS` → 405 (2 scenarios), PATCH (2 partial).

**The dominant one, and it was not on our list:** the pod stores **no non-RDF content** —
`format_for_content_type` answers 415 for `text/plain`. All six WAC `protected-operation`
features build a `plain` fixture first, inside a `callonce` background, so they abort
wholesale rather than failing individually. This outranks PATCH and CORS by a wide margin.

**Decisions, not reflex fixes:** `content-type-reject` expects 400 where the pod answers 415;
`post-target-not-found` expects 404 where the pod materialises ancestors and answers 201. Both
are deliberate behaviours here, so each needs a decision rather than a patch.

**Would indicate a real defect:** POST/`Slug`/`Location` handling, `If-None-Match: *`,
containment removal, 409 on a non-empty container, Turtle↔JSON-LD negotiation, the four
`acl-object` features, the anonymous-401 rows — or any failure inside `prepareServer`.

## 7. Non-goals

- Fixing everything the run reports. This plan ends with a triaged findings document; what
  gets fixed is decided from evidence afterwards.
- Non-RDF/blob support. It is the largest single blocker and it is its own plan.
- CI integration. Worth doing once the run is reproducible; not before.

## 8. Success criteria

- Both manifests run to completion against the pod, from one command, with no manual steps.
- Every failure is classified as expected gap, pending decision, or defect — with the
  evidence for the classification.
- The real outbound fetch path (OIDC discovery, JWKS, WebID) is exercised, against the
  production binary rather than a test-only build.
- `--allow-insecure-host` relaxes nothing for a host not listed, and a test proves it.

## 9. Open questions

1. Whether CSS client-credentials tokens carry `webid` and `iss` in the exact form this pod
   compares. Verify before writing the runner; it is the most likely place the whole setup
   stalls.
2. Whether the conneg tests' `parse(...).contains(expected)` round-trip survives a
   triple-store backend that does not preserve prefixes or blank-node labels.
3. The two POST `slash-semantics` scenarios, which the research could not resolve from the
   test source.
