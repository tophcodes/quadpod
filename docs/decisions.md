# Decisions

Decisions whose reasoning is long enough, or gets re-proposed often enough, that it needs
its own room. Everything shorter than that lives as a "because …" sentence in
[`architecture.md`](architecture.md), next to the thing it explains, and everything with an
executable check lives in [`constraints.md`](constraints.md).

Each entry states what holds now and why, followed by what would make it wrong. A decision
that no longer holds is rewritten in place — this file is not a log of what was once
believed. Numbers are stable identifiers so code comments can name one; they are not an
order of importance, and **ADR-4 does not exist** and never did.

A decision earns a place here when at least one is true: a plausible alternative was
measured and lost, the choice is deliberately stricter or looser than the specification it
follows, or getting it wrong is silent.

---

## ADR-1 — The WAC decision point is ours

`wac::pdp::decide` is a pure function of this codebase, taking ACL triples plus request
context and returning access modes. `manas_access_control` and `manas_space` are not
dependencies.

**Why.** The decisive property is the shape of the entry point. `WacDecisionPoint::resolve_grants`
never takes an ACL graph — it takes a `SlotAcrChain`, a stream of manas resource slots, and
walks the ancestry itself. That inverts the design here, where the PRP owns the walk and
hands the PDP a finished policy, and it forces `decide()` to become `async` and fallible for
a computation that is neither. Three lesser criteria favoured renting: it compiles, the heavy
`manas_repo` sits behind an off-by-default feature, and the oxigraph-to-sophia conversion is
27 lines. The fourth decided it.

Renting also carries costs that outlive the spike: manas requires an explicit
`a acl:Authorization` (which [ADR-5](#adr-5) deliberately does not), pulls roughly 80 crates
including a parallel end-of-life http 0.2 / hyper 0.14 / tower 0.4 stack, has a
`sophia_api` 0.8-versus-0.10 trap, and carries an `acl:agent`-versus-`acp:agent` namespace
bug.

**What would reopen it.** manas exposing a decision entry point that takes an ACL graph
rather than a slot chain. Or ACP arriving — the standalone `acp` crate was the original
argument for keeping the seam, and it fits behind the same `PolicyDecisionPoint`.

## ADR-2 — `SparqlStore` is dyn-dispatched, and sequence atomicity is the implementor's obligation

`AppState` holds `Arc<dyn SparqlStore>`, object-safe through `async_trait`. Every write path
assumes a `;`-separated update sequence runs as one transaction, and the trait says so.

**Why dynamic dispatch.** A generic `AppState<S>` with static dispatch cannot work: RPITIT
is not object-safe, and pinning `OxigraphStore` into `AppState` would contradict the
capability promise that the backend is config-swappable.

**Why the obligation is stated rather than assumed.** "SPARQL guarantees the sequence is
atomic" is false, and worth recording as false so nobody re-derives it. What actually holds
is narrower and belongs to the implementation:
`BoundPreparedSparqlUpdate::execute` evaluates every operation before calling
`transaction.commit()`, so a runtime failure part-way through commits nothing. That is a
property of `OxigraphStore`, measured, not of the query language.

**What would reopen it.** A second `SparqlStore` implementor — at which point the obligation
stops being a note and becomes something that must be verified. `constraints.md` carries the
tripwire that fires when one appears.

## ADR-3 — DPoP proofs signed RS256 are accepted

Proofs signed RS256 are verified through a pod-owned path dispatched on the header `alg`,
with an RFC 7638 RSA thumbprint for `cnf.jkt`. ES256 goes to `dpop-verifier` untouched.
`none` and the HS\* family stay rejected. Both paths meet at `VerifiedDpop`, so `htu`,
freshness, `cnf.jkt` and the replay check exist once.

**Why.** RFC 9449 permits any asymmetric algorithm except `none` and symmetric ones, so
accepting only ES256 was stricter than the specification without a reason. It was also
disqualifying: the conformance harness signs RS256 unconditionally — `JwsUtils.java` has the
ES256 line commented out and offers no switch — so the whole run aborted before a single
test executed.

Configuring the existing verifier was not an option. At `dpop-verifier` 4.4.0 the algorithm
match is fixed on `(alg, jwk)` and `Jwk` is a closed untagged enum holding only EC-P-256 and
OKP-Ed25519, so an RSA key fails to deserialize before `alg` is ever read. There is no RSA
thumbprint in it either.

**The part that is easy to get wrong.** `cnf.jkt` was computed with `thumbprint_ec_p256`,
which is EC-specific. Widening the accepted algorithms without widening the thumbprint would
have silently broken proof-of-possession for RSA keys — a worse outcome than rejecting them,
because it fails open rather than closed.

**What would reopen it.** `dpop-verifier` gaining RSA support, which would let the pod-owned
path be deleted. Or a decision to advertise a narrower `algs` list in the `WWW-Authenticate`
challenge, which `wac::guard`'s challenge constant would then have to track.

## ADR-5 — An ACL rule does not need an explicit `a acl:Authorization`

Every subject in an ACL graph is a candidate authorization. The type triple is not required.

**Why.** Real-world ACLs frequently omit it and the Community Solid Server accepts them
without it. Requiring it would reject policy documents that every other Solid client
produces — and a rejected ACL is an ACL that silently does not apply, which fails open in
the worst possible place.

**Why it is written down.** It is the single most permissive choice the decision point
makes. In the WAC specification it sits inside a section whose surrounding model — the
sibling-suffix ACL location — has since been superseded, so it reads as though it were part
of the dead text. It is not.

**What would reopen it.** ACP, or a conformance scenario that requires the type triple. The
current suite does not exercise one.

## ADR-6 — RDF 1.2 is served, and silence on the wire means RDF 1.1

The pod stores and serves RDF 1.2. A representation declares itself with the `version`
media-type parameter going in, and is told what it got coming out. An absent parameter means
RDF 1.1, and the parameter is emitted only on representations that actually use 1.2
functionality.

**Why the pod is stricter than the specification here.** RDF 1.2 Concepts treats an absent
`version` as 1.2, written for a world where 1.2 is ambient. Every deployed Solid client —
rdflib.js, SolidOS, the Inrupt libraries, CSS — is a 1.1 parser, and passing the Solid
conformance suites is a goal. The cost is asymmetric: being too conservative makes a
document less useful, being too eager makes it unreadable. Announcing `version` on every
response was rejected for the same reason, plus Concepts' own guidance that only documents
using 1.2 functionality should announce one — and it would break every client comparing
`Content-Type` for equality.

**Why a marker trait was not used for the capability.** `Rdf12Store: SparqlStore` would make
the capability a property of the type, which the remote case is not: one generic client has
two capabilities depending on which endpoint it is configured against. With `Arc<dyn SparqlStore>`
([ADR-2](#adr-2)) a subtrait would only be reachable by downcasting.

**The measurement that decided feasibility.** The pod talks to the store only in SPARQL
strings, so holding triple terms means the store must parse SPARQL 1.2. `spargebra` has its
own `sparql-12` feature which is not in its defaults, so `oxrdf/rdf-12` alone would have
produced a pod that reads 1.2 off the wire and cannot write it. The chain that works is
`oxigraph/rdf-12` → `spareval/sparql-12`, and `Cargo.toml` declares `oxigraph/rdf-12`
directly rather than inheriting it, so the capability is not a dependency's private choice.

**What would reopen it.** RDF 1.2 reaching Recommendation *and* the Solid ecosystem
following, at which point Concepts' default becomes the right one and this inverts. Or a
`SparqlStore` implementor that declares RDF 1.1, which turns the degradation path from a
specified case into an exercised one.

## ADR-7 — Embedded Oxigraph, one process per store directory

Embedded Oxigraph selected by `--rdf-store rocksdb:<dir>` is the recommended deployment.
`memory` stays the default so an unconfigured pod is uniformly ephemeral. An external SPARQL
1.1 endpoint remains a supported configuration behind the same trait.

**Why not an HTTP endpoint for the sake of several writers.** Because a second writer is not
a capability here, it is corruption with extra steps. Every write goes through LDP so that
WAC and SHACL are enforced, but that is not all a raw SPARQL writer would bypass: presence
markers in the `urn:quadpod:sys:` graphs, shelf IRIs minted with a `0x00` separator,
containment triples, and ETags. It would also break [ADR-2](#adr-2)'s sequence atomicity,
which every write path rests on and none can verify.

**What the constraint actually says.** Oxigraph permits one read-write `Store` at a time.
That is a statement about processes, not threads — inside this process any number of tasks
write concurrently. Multi-tenancy therefore does not collide with it: many spaces run in one
process as named graphs in one store. The constraint binds only when several pod *processes*
must see one dataset.

**Consequences.** One pod process per store directory. Deployment is stop-then-start, not a
rolling restart. Horizontal scale means either a process per space with its own directory —
the natural fit for a subdomain topology — or the external endpoint, which shares a store
rather than removing its single-writer property.

**What would reopen it.** A writer that genuinely cannot go through LDP, such as a bulk load
whose volume makes HTTP untenable. Or a requirement that the pod stay reachable across a
process restart.

## ADR-8 — `application/sparql-update` is not a PATCH format

`PATCH` accepts `text/n3` and nothing else. `Accept-Patch` advertises `text/n3` alone.

**Why.** Accepting it would mean executing a client-authored database command against a
store that holds every resource, every ACL and the server's own system graphs. What
separates such a command from a `DROP ALL` is a rejection list, and that list has to stay
exhaustive against a `spargebra` AST that may gain a variant in any minor release — a
safety property that silently weakens when a dependency is upgraded.

The format also has no standing to demand it. `application/sparql-update` does not appear in
the Solid Protocol at all: not as a MUST, not as a MAY, not as a mention. It is pre-N3-Patch
ecosystem behaviour that one row of the bundled conformance tests still encodes, and that
row is the only place in the entire suite that uses the media type. N3 Patch is what the
protocol requires, and it expresses the same intent with a grammar that cannot name a graph
the caller was not talking about.

**What would reopen it.** A client that matters and cannot emit N3 Patch. Adding it later
remains possible and would be its own design — the objection is to the blast radius, not to
the idea of a second format.
