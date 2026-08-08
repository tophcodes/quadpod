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

<a id="adr-1"></a>

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

<a id="adr-2"></a>

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

<a id="adr-3"></a>

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

<a id="adr-5"></a>

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

<a id="adr-6"></a>

## ADR-6 — RDF 1.2 is served, and an undeclared representation is RDF 1.1

The pod stores and serves RDF 1.2. A representation declares itself with the `version`
media-type parameter going in, and is told what it got coming out. An absent parameter means
RDF 1.1, and the parameter is emitted only on representations that actually use 1.2
functionality.

**Why the pod is stricter than the specification here.** RDF 1.2 Concepts treats an absent
`version` as 1.2, written for a world where 1.2 is ambient. The cost of guessing wrong is
asymmetric, and that is what decides the default: a document declared 1.1 that a 1.2 reader
meets is merely unambitious, while a document declared 1.2 that a 1.1 reader meets is
unreadable. Passing the Solid conformance suites points the same way. Announcing `version` on
every response was rejected for the same reason, plus Concepts' own guidance that only
documents using 1.2 functionality should announce one — and it would break every client
comparing `Content-Type` for equality.

A census of deployed parsers is not the argument and should not be reinstated as one. It was,
and it was wrong: a parser advertises the RDF 1.2 grammars without thereby handling triple
terms, which is the functionality actually at stake, so the claim was simultaneously
unfalsifiable in the direction that mattered and quick to rot.

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

<a id="adr-7"></a>

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

<a id="adr-8"></a>

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

<a id="adr-9"></a>

## ADR-9 — The pod issues the credentials it verifies

This pod is its own Solid-OIDC issuer (epic #57). It holds a signing key set, publishes it
at `/.well-known/jwks.json`, names itself `issuer` in an OIDC discovery document, and mints
DPoP-bound access tokens carrying a `webid` claim. An external issuer is not required, and
where the subject is one this pod owns, it is not wanted.

What the pod refuses is the rest of the job: **no third-party subjects** — it signs only for
identities it is authoritative for — and **no registration for anyone but the owner**.
Gaining a key does not make this a public IdP; every subject the epic will serve is the
owner's, and that bound holds past this slice.

**Why the pod signs at all.** `pod.toph.so` has to remain its own issuer across the JSS cutover
(#48). An identity minted by an external IdP is an identity that leaves with it, and a pod
whose owner's WebID authorizes a foreign issuer has handed that issuer the ability to
impersonate the owner against every other pod that trusts him. The second half is
arithmetic: every subject this epic must serve — service identity (#23), owner machines
(#49), humans (#60) — needs a signature over a `webid` claim, and one key, one JWKS and one
discovery document serve all three. Arranging each of them with an external issuer means
three trust roots, three rotation stories, and three ways for a subject to become
unverifiable.

Running an IdP is a whole subsystem, which is why it arrives in slices rather than at once,
and why the discovery document advertises no endpoint before something answers it.

**The part that is easy to get wrong.** Issuing does not fork the verification path. A
token this pod minted is presented, resolved, and checked exactly like anyone else's: the
issuer is fetched over `safe_fetch`, the keys come from the published JWKS, and the WebID
profile still has to authorize the issuer. A shortcut for "our own token" would be a second
verifier, and the one that gets less traffic is the one that rots.

**What would reopen it.** An issuer the pod could delegate to while `pod.toph.so` remains
the `iss` of its own tokens — which is not what OIDC delegation does. Short of that, the
question is only how much of the subsystem is worth carrying, not whether the pod signs.

<a id="adr-10"></a>

## ADR-10 — Extraction that needs code runs out of band, and an external extractor is a first-class one

Writing a blob never runs an extractor inline. The write path stores bytes, emits its change
event and answers; extraction happens afterwards, in another process, and reports back by
writing the derived index. A subscriber on `WebhookChannel2023` (#19) is therefore not a
lesser way to extract than a module the pod loads — it is the ordinary way, and the
declarative tier that stays in-process is the exception for inputs small enough to deserve it.

Three consequences, each of which settles a question the extraction design left open:

- **The write path has no extraction failure mode** (#74). Bytes the extractor cannot read are
  bytes with an empty derived index, not a refused `PUT`.
- **`.meta` is writable, and partitioned per extractor** (#65). It has to be, or an external
  extractor has nowhere to put its output; and it has to be partitioned, or two extractors
  overwrite each other.
- **A WASM tier is optional for v1** (#69). It is the tier that exists for logic a mapping
  cannot express, and that is now covered.

**Why.** The workload that decides it is OCR, and it fits none of the three tiers the design
names. Declarative mapping needs a tree, and a scanned PDF is not one. WASM is specified with
no network and a fuel bound, and a real scan is seconds to minutes of CPU and hundreds of
megabytes — a bound that admits it bounds nothing, and one that bites kills every honest
document. Shell hooks are refused outright, and that refusal is not negotiable on a pod that
is internet-facing and its own issuer.

Two lesser reasons point the same way. An extractor that needs the network while mapping is
normal rather than exceptional: resolving an identifier to the concept it denotes is a fetch,
and a sandbox defined as network-less cannot do it. And this pod mints its own tokens, so a
request thread spending a minute in Tesseract is a request thread not answering `/token`.

**The part that is easy to get wrong.** The loop closes only because auxiliaries stay out of
containment. An extractor subscribes to the container its documents land in; it writes
`/.aux/{subject}.meta`; that write publishes on the auxiliary's own topic and produces no
`Add` on the parent, because `Guard::materialize` holds `may_be_member = !matches!(target,
Target::Aux(_))` and `publish_containment` only walks what materialization recorded. Make an
auxiliary a container member and every extractor starts hearing its own output.

**What would reopen it.** A sandbox that can express a work budget of minutes and hundreds of
megabytes without the budget becoming a fiction, *and* a way for a sandboxed extractor to
resolve an identifier it does not already hold. Both, not either — the second is what a
mapping needs even when the first is generous.

---

<a id="adr-11"></a>

## ADR-11 — Replication scopes existence separately from content, and what is withheld does not converge

Replicas of one pod answer as the same base URI. A replica carries a subtree's content, or
only its existence, or neither, and those are two dials set independently per subtree.

Three answers follow, and a replica gives exactly one of them for any URL:

| The replica | Answer |
|---|---|
| holds the resource | the representation |
| knows it exists elsewhere | `421 Misdirected Request` |
| is not entitled to know it exists | `404` |

Existence is the server-owned graph, containment and the ACL. Content is the user graph and
the blob. A replica that carries existence can authorize and can redirect; a replica that
carries neither is indistinguishable from a pod where the resource was never written, which
is the point.

**A subtree withheld for confidentiality withholds existence too, and is not a participant
in convergence.** Not a replica that lags — not a participant.

**Why.** Sharing one base URI across replicas is what keeps identity unambiguous: a type
index entry, an ACL subject and a WebID profile name one URL no matter which replica answers
it. The alternative, an origin per replica, makes every one of those references ask which
copy it meant.

The cost is that reachability varies where identity does not, and `404` alone cannot say
which of the two it means. A client that reads `404` for a resource it wrote yesterday
concludes the resource was deleted and reconciles by dropping what it holds. Partial
replication answered with `404` is a data-loss primitive aimed at every generic client,
including the ones that behave correctly. `421` is the status that already means this server
cannot produce a response for this URI, which is the claim being made and no larger one.

But `421` asserts that the resource exists, so it cannot be the answer for a subtree whose
existence is the sensitive fact. Hence three answers rather than two: withholding content and
withholding existence are different decisions and a single dial cannot express both.

**The part that is easy to get wrong.** Convergence undoes this if it is allowed to see it. A
merge exists to eliminate divergence without losing writes, and a deliberately withheld
subtree is divergence that looks exactly like a replica one write behind. Containment is
where it bites first: the root container lists different members on different replicas, and a
convergent union of those member sets restores precisely what was withheld. So the exclusion
has to be declared as non-participation, using the per-container opt-in that convergence
already needs — never as data a replica happens not to have yet.

The private type index is the instance to get right first. It registers classes against
locations, so it leaks the *category* of what is held rather than a path that could mean
anything; `solid:forClass` naming a medical record says what a container called `/health/`
only hints at. It is always the withheld case, and it answers `404` — `421` would concede
that it exists.

**What replication breaks on the way in.** DPoP replay protection is a `JtiReplayStore`, and
the only implementor is in-memory. That is correct while exactly one process answers for a
base URI, which [ADR-7](#adr-7) guarantees today. It stops being correct here: replicas share
one base URI by construction, so a proof's `htu` is byte-identical at every one of them, and a
proof spent at one replica is unspent at all the others. Replication needs a replay store the
replicas share, or a proof binding narrower than the base URI — and the seam for the first
already exists, since the store is a trait rather than the process-wide static it started as.

**What would reopen it.** Replicas ceasing to share a base URI. If an origin identifies the
copy, location is carried by the identifier, every reference names the copy it meant, and
none of the three answers above has anything to distinguish.
