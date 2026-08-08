# quadpod

> **Pre-release (0.1.0).** This pod verifies credentials but does not yet issue any, so
> nothing can log in to it interactively — you must point it at an identity provider you
> already run. There is no released binary or container image. Don't put data in it that you
> cannot afford to lose.

quadpod is a personal data server. Applications store your data on it over HTTP — `PUT` a
document, `GET` it back — and you, not the application, decide who may read what. It
implements [Solid](https://solidproject.org/), an open specification for exactly that: your
data lives in one place you control, and apps come to it rather than keeping their own copy.

It is a single Rust binary. Under the hood it embeds [Oxigraph](https://github.com/oxigraph/oxigraph),
an RDF quad store, over RocksDB.

The unusual part is what it stores data *in*. Most Solid servers keep resources as files in a
directory tree. This one keeps every resource as a named graph inside one quad store, so
permissions live in the same store as the data they protect, and "which resources may this
agent read?" is a query rather than a second system that has to stay in sync with the first.
Bytes that are not RDF — images, PDFs — live beside it in a blob store and are described by
triples the server owns.

## Try it

Build needs the Nix dev shell. Bare `cargo build` fails: Oxigraph needs bindgen and libclang,
which only the flake provides.

```sh
nix develop -c cargo build --release
```

**This pod issues no credentials — it only verifies them.** To write anything you need a
Solid-OIDC identity provider, and you have to point the pod at it with `--trusted-issuer`.
Without that flag the pod trusts every issuer, which is not a useful default and not a safe
one. `conformance/run.sh` stands up a Community Solid Server for exactly this purpose and is
the shortest path to a working setup.

```sh
quadpod \
  --base-uri http://localhost:3000/ \
  --owner-webid https://you.example/profile/card#me \
  --trusted-issuer https://your-idp.example \
  --rdf-store rocksdb:/var/lib/quadpod/store \
  --blob-store local:/var/lib/quadpod/blobs
```

Then write a document and read it back in a different format — the point of the URL contract
below, in two requests:

```sh
curl -X PUT http://localhost:3000/greeting \
  -H "Authorization: DPoP $TOKEN" -H "DPoP: $PROOF" \
  -H 'Content-Type: text/turtle' \
  --data '<#it> <http://www.w3.org/2000/01/rdf-schema#label> "hello" .'

curl http://localhost:3000/greeting \
  -H "Authorization: DPoP $TOKEN" -H "DPoP: $PROOF" \
  -H 'Accept: application/ld+json'
```

The same graph goes in as Turtle and comes out as JSON-LD, because the name was never a
format claim.

## What works

Measured against `solidproject/conformance-test-harness` with the `protocol` and
`web-access-control` manifests: **638 of 652 scenarios pass, 34 of 41 features fully green**
(ninth run, 2026-08-08). Conditions worth knowing: plain HTTP on loopback, an in-memory store
so the persistence path is not exercised, and Community Solid Server 7.2.0 standing in as the
identity provider because this pod has no token endpoint yet.

Of the 14 remaining failures: **3 are open Web Access Control defects** (`DELETE` of a
container authorized only through inheritance — an over-denial, not an incorrect allow), 8
are decisions not yet settled, and 3 need `https` or a media type this pod refuses by design.
Every run is dated and reconciled against the previous one in
[`docs/conformance-findings.md`](docs/conformance-findings.md).

- **Linked Data Platform (LDP) over HTTP** — containers, resources, auxiliary resources, and
  containment maintained by the server.
- **Web Access Control (WAC)** — enforcement point, policy retrieval and a pure decision
  function kept as three separate parts, which is what would make an ACP engine swappable
  later. The nearest ACL wins outright rather than merging with its ancestors', which is what
  the WAC specification requires and what implementations most often get wrong.
- **Solid-OIDC authentication** — access tokens bound to a key with DPoP (Demonstration of
  Proof-of-Possession, RFC 9449), ES256 and RS256 proofs, and the token issuer cross-checked
  against the `solid:oidcIssuer` in the WebID profile it claims. A plain `Bearer` credential
  is refused: this pod requires the stronger binding, and the cost is that an issuer
  configured to hand out non-DPoP tokens will not work against it.
- **An SSRF control** on the fetches that happen while a request is still unauthenticated —
  the token names the URLs, so they are attacker-chosen. The address filter runs inside the
  DNS resolver, so a name cannot answer public for the check and private for the connection.
- **Content negotiation** — Turtle and JSON-LD in both directions.
- **`PATCH` is N3 Patch**, the Solid-specified patch format, and only that.
- **RDF 1.2** on the wire, declared with the `version` media-type parameter, and emitted only
  on representations that actually use 1.2 functionality. See
  [ADR-6](docs/decisions.md#adr-6) for the default an absent parameter gets and why.
- **Shape validation, opt-in per container** — a container binds a SHACL shape and writes into
  it are validated against it. Containers without a binding validate nothing; mandatory
  validation would break clients that know nothing about shapes.
- **Conditional requests** on ETags, `If-Match` and `If-None-Match`, reads and writes. The
  validator covers every representation of a resource, so a client that read Turtle can
  `If-Match` a JSON-LD write.

## The storage model

**A resource is a named graph.** `PUT /foo` with `Content-Type: text/turtle` stores the body's
triples in the graph named `<base>/foo`, and that graph is the unit access control decides
about. A JSON-LD body carrying `@graph` entries is a dataset rooted at that name rather than a
single graph.

**A URL is an identity, and a suffix is part of it.** `/foo`, `/foo.ttl` and `/foo.jsonld` are
three different resources. Nothing strips a suffix and nothing infers a format from one —
format on write comes from `Content-Type`, on read from `Accept`.

**RDF is stored parsed, blobs are stored whole.** A round-trip through an RDF resource
preserves triples, not bytes: prefixes, comment lines and whitespace do not survive, and
neither does anything that depends on canonical bytes, such as a signature over the document.
Blobs survive byte for byte.

**Three graphs per resource** — the user's triples, the ACL as its own addressable resource,
and server bookkeeping under a `urn:` scheme no request path can name. Keeping server-asserted
facts unaddressable is what allows a presence marker, which is what lets an absent ACL and an
empty ACL mean different things.

**ACLs are not siblings.** The ACL for `/foo` lives at `/.aux/foo.acl`, not at `/foo.acl`.
This is legal — the specification requires discovery through `Link: rel="acl"` — but it is
this pod's largest interop deviation, and the failure mode is silent: a client that assumes
the sibling URL and writes `/foo.acl` gets a `201` and no access control. See
[Do not construct auxiliary URLs — discover them](docs/uri-space.md#do-not-construct-auxiliary-urls--discover-them).

## Roadmap

No dates. The order is a dependency argument rather than a schedule, and the numbers link to
[the issue tracker](https://github.com/tophcodes/quadpod/issues).

**Being an identity provider** ([#57](https://github.com/tophcodes/quadpod/issues/57)). The
signing core mints DPoP-bound tokens already, and no HTTP path reaches it. Missing: the
Authorization Code flow with PKCE (#58), Client ID Documents and dynamic registration (#59),
authenticating the human (#60), and the algorithm and audience contract (#62). Until these
exist no browser application can log in, and no separate process can obtain a credential.
Alongside them the pod gains an identity of its own so it can authenticate outbound requests
(#22, #23, #49).

**Notifications** (#20). Every write emits a change event on an internal bus; no channel type
is served, so nothing outside the process can receive one. The Subscription API with
`WebSocketChannel2023` (#18) and `WebhookChannel2023` (#19) are what turn it into a protocol.
Extraction waits on this.

**Storage description and origin-based access control.** Two spec-surface gaps that matter for
interoperability: the storage root does not yet advertise itself as `pim:Storage` with a
storage description resource (#16), which is the first thing a generic Solid app looks for;
and `acl:origin` is not enforced, so an authenticated user's browser applications currently
act with that user's full authority.

**Extraction and projection** (#63). Deriving triples from a blob's bytes, and making
quad-store-only RDF visible as files. Bytes stay authoritative and nothing writes back into
them. Designed in [`docs/superpowers/specs/`](docs/superpowers/specs/), unimplemented, and
ending in questions that are genuinely open — what an extractor may reject (#74), how the
derived index is partitioned so two extractors cannot overwrite each other (#65), and what
revoking an extractor's trust does to configurations it already wrote (#68).

**A SPARQL query endpoint.** The store is a quad store and nothing exposes it as one. No issue
tracks it yet; the deciding question is access control, since a query endpoint that reads
across graphs is a second enforcement point and WAC has one.

**Convergent writes.** Several writers changing one resource from clients that were offline,
with the server merging so that a client holding no replica and speaking only `PUT` stays a
valid client — a CRDT under the hood, opt-in per container. Designed, unimplemented.

**Partial replicas.** Replicas answering as one base URI, each carrying a subtree's content,
only its existence, or neither, and answering `421 Misdirected Request` for what exists
elsewhere. Depends on convergent writes: what a replica withholds has to be declared as
non-participation in the merge, or convergence restores exactly what was withheld. See
[ADR-11](docs/decisions.md#adr-11).

**Limited OWL reasoning, materialized** (#76). Entailments computed and stored rather than
derived per query, so a reader that does no reasoning sees the same resource as one that does.

**Closing the conformance gap** (#53, #54) — the 3 defects and 8 undecided cases above.

**Seams without designs.** Multi-tenancy, ACP (Access Control Policy, the successor to WAC)
and an HTML view each have a place they would attach and nothing more.

## Not in scope

Decided against rather than not yet reached. Each carries a reason meant to outlive the
current implementation, and a cost worth knowing about.

- **Shell hooks.** Extraction never runs a script on write. This pod is internet-facing and
  its own issuer, so "writing a file runs a program" means whoever can `PUT` can execute
  ([ADR-10](docs/decisions.md#adr-10)).
- **`application/sparql-update` as a patch format.** N3 Patch only
  ([ADR-8](docs/decisions.md#adr-8)). The concrete cost: rdflib.js's `UpdateManager` emits
  SPARQL Update, so SolidOS and mashlib cannot currently write to this pod.
- **Byte preservation for RDF.** See the storage model. Write bytes as bytes if the bytes
  matter.
- **Mandatory validation and mandatory convergence.** Both are opt-in per container; either
  as a default would break clients that know nothing about them.
- **Writing back into a blob's bytes.** Extraction derives triples from bytes and never the
  reverse, which removes round-trip fidelity from the problem rather than defending it.
- **In-server TLS.** The pod binds to loopback and speaks plain HTTP; certificates and
  termination belong to the reverse proxy.
- **A second process over one store directory.** A `rocksdb:` directory is opened by exactly
  one process ([ADR-7](docs/decisions.md#adr-7)). A second one refuses to start rather than
  corrupting anything, but it means no rolling restart, no second replica, and downtime on
  every deployment.

## Configuration

| Flag | Environment | Meaning |
|---|---|---|
| `--base-uri` | `POD_BASE_URI` | the public URL this pod answers as |
| `--owner-webid` | `POD_OWNER_WEBID` | who the root ACL grants control to |
| `--trusted-issuer` | `POD_TRUSTED_ISSUERS` | issuers whose tokens are considered. **Without one, every issuer is trusted** |
| `--rdf-store` | `POD_RDF_STORE` | `memory` or `rocksdb:<dir>` |
| `--blob-store` | `POD_BLOB_STORE` | `memory` or `local:<dir>` |
| `--op-signing-keys` | `POD_OP_SIGNING_KEYS` | private JWKS the pod signs with; unset means it issues nothing |
| `--listen` | `POD_LISTEN` | socket, loopback by default |

`--config` takes a file holding the same keys. The full table is in
[`docs/architecture.md`](docs/architecture.md).

Both stores default to `memory`, so an unconfigured pod is uniformly ephemeral rather than
half-persistent. Set both, or restarting loses everything.

Behind a reverse proxy, every URL the pod mints derives from `--base-uri`, and a DPoP proof's
`htu` is compared against it byte for byte — so `--base-uri` must be the public URL the client
used, never what the proxy forwards. With `--op-signing-keys` set it must also be an origin
root, since the discovery document it implies hangs off `/.well-known/`.

Back up three things together, or the restore is inconsistent: the RocksDB directory, the blob
directory, and the file named by `--op-signing-keys` — losing the last invalidates every token
the pod has issued.

Pointing `--blob-store` at a directory that already holds files makes the backing tree
readable with ordinary tools, since the blob key is the resource's own path. Give the pod a
directory of its own: files it did not write have no containment triple, no ETag and no ACL,
so `ls` and `GET` will disagree about what exists.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — how the pod works and why.
- [`docs/uri-space.md`](docs/uri-space.md) — the client-facing URL contract, normative for
  what a client may address.
- [`docs/decisions.md`](docs/decisions.md) — decisions whose reasoning needs its own room.
- [`docs/constraints.md`](docs/constraints.md) — rules that must stay true, each with the
  command that decides it.
- [`docs/deployment.md`](docs/deployment.md) — outbound fetches and the SSRF policy.
- [`docs/conformance-findings.md`](docs/conformance-findings.md) — dated measurements, one
  section per run.

## License

MIT. See [`LICENSE`](LICENSE).
