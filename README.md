# quadpod

> **Under active development, well before a first release.** This pod verifies credentials
> and issues none, so nothing can log in to it interactively. Point it at an identity
> provider you already run. There is no released binary and no container image. Interfaces
> change without notice. Don't put data in it that you cannot afford to lose.

quadpod is a personal data server. Applications store your data on it over HTTP: `PUT` a
document, `GET` it back. Who may read what is yours to decide, and the application does not
get a say. It implements [Solid](https://solidproject.org/), an open specification for
exactly that: your data lives in one place you control, and apps come to it instead of
keeping their own copy.

It is a single Rust binary. Under the hood it embeds [Oxigraph](https://github.com/oxigraph/oxigraph),
an RDF quad store, over RocksDB.

The unusual part is what it stores data *in*. Most Solid servers keep resources as files in a
directory tree. This one keeps every resource as a named graph inside one quad store, so the
whole pod is a single dataset and a question that spans resources is one query. Access
control lives in that same dataset, so it comes along for free. Bytes that are not RDF,
images and PDFs, live beside the graphs in a blob store and are described by triples the
server owns.

## Try it

Build needs the Nix dev shell. A bare `cargo build` fails: Oxigraph needs bindgen and
libclang, which only the flake provides.

```sh
nix develop -c cargo build --release
```

**This pod verifies credentials and issues none.** To write anything you need a Solid-OIDC
identity provider, and you have to point the pod at it with `--trusted-issuer`. Without that
flag the pod trusts every issuer, which is unsafe. `conformance/run.sh` stands up a Community
Solid Server for exactly this purpose and is the shortest path to a working setup.

```sh
quadpod \
  --base-uri http://localhost:3000/ \
  --owner-webid https://you.example/profile/card#me \
  --trusted-issuer https://your-idp.example \
  --rdf-store rocksdb:/var/lib/quadpod/store \
  --blob-store local:/var/lib/quadpod/blobs
```

Then write a document and read it back in a different format. Two requests:

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

The official Solid conformance suite runs against this pod with one command,
`./conformance/run.sh`, over the `protocol` and `web-access-control` manifests. Current
figures live in [`docs/conformance-findings.md`](docs/conformance-findings.md), where every
run is dated, reconciled against the one before it and triaged failure by failure. A copy of
them here would go stale without anyone noticing.

Read them knowing what the run is: plain HTTP on loopback, an in-memory store so the
persistence path is never exercised, and Community Solid Server standing in as the identity
provider, because this pod has no token endpoint yet.

- **Linked Data Platform (LDP) over HTTP**: containers, resources, auxiliary resources, and
  containment maintained by the server.
- **Web Access Control (WAC)**: enforcement point, policy retrieval and a pure decision
  function kept as three separate parts, so an ACP engine could replace the decision function
  later. The nearest ACL wins outright and does not merge with its ancestors'. The WAC
  specification requires that, and implementations most often get it wrong.
- **Solid-OIDC authentication**: access tokens bound to a key with DPoP (Demonstration of
  Proof-of-Possession, RFC 9449), ES256 and RS256 for both the proof and the access token's
  own signature, and the token issuer cross-checked against the `solid:oidcIssuer` in the
  WebID profile it claims. Which algorithm a token is verified under follows the key the
  issuer published, never the token's own header, so widening past one algorithm gives a
  token no say in how it is checked. A plain `Bearer` credential is refused: this pod
  requires the stronger binding, and the cost is that an issuer configured to hand out
  non-DPoP tokens will not work against it.
- **An SSRF control** on the fetches that happen while a request is still unauthenticated.
  The token names the URLs, so they are attacker-chosen. The address filter runs inside the
  DNS resolver, so a name cannot answer public for the check and private for the connection.
- **Content negotiation**: Turtle and JSON-LD in both directions.
- **`PATCH` is N3 Patch**, the Solid-specified patch format, and only that.
- **RDF 1.2** on the wire, declared with the `version` media-type parameter, and emitted only
  on representations that use 1.2 functionality. See [ADR-6](docs/decisions.md#adr-6) for the
  default an absent parameter gets and why.
- **Shape validation, opt-in per container**: a container binds a SHACL shape and writes into
  it are validated against it. Containers without a binding validate nothing. Mandatory
  validation would break clients that know nothing about shapes.
- **Conditional requests** on ETags, `If-Match` and `If-None-Match`, reads and writes. The
  validator covers every representation of a resource, so a client that read Turtle can
  `If-Match` a JSON-LD write.

## The storage model

**A resource is a named graph.** `PUT /foo` with `Content-Type: text/turtle` stores the body's
triples in the graph named `<base>/foo`, and that graph is the unit access control decides
about. A JSON-LD body carrying `@graph` entries is a dataset rooted at that name instead of a
single graph.

**A URL is an identity, and a suffix is part of it.** `/foo`, `/foo.ttl` and `/foo.jsonld` are
three different resources. Nothing strips a suffix and nothing infers a format from one.
Format on write comes from `Content-Type`, on read from `Accept`.

**RDF is stored parsed, blobs are stored whole.** A round-trip through an RDF resource
preserves triples and discards bytes: prefixes, comment lines and whitespace do not survive,
and neither does anything that depends on canonical bytes, such as a signature over the
document. Blobs survive byte for byte.

**Three graphs per resource**: the user's triples, the ACL as its own addressable resource,
and server bookkeeping under a `urn:` scheme no request path can name. Because the
bookkeeping is unaddressable, the server can keep a presence marker there, and an absent ACL
and an empty ACL then mean different things.

**The ACL lives under `/.aux/`.** The ACL for `/foo` is at `/.aux/foo.acl`, and no ACL sits
beside the resource it governs. The specification requires discovery through
`Link: rel="acl"`, so this is legal, and it is this pod's largest interop deviation. The
failure mode is silent: a client that assumes the sibling URL and writes `/foo.acl` gets a
`201` and no access control. See
[Do not construct auxiliary URLs, discover them](docs/uri-space.md#do-not-construct-auxiliary-urls-discover-them).

## Roadmap

No dates. The order states dependencies, and
[the issue tracker](https://github.com/tophcodes/quadpod/issues) carries the detail, the
open questions and the current state of each.

**Being an identity provider.** The signing core mints DPoP-bound tokens and no HTTP path
reaches it, so no browser application can log in and no separate process can obtain a
credential. Alongside it the pod gains an identity of its own, so it can authenticate
outbound requests.

**Notifications.** Every write emits a change event on an internal bus, and no channel type
is served, so nothing outside the process can receive one. Extraction waits on this.

**Storage description and origin-based access control.** Two interoperability gaps. The
storage root does not advertise itself as `pim:Storage`, which is the first thing a generic
Solid app looks for, and `acl:origin` is not enforced, so a user's browser applications act
with that user's full authority.

**Extraction and projection.** Deriving triples from a blob's bytes, and making
quad-store-only RDF visible as files. Bytes stay authoritative and nothing writes back into
them. Designed, unimplemented.

**A SPARQL query endpoint.** The store is a quad store and nothing exposes it as one. The
shape it must take is settled ([ADR-12](docs/decisions.md#adr-12)): a read-only projection,
with access control the remaining open question, since a query that reads across graphs is a
second enforcement point and WAC has one.

**Convergent writes, then partial replicas.** Several writers changing one resource from
clients that were offline, merged server-side so that a client speaking only `PUT` stays a
valid client. Replicas answering as one base URI follow from it, and cannot precede it
([ADR-11](docs/decisions.md#adr-11)). Both designed, neither implemented.

**Limited OWL reasoning, materialized.** Entailments computed and stored instead of derived
per query, so a reader that does no reasoning sees the same resource as one that does.

**Seams without designs.** Multi-tenancy, ACP (Access Control Policy, the successor to WAC)
and an HTML view each have a place they would attach and nothing more.

## Not in scope

Decided against. Each carries a reason meant to outlive the current implementation, and a
cost worth knowing about.

- **Shell hooks.** Extraction never runs a script on write. This pod is internet-facing and
  its own issuer, so "writing a file runs a program" means whoever can `PUT` can execute
  ([ADR-10](docs/decisions.md#adr-10)).
- **`application/sparql-update` as a patch format.** N3 Patch only
  ([ADR-8](docs/decisions.md#adr-8)). rdflib.js clients still write here: its
  `UpdateManager` reads `Accept-Patch` and falls through to N3 Patch when that is all a
  server offers. They take a code path rdflib itself currently deprioritises, so blank-node
  inserts are the place to expect trouble.
- **Byte preservation for RDF.** See the storage model. Write bytes as bytes if the bytes
  matter.
- **Mandatory validation and mandatory convergence.** Both are opt-in per container. Either
  as a default would break clients that know nothing about them.
- **Writing back into a blob's bytes.** Extraction derives triples from bytes and never the
  reverse, which removes round-trip fidelity from the problem.
- **In-server TLS.** The pod binds to loopback and speaks plain HTTP; certificates and
  termination belong to the reverse proxy.
- **A second process over one store directory.** A `rocksdb:` directory is opened by exactly
  one process ([ADR-7](docs/decisions.md#adr-7)). A second one refuses to start, so nothing
  is corrupted. The cost is no rolling restart, no second replica, and downtime on every
  deployment.

## Configuration

Flags and their environment variables are listed by `quadpod --help`, and the full table with
what each one means is in [`docs/architecture.md`](docs/architecture.md). `--config` takes a
file holding the same keys.

Three things are worth knowing before the first run, because each fails quietly:

- **`--trusted-issuer` is not optional in practice.** Without one, every issuer is trusted.
- **Both stores default to `memory`**, so an unconfigured pod is uniformly ephemeral. Set
  `--rdf-store` and `--blob-store`, or restarting loses everything.
- **`--base-uri` must be the public URL the client used**, not what a reverse proxy forwards
  inside the network.

[`docs/deployment.md`](docs/deployment.md) covers those last two properly, along with what to
back up so a restore is consistent, and why a blob directory has to belong to the pod alone.

## Documentation

- [`docs/architecture.md`](docs/architecture.md): how the pod works and why.
- [`docs/uri-space.md`](docs/uri-space.md): the client-facing URL contract, normative for
  what a client may address.
- [`docs/decisions.md`](docs/decisions.md): decisions whose reasoning needs its own room.
- [`docs/constraints.md`](docs/constraints.md): rules that must stay true, each with the
  command that decides it.
- [`docs/deployment.md`](docs/deployment.md): outbound fetches and the SSRF policy.
- [`docs/conformance-findings.md`](docs/conformance-findings.md): dated measurements, one
  section per run.

## License

MIT. See [`LICENSE`](LICENSE).
