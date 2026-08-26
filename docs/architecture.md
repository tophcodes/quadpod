# Architecture

How this pod works, and why it works that way. Present tense throughout: this document
describes the pod as it is, and changes in the same commit as the code it describes.

Two neighbours carry parts of the picture and are not repeated here:

- [`decisions.md`](decisions.md): decisions whose reasoning is long enough, or contested
  often enough, that it needs its own room.
- [`constraints.md`](constraints.md): rules that must stay true, each with the command
  that decides it. The machine-checkable half of this document.
- [`uri-space.md`](uri-space.md): the client-facing URL contract, normative for what a
  client may address.

## What it is

A Solid pod whose authoritative storage is a SPARQL 1.1 quad store. One store holds every
triple; there is no mirror and no sync process. Bytes that are not RDF live beside it in a
blob backend, described by triples in a server-owned graph.

The pod speaks LDP over HTTP, enforces Web Access Control, and verifies Solid-OIDC
credentials. With `--op-signing-keys` set it also signs its own. That is the core of an
identity provider, and no browser app can log in to it yet; see [Limits](#limits).

## Storage model

**A resource is a named graph.** `PUT /foo` with `Content-Type: text/turtle` parses the
body and stores the triples in the graph named `<base>/foo`. This one-to-one mapping is
what makes access control tractable: a resource is a graph is a WAC unit, so "which graphs
may this agent read?" is a query against the same store that holds the data.

**A URL is an identity, and a suffix is part of it.** `/foo`, `/foo.ttl` and `/foo.jsonld`
are three different resources holding three different graphs. Nothing strips a suffix and
nothing infers a format from one. Format on write comes from `Content-Type`, format on
read from `Accept`. A resource named `.ttl` can be written as JSON-LD and read back as
Turtle, because the name was never a format claim. Extensionless URLs are the
recommendation; serialization does not belong in a path.

**RDF is stored parsed, blobs are stored whole.** A round-trip through an RDF resource
preserves triples and discards bytes: prefixes, comment lines and whitespace do not
survive. A blob survives byte for byte. Which of the two a write becomes is decided by
`Content-Type`: a media type the pod can parse as RDF becomes a graph, anything else
becomes bytes.

**Containers are the trailing slash.** `/foo/` is an `ldp:Container`, `/foo` is a
resource, and they can coexist only if nothing tries to make one the parent of the other.
The apex is always the root storage container, both `ldp:Container` and `pim:Storage`,
since HTTP normalizes an empty path to `/`.

### Three graphs per resource

| Graph | Holds | Reachable by a client |
|---|---|---|
| `<res>` | user triples; for a container also the server-managed `ldp:contains` | yes, as the representation |
| `<res>.acl` | the access control policy for `<res>` | yes, its own resource with its own URL |
| `urn:quadpod:sys:<res>` | server bookkeeping: blob key, size, hash, content type, ETag, timestamps, the presence marker | never |

The split follows from who writes each graph. An ACL is a document its owner writes, reads
and grants others control over, so it is a resource with a URL, discoverable through
`Link: rel="acl"` and governed by `acl:Control` like anything else. Server-asserted
bookkeeping must never appear in a namespace a client can address, so it lives under a
`urn:` scheme no request path can name. `resource.rs` is the only module that mints those
IRIs, which is how the presence marker can be a stored fact rather than a triple count.
An empty ACL and an absent ACL mean opposite things, and counting triples cannot tell them
apart.

The root container's `/.acl` is the anchor of the whole scheme: it is where the walk up
the container hierarchy terminates, so provisioning creates it before anything else.

## The request path

```
        HTTP (plain, behind a reverse proxy)
                     │
              ┌──────▼──────┐
              │ axum router │
              └──────┬──────┘
                     │
              ┌──────▼───────────────┐
              │ Auth: verify only     │   DPoP + Solid-OIDC
              │ htu from config       │
              └──────┬───────────────┘
                     │
              ┌──────▼───────────────┐
              │ LDP verb handlers     │   conneg, ETags, containment
              └──────┬───────────────┘
                     │
              ┌──────▼───────────────┐
              │ WAC: guard → PRP → PDP│   one probe per request
              └──────┬───────────────┘
                     │
              ┌──────▼───────────────┐
              │ SHACL, where a shape  │   only if a container binds one
              │ is bound              │
              └──────┬───────────────┘
                     │
              ┌──────▼───────────────┐
              │ Storage router        │   RDF or bytes
              └───┬──────────────┬───┘
          ┌───────▼────┐   ┌─────▼──────┐
          │ SparqlStore│   │ BlobStore  │
          │ → Oxigraph │   │→object_store│
          └────────────┘   └────────────┘
```

Every write passes through this path, and that is load-bearing: because there is no second
way in, the change-event bus below is complete by construction, and the presence markers,
shelf IRIs, containment triples and ETags that the LDP layer maintains cannot be bypassed.

## Authentication

Every credential takes the same path in, this pod's own included. A caller presents a
DPoP-bound Solid-OIDC access token; the pod checks the proof, resolves the token's issuer,
fetches that issuer's keys, fetches the WebID profile named by the `webid` claim, and
confirms the profile authorizes that issuer. The `DPoP` scheme is required and a `Bearer`
credential is refused, because a Solid-OIDC access token is DPoP-bound by construction and
a token presented without its proof is a token that has left its holder.

Proofs signed ES256 or RS256 are both accepted, with the thumbprint computed to match
(see [ADR-3](decisions.md#adr-3)).

`htu` is reconstructed from the configured base URI, never from the socket or from
`X-Forwarded-*`. In Solid a URL is an identity, so a spoofable header cannot be allowed to
decide what a signature covers.

Three of these fetches happen while the request is still unauthenticated, at URLs the
token itself supplies, which is a blind SSRF primitive if left open. `auth/safe_fetch.rs`
is the control: HTTPS only, no private or link-local addresses, no redirects, bounded
bodies and timeouts, with the address filter inside the resolver so a name cannot answer
public for the check and private for the connection. `--allow-insecure-host` opens a named
exception for local development.

**With `--op-signing-keys` set the pod also issues** ([ADR-9](decisions.md#adr-9)). `op::keys`
loads a private key set from that path, generating an ES256 key on first start and never
rewriting the file; `/.well-known/jwks.json` publishes the public half, and
`/.well-known/openid-configuration` names the pod as `issuer`. `op::mint` produces access
tokens carrying `webid`, `aud: ["solid"]`, a `cnf.jkt` that binds the token to the caller's
DPoP key, and a ten-minute lifetime. Nothing reaches minting over HTTP (see
[Limits](#limits)), and a minted token is verified through the paragraphs above unchanged,
fetches included. The pod accepts its own tokens only because `--trusted-issuer`
names it, like any other issuer.

## Authorization

Three parts with three different jobs:

- **The guard** is the enforcement point. It runs once per request, holds the decision,
  and is what the handlers ask. Materialization of missing ancestors happens here, which
  is why the trailing-slash-pair rule lives here too.
- **The PRP** fetches policy: the resource's own `.acl` if it has one, otherwise the
  nearest ancestor container's, terminating at the root. Because a resource is a graph,
  this is a SPARQL query instead of a filesystem walk.
- **The PDP** decides. `wac::pdp::decide` is a pure function over ACL triples plus request
  context. No I/O, no ancestry walking, no `async`, no failure case. Policy is an input to
  it, and it never goes and gets policy itself.

Nearest ACL wins outright: a resource's own policy replaces its ancestors' and does not
merge with them. A rule does not need an explicit `a acl:Authorization`
([ADR-5](decisions.md#adr-5)).

Only an `AuxUrl` may be deleted on its own, and only a `ResourceUrl` or `ContainerUrl` may
be written directly. Those bounds are types rather than conventions, so a call site that
would plant an ACL over a subject that does not exist fails to compile.

## Writing

**Content negotiation** covers Turtle and JSON-LD in both directions, which is what the
Solid Protocol requires of every RDF source. `Accept-Put` and `Accept-Post` advertise what
a write may carry; `Accept-Patch` advertises `text/n3`.

**PATCH is N3 Patch, and only N3 Patch.** `application/sparql-update` is refused
([ADR-8](decisions.md#adr-8)).

**RDF 1.2 is supported and declared.** A representation announces itself with the
`version` media-type parameter on the way in, and is told what it got on the way out.
Silence means RDF 1.1, deliberately stricter than RDF 1.2 Concepts, because every deployed
Solid client is a 1.1 parser ([ADR-6](decisions.md#adr-6)).

**Shape validation is opt-in per container.** A container binds a shape with
`ldp:constrainedBy`; writes into it are validated with SHACL and refused with `422` on
violation. Containers without a binding validate nothing. Mandatory validation would break
interoperability with generic Solid apps, which is what being a pod is for.

**Conditional requests** work on ETags, with `If-Match` and `If-None-Match` on both reads
and writes.

## Change events

Every write emits a change event on an in-process bus, keyed by topic. Because all writes
go through LDP, the bus sees all of them and no store-level change feed is needed. The
notification `state` is the resource's existing ETag, so no second validator has to be
computed.

The bus is a registry keyed by topic instead of one broadcast channel, so a subscriber
anywhere in the pod is not a reason every write computes a validator. Nothing reads state
for a topic with no live channel.

There is no subscription endpoint yet, so nothing outside the process can receive these.

## Configuration and deployment

The pod speaks plain HTTP and binds to loopback. TLS, certificates and wildcard DNS are
the reverse proxy's job. Every minted URL derives from the configured base URI: graph
names, `Location`, `Link: rel="acl"`, containment, `htu`.

| Flag | Environment | Meaning |
|---|---|---|
| `--base-uri` | `POD_BASE_URI` | the public URL this pod answers as |
| `--owner-webid` | `POD_OWNER_WEBID` | who the root ACL grants control to |
| `--trusted-issuer` | `POD_TRUSTED_ISSUERS` | issuers whose tokens are considered |
| `--expected-audience` | `POD_EXPECTED_AUDIENCE` | required `aud` |
| `--rdf-store` | `POD_RDF_STORE` | `memory` or `rocksdb:<dir>` |
| `--blob-store` | `POD_BLOB_STORE` | `memory` or `local:<dir>` |
| `--listen` | `POD_LISTEN` | socket, loopback by default |
| `--max-body-bytes` | `POD_MAX_BODY_BYTES` | request body ceiling |
| `--op-signing-keys` | `POD_OP_SIGNING_KEYS` | private JWKS the OP signs with; unset means no OP |
| `--allow-insecure-host` | `POD_ALLOW_INSECURE_HOSTS` | SSRF-policy exception, development only |
| `--config` | `POD_CONFIG` | file holding the same keys |

Both stores default to `memory`, so an unconfigured pod is uniformly ephemeral. A
`rocksdb:` directory may be opened by exactly one process
([ADR-7](decisions.md#adr-7)), which makes deployment a stop-then-start and rules out a
second replica over the same directory. `--op-signing-keys` requires a base URI at the
origin root and refuses the start otherwise, because the discovery document it implies hangs
off `/.well-known/`.

`deployment.md` carries the operator-facing detail on outbound fetches and the SSRF policy.

## Conformance

The Solid Protocol and WAC suites run from `conformance/run.sh`;
[`conformance-findings.md`](conformance-findings.md) is the measurement log, kept dated
and append-only because a measurement without its date has nothing to be compared against.

## Limits

Present-tense statements of what this pod does not do:

- **No endpoint issues a token.** The OP core exists: key set, JWKS, discovery document
  and minting. Nothing hands a credential to a caller, because there is no authorization
  endpoint, no token endpoint, no client registration and no human login (#58, #59, #60).
  A browser app cannot log in against this pod.
- **No SPARQL endpoint.** There is no query interface and no `application/sparql-update`
  write path. The store is reached only through LDP.
- **No notification delivery.** The change-event bus exists; no channel type is served.
- **No multi-tenancy.** The URI template matcher and `StorageSpace` exist and run a single
  zero-variable space. There is no registry mapping a `{user}` binding to an owner, and no
  provisioning for a second space.
- **No ACP.** WAC only, behind a decision-point seam that would take an ACP engine.
- **No HTML view.** `Accept: text/html` gets no viewer shell.
- **No in-server TLS.**
