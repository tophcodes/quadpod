# URI Space and Reserved Paths

This is the contract between this pod and its clients about **which URLs mean what**. It is
normative for the server and for anyone writing data into it.

One term runs through all of it. An **auxiliary resource** carries information *about*
another resource — its subject — rather than content of its own. The standing example is an
access control list: a document that says who may read the resource it belongs to. An
auxiliary has its own URL and you write it like anything else, but it is bound to its subject
rather than merely sitting next to it, and what that binding costs and buys is
[its own section](#auxiliary-resources) below.

## Your space, and the two segments that are not

Almost every path this pod serves is yours. Exactly two first-level segments are not:

| Path | Meaning |
|---|---|
| `/.aux/…` | auxiliary resources — your data, with a meaning the server has to understand |
| `/.well-known/…` | origin infrastructure (RFC 8615) — the server's, not yours, and never writable |
| everything else | ordinary resources and containers |

That is the whole reservation. `/.hidden`, `/.config`, `/notes/.env` and any other
dot-prefixed name are ordinary resources with no special treatment — the reservation costs
you the two names `.aux` and `.well-known` at the root, and nothing else, ever.

**One segment per reservation, not one per feature.** Every auxiliary kind lives inside
`/.aux/`, and every well-known name inside `/.well-known/`, so adding either later takes
nothing away from you at that point.

## `/box` and `/box/` are two names, and only one of them may exist

Solid Protocol §3.1: *"If two URIs differ only in the trailing slash, and the server has
associated a resource with one of them, then the other URI MUST NOT correspond to another
resource."* This pod enforces it on every create: while `/box/` exists, `PUT /box` answers
`409`, and while `/box` exists, `PUT /box/` answers `409`. The same applies to a container a
deep write would materialize — `PUT /a/b` is refused while a resource `/a` exists, because
serving it would create `/a/` beside it.

Nothing is merged: the two URIs still name different things, and requesting the one that does
not exist gives `404`, not a redirect. Delete the one that exists and the other name is free.
A `POST` is unaffected — the server allocates the name there, so it simply picks another, as
it does for any taken name.

## Auxiliary resources

An auxiliary resource holds information *about* another resource — its subject. The content
is **yours**: you write it, you read it, it is your data. What the server contributes is the
part a client cannot enforce alone:

- **Association.** The auxiliary is discoverable from its subject via a `Link` header.
- **Lifecycle.** It is created only for an existing subject, and deleted when the subject is
  deleted. No orphans, no stale policy resurrected by recreating a path.
- **Listing.** It never appears among a container's members, so it does not clutter or
  surprise a listing.
- **Authorization.** Access to it derives from the subject resource, not from itself.

| Kind | Path | Status | You may write it | Authorized by |
|---|---|---|---|---|
| access control (WAC) | `/.aux/{subject}.acl` | live | yes | `acl:Control` on the subject |
| description / metadata | `/.aux/{subject}.meta` | reserved, candidate — not promised | yes, if implemented | `acl:Write` on the subject |
| anything else under `/.aux/` | — | reserved | no | — |

An auxiliary URL is `/.aux`, then the subject's own path, then `.` and the kind's
name. The kind is a **suffix**, so an auxiliary URL never ends in a slash — which is what
every other Solid server produces (`.acl`, `.acr`, `.meta`) and the shape clients handle
without damage:

| Subject | Its ACL |
|---|---|
| `/` | `/.aux/.acl` |
| `/foo` | `/.aux/foo.acl` |
| `/box/` | `/.aux/box/.acl` |
| `/a/b/c` | `/.aux/a/b/c.acl` |

The auxiliary reservation is still the leading segment and nothing else: `/foo.acl` and
`/notes/x.meta` are ordinary resources of yours, because they do not begin with `/.aux`. A
path under `/.aux/` that ends in no kind's name — `/.aux/foo`, `/.aux/bogus/x`, `/.aux/`
itself — names nothing and answers `404`.

One shape under `/.aux/` answers `400`, not `404`: stripping a kind's suffix can leave a subject
path that is itself malformed — `/.aux/..acl` strips to the subject `/.`, a dot-segment no
request could ever address on its own. That is reported as a malformed path, the same `400` a
directly-requested `/.` would get, not as "no such auxiliary".

The set of kinds is **closed and defined by the server**. You cannot introduce your own: what
makes a resource auxiliary is behaviour the server enforces for you — the lifecycle binding,
the exclusion from listings, the authorization derived from the subject. A kind the server
does not understand would get none of that. If you want your own side-document about
something, create an ordinary resource and link it from your own data (`rdfs:seeAlso` or
whatever your vocabulary uses). It behaves like any other resource, with its own ACL and its
own lifecycle.

**Writable does not mean ordinary.** A description resource is yours to write, and it is
still an auxiliary: it lives and dies with its subject, stays out of listings, and is
authorized through the subject. The same holds for an ACL. Writability and ordinariness are
different properties, and this is the distinction the reserved segment encodes.

## Practical notes

**The link is always advertised, even when the auxiliary does not exist.** Following it and
receiving `404` is the normal answer for "no own policy here — you inherit, and this is where
to change that". The header has to be there before the resource is, or you could never create
the first one.

**An auxiliary is parsed with its own URL as base.** Inside `/.aux/foo.acl`, `<>` denotes the
ACL document itself, *not* `/foo`. Name the subject explicitly — `</foo>` or its absolute
IRI. This trips people up; it is the same rule other Solid servers use.

**Set policy on the container before you fill it.** Creating a resource and then setting its
ACL is two requests, and in between the inherited policy applies — so a resource created in a
public container is briefly public. There is no atomic "create with policy" operation in
Solid. Keep the window empty instead of trying to close it: create the container, set its
ACL, then write into it. An empty container discloses nothing.

**An empty ACL denies everything below it — deliberately, and there is no HTTP way back.**
Existence is a stored fact independent of content: an ACL with zero triples still exists, still
wins over whatever an ancestor would otherwise hand down, and grants nothing to anyone,
including its own owner. `DELETE` on it needs `acl:Control`, which that same empty ACL just
revoked from everyone — so at the root, an empty root ACL is terminal over HTTP: no request can
remove it, and no request can replace it. The way out is the operator, not the API: restart the
server with `--reset-root-acl` (or `POD_RESET_ROOT_ACL=1` or `POD_RESET_ROOT_ACL=true`), which
overwrites the root ACL with the owner's default grant regardless of what is there. **This is a
wholesale overwrite, not a merge:** it destroys every rule the root ACL held, not just the
one it restores — any share the owner had granted someone else at the root is gone too, and
has to be re-created after. The env variable accepts any boolish value: `1`, `0`, `true`,
`false`, `yes`, `no`, `on`, `off` (case-insensitive). This only exists for the root; an emptied
ACL anywhere else has no equivalent flag and is a real dead end for that subtree.

## `/.well-known/` is reserved and server-owned

`/.well-known/` is defined by RFC 8615 as a place the *host* provides, and this pod is the
host. It is the second reserved segment, and unlike `/.aux/` nothing inside it is yours:

- **Every write answers `405`.** `PUT`, `POST`, `DELETE` and `PATCH` anywhere under
  `/.well-known/` — and on the bare `/.well-known` and `/.well-known/` themselves — are
  refused by the router: no handler runs, no WAC decision is taken, and a valid credential
  does not change the answer, the owner's included. It holds whether or not the pod is
  running as an identity provider.
- **`GET` serves the names the pod implements, and `404`s the rest.** Two names are
  implemented, and only while the OP is on (`--op-signing-keys`):

| Path | Answer |
|---|---|
| `/.well-known/openid-configuration` | the OIDC discovery document, `application/json` |
| `/.well-known/jwks.json` | the public key set, `application/jwk-set+json` |

Both are served to a request carrying **no credentials at all** — a verifier reads issuer
metadata before it holds anything to present — while a request carrying *invalid* credentials
is refused by authentication before any route answers.

With the OP off, those two are `404` like every other name. The `405` on writes does not
move with them: the segment is reserved unconditionally, so a pod that later turns the OP on
does not have to take a name back from you.

**Why the whole segment rather than the two paths.** Once this origin is an identity
provider, a writable name under `/.well-known/` is a spoofing surface. RFC 8414 lets a verifier
look for issuer metadata at `/.well-known/oauth-authorization-server` — a name this pod does
not serve, and therefore exactly the kind of gap someone could fill. The writer need not be
the owner: any share granting `acl:Write` deep enough would do, which makes issuer metadata
the one thing in this URL space that must not be delegable at all. Reserving names as they
are implemented would turn each future name into a migration with a window in which the old
content still answers; reserving the segment closes the class once, and `/.well-known/solid`
(#16) lands in already-reserved space when it arrives.

**The pod answers these itself.** A reverse proxy in front of it passes `/.well-known/`
through rather than serving it, so a verifier reads the metadata of the process that holds
the signing key, and conformance does not depend on how the pod is fronted.

The reservation is unconditional, but serving it takes an origin. In a path-based topology
(`https://host/{user}/`) `/.well-known/` sits above the pod's base URI and is not part of
its space at all — which is why `--op-signing-keys` refuses the start on a base URI with a
path: an issuer whose discovery document is not at its origin is not one a verifier can
find.

## Do not construct auxiliary URLs — discover them

The tables above document the current mapping so operators can reason about the server.
**Clients must not depend on it.** WAC is explicit:

> "Clients MUST discover the ACL resource associated with a resource by making an HTTP
> request on the target URL, and checking the HTTP `Link` header with the `rel` parameter."
>
> "Clients MUST NOT derive the URI of the ACL resource through string operations on the URI
> of the resource."

This pod advertises `Link: <…>; rel="acl"` wherever a client mid-create-flow needs it: a
successful `GET` (and its `304`), a `404` for a resource that does not exist yet, a denial
(`401`/`403`), and a `201` on creation. It is not present on every possible response — a `406`,
`415`, `400`, `409`, `412`, `405`, `204`, or `500` carries no target to advertise a `Link` for
and has none. The auxiliary URL scheme is an implementation detail and may change; the `Link`
header is the interface.

Server implementations differ here, which is why the header exists: Community Solid Server
uses a configurable `.acl` suffix, Trellis uses `?ext=acl`, Manas uses `<res>._aux/acl`, and
Enterprise Solid Server hosts access-control resources on an entirely separate service.

## Server-asserted facts are not auxiliary resources

Existence, the kind of representation, and the media type it arrived as are **not**
addressable and not writable. They live in an internal graph (`urn:quadpod:sys:<res>`), and a
client reads them off the response rather than off a URL: existence as the status code (a
`200` or a `304` rather than a `404`), the media type as `Content-Type`, and the kind through
no header of its own — no response carries a promise of it. Today, every media type this pod
recognises as RDF names an RDF resource, and anything else names a binary one, so a client can
correlate kind with `Content-Type` in practice. That correlation is not a guarantee: the pod's
own storage layer stores the kind as a fact independent of the media type precisely because
`application/rdf+xml` is a plausible future addition to what this pod parses as RDF, and the
day it lands, every resource already stored under that type would answer with the same
`Content-Type` it always has while silently changing kind underneath a client that inferred
one from the other.

For a binary resource `Content-Type` is the stored media type exactly, because there is one
representation. For an RDF resource it is the negotiated one: a graph stored as Turtle and
fetched with `Accept: application/ld+json` answers `application/ld+json`. The stored value is
what `*/*` resolves to, not a promise about every response.

Byte size and content hash live nowhere: with a swappable blob backend, the pod does not
exclusively own the bytes behind a resource, so a stored size or hash would go silently false
the moment anything else writes into the same bucket. `Content-Length` and `ETag` are computed
from the bytes themselves instead. The storage key is derived from the resource's own URL
rather than recorded.

The split is by authority, not by subject matter. An auxiliary holds what *you* assert about
a resource; these are what the *server* asserts about it. This pod also never writes
association triples into your data — no `seeAlso` pointing at an ACL, nothing. The `Link`
header is the interface; your graphs stay yours. The moment a server-asserted fact has a
writable URL it stops being server-asserted: a client could declare its own resource binary
while storing triples, or claim a media type the bytes are not in, and every reader
downstream would believe it. A read-only projection of these facts may be offered later; it
will never be writable.

## One query parameter, and what it means

`GET <resource>?validate` returns the resource's current SHACL validation
report — a `sh:ValidationReport`, in the negotiated RDF format — instead of the
resource's own representation. It is a computed view: nothing is stored, so it
always describes the representation and the shape as they are now.

It is a query parameter rather than an auxiliary because a report is a
server-asserted fact about your data, not your data, and this document reserves
`/.aux/` for the latter. The parameter changes no path, so the URL's WAC target
is the resource itself and `acl:Read` on the resource is what it takes.

`?validate` on a resource whose container binds no shape is a `404`. Every other
query parameter is ignored, as it always has been.

## The vocabulary this pod mints

One link relation is minted here, because none is registered for what it says:

```
Link: <urn:example:g1>; rel="https://quadpod.toph.so/ns#containsGraph"
```

It appears on a `GET` answered in a format that cannot carry named graphs — Turtle or
N-Triples against a dataset-valued resource — and names a graph the response therefore does
**not** contain. It is what makes that partial answer honest rather than silently short, and
it is why the response is a `200` with the default graph rather than a `406`. RFC 8288 permits
extension relations; the only requirement is an absolute IRI.

`rel="alternate"` accompanies it, with `type="application/trig"` and
`type="application/ld+json"`. That one carries its ordinary meaning — another representation
exists — and **not** a claim about completeness; no registered relation says "this response is
lossy", which is why `containsGraph` exists at all.

**This IRI is provisional.** It is not dereferenceable yet, and it is tied to a hostname that
may change. Moving it later is a breaking change for anything that reads it, so it gets
settled — a permanent identifier, or a hosted document at that address — before this pod is
deployed anywhere, and at the latest before 1.0. The internal `urn:quadpod:` namespace is a
different thing entirely: it never leaves the server (see the design specs), while this one is
part of the contract.

## Design rationale

Auxiliaries live under a reserved *prefix* rather than behind a filename suffix: a
reserved prefix is a total function over the path space, evaluated once by the
router, while a reserved suffix is a predicate that has to be re-evaluated everywhere a path
is constructed — and every place it is forgotten is an authorization defect.
