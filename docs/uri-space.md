# URI Space and Reserved Paths

This is the contract between this pod and its clients about **which URLs mean what**. It is
normative for the server and for anyone writing data into it.

## Your space, and one segment that is not

Almost every path this pod serves is yours. Exactly one first-level segment is not:

| Path | Meaning |
|---|---|
| `/.aux/…` | auxiliary resources — your data, with a meaning the server has to understand |
| everything else | ordinary resources and containers |

That is the whole reservation. `/.hidden`, `/.config`, `/notes/.env` and any other
dot-prefixed name are ordinary resources with no special treatment — the reservation costs
you the single name `.aux` at the root, and nothing else, ever.

**One segment, not one per feature.** Every auxiliary kind lives inside `/.aux/`, so
adding a kind later takes nothing away from you at that point.

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

The reservation is still the leading segment and nothing else: `/foo.acl` and `/notes/x.meta`
are ordinary resources of yours, because they do not begin with `/.aux`. A path under `/.aux/`
that ends in no kind's name — `/.aux/foo`, `/.aux/bogus/x`, `/.aux/` itself — names nothing
and answers `404`.

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

## `/.well-known/` belongs to the origin, not to the pod

`/.well-known/` is defined by RFC 8615 as a place the *host* provides. `.well-known` is not
the reserved segment (only `.aux` is, see above), so this pod does not reserve it or treat it
specially: `PUT /.well-known/x` is an ordinary authorized write, like any other path. Serving
`/.well-known/` is expected to be the deployment's job instead — in this architecture the
reverse proxy that terminates TLS, which can answer it without the pod ever seeing the
request.

This only arises when the pod's base URI is the origin root. In a path-based topology
(`https://host/{user}/`) `/.well-known/` sits above the pod's base URI and is not part of
its space at all.

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
no header of its own; a client infers it from `Content-Type`, since only the media types this
pod recognises as RDF name an RDF resource, and anything else names a binary one.

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

See [`specs/2026-07-27-acl-auxiliary-model-design.md`](superpowers/specs/2026-07-27-acl-auxiliary-model-design.md)
for why auxiliaries live under a reserved *prefix* rather than behind a filename suffix. In
short: a reserved prefix is a total function over the path space, evaluated once by the
router, while a reserved suffix is a predicate that has to be re-evaluated everywhere a path
is constructed — and every place it is forgotten is an authorization defect.
