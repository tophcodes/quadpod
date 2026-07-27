# URI Space and Reserved Paths

This is the contract between this pod and its clients about **which URLs mean what**. It is
normative for the server and for anyone writing data into it.

## The two spaces

Every path served by this pod belongs to exactly one of two spaces, decided by its **first
path segment**:

| Space | Shape | Contents |
|---|---|---|
| Resource space | first segment does **not** begin with `.` | your data — documents, containers, blobs |
| Reserved space | first segment **begins with `.`** | server-managed auxiliary resources |

The classification is a total function of the path, applied once when the request is routed.
There is no path that is ambiguous between the two, and no way for a client-chosen name —
including a `Slug` — to land in the reserved space.

## Reserved prefixes

**The entire reserved space is claimed by the server**, whether or not a given prefix is
implemented yet. Requests to an unallocated reserved prefix are refused; they will never
become a place to store your data.

| Prefix | Purpose | Status | Client may write? | Authorized by |
|---|---|---|---|---|
| `/.acl/` | access control (WAC) | live | yes | `acl:Control` on the subject |
| `/.meta/` | description resource — client-supplied metadata *about* a resource | reserved, not implemented | yes, once implemented | `acl:Write` on the subject |
| any other `/.…/` | future auxiliary kinds | reserved | no | — |

An auxiliary URL is formed by prefixing the subject's path:

| Subject | ACL |
|---|---|
| `/` | `/.acl/` |
| `/foo` | `/.acl/foo` |
| `/box/` | `/.acl/box/` |
| `/a/b/c` | `/.acl/a/b/c` |

**`.meta` is client-writable but is still an auxiliary path.** Being writable does not make
it ordinary: it is created and deleted with its subject, it never appears in a container
listing, and its authorization derives from the subject resource, not from itself. The same
is true of `.acl`. Writability and ordinariness are different properties.

## Only the first segment is reserved

A dot anywhere else is ordinary. `/box/.acl`, `/notes/.hidden` and `/a/b/.config` are
perfectly normal resources in the resource space, with no special meaning whatsoever. The
reservation costs you exactly one thing: **you cannot create a resource whose first path
segment begins with a dot.**

## Do not construct auxiliary URLs — discover them

The table above documents the current mapping so that operators can reason about the
server. **Clients must not depend on it.** WAC is explicit:

> "Clients MUST discover the ACL resource associated with a resource by making an HTTP
> request on the target URL, and checking the HTTP `Link` header with the `rel` parameter."
>
> "Clients MUST NOT derive the URI of the ACL resource through string operations on the URI
> of the resource."

This pod advertises `Link: <…>; rel="acl"` on every response for a resource path —
including `404` and denial responses, so that a client mid-create-flow never has to guess.
The auxiliary URL scheme is an implementation detail and may change; the `Link` header is
the interface.

Server implementations differ here, which is why the header exists: Community Solid Server
uses a configurable `.acl` suffix, Trellis uses `?ext=acl`, Manas uses `<res>._aux/acl`, and
Enterprise Solid Server hosts access-control resources on an entirely separate service.

## Server-asserted facts are not auxiliary resources

Creation and modification times, byte size, content hash and storage keys are **not**
addressable and not writable. They live in a reserved internal graph (`urn:pod:sys:<res>`)
and are exposed through the HTTP headers that already exist for them — `Last-Modified`,
`ETag`, `Content-Length`.

The split is by authority, not by subject matter: the moment a server-asserted fact has a
writable URL, a client can assert its own creation timestamp, and the value is worthless for
auditing or ordering. A read-only projection of these facts may be offered later; it will
never be writable.

## Design rationale

See [`specs/2026-07-27-acl-auxiliary-model-design.md`](superpowers/specs/2026-07-27-acl-auxiliary-model-design.md)
for why auxiliaries live in a reserved *prefix* rather than behind a filename suffix. In
short: a reserved prefix is a total function over the path space, evaluated once by the
router, while a reserved suffix is a predicate that has to be re-evaluated everywhere a path
is constructed — and every place it is forgotten is an authorization defect.
