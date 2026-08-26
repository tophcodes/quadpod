# Extraction and Projection

How bytes in the blob store become triples in the quad store, how that is configured, and
how triples become visible again as files. This is a design, not an implementation report:
nothing here is built yet, and the open questions at the end are open.

## The setting that motivates it

The blob store is a directory a human uses directly. `--blob-store local:$HOME/pod` makes
`$HOME/pod` both this pod's byte storage and an Obsidian vault, which works only because
`BlobKey` is the resource's own path: the backing store mirrors the URL tree and can be
read with ordinary tools. Notes are Markdown blobs, preserved byte for byte; their metadata
is YAML frontmatter, which is JSON-LD once it has a context.

Two consequences follow, and everything below is a consequence of these two.

**Files appear that no request wrote.** An editor writes into the directory; a Syncthing
replica delivers bytes the local pod never saw. The quad store learns nothing, so
`urn:quadpod:sys:<res>` has no presence marker and the resource does not exist as far as
this pod is concerned.

**Files carry triples the store should know.** A note's frontmatter, a `.ttl` sitting in
the tree, EXIF in a photograph. The bytes are authoritative and must stay untouched; the
triples are an index over them.

## Bytes are authoritative, triples are derived

One direction, always. A blob's bytes are the truth; extraction produces triples about
those bytes; nothing ever writes back into the file. This is what makes the whole design
tractable: no round-trip fidelity to defend, no merge, no two writers.

The target is the description auxiliary, which `uri-space.md` currently lists as *reserved,
candidate, unpromised*. This design promises it, with a narrower meaning than "metadata":

> `/.aux/{subject}.meta` is the derived index over the bytes of its subject.

The four properties `uri-space.md` requires of an auxiliary are already true of it:
it exists only for an existing subject and dies with it, it stays out of container
listings, its authorization derives from the subject, and it is discoverable from the
subject by `Link`. Writability is the one open question; see below.

Extraction is per media type, and every extractor writes to the same place:

| Subject | Extractor | Target |
|---|---|---|
| `/making/simpit/note.md` | frontmatter → JSON-LD | `/.aux/making/simpit/note.md.meta` |
| `/foo.ttl` | parse as Turtle | `/.aux/foo.ttl.meta` |
| `/photo.jpg` | EXIF | `/.aux/photo.jpg.meta` |

**A `.ttl` in the blob store stays a blob.** It is not reclassified into the quad store.
`classify_body` decides RDF-vs-blob from `Content-Type`, and a file on disk has no
`Content-Type`. An extension is no format claim, which is why extensionless URLs are the
recommendation in the first place. So the rule is positional and needs no sniffing: what is
in the blob store is bytes, and what its bytes mean is what extraction reports. A Turtle
document you can edit and diff is worth more than one whose whitespace the pod ate.

RDF written over HTTP with `text/turtle` is unaffected. It is parsed into the quad store as
it is today, and it has no bytes, so it has nothing to extract.

## Configuring extractors

Extraction is behaviour the server performs on the user's data, so its configuration is
the user's data with a meaning the server has to understand, which is the definition of an
auxiliary. It lives at `/.aux/{subject}.config` and inherits down the container tree the
way an ACL does, so the root container can configure the whole pod and a subtree can
refine it.

Three tiers of extractor, and the first covers most of the need:

**Declarative.** Frontmatter is already a tree; a JSON-LD `@context` is already the
mapping. A user-supplied context plus a small set of mapping rules needs no code and has
no sandbox to get wrong.

**WASM.** For logic a mapping cannot express: a module stored as an ordinary blob in the
pod and referenced from the config. Sandboxed by construction, no ambient filesystem or
network, fuel-limited against non-termination, versioned and access-controlled like any
other resource.

**Never a shell hook.** This pod is internet-facing and is its own OP. "Writing a file runs
a script" means whoever can `PUT` can execute.

## The trust gate

Extractor configuration is triples the user writes that steer what the server executes.
The question the pod has to answer on such a write is not "may this agent write here" but
**"is this agent trusted to supply logic this server will run"**, and a no there means the write is
refused rather than accepted and ignored.

That is a distinct capability, so it is a distinct WAC mode. Two constraints on it:

**It cannot live in `urn:quadpod:`.** That namespace exists precisely so server bookkeeping
never appears where a client can address it. An access mode is the opposite: it is written
into ACL documents by clients and has to be dereferenceable. It needs an `https:` namespace
this pod serves.

**Name it for what it grants.** `ManageAcl` is the wrong name, because that is the definition of `acl:Control`,
and a mode by that name which does not manage ACLs is a trap for the reader. It grants the
right to configure extractors; say so.

**Status codes.** No credentials or bad credentials is `401`. Authenticated and lacking the
mode is `403`. The distinction matters here because the failure is expected in normal
operation, not only under attack.

**The ceiling.** A mode below `acl:Control` is no boundary against `acl:Control`:
whoever can write the ACL can grant themselves any mode in it. The value of a separate mode
is delegation downward: an agent that may configure extraction without also being able to
redistribute access. That is a real gain, and it is the only one.

**Stale grants.** The gate is checked when the configuration is written, but the
configuration keeps executing afterwards. Revoking an agent's trust must therefore do
something about configurations it already wrote: either the check is repeated at execution
time against the recorded author, or revocation sweeps existing configurations. Deciding
nothing here means revocation silently does not revoke.

## Reconcile

Two layers, and the split between them is the whole point.

**The watcher is advisory.** It says "look at this path" and decides nothing. inotify is
lossy: queue overflow under load, a blind window at startup, nothing at all on network
filesystems. Advisory, a lost event costs latency; authoritative, it would cost data.

**Reconcile is authoritative.** It walks a set of paths, mints presence markers and
containment for bytes the store does not know, retires markers whose bytes are gone, and
runs extraction. Idempotent, and it never copies bytes, since the key is derived from the path,
so a file already in the right place is already stored.

Around that, three things that decide whether it is cheap or wasteful:

**Debounce, 200–500 ms per path.** Editors write temp-then-rename; one save is a burst of
events. Without coalescing, one Ctrl-S extracts the same note five times.

**Do not poll the tree.** A periodic full `stat` walk over a vault with a multi-gigabyte
asset subtree is page-cache thrashing for nothing. When the blob store is a git working
tree, `git status --porcelain` names the changed set without walking. On a replica,
Syncthing's folder-completion event is a better trigger than any timer, because it fires
exactly when a batch of foreign writes has landed.

**Regular files only.** Reconcile skips symlinks and `.quads/`. Without that rule it finds
the projection symlinks below, treats them as blobs, and mints presence markers for derived
content, which is then itself projected.

## Projection

The reverse view: RDF that lives only in the quad store, made visible as files.

`<blob-store>/.quads/` is a read-only FUSE mount whose tree mirrors the URL space, and a
tool places symlinks from it into the directories where the subjects live:

    ~/pod/making/simpit/note.md              real file, real disk
    ~/pod/making/simpit/.note.md.ttl    ->   ../../.quads/making/simpit/note.md.ttl

FUSE stays out of the hot path this way. Reading the vault touches real files; `readdir` is
a real directory read; only opening a projection enters the mount. `.quads` is dot-prefixed
and therefore invisible to Obsidian, and dot-prefixing the symlinks keeps them out of its
file explorer too while leaving them to `ls -a`, `rapper` and scripts.

The symlinks are derived, host-local artefacts: git and Syncthing must exclude them, and
the tool regenerates them per host. A symlink into a mount the other machine does not have
is a broken link there.

**Metadata eager, bytes lazy.** `getattr` has to report `st_size` before anything reads,
and computing it by serializing would defeat the laziness entirely. So the canonical byte
length and the ETag are computed during extraction and stored in `urn:quadpod:sys:<res>`
beside the size, hash, content type and ETag already kept for blobs. `read` is the only
operation that serializes.

**Canonicalization.** [RDFC-1.0](https://www.w3.org/TR/rdf-canon/) canonicalizes a dataset
to canonical N-Quads: deterministic blank node labels, one LF per quad, byte-identical
output for isomorphic datasets. Turtle has no such standard: prefixes, abbreviations, list
syntax and ordering are all free. So N-Quads is the canonical basis, the ETag is a hash over
it, and every other serialization is a deterministic function of the same dataset. A
canonical Turtle writer is a quadpod-local convention, which is acceptable because this
FUSE layer is quadpod's, not a generic Solid client.

**ETags identify representations.** If `.ttl` and `.nq` differ in bytes they need different
ETags, and over HTTP content negotiation that also means `Vary: Accept`, or a cache
answers an N-Quads request with Turtle bytes. In the projection the serialization is in the
path, so they are different URLs and the problem does not arise; over the API it does.

## Open questions

**Is `.meta` writable?** `uri-space.md` reserves it as writable-if-implemented. As a
derived index it should not be, or a client write is lost on the next extraction. Either it
is read-only and user assertions about a blob go somewhere else, or it is partitioned into a
derived graph and an asserted one.

**Where does the extractor's output graph live?** `<res>.meta` as its own resource graph is
the obvious answer, but extraction results and user triples must not be able to overwrite
each other, and `constraints.md` will want a check that says so in one place.

**Trust revocation.** See above: repeated check at execution, or a sweep. Unresolved.

**Does the config auxiliary need its own kind, or is it `.meta` with a reserved
predicate?** A separate `.config` kind is cleaner to authorize; a predicate is one fewer
reserved name. The authorization argument probably wins, but it has not been made properly.

**Obsidian.** Making the projection navigable from inside Obsidian implies a plugin that
speaks Solid rather than the filesystem. That is a separate project with its own design;
none of the above depends on it.
