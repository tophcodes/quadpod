# Deployment

Operator-facing notes: what this pod fetches from the network, and the one flag that
changes which destinations it will accept.

## The pod makes outbound requests before it trusts anyone

Three fetches happen while a request is still unauthenticated, driven by strings the
*token* supplies:

| Fetch | URL comes from |
|---|---|
| OIDC discovery | `<iss>/.well-known/openid-configuration`, where `iss` is a claim in the presented token |
| JWKS | the `jwks_uri` the discovery document returns |
| WebID profile | the `webid` claim, with its fragment stripped |

None of these has been vouched for by anything at the moment it is fetched. A caller who
can pick the `iss` or `webid` string can therefore steer this process at a URL of their
choosing — a blind, pre-authentication SSRF primitive. `src/auth/safe_fetch.rs` is the
control that closes it, and by default it refuses:

- any scheme but https;
- any host resolving to loopback, RFC 1918 private space, link-local (`169.254/16`, which
  covers the cloud-metadata endpoint), CGNAT (`100.64/10`), or the IPv6 equivalents
  (`::1`, `fc00::/7`, `fe80::/10`, and the IPv4-mapped/compatible forms of all of the
  above);
- redirects — a 3xx is a failure, never followed;
- re-resolution: the filter runs inside the client's own DNS resolver, so the only
  addresses a connection can reach are ones it passed — a name cannot answer public for
  the check and private for the connection;
- bodies over 1 MiB, and anything slower than a 5 s connect / 10 s total timeout.

## `--allow-insecure-host`

    --allow-insecure-host <HOST>          repeatable
    POD_ALLOW_INSECURE_HOSTS=<HOST,HOST>  comma-separated

An entry is either `host` — every port on that host — or `host:port`, only that port.
Matching is on the **host string as it appears in the URL**, before resolution: if the
issuer is `http://localhost:3001/`, the entry must be `localhost:3001`. `127.0.0.1:3001`
will not match it, even though the name resolves there.

Each entry is parsed once, at startup, into a host and an optional port — not re-matched
as a raw string on every fetch. The host portion is parsed by handing it to the same URL
library (`url`, via `reqwest::Url`) that will parse the target of the actual fetch, instead
of re-deriving that normalization by hand: whatever canonical form `url` produces for a
request is exactly what gets stored, so the two cannot disagree. Concretely, that means an
entry's host is accepted and stored **in whatever form a real request to it would
normalize to** — lowercased, IDNA/punycoded, percent-decoded, with an IPv4 literal written
as `127.1`, `0x7f.1`, or a bare decimal (`2130706433`) collapsed to dotted-quad, and an
IPv6 address compressed per RFC 5952 — including an IPv4-mapped address
(`::ffff:127.0.0.1`), which is stored as `::ffff:7f00:1` (the WHATWG serializer's hex-group
form), never the dotted-quad form. You do not need to pre-normalize an entry by hand; write
it however you'd write the URL's host, and it will match.

Entry form:

- **No scheme, no path, no credentials, no query, no fragment** — `localhost:3001`, not
  `http://localhost:3001/`, `user@localhost:3001`, `localhost:3001/x`,
  `localhost:3001?q=1`, or `localhost:3001#frag`. Any of these is rejected outright.
- **Default ports are explicit.** A URL with no port is compared against the scheme's
  default, so `http://css.local/` matches the entry `css.local:80` (or the bare
  `css.local`), not `css.local:3001`.
- **A trailing dot on a hostname is not stripped.** `http://localhost.:3001/` has host
  `"localhost."` (a syntactically legal absolute FQDN), which will not match the entry
  `localhost:3001`. This is the safe direction — under-matching, never over-matching — but
  it costs an operator an hour if they don't know about it, so: don't write the trailing
  dot, and don't expect the entry to grow one for you.
- **IPv6 host, no port: unbracketed** — `fd00::1` or `::1`, matching every port on that
  address. Internally this is bracketed and canonicalized before being stored (matching
  what a URL to that address produces), but you write it bare.
- **IPv6 host with a port: bracketed, `[host]:port`** — `[fd00::1]:80`, `[::1]:3001`. This
  is the *only* way to pair an IPv6 host with a port. An unbracketed `host:port`-looking
  spelling for IPv6 (e.g. `fd00::1:80`, which reads exactly like the address
  `fd00::1:80`) is ambiguous — a colon-delimited port suffix is indistinguishable from
  another IPv6 group — and matches neither reading. The pod **refuses to start**, naming
  the entry and the bracketed form to use instead (`[fd00::1]:80`).
- **A non-canonical spelling still works — it's normalized, not compared verbatim.** This
  is no longer just an IPv6 courtesy: `[0:0:0:0:0:0:0:1]` and `[fd00::0001]:80` are
  IPv6-canonicalized (`::1`, `fd00::1`); `127.1:3001`, `0x7f.1:3001`, `2130706433:3001`, and
  `127.0.0.01:3001` are all IPv4-canonicalized to `127.0.0.1:3001`; `%6Cocalhost` is
  percent-decoded to `localhost`; and an internationalized hostname (`bücher.example`) is
  punycoded (`xn--bcher-kva.example`) — all matching what `url` produces for the same
  request, since that is the same library doing both.
- **A malformed entry also refuses to start the pod, rather than being stored inert.** A
  scheme, a path, credentials, a query, a fragment, whitespace, or an out-of-range port
  folded into the host — `http://localhost:3001`, `localhost/x`, `localhost:3001/`,
  `localhost:99999` — can never match a real URL host, so it is rejected outright, named at
  startup, with the entry printed.

### What it relaxes, for a listed host only

- the private/loopback/link-local/CGNAT IP filter;
- the https-only rule.

### What it does not relax, for any host including a listed one

- redirects are still refused;
- the connection still reaches only addresses the filter passed, so DNS rebinding is still
  closed;
- the 1 MiB body cap and the connect/total timeouts still hold;
- every other host on earth keeps the full default posture. Naming one host unblocks
  exactly that host.

There is no flag that turns the filter off globally. The blanket-permissive policy exists
only behind `#[cfg(test)]` and cannot be constructed in a release build. That gate is pinned
by a rule in `docs/constraints.md`, because no test can observe its absence — tests run with
`cfg(test)` on.

### Alternatives that were rejected

The line this flag draws is **named by the operator versus chosen by an attacker**, not
private versus public IP. Three other shapes were considered and dropped:

- **A global off switch** for the filter. It would open the pre-authentication fetch surface
  to every host on earth for the sake of one.
- **A test-only binary** that skips the filter. The conformance run has to exercise the
  production `authenticate` path, or it measures something other than the pod.
- **Drawing the line at private-versus-public IP ranges.** The wrong axis: a public address an
  attacker picked is more dangerous than a private one the operator typed.

Wildcards, subdomain matching or CIDR ranges would each reintroduce the attacker-chosen axis
this design exists to exclude. That is the change that should reopen the decision.

### The honest cost

For a listed host the pre-authentication fetch surface is open again. Anyone who can reach
this pod with a token they control can make it issue plain-http GETs to that host and port,
and read nothing back — but the request itself is the primitive, and services that act on a
GET act on it. The bound is exactly the set of entries the operator typed: no wildcards, no
subdomain matching, no CIDR ranges, no implicit localhost.

Two things keep that bound tight in practice:

- **Prefer `host:port` to a bare `host`.** Naming a host with no port opens every port on
  it, and port scanning is most of what an SSRF primitive is worth.
- **Pair it with `--trusted-issuer`.** With an issuer allowlist configured, a token naming
  an untrusted issuer is rejected *before* any fetch is attempted, so the relaxed policy is
  never reached by a token the operator did not expect. Without one the pod is open
  federation and any issuer gets as far as the fetch.

A non-empty list is logged at `warn` on startup — it is a security control being relaxed,
and an operator scanning their logs should see it without looking for it.

### Intended use

Local development and conformance runs against a locally-hosted IdP, e.g. a Community
Solid Server on `localhost:3001`:

```bash
sparql-pod \
  --owner-webid http://localhost:3001/alice/profile/card#me \
  --trusted-issuer http://localhost:3001/ \
  --allow-insecure-host localhost:3001
```

A production deployment reaching a real IdP over https needs none of this and should
pass no `--allow-insecure-host` at all.

## Where the data lives

    --rdf-store memory            (default) triples in this process, gone on restart
    --rdf-store rocksdb:<dir>     triples in <dir>
    --blob-store memory           (default) non-RDF bytes in this process
    --blob-store local:<dir>      non-RDF bytes mirroring the URL tree under <dir>

A `rocksdb:` directory is held by **one process at a time** — Oxigraph takes an exclusive
lock, so a second pod aimed at the same path refuses to start. That is a bound on processes,
not on concurrency: within the running pod, requests are served in parallel as before. Root
spec §16 ADR-7 has the reasoning, including why multi-tenancy does not collide with it (§9
runs many spaces in one process, as named graphs in one store).

Back up the store directory and the blob directory together. They are one dataset: a blob is
addressed by the resource path recorded in the triples, so a store restored without its blobs
describes bytes that are not there.

## The config file

    --config <path>
    POD_CONFIG=<path>

TOML, flat, with the flag names as keys. There is **no search path** — nothing is read unless
this names it, so a pod cannot start against a file that is invisible to whoever reads the
command line. A path that is named but unreadable, is not valid TOML, or carries a key this
binary does not know refuses the start.

```toml
base_uri     = "https://pod.toph.so/"
owner_webid  = "https://toph.so/profile/card#me"
rdf_store    = "rocksdb:/var/lib/sparql-pod/store"
blob_store   = "local:/var/lib/sparql-pod/blobs"
listen       = "127.0.0.1:3000"

trusted_issuers       = ["https://idp.toph.so/"]
expected_audience     = "https://pod.toph.so/"
allow_insecure_hosts  = []
reset_root_acl        = false  # a recovery lever, not a setting: leaving this `true` in
                                # a file resets the root ACL on *every* start, silently
                                # discarding any grant made to it over HTTP since. Turn
                                # it on for one restart, then turn it back off.
max_body_bytes        = 67108864
```

**Precedence: flag > environment > file > default.** A value in the file loses to the same
value in `POD_*`, which loses to the flag. Lists are TOML arrays, which is easier to read than
the comma-separated environment form and needs no quoting of the separator — but it is not
free of the comma problem: `trusted_issuers` and `allow_insecure_hosts` still carry the comma
delimiter that the environment form needs, clap applies it to a file-supplied value too, and a
single array entry containing a comma is split in two and cannot be expressed. The same
trimming and filtering the environment form needs still runs on a file-supplied value as well.

An error caused by a value the file supplied names the file and the key. An error about
`--rdf-store`, `--blob-store` or `--allow-insecure-host` names the flag even when the value
came from the file — those three are checked after the parse rather than inside it.
