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
- re-resolution: the connection is pinned to the exact address that was validated, so a
  name cannot answer public for the check and private for the connection;
- bodies over 1 MiB, and anything slower than a 5 s connect / 10 s total timeout.

## `--allow-insecure-host`

    --allow-insecure-host <HOST>          repeatable
    POD_ALLOW_INSECURE_HOSTS=<HOST,HOST>  comma-separated

An entry is either `host` — every port on that host — or `host:port`, only that port.
Matching is on the **host string as it appears in the URL**, before resolution: if the
issuer is `http://localhost:3001/`, the entry must be `localhost:3001`. `127.0.0.1:3001`
will not match it, even though the name resolves there.

Each entry is parsed once, at startup, into a host and an optional port — not re-matched
as a raw string on every fetch. That matters for IPv6: naively splitting `host:port` on
the last colon breaks as soon as the host itself contains colons, and — worse — the wrong
fallback (treating the whole string as one opaque token) let one entry alias a completely
different, unlisted address. Both failure modes are closed by the rules below.

Entry form, exactly:

- **Lowercase.** The URL's host is compared after the URL parser has lowercased it, so
  `LocalHost:3001` never matches. Write entries lowercase.
- **No scheme, no path, no trailing slash** — `localhost:3001`, not
  `http://localhost:3001/`.
- **Default ports are explicit.** A URL with no port is compared against the scheme's
  default, so `http://css.local/` matches the entry `css.local:80` (or the bare
  `css.local`), not `css.local:3001`.
- **A trailing dot on a hostname is not stripped.** `http://localhost.:3001/` has host
  `"localhost."` (a syntactically legal absolute FQDN), which will not match the entry
  `localhost:3001`. This is the safe direction — under-matching, never over-matching — but
  it costs an operator an hour if they don't know about it, so: don't write the trailing
  dot, and don't expect the entry to grow one for you.
- **IPv6 host, no port: unbracketed** — `fd00::1` or `::1`, matching every port on that
  address. The brackets a URL requires (`http://[::1]:3001/`) are stripped before the
  comparison, so the bare, unbracketed form is what you write.
- **IPv6 host with a port: bracketed, `[host]:port`** — `[fd00::1]:80`, `[::1]:3001`. This
  is the *only* way to pair an IPv6 host with a port. An unbracketed `host:port`-looking
  spelling for IPv6 (e.g. `fd00::1:80`, which reads exactly like the address
  `fd00::1:80`) is ambiguous — a colon-delimited port suffix is indistinguishable from
  another IPv6 group — and is **dropped entirely**, matching neither reading, rather than
  guessed at. It will not appear in the startup warning, and it grants nothing. Use the
  bracketed form.

### What it relaxes, for a listed host only

- the private/loopback/link-local/CGNAT IP filter;
- the https-only rule.

### What it does not relax, for any host including a listed one

- redirects are still refused;
- the connection is still pinned to the validated IP, so DNS rebinding is still closed;
- the 1 MiB body cap and the connect/total timeouts still hold;
- every other host on earth keeps the full default posture. Naming one host unblocks
  exactly that host.

There is no flag that turns the filter off globally. The blanket-permissive policy exists
only behind `#[cfg(test)]` and cannot be constructed in a release build.

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
