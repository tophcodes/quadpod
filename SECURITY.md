# Security policy

## Supported versions

None yet. quadpod is pre-release: there is no tagged release, no published binary and
no container image, so every report is against `main` and gets fixed there.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting — **Security → Report a vulnerability** on
this repository. Please do not open a public issue for anything exploitable.

Useful in a report: the request that triggers it, the pod's configuration (the flags
matter — `--trusted-issuer` above all), and what an attacker gets out of it. This is a
single-maintainer project without an on-call rotation; a report will be read, but no
response time is promised.

## What counts

The pod is meant to be reachable from the internet behind a reverse proxy, so anything
that survives that deployment is in scope:

- Authentication — accepting a token that should have been refused: a DPoP proof that
  does not bind the request, an issuer that is not trusted, a WebID whose
  `solid:oidcIssuer` does not name the issuer that signed the token.
- Authorization — a Web Access Control decision that **allows** what the ACL does not.
  An over-denial is a bug, not a vulnerability.
- Anything reachable before the request is authenticated. Those code paths handle
  attacker-chosen input by definition, including the URLs the pod fetches to verify a
  token — see [`docs/deployment.md`](docs/deployment.md) for the SSRF policy.
- Escaping the URL contract in [`docs/uri-space.md`](docs/uri-space.md): naming a graph
  no request path is supposed to be able to name, or reaching one resource's storage
  through another's URL.

## Known, open, and already public

Some weaknesses are tracked in the open issue list rather than treated as reports.
They are known; a report that restates one adds nothing, but a working exploit against
one is still worth sending privately.

## By design, and not a vulnerability

- No TLS in the server. It binds to loopback and speaks plain HTTP; certificates belong
  to the reverse proxy.
- Started without `--trusted-issuer`, the pod trusts every issuer. That is documented,
  loudly, in the README and in `--help`. It is a configuration mistake, not a defect.
- A `Bearer` credential is refused. That is the stronger position, not the weaker one.
- RDF is stored parsed, so bytes do not round-trip and a signature over a document does
  not survive. Write bytes as a blob if the bytes matter.
