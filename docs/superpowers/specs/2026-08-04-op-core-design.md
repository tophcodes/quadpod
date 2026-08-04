# OP core: signing key, JWKS, discovery, token minting

Slice 1 of the Solid-OIDC identity provider (epic #57), implementing issue #21.
The pod gains everything that signs and everything a verifier needs to check a
signature. It does not yet gain any endpoint that hands a token to a caller.

## Scope

In: a persisted signing key set, a public JWKS, the OIDC discovery document,
and an internal Rust API that mints DPoP-bound access tokens carrying a
`webid` claim.

Out, with their owning issues: the authorization and token endpoints and ID
tokens (#58), Client ID Documents and registration (#59), human
authentication (#60), and the service-identity WebID document, which moves
from #21 to #23 because it is specific to that subject.

Acceptance: the pod verifies a token it minted itself through its own
unmodified auth stack — `trusted_issuers` names the pod, and the round trip
(mint → authenticated request → 2xx) passes in an integration test.

## Key handling

The signing keys live in a private JWKS file — an RFC 7517 key set, JSON —
at a path named by a new config field `op_signing_keys` (config file and CLI
flag, clap precedence as everywhere else).

- Field absent → the OP is off. No routes, no key material, and the pod
  remains the verify-only server it is today.
- Field set, file missing → the pod generates an ES256 (P-256) key and
  writes the file with mode 0600. This mirrors `--rdf-store rocksdb`
  creating its directory.
- File present → it is never rewritten. A read-only file (agenix) works.
- A key without a `kid` gets its RFC 7638 thumbprint as `kid`, so the `kid`
  is stable across restarts and deterministic for the same key.
- The first key in the set signs; every key is published. Rotation is an
  operator edit: prepend the new key, keep the old until the last token
  signed with it has expired, then remove it. No admin verb and no
  automatic rotation in this slice.

## HTTP surface

`/.well-known/` becomes the second reserved leading segment, next to `.aux`,
unconditionally — whether or not the OP is enabled:

- Any write method anywhere under `/.well-known/` answers 405.
- `GET` serves only what the pod implements; every other name is 404.
- With the OP enabled, the pod implements two names, as exact routes ahead
  of the LDP wildcard:

| Route | Answer |
|---|---|
| `GET /.well-known/openid-configuration` | discovery JSON, `application/json` |
| `GET /.well-known/jwks.json` | public key set, `application/jwk-set+json` |

The JWKS response carries only public members — private members (`d`, RSA
CRT parameters) are stripped before serialization, and a test asserts their
absence.

Reserving the whole segment rather than two paths is deliberate: RFC 8615
defines `/.well-known/` as origin infrastructure, and once this origin is an
identity provider a writable name there is a spoofing surface — RFC 8414
lets verifiers look for issuer metadata at
`/.well-known/oauth-authorization-server`, so a WAC-authorized writer (any
share, not only the owner) could otherwise plant a discovery document at the
issuer origin. Server-owned closes that class, and #16
(`/.well-known/solid`) lands in already-reserved space.

Discovery document fields in this slice: `issuer` (the configured base
URL), `jwks_uri` (`{issuer}/.well-known/jwks.json`), `scopes_supported:
["openid", "webid"]` — the Solid-OIDC §10 conformance declaration — and
`id_token_signing_alg_values_supported`, derived from the algorithms in the
key set. `authorization_endpoint` and `token_endpoint` are deliberately
omitted until #58: nothing answers them yet, and the pod's own verifier
reads only `issuer` and `jwks_uri` from a discovery document.

The discovery path hangs off the origin, so the OP requires the pod's base
URL to be an origin root. OP enabled with a base URL that has a path is a
startup error.

## Minting

A new module, the landing zone for the rest of the epic:

```
src/op/
  keys.rs       load or generate the key set, expose the active signer
  discovery.rs  build the discovery document
  mint.rs       mint_access_token(webid, jkt) -> String
```

`mint_access_token` produces exactly what `src/auth/access_token.rs`
verifies: `iss` (the base URL), `sub` and `webid` (the subject's WebID),
`aud: ["solid"]`, `iat`, `exp = iat + 600 s` (fixed, not configurable),
`cnf.jkt` (the caller-supplied DPoP thumbprint), and a random `jti`. There
is no HTTP path to minting; the consumers are #23, #49 and #58, and in this
slice only tests call it.

## Documents and decisions

- **ADR-9** in `docs/decisions.md` withdraws the root spec §4 row
  "Verify-only auth, external IdP" and names what the pod still refuses to
  be: no third-party subjects, no registration for anyone but the owner.
  (Epic #57 says "the next number is ADR-8"; ADR-8 has since been taken by
  the sparql-update PATCH decision, so the withdrawal is ADR-9.)
- `docs/uri-space.md`: the "`/.well-known/` belongs to the origin" section
  is rewritten — the segment is now pod-reserved and server-owned, the
  reverse-proxy note survives only as deployment history, and "the
  reservation is exactly one segment" becomes two.
- `docs/architecture.md`: the auth section and Limits are updated — the pod
  now issues tokens; it is still not an IdP a human can log in to.
- Issue #21 gets a comment rescoping the service WebID document to #23.
- Constraint candidates for `docs/constraints.md`: only `op::keys` reads
  the key file; the JWKS route never serializes a private member.

## Tests

1. Boot with `op_signing_keys` set and no file: the file appears, 0600,
   and the `kid` is identical across a restart.
2. A read-only key file is used and never modified.
3. The discovery document carries `issuer`, `jwks_uri`, and `webid` in
   `scopes_supported`.
4. The JWKS response contains no private key members.
5. Round trip: a minted token authenticates a request against the pod's own
   middleware, with `safe_fetch` pointed at the test server.
6. An expired token and a token bound to the wrong `jkt` answer 401.
7. Writes under `/.well-known/` answer 405 even with the OP disabled.
