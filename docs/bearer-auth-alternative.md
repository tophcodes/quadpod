# Accepting bearer tokens alongside DPoP

Status: wanted, not designed. Recorded so the trade-off is not re-derived later.

## What is being asked for

The pod currently requires proof-of-possession: a token is bound to a key, and
every request carries a fresh signed proof over the method and target URI. The
request is to also accept a plain bearer token, as an alternative rather than a
replacement.

## What that gives up

DPoP exists so that a stolen token is not enough. Possession of the token
without the private key buys nothing, which matters when a token can leak
through a log, a proxy, a browser, or an intermediary that sees headers.

A bearer token is exactly the opposite premise: whoever holds it is the client.
Adding it does not weaken DPoP for anyone still using DPoP, but it does mean the
pod can no longer state a single property about how its clients authenticate.

## When the trade is honest

For a server-side daemon on a machine the pod's owner controls, reached over a
private network, the attacker who can read the token can generally also read the
key file next to it. The proof adds ceremony without changing the threat model,
and it adds a dependency on clock skew and on the client implementing a signing
flow correctly, which is where real integrations break.

For anything reached from a browser, from third-party code, or across a network
the owner does not control, the trade is not honest and DPoP should stay
mandatory.

## What must hold if it is added

- **Opt-in per deployment, never the default.** A pod that has not been told to
  accept bearer tokens must reject them, so the weaker mode is always a decision
  somebody made rather than a state something drifted into.
- **Identity is unaffected.** This is only about proof of possession. A bearer
  token still has to be issued by a trusted issuer and still has to carry the
  identity the request acts as; nothing about who may read what changes.
- **Short lifetimes, because replay defence disappears.** DPoP has per-request
  replay protection through a proof identifier. A bearer token has none, so a
  captured token is valid for its whole remaining life against every replica.
  Lifetime is the only remaining control, which makes it a security parameter
  rather than a convenience one.
- **Visible in logs and in any audit trail.** Which mode authenticated a request
  is part of what happened, and a later question about a write should not need
  the deployment's configuration history to answer.

## Related

The replay store discussed under replication is per-process today. Bearer
acceptance interacts with that: it removes the only mechanism that store
protects, for the requests that use it.
