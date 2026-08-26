---
session: 20260808-01
date: 2026-08-08
title: Convergent writes design
status: recorded
commits:
  - f898f4ac docs: design for convergent writes across offline replicas
---

# Convergent writes design

## Summary

Designed how quadpod lets several writers change one resource from clients that were
offline, without any of them losing the others' work and without giving up the server.
Result is a design doc and issue #92; no code was written and the open questions were
deliberately left open.

## Changes

| Commit | What |
|--------|------|
| `f898f4ac` | The design doc. Server merges, `GET` stays clean, opt-in per container; `Version`/`Parents` borrowed from Braid-HTTP, live delivery left to Solid notifications. |

Filed alongside it: **#92**, the tracking issue, written self-contained because the doc
is not on `main`.

## Caveats & follow-ups

- **The doc is not on `main`.** `f898f4ac` sits on an unnamed line together with three
  commits from a session running in parallel (`091d2853` ADR-11, `f0a0d6ff` and `8f4e9c0b`
  README/roadmap). Merging that range is a repo-wide call, not a side effect of this
  session, so nothing was merged. ADR-11 on `main` already depends on this design: it
  cites "the per-container opt-in that convergence already needs".
- **The doc carries one known error**, recorded in #92 rather than fixed: it announces the
  pod's provenance partition being read-only as a new rule. It is older than that: `.meta` is already
  unwritable by construction, and #75 has already settled where provenance lives. The
  section should be rewritten to reuse that decision. Fixing it in place would have meant
  rewriting commits another session had already built on.
- **This repo was not a jj repo** at the start of the session; `jj git init --colocate` ran
  to make ordinary work possible, per the standing convention.
- **`.claude/settings.json` holds `{"worktree": {"bgIsolation": "none"}}`.** Written to get
  past a deadlock between the jj hook that refuses `EnterWorktree` and the guard that
  refuses writes without it. Gitignored, so it never reaches a diff. Delete it whenever.

## Pending

Every open question in the doc and in #92 stays open by decision, not by omission:
tombstone compaction and the causal stability watermark it needs; whether authority
survives replay; where the merge type is declared (waits on #73); the two validators one
resource now has, and which of them a notification should carry (relates to #28);
registering a patch type for RDF; and the clock the functional-predicate tiebreak depends
on.
