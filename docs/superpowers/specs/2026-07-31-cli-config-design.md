# Persistent Store and a Config File — Design

**Date:** 2026-07-31
**Status:** Proposed (pre-implementation)
**Author:** Christopher Mühl (with Claude)
**Parent spec:** [2026-07-24-sparql-solid-pod-design.md](2026-07-24-sparql-solid-pod-design.md) §4, §10
**Origin:** the pod has no way to keep anything across a restart, and no way to be configured
except by flags and environment variables. This adds an on-disk store and a TOML file, and
corrects the root spec's reason for preferring a remote store.

## 1. What is missing today

`src/main.rs` builds the store with `OxigraphStore::in_memory().expect("store")`. There is no
flag, no environment variable and no code path that produces any other backend. Every restart
is a fresh, empty pod. `--blob-store local:<dir>` already exists, so blobs can outlive a
restart while the triples describing them cannot — the pod is *less* uniform today than the
doc comment on `--blob-store` claims it is trying to be.

Configuration is flags plus `POD_*` environment variables. That is enough for a conformance
run and for `sparql-pod --owner-webid … --trusted-issuer …` on a laptop. It is thin for a
deployment whose full invocation is a dozen arguments, some of which (an issuer allowlist, an
insecure-host list) are lists that read badly as comma-separated environment values.

## 2. The root spec's reason for a remote store no longer holds

§4 justifies the store choice with: *"Oxigraph default, behind a `SparqlStore` trait … HTTP
endpoint (not embedded) keeps multi-writer (Windmill pipelines) and avoids the single-writer
RocksDB constraint."*

That rationale rests on a premise the same document denies. §3 Non-Goals: *"No SPARQL UPDATE
write path (writes go through LDP, which already enforces WAC+SHACL)."* If every write goes
through LDP, the store has exactly one legitimate writer — this process. Windmill is an HTTP
client, not a second writer.

The gap is not merely formal. The store is not a bag of triples that a second process could
append to harmlessly:

- `resource.rs` writes presence markers into `urn:quadpod:sys:` graphs, which is what makes
  existence a stored fact rather than a triple count.
- `shelf.rs` mints subgraph IRIs with a `0x00` separator; two writers deriving that string
  independently is how two resources come to share one shelf.
- Containment triples, ETags, WAC evaluation and SHACL validation all hang off the same
  writes.
- ADR-2 obliges an implementor to make a `;`-separated update sequence atomic, and every
  write path depends on it.

A second process issuing raw SPARQL UPDATE bypasses all of it. That is not a multi-writer
capability; it is corruption with extra steps. §4 buys a property §3 forbids.

`2026-07-30-rdf12-design.md` §8 already recorded the divergence — *"The multi-writer rationale
is therefore currently unmet — a pre-existing divergence, out of scope here"* — and rewrote the
deployment matrix to two implementors: embedded Oxigraph as the recommended default, and one
generic client for any external SPARQL 1.1 endpoint. This design finishes that correction; the
record is **root spec §16 ADR-7**, and §8 lists what it changes.

### 2.1 What the single-writer constraint actually costs

Stated precisely, because the root spec's phrasing invites the wrong reading. Oxigraph's
on-disk backend permits one read-write `Store` at a time (`oxigraph-0.5.9/src/store.rs:177`).
That is a statement about *processes*, not threads: within this process any number of Tokio
tasks write concurrently. `Store::open_read_only` exists (`:208`) but is not a live-replica
mechanism — *"Opening as read-only while having an other process writing the database is
undefined behavior"* — and 0.5.9 has no secondary-instance API.

Multi-tenancy does not collide with this. Root spec §9 runs many spaces in **one** process:
the template matches an incoming URL, yields a `StorageSpace`, and all spaces live as named
graphs in the same store. One process, one directory.

The constraint binds only when several pod *processes* must see one dataset — horizontal
scale or HA. Three ways out, none needed now and none in scope here: a pod process per space
with its own directory (the natural fit for the subdomain topology of §9 caveat 2); a
separately deployed Oxigraph server reached over SPARQL 1.1 (which does not remove the
single-writer — it moves it behind a socket and makes it *shared*, which is the actual gain);
or one directory per space inside one process, which helps blast radius and backup
granularity but not availability.

## 3. `--rdf-store`

A spec string, shaped exactly like `--blob-store`:

| Value | Backend |
|---|---|
| `memory` (default) | `OxigraphStore::in_memory()` — unchanged behaviour |
| `rocksdb:<dir>` | `OxigraphStore::open(<dir>)`, wrapping `oxigraph::store::Store::open` |
| anything else | refuse to start, exit 2 |

`Config::rdf_store() -> Result<Arc<dyn SparqlStore>, String>` mirrors `Config::blobs()` term
for term, and `main.rs` consumes it with the same match-and-exit-2 shape as the blob backend
beside it. Refusing an unknown spec rather than falling back is the rule the existing
`blobs()` states: a pod that starts with a backend other than the one configured is
indistinguishable from one configured correctly, and the difference is discovered only when
data is missing.

`memory` stays the default. The alternative — requiring a directory on every start — would
break the conformance harness and every ad-hoc invocation in the docs for the benefit of a
deployment that can pass one flag.

### 3.1 This costs nothing to build

Oxigraph's `rocksdb` feature is on by default (`oxigraph-0.5.9/Cargo.toml`), `oxrocksdb-sys`
is already in `Cargo.lock`, and `flake.nix` already provides `clang`, `libclang` and
`LIBCLANG_PATH`. `Store::open` is callable from this tree today. No new dependency, no new
build requirement, no change to the dev shell.

### 3.2 Naming

**The flag is `--rdf-store`, not `--store`.** `blob_store` says what it holds; a bare `store`
says only that it is one, which asks an operator to know that "the store" is the RDF one by
convention. The two flags now read as a pair, and the `Config` field and method are
`rdf_store` throughout — including on `FileConfig`, which takes its key names from `Config`.

`rocksdb:` names the storage engine, not the product: `memory` and `rocksdb` are both
Oxigraph, so `oxigraph:<dir>` would not distinguish them. Should a second embeddable quad
store ever appear, its spec string names its engine too, and the prefix stays honest.

`AppState`'s field stays `store` — there is only one there, and nothing to distinguish it
from.

## 4. The config file

`--config <path>` / `POD_CONFIG`. **No default search path.** Nothing is loaded implicitly:
a pod must not be able to start against a file that no one reading the command line can see.
A path that is given but unreadable, or is not valid TOML, is exit 2 — never a silent fallback
to flags alone.

Flat TOML whose keys are the `Config` struct's own field names. No second vocabulary to keep
in sync with the flags:

```toml
base_uri     = "https://pod.toph.so/"
owner_webid  = "https://toph.so/profile/card#me"
rdf_store    = "rocksdb:/var/lib/sparql-pod/store"
blob_store   = "local:/var/lib/sparql-pod/blobs"
listen       = "127.0.0.1:3000"

trusted_issuers       = ["https://idp.toph.so/"]
expected_audience     = "https://pod.toph.so/"
allow_insecure_hosts  = []
reset_root_acl        = false
max_body_bytes        = 67108864
```

Lists are TOML arrays, which is the whole reason a file helps: `trusted_issuers` as an array
has no comma-splitting, no trimming and no empty-entry problem, so the defensive parsing that
`auth_config()` and `try_fetch_policy()` perform on the environment form is simply not
exercised. That parsing stays exactly as it is — it still guards the environment path.

### 4.1 An unknown key refuses the start

`#[serde(deny_unknown_fields)]`. The rule is the one `--allow-insecure-host` already follows:
rather run nothing than run with less configuration than the operator wrote. A typo like
`owner_web_id` is otherwise a pod that starts and then fails every authenticated request, with
nothing in the log to grep for.

The cost is real and accepted: rolling a binary *back* while a newer file is in place fails to
start. That is the same failure a removed flag produces, and it is loud.

### 4.2 Dependencies

`serde` (with `derive`) and `toml` become direct dependencies. Both, and `serde_derive`, are
already in `Cargo.lock` transitively, so nothing new compiles.

`toml` is pinned to `0.9` for exactly that reason: `rudof_lib` already pulls in 0.9.12, and
`cargo add toml` would otherwise take 1.1, putting two majors of a TOML parser in one binary
to no end. The pin is what makes the sentence above true rather than nearly true.

## 5. Precedence, without hand-written precedence

**Flag > environment > file > default.**

The mechanism is chosen to preserve the invariant `config.rs`'s module header states: *"clap
provides the precedence (flag > env > default); there is deliberately no hand-written
precedence logic on top of it."*

Two passes:

1. A minimal pre-parser — a `Command` carrying only `--config`, with `ignore_errors` set —
   extracts the path from the argv and `POD_CONFIG`. It must tolerate every other argument,
   including a missing required `--owner-webid`, because it runs before the real parse.
2. The file is read and deserialized. The real `Command` is then built with
   `.default_value(…)` set for every key the file supplied. clap applies its own precedence,
   and the file lands exactly one rung below the environment because that is where a default
   sits.

No merge function, no per-field arm, nothing to forget when a flag is added later: a new field
picks up file support from the same table that gives it its flag.

### 5.1 The cost, named

A malformed value from the file surfaces as a clap error phrased in terms of the flag —
`invalid value 'nope' for '--listen'` — when no `--listen` was typed. Left alone, that
misdirects an operator into checking a command line that is correct.

So the error is rewritten before it is printed: `clap::Error::get(ContextKind::InvalidArg)`
names the argument, and the set of keys the file supplied is known from pass 2, so an error
whose argument is in that set gets the config path and the TOML key prefixed onto it. An error
about an argument the file did not supply is left exactly as clap phrased it.

`ArgMatches::value_source()` was the alternative: parse normally, then overwrite every field
whose source is `DefaultValue` from the file. Simpler mechanically, and rejected because it
requires one merge arm per field — precisely the hand-written precedence the module says it
does not have — and each future flag must remember to add one, with nothing to catch the
omission but a missing test.

### 5.2 A file value satisfies a required argument

`--owner-webid` is required. Once the file supplies it, clap sees an argument with a default
and treats it as present, so the requirement is met without special-casing — the order in
`clap_builder-4.6.0/src/parser/parser.rs` is `add_env`, then `add_defaults`, then
`Validator::validate`. A file that omits it, with no flag and no environment variable, still
fails with clap's own missing-argument error.

The same ordering is what makes the pre-parser of step 1 work: its `ignore_errors` path also
runs `add_env`, so `POD_CONFIG` is still seen when the partial parse fails — which it always
does, since the pre-parser knows none of the real arguments.

### 5.3 Validation belongs in the parser, not after it

§5.1 can only re-point errors clap produced. That leaves a hole the first draft of this design
missed: `base_uri` and `owner_webid` were plain `String` to clap and were checked afterwards
in `main.rs`, so a bad value from the file produced `invalid --owner-webid: must be an
absolute IRI` — naming a flag nobody typed, with no way to reach the file, because by then the
error is a printed string rather than a `clap::Error`.

So both become `value_parser`s, and the fields hold the checked types:

| Field | Type | Parser |
|---|---|---|
| `base_uri` | `StorageSpace` | `parse_space` — `StorageSpace::new` |
| `owner_webid` | `NamedNode` | `parse_owner_webid` — `NamedNode::new` |

The validation is the same validation; it moves, it does not change. `Config::space()` and
`Config::validated_owner_webid()` are retired, because a `Config` that exists now *has* a
usable base URI and a checked owner IRI — there is nothing left for a later caller to ask.
Two of `main.rs`'s `exit(2)` blocks go with them.

The typing is load-bearing beyond error messages: `provision_root_acl` interpolates the owner
WebID into Turtle, and `NamedNode` is what stops an unchecked string from reaching that call
at all. The old comment there — *"Validated because it is interpolated into Turtle below"* —
becomes a property of the type rather than a note asking the next reader to keep it true.

**What is deliberately not moved.** `allow_insecure_hosts` keeps its own two-stage treatment:
it reports every entry it could not understand, with a per-entry hint, which a `value_parser`
returning one error cannot do. `rdf_store` and `blob_store` keep theirs too — those build a
backend, which is a resource to acquire, not a string to check, and acquiring RocksDB's
exclusive lock inside argument parsing would put a side effect somewhere nobody expects one.
Errors from all three still name a flag rather than the file; that is the residual limit of
§5.1, and it is bounded to three fields whose values are paths and hostnames rather than the
IRIs most likely to be mistyped.

`trusted_issuers` and `expected_audience` are checked nowhere at all, before this design and
after it. Out of scope, tracked as issue #24.

## 6. What this design does not do

- **No remote SPARQL 1.1 client.** The seam stays open — `SparqlStore` is already
  `dyn`-dispatched (ADR-2) — and the implementor is not written here. It is the only way to
  serve one dataset from several pod processes, and nothing today needs that.
- **No transaction seam.** `check_conditionals` (`src/http.rs:931`) reads current ETags and
  the write follows in a separate store call, so `If-Match` cannot actually prevent a lost
  update. That defect exists today with the in-memory store and is neither created nor closed
  by this design; adding a transaction to `SparqlStore` would reopen the backend-pluggability
  question ADR-2 settled, which deserves its own decision. Tracked as issue #10.
- **No multi-user filesystem mapping.** How several users' resources map onto one directory
  tree is a multi-tenancy question (root spec §9), deferred with the registry it needs. v1 is
  one space, and the blob layout mirrors the URL tree as root spec §3.2 already specifies.
- **No change to `--blob-store`.** It works and its spelling is the model this design copies.
- **No subcommands.** `sparql-pod [flags]` still starts the server, so `docs/deployment.md`
  and the conformance harness stay valid.

## 7. Testing

- `rdf_store()` selects a backend and refuses an unknown one — the mirror of the existing
  `blob_store_selects_a_backend_and_refuses_an_unknown_one`, including a rejected
  `http://…` spec so the unimplemented-backend case is pinned rather than assumed.
- The existing `non_iri_owner_webid_is_rejected` moves from "parses, then fails validation"
  to "fails to parse". That is the whole of §5.3 in one assertion, and it is where a
  regression to a post-parse check would show up first.
- **Persistence round trip:** write through the store, drop it, reopen the same directory,
  read the data back. This is the property the flag exists for; a test that only asserts
  `open` returns `Ok` would pass against a backend that persisted nothing.
- Precedence, one test per rung: file alone supplies a value; environment beats file; flag
  beats both; a default survives an empty file.
- An unknown key is refused; an unreadable path is refused; malformed TOML is refused — each
  as an error, not a fallback.
- A file supplying `owner_webid` parses with no flag present (§5.2).
- A file-sourced invalid value produces an error naming the config path, not only the flag
  (§5.1) — the test that keeps the message from silently reverting to clap's phrasing.

All of it runs through the `try_parse_from` harness already in `config.rs`'s test module,
which is why the file path has to be injectable rather than read from a fixed location.

## 8. Deltas against documents already in force

**Root spec §4, the Oxigraph row.** Its parenthetical rationale — *"HTTP endpoint (not
embedded) keeps multi-writer (Windmill pipelines) and avoids the single-writer RocksDB
constraint"* — is withdrawn. Replaced by: embedded Oxigraph is the default and the recommended
deployment; an external SPARQL 1.1 endpoint remains a supported configuration behind the same
trait, for the case where several pod processes must share one dataset. See §16 ADR-7.

**`Config::space()` and `Config::validated_owner_webid()` are retired**, together with the two
`main.rs` `exit(2)` blocks that consumed them (§5.3). Their validation is unchanged and now
lives in `parse_space` and `parse_owner_webid`. `main.rs` also drops its `clap::Parser` import,
since `Config::load` replaces `Config::parse`.

**Root spec §10, Deployment.** Gains the on-disk store: the pod now owns a state directory,
which is a backup and a restore concern, and only one process may hold it.

**`docs/deployment.md`.** Gains a section covering `--rdf-store`, the config file, precedence, and
the single-process constraint on a `rocksdb:` directory.

**`docs/constraints.md:110`, the `SparqlStore` one-implementor tripwire, is untouched.** This
design adds a constructor to `OxigraphStore`, not a second implementor, and §6 declines to
write the remote client precisely because that rule says a second implementor must reopen
ADR-2's atomicity decision.

**`docs/constraints.md` gains nothing yet.** Two candidate rules exist, and that file requires a
rule to have been *demonstrated red* against a real violation before it is written down —
which can only happen during implementation:

1. *The config file has no default search path* — guards §4 of this design against a later
   convenience commit that adds one. Shape: no literal config filename anywhere in `src/`.
2. *Precedence is clap's, not hand-written* — pins mechanism (A) of §5 against drift to (B).
   Shape: `value_source` does not appear in `src/config.rs`.

The implementation plan carries the obligation to demonstrate each red first, or to drop it.
A check that cannot fail is worse than none — this repo has already shipped one.

**`2026-07-30-rdf12-design.md` §8** is confirmed, not changed: it named this divergence and
declined to fix it. This is the fix.

**The record itself lives in the root spec, not here.** §16 says why: decisions that correct
that document are recorded in it, *"rather than in a separate decision directory because this
is the document they correct — a second home would give the contradiction a third place to
live."* So the withdrawal is written as **ADR-7 in root spec §16**, and this section only
points at it. The reasoning above (§2, §2.1) is the working-out; the ADR is the record.
