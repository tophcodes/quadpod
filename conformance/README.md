# Conformance harness

One command runs the official Solid conformance suite against this pod:

```bash
./conformance/run.sh
```

No arguments, no manual steps, no state carried between runs. Everything it
starts, it stops.

## Current status

The full suite runs and a report lands on disk. The numbers are deliberately not
repeated here: they change with every run, and a copy in a second file is a copy
that goes stale without anyone noticing. Each run is dated and reconciled against
the one before it in
[`docs/conformance-findings.md`](../docs/conformance-findings.md), which is where
the current figures and the triage both live.

## What it starts

| Port | What | Why |
|---|---|---|
| `3001` | Community Solid Server 7.2.0, in Docker | **Identity provider only** |
| `3000` | this pod, built from the working tree | the server under test |
| — | `solidproject/conformance-test-harness`, in Docker | the runner |

**The CSS is scaffolding for the test, not a component of this pod.** This pod
exposes no token endpoint, so nothing here hands the harness a credential and a
conformance run needs *some* Solid-OIDC IdP to mint one.
The CSS is the cheapest one to stand up. Nothing in the pod depends on it,
nothing in the pod talks to it outside a run, and a production deployment
points `--trusted-issuer` at a real IdP instead. It runs in a container with no
volume, so its accounts vanish when the run ends.

Both containers use `--network=host` so that `localhost` means the same thing
to the pod, to the harness and to CSS. That matters more than it looks:
`--allow-insecure-host` matches on the host string as written in the URL, and
the pod's DPoP check compares against `--base-uri` byte for byte, so
`localhost` and `127.0.0.1` are *not* interchangeable anywhere in this setup.

## What you need installed

- **Docker** — for CSS, the harness, and (via the CSS image's Node) for
  running `createCredentials.js`. The two images are pulled on first use.
- **Nix**, for `nix develop -c cargo build`. Bare `cargo` does not work in this
  repo: oxigraph needs bindgen/libclang, which only the flake dev shell
  provides. Set `POD_BIN=/path/to/quadpod` to skip the build.
- **Network access**, twice over: to pull the images, and during the run,
  because the harness resolves `https://solidproject.org/TR/protocol` and
  `.../TR/wac` to discover which requirements the manifests cover.

You do **not** need Node, a Solid account, a public DNS name, or a TLS
certificate.

## What it does

1. Cleans up after any previous run — kills a pod left behind by an
   interrupted run, removes both containers, wipes `.run/` and `reports/`,
   then checks both ports are actually free and stops with a clear message if
   not.
2. Builds the pod.
3. Starts CSS and waits for it to answer.
4. Extracts `createCredentials.js` from the *harness* image (it ships in
   `solid-contrib/specification-tests`, which the image bundles under `/data`)
   and runs it against CSS. That registers alice and bob, creates their pods,
   and prints client credentials. It runs both users concurrently, so the
   runner reads its output by key, never by line.
5. Writes `.run/harness.env` and `.run/test-subjects.ttl` — see
   [`harness.env.example`](harness.env.example) for what each key means.
6. Starts the pod with `--owner-webid` set to alice, `--trusted-issuer` and
   `--allow-insecure-host` naming the CSS.
   **No ACL is written anywhere**: the pod provisions its own root ACL for the
   owner at boot. The suite's CSS script `PUT`s `<root>/.acl`, which here would
   be an ordinary resource write that silently achieves nothing — ACLs live in
   the reserved `/.aux/` namespace, as `/.aux/{path}.acl` (`/foo` → `/.aux/foo.acl`,
   `/box/` → `/.aux/box/.acl`, the root → `/.aux/.acl`), and are found through
   the `Link` header.
7. Runs the harness against the `protocol` and `web-access-control` manifests
   — the two the harness's own `application.yaml` links by default. The
   `sparql-update` manifest stays off; it is commented out upstream, and this
   pod refuses `application/sparql-update` by design ([ADR-8](../docs/decisions.md#adr-8))
   — `PATCH` here is N3 Patch.
8. Stops everything.

Cleanup between runs is a **pod restart**. The store is in-memory
(`OxigraphStore::in_memory()`), so every run starts from an empty pod — better
isolation than the upstream scripts get, and why the runner needs no teardown
logic on the pod side at all.

## Where the report lands

```
conformance/reports/report.html    the human-readable report
conformance/reports/report.ttl     the same results as EARL, for diffing
conformance/.run/harness.log       everything the harness printed
conformance/.run/karate/           karate's own summary, incl. karate-summary-json.txt
conformance/.run/pod.log           the pod's own log for the run
conformance/.run/css.log           the IdP's log
```

`karate-summary-json.txt` carries the per-feature pass/fail counts as JSON,
which is a far quicker way to diff two runs than the 10 MB HTML.

`/app/target` inside the harness container is bind-mounted to
`conformance/.run/karate` for a reason worth knowing before you touch the
docker invocation: karate writes its intermediate JSON to a **relative**
`target/karate-reports/`, resolved against the container's working directory.
That directory is `/app`, owned by uid 185, so under `--user $(id -u)` the
write fails and the harness dies in `Results.of()` *before rendering the
report* — the symptom is a stack trace and an empty `reports/`. The working
directory cannot simply be moved either: the harness reads
`config/application.yaml` relative to it too, and a `-w` elsewhere trades this
failure for `Missing mandatory option: 'subjects'`.

`reports/` and `.run/` are both wiped at the start of every run and both are
git-ignored. `.run/harness.env` holds live client credentials for the run's
lifetime; it is written `0600` inside a `0700` directory.

## How to read it

Open `report.html`. It lists every test case with its scenarios, and each
scenario's requests and responses — enough to reproduce a failure with `curl`
without re-running the suite.

Three things to know before drawing conclusions from it:

- **The exit code is the harness's.** It is non-zero while any scenario fails.
  A report on disk is the deliverable; a green report is not the bar yet.
- **A failed scenario and an aborted feature are different.** Several features
  build their fixtures in a `callonce` `Background`; if that setup request
  fails, the whole feature errors out at once rather than failing row by row.
  A `text/plain` fixture used to do this — before Plan 10, the pod answered
  `415` to any non-RDF media type, which took out all six WAC
  `protected-operation` features before their assertions ran. It no longer
  does; `text/plain` and any other non-RDF type now store as a blob.
- **Some failures are decisions, not defects.** `post-target-not-found`
  expects `404` where this pod deliberately materialises missing ancestors
  and answers `201`; `DELETE` of a resource the suite reserved a name for but
  never created expects `403` where this pod, having authorized the request,
  finds nothing there and answers `404`. Triage lives in
  `docs/conformance-findings.md`, not here.

## Knobs

All optional, all environment variables:

| Variable | Default | For |
|---|---|---|
| `POD_BIN` | built from source | skip the `nix develop` build |
| `CSS_PORT` / `POD_PORT` | `3001` / `3000` | when something else owns a port |
| `KEEP_RUNNING=1` | off | leave CSS and the pod up to poke at by hand; the next run stops them |
| `REPORT_DIR` | `conformance/reports` | write the report elsewhere |
| `HARNESS_IMAGE` / `CSS_IMAGE` | see the script | pin a different version |

## Versions

The harness image bundles both the runner and the tests, so one pull pins
both. As of writing: harness **1.2.2**, tests **v0.0.19 (2024-03-21)**, 41 test
cases across the two manifests. `run.sh` records the pod's commit in
`test-subjects.ttl` so a report always says which build produced it.
