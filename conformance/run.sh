#!/usr/bin/env bash
#
# One-command Solid conformance run against this pod.
#
# What it does, in order:
#   1. tears down anything a previous run left behind (containers, pod process)
#   2. starts a Community Solid Server in Docker — as an *identity provider only*
#   3. registers alice and bob there and mints client credentials for them
#   4. writes the harness environment file from those credentials
#   5. builds and starts this pod, pointed at that CSS as its trusted issuer
#   6. runs the official conformance-test-harness image (protocol +
#      web-access-control manifests) against the pod
#   7. stops everything, leaving the report on disk
#
# The CSS exists for the duration of the run and nothing in the pod depends on
# it: the pod is verify-only and never issues a token. See ./README.md.
#
# Exit code is the harness's own: non-zero while any scenario fails. A report
# is written either way — that is the deliverable, not a green run.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

# --- knobs (all overridable from the environment) ---------------------------
CSS_IMAGE="${CSS_IMAGE:-solidproject/community-server:7.2.0}"
HARNESS_IMAGE="${HARNESS_IMAGE:-solidproject/conformance-test-harness:latest}"
CSS_PORT="${CSS_PORT:-3001}"
POD_PORT="${POD_PORT:-3000}"
RUN_DIR="${RUN_DIR:-$HERE/.run}"
REPORT_DIR="${REPORT_DIR:-$HERE/reports}"
POD_BIN="${POD_BIN:-}"
KEEP_RUNNING="${KEEP_RUNNING:-0}"

CSS_CONTAINER="sparql-pod-conformance-idp"
HARNESS_CONTAINER="sparql-pod-conformance-harness"

# The host string matters twice over and must be spelled the same way in both
# places: `--allow-insecure-host` matches on the host as written in the URL
# (so `localhost:3001`, never `127.0.0.1:3001`), and every DPoP `htu` the pod
# checks is derived from `--base-uri`, which must be byte-identical to the
# origin the harness dials.
CSS_BASE="http://localhost:${CSS_PORT}/"
POD_BASE="http://localhost:${POD_PORT}/"
ALICE_WEBID="${CSS_BASE}alice/profile/card#me"
BOB_WEBID="${CSS_BASE}bob/profile/card#me"

# The test-subject IRI is an identifier, not a location: it only has to match
# the `--target` we pass. The `solid/conformance-test-harness/` prefix is the
# convention the shipped test-subjects.ttl uses.
TARGET_IRI="https://github.com/solid/conformance-test-harness/sparql-pod"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*" >&2; }
note() { printf '    %s\n' "$*" >&2; }
die() { printf '\n\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- teardown ---------------------------------------------------------------

stop_pod() {
    local pid_file="$RUN_DIR/pod.pid" pid
    [[ -f "$pid_file" ]] || return 0
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    rm -f "$pid_file"
    [[ -n "$pid" ]] || return 0
    kill -0 "$pid" 2>/dev/null || return 0
    note "stopping pod (pid $pid)"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -9 "$pid" 2>/dev/null || true
}

stop_containers() {
    local name
    for name in "$HARNESS_CONTAINER" "$CSS_CONTAINER"; do
        if docker container inspect "$name" >/dev/null 2>&1; then
            note "removing container $name"
            docker rm -f "$name" >/dev/null 2>&1 || true
        fi
    done
}

teardown() {
    local code=$?
    trap - EXIT INT TERM
    if [[ "$KEEP_RUNNING" == "1" ]]; then
        log "KEEP_RUNNING=1 — leaving CSS on :$CSS_PORT and the pod on :$POD_PORT up"
        note "the next run of this script will stop them for you"
        exit "$code"
    fi
    log "Tearing down"
    if docker container inspect "$CSS_CONTAINER" >/dev/null 2>&1; then
        docker logs "$CSS_CONTAINER" >"$RUN_DIR/css.log" 2>&1 || true
    fi
    stop_pod
    stop_containers
    exit "$code"
}

# --- preflight --------------------------------------------------------------

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH$2"
}

port_is_free() {
    # Bash's own TCP client — no ss/lsof/netstat dependency.
    ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

require_port() {
    local port="$1" what="$2"
    port_is_free "$port" && return 0
    die "port $port is already in use, and the $what needs it.
       Nothing this script started is listening there (its own leftovers were
       just cleaned up), so something else on this machine owns it. Free it, or
       re-run with ${3}=<other port>."
}

wait_for_http() {
    # Ready = the port answers HTTP at all. The pod answers 401 to an
    # anonymous GET of its root, which is a perfectly good sign of life.
    local url="$1" what="$2" deadline=$((SECONDS + ${3:-120})) code
    while ((SECONDS < deadline)); do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" || true)"
        if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
            note "$what is up ($url -> HTTP $code)"
            return 0
        fi
        sleep 1
    done
    die "$what did not become ready at $url within ${3:-120}s. See $RUN_DIR/*.log"
}

# --- steps ------------------------------------------------------------------

build_pod() {
    if [[ -n "$POD_BIN" ]]; then
        [[ -x "$POD_BIN" ]] || die "POD_BIN=$POD_BIN is not executable"
        note "using POD_BIN=$POD_BIN"
        return
    fi
    log "Building the pod (nix develop -c cargo build)"
    # Bare cargo does not work in this repo: oxigraph needs bindgen/libclang,
    # which only the flake dev shell provides.
    (cd "$REPO" && nix develop -c cargo build) || die "pod build failed"
    POD_BIN="$REPO/target/debug/sparql-pod"
    [[ -x "$POD_BIN" ]] || die "expected a binary at $POD_BIN after the build"
}

start_css() {
    log "Starting the identity provider (CSS $CSS_IMAGE) on :$CSS_PORT"
    # No volume and no --rm: the writable layer is thrown away with the
    # container at teardown, so every run gets a virgin CSS with no accounts.
    # Host networking so that `localhost` means the same thing to the pod, to
    # the harness container and to CSS itself.
    docker run -d --name "$CSS_CONTAINER" --network=host "$CSS_IMAGE" \
        -c @css:config/default.json \
        --port "$CSS_PORT" \
        --baseUrl "$CSS_BASE" \
        --rootFilePath /tmp/css-data \
        --loggingLevel warn >/dev/null || die "could not start CSS"
    wait_for_http "$CSS_BASE" "CSS" 180
}

mint_credentials() {
    log "Registering alice and bob and minting client credentials"
    # Use the harness image's own copy of the script rather than a checked-in
    # or downloaded one, so it can never drift from the harness that consumes
    # its output. (It lives in solid-contrib/specification-tests, whose
    # contents the harness image bundles under /data.)
    docker run --rm --entrypoint cat "$HARNESS_IMAGE" /data/createCredentials.js \
        >"$RUN_DIR/createCredentials.js" ||
        die "could not extract createCredentials.js from $HARNESS_IMAGE"

    # Run it with the CSS image's Node, so the host needs no Node at all.
    docker run --rm --network=host \
        -v "$RUN_DIR/createCredentials.js:/createCredentials.js:ro" \
        --entrypoint node "$CSS_IMAGE" /createCredentials.js "$CSS_BASE" \
        >"$RUN_DIR/credentials.env" || die "createCredentials.js failed"

    # It runs both users concurrently, so the output order is not stable:
    # always read by key, never by line.
    local key
    for key in USERS_ALICE_CLIENTID USERS_ALICE_CLIENTSECRET \
        USERS_BOB_CLIENTID USERS_BOB_CLIENTSECRET; do
        grep -qE "^$key=.+" "$RUN_DIR/credentials.env" ||
            die "createCredentials.js did not print $key. Output:
$(cat "$RUN_DIR/credentials.env")"
    done
    note "got client credentials for alice and bob"
}

write_harness_config() {
    log "Writing the harness configuration"
    {
        echo "SOLID_IDENTITY_PROVIDER=$CSS_BASE"
        echo "USERS_ALICE_WEBID=$ALICE_WEBID"
        echo "USERS_BOB_WEBID=$BOB_WEBID"
        # TEST_CONTAINER must be an *absolute* URL: an absolute value makes
        # the harness skip findStorage(), which would otherwise demand
        # pim:storage in the WebID document and a rel="type" pim:Storage link
        # on the pod root — neither of which exists here.
        echo "TEST_CONTAINER=$POD_BASE"
        grep -E '^USERS_(ALICE|BOB)_CLIENT(ID|SECRET)=' "$RUN_DIR/credentials.env"
    } >"$RUN_DIR/harness.env"
    chmod 600 "$RUN_DIR/harness.env"

    cat >"$RUN_DIR/test-subjects.ttl" <<TTL
@prefix solid-test: <https://github.com/solid/conformance-test-harness/vocab#> .
@prefix doap: <http://usefulinc.com/ns/doap#> .
@prefix earl: <http://www.w3.org/ns/earl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<$TARGET_IRI>
    a earl:Software, earl:TestSubject ;
    doap:name "sparql-pod"@en ;
    doap:release <${TARGET_IRI}#release> ;
    doap:developer <https://github.com/tophcodes> ;
    doap:homepage <https://github.com/tophcodes/sparql-pod> ;
    doap:description "A SPARQL-authoritative, verify-only Solid pod."@en ;
    doap:programming-language "Rust"@en ;
    solid-test:skip "acp" .

<${TARGET_IRI}#release>
    doap:revision "$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo unknown)" ;
    doap:created "$(date -u +%Y-%m-%d)"^^xsd:date .
TTL
}

start_pod() {
    log "Starting the pod on :$POD_PORT"
    # No ACL bootstrap: the pod provisions its root ACL for --owner-webid at
    # boot. Writing <root>/.acl the way the suite's CSS script does would be an
    # ordinary resource write here and would achieve nothing.
    #
    # --allow-insecure-host names the CSS by the host string that appears in
    # the three URLs the pod fetches (discovery, JWKS, alice's profile), all of
    # which say `localhost`. --trusted-issuer rejects any other issuer before a
    # fetch is even attempted.
    "$POD_BIN" \
        --base-uri "$POD_BASE" \
        --listen "127.0.0.1:$POD_PORT" \
        --owner-webid "$ALICE_WEBID" \
        --trusted-issuer "$CSS_BASE" \
        --allow-insecure-host "localhost:$CSS_PORT" \
        >"$RUN_DIR/pod.log" 2>&1 &
    echo $! >"$RUN_DIR/pod.pid"
    wait_for_http "$POD_BASE" "pod" 60
}

run_harness() {
    log "Running the conformance harness (protocol + web-access-control)"
    mkdir -p "$REPORT_DIR"
    # --user: the image runs as uid 185; without this the report lands
    # root-owned or not at all.
    # --network=host: the harness must reach both localhost:3000 (pod) and
    # localhost:3001 (token endpoint, JWKS, WebID documents).
    # The bundled /data/test-subjects.ttl is replaced with ours; everything
    # else in /data — the manifests and the .feature files — is the image's.
    set +e
    docker run -i --rm --name "$HARNESS_CONTAINER" \
        --network=host \
        --user "$(id -u):$(id -g)" \
        --env-file "$RUN_DIR/harness.env" \
        -v "$REPORT_DIR:/reports" \
        -v "$RUN_DIR/test-subjects.ttl:/data/test-subjects.ttl:ro" \
        "$HARNESS_IMAGE" \
        --output=/reports \
        --target="$TARGET_IRI" \
        2>&1 | tee "$RUN_DIR/harness.log"
    # `tee` is last in the pipeline and always succeeds, so read the harness's
    # own status out of PIPESTATUS — and read it *here*, before any other
    # command runs, because the next command overwrites it.
    local rc=${PIPESTATUS[0]}
    set -e
    return "$rc"
}

# --- main -------------------------------------------------------------------

require_cmd docker ""
require_cmd curl ""
[[ -n "$POD_BIN" ]] || require_cmd nix " (needed for 'nix develop -c cargo build'; \
set POD_BIN=/path/to/sparql-pod to skip the build)"

mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"

log "Cleaning up after any previous run"
stop_pod
stop_containers
rm -rf "$REPORT_DIR"
rm -f "$RUN_DIR"/*.log "$RUN_DIR"/*.env "$RUN_DIR"/test-subjects.ttl \
    "$RUN_DIR"/createCredentials.js
require_port "$CSS_PORT" "identity provider" CSS_PORT
require_port "$POD_PORT" "pod" POD_PORT

trap teardown EXIT INT TERM

build_pod
start_css
mint_credentials
write_harness_config
start_pod

HARNESS_RC=0
run_harness || HARNESS_RC=$?

if [[ -f "$REPORT_DIR/report.html" ]]; then
    log "Report: $REPORT_DIR/report.html"
    note "machine-readable EARL: $REPORT_DIR/report.ttl"
    if ((HARNESS_RC != 0)); then
        note "The harness exited $HARNESS_RC — scenarios failed. That is expected"
        note "until the gaps are closed; the report is the deliverable."
    fi
else
    log "No report was written — the harness aborted before running any test"
    note "This is not a scenario failure. The harness gave up during its own"
    note "setup (REGISTER CLIENTS / PREPARE SERVER), so nothing was measured."
    note "Read $RUN_DIR/harness.log from the bottom for the cause."
fi
note "harness output: $RUN_DIR/harness.log"
note "pod log:        $RUN_DIR/pod.log"
note "CSS log:        $RUN_DIR/css.log"
exit "$HARNESS_RC"
