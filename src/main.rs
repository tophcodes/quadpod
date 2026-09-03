use std::sync::Arc;
use quadpod::{auth::{GuardedClient, HttpJwksResolver, HttpWebIdIssuers, InMemoryJtiReplayStore},
    config::Config, http::{AppState, router}};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    // Both the base URI and the owner WebID are checked by the parser that
    // produced them, so there is nothing left to validate here, and an error
    // in either still names the config file when that is where it came from,
    // which a check at this point could not do.
    let cfg = Config::load().unwrap_or_else(|e| e.exit());
    let space = cfg.base_uri.clone();
    let (fetch_policy, rejected_insecure_hosts) = cfg.try_fetch_policy();
    if !rejected_insecure_hosts.is_empty() {
        // An entry that reaches here is a non-blank string the operator
        // typed (config.rs trims and drops empty/whitespace entries before
        // parsing) that this process could not understand unambiguously,
        // the same class of mistake as an invalid --base-uri or
        // --owner-webid above. Refuse to start rather than silently grant
        // fewer hosts than configured: a pod that starts clean here is
        // indistinguishable from one started without the flag at all, and
        // would fail every fetch to that host with a 401 the operator has
        // nothing to grep for.
        for entry in &rejected_insecure_hosts {
            eprintln!(
                "invalid --allow-insecure-host entry: {}",
                quadpod::auth::safe_fetch::insecure_host_rejection_hint(entry)
            );
        }
        std::process::exit(2);
    }
    let understood_insecure_hosts = fetch_policy.insecure_host_entries();
    if !understood_insecure_hosts.is_empty() {
        // Loud on purpose: this is the operator relaxing an SSRF control.
        // For these hosts the pod will talk plain http and reach private
        // addresses on pre-authentication fetches. Logs what was
        // understood after trimming/parsing, not the raw flag value.
        tracing::warn!(
            hosts = %understood_insecure_hosts.join(", "),
            "--allow-insecure-host: private-IP and https-only checks are waived for these hosts"
        );
    }
    let guarded_client = GuardedClient::new(&fetch_policy);
    let blobs = match cfg.blobs() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let store = match cfg.rdf_store() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let op_keys = match cfg.op_keys() {
        Ok(k) => k.map(Arc::new),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let state = AppState {
        store,
        events: Arc::new(quadpod::notify::Bus::new()),
        blobs,
        space,
        // One client for every outbound auth fetch in the process: cloning it
        // shares the connection pool, so discovery, JWKS and WebID profile
        // lookups to the same origin reuse connections and TLS sessions.
        resolver: Arc::new(HttpJwksResolver::new(
            guarded_client.clone(),
            fetch_policy.clone(),
        )),
        webid_verifier: Arc::new(HttpWebIdIssuers::new(guarded_client, fetch_policy)),
        auth_config: Arc::new(cfg.auth_config()),
        replay: Arc::new(InMemoryJtiReplayStore::new()),
        max_body_bytes: cfg.max_body_bytes,
        op_keys,
    };
    quadpod::container::provision_root(state.store.as_ref(), &state.space.root())
        .await.expect("provision root container");
    quadpod::wac::provision::provision_root_acl(
        state.store.as_ref(), &state.space, &cfg.owner_webid, cfg.reset_root_acl,
    ).await.expect("provision root ACL");
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    tracing::info!("quadpod listening on {}", cfg.listen);
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    tracing::info!("quadpod stopped");
}

/// Resolves on `SIGTERM` or `SIGINT`, which is what lets `axum::serve` stop
/// accepting connections and then wait for the requests already in flight.
///
/// It matters more here than it would elsewhere. ADR-7 gives a `rocksdb:`
/// directory to exactly one process, so every deployment is a stop and a
/// start with no second replica to absorb the gap, and without this the
/// supervisor's `SIGTERM` kills in-flight requests at whatever `.await` they
/// were parked on. Nothing is corrupted by that (ADR-2 makes each update
/// sequence atomic, so a killed write either took effect whole or not at
/// all), but a caller learns the outcome of its own `PUT` by having the
/// connection dropped, which for a non-idempotent `POST` it cannot safely
/// retry. Draining turns that into an ordinary response.
///
/// `SIGTERM` is what a supervisor sends (systemd, Kubernetes, `docker
/// stop`); `SIGINT` is Ctrl-C in a terminal. A second signal is not handled,
/// and deliberately: the runtime's default disposition is restored for
/// neither, so an operator who wants to stop waiting can send `SIGKILL`,
/// which no process can trap anyway.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");

    let received = tokio::select! {
        _ = term.recv() => "SIGTERM",
        _ = int.recv() => "SIGINT",
    };
    tracing::info!("{received} received, draining in-flight requests");
}
