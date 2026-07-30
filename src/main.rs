use std::sync::Arc;
use clap::Parser;
use sparql_pod::{auth::{HttpJwksResolver, HttpWebIdIssuers}, config::Config,
    http::{AppState, router}, store::OxigraphStore};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cfg = Config::parse();
    let space = match cfg.space() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invalid --base-uri: {e}");
            std::process::exit(2);
        }
    };
    if cfg.validated_owner_webid().is_err() {
        eprintln!("invalid --owner-webid: must be an absolute IRI");
        std::process::exit(2);
    }
    let (fetch_policy, rejected_insecure_hosts) = cfg.try_fetch_policy();
    if !rejected_insecure_hosts.is_empty() {
        // An entry that reaches here is a non-blank string the operator
        // typed (config.rs trims and drops empty/whitespace entries before
        // parsing) that this process could not understand unambiguously —
        // the same class of mistake as an invalid --base-uri or
        // --owner-webid above. Refuse to start rather than silently grant
        // fewer hosts than configured: a pod that starts clean here is
        // indistinguishable from one started without the flag at all, and
        // would fail every fetch to that host with a 401 the operator has
        // nothing to grep for.
        for entry in &rejected_insecure_hosts {
            eprintln!(
                "invalid --allow-insecure-host entry: {}",
                sparql_pod::auth::safe_fetch::insecure_host_rejection_hint(entry)
            );
        }
        std::process::exit(2);
    }
    let understood_insecure_hosts = fetch_policy.insecure_host_entries();
    if !understood_insecure_hosts.is_empty() {
        // Loud on purpose: this is the operator relaxing an SSRF control.
        // For these hosts the pod will talk plain http and reach private
        // addresses on pre-authentication fetches. Logs what was actually
        // understood after trimming/parsing, not the raw flag value.
        tracing::warn!(
            hosts = %understood_insecure_hosts.join(", "),
            "--allow-insecure-host: private-IP and https-only checks are waived for these hosts"
        );
    }
    let blobs = match cfg.blobs() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let state = AppState {
        store: Arc::new(OxigraphStore::in_memory().expect("store")),
        blobs,
        space,
        resolver: Arc::new(HttpJwksResolver::new(fetch_policy.clone())),
        webid_verifier: Arc::new(HttpWebIdIssuers::new(fetch_policy)),
        auth_config: Arc::new(cfg.auth_config()),
        max_body_bytes: cfg.max_body_bytes,
    };
    sparql_pod::container::provision_root(state.store.as_ref(), &state.space.root())
        .await.expect("provision root container");
    let owner = cfg.validated_owner_webid().expect("owner WebID validated above");
    sparql_pod::wac::provision::provision_root_acl(
        state.store.as_ref(), &state.space, &owner, cfg.reset_root_acl,
    ).await.expect("provision root ACL");
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    tracing::info!("sparql-pod listening on {}", cfg.listen);
    axum::serve(listener, router(state)).await.unwrap();
}
