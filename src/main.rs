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
    let fetch_policy = cfg.fetch_policy();
    if !cfg.allow_insecure_hosts.is_empty() {
        // Loud on purpose: this is the operator relaxing an SSRF control.
        // For these hosts the pod will talk plain http and reach private
        // addresses on pre-authentication fetches.
        tracing::warn!(
            hosts = %cfg.allow_insecure_hosts.join(", "),
            "--allow-insecure-host: private-IP and https-only checks are waived for these hosts"
        );
    }
    let state = AppState {
        store: Arc::new(OxigraphStore::in_memory().expect("store")),
        space,
        resolver: Arc::new(HttpJwksResolver::new(fetch_policy.clone())),
        webid_verifier: Arc::new(HttpWebIdIssuers::new(fetch_policy)),
        auth_config: Arc::new(cfg.auth_config()),
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
