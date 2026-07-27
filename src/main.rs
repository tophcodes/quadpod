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
    let state = AppState {
        store: Arc::new(OxigraphStore::in_memory().expect("store")),
        space,
        resolver: Arc::new(HttpJwksResolver::new()),
        webid_verifier: Arc::new(HttpWebIdIssuers::new()),
        auth_config: Arc::new(cfg.auth_config()),
    };
    sparql_pod::container::provision_root(state.store.as_ref(), &state.space.root())
        .await.expect("provision root container");
    let owner = cfg.validated_owner_webid().expect("owner WebID validated above");
    sparql_pod::wac::provision::provision_root_acl(state.store.as_ref(), &state.space, &owner)
        .await.expect("provision root ACL");
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    tracing::info!("sparql-pod listening on {}", cfg.listen);
    axum::serve(listener, router(state)).await.unwrap();
}
