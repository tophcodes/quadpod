use std::sync::Arc;
use sparql_pod::{http::{AppState, router}, space::StorageSpace, store::OxigraphStore};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let base = std::env::var("POD_BASE_URI").unwrap_or_else(|_| "http://localhost:3000/".into());
    let state = AppState {
        store: Arc::new(OxigraphStore::in_memory().expect("store")),
        space: StorageSpace::new(base).expect("valid POD_BASE_URI (absolute, trailing slash)"),
    };
    sparql_pod::container::provision_root(state.store.as_ref(), &state.space)
        .await.expect("provision root container");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    tracing::info!("sparql-pod listening on 127.0.0.1:3000");
    axum::serve(listener, router(state)).await.unwrap();
}
