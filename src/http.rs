use std::sync::Arc;
use axum::{Router, routing::get, extract::{State, Path}, body::Bytes,
    http::{StatusCode, HeaderMap, header}, response::{IntoResponse, Response}};
use crate::{space::StorageSpace, store::OxigraphStore, resource::{put_rdf, get_rdf}};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<OxigraphStore>,
    pub space: StorageSpace,
}

pub fn router(state: AppState) -> Router {
    // axum 0.8 wildcard capture syntax: "/{*path}" (NOT the old "/*path").
    Router::new().route("/{*path}", get(handle_get).put(handle_put)).with_state(state)
}

async fn handle_put(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap, body: Bytes,
) -> Response {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.starts_with("text/turtle") {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let req_path = format!("/{path}");
    let turtle = String::from_utf8_lossy(&body);
    match put_rdf(st.store.as_ref(), &st.space, &req_path, &turtle).await {
        Ok(()) => {
            let loc = st.space.graph_iri(&req_path);
            (StatusCode::CREATED, [(header::LOCATION, loc)]).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn handle_get(State(st): State<AppState>, Path(path): Path<String>) -> Response {
    let req_path = format!("/{path}");
    match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(Some(ttl)) => ([(header::CONTENT_TYPE, "text/turtle")], ttl).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;
    use std::sync::Arc;
    use crate::{space::StorageSpace, store::OxigraphStore};

    fn app() -> axum::Router {
        let state = AppState {
            store: Arc::new(OxigraphStore::in_memory().unwrap()),
            space: StorageSpace::new("https://pod.toph.so/").unwrap(),
        };
        router(state)
    }

    #[tokio::test]
    async fn put_then_get_roundtrips_over_http() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        let res = app.clone().oneshot(put).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/foo");

        let get = Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap();
        let res = app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Toph"));
    }

    #[tokio::test]
    async fn get_missing_is_404() {
        let res = app().oneshot(
            Request::builder().method("GET").uri("/nope").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_wrong_content_type_is_415() {
        let req = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}")).unwrap();
        assert_eq!(app().oneshot(req).await.unwrap().status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
