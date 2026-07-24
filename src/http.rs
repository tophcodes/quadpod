use std::sync::Arc;
use axum::{Router, routing::get, extract::{State, Path}, body::Bytes,
    http::{StatusCode, HeaderMap, header, header::{IF_MATCH, IF_NONE_MATCH}}, response::{IntoResponse, Response}};
use crate::{space::StorageSpace, store::SparqlStore, resource::{put_rdf, get_rdf, delete_rdf, ResourceError},
    rdf::{format_for_content_type, format_for_accept, parse, serialize, etag}};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn SparqlStore>,
    pub space: StorageSpace,
}

pub fn router(state: AppState) -> Router {
    // axum 0.8 wildcard capture syntax: "/{*path}" (NOT the old "/*path").
    Router::new().route("/{*path}", get(handle_get).put(handle_put).delete(handle_delete)).with_state(state)
}

fn put_status(e: &ResourceError) -> StatusCode {
    match e {
        ResourceError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

async fn handle_put(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap, body: Bytes,
) -> Response {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_content_type(ct) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let req_path = format!("/{path}");
    let g = match st.space.graph_iri(&req_path) {
        Ok(g) => g,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if headers.contains_key(IF_MATCH) || headers.contains_key(IF_NONE_MATCH) {
        let current_tag = match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
            Ok(Some(tr)) => Some(etag(&tr)),
            Ok(None) => None,
            Err(e) => return (put_status(&e), e.to_string()).into_response(),
        };
        if let Some(im) = headers.get(IF_MATCH).and_then(|v| v.to_str().ok()) {
            if Some(im) != current_tag.as_deref() {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
        }
        if headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some("*")
            && current_tag.is_some()
        {
            return StatusCode::PRECONDITION_FAILED.into_response();
        }
    }
    let triples = match parse(&body, fmt, &g) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match put_rdf(st.store.as_ref(), &st.space, &req_path, &triples).await {
        Ok(()) => (StatusCode::CREATED, [(header::LOCATION, g)]).into_response(),
        Err(e) => (put_status(&e), e.to_string()).into_response(),
    }
}

async fn handle_get(
    State(st): State<AppState>, Path(path): Path<String>, headers: HeaderMap,
) -> Response {
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(fmt) = format_for_accept(accept) else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    let req_path = format!("/{path}");
    match get_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(Some(triples)) => {
            let tag = etag(&triples);
            if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag.as_str()) {
                return (StatusCode::NOT_MODIFIED, [(header::ETAG, tag)]).into_response();
            }
            match serialize(&triples, fmt) {
                Ok(bytes) => (
                    [(header::CONTENT_TYPE, fmt.media_type().to_string()), (header::ETAG, tag)],
                    bytes,
                )
                    .into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(ResourceError::InvalidIri) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn handle_delete(State(st): State<AppState>, Path(path): Path<String>) -> Response {
    let req_path = format!("/{path}");
    match delete_rdf(st.store.as_ref(), &st.space, &req_path).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(ResourceError::InvalidIri) => StatusCode::BAD_REQUEST.into_response(),
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

    async fn body_string(res: axum::response::Response) -> String {
        let b = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        String::from_utf8_lossy(&b).into_owned()
    }

    #[tokio::test]
    async fn put_turtle_then_get_jsonld_negotiates() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        let put_res = app.clone().oneshot(put).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::CREATED);
        assert_eq!(put_res.headers().get(header::LOCATION).unwrap(), "https://pod.toph.so/foo");

        let get = Request::builder().method("GET").uri("/foo")
            .header(header::ACCEPT, "application/ld+json").body(Body::empty()).unwrap();
        let res = app.oneshot(get).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "application/ld+json");
        assert!(body_string(res).await.contains("schema.org/name"));
    }

    #[tokio::test]
    async fn get_default_accept_is_turtle() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();
        let res = app.oneshot(Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/turtle");
    }

    #[tokio::test]
    async fn get_unsupported_accept_is_406() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();
        let res = app.oneshot(Request::builder().method("GET").uri("/foo")
            .header(header::ACCEPT, "image/png").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn put_unsupported_content_type_is_415() {
        let res = app().oneshot(Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "application/json").body(Body::from("{}")).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn get_missing_is_404() {
        let res = app().oneshot(Request::builder().method("GET").uri("/nope").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn iri_breaking_path_is_400() {
        let res = app().oneshot(Request::builder().method("GET").uri("/foo%3E%20bar").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_iri_breaking_path_is_400() {
        let req = Request::builder().method("PUT").uri("/foo%3E%20bar")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"x\" .")).unwrap();
        assert_eq!(app().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_emits_etag_and_304_on_if_none_match() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();

        let res = app.clone().oneshot(Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap()).await.unwrap();
        let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();

        let cond = Request::builder().method("GET").uri("/foo")
            .header(header::IF_NONE_MATCH, &etag).body(Body::empty()).unwrap();
        assert_eq!(app.oneshot(cond).await.unwrap().status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn put_if_match_mismatch_is_412() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();

        let stale = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, "\"deadbeef\"")
            .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
        assert_eq!(app.oneshot(stale).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn put_if_none_match_star_on_existing_is_412() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();

        let create_only = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_NONE_MATCH, "*")
            .body(Body::from("<#it> <http://schema.org/name> \"X\" .")).unwrap();
        assert_eq!(app.oneshot(create_only).await.unwrap().status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn put_if_match_matching_succeeds() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();
        // read current etag
        let res = app.clone().oneshot(Request::builder().method("GET").uri("/foo").body(Body::empty()).unwrap()).await.unwrap();
        let etag = res.headers().get(header::ETAG).unwrap().to_str().unwrap().to_owned();
        // conditional update with matching If-Match must succeed
        let upd = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_MATCH, &etag)
            .body(Body::from("<#it> <http://schema.org/name> \"New\" .")).unwrap();
        assert_eq!(app.oneshot(upd).await.unwrap().status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn put_if_none_match_star_on_absent_creates() {
        let app = app();
        let req = Request::builder().method("PUT").uri("/brand-new")
            .header(header::CONTENT_TYPE, "text/turtle")
            .header(header::IF_NONE_MATCH, "*")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn delete_existing_is_204_then_404() {
        let app = app();
        let put = Request::builder().method("PUT").uri("/foo")
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from("<#it> <http://schema.org/name> \"Toph\" .")).unwrap();
        app.clone().oneshot(put).await.unwrap();
        let del = Request::builder().method("DELETE").uri("/foo").body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
        let del2 = Request::builder().method("DELETE").uri("/foo").body(Body::empty()).unwrap();
        assert_eq!(app.oneshot(del2).await.unwrap().status(), StatusCode::NOT_FOUND);
    }
}
