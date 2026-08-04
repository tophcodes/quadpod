//! The reserved `/.well-known/` space: discovery and JWKS when the OP is
//! on, 404 for every other name, 405 for every write — OP on or off.
//!
//! That the segment is reserved in the URI space itself — so no write can
//! allocate a resource under it, and an adjacent name like
//! `/.well-known-x` stays ordinary — is pinned in `crate::space`, which is
//! where the refusal lives.

use super::fixture::*;

async fn get(app: &axum::Router, path: &str) -> axum::response::Response {
    app.clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get_json(app: &axum::Router, path: &str) -> (StatusCode, Option<serde_json::Value>) {
    let res = get(app, path).await;
    let status = res.status();
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    (status, serde_json::from_slice(&bytes).ok())
}

#[tokio::test]
async fn discovery_is_served_unauthenticated_when_the_op_is_on() {
    let (f, _op, p) = fixture_with_op().await;
    let res = get(&f.app, "/.well-known/openid-configuration").await;
    assert_eq!(res.status(), StatusCode::OK);
    // RFC 8414 §3.2: the metadata document is `application/json`, which is
    // also what a verifier's `Accept` asks for.
    assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["issuer"], "https://pod.toph.so/");
    assert_eq!(doc["scopes_supported"], serde_json::json!(["openid", "webid"]));
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn the_jwks_route_serves_public_members_only_with_its_media_type() {
    let (f, _op, p) = fixture_with_op().await;
    let res = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "application/jwk-set+json");
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let jwks: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for k in jwks["keys"].as_array().unwrap() {
        assert!(k.get("d").is_none(), "private member leaked");
        assert!(k.get("kid").is_some());
    }
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn an_unimplemented_name_is_404_and_the_bare_forms_too() {
    let (f, _op, p) = fixture_with_op().await;
    for path in ["/.well-known/security.txt", "/.well-known", "/.well-known/"] {
        let (status, _) = get_json(&f.app, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn the_op_off_pod_answers_404_for_both_documents_but_still_refuses_writes() {
    let f = fixture().await;
    for path in ["/.well-known/openid-configuration", "/.well-known/jwks.json"] {
        let (status, _) = get_json(&f.app, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    every_write_is_405(&f, |b, method, path| f.sign(b, OWNER, method, path)).await;
}

// The segment is reserved unconditionally, so turning the OP on takes no
// name back from anyone: the two documents it adds become readable, and
// every write is refused by the router exactly as before.
#[tokio::test]
async fn the_op_on_pod_refuses_writes_too() {
    let (f, op, p) = fixture_with_op().await;
    every_write_is_405(&f, |b, method, path| op_credentials(&f, &op, b, method, path)).await;
    std::fs::remove_file(&p).ok();
}

/// Every write method, on names the pod serves and on one it does not,
/// answered `405` by the router before any handler runs or any WAC
/// decision is taken. Even an authorized owner cannot plant a document in
/// the reserved space (RFC 8414 spoofing surface — see docs/uri-space.md).
///
/// `credentials` signs as the owner with an issuer the app under test
/// trusts — the external test IdP with the OP off, the pod's own OP with it
/// on — so what is measured is the router's refusal, not authentication's.
async fn every_write_is_405(
    f: &Fixture,
    credentials: impl Fn(
        axum::http::request::Builder,
        &str,
        &str,
    ) -> axum::http::request::Builder,
) {
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/.well-known",
        "/.well-known/",
    ] {
        for method in ["PUT", "POST", "DELETE", "PATCH"] {
            let req = credentials(Request::builder().method(method).uri(path), method, path)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#a> <http://schema.org/name> \"x\" ."))
                .unwrap();
            let res = f.app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        }
    }
}

/// Owner credentials minted by the pod's own OP, which is the only issuer
/// an OP-on fixture's app trusts.
fn op_credentials(
    f: &Fixture,
    op: &Arc<crate::op::KeySet>,
    builder: axum::http::request::Builder,
    method: &str,
    path: &str,
) -> axum::http::request::Builder {
    let token = crate::op::mint_access_token(
        op,
        &f.space,
        &oxigraph::model::NamedNode::new(OWNER).unwrap(),
        &f.client.jkt(),
        now_unix(),
    );
    let proof = f.client.mint_dpop(
        &format!("https://pod.toph.so{path}"),
        method,
        now_unix(),
        &uuid::Uuid::new_v4().to_string(),
    );
    builder
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("dpop", proof)
}

/// The seam between what the pod publishes and what its own verifier
/// parses: the JWKS is taken off a real socket, through the same
/// `guarded_get` and the same `Vec<Jwk>` deserialization
/// `HttpJwksResolver::fetch` performs, and a token minted by this pod's OP
/// verifies against exactly those bytes.
///
/// The two fetches are driven here rather than by `HttpJwksResolver`
/// itself because the served `jwks_uri` is absolute at the configured base
/// (`https://pod.toph.so/`), which is not where the test listener is —
/// following it verbatim would leave the machine. Its *path* is what is
/// fetched, and that the path is one this pod routes is part of what the
/// test asserts.
#[tokio::test]
async fn the_served_jwks_is_what_this_pods_verifier_parses() {
    use crate::auth::safe_fetch::{guarded_get, FetchPolicy, GuardedClient};

    let (f, op, p) = fixture_with_op().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = f.app.clone();
    tokio::spawn(async move { axum::serve(listener, served).await.unwrap() });

    let policy = FetchPolicy::permissive();
    let client = GuardedClient::new(&policy);
    let (discovery_body, _) = guarded_get(
        &client,
        &format!("http://{addr}/.well-known/openid-configuration"),
        "application/json",
        &policy,
    )
    .await
    .expect("discovery is served over a real socket");
    let discovery: serde_json::Value = serde_json::from_str(&discovery_body).unwrap();
    let jwks_uri = discovery["jwks_uri"].as_str().expect("discovery names a jwks_uri");
    let jwks_path = jwks_uri
        .strip_prefix("https://pod.toph.so")
        .expect("the jwks_uri is at the configured base");
    let (jwks_body, _) = guarded_get(
        &client,
        &format!("http://{addr}{jwks_path}"),
        "application/json",
        &policy,
    )
    .await
    .expect("the advertised jwks_uri is a path this pod routes");

    let doc: serde_json::Value = serde_json::from_str(&jwks_body).unwrap();
    let keys: Vec<josekit::jwk::Jwk> = serde_json::from_value(doc["keys"].clone())
        .expect("the served keys deserialize as the verifier's own key type");
    let resolver = StaticJwksResolver::new("https://pod.toph.so/", crate::auth::Jwks { keys });

    let token = crate::op::mint_access_token(
        &op,
        &f.space,
        &oxigraph::model::NamedNode::new(OWNER).unwrap(),
        &f.client.jkt(),
        now_unix(),
    );
    let claims = crate::auth::verify_access_token(&token, &resolver, now_unix())
        .await
        .expect("a token this pod minted verifies against the keys it published");
    assert_eq!(claims.webid, OWNER);
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn the_acceptance_round_trip_a_self_minted_token_authenticates() {
    let (f, op, p) = fixture_with_op().await;
    // `f.sign` mints from the external test IdP, which this app does not
    // trust: its resolver holds the pod's own JWKS. So mint from the pod's
    // own OP and carry the DPoP proof by hand.
    let token = crate::op::mint_access_token(
        &op,
        &f.space,
        &oxigraph::model::NamedNode::new(OWNER).unwrap(),
        &f.client.jkt(),
        now_unix(),
    );
    let proof = f.client.mint_dpop(
        "https://pod.toph.so/from-own-op",
        "PUT",
        now_unix(),
        &uuid::Uuid::new_v4().to_string(),
    );
    let res = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/from-own-op")
                .header(header::AUTHORIZATION, format!("DPoP {token}"))
                .header("dpop", proof)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#it> <http://schema.org/name> \"own op\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "the pod accepts its own token");
    std::fs::remove_file(&p).ok();
}
