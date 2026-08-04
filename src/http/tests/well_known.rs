//! The reserved `/.well-known/` space: discovery and JWKS when the OP is
//! on, 404 for every other name, 405 for every write — OP on or off.

use super::fixture::*;

async fn get_json(app: &axum::Router, path: &str) -> (StatusCode, Option<serde_json::Value>) {
    let res = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
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
    let (status, body) = get_json(&f.app, "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::OK);
    let doc = body.unwrap();
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
async fn the_op_off_pod_answers_404_for_discovery_but_still_refuses_writes() {
    let f = fixture().await;
    let (status, _) = get_json(&f.app, "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for method in ["PUT", "POST", "DELETE", "PATCH"] {
        let res = f
            .app
            .clone()
            .oneshot(owner_write(
                &f,
                method,
                "/.well-known/oauth-authorization-server",
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
    }
}

/// Even an authorized owner cannot plant a document in the reserved space
/// (RFC 8414 spoofing surface — see docs/uri-space.md).
fn owner_write(f: &Fixture, method: &str, path: &str) -> Request<Body> {
    f.owner_request(method, path)
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#a> <http://schema.org/name> \"x\" ."))
        .unwrap()
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
