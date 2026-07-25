//! Verifying a DPoP proof and binding it to an access token's `cnf.jkt`.
//!
//! `dpop-verifier` checks the proof's own signature, `htu`/`htm` match, and
//! `jti` replay, but it has **no concept of an access token's `cnf` claim at
//! all** — its only access-token-aware feature is the separate, unused-here
//! `ath` hash-binding mechanism. So after `dpop-verifier` accepts the proof,
//! this module manually compares the proof key's thumbprint (which
//! `dpop-verifier` returns as `VerifiedDpop::jkt`) against `expected_jkt` —
//! the access token's `cnf.jkt` — and rejects on any mismatch. Without that
//! manual compare, a valid DPoP proof from *any* key would be accepted for
//! an access token bound to a *different* key, breaking proof-of-possession
//! entirely. Fails closed: every verification error, or a `jkt` mismatch,
//! is rejected.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use async_trait::async_trait;
use dpop_verifier::{DpopError, DpopVerifier, ReplayContext, ReplayStore};

use super::AuthError;

/// `dpop-verifier`'s own freshness check (`check_timestamp_freshness`) is
/// hardcoded to the real wall clock (`OffsetDateTime::now_utc()`) — it
/// cannot be parameterized by the `now_unix` this module is given, which
/// would make it untestable with fixed clocks. We disable it here (a very
/// large window that never rejects) and instead check freshness ourselves,
/// below, against the caller-supplied `now_unix`.
const DISABLE_INTERNAL_CLOCK_CHECK_SECONDS: i64 = 999_999_999_999;

/// Our own freshness window for the DPoP proof's `iat`, checked against the
/// caller-supplied `now_unix` (see `DISABLE_INTERNAL_CLOCK_CHECK_SECONDS`).
const MAX_AGE_SECONDS: i64 = 300;
const FUTURE_SKEW_SECONDS: i64 = 5;

/// Replay-detection storage backing the `jti` check, shared across all
/// calls to `verify_dpop` in this process.
///
/// This is process-lifetime, in-memory storage: a `jti` is only rejected as
/// a replay within the single running process that first saw it (restarts
/// or multiple replicas don't share this state), and the set grows
/// unbounded for the process's lifetime (no eviction). Acceptable for v1;
/// noted as a known limitation.
static REPLAY_JTIS: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();

fn replay_jtis() -> &'static Mutex<HashSet<[u8; 32]>> {
    REPLAY_JTIS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// A `ReplayStore` backed by the process-lifetime `REPLAY_JTIS` set above
/// (rather than storage private to one call), so a `jti` replayed in a
/// later, separate call to `verify_dpop` is actually detected.
struct ProcessReplayStore;

#[async_trait]
impl ReplayStore for ProcessReplayStore {
    async fn insert_once(
        &mut self,
        jti_hash: [u8; 32],
        _ctx: ReplayContext<'_>,
    ) -> Result<bool, DpopError> {
        Ok(replay_jtis().lock().unwrap().insert(jti_hash))
    }
}

/// Verify a DPoP proof: signature (against its own embedded `jwk`), `htu`
/// and `htm` match, `iat` freshness (against `now_unix`), `jti` replay, and
/// — critically — that the proof key's thumbprint matches `expected_jkt`
/// (the access token's `cnf.jkt`). Fails closed.
pub async fn verify_dpop(
    proof: &str,
    htu: &str,
    htm: &str,
    expected_jkt: &str,
    now_unix: i64,
) -> Result<(), AuthError> {
    let verifier = DpopVerifier::new()
        .with_max_age_seconds(DISABLE_INTERNAL_CLOCK_CHECK_SECONDS)
        .with_future_skew_seconds(DISABLE_INTERNAL_CLOCK_CHECK_SECONDS);

    let mut store = ProcessReplayStore;
    let verified = verifier
        .verify(&mut store, proof, htu, htm, None)
        .await
        .map_err(|e| AuthError::DpopInvalid(e.to_string()))?;

    if verified.iat > now_unix + FUTURE_SKEW_SECONDS {
        return Err(AuthError::DpopInvalid(
            "DPoP proof iat is too far in the future".to_string(),
        ));
    }
    if now_unix - verified.iat > MAX_AGE_SECONDS {
        return Err(AuthError::DpopInvalid(
            "DPoP proof iat is stale".to_string(),
        ));
    }

    // THE critical proof-of-possession check: dpop-verifier verified the
    // proof's signature against ITS OWN embedded key, but never compared
    // that key to the access token's cnf.jkt. Do that here.
    if verified.jkt != expected_jkt {
        return Err(AuthError::Binding);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testsupport::TestClient;

    #[tokio::test]
    async fn valid_proof_matching_jkt_passes() {
        let client = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-a");
        assert!(verify_dpop(
            &proof,
            "https://pod.toph.so/foo",
            "GET",
            &client.jkt(),
            1_010
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn wrong_htu_is_rejected() {
        let client = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-b");
        assert!(verify_dpop(
            &proof,
            "https://pod.toph.so/OTHER",
            "GET",
            &client.jkt(),
            1_010
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn jkt_mismatch_is_binding_error() {
        let client = TestClient::new();
        let other = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-c");
        // proof is from `client`, but we claim the token was bound to `other`'s key
        assert!(verify_dpop(
            &proof,
            "https://pod.toph.so/foo",
            "GET",
            &other.jkt(),
            1_010
        )
        .await
        .is_err());
    }
}
