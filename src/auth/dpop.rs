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

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use async_trait::async_trait;
use dpop_verifier::{DpopError, DpopVerifier, ReplayContext, ReplayStore};
use sha2::{Digest, Sha256};

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
/// or multiple replicas don't share this state) — a shared/persistent
/// (e.g. Redis) store is still needed for multi-replica deployments; this
/// remains single-instance only. Each entry is keyed by the `jti` hash and
/// stores the `now_unix` at which it was recorded, so stale entries can be
/// evicted (see `record_jti_or_reject_replay`) and the set stays bounded
/// instead of growing for the process's lifetime.
static REPLAY_JTIS: OnceLock<Mutex<HashMap<[u8; 32], i64>>> = OnceLock::new();

fn replay_jtis() -> &'static Mutex<HashMap<[u8; 32], i64>> {
    REPLAY_JTIS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Serializes tests that record a `jti` into the process-wide
/// [`REPLAY_JTIS`] store. `cargo test` runs tests in parallel by default,
/// and the tests that touch this store use wildly different `now_unix`
/// values — this module's own use simulated times near `1_000` (and one far
/// in the future, to exercise eviction), while `http`'s handler tests go
/// through `auth_layer`, which uses the real wall clock. A large `now_unix`
/// in one test evicts another concurrently-running test's just-inserted,
/// still-fresh entry out from under it (see
/// `record_jti_or_reject_replay`), so any test that both records a `jti`
/// and depends on it staying recorded must hold this lock.
///
/// Uses `tokio::sync::Mutex`, not `std::sync::Mutex`, because the guard is
/// held across `.await` points in those tests (clippy's
/// `await_holding_lock` correctly flags a std lock there).
#[cfg(test)]
static TEST_REPLAY_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

#[cfg(test)]
pub fn test_replay_lock() -> &'static tokio::sync::Mutex<()> {
    TEST_REPLAY_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Hash a `jti` the same way `dpop-verifier` does internally (the SHA-256
/// digest of the raw `jti` string; `dpop-verifier`'s `JTI_HASH_LENGTH` is 32
/// bytes, which is the full SHA-256 output, so no truncation is lost here).
fn hash_jti(jti: &str) -> [u8; 32] {
    Sha256::digest(jti.as_bytes()).into()
}

/// Record `jti` as seen in the process-lifetime replay set.
///
/// Deliberately called by `verify_dpop` only after every other check
/// (signature, htu/htm, freshness, `cnf.jkt` binding) has already passed —
/// so a proof rejected by any of those checks never consumes its `jti`, and
/// only a fully-valid proof does. A *second* submission of that same valid
/// proof is then rejected here as a replay.
///
/// Before checking/inserting, evicts every entry recorded further back than
/// the freshness window (`MAX_AGE_SECONDS + FUTURE_SKEW_SECONDS`) from
/// `now_unix`. This is safe because a `jti` can never be legitimately
/// replayed *within* that window (this function rejects it), and *outside*
/// the window `verify_dpop`'s own freshness check (Fix 1, above) already
/// rejects the proof on `iat` staleness before we ever get here — so
/// nothing that still needs replay protection is ever evicted, and the set
/// stays bounded instead of growing for the process's lifetime. Note: this
/// is still an in-process, single-instance store (see `REPLAY_JTIS`); a
/// shared/persistent store (e.g. Redis) is required for multi-replica
/// deployments, which is out of scope here.
fn record_jti_or_reject_replay(jti: &str, now_unix: i64) -> Result<(), AuthError> {
    let mut jtis = replay_jtis().lock().unwrap();
    let cutoff = now_unix - (MAX_AGE_SECONDS + FUTURE_SKEW_SECONDS);
    jtis.retain(|_, recorded_at| *recorded_at >= cutoff);

    let hash = hash_jti(jti);
    if let std::collections::hash_map::Entry::Vacant(entry) = jtis.entry(hash) {
        entry.insert(now_unix);
        Ok(())
    } else {
        Err(AuthError::DpopInvalid("dpop proof replayed".to_string()))
    }
}

/// A `ReplayStore` that never records or rejects on replay, passed to
/// `dpop-verifier`'s own `verify()` in place of the real replay store.
///
/// `dpop-verifier` checks replay *before* returning control to this module,
/// i.e. before our own freshness (Fix 1) and `cnf.jkt` binding checks run.
/// If those were given the real store directly, a proof that fails one of
/// *our* later checks would still have permanently burned its `jti` inside
/// `dpop-verifier` — letting an attacker who merely observes (or replays
/// with a wrong key) a proof deny that `jti` to the legitimate client
/// forever. Using this no-op store here means `dpop-verifier` never
/// consumes a `jti`; the real, process-wide replay check happens in
/// `record_jti_or_reject_replay`, called only once every check has passed.
struct NoopReplayStore;

#[async_trait]
impl ReplayStore for NoopReplayStore {
    async fn insert_once(
        &mut self,
        _jti_hash: [u8; 32],
        _ctx: ReplayContext<'_>,
    ) -> Result<bool, DpopError> {
        Ok(true)
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

    let mut store = NoopReplayStore;
    let verified = verifier
        .verify(&mut store, proof, htu, htm, None)
        .await
        .map_err(|e| AuthError::DpopInvalid(e.to_string()))?;

    // `iat` comes from the proof's own JSON claims and is fully
    // caller-controlled (e.g. `i64::MIN`), so these comparisons use
    // saturating arithmetic rather than plain `+`/`-`: an extreme `iat`
    // must be rejected as not-fresh, never overflow/panic (debug) or wrap
    // around to look fresh (release).
    if verified.iat.saturating_sub(now_unix) > FUTURE_SKEW_SECONDS {
        return Err(AuthError::DpopInvalid(
            "DPoP proof iat is too far in the future".to_string(),
        ));
    }
    if now_unix.saturating_sub(verified.iat) > MAX_AGE_SECONDS {
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

    // Every check above has passed: only now do we consume the jti, so a
    // proof rejected by any earlier check leaves its jti reusable (see
    // `NoopReplayStore` and `record_jti_or_reject_replay`).
    record_jti_or_reject_replay(&verified.jti, now_unix)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testsupport::TestClient;

    /// Serializes tests that actually record a `jti` into the process-wide
    /// `REPLAY_JTIS` store (i.e. reach a fully-valid `verify_dpop` call) —
    /// see [`super::test_replay_lock`], which `http`'s handler tests share.
    /// Tests that never reach `record_jti_or_reject_replay` (rejected
    /// earlier by htu/htm, freshness, or jkt binding) don't touch the shared
    /// store and don't need this lock.
    fn test_lock() -> &'static tokio::sync::Mutex<()> {
        super::test_replay_lock()
    }

    #[tokio::test]
    async fn valid_proof_matching_jkt_passes() {
        let _guard = test_lock().lock().await;
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

    #[tokio::test]
    async fn stale_proof_is_rejected() {
        let client = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-stale");
        // now far beyond MAX_AGE after iat
        assert!(verify_dpop(
            &proof,
            "https://pod.toph.so/foo",
            "GET",
            &client.jkt(),
            9_999_999
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn future_proof_is_rejected() {
        let client = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 5_000_000, "jti-future");
        assert!(verify_dpop(
            &proof,
            "https://pod.toph.so/foo",
            "GET",
            &client.jkt(),
            1_000
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn extreme_iat_does_not_panic_and_is_rejected() {
        // `TestClient::mint_dpop` goes through `josekit`'s registered-claim
        // validation, which rejects *any* negative `iat` at mint time (not
        // specific to this module) -- so an extreme-negative `iat` can't be
        // minted here to reach `verify_dpop`. `now_unix` is exactly as
        // caller-controlled as `iat` from the arithmetic's point of view
        // (both are plain `i64` inputs to the two comparisons Fix 1
        // rewrote), so this exercises the same overflow with an extreme
        // `now_unix` instead: the *original* `verified.iat > now_unix +
        // FUTURE_SKEW_SECONDS` formula overflows computing `i64::MAX + 5`
        // and panics; Fix 1's `saturating_sub` does not.
        let client = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-extreme");
        assert!(verify_dpop(
            &proof,
            "https://pod.toph.so/foo",
            "GET",
            &client.jkt(),
            i64::MAX
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn replay_of_valid_proof_is_rejected_but_rejected_proof_does_not_burn_jti() {
        let _guard = test_lock().lock().await;
        let client = TestClient::new();
        // a proof that will FAIL the jkt binding (wrong expected_jkt) must NOT burn its jti
        let other = TestClient::new();
        let p_reject = client.mint_dpop("https://pod.toph.so/x", "GET", 1_000, "jti-shared");
        assert!(
            verify_dpop(&p_reject, "https://pod.toph.so/x", "GET", &other.jkt(), 1_010)
                .await
                .is_err()
        );
        // same jti now used by a VALID proof -> must SUCCEED (jti not burned by the rejected attempt)
        let p_ok = client.mint_dpop("https://pod.toph.so/y", "GET", 1_000, "jti-shared");
        assert!(
            verify_dpop(&p_ok, "https://pod.toph.so/y", "GET", &client.jkt(), 1_010)
                .await
                .is_ok()
        );
        // replay the SAME valid proof/jti -> must be rejected
        assert!(
            verify_dpop(&p_ok, "https://pod.toph.so/y", "GET", &client.jkt(), 1_010)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn replayed_jti_outside_window_is_allowed_again_and_set_stays_bounded() {
        let _guard = test_lock().lock().await;
        let client = crate::auth::testsupport::TestClient::new();
        // first use at t=1000
        let p1 = client.mint_dpop("https://pod.toph.so/a", "GET", 1_000, "jti-ttl");
        assert!(verify_dpop(&p1, "https://pod.toph.so/a", "GET", &client.jkt(), 1_010)
            .await
            .is_ok());
        // immediate replay (same jti, within window) → rejected
        assert!(verify_dpop(&p1, "https://pod.toph.so/a", "GET", &client.jkt(), 1_010)
            .await
            .is_err());
        // a NEW proof with the SAME jti but far in the future (past the eviction window) → allowed
        let p2 = client.mint_dpop("https://pod.toph.so/a", "GET", 1_000_000, "jti-ttl");
        assert!(verify_dpop(&p2, "https://pod.toph.so/a", "GET", &client.jkt(), 1_000_010)
            .await
            .is_ok());
    }
}
