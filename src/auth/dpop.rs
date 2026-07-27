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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use dpop_verifier::{DpopError, DpopVerifier, ReplayContext, ReplayStore};
use serde_json::Value;
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

/// Read the `htu` claim out of a proof whose signature has ALREADY been
/// verified.
///
/// `dpop-verifier`'s `VerifiedDpop` carries only `jkt`, `jti` and `iat` — it
/// never hands back the `htu` it compared — so the claim has to be decoded
/// here. The caller must only ever pass a `proof` string that
/// `DpopVerifier::verify` has just accepted: the signature covers exactly
/// the `header.payload` prefix of that same string, so re-decoding its
/// payload segment yields signed bytes, not an unverified peek. This is
/// deliberately *not* the pattern in `access_token::peek_untrusted_issuer`
/// (which reads an unsigned payload to pick a key); nothing here may be read
/// before verification.
fn verified_htu_claim(proof: &str) -> Result<String, AuthError> {
    let parts: Vec<&str> = proof.split('.').collect();
    let [_header_part, payload_part, _signature_part] = parts[..] else {
        return Err(AuthError::DpopInvalid(
            "dpop proof is not a compact JWS".to_string(),
        ));
    };
    let bytes = URL_SAFE_NO_PAD.decode(payload_part).map_err(|_| {
        AuthError::DpopInvalid("dpop proof payload is not base64url".to_string())
    })?;
    let payload: Value = serde_json::from_slice(&bytes)
        .map_err(|_| AuthError::DpopInvalid("dpop proof payload is not JSON".to_string()))?;
    payload
        .get("htu")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| AuthError::DpopInvalid("dpop proof has no htu claim".to_string()))
}

/// Whether the proof's own `htu` names exactly the resource `expected`
/// names.
///
/// `dpop-verifier` compares the two through `uri::normalize_htu`, which
/// **drops empty path segments** — and a trailing slash is an empty final
/// segment. In this pod the trailing slash is precisely what separates a
/// container from a resource: `/foo` and `/foo/` are distinct named graphs
/// with distinct ACLs. Left at `dpop-verifier`'s comparison, a proof minted
/// for `/.aux/acl/foo` also verifies against `PUT /.aux/acl/foo/`, so an
/// on-path adversary can re-target a signed ACL write at the container's
/// ACL, whose rules then name no governed IRI at all — an empty ACL that
/// wins over every ancestor and locks the subtree out permanently. Refusing
/// trailing slashes the way [`crate::space::StorageSpace::resolve`] refuses
/// the other normalization-unstable shapes is not an option here, so the
/// comparison is tightened instead.
///
/// The tightening is deliberately scoped to the **path only** — scheme,
/// host, port and query are left to `dpop-verifier`'s own
/// RFC-3986-following comparison. `normalize_htu` already lowercases
/// scheme/host and elides a default port, and RFC 9449 §4.3 says a server
/// SHOULD apply exactly that normalization "to reduce the likelihood of
/// false negatives"; comparing the whole URL byte-for-byte here would
/// silently re-impose case- and default-port-sensitivity that
/// `dpop-verifier` deliberately relaxed, 401-ing e.g. `solid-client-authn-js`
/// clients that mint `htu` with an explicit `:443` or a differently-cased
/// host. Comparing only `.path()` keeps the trailing-slash fix (`Url::path`
/// preserves it; `normalize_htu` only loses it because it rebuilds the path
/// from `path_segments()`, which yields no empty final segment) without
/// discarding any of `dpop-verifier`'s own RFC-conformant tolerance.
///
/// Within the path, the comparison is **not** raw byte equality: `Url::path`
/// is the WHATWG-URL-Standard-normalized wire path, not the literal wire
/// bytes. `Url::parse` runs that parsing to get there, and it resolves
/// `.`/`..` segments (`/a/../b` → `/b`), maps a lone `\` to `/`, and — for a
/// few bytes that are not valid unescaped IRI characters anyway (space, `<`,
/// `>`, `"`, `{`, `}`, a backtick) — percent-encodes them if they appear raw.
/// It still does no empty-segment collapsing and no case folding, and no
/// *further* percent-decoding is layered on top of any of that: an escape
/// neither side introduced is still compared verbatim, so `/a%41` and
/// `/a%2541` remain different strings below (see the tests). Both sides are
/// this normalized form: `expected` comes from `auth::middleware::derive_htu`,
/// which is the configured base plus the raw request path, and a client signs
/// the URL as it puts it on the wire (`/caf%C3%A9`, not `/café`); `Url::path`
/// turns each side into its WHATWG form the same way, so the two still line up.
///
/// Dot-segment resolution and the backslash mapping are the two ways this
/// normalization could, in principle, make two distinct wire paths compare
/// equal — and closing that off is not this function's job. It is closed one
/// layer up, and the closure argument belongs here:
///
/// - A wire path containing a raw `.`/`..` segment, or an internal empty
///   segment, is refused by
///   [`crate::space::StorageSpace::is_normalization_stable`] at `resolve`
///   time, before the store is ever touched.
/// - A wire path containing a raw `\` — or any of the other bytes named
///   above, or `^`, `|`, a lone backtick — is refused by `NamedNode::new`'s
///   IRI validation, also invoked from `resolve`, with "Invalid IRI code
///   point" (the same rejection `http::tests::iri_breaking_path_is_400`
///   exercises for a raw `<` and space). This holds regardless of whether
///   `Url::path` happens to percent-encode that particular byte or leaves it
///   untouched — either way it never becomes part of a stored graph IRI.
///
/// So no request carrying one of these raw shapes ever names a stored
/// resource, and there is no real graph IRI for the WHATWG-normalized form to
/// be mistaken for a different one. This function's safety rests on both
/// checks staying exactly as strict as they are: loosening
/// `is_normalization_stable` or the IRI validation to accept any of these
/// shapes as ordinary path content would reopen the re-targeting this
/// comparison exists to close, even though nothing in this function would
/// have changed.
///
/// None of this touches percent-escapes the client itself chose to send:
/// those pass through `Url::path` unchanged, so a proof minted for `/a%41`
/// still does not verify against a request to `/a%2541` — a *different*
/// resource, per `derive_htu`'s doc comment — and a client signing `/a%2541`
/// for a request to `/a%2541` still matches exactly.
///
/// Either side failing to parse as a URL (the proof's claimed `htu` is
/// attacker-controlled and need not be one) is treated as a mismatch, not a
/// separate error — the caller already turns "not the same resource" into
/// the one `DpopInvalid` rejection.
fn htu_names_the_same_resource(proof_htu: &str, expected: &str) -> bool {
    fn wire_path(s: &str) -> Option<String> {
        Some(url::Url::parse(s).ok()?.path().to_string())
    }
    match (wire_path(proof_htu), wire_path(expected)) {
        (Some(p), Some(e)) => p == e,
        _ => false,
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

    // `dpop-verifier` has now checked the proof's `htu` against ours, but
    // only through its normalizing comparison, which erases the trailing
    // slash that separates a container from a resource in this pod. Redo it
    // exactly, on the signed claim (see `verified_htu_claim` and
    // `htu_names_the_same_resource`), and reject with the same
    // `DpopInvalid` the crate's own htu mismatch produces — the middleware
    // answers 401 either way.
    if !htu_names_the_same_resource(&verified_htu_claim(proof)?, htu) {
        return Err(AuthError::DpopInvalid(
            "dpop proof htu does not match the request URL exactly".to_string(),
        ));
    }

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

    /// The trailing slash is what separates a container from a resource
    /// here, and `dpop-verifier`'s `normalize_htu` drops it — so on its
    /// comparison alone a proof minted for `/foo` verifies against a request
    /// for `/foo/` and vice versa. Both directions must be rejected: the
    /// dangerous one is a signed `PUT /.aux/acl/foo` re-delivered as
    /// `PUT /.aux/acl/foo/`, which would write the body as the *container's*
    /// ACL, naming no governed IRI and locking the subtree out for good.
    #[tokio::test]
    async fn trailing_slash_difference_is_rejected_in_both_directions() {
        let client = TestClient::new();
        let resource = client.mint_dpop("https://pod.toph.so/foo", "PUT", 1_000, "jti-slash-1");
        assert!(verify_dpop(
            &resource,
            "https://pod.toph.so/foo/",
            "PUT",
            &client.jkt(),
            1_010
        )
        .await
        .is_err());

        let container = client.mint_dpop("https://pod.toph.so/foo/", "PUT", 1_000, "jti-slash-2");
        assert!(verify_dpop(
            &container,
            "https://pod.toph.so/foo",
            "PUT",
            &client.jkt(),
            1_010
        )
        .await
        .is_err());

        // The exact scenario the fix exists for: a proof for the resource's
        // ACL must not authorize a write to the container's ACL.
        let acl = client.mint_dpop("https://pod.toph.so/.aux/acl/foo", "PUT", 1_000, "jti-slash-3");
        assert!(verify_dpop(
            &acl,
            "https://pod.toph.so/.aux/acl/foo/",
            "PUT",
            &client.jkt(),
            1_010
        )
        .await
        .is_err());
    }

    /// The other half of the same boundary: tightening the comparison must
    /// not start rejecting correctly-signed proofs. A container path (the
    /// shape the fix is about), a plain resource and an auxiliary all keep
    /// working when the proof names them exactly.
    #[tokio::test]
    async fn exact_htu_still_passes_for_resource_container_and_auxiliary() {
        let _guard = test_lock().lock().await;
        let client = TestClient::new();
        for (i, htu) in [
            "https://pod.toph.so/foo",
            "https://pod.toph.so/box/",
            "https://pod.toph.so/",
            "https://pod.toph.so/.aux/acl/foo",
            "https://pod.toph.so/.aux/acl/box/",
        ]
        .iter()
        .enumerate()
        {
            let jti = format!("jti-exact-{i}");
            let proof = client.mint_dpop(htu, "GET", 1_000, &jti);
            assert!(
                verify_dpop(&proof, htu, "GET", &client.jkt(), 1_010)
                    .await
                    .is_ok(),
                "exact htu {htu} must still verify"
            );
        }
    }

    /// A client signs the URL as it goes on the wire, and `derive_htu` now
    /// hands `verify_dpop` that same wire form — so a percent-encoded path
    /// verifies for the request it was actually signed for, with no decoding
    /// step on either side. Both an escape the `url` crate would itself
    /// produce (`%C3%A9`) and one it would not (`%41`, a plain `A`) must work;
    /// before this fix the latter was answered `401` even for the honest
    /// client, because `dpop-verifier` compared the still-encoded `%41`
    /// against a `derive_htu` that had already decoded it to `A`.
    #[tokio::test]
    async fn a_percent_encoded_path_verifies_for_the_request_it_was_signed_for() {
        let _guard = test_lock().lock().await;
        let client = TestClient::new();
        for (i, htu) in [
            "https://pod.toph.so/caf%C3%A9",
            "https://pod.toph.so/a%41",
            "https://pod.toph.so/a%2541",
            "https://pod.toph.so/a%2Fb",
        ]
        .iter()
        .enumerate()
        {
            let jti = format!("jti-pct-{i}");
            let proof = client.mint_dpop(htu, "GET", 1_000, &jti);
            assert!(
                verify_dpop(&proof, htu, "GET", &client.jkt(), 1_010)
                    .await
                    .is_ok(),
                "wire-form htu {htu} must verify for its own request"
            );
        }
    }

    /// A percent-escape difference in the path is a mismatch, full stop: this
    /// comparison never decodes its way to an equivalence. `/a%41` and
    /// `/a%2541` name different resources here — the handlers read them as
    /// `/aA` and `/a%41` — so a proof for one must not verify against the
    /// other, in either direction.
    ///
    /// `dpop-verifier`'s own comparison rejects these too, because
    /// `normalize_htu` preserves percent-escapes; this pins the property at
    /// the layer that has to hold it whatever the crate does. The `%25`
    /// redirect itself lived one level up, in `derive_htu`: while that handed
    /// `verify_dpop` the percent-DECODED graph IRI, a request to `/a%2541`
    /// arrived here already decoded to `/a%41` and matched a proof minted for
    /// `/a%41` at *both* comparisons. That defect is pinned end to end by
    /// `http::tests::a_proof_for_one_acl_cannot_be_redirected_by_a_double_escape`.
    #[tokio::test]
    async fn a_percent_encoded_proof_cannot_be_redirected_through_a_double_escape() {
        let client = TestClient::new();
        let plain = client.mint_dpop("https://pod.toph.so/a%41", "PUT", 1_000, "jti-pct25-1");
        assert!(verify_dpop(
            &plain,
            "https://pod.toph.so/a%2541",
            "PUT",
            &client.jkt(),
            1_010
        )
        .await
        .is_err());

        let doubled = client.mint_dpop("https://pod.toph.so/a%2541", "PUT", 1_000, "jti-pct25-2");
        assert!(verify_dpop(
            &doubled,
            "https://pod.toph.so/a%41",
            "PUT",
            &client.jkt(),
            1_010
        )
        .await
        .is_err());

        // The shape it matters for: a signed ACL write must not be re-targeted
        // at the ACL of a different resource.
        let acl = client.mint_dpop(
            "https://pod.toph.so/.aux/acl/a%41",
            "PUT",
            1_000,
            "jti-pct25-3",
        );
        assert!(verify_dpop(
            &acl,
            "https://pod.toph.so/.aux/acl/a%2541",
            "PUT",
            &client.jkt(),
            1_010
        )
        .await
        .is_err());
    }

    /// The tightened check compares only the path; scheme/host/port are left
    /// to `dpop-verifier`'s own RFC-3986 normalization. A proof minted with
    /// an explicit default port (`:443`) must still verify against a request
    /// `htu` that omits it — before this fix, comparing the whole URL
    /// byte-for-byte rejected this even though `dpop-verifier` itself (and
    /// `solid-client-authn-js`, which elides default ports via `new URL()`)
    /// treats the two as identical.
    #[tokio::test]
    async fn explicit_default_port_in_proof_htu_still_verifies() {
        let _guard = test_lock().lock().await;
        let client = TestClient::new();
        let proof = client.mint_dpop("https://pod.toph.so:443/foo", "GET", 1_000, "jti-port");
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

    /// Same reasoning, for host casing: `dpop-verifier` lowercases the host
    /// before comparing, so a proof minted against a differently-cased host
    /// must still verify. Comparing the whole URL would have rejected this.
    #[tokio::test]
    async fn differently_cased_host_in_proof_htu_still_verifies() {
        let _guard = test_lock().lock().await;
        let client = TestClient::new();
        let proof = client.mint_dpop("https://POD.TOPH.SO/foo", "GET", 1_000, "jti-case");
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
