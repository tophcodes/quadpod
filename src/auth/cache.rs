//! The bound every pre-authentication cache in this module is held to.
//!
//! Both `http_jwks` and `webid_issuer` cache what they resolve, and both are
//! keyed by a string taken off an unverified credential: the token's `iss`
//! for one, its `webid` claim for the other. Neither key is the pod's to
//! choose, and with no `--trusted-issuer` allowlist configured neither is
//! even constrained, anyone running their own IdP writes both. A cache keyed
//! that way and never swept is memory an anonymous caller allocates.
//!
//! One derivation, used by both, because the two got different answers when
//! each held its own: `webid_issuer` was bounded and `http_jwks` was not, and
//! nothing said so. `http_jwks` is also the one reached FIRST, since a JWKS
//! is resolved before the WebID-issuer binding is checked, so the unbounded
//! half was the half in front.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cap on entries in any one of those caches.
///
/// Sized for the deployment this pod is for rather than for a public
/// federation hub: a pod serves one owner and the handful of issuers and
/// WebIDs that owner's applications actually use, so a thousand live entries
/// is far past the working set and still small enough that a full sweep is
/// nothing. Exceeding it is the signal that the keys are no longer a working
/// set at all.
pub(super) const MAX_CACHE_ENTRIES: usize = 1024;

/// Insert into a bounded cache, making room first if the map is at
/// [`MAX_CACHE_ENTRIES`]: expired entries go first, and if that frees nothing
/// the least recently fetched entry is evicted.
///
/// Eviction rather than refusal because the entry being inserted is the one
/// just proven live; the worst case is a cache miss, never unbounded memory.
///
/// `stamp` reads the `Instant` out of whatever the value happens to be, which
/// is what lets one function serve a positive cache (a payload beside its
/// timestamp) and a negative one (a bare timestamp) without either growing a
/// wrapper type for the sake of this call.
pub(super) fn insert_bounded<V>(
    map: &mut HashMap<String, V>,
    key: String,
    value: V,
    ttl: Duration,
    stamp: fn(&V) -> Instant,
) {
    if map.len() >= MAX_CACHE_ENTRIES && !map.contains_key(&key) {
        map.retain(|_, v| stamp(v).elapsed() < ttl);

        if map.len() >= MAX_CACHE_ENTRIES {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, v)| stamp(v))
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
    }

    map.insert(key, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(300);

    /// The property both callers depend on, asserted once here rather than
    /// once per caller: the map does not grow past the cap however many
    /// distinct keys arrive.
    #[test]
    fn a_bounded_cache_does_not_grow_past_its_cap() {
        let mut map: HashMap<String, Instant> = HashMap::new();
        for i in 0..MAX_CACHE_ENTRIES + 50 {
            insert_bounded(&mut map, format!("k{i}"), Instant::now(), TTL, |at| *at);
        }
        assert_eq!(map.len(), MAX_CACHE_ENTRIES);
    }

    /// Eviction must not fire on a key already present: refreshing an entry
    /// replaces it rather than displacing someone else's.
    #[test]
    fn refreshing_an_existing_entry_evicts_nothing() {
        let mut map: HashMap<String, (u32, Instant)> = HashMap::new();
        for i in 0..MAX_CACHE_ENTRIES {
            insert_bounded(
                &mut map,
                format!("k{i}"),
                (0, Instant::now()),
                TTL,
                |(_, at)| *at,
            );
        }

        insert_bounded(
            &mut map,
            "k0".to_string(),
            (7, Instant::now()),
            TTL,
            |(_, at)| *at,
        );

        assert_eq!(map.len(), MAX_CACHE_ENTRIES);
        assert_eq!(map["k0"].0, 7, "the refreshed value is the one held");
    }

    /// An expired entry is what the sweep is supposed to reclaim, so a map
    /// full of them makes room without evicting anything live.
    #[test]
    fn expired_entries_are_reclaimed_before_a_live_one_is_evicted() {
        let mut map: HashMap<String, Instant> = HashMap::new();
        for i in 0..MAX_CACHE_ENTRIES {
            insert_bounded(&mut map, format!("k{i}"), Instant::now(), TTL, |at| *at);
        }
        // A zero TTL makes every existing entry expired at the next insert,
        // which is the sweep's own condition rather than a simulated clock.
        insert_bounded(
            &mut map,
            "fresh".to_string(),
            Instant::now(),
            Duration::ZERO,
            |at| *at,
        );
        assert_eq!(map.len(), 1, "the sweep reclaimed the expired entries");
        assert!(map.contains_key("fresh"));
    }
}
