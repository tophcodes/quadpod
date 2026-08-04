//! The signing key set: a private JWKS file, loaded or generated, and the
//! signing primitive every minted token goes through. The first key in the
//! set signs; every key is published. This file is the only place that
//! reads or writes the key file.

use std::collections::BTreeMap;
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwt::JwtPayload;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Why a key file could not become a usable key set. Any variant refuses
/// the start: a pod signing with a key other than the configured one looks
/// exactly like a correct one until verification fails elsewhere.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("reading {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not a JWK set: {reason}")]
    Malformed {
        path: std::path::PathBuf,
        reason: String,
    },
    #[error("{path} holds no keys")]
    Empty { path: std::path::PathBuf },
}

/// The pod's signing keys, in publication order: the first key signs, all
/// keys are served in the public JWKS. Every key has a `kid` — one missing
/// in the file gets its RFC 7638 thumbprint at load time, so the `kid` is
/// stable across restarts and deterministic for the same key. Every key is
/// `EC` or `RSA`: a key of any other type is refused at load time rather than
/// published with no algorithm the pod could sign it with.
pub struct KeySet {
    keys: Vec<josekit::jwk::Jwk>,
}

impl KeySet {
    /// The key set at `path`. A missing file is generated — one ES256
    /// (P-256) key, written 0600 — mirroring `--rdf-store rocksdb:` creating
    /// its directory. An existing file, read-only included, is never
    /// rewritten.
    pub fn load_or_generate(path: &Path) -> Result<Self, KeyError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut jwk =
                    josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P256)
                        .map_err(|e| KeyError::Malformed {
                            path: path.into(),
                            reason: e.to_string(),
                        })?;
                jwk.set_algorithm("ES256");
                jwk.set_key_id(thumbprint(&jwk));
                let body = serde_json::json!({ "keys": [&jwk] }).to_string();
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| KeyError::Io {
                        path: path.into(),
                        source: e,
                    })?;
                f.write_all(body.as_bytes()).map_err(|e| KeyError::Io {
                    path: path.into(),
                    source: e,
                })?;
                return Ok(Self { keys: vec![jwk] });
            }
            Err(e) => {
                return Err(KeyError::Io {
                    path: path.into(),
                    source: e,
                })
            }
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| KeyError::Malformed {
                path: path.into(),
                reason: e.to_string(),
            })?;
        let raw = parsed
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| KeyError::Malformed {
                path: path.into(),
                reason: "no `keys` array".into(),
            })?;
        let mut keys = Vec::new();
        for v in raw {
            let map = v.as_object().ok_or_else(|| KeyError::Malformed {
                path: path.into(),
                reason: "key is not an object".into(),
            })?;
            let mut jwk =
                josekit::jwk::Jwk::from_map(map.clone()).map_err(|e| KeyError::Malformed {
                    path: path.into(),
                    reason: e.to_string(),
                })?;
            // Only key types this pod can sign with and thumbprint per RFC
            // 7638 are admitted, so the rest of the crate may assume it: an
            // `oct` or `OKP` key would otherwise reach `sign_jwt` and the
            // published JWKS with no algorithm behind it.
            if !matches!(jwk.key_type(), "EC" | "RSA") {
                return Err(KeyError::Malformed {
                    path: path.into(),
                    reason: format!("unsupported key type {}", jwk.key_type()),
                });
            }
            // A key can claim `EC`/`RSA` and still be missing the public
            // members (`crv`/`x`/`y`, `e`/`n`) those types require: deriving
            // the public half is the same check `public_jwks` needs later,
            // so doing it now turns a would-be runtime panic there into a
            // refusal at start.
            jwk.to_public_key().map_err(|e| KeyError::Malformed {
                path: path.into(),
                reason: e.to_string(),
            })?;
            if jwk.key_id().is_none() {
                let t = thumbprint(&jwk);
                jwk.set_key_id(t);
            }
            keys.push(jwk);
        }
        let set = Self { keys };
        if set.keys.is_empty() {
            return Err(KeyError::Empty { path: path.into() });
        }
        Ok(set)
    }

    /// The public half of every key, as an RFC 7517 key set ready to serve:
    /// private members (`d`, RSA CRT parameters) are stripped before
    /// serialization. `kid` and `alg` are deliberately restored after that
    /// stripping, since josekit's public-key derivation drops them too but
    /// consumers of the published set need both to pick the right key.
    pub fn public_jwks(&self) -> serde_json::Value {
        let keys: Vec<serde_json::Value> = self
            .keys
            .iter()
            .map(|k| {
                let mut public = k.to_public_key().expect(
                    "load_or_generate refuses any key to_public_key cannot derive from",
                );
                if let Some(kid) = k.key_id() {
                    public.set_key_id(kid);
                }
                if let Some(alg) = k.algorithm() {
                    public.set_algorithm(alg);
                }
                serde_json::to_value(&public).expect("a Jwk serializes")
            })
            .collect();
        serde_json::json!({ "keys": keys })
    }

    /// The distinct signature algorithms of the set, for the discovery
    /// document's `id_token_signing_alg_values_supported`.
    pub fn signing_algs(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for k in &self.keys {
            if let Some(alg) = k.algorithm() {
                if !out.iter().any(|a| a == alg) {
                    out.push(alg.to_string());
                }
            }
        }
        out
    }

    /// `payload` as a compact JWS signed by the active (first) key, the
    /// header carrying `typ`, the key's `alg` and its `kid`.
    pub(crate) fn sign_jwt(&self, payload: &JwtPayload) -> String {
        let _ = payload;
        todo!()
    }
}

/// The RFC 7638 thumbprint of `jwk`, base64url-encoded without padding — the
/// `kid` a key in the file gets when it carries none.
///
/// RFC 7638 §3.2 fixes the required members per key type: `crv`, `kty`, `x`,
/// `y` for EC, `e`, `kty`, `n` for RSA. Those members and only those, as a
/// JSON object with no whitespace and keys in lexicographic order, SHA-256'd
/// — a `BTreeMap` through `serde_json` emits exactly that, the same
/// construction the verifying side (`crate::auth::dpop`, `dpop-verifier`)
/// uses, so a `kid` derived here is the same string a client computing this
/// key's thumbprint arrives at.
///
/// Only `EC` and `RSA` keys reach this function: a generated key is `EC`, and
/// a loaded one has had its type checked before it gets here.
fn thumbprint(jwk: &josekit::jwk::Jwk) -> String {
    let members: &[&str] = match jwk.key_type() {
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        other => unreachable!("no thumbprint rule for key type {other}"),
    };
    let canonical: BTreeMap<&str, &str> = members
        .iter()
        .filter_map(|name| {
            jwk.parameter(name)
                .and_then(|v| v.as_str())
                .map(|v| (*name, v))
        })
        .collect();
    let canonical_json = serde_json::to_string(&canonical)
        .expect("a BTreeMap<&str, &str> always serializes as JSON");
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_json.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("op-keys-{}.json", uuid::Uuid::new_v4()))
    }

    #[test]
    fn a_missing_file_is_generated_with_0600_and_one_es256_key() {
        use std::os::unix::fs::PermissionsExt;
        let p = temp_path();
        let set = KeySet::load_or_generate(&p).expect("generates");
        assert_eq!(set.keys.len(), 1);
        assert_eq!(set.keys[0].curve(), Some("P-256"));
        assert!(
            set.keys[0].key_id().is_some(),
            "generated key carries a kid"
        );
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "private key file is 0600");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn the_kid_is_stable_across_two_loads() {
        let p = temp_path();
        let a = KeySet::load_or_generate(&p).unwrap();
        let b = KeySet::load_or_generate(&p).unwrap();
        assert_eq!(a.keys[0].key_id(), b.keys[0].key_id());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn an_existing_file_is_never_rewritten_and_a_kidless_key_gets_its_thumbprint() {
        use std::os::unix::fs::PermissionsExt;
        // A file whose key has no kid: the loaded set has one (the RFC 7638
        // thumbprint), the bytes on disk stay exactly as written.
        let mut jwk =
            josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
        jwk.set_algorithm("ES256");
        let body = serde_json::json!({ "keys": [jwk] }).to_string();
        let p = temp_path();
        std::fs::write(&p, &body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        let set = KeySet::load_or_generate(&p).expect("loads read-only");
        assert!(
            set.keys[0].key_id().is_some(),
            "thumbprint assigned in memory"
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), body, "file untouched");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_malformed_file_refuses_with_its_path_in_the_error() {
        let p = temp_path();
        std::fs::write(&p, "not json").unwrap();
        // `.err().expect(…)` rather than `unwrap_err()`: the latter would
        // need `KeySet: Debug`, i.e. a Debug rendering of private key
        // material.
        let err = KeySet::load_or_generate(&p).err().expect("refuses");
        assert!(matches!(err, KeyError::Malformed { .. }), "{err}");
        assert!(err.to_string().contains(p.to_str().unwrap()));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_key_of_an_unsignable_type_refuses_by_name() {
        let p = temp_path();
        std::fs::write(&p, r#"{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}"#).unwrap();
        let err = KeySet::load_or_generate(&p).err().expect("refuses");
        assert!(matches!(err, KeyError::Malformed { .. }), "{err}");
        assert!(err.to_string().contains("oct"), "{err}");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn an_empty_key_set_refuses() {
        let p = temp_path();
        std::fs::write(&p, r#"{"keys":[]}"#).unwrap();
        assert!(matches!(
            KeySet::load_or_generate(&p).err().expect("refuses"),
            KeyError::Empty { .. }
        ));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn public_jwks_strips_private_members_and_keeps_kid() {
        let p = temp_path();
        let set = KeySet::load_or_generate(&p).unwrap();
        let jwks = set.public_jwks();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        let k = keys[0].as_object().unwrap();
        assert!(k.contains_key("kid") && k.contains_key("kty") && k.contains_key("x"));
        for private in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(!k.contains_key(private), "leaked `{private}`");
        }
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn signing_algs_reports_the_set() {
        let p = temp_path();
        let set = KeySet::load_or_generate(&p).unwrap();
        assert_eq!(set.signing_algs(), vec!["ES256".to_string()]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_key_missing_its_public_members_refuses_at_load() {
        let p = temp_path();
        std::fs::write(&p, r#"{"keys":[{"kty":"EC","kid":"x","alg":"ES256"}]}"#).unwrap();
        let err = KeySet::load_or_generate(&p).err().expect("refuses");
        assert!(matches!(err, KeyError::Malformed { .. }), "{err}");
        std::fs::remove_file(&p).ok();
    }
}
