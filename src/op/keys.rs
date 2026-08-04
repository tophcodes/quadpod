//! The signing key set: a private JWKS file, loaded or generated, and the
//! signing primitive every minted token goes through. The first key in the
//! set signs; every key is published. This file is the only place that
//! reads or writes the key file.

use std::path::Path;

use josekit::jwt::JwtPayload;
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
/// stable across restarts and deterministic for the same key.
pub struct KeySet {
    keys: Vec<josekit::jwk::Jwk>,
}

impl KeySet {
    /// The key set at `path`. A missing file is generated — one ES256
    /// (P-256) key, written 0600 — mirroring `--rdf-store rocksdb:` creating
    /// its directory. An existing file, read-only included, is never
    /// rewritten.
    pub fn load_or_generate(path: &Path) -> Result<Self, KeyError> {
        let _ = path;
        let _ = &Self { keys: Vec::new() }.keys;
        todo!()
    }

    /// The public half of every key, as an RFC 7517 key set ready to serve:
    /// private members (`d`, RSA CRT parameters) are stripped before
    /// serialization.
    pub fn public_jwks(&self) -> serde_json::Value {
        todo!()
    }

    /// The distinct signature algorithms of the set, for the discovery
    /// document's `id_token_signing_alg_values_supported`.
    pub fn signing_algs(&self) -> Vec<String> {
        todo!()
    }

    /// `payload` as a compact JWS signed by the active (first) key, the
    /// header carrying `typ`, the key's `alg` and its `kid`.
    pub(crate) fn sign_jwt(&self, payload: &JwtPayload) -> String {
        let _ = payload;
        todo!()
    }
}
