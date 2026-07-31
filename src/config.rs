//! Process configuration: command-line flags with environment-variable
//! fallbacks. `clap` provides the precedence (flag > env > default); there is
//! deliberately no hand-written precedence logic on top of it.

use std::collections::HashSet;
use std::net::SocketAddr;

use clap::builder::BoolishValueParser;
use clap::Parser;
use oxigraph::model::NamedNode;
use thiserror::Error;

use crate::auth::AuthConfig;
use crate::space::{SpaceError, StorageSpace};

#[derive(Debug, Error, PartialEq)]
#[error("owner WebID must be an absolute IRI")]
pub struct InvalidOwnerWebId;

#[derive(Parser, Debug, Clone)]
#[command(name = "sparql-pod", about = "A SPARQL-authoritative Solid pod")]
pub struct Config {
    /// Public base URI of this pod. Absolute, with a trailing slash. All
    /// minted URLs and the DPoP `htu` derive from this, never from the socket.
    ///
    /// Held as the space it denotes rather than as the text of it: the value
    /// is checked where it is parsed, so a `Config` that exists has a usable
    /// base URI and no later caller has to ask again.
    #[arg(
        long,
        env = "POD_BASE_URI",
        default_value = "http://localhost:3000/",
        value_parser = parse_space
    )]
    pub base_uri: StorageSpace,

    /// WebID of the pod owner. Required: the root ACL is provisioned for it,
    /// and a pod with no known owner could only be all-open or all-closed.
    ///
    /// A `NamedNode` for the same reason `base_uri` is a `StorageSpace`, and
    /// one more: provisioning interpolates it into SPARQL, so the type is what
    /// keeps an unchecked string from ever reaching that call.
    #[arg(long, env = "POD_OWNER_WEBID", value_parser = parse_owner_webid)]
    pub owner_webid: NamedNode,

    /// Trusted access-token issuer. Repeatable; may also be given as a
    /// comma-separated list via the environment variable. Empty = open
    /// federation (any issuer may proceed to the WebID-issuer binding check).
    #[arg(long = "trusted-issuer", env = "POD_TRUSTED_ISSUERS", value_delimiter = ',')]
    pub trusted_issuers: Vec<String>,

    /// Expected access-token `aud` value. Unset = no audience check.
    #[arg(long, env = "POD_EXPECTED_AUDIENCE")]
    pub expected_audience: Option<String>,

    /// A host the operator vouches for: the private-IP filter and the
    /// https-only rule do not apply to it. Repeatable. `host` opens every
    /// port on that host; `host:port` opens only that port. Everything else
    /// — redirect refusal, IP pinning, body cap, timeout — still applies.
    /// Pair it with `--trusted-issuer` so an untrusted issuer is rejected
    /// before any fetch is attempted.
    #[arg(long = "allow-insecure-host", env = "POD_ALLOW_INSECURE_HOSTS", value_delimiter = ',')]
    pub allow_insecure_hosts: Vec<String>,

    /// Address to bind. Plain HTTP — keep it behind the reverse proxy.
    #[arg(long, env = "POD_LISTEN", default_value = "127.0.0.1:3000")]
    pub listen: SocketAddr,

    /// Overwrite the root ACL with the owner's default grant on startup,
    /// even if one already exists. The only way back from a root ACL that
    /// grants nobody (not even the owner) Control — see
    /// `wac::provision::provision_root_acl`. Off by default: every other
    /// start must leave an operator's or owner's own root ACL exactly as
    /// they left it. Accepts boolish values: 1, 0, true, false, yes, no, on,
    /// off (case-insensitive). Both `--reset-root-acl` (bare flag) and
    /// `POD_RESET_ROOT_ACL=1` work as documented.
    #[arg(
        long,
        env = "POD_RESET_ROOT_ACL",
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    pub reset_root_acl: bool,

    /// A TOML file supplying any of the values below. Nothing is loaded unless
    /// this names a path: there is no search path, so a pod cannot start
    /// against a file that is invisible to whoever reads the command line. A
    /// path that is named but unreadable, or is not valid TOML, refuses the
    /// start rather than falling back to flags alone.
    #[arg(long, env = "POD_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Where the RDF lives. `memory` keeps it in this process, so every restart
    /// is a fresh pod. `rocksdb:<dir>` holds it in `<dir>`, which exactly one
    /// process may open at a time — root spec §16 ADR-7.
    #[arg(long, env = "POD_RDF_STORE", default_value = "memory")]
    pub rdf_store: String,

    /// Where non-RDF resource bytes live. `memory` keeps them in process,
    /// matching the triple store, so the pod is uniformly ephemeral rather
    /// than making blobs outlive the triples describing them.
    /// `local:<dir>` mirrors the URL tree under `<dir>`, so it can be read and
    /// backed up with ordinary tools.
    #[arg(long, env = "POD_BLOB_STORE", default_value = "memory")]
    pub blob_store: String,

    /// Largest request body accepted, in bytes, for every write path. axum
    /// applies a 2 MiB default of its own when nothing is set; naming it here
    /// makes a `413` a statement about this pod rather than a framework
    /// artefact. The body is buffered whole in memory, which is the real
    /// ceiling behind this number.
    #[arg(long, env = "POD_MAX_BODY_BYTES", default_value_t = 64 * 1024 * 1024)]
    pub max_body_bytes: usize,
}

/// Where `--base-uri` becomes the space it names.
///
/// A `value_parser` rather than a check after the parse, so that a bad value
/// is a clap error like any other — which is what lets [`blame_file`] point at
/// the config file when the value came from there. A check in `main.rs` cannot
/// be pointed anywhere, because by then the error is a string.
fn parse_space(s: &str) -> Result<StorageSpace, SpaceError> {
    StorageSpace::new(s.to_string())
}

/// Where `--owner-webid` becomes an IRI. Same bargain as [`parse_space`].
fn parse_owner_webid(s: &str) -> Result<NamedNode, InvalidOwnerWebId> {
    NamedNode::new(s).map_err(|_| InvalidOwnerWebId)
}

/// The `--config` file as it is written, before any of it reaches clap.
///
/// Every field is optional because the file supplies what it wants and clap
/// settles the rest. `deny_unknown_fields` is what makes a mistyped key refuse
/// the start: a pod that runs with less configuration than the operator wrote
/// is indistinguishable from one configured correctly, and the difference
/// surfaces only as failing requests.
///
/// The field names are `Config`'s own, so there is no second vocabulary to keep
/// in sync with the flags. The *types* differ where TOML has a better one —
/// `max_body_bytes` is an integer here and a string on the command line — which
/// is why [`FileConfig::as_defaults`] exists rather than a direct assignment.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    base_uri: Option<String>,
    owner_webid: Option<String>,
    trusted_issuers: Option<Vec<String>>,
    expected_audience: Option<String>,
    allow_insecure_hosts: Option<Vec<String>>,
    listen: Option<String>,
    reset_root_acl: Option<bool>,
    rdf_store: Option<String>,
    blob_store: Option<String>,
    max_body_bytes: Option<u64>,
}

impl FileConfig {
    /// Read and parse `path`. Unreadable, or not TOML, or carrying a key this
    /// binary does not know: all three are the same answer, an error that
    /// refuses the start.
    fn read(path: &std::path::Path) -> Result<Self, clap::Error> {
        let _ = path;
        todo!("2026-07-31-cli-config-design.md §4, §4.1")
    }

    /// Every key the file set, rendered as the strings clap will parse, keyed
    /// by the long flag name.
    ///
    /// Rendering to strings is deliberate: the file's values then travel the
    /// same `value_parser` as a typed flag, so a bad `listen` in TOML is caught
    /// by the parser that catches a bad `--listen`, and the file cannot reach
    /// a field by a route that skips validation. `Vec<String>` covers both the
    /// scalar arguments and the repeatable ones without a second shape.
    fn as_defaults(&self) -> std::collections::BTreeMap<&'static str, Vec<String>> {
        todo!("2026-07-31-cli-config-design.md §5")
    }
}

/// Pass 1: the `--config` path, from the argv or `POD_CONFIG`.
///
/// Parses with `ignore_errors`, because it runs before anything else is known
/// and must survive an argv it cannot fully understand — including a missing
/// required `--owner-webid`. clap's error path still applies environment
/// variables, so `POD_CONFIG` is seen even though this parse fails.
fn config_path_from<I, T>(argv: I) -> Option<std::path::PathBuf>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let _ = argv.into_iter();
    todo!("2026-07-31-cli-config-design.md §5 step 1")
}

/// Pass 2: `Config`'s own command, with the file's values installed as defaults.
///
/// This is the whole precedence mechanism. clap already resolves flag > env >
/// default; putting the file in the default slot lands it exactly one rung
/// below the environment without a line of merge logic, and a flag added later
/// picks up file support from the same derive that gives it its flag.
fn command_with(defaults: std::collections::BTreeMap<&'static str, Vec<String>>) -> clap::Command {
    let _ = defaults;
    todo!("2026-07-31-cli-config-design.md §5 step 2")
}

/// Re-point a clap error at the file that actually caused it.
///
/// A file-supplied value arrives as a default, so clap phrases its complaint in
/// terms of a flag the operator never typed. An error naming an argument the
/// file supplied gets the path and the TOML key prefixed; anything else is
/// passed through exactly as clap wrote it.
fn blame_file(
    err: clap::Error,
    path: &std::path::Path,
    from_file: &std::collections::BTreeMap<&'static str, Vec<String>>,
) -> clap::Error {
    let _ = (err, path, from_file);
    todo!("2026-07-31-cli-config-design.md §5.1")
}

impl Config {
    /// This process's configuration, from the real argv and environment.
    pub fn load() -> Result<Self, clap::Error> {
        todo!("2026-07-31-cli-config-design.md §5")
    }

    /// [`Config::load`] against a supplied argv, which is what makes the file
    /// reachable from a test: the path arrives as `--config <tmpfile>` rather
    /// than from a fixed location.
    pub fn try_load_from<I, T>(argv: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let _ = argv.into_iter();
        todo!("2026-07-31-cli-config-design.md §5")
    }

    pub fn auth_config(&self) -> AuthConfig {
        let set: HashSet<String> = self
            .trusted_issuers
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        AuthConfig {
            trusted_issuers: if set.is_empty() { None } else { Some(set) },
            expected_audience: self.expected_audience.clone(),
        }
    }

    /// The outbound-fetch posture for this process: the SSRF-safe default
    /// plus whatever hosts the operator named on the command line. Entries
    /// are trimmed and empty ones dropped before parsing, mirroring
    /// `auth_config()`'s treatment of `trusted_issuers` — a comma-separated
    /// env value like `"localhost:3001, css.local,,"` must not leave
    /// whitespace- or empty-string entries in the set that can never match
    /// a URL host.
    pub fn fetch_policy(&self) -> crate::auth::safe_fetch::FetchPolicy {
        self.try_fetch_policy().0
    }

    /// Same as [`Config::fetch_policy`], but also returns every entry that
    /// could not be understood — for `main.rs`, which must refuse to start
    /// rather than run with fewer hosts than the operator configured. Since
    /// entries are trimmed and empty ones dropped right here (same
    /// `.map(str::trim).filter(|s| !s.is_empty())` as above), any rejected
    /// entry reaching `main.rs` was a real, non-blank string the operator
    /// typed — not comma-separated-list noise.
    pub fn try_fetch_policy(
        &self,
    ) -> (crate::auth::safe_fetch::FetchPolicy, Vec<String>) {
        crate::auth::safe_fetch::FetchPolicy::try_with_insecure_hosts(
            self.allow_insecure_hosts
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        )
    }

    /// The blob backend this process will use, or the operator-facing reason
    /// it cannot be built. Refusing to start beats starting with a backend
    /// that silently differs from the one configured.
    pub fn blobs(&self) -> Result<std::sync::Arc<dyn crate::blob::BlobStore>, String> {
        let spec = self.blob_store.trim();
        if spec == "memory" {
            return Ok(std::sync::Arc::new(crate::blob::ObjectStoreBlobs::in_memory()));
        }
        if let Some(dir) = spec.strip_prefix("local:") {
            return crate::blob::ObjectStoreBlobs::local(std::path::Path::new(dir))
                .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn crate::blob::BlobStore>)
                .map_err(|e| format!("--blob-store local: {e}"));
        }
        Err(format!(
            "--blob-store: expected `memory` or `local:<dir>`, got `{spec}`"
        ))
    }

    /// The triple store this process will use, or the operator-facing reason it
    /// cannot be built. Same bargain as [`Config::blobs`]: an unrecognised spec
    /// refuses the start, because a pod running on a backend other than the
    /// configured one looks exactly like a correct one until data is missing.
    ///
    /// Shares its name with the field it reads; the field is the spec string,
    /// this is the thing it names.
    pub fn rdf_store(&self) -> Result<std::sync::Arc<dyn crate::store::SparqlStore>, String> {
        let spec = self.rdf_store.trim();
        if spec == "memory" {
            return crate::store::OxigraphStore::in_memory()
                .map(|s| std::sync::Arc::new(s) as std::sync::Arc<dyn crate::store::SparqlStore>)
                .map_err(|e| format!("--rdf-store memory: {e}"));
        }
        if let Some(dir) = spec.strip_prefix("rocksdb:") {
            return crate::store::OxigraphStore::open(std::path::Path::new(dir))
                .map(|s| std::sync::Arc::new(s) as std::sync::Arc<dyn crate::store::SparqlStore>)
                .map_err(|e| format!("--rdf-store rocksdb: {e}"));
        }
        Err(format!(
            "--rdf-store: expected `memory` or `rocksdb:<dir>`, got `{spec}`"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use crate::space::GraphName;

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_parse_from(std::iter::once("sparql-pod").chain(args.iter().copied()))
    }

    #[test]
    fn owner_webid_is_required() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn flags_populate_every_field() {
        let c = parse(&[
            "--base-uri", "https://pod.toph.so/",
            "--owner-webid", "https://alice.example/card#me",
            "--trusted-issuer", "https://idp.example/",
            "--trusted-issuer", "https://other.example/",
            "--expected-audience", "https://pod.toph.so/",
            "--listen", "0.0.0.0:8080",
        ]).expect("parses");
        assert_eq!(c.base_uri.root().graph_iri(), "https://pod.toph.so/");
        assert_eq!(c.owner_webid, "https://alice.example/card#me");
        assert_eq!(c.trusted_issuers.len(), 2);
        assert_eq!(c.expected_audience.as_deref(), Some("https://pod.toph.so/"));
        assert_eq!(c.listen.to_string(), "0.0.0.0:8080");
    }

    // Plan 5's lesson: a set-but-empty issuer list must mean "open federation",
    // not "trust nobody" (which would be a total auth lockout).
    #[test]
    fn empty_issuer_list_is_open_federation() {
        let c = parse(&["--owner-webid", "https://alice.example/card#me"]).unwrap();
        assert!(c.auth_config().trusted_issuers.is_none());
    }

    #[test]
    fn populated_issuer_list_becomes_the_allowlist() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--trusted-issuer", "https://idp.example/",
        ]).unwrap();
        let set = c.auth_config().trusted_issuers.expect("allowlist");
        assert!(set.contains("https://idp.example/"));
    }

    // The rejection is the parser's, which is what lets `blame_file` name the
    // config file when the value came from there — a check after the parse
    // could only name a flag.
    #[test]
    fn non_iri_owner_webid_is_rejected() {
        assert!(parse(&["--owner-webid", "not an iri"]).is_err());
    }

    #[test]
    fn iri_owner_webid_is_accepted() {
        let c = parse(&["--owner-webid", "https://alice.example/card#me"]).unwrap();
        assert_eq!(c.owner_webid.as_str(), "https://alice.example/card#me");
    }

    #[test]
    fn insecure_hosts_are_repeatable_and_default_empty() {
        let c = parse(&["--owner-webid", "https://alice.example/card#me"]).unwrap();
        assert!(c.allow_insecure_hosts.is_empty());

        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--allow-insecure-host", "localhost:3001",
            "--allow-insecure-host", "css.local",
        ]).unwrap();
        assert_eq!(c.allow_insecure_hosts, vec!["localhost:3001", "css.local"]);
    }

    // The comma-separated env form (`POD_ALLOW_INSECURE_HOSTS=a, b,,`) is what the docs
    // advertise, and clap's `value_delimiter` does not trim or drop what it splits: a
    // whitespace- or empty-string entry must not survive into the working fetch policy, and
    // the startup warning (built from `insecure_host_entries()`) must not confirm a setting
    // that does nothing — mirrors `auth_config()`'s `.map(str::trim).filter(|s|
    // !s.is_empty())` treatment of `trusted_issuers`.
    #[test]
    fn fetch_policy_trims_and_drops_empty_insecure_host_entries() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--allow-insecure-host", "localhost:3001, css.local,,",
        ]).unwrap();
        assert_eq!(
            c.allow_insecure_hosts,
            vec!["localhost:3001", " css.local", "", ""],
            "clap's value_delimiter itself does not trim or filter"
        );
        assert_eq!(
            c.fetch_policy().insecure_host_entries(),
            vec!["css.local".to_string(), "localhost:3001".to_string()],
            "the built policy must reflect only the entries actually understood"
        );
    }

    // A malformed or ambiguous entry must be reported by `try_fetch_policy`,
    // not silently dropped — `main.rs` uses this to refuse to start rather
    // than run with fewer hosts than the operator configured.
    #[test]
    fn try_fetch_policy_reports_entries_it_could_not_understand() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--allow-insecure-host", "localhost:3001,localhost:99999",
        ]).unwrap();
        let (policy, rejected) = c.try_fetch_policy();
        assert_eq!(rejected, vec!["localhost:99999".to_string()]);
        assert_eq!(
            policy.insecure_host_entries(),
            vec!["localhost:3001".to_string()],
            "the understood entry must still take effect alongside the reject"
        );
    }

    #[test]
    fn reset_root_acl_defaults_to_false() {
        let c = parse(&["--owner-webid", "https://alice.example/card#me"]).unwrap();
        assert!(!c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_bare_flag_is_true() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl",
        ]).unwrap();
        assert!(c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_with_true_value() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl", "true",
        ]).unwrap();
        assert!(c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_with_false_value() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl", "false",
        ]).unwrap();
        assert!(!c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_with_1_value() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl", "1",
        ]).unwrap();
        assert!(c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_with_0_value() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl", "0",
        ]).unwrap();
        assert!(!c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_with_yes_value() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl", "yes",
        ]).unwrap();
        assert!(c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_with_no_value() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl", "no",
        ]).unwrap();
        assert!(!c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_with_on_value() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl", "on",
        ]).unwrap();
        assert!(c.reset_root_acl);
    }

    #[test]
    fn reset_root_acl_with_off_value() {
        let c = parse(&[
            "--owner-webid", "https://alice.example/card#me",
            "--reset-root-acl", "off",
        ]).unwrap();
        assert!(!c.reset_root_acl);
    }

    #[test]
    fn blob_store_selects_a_backend_and_refuses_an_unknown_one() {
        let mut cfg = Config::parse_from(["sparql-pod", "--owner-webid", "https://a.example/#me"]);
        assert_eq!(cfg.blob_store, "memory", "the default matches the in-memory triple store");
        assert!(cfg.blobs().is_ok());

        let dir = std::env::temp_dir().join(format!("sparql-pod-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        cfg.blob_store = format!("local:{}", dir.display());
        assert!(cfg.blobs().is_ok());
        std::fs::remove_dir_all(&dir).ok();

        cfg.blob_store = "s3:bucket".into();
        assert!(cfg.blobs().is_err(), "an unimplemented backend must refuse to start");
        cfg.blob_store = "nonsense".into();
        assert!(cfg.blobs().is_err());
    }

    // axum's own default is 2 MiB and already applies to every write path.
    // Making it a flag is what turns a 413 into a decision.
    #[test]
    fn max_body_bytes_has_an_explicit_default() {
        let cfg = Config::parse_from(["sparql-pod", "--owner-webid", "https://a.example/#me"]);
        assert_eq!(cfg.max_body_bytes, 64 * 1024 * 1024);
    }

    // Mirrors `blob_store_selects_a_backend_and_refuses_an_unknown_one`. The
    // rejected `http://…` pins the unimplemented remote backend as a refusal
    // rather than leaving it to be assumed.
    #[test]
    fn rdf_store_selects_a_backend_and_refuses_an_unknown_one() {
        let mut cfg =
            Config::parse_from(["sparql-pod", "--owner-webid", "https://a.example/#me"]);
        assert_eq!(cfg.rdf_store, "memory", "the default is the in-memory store");
        assert!(cfg.rdf_store().is_ok());

        let dir = std::env::temp_dir()
            .join(format!("sparql-pod-cfg-store-{}", uuid::Uuid::new_v4()));
        cfg.rdf_store = format!("rocksdb:{}", dir.display());
        assert!(cfg.rdf_store().is_ok());
        std::fs::remove_dir_all(&dir).ok();

        cfg.rdf_store = "http://oxigraph:7878/".into();
        assert!(cfg.rdf_store().is_err(), "an unimplemented backend must refuse to start");
        cfg.rdf_store = "nonsense".into();
        assert!(cfg.rdf_store().is_err());
    }
}
