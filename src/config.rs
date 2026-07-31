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
        let text = std::fs::read_to_string(path).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::Io,
                format!("--config {}: {e}\n", path.display()),
            )
        })?;
        toml::from_str(&text).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("--config {}: {e}\n", path.display()),
            )
        })
    }

    /// Every key the file set, rendered as the strings clap will parse, keyed
    /// by argument id — `Config`'s field names, which is what `Command::mut_arg`
    /// takes. The id differs from the long flag for every multi-word one, by
    /// kebab-casing alone (`base_uri` / `--base-uri`) — except two, which are
    /// renamed outright: `trusted_issuers` (`--trusted-issuer`) and
    /// `allow_insecure_hosts` (`--allow-insecure-host`). [`blame_file`] takes
    /// its own long-flag-keyed map rather than this one because of those two.
    ///
    /// Rendering to strings is deliberate: the file's values then travel the
    /// same `value_parser` as a typed flag, so a bad `listen` in TOML is caught
    /// by the parser that catches a bad `--listen`, and the file cannot reach
    /// a field by a route that skips validation. `Vec<String>` covers both the
    /// scalar arguments and the repeatable ones without a second shape.
    fn as_defaults(&self) -> std::collections::BTreeMap<&'static str, Vec<String>> {
        let mut out = std::collections::BTreeMap::new();
        for (key, value) in [
            ("base_uri", &self.base_uri),
            ("owner_webid", &self.owner_webid),
            ("expected_audience", &self.expected_audience),
            ("listen", &self.listen),
            ("rdf_store", &self.rdf_store),
            ("blob_store", &self.blob_store),
        ] {
            if let Some(v) = value {
                out.insert(key, vec![v.clone()]);
            }
        }
        if let Some(v) = &self.trusted_issuers {
            out.insert("trusted_issuers", v.clone());
        }
        if let Some(v) = &self.allow_insecure_hosts {
            out.insert("allow_insecure_hosts", v.clone());
        }
        if let Some(v) = self.reset_root_acl {
            out.insert("reset_root_acl", vec![v.to_string()]);
        }
        if let Some(v) = self.max_body_bytes {
            out.insert("max_body_bytes", vec![v.to_string()]);
        }
        out
    }
}

/// Pass 1: the `--config` path, from the argv or `POD_CONFIG`.
///
/// Runs before anything else is known and must survive an argv it cannot
/// fully understand — including a missing required `--owner-webid` and flags
/// it has never heard of. A `clap::Command` with `ignore_errors(true)` cannot
/// do this: on an unrecognized flag it loses track of whether the next token
/// is that flag's value or the next flag, and can walk past `--config`
/// entirely. So this scans the argv by hand instead, and falls back to
/// `POD_CONFIG` when no `--config` is present.
///
/// Deliberately looser than clap: it does not stop at a `--` separator, it
/// takes the first `--config` rather than rejecting a repeat, and it does not
/// check whether the value looks like another flag. Every input where that
/// looseness would matter is one the real parse in [`Config::try_load_from`]
/// refuses to start on, so none of them can run a pod against the wrong file.
fn config_path_from<I, T>(argv: I) -> Option<std::path::PathBuf>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut args = argv.into_iter().map(Into::into);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            return args.next().map(std::path::PathBuf::from);
        }
        if let Some(rest) = arg.as_encoded_bytes().strip_prefix(b"--config=") {
            // SAFETY: the split is on an ASCII boundary of the original `OsStr`,
            // which is exactly the condition `from_encoded_bytes_unchecked`
            // documents.
            return Some(std::path::PathBuf::from(unsafe {
                std::ffi::OsStr::from_encoded_bytes_unchecked(rest)
            }));
        }
    }
    std::env::var_os("POD_CONFIG").map(std::path::PathBuf::from)
}

/// Pass 2: `Config`'s own command, with the file's values installed as defaults.
///
/// This is the whole precedence mechanism. clap already resolves flag > env >
/// default; putting the file in the default slot lands it exactly one rung
/// below the environment without a line of merge logic, and a flag added later
/// picks up file support from the same derive that gives it its flag.
///
/// Two visible consequences follow from defaults being how the file is
/// represented. With a file supplying a required argument, `--help`'s usage
/// line changes from `sparql-pod --owner-webid <OWNER_WEBID>` to `sparql-pod
/// [OPTIONS]` — correct, since help reflects the effective configuration, but
/// a visible change. And a repeatable flag given on the command line replaces
/// the file's whole list rather than appending to it, because clap skips
/// defaults entirely for an argument that is present — the same rule as every
/// other rung.
fn command_with(defaults: std::collections::BTreeMap<&'static str, Vec<String>>) -> clap::Command {
    use clap::CommandFactory;
    let mut cmd = Config::command();
    for (id, values) in defaults {
        // `required(false)` alongside the default: clap's own required check
        // looks only at whether the value came from the command line or the
        // environment (`ValueSource::is_explicit`), never at whether a
        // default was set — so a required argument with nothing but a
        // default still reports missing. Explicitly lifting the requirement
        // is what lets a file-supplied value satisfy it. Chained only onto
        // ids the file actually supplied, not onto the whole argument list —
        // see `a_file_that_omits_owner_webid_still_refuses_the_start`.
        cmd = cmd.mut_arg(id, move |a| a.default_values(values).required(false));
    }
    cmd
}

/// Re-point a clap error at the file that actually caused it.
///
/// A file-supplied value arrives as a default, so clap phrases its complaint in
/// terms of a flag the operator never typed. `from_file` maps each long flag
/// the file supplied to its TOML key and the values the file gave it. Knowing
/// the file supplied that *key* is not enough — a flag overrides a default, so
/// the value clap rejected may be the flag's own and the file may say nothing
/// about it. The file is blamed only when the rejected value is one it
/// actually supplied; a value the operator retypes identically to the file's
/// is attributed to the file regardless, since it is in both places and
/// naming the file is not wrong. Anything else is passed through exactly as
/// clap wrote it.
///
/// Keyed by long flag rather than by argument id because that is what clap puts
/// in the error, and the two differ wherever `#[arg(long = "…")]` renames one —
/// `--trusted-issuer` carries the id `trusted_issuers`.
fn blame_file(
    err: clap::Error,
    path: &std::path::Path,
    from_file: &std::collections::BTreeMap<String, (&'static str, Vec<String>)>,
) -> clap::Error {
    use clap::error::{ContextKind, ContextValue};
    let Some(ContextValue::String(arg)) = err.get(ContextKind::InvalidArg) else {
        return err;
    };
    // clap renders the argument as it appears on the command line, e.g.
    // "--listen <LISTEN>"; only the flag itself is a stable key.
    let long = arg.trim_start_matches("--").split([' ', '=', '<']).next().unwrap();
    let Some((key, values)) = from_file.get(long) else {
        return err;
    };
    let Some(ContextValue::String(bad_value)) = err.get(ContextKind::InvalidValue) else {
        return err;
    };
    if !values.contains(bad_value) {
        return err;
    }
    // clap's own text is the whole message; only its framing as a standalone
    // error is undone before it is nested inside this one.
    let rendered = err.to_string();
    let mut msg = rendered.strip_prefix("error: ").unwrap_or(rendered.as_str());
    msg = msg.trim_end();
    if let Some(stripped) = msg.strip_suffix("For more information, try '--help'.") {
        msg = stripped.trim_end();
    }
    clap::Error::raw(err.kind(), format!("{}: `{key}`: {msg}\n", path.display()))
}

impl Config {
    /// This process's configuration, from the real argv and environment.
    pub fn load() -> Result<Self, clap::Error> {
        Self::try_load_from(std::env::args_os())
    }

    /// [`Config::load`] against a supplied argv, which is what makes the file
    /// reachable from a test: the path arrives as `--config <tmpfile>` rather
    /// than from a fixed location.
    pub fn try_load_from<I, T>(argv: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        // Collected once: the pre-parse and the real parse must see the same
        // arguments, and `I` is consumed by whichever runs first.
        let argv: Vec<std::ffi::OsString> = argv.into_iter().map(Into::into).collect();
        let Some(path) = config_path_from(argv.clone()) else {
            let matches = command_with(Default::default()).try_get_matches_from(argv)?;
            return <Self as clap::FromArgMatches>::from_arg_matches(&matches);
        };
        let defaults = FileConfig::read(&path)?.as_defaults();
        let cmd = command_with(defaults.clone());
        // Built from the command rather than guessed, so an id and its long
        // flag can never drift apart here.
        let from_file: std::collections::BTreeMap<String, (&'static str, Vec<String>)> = cmd
            .get_arguments()
            .filter_map(|a| {
                let (id, values) = defaults.get_key_value(a.get_id().as_str())?;
                Some((a.get_long()?.to_string(), (*id, values.clone())))
            })
            .collect();
        let matches = cmd
            .try_get_matches_from(argv)
            .map_err(|e| blame_file(e, &path, &from_file))?;
        <Self as clap::FromArgMatches>::from_arg_matches(&matches)
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

    fn write_temp_toml(body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir()
            .join(format!("sparql-pod-{}", uuid::Uuid::new_v4()))
            .with_extension("toml");
        std::fs::write(&p, body).expect("write temp toml");
        p
    }

    #[test]
    fn a_file_supplies_what_it_names_and_leaves_the_rest_unset() {
        let p = write_temp_toml("owner_webid = \"https://a.example/#me\"\nmax_body_bytes = 42\n");
        let f = FileConfig::read(&p).expect("reads");
        assert_eq!(f.owner_webid.as_deref(), Some("https://a.example/#me"));
        assert_eq!(f.max_body_bytes, Some(42));
        assert_eq!(f.listen, None);
        std::fs::remove_file(&p).ok();
    }

    // §4.1: a key this binary does not know is a typo, and a pod that starts
    // with less configuration than was written looks exactly like one
    // configured correctly.
    #[test]
    fn an_unknown_key_refuses_the_start() {
        let p = write_temp_toml("owner_web_id = \"https://a.example/#me\"\n");
        assert!(FileConfig::read(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn malformed_toml_refuses_the_start() {
        let p = write_temp_toml("owner_webid = \n");
        assert!(FileConfig::read(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn an_unreadable_path_refuses_the_start() {
        let p = std::env::temp_dir()
            .join("sparql-pod-does-not-exist")
            .with_extension("toml");
        assert!(FileConfig::read(&p).is_err());
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

    // Everything is rendered to a string so the file's values travel the same
    // `value_parser` as a typed flag. The keys are argument ids, which is what
    // `Command::mut_arg` takes.
    #[test]
    fn as_defaults_renders_only_the_keys_the_file_set() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://a.example/#me\"\n",
            "trusted_issuers = [\"https://one.example/\", \"https://two.example/\"]\n",
            "reset_root_acl = true\n",
            "max_body_bytes = 42\n",
        ));
        let d = FileConfig::read(&p).expect("reads").as_defaults();
        assert_eq!(d.get("owner_webid"), Some(&vec!["https://a.example/#me".to_string()]));
        assert_eq!(
            d.get("trusted_issuers"),
            Some(&vec!["https://one.example/".to_string(), "https://two.example/".to_string()]),
            "a list becomes several values, not one joined string"
        );
        assert_eq!(d.get("reset_root_acl"), Some(&vec!["true".to_string()]));
        assert_eq!(d.get("max_body_bytes"), Some(&vec!["42".to_string()]));
        assert_eq!(d.get("listen"), None, "an unset key must not become a default");
        std::fs::remove_file(&p).ok();
    }

    // The pre-parser runs before anything is known, so it must survive an argv
    // it cannot fully understand — here a required flag it has never heard of.
    // That is the case the hand-written scan exists for, and the one most
    // likely to break silently.
    #[test]
    fn the_pre_parser_finds_config_beside_arguments_it_does_not_know() {
        let found = config_path_from([
            "sparql-pod",
            "--owner-webid",
            "https://a.example/#me",
            "--config",
            "/tmp/pod.conf",
            "--trusted-issuer",
            "https://idp.example/",
        ]);
        assert_eq!(found, Some(std::path::PathBuf::from("/tmp/pod.conf")));
    }

    #[test]
    fn the_pre_parser_returns_none_without_config() {
        let found = config_path_from(["sparql-pod", "--owner-webid", "https://a.example/#me"]);
        assert_eq!(found, None);
    }

    // A path the joined form must carry through untouched: `OsStr::to_str`
    // answers `None` for it, and a scan that asks for UTF-8 first would drop
    // the argument and start the pod against no file at all.
    #[test]
    fn the_pre_parser_reads_a_non_utf8_path_in_either_spelling() {
        use std::os::unix::ffi::OsStrExt;
        let raw = std::ffi::OsStr::from_bytes(b"/tmp/pod-\xFF\xFE");
        let joined = {
            let mut s = std::ffi::OsString::from("--config=");
            s.push(raw);
            s
        };
        let want = Some(std::path::PathBuf::from(raw));
        assert_eq!(
            config_path_from([std::ffi::OsString::from("sparql-pod"), joined]),
            want,
            "--config=<path>"
        );
        assert_eq!(
            config_path_from([
                std::ffi::OsString::from("sparql-pod"),
                std::ffi::OsString::from("--config"),
                raw.to_os_string(),
            ]),
            want,
            "--config <path>"
        );
    }

    fn load(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_load_from(std::iter::once("sparql-pod").chain(args.iter().copied()))
    }

    #[test]
    fn a_file_value_is_used_when_nothing_overrides_it() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "listen = \"127.0.0.1:9999\"\n",
        ));
        let c = load(&["--config", p.to_str().unwrap()]).expect("loads");
        assert_eq!(c.owner_webid.as_str(), "https://file.example/#me");
        assert_eq!(c.listen.to_string(), "127.0.0.1:9999");
        std::fs::remove_file(&p).ok();
    }

    // §5.2: a file value satisfies a required argument. Not because clap
    // treats a default as present — it does not — but because `command_with`
    // chains `.required(false)` onto every id the file supplied.
    #[test]
    fn a_file_satisfies_the_required_owner_webid() {
        let p = write_temp_toml("owner_webid = \"https://file.example/#me\"\n");
        assert!(load(&["--config", p.to_str().unwrap()]).is_ok());
        std::fs::remove_file(&p).ok();
    }

    // The bound on `required(false)`: it is chained only onto ids the file
    // actually supplied, so an argument the file is silent about keeps its
    // requirement. Widening it — to `mut_args`, or across the whole argument
    // list — would let a pod start with no owner, and nothing else in this
    // suite would notice.
    #[test]
    fn a_file_that_omits_owner_webid_still_refuses_the_start() {
        let p = write_temp_toml("listen = \"127.0.0.1:9999\"\n");
        assert!(load(&["--config", p.to_str().unwrap()]).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_flag_beats_the_file() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "listen = \"127.0.0.1:9999\"\n",
        ));
        let c = load(&["--config", p.to_str().unwrap(), "--listen", "127.0.0.1:1234"])
            .expect("loads");
        assert_eq!(c.listen.to_string(), "127.0.0.1:1234");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_default_survives_a_file_that_says_nothing() {
        let p = write_temp_toml("owner_webid = \"https://file.example/#me\"\n");
        let c = load(&["--config", p.to_str().unwrap()]).expect("loads");
        assert_eq!(c.rdf_store, "memory");
        assert_eq!(c.max_body_bytes, 64 * 1024 * 1024);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_file_list_becomes_several_values() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "trusted_issuers = [\"https://one.example/\", \"https://two.example/\"]\n",
        ));
        let c = load(&["--config", p.to_str().unwrap()]).expect("loads");
        assert_eq!(
            c.trusted_issuers,
            vec!["https://one.example/".to_string(), "https://two.example/".to_string()]
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn no_config_flag_loads_nothing() {
        let c = load(&["--owner-webid", "https://a.example/#me"]).expect("loads");
        assert_eq!(c.rdf_store, "memory");
        assert!(c.config.is_none());
    }

    // §5.1: without this the operator reads `invalid value for '--listen'` and
    // goes looking at a command line that is correct.
    #[test]
    fn a_bad_file_value_names_the_file_and_the_key() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "listen = \"not-a-socket-address\"\n",
        ));
        let err = load(&["--config", p.to_str().unwrap()]).expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.contains(p.to_str().unwrap()), "names the file: {msg}");
        assert!(msg.contains("listen"), "names the key: {msg}");
        std::fs::remove_file(&p).ok();
    }

    // The other half of the same rule: an error about a value the file never
    // supplied must stay exactly as clap wrote it.
    #[test]
    fn a_bad_flag_value_is_left_alone() {
        let p = write_temp_toml("owner_webid = \"https://file.example/#me\"\n");
        let err = load(&["--config", p.to_str().unwrap(), "--listen", "not-a-socket-address"])
            .expect_err("must fail");
        assert!(
            !err.to_string().contains(p.to_str().unwrap()),
            "the file did not set `listen`, so it must not be blamed"
        );
        std::fs::remove_file(&p).ok();
    }

    // The lookup bridges an id and a long flag that are different strings —
    // it is not specific to the two arguments renamed outright
    // (`trusted_issuers`/`allow_insecure_hosts`), which cannot fail
    // validation and so cannot be covered by a test like this one.
    #[test]
    fn a_bad_file_value_under_a_differently_spelled_long_is_still_blamed() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "base_uri = \"not an absolute uri\"\n",
        ));
        let err = load(&["--config", p.to_str().unwrap()]).expect_err("must fail");
        assert!(err.to_string().contains("base_uri"), "{err}");
        std::fs::remove_file(&p).ok();
    }

    // A flag overriding a file-supplied key: the failing value is the flag's,
    // and the file says nothing about it. Blaming the file here is the same
    // misdirection this function exists to remove, only pointing the other way.
    #[test]
    fn a_flag_that_overrides_a_file_key_is_not_blamed_on_the_file() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "listen = \"127.0.0.1:9999\"\n",
        ));
        let err = load(&["--config", p.to_str().unwrap(), "--listen", "nope"])
            .expect_err("must fail");
        assert!(
            !err.to_string().contains(p.to_str().unwrap()),
            "the file supplied a different, valid value: {err}"
        );
        std::fs::remove_file(&p).ok();
    }

    // The message an operator reads is the whole deliverable of this function.
    #[test]
    fn a_blamed_message_reads_as_one_error() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "listen = \"not-a-socket-address\"\n",
        ));
        let msg = load(&["--config", p.to_str().unwrap()])
            .expect_err("must fail")
            .to_string();
        assert!(!msg.contains("error: error:"), "doubled prefix: {msg}");
        assert!(!msg.ends_with("\n\n"), "trailing blank line: {msg}");
        std::fs::remove_file(&p).ok();
    }
}
