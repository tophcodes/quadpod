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
    #[arg(long, env = "POD_BASE_URI", default_value = "http://localhost:3000/")]
    pub base_uri: String,

    /// WebID of the pod owner. Required: the root ACL is provisioned for it,
    /// and a pod with no known owner could only be all-open or all-closed.
    #[arg(long, env = "POD_OWNER_WEBID")]
    pub owner_webid: String,

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
}

impl Config {
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
    /// plus whatever hosts the operator named on the command line.
    pub fn fetch_policy(&self) -> crate::auth::safe_fetch::FetchPolicy {
        crate::auth::safe_fetch::FetchPolicy::with_insecure_hosts(
            self.allow_insecure_hosts.iter().cloned(),
        )
    }

    pub fn space(&self) -> Result<StorageSpace, SpaceError> {
        StorageSpace::new(self.base_uri.clone())
    }

    /// The owner WebID, confirmed to be an absolute IRI. Provisioning
    /// interpolates it into SPARQL, so it must never be unvalidated.
    pub fn validated_owner_webid(&self) -> Result<String, InvalidOwnerWebId> {
        NamedNode::new(&self.owner_webid)
            .map(|_| self.owner_webid.clone())
            .map_err(|_| InvalidOwnerWebId)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

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
        assert_eq!(c.base_uri, "https://pod.toph.so/");
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

    #[test]
    fn non_iri_owner_webid_is_rejected() {
        let c = parse(&["--owner-webid", "not an iri"]).unwrap();
        assert!(c.validated_owner_webid().is_err());
    }

    #[test]
    fn iri_owner_webid_is_accepted() {
        let c = parse(&["--owner-webid", "https://alice.example/card#me"]).unwrap();
        assert_eq!(
            c.validated_owner_webid().unwrap(),
            "https://alice.example/card#me"
        );
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
}
