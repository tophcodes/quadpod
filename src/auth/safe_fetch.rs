//! SSRF-hardened outbound HTTP fetcher.
//!
//! Any URL this crate fetches on a caller's behalf — most notably OIDC
//! discovery, which follows a token's attacker-controlled `iss` claim to
//! `<iss>/.well-known/openid-configuration` *before* any credential has
//! been verified — is a blind-SSRF primitive: a malicious `iss` could
//! point at an internal service, a cloud-metadata endpoint, or localhost
//! and get this process to fetch it with zero valid credentials
//! presented. [`guarded_get`] closes that hole by enforcing https-only
//! (by default) and refusing to contact any resolved IP in a
//! private/loopback/link-local/CGNAT range.
//!
//! Residual limitation (v1): this resolves the host once to check it,
//! then hands the same URL to `reqwest` to connect, which resolves DNS
//! again itself. A DNS-rebinding attacker (a name that answers with a
//! public IP on the first lookup and a private one moments later) can
//! race past this check. Closing that fully needs a custom
//! resolver/connector that pins the checked IP for the actual connection;
//! out of scope for this pass. The https-default + private-IP block
//! still covers the common SSRF vectors (cloud metadata, internal
//! services reachable by static IP/hostname, localhost).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::net::lookup_host;

use super::AuthError;

/// Maximum response body accepted from a guarded fetch, to bound memory
/// use against a malicious or misbehaving server.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Controls which network destinations [`guarded_get`] will contact.
/// `Default` is the production-safe posture: https-only, private IPs
/// blocked. Tests that must hit a local (`127.0.0.1`) hermetic server
/// construct a permissive policy explicitly.
#[derive(Clone, Default)]
pub struct FetchPolicy {
    pub allow_http: bool,
    pub allow_private_ips: bool,
}

/// True if `ip` must never be reached by a fetch driven by
/// attacker-controlled input: loopback, unspecified (`0.0.0.0`/`::`),
/// private (RFC 1918: `10/8`, `172.16/12`, `192.168/16`), link-local
/// (`169.254/16` — covers cloud-metadata `169.254.169.254`), shared
/// address space / CGNAT (`100.64/10`), or the IPv6 equivalents
/// (loopback `::1`, unspecified `::`, unique-local `fc00::/7`,
/// link-local `fe80::/10`).
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || is_cgnat(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || is_unique_local(v6) || is_link_local_v6(v6)
        }
    }
}

/// `100.64.0.0/10`, the shared address space used for carrier-grade NAT.
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (b & 0b1100_0000) == 0b0100_0000
}

/// `fc00::/7`, the IPv6 unique local address range.
fn is_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// `fe80::/10`, the IPv6 link-local address range.
fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Fetch `url` with the `accept` header, refusing to run at all unless it
/// passes `policy`: https-only (unless `allow_http`), and every IP the
/// host resolves to must be a public address (unless `allow_private_ips`).
/// Fails closed on any parse, resolution, network, status, size, or
/// encoding error.
pub async fn guarded_get(
    client: &reqwest::Client,
    url: &str,
    accept: &str,
    policy: &FetchPolicy,
) -> Result<String, AuthError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| AuthError::FetchBlocked(format!("invalid URL: {e}")))?;

    match parsed.scheme() {
        "https" => {}
        "http" if policy.allow_http => {}
        other => {
            return Err(AuthError::FetchBlocked(format!(
                "refusing non-https scheme: {other}"
            )))
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| AuthError::FetchBlocked("URL has no host".to_string()))?;

    if !policy.allow_private_ips {
        // `host_str()` brackets IPv6 literals (e.g. "[::1]"); strip that
        // before trying to parse it as an IP.
        let ip_literal = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>();

        let resolved_ips: Vec<IpAddr> = match ip_literal {
            Ok(ip) => vec![ip],
            Err(_) => {
                let port = parsed
                    .port_or_known_default()
                    .ok_or_else(|| AuthError::FetchBlocked("URL has no port".to_string()))?;
                lookup_host((host, port))
                    .await
                    .map_err(|e| AuthError::FetchBlocked(format!("DNS resolution failed: {e}")))?
                    .map(|addr| addr.ip())
                    .collect()
            }
        };

        if resolved_ips.is_empty() {
            return Err(AuthError::FetchBlocked(
                "host resolved to no addresses".to_string(),
            ));
        }
        if resolved_ips.into_iter().any(is_forbidden_ip) {
            return Err(AuthError::FetchBlocked(
                "target resolves to a forbidden (private/loopback/link-local) IP".to_string(),
            ));
        }
    }

    let response = client
        .get(parsed)
        .header(reqwest::header::ACCEPT, accept)
        .send()
        .await
        .map_err(|e| AuthError::FetchBlocked(format!("request failed: {e}")))?
        .error_for_status()
        .map_err(|e| AuthError::FetchBlocked(format!("non-success status: {e}")))?;

    if let Some(len) = response.content_length() {
        if len > MAX_BODY_BYTES as u64 {
            return Err(AuthError::FetchBlocked(
                "response exceeds size cap".to_string(),
            ));
        }
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| AuthError::FetchBlocked(format!("failed to read body: {e}")))?;

    if body.len() > MAX_BODY_BYTES {
        return Err(AuthError::FetchBlocked(
            "response exceeds size cap".to_string(),
        ));
    }

    String::from_utf8(body.to_vec())
        .map_err(|_| AuthError::FetchBlocked("response was not valid UTF-8".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn forbidden_ip_classification() {
        assert!(is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))); // loopback
        assert!(is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))); // private
        assert!(is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))); // private
        assert!(is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))); // metadata
        assert!(is_forbidden_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))); // ::1
        assert!(!is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))) // public
    }

    #[tokio::test]
    async fn rejects_http_scheme_by_default() {
        let c = reqwest::Client::new();
        let r = guarded_get(&c, "http://example.com/x", "text/turtle", &FetchPolicy::default()).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn rejects_loopback_target_by_default() {
        let c = reqwest::Client::new();
        let r = guarded_get(&c, "https://127.0.0.1/x", "text/turtle", &FetchPolicy::default()).await;
        assert!(r.is_err());
    }
}
