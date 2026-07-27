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
//! DNS-rebinding closed: [`resolve_allowed`] resolves the host once,
//! validates every candidate address, and [`guarded_get`] then **pins**
//! the connection to one of those already-validated addresses (via
//! reqwest's per-client DNS override) instead of handing the bare
//! hostname to `reqwest` and letting it re-resolve — which is what would
//! let a name that answers with a public IP on the first lookup and a
//! private one moments later race past the check.
//!
//! See `docs/deployment.md` for the operator-facing contract: what this
//! module fetches before any credential is verified, and the entry-form
//! rules for `--allow-insecure-host`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::lookup_host;

use super::AuthError;

/// Maximum response body accepted from a guarded fetch, to bound memory
/// use against a malicious or misbehaving server.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Connect/total timeouts for the pinned per-request client built inside
/// [`guarded_get`]. Matches the values every production caller
/// (`HttpJwksResolver`, `WebIdIssuerVerifier`) already configures on the
/// client they pass in.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Controls which network destinations [`guarded_get`] will contact.
///
/// `Default` is the production-safe posture: https-only, private IPs
/// blocked, no named hosts. The blanket-permissive combination (both
/// `allow_*` flags `true`) is only constructible via
/// [`FetchPolicy::permissive`], which is `#[cfg(test)]`-gated: a production
/// build cannot obtain anything but the default plus an explicit host list,
/// so a future caller can't accidentally (or maliciously) bypass SSRF
/// protection wholesale by hand-constructing a permissive policy.
///
/// `insecure_hosts` is the operator's explicit exception list. The
/// distinction that matters for SSRF is not private-versus-public but
/// **named-by-the-operator versus chosen-by-the-attacker**: the fetch that
/// this policy guards happens before any credential is verified, so the URL
/// is attacker-influenced — unless the operator has named the host, which is
/// what this list is. For a named host the private-IP filter and the
/// https-only rule do not apply. Everything else still does, for every host:
/// redirects are refused, the connection is pinned to the validated IP, and
/// the body cap and timeout hold.
#[derive(Clone, Default)]
pub struct FetchPolicy {
    allow_http: bool,
    allow_private_ips: bool,
    insecure_hosts: std::sync::Arc<std::collections::HashSet<(String, Option<u16>)>>,
}

impl FetchPolicy {
    /// The production constructor: the safe default plus the hosts the
    /// operator vouched for. Each entry is parsed once, here — not
    /// re-matched as a raw string on every lookup — into a normalized
    /// `(host, Option<port>)` pair. See [`parse_insecure_host_entry`] for
    /// the grammar. An entry that cannot be understood unambiguously
    /// (empty, or ambiguous IPv6) is dropped rather than guessed at;
    /// [`FetchPolicy::insecure_host_entries`] reports what actually made
    /// it into the set, for logging.
    pub fn with_insecure_hosts(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            insecure_hosts: std::sync::Arc::new(
                hosts
                    .into_iter()
                    .filter_map(|entry| parse_insecure_host_entry(&entry))
                    .collect(),
            ),
            ..Self::default()
        }
    }

    /// The entries actually understood after parsing and normalization —
    /// for logging what will really take effect, not what was typed.
    /// Sorted for deterministic output.
    pub fn insecure_host_entries(&self) -> Vec<String> {
        let mut entries: Vec<String> = self
            .insecure_hosts
            .iter()
            .map(|(host, port)| display_insecure_host_entry(host, *port))
            .collect();
        entries.sort();
        entries
    }

    /// Allow http and private/loopback IPs — for hermetic tests hitting a
    /// local (`127.0.0.1`) test server. Unavailable outside `#[cfg(test)]`,
    /// so this combination cannot exist in a release build.
    #[cfg(test)]
    pub fn permissive() -> Self {
        Self {
            allow_http: true,
            allow_private_ips: true,
            ..Self::default()
        }
    }

    /// Whether this exact host (and port) is on the operator's list.
    fn permits_insecure(&self, host: &str, port: u16) -> bool {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_lowercase();
        self.insecure_hosts.contains(&(host.clone(), None))
            || self.insecure_hosts.contains(&(host, Some(port)))
    }
}

/// Parse one `--allow-insecure-host` / `POD_ALLOW_INSECURE_HOSTS` entry into
/// a normalized `(host, port)` pair, where `port: None` means "every port on
/// this host". Returns `None` for an entry that cannot be understood
/// unambiguously — it is dropped from the set rather than guessed at.
///
/// Grammar:
///
/// - **Bracketed IPv6**, `[addr]` or `[addr]:port` — the unambiguous way to
///   name an IPv6 host, with or without a port. `addr` must itself parse as
///   an [`Ipv6Addr`]; a malformed bracketed entry is dropped.
/// - A bare entry that parses as a whole [`Ipv6Addr`] (e.g. `fd00::1`) is a
///   host with no port restriction — every colon in it is part of the
///   address, never a port separator, so it is never split.
/// - A bare entry that is *simultaneously* a valid whole `Ipv6Addr` **and**
///   has a `host:port` reading whose `host` portion is *also* a valid
///   `Ipv6Addr` (e.g. `fd00::1:80`, which is at once the address
///   `fd00::1:80` and the pair `fd00::1` + port `80`) is ambiguous and is
///   dropped entirely: guessing "whole address" would silently grant an
///   unnamed address every port, and guessing "split" would silently drop
///   the address actually typed. There is no safe default, so the entry
///   contributes nothing — the bracketed form must be used instead.
/// - Otherwise, split on the last colon: `host:port` (hostnames, IPv4
///   literals) if the tail parses as a `u16`, else a bare host with no
///   port.
///
/// The returned host is de-bracketed and lowercased, matching how
/// [`FetchPolicy::permits_insecure`] normalizes the host it looks up, so
/// the two representations cannot disagree.
fn parse_insecure_host_entry(entry: &str) -> Option<(String, Option<u16>)> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    if let Some(rest) = entry.strip_prefix('[') {
        let close = rest.find(']')?;
        let addr = &rest[..close];
        addr.parse::<Ipv6Addr>().ok()?;
        return match &rest[close + 1..] {
            "" => Some((addr.to_lowercase(), None)),
            tail => {
                let port = tail.strip_prefix(':')?.parse::<u16>().ok()?;
                Some((addr.to_lowercase(), Some(port)))
            }
        };
    }

    if entry.parse::<Ipv6Addr>().is_ok() {
        let ambiguous = entry.rfind(':').is_some_and(|idx| {
            let (host, port_str) = (&entry[..idx], &entry[idx + 1..]);
            host.parse::<Ipv6Addr>().is_ok() && port_str.parse::<u16>().is_ok()
        });
        return if ambiguous {
            None
        } else {
            Some((entry.to_lowercase(), None))
        };
    }

    if let Some(idx) = entry.rfind(':') {
        let (host, port_str) = (&entry[..idx], &entry[idx + 1..]);
        if !host.is_empty() {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_lowercase(), Some(port)));
            }
        }
    }

    Some((entry.to_lowercase(), None))
}

/// Render a parsed entry back to display form, for the startup warning.
/// Brackets the host if it contains a colon (IPv6), so the result is
/// itself a valid re-parseable entry in the grammar above.
fn display_insecure_host_entry(host: &str, port: Option<u16>) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
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
            // IPv4-mapped (`::ffff:a.b.c.d`) — the classic metadata-endpoint
            // bypass: on a dual-stack host the kernel connects to the real
            // IPv4 address, so this must be classified by the v4 rules, not
            // treated as an opaque v6 address.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_ip(IpAddr::V4(v4));
            }
            // IPv4-compatible (deprecated `::a.b.c.d` form): top 96 bits
            // zero, excluding `::` and `::1` which are handled below.
            let seg = v6.segments();
            if seg[0..6] == [0, 0, 0, 0, 0, 0] && !(v6.is_loopback() || v6.is_unspecified()) {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    seg[6] as u8,
                    (seg[7] >> 8) as u8,
                    seg[7] as u8,
                );
                return is_forbidden_ip(IpAddr::V4(v4));
            }
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

/// Resolve `host` (IP literal used directly; hostname resolved via the
/// system resolver against `port`) and validate every candidate address
/// against [`is_forbidden_ip`] (skipped entirely when
/// `policy.allow_private_ips`, or when the operator named this host —
/// see [`FetchPolicy`]). Returns the resolved addresses so the
/// caller can pin the actual connection to one of them, or an error if
/// resolution fails, yields nothing, or (under the default policy) yields
/// any forbidden address.
pub(crate) async fn resolve_allowed(
    host: &str,
    port: u16,
    policy: &FetchPolicy,
) -> Result<Vec<SocketAddr>, AuthError> {
    // `host_str()` brackets IPv6 literals (e.g. "[::1]"); strip that before
    // trying to parse it as an IP so a literal resolves without a DNS
    // round-trip.
    let ip_literal = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>();

    let resolved: Vec<SocketAddr> = match ip_literal {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => lookup_host((host, port))
            .await
            .map_err(|e| AuthError::FetchBlocked(format!("DNS resolution failed: {e}")))?
            .collect(),
    };

    if resolved.is_empty() {
        return Err(AuthError::FetchBlocked(
            "host resolved to no addresses".to_string(),
        ));
    }

    let allow_private = policy.allow_private_ips || policy.permits_insecure(host, port);
    if !allow_private && resolved.iter().any(|addr| is_forbidden_ip(addr.ip())) {
        return Err(AuthError::FetchBlocked(
            "target resolves to a forbidden (private/loopback/link-local) IP".to_string(),
        ));
    }

    Ok(resolved)
}

/// Fetch `url` with the `accept` header, refusing to run at all unless it
/// passes `policy`: https-only (unless `allow_http`, or the host is on the
/// operator's `insecure_hosts` list), and every IP the host resolves to
/// must be a public address (unless `allow_private_ips`, or the host is on
/// that same list). Fails closed on any parse, resolution, network, status,
/// size, or encoding error.
///
/// The connection is pinned to the exact validated address (via a
/// per-request client built with reqwest's DNS override) rather than
/// handing the hostname to `reqwest` to resolve again — closing the
/// DNS-rebinding race where a name resolves to a public IP for this
/// check and a private one for the real connection. The `_client`
/// parameter is accepted for API stability but unused: pinning requires
/// a fresh `ClientBuilder` per request (a built `reqwest::Client`'s DNS
/// overrides can't be changed after construction), so the connection
/// always goes out on a client built here, not the one passed in.
pub async fn guarded_get(
    _client: &reqwest::Client,
    url: &str,
    accept: &str,
    policy: &FetchPolicy,
) -> Result<(String, Option<String>), AuthError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| AuthError::FetchBlocked(format!("invalid URL: {e}")))?;

    // Host and port are extracted before the scheme check because the
    // scheme rule now depends on them: http is permitted only for a host
    // the operator named.
    let host = parsed
        .host_str()
        .ok_or_else(|| AuthError::FetchBlocked("URL has no host".to_string()))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| AuthError::FetchBlocked("URL has no port".to_string()))?;

    let insecure_ok = policy.permits_insecure(host, port);
    match parsed.scheme() {
        "https" => {}
        "http" if policy.allow_http || insecure_ok => {}
        other => {
            return Err(AuthError::FetchBlocked(format!(
                "refusing non-https scheme: {other}"
            )))
        }
    }

    let pinned_addr = *resolve_allowed(host, port, policy).await?.first().expect(
        "resolve_allowed only returns Ok with a non-empty Vec (empty case is its own Err)",
    );

    // Build a fresh client for this one request, pinned to the validated
    // address: reqwest's DNS override is baked into a `Client` at build
    // time, so there is no way to point an already-built client at a
    // different address per call. The Host header + TLS SNI still use
    // `host` (only the socket target is overridden).
    let pinned_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .resolve(host, pinned_addr)
        .build()
        .map_err(|e| AuthError::FetchBlocked(format!("failed to build pinned client: {e}")))?;

    let mut response = pinned_client
        .get(parsed)
        .header(reqwest::header::ACCEPT, accept)
        .send()
        .await
        .map_err(|e| AuthError::FetchBlocked(format!("request failed: {e}")))?;

    // Only a 2xx is treated as a usable response. In particular this
    // rejects 3xx redirects outright rather than parsing whatever body
    // came with them: the client's redirect policy is `none()`, so a
    // redirect response reaches here as-is instead of being transparently
    // followed to an unvalidated (and possibly internal) target.
    if !response.status().is_success() {
        return Err(AuthError::FetchBlocked(format!(
            "non-success status: {}",
            response.status()
        )));
    }

    // Captured before the body is consumed below: the caller (e.g. WebID
    // profile content negotiation) needs it to pick the right RDF parser.
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Cheap fast-path: a declared size already over the cap is rejected
    // without reading any body at all.
    if let Some(len) = response.content_length() {
        if len > MAX_BODY_BYTES as u64 {
            return Err(AuthError::FetchBlocked(
                "response exceeds size cap".to_string(),
            ));
        }
    }

    // Read incrementally and bail as soon as the running total exceeds the
    // cap, so a malicious/misbehaving server can't force this process to
    // buffer an unbounded (or merely huge) body in memory before the size
    // is checked — the server can lie about (or omit) `Content-Length`.
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| AuthError::FetchBlocked(format!("failed to read body: {e}")))?
    {
        if buf.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(AuthError::FetchBlocked(
                "response exceeds size cap".to_string(),
            ));
        }
        buf.extend_from_slice(&chunk);
    }

    let body = String::from_utf8(buf)
        .map_err(|_| AuthError::FetchBlocked("response was not valid UTF-8".to_string()))?;

    Ok((body, content_type))
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

    #[test]
    fn ipv4_mapped_ipv6_is_forbidden() {
        assert!(is_forbidden_ip(
            "::ffff:169.254.169.254".parse::<IpAddr>().unwrap()
        )); // metadata
        assert!(is_forbidden_ip("::ffff:127.0.0.1".parse::<IpAddr>().unwrap())); // loopback
        assert!(is_forbidden_ip("::ffff:10.0.0.1".parse::<IpAddr>().unwrap())); // private
        assert!(!is_forbidden_ip(
            "::ffff:93.184.216.34".parse::<IpAddr>().unwrap()
        )); // public stays public
    }

    #[test]
    fn ipv4_compatible_ipv6_is_forbidden() {
        // deprecated `::a.b.c.d` form embedding a private address
        assert!(is_forbidden_ip("::10.0.0.1".parse::<IpAddr>().unwrap()));
        // `::` (unspecified) and `::1` (loopback) must still classify via
        // their dedicated v6 checks, not be misread as embedding 0.0.0.0/0.0.0.1
        assert!(is_forbidden_ip(Ipv6Addr::UNSPECIFIED.into()));
        assert!(is_forbidden_ip(Ipv6Addr::LOCALHOST.into()));
    }

    #[tokio::test]
    async fn resolve_allowed_rejects_forbidden_ip_literals_under_default_policy() {
        let policy = FetchPolicy::default();
        assert!(resolve_allowed("127.0.0.1", 443, &policy).await.is_err());
        assert!(resolve_allowed("10.0.0.1", 443, &policy).await.is_err());
    }

    #[tokio::test]
    async fn resolve_allowed_permits_forbidden_ip_literal_under_permissive_policy() {
        let policy = FetchPolicy::permissive();
        let addrs = resolve_allowed("127.0.0.1", 8080, &policy).await.unwrap();
        assert_eq!(addrs, vec![SocketAddr::from(([127, 0, 0, 1], 8080))]);
    }

    #[tokio::test]
    async fn rejects_hostname_resolving_to_loopback() {
        // Exercises the `lookup_host` branch (not the IP-literal
        // fast-path): "localhost" resolves via the system resolver, not a
        // network DNS query, so this stays hermetic.
        let c = reqwest::Client::new();
        let r = guarded_get(&c, "https://localhost/x", "text/turtle", &FetchPolicy::default())
            .await;
        assert!(r.is_err());
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

    /// A malicious/misbehaving server that streams a body over
    /// `MAX_BODY_BYTES` via chunked transfer-encoding (deliberately no
    /// `Content-Length`, so the cheap early-reject can't fire) must still be
    /// rejected — proving the cap is enforced as bytes arrive, not only
    /// after the whole body has been buffered.
    async fn spawn_oversized_chunked_server() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Drain (and discard) the request before responding.
            let mut req_buf = [0u8; 1024];
            let _ = socket.read(&mut req_buf).await;

            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            // MAX_BODY_BYTES is 1 MiB; send well over that across many
            // chunks so the server is genuinely streaming, not buffering.
            let chunk_data = vec![b'a'; 64 * 1024];
            let total_chunks = (MAX_BODY_BYTES / chunk_data.len()) + 4;
            for _ in 0..total_chunks {
                let header = format!("{:x}\r\n", chunk_data.len());
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&chunk_data).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }
            socket.write_all(b"0\r\n\r\n").await.unwrap();
            let _ = socket.shutdown().await;
        });

        format!("http://{addr}/big")
    }

    #[tokio::test]
    async fn streamed_body_over_cap_is_rejected_without_full_buffering() {
        let url = spawn_oversized_chunked_server().await;
        let c = reqwest::Client::new();
        let policy = FetchPolicy::permissive();
        let r = guarded_get(&c, &url, "text/plain", &policy).await;
        assert!(r.is_err(), "oversized streamed body must be rejected");
    }

    /// A malicious/compromised host (issuer or webid — both
    /// attacker-influenced) that passes the initial IP check but then
    /// 302-redirects to an internal address (e.g. `169.254.169.254`) must
    /// not have that redirect transparently followed. This proves the
    /// guard holds even when the client uses `Policy::none()`: the redirect
    /// surfaces as a non-2xx status and is rejected, not chased.
    async fn spawn_redirect_server() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut req_buf = [0u8; 1024];
            let _ = socket.read(&mut req_buf).await;

            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\n\
                      Location: http://169.254.169.254/secret\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let _ = socket.shutdown().await;
        });

        format!("http://{addr}/redirect-me")
    }

    fn named(hosts: &[&str]) -> FetchPolicy {
        FetchPolicy::with_insecure_hosts(hosts.iter().map(|h| h.to_string()))
    }

    // The rule is "named by the operator", not "private vs public": a host
    // the operator vouched for may be private and may be plain http.
    #[tokio::test]
    async fn a_named_host_may_be_private() {
        let addrs = resolve_allowed("127.0.0.1", 3001, &named(&["127.0.0.1"])).await;
        assert!(addrs.is_ok(), "an operator-named host must be reachable");
    }

    #[tokio::test]
    async fn an_unnamed_host_is_still_blocked() {
        let addrs = resolve_allowed("127.0.0.1", 3001, &named(&["other.example"])).await;
        assert!(addrs.is_err(), "naming one host must not unblock another");
    }

    // Naming a host:port must not open every port on that host — port
    // scanning is most of what an SSRF primitive is worth.
    #[tokio::test]
    async fn naming_a_port_does_not_open_the_others() {
        let policy = named(&["127.0.0.1:3001"]);
        assert!(resolve_allowed("127.0.0.1", 3001, &policy).await.is_ok());
        assert!(resolve_allowed("127.0.0.1", 9999, &policy).await.is_err());
    }

    #[tokio::test]
    async fn naming_a_bare_host_opens_every_port_on_it() {
        let policy = named(&["127.0.0.1"]);
        assert!(resolve_allowed("127.0.0.1", 3001, &policy).await.is_ok());
        assert!(resolve_allowed("127.0.0.1", 9999, &policy).await.is_ok());
    }

    #[tokio::test]
    async fn an_empty_host_list_is_the_default_posture() {
        let addrs = resolve_allowed("127.0.0.1", 3001, &named(&[])).await;
        assert!(addrs.is_err());
    }

    // http is permitted for a named host and refused everywhere else.
    #[tokio::test]
    async fn http_is_refused_for_an_unnamed_host() {
        let c = reqwest::Client::new();
        let r = guarded_get(&c, "http://example.com/x", "text/turtle", &named(&["other.example"]))
            .await;
        assert!(matches!(r, Err(AuthError::FetchBlocked(_))));
    }

    // The Critical fix: `permits_insecure` used to build its port-scoped key
    // via `format!("{host}:{port}")` and look it up in the *same* flat set
    // as the bare-host check. For an entry like `fd00::1:80` (the exact
    // spelling the docs used to instruct, meaning "host fd00::1, port 80"),
    // that concatenation is itself a syntactically valid, *different* IPv6
    // address — so the bare-host arm matched it and opened every port on
    // `fd00::1:80`, an address nobody named. Entries are now parsed once,
    // structurally, and this exact spelling — ambiguous between "the
    // address fd00::1:80" and "fd00::1 + port 80" — is dropped rather than
    // guessed at, so it must not permit `fd00::1:80` on any port.
    #[tokio::test]
    async fn an_ambiguous_ipv6_host_port_entry_does_not_alias_a_different_address() {
        let policy = named(&["fd00::1:80"]);
        assert!(
            resolve_allowed("fd00::1:80", 22, &policy).await.is_err(),
            "an ambiguous entry must not alias a different address"
        );
        assert!(
            resolve_allowed("fd00::1:80", 6379, &policy).await.is_err(),
            "an ambiguous entry must not alias a different address on any port"
        );
        assert!(
            resolve_allowed("fd00::1:80", 80, &policy).await.is_err(),
            "an ambiguous entry must not alias a different address even on the port it names"
        );
    }

    // The bracketed form is the unambiguous way to pair an IPv6 host with a
    // port — it must actually work (Minor 5 in the review: it was silently
    // inert before this fix) and must stay port-scoped like any other
    // `host:port` entry.
    #[tokio::test]
    async fn bracketed_ipv6_entry_is_port_scoped() {
        let policy = named(&["[::1]:3001"]);
        assert!(resolve_allowed("::1", 3001, &policy).await.is_ok());
        assert!(resolve_allowed("::1", 9999, &policy).await.is_err());
    }

    // A bare (unbracketed) IPv6 address with no trailing ambiguity opens
    // every port on it, same as a bare hostname or IPv4 literal.
    #[tokio::test]
    async fn bare_ipv6_entry_opens_every_port_on_it() {
        let policy = named(&["fd00::1"]);
        assert!(resolve_allowed("fd00::1", 80, &policy).await.is_ok());
        assert!(resolve_allowed("fd00::1", 9999, &policy).await.is_ok());
    }

    #[tokio::test]
    async fn redirect_to_forbidden_target_is_not_followed() {
        let url = spawn_redirect_server().await;
        // Mirrors the production client construction: redirects disabled.
        let c = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let policy = FetchPolicy::permissive();
        let r = guarded_get(&c, &url, "text/plain", &policy).await;
        assert!(
            r.is_err(),
            "a 3xx redirect must not be transparently followed to an unvalidated target"
        );
    }
}
