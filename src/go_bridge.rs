//! Go module/checksum proxy bridge used on macOS.
//!
//! Go's `crypto/x509` deliberately ignores `SSL_CERT_FILE` on macOS. Rather
//! than modifying a user's keychain, hood gives the `go` command loopback HTTP
//! URLs and performs the verified upstream HTTPS requests itself. The bridge
//! preserves `GOPROXY` ordering and comma/pipe fallback semantics, and keeps
//! the original checksum-database verifier identity intact.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::process::Command;
use url::Url;

/// Prefix reserved for authenticated loopback Go bridge requests.
pub(crate) const ROUTE_PREFIX: &str = "/__hood_go/";

/// Effective Go network settings captured from `go env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoBridge {
    proxies: Vec<ProxyEntry>,
    sumdb: SumDb,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyEntry {
    endpoint: ProxyEndpoint,
    fallback: Option<Fallback>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProxyEndpoint {
    Bridge(Url),
    Direct,
    Off,
    File(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fallback {
    NotFound,
    AnyError,
}

impl Fallback {
    const fn as_char(self) -> char {
        match self {
            Self::NotFound => ',',
            Self::AnyError => '|',
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SumDb {
    Off,
    Verify { identity: String, target: Url },
}

/// Environment values injected into the child `go` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoChildEnv {
    /// Loopback-only replacement for the effective `GOPROXY` value.
    pub goproxy: String,
    /// Original sumdb identity/key paired with a loopback transport URL.
    pub gosumdb: String,
}

impl GoBridge {
    /// Query the real Go binary for settings that may come from either the
    /// process environment or Go's persistent `go env -w` configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `go env` fails or reports invalid network settings.
    pub async fn query(go_binary: &Path) -> Result<Self> {
        let output = Command::new(go_binary)
            .args(["env", "GOPROXY", "GOSUMDB"])
            .output()
            .await
            .with_context(|| format!("run {} env", go_binary.display()))?;
        if !output.status.success() {
            return Err(anyhow!(
                "{} env failed with status {}: {}",
                go_binary.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            ));
        }
        let stdout = String::from_utf8(output.stdout).context("go env output is not UTF-8")?;
        let mut lines = stdout.split('\n');
        let goproxy = lines.next().unwrap_or_default().trim_end_matches('\r');
        let gosumdb = lines.next().unwrap_or_default().trim_end_matches('\r');
        Self::new(goproxy, gosumdb)
    }

    /// Parse effective `GOPROXY` and `GOSUMDB` values into validated state.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unsupported proxy and sumdb URLs.
    pub fn new(goproxy: &str, gosumdb: &str) -> Result<Self> {
        Ok(Self {
            proxies: parse_proxy_chain(goproxy)?,
            sumdb: parse_sumdb(gosumdb)?,
        })
    }

    /// Build child values once the proxy has bound its ephemeral port and its
    /// per-run route token is known.
    #[must_use]
    pub fn child_env(&self, addr: SocketAddr, token: &str) -> GoChildEnv {
        let mut goproxy = String::new();
        for entry in &self.proxies {
            match &entry.endpoint {
                ProxyEndpoint::Bridge(url) => goproxy.push_str(&bridge_base(addr, token, url)),
                ProxyEndpoint::Direct => goproxy.push_str("direct"),
                ProxyEndpoint::Off => goproxy.push_str("off"),
                ProxyEndpoint::File(url) => goproxy.push_str(url),
            }
            if let Some(fallback) = entry.fallback {
                goproxy.push(fallback.as_char());
            }
        }

        let gosumdb = match &self.sumdb {
            SumDb::Off => "off".to_owned(),
            SumDb::Verify { identity, target } => {
                format!("{identity} {}", bridge_base(addr, token, target))
            }
        };
        GoChildEnv { goproxy, gosumdb }
    }
}

/// Convert a loopback bridge request URI into its verified upstream target.
pub(crate) fn resolve_request(uri: &hyper::Uri, token: &str) -> Result<Option<Url>> {
    let expected = format!("{ROUTE_PREFIX}{token}/");
    let Some(rest) = uri.path().strip_prefix(&expected) else {
        return Ok(None);
    };
    let (encoded, suffix) = rest.split_once('/').map_or((rest, ""), |(a, b)| (a, b));
    if encoded.is_empty() {
        return Err(anyhow!("missing Go bridge target"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode Go bridge target")?;
    let raw = String::from_utf8(decoded).context("Go bridge target is not UTF-8")?;
    let mut base = Url::parse(&raw).context("parse Go bridge target")?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(anyhow!(
            "unsupported Go bridge target scheme: {}",
            base.scheme()
        ));
    }
    base.set_fragment(None);
    if suffix.is_empty() {
        return Ok(Some(base));
    }

    // Go module proxy requests have no query string. Preserve a query carried
    // by a configured proxy URL while joining its module-protocol path.
    let configured_query = base.query().map(str::to_owned);
    base.set_query(None);
    if !base.path().ends_with('/') {
        let mut path = base.path().to_owned();
        path.push('/');
        base.set_path(&path);
    }
    let mut target = base.join(suffix).context("join Go bridge request path")?;
    target.set_query(configured_query.as_deref());
    Ok(Some(target))
}

/// Turn an upstream redirect into a relative loopback bridge location.
pub(crate) fn redirect_location(token: &str, target: &Url) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(target.as_str().as_bytes());
    format!("{ROUTE_PREFIX}{token}/{encoded}")
}

fn bridge_base(addr: SocketAddr, token: &str, upstream: &Url) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(upstream.as_str().as_bytes());
    format!("http://{addr}{ROUTE_PREFIX}{token}/{encoded}")
}

fn normalize_proxy_url(entry: &str) -> Result<Url> {
    let candidate = if entry.contains(":/") {
        entry.to_owned()
    } else {
        format!("https://{entry}")
    };
    let url = Url::parse(&candidate).with_context(|| format!("invalid GOPROXY entry {entry:?}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!("unsupported GOPROXY scheme: {}", url.scheme()));
    }
    Ok(url)
}

fn parse_proxy_chain(value: &str) -> Result<Vec<ProxyEntry>> {
    let entries: Vec<_> = value
        .split_inclusive([',', '|'])
        .filter_map(|part| {
            let (endpoint, fallback) = match (part.strip_suffix(','), part.strip_suffix('|')) {
                (Some(endpoint), _) => (endpoint, Some(Fallback::NotFound)),
                (_, Some(endpoint)) => (endpoint, Some(Fallback::AnyError)),
                (None, None) => (part, None),
            };
            let endpoint = endpoint.trim();
            (!endpoint.is_empty()).then_some((endpoint, fallback))
        })
        .map(|(endpoint, fallback)| {
            let endpoint = match endpoint {
                "direct" => ProxyEndpoint::Direct,
                "off" => ProxyEndpoint::Off,
                file if file.starts_with("file:") => ProxyEndpoint::File(file.to_owned()),
                remote => ProxyEndpoint::Bridge(normalize_proxy_url(remote)?),
            };
            Ok(ProxyEntry { endpoint, fallback })
        })
        .collect::<Result<_>>()?;
    if entries.is_empty() {
        return Err(anyhow!("GOPROXY must contain at least one entry"));
    }
    Ok(entries)
}

fn parse_sumdb(value: &str) -> Result<SumDb> {
    if value == "off" {
        return Ok(SumDb::Off);
    }
    let mut fields = value.split_whitespace();
    let raw_identity = fields
        .next()
        .ok_or_else(|| anyhow!("invalid GOSUMDB value {value:?}"))?;
    let explicit_target = fields.next();
    if fields.next().is_some() {
        return Err(anyhow!("invalid GOSUMDB value {value:?}"));
    }

    let identity = if raw_identity == "sum.golang.google.cn" {
        "sum.golang.org"
    } else {
        raw_identity
    };
    let target = sumdb_target(raw_identity, explicit_target)?;
    if !matches!(target.scheme(), "http" | "https") {
        return Err(anyhow!(
            "unsupported GOSUMDB URL scheme: {}",
            target.scheme()
        ));
    }
    Ok(SumDb::Verify {
        identity: identity.to_owned(),
        target,
    })
}

fn sumdb_target(identity: &str, explicit: Option<&str>) -> Result<Url> {
    if let Some(explicit) = explicit {
        return Url::parse(explicit).with_context(|| format!("invalid GOSUMDB URL {explicit:?}"));
    }
    if identity == "sum.golang.google.cn" {
        return Url::parse("https://sum.golang.google.cn").context("parse Go sumdb alias URL");
    }
    let name = identity.split_once('+').map_or(identity, |(name, _)| name);
    Url::parse(&format!("https://{name}")).with_context(|| format!("invalid GOSUMDB name {name:?}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef";

    fn addr() -> SocketAddr {
        "127.0.0.1:43210".parse().unwrap()
    }

    #[test]
    fn goproxy_order_and_fallback_separators_are_preserved() {
        let bridge = GoBridge::new(
            "https://private.example/proxy|proxy.golang.org,direct",
            "sum.golang.org",
        )
        .unwrap();
        let child = bridge.child_env(addr(), TOKEN);
        assert!(child.goproxy.starts_with("http://127.0.0.1:43210/"));
        assert!(child.goproxy.contains('|'));
        assert!(child.goproxy.contains(",direct"));
        assert!(!child.goproxy.contains("https://private.example"));
    }

    #[test]
    fn bridge_route_restores_proxy_base_and_raw_module_path() {
        let bridge = GoBridge::new("https://proxy.example/base", "off").unwrap();
        let child = bridge.child_env(addr(), TOKEN);
        let uri: hyper::Uri = format!("{}/golang.org/x/text/@v/v0.3.2.mod", child.goproxy)
            .parse()
            .unwrap();
        let target = resolve_request(&uri, TOKEN).unwrap().unwrap();
        assert_eq!(
            target.as_str(),
            "https://proxy.example/base/golang.org/x/text/@v/v0.3.2.mod",
        );
    }

    #[test]
    fn sumdb_identity_and_key_are_preserved() {
        let identity = "corp.example+0123456789+abcdefghijklmnop";
        let bridge = GoBridge::new(
            "https://proxy.golang.org",
            &format!("{identity} https://sum.corp.example/base"),
        )
        .unwrap();
        let child = bridge.child_env(addr(), TOKEN);
        assert!(
            child
                .gosumdb
                .starts_with(&format!("{identity} http://127.0.0.1:"))
        );
        assert!(!child.gosumdb.contains("https://sum.corp.example"));
    }

    #[test]
    fn sumdb_off_stays_off() {
        let bridge = GoBridge::new("https://proxy.golang.org", "off").unwrap();
        assert_eq!(bridge.child_env(addr(), TOKEN).gosumdb, "off");
    }

    #[test]
    fn redirect_round_trip_accepts_an_arbitrary_https_origin() {
        let target = Url::parse("https://storage.example/object.zip?signature=abc").unwrap();
        let location = redirect_location(TOKEN, &target);
        let uri: hyper::Uri = location.parse().unwrap();
        assert_eq!(resolve_request(&uri, TOKEN).unwrap(), Some(target));
    }

    #[test]
    fn wrong_token_does_not_resolve() {
        let uri: hyper::Uri = "/__hood_go/not-the-token/abc".parse().unwrap();
        assert_eq!(resolve_request(&uri, TOKEN).unwrap(), None);
    }

    #[test]
    fn malformed_network_settings_are_rejected_at_construction() {
        assert!(GoBridge::new("", "sum.golang.org").is_err());
        assert!(GoBridge::new("ftp://proxy.example", "sum.golang.org").is_err());
        assert!(GoBridge::new("https://proxy.example", "").is_err());
        assert!(GoBridge::new("https://proxy.example", "name one two").is_err());
    }
}
