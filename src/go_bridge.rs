//! Go module/checksum proxy bridge used on macOS.
//!
//! Go's `crypto/x509` deliberately ignores `SSL_CERT_FILE` on macOS. Rather
//! than modifying a user's keychain, hood gives the `go` command loopback HTTP
//! URLs and performs the verified upstream HTTPS requests itself. The bridge
//! preserves `GOPROXY` ordering and comma/pipe fallback semantics, and keeps
//! the original checksum-database verifier identity intact.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use tokio::process::Command;
use url::Url;

/// Prefix reserved for authenticated loopback Go bridge requests.
pub(crate) const ROUTE_PREFIX: &str = "/__hood_go/";

/// Effective Go network settings captured from `go env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoBridge {
    goproxy: String,
    gosumdb: String,
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

    /// Parse effective `GOPROXY` and `GOSUMDB` values.
    pub fn new(goproxy: &str, gosumdb: &str) -> Result<Self> {
        // Validate now so a malformed persistent Go setting produces a useful
        // hood startup error instead of an opaque local-proxy failure later.
        for (entry, _) in split_goproxy(goproxy) {
            if matches!(entry.as_str(), "direct" | "off") || entry.starts_with("file:") {
                continue;
            }
            drop(normalize_proxy_url(&entry)?);
        }
        validate_sumdb(gosumdb)?;
        Ok(Self {
            goproxy: goproxy.to_owned(),
            gosumdb: gosumdb.to_owned(),
        })
    }

    /// Build child values once the proxy has bound its ephemeral port and its
    /// per-run route token is known.
    pub fn child_env(&self, addr: SocketAddr, token: &str) -> Result<GoChildEnv> {
        let mut goproxy = String::new();
        for (entry, separator) in split_goproxy(&self.goproxy) {
            let bridged =
                if matches!(entry.as_str(), "direct" | "off") || entry.starts_with("file:") {
                    entry
                } else {
                    bridge_base(addr, token, &normalize_proxy_url(&entry)?)
                };
            goproxy.push_str(&bridged);
            if let Some(separator) = separator {
                goproxy.push(separator);
            }
        }

        let gosumdb = bridge_sumdb(&self.gosumdb, addr, token)?;
        Ok(GoChildEnv { goproxy, gosumdb })
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

fn split_goproxy(value: &str) -> Vec<(String, Option<char>)> {
    let mut out = Vec::new();
    let mut remaining = value;
    while !remaining.is_empty() {
        let (piece, separator, rest) = match remaining.find([',', '|']) {
            Some(index) => (
                &remaining[..index],
                remaining[index..].chars().next(),
                &remaining[index + 1..],
            ),
            None => (remaining, None, ""),
        };
        let piece = piece.trim();
        if !piece.is_empty() {
            out.push((piece.to_owned(), separator));
        }
        remaining = rest;
    }
    out
}

fn validate_sumdb(value: &str) -> Result<()> {
    if value == "off" {
        return Ok(());
    }
    let fields: Vec<&str> = value.split_whitespace().collect();
    if fields.is_empty() || fields.len() > 2 {
        return Err(anyhow!("invalid GOSUMDB value {value:?}"));
    }
    let target = sumdb_target(&fields)?;
    if !matches!(target.scheme(), "http" | "https") {
        return Err(anyhow!(
            "unsupported GOSUMDB URL scheme: {}",
            target.scheme()
        ));
    }
    Ok(())
}

fn bridge_sumdb(value: &str, addr: SocketAddr, token: &str) -> Result<String> {
    if value == "off" {
        return Ok(value.to_owned());
    }
    let fields: Vec<&str> = value.split_whitespace().collect();
    validate_sumdb(value)?;
    let identity = if fields[0] == "sum.golang.google.cn" {
        "sum.golang.org"
    } else {
        fields[0]
    };
    let target = sumdb_target(&fields)?;
    Ok(format!("{identity} {}", bridge_base(addr, token, &target)))
}

fn sumdb_target(fields: &[&str]) -> Result<Url> {
    if fields[0] == "sum.golang.google.cn" && fields.len() == 1 {
        return Url::parse("https://sum.golang.google.cn").context("parse Go sumdb alias URL");
    }
    if let Some(explicit) = fields.get(1) {
        return Url::parse(explicit).with_context(|| format!("invalid GOSUMDB URL {explicit:?}"));
    }
    let name = fields[0]
        .split_once('+')
        .map_or(fields[0], |(name, _)| name);
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
        let child = bridge.child_env(addr(), TOKEN).unwrap();
        assert!(child.goproxy.starts_with("http://127.0.0.1:43210/"));
        assert!(child.goproxy.contains('|'));
        assert!(child.goproxy.contains(",direct"));
        assert!(!child.goproxy.contains("https://private.example"));
    }

    #[test]
    fn bridge_route_restores_proxy_base_and_raw_module_path() {
        let bridge = GoBridge::new("https://proxy.example/base", "off").unwrap();
        let child = bridge.child_env(addr(), TOKEN).unwrap();
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
        let child = bridge.child_env(addr(), TOKEN).unwrap();
        assert!(child
            .gosumdb
            .starts_with(&format!("{identity} http://127.0.0.1:")));
        assert!(!child.gosumdb.contains("https://sum.corp.example"));
    }

    #[test]
    fn sumdb_off_stays_off() {
        let bridge = GoBridge::new("https://proxy.golang.org", "off").unwrap();
        assert_eq!(bridge.child_env(addr(), TOKEN).unwrap().gosumdb, "off");
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
}
