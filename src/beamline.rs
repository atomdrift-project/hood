//! Minimal-disclosure Beamline transport. Never accepts artifact bytes or URLs.

// Explicit crate visibility satisfies rustc's unreachable_pub lint; Clippy's
// redundant_pub_crate recommendation conflicts with it in this internal module.
#![allow(clippy::redundant_pub_crate)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use scan::model::Classification;
use serde::{Deserialize, Serialize};

use crate::beamline_cache::Cache;
use tokio::sync::Semaphore;
use url::Url;

pub(crate) const FOLLOW: &str = "references";
pub(crate) const BUDGET: &str = "25";

const MAX_LINE: usize = 64 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const ANALYSIS_TIMEOUT: Duration = Duration::from_mins(30);

/// A measured assessment. Unrecognized statuses/severities never authorize release.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Assessment {
    status: String,
    severity: String,
    sha256: Option<String>,
    #[serde(default)]
    pub(crate) findings: Vec<Finding>,
    pub(crate) reason: Option<String>,
    pub(crate) engine_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Finding {
    pub(crate) id: String,
    pub(crate) desc: Option<String>,
}

impl Assessment {
    pub(crate) fn classification(&self, sha256: &str) -> Option<Classification> {
        if self.status != "analyzed" || !self.sha256.as_ref()?.eq_ignore_ascii_case(sha256) {
            return None;
        }
        match self.severity.as_str() {
            "benign" => Some(Classification::Benign),
            "suspicious" => Some(Classification::Suspicious),
            "hostile" => Some(Classification::Hostile),
            _ => None,
        }
    }
}

pub(crate) struct Client {
    http: reqwest::Client,
    base: Url,
    token: Option<String>,
    slots: Semaphore,
    cache: Option<Arc<Cache>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither the token nor a configured private endpoint belongs in logs.
        f.debug_struct("BeamlineClient").finish_non_exhaustive()
    }
}

impl Client {
    pub(crate) fn from_env() -> Result<Option<Self>> {
        if std::env::var("HOOD_LOCAL").as_deref() == Ok("1") {
            return Ok(None);
        }
        let base = std::env::var("HOOD_BEAMLINE_URL")
            .unwrap_or_else(|_| "https://api.isotope13.ai".to_owned());
        let token = std::env::var("HOOD_BEAMLINE_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        let mut client = Self::new(&base, token)?;
        client.cache = match Cache::from_env(client.base.as_str(), client.token.as_deref()) {
            Ok(cache) => cache.map(Arc::new),
            Err(error) => {
                tracing::warn!(%error, "Beamline cache disabled; remote assessment remains enabled");
                None
            }
        };
        Ok(Some(client))
    }

    pub(crate) fn new(base: &str, token: Option<String>) -> Result<Self> {
        let base = Url::parse(base).context("invalid Beamline endpoint")?;
        let loopback = base.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if (base.scheme() != "https" && !(base.scheme() == "http" && loopback))
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            bail!("Beamline endpoint must be an HTTPS origin (HTTP allowed on loopback)");
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .build()
            .context("build Beamline client")?;
        Ok(Self {
            http,
            base,
            token,
            slots: Semaphore::new(4),
            cache: None,
        })
    }

    /// No retries: outages, quotas, and incomplete streams go to local analysis.
    pub(crate) async fn assess(&self, purl: Option<&str>, sha256: &str) -> Result<Assessment> {
        if let Some(cache) = &self.cache {
            let cache = Arc::clone(cache);
            let sha = sha256.to_owned();
            if let Ok(Some(assessment)) = tokio::task::spawn_blocking(move || cache.get(&sha)).await
            {
                tracing::debug!("using cached Beamline assessment");
                return Ok(assessment);
            }
        }
        let result = self.assess_remote(purl, sha256).await?;
        if result.classification(sha256).is_some()
            && let Some(cache) = &self.cache
        {
            let cache = Arc::clone(cache);
            let sha = sha256.to_owned();
            let stored = result.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || cache.put(&sha, stored))
                .await
                .context("Beamline cache write task")
                .and_then(std::convert::identity)
            {
                tracing::debug!(%error, "could not cache Beamline assessment");
            }
        }
        Ok(result)
    }

    async fn assess_remote(&self, purl: Option<&str>, sha256: &str) -> Result<Assessment> {
        // Don't queue installs behind a saturated remote service; use the local engine.
        let _slot = self
            .slots
            .try_acquire()
            .context("Beamline concurrency limit")?;
        let budget = if purl.is_some() {
            ANALYSIS_TIMEOUT
        } else {
            IDLE_TIMEOUT
        };
        tokio::time::timeout(budget, async {
            if let Some(purl) = purl {
                let result = self.request("purl", purl).await?;
                if result.status != "analyzed" || result.classification(sha256).is_some() {
                    return Ok(result);
                }
                // A release may resolve to another wheel or archive. Ask about our bytes.
            }
            self.request("sha256", sha256).await
        })
        .await
        .context("Beamline deadline exceeded")?
    }

    async fn request(&self, kind: &str, value: &str) -> Result<Assessment> {
        let analyze = kind == "purl";
        let mut url = self.base.clone();
        url.set_path(if analyze { "/v1/analyze" } else { "/v1/lookup" });
        url.query_pairs_mut()
            .append_pair(kind, value)
            .append_pair("follow", FOLLOW)
            .append_pair("false_positive_budget", BUDGET);
        let request = if analyze {
            self.http.post(url)
        } else {
            self.http.get(url)
        };
        let request = if let Some(token) = &self.token {
            request.bearer_auth(token)
        } else {
            request
        };
        let mut response = tokio::time::timeout(IDLE_TIMEOUT, request.send())
            .await
            .context("Beamline headers timed out")?
            .map_err(reqwest::Error::without_url)?
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        // Reject redirects too: neither identifiers nor authentication may be forwarded.
        if !response.status().is_success() {
            bail!("Beamline returned HTTP {}", response.status());
        }
        let mut pending = Vec::new();
        let mut progress_reported = false;
        loop {
            let chunk = tokio::time::timeout(IDLE_TIMEOUT, response.chunk())
                .await
                .context("Beamline stream stalled")?
                .map_err(reqwest::Error::without_url)?;
            let Some(chunk) = chunk else {
                if !pending.is_empty()
                    && let Some(result) = parse_line(&pending)?
                {
                    return Ok(result);
                }
                bail!("Beamline stream ended without an assessment");
            };
            // Process arbitrarily fragmented NDJSON without retaining the stream.
            for segment in chunk.split_inclusive(|b| *b == b'\n') {
                if pending.len() + segment.len() > MAX_LINE {
                    bail!("Beamline frame too large");
                }
                pending.extend_from_slice(segment);
                if segment.last() == Some(&b'\n') {
                    if let Some(result) = parse_line(&pending)? {
                        return Ok(result);
                    }
                    pending.clear();
                    if analyze && !progress_reported {
                        tracing::info!(
                            "Beamline is analyzing the package; download held until assessment"
                        );
                        progress_reported = true;
                    }
                }
            }
        }
    }
}

fn parse_line(line: &[u8]) -> Result<Option<Assessment>> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let value: serde_json::Value =
        serde_json::from_slice(line).context("invalid Beamline frame")?;
    if value.get("status").is_some() {
        return serde_json::from_value(value)
            .map(Some)
            .context("invalid Beamline assessment");
    }
    match value.get("state").and_then(serde_json::Value::as_str) {
        Some("analyzing" | "resumed") => Ok(None),
        _ => bail!("unexpected Beamline frame"),
    }
}

/// Conservative public-coordinate recognition; private/ambiguous origins use hashes.
/// The caller must additionally exclude authenticated requests and cookies.
pub(crate) fn public_purl(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    if url.scheme() != "https"
        || url.port().is_some_and(|port| port != 443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    // GitHub archives may be private, and registry hosts can serve private npm scopes.
    if !matches!(
        url.host_str()?,
        "registry.npmjs.org"
            | "registry.yarnpkg.com"
            | "static.crates.io"
            | "crates.io"
            | "files.pythonhosted.org"
            | "rubygems.org"
            | "proxy.golang.org"
            | "api.nuget.org"
            | "repo1.maven.org"
            | "repo.maven.apache.org"
    ) {
        return None;
    }
    let purl = fletch::url_to_purl(raw)?;
    if purl.starts_with("pkg:npm/%40") || purl.starts_with("pkg:npm/@") {
        return None;
    }
    Some(purl)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::{Cache, Client};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    pub(crate) struct Server {
        pub(crate) url: String,
        pub(crate) requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[allow(clippy::unwrap_used)]
    pub(crate) async fn server(replies: Vec<(u16, Vec<String>)>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            for (status, chunks) in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut byte = [0];
                    if stream.read(&mut byte).await.unwrap() == 0 {
                        return;
                    }
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() < 8192);
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(request).unwrap());
                let length: usize = chunks.iter().map(String::len).sum();
                let header = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/x-ndjson\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(header.as_bytes()).await.is_err() {
                    continue;
                }
                for chunk in chunks {
                    if stream.write_all(chunk.as_bytes()).await.is_err() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
        });
        Server {
            url,
            requests,
            task,
        }
    }

    pub(crate) fn assessment(sha: &str, severity: &str) -> String {
        serde_json::json!({"status":"analyzed", "severity":severity, "sha256":sha, "findings":[]})
            .to_string()
    }

    #[allow(clippy::unwrap_used)]
    pub(crate) fn cached_client(endpoint: &str, root: &std::path::Path) -> Client {
        let mut client = Client::new(endpoint, None).unwrap();
        client.cache = Some(Arc::new(Cache::new(
            root.into(),
            Duration::from_hours(30 * 24),
            client.base.as_str(),
            None,
        )));
        client
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use test_support::{assessment, cached_client, server};
    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn only_unambiguous_public_coordinates_are_disclosed() {
        assert_eq!(
            public_purl("https://registry.npmjs.org/demo/-/demo-1.2.3.tgz").as_deref(),
            Some("pkg:npm/demo@1.2.3")
        );
        for url in [
            "https://registry.npmjs.org/@company/private/-/private-1.0.0.tgz",
            "https://registry.npmjs.org/%40company/private/-/private-1.0.0.tgz",
            "https://codeload.github.com/company/private/tar.gz/v1",
            "https://private.example/demo-1.0.0.tgz",
            "https://registry.npmjs.org/demo/-/demo-1.2.3.tgz?token=private",
            "https://user:secret@registry.npmjs.org/demo/-/demo-1.2.3.tgz",
            "http://registry.npmjs.org/demo/-/demo-1.2.3.tgz",
            "https://registry.npmjs.org:8443/demo/-/demo-1.2.3.tgz",
            "https://registry.npmjs.org.evil.example/demo/-/demo-1.2.3.tgz",
        ] {
            assert_eq!(public_purl(url), None, "{url}");
        }
    }

    #[tokio::test]
    async fn fragmented_analysis_waits_for_terminal_verdict_and_sends_only_locator() {
        let verdict = assessment(SHA, "benign");
        let mock = server(vec![(
            200,
            vec![
                "{\"state\":\"ana".into(),
                "lyzing\"}\n{\"state\":\"resumed\"}\n".into(),
                verdict[..20].into(),
                verdict[20..].into(),
            ],
        )])
        .await;
        let client = Client::new(&mock.url, Some("test-beamline-token".into())).unwrap();
        let result = client
            .assess(Some("pkg:npm/demo@1.2.3"), SHA)
            .await
            .unwrap();
        assert_eq!(result.classification(SHA), Some(Classification::Benign));
        let requests = mock.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert!(request.starts_with("POST /v1/analyze?"));
        assert!(request.contains("purl=pkg%3Anpm%2Fdemo%401.2.3"));
        assert!(request.contains("false_positive_budget=25"));
        assert!(request.contains("authorization: Bearer test-beamline-token"));
        assert!(!request.contains("?url="));
        assert!(!request.contains("&url="));
        assert!(!request.contains("sha256="));
    }

    #[tokio::test]
    async fn different_artifact_requires_exact_hash_lookup() {
        let mock = server(vec![
            (200, vec![assessment(&"b".repeat(64), "benign")]),
            (200, vec![assessment(SHA, "hostile")]),
        ])
        .await;
        let client = Client::new(&mock.url, None).unwrap();
        let result = client.assess(Some("pkg:pypi/demo@1"), SHA).await.unwrap();
        assert_eq!(result.classification(SHA), Some(Classification::Hostile));
        let requests = mock.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with(&format!("GET /v1/lookup?sha256={SHA}")));
        assert!(!requests[1].contains("purl="));
    }

    #[tokio::test]
    async fn quota_errors_and_cut_streams_are_not_retried() {
        for (status, body) in [
            (429, "quota exhausted".to_owned()),
            (503, "unavailable".to_owned()),
            (401, "unauthorized".to_owned()),
            (302, "redirect".to_owned()),
            (200, "{\"state\":\"analyzing\"}\n".to_owned()),
            (200, "invalid json".to_owned()),
            (200, "x".repeat(MAX_LINE + 1)),
        ] {
            let mock = server(vec![(status, vec![body])]).await;
            let client = Client::new(&mock.url, None).unwrap();
            assert!(client.assess(Some("pkg:npm/demo@1"), SHA).await.is_err());
            assert_eq!(mock.requests.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn unavailable_is_not_a_verdict_and_does_not_trigger_second_request() {
        let mock = server(vec![(200, vec![r#"{"status":"unavailable","severity":"unknown","cause":"saturated","findings":[]}"#.into()])]).await;
        let client = Client::new(&mock.url, None).unwrap();
        let result = client.assess(Some("pkg:npm/demo@1"), SHA).await.unwrap();
        assert_eq!(result.classification(SHA), None);
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn silent_connection_times_out() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client =
            Client::new(&format!("http://{}", listener.local_addr().unwrap()), None).unwrap();
        let task = tokio::spawn(async move { client.assess(Some("pkg:npm/demo@1"), SHA).await });
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            request.push(byte[0]);
        }
        tokio::time::pause();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .await
            .unwrap();
        tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn connection_refusal_and_local_saturation_return_for_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client = Client::new(&endpoint, None).unwrap();
        assert!(client.assess(None, SHA).await.is_err());
        let permits = client.slots.acquire_many(4).await.unwrap();
        assert!(
            client
                .assess(None, SHA)
                .await
                .unwrap_err()
                .to_string()
                .contains("concurrency limit")
        );
        drop(permits);
    }

    #[tokio::test]
    async fn disk_cache_reuses_purl_assessment_by_hash_across_clients_without_network() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = server(vec![(200, vec![assessment(SHA, "hostile")])]).await;
        let client = cached_client(&mock.url, tmp.path());
        let first = client.assess(Some("pkg:npm/demo@1"), SHA).await.unwrap();
        assert_eq!(first.classification(SHA), Some(Classification::Hostile));
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
        let endpoint = mock.url.clone();
        drop(client);
        drop(mock);
        // The server is gone and all network slots are occupied: this must be a disk hit.
        let client = cached_client(&endpoint, tmp.path());
        let permits = client.slots.acquire_many(4).await.unwrap();
        let cached = client.assess(None, SHA).await.unwrap();
        drop(permits);
        assert_eq!(cached.classification(SHA), Some(Classification::Hostile));
    }

    #[tokio::test]
    async fn unknown_and_failed_queries_do_not_populate_cache() {
        for (status, body) in [
            (429, "quota"),
            (503, "outage"),
            (200, r#"{"status":"unanalyzed","severity":"unknown"}"#),
            (200, r#"{"status":"unavailable","severity":"unknown"}"#),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let mock = server(vec![
                (status, vec![body.into()]),
                (200, vec![assessment(SHA, "benign")]),
            ])
            .await;
            let client = cached_client(&mock.url, tmp.path());
            drop(client.assess(None, SHA).await);
            let second = client.assess(None, SHA).await.unwrap();
            assert_eq!(second.classification(SHA), Some(Classification::Benign));
            assert_eq!(mock.requests.lock().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn unwritable_cache_does_not_discard_remote_verdict() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // A file cannot be used as a cache directory, on every supported platform.
        let mock = server(vec![(200, vec![assessment(SHA, "benign")])]).await;
        let client = cached_client(&mock.url, tmp.path());
        let result = client.assess(None, SHA).await.unwrap();
        assert_eq!(result.classification(SHA), Some(Classification::Benign));
    }

    #[test]
    fn unknown_and_unbound_assessments_cannot_allow() {
        for body in [
            r#"{"status":"unanalyzed","severity":"benign"}"#,
            r#"{"status":"analyzed","severity":"benign"}"#,
            r#"{"status":"future","severity":"benign","sha256":"a"}"#,
        ] {
            assert_eq!(
                parse_line(body.as_bytes())
                    .unwrap()
                    .unwrap()
                    .classification(SHA),
                None
            );
        }
        let result = parse_line(assessment(SHA, "future").as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(result.classification(SHA), None);
    }
}
