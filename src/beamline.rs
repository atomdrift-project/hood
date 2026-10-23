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

/// isotope13's API, and the only origin the subscription token is sent to.
const API_URL: &str = "https://api.isotope13.ai";

/// The isotope13 token for requests to `base`: `ISOTOPE13_TOKEN`, else the one
/// `hood login` saved. Only ever for [`API_URL`] itself — `HOOD_BEAMLINE_URL`
/// pointing anywhere else gets no token, so redirecting the endpoint can never
/// carry a subscriber's credential with it.
fn isotope13_token(base: &str) -> Option<String> {
    if base.trim_end_matches('/') != API_URL {
        return None;
    }
    match cleave::enriched::token() {
        Ok(found) => found.map(|(token, _)| token.secret().to_owned()),
        Err(error) => {
            tracing::warn!(%error, "isotope13 token unusable; asking Beamline without one");
            None
        }
    }
}

pub(crate) struct Client {
    /// Built on first use with the process-wide roots the proxy prefetches,
    /// so intercepted commands never wait on a root-store load up front.
    http: tokio::sync::OnceCell<reqwest::Client>,
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
        let base = std::env::var("HOOD_BEAMLINE_URL").unwrap_or_else(|_| API_URL.to_owned());
        let mut client = Self::new(&base, isotope13_token(&base))?;
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
        Ok(Self {
            http: tokio::sync::OnceCell::new(),
            base,
            token,
            slots: Semaphore::new(4),
            cache: None,
        })
    }

    async fn http(&self) -> Result<&reqwest::Client> {
        self.http
            .get_or_try_init(|| async {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let https = self.base.scheme() == "https";
                // A detached thread, not `spawn_blocking`: runtime shutdown
                // waits for blocking tasks, and a stalled root-store load must
                // not hold the user's command open after it finishes.
                std::thread::Builder::new()
                    .name("hood-beamline-tls".to_owned())
                    .spawn(move || {
                        let builder = reqwest::Client::builder()
                            .no_proxy()
                            .redirect(reqwest::redirect::Policy::none())
                            .connect_timeout(Duration::from_secs(5));
                        // A plain-HTTP endpoint (loopback only) needs no roots.
                        let builder = if https {
                            let mut tls = rustls::ClientConfig::builder()
                                .with_root_certificates(crate::proxy::native_roots().clone())
                                .with_no_client_auth();
                            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
                            builder.use_preconfigured_tls(tls)
                        } else {
                            builder.tls_built_in_native_certs(false)
                        };
                        drop(tx.send(builder.build().context("build Beamline client")));
                    })
                    .context("spawn Beamline client builder")?;
                rx.await.context("Beamline client builder exited")?
            })
            .await
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
        let http = self.http().await?;
        let request = if analyze {
            http.post(url)
        } else {
            http.get(url)
        };
        let request = if let Some(token) = &self.token {
            request.bearer_auth(token)
        } else {
            request
        };
        let mut response = tokio::time::timeout(IDLE_TIMEOUT, request.send())
            .await
            .context("Beamline headers timed out")?
            .map_err(reqwest::Error::without_url)?;
        // Reject redirects too: neither identifiers nor authentication may be forwarded.
        if !response.status().is_success() {
            bail!("{}", rejection(&mut response).await);
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

/// Largest error body read for a message.
const MAX_ERROR_BODY: usize = 4096;

/// Describe a non-success response with the server's own explanation, such
/// as a 429's spent hourly quota, so users can see why hood fell back to a
/// slower local scan.
async fn rejection(response: &mut reqwest::Response) -> String {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(printable);
    let mut body = Vec::new();
    while body.len() < MAX_ERROR_BODY
        && let Ok(Ok(Some(chunk))) = tokio::time::timeout(IDLE_TIMEOUT, response.chunk()).await
    {
        body.extend_from_slice(&chunk);
    }
    body.truncate(MAX_ERROR_BODY);
    let mut message = format!("Beamline returned HTTP {status}");
    if let Some(detail) = server_message(&body) {
        message.push_str(": ");
        message.push_str(&detail);
    }
    if let Some(retry_after) = retry_after.filter(|value| !value.is_empty()) {
        // Beamline sends whole seconds; an HTTP date passes through as is.
        let unit = if retry_after.bytes().all(|b| b.is_ascii_digit()) {
            "s"
        } else {
            ""
        };
        message.push_str(" (retry after ");
        message.push_str(&retry_after);
        message.push_str(unit);
        message.push(')');
    }
    message
}

/// Extract a server's error message: Beamline's `{"error": {"code",
/// "message"}}` envelope (the message is for people, the code a fallback),
/// else the first line of text. Control characters are dropped so an
/// endpoint cannot inject terminal escapes into hood's output.
fn server_message(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let message = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|value| {
            let error = value.get("error")?;
            ["message", "code"]
                .into_iter()
                .find_map(|key| error.get(key)?.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| text.lines().next().unwrap_or_default().to_owned());
    let message = printable(&message);
    (!message.is_empty()).then_some(message)
}

/// Keep at most 200 printable characters.
fn printable(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .trim()
        .to_owned()
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
    // GitHub archives may be private. A private npm scope is never fetched without
    // credentials, and the caller already sends authenticated requests by hash, so
    // an unauthenticated scoped package on the public registry is public.
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
    fletch::url_to_purl(raw)
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

    /// The subscription token goes to isotope13's API and nowhere else, so an
    /// endpoint override can never carry it away — whatever token is saved.
    #[test]
    fn the_token_never_follows_an_endpoint_override() {
        for base in [
            "https://beamline.example",
            "http://127.0.0.1:8787",
            "https://api.isotope13.ai.example",
            "https://api.isotope13.ai:8443",
        ] {
            assert_eq!(isotope13_token(base), None, "{base}");
        }
    }

    #[test]
    fn only_unambiguous_public_coordinates_are_disclosed() {
        assert_eq!(
            public_purl("https://registry.npmjs.org/demo/-/demo-1.2.3.tgz").as_deref(),
            Some("pkg:npm/demo@1.2.3")
        );
        // A scope on the public registry is a mainstream coordinate; a private
        // scope's download is authenticated, and the caller hashes those.
        assert!(public_purl("https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz").is_some());
        for url in [
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
    async fn rejections_report_status_and_server_message() {
        for (body, expected) in [
            (
                r#"{"error":{"code":"quota_exceeded","message":"anonymous quota exceeded, visit https://dash.isotope13.io/ for a token"}}"#,
                "Beamline returned HTTP 429 Too Many Requests: anonymous quota exceeded, visit https://dash.isotope13.io/ for a token",
            ),
            (
                r#"{"error":{"code":"quota_exceeded"}}"#,
                "Beamline returned HTTP 429 Too Many Requests: quota_exceeded",
            ),
            (
                "slow down\u{1b}[31m\nsecond line",
                "Beamline returned HTTP 429 Too Many Requests: slow down[31m",
            ),
            ("", "Beamline returned HTTP 429 Too Many Requests"),
        ] {
            let mock = server(vec![(429, vec![body.to_owned()])]).await;
            let client = Client::new(&mock.url, None).unwrap();
            let error = client.assess(None, SHA).await.unwrap_err();
            assert_eq!(error.to_string(), expected);
        }
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
