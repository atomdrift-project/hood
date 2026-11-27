//! Minimal-disclosure Beamline transport. Never accepts artifact bytes or URLs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
/// Beamline requests in flight at once; a package manager's parallel
/// downloads queue here rather than flood the API. Waiting in the queue
/// counts against a request's budget.
const MAX_CONCURRENT_LOOKUPS: usize = 8;
/// The longest a spent quota keeps hood from asking, whatever `Retry-After`
/// says: a wrong or forged header must not silence Beamline for good.
const MAX_QUOTA_PAUSE: Duration = Duration::from_hours(24);
/// How long a TCP and TLS connection to Beamline may take before local
/// analysis takes over.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The whole budget for a package analysis, and for a hash lookup. An
/// analysis begins with its download, so most of it is spent while bytes
/// still arrive; a lookup begins once they have, while the tool waiting on
/// hood sees silence: pacman gives up after 10 s, pip after 15 s.
const ANALYSIS_TIMEOUT: Duration = Duration::from_secs(8);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// A measured assessment. Unrecognized statuses/severities never authorize release.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Assessment {
    status: Status,
    severity: Severity,
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

/// How far Beamline got. Only a finished analysis carries a verdict; every
/// other status, including ones added later, is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Analyzed,
    #[serde(other)]
    Other,
}

/// Beamline's verdict. A severity this build does not know is `Unknown`, and
/// authorizes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Benign,
    Suspicious,
    Hostile,
    #[serde(other)]
    Unknown,
}

impl Assessment {
    /// The verdict, only if it is a finished analysis of exactly `sha256`.
    pub(crate) fn classification(&self, sha256: &str) -> Option<Classification> {
        if self.status != Status::Analyzed || !self.sha256.as_ref()?.eq_ignore_ascii_case(sha256) {
            return None;
        }
        match self.severity {
            Severity::Benign => Some(Classification::Benign),
            Severity::Suspicious => Some(Classification::Suspicious),
            Severity::Hostile => Some(Classification::Hostile),
            Severity::Unknown => None,
        }
    }

    /// Whether this is a finished analysis with a verdict, on whichever
    /// bytes it names.
    pub(crate) fn is_verdict(&self) -> bool {
        self.sha256
            .as_deref()
            .is_some_and(|sha256| self.classification(sha256).is_some())
    }
}

/// What a request asks Beamline about.
#[derive(Debug, Clone, Copy)]
enum Query<'a> {
    /// A public package coordinate, analyzed on demand.
    Purl(&'a str),
    /// Exact bytes, looked up by digest.
    Sha256(&'a str),
}

/// isotope13's API, and the only origin the subscription token is sent to.
const API_URL: &str = "https://api.isotope13.ai";

/// The isotope13 token for requests to `base`: `ISOTOPE13_TOKEN`, else the one
/// `hood uplink` saved. Only ever for [`API_URL`] itself — `HOOD_BEAMLINE_URL`
/// pointing anywhere else gets no token, so redirecting the endpoint can never
/// carry a subscriber's credential with it.
fn isotope13_token(base: &str) -> Option<String> {
    if base.trim_end_matches('/') != API_URL {
        return None;
    }
    match cleave::feed::token() {
        Ok(found) => found.map(|(token, _)| token.secret().to_owned()),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "isotope13 token unusable; asking Beamline without one");
            None
        }
    }
}

/// True when `url` names this machine: `localhost` or a loopback IP literal.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
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
    /// When a spent quota resets, in seconds since the epoch; 0 if it is not
    /// known to be spent. Nothing is asked before then.
    quota_reset: AtomicU64,
    /// Whether this run has said that the quota is spent.
    quota_reported: AtomicBool,
}

/// Why a request was not sent: the quota is spent, and the server said when
/// it resets. The run says so once; after that, only this.
#[derive(Debug)]
pub(crate) struct QuotaSpent;

impl std::fmt::Display for QuotaSpent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Beamline quota is spent")
    }
}

impl std::error::Error for QuotaSpent {}

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
        // A loopback endpoint is a development or test server; its answers
        // are not worth keeping across runs.
        if !is_loopback(&client.base)
            && let Some(root) = dirs::cache_dir()
        {
            client = client.caching_under(root.join("atomdrift/hood/beamline/v1"));
        }
        Ok(Some(client))
    }

    /// Keep verdicts, and word of a spent quota, under `root` between runs.
    fn caching_under(mut self, root: std::path::PathBuf) -> Self {
        let cache = Cache::new(root, self.base.as_str(), self.token.as_deref());
        // A quota an earlier run spent is still spent.
        if let Some(reset) = cache.quota_reset() {
            self.quota_reset = AtomicU64::new(reset);
        }
        self.cache = Some(Arc::new(cache));
        self
    }

    pub(crate) fn new(base: &str, token: Option<String>) -> Result<Self> {
        let base = Url::parse(base).context("invalid Beamline endpoint")?;
        if (base.scheme() != "https" && !(base.scheme() == "http" && is_loopback(&base)))
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
            slots: Semaphore::new(MAX_CONCURRENT_LOOKUPS),
            cache: None,
            quota_reset: AtomicU64::new(0),
            quota_reported: AtomicBool::new(false),
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
                            .connect_timeout(CONNECT_TIMEOUT);
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

    /// The assessment of exactly `sha256`: by analyzing `purl`, when there is
    /// a public coordinate to ask about, then by digest.
    ///
    /// No retries: outages, quotas, and incomplete streams go to local analysis.
    pub(crate) async fn assess(&self, purl: Option<&str>, sha256: &str) -> Result<Assessment> {
        if let Some(assessment) = self.cached(sha256).await {
            return Ok(assessment);
        }
        let early = match purl {
            Some(purl) => Some(self.analyze(purl).await),
            None => None,
        };
        self.settle(early, sha256).await
    }

    /// Analyze a public package coordinate. This needs none of the package's
    /// bytes, so it can run while they download; [`Self::settle`] then checks
    /// the answer against them. A verdict is kept, so a later run of the same
    /// install asks nothing.
    pub(crate) async fn analyze(&self, purl: &str) -> Result<Assessment> {
        let coordinate = purl.to_owned();
        if let Some(assessment) = self
            .with_cache(move |cache| cache.coordinate(&coordinate))
            .await
            .flatten()
        {
            tracing::debug!("using cached Beamline analysis");
            return Ok(assessment);
        }
        let result = self.ask(Query::Purl(purl), ANALYSIS_TIMEOUT).await?;
        let (coordinate, stored) = (purl.to_owned(), result.clone());
        self.store(move |cache| cache.put_coordinate(&coordinate, stored))
            .await;
        Ok(result)
    }

    /// The assessment of exactly `sha256`, given what [`Self::analyze`] said
    /// of its coordinate, if that was asked.
    pub(crate) async fn settle(
        &self,
        early: Option<Result<Assessment>>,
        sha256: &str,
    ) -> Result<Assessment> {
        if let Some(assessment) = self.cached(sha256).await {
            return Ok(assessment);
        }
        let result = match early {
            // A release may resolve to another wheel or archive. Ask about our bytes.
            Some(Ok(early))
                if early.status == Status::Analyzed && early.classification(sha256).is_none() =>
            {
                self.ask(Query::Sha256(sha256), LOOKUP_TIMEOUT).await?
            }
            Some(early) => early?,
            None => self.ask(Query::Sha256(sha256), LOOKUP_TIMEOUT).await?,
        };
        let (sha, stored) = (sha256.to_owned(), result.clone());
        self.store(move |cache| cache.put(&sha, stored)).await;
        Ok(result)
    }

    /// The stored verdict on exactly `sha256`.
    async fn cached(&self, sha256: &str) -> Option<Assessment> {
        let sha = sha256.to_owned();
        let assessment = self.with_cache(move |cache| cache.get(&sha)).await??;
        tracing::debug!("using cached Beamline assessment");
        Some(assessment)
    }

    /// Run `job` against the cache, off the async runtime; `None` without one.
    async fn with_cache<T: Send + 'static>(
        &self,
        job: impl FnOnce(&Cache) -> T + Send + 'static,
    ) -> Option<T> {
        let cache = Arc::clone(self.cache.as_ref()?);
        tokio::task::spawn_blocking(move || job(&cache))
            .await
            .inspect_err(|error| tracing::debug!(%error, "Beamline cache task failed"))
            .ok()
    }

    /// Write to the cache. A failure costs a later lookup, not this verdict.
    async fn store(&self, write: impl FnOnce(&Cache) -> Result<()> + Send + 'static) {
        if let Some(Err(error)) = self.with_cache(write).await {
            tracing::debug!(error = %format!("{error:#}"), "could not write Beamline cache");
        }
    }

    /// Send one request within `budget`, unless the quota is known spent.
    async fn ask(&self, query: Query<'_>, budget: Duration) -> Result<Assessment> {
        let reset = self.quota_reset.load(Ordering::Relaxed);
        if let Some(wait) = quota_wait(reset, SystemTime::now()) {
            if !self.quota_reported.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "Beamline quota is spent for another {}; scanning locally",
                    rounded(wait)
                );
            }
            return Err(QuotaSpent.into());
        }
        tokio::time::timeout(budget, async {
            let _slot = self
                .slots
                .acquire()
                .await
                .context("Beamline client closed")?;
            self.request(query).await
        })
        .await
        .context("Beamline deadline exceeded")?
    }

    /// Stop asking until a spent quota resets, in this run and later ones.
    async fn pause_for_quota(&self, retry_after: Duration) {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return;
        };
        let reset = (now + retry_after.min(MAX_QUOTA_PAUSE)).as_secs();
        self.quota_reset.store(reset, Ordering::Relaxed);
        // The rejection that brought the news is itself reported.
        self.quota_reported.store(true, Ordering::Relaxed);
        self.store(move |cache| cache.set_quota_reset(reset)).await;
    }

    async fn request(&self, query: Query<'_>) -> Result<Assessment> {
        let (path, key, value) = match query {
            Query::Purl(purl) => ("/v1/analyze", "purl", purl),
            Query::Sha256(sha256) => ("/v1/lookup", "sha256", sha256),
        };
        let analyze = matches!(query, Query::Purl(_));
        let mut url = self.base.clone();
        url.set_path(path);
        url.query_pairs_mut()
            .append_pair(key, value)
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
            // Beamline says in whole seconds when a spent quota resets.
            if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                && let Some(seconds) = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()?.parse().ok())
            {
                self.pause_for_quota(Duration::from_secs(seconds)).await;
            }
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

/// How long until a quota that resets at `reset` (seconds since the epoch)
/// can be used again; `None` once it has reset. A reset further off than any
/// pause hood would have recorded is a damaged or planted one, and ignored.
fn quota_wait(reset: u64, now: SystemTime) -> Option<Duration> {
    let now = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let wait = Duration::from_secs(reset.checked_sub(now).filter(|&wait| wait > 0)?);
    (wait <= MAX_QUOTA_PAUSE).then_some(wait)
}

/// A wait in the largest unit that fits, for a message.
fn rounded(wait: Duration) -> String {
    match wait.as_secs() {
        seconds @ ..60 => format!("{seconds}s"),
        seconds @ ..3600 => format!("{}m", seconds / 60),
        seconds => format!("{}h", seconds / 3600),
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

/// Keep at most 200 printable characters, without bidi overrides.
fn printable(text: &str) -> String {
    text.chars()
        .filter(|&c| !c.is_control() && !crate::output::is_bidi_control(c))
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
    // credentials, and the caller discloses nothing of an authenticated request,
    // so an unauthenticated scoped package on the public registry is public.
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
    fletch::purl::url_to_purl(raw)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::Client;
    use std::sync::{Arc, Mutex};
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

    pub(crate) async fn server(replies: Vec<(u16, Vec<String>)>) -> Server {
        server_with("", replies).await
    }

    /// A server that answers one connection per reply, in order, each with
    /// `headers` (complete lines) added.
    #[allow(clippy::unwrap_used)]
    pub(crate) async fn server_with(
        headers: &'static str,
        replies: Vec<(u16, Vec<String>)>,
    ) -> Server {
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
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/x-ndjson\r\nContent-Length: {length}\r\nConnection: close\r\n{headers}\r\n"
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
        Client::new(endpoint, None)
            .unwrap()
            .caching_under(root.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use test_support::{assessment, cached_client, server, server_with};
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
    fn plain_http_is_allowed_only_on_loopback() {
        for base in [
            "http://localhost:8787",
            "http://127.0.0.1:8787",
            "http://[::1]:8787",
        ] {
            assert!(Client::new(base, None).is_ok(), "{base}");
        }
        for base in ["http://beamline.example", "http://10.0.0.1:8787"] {
            assert!(Client::new(base, None).is_err(), "{base}");
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
    async fn connection_refusal_returns_for_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client = Client::new(&endpoint, None).unwrap();
        assert!(client.assess(None, SHA).await.is_err());
    }

    /// Every slot taken, as by a package manager's parallel downloads.
    async fn saturated(client: &Client) -> tokio::sync::SemaphorePermit<'_> {
        let slots = u32::try_from(MAX_CONCURRENT_LOOKUPS).unwrap();
        client.slots.acquire_many(slots).await.unwrap()
    }

    #[tokio::test]
    async fn a_request_beyond_the_concurrency_limit_waits_its_turn() {
        let mock = server(vec![(200, vec![assessment(SHA, "benign")])]).await;
        let client = Arc::new(Client::new(&mock.url, None).unwrap());
        let permits = saturated(&client).await;
        let queued = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.assess(None, SHA).await }
        });
        tokio::task::yield_now().await;
        assert!(mock.requests.lock().unwrap().is_empty());
        drop(permits);
        let result = queued.await.unwrap().unwrap();
        assert_eq!(result.classification(SHA), Some(Classification::Benign));
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_for_a_slot_is_bounded_by_the_request_budget() {
        let client = Client::new("http://127.0.0.1:9", None).unwrap();
        let _permits = saturated(&client).await;
        let error = client.assess(None, SHA).await.unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"), "{error:#}");
    }

    #[tokio::test]
    async fn analysis_begun_with_the_request_is_settled_by_the_digest() {
        // The package's bytes are the ones analyzed: one request decides.
        let mock = server(vec![(200, vec![assessment(SHA, "hostile")])]).await;
        let client = Client::new(&mock.url, None).unwrap();
        let early = client.analyze("pkg:npm/demo@1").await;
        let result = client.settle(Some(early), SHA).await.unwrap();
        assert_eq!(result.classification(SHA), Some(Classification::Hostile));
        assert_eq!(mock.requests.lock().unwrap().len(), 1);

        // Other bytes were analyzed: ask about ours.
        let mock = server(vec![
            (200, vec![assessment(&"b".repeat(64), "benign")]),
            (200, vec![assessment(SHA, "hostile")]),
        ])
        .await;
        let client = Client::new(&mock.url, None).unwrap();
        let early = client.analyze("pkg:npm/demo@1").await;
        let result = client.settle(Some(early), SHA).await.unwrap();
        assert_eq!(result.classification(SHA), Some(Classification::Hostile));
        let requests = mock.requests.lock().unwrap().clone();
        assert!(requests[1].starts_with(&format!("GET /v1/lookup?sha256={SHA}")));

        // The analysis failed: local analysis decides, with no second request.
        let mock = server(vec![(503, vec!["outage".into()])]).await;
        let client = Client::new(&mock.url, None).unwrap();
        let early = client.analyze("pkg:npm/demo@1").await;
        assert!(client.settle(Some(early), SHA).await.is_err());
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_cached_analysis_is_reused_but_never_vouches_for_other_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let other = "b".repeat(64);
        let mock = server(vec![
            (200, vec![assessment(SHA, "benign")]),
            (200, vec![assessment(&other, "hostile")]),
        ])
        .await;
        let client = cached_client(&mock.url, tmp.path());
        drop(client.analyze("pkg:npm/demo@1").await.unwrap());
        // A later run asks nothing about the same package...
        let client = cached_client(&mock.url, tmp.path());
        let early = client.analyze("pkg:npm/demo@1").await;
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
        // ...and its verdict covers only the bytes it names.
        let result = client.settle(Some(early), &other).await.unwrap();
        assert_eq!(result.classification(&other), Some(Classification::Hostile));
        let requests = mock.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with(&format!("GET /v1/lookup?sha256={other}")));
        // No package name reaches the disk.
        for entry in walk(tmp.path()) {
            let stored = std::fs::read_to_string(&entry).unwrap();
            assert!(!entry.to_string_lossy().contains("demo"), "{entry:?}");
            assert!(!stored.contains("demo"), "{stored}");
        }
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .flat_map(|entry| {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path)
                } else {
                    vec![path]
                }
            })
            .collect()
    }

    #[tokio::test]
    async fn a_spent_quota_is_not_asked_again_until_it_resets() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = server_with(
            "Retry-After: 1800\r\n",
            vec![(429, vec!["quota exhausted".into()])],
        )
        .await;
        let client = cached_client(&mock.url, tmp.path());
        let error = client.assess(None, SHA).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Beamline returned HTTP 429 Too Many Requests: quota exhausted (retry after 1800s)"
        );
        // Neither this run nor the next asks again.
        for client in [client, cached_client(&mock.url, tmp.path())] {
            for purl in [None, Some("pkg:npm/demo@1")] {
                let error = client.assess(purl, SHA).await.unwrap_err();
                assert!(error.is::<QuotaSpent>(), "{error:#}");
            }
        }
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_rejection_that_names_no_reset_does_not_pause() {
        let mock = server(vec![
            (429, vec!["slow down".into()]),
            (200, vec![assessment(SHA, "benign")]),
        ])
        .await;
        let client = Client::new(&mock.url, None).unwrap();
        assert!(client.assess(None, SHA).await.is_err());
        let result = client.assess(None, SHA).await.unwrap();
        assert_eq!(result.classification(SHA), Some(Classification::Benign));
    }

    #[test]
    fn a_quota_pause_ends_and_is_never_longer_than_a_day() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let day = MAX_QUOTA_PAUSE.as_secs();
        for (reset, expected) in [
            (0, None),
            (999_999, None),
            (1_000_000, None),
            (1_000_060, Some(Duration::from_mins(1))),
            (1_000_000 + day, Some(MAX_QUOTA_PAUSE)),
            // No pause hood records is this long: a damaged or planted stamp.
            (1_000_001 + day, None),
            (u64::MAX, None),
        ] {
            assert_eq!(quota_wait(reset, now), expected, "{reset}");
        }
    }

    #[tokio::test]
    async fn an_absurd_retry_after_is_capped() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = server_with(
            "Retry-After: 99999999999\r\n",
            vec![(429, vec!["quota exhausted".into()])],
        )
        .await;
        let client = cached_client(&mock.url, tmp.path());
        assert!(client.assess(None, SHA).await.is_err());
        let reset = client.quota_reset.load(Ordering::Relaxed);
        assert_eq!(
            quota_wait(reset, SystemTime::now()).map(|wait| wait > Duration::from_hours(23)),
            Some(true)
        );
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
        let permits = saturated(&client).await;
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
