//! Local Bloom gate, minimal-disclosure Beamline assessment, and lazy local analysis.
//! Every available identity participates in the Bloom decision before any API call.
//!
//! A download is decided by the first of these that can: the Bloom filters,
//! a pass an earlier local analysis of the same bytes and URL reached,
//! Beamline, local analysis. The
//! last two overlap. Beamline is asked about a public package as soon as it
//! is requested, and local analysis starts beside a lookup that has not
//! answered within [`HEDGE`] of the download finishing.

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use scan::Analyzer;
use scan::bloom_repo::{Decision, Lookup};
use scan::engine::ScanResult;
use scan::model::Classification;
use tokio::sync::OnceCell;

use crate::beamline;
use crate::output::{Disposition, ShownUrl};
use crate::verdict_cache::VerdictCache;

// `Analyzer::load` classifies at scan's default severity; hood's verdicts,
// panels and Beamline budget are all calibrated for L25.
const _: () = assert!(
    scan::model::DEFAULT_SEVERITY_LEVEL == 25,
    "scan's default severity changed from L25"
);

/// How long a Bloom known-bad block waits for Beamline's explanation.
const KNOWN_BAD_DETAILS_TIMEOUT: Duration = Duration::from_secs(5);

/// The shortest body whose digest Beamline is asked about. Anything shorter
/// is a stock reply rather than a file: `OK`, `Not Found`, `{"success":true}`,
/// Go's `404 page not found`. Unrelated servers send the same bytes, so what
/// is known of the hash is known of some other download; and so few bytes can
/// be guessed from their hash, which would hand over a short token a server
/// returned. Local analysis still sees them.
const MIN_LOOKUP_BYTES: usize = 20;

/// How long a finished download waits on Beamline alone before local analysis
/// starts beside it. Beamline usually answers well inside this, and then no
/// analyzer is loaded; past it, waiting costs more than the work.
const HEDGE: Duration = Duration::from_millis(250);

/// Outcome of scanning a single payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Payload may be forwarded to the requesting tool.
    Allow,
    /// Payload should be withheld. The reason carries display detail.
    Block(BlockReason),
}

/// Why a payload was blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// Matched the known-bad bloom filter (by content hash or PURL) — blocked
    /// without any ML scan. Carries the payload's SHA-256 hex for the lab link.
    KnownBad(String),
    /// Scanner classified the payload as hostile.
    Hostile,
    /// Scanner classified the payload as suspicious (and policy blocks those).
    Suspicious,
    /// Scanner returned an unexpected error and policy is fail-closed.
    ScanError(String),
}

impl Verdict {
    /// What the verdict does with the payload.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::Allow => Disposition::Forwarded,
            Self::Block(_) => Disposition::Blocked,
        }
    }
}

impl BlockReason {
    /// Short human-readable label for log and error messages.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::KnownBad(_) => "known-bad",
            Self::Hostile => "hostile",
            Self::Suspicious => "suspicious",
            Self::ScanError(_) => "scan-error",
        }
    }
}

/// What may be told to Beamline about a response, given how it was requested.
/// Ordered from least to most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disclosure {
    /// Nothing. The request carried credentials, so what it fetched may be
    /// private, and even its digest says that this machine holds it. Or the
    /// body is a stock reply, whose digest names no download.
    Nothing,
    /// The SHA-256 of the body.
    Digest,
    /// The SHA-256, and the public package coordinate the URL names.
    Coordinate,
}

/// What a scanner began when a request arrived, handed back to it with the
/// response; see [`Scanner::anticipate`]. The default is nothing begun.
#[derive(Debug, Default)]
pub struct Anticipated(Option<tokio::task::JoinHandle<Option<Result<beamline::Assessment>>>>);

/// Context the scanner gets alongside the payload bytes.
#[derive(Debug)]
pub struct ScanRequest {
    /// The URL the tool originally requested. Used as the filename hint to
    /// cleave (which keys off extension) and as a log field.
    pub url: String,
    /// What request provenance permits telling Beamline.
    pub disclosure: Disclosure,
    /// What [`Scanner::anticipate`] began for this request.
    pub early: Anticipated,
    /// Full payload body. Shared with the response hood forwards, so only a
    /// local analysis, which needs bytes of its own, ever copies it.
    pub body: Bytes,
    /// SHA-256 of `body`, computed while it streamed in.
    pub sha256: [u8; 32],
}

/// A payload too large to buffer in RAM, spilled to a temporary file.
///
/// The SHA-256 is computed incrementally as the body streams to disk, so the bloom
/// gate runs without re-reading the file, and cleave memory-maps the path so the
/// ML scan's resident memory stays bounded regardless of payload size.
#[derive(Debug)]
pub struct DiskScanRequest {
    /// The URL the tool requested — cleave filename hint and log/panel field.
    pub url: String,
    /// What request provenance permits telling Beamline.
    pub disclosure: Disclosure,
    /// What [`Scanner::anticipate`] began for this request.
    pub early: Anticipated,
    /// On-disk file holding the full payload. Named with the payload's real
    /// extension so cleave's type detection matches an in-memory scan.
    pub path: PathBuf,
    /// SHA-256 of the payload, computed while it streamed to disk.
    pub sha256: [u8; 32],
}

/// A scanner backend.
///
/// Every required method decides; none can fail. A backend that cannot
/// inspect a payload says what its policy does with that, so no caller has to
/// guess whether an error forwards or blocks. No deciding method has a
/// default, so a new backend cannot inherit a decision it did not make.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync + std::fmt::Debug {
    /// Begin, as a request for `url` goes out, whatever needs none of the
    /// response: the download and this work then overlap. The caller puts the
    /// result in the [`ScanRequest`] for the response, or drops it if there
    /// is nothing to scan. Must be called within a Tokio runtime.
    fn anticipate(self: Arc<Self>, _url: &str, _disclosure: Disclosure) -> Anticipated {
        Anticipated::default()
    }

    /// Decide an in-memory payload.
    async fn scan(&self, req: ScanRequest) -> Verdict;

    /// Decide a payload spilled to disk, too large to buffer in RAM.
    async fn scan_disk(&self, req: DiskScanRequest) -> Verdict;

    /// Decide a payload too large to inspect: larger than `limit` bytes, and
    /// `size` bytes when the server declared it.
    fn scan_limit(&self, url: &str, limit: u64, size: Option<u64>) -> Verdict;

    /// Decide a payload hood cannot inspect for the reason `why`, such as an
    /// encoding it does not decode.
    fn uninspectable(&self, url: &str, why: &str) -> Verdict;
}

/// Trivial scanner that allows everything. For tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

#[async_trait::async_trait]
impl Scanner for AllowAll {
    async fn scan(&self, _req: ScanRequest) -> Verdict {
        Verdict::Allow
    }
    async fn scan_disk(&self, _req: DiskScanRequest) -> Verdict {
        Verdict::Allow
    }
    fn scan_limit(&self, _url: &str, _limit: u64, _size: Option<u64>) -> Verdict {
        Verdict::Allow
    }
    fn uninspectable(&self, _url: &str, _why: &str) -> Verdict {
        Verdict::Allow
    }
}

/// Policy for how non-benign verdicts and scan errors are handled when
/// forwarding through the proxy.
///
/// Hood always *scans* and always *emits a panel* for non-allow paths — this
/// policy controls only whether the body is then forwarded to the caller.
///
/// The four levels form a strict ladder: each higher tier passes everything
/// the previous tier did, plus one more class of payload. The order tracks
/// trust: scan errors are "we couldn't tell," suspicious is "the model
/// thinks something is off," hostile is "we're confident this is bad."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanPolicy {
    /// Block everything non-benign, including scan errors. Default.
    #[default]
    Strict,
    /// Forward when the scanner errors out (e.g. trait load failure, malformed
    /// payload). Block hostile and suspicious classifications.
    AllowErrors,
    /// Forward errors and suspicious; block hostile only.
    AllowSuspicious,
    /// Forward everything. Hood still logs every non-benign payload, but the
    /// blocking decision is deferred to whoever reads the panel.
    Bypass,
}

/// Bloom and Beamline assessment with a lazily initialized local analyzer.
///
/// Construction does not load models. Both the Bloom bundle and the local
/// analyzer are initialized once, shared by concurrent downloads.
pub struct AtomScanner {
    analyzer: OnceCell<std::result::Result<Arc<Analyzer>, String>>,
    /// Where the models are. `None` resolves them through scan, which honors
    /// `SCAN_MODELS_DIR`; unit tests name a directory with none.
    model_dir: Option<PathBuf>,
    remote: Option<beamline::Client>,
    policy: ScanPolicy,
    invocation: String,
    status: Option<Arc<ScanStats>>,
    bloom: OnceCell<Option<Lookup>>,
    /// Passes of earlier local analyses; holds `None` when none may be kept.
    verdicts: OnceCell<Option<Arc<VerdictCache>>>,
    /// See [`HEDGE`]. A field so that tests choose which of Beamline and
    /// local analysis is asked, rather than leave it to timing.
    hedge: Duration,
}

/// Thread-safe counters used to summarize a verbose Hood run.
#[derive(Debug, Default)]
pub struct ScanStats {
    passed: AtomicU64,
    suspicious_blocked: AtomicU64,
    suspicious_forwarded: AtomicU64,
    hostile_blocked: AtomicU64,
    hostile_forwarded: AtomicU64,
    errors_blocked: AtomicU64,
    errors_forwarded: AtomicU64,
}

/// Stable snapshot of assessment outcomes in one Hood invocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// Downloads classified as benign.
    pub passed: u64,
    /// Suspicious downloads withheld by policy.
    pub suspicious_blocked: u64,
    /// Suspicious downloads forwarded by policy.
    pub suspicious_forwarded: u64,
    /// Hostile downloads withheld by policy.
    pub hostile_blocked: u64,
    /// Hostile downloads forwarded by policy.
    pub hostile_forwarded: u64,
    /// Scan errors withheld by policy.
    pub errors_blocked: u64,
    /// Scan errors forwarded by policy.
    pub errors_forwarded: u64,
}

impl ScanSummary {
    /// Total number of downloads assessed.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.passed
            + self.suspicious_blocked
            + self.suspicious_forwarded
            + self.hostile_blocked
            + self.hostile_forwarded
            + self.errors_blocked
            + self.errors_forwarded
    }

    /// Total number of downloads Hood withheld.
    #[must_use]
    pub const fn blocked(self) -> u64 {
        self.suspicious_blocked + self.hostile_blocked + self.errors_blocked
    }
}

impl ScanStats {
    fn record(&self, classification: Classification, disposition: Disposition) {
        let counter = match (classification, disposition) {
            (Classification::Benign, _) => &self.passed,
            (Classification::Suspicious, Disposition::Blocked) => &self.suspicious_blocked,
            (Classification::Suspicious, Disposition::Forwarded) => &self.suspicious_forwarded,
            (Classification::Hostile, Disposition::Blocked) => &self.hostile_blocked,
            (Classification::Hostile, Disposition::Forwarded) => &self.hostile_forwarded,
            // `Classification` is non-exhaustive; an unknown one is an error.
            _ => {
                self.record_error(disposition);
                return;
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_error(&self, disposition: Disposition) {
        let counter = match disposition {
            Disposition::Blocked => &self.errors_blocked,
            Disposition::Forwarded => &self.errors_forwarded,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Take a consistent-enough diagnostic snapshot after the proxy stops.
    #[must_use]
    pub fn snapshot(&self) -> ScanSummary {
        ScanSummary {
            passed: self.passed.load(Ordering::Relaxed),
            suspicious_blocked: self.suspicious_blocked.load(Ordering::Relaxed),
            suspicious_forwarded: self.suspicious_forwarded.load(Ordering::Relaxed),
            hostile_blocked: self.hostile_blocked.load(Ordering::Relaxed),
            hostile_forwarded: self.hostile_forwarded.load(Ordering::Relaxed),
            errors_blocked: self.errors_blocked.load(Ordering::Relaxed),
            errors_forwarded: self.errors_forwarded.load(Ordering::Relaxed),
        }
    }
}

impl std::fmt::Debug for AtomScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomScanner")
            .field("policy", &self.policy)
            .field("model_dir", &self.model_dir)
            .finish_non_exhaustive()
    }
}

impl AtomScanner {
    /// Prepare a scanner; model loading is deferred until local analysis is
    /// needed, and resolved through scan (`SCAN_MODELS_DIR`, else the
    /// installed models).
    ///
    /// `invocation` is the shell-quoted command the user ran (e.g.
    /// `"curl -fsSL https://x"`), surfaced in the bypass hint of the
    /// stderr panel so they can copy/paste a working command.
    ///
    /// `status`, when present, collects counters for verbose status reporting.
    #[must_use]
    pub fn new(policy: ScanPolicy, invocation: String, status: Option<Arc<ScanStats>>) -> Self {
        let remote = if options().local {
            tracing::info!("--local: not asking Beamline");
            None
        } else {
            match beamline::Client::from_env() {
                Ok(client) => Some(client),
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "Beamline configuration unavailable; using local analysis");
                    None
                }
            }
        };
        Self {
            analyzer: OnceCell::new(),
            model_dir: None,
            remote,
            policy,
            invocation,
            status,
            bloom: OnceCell::new(),
            verdicts: OnceCell::new(),
            hedge: HEDGE,
        }
    }

    async fn bloom(&self) -> Option<&Lookup> {
        self.bloom
            .get_or_init(|| async {
                tokio::task::spawn_blocking(load_bloom)
                    .await
                    .unwrap_or_else(|error| {
                        tracing::warn!(%error, "Bloom load failed; continuing to assessment");
                        None
                    })
            })
            .await
            .as_ref()
    }

    async fn verdicts(&self) -> Option<Arc<VerdictCache>> {
        self.verdicts
            .get_or_init(|| async {
                tokio::task::spawn_blocking(open_verdicts)
                    .await
                    .inspect_err(|error| tracing::debug!(%error, "verdict cache task failed"))
                    .ok()
                    .flatten()
                    .map(Arc::new)
            })
            .await
            .clone()
    }

    async fn analyzer(&self) -> Result<Arc<Analyzer>> {
        let result = self
            .analyzer
            .get_or_init(|| async {
                let model_dir = self.model_dir.clone();
                tokio::task::spawn_blocking(move || {
                    // Before the analyzer resolves a rules tree: this host's
                    // feed, and never the working directory's.
                    activate_feed();
                    scan::traits_repo::prepare_runtime_env();
                    let model_dir = match model_dir {
                        Some(dir) => dir,
                        None => scan::models_repo::ensure_model_dir()
                            .context("resolve scan model dir")?,
                    };
                    Analyzer::load(model_dir)
                        .map(Arc::new)
                        .context("load scan analyzer")
                })
                .await
                .context("load analyzer task")
                .flatten()
                // Cached once for every download, so kept as its rendered chain.
                .map_err(|error| format!("{error:#}"))
            })
            .await;
        result
            .as_ref()
            .cloned()
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    /// What can start before a download's bytes arrive: Beamline's analysis
    /// of a public package, or else the analyzer that will have to judge it.
    async fn begin(
        &self,
        url: &str,
        disclosure: Disclosure,
    ) -> Option<Result<beamline::Assessment>> {
        // A package the filters know by name is settled by its digest.
        let purl = fletch::purl::url_to_purl(url);
        if let Some(lookup) = self.bloom().await
            && matches!(
                lookup.decide_any(purl.as_deref(), None),
                Decision::Skip | Decision::KnownBad
            )
        {
            return None;
        }
        if disclosure == Disclosure::Coordinate
            && let Some(client) = &self.remote
            && let Some(purl) = beamline::public_purl(url)
        {
            return Some(client.analyze(&purl).await);
        }
        // Nothing public to ask about, so local analysis is the likely judge.
        // A failure to load is reported by the download that needs it.
        drop(tokio::join!(self.verdicts(), self.analyzer()));
        None
    }

    /// Decide a finished download, whose local analysis would be `job`.
    async fn decide<F>(
        &self,
        url: &str,
        disclosure: Disclosure,
        early: Anticipated,
        sha: &[u8; 32],
        job: F,
    ) -> Verdict
    where
        F: FnOnce(&Analyzer) -> Result<ScanResult> + Send + 'static,
    {
        // Bloom revocations must take precedence over even a fresh benign cache entry.
        let mut sighting = None;
        if let Some(lookup) = self.bloom().await {
            // Local identity checks may use private coordinates; disclosure is
            // decided separately, only if the bundle cannot resolve the artifact.
            let purl = fletch::purl::url_to_purl(url);
            let decision = lookup.decide_any(purl.as_deref(), Some(sha));
            if let Some(verdict) = bloom_verdict(decision, self.policy, url, sha) {
                return self
                    .report_bloom(decision, verdict, url, sha, disclosure)
                    .await;
            }
            // A threat feed's claim decides nothing, but explains a block.
            sighting = sighting_of(decision);
            if let Some(sighting) = sighting {
                tracing::debug!(url = %ShownUrl(url), ?sighting, "threat feeds report these bytes; analyzing");
            }
        }
        let digest = hex(sha);
        let verdicts = self.verdicts().await;
        if let Some(verdicts) = verdicts.clone() {
            let (digest, name) = (digest.clone(), url.to_owned());
            if let Ok(Some(probability)) =
                tokio::task::spawn_blocking(move || verdicts.get(&digest, &name)).await
            {
                tracing::debug!(url = %ShownUrl(url), probability, "scan clean (remembered)");
                return self.pass(url, probability);
            }
        }

        // Beamline alone first: it has usually seen the bytes already.
        // Beamline's verdict ends the decision; anything less it knows of the
        // bytes is carried on to explain a local one.
        let remote = async {
            let assessment = self
                .remote_assessment(url, disclosure, early, &digest)
                .await;
            self.remote_verdict(url, &digest, assessment.as_ref(), sighting)
                .map_or(ControlFlow::Continue(assessment), ControlFlow::Break)
        };
        tokio::pin!(remote);
        let (answer, result) = if let Ok(answer) =
            tokio::time::timeout(self.hedge, &mut remote).await
        {
            if let ControlFlow::Break(verdict) = answer {
                return verdict;
            }
            (answer, self.analyze(job).await)
        } else {
            tracing::debug!("Beamline has yet to answer; scanning locally beside it");
            let local = self.analyze(job);
            tokio::pin!(local);
            tokio::select! {
                answer = &mut remote => {
                    if let ControlFlow::Break(verdict) = answer {
                        return verdict;
                    }
                    (answer, local.await)
                }
                result = &mut local => {
                    // A pass needs no second opinion. A block or a failure
                    // waits for the one already asked for, which may clear
                    // it, and otherwise explains it.
                    let passed = matches!(&result, Ok(r) if r.classification == Classification::Benign);
                    let answer = if passed {
                        ControlFlow::Continue(None)
                    } else {
                        remote.await
                    };
                    (answer, result)
                }
            }
        };
        let assessment = match answer {
            ControlFlow::Break(verdict) => return verdict,
            ControlFlow::Continue(assessment) => assessment,
        };
        // scan keeps only a finished analysis, so one it has replayed is one
        // that no deadline cut short: a pass that will be the same next time.
        if let (Some(verdicts), Ok(result)) = (verdicts, &result)
            && result.classification == Classification::Benign
            && result.analysis_cached
        {
            let (key, name, probability) = (digest.clone(), url.to_owned(), result.probability);
            if let Err(error) =
                tokio::task::spawn_blocking(move || verdicts.put(&key, &name, probability))
                    .await
                    .context("verdict cache write task")
                    .flatten()
            {
                tracing::debug!(error = %format!("{error:#}"), "could not remember local verdict");
            }
        }
        // What Beamline knows of these bytes without settling them — a feed's
        // citation, say — still explains a local block.
        let record = assessment.as_ref().filter(|a| a.describes(&digest));
        match result {
            Ok(result) => self.classify_result(url, &digest, &result, record, sighting),
            Err(error) => self.scan_error(url, &format!("{error:#}")),
        }
    }

    /// The verdict `assessment` settles, counted and shown: it must be a
    /// verdict on exactly the bytes `digest` names. Anything less is left to
    /// local analysis.
    fn remote_verdict(
        &self,
        url: &str,
        digest: &str,
        assessment: Option<&beamline::Assessment>,
        sighting: Option<crate::output::Sighting>,
    ) -> Option<Verdict> {
        let assessment = assessment?;
        let Some(classification) = assessment.classification(digest) else {
            if assessment.cited_only() {
                tracing::debug!("Beamline holds only a feed's citation; scanning locally");
            } else {
                tracing::debug!("Beamline has no matching assessment; scanning locally");
            }
            return None;
        };
        let verdict = verdict_from(classification, self.policy);
        let disposition = verdict.disposition();
        tracing::debug!(
            url = %ShownUrl(url),
            verdict = crate::output::classification_label(classification),
            "Beamline verdict"
        );
        if let Some(status) = &self.status {
            status.record(classification, disposition);
        }
        if classification != Classification::Benign {
            crate::output::emit(&crate::output::Panel {
                classification,
                disposition,
                policy: self.policy,
                url,
                sha256: digest,
                basis: crate::output::Basis::Beamline,
                beamline: Some(assessment),
                sighting,
                invocation: &self.invocation,
            });
        } else if self.status.is_some() {
            crate::output::emit_pass(url, None);
        }
        Some(verdict)
    }

    /// Beamline's assessment of the download, if it may be told of it and
    /// answers. A failure is logged and left to local analysis.
    async fn remote_assessment(
        &self,
        url: &str,
        disclosure: Disclosure,
        early: Anticipated,
        digest: &str,
    ) -> Option<beamline::Assessment> {
        let client = self.remote.as_ref()?;
        let result = match (disclosure, early.0) {
            (Disclosure::Nothing, _) => return None,
            (Disclosure::Coordinate, Some(begun)) => {
                let early = begun
                    .await
                    .unwrap_or_else(|error| Some(Err(error).context("Beamline analysis task")));
                client.settle(early, digest).await
            }
            (Disclosure::Coordinate, None) => {
                let purl = beamline::public_purl(url);
                client.assess(purl.as_deref(), digest).await
            }
            (Disclosure::Digest, _) => client.settle(None, digest).await,
        };
        match result {
            Ok(assessment) => Some(assessment),
            // Said once, by the client.
            Err(error) if error.is::<beamline::QuotaSpent>() => {
                tracing::debug!("Beamline quota is spent; scanning locally");
                None
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "Beamline unavailable; scanning locally");
                None
            }
        }
    }

    /// Run `job` on the local analyzer, off the async runtime.
    async fn analyze<F>(&self, job: F) -> Result<ScanResult>
    where
        F: FnOnce(&Analyzer) -> Result<ScanResult> + Send + 'static,
    {
        let analyzer = self.analyzer().await?;
        let result = tokio::task::spawn_blocking(move || job(&analyzer))
            .await
            .context("scan task join")
            .flatten()?;
        if !result.probability.is_finite()
            || !(0.0..=1.0).contains(&result.probability)
            || !result.threshold.is_finite()
            || !(0.0..=1.0).contains(&result.threshold)
        {
            anyhow::bail!(
                "scanner returned invalid probability/threshold ({:?}/{:?})",
                result.probability,
                result.threshold,
            );
        }
        Ok(result)
    }

    /// Count and show a pass by local analysis, now or remembered.
    fn pass(&self, url: &str, probability: f32) -> Verdict {
        if let Some(status) = &self.status {
            status.record(Classification::Benign, Disposition::Forwarded);
            crate::output::emit_pass(url, Some(probability));
        }
        Verdict::Allow
    }

    /// Show and count a decision the Bloom filter made on its own.
    async fn report_bloom(
        &self,
        decision: Decision,
        verdict: Verdict,
        url: &str,
        sha: &[u8; 32],
        disclosure: Disclosure,
    ) -> Verdict {
        let known_bad = decision == Decision::KnownBad;
        if known_bad {
            let record = if disclosure == Disclosure::Nothing {
                None
            } else {
                self.known_bad_record(sha).await
            };
            crate::output::emit(&crate::output::Panel {
                classification: Classification::Hostile,
                disposition: verdict.disposition(),
                policy: self.policy,
                url,
                sha256: &hex(sha),
                basis: crate::output::Basis::KnownBad,
                beamline: record.as_ref(),
                sighting: None,
                invocation: &self.invocation,
            });
        }
        if let Some(status) = &self.status {
            let classification = if known_bad {
                Classification::Hostile
            } else {
                Classification::Benign
            };
            status.record(classification, verdict.disposition());
        }
        verdict
    }

    /// Beamline's analysis of a payload the Bloom filter has already
    /// condemned, to explain the block.
    ///
    /// The verdict never depends on this. It is a hash-only lookup, made only
    /// when the digest may be disclosed and bounded by
    /// [`KNOWN_BAD_DETAILS_TIMEOUT`], and an answer that does not agree the
    /// payload is bad is dropped rather than shown beside the block.
    async fn known_bad_record(&self, sha: &[u8; 32]) -> Option<beamline::Assessment> {
        let client = self.remote.as_ref()?;
        let sha = hex(sha);
        let assessment = match tokio::time::timeout(
            KNOWN_BAD_DETAILS_TIMEOUT,
            client.assess(None, &sha),
        )
        .await
        {
            Ok(Ok(assessment)) => assessment,
            Ok(Err(error)) => {
                tracing::debug!(error = %format!("{error:#}"), "no Beamline details for known-bad payload");
                return None;
            }
            Err(_) => {
                tracing::debug!("Beamline details for known-bad payload timed out");
                return None;
            }
        };
        if !matches!(
            assessment.classification(&sha),
            Some(Classification::Hostile | Classification::Suspicious)
        ) {
            tracing::debug!("Beamline does not confirm the known-bad payload; no details shown");
            return None;
        }
        Some(assessment)
    }

    /// Turn a local analysis of the bytes `digest` names into a [`Verdict`],
    /// showing a panel for a non-benign one, with what Beamline's `record` of
    /// the same bytes says.
    fn classify_result(
        &self,
        url: &str,
        digest: &str,
        result: &ScanResult,
        record: Option<&beamline::Assessment>,
        sighting: Option<crate::output::Sighting>,
    ) -> Verdict {
        if result.classification == Classification::Benign {
            tracing::debug!(
                url = %ShownUrl(url),
                probability = result.probability,
                replayed = result.analysis_cached,
                "scan clean"
            );
            return self.pass(url, result.probability);
        }
        let verdict = verdict_from(result.classification, self.policy);
        let disposition = verdict.disposition();
        tracing::debug!(
            url = %ShownUrl(url),
            verdict = crate::output::classification_label(result.classification),
            probability = result.probability,
            beamline_record = record.is_some(),
            ?sighting,
            "local verdict"
        );
        if let Some(status) = &self.status {
            status.record(result.classification, disposition);
        }
        // `top_findings` is already deduped, ranked strongest-first, and
        // capped at 5 by the engine; the panel shows the leading few.
        let reasons = result.reasons.get(..3).unwrap_or(&result.reasons);
        crate::output::emit(&crate::output::Panel {
            classification: result.classification,
            disposition,
            policy: self.policy,
            url,
            sha256: digest,
            basis: crate::output::Basis::Local {
                probability: result.probability,
                level: result.level,
                traits: &result.top_findings,
                reasons,
            },
            beamline: record,
            sighting,
            invocation: &self.invocation,
        });
        verdict
    }

    /// Decide a payload hood could not judge, for the reason `error`, under
    /// the active policy, and show why.
    fn scan_error(&self, url: &str, error: &str) -> Verdict {
        let verdict = if policy_allows_error(self.policy) {
            Verdict::Allow
        } else {
            Verdict::Block(BlockReason::ScanError(error.to_owned()))
        };
        let disposition = verdict.disposition();
        if let Some(status) = &self.status {
            status.record_error(disposition);
        }
        crate::output::emit_scan_error(&crate::output::ScanErrorPanel {
            url,
            error,
            policy: self.policy,
            disposition,
            invocation: &self.invocation,
        });
        verdict
    }
}

/// The verdict a Bloom decision settles on its own, if any. Pure: the caller
/// reports known-bad matches.
fn bloom_verdict(
    decision: Decision,
    policy: ScanPolicy,
    url: &str,
    sha: &[u8; 32],
) -> Option<Verdict> {
    match gate_outcome(decision, policy) {
        GateOutcome::Scan => None,
        GateOutcome::Skip => {
            tracing::debug!(url = %crate::output::ShownUrl(url), "bloom known-good skip");
            Some(Verdict::Allow)
        }
        GateOutcome::Block => Some(Verdict::Block(BlockReason::KnownBad(hex(sha)))),
        GateOutcome::Forward => Some(Verdict::Allow),
    }
}

/// What the filters' threat-feed claims say of a payload they did not settle.
const fn sighting_of(decision: Decision) -> Option<crate::output::Sighting> {
    match decision {
        Decision::SightedHostile => Some(crate::output::Sighting::Corroborated),
        Decision::SightedSuspicious => Some(crate::output::Sighting::Lone),
        _ => None,
    }
}

/// What the bloom gate decided to do with a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateOutcome {
    /// Known-bad; withhold the body and show the block panel.
    Block,
    /// Known-bad, but `HOOD_BYPASS=3` is active — forward and show a panel.
    Forward,
    /// All supplied identities are blessed; forward without scanning.
    Skip,
    /// No decisive signal — proceed to the ML scan.
    Scan,
}

/// Map scan's shared Bloom decision to Hood's enforcement policy.
const fn gate_outcome(decision: Decision, policy: ScanPolicy) -> GateOutcome {
    match decision {
        Decision::KnownBad if matches!(policy, ScanPolicy::Bypass) => GateOutcome::Forward,
        Decision::KnownBad => GateOutcome::Block,
        Decision::Skip => GateOutcome::Skip,
        _ => GateOutcome::Scan,
    }
}

/// Load the bloom filters, dropping an empty (unsynced) set so the gate is a
/// no-op rather than a wasted hash per payload.
fn load_bloom() -> Option<Lookup> {
    refresh_bloom();
    let lookup = Lookup::load();
    lookup.is_active().then_some(lookup)
}

/// Open the cache of local passes for the rules, models and build in use;
/// `None` when a pass cannot be tied to them. Blocking: reads the rules.
fn open_verdicts() -> Option<VerdictCache> {
    // Models named by `SCAN_MODELS_DIR` are used as they are: nothing says
    // which they are, or that they are the same ones next time.
    if std::env::var_os("SCAN_MODELS_DIR").is_some() {
        return None;
    }
    let directory = dirs::cache_dir()?.join("atomdrift/hood/verdicts/v1");
    // The rules in use are this host's feed, never the working directory's.
    activate_feed();
    scan::traits_repo::prepare_runtime_env();
    let models = scan::models_repo::version()?;
    // cleave's fingerprint covers every rule file and the running build.
    let rules = cleave::cache::traits_revision_fingerprint();
    Some(VerdictCache::new(directory, format!("{rules:x}-{models}")))
}

/// Reuse scan's verified atomic updater, at most once per day, including failures.
fn refresh_bloom() {
    if !due_today("bloom-checked") {
        return;
    }
    if let Err(error) = scan::bloom_repo::install_dir()
        .and_then(|dir| scan::bloom_update::update(&dir, false, true))
    {
        tracing::warn!(error = %format!("{error:#}"), "Bloom refresh failed; using installed bundle if available");
    }
}

/// Do the network work local analysis may need before the command starts.
///
/// That is a first-run install of the models and rules, and the daily Bloom and
/// paid-feed refreshes. Left to the first scan, the download happens inside a
/// request, and package managers abandon a transfer that sends nothing for a
/// few seconds (pacman after 10). Failures are logged and left to the lazy
/// analyzer load, which applies the scan policy per download.
///
/// Blocking: network and disk I/O.
pub fn prepare() {
    // Before anything resolves a rules tree: this host's feed.
    activate_feed();
    refresh_bloom();
    // `SCAN_MODELS_DIR` names models scan uses as they are, never fetching.
    if let Err(error) = scan::models_repo::ensure_model_dir() {
        tracing::warn!(error = %format!("{error:#}"), "model install failed before the command started");
    }
    install_traits();
}

/// Install the rules on first run, then pin cleave to the installed tree. Left
/// to itself, cleave prefers a `traits/` in the working directory, which would
/// let the checkout being installed supply its own rules.
fn install_traits() {
    let explicit = std::env::var_os("CLEAVE_TRAITS_DIR").is_some_and(|dir| !dir.is_empty());
    let installed = cleave::traits_repo::installed_dir(cleave::feed::current());
    if !explicit
        && !installed.is_dir()
        && let Err(error) = scan::traits_repo::update(false, false)
    {
        tracing::warn!(error = %format!("{error:#}"), "rules install failed before the command started");
    }
    scan::traits_repo::prepare_runtime_env();
}

/// What hood was started with, for a check to act on when it first runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// `--feed` (or `HOOD_FEED`).
    pub feed: cleave::feed::Choice,
    /// `--local` (or `HOOD_LOCAL`): never ask Beamline.
    pub local: bool,
}

/// The [`Options`] hood was started with; the defaults until [`configure`].
static OPTIONS: std::sync::OnceLock<Options> = std::sync::OnceLock::new();

/// Record hood's options for a check to act on when it first runs: a
/// pass-through never does, and reads nothing for them.
pub fn configure(options: Options) {
    if OPTIONS.set(options).is_err() {
        tracing::debug!("hood's options were already set");
    }
}

fn options() -> Options {
    OPTIONS.get().copied().unwrap_or_default()
}

/// Check downloads with this run's rule feed — `--feed`, else the best the
/// login (`hood login`, shared with cleave and atomscan) opens — refreshing
/// a paid feed at most once a day.
///
/// A named paid feed with no login asks for one on a terminal. A refused
/// token is a warning, never a failed install: a billing problem must not
/// block a developer's `npm install`, and the check itself still runs — on
/// the feed's rules already installed, or on the open-source ones when there
/// are none yet.
fn activate_feed() {
    static ACTIVATE: std::sync::Once = std::sync::Once::new();
    ACTIVATE.call_once(|| {
        // The refresh is what first installs a paid feed's tree after `hood
        // login`, so it runs before the installed tree is checked. A refused
        // token falls the run back inside the refresh, with its own warning;
        // what is left to say is a network failure.
        let feed = resolve_feed();
        if let Err(error) = cleave::rule_update::sign_in() {
            tracing::warn!(error = %error, "not logged in; checking with installed or open-source rules");
        }
        if feed.needs_token()
            && due_today(&format!("traits-{}-checked", feed.slug()))
            && let Err(error) = scan::traits_repo::update(false, true)
        {
            tracing::warn!(error = %format!("{error:#}"), "{feed} refresh failed; using installed rules");
        }
        installed_or_open_source();
    });
}

/// Choose the rules a check uses, with no network: this host's feed when its
/// tree is installed, the open-source one otherwise.
pub fn select_rules() {
    resolve_feed();
    installed_or_open_source();
}

/// This run's feed, from `--feed` and the sign-in.
pub fn resolve_feed() -> cleave::feed::Feed {
    if let Err(error) = cleave::feed::resolve(options().feed) {
        tracing::warn!(error = %format!("{error:#}"), "isotope13 token unusable; checking with open-source rules");
        cleave::feed::select(cleave::feed::Feed::Oss, false);
    }
    cleave::feed::current()
}

/// Keep a paid feed only if its tree is on disk; a check never runs on no rules.
fn installed_or_open_source() {
    let feed = cleave::feed::current();
    let installed = cleave::traits_repo::installed_dir(feed);
    if feed.needs_token() && cleave::rule_update::installed(&installed).is_none() {
        tracing::warn!(dir = %installed.display(), "no {feed} rules installed; checking with open-source rules");
        cleave::feed::select(cleave::feed::Feed::Oss, false);
    }
}

/// Whether a once-a-day job named `name` is due, stamping it when it is.
/// Failures stamp too, so an offline host does not retry on every command;
/// `HOOD_NO_UPDATE=1` turns every refresh off.
fn due_today(name: &str) -> bool {
    if std::env::var_os("HOOD_NO_UPDATE").is_some_and(|value| value == "1") {
        return false;
    }
    let Some(cache) = dirs::cache_dir() else {
        return false;
    };
    let stamp = cache.join("atomdrift/hood").join(name);
    if std::fs::metadata(&stamp)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age < Duration::from_hours(24))
    {
        return false;
    }
    if let Some(parent) = stamp.parent()
        && let Err(error) =
            std::fs::create_dir_all(parent).and_then(|()| std::fs::write(&stamp, []))
    {
        tracing::debug!(%error, stamp = %stamp.display(), "could not stamp daily refresh");
    }
    true
}

/// Lower-hex encode bytes without pulling in a hex crate.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Apply [`ScanPolicy`] to a classification. Pulled out of [`AtomScanner`]
/// so the decision matrix is testable without loading a real model.
///
/// Scan errors (the analyzer-returned-Err branch) are handled separately by
/// `policy_allows_error`; this function only sees successful classifications.
fn verdict_from(classification: Classification, policy: ScanPolicy) -> Verdict {
    match (classification, policy) {
        (_, ScanPolicy::Bypass)
        | (Classification::Benign, _)
        | (Classification::Suspicious, ScanPolicy::AllowSuspicious) => Verdict::Allow,
        // Block paths.
        (Classification::Hostile, _) => Verdict::Block(BlockReason::Hostile),
        (Classification::Suspicious, _) => Verdict::Block(BlockReason::Suspicious),
        // scan marks Classification non_exhaustive — fail-closed on new
        // variants we don't recognize (bypass already handled above).
        (other, _) => Verdict::Block(BlockReason::ScanError(format!(
            "unknown classification: {other:?}",
        ))),
    }
}

/// True when the active policy lets a scan-error payload through.
const fn policy_allows_error(policy: ScanPolicy) -> bool {
    matches!(
        policy,
        ScanPolicy::AllowErrors | ScanPolicy::AllowSuspicious | ScanPolicy::Bypass,
    )
}

#[async_trait::async_trait]
impl Scanner for AtomScanner {
    fn anticipate(self: Arc<Self>, url: &str, disclosure: Disclosure) -> Anticipated {
        let url = url.to_owned();
        Anticipated(Some(tokio::spawn(async move {
            self.begin(&url, disclosure).await
        })))
    }

    async fn scan(&self, req: ScanRequest) -> Verdict {
        let ScanRequest {
            url,
            disclosure,
            early,
            body,
            sha256,
        } = req;
        // A spilled body is never this short.
        let disclosure = if body.len() < MIN_LOOKUP_BYTES {
            Disclosure::Nothing
        } else {
            disclosure
        };
        let name = url.clone();
        self.decide(&url, disclosure, early, &sha256, move |analyzer| {
            analyzer.scan_bytes(body.into(), &name)
        })
        .await
    }

    async fn scan_disk(&self, req: DiskScanRequest) -> Verdict {
        let DiskScanRequest {
            url,
            disclosure,
            early,
            path,
            sha256,
        } = req;
        let name = url.clone();
        self.decide(&url, disclosure, early, &sha256, move |analyzer| {
            analyzer.scan_file(&path, &name)
        })
        .await
    }

    /// A download past the inspection limit is forwarded, never failed: the
    /// limit bounds hood's own disk and time, not what the user may install.
    /// The panel says plainly that it went unscanned.
    fn scan_limit(&self, url: &str, limit: u64, size: Option<u64>) -> Verdict {
        tracing::debug!(url = %crate::output::ShownUrl(url), limit, size, "over inspection limit");
        crate::output::emit_unscanned(&crate::output::UnscannedPanel { url, size, limit });
        Verdict::Allow
    }

    fn uninspectable(&self, url: &str, why: &str) -> Verdict {
        self.scan_error(url, why)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use burton::{KeySets, Record, Tier};
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn allow_all_allows() {
        let s = AllowAll;
        let v = s
            .scan(ScanRequest {
                url: "http://x".into(),
                disclosure: Disclosure::Digest,
                early: Anticipated::default(),
                body: Bytes::from_static(b"hi"),
                sha256: [0; 32],
            })
            .await;
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn block_reason_labels() {
        assert_eq!(
            BlockReason::KnownBad("deadbeef".into()).label(),
            "known-bad"
        );
        assert_eq!(BlockReason::Hostile.label(), "hostile");
        assert_eq!(BlockReason::Suspicious.label(), "suspicious");
        assert_eq!(BlockReason::ScanError("boom".into()).label(), "scan-error");
    }

    #[test]
    fn scan_stats_separate_verdicts_from_policy_actions() {
        let stats = ScanStats::default();
        stats.record(Classification::Benign, Disposition::Forwarded);
        stats.record(Classification::Suspicious, Disposition::Blocked);
        stats.record(Classification::Suspicious, Disposition::Forwarded);
        stats.record_error(Disposition::Blocked);
        assert_eq!(
            stats.snapshot(),
            ScanSummary {
                passed: 1,
                suspicious_blocked: 1,
                suspicious_forwarded: 1,
                errors_blocked: 1,
                ..ScanSummary::default()
            }
        );
    }

    // ----- bloom gate ------------------------------------------------------

    fn bloom_gate_sha(
        lookup: &Lookup,
        policy: ScanPolicy,
        url: &str,
        purl: Option<&str>,
        sha: &[u8; 32],
    ) -> Option<Verdict> {
        bloom_verdict(lookup.decide_any(purl, Some(sha)), policy, url, sha)
    }

    #[test]
    fn gate_enforces_shared_decision() {
        assert_eq!(
            gate_outcome(Decision::KnownBad, ScanPolicy::Strict),
            GateOutcome::Block
        );
        assert_eq!(
            gate_outcome(Decision::KnownBad, ScanPolicy::AllowSuspicious),
            GateOutcome::Block
        );
        assert_eq!(
            gate_outcome(Decision::KnownBad, ScanPolicy::Bypass),
            GateOutcome::Forward
        );
        assert_eq!(
            gate_outcome(Decision::Skip, ScanPolicy::Strict),
            GateOutcome::Skip
        );
        for decision in [
            Decision::Unknown,
            Decision::Conflicted,
            Decision::SightedHostile,
            Decision::SightedSuspicious,
        ] {
            assert_eq!(
                gate_outcome(decision, ScanPolicy::Strict),
                GateOutcome::Scan
            );
        }
    }

    /// Build a bloom bundle (the `.adbl` filters plus `bloom.toml`) from a small
    /// pool and write it to `dir` exactly as `atomscan update-rules` would, so
    /// the gate exercises the real on-disk load + query path. PURLs are
    /// canonicalized with scan's key scheme, as the producer does.
    fn publish_filters(dir: &std::path::Path, rows: &[(Tier, Record)]) {
        let mut sets = KeySets::new();
        for (tier, record) in rows {
            sets.insert(*tier, record.clone());
        }
        burton::write_bundle(
            dir,
            &sets.into_filters(1e-9),
            "2026-09-09",
            scan::bloom_repo::KEY_SCHEME,
        )
        .unwrap();
    }

    /// A pool record with the PURL in scan's canonical key form.
    fn rec(purl: Option<&str>, sha256: Option<[u8; 32]>) -> Record {
        Record {
            purl: purl.and_then(scan::bloom_repo::purl_key),
            sha256,
        }
    }

    fn sha_of(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    #[test]
    fn bloom_gate_end_to_end_over_real_filters() {
        let tmp = tempfile::tempdir().unwrap();
        let good_sha = sha_of(b"benign package bytes");
        let bad_sha = sha_of(b"malware package bytes");
        let sighted_sha = sha_of(b"reported package bytes");

        publish_filters(
            tmp.path(),
            &[
                (Tier::Good, rec(Some("pkg:npm/good@1.0.0"), Some(good_sha))),
                // Known-bad by BOTH a hash and, separately, a PURL coordinate.
                (Tier::Bad, rec(Some("pkg:npm/evil@1.0.0"), Some(bad_sha))),
                // A lone outside report: denies a skip, does not block.
                (Tier::SightedSuspicious, rec(None, Some(sighted_sha))),
            ],
        );
        let lookup = scan::bloom_repo::test_support::load_from(tmp.path());
        assert!(lookup.is_active());

        // Known-bad hash → hard block carrying the payload's SHA-256.
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "https://x/e.tgz",
            None,
            &bad_sha,
        );
        assert_eq!(
            v,
            Some(Verdict::Block(BlockReason::KnownBad(hex(&bad_sha))))
        );

        // Same known-bad hash under HOOD_BYPASS=3 → forwarded, not blocked.
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Bypass,
            "https://x/e.tgz",
            None,
            &bad_sha,
        );
        assert_eq!(v, Some(Verdict::Allow));

        // Known-bad *PURL* (derived from the npm URL) with novel bytes → block,
        // even though the hash is unknown. Proves the fletch url→purl wiring.
        let novel = sha_of(b"repackaged novel bytes");
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
            Some("pkg:npm/evil@1.0.0"),
            &novel,
        );
        assert!(matches!(v, Some(Verdict::Block(BlockReason::KnownBad(_)))));

        // Known-good digest alone → skip (allow) without scanning.
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "https://x/g.tgz",
            None,
            &good_sha,
        );
        assert_eq!(v, Some(Verdict::Allow));

        // Every supplied identity must be blessed; contradictory evidence is unresolved.
        for (purl, sha, expected) in [
            ("pkg:npm/good@1.0.0", good_sha, Some(Verdict::Allow)),
            ("pkg:npm/unknown@1.0.0", good_sha, None),
            ("pkg:npm/good@1.0.0", bad_sha, None),
        ] {
            assert_eq!(
                bloom_gate_sha(&lookup, ScanPolicy::Strict, "https://x", Some(purl), &sha),
                expected
            );
        }

        // A good package name cannot bless unknown or substituted bytes.
        let tampered = sha_of(b"tampered bytes under a good name");
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "https://registry.npmjs.org/good/-/good-1.0.0.tgz",
            Some("pkg:npm/good@1.0.0"),
            &tampered,
        );
        assert_eq!(v, None);

        // Nothing matches → fall through to the ML scan.
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "https://x/u.tgz",
            None,
            &sha_of(b"novel"),
        );
        assert_eq!(v, None);

        // A sighted hash under a known-good PURL: the claim denies the
        // allowlist skip, so the payload goes to the ML scan rather than
        // being forwarded unexamined — and is not blocked outright either.
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "https://registry.npmjs.org/good/-/good-1.0.0.tgz",
            Some("pkg:npm/good@1.0.0"),
            &sighted_sha,
        );
        assert_eq!(v, None);
    }

    fn test_scanner(
        remote: Option<beamline::Client>,
        bloom: Option<Lookup>,
        model_dir: PathBuf,
        policy: ScanPolicy,
    ) -> AtomScanner {
        AtomScanner {
            analyzer: OnceCell::new(),
            model_dir: Some(model_dir),
            remote,
            policy,
            invocation: String::new(),
            status: Some(Arc::new(ScanStats::default())),
            bloom: OnceCell::new_with(Some(bloom)),
            verdicts: OnceCell::new_with(Some(None)),
            // Beamline is given all the time it needs, so that whether local
            // analysis runs depends on its answer, not on the machine.
            hedge: Duration::from_hours(1),
        }
    }

    #[tokio::test]
    async fn bloom_answers_without_network_or_model_loading() {
        let tmp = tempfile::tempdir().unwrap();
        let body = b"known package".to_vec();
        publish_filters(
            tmp.path(),
            &[(Tier::Good, rec(Some("pkg:npm/demo@1"), Some(sha_of(&body))))],
        );
        let mock = beamline::test_support::server(vec![]).await;
        let scanner = test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            Some(scan::bloom_repo::test_support::load_from(tmp.path())),
            tmp.path().join("missing-model"),
            ScanPolicy::Strict,
        );
        let verdict = scanner
            .scan(ScanRequest {
                url: "https://registry.npmjs.org/demo/-/demo-1.tgz".into(),
                disclosure: Disclosure::Coordinate,
                early: Anticipated::default(),
                sha256: sha_of(&body),
                body: body.into(),
            })
            .await;
        assert_eq!(verdict, Verdict::Allow);
        assert!(scanner.analyzer.get().is_none());
        assert!(mock.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bad_bloom_overrides_cached_good_assessment() {
        use beamline::test_support::{assessment, cached_client, server};

        let cache_dir = tempfile::tempdir().unwrap();
        let body = b"previously benign package".to_vec();
        let sha = sha_of(&body);
        let sha_hex = hex(&sha);
        let url = "https://registry.npmjs.org/demo/-/demo-1.tgz";
        let purl = "pkg:npm/demo@1";
        let mock = server(vec![(200, vec![assessment(&sha_hex, "benign")])]).await;
        let endpoint = mock.url.clone();
        let client = cached_client(&endpoint, cache_dir.path());
        assert_eq!(
            client
                .assess(Some(purl), &sha_hex)
                .await
                .unwrap()
                .classification(&sha_hex),
            Some(Classification::Benign)
        );
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
        drop(client);
        drop(mock);

        // A new client with no server can only obtain this benign verdict from disk.
        let client = cached_client(&endpoint, cache_dir.path());
        assert_eq!(
            client
                .assess(None, &sha_hex)
                .await
                .unwrap()
                .classification(&sha_hex),
            Some(Classification::Benign)
        );

        for bad_record in [rec(None, Some(sha)), rec(Some(purl), None)] {
            let bundle = tempfile::tempdir().unwrap();
            publish_filters(bundle.path(), &[(Tier::Bad, bad_record)]);
            let scanner = test_scanner(
                Some(cached_client(&endpoint, cache_dir.path())),
                Some(scan::bloom_repo::test_support::load_from(bundle.path())),
                bundle.path().join("missing-model"),
                ScanPolicy::default(),
            );
            let expected = Verdict::Block(BlockReason::KnownBad(sha_hex.clone()));
            assert_eq!(
                scanner
                    .scan(ScanRequest {
                        url: url.into(),
                        disclosure: Disclosure::Coordinate,
                        early: Anticipated::default(),
                        sha256: sha_of(&body),
                        body: body.clone().into(),
                    })
                    .await,
                expected
            );
            let path = bundle.path().join("artifact.tgz");
            std::fs::write(&path, &body).unwrap();
            assert_eq!(
                scanner
                    .scan_disk(DiskScanRequest {
                        url: url.into(),
                        disclosure: Disclosure::Coordinate,
                        early: Anticipated::default(),
                        path,
                        sha256: sha,
                    })
                    .await,
                expected
            );
            assert!(scanner.analyzer.get().is_none());
        }
    }

    #[tokio::test]
    async fn remote_assessments_enforce_policy_without_loading_model() {
        use beamline::test_support::{assessment, server};
        let tmp = tempfile::tempdir().unwrap();
        let body = b"artifact bytes of a private release tarball".to_vec();
        let sha = hex(&sha_of(&body));
        for (severity, policy, expected) in [
            ("benign", ScanPolicy::Strict, Verdict::Allow),
            (
                "hostile",
                ScanPolicy::Strict,
                Verdict::Block(BlockReason::Hostile),
            ),
            (
                "suspicious",
                ScanPolicy::Strict,
                Verdict::Block(BlockReason::Suspicious),
            ),
            (
                "hostile",
                ScanPolicy::AllowErrors,
                Verdict::Block(BlockReason::Hostile),
            ),
            ("suspicious", ScanPolicy::AllowSuspicious, Verdict::Allow),
        ] {
            let mock = server(vec![(200, vec![assessment(&sha, severity)])]).await;
            let scanner = test_scanner(
                Some(beamline::Client::new(&mock.url, None).unwrap()),
                None,
                tmp.path().into(),
                policy,
            );
            let verdict = scanner
                .scan(ScanRequest {
                    url: "https://private.example/private.tar.gz?token=secret".into(),
                    disclosure: Disclosure::Digest,
                    early: Anticipated::default(),
                    sha256: sha_of(&body),
                    body: body.clone().into(),
                })
                .await;
            assert_eq!(verdict, expected);
            assert!(scanner.analyzer.get().is_none());
            let requests = mock.requests.lock().unwrap().clone();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].starts_with("GET /v1/lookup?sha256="));
            assert!(!requests[0].contains("private"));
            assert!(!requests[0].contains("secret"));
        }
    }

    /// A telemetry endpoint answered `OK`, a hash one feed cites, and its
    /// client was blocked on Beamline's word. Bytes that few are no longer
    /// asked about at all; for a stock page long enough to be, the citation
    /// sends the bytes to local analysis, which decides.
    #[tokio::test]
    async fn a_lone_feed_citation_is_scanned_locally_rather_than_blocked() {
        let tmp = tempfile::tempdir().unwrap(); // No models: local analysis fails, visibly.
        let body = b"<html><body><h1>404 Not Found</h1></body></html>";
        let cited = serde_json::json!({
            "status": "analyzed", "severity": "suspicious", "sha256": hex(&sha_of(body)),
            "engine_version": "3.0.0-beta.0",
            "findings": [{
                "id": "intel/feed/malicious",
                "desc": "Cited as malicious by one threat intelligence feed.",
            }],
        })
        .to_string();
        let mock = beamline::test_support::server(vec![(200, vec![cited])]).await;
        let scanner = test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            None,
            tmp.path().into(),
            ScanPolicy::Strict,
        );
        let verdict = scanner
            .scan(request(
                "https://sparrow.cloudflare.com/api/v1/event",
                Disclosure::Digest,
                Anticipated::default(),
                body,
            ))
            .await;
        // Not Beamline's suspicion: the local analyzer was asked.
        assert!(matches!(verdict, Verdict::Block(BlockReason::ScanError(_))));
        assert!(matches!(scanner.analyzer.get(), Some(Err(_))));
        assert_eq!(scanner.status.as_ref().unwrap().snapshot().total(), 1);
        assert_eq!(scanner.status.unwrap().snapshot().suspicious_blocked, 0);
    }

    /// `OK`, `{"success":true}` and the like are what unrelated servers all
    /// send: their hash names no download, and gives the bytes away.
    #[tokio::test]
    async fn a_stock_reply_is_never_looked_up() {
        use beamline::test_support::{assessment, server};
        let tmp = tempfile::tempdir().unwrap(); // No models: local analysis fails, visibly.
        let url = "https://sparrow.cloudflare.com/api/v1/event";
        let mock = server(vec![]).await;
        for body in [
            &b"OK"[..],
            br#"{"success":true}"#,
            b"curl a.io|sh",
            &[b'x'; MIN_LOOKUP_BYTES - 1],
        ] {
            let scanner = test_scanner(
                Some(beamline::Client::new(&mock.url, None).unwrap()),
                None,
                tmp.path().into(),
                ScanPolicy::Strict,
            );
            let verdict = scanner
                .scan(request(
                    url,
                    Disclosure::Coordinate,
                    Anticipated::default(),
                    body,
                ))
                .await;
            // Still analyzed, on this machine.
            assert!(matches!(verdict, Verdict::Block(BlockReason::ScanError(_))));
            assert!(matches!(scanner.analyzer.get(), Some(Err(_))));
        }
        assert!(mock.requests.lock().unwrap().is_empty());

        // One byte more, and Beamline is asked.
        let body = [b'x'; MIN_LOOKUP_BYTES];
        let mock = server(vec![(
            200,
            vec![assessment(&hex(&sha_of(&body)), "benign")],
        )])
        .await;
        let scanner = test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            None,
            tmp.path().into(),
            ScanPolicy::Strict,
        );
        let verdict = scanner
            .scan(request(
                url,
                Disclosure::Digest,
                Anticipated::default(),
                &body,
            ))
            .await;
        assert_eq!(verdict, Verdict::Allow);
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn known_bad_record_is_kept_only_when_it_confirms() {
        use beamline::test_support::server;
        let tmp = tempfile::tempdir().unwrap();
        let body = b"known bad payload";
        let sha: [u8; 32] = sha_of(body);
        let hex = hex(&sha);
        let confirming = serde_json::json!({
            "status": "analyzed", "severity": "hostile", "sha256": hex,
            "reason": "steals credentials",
            "findings": [{"id": "exfil/ssh-key", "crit": 5, "desc": "reads ~/.ssh"}, {"id": "exec/curl-sh"}],
        })
        .to_string();
        let benign = serde_json::json!({
            "status": "analyzed", "severity": "benign", "sha256": hex, "findings": [],
        })
        .to_string();
        for (status, response, expected) in [
            (200, confirming, Some("steals credentials")),
            // A disagreeing or failed lookup adds nothing; the block stands.
            (200, benign, None),
            (429, "quota".to_owned(), None),
        ] {
            let mock = server(vec![(status, vec![response])]).await;
            let scanner = test_scanner(
                Some(beamline::Client::new(&mock.url, None).unwrap()),
                None,
                tmp.path().into(),
                ScanPolicy::Strict,
            );
            let record = scanner.known_bad_record(&sha).await;
            assert_eq!(record.as_ref().and_then(|r| r.reason.as_deref()), expected);
            if let Some(record) = record {
                let findings: Vec<_> = record
                    .findings
                    .iter()
                    .map(|f| (f.id.as_str(), f.criticality()))
                    .collect();
                assert_eq!(
                    findings,
                    [
                        ("exfil/ssh-key", cleave::Criticality::Hostile),
                        ("exec/curl-sh", cleave::Criticality::Baseline),
                    ]
                );
            }
            let requests = mock.requests.lock().unwrap().clone();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].starts_with("GET /v1/lookup?sha256="));
        }
        let offline = test_scanner(None, None, tmp.path().into(), ScanPolicy::Strict);
        assert!(offline.known_bad_record(&sha).await.is_none());
    }

    #[tokio::test]
    async fn remote_failures_attempt_local_analysis_and_preserve_failure_policy() {
        use beamline::test_support::server;
        let tmp = tempfile::tempdir().unwrap(); // An empty model directory fails deterministically, offline.
        for (status, response) in [
            (429, "quota"),
            (503, "outage"),
            (
                200,
                r#"{"status":"unavailable","severity":"unknown","cause":"saturated"}"#,
            ),
            (200, r#"{"status":"unanalyzed","severity":"unknown"}"#),
            (200, r#"{"state":"analyzing"}"#),
        ] {
            for policy in [ScanPolicy::Strict, ScanPolicy::AllowErrors] {
                let mock = server(vec![(status, vec![response.into()])]).await;
                let scanner = test_scanner(
                    Some(beamline::Client::new(&mock.url, None).unwrap()),
                    None,
                    tmp.path().into(),
                    policy,
                );
                let verdict = scanner
                    .scan(ScanRequest {
                        url: "https://registry.npmjs.org/demo/-/demo-1.tgz".into(),
                        disclosure: Disclosure::Coordinate,
                        early: Anticipated::default(),
                        body: Bytes::from_static(b"bytes that Beamline has never been shown"),
                        sha256: sha_of(b"bytes that Beamline has never been shown"),
                    })
                    .await;
                assert!(
                    matches!(scanner.analyzer.get(), Some(Err(_))),
                    "local initialization was not attempted"
                );
                if policy == ScanPolicy::Strict {
                    assert!(matches!(verdict, Verdict::Block(BlockReason::ScanError(_))));
                } else {
                    assert_eq!(verdict, Verdict::Allow);
                }
                assert_eq!(mock.requests.lock().unwrap().len(), 1);
            }
        }
    }

    #[tokio::test]
    async fn disk_assessment_uses_streamed_digest_and_a_digest_names_no_package() {
        use beamline::test_support::{assessment, server};
        let tmp = tempfile::tempdir().unwrap();
        let body = b"disk artifact";
        let path = tmp.path().join("artifact.tgz");
        std::fs::write(&path, body).unwrap();
        let sha = sha_of(body);
        let mock = server(vec![(200, vec![assessment(&hex(&sha), "benign")])]).await;
        let scanner = test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            None,
            tmp.path().into(),
            ScanPolicy::Strict,
        );
        let verdict = scanner
            .scan_disk(DiskScanRequest {
                url: "https://registry.npmjs.org/demo/-/demo-1.tgz".into(),
                disclosure: Disclosure::Digest,
                early: Anticipated::default(),
                path,
                sha256: sha,
            })
            .await;
        assert_eq!(verdict, Verdict::Allow);
        assert!(scanner.analyzer.get().is_none());
        let requests = mock.requests.lock().unwrap().clone();
        assert!(requests[0].starts_with(&format!("GET /v1/lookup?sha256={}", hex(&sha))));
        assert!(!requests[0].contains("purl="));
    }

    const PUBLIC_URL: &str = "https://registry.npmjs.org/demo/-/demo-1.tgz";

    fn request(url: &str, disclosure: Disclosure, early: Anticipated, body: &[u8]) -> ScanRequest {
        ScanRequest {
            url: url.into(),
            disclosure,
            early,
            body: Bytes::copy_from_slice(body),
            sha256: sha_of(body),
        }
    }

    #[tokio::test]
    async fn a_credentialed_download_tells_beamline_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let body = b"private artifact";
        let mock = beamline::test_support::server(vec![]).await;
        let client = || Some(beamline::Client::new(&mock.url, None).unwrap());

        // Unknown to the filters: decided locally, here by failing to.
        let scanner = Arc::new(test_scanner(
            client(),
            None,
            tmp.path().into(),
            ScanPolicy::Strict,
        ));
        let early = Arc::clone(&scanner).anticipate(PUBLIC_URL, Disclosure::Nothing);
        let verdict = scanner
            .scan(request(PUBLIC_URL, Disclosure::Nothing, early, body))
            .await;
        assert!(matches!(verdict, Verdict::Block(BlockReason::ScanError(_))));

        // Known bad: blocked without asking Beamline to explain.
        publish_filters(tmp.path(), &[(Tier::Bad, rec(None, Some(sha_of(body))))]);
        let scanner = test_scanner(
            client(),
            Some(scan::bloom_repo::test_support::load_from(tmp.path())),
            tmp.path().join("missing-model"),
            ScanPolicy::Strict,
        );
        let verdict = scanner
            .scan(request(
                PUBLIC_URL,
                Disclosure::Nothing,
                Anticipated::default(),
                body,
            ))
            .await;
        assert_eq!(
            verdict,
            Verdict::Block(BlockReason::KnownBad(hex(&sha_of(body))))
        );
        assert!(mock.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_public_package_is_analyzed_while_it_downloads() {
        use beamline::test_support::{assessment, server};
        let tmp = tempfile::tempdir().unwrap();
        let body = b"public package tarball, as the registry serves it";
        let sha = hex(&sha_of(body));
        let mock = server(vec![(200, vec![assessment(&sha, "hostile")])]).await;
        let scanner = Arc::new(test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            None,
            tmp.path().into(),
            ScanPolicy::Strict,
        ));
        let mut early = Arc::clone(&scanner).anticipate(PUBLIC_URL, Disclosure::Coordinate);
        // The analysis is over before there is a body to hash.
        let analysis = early.0.take().unwrap().await.unwrap();
        assert!(analysis.unwrap().is_ok());
        let requests = mock.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST /v1/analyze?"));
        assert!(requests[0].contains("purl=pkg%3Anpm%2Fdemo%401"));

        // Begun again, as the proxy would, the download asks nothing more.
        let mock = server(vec![(200, vec![assessment(&sha, "hostile")])]).await;
        let scanner = Arc::new(test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            None,
            tmp.path().into(),
            ScanPolicy::Strict,
        ));
        let early = Arc::clone(&scanner).anticipate(PUBLIC_URL, Disclosure::Coordinate);
        let verdict = scanner
            .scan(request(PUBLIC_URL, Disclosure::Coordinate, early, body))
            .await;
        assert_eq!(verdict, Verdict::Block(BlockReason::Hostile));
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
        assert!(scanner.analyzer.get().is_none());
    }

    #[tokio::test]
    async fn an_error_page_is_not_judged_by_its_packages_analysis() {
        use beamline::test_support::{assessment, server};
        let tmp = tempfile::tempdir().unwrap();
        let body = b"<html><body><h1>404 Not Found</h1></body></html>";
        let sha = hex(&sha_of(body));
        // The package the URL names is benign; these bytes are not it.
        let mock = server(vec![
            (200, vec![assessment(&"b".repeat(64), "benign")]),
            (200, vec![assessment(&sha, "hostile")]),
        ])
        .await;
        let scanner = Arc::new(test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            None,
            tmp.path().into(),
            ScanPolicy::Strict,
        ));
        let mut early = Arc::clone(&scanner).anticipate(PUBLIC_URL, Disclosure::Coordinate);
        let analysis = early.0.take().unwrap().await.unwrap();
        early.0 = Some(tokio::spawn(async move { analysis }));
        // The proxy lowers the disclosure of a response that did not succeed.
        let verdict = scanner
            .scan(request(PUBLIC_URL, Disclosure::Digest, early, body))
            .await;
        assert_eq!(verdict, Verdict::Block(BlockReason::Hostile));
        let requests = mock.requests.lock().unwrap().clone();
        assert!(requests[1].starts_with(&format!("GET /v1/lookup?sha256={sha}")));
    }

    #[tokio::test]
    async fn a_download_beamline_cannot_know_warms_the_analyzer_instead() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = beamline::test_support::server(vec![]).await;
        for (url, disclosure) in [
            (
                "https://private.example/tool.tar.gz",
                Disclosure::Coordinate,
            ),
            (PUBLIC_URL, Disclosure::Digest),
            (PUBLIC_URL, Disclosure::Nothing),
        ] {
            let scanner = Arc::new(test_scanner(
                Some(beamline::Client::new(&mock.url, None).unwrap()),
                None,
                tmp.path().into(),
                ScanPolicy::Strict,
            ));
            let mut early = Arc::clone(&scanner).anticipate(url, disclosure);
            assert!(early.0.take().unwrap().await.unwrap().is_none());
            // The model directory is empty, so the load was tried and failed.
            assert!(matches!(scanner.analyzer.get(), Some(Err(_))), "{url}");
        }
        assert!(mock.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_package_the_filters_know_by_name_starts_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let body = b"known package";
        publish_filters(
            tmp.path(),
            &[(Tier::Good, rec(Some("pkg:npm/demo@1"), Some(sha_of(body))))],
        );
        let mock = beamline::test_support::server(vec![]).await;
        let scanner = Arc::new(test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            Some(scan::bloom_repo::test_support::load_from(tmp.path())),
            tmp.path().join("missing-model"),
            ScanPolicy::Strict,
        ));
        let mut early = Arc::clone(&scanner).anticipate(PUBLIC_URL, Disclosure::Coordinate);
        assert!(early.0.take().unwrap().await.unwrap().is_none());
        assert!(scanner.analyzer.get().is_none());
        assert!(mock.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_remembered_pass_needs_neither_beamline_nor_an_analyzer() {
        let tmp = tempfile::tempdir().unwrap();
        let body = b"scanned before";
        let url = "https://private.example/tool.tar.gz";
        let remember = || {
            let verdicts = VerdictCache::new(tmp.path().join("verdicts"), "r1".into());
            verdicts.put(&hex(&sha_of(body)), url, 0.01).unwrap();
            OnceCell::new_with(Some(Some(Arc::new(verdicts))))
        };
        let mock = beamline::test_support::server(vec![]).await;
        let mut scanner = test_scanner(
            Some(beamline::Client::new(&mock.url, None).unwrap()),
            None,
            tmp.path().join("missing-model"),
            ScanPolicy::Strict,
        );
        scanner.verdicts = remember();
        let scan = |scanner: AtomScanner| async move {
            scanner
                .scan(request(
                    url,
                    Disclosure::Coordinate,
                    Anticipated::default(),
                    body,
                ))
                .await
        };
        assert_eq!(scan(scanner).await, Verdict::Allow);
        assert!(mock.requests.lock().unwrap().is_empty());

        // The filters are newer than any pass: a revocation still blocks.
        publish_filters(tmp.path(), &[(Tier::Bad, rec(None, Some(sha_of(body))))]);
        let mut scanner = test_scanner(
            None,
            Some(scan::bloom_repo::test_support::load_from(tmp.path())),
            tmp.path().join("missing-model"),
            ScanPolicy::Strict,
        );
        scanner.verdicts = remember();
        assert!(matches!(
            scan(scanner).await,
            Verdict::Block(BlockReason::KnownBad(_))
        ));
    }

    /// Local analysis starts beside a Beamline that is slow to answer; here
    /// it fails, and the answer already asked for decides.
    #[tokio::test]
    async fn a_local_failure_waits_for_the_answer_beamline_owes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tmp = tempfile::tempdir().unwrap();
        let body = b"slowly assessed, and long enough to be asked about";
        let reply = beamline::test_support::assessment(&hex(&sha_of(body)), "benign");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mut scanner = test_scanner(
            Some(beamline::Client::new(&endpoint, None).unwrap()),
            None,
            tmp.path().into(),
            ScanPolicy::Strict,
        );
        scanner.hedge = Duration::ZERO;
        let scanner = Arc::new(scanner);
        let scan = tokio::spawn({
            let scanner = Arc::clone(&scanner);
            async move {
                scanner
                    .scan(request(
                        "https://private.example/tool.tar.gz",
                        Disclosure::Digest,
                        Anticipated::default(),
                        body,
                    ))
                    .await
            }
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            request.push(byte[0]);
        }
        // Beamline answers only once local analysis has started and failed.
        while scanner.analyzer.get().is_none() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        assert_eq!(scan.await.unwrap(), Verdict::Allow);
    }

    #[test]
    fn hex32_is_lowercase_and_64_wide() {
        let mut d = [0u8; 32];
        d[1] = 0xff;
        d[31] = 0xab;
        let s = hex(&d);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("00ff"));
        assert!(s.ends_with("ab"));
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    // ----- verdict matrix --------------------------------------------------

    #[test]
    fn strict_policy_blocks_everything_non_benign() {
        assert_eq!(
            verdict_from(Classification::Benign, ScanPolicy::Strict),
            Verdict::Allow,
        );
        assert_eq!(
            verdict_from(Classification::Suspicious, ScanPolicy::Strict),
            Verdict::Block(BlockReason::Suspicious),
        );
        assert_eq!(
            verdict_from(Classification::Hostile, ScanPolicy::Strict),
            Verdict::Block(BlockReason::Hostile),
        );
    }

    #[test]
    fn allow_errors_blocks_suspicious_and_hostile() {
        // AllowErrors changes nothing about classification verdicts — it only
        // affects what happens when the scanner *itself* errors out. So the
        // matrix for AllowErrors matches Strict at this layer.
        assert_eq!(
            verdict_from(Classification::Benign, ScanPolicy::AllowErrors),
            Verdict::Allow,
        );
        assert_eq!(
            verdict_from(Classification::Suspicious, ScanPolicy::AllowErrors),
            Verdict::Block(BlockReason::Suspicious),
        );
        assert_eq!(
            verdict_from(Classification::Hostile, ScanPolicy::AllowErrors),
            Verdict::Block(BlockReason::Hostile),
        );
    }

    #[test]
    fn allow_suspicious_blocks_only_hostile() {
        assert_eq!(
            verdict_from(Classification::Benign, ScanPolicy::AllowSuspicious),
            Verdict::Allow,
        );
        assert_eq!(
            verdict_from(Classification::Suspicious, ScanPolicy::AllowSuspicious),
            Verdict::Allow,
        );
        assert_eq!(
            verdict_from(Classification::Hostile, ScanPolicy::AllowSuspicious),
            Verdict::Block(BlockReason::Hostile),
        );
    }

    #[test]
    fn bypass_allows_everything() {
        for c in [
            Classification::Benign,
            Classification::Suspicious,
            Classification::Hostile,
        ] {
            assert_eq!(
                verdict_from(c, ScanPolicy::Bypass),
                Verdict::Allow,
                "bypass must allow {c:?}",
            );
        }
    }

    #[test]
    fn policy_allows_error_ladder() {
        assert!(!policy_allows_error(ScanPolicy::Strict));
        assert!(policy_allows_error(ScanPolicy::AllowErrors));
        assert!(policy_allows_error(ScanPolicy::AllowSuspicious));
        assert!(policy_allows_error(ScanPolicy::Bypass));
    }
}
