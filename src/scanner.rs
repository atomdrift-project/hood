//! Local Bloom gate, minimal-disclosure Beamline assessment, and lazy local analysis.
//! Every available identity participates in the Bloom decision before any API call.

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
use crate::output::Disposition;

// `Analyzer::load` classifies at scan's default severity; hood's verdicts,
// panels and Beamline budget are all calibrated for L25.
const _: () = assert!(
    scan::model::DEFAULT_SEVERITY_LEVEL == 25,
    "scan's default severity changed from L25"
);

/// How long a Bloom known-bad block waits for Beamline's explanation.
const KNOWN_BAD_DETAILS_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Context the scanner gets alongside the payload bytes.
#[derive(Debug)]
pub struct ScanRequest {
    /// The URL the tool originally requested. Used as the filename hint to
    /// cleave (which keys off extension) and as a log field.
    pub url: String,
    /// Whether request provenance permits disclosing a public package coordinate.
    pub allow_purl: bool,
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
    /// Whether request provenance permits disclosing a public package coordinate.
    pub allow_purl: bool,
    /// On-disk file holding the full payload. Named with the payload's real
    /// extension so cleave's type detection matches an in-memory scan.
    pub path: PathBuf,
    /// SHA-256 of the payload, computed while it streamed to disk.
    pub sha256: [u8; 32],
}

/// A scanner backend.
///
/// Every method decides; none can fail. A backend that cannot inspect a
/// payload says what its policy does with that, so no caller has to guess
/// whether an error forwards or blocks. No method has a default, so a new
/// backend cannot inherit a decision it did not make.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync + std::fmt::Debug {
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
        let remote = match beamline::Client::from_env() {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "Beamline configuration unavailable; using local analysis");
                None
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
        }
    }

    async fn analyzer(&self) -> Result<Arc<Analyzer>> {
        let result = self
            .analyzer
            .get_or_init(|| async {
                let model_dir = self.model_dir.clone();
                tokio::task::spawn_blocking(move || {
                    // Before the analyzer resolves a rules tree: logged in
                    // means the Enriched one, and never the working directory's.
                    activate_enriched();
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

    /// Run `job` on the local analyzer, off the async runtime, and decide its
    /// result under policy.
    async fn analyze<F>(&self, url: &str, job: F) -> Verdict
    where
        F: FnOnce(&Analyzer) -> Result<ScanResult> + Send + 'static,
    {
        let result = match self.analyzer().await {
            Ok(analyzer) => tokio::task::spawn_blocking(move || job(&analyzer))
                .await
                .context("scan task join")
                .flatten(),
            Err(error) => Err(error),
        };
        self.classify_result(url, result)
    }

    async fn gate(&self, url: &str, allow_purl: bool, sha: &[u8; 32]) -> Option<Verdict> {
        // Local identity checks may use private coordinates; disclosure is decided
        // separately, only if the local bundle cannot resolve the artifact.
        let purl = fletch::purl::url_to_purl(url);
        let bloom = self
            .bloom
            .get_or_init(|| async {
                tokio::task::spawn_blocking(load_bloom)
                    .await
                    .unwrap_or_else(|error| {
                        tracing::warn!(%error, "Bloom load failed; continuing to assessment");
                        None
                    })
            })
            .await;
        // Bloom revocations must take precedence over even a fresh benign cache entry.
        if let Some(lookup) = bloom {
            let decision = lookup.decide_any(purl.as_deref(), Some(sha));
            if let Some(verdict) = bloom_verdict(decision, self.policy, url, sha) {
                return Some(self.report_bloom(decision, verdict, url, sha).await);
            }
        }
        let client = self.remote.as_ref()?;
        let purl = allow_purl.then(|| beamline::public_purl(url)).flatten();
        let sha = hex(sha);
        match client.assess(purl.as_deref(), &sha).await {
            Ok(assessment) => {
                let Some(classification) = assessment.classification(&sha) else {
                    tracing::debug!("Beamline has no matching assessment; scanning locally");
                    return None;
                };
                let verdict = verdict_from(classification, self.policy);
                if let Some(status) = &self.status {
                    status.record(classification, verdict.disposition());
                }
                if classification != Classification::Benign || self.status.is_some() {
                    crate::output::emit_remote(
                        classification,
                        verdict.disposition(),
                        self.policy,
                        &assessment,
                    );
                }
                Some(verdict)
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "Beamline unavailable; scanning locally");
                None
            }
        }
    }

    /// Show and count a decision the Bloom filter made on its own.
    async fn report_bloom(
        &self,
        decision: Decision,
        verdict: Verdict,
        url: &str,
        sha: &[u8; 32],
    ) -> Verdict {
        let known_bad = decision == Decision::KnownBad;
        if known_bad {
            let explanation = self.known_bad_explanation(sha).await;
            crate::output::emit_known_bad(&crate::output::KnownBadPanel {
                url,
                sha256: &hex(sha),
                policy: self.policy,
                disposition: verdict.disposition(),
                invocation: &self.invocation,
                beamline: &explanation,
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

    /// Beamline's explanation of a payload the Bloom filter has already
    /// condemned, as display lines: its reason, then its leading findings.
    ///
    /// The verdict never depends on this. It is a hash-only lookup, bounded
    /// by [`KNOWN_BAD_DETAILS_TIMEOUT`], and an answer that does not agree the
    /// payload is bad is dropped rather than shown beside the block.
    async fn known_bad_explanation(&self, sha: &[u8; 32]) -> Vec<String> {
        let Some(client) = &self.remote else {
            return Vec::new();
        };
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
                return Vec::new();
            }
            Err(_) => {
                tracing::debug!("Beamline details for known-bad payload timed out");
                return Vec::new();
            }
        };
        if !matches!(
            assessment.classification(&sha),
            Some(Classification::Hostile | Classification::Suspicious)
        ) {
            tracing::debug!("Beamline does not confirm the known-bad payload; no details shown");
            return Vec::new();
        }
        assessment
            .reason
            .iter()
            .cloned()
            .chain(assessment.findings.iter().take(3).map(|finding| {
                finding.desc.as_ref().map_or_else(
                    || finding.id.clone(),
                    |desc| format!("{} {desc}", finding.id),
                )
            }))
            .collect()
    }

    /// Turn a raw analyzer result into a [`Verdict`], emitting the appropriate
    /// panel — a non-benign classification, or a scan error handled under the
    /// active policy. Shared by the in-memory ([`Scanner::scan`]) and
    /// streamed-to-disk ([`Scanner::scan_disk`]) paths so both render identically.
    fn classify_result(&self, url: &str, result: Result<ScanResult>) -> Verdict {
        let result = result.and_then(|result| {
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
        });
        match result {
            Ok(r) => {
                let verdict = verdict_from(r.classification, self.policy);
                let disposition = verdict.disposition();
                if let Some(status) = &self.status {
                    status.record(r.classification, disposition);
                }
                if matches!(r.classification, Classification::Benign) {
                    tracing::debug!(url = %crate::output::ShownUrl(url), probability = r.probability, "scan clean");
                    if self.status.is_some() {
                        crate::output::emit_pass(url, r.probability);
                    }
                } else {
                    // `top_findings` is already deduped, ranked strongest-first,
                    // and capped at 5 by the engine; take the leading three to
                    // keep the panel tight.
                    let traits = r.top_findings.get(..3).unwrap_or(&r.top_findings);
                    let reasons = r.reasons.get(..3).unwrap_or(&r.reasons);
                    crate::output::emit(&crate::output::Panel {
                        classification: r.classification,
                        disposition,
                        policy: self.policy,
                        probability: r.probability,
                        url,
                        traits,
                        reasons,
                        invocation: &self.invocation,
                    });
                }
                verdict
            }
            Err(e) => {
                let msg = format!("{e:#}");
                let verdict = if policy_allows_error(self.policy) {
                    Verdict::Allow
                } else {
                    Verdict::Block(BlockReason::ScanError(msg.clone()))
                };
                let disposition = verdict.disposition();
                if let Some(status) = &self.status {
                    status.record_error(disposition);
                }
                crate::output::emit_scan_error(&crate::output::ScanErrorPanel {
                    url,
                    error: &msg,
                    policy: self.policy,
                    disposition,
                    invocation: &self.invocation,
                });
                verdict
            }
        }
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
/// Enriched refreshes. Left to the first scan, the download happens inside a
/// request, and package managers abandon a transfer that sends nothing for a
/// few seconds (pacman after 10). Failures are logged and left to the lazy
/// analyzer load, which applies the scan policy per download.
///
/// Blocking: network and disk I/O.
pub fn prepare() {
    // Before anything resolves a rules tree: logged in means the Enriched one.
    activate_enriched();
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
    let installed = cleave::traits_repo::installed_dir(cleave::enriched::enabled());
    if !explicit
        && !installed.is_dir()
        && let Err(error) = scan::traits_repo::update(false, false)
    {
        tracing::warn!(error = %format!("{error:#}"), "rules install failed before the command started");
    }
    scan::traits_repo::prepare_runtime_env();
}

/// Check downloads with the isotope13 Enriched rules once `hood enrich` has
/// saved a token (or `ISOTOPE13_TOKEN` names one), refreshing them at most
/// once a day.
///
/// A refused token is a warning, never a failed install: a billing problem
/// must not block a developer's `npm install`, and the check itself still runs
/// — on the Enriched rules already installed, or on the open-source ones when
/// there are none yet.
fn activate_enriched() {
    static ACTIVATE: std::sync::Once = std::sync::Once::new();
    ACTIVATE.call_once(|| {
        // The refresh is what first installs the Enriched tree after `hood
        // enrich`, so it runs before the installed tree is checked. A refused
        // token falls the run back to the open-source rules inside the refresh,
        // with its own warning; what is left to say is a network failure.
        if token_selects_enriched()
            && due_today("traits-enriched-checked")
            && let Err(error) = scan::traits_repo::update(false, true)
        {
            tracing::warn!(error = %format!("{error:#}"), "Enriched rules refresh failed; using installed rules");
        }
        installed_or_open_source();
    });
}

/// Choose the rules a check uses, with no network.
///
/// That is the Enriched tree when this host holds a token (`hood enrich`, or
/// `ISOTOPE13_TOKEN`) and that tree is installed, the open-source one
/// otherwise.
pub fn select_rules() {
    if token_selects_enriched() {
        installed_or_open_source();
    }
}

/// Whether this host's token, or its absence, selects the Enriched rules.
fn token_selects_enriched() -> bool {
    if let Err(error) = cleave::enriched::resolve(false) {
        tracing::warn!(error = %format!("{error:#}"), "isotope13 token unusable; checking with open-source rules");
        return false;
    }
    cleave::enriched::enabled()
}

/// Keep Enriched only if its tree is on disk; a check never runs on no rules.
fn installed_or_open_source() {
    let installed = cleave::traits_repo::installed_dir(true);
    if cleave::enriched::enabled() && cleave::rule_update::installed(&installed).is_none() {
        tracing::warn!(dir = %installed.display(), "no Enriched rules installed; checking with open-source rules");
        cleave::enriched::set_enabled(false);
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
    async fn scan(&self, req: ScanRequest) -> Verdict {
        let ScanRequest {
            url,
            allow_purl,
            body,
            sha256,
        } = req;
        if let Some(verdict) = self.gate(&url, allow_purl, &sha256).await {
            return verdict;
        }
        let name = url.clone();
        self.analyze(&url, move |analyzer| {
            analyzer.scan_bytes(body.into(), &name)
        })
        .await
    }

    async fn scan_disk(&self, req: DiskScanRequest) -> Verdict {
        let DiskScanRequest {
            url,
            allow_purl,
            path,
            sha256,
        } = req;
        if let Some(verdict) = self.gate(&url, allow_purl, &sha256).await {
            return verdict;
        }
        let name = url.clone();
        self.analyze(&url, move |analyzer| analyzer.scan_file(&path, &name))
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
        self.classify_result(url, Err(anyhow::anyhow!("{why}")))
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
                allow_purl: false,
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
        let lookup = Lookup::load_from(tmp.path());
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
            Some(Lookup::load_from(tmp.path())),
            tmp.path().join("missing-model"),
            ScanPolicy::Strict,
        );
        let verdict = scanner
            .scan(ScanRequest {
                url: "https://registry.npmjs.org/demo/-/demo-1.tgz".into(),
                allow_purl: true,
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
                Some(Lookup::load_from(bundle.path())),
                bundle.path().join("missing-model"),
                ScanPolicy::default(),
            );
            let expected = Verdict::Block(BlockReason::KnownBad(sha_hex.clone()));
            assert_eq!(
                scanner
                    .scan(ScanRequest {
                        url: url.into(),
                        allow_purl: true,
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
                        allow_purl: true,
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
        let body = b"artifact bytes".to_vec();
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
                    allow_purl: false,
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

    #[tokio::test]
    async fn known_bad_explanation_shows_only_confirming_assessments() {
        use beamline::test_support::server;
        let tmp = tempfile::tempdir().unwrap();
        let body = b"known bad payload";
        let sha: [u8; 32] = sha_of(body);
        let hex = hex(&sha);
        let confirming = serde_json::json!({
            "status": "analyzed", "severity": "hostile", "sha256": hex,
            "reason": "steals credentials",
            "findings": [{"id": "exfil/ssh-key", "desc": "reads ~/.ssh"}, {"id": "exec/curl-sh"}],
        })
        .to_string();
        let benign = serde_json::json!({
            "status": "analyzed", "severity": "benign", "sha256": hex, "findings": [],
        })
        .to_string();
        for (status, response, expected) in [
            (
                200,
                confirming,
                vec![
                    "steals credentials".to_owned(),
                    "exfil/ssh-key reads ~/.ssh".to_owned(),
                    "exec/curl-sh".to_owned(),
                ],
            ),
            // A disagreeing or failed lookup adds nothing; the block stands.
            (200, benign, Vec::new()),
            (429, "quota".to_owned(), Vec::new()),
        ] {
            let mock = server(vec![(status, vec![response])]).await;
            let scanner = test_scanner(
                Some(beamline::Client::new(&mock.url, None).unwrap()),
                None,
                tmp.path().into(),
                ScanPolicy::Strict,
            );
            assert_eq!(scanner.known_bad_explanation(&sha).await, expected);
            let requests = mock.requests.lock().unwrap().clone();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].starts_with("GET /v1/lookup?sha256="));
        }
        let offline = test_scanner(None, None, tmp.path().into(), ScanPolicy::Strict);
        assert!(offline.known_bad_explanation(&sha).await.is_empty());
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
                        allow_purl: true,
                        body: Bytes::from_static(b"unknown"),
                        sha256: sha_of(b"unknown"),
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
    async fn disk_assessment_uses_streamed_digest_and_authentication_forces_hash_only() {
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
                allow_purl: false,
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
