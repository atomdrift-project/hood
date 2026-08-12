//! In-process payload scanner.
//!
//! `hood` does not shell out to `atomscan`. Instead it loads the scan crate's
//! model, feature extractor, and SHAP table once at startup and reuses them for
//! every intercepted response. cleave's SHA256-keyed analysis cache
//! short-circuits repeated identical payloads (very common on `npm
//! install`-style workloads).
//!
//! Two backends ship today:
//!
//! - [`AllowAll`] — short-circuits to [`Verdict::Allow`]. Used in tests and
//!   when `--no-scan` is requested.
//! - [`AtomScanner`] — production backend. Calls [`Analyzer::scan_bytes`] with
//!   bytes drawn directly from the buffered HTTP response.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use scan::bloom_repo::{Decision, Lookup};
use scan::engine::ScanResult;
use scan::model::Classification;
use scan::Analyzer;
use sha2::{Digest, Sha256};

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

impl BlockReason {
    /// Short human-readable label for log and error messages.
    #[must_use]
    pub fn label(&self) -> &str {
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
    /// Full payload body. The scanner takes ownership so cleave can avoid one
    /// full-size memcpy on hot paths.
    pub body: Vec<u8>,
}

/// A payload too large to buffer in RAM, spilled to a temporary file. The
/// SHA-256 is computed incrementally as the body streams to disk, so the bloom
/// gate runs without re-reading the file, and cleave memory-maps the path so the
/// ML scan's resident memory stays bounded regardless of payload size.
#[derive(Debug)]
pub struct DiskScanRequest {
    /// The URL the tool requested — cleave filename hint and log/panel field.
    pub url: String,
    /// On-disk file holding the full payload. Named with the payload's real
    /// extension so cleave's type detection matches an in-memory scan.
    pub path: std::path::PathBuf,
    /// SHA-256 of the payload, computed while it streamed to disk.
    pub sha256: [u8; 32],
}

/// Outcome of the pre-fetch PURL gate — decided from the URL alone, before a
/// single response byte is downloaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prefetch {
    /// Known-good PURL: forward the response without scanning it.
    SkipForward,
    /// Known-bad PURL: withhold before spending any download (unless a bypass
    /// policy forwards it, in which case [`Prefetch::SkipForward`] is returned).
    Block(BlockReason),
    /// No decisive PURL signal: fetch, then scan according to size.
    Proceed,
}

/// A scanner backend.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync + std::fmt::Debug {
    /// Inspect an in-memory payload and return a verdict.
    async fn scan(&self, req: ScanRequest) -> Result<Verdict>;

    /// Consult the known-good/known-bad PURL channel before fetching. The
    /// default backend (no bloom) always proceeds to a full fetch-and-scan.
    fn prefetch(&self, _url: &str) -> Prefetch {
        Prefetch::Proceed
    }

    /// Scan a payload spilled to disk (too large to buffer in RAM). The default
    /// backend has no model, so it forwards the payload unscanned.
    async fn scan_disk(&self, _req: DiskScanRequest) -> Result<Verdict> {
        Ok(Verdict::Allow)
    }
}

/// Trivial scanner that allows everything. For tests and `--no-scan`.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

#[async_trait::async_trait]
impl Scanner for AllowAll {
    async fn scan(&self, _req: ScanRequest) -> Result<Verdict> {
        Ok(Verdict::Allow)
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

/// In-process atomscan scanner.
///
/// Construct with [`AtomScanner::load`], which loads model artifacts and
/// warms cleave's shared resources via [`Analyzer::load`]. The struct is
/// cheap to clone (everything is held behind `Arc`) and is `Send + Sync` so
/// the proxy can share it across all concurrent connections.
#[derive(Clone)]
pub struct AtomScanner {
    inner: Arc<Inner>,
}

struct Inner {
    analyzer: Analyzer,
    policy: ScanPolicy,
    invocation: String,
    /// Known-good/known-bad bloom filters, when synced. `None` disables the
    /// fast path entirely (no hashing, no lookups) — the safe, zero-overhead
    /// default on a machine that has never run `atomscan update-rules`.
    bloom: Option<Lookup>,
}

impl std::fmt::Debug for AtomScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomScanner")
            .field("policy", &self.inner.policy)
            .field("model_dir", &self.inner.analyzer.model_dir())
            .finish()
    }
}

impl AtomScanner {
    /// Load model artifacts from disk and prepare a ready-to-use scanner.
    ///
    /// `model_dir` is the same directory passed to `atomscan --model-dir`;
    /// when `None`, the scan models_repo resolver is used (auto-clone on
    /// first call).
    ///
    /// `invocation` is the shell-quoted command the user ran (e.g.
    /// `"curl -fsSL https://x"`), surfaced in the bypass hint of the
    /// stderr panel so they can copy/paste a working command.
    pub fn load(
        model_dir: Option<PathBuf>,
        policy: ScanPolicy,
        invocation: String,
    ) -> Result<Self> {
        let model_dir = match model_dir {
            Some(d) => d,
            None => scan::models_repo::model_dir().context("resolve scan model dir")?,
        };
        let analyzer = Analyzer::load(model_dir).context("load scan analyzer")?;
        Ok(Self {
            inner: Arc::new(Inner {
                analyzer,
                policy,
                invocation,
                bloom: load_bloom(),
            }),
        })
    }

    /// Consult the bloom filters before any expensive analysis. Returns
    /// `Some(verdict)` to short-circuit (a known-good skip or a known-bad
    /// block), or `None` to fall through to the ML scan. Hashes the body, then
    /// defers to [`bloom_gate_sha`].
    fn bloom_gate(&self, req: &ScanRequest) -> Option<Verdict> {
        let lookup = self.inner.bloom.as_ref()?;
        let mut hasher = Sha256::new();
        hasher.update(&req.body);
        let sha: [u8; 32] = hasher.finalize().into();
        bloom_gate_sha(
            lookup,
            self.inner.policy,
            &self.inner.invocation,
            &req.url,
            &sha,
        )
    }

    fn verdict_for(&self, result: &ScanResult) -> Verdict {
        verdict_from(result.classification, self.inner.policy)
    }

    /// Turn a raw analyzer result into a [`Verdict`], emitting the appropriate
    /// panel — a non-benign classification, or a scan error handled under the
    /// active policy. Shared by the in-memory ([`Scanner::scan`]) and
    /// streamed-to-disk ([`Scanner::scan_disk`]) paths so both render identically.
    fn classify_result(&self, url: &str, result: Result<ScanResult>) -> Verdict {
        match result {
            Ok(r) => {
                let verdict = self.verdict_for(&r);
                if matches!(r.classification, Classification::Benign) {
                    tracing::debug!(url, probability = r.probability, "scan clean");
                } else {
                    let disposition = match &verdict {
                        Verdict::Allow => crate::output::Disposition::Forwarded,
                        Verdict::Block(_) => crate::output::Disposition::Blocked,
                    };
                    // `top_findings` is already deduped, ranked strongest-first,
                    // and capped at 5 by the engine; take the leading three to
                    // keep the panel tight.
                    let n_traits = r.top_findings.len().min(3);
                    let traits_slice = r.top_findings.get(..n_traits).unwrap_or(&[]);
                    let n_reasons = r.reasons.len().min(3);
                    let reasons_slice = r.reasons.get(..n_reasons).unwrap_or(&[]);
                    crate::output::emit(&crate::output::Panel {
                        classification: r.classification,
                        // The scan backend no longer exposes a pre-upgrade
                        // classification, so there is nothing to attribute here.
                        original: None,
                        disposition,
                        policy: self.inner.policy,
                        probability: r.probability,
                        url,
                        traits: traits_slice,
                        reasons: reasons_slice,
                        invocation: &self.inner.invocation,
                    });
                }
                verdict
            }
            Err(e) => {
                let msg = format!("{e:#}");
                let policy = self.inner.policy;
                let allowed = policy_allows_error(policy);
                let disposition = if allowed {
                    crate::output::Disposition::Forwarded
                } else {
                    crate::output::Disposition::Blocked
                };
                crate::output::emit_scan_error(&crate::output::ScanErrorPanel {
                    url,
                    error: &msg,
                    policy,
                    disposition,
                    invocation: &self.inner.invocation,
                });
                if allowed {
                    Verdict::Allow
                } else {
                    Verdict::Block(BlockReason::ScanError(msg))
                }
            }
        }
    }
}

/// Run the bloom gate against a loaded filter set, given a payload's URL and its
/// already-computed SHA-256. Free-standing (rather than a method) so it can be
/// exercised with a synthetic [`Lookup`] and no ML model, and so both the
/// in-memory ([`AtomScanner::bloom_gate`]) and streamed-to-disk
/// ([`AtomScanner::scan_disk`]) paths share one gate. Derives a PURL from the URL
/// via [`fletch::url_to_purl`], consults both channels, and emits the known-bad
/// panel as a side effect on a bad hit.
///
/// Trust model: a byte-exact known-good *hash* proves the bytes are good, and a
/// known-good *PURL* is likewise honored as a skip here (hood trusts the synced
/// good set as an allowlist). Either known-bad channel blocks, except under
/// `HOOD_BYPASS=3` which forwards everything. The panel links the lab by the
/// payload's own SHA-256.
fn bloom_gate_sha(
    lookup: &Lookup,
    policy: ScanPolicy,
    invocation: &str,
    url: &str,
    sha: &[u8; 32],
) -> Option<Verdict> {
    let by_hash = lookup.decide_sha256(sha);
    let by_purl = fletch::url_to_purl(url).map_or(Decision::Unknown, |p| lookup.decide_purl(&p));

    match gate_outcome(by_hash, by_purl, policy) {
        GateOutcome::Scan => None,
        GateOutcome::Skip => {
            tracing::debug!(url, "bloom known-good skip");
            Some(Verdict::Allow)
        }
        outcome => {
            let sha_hex = hex32(sha);
            let blocked = matches!(outcome, GateOutcome::Block);
            crate::output::emit_known_bad(&crate::output::KnownBadPanel {
                url,
                sha256: &sha_hex,
                purl: None,
                policy,
                disposition: if blocked {
                    crate::output::Disposition::Blocked
                } else {
                    crate::output::Disposition::Forwarded
                },
                invocation,
            });
            Some(if blocked {
                Verdict::Block(BlockReason::KnownBad(sha_hex))
            } else {
                Verdict::Allow
            })
        }
    }
}

/// What the bloom gate decided to do with a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateOutcome {
    /// Known-bad; withhold the body and show the block panel.
    Block,
    /// Known-bad, but `HOOD_BYPASS=3` is active — forward and show a panel.
    Forward,
    /// Byte-exact known-good; forward without scanning.
    Skip,
    /// No decisive signal — proceed to the ML scan.
    Scan,
}

/// Resolve the two bloom channels + policy into an action. Pulled out so the
/// precedence (known-bad wins; a known-good *hash or PURL* skips) is
/// unit-testable without loading real filters.
fn gate_outcome(by_hash: Decision, by_purl: Decision, policy: ScanPolicy) -> GateOutcome {
    if matches!(by_hash, Decision::KnownBad) || matches!(by_purl, Decision::KnownBad) {
        // Known-bad is at least as severe as an ML "hostile" verdict, so only
        // the top bypass tier (forward everything) lets it through.
        if matches!(policy, ScanPolicy::Bypass) {
            GateOutcome::Forward
        } else {
            GateOutcome::Block
        }
    } else if matches!(by_hash, Decision::Skip) || matches!(by_purl, Decision::Skip) {
        // A known-good hash proves the bytes; a known-good PURL is trusted as an
        // allowlist entry. Either skips the scan.
        GateOutcome::Skip
    } else {
        GateOutcome::Scan
    }
}

/// Load the bloom filters, honoring `HOOD_NO_BLOOM` and dropping an empty
/// (unsynced) set so the gate is a no-op rather than a wasted hash per payload.
fn load_bloom() -> Option<Lookup> {
    if std::env::var_os("HOOD_NO_BLOOM").is_some_and(|v| !v.is_empty()) {
        tracing::debug!("HOOD_NO_BLOOM set — bloom fast path disabled");
        return None;
    }
    let lookup = Lookup::load();
    lookup.is_active().then_some(lookup)
}

/// Lower-hex encode a 32-byte digest without pulling in a hex crate.
fn hex32(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in digest {
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
        // Bypass forwards every classification.
        (_, ScanPolicy::Bypass) => Verdict::Allow,
        // Benign is always allowed.
        (Classification::Benign, _) => Verdict::Allow,
        // Suspicious: allowed by AllowSuspicious (and Bypass, handled above).
        (Classification::Suspicious, ScanPolicy::AllowSuspicious) => Verdict::Allow,
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
    async fn scan(&self, req: ScanRequest) -> Result<Verdict> {
        // Fast path: a bloom hit (known-good hash/PURL → skip, known-bad → block)
        // returns a verdict without ever touching the ML model. Near-invisible
        // for the common known-good case.
        if let Some(verdict) = self.bloom_gate(&req) {
            return Ok(verdict);
        }

        // Analyzer::scan_bytes is CPU-bound (XGBoost + cleave). Run it on
        // the blocking pool so the proxy's async reactor isn't stalled by a
        // multi-megabyte binary classification.
        let inner = Arc::clone(&self.inner);
        let url = req.url.clone();
        let body = req.body;
        let result = tokio::task::spawn_blocking(move || inner.analyzer.scan_bytes(body, &url))
            .await
            .context("scan task join")?;
        Ok(self.classify_result(&req.url, result))
    }

    fn prefetch(&self, url: &str) -> Prefetch {
        let Some(lookup) = self.inner.bloom.as_ref() else {
            return Prefetch::Proceed;
        };
        let Some(purl) = fletch::url_to_purl(url) else {
            return Prefetch::Proceed;
        };
        match lookup.decide_purl(&purl) {
            // Known-good PURL: trusted allowlist entry — forward without scanning.
            Decision::Skip => {
                tracing::debug!(url, purl, "bloom known-good purl skip (pre-fetch)");
                Prefetch::SkipForward
            }
            // Known-bad PURL: withhold before downloading a byte. `HOOD_BYPASS=3`
            // forwards it (still unscanned) instead of blocking.
            Decision::KnownBad => {
                let blocked = !matches!(self.inner.policy, ScanPolicy::Bypass);
                crate::output::emit_known_bad(&crate::output::KnownBadPanel {
                    url,
                    // No bytes fetched yet, so no hash to link — the panel keys
                    // the match on the PURL instead.
                    sha256: "",
                    purl: Some(&purl),
                    policy: self.inner.policy,
                    disposition: if blocked {
                        crate::output::Disposition::Blocked
                    } else {
                        crate::output::Disposition::Forwarded
                    },
                    invocation: &self.inner.invocation,
                });
                if blocked {
                    Prefetch::Block(BlockReason::KnownBad(purl))
                } else {
                    Prefetch::SkipForward
                }
            }
            Decision::Conflicted | Decision::Unknown => Prefetch::Proceed,
        }
    }

    async fn scan_disk(&self, req: DiskScanRequest) -> Result<Verdict> {
        // Bloom gate on the SHA computed while streaming to disk (plus the URL's
        // PURL) — no re-read of the file. A decisive hit skips the ML scan.
        if let Some(lookup) = self.inner.bloom.as_ref() {
            if let Some(verdict) = bloom_gate_sha(
                lookup,
                self.inner.policy,
                &self.inner.invocation,
                &req.url,
                &req.sha256,
            ) {
                return Ok(verdict);
            }
        }

        // cleave memory-maps the file, so this classifies a multi-hundred-megabyte
        // payload without loading it whole into RAM. Still CPU-bound → blocking pool.
        let inner = Arc::clone(&self.inner);
        let url = req.url.clone();
        let path = req.path.clone();
        let result = tokio::task::spawn_blocking(move || inner.analyzer.scan_file(&path, &url))
            .await
            .context("disk scan task join")?;
        Ok(self.classify_result(&req.url, result))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allow_all_allows() {
        let s = AllowAll;
        let v = s
            .scan(ScanRequest {
                url: "http://x".into(),
                body: b"hi".to_vec(),
            })
            .await
            .unwrap();
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

    // ----- bloom gate ------------------------------------------------------

    #[test]
    fn gate_blocks_known_bad_from_either_channel() {
        assert_eq!(
            gate_outcome(Decision::KnownBad, Decision::Unknown, ScanPolicy::Strict),
            GateOutcome::Block,
        );
        assert_eq!(
            gate_outcome(Decision::Unknown, Decision::KnownBad, ScanPolicy::Strict),
            GateOutcome::Block,
        );
        // A known-bad is at least as severe as ML "hostile": even =2 blocks it.
        assert_eq!(
            gate_outcome(
                Decision::KnownBad,
                Decision::Unknown,
                ScanPolicy::AllowSuspicious
            ),
            GateOutcome::Block,
        );
        // Only =3 (forward everything) lets it through.
        assert_eq!(
            gate_outcome(Decision::KnownBad, Decision::Unknown, ScanPolicy::Bypass),
            GateOutcome::Forward,
        );
    }

    #[test]
    fn gate_skips_on_hash_or_purl_known_good() {
        // Byte-exact known-good is safe to skip.
        assert_eq!(
            gate_outcome(Decision::Skip, Decision::Unknown, ScanPolicy::Strict),
            GateOutcome::Skip,
        );
        // A known-good PURL also skips: hood trusts the synced good set as an
        // allowlist (the deliberate trust-model change).
        assert_eq!(
            gate_outcome(Decision::Unknown, Decision::Skip, ScanPolicy::Strict),
            GateOutcome::Skip,
        );
        // Conflicted and Unknown both fall through to the ML scan.
        assert_eq!(
            gate_outcome(
                Decision::Conflicted,
                Decision::Conflicted,
                ScanPolicy::Strict
            ),
            GateOutcome::Scan,
        );
        assert_eq!(
            gate_outcome(Decision::Unknown, Decision::Unknown, ScanPolicy::Strict),
            GateOutcome::Scan,
        );
    }

    #[test]
    fn gate_known_bad_wins_over_hash_skip() {
        // Contradictory channels resolve conservatively toward blocking.
        assert_eq!(
            gate_outcome(Decision::Skip, Decision::KnownBad, ScanPolicy::Strict),
            GateOutcome::Block,
        );
    }

    /// Build the four `.adbl` filters from a small pool and write them to `dir`
    /// exactly as `atomscan update-rules` would, so the gate exercises the real
    /// on-disk load + query path.
    fn publish_filters(
        dir: &std::path::Path,
        good: Vec<scan::bloom::Record>,
        bad: Vec<scan::bloom::Record>,
    ) {
        for f in scan::bloom::generate(good, bad, 1e-9) {
            let path = dir.join(format!("{}.adbl", f.artifact_stem()));
            std::fs::write(path, f.to_bytes()).unwrap();
        }
    }

    fn sha_of(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    #[test]
    fn bloom_gate_end_to_end_over_real_filters() {
        use scan::bloom::Record;

        let tmp = tempfile::tempdir().unwrap();
        let good_body = b"benign package bytes".to_vec();
        let bad_body = b"malware package bytes".to_vec();
        let good_sha = sha_of(&good_body);
        let bad_sha = sha_of(&bad_body);

        publish_filters(
            tmp.path(),
            vec![Record {
                purl: Some("pkg:npm/good@1.0.0".into()),
                sha256: Some(good_sha),
            }],
            vec![Record {
                // Known-bad by BOTH a hash and, separately, a PURL coordinate.
                purl: Some("pkg:npm/evil@1.0.0".into()),
                sha256: Some(bad_sha),
            }],
        );
        let lookup = Lookup::load_from(tmp.path());
        assert!(lookup.is_active());

        // Known-bad hash → hard block carrying the payload's SHA-256.
        let v = bloom_gate_sha(&lookup, ScanPolicy::Strict, "", "https://x/e.tgz", &bad_sha);
        assert_eq!(
            v,
            Some(Verdict::Block(BlockReason::KnownBad(hex32(&bad_sha))))
        );

        // Same known-bad hash under HOOD_BYPASS=3 → forwarded, not blocked.
        let v = bloom_gate_sha(&lookup, ScanPolicy::Bypass, "", "https://x/e.tgz", &bad_sha);
        assert_eq!(v, Some(Verdict::Allow));

        // Known-bad *PURL* (derived from the npm URL) with novel bytes → block,
        // even though the hash is unknown. Proves the fletch url→purl wiring.
        let novel = sha_of(b"repackaged novel bytes");
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "",
            "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
            &novel,
        );
        assert!(matches!(v, Some(Verdict::Block(BlockReason::KnownBad(_)))));

        // Byte-exact known-good → skip (allow) without scanning.
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "",
            "https://x/g.tgz",
            &good_sha,
        );
        assert_eq!(v, Some(Verdict::Allow));

        // A known-good PURL now skips even with unknown bytes: hood trusts the
        // synced good set as an allowlist (the deliberate trust-model change).
        let tampered = sha_of(b"tampered bytes under a good name");
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "",
            "https://registry.npmjs.org/good/-/good-1.0.0.tgz",
            &tampered,
        );
        assert_eq!(v, Some(Verdict::Allow));

        // Nothing matches → fall through to the ML scan.
        let v = bloom_gate_sha(
            &lookup,
            ScanPolicy::Strict,
            "",
            "https://x/u.tgz",
            &sha_of(b"novel"),
        );
        assert_eq!(v, None);
    }

    #[test]
    fn hex32_is_lowercase_and_64_wide() {
        let mut d = [0u8; 32];
        d[1] = 0xff;
        d[31] = 0xab;
        let s = hex32(&d);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("00ff"));
        assert!(s.ends_with("ab"));
        assert!(s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
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
