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
use scan::engine::ScanResult;
use scan::model::Classification;
use scan::Analyzer;

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

/// A scanner backend.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync + std::fmt::Debug {
    /// Inspect a payload and return a verdict.
    async fn scan(&self, req: ScanRequest) -> Result<Verdict>;
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
            }),
        })
    }

    fn verdict_for(&self, result: &ScanResult) -> Verdict {
        verdict_from(result.classification, self.inner.policy)
    }
}

/// Apply [`ScanPolicy`] to a classification. Pulled out of [`LitmusScanner`]
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
        // Analyzer::scan_bytes is CPU-bound (XGBoost + cleave). Run it on
        // the blocking pool so the proxy's async reactor isn't stalled by a
        // multi-megabyte binary classification.
        let inner = Arc::clone(&self.inner);
        let url = req.url.clone();
        let body = req.body;
        let result = tokio::task::spawn_blocking(move || inner.analyzer.scan_bytes(body, &url))
            .await
            .context("scan task join")?;

        match result {
            Ok(r) => {
                let verdict = self.verdict_for(&r);
                if !matches!(r.classification, Classification::Benign) {
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
                        url: &req.url,
                        traits: traits_slice,
                        reasons: reasons_slice,
                        invocation: &self.inner.invocation,
                    });
                } else {
                    tracing::debug!(
                        url = req.url,
                        probability = r.probability,
                        "scan clean",
                    );
                }
                Ok(verdict)
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
                    url: &req.url,
                    error: &msg,
                    policy,
                    disposition,
                    invocation: &self.inner.invocation,
                });
                if allowed {
                    Ok(Verdict::Allow)
                } else {
                    Ok(Verdict::Block(BlockReason::ScanError(msg)))
                }
            }
        }
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
        assert_eq!(BlockReason::Hostile.label(), "hostile");
        assert_eq!(BlockReason::Suspicious.label(), "suspicious");
        assert_eq!(
            BlockReason::ScanError("boom".into()).label(),
            "scan-error"
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
