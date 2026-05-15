//! In-process payload scanner.
//!
//! `hood` does not shell out to `litmus`. Instead it loads litmus's model,
//! feature extractor, and SHAP table once at startup and reuses them for every
//! intercepted response. cleave's SHA256-keyed analysis cache short-circuits
//! repeated identical payloads (very common on `npm install`-style workloads).
//!
//! Two backends ship today:
//!
//! - [`AllowAll`] — short-circuits to [`Verdict::Allow`]. Used in tests and
//!   when `--no-scan` is requested.
//! - [`LitmusScanner`] — production backend. Calls
//!   [`litmus::scan::scan_bytes`] with bytes drawn directly from the buffered
//!   HTTP response.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use litmus::model::Classification;
use litmus::scan::ScanResult;
use litmus::Analyzer;

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
    /// The URL the tool originally requested. Used as the filename hint and
    /// in log messages.
    pub url: String,
    /// Response Content-Type, if the upstream provided one.
    pub content_type: Option<String>,
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

/// Policy for how `suspicious` (model-flagged but below the hostile threshold)
/// payloads should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SuspiciousPolicy {
    /// Block. Default — fail-closed.
    #[default]
    Block,
    /// Forward, but emit a warning to the operator.
    Warn,
}

/// In-process litmus scanner.
///
/// Construct with [`LitmusScanner::load`], which loads model artifacts and
/// warms cleave's shared resources via [`Analyzer::load`]. The struct is
/// cheap to clone (everything is held behind `Arc`) and is `Send + Sync` so
/// the proxy can share it across all concurrent connections.
#[derive(Clone)]
pub struct LitmusScanner {
    inner: Arc<Inner>,
}

struct Inner {
    analyzer: Analyzer,
    suspicious: SuspiciousPolicy,
}

impl std::fmt::Debug for LitmusScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LitmusScanner")
            .field("suspicious", &self.inner.suspicious)
            .field("model_dir", &self.inner.analyzer.model_dir())
            .finish()
    }
}

impl LitmusScanner {
    /// Load model artifacts from disk and prepare a ready-to-use scanner.
    ///
    /// `model_dir` is the same directory passed to `litmus scan --model-dir`;
    /// when `None`, the litmus models_repo resolver is used (auto-clone on
    /// first call).
    pub fn load(model_dir: Option<PathBuf>, suspicious: SuspiciousPolicy) -> Result<Self> {
        let model_dir = match model_dir {
            Some(d) => d,
            None => litmus::models_repo::model_dir()
                .map_err(|e| anyhow::anyhow!("resolve litmus model dir: {e}"))?,
        };
        let analyzer = Analyzer::load(model_dir).context("load litmus analyzer")?;
        Ok(Self {
            inner: Arc::new(Inner {
                analyzer,
                suspicious,
            }),
        })
    }

    fn verdict_for(&self, result: &ScanResult, url: &str) -> Verdict {
        match result.classification {
            Classification::Benign => Verdict::Allow,
            Classification::Hostile => Verdict::Block(BlockReason::Hostile),
            Classification::Suspicious => match self.inner.suspicious {
                SuspiciousPolicy::Block => Verdict::Block(BlockReason::Suspicious),
                SuspiciousPolicy::Warn => {
                    tracing::warn!(
                        url,
                        probability = result.probability,
                        "forwarding suspicious payload (SuspiciousPolicy::Warn)",
                    );
                    Verdict::Allow
                }
            },
            // litmus marks Classification non_exhaustive so new verdicts (e.g.
            // "unknown") can land without breaking downstream code. Treat any
            // future variant as a fail-closed scan error until we update.
            other => Verdict::Block(BlockReason::ScanError(format!(
                "unknown classification: {other:?}",
            ))),
        }
    }
}

#[async_trait::async_trait]
impl Scanner for LitmusScanner {
    async fn scan(&self, req: ScanRequest) -> Result<Verdict> {
        // litmus::scan::scan_bytes is CPU-bound (XGBoost + cleave). Run it on
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
                tracing::debug!(
                    url = req.url,
                    classification = ?r.classification,
                    probability = r.probability,
                    "scan complete",
                );
                Ok(self.verdict_for(&r, &req.url))
            }
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!(url = req.url, error = %msg, "scan failed; fail-closed");
                Ok(Verdict::Block(BlockReason::ScanError(msg)))
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
                content_type: None,
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
}
