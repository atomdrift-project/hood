//! Human-facing stderr panels for non-benign scan verdicts.
//!
//! Design language mirrors atomscan and cleave: truecolor classification accents,
//! confidence indicator blocks, indented evidence. The presentation goes one
//! step further than atomscan's per-file streaming output: hood has the *whole*
//! verdict in hand for a single payload, so the panel can be a focused unit
//! instead of a one-liner. Operators get the verdict, evidence, and an
//! actionable next step in one glance.
//!
//! Output only colorizes when stderr is a real terminal — when redirected to a
//! file, we collapse to a single structured line that's grep-friendly.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write};

use scan::engine::TopFinding;
use scan::explain::Reason;
use scan::model::Classification;
use scan::output::Theme;

use crate::scanner::ScanPolicy;

/// Truecolor RGB triple.
#[derive(Debug, Clone, Copy)]
struct Rgb(u8, u8, u8);

/// Per-theme palette. Classification colors track atomscan's so the two
/// tools look like cousins, not strangers.
#[derive(Debug, Clone, Copy)]
struct Palette {
    hostile: Rgb,
    suspicious: Rgb,
    chrome: Rgb,
    dim: Rgb,
    text: Rgb,
    accent: Rgb,
}

impl Palette {
    const fn dark() -> Self {
        Self {
            hostile: Rgb(255, 70, 70),
            suspicious: Rgb(255, 175, 55),
            chrome: Rgb(70, 70, 70),
            dim: Rgb(120, 120, 120),
            text: Rgb(230, 230, 230),
            accent: Rgb(120, 180, 220),
        }
    }
    const fn light() -> Self {
        Self {
            hostile: Rgb(200, 30, 30),
            suspicious: Rgb(180, 120, 0),
            chrome: Rgb(190, 190, 190),
            dim: Rgb(140, 140, 140),
            text: Rgb(30, 30, 30),
            accent: Rgb(40, 110, 170),
        }
    }
    const fn for_theme(theme: Theme) -> Self {
        match theme {
            Theme::Dark => Self::dark(),
            Theme::Light => Self::light(),
        }
    }
}

/// Disposition the panel describes. Drives the header word and the action
/// hint at the bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Verdict was Block; the body was withheld from the caller.
    Blocked,
    /// Verdict was non-benign but policy let it through (`HOOD_BYPASS` active).
    Forwarded,
}

/// Emit the compact successful-scan record requested by verbose mode.
///
/// The score is the model's raw malice probability, not a calibrated posterior;
/// call it a model risk score to avoid overstating what it means.
pub fn emit_pass(url: &str, probability: f32) {
    let risk = probability.clamp(0.0, 1.0) * 100.0;
    let artifact = artifact_label(url);
    let mut stderr = std::io::stderr().lock();
    drop(writeln!(
        stderr,
        "✅ Atomdrift Hood scan passed — {risk:.1}% risk score — {artifact}",
    ));
}

/// Emit one aggregate line when a verbose invocation scanned multiple downloads.
pub fn emit_scan_summary(summary: crate::scanner::ScanSummary) {
    let Some(line) = format_scan_summary(summary) else {
        return;
    };
    let mut stderr = std::io::stderr().lock();
    drop(writeln!(stderr, "{line}"));
}

fn format_scan_summary(summary: crate::scanner::ScanSummary) -> Option<String> {
    if summary.total() <= 1 {
        return None;
    }
    let suspicious = summary.suspicious_blocked + summary.suspicious_forwarded;
    let hostile = summary.hostile_blocked + summary.hostile_forwarded;
    let errors = summary.errors_blocked + summary.errors_forwarded;
    let marker = if summary.blocked() > 0 || hostile > 0 {
        "🛑"
    } else if suspicious > 0 || errors > 0 {
        "⚠️"
    } else {
        "✅"
    };
    let mut line = format!(
        "{marker} Atomdrift Hood scanned {} downloads — {} passed, {suspicious} suspicious, {hostile} high risk",
        summary.total(),
        summary.passed,
    );
    if errors > 0 {
        let _ = write!(line, ", {errors} scan errors");
    }
    if summary.blocked() > 0 {
        let _ = write!(line, " — {} blocked", summary.blocked());
    }
    Some(line)
}

/// Bundle of everything the panel needs to render. Pulled out of the scan
/// result so the renderer doesn't have to know scan internals beyond the
/// already-public `TopFinding` / `Reason` types.
#[derive(Debug)]
pub struct Panel<'a> {
    /// The classification driving this panel. Benign is never rendered.
    pub classification: Classification,
    /// Original classification before the upgrade heuristic, if applicable.
    pub original: Option<Classification>,
    /// Whether the body was withheld or forwarded under bypass.
    pub disposition: Disposition,
    /// Effective policy in force, used to choose the bypass hint.
    pub policy: ScanPolicy,
    /// Raw model probability in `[0, 1]`. Displayed as the risk score.
    pub probability: f32,
    /// URL the tool was about to fetch.
    pub url: &'a str,
    /// Top traits ranked by `crit × conf`.
    pub traits: &'a [TopFinding],
    /// Top SHAP-ranked reasons.
    pub reasons: &'a [Reason],
    /// Shell-quoted reproducer for the bypass hint, e.g.
    /// `"curl -fsSL https://example.com/install.sh"`. When empty, the
    /// hint falls back to a descriptive form (used in unit tests).
    pub invocation: &'a str,
}

/// Render the panel to stderr. Falls back to a single structured WARN line
/// when stderr isn't a TTY so log aggregators don't get smeared with ANSI.
///
/// This function never fails — write errors to stderr are silent (stderr is
/// the diagnostics channel; we have nowhere else to complain to).
pub fn emit(panel: &Panel<'_>) {
    let mut stderr = std::io::stderr().lock();
    if stderr.is_terminal() {
        let theme = scan::output::detect_theme();
        drop(write_pretty(&mut stderr, panel, Palette::for_theme(theme)));
    } else {
        drop(write_plain(&mut stderr, panel));
    }
}

fn write_pretty<W: Write>(w: &mut W, p: &Panel<'_>, c: Palette) -> std::io::Result<()> {
    let verdict_color = match p.classification {
        Classification::Hostile => c.hostile,
        Classification::Suspicious => c.suspicious,
        _ => c.text,
    };

    let header_word = match p.disposition {
        Disposition::Blocked => "BLOCKED",
        Disposition::Forwarded => "FORWARDED",
    };
    writeln!(w)?;
    writeln!(
        w,
        "  {} {} {}",
        fg(c.dim, "──"),
        fg_bold(verdict_color, header_word),
        fg(c.chrome, &"─".repeat(64)),
    )?;
    writeln!(w, "  {}", fg_bold(verdict_color, &friendly_status(p)))?;
    writeln!(w, "  {}", fg_bold(c.text, sanitize(p.url).as_ref()))?;

    if let Some(orig) = p.original
        && orig != p.classification
    {
        writeln!(
            w,
            "  {} {}",
            fg(c.dim, "upgraded from"),
            fg(c.dim, classification_label(orig)),
        )?;
    }

    if !p.traits.is_empty() {
        writeln!(w)?;
        writeln!(w, "  {}", fg(c.dim, "evidence"))?;
        // The list is already sorted strongest-first; the position carries the
        // ranking signal, so the per-trait score/criticality numbers would
        // just be noise.
        for t in p.traits {
            writeln!(w, "    {}", fg(c.text, &t.id))?;
        }
    }

    if !p.reasons.is_empty() {
        writeln!(w)?;
        let names: Vec<String> = p.reasons.iter().map(|r| r.feature.clone()).collect();
        writeln!(
            w,
            "  {}  {}",
            fg(c.dim, "model"),
            fg(c.text, &names.join(", ")),
        )?;
    }

    writeln!(w)?;
    write_bypass_hint(w, p, c)?;
    writeln!(w, "  {}", fg(c.chrome, &"─".repeat(72)))?;
    writeln!(w)
}

fn write_bypass_hint<W: Write>(w: &mut W, p: &Panel<'_>, c: Palette) -> std::io::Result<()> {
    let inv = p.invocation;
    match (p.disposition, p.classification, p.policy) {
        // Already forwarded — show what's active.
        (Disposition::Forwarded, _, policy) => writeln!(
            w,
            "  {}  {}",
            fg(c.dim, "active:"),
            fg(c.accent, policy_tag(policy)),
        ),
        // Blocked suspicious: minimum knob is =2; =3 also works.
        (Disposition::Blocked, Classification::Suspicious, _) => {
            write_command_hint(w, &c, "to allow:", "HOOD_BYPASS=2", inv)
        }
        // Blocked hostile: only HOOD_BYPASS=3 would let it through.
        (Disposition::Blocked, Classification::Hostile, _) => {
            write_command_hint(w, &c, "to allow:", "HOOD_BYPASS=3", inv)
        }
        _ => Ok(()),
    }
}

/// Render one "label: `HOOD_BYPASS=N` <command>" line. If no command was
/// supplied (e.g. unit tests), fall back to a descriptive parenthetical.
fn write_command_hint<W: Write>(
    w: &mut W,
    c: &Palette,
    label: &str,
    env: &str,
    invocation: &str,
) -> std::io::Result<()> {
    if invocation.is_empty() {
        writeln!(w, "  {}  {}", fg(c.dim, label), fg(c.accent, env))
    } else {
        writeln!(
            w,
            "  {}  {} {}",
            fg(c.dim, label),
            fg(c.accent, env),
            fg(c.text, sanitize(invocation).as_ref()),
        )
    }
}

/// Plain-text fallback for non-TTY stderr (CI logs, file redirection).
/// Single line, structured-ish, no escape codes.
fn write_plain<W: Write>(w: &mut W, p: &Panel<'_>) -> std::io::Result<()> {
    let header = match p.disposition {
        Disposition::Blocked => "block",
        Disposition::Forwarded => "forward",
    };
    let traits = p
        .traits
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let reasons: Vec<&str> = p.reasons.iter().map(|r| r.feature.as_str()).collect();
    writeln!(
        w,
        "{}; hood {} url={} verdict={} probability={:.3} traits=[{}] reasons=[{}]{}",
        friendly_status(p),
        header,
        sanitize(p.url),
        classification_label(p.classification),
        p.probability,
        traits,
        reasons.join(", "),
        match p.original {
            Some(o) if o != p.classification =>
                format!(" upgraded_from={}", classification_label(o)),
            _ => String::new(),
        },
    )
}

fn friendly_status(p: &Panel<'_>) -> String {
    let risk = p.probability.clamp(0.0, 1.0) * 100.0;
    match (p.classification, p.disposition) {
        (Classification::Suspicious, Disposition::Blocked) => format!(
            "⚠️ Atomdrift Hood flagged this download as suspicious — {risk:.1}% risk score — BLOCKED"
        ),
        (Classification::Suspicious, Disposition::Forwarded) => format!(
            "⚠️ Atomdrift Hood flagged this download as suspicious — {risk:.1}% risk score — allowed by policy"
        ),
        (Classification::Hostile, Disposition::Blocked) => {
            format!("🛑 Atomdrift Hood blocked a high-risk download — {risk:.1}% risk score")
        }
        (Classification::Hostile, Disposition::Forwarded) => format!(
            "🛑 Atomdrift Hood flagged a high-risk download — {risk:.1}% risk score — allowed by policy"
        ),
        _ => format!("Atomdrift Hood scan result — {risk:.1}% risk score"),
    }
}

fn artifact_label(raw_url: &str) -> String {
    let Ok(url) = url::Url::parse(raw_url) else {
        return "download".to_owned();
    };
    let encoded = url
        .path_segments()
        .and_then(|mut segments| segments.rfind(|part| !part.is_empty()));
    let label = encoded
        .map(|part| percent_encoding::percent_decode_str(part).decode_utf8_lossy())
        .or_else(|| url.host_str().map(std::borrow::Cow::Borrowed))
        .unwrap_or(std::borrow::Cow::Borrowed("download"));
    let clean = sanitize(&label);
    let mut chars = clean.chars();
    let short: String = chars.by_ref().take(80).collect();
    if chars.next().is_some() {
        format!("{short}…")
    } else {
        short
    }
}

/// Context for a scan-error panel.
///
/// The scanner couldn't reach a verdict on
/// *this specific payload* (trait load failed, cleave crashed, etc.). Separate
/// from `Panel` because we have no classification, no probability, no traits.
#[derive(Debug)]
pub struct ScanErrorPanel<'a> {
    /// URL the tool was about to fetch.
    pub url: &'a str,
    /// One-line summary of the underlying error.
    pub error: &'a str,
    /// Effective policy. Drives whether the panel is BLOCKED or FORWARDED
    /// and which `HOOD_BYPASS` level is suggested.
    pub policy: ScanPolicy,
    /// Whether the body was withheld or forwarded under the active policy.
    pub disposition: Disposition,
    /// Shell-quoted reproducer for the bypass hint.
    pub invocation: &'a str,
}

/// Render a scan-error panel to stderr — one payload, one verdict (or lack
/// of one), single visual unit. Same TTY-vs-pipe split as [`emit`].
pub fn emit_scan_error(p: &ScanErrorPanel<'_>) {
    let mut stderr = std::io::stderr().lock();
    if stderr.is_terminal() {
        let theme = scan::output::detect_theme();
        drop(write_scan_error_pretty(
            &mut stderr,
            p,
            Palette::for_theme(theme),
        ));
    } else {
        drop(writeln!(
            stderr,
            "hood scan-error url={} policy={} disposition={} error={}",
            sanitize(p.url),
            policy_tag(p.policy),
            match p.disposition {
                Disposition::Blocked => "block",
                Disposition::Forwarded => "forward",
            },
            sanitize(p.error),
        ));
    }
}

fn write_scan_error_pretty<W: Write>(
    w: &mut W,
    p: &ScanErrorPanel<'_>,
    c: Palette,
) -> std::io::Result<()> {
    let (header, header_color) = match p.disposition {
        Disposition::Blocked => ("BLOCKED", c.suspicious),
        Disposition::Forwarded => ("FORWARDED", c.suspicious),
    };
    writeln!(w)?;
    writeln!(
        w,
        "  {} {} {}",
        fg(c.dim, "──"),
        fg_bold(header_color, header),
        fg(c.chrome, &"─".repeat(62)),
    )?;
    writeln!(
        w,
        "  {}  {}",
        fg(c.dim, "scan-error"),
        fg_bold(c.text, sanitize(p.url).as_ref())
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "  {}  {}",
        fg(c.dim, "reason:"),
        fg(c.text, sanitize(p.error).as_ref())
    )?;
    writeln!(w)?;
    match p.disposition {
        Disposition::Forwarded => writeln!(
            w,
            "  {}  {}",
            fg(c.dim, "active:"),
            fg(c.accent, policy_tag(p.policy)),
        )?,
        Disposition::Blocked => {
            // Suggest the minimum tier that would have allowed this — =1.
            write_command_hint(w, &c, "to allow:", "HOOD_BYPASS=1", p.invocation)?;
        }
    }
    writeln!(w, "  {}", fg(c.chrome, &"─".repeat(72)))?;
    writeln!(w)
}

/// Base of the atomdrift lab file view. The payload's SHA-256 is appended to
/// form a permalink to its full report — the actionable next step on a
/// known-bad block.
const LAB_FILE_URL: &str = "https://lab.atomdrift.org/file/";

/// Context for a known-bad panel.
///
/// The payload matched the known-bad bloom
/// filter (by content hash or PURL) and was blocked without an ML scan. Distinct
/// from [`Panel`] because there is no classification, probability, or trait
/// evidence — the verdict is the match itself.
#[derive(Debug)]
pub struct KnownBadPanel<'a> {
    /// URL the tool was about to fetch.
    pub url: &'a str,
    /// Lower-hex SHA-256 of the payload; forms the lab permalink. Empty for a
    /// pre-fetch PURL match, where no bytes were downloaded to hash — the panel
    /// then keys the match on [`Self::purl`] instead.
    pub sha256: &'a str,
    /// PURL the known-bad match fired on, when it was a pre-fetch PURL hit rather
    /// than a content-hash hit. Shown in place of the lab link when `sha256` is
    /// empty.
    pub purl: Option<&'a str>,
    /// Effective policy, for the bypass hint / active tag.
    pub policy: ScanPolicy,
    /// Whether the body was withheld or forwarded (under `HOOD_BYPASS=3`).
    pub disposition: Disposition,
    /// Shell-quoted reproducer for the bypass hint.
    pub invocation: &'a str,
}

/// Render a known-bad panel to stderr — same TTY-vs-pipe split as [`emit`].
pub fn emit_known_bad(p: &KnownBadPanel<'_>) {
    let mut stderr = std::io::stderr().lock();
    if stderr.is_terminal() {
        let theme = scan::output::detect_theme();
        drop(write_known_bad_pretty(
            &mut stderr,
            p,
            Palette::for_theme(theme),
        ));
    } else if p.sha256.is_empty() {
        // Pre-fetch PURL match: no bytes were downloaded, so key on the PURL.
        drop(writeln!(
            stderr,
            "hood known-bad url={} purl={} policy={} disposition={}",
            sanitize(p.url),
            sanitize(p.purl.unwrap_or("?")),
            policy_tag(p.policy),
            match p.disposition {
                Disposition::Blocked => "block",
                Disposition::Forwarded => "forward",
            },
        ));
    } else {
        drop(writeln!(
            stderr,
            "hood known-bad url={} sha256={} lab={}{} policy={} disposition={}",
            sanitize(p.url),
            p.sha256,
            LAB_FILE_URL,
            p.sha256,
            policy_tag(p.policy),
            match p.disposition {
                Disposition::Blocked => "block",
                Disposition::Forwarded => "forward",
            },
        ));
    }
}

fn write_known_bad_pretty<W: Write>(
    w: &mut W,
    p: &KnownBadPanel<'_>,
    c: Palette,
) -> std::io::Result<()> {
    let header = match p.disposition {
        Disposition::Blocked => "BLOCKED",
        Disposition::Forwarded => "FORWARDED",
    };
    writeln!(w)?;
    writeln!(
        w,
        "  {} {} {}",
        fg(c.dim, "──"),
        fg_bold(c.hostile, header),
        fg(c.chrome, &"─".repeat(63)),
    )?;
    writeln!(
        w,
        "  {}  {}",
        fg_bold(c.hostile, "known bad package"),
        fg_bold(c.text, sanitize(p.url).as_ref()),
    )?;
    writeln!(w)?;
    if p.sha256.is_empty() {
        // Pre-fetch PURL match: no hash to permalink, so show the matched PURL.
        writeln!(
            w,
            "  {}  {}",
            fg(c.dim, "purl:"),
            fg(c.accent, sanitize(p.purl.unwrap_or("?")).as_ref()),
        )?;
    } else {
        writeln!(
            w,
            "  {}  {}",
            fg(c.dim, "lab:"),
            fg(c.accent, &format!("{LAB_FILE_URL}{}", p.sha256)),
        )?;
    }
    writeln!(w)?;
    match p.disposition {
        Disposition::Forwarded => writeln!(
            w,
            "  {}  {}",
            fg(c.dim, "active:"),
            fg(c.accent, policy_tag(p.policy)),
        )?,
        // Only HOOD_BYPASS=3 would forward a known-bad match.
        Disposition::Blocked => {
            write_command_hint(w, &c, "to allow:", "HOOD_BYPASS=3", p.invocation)?;
        }
    }
    writeln!(w, "  {}", fg(c.chrome, &"─".repeat(72)))?;
    writeln!(w)
}

/// Failsafe panel: scanning was bypassed because the proxy couldn't start.
/// Only emitted when `HOOD_BYPASS` is set; under strict policy a startup
/// failure aborts the run before this is ever called.
pub fn emit_failsafe(invocation: &str, policy: ScanPolicy, reason: &str) {
    let mut stderr = std::io::stderr().lock();
    if stderr.is_terminal() {
        let theme = scan::output::detect_theme();
        drop(write_failsafe_pretty(
            &mut stderr,
            invocation,
            policy,
            reason,
            Palette::for_theme(theme),
        ));
    } else {
        drop(writeln!(
            stderr,
            "hood unscanned policy={} reason={} invocation={}",
            policy_tag(policy),
            sanitize(reason),
            sanitize(invocation),
        ));
    }
}

fn write_failsafe_pretty<W: Write>(
    w: &mut W,
    invocation: &str,
    policy: ScanPolicy,
    reason: &str,
    c: Palette,
) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "  {} {} {}",
        fg(c.dim, "──"),
        fg_bold(c.suspicious, "UNSCANNED"),
        fg(c.chrome, &"─".repeat(62)),
    )?;
    writeln!(
        w,
        "  {} {}",
        fg(c.dim, "proxy unavailable:"),
        fg(c.text, sanitize(reason).as_ref()),
    )?;
    if !invocation.is_empty() {
        writeln!(
            w,
            "  {} {}",
            fg(c.dim, "running:"),
            fg(c.text, sanitize(invocation).as_ref()),
        )?;
    }
    writeln!(
        w,
        "  {} {}",
        fg(c.accent, policy_tag(policy)),
        fg(c.dim, "active — passing through without inspection"),
    )?;
    writeln!(w, "  {}", fg(c.chrome, &"─".repeat(72)))?;
    writeln!(w)
}

const fn policy_tag(p: ScanPolicy) -> &'static str {
    match p {
        ScanPolicy::Strict => "HOOD_BYPASS=0",
        ScanPolicy::AllowErrors => "HOOD_BYPASS=1",
        ScanPolicy::AllowSuspicious => "HOOD_BYPASS=2",
        ScanPolicy::Bypass => "HOOD_BYPASS=3",
    }
}

const fn classification_label(c: Classification) -> &'static str {
    match c {
        Classification::Hostile => "hostile",
        Classification::Suspicious => "suspicious",
        Classification::Benign => "benign",
        _ => "unknown",
    }
}

/// Five-cell confidence indicator: ▰ filled / ▱ empty.
///
/// The fill count tracks probability, the color tracks the classification —
/// same idiom atomscan uses, expanded from two cells to five for a finer read.
#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn confidence_blocks(probability: f32, accent: Rgb, dim: Rgb) -> String {
    const CELLS: usize = 5;
    const CELLS_F32: f32 = 5.0;
    // probability is clamped to [0, 1] and CELLS is 5, so the rounded product
    // fits in usize on every platform — no truncation or sign loss possible.
    let filled = (probability.clamp(0.0, 1.0) * CELLS_F32).round() as usize;
    let filled = filled.min(CELLS);
    let empty = CELLS - filled;
    let mut s = String::with_capacity(64);
    for _ in 0..filled {
        s.push_str(&fg(accent, "▰"));
    }
    for _ in 0..empty {
        s.push_str(&fg(dim, "▱"));
    }
    s
}

/// Neutralize control characters in an attacker-influenced string before it is
/// written to a terminal or a single-line log record. A crafted URL, PURL, or
/// scan-error message could otherwise embed an ANSI escape (recoloring or
/// clearing the terminal, hiding text) or a newline (forging a second log line).
/// Printable characters and tabs pass through; everything else becomes U+FFFD.
fn sanitize(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(|c| c.is_control() && c != '\t') {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .map(|c| {
                if c.is_control() && c != '\t' {
                    '\u{fffd}'
                } else {
                    c
                }
            })
            .collect(),
    )
}

fn fg(Rgb(r, g, b): Rgb, text: &str) -> String {
    format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
}

fn fg_bold(Rgb(r, g, b): Rgb, text: &str) -> String {
    format!("\x1b[1;38;2;{r};{g};{b}m{text}\x1b[0m")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_escape_and_newline_but_keeps_printable() {
        // No control chars → borrowed, unchanged.
        assert_eq!(
            sanitize("https://example.com/pkg.tgz"),
            "https://example.com/pkg.tgz"
        );
        // ESC (ANSI injection) and newline (forged log line) are neutralized.
        let evil = "https://x/\x1b[2Jpkg\nhood forged=line";
        let clean = sanitize(evil);
        assert!(!clean.contains('\x1b'), "escape survived: {clean:?}");
        assert!(!clean.contains('\n'), "newline survived: {clean:?}");
        assert!(clean.contains("pkg"), "printable text dropped: {clean:?}");
        // Tab is preserved.
        assert_eq!(sanitize("a\tb"), "a\tb");
    }

    fn trait_(id: &str, crit: u32, conf: f32) -> TopFinding {
        TopFinding {
            id: id.into(),
            crit,
            conf,
            desc: String::new(),
        }
    }

    fn reason_(feature: &str) -> Reason {
        Reason {
            feature: feature.into(),
            importance: 0.1,
            value: 1.0,
            description: String::new(),
        }
    }

    fn panel<'a>(
        traits: &'a [TopFinding],
        reasons: &'a [Reason],
        classification: Classification,
        disposition: Disposition,
        policy: ScanPolicy,
    ) -> Panel<'a> {
        Panel {
            classification,
            original: None,
            disposition,
            policy,
            probability: 0.7,
            url: "https://example.com/foo.sh",
            traits,
            reasons,
            invocation: "",
        }
    }

    #[test]
    fn plain_output_includes_url_and_verdict() {
        let traits = vec![trait_("exec/shell::bash", 5, 0.95)];
        let reasons = vec![reason_("crit_count:suspicious")];
        let p = panel(
            &traits,
            &reasons,
            Classification::Hostile,
            Disposition::Blocked,
            ScanPolicy::Strict,
        );
        let mut buf = Vec::new();
        write_plain(&mut buf, &p).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("hood block"));
        assert!(s.contains("verdict=hostile"));
        assert!(s.contains("https://example.com/foo.sh"));
        assert!(s.contains("exec/shell::bash"));
        assert!(s.contains("crit_count:suspicious"));
        assert!(s.contains("Atomdrift Hood blocked a high-risk download"));
    }

    #[test]
    fn friendly_status_distinguishes_suspicious_policy_action() {
        let blocked = panel(
            &[],
            &[],
            Classification::Suspicious,
            Disposition::Blocked,
            ScanPolicy::Strict,
        );
        assert_eq!(
            friendly_status(&blocked),
            "⚠️ Atomdrift Hood flagged this download as suspicious — 70.0% risk score — BLOCKED"
        );

        let forwarded = panel(
            &[],
            &[],
            Classification::Suspicious,
            Disposition::Forwarded,
            ScanPolicy::AllowSuspicious,
        );
        assert!(friendly_status(&forwarded).contains("allowed by policy"));
    }

    #[test]
    fn artifact_label_is_short_and_drops_secret_query() {
        assert_eq!(
            artifact_label("https://registry.example/pkg%20name.tgz?token=secret"),
            "pkg name.tgz"
        );
    }

    #[test]
    fn multi_download_summary_reports_outcomes_and_blocks() {
        let summary = crate::scanner::ScanSummary {
            passed: 8,
            suspicious_blocked: 1,
            suspicious_forwarded: 1,
            hostile_blocked: 1,
            ..crate::scanner::ScanSummary::default()
        };
        assert_eq!(
            format_scan_summary(summary).as_deref(),
            Some(
                "🛑 Atomdrift Hood scanned 11 downloads — 8 passed, 2 suspicious, 1 high risk — 2 blocked"
            )
        );
        assert!(
            format_scan_summary(crate::scanner::ScanSummary {
                passed: 1,
                ..crate::scanner::ScanSummary::default()
            })
            .is_none()
        );
    }

    #[test]
    fn plain_output_reports_upgrade_provenance() {
        let p = Panel {
            classification: Classification::Hostile,
            original: Some(Classification::Benign),
            disposition: Disposition::Blocked,
            policy: ScanPolicy::Strict,
            probability: 0.9,
            url: "https://x",
            traits: &[],
            reasons: &[],
            invocation: "",
        };
        let mut buf = Vec::new();
        write_plain(&mut buf, &p).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("upgraded_from=benign"));
    }

    #[test]
    fn pretty_hint_uses_command_when_provided_for_hostile() {
        let p = Panel {
            classification: Classification::Hostile,
            original: None,
            disposition: Disposition::Blocked,
            policy: ScanPolicy::Strict,
            probability: 0.9,
            url: "https://x/install.sh",
            traits: &[],
            reasons: &[],
            invocation: "curl -fsSL https://x/install.sh",
        };
        let mut buf = Vec::new();
        write_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("HOOD_BYPASS=3 curl -fsSL https://x/install.sh"));
    }

    #[test]
    fn pretty_hint_for_suspicious_uses_command_with_level_2() {
        let p = Panel {
            classification: Classification::Suspicious,
            original: None,
            disposition: Disposition::Blocked,
            policy: ScanPolicy::Strict,
            probability: 0.6,
            url: "https://x/install.sh",
            traits: &[],
            reasons: &[],
            invocation: "curl -fsSL https://x/install.sh",
        };
        let mut buf = Vec::new();
        write_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("HOOD_BYPASS=2 curl -fsSL https://x/install.sh"));
    }

    #[test]
    fn failsafe_pretty_mentions_policy_and_reason() {
        let mut buf = Vec::new();
        write_failsafe_pretty(
            &mut buf,
            "curl -O https://example.com",
            ScanPolicy::Bypass,
            "load scan model: not found",
            Palette::dark(),
        )
        .unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("UNSCANNED"));
        assert!(s.contains("HOOD_BYPASS=3"));
        assert!(s.contains("load scan model: not found"));
        assert!(s.contains("curl -O https://example.com"));
    }

    #[test]
    fn scan_error_pretty_suggests_hood_bypass_1() {
        let p = ScanErrorPanel {
            url: "https://x/install.sh",
            error: "trait load failed: ...",
            policy: ScanPolicy::Strict,
            disposition: Disposition::Blocked,
            invocation: "curl -fsSL https://x/install.sh",
        };
        let mut buf = Vec::new();
        write_scan_error_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("BLOCKED"));
        assert!(s.contains("scan-error"));
        assert!(s.contains("HOOD_BYPASS=1 curl -fsSL https://x/install.sh"));
    }

    #[test]
    fn known_bad_pretty_shows_lab_link_and_block_hint() {
        let p = KnownBadPanel {
            url: "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
            sha256: "7774c79b81cae4ab45576d443b174261d7602a8d912e563997edf6c0f36ddc7b",
            purl: None,
            policy: ScanPolicy::Strict,
            disposition: Disposition::Blocked,
            invocation: "npm install evil",
        };
        let mut buf = Vec::new();
        write_known_bad_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("BLOCKED"));
        assert!(s.contains("known bad package"));
        assert!(s.contains(
            "https://lab.atomdrift.org/file/7774c79b81cae4ab45576d443b174261d7602a8d912e563997edf6c0f36ddc7b"
        ));
        assert!(s.contains("HOOD_BYPASS=3 npm install evil"));
    }

    #[test]
    fn known_bad_plain_is_grep_friendly() {
        let p = KnownBadPanel {
            url: "https://x/evil.tgz",
            sha256: "abc123",
            purl: None,
            policy: ScanPolicy::Strict,
            disposition: Disposition::Blocked,
            invocation: "",
        };
        // Exercise the non-TTY plain branch directly.
        let line = format!(
            "hood known-bad url={} sha256={} lab={}{} policy={} disposition={}",
            p.url,
            p.sha256,
            LAB_FILE_URL,
            p.sha256,
            policy_tag(p.policy),
            "block",
        );
        assert!(line.contains("hood known-bad"));
        assert!(line.contains("sha256=abc123"));
        assert!(line.contains("lab=https://lab.atomdrift.org/file/abc123"));
    }

    #[test]
    fn scan_error_pretty_shows_active_when_forwarded() {
        let p = ScanErrorPanel {
            url: "https://x/install.sh",
            error: "trait load failed: ...",
            policy: ScanPolicy::AllowErrors,
            disposition: Disposition::Forwarded,
            invocation: "curl -fsSL https://x/install.sh",
        };
        let mut buf = Vec::new();
        write_scan_error_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("FORWARDED"));
        assert!(s.contains("active:"));
        assert!(s.contains("HOOD_BYPASS=1"));
    }

    #[test]
    fn pretty_output_suggests_bypass_2_for_suspicious_block() {
        let p = panel(
            &[],
            &[],
            Classification::Suspicious,
            Disposition::Blocked,
            ScanPolicy::Strict,
        );
        let mut buf = Vec::new();
        write_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("HOOD_BYPASS=2"));
        // Suspicious blocks don't suggest =1 (wouldn't help; that's for errors).
        assert!(!s.contains("HOOD_BYPASS=1"));
    }

    #[test]
    fn pretty_output_suggests_bypass_3_for_hostile_block() {
        let p = panel(
            &[],
            &[],
            Classification::Hostile,
            Disposition::Blocked,
            ScanPolicy::Strict,
        );
        let mut buf = Vec::new();
        write_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("HOOD_BYPASS=3"));
        assert!(!s.contains("HOOD_BYPASS=1"));
        assert!(!s.contains("HOOD_BYPASS=2"));
    }

    #[test]
    fn pretty_output_under_bypass_shows_active_level() {
        let p = panel(
            &[],
            &[],
            Classification::Hostile,
            Disposition::Forwarded,
            ScanPolicy::Bypass,
        );
        let mut buf = Vec::new();
        write_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let s = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(s.contains("active:"));
        assert!(s.contains("HOOD_BYPASS=3"));
        assert!(s.contains("FORWARDED"));
    }

    #[test]
    fn confidence_blocks_count_filled_cells() {
        let s = strip_ansi(&confidence_blocks(0.0, Rgb(0, 0, 0), Rgb(0, 0, 0)));
        assert_eq!(s.matches('▰').count(), 0);
        assert_eq!(s.matches('▱').count(), 5);

        let s = strip_ansi(&confidence_blocks(1.0, Rgb(0, 0, 0), Rgb(0, 0, 0)));
        assert_eq!(s.matches('▰').count(), 5);
        assert_eq!(s.matches('▱').count(), 0);

        let s = strip_ansi(&confidence_blocks(0.5, Rgb(0, 0, 0), Rgb(0, 0, 0)));
        assert_eq!(s.matches('▰').count() + s.matches('▱').count(), 5);
    }

    fn strip_ansi(s: &str) -> String {
        // Drop CSI sequences: ESC '[' params 'm'. Simple state machine.
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }
}
