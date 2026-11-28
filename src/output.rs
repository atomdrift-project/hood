//! Human-facing stderr panels for non-benign scan verdicts.
//!
//! Design language mirrors atomscan and cleave: truecolor classification
//! accents and indented evidence. hood has the *whole* verdict in hand for a
//! single payload, so a panel is a focused unit rather than a one-liner:
//! verdict, evidence, and an actionable next step in one glance.
//!
//! Output only colorizes when stderr is a real terminal — when redirected to a
//! file, we collapse to a single structured line that's grep-friendly.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, StderrLock, Write};

use scan::engine::{Reason, TopFinding};
use scan::model::{Classification, Level};
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
}

impl From<Theme> for Palette {
    fn from(theme: Theme) -> Self {
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

impl Disposition {
    /// Lowercase verb for single-line log records.
    const fn verb(self) -> &'static str {
        match self {
            Self::Blocked => "block",
            Self::Forwarded => "forward",
        }
    }

    /// Uppercase panel header word.
    const fn header(self) -> &'static str {
        match self {
            Self::Blocked => "BLOCKED",
            Self::Forwarded => "FORWARDED",
        }
    }
}

/// Write to stderr: on a terminal, `pretty` renders a panel's body and
/// names its heading, and the panel is framed to fit; otherwise `plain`
/// writes one line without escapes, so log aggregators are not smeared with
/// ANSI. Write errors are dropped: stderr is the diagnostics channel, with
/// nowhere else to complain.
fn to_stderr(
    pretty: impl FnOnce(&mut Vec<u8>, Palette) -> io::Result<Heading>,
    plain: impl FnOnce(&mut StderrLock<'static>) -> io::Result<()>,
) {
    let mut stderr = io::stderr().lock();
    let written = if stderr.is_terminal() {
        let c = Palette::from(scan::output::detect_theme());
        let mut body = Vec::new();
        pretty(&mut body, c)
            .and_then(|heading| write_framed(&mut stderr, c, heading, &body, columns()))
    } else {
        plain(&mut stderr)
    };
    drop(written);
}

/// The width of the terminal stderr writes to. Not stdout's: under
/// `curl … | sh` that is a pipe.
fn columns() -> usize {
    terminal_size::terminal_size_of(io::stderr()).map_or(100, |(width, _)| usize::from(width.0))
}

/// The narrowest a panel's rules are drawn, in columns after the indent.
const MIN_PANEL_WIDTH: usize = 72;

/// The widest they are drawn: room for every line hood writes itself, such
/// as a report link. Past it, one long command would stretch the frame far
/// beyond the text it holds; the command runs past the rule instead.
const MAX_PANEL_WIDTH: usize = 100;

/// Every panel line's left indent.
const INDENT: usize = 2;

/// Who is speaking, named in every panel's opening rule: the panel lands in
/// the middle of another tool's output.
const BRAND: &str = "Atomdrift Hood";

/// The state word of a panel's opening rule, and its color.
#[derive(Debug, Clone, Copy)]
struct Heading {
    word: &'static str,
    color: Rgb,
}

/// `body` between rules sized to it: as wide as its longest line, within
/// [`MIN_PANEL_WIDTH`] and [`MAX_PANEL_WIDTH`], and never past the terminal's
/// last column but one. A URL or command longer than that runs on; it is
/// never broken, so it still copies whole.
fn write_framed<W: Write>(
    w: &mut W,
    c: Palette,
    heading: Heading,
    body: &[u8],
    columns: usize,
) -> io::Result<()> {
    let longest = String::from_utf8_lossy(body)
        .lines()
        .map(|line| visible_width(line).saturating_sub(INDENT))
        .max()
        .unwrap_or(0);
    let width = longest
        .clamp(MIN_PANEL_WIDTH, MAX_PANEL_WIDTH)
        .min(columns.saturating_sub(INDENT + 1));
    // "── " + brand + " · " + word + " ", then rule to the panel's edge.
    let used = 3 + BRAND.chars().count() + 3 + heading.word.chars().count() + 1;
    writeln!(w)?;
    writeln!(
        w,
        "  {} {} {} {} {}",
        fg(c.chrome, "──"),
        fg(c.dim, BRAND),
        fg(c.chrome, "·"),
        fg_bold(heading.color, heading.word),
        fg(c.chrome, &"─".repeat(width.saturating_sub(used))),
    )?;
    w.write_all(body)?;
    writeln!(w, "  {}", fg(c.chrome, &"─".repeat(width)))?;
    writeln!(w)
}

/// Terminal cells a rendered line takes: its characters once escape
/// sequences are dropped, with the one emoji panels use, `⚡`, two cells.
fn visible_width(line: &str) -> usize {
    let mut width = 0;
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\x1b' => {
                // A color sequence, `ESC [ … m`: skip through its final byte.
                for ch in chars.by_ref() {
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            '⚡' => width += 2,
            _ => width += 1,
        }
    }
    width
}

/// Emit the compact successful-scan record requested by verbose mode: with
/// the local model's risk score, or `None` for a pass Beamline vouched for.
///
/// The score is the model's raw malice probability, not a calibrated posterior;
/// call it a model risk score to avoid overstating what it means.
pub fn emit_pass(url: &str, probability: Option<f32>) {
    let artifact = artifact_label(url);
    let basis = probability.map_or_else(
        || "Beamline".to_owned(),
        |p| format!("{:.1}% risk score", p.clamp(0.0, 1.0) * 100.0),
    );
    let mut stderr = std::io::stderr().lock();
    drop(writeln!(
        stderr,
        "✅ Atomdrift Hood scan passed — {basis} — {artifact}",
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

/// Public report page for a payload, keyed by its lower-hex SHA-256.
const REPORT_URL: &str = "https://sha256.is/";

/// Most evidence lines a panel shows.
const MAX_EVIDENCE: usize = 3;

/// What reached a verdict panel's classification.
#[derive(Debug)]
pub(crate) enum Basis<'a> {
    /// Local static analysis and ML.
    Local {
        /// Raw model probability in `[0, 1]`, shown as the risk score.
        probability: f32,
        /// The strictest false-positive level the bytes are flagged hostile
        /// at; hostile at or below hood's L25, suspicious above it.
        level: Level,
        /// Top traits, strongest first.
        traits: &'a [TopFinding],
        /// Top SHAP-ranked model features.
        reasons: &'a [Reason],
    },
    /// Beamline's verdict on these exact bytes.
    Beamline,
    /// A match in the known-bad Bloom filter.
    KnownBad,
}

/// What the local Bloom filters' outside claims say of a payload they did
/// not settle: threat feeds report it, but nothing of Atomdrift's measured it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sighting {
    /// A lone, unconfirmed report.
    Lone,
    /// Reports that agree with each other.
    Corroborated,
}

/// Where a verdict's evidence came from, as a panel names it. The words are
/// the README's: local filters and local analysis on this machine, cloud
/// analysis from Beamline, and outside threat feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    LocalFilters,
    LocalAnalysis,
    CloudAnalysis,
    OneThreatFeed,
    ThreatFeeds,
}

impl Origin {
    /// How the panel's headline names it.
    const fn name(self) -> &'static str {
        match self {
            Self::LocalFilters => "local filters",
            Self::LocalAnalysis => "local analysis",
            Self::CloudAnalysis => "cloud analysis",
            Self::OneThreatFeed => "1 threat feed",
            Self::ThreatFeeds => "threat feeds",
        }
    }

    /// How a single-line record names it.
    const fn tag(self) -> &'static str {
        match self {
            Self::LocalFilters => "local-filters",
            Self::LocalAnalysis => "local-analysis",
            Self::CloudAnalysis => "cloud-analysis",
            Self::OneThreatFeed | Self::ThreatFeeds => "threat-feeds",
        }
    }
}

/// One line of evidence: a trait or finding, and how bad it is.
#[derive(Debug)]
struct Evidence<'a> {
    crit: cleave::Criticality,
    id: &'a str,
    desc: &'a str,
}

impl<'a> Evidence<'a> {
    /// What a person reads, as a dim lead and the text after it: the
    /// description alone, else the id split before its last component, so
    /// `anti-static/packer/upx/decompression-failed` leads with what failed.
    fn parts(&self) -> (&'a str, &'a str) {
        if !self.desc.trim().is_empty() {
            return ("", self.desc);
        }
        let split = self
            .id
            .rfind("::")
            .map(|i| i + 2)
            .or_else(|| self.id.rfind('/').map(|i| i + 1))
            .unwrap_or(0);
        self.id.split_at(split)
    }
}

/// Everything a verdict panel shows: what was decided, on what basis, what
/// Beamline knows of the bytes, and how to proceed.
#[derive(Debug)]
pub(crate) struct Panel<'a> {
    /// The classification driving this panel. Benign is never rendered.
    pub(crate) classification: Classification,
    /// Whether the body was withheld or forwarded under bypass.
    pub(crate) disposition: Disposition,
    /// Effective policy in force, used to choose the bypass hint.
    pub(crate) policy: ScanPolicy,
    /// URL the tool was about to fetch.
    pub(crate) url: &'a str,
    /// Lower-hex SHA-256 of the payload.
    pub(crate) sha256: &'a str,
    /// What reached the classification.
    pub(crate) basis: Basis<'a>,
    /// Beamline's finished analysis of exactly these bytes, when it has one:
    /// its reason is shown, and its report page linked.
    pub(crate) beamline: Option<&'a crate::beamline::Assessment>,
    /// What the local filters' threat-feed claims say of the payload, when
    /// they make some without settling it.
    pub(crate) sighting: Option<Sighting>,
    /// Shell-quoted reproducer for the bypass hint, e.g.
    /// `"curl -fsSL https://example.com/install.sh"`. When empty, the hint
    /// names only the variable.
    pub(crate) invocation: &'a str,
}

impl Panel<'_> {
    /// The report page for these bytes, when Atomdrift holds a record of
    /// them: cloud analysis, the known-bad filter, or a threat-feed sighting.
    fn report(&self) -> Option<String> {
        (self.beamline.is_some()
            || self.sighting.is_some()
            || matches!(self.basis, Basis::KnownBad))
        .then(|| format!("{REPORT_URL}{}", self.sha256))
    }

    /// Beamline's one-sentence explanation, when it measured the bytes itself.
    /// A reason that only counts feeds says what the headline already does.
    fn reason(&self) -> Option<&str> {
        let record = self.beamline.filter(|r| r.measured())?;
        record.reason.as_deref().filter(|r| !r.trim().is_empty())
    }

    /// Every source of the verdict's evidence, in a fixed order.
    fn origins(&self) -> Vec<Origin> {
        let mut origins = Vec::with_capacity(3);
        match self.basis {
            Basis::KnownBad => origins.push(Origin::LocalFilters),
            Basis::Local { .. } => origins.push(Origin::LocalAnalysis),
            Basis::Beamline => {}
        }
        if self
            .beamline
            .is_some_and(crate::beamline::Assessment::measured)
        {
            origins.push(Origin::CloudAnalysis);
        }
        // Beamline does not count the feeds behind a citation; only the
        // filters' lone claim is known to be one.
        if self
            .beamline
            .is_some_and(crate::beamline::Assessment::cited)
            || self.sighting == Some(Sighting::Corroborated)
        {
            origins.push(Origin::ThreatFeeds);
        } else if self.sighting == Some(Sighting::Lone) {
            origins.push(Origin::OneThreatFeed);
        }
        origins
    }

    /// What the bytes were seen to do, strongest first: local traits when
    /// local analysis decided, else Beamline's findings.
    fn evidence(&self) -> Vec<Evidence<'_>> {
        match (&self.basis, self.beamline) {
            (Basis::Local { traits, .. }, _) => traits
                .iter()
                .take(MAX_EVIDENCE)
                .map(|t| Evidence {
                    crit: t.crit,
                    id: &t.id,
                    desc: &t.desc,
                })
                .collect(),
            (_, Some(assessment)) => assessment
                .findings
                .iter()
                .filter(|f| !f.is_citation())
                .take(MAX_EVIDENCE)
                .map(|f| Evidence {
                    crit: f.criticality(),
                    id: &f.id,
                    desc: f.desc.as_deref().unwrap_or(""),
                })
                .collect(),
            (_, None) => Vec::new(),
        }
    }

    /// The verdict in plain words, as sure as its basis is: known when
    /// Atomdrift's record holds these bytes as malware, likely when local
    /// analysis finds them hostile, possible when anything finds them only
    /// suspicious.
    const fn verdict(&self) -> &'static str {
        match (self.classification, &self.basis) {
            (Classification::Hostile, Basis::Local { .. }) => "Likely malware",
            (Classification::Hostile, _) => "Known malware",
            (Classification::Suspicious, _) => "Possible malware",
            _ => "Unrecognized verdict",
        }
    }

    /// Whether the panel names the URL: only when the command shown in the
    /// bypass hint does not. `curl https://…` says what it fetched; `npm
    /// install` does not say which of its downloads was blocked.
    fn shows_url(&self) -> bool {
        !self.invocation.contains("://")
    }

    /// How sure the headline is, `60% confident [L25]`: the level local
    /// analysis placed the bytes at, read as the confidence prism and atomscan
    /// show for it. 60% and up is hostile at hood's L25, 30% to 60%
    /// suspicious. The raw model score is left to the log line: it means
    /// different things on different routes, the level does not.
    fn confidence(&self) -> Option<String> {
        let Basis::Local {
            level: level @ Level::At(_),
            ..
        } = self.basis
        else {
            return None;
        };
        let percent = scan::engine::level_confidence(level)?;
        Some(format!("{percent}% confident [{level}]"))
    }
}

/// Render a verdict panel to stderr.
pub(crate) fn emit(panel: &Panel<'_>) {
    to_stderr(|w, c| write_pretty(w, panel, c), |w| write_plain(w, panel));
}

fn write_pretty<W: Write>(w: &mut W, p: &Panel<'_>, c: Palette) -> io::Result<Heading> {
    let color = match p.classification {
        Classification::Hostile => c.hostile,
        Classification::Suspicious => c.suspicious,
        _ => c.text,
    };
    let origins: Vec<&str> = p.origins().into_iter().map(Origin::name).collect();
    write!(
        w,
        "  {} {} {}",
        fg_bold(color, p.verdict()),
        fg(c.chrome, "·"),
        fg(c.dim, &origins.join(", ")),
    )?;
    if let Some(confidence) = p.confidence() {
        write!(w, " {} {}", fg(c.chrome, "·"), fg(color, &confidence))?;
    }
    writeln!(w)?;
    if p.shows_url() {
        writeln!(w, "  {}", fg(c.text, &ShownUrl(p.url).to_string()))?;
    }

    // The detail rows lead with atomscan's markers: ⚡ for cloud analysis's
    // word, severity dots for each piece of evidence.
    let reason = p.reason();
    let evidence = p.evidence();
    if reason.is_some() || !evidence.is_empty() {
        writeln!(w)?;
    }
    if let Some(reason) = reason {
        let mut lead = rail("⚡", 2);
        for line in wrap(&sanitize(reason), MIN_PANEL_WIDTH - RAIL_WIDTH) {
            writeln!(w, "  {lead}{}", fg_bold(c.text, &line))?;
            lead = rail("", 0);
        }
    }
    for e in evidence {
        let (dots, color) = match e.crit {
            cleave::Criticality::Hostile => ("●●●", c.hostile),
            cleave::Criticality::Suspicious => ("●●", c.suspicious),
            cleave::Criticality::Notable => ("●", c.accent),
            _ => ("·", c.dim),
        };
        let lead = rail(&fg(color, dots), dots.chars().count());
        let (namespace, name) = e.parts();
        writeln!(
            w,
            "  {lead}{}{}",
            fg(c.dim, &sanitize(namespace)),
            fg(c.text, &sanitize(name))
        )?;
    }

    writeln!(w)?;
    match p.report() {
        Some(report) => writeln!(w, "  {} {}", fg(c.dim, "Details:"), fg(c.accent, &report))?,
        None => writeln!(w, "  {} {}", fg(c.dim, "SHA-256:"), fg(c.text, p.sha256))?,
    }
    match (p.disposition, p.classification) {
        (Disposition::Forwarded, _) => write_allowed(w, c, p.policy)?,
        // The lowest level that lets this through: =2 for suspicious, and
        // only =3 for hostile.
        (Disposition::Blocked, Classification::Suspicious) => {
            write_command_hint(w, c, "To download anyway:", "HOOD_BYPASS=2", p.invocation)?;
        }
        (Disposition::Blocked, Classification::Hostile) => write_command_hint(
            w,
            c,
            "To download anyway (not recommended):",
            "HOOD_BYPASS=3",
            p.invocation,
        )?,
        _ => {}
    }
    Ok(Heading {
        word: p.disposition.header(),
        color,
    })
}

/// Columns a row's marker rail takes: a 3-cell marker and a 1-cell gutter.
const RAIL_WIDTH: usize = 4;

/// `marker`, `width` cells wide, padded to the rail so the text after every
/// marker starts in one column. Emoji are two cells; dots are one each.
fn rail(marker: &str, width: usize) -> String {
    format!("{marker}{}", " ".repeat(RAIL_WIDTH.saturating_sub(width)))
}

/// `text` broken at spaces into lines of at most `width` columns; a word
/// longer than that gets a line of its own.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// The closing line of a panel whose download went through anyway.
fn write_allowed<W: Write>(w: &mut W, c: Palette, policy: ScanPolicy) -> io::Result<()> {
    writeln!(
        w,
        "  {} {}",
        fg(c.dim, "Allowed by"),
        fg(c.accent, policy_tag(policy))
    )
}

/// The `instruction` line, then the command that follows it on its own line,
/// ready to copy. Without a command (unit tests), only the variable.
fn write_command_hint<W: Write>(
    w: &mut W,
    c: Palette,
    instruction: &str,
    env: &str,
    invocation: &str,
) -> io::Result<()> {
    writeln!(w, "  {}", fg(c.dim, instruction))?;
    if invocation.is_empty() {
        writeln!(w, "  {}", fg(c.accent, env))
    } else {
        writeln!(
            w,
            "  {} {}",
            fg(c.accent, env),
            fg(c.text, sanitize(invocation).as_ref()),
        )
    }
}

/// Plain-text fallback for non-TTY stderr (CI logs, file redirection): one
/// line of `key=value` fields, the free-text reason last, no escape codes.
fn write_plain<W: Write>(w: &mut W, p: &Panel<'_>) -> io::Result<()> {
    write!(
        w,
        "hood {} verdict={} origin={} url={} sha256={}",
        p.disposition.verb(),
        classification_label(p.classification),
        p.origins()
            .into_iter()
            .map(Origin::tag)
            .collect::<Vec<_>>()
            .join(","),
        ShownUrl(p.url),
        p.sha256,
    )?;
    if let Basis::Local {
        probability, level, ..
    } = p.basis
    {
        write!(w, " risk={:.3} level={level}", probability.clamp(0.0, 1.0))?;
    }
    if let Some(report) = p.report() {
        write!(w, " report={report}")?;
    }
    write!(w, " policy={}", policy_tag(p.policy))?;
    let evidence: Vec<&str> = p.evidence().iter().map(|e| e.id).collect();
    if !evidence.is_empty() {
        write!(w, " evidence=[{}]", sanitize(&evidence.join(", ")))?;
    }
    if let Basis::Local { reasons, .. } = p.basis
        && !reasons.is_empty()
    {
        let names: Vec<&str> = reasons.iter().map(|r| r.feature.as_str()).collect();
        write!(w, " model=[{}]", names.join(", "))?;
    }
    if let Some(reason) = p.reason() {
        write!(w, " reason={}", sanitize(reason))?;
    }
    writeln!(w)
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

/// Render a scan-error panel to stderr.
pub fn emit_scan_error(p: &ScanErrorPanel<'_>) {
    to_stderr(
        |w, c| write_scan_error_pretty(w, p, c),
        |w| {
            writeln!(
                w,
                "hood scan-error url={} policy={} disposition={} error={}",
                ShownUrl(p.url),
                policy_tag(p.policy),
                p.disposition.verb(),
                sanitize(p.error),
            )
        },
    );
}

fn write_scan_error_pretty<W: Write>(
    w: &mut W,
    p: &ScanErrorPanel<'_>,
    c: Palette,
) -> io::Result<Heading> {
    writeln!(w, "  {}", fg_bold(c.suspicious, "Scan failed"))?;
    if !p.invocation.contains("://") {
        writeln!(w, "  {}", fg(c.text, &ShownUrl(p.url).to_string()))?;
    }
    writeln!(w)?;
    writeln!(
        w,
        "  {} {}",
        fg(c.dim, "Error:"),
        fg(c.text, sanitize(p.error).as_ref())
    )?;
    writeln!(w)?;
    match p.disposition {
        Disposition::Forwarded => write_allowed(w, c, p.policy)?,
        // The lowest level that lets this through.
        Disposition::Blocked => {
            write_command_hint(w, c, "To download anyway:", "HOOD_BYPASS=1", p.invocation)?;
        }
    }
    Ok(Heading {
        word: p.disposition.header(),
        color: c.suspicious,
    })
}

/// Context for an unscanned-download panel.
///
/// A download past the inspection limit is forwarded without a verdict. It is
/// not a block, so it carries no policy — only what went through and how large
/// it was.
#[derive(Debug)]
pub struct UnscannedPanel<'a> {
    /// URL the tool fetched.
    pub url: &'a str,
    /// Size the server declared, when it declared one; otherwise the download
    /// is known only to be past `limit`.
    pub size: Option<u64>,
    /// The inspection limit in bytes.
    pub limit: u64,
}

/// Render an unscanned-download warning to stderr.
pub fn emit_unscanned(p: &UnscannedPanel<'_>) {
    to_stderr(
        |w, c| write_unscanned_pretty(w, p, c),
        |w| write_unscanned_plain(w, p),
    );
}

fn write_unscanned_pretty<W: Write>(
    w: &mut W,
    p: &UnscannedPanel<'_>,
    c: Palette,
) -> io::Result<Heading> {
    writeln!(
        w,
        "  {}",
        fg_bold(
            c.suspicious,
            &format!("Forwarded unscanned — {}", unscanned_status(p))
        )
    )?;
    writeln!(w, "  {}", fg(c.text, &ShownUrl(p.url).to_string()))?;
    Ok(Heading {
        word: "UNSCANNED",
        color: c.suspicious,
    })
}

fn write_unscanned_plain<W: Write>(w: &mut W, p: &UnscannedPanel<'_>) -> io::Result<()> {
    writeln!(
        w,
        "Not scanned: {}; hood forward url={} verdict=unscanned size_bytes={} limit_bytes={}",
        unscanned_status(p),
        ShownUrl(p.url),
        p.size
            .map_or_else(|| "unknown".to_owned(), |size| size.to_string()),
        p.limit,
    )
}

fn unscanned_status(p: &UnscannedPanel<'_>) -> String {
    let limit = human_size(p.limit);
    let size = p.size.map_or_else(|| "Size".to_owned(), human_size);
    format!("{size} exceeds the {limit} scan limit")
}

/// A byte count in binary megabytes or gigabytes, rounded to one decimal.
fn human_size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    let (unit, name) = if bytes >= GIB {
        (GIB, "GB")
    } else {
        (MIB, "MB")
    };
    let unit = u128::from(unit);
    let tenths = (u128::from(bytes) * 10 + unit / 2) / unit;
    format!("{}.{} {name}", tenths / 10, tenths % 10)
}

/// Failsafe panel: scanning was bypassed because the proxy couldn't start.
/// Only emitted when `HOOD_BYPASS` is set; under strict policy a startup
/// failure aborts the run before this is ever called.
pub fn emit_failsafe(invocation: &str, policy: ScanPolicy, reason: &str) {
    to_stderr(
        |w, c| write_failsafe_pretty(w, policy, reason, c),
        |w| {
            writeln!(
                w,
                "hood unscanned policy={} reason={} invocation={}",
                policy_tag(policy),
                sanitize(reason),
                sanitize(invocation),
            )
        },
    );
}

fn write_failsafe_pretty<W: Write>(
    w: &mut W,
    policy: ScanPolicy,
    reason: &str,
    c: Palette,
) -> io::Result<Heading> {
    writeln!(w, "  {}", fg_bold(c.suspicious, "Scanner unavailable"))?;
    writeln!(w)?;
    writeln!(
        w,
        "  {} {}",
        fg(c.dim, "Error:"),
        fg(c.text, sanitize(reason).as_ref())
    )?;
    writeln!(w)?;
    write_allowed(w, c, policy)?;
    Ok(Heading {
        word: "UNSCANNED",
        color: c.suspicious,
    })
}

const fn policy_tag(p: ScanPolicy) -> &'static str {
    match p {
        ScanPolicy::Strict => "HOOD_BYPASS=0",
        ScanPolicy::AllowErrors => "HOOD_BYPASS=1",
        ScanPolicy::AllowSuspicious => "HOOD_BYPASS=2",
        ScanPolicy::Bypass => "HOOD_BYPASS=3",
    }
}

pub(crate) const fn classification_label(c: Classification) -> &'static str {
    match c {
        Classification::Hostile => "hostile",
        Classification::Suspicious => "suspicious",
        Classification::Benign => "benign",
        _ => "unknown",
    }
}

/// Unicode bidirectional formatting characters. They are not control
/// characters, yet they reorder how the text after them is displayed, so an
/// attacker-chosen string could make a panel read differently than it says
/// ("Trojan Source").
pub(crate) const fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// Neutralize control characters in an attacker-influenced string before it is
/// written to a terminal or a single-line log record. A crafted URL, PURL, or
/// scan-error message could otherwise embed an ANSI escape (recoloring or
/// clearing the terminal, hiding text), a newline (forging a second log line),
/// or a bidi override (reordering what is shown). Printable characters and
/// tabs pass through; everything else becomes U+FFFD.
fn sanitize(s: &str) -> std::borrow::Cow<'_, str> {
    let unsafe_char = |c: char| (c.is_control() && c != '\t') || is_bidi_control(c);
    if !s.chars().any(unsafe_char) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .map(|c| if unsafe_char(c) { '\u{fffd}' } else { c })
            .collect(),
    )
}

/// A URL as hood shows it, in panels and logs: sanitized, and without the
/// userinfo, query, and fragment that carry credentials and signatures —
/// `?token=`, presigned object-storage links — into terminals and CI logs,
/// which are often public. `?…` marks an elided query or fragment.
pub(crate) struct ShownUrl<'a>(pub(crate) &'a str);

impl std::fmt::Display for ShownUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Ok(mut url) = url::Url::parse(self.0) else {
            // Not a URL hood built; keep only what precedes any query.
            let head = self.0.split(['?', '#']).next().unwrap_or_default();
            return f.write_str(&sanitize(head));
        };
        let elided = url.query().is_some() || url.fragment().is_some();
        url.set_query(None);
        url.set_fragment(None);
        // Both fail only for URLs that cannot carry userinfo at all.
        let _ = url.set_username("");
        let _ = url.set_password(None);
        f.write_str(&sanitize(url.as_str()))?;
        if elided {
            f.write_str("?…")?;
        }
        Ok(())
    }
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
    fn shown_urls_drop_credentials_queries_and_fragments() {
        assert_eq!(
            ShownUrl("https://registry.example/pkg.tgz").to_string(),
            "https://registry.example/pkg.tgz"
        );
        let shown =
            ShownUrl("https://user:pw@bucket.example/a.tgz?X-Amz-Signature=sig&token=secret#frag")
                .to_string();
        assert_eq!(shown, "https://bucket.example/a.tgz?…");
        assert_eq!(ShownUrl("not a url?token=secret").to_string(), "not a url");
    }

    #[test]
    fn sanitize_neutralizes_bidi_overrides() {
        let clean = sanitize("evil\u{202e}hs.tgz");
        assert!(!clean.contains('\u{202e}'), "{clean:?}");
        assert!(clean.contains("evil") && clean.contains("hs.tgz"));
    }

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

    const SHA: &str = "b5cf68c7cb5bb2d21d60bf6654926f61566d95bfd7c9f9e182d032f1da5b4605";

    fn trait_(id: &str, crit: cleave::Criticality, desc: &str) -> TopFinding {
        TopFinding {
            id: id.into(),
            crit,
            conf: 0.9,
            desc: desc.into(),
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

    fn assessment(json: serde_json::Value) -> crate::beamline::Assessment {
        serde_json::from_value(json).unwrap()
    }

    fn local(
        traits: &[TopFinding],
        classification: Classification,
        disposition: Disposition,
        policy: ScanPolicy,
    ) -> Panel<'_> {
        Panel {
            classification,
            disposition,
            policy,
            url: "https://example.com/foo.sh",
            sha256: SHA,
            basis: Basis::Local {
                probability: 0.7,
                level: Level::At(10),
                traits,
                reasons: &[],
            },
            beamline: None,
            sighting: None,
            invocation: "",
        }
    }

    /// A panel as a terminal `columns` wide shows it, escapes stripped.
    fn framed(
        columns: usize,
        pretty: impl FnOnce(&mut Vec<u8>, Palette) -> io::Result<Heading>,
    ) -> String {
        let c = Palette::dark();
        let mut body = Vec::new();
        let heading = pretty(&mut body, c).unwrap();
        let mut out = Vec::new();
        write_framed(&mut out, c, heading, &body, columns).unwrap();
        strip_ansi(&String::from_utf8(out).unwrap())
    }

    fn pretty(p: &Panel<'_>) -> String {
        framed(200, |w, c| write_pretty(w, p, c))
    }

    fn plain(p: &Panel<'_>) -> String {
        let mut buf = Vec::new();
        write_plain(&mut buf, p).unwrap();
        String::from_utf8(buf).unwrap()
    }

    /// The GitHub release download that prompted this layout: a local
    /// hostile verdict Beamline had not analyzed.
    #[test]
    fn local_block_reads_like_atomscan() {
        let traits = [
            trait_(
                "objectives/collection/monitor/capture::go-websocket-ffmpeg-audio-video-capture",
                cleave::Criticality::Hostile,
                "Captures audio and video with ffmpeg and streams it over a WebSocket",
            ),
            trait_(
                "objectives/credential-access/browser/firefox::go-multi-browser-credential-collection",
                cleave::Criticality::Suspicious,
                "",
            ),
        ];
        let p = Panel {
            url: "https://release-assets.githubusercontent.com/asset/1474925739/99707390?sp=r&sig=secret",
            invocation: "curl -LO https://github.com/x/y/releases/download/z/a.exe",
            ..local(
                &traits,
                Classification::Hostile,
                Disposition::Blocked,
                ScanPolicy::Strict,
            )
        };
        let s = pretty(&p);
        assert!(s.contains("── Atomdrift Hood · BLOCKED ──"), "{s}");
        assert!(
            s.contains("  Likely malware · local analysis · 70% confident [L10]\n"),
            "{s}"
        );
        // The command names what was fetched; the redirect target is noise.
        assert!(!s.contains("release-assets"), "{s}");
        assert!(!s.contains("secret"), "{s}");
        // Descriptions read first; an id without one leads with its leaf.
        assert!(
            s.contains("  ●●● Captures audio and video with ffmpeg"),
            "{s}"
        );
        assert!(
            s.contains("  ●●  objectives/credential-access/browser/firefox::go-multi-browser"),
            "{s}"
        );
        // Nothing Beamline knows: the bare hash, no report link, no ⚡.
        assert!(s.contains(&format!("  SHA-256: {SHA}\n")), "{s}");
        assert!(!s.contains("sha256.is") && !s.contains('⚡'), "{s}");
        assert!(
            s.contains("To download anyway (not recommended):\n  HOOD_BYPASS=3 curl -LO https://github.com/"),
            "{s}"
        );
        assert!(!s.contains('🛑'), "{s}");
    }

    /// The known-bad MIPS loader: Beamline confirms it, with findings that
    /// carry no description.
    #[test]
    fn known_bad_block_links_report_and_shows_beamline_reason() {
        let record = assessment(serde_json::json!({
            "status": "analyzed", "severity": "hostile", "sha256": SHA,
            "reason": "Packed MIPS binary with high entropy",
            "findings": [
                {"id": "anti-static/packer/upx/decompression-failed", "crit": 5},
                {"id": "objectives/anti-static/pack/detect::upx-marked-sectionless-loader", "crit": 4},
                {"id": "anti-static/packer/upx", "crit": 3},
            ],
        }));
        let p = Panel {
            classification: Classification::Hostile,
            disposition: Disposition::Blocked,
            policy: ScanPolicy::Strict,
            url: "http://125.41.227.76:47512/i",
            sha256: SHA,
            basis: Basis::KnownBad,
            beamline: Some(&record),
            sighting: None,
            invocation: "curl http://125.41.227.76:47512/i",
        };
        let s = pretty(&p);
        assert!(
            s.contains("  Known malware · local filters, cloud analysis\n"),
            "{s}"
        );
        assert_eq!(s.matches("125.41.227.76").count(), 1, "{s}");
        assert!(
            s.contains("  ⚡  Packed MIPS binary with high entropy\n"),
            "{s}"
        );
        assert!(
            s.contains(&format!("  Details: https://sha256.is/{SHA}\n")),
            "{s}"
        );
        assert!(
            s.contains("  ●●● anti-static/packer/upx/decompression-failed\n"),
            "{s}"
        );
        assert!(
            s.contains("  ●●  objectives/anti-static/pack/detect::upx-marked"),
            "{s}"
        );
        assert!(s.contains("  ●   anti-static/packer/upx\n"), "{s}");
        assert!(
            s.contains("\n  HOOD_BYPASS=3 curl http://125.41.227.76:47512/i\n"),
            "{s}"
        );
        assert!(!s.contains("lab.atomdrift.org"), "{s}");

        let line = plain(&p);
        assert_eq!(line.lines().count(), 1, "{line}");
        assert!(line.starts_with(&format!(
            "hood block verdict=hostile origin=local-filters,cloud-analysis url=http://125.41.227.76:47512/i sha256={SHA} report=https://sha256.is/{SHA} policy=HOOD_BYPASS=0 evidence=["
        )), "{line}");
        assert!(
            line.ends_with(" reason=Packed MIPS binary with high entropy\n"),
            "{line}"
        );
    }

    #[test]
    fn known_bad_without_beamline_still_links_report() {
        let p = Panel {
            basis: Basis::KnownBad,
            invocation: "npm install evil",
            ..local(
                &[],
                Classification::Hostile,
                Disposition::Blocked,
                ScanPolicy::Strict,
            )
        };
        let s = pretty(&p);
        assert!(
            s.contains(&format!("  Details: https://sha256.is/{SHA}\n")),
            "{s}"
        );
        assert!(s.contains("  Known malware · local filters\n"), "{s}");
        assert!(s.contains("HOOD_BYPASS=3 npm install evil"), "{s}");
        assert!(s.contains("  https://example.com/foo.sh\n"), "{s}");
        assert!(!s.contains('⚡'), "{s}");
    }

    #[test]
    fn beamline_verdict_shows_reason_report_and_findings() {
        let record = assessment(serde_json::json!({
            "status": "analyzed", "severity": "hostile", "sha256": SHA,
            "reason": "steals credentials", "analyzed_at": "2026-11-20T08:00:00Z",
            "findings": [{"id": "exfil/ssh-key", "crit": 5, "desc": "reads ~/.ssh"}],
        }));
        let p = Panel {
            basis: Basis::Beamline,
            beamline: Some(&record),
            ..local(
                &[],
                Classification::Hostile,
                Disposition::Blocked,
                ScanPolicy::Strict,
            )
        };
        let s = pretty(&p);
        assert!(s.contains("  Known malware · cloud analysis\n"), "{s}");
        assert!(!s.contains("% confident"), "{s}");
        assert!(s.contains("  ⚡  steals credentials\n"), "{s}");
        assert!(
            s.contains(&format!("  Details: https://sha256.is/{SHA}\n")),
            "{s}"
        );
        assert!(s.contains("  ●●● reads ~/.ssh\n"), "{s}");
        assert!(plain(&p).contains(" origin=cloud-analysis "));
    }

    /// A feed's citation does not settle the bytes, but it explains a local
    /// block: its reason and report ride along, marked as a sighting.
    #[test]
    fn local_block_carries_beamline_sighting() {
        let record = assessment(serde_json::json!({
            "status": "analyzed", "severity": "suspicious", "sha256": SHA,
            "reason": "Cited as malicious by 1 threat intelligence feed.",
            "findings": [{"id": "intel/feed/malicious", "crit": 4}],
        }));
        let traits = [trait_(
            "exec/shell::bash",
            cleave::Criticality::Hostile,
            "Runs bash",
        )];
        let p = Panel {
            beamline: Some(&record),
            ..local(
                &traits,
                Classification::Hostile,
                Disposition::Blocked,
                ScanPolicy::Strict,
            )
        };
        let s = pretty(&p);
        assert!(
            s.contains("  Likely malware · local analysis, threat feeds · 70% confident [L10]\n"),
            "{s}"
        );
        // A reason that only counts feeds repeats the headline.
        assert!(
            !s.contains('⚡') && !s.contains("Cited as malicious"),
            "{s}"
        );
        assert!(
            s.contains(&format!("  Details: https://sha256.is/{SHA}\n")),
            "{s}"
        );
        // Local analysis decided, so its traits are the evidence.
        assert!(s.contains("●●● Runs bash"), "{s}");
        assert!(!s.contains("intel/feed"), "{s}");
        assert!(
            plain(&p).contains(" origin=local-analysis,threat-feeds "),
            "{}",
            plain(&p)
        );
    }

    /// Agreeing feeds settle a verdict in the cloud with nothing measured:
    /// the headline names them, and no citation is listed as evidence.
    #[test]
    fn feeds_only_cloud_verdict_names_threat_feeds() {
        let record = assessment(serde_json::json!({
            "status": "analyzed", "severity": "hostile", "sha256": SHA,
            "reason": "Cited as malicious by 3 independent threat intelligence feeds.",
            "findings": [{"id": "intel/feed/malicious", "crit": 5}],
        }));
        let p = Panel {
            basis: Basis::Beamline,
            beamline: Some(&record),
            ..local(
                &[],
                Classification::Hostile,
                Disposition::Blocked,
                ScanPolicy::Strict,
            )
        };
        let s = pretty(&p);
        assert!(s.contains("  Known malware · threat feeds\n"), "{s}");
        assert!(!s.contains('⚡') && !s.contains('●'), "{s}");
        assert!(
            s.contains(&format!("  Details: https://sha256.is/{SHA}\n")),
            "{s}"
        );
    }

    /// The filters know of a lone feed report, with no cloud asked: it still
    /// shows, and links Atomdrift's record.
    #[test]
    fn filter_sighting_shows_without_the_cloud() {
        let traits = [trait_(
            "exec/shell::bash",
            cleave::Criticality::Hostile,
            "Runs bash",
        )];
        for (sighting, origin) in [
            (Sighting::Lone, "1 threat feed"),
            (Sighting::Corroborated, "threat feeds"),
        ] {
            let p = Panel {
                sighting: Some(sighting),
                ..local(
                    &traits,
                    Classification::Hostile,
                    Disposition::Blocked,
                    ScanPolicy::Strict,
                )
            };
            let s = pretty(&p);
            assert!(
                s.contains(&format!(
                    "  Likely malware · local analysis, {origin} · 70% confident [L10]\n"
                )),
                "{s}"
            );
            assert!(
                s.contains(&format!("  Details: https://sha256.is/{SHA}\n")),
                "{s}"
            );
        }
    }

    #[test]
    fn beamline_text_is_sanitized_and_wrapped_under_the_rail() {
        let reason = format!(
            "credential theft\u{1b}[31m {}",
            "exfiltrates data ".repeat(10)
        );
        let record = assessment(serde_json::json!({
            "status": "analyzed", "severity": "hostile", "sha256": SHA,
            "reason": reason,
            "findings": [{"id": "exfil/x", "crit": 5, "desc": "evil\u{202e}txt"}],
        }));
        let p = Panel {
            basis: Basis::Beamline,
            beamline: Some(&record),
            ..local(
                &[],
                Classification::Hostile,
                Disposition::Blocked,
                ScanPolicy::Strict,
            )
        };
        let mut buf = Vec::new();
        write_pretty(&mut buf, &p, Palette::dark()).unwrap();
        let raw = String::from_utf8(buf).unwrap();
        assert!(
            !raw.contains("\u{1b}[31m") && !raw.contains('\u{202e}'),
            "{raw:?}"
        );
        let s = strip_ansi(&raw);
        let reason_lines: Vec<&str> = s
            .lines()
            .skip_while(|l| !l.contains('⚡'))
            .take_while(|l| !l.contains('●'))
            .collect();
        assert!(reason_lines.len() > 1, "{s}");
        for line in &reason_lines[1..] {
            assert!(
                line.starts_with("      ") && line.chars().count() <= INDENT + MIN_PANEL_WIDTH,
                "{line:?}"
            );
        }
    }

    #[test]
    fn plain_output_is_one_structured_line() {
        let traits = [trait_(
            "exec/shell::bash",
            cleave::Criticality::Hostile,
            "Runs bash",
        )];
        let reasons = [reason_("crit_count:suspicious")];
        let p = Panel {
            basis: Basis::Local {
                probability: 0.7,
                level: Level::At(10),
                traits: &traits,
                reasons: &reasons,
            },
            ..local(
                &[],
                Classification::Hostile,
                Disposition::Blocked,
                ScanPolicy::Strict,
            )
        };
        assert_eq!(
            plain(&p),
            format!(
                "hood block verdict=hostile origin=local-analysis url=https://example.com/foo.sh sha256={SHA} \
                 risk=0.700 level=L10 policy=HOOD_BYPASS=0 evidence=[exec/shell::bash] model=[crit_count:suspicious]\n"
            )
        );
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
    fn hints_name_the_lowest_level_that_would_allow() {
        for (classification, level, absent) in [
            (
                Classification::Suspicious,
                "HOOD_BYPASS=2",
                ["HOOD_BYPASS=1", "HOOD_BYPASS=3"],
            ),
            (
                Classification::Hostile,
                "HOOD_BYPASS=3",
                ["HOOD_BYPASS=1", "HOOD_BYPASS=2"],
            ),
        ] {
            let p = Panel {
                invocation: "curl -fsSL https://x/install.sh",
                ..local(
                    &[],
                    classification,
                    Disposition::Blocked,
                    ScanPolicy::Strict,
                )
            };
            let s = pretty(&p);
            assert!(
                s.contains(&format!("  {level} curl -fsSL https://x/install.sh\n")),
                "{s}"
            );
            for other in absent {
                assert!(!s.contains(other), "{s}");
            }
        }
    }

    /// The level is what hood's L25 was compared against, so its confidence
    /// is what tells a suspicious verdict from a hostile one; with no level
    /// there is nothing to show, and the raw score stays out of the panel.
    #[test]
    fn headline_names_the_confidence_and_level() {
        for (classification, level, expected) in [
            (
                Classification::Suspicious,
                Level::At(500),
                "  Possible malware · local analysis · 40% confident [L500]\n",
            ),
            (
                Classification::Hostile,
                Level::At(0),
                "  Likely malware · local analysis · 99% confident [L0]\n",
            ),
            (
                Classification::Hostile,
                Level::Manual,
                "  Likely malware · local analysis\n",
            ),
        ] {
            let p = Panel {
                basis: Basis::Local {
                    probability: 0.41,
                    level,
                    traits: &[],
                    reasons: &[],
                },
                ..local(
                    &[],
                    classification,
                    Disposition::Blocked,
                    ScanPolicy::Strict,
                )
            };
            let s = pretty(&p);
            assert!(s.contains(expected), "{s}");
        }
    }

    #[test]
    fn forwarded_panel_shows_active_level() {
        let s = pretty(&local(
            &[],
            Classification::Hostile,
            Disposition::Forwarded,
            ScanPolicy::Bypass,
        ));
        assert!(s.contains("FORWARDED"), "{s}");
        assert!(s.contains("  Allowed by HOOD_BYPASS=3\n"), "{s}");
        assert!(!s.contains("To download anyway"), "{s}");
    }

    #[test]
    fn failsafe_pretty_mentions_policy_and_reason() {
        let s = framed(200, |w, c| {
            write_failsafe_pretty(w, ScanPolicy::Bypass, "load scan model: not found", c)
        });
        assert!(s.contains("UNSCANNED"));
        assert!(s.contains("HOOD_BYPASS=3"));
        assert!(s.contains("load scan model: not found"));
        assert!(s.contains("Scanner unavailable"));
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
        let s = framed(200, |w, c| write_scan_error_pretty(w, &p, c));
        assert!(s.contains("BLOCKED"), "{s}");
        assert!(s.contains("  Scan failed\n"), "{s}");
        assert!(s.contains("  Error: trait load failed"), "{s}");
        assert!(
            s.contains("To download anyway:\n  HOOD_BYPASS=1 curl -fsSL https://x/install.sh\n"),
            "{s}"
        );
    }

    /// Widths of a framed panel's two rules, and of its widest body line.
    fn rule_widths(s: &str) -> (usize, usize, usize) {
        let lines: Vec<&str> = s.lines().filter(|l| !l.is_empty()).collect();
        let width = |l: &str| visible_width(l) - INDENT;
        let body = lines[1..lines.len() - 1].iter().map(|l| width(l));
        (
            width(lines[0]),
            width(lines[lines.len() - 1]),
            body.max().unwrap(),
        )
    }

    #[test]
    fn rules_close_around_the_panel() {
        let short = |w: &mut Vec<u8>, c: Palette| {
            writeln!(w, "  {}", fg(c.text, "Likely malware"))?;
            Ok(Heading {
                word: "BLOCKED",
                color: c.hostile,
            })
        };
        let link = format!("  Details: {REPORT_URL}{}", "a".repeat(64));
        let long = |w: &mut Vec<u8>, c: Palette| {
            writeln!(w, "  {}", fg(c.accent, &link[2..]))?;
            Ok(Heading {
                word: "FORWARDED",
                color: c.suspicious,
            })
        };
        // A short panel keeps the minimum; both rules end together.
        assert_eq!(rule_widths(&framed(200, short)).0, MIN_PANEL_WIDTH);
        assert_eq!(rule_widths(&framed(200, short)).1, MIN_PANEL_WIDTH);
        // A long line widens both rules to it.
        let (top, bottom, body) = rule_widths(&framed(200, long));
        assert_eq!((top, bottom), (body, body));
        assert_eq!(body, link.len() - INDENT);
        // A command longer than any line hood writes runs past the rules.
        let command = format!("  HOOD_BYPASS=3 curl -LO https://x/{}", "a".repeat(150));
        let (top, bottom, _) = rule_widths(&framed(200, |w, c| {
            writeln!(w, "{command}")?;
            Ok(Heading {
                word: "BLOCKED",
                color: c.hostile,
            })
        }));
        assert_eq!((top, bottom), (MAX_PANEL_WIDTH, MAX_PANEL_WIDTH));
        // A narrow terminal caps them a column short of its edge.
        let (top, bottom, _) = rule_widths(&framed(60, long));
        assert_eq!((top, bottom), (60 - INDENT - 1, 60 - INDENT - 1));
    }

    #[test]
    fn visible_width_skips_escapes_and_counts_emoji_wide() {
        assert_eq!(visible_width(&fg(Rgb(1, 2, 3), "abc")), 3);
        assert_eq!(visible_width("  ⚡  reason"), 2 + 2 + 2 + 6);
        assert_eq!(visible_width("●●● x"), 5);
    }

    #[test]
    fn unscanned_panel_names_size_and_limit() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let p = UnscannedPanel {
            url: "https://cdn.example/big.iso?signature=secret",
            size: Some(3 * GIB + GIB / 10),
            limit: 2 * GIB,
        };
        let s = framed(200, |w, c| write_unscanned_pretty(w, &p, c));
        assert!(s.contains("UNSCANNED"), "{s}");
        assert!(s.contains("3.1 GB exceeds the 2.0 GB scan limit"), "{s}");
        assert!(s.contains("https://cdn.example/big.iso?…"), "{s}");
        assert!(!s.contains("secret"), "{s}");

        let undeclared = UnscannedPanel { size: None, ..p };
        let mut buf = Vec::new();
        write_unscanned_plain(&mut buf, &undeclared).unwrap();
        let line = String::from_utf8(buf).unwrap();
        assert!(
            line.contains("Not scanned: Size exceeds the 2.0 GB scan limit"),
            "{line}"
        );
        assert!(
            line.contains("hood forward url=https://cdn.example/big.iso?…"),
            "{line}"
        );
        assert!(line.contains("size_bytes=unknown"), "{line}");
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn human_sizes_use_one_decimal() {
        assert_eq!(human_size(512 * 1024 * 1024), "512.0 MB");
        assert_eq!(human_size(2 * 1024 * 1024 * 1024), "2.0 GB");
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
        let s = framed(200, |w, c| write_scan_error_pretty(w, &p, c));
        assert!(s.contains("FORWARDED"));
        assert!(s.contains("  Allowed by HOOD_BYPASS=1\n"), "{s}");
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

    #[test]
    fn zz_preview_classes() {
        let traits = [trait_(
            "objectives/supply-chain/impersonation/npm-clone::events-shim-republished-under-new-name",
            cleave::Criticality::Hostile,
            "",
        )];
        for class in [Classification::Hostile, Classification::Suspicious] {
            let p = Panel {
                url: "https://proxy.golang.org/github.com/atomdrift-project/hopper/@v/v0.0.0-20261128011454-c270bfa7de0c.zip",
                invocation: "go get -u ./...",
                ..local(&traits, class, Disposition::Blocked, ScanPolicy::Strict)
            };
            eprintln!("{}", pretty(&p));
        }
    }
}
