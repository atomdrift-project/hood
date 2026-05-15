//! Human-facing stderr panels for non-benign scan verdicts.
//!
//! Design language mirrors litmus and cleave: truecolor classification accents,
//! confidence indicator blocks, indented evidence. The presentation goes one
//! step further than litmus's per-file streaming output: hood has the *whole*
//! verdict in hand for a single payload, so the panel can be a focused unit
//! instead of a one-liner. Operators get the verdict, evidence, and an
//! actionable next step in one glance.
//!
//! Output only colorizes when stderr is a real terminal — when redirected to a
//! file, we collapse to a single structured line that's grep-friendly.

use std::io::{IsTerminal, Write};

use litmus::explain::Reason;
use litmus::model::Classification;
use litmus::output::Theme;
use litmus::scan::TopFinding;

use crate::scanner::ScanPolicy;

/// Truecolor RGB triple.
#[derive(Debug, Clone, Copy)]
struct Rgb(u8, u8, u8);

/// Per-theme palette. Classification colors track litmus's so the two
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
#[derive(Debug, Clone, Copy)]
pub enum Disposition {
    /// Verdict was Block; the body was withheld from the caller.
    Blocked,
    /// Verdict was non-benign but policy let it through (HOOD_BYPASS active).
    Forwarded,
}

/// Bundle of everything the panel needs to render. Pulled out of the scan
/// result so the renderer doesn't have to know litmus internals beyond the
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
    /// Raw model probability in `[0, 1]`. Drives the indicator length.
    pub probability: f32,
    /// URL the tool was about to fetch.
    pub url: &'a str,
    /// Top traits ranked by `crit × conf`.
    pub traits: &'a [TopFinding],
    /// Top SHAP-ranked reasons.
    pub reasons: &'a [Reason],
}

/// Render the panel to stderr. Falls back to a single structured WARN line
/// when stderr isn't a TTY so log aggregators don't get smeared with ANSI.
///
/// This function never fails — write errors to stderr are silent (stderr is
/// the diagnostics channel; we have nowhere else to complain to).
pub fn emit(panel: &Panel<'_>) {
    let mut stderr = std::io::stderr().lock();
    if stderr.is_terminal() {
        let theme = litmus::output::detect_theme();
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
    let verdict_label = classification_label(p.classification);

    writeln!(w)?;
    writeln!(
        w,
        "  {} {} {}",
        fg(c.dim, "──"),
        fg_bold(verdict_color, header_word),
        fg(c.chrome, &"─".repeat(64)),
    )?;
    writeln!(
        w,
        "  {}  {}  {}",
        confidence_blocks(p.probability, verdict_color, c.dim),
        fg_bold(verdict_color, verdict_label),
        fg(c.dim, &format!("{:>3}%", percent(p.probability))),
    )?;
    writeln!(w, "  {}", fg_bold(c.text, p.url))?;

    if let Some(orig) = p.original {
        if orig != p.classification {
            writeln!(
                w,
                "  {} {}",
                fg(c.dim, "upgraded from"),
                fg(c.dim, classification_label(orig)),
            )?;
        }
    }

    if !p.traits.is_empty() {
        writeln!(w)?;
        writeln!(w, "  {}", fg(c.dim, "evidence"))?;
        for t in p.traits {
            let score = score_value(t);
            writeln!(
                w,
                "    {}  {}  {}",
                fg(c.dim, &format!("{}×{:.2}", t.crit, t.conf)),
                fg(verdict_color, &format!("{score:>5.2}")),
                fg(c.text, &t.id),
            )?;
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
    match (p.disposition, p.classification, p.policy) {
        // Already forwarded — tell the operator what's already active.
        (Disposition::Forwarded, _, ScanPolicy::Bypass) => writeln!(
            w,
            "  {}  {}",
            fg(c.dim, "active:"),
            fg(c.accent, "HOOD_BYPASS=2"),
        ),
        (Disposition::Forwarded, _, ScanPolicy::AllowSuspicious) => writeln!(
            w,
            "  {}  {}",
            fg(c.dim, "active:"),
            fg(c.accent, "HOOD_BYPASS=1"),
        ),
        // Blocked: tell the user the minimum knob that would let it through.
        (Disposition::Blocked, Classification::Suspicious, _) => {
            writeln!(
                w,
                "  {}  {}  {}",
                fg(c.dim, "to allow:"),
                fg(c.accent, "HOOD_BYPASS=1"),
                fg(c.dim, "(allow suspicious)"),
            )?;
            writeln!(
                w,
                "  {}  {}  {}",
                fg(c.dim, "         "),
                fg(c.accent, "HOOD_BYPASS=2"),
                fg(c.dim, "(allow suspicious + hostile)"),
            )
        }
        (Disposition::Blocked, Classification::Hostile, _) => writeln!(
            w,
            "  {}  {}  {}",
            fg(c.dim, "to allow:"),
            fg(c.accent, "HOOD_BYPASS=2"),
            fg(c.dim, "(allow suspicious + hostile — proceed with care)"),
        ),
        _ => Ok(()),
    }
}

/// Plain-text fallback for non-TTY stderr (CI logs, file redirection).
/// Single line, structured-ish, no escape codes.
fn write_plain<W: Write>(w: &mut W, p: &Panel<'_>) -> std::io::Result<()> {
    let header = match p.disposition {
        Disposition::Blocked => "block",
        Disposition::Forwarded => "forward",
    };
    let traits = format_traits_inline(p.traits);
    let reasons: Vec<&str> = p.reasons.iter().map(|r| r.feature.as_str()).collect();
    writeln!(
        w,
        "hood {} url={} verdict={} probability={:.3} traits=[{}] reasons=[{}]{}",
        header,
        p.url,
        classification_label(p.classification),
        p.probability,
        traits,
        reasons.join(", "),
        match p.original {
            Some(o) if o != p.classification => format!(" upgraded_from={}", classification_label(o)),
            _ => String::new(),
        },
    )
}

fn format_traits_inline(traits: &[TopFinding]) -> String {
    traits
        .iter()
        .map(|t| format!("{} ({:.2})", t.id, score_value(t)))
        .collect::<Vec<_>>()
        .join(", ")
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
/// same idiom litmus uses, expanded from two cells to five for a finer read.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn confidence_blocks(probability: f32, accent: Rgb, dim: Rgb) -> String {
    const CELLS: usize = 5;
    // probability is clamped to [0, 1] and CELLS is 5, so the rounded product
    // fits in usize on every platform — no truncation or sign loss possible.
    let filled = (probability.clamp(0.0, 1.0) * CELLS as f32).round() as usize;
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

#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn score_value(t: &TopFinding) -> f32 {
    (t.crit as f32) * t.conf
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn percent(p: f32) -> u32 {
    (p.clamp(0.0, 1.0) * 100.0).round() as u32
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
        };
        let mut buf = Vec::new();
        write_plain(&mut buf, &p).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("upgraded_from=benign"));
    }

    #[test]
    fn pretty_output_suggests_bypass_1_for_suspicious_block() {
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
        assert!(s.contains("HOOD_BYPASS=1"));
        assert!(s.contains("HOOD_BYPASS=2"));
    }

    #[test]
    fn pretty_output_suggests_bypass_2_for_hostile_block() {
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
        assert!(s.contains("HOOD_BYPASS=2"));
        // Hostile blocks don't suggest HOOD_BYPASS=1 (wouldn't be enough).
        assert!(!s.contains("HOOD_BYPASS=1"));
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
        assert!(s.contains("HOOD_BYPASS=2"));
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
