//! `hood install` / `hood uninstall`.
//!
//! Installs busybox-style symlinks at `~/.hood/bin/<tool>` pointing at the
//! hood binary itself. At startup, hood inspects `argv[0]` — when invoked via
//! one of these symlinks (e.g. as `npm`), it dispatches as if the user had
//! typed `hood npm <args>`. Then it shells out to the real tool through `PATH`,
//! skipping `~/.hood/bin/` so the symlink can't reinvoke itself.
//!
//! Why symlinks instead of shim scripts:
//! - one binary, many faces — replacing `hood` upgrades every "tool" atomically;
//! - no `/bin/sh` spawn per invocation;
//! - no shell-quoting concerns embedded in generated files;
//! - uninstall is a `rm` of links that point at our binary, nothing to grep for.
//!
//! On Windows the platform doesn't have user-level symlinks reliably, so we
//! fall back to hardlinks (preserving the single-binary semantics) or, as a
//! last resort, copies.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::tools::Tool;

/// Sentinel marker bookending hood's edits in a shell rc file.
const MARK_BEGIN: &str = "# >>> hood shim (added by `hood install`) >>>";
const MARK_END: &str = "# <<< hood shim <<<";

/// Resolve the directory where hood installs its busybox-style symlinks.
/// Defaults to `~/.hood/bin`. Honors `HOOD_HOME` for test/sandbox use.
///
/// # Errors
/// Returns an error if `$HOME` (or `$HOOD_HOME`) cannot be resolved.
pub fn shim_dir() -> Result<PathBuf> {
    Ok(layout_default()?.shim_dir)
}

/// Where hood lays out its on-disk state during install/uninstall. Pulled
/// into a struct (rather than threaded as separate args) so tests can build
/// a synthetic layout pointing at a tempdir.
#[derive(Debug, Clone)]
pub struct Layout {
    /// User's home directory; rc files are discovered relative to this.
    pub home: PathBuf,
    /// Directory the busybox-style shims live in.
    pub shim_dir: PathBuf,
}

impl Layout {
    /// Layout rooted at an arbitrary `home`. The shim directory follows the
    /// `<home>/.hood/bin` convention used by the platform-default layout.
    #[must_use]
    pub fn at_home(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let shim_dir = home.join(".hood").join("bin");
        Self { home, shim_dir }
    }
}

/// Resolve the platform default layout: `HOME` (or `HOOD_HOME` override) plus the
/// standard `<home>/.hood/bin` shim directory.
fn layout_default() -> Result<Layout> {
    if let Some(home) = std::env::var_os("HOOD_HOME") {
        return Ok(Layout::at_home(PathBuf::from(home)));
    }
    let home = dirs::home_dir().context("HOME not set; cannot resolve home directory")?;
    Ok(Layout::at_home(home))
}

/// Absolute path of the current hood binary — the target every shim symlink
/// points at. We prefer the canonicalized path so symlinks resolve to a
/// stable location regardless of how hood was launched.
fn hood_binary_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolve current_exe")?;
    Ok(exe.canonicalize().unwrap_or(exe))
}

/// Names hood will respond to when invoked via a symlink. Mirrors
/// [`Tool::SHIMMABLE`] but lifted into a slice of `&'static str` for easy
/// matching against `argv[0]`.
#[must_use]
pub fn shim_names() -> Vec<&'static str> {
    Tool::SHIMMABLE.iter().map(|t| t.name()).collect()
}

/// If `argv0` (basename) is a shimmed tool name, return the matching tool.
///
/// Used by `main.rs` to translate `npm install foo` into the `hood npm install foo`
/// dispatch path when hood was invoked through one of its busybox links.
#[must_use]
pub fn tool_from_argv0(argv0: &str) -> Option<Tool> {
    // Strip a trailing ".exe" (Windows) for matching purposes.
    let base = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let stripped = base.strip_suffix(".exe").unwrap_or(base);
    Tool::SHIMMABLE
        .iter()
        .copied()
        .find(|t| t.name() == stripped)
}

/// Run the installer:
/// 1. Probe `PATH` for each supported tool.
/// 2. Symlink `~/.hood/bin/<tool>` to the current hood binary for every tool found.
/// 3. Add the shim directory to the front of `PATH` in every detected shell
///    rc file, bracketed by stable sentinel markers.
///
/// `force` re-creates symlinks even when they already exist and resolve
/// correctly (otherwise correct existing links are left alone).
///
/// # Errors
/// Surfaces filesystem errors and missing-HOME conditions; partial state is
/// possible if a write fails mid-loop, but each operation is itself atomic
/// (symlink-and-rename for links; append-or-replace bracketed block for rc).
pub fn install(force: bool) -> Result<i32> {
    let layout = layout_default()?;
    let hood_bin = hood_binary_path()?;
    let report = install_at(&layout, &hood_bin, force, std::env::consts::OS)?;
    print_install_report(&layout, &hood_bin, &report);
    Ok(0)
}

/// Summary of what `install_at` did. Captured separately so tests can assert
/// outcomes without parsing stderr.
#[derive(Debug, Default)]
pub struct InstallReport {
    /// Tool names that received a symlink in this run.
    pub installed: Vec<&'static str>,
    /// Tool names skipped because the binary wasn't on `PATH`.
    pub skipped: Vec<&'static str>,
    /// Shell rc files that were updated.
    pub touched_files: Vec<PathBuf>,
}

/// Install hood shims using an explicit [`Layout`] and hood binary path.
///
/// The public [`install`] derives the layout from the user's
/// real home and passes [`std::env::consts::OS`]. Tests should use this entry
/// point.
///
/// `os` gates which tools are candidates: a tool is shimmed when it is present
/// on `PATH` (it demonstrably exists), or reported as skipped when it is absent
/// but [plausible][`Tool::plausible_on`] for `os`. Tools that are both absent
/// and implausible for the platform (pacman on macOS) are ignored outright, so
/// the report stays relevant to the machine it ran on.
///
/// # Errors
/// Filesystem errors creating the shim directory, symlinking, or writing
/// shell rc files.
pub fn install_at(
    layout: &Layout,
    hood_bin: &Path,
    force: bool,
    os: &str,
) -> Result<InstallReport> {
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    install_at_with_path(layout, hood_bin, force, os, &search_path)
}

fn install_at_with_path(
    layout: &Layout,
    hood_bin: &Path,
    force: bool,
    os: &str,
    search_path: &OsStr,
) -> Result<InstallReport> {
    fs::create_dir_all(&layout.shim_dir)
        .with_context(|| format!("create shim dir {}", layout.shim_dir.display()))?;

    let mut report = InstallReport::default();
    for tool in Tool::SHIMMABLE {
        let name = tool.name();
        if is_tool_present(name, &layout.shim_dir, search_path) {
            // Present on PATH — it exists here, so shim it whatever the platform.
            install_link(&layout.shim_dir, name, hood_bin, force)
                .with_context(|| format!("install shim for {name}"))?;
            report.installed.push(name);
        } else if tool.plausible_on(os) {
            // Absent but appropriate for this OS — surface it so the user knows
            // hood will cover it once the tool is installed.
            report.skipped.push(name);
        }
        // Absent and implausible for this OS: not a candidate; leave it unlisted.
    }

    for rc in detect_shell_rcs_at(&layout.home) {
        write_shell_block(&rc, &layout.shim_dir)
            .with_context(|| format!("update {}", rc.display()))?;
        report.touched_files.push(rc);
    }
    Ok(report)
}

fn print_install_report(layout: &Layout, hood_bin: &Path, report: &InstallReport) {
    eprintln!("hood install complete.");
    eprintln!("  shim dir:  {}", layout.shim_dir.display());
    eprintln!("  hood bin:  {}", hood_bin.display());
    if !report.installed.is_empty() {
        eprintln!("  installed: {}", report.installed.join(", "));
    }
    if !report.skipped.is_empty() {
        eprintln!("  skipped (not on PATH): {}", report.skipped.join(", "));
    }
    if report.touched_files.is_empty() {
        eprintln!(
            "\nNo shell rc file was updated. Add this line to your shell rc manually:\n  export PATH={}:\"$PATH\"",
            posix_quote(&layout.shim_dir.to_string_lossy())
        );
    } else {
        eprintln!("  updated rc files:");
        for f in &report.touched_files {
            eprintln!("    {}", f.display());
        }
        eprintln!("\nRestart your shell (or `source` the rc file) to activate.");
    }
}

/// Remove hood's symlinks and any sentinel-bracketed blocks in shell rc files.
/// Idempotent — safe to run when nothing is installed.
///
/// Only files in the shim directory whose link target's basename is `hood`
/// are removed. Anything else the user has placed there is left alone.
///
/// # Errors
/// Surfaces filesystem errors on link removal and rc-file rewrites.
pub fn uninstall() -> Result<i32> {
    let layout = layout_default()?;
    let report = uninstall_at(&layout)?;
    eprintln!("hood uninstall complete.");
    eprintln!("  shims removed: {}", report.removed_shims);
    if !report.cleaned_files.is_empty() {
        eprintln!("  cleaned rc files:");
        for f in &report.cleaned_files {
            eprintln!("    {}", f.display());
        }
    }
    Ok(0)
}

/// Summary of what `uninstall_at` did.
#[derive(Debug, Default)]
pub struct UninstallReport {
    /// Count of shim files removed from the shim directory.
    pub removed_shims: usize,
    /// Shell rc files that had their hood block stripped.
    pub cleaned_files: Vec<PathBuf>,
}

/// Uninstall hood shims using an explicit [`Layout`]. Tests should use this
/// entry point.
///
/// # Errors
/// Filesystem errors when reading the shim directory or rewriting rc files.
pub fn uninstall_at(layout: &Layout) -> Result<UninstallReport> {
    let mut report = UninstallReport::default();
    if layout.shim_dir.is_dir() {
        for entry in fs::read_dir(&layout.shim_dir)
            .with_context(|| format!("read {}", layout.shim_dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!("read directory entry in {}", layout.shim_dir.display())
            })?;
            let path = entry.path();
            if is_shim_name(&path) && is_hood_shim(&path) {
                fs::remove_file(&path)
                    .with_context(|| format!("remove shim {}", path.display()))?;
                report.removed_shims = report.removed_shims.saturating_add(1);
            }
        }
        drop(fs::remove_dir(&layout.shim_dir));
        if let Some(parent) = layout.shim_dir.parent() {
            drop(fs::remove_dir(parent));
        }
    }
    for rc in detect_shell_rcs_at(&layout.home) {
        if remove_shell_block(&rc).context("strip shim block")? {
            report.cleaned_files.push(rc);
        }
    }
    Ok(report)
}

/// Restrict uninstall to names hood actually installs. A user may keep other
/// links in the same directory; their target being named `hood` is not enough
/// to make them ours.
fn is_shim_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.strip_suffix(".exe").unwrap_or(name);
    Tool::SHIMMABLE.iter().any(|tool| tool.name() == name)
}

/// Probe whether a tool binary exists somewhere on `PATH` *other than* our
/// own shim directory (to avoid claiming success based on stale shims).
fn is_tool_present(name: &str, skip_dir: &Path, search_path: &OsStr) -> bool {
    for entry in std::env::split_paths(search_path) {
        if entry == skip_dir {
            continue;
        }
        let candidate = entry.join(name);
        if !candidate.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = candidate.metadata()
                && meta.permissions().mode() & 0o111 != 0
            {
                return true;
            }
        }
        #[cfg(not(unix))]
        return true;
    }
    false
}

/// True iff `path` is a hood-managed shim — i.e. a symlink (or hardlink/copy
/// on Windows) that ultimately resolves to a file named `hood`. We never
/// remove anything outside this contract.
fn is_hood_shim(path: &Path) -> bool {
    // Symlink case (Unix + Windows).
    if let Ok(target) = fs::read_link(path) {
        return target
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("hood") || s.eq_ignore_ascii_case("hood.exe"));
    }
    // Hard-linked / copied fallback (Windows): match by canonicalized target
    // path against our own current_exe.
    let Ok(canon) = path.canonicalize() else {
        return false;
    };
    let Ok(me) = std::env::current_exe().and_then(|p| p.canonicalize()) else {
        return false;
    };
    canon == me
}

#[cfg(unix)]
fn install_link(dir: &Path, tool: &str, hood_bin: &Path, force: bool) -> Result<()> {
    let link = dir.join(tool);
    match fs::symlink_metadata(&link) {
        Ok(_) => {
            // If it's a hood shim already pointing at the right target, leave it.
            if !force
                && let Ok(current) = fs::read_link(&link)
                && current == hood_bin
            {
                return Ok(());
            }
            if !is_hood_shim(&link) {
                return Err(anyhow::anyhow!(
                    "refusing to replace unrelated file {}",
                    link.display(),
                ));
            }
            fs::remove_file(&link).with_context(|| format!("remove stale {}", link.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("inspect {}", link.display())),
    }
    std::os::unix::fs::symlink(hood_bin, &link)
        .with_context(|| format!("symlink {} -> {}", link.display(), hood_bin.display()))
}

#[cfg(windows)]
fn install_link(dir: &Path, tool: &str, hood_bin: &Path, force: bool) -> Result<()> {
    // Windows: try a hard link first (no admin needed, single inode, no
    // symlink privilege required). Fall back to copying.
    let link = dir.join(format!("{tool}.exe"));
    if link.exists() && !force {
        return Ok(());
    }
    if link.exists() {
        let _ = fs::remove_file(&link);
    }
    if fs::hard_link(hood_bin, &link).is_ok() {
        return Ok(());
    }
    fs::copy(hood_bin, &link)
        .with_context(|| format!("copy {} -> {}", hood_bin.display(), link.display()))?;
    Ok(())
}

/// Detect candidate shell rc files relative to a given home directory.
///
/// POSIX rc files (`.zshrc`, `.bashrc`, `.bash_profile`, `.profile`) are added
/// when they exist. Fish config (`~/.config/fish/config.fish`) is added when
/// it exists *or* when its parent directory exists — fish users commonly run
/// without a config.fish until first customization, and `hood install` should
/// create one rather than waiting for them.
fn detect_shell_rcs_at(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for rc in [".zshrc", ".bashrc", ".bash_profile", ".profile"] {
        let path = home.join(rc);
        if path.exists() {
            out.push(path);
        }
    }
    let fish = home.join(".config").join("fish").join("config.fish");
    if fish.exists() || fish.parent().is_some_and(Path::is_dir) {
        out.push(fish);
    }
    out
}

/// POSIX single-quote a string so every character is literal — spaces, `$`,
/// `"`, `;` and the like can't break the surrounding rc line or inject shell
/// text. An embedded single quote becomes `'\''` (close, escaped quote, reopen).
fn posix_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// fish single-quote: inside `'…'` fish treats only `\` and `'` specially, so
/// escape just those two. Spaces and `$` are already literal.
fn fish_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\\' || ch == '\'' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('\'');
    out
}

/// Add (or replace) the hood-marked block in `rc_file`. Idempotent.
fn write_shell_block(rc_file: &Path, shim_dir: &Path) -> Result<()> {
    let is_fish = rc_file
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("fish"));

    let existing = match fs::read_to_string(rc_file) {
        Ok(existing) => existing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("read {}", rc_file.display())),
    };
    let mut filtered = strip_block(&existing);

    let block = if is_fish {
        let dir = fish_quote(&shim_dir.to_string_lossy());
        format!(
            "{MARK_BEGIN}\nif type -q fish_add_path\n    fish_add_path -p {dir}\nelse\n    set -gx PATH {dir} $PATH\nend\n{MARK_END}\n",
        )
    } else {
        // Single-quote the literal dir (so spaces, `$`, `"` stay literal) and
        // concatenate the still-expanding "$PATH".
        let dir = posix_quote(&shim_dir.to_string_lossy());
        format!("{MARK_BEGIN}\nexport PATH={dir}:\"$PATH\"\n{MARK_END}\n")
    };

    if !filtered.is_empty() && !filtered.ends_with('\n') {
        filtered.push('\n');
    }
    filtered.push_str(&block);

    if let Some(parent) = rc_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create shell config directory {}", parent.display()))?;
    }
    atomic_write(rc_file, filtered.as_bytes())
        .with_context(|| format!("write {}", rc_file.display()))
}

/// Remove the hood-marked block, if any. Returns whether anything changed.
fn remove_shell_block(rc_file: &Path) -> Result<bool> {
    let existing = match fs::read_to_string(rc_file) {
        Ok(existing) => existing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("read {}", rc_file.display())),
    };
    let stripped = strip_block(&existing);
    if stripped == existing {
        return Ok(false);
    }
    atomic_write(rc_file, stripped.as_bytes())
        .with_context(|| format!("rewrite {}", rc_file.display()))?;
    Ok(true)
}

/// Remove everything between `MARK_BEGIN` and `MARK_END` (inclusive), supporting
/// multiple blocks (defensive against hand-pasted duplicates).
fn strip_block(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut pending = String::new();
    let mut in_block = false;
    for line in input.lines() {
        let t = line.trim();
        if !in_block && t == MARK_BEGIN {
            in_block = true;
            pending.push_str(line);
            pending.push('\n');
            continue;
        }
        if in_block {
            pending.push_str(line);
            pending.push('\n');
            if t == MARK_END {
                in_block = false;
                pending.clear();
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    // An unmatched begin marker may be user-authored text or a truncated file.
    // Never interpret it as permission to discard the remainder of the rc file.
    if in_block {
        out.push_str(&pending);
    }
    if !input.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    // Preserve dotfile-manager symlinks by replacing their target, not the
    // symlink itself. Canonicalization also makes the destination directory
    // unambiguous before the temporary file is created.
    let destination = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::canonicalize(path)
            .with_context(|| format!("resolve shell config symlink {}", path.display()))?,
        Ok(_) => path.to_path_buf(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => path.to_path_buf(),
        Err(e) => return Err(e).with_context(|| format!("inspect {}", path.display())),
    };
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let permissions = fs::metadata(&destination)
        .ok()
        .map(|metadata| metadata.permissions());

    // tempfile uses an unpredictable create-new name, closing the predictable
    // `<rc>.hood-tmp` symlink-clobber race. Persist is an atomic rename within
    // the destination directory.
    let mut tmp = tempfile::Builder::new()
        .prefix(".hood-rc-")
        .tempfile_in(parent)
        .with_context(|| format!("create temporary file in {}", parent.display()))?;
    tmp.write_all(bytes)
        .context("write temporary shell config")?;
    tmp.flush().context("flush temporary shell config")?;
    tmp.as_file()
        .sync_all()
        .context("sync temporary shell config")?;
    if let Some(permissions) = permissions {
        tmp.as_file()
            .set_permissions(permissions)
            .context("preserve shell config permissions")?;
    }
    tmp.persist(&destination)
        .map_err(|e| e.error)
        .with_context(|| format!("replace {}", destination.display()))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn tool_from_argv0_matches_basename() {
        assert_eq!(tool_from_argv0("npm"), Some(Tool::Npm));
        assert_eq!(tool_from_argv0("npx"), Some(Tool::Npx));
        assert_eq!(tool_from_argv0("pip3"), Some(Tool::Pip3));
        assert_eq!(tool_from_argv0("uvx"), Some(Tool::Uvx));
        assert_eq!(tool_from_argv0("pdm"), Some(Tool::Pdm));
        assert_eq!(tool_from_argv0("/usr/local/bin/cargo"), Some(Tool::Cargo));
        assert_eq!(tool_from_argv0("./brew"), Some(Tool::Brew));
        assert_eq!(tool_from_argv0("npm.exe"), Some(Tool::Npm));
    }

    #[test]
    fn tool_from_argv0_rejects_hood_itself() {
        // The hood binary's own name must NOT match a shimmable tool.
        assert_eq!(tool_from_argv0("hood"), None);
        assert_eq!(tool_from_argv0("/usr/local/bin/hood"), None);
    }

    #[test]
    fn tool_from_argv0_rejects_unknown_names() {
        assert_eq!(tool_from_argv0("rsync"), None);
        assert_eq!(tool_from_argv0(""), None);
    }

    #[test]
    fn strip_block_removes_marked_section() {
        let input = format!("before\n{MARK_BEGIN}\nexport PATH=...\n{MARK_END}\nafter\n");
        assert_eq!(strip_block(&input), "before\nafter\n");
    }

    #[test]
    fn strip_block_removes_multiple_marked_sections() {
        let input = format!("a\n{MARK_BEGIN}\nx\n{MARK_END}\nb\n{MARK_BEGIN}\ny\n{MARK_END}\nc\n");
        assert_eq!(strip_block(&input), "a\nb\nc\n");
    }

    #[test]
    fn strip_block_preserves_unterminated_marker_and_trailing_content() {
        let input = format!("before\n{MARK_BEGIN}\nuser data\n");
        assert_eq!(strip_block(&input), input);
    }

    #[test]
    fn strip_block_is_noop_on_unmarked_input() {
        let input = "alpha\nbeta\ngamma\n";
        assert_eq!(strip_block(input), input);
    }

    #[test]
    fn shell_quoting_neutralizes_special_chars() {
        // POSIX: a space, `$`, and `"` must all end up literal, and an embedded
        // single quote must be escaped without breaking out of the quoting.
        assert_eq!(posix_quote("/home/a b/.hood/bin"), "'/home/a b/.hood/bin'");
        assert_eq!(posix_quote("/x/$y/bin"), "'/x/$y/bin'");
        assert_eq!(posix_quote("/x/a'b/bin"), "'/x/a'\\''b/bin'");
        // fish: only `\` and `'` are special inside single quotes.
        assert_eq!(fish_quote("/home/a b/.hood/bin"), "'/home/a b/.hood/bin'");
        assert_eq!(fish_quote(r"/x/a\b/bin"), r"'/x/a\\b/bin'");
        assert_eq!(fish_quote("/x/a'b/bin"), r"'/x/a\'b/bin'");
    }

    #[test]
    fn write_and_strip_block_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".zshrc");
        fs::write(&rc, "echo hi\n").unwrap();
        let shim = dir.path().join("hood-bin");

        write_shell_block(&rc, &shim).unwrap();
        let after_add = fs::read_to_string(&rc).unwrap();
        assert!(after_add.contains(MARK_BEGIN));
        assert!(after_add.contains(shim.to_str().unwrap()));

        write_shell_block(&rc, &shim).unwrap();
        let after_replace = fs::read_to_string(&rc).unwrap();
        assert_eq!(
            after_replace.matches(MARK_BEGIN).count(),
            1,
            "block must be replaced, not duplicated"
        );

        assert!(remove_shell_block(&rc).unwrap());
        let after_remove = fs::read_to_string(&rc).unwrap();
        assert_eq!(after_remove, "echo hi\n");

        assert!(!remove_shell_block(&rc).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn install_link_creates_symlink_to_hood() {
        let tmp = tempfile::tempdir().unwrap();
        let hood = tmp.path().join("hood");
        fs::write(&hood, b"#!/bin/sh\n").unwrap();
        let dir = tmp.path().join("bin");
        fs::create_dir(&dir).unwrap();

        install_link(&dir, "npm", &hood, true).unwrap();
        let link = dir.join("npm");
        assert!(is_hood_shim(&link));
        let target = fs::read_link(&link).unwrap();
        assert_eq!(target, hood);
    }

    #[cfg(unix)]
    #[test]
    fn install_link_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let hood = tmp.path().join("hood");
        fs::write(&hood, b"#!/bin/sh\n").unwrap();
        let dir = tmp.path().join("bin");
        fs::create_dir(&dir).unwrap();

        install_link(&dir, "npm", &hood, false).unwrap();
        install_link(&dir, "npm", &hood, false).unwrap();
        let link = dir.join("npm");
        assert!(is_hood_shim(&link));
    }

    #[cfg(unix)]
    #[test]
    fn is_hood_shim_rejects_unrelated_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let other = tmp.path().join("rsync");
        fs::write(&other, b"").unwrap();
        let link = tmp.path().join("npm");
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert!(!is_hood_shim(&link));
    }

    #[cfg(unix)]
    #[test]
    fn is_hood_shim_handles_unreadable_path() {
        // Nonexistent paths must return false, not error.
        assert!(!is_hood_shim(Path::new("/this/does/not/exist/12345")));
    }

    #[test]
    fn shim_names_lists_every_tool_except_exec() {
        let names = shim_names();
        assert!(names.contains(&"npm"));
        assert!(names.contains(&"cargo"));
        assert!(names.contains(&"brew"));
        assert!(!names.contains(&"exec"));
        assert!(!names.contains(&"hood"));
    }

    #[test]
    fn detect_shell_rcs_picks_up_existing_files() {
        let tmp = tempfile::tempdir().unwrap();
        // Empty home → nothing detected.
        assert!(detect_shell_rcs_at(tmp.path()).is_empty());

        fs::write(tmp.path().join(".zshrc"), "").unwrap();
        fs::write(tmp.path().join(".bashrc"), "").unwrap();
        let rcs = detect_shell_rcs_at(tmp.path());
        assert!(rcs.iter().any(|p| p.ends_with(".zshrc")));
        assert!(rcs.iter().any(|p| p.ends_with(".bashrc")));
        // Files we didn't create shouldn't show up.
        assert!(!rcs.iter().any(|p| p.ends_with(".profile")));
    }

    #[test]
    fn detect_shell_rcs_includes_fish_when_parent_dir_exists() {
        // Fish users may not have a config.fish yet; we still want to write one.
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join(".config").join("fish")).unwrap();
        let rcs = detect_shell_rcs_at(tmp.path());
        assert!(rcs.iter().any(|p| p.ends_with("config.fish")));
    }

    #[test]
    fn detect_shell_rcs_skips_fish_when_no_config_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let rcs = detect_shell_rcs_at(tmp.path());
        assert!(!rcs.iter().any(|p| p.ends_with("config.fish")));
    }

    #[cfg(unix)]
    fn fake_hood_binary(dir: &Path) -> PathBuf {
        let p = dir.join("hood");
        fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    fn fake_tool_binary(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn install_creates_symlinks_for_tools_on_path() {
        let tmp = tempfile::tempdir().unwrap();
        // Stage a fake PATH containing only a `cargo` binary, then run install.
        let bin = tmp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fake_tool_binary(&bin, "cargo");

        let hood = fake_hood_binary(tmp.path());

        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join(".zshrc"), "echo hi\n").unwrap();
        let layout = Layout::at_home(&home);

        let report = install_at_with_path(&layout, &hood, false, "linux", bin.as_os_str()).unwrap();
        assert!(report.installed.contains(&"cargo"));
        assert!(report.skipped.contains(&"npm")); // not on staged PATH
        assert!(report.touched_files.iter().any(|p| p.ends_with(".zshrc")));

        // Symlink was created and points at our fake hood.
        let cargo_link = layout.shim_dir.join("cargo");
        assert!(is_hood_shim(&cargo_link));
        let target = fs::read_link(&cargo_link).unwrap();
        assert_eq!(target, hood);

        // .zshrc got the marker block.
        let zshrc = fs::read_to_string(home.join(".zshrc")).unwrap();
        assert!(zshrc.contains(MARK_BEGIN));
        assert!(zshrc.contains(layout.shim_dir.to_str().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn install_omits_platform_inappropriate_tools() {
        let tmp = tempfile::tempdir().unwrap();
        // Empty PATH: nothing is present, so the skipped list is purely the set
        // of tools plausible for the OS we pass.
        let empty_path = std::ffi::OsStr::new("");
        let hood = fake_hood_binary(tmp.path());
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let layout = Layout::at_home(&home);

        // On macOS, Linux/BSD system managers are not candidates at all.
        let mac = install_at_with_path(&layout, &hood, false, "macos", empty_path).unwrap();
        for absent in ["pacman", "yay", "makepkg", "dnf", "rpm", "apk", "pkg"] {
            assert!(
                !mac.skipped.contains(&absent),
                "{absent} must not be listed on macOS",
            );
        }
        assert!(mac.skipped.contains(&"brew"), "brew is a macOS candidate");
        assert!(mac.skipped.contains(&"npm"), "npm is cross-platform");

        // On Linux the Arch/RPM/Alpine managers are candidates; FreeBSD's pkg
        // is not.
        let linux = install_at_with_path(&layout, &hood, false, "linux", empty_path).unwrap();
        for present in ["pacman", "dnf", "rpm", "apk", "brew"] {
            assert!(
                linux.skipped.contains(&present),
                "{present} should be a Linux candidate",
            );
        }
        assert!(!linux.skipped.contains(&"pkg"), "pkg is BSD-only");
    }

    #[cfg(unix)]
    #[test]
    fn install_shims_present_tool_even_when_implausible() {
        // "if they exist" wins over platform plausibility: a binary actually on
        // PATH gets shimmed regardless of the OS gate.
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fake_tool_binary(&bin, "pacman");

        let hood = fake_hood_binary(tmp.path());
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let layout = Layout::at_home(&home);

        // pacman is implausible on macOS, but it's present, so it's installed.
        let report = install_at_with_path(&layout, &hood, false, "macos", bin.as_os_str()).unwrap();
        assert!(report.installed.contains(&"pacman"));
        assert!(!report.skipped.contains(&"pacman"));
    }

    #[cfg(unix)]
    #[test]
    fn install_then_uninstall_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fake_tool_binary(&bin, "go");
        fake_tool_binary(&bin, "curl");

        let hood = fake_hood_binary(tmp.path());

        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let zshrc = home.join(".zshrc");
        fs::write(&zshrc, "echo before\n").unwrap();
        let layout = Layout::at_home(&home);

        // Install twice — second call should be idempotent.
        install_at_with_path(&layout, &hood, false, "linux", bin.as_os_str()).unwrap();
        install_at_with_path(&layout, &hood, false, "linux", bin.as_os_str()).unwrap();
        let after_install = fs::read_to_string(&zshrc).unwrap();
        assert_eq!(after_install.matches(MARK_BEGIN).count(), 1);
        assert!(layout.shim_dir.join("go").exists());
        assert!(layout.shim_dir.join("curl").exists());

        // Uninstall puts the file back; second call is a noop.
        let report = uninstall_at(&layout).unwrap();
        assert!(report.removed_shims >= 2);
        let after_uninstall = fs::read_to_string(&zshrc).unwrap();
        assert_eq!(after_uninstall, "echo before\n");

        let report2 = uninstall_at(&layout).unwrap();
        assert_eq!(report2.removed_shims, 0);
    }

    #[cfg(unix)]
    #[test]
    fn install_writes_fish_block_when_fish_dir_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let empty_path = std::ffi::OsStr::new("");
        let hood = fake_hood_binary(tmp.path());

        let home = tmp.path().join("home");
        let fish_dir = home.join(".config").join("fish");
        fs::create_dir_all(&fish_dir).unwrap();
        let layout = Layout::at_home(&home);

        install_at_with_path(&layout, &hood, false, "linux", empty_path).unwrap();
        let fish_cfg = fish_dir.join("config.fish");
        let content = fs::read_to_string(&fish_cfg).unwrap();
        assert!(content.contains("fish_add_path"));
        assert!(content.contains(layout.shim_dir.to_str().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn install_with_force_replaces_existing_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fake_tool_binary(&bin, "npm");

        let hood1 = fake_hood_binary(tmp.path());
        let hood2 = {
            let p = tmp.path().join("hood2");
            fs::copy(&hood1, &p).unwrap();
            p
        };

        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let layout = Layout::at_home(&home);

        install_at_with_path(&layout, &hood1, false, "linux", bin.as_os_str()).unwrap();
        let target1 = fs::read_link(layout.shim_dir.join("npm")).unwrap();
        assert_eq!(target1, hood1);

        install_at_with_path(&layout, &hood2, true, "linux", bin.as_os_str()).unwrap();
        let target2 = fs::read_link(layout.shim_dir.join("npm")).unwrap();
        assert_eq!(target2, hood2);
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_leaves_unrelated_files_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = Layout::at_home(tmp.path());
        fs::create_dir_all(&layout.shim_dir).unwrap();

        // A non-hood file in the shim dir that uninstall must not touch.
        let stranger = layout.shim_dir.join("readme.txt");
        fs::write(&stranger, b"unrelated\n").unwrap();

        // A real hood shim.
        let hood = fake_hood_binary(tmp.path());
        std::os::unix::fs::symlink(&hood, layout.shim_dir.join("npm")).unwrap();

        let report = uninstall_at(&layout).unwrap();
        assert_eq!(report.removed_shims, 1);
        assert!(stranger.exists(), "non-hood file must survive uninstall");
    }
}
