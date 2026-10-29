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
//! On Windows an unprivileged symlink needs Developer Mode, so hood falls back
//! to a hard link or, across volumes, a copy; those two do not follow an
//! upgrade of hood.exe, and `hood install` re-links them when run again.
//! Windows has no rc file; the shim directory is instead
//! prepended to `$env:Path` from both PowerShell profiles, which is also what
//! lets a user-level shim shadow `C:\Windows\System32\curl.exe`.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::tools::{Tool, resolve_binary_in_path};

/// Sentinel marker bookending hood's edits in a shell rc file.
const MARK_BEGIN: &str = "# >>> hood shim (added by `hood install`) >>>";
const MARK_END: &str = "# <<< hood shim <<<";

/// Resolve the directory where hood installs its busybox-style symlinks.
/// `~/.hood/bin`.
///
/// # Errors
/// Returns an error if `$HOME` cannot be resolved.
pub fn shim_dir() -> Result<PathBuf> {
    Ok(layout_default()?.shim_dir)
}

/// Where hood lays out its on-disk state during install/uninstall. Pulled
/// into a struct (rather than threaded as separate args) so tests can build
/// a synthetic layout pointing at a tempdir.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    /// User's home directory; rc files are discovered relative to this.
    pub(crate) home: PathBuf,
    /// User's Documents folder, where PowerShell keeps its profiles.
    pub(crate) documents: PathBuf,
    /// Directory the busybox-style shims live in.
    pub(crate) shim_dir: PathBuf,
}

impl Layout {
    /// Layout rooted at an arbitrary `home`. The shim directory follows the
    /// `<home>/.hood/bin` convention used by the platform-default layout.
    #[must_use]
    pub(crate) fn at_home(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let documents = home.join("Documents");
        let shim_dir = home.join(".hood").join("bin");
        Self {
            home,
            documents,
            shim_dir,
        }
    }
}

/// Resolve the platform default layout: `HOME` plus the standard
/// `<home>/.hood/bin` shim directory. The Documents folder follows the
/// platform's own answer, since Windows lets users and folder redirection move it.
fn layout_default() -> Result<Layout> {
    let home = dirs::home_dir().context("HOME not set; cannot resolve home directory")?;
    let mut layout = Layout::at_home(home);
    if let Some(documents) = dirs::document_dir() {
        layout.documents = documents;
    }
    Ok(layout)
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
    Tool::from_name(base.strip_suffix(".exe").unwrap_or(base))
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
/// (symlink-and-rename for Unix links; append-or-replace bracketed block for rc).
pub fn install(force: bool) -> Result<()> {
    let layout = layout_default()?;
    let hood_bin = std::env::current_exe().context("resolve current_exe")?;
    // A canonical target keeps every shim stable regardless of how Hood ran.
    let hood_bin = hood_bin.canonicalize().unwrap_or(hood_bin);
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    let report = install_at(
        &layout,
        &hood_bin,
        force,
        std::env::consts::OS,
        &search_path,
    )?;
    print_install_report(&layout, &hood_bin, &report);
    Ok(())
}

/// Summary of what `install_at` did. Captured separately so tests can assert
/// outcomes without parsing stderr.
#[derive(Debug, Default)]
pub(crate) struct InstallReport {
    /// Tool names that received a symlink in this run.
    pub(crate) installed: Vec<&'static str>,
    /// Tool names skipped because the binary wasn't on `PATH`.
    pub(crate) skipped: Vec<&'static str>,
    /// Shell rc files that now carry the hood block.
    pub(crate) touched_files: Vec<PathBuf>,
    /// Shell rc files hood left alone, and why.
    pub(crate) untouched_files: Vec<(PathBuf, &'static str)>,
}

/// Install hood shims using an explicit [`Layout`], hood binary path, and
/// `search_path` (the `PATH` probed for each tool).
///
/// [`install`] derives the layout from the user's real home and
/// passes [`std::env::consts::OS`] and `$PATH`. Tests should use this entry
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
pub(crate) fn install_at(
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
        // Look past our own shim directory so a stale shim is not mistaken
        // for the tool itself.
        if resolve_binary_in_path(name, search_path, Some(&layout.shim_dir), None).is_some() {
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

    for rc in shell_configs(layout) {
        match write_shell_block(&rc, &layout.shim_dir)
            .with_context(|| format!("update {}", rc.display()))?
        {
            Outcome::Written | Outcome::Unchanged => report.touched_files.push(rc),
            Outcome::Skipped(why) => report.untouched_files.push((rc, why)),
        }
    }
    Ok(report)
}

/// Warn about each shell config hood would not edit; the user has to.
fn print_untouched(untouched: &[(PathBuf, &str)]) {
    for (file, why) in untouched {
        eprintln!("  left alone: {} — {why}", file.display());
    }
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
    print_untouched(&report.untouched_files);
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
        if cfg!(windows) {
            eprintln!(
                "\nRestart PowerShell to activate. cmd.exe is not covered; put {} first in your PATH for it.",
                layout.shim_dir.display()
            );
            #[cfg(windows)]
            warn_if_profiles_blocked();
        } else {
            eprintln!("\nRestart your shell (or `source` the rc file) to activate.");
        }
    }
}

/// Windows PowerShell runs no profile at all under the `Restricted` execution
/// policy, the Windows client default, and no unsigned one under `AllSigned`.
/// Say so now, rather than leave an error on every PowerShell launch.
#[cfg(windows)]
fn warn_if_profiles_blocked() {
    let Ok(output) = std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-ExecutionPolicy",
        ])
        .output()
    else {
        return;
    };
    let policy = String::from_utf8_lossy(&output.stdout);
    let policy = policy.trim();
    if matches!(policy, "Restricted" | "AllSigned") {
        eprintln!(
            "\nWindows PowerShell's execution policy is {policy}, so it will not run the profile hood wrote.\n\
             Allow it with `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`."
        );
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
pub fn uninstall() -> Result<()> {
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
    print_untouched(&report.untouched_files);
    Ok(())
}

/// Summary of what `uninstall_at` did.
#[derive(Debug, Default)]
pub(crate) struct UninstallReport {
    /// Count of shim files removed from the shim directory.
    pub(crate) removed_shims: usize,
    /// Shell rc files that had their hood block stripped.
    pub(crate) cleaned_files: Vec<PathBuf>,
    /// Shell rc files hood left alone, and why.
    pub(crate) untouched_files: Vec<(PathBuf, &'static str)>,
}

/// Uninstall hood shims using an explicit [`Layout`]. Tests should use this
/// entry point.
///
/// # Errors
/// Filesystem errors when reading the shim directory or rewriting rc files.
pub(crate) fn uninstall_at(layout: &Layout) -> Result<UninstallReport> {
    let mut report = UninstallReport::default();
    if layout.shim_dir.is_dir() {
        for entry in fs::read_dir(&layout.shim_dir)
            .with_context(|| format!("read {}", layout.shim_dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!("read directory entry in {}", layout.shim_dir.display())
            })?;
            let path = entry.path();
            // Only names hood installs: a user may keep other links here, and
            // their target being named `hood` is not enough to make them ours.
            let shim_name = path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| tool_from_argv0(name).is_some());
            if shim_name && is_hood_shim(&path) {
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
    for rc in shell_configs(layout) {
        match remove_shell_block(&rc).context("strip shim block")? {
            Outcome::Written => report.cleaned_files.push(rc),
            Outcome::Unchanged => {}
            Outcome::Skipped(why) => report.untouched_files.push((rc, why)),
        }
    }
    Ok(report)
}

/// True iff `path` is a hood-managed shim. We never remove anything outside
/// this contract.
///
/// A symlink qualifies when it resolves to a file named `hood`. On Windows a
/// hard link or copy carries no pointer back to hood, and after an upgrade
/// not even its bytes, so there a regular file qualifies: hood owns the shim
/// directory and only ever writes shim-named executables into it, which is
/// the same contract rustup's proxies rely on. Callers restrict the name.
fn is_hood_shim(path: &Path) -> bool {
    if let Ok(target) = fs::read_link(path) {
        return target
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("hood") || s.eq_ignore_ascii_case("hood.exe"));
    }
    cfg!(windows) && fs::metadata(path).is_ok_and(|meta| meta.is_file())
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
                bail!("refusing to replace unrelated file {}", link.display());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("inspect {}", link.display())),
    }
    // Built beside the shim and renamed over it, so a replaced shim is never
    // missing, even if this fails halfway.
    let staged = dir.join(format!(".{tool}.hood-new"));
    match fs::remove_file(&staged) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("remove leftover {}", staged.display()));
        }
        _ => {}
    }
    std::os::unix::fs::symlink(hood_bin, &staged)
        .with_context(|| format!("symlink {} -> {}", staged.display(), hood_bin.display()))?;
    fs::rename(&staged, &link).with_context(|| format!("move {} into place", link.display()))
}

#[cfg(windows)]
fn install_link(dir: &Path, tool: &str, hood_bin: &Path, force: bool) -> Result<()> {
    let link = dir.join(format!("{tool}.exe"));
    match fs::symlink_metadata(&link) {
        Ok(_) => {
            if !is_hood_shim(&link) {
                bail!("refusing to replace unrelated file {}", link.display());
            }
            // Upgrading hood replaces hood.exe. A symlink follows that; a hard
            // link or copy keeps the old bytes, so it is re-linked here.
            let current = fs::read_link(&link).is_ok_and(|target| target == hood_bin)
                || same_file::is_same_file(&link, hood_bin).unwrap_or(false);
            if !force && current {
                return Ok(());
            }
            fs::remove_file(&link).with_context(|| format!("remove stale {}", link.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("inspect {}", link.display())),
    }
    // A symlink needs Developer Mode or a privilege; a hard link needs neither
    // but must share a volume; a copy always works.
    if std::os::windows::fs::symlink_file(hood_bin, &link).is_ok()
        || fs::hard_link(hood_bin, &link).is_ok()
    {
        return Ok(());
    }
    fs::copy(hood_bin, &link)
        .with_context(|| format!("copy {} -> {}", hood_bin.display(), link.display()))?;
    Ok(())
}

/// Shell startup files to edit for this platform: PowerShell profiles on
/// Windows, POSIX and fish rc files elsewhere.
fn shell_configs(layout: &Layout) -> Vec<PathBuf> {
    if cfg!(windows) {
        powershell_profiles(&layout.documents)
    } else {
        detect_shell_rcs_at(&layout.home)
    }
}

/// The per-user profiles of Windows PowerShell 5.1 and PowerShell 7, which
/// live under the user's Documents folder. Windows PowerShell ships with
/// every Windows, and PowerShell 7 is a plain install away, so both profiles
/// are written whether or not they exist yet; cmd.exe sessions are not covered.
fn powershell_profiles(documents: &Path) -> Vec<PathBuf> {
    ["WindowsPowerShell", "PowerShell"]
        .into_iter()
        .map(|shell| {
            documents
                .join(shell)
                .join("Microsoft.PowerShell_profile.ps1")
        })
        .collect()
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

/// PowerShell single-quote: only `'` is special inside `'…'`, written `''`.
fn powershell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// What editing one shell config came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The file now says what it should, and had to be rewritten to.
    Written,
    /// The file already said what it should.
    Unchanged,
    /// hood left the file alone, for this reason; the user has to look.
    Skipped(&'static str),
}

/// Read `rc_file`, strip any hood block, let `render` produce the new text,
/// and write it back if that changed anything. A missing file reads as empty.
///
/// A file hood cannot read as text, or whose markers do not pair up, is left
/// exactly as it is: rewriting either could destroy lines the user wrote.
fn edit_shell_config(rc_file: &Path, render: impl FnOnce(String) -> String) -> Result<Outcome> {
    let existing = match fs::read(rc_file) {
        Ok(existing) => existing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("read {}", rc_file.display())),
    };
    let Ok(existing) = String::from_utf8(existing) else {
        return Ok(Outcome::Skipped(
            "not UTF-8 text (a PowerShell profile saved as UTF-16?)",
        ));
    };
    let Some(stripped) = strip_block(&existing) else {
        return Ok(Outcome::Skipped(
            "its hood markers do not pair up; remove them by hand",
        ));
    };
    let updated = render(stripped);
    if updated == existing {
        return Ok(Outcome::Unchanged);
    }
    if let Some(parent) = rc_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create shell config directory {}", parent.display()))?;
    }
    atomic_write(rc_file, updated.as_bytes())
        .with_context(|| format!("write {}", rc_file.display()))?;
    Ok(Outcome::Written)
}

/// Add (or replace) the hood-marked block in `rc_file`. Idempotent.
fn write_shell_block(rc_file: &Path, shim_dir: &Path) -> Result<Outcome> {
    let extension = rc_file.extension().and_then(|e| e.to_str()).unwrap_or("");
    let block = if extension.eq_ignore_ascii_case("fish") {
        // `--path` sets this session's `$PATH` only: the default would store
        // the directory in a universal variable that outlives `hood uninstall`.
        let dir = fish_quote(&shim_dir.to_string_lossy());
        format!(
            "{MARK_BEGIN}\nif type -q fish_add_path\n    fish_add_path --path --prepend --move {dir}\nelse\n    set -gx PATH {dir} $PATH\nend\n{MARK_END}\n",
        )
    } else if extension.eq_ignore_ascii_case("ps1") {
        let dir = powershell_quote(&shim_dir.to_string_lossy());
        format!("{MARK_BEGIN}\n$env:Path = {dir} + ';' + $env:Path\n{MARK_END}\n")
    } else {
        // Single-quote the literal dir (so spaces, `$`, `"` stay literal) and
        // concatenate the still-expanding "$PATH".
        let dir = posix_quote(&shim_dir.to_string_lossy());
        format!("{MARK_BEGIN}\nexport PATH={dir}:\"$PATH\"\n{MARK_END}\n")
    };
    edit_shell_config(rc_file, |mut text| {
        // Match the file's own line endings; Windows profiles are often CRLF.
        let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
        if !text.is_empty() && !text.ends_with('\n') {
            text.push_str(eol);
        }
        text.push_str(&block.replace('\n', eol));
        text
    })
}

/// Remove the hood-marked block, if any.
fn remove_shell_block(rc_file: &Path) -> Result<Outcome> {
    edit_shell_config(rc_file, |text| text)
}

/// Remove every `MARK_BEGIN`…`MARK_END` block (inclusive), keeping every other
/// line byte for byte, its line ending included. Several blocks are tolerated,
/// as from a hand-pasted duplicate.
///
/// `None` when the markers do not pair up — a begin with no end, or a begin
/// inside a block. That may be user text or a damaged file, and neither is
/// permission to discard what follows the marker.
fn strip_block(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    let mut in_block = false;
    for line in input.split_inclusive('\n') {
        match (in_block, line.trim()) {
            (false, MARK_BEGIN) => in_block = true,
            (true, MARK_BEGIN) => return None,
            (true, MARK_END) => in_block = false,
            (true, _) => {}
            (false, _) => out.push_str(line),
        }
    }
    (!in_block).then_some(out)
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
    let original = fs::metadata(&destination).ok();

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
    if let Some(original) = &original {
        tmp.as_file()
            .set_permissions(original.permissions())
            .context("preserve shell config permissions")?;
        #[cfg(unix)]
        preserve_owner(tmp.as_file(), original);
    }
    tmp.persist(&destination)
        .map_err(|e| e.error)
        .with_context(|| format!("replace {}", destination.display()))?;
    Ok(())
}

/// Give the replacement the original's owner. The rename would otherwise hand
/// a `sudo hood install` user's `.zshrc` to root. Only root can change an
/// owner, and only a run as another user needs to; anyone else's attempt
/// fails harmlessly and is logged.
#[cfg(unix)]
fn preserve_owner(file: &fs::File, original: &fs::Metadata) {
    use std::os::unix::fs::MetadataExt;
    let Ok(current) = file.metadata() else {
        return;
    };
    if (current.uid(), current.gid()) == (original.uid(), original.gid()) {
        return;
    }
    if let Err(error) = std::os::unix::fs::fchown(file, Some(original.uid()), Some(original.gid()))
    {
        tracing::debug!(%error, "could not preserve shell config owner");
    }
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
        assert_eq!(tool_from_argv0("zig"), Some(Tool::Zig));
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
    fn powershell_profiles_cover_both_shells() {
        let profiles = powershell_profiles(Path::new("D:\\Docs"));
        assert_eq!(profiles.len(), 2);
        assert!(
            profiles
                .iter()
                .all(|p| p.ends_with("Microsoft.PowerShell_profile.ps1"))
        );
        assert!(profiles[0].to_string_lossy().contains("WindowsPowerShell"));
        assert!(!profiles[1].to_string_lossy().contains("WindowsPowerShell"));
    }

    #[test]
    fn powershell_quote_doubles_single_quotes() {
        assert_eq!(
            powershell_quote("C:\\Users\\o'brien"),
            "'C:\\Users\\o''brien'"
        );
        assert_eq!(powershell_quote("$env:HOME \"x\""), "'$env:HOME \"x\"'");
    }

    #[test]
    fn write_shell_block_emits_powershell_for_ps1() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = tmp
            .path()
            .join("PowerShell")
            .join("Microsoft.PowerShell_profile.ps1");
        write_shell_block(&profile, Path::new("C:\\Users\\x\\.hood\\bin")).unwrap();
        let body = fs::read_to_string(&profile).unwrap();
        assert!(body.contains("$env:Path = 'C:\\Users\\x\\.hood\\bin' + ';' + $env:Path"));
        assert!(body.starts_with(MARK_BEGIN));
        assert!(!body.contains("export PATH"));
        // Idempotent: a second write replaces rather than appends.
        write_shell_block(&profile, Path::new("C:\\Users\\x\\.hood\\bin")).unwrap();
        assert_eq!(fs::read_to_string(&profile).unwrap(), body);
        assert_eq!(remove_shell_block(&profile).unwrap(), Outcome::Written);
        assert_eq!(fs::read_to_string(&profile).unwrap(), "");
    }

    #[test]
    fn strip_block_removes_marked_section() {
        let input = format!("before\n{MARK_BEGIN}\nexport PATH=...\n{MARK_END}\nafter\n");
        assert_eq!(strip_block(&input).unwrap(), "before\nafter\n");
    }

    #[test]
    fn strip_block_removes_multiple_marked_sections() {
        let input = format!("a\n{MARK_BEGIN}\nx\n{MARK_END}\nb\n{MARK_BEGIN}\ny\n{MARK_END}\nc\n");
        assert_eq!(strip_block(&input).unwrap(), "a\nb\nc\n");
    }

    /// An unpaired marker may be user text or a damaged file; neither is
    /// permission to discard what follows it.
    #[test]
    fn strip_block_refuses_unpaired_markers() {
        let unterminated = format!("before\n{MARK_BEGIN}\nuser data\n");
        assert_eq!(strip_block(&unterminated), None);
        // An orphaned begin, then a complete block: stripping the outer pair
        // would take the user's line with it.
        let nested = format!("{MARK_BEGIN}\nuser data\n{MARK_BEGIN}\nx\n{MARK_END}\n");
        assert_eq!(strip_block(&nested), None);
    }

    #[test]
    fn strip_block_is_noop_on_unmarked_input() {
        let input = "alpha\nbeta\ngamma\n";
        assert_eq!(strip_block(input).unwrap(), input);
    }

    #[test]
    fn crlf_files_keep_their_line_endings() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile.ps1");
        fs::write(&profile, "Set-Alias ll ls\r\n").unwrap();
        write_shell_block(&profile, Path::new("C:\\hood")).unwrap();
        let written = fs::read_to_string(&profile).unwrap();
        assert!(written.starts_with("Set-Alias ll ls\r\n"));
        assert_eq!(
            written.matches('\n').count(),
            written.matches("\r\n").count()
        );
        assert_eq!(remove_shell_block(&profile).unwrap(), Outcome::Written);
        assert_eq!(fs::read_to_string(&profile).unwrap(), "Set-Alias ll ls\r\n");
        // Nothing of hood's left: nothing to do, and nothing reported.
        assert_eq!(remove_shell_block(&profile).unwrap(), Outcome::Unchanged);
    }

    #[test]
    fn unreadable_or_unpaired_configs_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let utf16 = dir.path().join("utf16.ps1");
        let bytes = [0xff, 0xfe, b'#', 0, b'\n', 0];
        fs::write(&utf16, bytes).unwrap();
        assert!(matches!(
            write_shell_block(&utf16, Path::new("C:\\hood")).unwrap(),
            Outcome::Skipped(_)
        ));
        assert_eq!(fs::read(&utf16).unwrap(), bytes);

        let unpaired = dir.path().join(".zshrc");
        let text = format!("{MARK_BEGIN}\nalias x=y\n");
        fs::write(&unpaired, &text).unwrap();
        for outcome in [
            write_shell_block(&unpaired, Path::new("/hood")).unwrap(),
            remove_shell_block(&unpaired).unwrap(),
        ] {
            assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
        }
        assert_eq!(fs::read_to_string(&unpaired).unwrap(), text);
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

        assert_eq!(remove_shell_block(&rc).unwrap(), Outcome::Written);
        let after_remove = fs::read_to_string(&rc).unwrap();
        assert_eq!(after_remove, "echo hi\n");

        assert_eq!(remove_shell_block(&rc).unwrap(), Outcome::Unchanged);
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

    #[cfg(windows)]
    #[test]
    fn windows_install_link_creates_a_recognized_shim() {
        let tmp = tempfile::tempdir().unwrap();
        let hood = tmp.path().join("hood.exe");
        fs::write(&hood, b"MZ hood bytes").unwrap();
        let dir = tmp.path().join("bin");
        fs::create_dir(&dir).unwrap();

        install_link(&dir, "npm", &hood, true).unwrap();
        // The shim carries the `.exe` suffix Windows needs to execute it.
        let link = dir.join("npm.exe");
        assert!(link.exists());
        assert!(is_hood_shim(&link));
        // However it was linked (symlink, hard link, or copy), it is hood.
        assert_eq!(fs::read(&link).unwrap(), b"MZ hood bytes");
    }

    #[cfg(windows)]
    #[test]
    fn windows_install_link_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let hood = tmp.path().join("hood.exe");
        fs::write(&hood, b"MZ").unwrap();
        let dir = tmp.path().join("bin");
        fs::create_dir(&dir).unwrap();

        install_link(&dir, "cargo", &hood, false).unwrap();
        install_link(&dir, "cargo", &hood, false).unwrap();
        assert!(is_hood_shim(&dir.join("cargo.exe")));
    }

    #[cfg(windows)]
    #[test]
    fn windows_install_link_replaces_a_stale_copy_after_upgrade() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("bin");
        fs::create_dir(&dir).unwrap();
        // A copy left by a previous hood, now out of date.
        let link = dir.join("npm.exe");
        fs::write(&link, b"old hood bytes").unwrap();
        let hood = tmp.path().join("hood.exe");
        fs::write(&hood, b"new hood bytes").unwrap();

        install_link(&dir, "npm", &hood, false).unwrap();
        assert_eq!(fs::read(&link).unwrap(), b"new hood bytes");
    }

    #[test]
    fn argv0_names_only_shimmable_tools() {
        for name in ["npm", "/home/u/.hood/bin/cargo", "zig", "brew.exe"] {
            assert!(tool_from_argv0(name).is_some(), "{name}");
        }
        for name in ["exec", "hood", "npmx", ""] {
            assert!(tool_from_argv0(name).is_none(), "{name}");
        }
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

        let report = install_at(&layout, &hood, false, "linux", bin.as_os_str()).unwrap();
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
        let mac = install_at(&layout, &hood, false, "macos", empty_path).unwrap();
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
        let linux = install_at(&layout, &hood, false, "linux", empty_path).unwrap();
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
        let report = install_at(&layout, &hood, false, "macos", bin.as_os_str()).unwrap();
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
        install_at(&layout, &hood, false, "linux", bin.as_os_str()).unwrap();
        install_at(&layout, &hood, false, "linux", bin.as_os_str()).unwrap();
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

        install_at(&layout, &hood, false, "linux", empty_path).unwrap();
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

        install_at(&layout, &hood1, false, "linux", bin.as_os_str()).unwrap();
        let target1 = fs::read_link(layout.shim_dir.join("npm")).unwrap();
        assert_eq!(target1, hood1);

        install_at(&layout, &hood2, true, "linux", bin.as_os_str()).unwrap();
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
