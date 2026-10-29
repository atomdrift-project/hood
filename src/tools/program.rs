//! Finding and running the real program behind a shim.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::process::Command;

use super::{PreparedChildEnv, Tool, TrustProfile};

/// A validated path supplied to `hood exec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutablePath(PathBuf);

impl ExecutablePath {
    /// Borrow the executable path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl TryFrom<PathBuf> for ExecutablePath {
    type Error = anyhow::Error;

    fn try_from(path: PathBuf) -> Result<Self> {
        if path.as_os_str().is_empty() {
            anyhow::bail!("hood exec requires a non-empty command");
        }
        Ok(Self(path))
    }
}

impl AsRef<Path> for ExecutablePath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl std::fmt::Display for ExecutablePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.display().fmt(f)
    }
}

/// A process Hood can launch.
///
/// Known tools resolve through `PATH`; arbitrary commands carry the path from
/// `hood exec`. This cannot represent a missing command or attach an override
/// to a known tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    /// A package manager or downloader known to Hood.
    Tool(Tool),
    /// An arbitrary command supplied to `hood exec`.
    Command(ExecutablePath),
}

impl Program {
    /// Construct an arbitrary command target.
    ///
    /// # Errors
    ///
    /// Returns an error when `path` is empty.
    pub fn command(path: impl Into<PathBuf>) -> Result<Self> {
        ExecutablePath::try_from(path.into()).map(Self::Command)
    }

    /// Return the known tool, if this is not an arbitrary command.
    #[must_use]
    pub const fn tool(&self) -> Option<Tool> {
        match self {
            Self::Tool(tool) => Some(*tool),
            Self::Command(_) => None,
        }
    }

    pub(super) const fn trust_profile(&self) -> TrustProfile {
        match self {
            Self::Tool(tool) => tool.trust_profile(),
            Self::Command(_) => TrustProfile::Exec,
        }
    }

    /// How much of one download hood inspects before forwarding the rest
    /// unscanned; `None` inspects every byte. Fetch tools pull ISOs, disk
    /// images and model weights no package manager would, and an arbitrary
    /// `hood exec` command may too. Package-manager downloads are always
    /// inspected whole: they are what a supply-chain attack ships.
    #[must_use]
    pub const fn scan_limit(&self) -> Option<u64> {
        /// 1 GiB.
        const FETCH_SCAN_LIMIT: u64 = 1 << 30;
        match self {
            Self::Tool(Tool::Curl | Tool::Wget) | Self::Command(_) => Some(FETCH_SCAN_LIMIT),
            Self::Tool(_) => None,
        }
    }

    /// Whether this program is curl, by tool identity or by the exec'd binary's
    /// name. Windows curl is Schannel: it takes its trust from a `--cacert`
    /// flag, not an environment variable, so both the `curl` shim and
    /// `hood exec -- curl` need that flag injected.
    #[must_use]
    pub fn is_curl(&self) -> bool {
        match self {
            Self::Tool(tool) => *tool == Tool::Curl,
            Self::Command(path) => path
                .as_path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem.eq_ignore_ascii_case("curl")),
        }
    }

    fn resolve<'a>(&'a self, shim_dir: Option<&Path>) -> Result<Cow<'a, Path>> {
        match self {
            Self::Tool(tool) => {
                let name = tool.name();
                resolve_real_binary(name, shim_dir)
                    .map(Cow::Owned)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no real `{name}` found on PATH (only the hood shim); refusing to re-exec the shim",
                        )
                    })
            }
            Self::Command(path) => Ok(Cow::Borrowed(path.as_path())),
        }
    }
}

impl From<Tool> for Program {
    fn from(tool: Tool) -> Self {
        Self::Tool(tool)
    }
}

/// Resolve the real binary for `tool`, skipping any directory matching
/// `skip_dir` during PATH search. This prevents the `hood`-installed PATH shim
/// from being invoked recursively.
#[must_use]
pub fn resolve_real_binary(name: &str, skip_dir: Option<&Path>) -> Option<PathBuf> {
    let search_path = std::env::var_os("PATH")?;
    let current_exe = std::env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok());
    resolve_binary_in_path(name, &search_path, skip_dir, current_exe.as_deref())
}

pub(crate) fn resolve_binary_in_path(
    name: &str,
    search_path: &OsStr,
    skip_dir: Option<&Path>,
    current_exe: Option<&Path>,
) -> Option<PathBuf> {
    let canonical_skip = skip_dir.and_then(|path| path.canonicalize().ok());
    let names = candidate_names(name);
    for entry in std::env::split_paths(search_path) {
        // A relative entry (`.`, or the empty one a stray `:` leaves) resolves
        // against the working directory, often the checkout being installed,
        // where a planted `./npm` would run as the tool. Go's `exec.LookPath`
        // refuses these for the same reason.
        if !entry.is_absolute() {
            continue;
        }
        if let Some(skip) = skip_dir
            && (entry == skip
                || canonical_skip
                    .as_ref()
                    .is_some_and(|canonical| entry.canonicalize().ok().as_ref() == Some(canonical)))
        {
            continue;
        }
        for file in &names {
            let candidate = entry.join(file);
            if is_executable(&candidate)
                && current_exe
                    .is_none_or(|current| candidate.canonicalize().ok().as_deref() != Some(current))
            {
                return Some(candidate);
            }
        }
    }
    None
}

/// File names that satisfy a lookup for `name`. Windows resolves a bare name
/// through `PATHEXT`, so `npm` is `npm.cmd` and `pip` is `pip.exe`; a name
/// that already carries an extension is looked up as written.
fn candidate_names(name: &str) -> Vec<OsString> {
    if !cfg!(windows) || Path::new(name).extension().is_some() {
        return vec![OsString::from(name)];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned());
    pathext
        .split(';')
        .filter(|ext| ext.starts_with('.'))
        .map(|ext| OsString::from(format!("{name}{ext}")))
        .collect()
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .ok()
        .filter(std::fs::Metadata::is_file)
        .is_some_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// Run the real program and return its exit code: behind the proxy with
/// `env`, or untouched without one, when [`dispatch`] found nothing to fetch.
///
/// `shim_dir`, when supplied, is excluded from `PATH` resolution so an
/// installed Hood shim cannot recursively invoke itself.
///
/// # Errors
///
/// Returns an error if the real program cannot be found, spawned, or awaited.
pub async fn run_tool(
    program: &Program,
    args: Vec<OsString>,
    env: Option<&PreparedChildEnv>,
    shim_dir: Option<&Path>,
) -> Result<i32> {
    let binary = program.resolve(shim_dir)?;
    let mut command = Command::new(&*binary);
    command.args(args);
    if let Some(PreparedChildEnv { env, .. }) = env {
        command.args(env.args_for_program(program));
        command.envs(env.vars_for_program(program));
    }
    // The child inherits stdio, so the tool talks to the user's terminal.
    let mut child = command
        .spawn()
        .with_context(|| format!("run {}", binary.display()))?;
    let status = wait_relaying_signals(&mut child)
        .await
        .with_context(|| format!("wait for {}", binary.display()))?;
    Ok(exit_code(status))
}

/// Wait for the child, staying alive to clean up after it.
///
/// A terminal's Ctrl-C already reaches the child, which shares hood's process
/// group, so hood only outlives it. A SIGTERM or SIGHUP sent to hood alone —
/// `timeout`, a CI runner cancelling a step — is passed on, so the child is
/// never orphaned with a proxy that has gone away.
#[cfg(unix)]
async fn wait_relaying_signals(
    child: &mut tokio::process::Child,
) -> std::io::Result<std::process::ExitStatus> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            status = child.wait() => return status,
            _ = interrupt.recv() => {}
            _ = terminate.recv() => relay_signal(child, libc::SIGTERM),
            _ = hangup.recv() => relay_signal(child, libc::SIGHUP),
        }
    }
}

/// Send `signal` to the child, unless it has already been reaped.
#[cfg(unix)]
fn relay_signal(child: &tokio::process::Child, signal: libc::c_int) {
    let Some(pid) = child.id().and_then(|pid| libc::pid_t::try_from(pid).ok()) else {
        return;
    };
    // SAFETY: kill(2) takes no pointers and has no memory-safety
    // preconditions. `pid` is our own child, not yet reaped, so it cannot
    // name a recycled process.
    #[allow(unsafe_code)]
    let sent = unsafe { libc::kill(pid, signal) };
    if sent != 0 {
        tracing::debug!(error = %std::io::Error::last_os_error(), signal, "could not relay signal");
    }
}

/// Wait for the child. Ctrl-C reaches every process on the console, the child
/// included, so hood only has to outlive it.
#[cfg(windows)]
async fn wait_relaying_signals(
    child: &mut tokio::process::Child,
) -> std::io::Result<std::process::ExitStatus> {
    let mut ctrl_c = tokio::signal::windows::ctrl_c()?;
    loop {
        tokio::select! {
            status = child.wait() => return status,
            _ = ctrl_c.recv() => {}
        }
    }
}

/// The exit code a shell would report: 128 plus the signal for a child the
/// signal killed, so `Ctrl-C` reads as 130 rather than a generic failure.
fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return 128 + signal;
    }
    status.code().unwrap_or(1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// A child killed by a signal exits as a shell would report it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_signalled_child_exits_with_128_plus_the_signal() {
        let sh = Program::command("/bin/sh").unwrap();
        for (signal, code) in [("TERM", 143), ("INT", 130)] {
            let args = vec![
                OsString::from("-c"),
                OsString::from(format!("kill -{signal} $$")),
            ];
            assert_eq!(
                run_tool(&sh, args, None, None).await.unwrap(),
                code,
                "{signal}"
            );
        }
        let ok = vec![OsString::from("-c"), OsString::from("exit 3")];
        assert_eq!(run_tool(&sh, ok, None, None).await.unwrap(), 3);
    }

    #[test]
    fn only_fetch_tools_stop_inspecting_large_downloads() {
        let exec = Program::command("/usr/bin/aria2c").unwrap();
        for program in [Program::Tool(Tool::Curl), Program::Tool(Tool::Wget), exec] {
            assert_eq!(program.scan_limit(), Some(1 << 30), "{program:?}");
        }
        for &tool in Tool::SHIMMABLE {
            if !matches!(tool, Tool::Curl | Tool::Wget) {
                assert_eq!(Program::Tool(tool).scan_limit(), None, "{tool:?}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn relative_path_entries_are_never_searched() {
        use std::os::unix::fs::PermissionsExt;
        let planted = tempfile::tempdir().unwrap();
        let p = planted.path().join("hood-planted-tool");
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The same directory, spelled relative to wherever the test runs, so
        // nothing is written into the checkout.
        let up: PathBuf = std::env::current_dir()
            .unwrap()
            .components()
            .skip(1)
            .map(|_| "..")
            .collect();
        let relative = up.join(planted.path().strip_prefix("/").unwrap());
        assert!(relative.is_relative() && relative.join("hood-planted-tool").is_file());
        let path = std::env::join_paths([relative]).unwrap();
        assert_eq!(
            resolve_binary_in_path("hood-planted-tool", &path, None, None),
            None
        );
        let absolute = std::env::join_paths([planted.path()]).unwrap();
        assert!(resolve_binary_in_path("hood-planted-tool", &absolute, None, None).is_some());
    }

    #[test]
    fn empty_explicit_command_is_rejected() {
        assert!(Program::command(OsString::new()).is_err());
    }

    #[test]
    fn candidate_names_keep_explicit_extensions() {
        assert_eq!(candidate_names("npm.cmd"), vec![OsString::from("npm.cmd")]);
    }

    #[cfg(windows)]
    #[test]
    fn candidate_names_expand_pathext_on_windows() {
        let names = candidate_names("npm");
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("npm.cmd")),
            "{names:?}"
        );
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("npm.exe")),
            "{names:?}"
        );
        assert!(!names.contains(&OsString::from("npm")));
    }

    #[cfg(not(windows))]
    #[test]
    fn candidate_names_are_bare_off_windows() {
        assert_eq!(candidate_names("npm"), vec![OsString::from("npm")]);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_real_binary_skips_shim_dir() {
        use std::os::unix::fs::PermissionsExt;
        let real_dir = tempfile::tempdir().unwrap();
        let shim_dir = tempfile::tempdir().unwrap();

        // Put an executable in both dirs.
        for d in [real_dir.path(), shim_dir.path()] {
            let p = d.join("npm");
            std::fs::write(&p, b"#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // PATH: shim_dir first, then real_dir.
        let path = std::env::join_paths([shim_dir.path(), real_dir.path()]).unwrap();
        let found = resolve_binary_in_path("npm", &path, Some(shim_dir.path()), None).unwrap();
        // Must have skipped shim_dir and found real_dir's copy.
        assert!(
            found.starts_with(real_dir.path()),
            "expected real path, got {}",
            found.display()
        );
    }
}
