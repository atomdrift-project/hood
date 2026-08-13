//! Tool-specific argv classification + env-var orchestration.
//!
//! Each [`Tool`] knows three things:
//!
//! 1. Its binary name.
//! 2. Which env vars to set in the child so it routes traffic through hood
//!    *and* trusts hood's ephemeral CA.
//! 3. Which subcommands warrant interception. `go run` / `npm test` /
//!    `cargo build` are passed through unchanged because they don't fetch
//!    network content; `go get` / `npm install` / `cargo install` do, so they
//!    are routed through the proxy.
//!
//! Spawning the child is delegated to [`run_child`], which writes the CA PEM
//! to a tempfile under the OS temp dir, runs the command, and cleans up on
//! exit (success or panic).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use tempfile::TempDir;
use tokio::process::Command;

use crate::go_bridge::GoChildEnv;

/// Subcommands hood knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `curl <args...>` — libcurl, respects `CURL_CA_BUNDLE` / `SSL_CERT_FILE`.
    Curl,
    /// `wget <args...>` — gnutls/openssl, respects `SSL_CERT_FILE`.
    Wget,
    /// `npm <args...>` — Node, respects `NODE_EXTRA_CA_CERTS`.
    Npm,
    /// `npx <args...>` — npm's package-executable runner.
    Npx,
    /// `pnpm <args...>` — same trust model as npm.
    Pnpm,
    /// `pnpx <args...>` — pnpm's package-executable runner.
    Pnpx,
    /// `yarn <args...>` — Node, same trust as npm.
    Yarn,
    /// `rush <args...>` — Rush monorepo manager; commands may provision tools.
    Rush,
    /// `rushx <args...>` — Rush project-script runner; scripts may fetch dependencies.
    Rushx,
    /// `bun <args...>` — Node-compatible toolchain.
    Bun,
    /// `bunx <args...>` — alias for `bun x`.
    Bunx,
    /// `pip <args...>` — pip uses bundled certifi; needs `PIP_CERT`.
    Pip,
    /// `pip3 <args...>` — Python 3 spelling of pip.
    Pip3,
    /// `pipx <args...>` — pip-based; inherits `PIP_CERT`.
    Pipx,
    /// `uv <args...>` — Astral's pip replacement; `SSL_CERT_FILE` works.
    Uv,
    /// `uvx <args...>` — alias for `uv tool run`.
    Uvx,
    /// `poetry <args...>` — Python; `POETRY_REQUESTS_CA_BUNDLE` honored.
    Poetry,
    /// `pdm <args...>` — Python package and project manager.
    Pdm,
    /// `go <args...>` — Go toolchain. Uses `SSL_CERT_FILE` where supported and
    /// hood's loopback module/sumdb bridge on macOS.
    Go,
    /// `cargo <args...>` — Rust. Respects `CARGO_HTTP_CAINFO` and `SSL_CERT_FILE`.
    Cargo,
    /// `brew <args...>` — Homebrew (curl-backed under the hood).
    Brew,
    /// `pacman <args...>` — Arch Linux. libalpm links libcurl, so honors
    /// `CURL_CA_BUNDLE` / `SSL_CERT_FILE` plus the standard proxy vars. The
    /// operation is a flag (`-S`/`-U`), not a positional subcommand.
    Pacman,
    /// `yay <args...>` — Arch AUR helper (Go). Repo/source downloads delegate to
    /// pacman and makepkg; its own AUR RPC uses Go's TLS stack.
    Yay,
    /// `paru <args...>` — Arch AUR helper (Rust). Same delegation model as yay.
    Paru,
    /// `makepkg <args...>` — Arch source build; fetches PKGBUILD sources through
    /// curl DLAGENTs. Any real build fetches, so only info flags pass through.
    Makepkg,
    /// `dnf <args...>` — Fedora/RHEL. librepo links libcurl.
    Dnf,
    /// `yum <args...>` — RHEL (dnf-compatible front end).
    Yum,
    /// `zypper <args...>` — openSUSE. libzypp links libcurl.
    Zypper,
    /// `rpm <args...>` — low-level RPM. Only reaches the network when handed an
    /// `http(s)`/`ftp` URL; local-file installs pass straight through.
    Rpm,
    /// `pkg <args...>` — FreeBSD. libfetch honors `SSL_CA_CERT_FILE` and proxy vars.
    Pkg,
    /// `apk <args...>` — Alpine. apk-tools' libfetch honors `SSL_CA_CERT_FILE`.
    Apk,
}

impl Tool {
    /// Binary to invoke on the host, before any user-supplied first arg.
    #[must_use]
    pub const fn default_binary(self) -> &'static str {
        match self {
            Self::Curl => "curl",
            Self::Wget => "wget",
            Self::Npm => "npm",
            Self::Npx => "npx",
            Self::Pnpm => "pnpm",
            Self::Pnpx => "pnpx",
            Self::Yarn => "yarn",
            Self::Rush => "rush",
            Self::Rushx => "rushx",
            Self::Bun => "bun",
            Self::Bunx => "bunx",
            Self::Pip => "pip",
            Self::Pip3 => "pip3",
            Self::Pipx => "pipx",
            Self::Uv => "uv",
            Self::Uvx => "uvx",
            Self::Poetry => "poetry",
            Self::Pdm => "pdm",
            Self::Go => "go",
            Self::Cargo => "cargo",
            Self::Brew => "brew",
            Self::Pacman => "pacman",
            Self::Yay => "yay",
            Self::Paru => "paru",
            Self::Makepkg => "makepkg",
            Self::Dnf => "dnf",
            Self::Yum => "yum",
            Self::Zypper => "zypper",
            Self::Rpm => "rpm",
            Self::Pkg => "pkg",
            Self::Apk => "apk",
        }
    }

    /// The canonical short name for this tool — used in shim file names,
    /// `--shells` hints, and log fields.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Curl => "curl",
            Self::Wget => "wget",
            Self::Npm => "npm",
            Self::Npx => "npx",
            Self::Pnpm => "pnpm",
            Self::Pnpx => "pnpx",
            Self::Yarn => "yarn",
            Self::Rush => "rush",
            Self::Rushx => "rushx",
            Self::Bun => "bun",
            Self::Bunx => "bunx",
            Self::Pip => "pip",
            Self::Pip3 => "pip3",
            Self::Pipx => "pipx",
            Self::Uv => "uv",
            Self::Uvx => "uvx",
            Self::Poetry => "poetry",
            Self::Pdm => "pdm",
            Self::Go => "go",
            Self::Cargo => "cargo",
            Self::Brew => "brew",
            Self::Pacman => "pacman",
            Self::Yay => "yay",
            Self::Paru => "paru",
            Self::Makepkg => "makepkg",
            Self::Dnf => "dnf",
            Self::Yum => "yum",
            Self::Zypper => "zypper",
            Self::Rpm => "rpm",
            Self::Pkg => "pkg",
            Self::Apk => "apk",
        }
    }

    /// Whether this tool could plausibly exist on the given OS — matched against
    /// [`std::env::consts::OS`] (`"macos"`, `"linux"`, `"freebsd"`, `"windows"`, …).
    ///
    /// This is a coarse OS-family gate, not a distro check: it removes tools that
    /// cannot belong on the platform at all (pacman on macOS, `pkg` on Linux) so
    /// the installer neither advertises them nor shims a stray same-named binary.
    /// Distro-level nuance — Arch's pacman vs Fedora's dnf, both "linux" — is left
    /// to the PATH probe, which only ever finds the one that's actually installed.
    #[must_use]
    pub fn plausible_on(self, os: &str) -> bool {
        match self {
            // Downloaders and language toolchains ship everywhere hood runs.
            Self::Curl
            | Self::Wget
            | Self::Npm
            | Self::Npx
            | Self::Pnpm
            | Self::Pnpx
            | Self::Yarn
            | Self::Rush
            | Self::Rushx
            | Self::Bun
            | Self::Bunx
            | Self::Pip
            | Self::Pip3
            | Self::Pipx
            | Self::Uv
            | Self::Uvx
            | Self::Poetry
            | Self::Pdm
            | Self::Go
            | Self::Cargo => true,
            // Homebrew targets macOS and Linux (Linuxbrew).
            Self::Brew => matches!(os, "macos" | "linux"),
            // Arch (pacman/AUR), RPM (dnf/yum/zypper/rpm), and Alpine (apk) system
            // package managers are Linux-only.
            Self::Pacman
            | Self::Yay
            | Self::Paru
            | Self::Makepkg
            | Self::Dnf
            | Self::Yum
            | Self::Zypper
            | Self::Rpm
            | Self::Apk => os == "linux",
            // pkgng is the BSD family.
            Self::Pkg => matches!(os, "freebsd" | "dragonfly" | "netbsd" | "openbsd"),
        }
    }

    /// Tools eligible for shell-shim installation.
    pub const SHIMMABLE: &'static [Self] = &[
        Self::Curl,
        Self::Wget,
        Self::Npm,
        Self::Npx,
        Self::Pnpm,
        Self::Pnpx,
        Self::Yarn,
        Self::Rush,
        Self::Rushx,
        Self::Bun,
        Self::Bunx,
        Self::Pip,
        Self::Pip3,
        Self::Pipx,
        Self::Uv,
        Self::Uvx,
        Self::Poetry,
        Self::Pdm,
        Self::Go,
        Self::Cargo,
        Self::Brew,
        Self::Pacman,
        Self::Yay,
        Self::Paru,
        Self::Makepkg,
        Self::Dnf,
        Self::Yum,
        Self::Zypper,
        Self::Rpm,
        Self::Pkg,
        Self::Apk,
    ];
}

impl std::fmt::Display for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

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

    const fn trust_profile(&self) -> TrustProfile {
        match self {
            Self::Tool(tool) => tool.trust_profile(),
            Self::Command(_) => TrustProfile::Exec,
        }
    }

    fn resolve<'a>(&'a self, shim_dir: Option<&Path>) -> Result<Cow<'a, Path>> {
        match self {
            Self::Tool(tool) => {
                let name = tool.default_binary();
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

/// Decision on whether to route a tool invocation through hood's proxy.
#[derive(Debug)]
pub enum Dispatch {
    /// Run the tool through the proxy with these (possibly rewritten) args.
    Intercept(Vec<OsString>),
    /// Exec the tool directly — no proxy needed for this subcommand.
    Passthrough(Vec<OsString>),
}

/// Classify a tool invocation: should it go through the proxy or pass straight
/// through? `enable_scripts` only affects npm/pnpm/yarn/bun (controls whether
/// `--ignore-scripts` is injected).
#[must_use]
pub fn dispatch(tool: Tool, args: Vec<OsString>, enable_scripts: bool) -> Dispatch {
    // Downloaders, package-executable runners, and Rush script/custom-command
    // runners can fetch without a stable leading verb. Keep them inside the
    // proxy environment for every invocation; local-only runs pay only proxy
    // startup and preserve their original argv exactly.
    if matches!(
        tool,
        Tool::Curl
            | Tool::Wget
            | Tool::Npx
            | Tool::Pnpx
            | Tool::Rush
            | Tool::Rushx
            | Tool::Bunx
            | Tool::Uvx
    ) {
        return Dispatch::Intercept(args);
    }

    // Most tools fetch through a positional verb (`npm install`). Arch tools
    // use operation flags, while rpm fetches only when given a remote URL.
    let fetches = match tool {
        Tool::Pacman => pacman_fetches(&args),
        Tool::Yay | Tool::Paru => aur_helper_fetches(&args),
        Tool::Makepkg => makepkg_fetches(&args),
        Tool::Rpm => args.iter().any(|arg| is_remote_url(&arg.to_string_lossy())),
        // Search every positional token so global option values cannot hide a
        // later fetch verb such as `npm --prefix /tmp install`.
        _ => args.iter().any(|arg| {
            let arg = arg.to_string_lossy();
            !arg.starts_with('-')
                && !arg.starts_with('+')
                && is_fetching_subcommand(tool, Some(arg.as_ref()))
        }),
    };
    if !fetches {
        return Dispatch::Passthrough(args);
    }

    // Only the leading verb controls lifecycle scripts; a later flag value
    // resembling a verb must not trigger argument injection.
    let leading_subcommand = args
        .iter()
        .map(|arg| arg.to_string_lossy())
        .find(|arg| !arg.starts_with('-') && !arg.starts_with('+'));
    let runs_install_scripts = matches!(tool, Tool::Npm | Tool::Pnpm | Tool::Yarn | Tool::Bun)
        && leading_subcommand.as_deref() != Some("x")
        && is_fetching_subcommand(tool, leading_subcommand.as_deref());
    let final_args = if runs_install_scripts {
        maybe_add_ignore_scripts(args, enable_scripts)
    } else {
        args
    };
    Dispatch::Intercept(final_args)
}

/// Per-tool subcommand list that triggers interception. Anything not in the
/// list passes through.
fn is_fetching_subcommand(tool: Tool, sub: Option<&str>) -> bool {
    let Some(sub) = sub else {
        // Bare `npm`, `pip`, etc. prints help — no network. Pass through.
        return false;
    };
    match tool {
        Tool::Curl
        | Tool::Wget
        | Tool::Npx
        | Tool::Pnpx
        | Tool::Rush
        | Tool::Rushx
        | Tool::Bunx
        | Tool::Uvx => true, // handled before this fn

        Tool::Npm | Tool::Pnpm | Tool::Yarn => matches!(
            sub,
            "install" | "i" | "add" | "ci" | "update" | "up" | "upgrade" | "rebuild"
        ),

        Tool::Bun => matches!(sub, "install" | "i" | "add" | "x" | "update" | "upgrade"),

        Tool::Pip | Tool::Pip3 => matches!(sub, "install" | "download" | "wheel"),

        Tool::Pipx => matches!(sub, "install" | "upgrade" | "inject" | "run" | "runpip"),

        // uv's pip/tool subcommands are namespaced; we intercept on the
        // leading group — the inner verb is the user's business.
        Tool::Uv => matches!(sub, "pip" | "tool" | "add" | "sync" | "lock" | "run"),

        Tool::Poetry => matches!(sub, "add" | "install" | "update" | "lock" | "publish"),

        // PDM can resolve or provision dependencies through its normal project
        // commands, script runner, self-management, and Python manager.
        Tool::Pdm => matches!(
            sub,
            "add"
                | "install"
                | "update"
                | "sync"
                | "lock"
                | "run"
                | "build"
                | "publish"
                | "self"
                | "python"
                | "import"
        ),

        // Go: only network-fetch verbs. NOT `run`/`test`/`build`/`vet`.
        // `go install` and `go mod download` both fetch modules; the latter
        // is two-word so we accept "mod" as the gate and let the real go
        // binary handle the inner verb.
        Tool::Go => matches!(sub, "get" | "install" | "mod"),

        // Cargo: install/add/update/fetch are explicit network actions.
        // `cargo build` etc. *can* fetch on first encounter, but those
        // fetches are gated by the user's Cargo.lock — already a trust
        // boundary. Don't slow down every build.
        Tool::Cargo => matches!(sub, "install" | "add" | "update" | "fetch" | "search"),

        // Brew: bottle downloads happen on install/upgrade/reinstall/fetch/tap.
        // List/info/cleanup don't touch the network for new payloads.
        Tool::Brew => matches!(
            sub,
            "install" | "upgrade" | "reinstall" | "fetch" | "tap" | "bundle"
        ),

        // dnf/yum share a verb vocabulary; the fetching ones pull RPMs or
        // refresh metadata. `list`/`info`/`remove`/`history` stay local.
        Tool::Dnf | Tool::Yum => matches!(
            sub,
            "install"
                | "in"
                | "reinstall"
                | "upgrade"
                | "upgrade-minimal"
                | "update"
                | "up"
                | "downgrade"
                | "distro-sync"
                | "dsync"
                | "group"
                | "groupinstall"
                | "groupupdate"
                | "localinstall"
                | "swap"
                | "download"
        ),

        // zypper accepts both long verbs and its classic short aliases.
        Tool::Zypper => matches!(
            sub,
            "install"
                | "in"
                | "remove-and-install"
                | "update"
                | "up"
                | "dist-upgrade"
                | "dup"
                | "patch"
                | "source-install"
                | "si"
                | "install-new-recommends"
                | "inr"
                | "refresh"
                | "ref"
        ),

        // FreeBSD pkg: install/add/upgrade/fetch pull packages; update and
        // bootstrap refresh the catalogue / the pkg tool itself.
        Tool::Pkg => matches!(
            sub,
            "install" | "add" | "upgrade" | "fetch" | "update" | "bootstrap"
        ),

        // Alpine apk: add installs, upgrade/update refresh, fetch downloads.
        Tool::Apk => matches!(sub, "add" | "upgrade" | "update" | "fetch"),

        // The Arch and RPM families are flag-driven and are classified by
        // `dispatch` before this function is reached; never routed here.
        Tool::Pacman | Tool::Yay | Tool::Paru | Tool::Makepkg | Tool::Rpm => false,
    }
}

/// True when a `pacman` invocation performs a sync (`-S`) or upgrade (`-U`)
/// operation, or refreshes the files database (`-F`) — the operations that
/// reach the network. Query/remove/database ops (`-Q`/`-R`/`-D`) stay local.
///
/// pacman spells the operation as an uppercase letter inside a single-dash
/// flag group (`-Syu`), so we scan those groups for `S`/`U`/`F`. Case matters:
/// `-Rns` (remove) must not be mistaken for a sync.
fn pacman_fetches(args: &[OsString]) -> bool {
    args.iter().any(|a| {
        let s = a.to_string_lossy();
        if let Some(group) = short_flag_group(&s) {
            return group.chars().any(|c| matches!(c, 'S' | 'U' | 'F'));
        }
        matches!(s.as_ref(), "--sync" | "--upgrade" | "--files")
    })
}

/// True when a `yay`/`paru` invocation fetches. These pacman wrappers add
/// implicit operations: a bare invocation means `-Syu`, and a bare package
/// name means "search the AUR and install". So the rule inverts pacman's — we
/// intercept unless the command is unambiguously a local query/remove/database
/// operation or a help/version request.
fn aur_helper_fetches(args: &[OsString]) -> bool {
    // Bare `yay` / `paru` performs a full system upgrade.
    if args.is_empty() {
        return true;
    }
    let mut saw_positional = false;
    for a in args {
        let s = a.to_string_lossy();
        if let Some(group) = short_flag_group(&s) {
            if group.chars().any(|c| matches!(c, 'S' | 'U' | 'F')) {
                return true;
            }
            if group.chars().any(|c| matches!(c, 'Q' | 'R' | 'D' | 'T')) {
                return false;
            }
        } else if let Some(long) = s.strip_prefix("--") {
            match long {
                "sync" | "upgrade" | "files" => return true,
                "query" | "remove" | "database" | "deptest" | "help" | "version" => return false,
                _ => {}
            }
        } else if !s.starts_with('-') {
            saw_positional = true;
        }
    }
    // No explicit operation flag: a package name implies an AUR install.
    saw_positional
}

/// True when a `makepkg` invocation builds (and therefore downloads sources).
/// Only the pure informational flags stay offline; a bare `makepkg` builds the
/// PKGBUILD in the current directory.
fn makepkg_fetches(args: &[OsString]) -> bool {
    if args.is_empty() {
        return true;
    }
    !args.iter().all(|a| {
        matches!(
            a.to_string_lossy().as_ref(),
            "-h" | "--help" | "-V" | "--version" | "--packagelist" | "--printsrcinfo"
        )
    })
}

/// True when `s` begins with a remote URL scheme libcurl would fetch. URL
/// schemes are case-insensitive (RFC 3986 §3.1), so `HTTPS://` must match too —
/// matching only lowercase would let `rpm -i HTTPS://host/x.rpm` fetch unscanned.
fn is_remote_url(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once("://") else {
        return false;
    };
    !rest.is_empty()
        && ["http", "https", "ftp", "ftps"]
            .iter()
            .any(|p| scheme.eq_ignore_ascii_case(p))
}

/// Return the letters of a single-dash flag group (`-Syu` → `Syu`). Returns
/// `None` for long options (`--sync`), bare `-`, and positionals — anything
/// that isn't a classic short-flag cluster.
fn short_flag_group(arg: &str) -> Option<&str> {
    let rest = arg.strip_prefix('-')?;
    if rest.is_empty() || rest.starts_with('-') {
        return None;
    }
    Some(rest)
}

fn maybe_add_ignore_scripts(args: Vec<OsString>, enable_scripts: bool) -> Vec<OsString> {
    if enable_scripts {
        return args;
    }
    let already = args.iter().any(|a| {
        let s = a.to_string_lossy();
        s == "--ignore-scripts" || s == "--ignore-scripts=true"
    });
    if already {
        return args;
    }
    let mut out = args;
    out.push(OsString::from("--ignore-scripts"));
    out
}

/// TLS/proxy behavior shared by command aliases and tools built on the same
/// network stack. Keeping this separate from [`Tool`] prevents aliases such as
/// `pip3` and `uvx` from accumulating subtly different environment overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustProfile {
    Curl,
    Wget,
    Node,
    Pip,
    Uv,
    Requests,
    Pdm,
    Go,
    Cargo,
    Brew,
    SystemCurl,
    Yay,
    Exec,
}

impl Tool {
    const fn trust_profile(self) -> TrustProfile {
        match self {
            Self::Curl => TrustProfile::Curl,
            Self::Wget => TrustProfile::Wget,
            Self::Npm
            | Self::Npx
            | Self::Pnpm
            | Self::Pnpx
            | Self::Yarn
            | Self::Rush
            | Self::Rushx
            | Self::Bun
            | Self::Bunx => TrustProfile::Node,
            Self::Pip | Self::Pip3 | Self::Pipx => TrustProfile::Pip,
            Self::Uv | Self::Uvx => TrustProfile::Uv,
            Self::Poetry => TrustProfile::Requests,
            Self::Pdm => TrustProfile::Pdm,
            Self::Go => TrustProfile::Go,
            Self::Cargo => TrustProfile::Cargo,
            Self::Brew => TrustProfile::Brew,
            Self::Pacman
            | Self::Paru
            | Self::Makepkg
            | Self::Dnf
            | Self::Yum
            | Self::Zypper
            | Self::Rpm
            | Self::Pkg
            | Self::Apk => TrustProfile::SystemCurl,
            Self::Yay => TrustProfile::Yay,
        }
    }
}

/// Per-tool runtime context: where the proxy listens, where the CA file lives.
#[derive(Debug)]
pub struct ChildEnv {
    /// Proxy listen address as `http://host:port`.
    proxy_url: String,
    /// Path the child process can pass to its TLS verifier.
    ca_pem_path: PathBuf,
    /// macOS Go module/sumdb bridge settings, when enabled for this run.
    go: Option<GoChildEnv>,
}

/// Child environment coupled to the temporary CA file it references.
///
/// Keeping both values under one owner prevents the CA file from being
/// deleted while a child still depends on it.
#[derive(Debug)]
pub struct PreparedChildEnv {
    env: ChildEnv,
    _ca_dir: TempDir,
}

impl PreparedChildEnv {
    /// Add macOS Go bridge settings to the environment.
    pub fn set_go_bridge(&mut self, go: GoChildEnv) {
        self.env.go = Some(go);
    }
}

impl ChildEnv {
    /// Build the env-var overlay for a given tool.
    #[must_use]
    pub fn vars_for(&self, tool: Tool) -> BTreeMap<&'static str, OsString> {
        self.vars_for_profile(tool.trust_profile())
    }

    fn vars_for_program(&self, program: &Program) -> BTreeMap<&'static str, OsString> {
        self.vars_for_profile(program.trust_profile())
    }

    fn vars_for_profile(&self, profile: TrustProfile) -> BTreeMap<&'static str, OsString> {
        let mut out = BTreeMap::new();
        let proxy = OsString::from(&self.proxy_url);
        let ca = OsString::from(&self.ca_pem_path);

        // Universal proxy env vars (both lowercase and uppercase variants —
        // some clients only consult one or the other).
        for k in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
        ] {
            out.insert(k, proxy.clone());
        }

        // Neutralize any inherited NO_PROXY exclusion list. A curl/Go/Node child
        // that inherits `NO_PROXY=*.internal` (or `NO_PROXY=*`) would route
        // matching hosts straight to the origin, bypassing the proxy entirely and
        // leaving those downloads unscanned. Setting it empty (both cases, since
        // clients differ on which they read) excludes no host, so everything is
        // forced through hood.
        for k in ["no_proxy", "NO_PROXY"] {
            out.insert(k, OsString::new());
        }

        match profile {
            TrustProfile::Curl => {
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Wget => {
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Node => {
                out.insert("NODE_EXTRA_CA_CERTS", ca.clone());
                out.insert("npm_config_proxy", proxy.clone());
                out.insert("npm_config_https_proxy", proxy);
                out.insert("npm_config_cafile", ca);
            }
            TrustProfile::Pip => {
                // pip uses certifi by default; PIP_CERT is the supported override.
                out.insert("PIP_CERT", ca);
            }
            TrustProfile::Uv => {
                // uv (Astral) honors SSL_CERT_FILE and also its own UV_CA_CERT.
                out.insert("UV_CA_CERT", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Requests => {
                // poetry uses requests under the hood and honors
                // POETRY_REQUESTS_CA_BUNDLE per-repo, but supports the bundled
                // env at runtime as well. Set both to be safe.
                out.insert("POETRY_REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("REQUESTS_CA_BUNDLE", ca);
            }
            TrustProfile::Pdm => {
                // PDM documents both variables as CA-bundle overrides. Keep
                // the user's index and credential configuration untouched.
                out.insert("REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Go => {
                if let Some(go) = &self.go {
                    out.insert("GOPROXY", OsString::from(&go.goproxy));
                    out.insert("GOSUMDB", OsString::from(&go.gosumdb));
                    // The Go bridge is an origin server on loopback. Make the
                    // bypass explicit so inherited proxy behavior cannot feed
                    // that request recursively back into this same listener.
                    let loopback = OsString::from("127.0.0.1,localhost");
                    out.insert("no_proxy", loopback.clone());
                    out.insert("NO_PROXY", loopback);
                } else {
                    // Go honors this on Unix systems other than macOS.
                    out.insert("SSL_CERT_FILE", ca);
                }
            }
            TrustProfile::Cargo => {
                // CARGO_HTTP_CAINFO is the documented cargo override.
                // SSL_CERT_FILE covers git+https fetches that cargo invokes.
                out.insert("CARGO_HTTP_CAINFO", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Brew => {
                // brew uses curl internally and respects CURL_CA_BUNDLE.
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
                // Most brew formulae build with curl; the env carries.
                out.insert(
                    "HOMEBREW_NO_AUTO_UPDATE",
                    OsString::from("0"), // don't suppress; just declare
                );
            }
            // System package managers reach the network through one of a few
            // TLS backends: libcurl (pacman's libalpm, dnf's librepo, zypper's
            // libzypp, rpm) reads CURL_CA_BUNDLE/SSL_CERT_FILE; libfetch
            // (FreeBSD pkg, Alpine apk-tools) reads SSL_CA_CERT_FILE; makepkg
            // shells out to curl DLAGENTs. We set every CA-file var these
            // backends honor — each tool consults the one matching its stack
            // and ignores the rest, which keeps the overlay backend-agnostic.
            TrustProfile::SystemCurl => {
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("SSL_CA_CERT_FILE", ca);
            }
            TrustProfile::Yay => {
                // yay is Go: its AUR RPC uses crypto/tls (SSL_CERT_FILE, plus
                // the macOS fallback-roots knob), while package and source
                // downloads delegate to pacman and makepkg (libcurl / curl).
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("SSL_CA_CERT_FILE", ca);
                out.insert("GODEBUG", OsString::from("x509usefallbackroots=1"));
            }
            TrustProfile::Exec => {
                // Set every flavor we know about so whatever the user runs
                // has a reasonable shot at trusting us.
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("SSL_CA_CERT_FILE", ca.clone());
                out.insert("NODE_EXTRA_CA_CERTS", ca.clone());
                out.insert("PIP_CERT", ca.clone());
                out.insert("UV_CA_CERT", ca.clone());
                out.insert("REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("POETRY_REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("CARGO_HTTP_CAINFO", ca.clone());
                out.insert("npm_config_cafile", ca);
                out.insert("npm_config_proxy", proxy.clone());
                out.insert("npm_config_https_proxy", proxy);
                out.insert("GODEBUG", OsString::from("x509usefallbackroots=1"));
            }
        }
        out
    }
}

/// Build a child environment whose owner keeps its temporary CA file alive.
///
/// # Errors
///
/// Returns an error if the CA file cannot be created, secured, or written.
pub fn prepare_child_env(proxy_addr: SocketAddr, ca_pem: &str) -> Result<PreparedChildEnv> {
    let dir = tempfile::Builder::new()
        .prefix("hood-ca-")
        .tempdir()
        .context("create CA tempdir")?;
    let pem_path = dir.path().join("hood-ca.pem");
    let mut f = std::fs::File::create(&pem_path).context("create CA pem")?;
    f.write_all(ca_pem.as_bytes()).context("write CA pem")?;
    f.flush().context("flush CA pem")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = f.metadata().context("stat CA pem")?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&pem_path, perms).context("chmod CA pem")?;
    }
    drop(f);

    let proxy_url = format!("http://{proxy_addr}");
    Ok(PreparedChildEnv {
        env: ChildEnv {
            proxy_url,
            ca_pem_path: pem_path,
            go: None,
        },
        _ca_dir: dir,
    })
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

fn resolve_binary_in_path(
    name: &str,
    search_path: &OsStr,
    skip_dir: Option<&Path>,
    current_exe: Option<&Path>,
) -> Option<PathBuf> {
    let canonical_skip = skip_dir.and_then(|path| path.canonicalize().ok());
    for entry in std::env::split_paths(search_path) {
        if let Some(skip) = skip_dir
            && (entry == skip
                || canonical_skip
                    .as_ref()
                    .is_some_and(|canonical| entry.canonicalize().ok().as_ref() == Some(canonical)))
        {
            continue;
        }
        let candidate = entry.join(name);
        if is_executable(&candidate)
            && current_exe
                .is_none_or(|current| candidate.canonicalize().ok().as_deref() != Some(current))
        {
            return Some(candidate);
        }
    }
    None
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

/// Spawn a child with Hood's environment, then return its exit code.
///
/// `shim_dir`, when supplied, is excluded from `PATH` resolution so an
/// installed Hood shim cannot recursively invoke itself.
///
/// # Errors
///
/// Returns an error if the real program cannot be found, spawned, or awaited.
pub async fn run_child(
    program: &Program,
    args: Vec<OsString>,
    env: &PreparedChildEnv,
    shim_dir: Option<&Path>,
) -> Result<i32> {
    execute(program, args, Some(&env.env), shim_dir).await
}

/// Pass through to the real binary without setting up the proxy. Used when
/// [`dispatch`] decides the subcommand doesn't fetch network content.
///
/// # Errors
///
/// Returns an error if the real program cannot be found, spawned, or awaited.
pub async fn run_passthrough(
    program: &Program,
    args: Vec<OsString>,
    shim_dir: Option<&Path>,
) -> Result<i32> {
    execute(program, args, None, shim_dir).await
}

async fn execute(
    program: &Program,
    args: Vec<OsString>,
    env: Option<&ChildEnv>,
    shim_dir: Option<&Path>,
) -> Result<i32> {
    let binary = program.resolve(shim_dir)?;
    let mut command = Command::new(&*binary);
    command.args(args);
    if let Some(env) = env {
        command.envs(env.vars_for_program(program));
    }
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {}", binary.display()))?
        .wait()
        .await
        .with_context(|| format!("wait {}", binary.display()))?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn fake_env() -> ChildEnv {
        ChildEnv {
            proxy_url: "http://127.0.0.1:12345".into(),
            ca_pem_path: PathBuf::from("/tmp/hood.pem"),
            go: None,
        }
    }

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    // ----- env-var matrix -------------------------------------------------

    #[test]
    fn curl_env_includes_curl_ca_bundle() {
        let v = fake_env().vars_for(Tool::Curl);
        assert!(v.contains_key("CURL_CA_BUNDLE"));
        assert!(v.contains_key("SSL_CERT_FILE"));
        assert!(v.contains_key("http_proxy"));
    }

    #[test]
    fn npm_env_includes_node_extra_ca() {
        let v = fake_env().vars_for(Tool::Npm);
        assert!(v.contains_key("NODE_EXTRA_CA_CERTS"));
        assert!(v.contains_key("npm_config_https_proxy"));
    }

    #[test]
    fn command_aliases_share_their_ecosystem_trust_profile() {
        let node = fake_env().vars_for(Tool::Npm);
        for tool in [Tool::Npx, Tool::Pnpx, Tool::Rush, Tool::Rushx, Tool::Bunx] {
            assert_eq!(fake_env().vars_for(tool), node, "{tool:?}");
        }

        assert_eq!(
            fake_env().vars_for(Tool::Pip3),
            fake_env().vars_for(Tool::Pip)
        );
        assert_eq!(
            fake_env().vars_for(Tool::Uvx),
            fake_env().vars_for(Tool::Uv)
        );
    }

    #[test]
    fn pdm_env_uses_documented_ca_bundle_overrides() {
        let v = fake_env().vars_for(Tool::Pdm);
        assert!(v.contains_key("REQUESTS_CA_BUNDLE"));
        assert!(v.contains_key("CURL_CA_BUNDLE"));
        assert!(v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn pip_env_uses_pip_cert_not_ssl_cert_file() {
        let v = fake_env().vars_for(Tool::Pip);
        assert!(v.contains_key("PIP_CERT"));
        assert!(!v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn cargo_env_uses_cargo_http_cainfo() {
        let v = fake_env().vars_for(Tool::Cargo);
        assert!(v.contains_key("CARGO_HTTP_CAINFO"));
        assert!(v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn brew_env_uses_curl_ca_bundle() {
        let v = fake_env().vars_for(Tool::Brew);
        assert!(v.contains_key("CURL_CA_BUNDLE"));
    }

    #[test]
    fn go_env_uses_ssl_cert_file_without_bridge() {
        let v = fake_env().vars_for(Tool::Go);
        assert!(v.contains_key("SSL_CERT_FILE"));
        assert!(!v.contains_key("GODEBUG"));
        assert!(!v.contains_key("GOPROXY"));
    }

    #[test]
    fn go_bridge_replaces_ca_override_and_exempts_loopback() {
        let mut env = fake_env();
        env.go = Some(GoChildEnv {
            goproxy: "http://127.0.0.1:12345/__hood_go/token/proxy".into(),
            gosumdb: "sum.golang.org http://127.0.0.1:12345/__hood_go/token/sumdb".into(),
        });
        let v = env.vars_for(Tool::Go);
        assert_eq!(
            v.get("GOPROXY"),
            Some(&OsString::from(
                "http://127.0.0.1:12345/__hood_go/token/proxy"
            )),
        );
        assert!(v.contains_key("GOSUMDB"));
        assert!(!v.contains_key("SSL_CERT_FILE"));
        assert_eq!(
            v.get("NO_PROXY"),
            Some(&OsString::from("127.0.0.1,localhost")),
        );
    }

    #[test]
    fn exec_env_is_superset() {
        let program = Program::command("/tmp/example").unwrap();
        let v = fake_env().vars_for_program(&program);
        for key in [
            "CURL_CA_BUNDLE",
            "SSL_CERT_FILE",
            "NODE_EXTRA_CA_CERTS",
            "PIP_CERT",
            "UV_CA_CERT",
            "REQUESTS_CA_BUNDLE",
            "POETRY_REQUESTS_CA_BUNDLE",
            "CARGO_HTTP_CAINFO",
            "GODEBUG",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        ] {
            assert!(v.contains_key(key), "missing {key} in exec env");
        }
    }

    // ----- dispatch / intercept matrix ------------------------------------

    fn intercept_args(d: Dispatch) -> Vec<OsString> {
        match d {
            Dispatch::Intercept(a) => a,
            Dispatch::Passthrough(a) => panic!("expected Intercept, got Passthrough({a:?})"),
        }
    }
    fn passthrough_args(d: Dispatch) -> Vec<OsString> {
        match d {
            Dispatch::Passthrough(a) => a,
            Dispatch::Intercept(a) => panic!("expected Passthrough, got Intercept({a:?})"),
        }
    }

    #[test]
    fn go_get_is_intercepted() {
        let d = dispatch(Tool::Go, vec![os("get"), os("example.com/x")], false);
        assert_eq!(intercept_args(d), vec![os("get"), os("example.com/x")]);
    }

    #[test]
    fn go_install_is_intercepted() {
        let d = dispatch(Tool::Go, vec![os("install"), os("./cmd/foo")], false);
        let _v = intercept_args(d);
    }

    #[test]
    fn go_run_is_passthrough() {
        let d = dispatch(Tool::Go, vec![os("run"), os("./cmd/foo")], false);
        let _v = passthrough_args(d);
    }

    #[test]
    fn go_test_is_passthrough() {
        let d = dispatch(Tool::Go, vec![os("test"), os("./...")], false);
        let _v = passthrough_args(d);
    }

    #[test]
    fn cargo_install_intercepted_cargo_build_passthrough() {
        let _v = intercept_args(dispatch(
            Tool::Cargo,
            vec![os("install"), os("ripgrep")],
            false,
        ));
        let _v = passthrough_args(dispatch(
            Tool::Cargo,
            vec![os("build"), os("--release")],
            false,
        ));
    }

    #[test]
    fn npm_install_intercepted_npm_test_passthrough() {
        let _v = intercept_args(dispatch(
            Tool::Npm,
            vec![os("install"), os("lodash")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Npm, vec![os("test")], false));
    }

    #[test]
    fn executable_runners_and_rush_always_intercept_without_rewriting() {
        for tool in [
            Tool::Npx,
            Tool::Pnpx,
            Tool::Rush,
            Tool::Rushx,
            Tool::Bunx,
            Tool::Uvx,
        ] {
            let args = vec![os("--flag"), os("package")];
            assert_eq!(intercept_args(dispatch(tool, args.clone(), false)), args);
        }
    }

    #[test]
    fn pip3_matches_pip_dispatch() {
        let install = vec![os("install"), os("example")];
        assert_eq!(
            intercept_args(dispatch(Tool::Pip3, install.clone(), false)),
            install,
        );
        let _v = passthrough_args(dispatch(Tool::Pip3, vec![os("list")], false));
    }

    #[test]
    fn pdm_fetching_commands_intercept_and_local_commands_pass_through() {
        for command in ["add", "install", "update", "sync", "lock", "run", "self"] {
            let _v = intercept_args(dispatch(Tool::Pdm, vec![os(command)], false));
        }
        let _v = passthrough_args(dispatch(Tool::Pdm, vec![os("info")], false));
        let _v = passthrough_args(dispatch(Tool::Pdm, vec![os("config")], false));
    }

    #[test]
    fn brew_install_intercepted_brew_list_passthrough() {
        let _v = intercept_args(dispatch(Tool::Brew, vec![os("install"), os("jq")], false));
        let _v = passthrough_args(dispatch(Tool::Brew, vec![os("list")], false));
    }

    #[test]
    fn curl_always_intercepted_regardless_of_args() {
        let _v = intercept_args(dispatch(
            Tool::Curl,
            vec![os("-fsSL"), os("https://x")],
            false,
        ));
        let _v = intercept_args(dispatch(Tool::Curl, vec![os("--help")], false));
    }

    #[test]
    fn pip_install_injects_nothing_but_is_intercepted() {
        let d = dispatch(Tool::Pip, vec![os("install"), os("flask")], false);
        let args = intercept_args(d);
        assert!(!args.contains(&os("--ignore-scripts")));
    }

    #[test]
    fn npm_install_injects_ignore_scripts_when_disabled() {
        let d = dispatch(Tool::Npm, vec![os("install"), os("lodash")], false);
        let args = intercept_args(d);
        assert!(args.contains(&os("--ignore-scripts")));
    }

    #[test]
    fn npm_install_respects_enable_scripts() {
        let d = dispatch(Tool::Npm, vec![os("install"), os("lodash")], true);
        let args = intercept_args(d);
        assert!(!args.contains(&os("--ignore-scripts")));
    }

    #[test]
    fn npm_install_does_not_duplicate_ignore_scripts() {
        let d = dispatch(
            Tool::Npm,
            vec![os("install"), os("lodash"), os("--ignore-scripts")],
            false,
        );
        let args = intercept_args(d);
        let count = args
            .iter()
            .filter(|a| *a == &os("--ignore-scripts"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn bare_invocation_is_passthrough() {
        let _v = passthrough_args(dispatch(Tool::Npm, vec![], false));
        let _v = passthrough_args(dispatch(Tool::Cargo, vec![], false));
    }

    // ----- expanded env-var coverage --------------------------------------

    #[test]
    fn wget_env_uses_ssl_cert_file_only() {
        let v = fake_env().vars_for(Tool::Wget);
        assert!(v.contains_key("SSL_CERT_FILE"));
        // wget doesn't use NODE/PIP variants.
        assert!(!v.contains_key("NODE_EXTRA_CA_CERTS"));
        assert!(!v.contains_key("PIP_CERT"));
    }

    #[test]
    fn yarn_and_bun_share_npm_env() {
        for tool in [Tool::Yarn, Tool::Bun, Tool::Pnpm] {
            let v = fake_env().vars_for(tool);
            assert!(
                v.contains_key("NODE_EXTRA_CA_CERTS"),
                "{tool:?} should set NODE_EXTRA_CA_CERTS",
            );
            assert!(v.contains_key("npm_config_https_proxy"));
        }
    }

    #[test]
    fn uv_env_uses_uv_ca_cert_and_ssl_cert_file() {
        let v = fake_env().vars_for(Tool::Uv);
        assert!(v.contains_key("UV_CA_CERT"));
        assert!(v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn poetry_env_uses_poetry_and_requests_bundles() {
        let v = fake_env().vars_for(Tool::Poetry);
        assert!(v.contains_key("POETRY_REQUESTS_CA_BUNDLE"));
        assert!(v.contains_key("REQUESTS_CA_BUNDLE"));
    }

    #[test]
    fn pipx_env_matches_pip() {
        let v = fake_env().vars_for(Tool::Pipx);
        assert!(v.contains_key("PIP_CERT"));
    }

    // ----- dispatch coverage for new tools --------------------------------

    #[test]
    fn yarn_install_is_intercepted() {
        let _v = intercept_args(dispatch(Tool::Yarn, vec![os("install")], false));
        let _v = passthrough_args(dispatch(Tool::Yarn, vec![os("run"), os("test")], false));
    }

    #[test]
    fn bun_x_is_intercepted_but_bun_test_is_not() {
        let args = intercept_args(dispatch(Tool::Bun, vec![os("x"), os("create-app")], false));
        // `bun x` is exec, not install: --ignore-scripts would go to the executed
        // package and suppress nothing, so it must NOT be injected.
        assert!(
            !args.contains(&os("--ignore-scripts")),
            "bun x got {args:?}"
        );
        // But `bun install` is an install and does get the flag.
        let installed = intercept_args(dispatch(Tool::Bun, vec![os("install")], false));
        assert!(installed.contains(&os("--ignore-scripts")));
        let _v = passthrough_args(dispatch(Tool::Bun, vec![os("test")], false));
    }

    #[test]
    fn pipx_install_intercepted() {
        let _v = intercept_args(dispatch(Tool::Pipx, vec![os("install"), os("ruff")], false));
        let _v = passthrough_args(dispatch(Tool::Pipx, vec![os("list")], false));
    }

    #[test]
    fn uv_pip_group_intercepted() {
        let _v = intercept_args(dispatch(
            Tool::Uv,
            vec![os("pip"), os("install"), os("flask")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Uv, vec![os("--help")], false));
    }

    #[test]
    fn poetry_add_intercepted_run_passthrough() {
        let _v = intercept_args(dispatch(Tool::Poetry, vec![os("add"), os("flask")], false));
        let _v = passthrough_args(dispatch(Tool::Poetry, vec![os("run"), os("pytest")], false));
    }

    #[test]
    fn go_mod_download_intercepted() {
        let _v = intercept_args(dispatch(Tool::Go, vec![os("mod"), os("download")], false));
    }

    #[test]
    fn cargo_update_and_fetch_intercepted() {
        let _v = intercept_args(dispatch(Tool::Cargo, vec![os("update")], false));
        let _v = intercept_args(dispatch(Tool::Cargo, vec![os("fetch")], false));
    }

    #[test]
    fn cargo_toolchain_selector_does_not_hide_the_subcommand() {
        // `+nightly` is a rustup toolchain selector, not the subcommand — the
        // install must still be intercepted, and the selector preserved in argv.
        let d = dispatch(
            Tool::Cargo,
            vec![os("+nightly"), os("install"), os("ripgrep")],
            false,
        );
        assert_eq!(
            intercept_args(d),
            vec![os("+nightly"), os("install"), os("ripgrep")],
        );
        // A toolchain selector in front of a non-fetching verb still passes through.
        let _v = passthrough_args(dispatch(
            Tool::Cargo,
            vec![os("+stable"), os("build")],
            false,
        ));
    }

    #[test]
    fn value_flag_before_subcommand_still_intercepts() {
        // A value-taking global flag (`--prefix /tmp`) pushes `install` out of
        // first position; the fetch must still be intercepted, not passed through.
        let d = dispatch(
            Tool::Npm,
            vec![os("--prefix"), os("/tmp"), os("install"), os("lodash")],
            false,
        );
        let _v = intercept_args(d);
        // And a non-fetching run with a flag value that isn't a verb stays local.
        let _v = passthrough_args(dispatch(Tool::Npm, vec![os("run"), os("test")], false));
    }

    #[test]
    fn no_proxy_is_neutralized_in_env() {
        // The overlay must blank out any inherited NO_PROXY so the child can't
        // route matching hosts around the proxy unscanned.
        let v = fake_env().vars_for(Tool::Curl);
        assert_eq!(v.get("NO_PROXY"), Some(&OsString::new()));
        assert_eq!(v.get("no_proxy"), Some(&OsString::new()));
    }

    #[test]
    fn brew_bundle_intercepted_brew_info_passthrough() {
        let _v = intercept_args(dispatch(
            Tool::Brew,
            vec![os("bundle"), os("install")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Brew, vec![os("info"), os("jq")], false));
    }

    // ----- tool metadata --------------------------------------------------

    // ----- system package managers: env matrix ---------------------------

    #[test]
    fn libcurl_package_managers_set_curl_and_ssl_ca() {
        for tool in [
            Tool::Pacman,
            Tool::Paru,
            Tool::Makepkg,
            Tool::Dnf,
            Tool::Yum,
            Tool::Zypper,
            Tool::Rpm,
            Tool::Pkg,
            Tool::Apk,
        ] {
            let v = fake_env().vars_for(tool);
            assert!(v.contains_key("CURL_CA_BUNDLE"), "{tool:?} CURL_CA_BUNDLE");
            assert!(v.contains_key("SSL_CERT_FILE"), "{tool:?} SSL_CERT_FILE");
            assert!(
                v.contains_key("SSL_CA_CERT_FILE"),
                "{tool:?} SSL_CA_CERT_FILE (libfetch)",
            );
            assert!(v.contains_key("https_proxy"), "{tool:?} proxy");
        }
    }

    #[test]
    fn yay_sets_go_fallback_roots_and_ca() {
        let v = fake_env().vars_for(Tool::Yay);
        assert!(v.contains_key("SSL_CERT_FILE"));
        assert!(v.contains_key("CURL_CA_BUNDLE"));
        assert!(v.contains_key("SSL_CA_CERT_FILE"));
        assert!(
            v.get("GODEBUG")
                .is_some_and(|g| g.to_string_lossy().contains("x509usefallbackroots=1"))
        );
    }

    #[test]
    fn exec_superset_includes_libfetch_ca() {
        let program = Program::command("/tmp/example").unwrap();
        let v = fake_env().vars_for_program(&program);
        assert!(v.contains_key("SSL_CA_CERT_FILE"));
    }

    // ----- pacman family: flag-operation dispatch ------------------------

    #[test]
    fn pacman_sync_and_upgrade_intercepted_query_passthrough() {
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("-Syu")], false));
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("-S"), os("firefox")], false));
        let _v = intercept_args(dispatch(
            Tool::Pacman,
            vec![os("-U"), os("./p.pkg.tar.zst")],
            false,
        ));
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("--sync"), os("vim")], false));
        // Query/remove are local — and `-Rns` must not be read as a sync.
        let _v = passthrough_args(dispatch(Tool::Pacman, vec![os("-Q")], false));
        let _v = passthrough_args(dispatch(Tool::Pacman, vec![os("-Rns"), os("vim")], false));
        let _v = passthrough_args(dispatch(Tool::Pacman, vec![], false));
    }

    #[test]
    fn aur_helper_implicit_operations_intercepted() {
        // Bare invocation = -Syu; bare package name = AUR search+install.
        let _v = intercept_args(dispatch(Tool::Yay, vec![], false));
        let _v = intercept_args(dispatch(Tool::Yay, vec![os("firefox")], false));
        let _v = intercept_args(dispatch(Tool::Paru, vec![os("-Syu")], false));
        // Local ops and help pass through.
        let _v = passthrough_args(dispatch(Tool::Yay, vec![os("-Qi"), os("firefox")], false));
        let _v = passthrough_args(dispatch(Tool::Yay, vec![os("--help")], false));
        let _v = passthrough_args(dispatch(Tool::Paru, vec![os("-R"), os("vim")], false));
    }

    #[test]
    fn makepkg_builds_intercepted_info_flags_passthrough() {
        let _v = intercept_args(dispatch(Tool::Makepkg, vec![], false));
        let _v = intercept_args(dispatch(Tool::Makepkg, vec![os("-si")], false));
        let _v = passthrough_args(dispatch(Tool::Makepkg, vec![os("--printsrcinfo")], false));
        let _v = passthrough_args(dispatch(Tool::Makepkg, vec![os("--version")], false));
    }

    #[test]
    fn rpm_intercepts_urls_only() {
        let _v = intercept_args(dispatch(
            Tool::Rpm,
            vec![os("-Uvh"), os("https://example.com/x.rpm")],
            false,
        ));
        let _v = passthrough_args(dispatch(
            Tool::Rpm,
            vec![os("-ivh"), os("./local.rpm")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Rpm, vec![os("-q"), os("bash")], false));
        // URL schemes are case-insensitive: an uppercase scheme must still be
        // recognized as remote, not passed through unscanned.
        let _v = intercept_args(dispatch(
            Tool::Rpm,
            vec![os("-i"), os("HTTPS://example.com/x.rpm")],
            false,
        ));
        let _v = intercept_args(dispatch(
            Tool::Rpm,
            vec![os("-i"), os("FTPS://example.com/x.rpm")],
            false,
        ));
    }

    // ----- subcommand package managers: dispatch -------------------------

    #[test]
    fn dnf_yum_install_intercepted_list_passthrough() {
        let _v = intercept_args(dispatch(
            Tool::Dnf,
            vec![os("install"), os("ripgrep")],
            false,
        ));
        let _v = intercept_args(dispatch(Tool::Yum, vec![os("upgrade")], false));
        let _v = passthrough_args(dispatch(
            Tool::Dnf,
            vec![os("list"), os("installed")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Yum, vec![os("remove"), os("nano")], false));
    }

    #[test]
    fn zypper_short_and_long_verbs_intercepted() {
        let _v = intercept_args(dispatch(Tool::Zypper, vec![os("in"), os("vim")], false));
        let _v = intercept_args(dispatch(Tool::Zypper, vec![os("dup")], false));
        let _v = passthrough_args(dispatch(Tool::Zypper, vec![os("search"), os("vim")], false));
    }

    #[test]
    fn pkg_and_apk_install_intercepted() {
        let _v = intercept_args(dispatch(Tool::Pkg, vec![os("install"), os("curl")], false));
        let _v = intercept_args(dispatch(Tool::Pkg, vec![os("upgrade")], false));
        let _v = passthrough_args(dispatch(Tool::Pkg, vec![os("info")], false));
        let _v = intercept_args(dispatch(Tool::Apk, vec![os("add"), os("curl")], false));
        let _v = passthrough_args(dispatch(Tool::Apk, vec![os("info")], false));
    }

    #[test]
    fn every_shimmable_tool_has_a_default_binary() {
        for tool in Tool::SHIMMABLE {
            assert!(!tool.default_binary().is_empty());
            assert!(!tool.name().is_empty());
        }
    }

    #[test]
    fn empty_explicit_command_is_rejected() {
        assert!(Program::command(OsString::new()).is_err());
    }

    #[test]
    fn plausible_on_gates_system_managers_by_os() {
        // Arch/RPM/Alpine managers are Linux-only.
        for t in [Tool::Pacman, Tool::Yay, Tool::Dnf, Tool::Rpm, Tool::Apk] {
            assert!(
                t.plausible_on("linux"),
                "{t:?} should be plausible on linux"
            );
            assert!(
                !t.plausible_on("macos"),
                "{t:?} must not be plausible on macos"
            );
            assert!(
                !t.plausible_on("windows"),
                "{t:?} must not be plausible on windows"
            );
        }
        // Homebrew: macOS and Linux, not BSD/Windows.
        assert!(Tool::Brew.plausible_on("macos"));
        assert!(Tool::Brew.plausible_on("linux"));
        assert!(!Tool::Brew.plausible_on("freebsd"));
        // pkgng: BSD only.
        assert!(Tool::Pkg.plausible_on("freebsd"));
        assert!(!Tool::Pkg.plausible_on("linux"));
        assert!(!Tool::Pkg.plausible_on("macos"));
        // Language toolchains and downloaders: everywhere.
        for t in [Tool::Curl, Tool::Npm, Tool::Cargo, Tool::Go, Tool::Pip] {
            for os in ["macos", "linux", "windows", "freebsd"] {
                assert!(t.plausible_on(os), "{t:?} should be plausible on {os}");
            }
        }
    }

    // ----- PATH-skipping binary resolution --------------------------------

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
