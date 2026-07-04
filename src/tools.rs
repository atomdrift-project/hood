//! Tool-specific argv classification + env-var orchestration.
//!
//! Each [`Tool`] knows three things:
//!
//! 1. Its default binary name (and on `Tool::Exec`, takes one from the caller).
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

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use tempfile::TempDir;
use tokio::process::Command;

/// Subcommands hood knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `curl <args...>` — libcurl, respects `CURL_CA_BUNDLE` / `SSL_CERT_FILE`.
    Curl,
    /// `wget <args...>` — gnutls/openssl, respects `SSL_CERT_FILE`.
    Wget,
    /// `npm <args...>` — Node, respects `NODE_EXTRA_CA_CERTS`.
    Npm,
    /// `pnpm <args...>` — same trust model as npm.
    Pnpm,
    /// `yarn <args...>` — Node, same trust as npm.
    Yarn,
    /// `bun <args...>` — Node-compatible toolchain.
    Bun,
    /// `pip <args...>` — pip uses bundled certifi; needs `PIP_CERT`.
    Pip,
    /// `pipx <args...>` — pip-based; inherits `PIP_CERT`.
    Pipx,
    /// `uv <args...>` — Astral's pip replacement; `SSL_CERT_FILE` works.
    Uv,
    /// `poetry <args...>` — Python; `POETRY_REQUESTS_CA_BUNDLE` honored.
    Poetry,
    /// `go <args...>` — Go toolchain. Needs `SSL_CERT_FILE` plus `GODEBUG`
    /// fallback on macOS.
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
    /// `exec -- <cmd...>` — open-ended: sets every known env var.
    Exec,
}

impl Tool {
    /// Binary to invoke on the host, before any user-supplied first arg.
    #[must_use]
    pub const fn default_binary(self) -> Option<&'static str> {
        match self {
            Self::Curl => Some("curl"),
            Self::Wget => Some("wget"),
            Self::Npm => Some("npm"),
            Self::Pnpm => Some("pnpm"),
            Self::Yarn => Some("yarn"),
            Self::Bun => Some("bun"),
            Self::Pip => Some("pip"),
            Self::Pipx => Some("pipx"),
            Self::Uv => Some("uv"),
            Self::Poetry => Some("poetry"),
            Self::Go => Some("go"),
            Self::Cargo => Some("cargo"),
            Self::Brew => Some("brew"),
            Self::Pacman => Some("pacman"),
            Self::Yay => Some("yay"),
            Self::Paru => Some("paru"),
            Self::Makepkg => Some("makepkg"),
            Self::Dnf => Some("dnf"),
            Self::Yum => Some("yum"),
            Self::Zypper => Some("zypper"),
            Self::Rpm => Some("rpm"),
            Self::Pkg => Some("pkg"),
            Self::Apk => Some("apk"),
            // exec uses argv[0] supplied by the user.
            Self::Exec => None,
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
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
            Self::Pip => "pip",
            Self::Pipx => "pipx",
            Self::Uv => "uv",
            Self::Poetry => "poetry",
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
            Self::Exec => "exec",
        }
    }

    /// Tools eligible for shell-shim installation (everything except `Exec`).
    pub const SHIMMABLE: &'static [Self] = &[
        Self::Curl,
        Self::Wget,
        Self::Npm,
        Self::Pnpm,
        Self::Yarn,
        Self::Bun,
        Self::Pip,
        Self::Pipx,
        Self::Uv,
        Self::Poetry,
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
    // Exec is always intercepted — that's its entire purpose.
    if tool == Tool::Exec {
        return Dispatch::Intercept(args);
    }
    // curl/wget are downloaders by nature — intercept every invocation.
    if matches!(tool, Tool::Curl | Tool::Wget) {
        return Dispatch::Intercept(args);
    }

    // Decide whether this invocation touches the network. Most tools express
    // the operation as a leading positional subcommand (`npm install`); the
    // Arch and RPM families express it as a flag (`pacman -S`, `rpm -U`), so
    // they get dedicated detectors that read the whole argv.
    let fetches = match tool {
        Tool::Pacman => pacman_fetches(&args),
        Tool::Yay | Tool::Paru => aur_helper_fetches(&args),
        Tool::Makepkg => makepkg_fetches(&args),
        Tool::Rpm => rpm_fetches(&args),
        _ => is_fetching_subcommand(tool, first_positional(&args).as_deref()),
    };
    if !fetches {
        return Dispatch::Passthrough(args);
    }

    // For npm-family install-style subcommands, inject --ignore-scripts so we
    // match pnpm's default safety posture. The user can opt back in with
    // --enable-scripts on the hood command.
    let final_args = if matches!(tool, Tool::Npm | Tool::Pnpm | Tool::Yarn | Tool::Bun) {
        maybe_add_ignore_scripts(args, enable_scripts)
    } else {
        args
    };
    Dispatch::Intercept(final_args)
}

/// Find the first positional (non-flag) argument. Flags here are anything
/// starting with `-`; we don't expand combined short flags, but the only
/// thing that matters is "is the subcommand we expect at the front."
fn first_positional(args: &[OsString]) -> Option<String> {
    args.iter()
        .find(|a| !a.to_string_lossy().starts_with('-'))
        .map(|a| a.to_string_lossy().into_owned())
}

/// Per-tool subcommand list that triggers interception. Anything not in the
/// list passes through.
fn is_fetching_subcommand(tool: Tool, sub: Option<&str>) -> bool {
    let Some(sub) = sub else {
        // Bare `npm`, `pip`, etc. prints help — no network. Pass through.
        return false;
    };
    match tool {
        Tool::Curl | Tool::Wget | Tool::Exec => true, // handled before this fn

        Tool::Npm | Tool::Pnpm | Tool::Yarn => matches!(
            sub,
            "install" | "i" | "add" | "ci" | "update" | "up" | "upgrade" | "rebuild"
        ),

        Tool::Bun => matches!(sub, "install" | "i" | "add" | "x" | "update" | "upgrade"),

        Tool::Pip => matches!(sub, "install" | "download" | "wheel"),

        Tool::Pipx => matches!(sub, "install" | "upgrade" | "inject" | "run" | "runpip"),

        // uv's pip/tool subcommands are namespaced; we intercept on the
        // leading group — the inner verb is the user's business.
        Tool::Uv => matches!(sub, "pip" | "tool" | "add" | "sync" | "lock" | "run"),

        Tool::Poetry => matches!(sub, "add" | "install" | "update" | "lock" | "publish"),

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
            "install" | "in" | "reinstall" | "upgrade" | "upgrade-minimal" | "update"
                | "up" | "downgrade" | "distro-sync" | "dsync" | "group"
                | "groupinstall" | "groupupdate" | "localinstall" | "swap" | "download"
        ),

        // zypper accepts both long verbs and its classic short aliases.
        Tool::Zypper => matches!(
            sub,
            "install" | "in" | "remove-and-install" | "update" | "up" | "dist-upgrade"
                | "dup" | "patch" | "source-install" | "si" | "install-new-recommends"
                | "inr" | "refresh" | "ref"
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
                "query" | "remove" | "database" | "deptest" | "help" | "version" => {
                    return false
                }
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

/// True when an `rpm` invocation names a remote payload. rpm installs local
/// files the vast majority of the time; it only reaches the network when an
/// argument is an explicit `http(s)`/`ftp` URL, so that is the precise trigger.
fn rpm_fetches(args: &[OsString]) -> bool {
    args.iter().any(|a| {
        let s = a.to_string_lossy();
        s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
    })
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

/// Per-tool runtime context: where the proxy listens, where the CA file lives.
#[derive(Debug)]
pub struct ChildEnv {
    /// Proxy listen address as `http://host:port`.
    pub proxy_url: String,
    /// Path the child process can pass to its TLS verifier.
    pub ca_pem_path: PathBuf,
}

impl ChildEnv {
    /// Build the env-var overlay for a given tool.
    #[must_use]
    pub fn vars_for(&self, tool: Tool) -> BTreeMap<&'static str, OsString> {
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

        match tool {
            Tool::Curl => {
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            Tool::Wget => {
                out.insert("SSL_CERT_FILE", ca);
            }
            Tool::Npm | Tool::Pnpm | Tool::Yarn | Tool::Bun => {
                out.insert("NODE_EXTRA_CA_CERTS", ca.clone());
                out.insert("npm_config_proxy", proxy.clone());
                out.insert("npm_config_https_proxy", proxy);
                out.insert("npm_config_cafile", ca);
            }
            Tool::Pip | Tool::Pipx => {
                // pip uses certifi by default; PIP_CERT is the supported override.
                out.insert("PIP_CERT", ca);
            }
            Tool::Uv => {
                // uv (Astral) honors SSL_CERT_FILE and also its own UV_CA_CERT.
                out.insert("UV_CA_CERT", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            Tool::Poetry => {
                // poetry uses requests under the hood and honors
                // POETRY_REQUESTS_CA_BUNDLE per-repo, but supports the bundled
                // env at runtime as well. Set both to be safe.
                out.insert("POETRY_REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("REQUESTS_CA_BUNDLE", ca);
            }
            Tool::Go => {
                out.insert("SSL_CERT_FILE", ca);
                // macOS Go uses the system keychain unless this is set.
                // Harmless on other platforms.
                out.insert("GODEBUG", OsString::from("x509usefallbackroots=1"));
            }
            Tool::Cargo => {
                // CARGO_HTTP_CAINFO is the documented cargo override.
                // SSL_CERT_FILE covers git+https fetches that cargo invokes.
                out.insert("CARGO_HTTP_CAINFO", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            Tool::Brew => {
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
            Tool::Pacman
            | Tool::Paru
            | Tool::Makepkg
            | Tool::Dnf
            | Tool::Yum
            | Tool::Zypper
            | Tool::Rpm
            | Tool::Pkg
            | Tool::Apk => {
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("SSL_CA_CERT_FILE", ca);
            }
            Tool::Yay => {
                // yay is Go: its AUR RPC uses crypto/tls (SSL_CERT_FILE, plus
                // the macOS fallback-roots knob), while package and source
                // downloads delegate to pacman and makepkg (libcurl / curl).
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("SSL_CA_CERT_FILE", ca);
                out.insert("GODEBUG", OsString::from("x509usefallbackroots=1"));
            }
            Tool::Exec => {
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

/// Build a `ChildEnv` from a proxy address + CA pem written to a tempdir.
///
/// The returned [`TempDir`] must outlive the child process — drop it after the
/// child exits to remove the PEM file.
pub fn prepare_child_env(proxy_addr: SocketAddr, ca_pem: &str) -> Result<(ChildEnv, TempDir)> {
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
        perms.set_mode(0o644);
        std::fs::set_permissions(&pem_path, perms).context("chmod CA pem")?;
    }
    drop(f);

    let proxy_url = format!("http://{proxy_addr}");
    Ok((
        ChildEnv {
            proxy_url,
            ca_pem_path: pem_path,
        },
        dir,
    ))
}

/// Resolve the real binary for `tool`, skipping any directory matching
/// `skip_dir` during PATH search. This prevents the `hood`-installed PATH shim
/// from being invoked recursively.
fn resolve_real_binary(name: &str, skip_dir: Option<&Path>) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path) {
        if let Some(skip) = skip_dir {
            if entry == skip {
                continue;
            }
        }
        let candidate = entry.join(name);
        if is_executable(&candidate) {
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

/// Spawn the child with the chosen tool's env overlay, wait for it, and return
/// the exit code (or `1` if it was terminated by a signal).
///
/// `bin_override` lets `Tool::Exec` supply argv[0]. For named tools, pass
/// `None`. `shim_dir`, when supplied, is excluded from PATH search so the
/// installed `~/.hood/bin/<tool>` shim doesn't re-enter hood.
pub async fn run_child(
    tool: Tool,
    bin_override: Option<&Path>,
    args: Vec<OsString>,
    env: &ChildEnv,
    shim_dir: Option<&Path>,
) -> Result<i32> {
    let bin: PathBuf = match (bin_override, tool.default_binary()) {
        (Some(p), _) => p.to_path_buf(),
        (None, Some(name)) => resolve_real_binary(name, shim_dir)
            .unwrap_or_else(|| PathBuf::from(name)),
        (None, None) => {
            return Err(anyhow::anyhow!(
                "hood exec requires a command to run (use `hood exec -- <cmd> [args]`)",
            ));
        }
    };

    let mut cmd = Command::new(&bin);
    cmd.args(&args);
    for (k, v) in env.vars_for(tool) {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?
        .wait()
        .await
        .with_context(|| format!("wait {}", bin.display()))?;

    Ok(status.code().unwrap_or(1))
}

/// Pass through to the real binary without setting up the proxy. Used when
/// [`dispatch`] decides the subcommand doesn't fetch network content.
pub async fn run_passthrough(
    tool: Tool,
    bin_override: Option<&Path>,
    args: Vec<OsString>,
    shim_dir: Option<&Path>,
) -> Result<i32> {
    let bin: PathBuf = match (bin_override, tool.default_binary()) {
        (Some(p), _) => p.to_path_buf(),
        (None, Some(name)) => resolve_real_binary(name, shim_dir)
            .unwrap_or_else(|| PathBuf::from(name)),
        (None, None) => return Err(anyhow::anyhow!("missing binary for passthrough")),
    };

    let status = Command::new(&bin)
        .args(&args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?
        .wait()
        .await
        .with_context(|| format!("wait {}", bin.display()))?;

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
    fn go_env_sets_godebug_fallback_roots() {
        let v = fake_env().vars_for(Tool::Go);
        let godebug = v.get("GODEBUG").unwrap().to_string_lossy();
        assert!(godebug.contains("x509usefallbackroots=1"));
    }

    #[test]
    fn exec_env_is_superset() {
        let v = fake_env().vars_for(Tool::Exec);
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
    fn brew_install_intercepted_brew_list_passthrough() {
        let _v = intercept_args(dispatch(Tool::Brew, vec![os("install"), os("jq")], false));
        let _v = passthrough_args(dispatch(Tool::Brew, vec![os("list")], false));
    }

    #[test]
    fn curl_always_intercepted_regardless_of_args() {
        let _v = intercept_args(dispatch(Tool::Curl, vec![os("-fsSL"), os("https://x")], false));
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
        let count = args.iter().filter(|a| *a == &os("--ignore-scripts")).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn bare_invocation_is_passthrough() {
        let _v = passthrough_args(dispatch(Tool::Npm, vec![], false));
        let _v = passthrough_args(dispatch(Tool::Cargo, vec![], false));
    }

    #[test]
    fn exec_always_intercepted() {
        let _v = intercept_args(dispatch(Tool::Exec, vec![os("any"), os("args")], false));
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
        let _v = intercept_args(dispatch(Tool::Bun, vec![os("x"), os("create-app")], false));
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
        let _v = passthrough_args(dispatch(
            Tool::Poetry,
            vec![os("run"), os("pytest")],
            false,
        ));
    }

    #[test]
    fn go_mod_download_intercepted() {
        let _v = intercept_args(dispatch(
            Tool::Go,
            vec![os("mod"), os("download")],
            false,
        ));
    }

    #[test]
    fn cargo_update_and_fetch_intercepted() {
        let _v = intercept_args(dispatch(Tool::Cargo, vec![os("update")], false));
        let _v = intercept_args(dispatch(Tool::Cargo, vec![os("fetch")], false));
    }

    #[test]
    fn brew_bundle_intercepted_brew_info_passthrough() {
        let _v = intercept_args(dispatch(Tool::Brew, vec![os("bundle"), os("install")], false));
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
        assert!(v
            .get("GODEBUG")
            .is_some_and(|g| g.to_string_lossy().contains("x509usefallbackroots=1")));
    }

    #[test]
    fn exec_superset_includes_libfetch_ca() {
        let v = fake_env().vars_for(Tool::Exec);
        assert!(v.contains_key("SSL_CA_CERT_FILE"));
    }

    // ----- pacman family: flag-operation dispatch ------------------------

    #[test]
    fn pacman_sync_and_upgrade_intercepted_query_passthrough() {
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("-Syu")], false));
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("-S"), os("firefox")], false));
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("-U"), os("./p.pkg.tar.zst")], false));
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
        let _v = passthrough_args(dispatch(Tool::Rpm, vec![os("-ivh"), os("./local.rpm")], false));
        let _v = passthrough_args(dispatch(Tool::Rpm, vec![os("-q"), os("bash")], false));
    }

    // ----- subcommand package managers: dispatch -------------------------

    #[test]
    fn dnf_yum_install_intercepted_list_passthrough() {
        let _v = intercept_args(dispatch(Tool::Dnf, vec![os("install"), os("ripgrep")], false));
        let _v = intercept_args(dispatch(Tool::Yum, vec![os("upgrade")], false));
        let _v = passthrough_args(dispatch(Tool::Dnf, vec![os("list"), os("installed")], false));
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
            assert!(
                tool.default_binary().is_some(),
                "{} has no default binary",
                tool.name()
            );
            assert!(!tool.name().is_empty());
        }
    }

    #[test]
    fn exec_has_no_default_binary() {
        assert!(Tool::Exec.default_binary().is_none());
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
        // We can't safely toggle process env in parallel tests; instead, exercise
        // the function directly with a temporary scope.
        let prev = std::env::var_os("PATH");
        // SAFETY: only this thread should consult PATH during this test; resolved
        // immediately and restored before returning.
        unsafe {
            std::env::set_var("PATH", &path);
        }
        let found = resolve_real_binary("npm", Some(shim_dir.path()));
        unsafe {
            match prev {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
        }

        let found = found.unwrap();
        // Must have skipped shim_dir and found real_dir's copy.
        assert!(
            found.starts_with(real_dir.path()),
            "expected real path, got {}",
            found.display()
        );
    }
}
