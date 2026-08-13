//! `hood` — run a command behind a short-lived HTTPS-intercepting proxy that
//! scans every downloaded payload before it reaches the tool.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hood::go_bridge::GoBridge;
use hood::proxy::{Config, Proxy};
use hood::scanner::{AllowAll, AtomScanner, ScanPolicy, ScanStats, Scanner};
use hood::tools::{
    Dispatch, PreparedChildEnv, Program, Tool, dispatch, prepare_child_env, resolve_real_binary,
    run_child, run_passthrough,
};

#[derive(Parser, Debug)]
#[command(name = "hood")]
#[command(version)]
#[command(about = "Scan HTTP(S) payloads before they reach package managers and installers")]
struct Cli {
    /// Override scan model directory (default: auto-resolve via atomscan models repo).
    #[arg(long, global = true)]
    model_dir: Option<PathBuf>,

    /// Verbose logging (debug level for hood; info for everything else).
    #[arg(short, long, global = true)]
    verbose: bool,

    /// For npm/pnpm: allow lifecycle scripts (off by default — pnpm-style).
    #[arg(long, global = true)]
    enable_scripts: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run `curl` through the proxy.
    Curl {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `wget` through the proxy.
    Wget {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `npm`. install/i/add/ci/update get `--ignore-scripts` by default;
    /// `test`/`run` and friends pass straight through.
    Npm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `npx` through the proxy; argv is preserved exactly.
    Npx {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pnpm` (same intercept set as npm).
    Pnpm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pnpx` through the proxy; argv is preserved exactly.
    Pnpx {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `yarn` (same intercept set as npm).
    Yarn {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `rush`; custom commands may provision autoinstallers.
    Rush {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `rushx`; project scripts inherit hood's proxy environment.
    Rushx {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `bun`.
    Bun {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `bunx` through the proxy; argv is preserved exactly.
    Bunx {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pip`. install/download/wheel are intercepted; everything else passes through.
    Pip {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pip3` (same intercept set and trust model as pip).
    Pip3 {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pipx`.
    Pipx {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `uv` (Astral's pip replacement).
    Uv {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `uvx` (equivalent to `uv tool run`) through the proxy.
    Uvx {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `poetry`.
    Poetry {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pdm`; dependency-resolving commands are intercepted.
    Pdm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `go`. `get`/`install`/`mod` are intercepted; `run`/`test`/`build`/`vet` pass through.
    Go {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `cargo`. `install`/`add`/`update`/`fetch` are intercepted; `build`/`test`/`run` pass through.
    Cargo {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `brew`. `install`/`upgrade`/`reinstall`/`fetch`/`tap`/`bundle` are intercepted.
    Brew {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pacman`. `-S`/`-U` (sync/upgrade) operations are intercepted; `-Q`/`-R` pass through.
    Pacman {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `yay` (Arch AUR helper). Installs and upgrades are intercepted; queries pass through.
    Yay {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `paru` (Arch AUR helper). Same intercept model as yay.
    Paru {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `makepkg`. Any build fetches sources and is intercepted; info flags pass through.
    Makepkg {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `dnf`. `install`/`upgrade`/`update`/`download` and friends are intercepted.
    Dnf {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `yum` (dnf-compatible front end).
    Yum {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `zypper`. `install`/`in`/`update`/`dup`/`patch`/`refresh` are intercepted.
    Zypper {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `rpm`. Intercepted only when given an `http(s)`/`ftp` URL; local installs pass through.
    Rpm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pkg` (FreeBSD). `install`/`add`/`upgrade`/`fetch`/`update` are intercepted.
    Pkg {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `apk` (Alpine). `add`/`upgrade`/`update`/`fetch` are intercepted.
    Apk {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run an arbitrary command; hood injects every env var it knows.
    Exec {
        /// Binary to run, followed by its args.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true, num_args = 1..)]
        argv: Vec<OsString>,
    },
    /// Install PATH shims for supported tools and wire them into your shell.
    Install {
        /// Re-run setup even if shims already exist.
        #[arg(long)]
        force: bool,
    },
    /// Remove hood shims and shell-rc entries.
    Uninstall,
}

fn main() -> ExitCode {
    let mut cli = parse_cli_with_argv0_dispatch();
    cli.verbose = resolve_verbose(cli.verbose);
    init_logging(cli.verbose);

    // Install the ring crypto provider for rustls. Without this rustls panics
    // the first time it needs default crypto.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        // Another caller (tests, etc.) already installed it — fine.
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hood: failed to start tokio runtime: {e:#}");
            return ExitCode::from(70);
        }
    };

    match rt.block_on(run(cli)) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("hood: {e:#}");
            ExitCode::from(70)
        }
    }
}

/// Busybox-style entrypoint: if `argv[0]`'s basename matches one of hood's
/// known tool shims (installed via `hood install`), translate the invocation
/// into the corresponding `hood <tool> <args>` form before clap parses it.
///
/// Falls back to the normal CLI when `argv[0]` is `hood` (the canonical name)
/// or anything unrecognized.
fn parse_cli_with_argv0_dispatch() -> Cli {
    let argv: Vec<OsString> = std::env::args_os().collect();
    Cli::parse_from(rewrite_argv_for_shim(argv))
}

/// Pure-function half of [`parse_cli_with_argv0_dispatch`]: takes the raw argv
/// and, if `argv[0]`'s basename is a recognized tool shim, prepends `hood`
/// and the canonical tool name. Otherwise the argv is returned unchanged.
fn rewrite_argv_for_shim(argv: Vec<OsString>) -> Vec<OsString> {
    let Some(argv0) = argv.first() else {
        return argv;
    };
    let basename = std::path::Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let Some(tool) = hood::install::tool_from_argv0(basename) else {
        return argv;
    };
    let mut synth: Vec<OsString> = Vec::with_capacity(argv.len().saturating_add(1));
    synth.push(OsString::from("hood"));
    synth.push(OsString::from(tool.name()));
    synth.extend(argv.into_iter().skip(1));
    synth
}

async fn run(cli: Cli) -> Result<i32> {
    let Cli {
        model_dir,
        verbose,
        enable_scripts,
        command,
    } = cli;
    let (program, initial_args) = match Action::try_from(command)? {
        Action::Run { program, argv } => (program, argv),
        Action::Install { force } => return hood::install::install(force),
        Action::Uninstall => return hood::install::uninstall(),
    };
    let shim_dir = hood::install::shim_dir().ok();
    let invocation = format_invocation(&program, &initial_args);

    // Pass-through: skip proxy startup entirely for `npm test`, `cargo build`,
    // `go run`, etc. Hot path; no model load, no listener, no env injection.
    let dispatched = match program.tool() {
        Some(tool) => dispatch(tool, initial_args, enable_scripts),
        None => Dispatch::Intercept(initial_args),
    };
    let child_args = match dispatched {
        Dispatch::Passthrough(child_args) => {
            return run_passthrough(&program, child_args, shim_dir.as_deref()).await;
        }
        Dispatch::Intercept(child_args) => child_args,
    };

    let policy = resolve_policy();

    // Setup the full scan/proxy pipeline. Only the top bypass tier
    // (`HOOD_BYPASS=3`) tolerates a startup failure by forwarding unscanned —
    // that level already forwards every verdict. Levels 1 and 2 promise to keep
    // *blocking* hostile/suspicious payloads; the scanner being down makes that
    // impossible, so an infrastructure failure fails closed like Strict rather
    // than silently downgrading to "download everything unscanned."
    let go_bridge = if cfg!(target_os = "macos") && program.tool() == Some(Tool::Go) {
        let go = resolve_real_binary("go", shim_dir.as_deref())
            .ok_or_else(|| anyhow::anyhow!("no real `go` found on PATH (only the hood shim)"))?;
        Some(
            GoBridge::query(&go)
                .await
                .context("read effective Go network settings")?,
        )
    } else {
        None
    };

    let setup_result = setup_proxy(model_dir, policy, invocation.clone(), go_bridge, verbose).await;
    let proxy_setup = match setup_result {
        Ok(setup) => setup,
        Err(e) if matches!(policy, ScanPolicy::Bypass) => {
            hood::output::emit_failsafe(&invocation, policy, &format!("{e:#}"));
            return run_passthrough(&program, child_args, shim_dir.as_deref()).await;
        }
        Err(e) => return Err(e),
    };

    let exit_code = run_child(&program, child_args, &proxy_setup.env, shim_dir.as_deref()).await?;
    proxy_setup.handle.stop().await;
    if let Some(stats) = &proxy_setup.stats {
        hood::output::emit_scan_summary(stats.snapshot());
    }
    Ok(exit_code)
}

/// Everything `run` needs once the proxy is up.
struct ProxySetup {
    handle: hood::proxy::Handle,
    env: PreparedChildEnv,
    stats: Option<Arc<ScanStats>>,
}

/// Build the scanner, construct the proxy, spawn it, and prepare the child
/// env. Returns one struct holding everything the run loop needs.
async fn setup_proxy(
    model_dir: Option<PathBuf>,
    policy: ScanPolicy,
    invocation: String,
    go_bridge: Option<GoBridge>,
    show_passes: bool,
) -> Result<ProxySetup> {
    let stats = show_passes.then(|| Arc::new(ScanStats::default()));
    let scanner = build_scanner(model_dir, policy, invocation, stats.clone())?;
    let config = Config::from_env().context("read proxy configuration")?;
    let proxy = Proxy::new(scanner, config).context("build proxy")?;
    let ca_pem = proxy.ca_pem().to_owned();
    let go_bridge_token = proxy.go_bridge_token().to_owned();
    let handle = proxy.spawn().await.context("start proxy")?;
    tracing::debug!(addr = %handle.addr, "hood proxy listening");
    let mut env = match prepare_child_env(handle.addr, &ca_pem) {
        Ok(env) => env,
        Err(error) => {
            handle.stop().await;
            return Err(error).context("prepare child trust environment");
        }
    };
    if let Some(go_bridge) = go_bridge {
        env.set_go_bridge(go_bridge.child_env(handle.addr, &go_bridge_token));
    }
    Ok(ProxySetup { handle, env, stats })
}

/// Build a single-line shell command that reproduces what the user typed.
/// Used inside the bypass hint so the user can copy/paste a working command.
fn format_invocation(program: &Program, args: &[OsString]) -> String {
    let head = match program {
        Program::Tool(tool) => tool.name().to_owned(),
        Program::Command(path) => sh_quote(&path.to_string()),
    };
    if args.is_empty() {
        return head;
    }
    let mut out = head;
    let mut redact_next = false;
    for a in args {
        out.push(' ');
        let raw = a.to_string_lossy();
        if redact_next {
            out.push_str("'<redacted>'");
            redact_next = false;
            continue;
        }
        let (safe, takes_secret_value) = redact_invocation_arg(&raw);
        redact_next = takes_secret_value;
        out.push_str(&sh_quote(&safe));
    }
    out
}

/// Redact common credential-bearing command arguments before an invocation is
/// retained for diagnostics. The real child argv is untouched. This list is
/// deliberately broad: a less-copyable bypass hint is preferable to placing a
/// registry token or Authorization header in terminal and CI logs.
fn redact_invocation_arg(arg: &str) -> (String, bool) {
    const VALUE_FLAGS: &[&str] = &[
        "-H",
        "--header",
        "-u",
        "--user",
        "--proxy-user",
        "--oauth2-bearer",
        "--password",
        "--token",
        "--secret",
        "--auth",
    ];
    if VALUE_FLAGS.contains(&arg) {
        return (arg.to_owned(), true);
    }
    if (arg.starts_with("-H") || arg.starts_with("-u")) && arg.len() > 2 {
        return (format!("{}<redacted>", &arg[..2]), false);
    }
    if !arg.contains("://")
        && let Some((key, _)) = arg.split_once('=')
        && (is_sensitive_name(key) || VALUE_FLAGS.contains(&key))
    {
        return (format!("{key}=<redacted>"), false);
    }
    if let Ok(mut url) = url::Url::parse(arg)
        && matches!(url.scheme(), "http" | "https")
    {
        let had_userinfo = !url.username().is_empty() || url.password().is_some();
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, value)| {
                let value = if is_sensitive_name(&key) {
                    "<redacted>".to_owned()
                } else {
                    value.into_owned()
                };
                (key.into_owned(), value)
            })
            .collect();
        let had_sensitive_query = query.iter().any(|(key, _)| is_sensitive_name(key));
        if had_sensitive_query {
            url.set_query(None);
            url.query_pairs_mut().extend_pairs(query);
        }
        if had_userinfo || had_sensitive_query {
            // Rebuild from the origin instead of mutating userinfo in place.
            // This keeps credentials out if setter semantics ever change.
            let mut safe = format!("{}://", url.scheme());
            if let Some(host) = url.host_str() {
                if host.contains(':') {
                    safe.push('[');
                    safe.push_str(host);
                    safe.push(']');
                } else {
                    safe.push_str(host);
                }
            }
            if let Some(port) = url.port() {
                safe.push(':');
                safe.push_str(&port.to_string());
            }
            safe.push_str(url.path());
            if let Some(query) = url.query() {
                safe.push('?');
                safe.push_str(query);
            }
            if let Some(fragment) = url.fragment() {
                safe.push('#');
                safe.push_str(fragment);
            }
            return (safe, false);
        }
    }
    (arg.to_owned(), false)
}

fn is_sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "_auth",
        "api-key",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

/// Minimal POSIX-shell quoter: wrap in single quotes when the value contains
/// anything outside `[A-Za-z0-9_./:@%+,=-]`. Embedded single quotes are
/// escaped as `'\''`.
fn sh_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_owned();
    }
    let safe = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_./:@%+,=-".contains(&b));
    if safe {
        return s.to_owned();
    }
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

#[derive(Debug)]
enum Action {
    Run {
        program: Program,
        argv: Vec<OsString>,
    },
    Install {
        force: bool,
    },
    Uninstall,
}

impl TryFrom<Command> for Action {
    type Error = anyhow::Error;

    fn try_from(command: Command) -> Result<Self> {
        let (tool, argv) = match command {
            Command::Curl { args } => (Tool::Curl, args),
            Command::Wget { args } => (Tool::Wget, args),
            Command::Npm { args } => (Tool::Npm, args),
            Command::Npx { args } => (Tool::Npx, args),
            Command::Pnpm { args } => (Tool::Pnpm, args),
            Command::Pnpx { args } => (Tool::Pnpx, args),
            Command::Yarn { args } => (Tool::Yarn, args),
            Command::Rush { args } => (Tool::Rush, args),
            Command::Rushx { args } => (Tool::Rushx, args),
            Command::Bun { args } => (Tool::Bun, args),
            Command::Bunx { args } => (Tool::Bunx, args),
            Command::Pip { args } => (Tool::Pip, args),
            Command::Pip3 { args } => (Tool::Pip3, args),
            Command::Pipx { args } => (Tool::Pipx, args),
            Command::Uv { args } => (Tool::Uv, args),
            Command::Uvx { args } => (Tool::Uvx, args),
            Command::Poetry { args } => (Tool::Poetry, args),
            Command::Pdm { args } => (Tool::Pdm, args),
            Command::Go { args } => (Tool::Go, args),
            Command::Cargo { args } => (Tool::Cargo, args),
            Command::Brew { args } => (Tool::Brew, args),
            Command::Pacman { args } => (Tool::Pacman, args),
            Command::Yay { args } => (Tool::Yay, args),
            Command::Paru { args } => (Tool::Paru, args),
            Command::Makepkg { args } => (Tool::Makepkg, args),
            Command::Dnf { args } => (Tool::Dnf, args),
            Command::Yum { args } => (Tool::Yum, args),
            Command::Zypper { args } => (Tool::Zypper, args),
            Command::Rpm { args } => (Tool::Rpm, args),
            Command::Pkg { args } => (Tool::Pkg, args),
            Command::Apk { args } => (Tool::Apk, args),
            Command::Exec { argv } => {
                let mut argv = argv.into_iter();
                let program = argv.next().context("hood exec requires a command to run")?;
                return Ok(Self::Run {
                    program: Program::command(program)?,
                    argv: argv.collect(),
                });
            }
            Command::Install { force } => return Ok(Self::Install { force }),
            Command::Uninstall => return Ok(Self::Uninstall),
        };
        Ok(Self::Run {
            program: tool.into(),
            argv,
        })
    }
}

/// Map the `HOOD_BYPASS` env var to a policy. The ladder is strict — each
/// higher level passes everything the previous one did, plus one more class
/// of payload:
///
/// - unset or `0` → `Strict` (block scan errors, suspicious, hostile)
/// - `1` → `AllowErrors` (forward on scanner failure; still block verdicts)
/// - `2` → `AllowSuspicious` (forward errors + suspicious; block hostile)
/// - `3` → `Bypass` (forward everything)
///
/// Any other value falls back to `Strict` with a WARN so typos don't silently
/// downgrade protection.
fn resolve_policy() -> ScanPolicy {
    match std::env::var("HOOD_BYPASS").ok().as_deref() {
        None | Some("" | "0") => ScanPolicy::Strict,
        Some("1") => ScanPolicy::AllowErrors,
        Some("2") => ScanPolicy::AllowSuspicious,
        Some("3") => ScanPolicy::Bypass,
        Some(other) => {
            tracing::warn!(
                value = other,
                "HOOD_BYPASS set to unrecognized value; defaulting to strict",
            );
            ScanPolicy::Strict
        }
    }
}

/// Build the live scanner. `HOOD_NO_SCAN=1` is a debug-only escape hatch
/// (loud WARN, transparent forwarding) deliberately kept off the CLI surface.
fn build_scanner(
    model_dir: Option<PathBuf>,
    policy: ScanPolicy,
    invocation: String,
    status: Option<Arc<ScanStats>>,
) -> Result<Arc<dyn Scanner>> {
    if let Some(value) = std::env::var_os("HOOD_NO_SCAN") {
        if value == "1" {
            tracing::warn!("HOOD_NO_SCAN=1 — payloads forwarded without inspection");
            return Ok(Arc::new(AllowAll));
        }
        tracing::warn!("invalid HOOD_NO_SCAN value ignored; scanning remains enabled");
    }
    Ok(Arc::new(
        AtomScanner::load_with_status(model_dir, policy, invocation, status)
            .context("load scan scanner")?,
    ))
}

/// `HOOD_VERBOSE=1` is the environment equivalent of `-v/--verbose`. Invalid
/// values fail closed to normal verbosity rather than treating every non-empty
/// string (including `0`) as an opt-in.
fn resolve_verbose(cli_verbose: bool) -> bool {
    match std::env::var_os("HOOD_VERBOSE") {
        None => cli_verbose,
        Some(value) if value == "1" => true,
        Some(_) => {
            eprintln!("hood: invalid HOOD_VERBOSE value ignored (expected 1)");
            cli_verbose
        }
    }
}

fn init_logging(verbose: bool) {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::new("hood=debug,scan=info,cleave=warn")
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hood=info,warn"))
    };
    // try_init returns SubscriberInitExt's SetGlobalDefaultError on second
    // call (tests, repeated entry); harmless to ignore.
    drop(
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .without_time()
            .try_init(),
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn curl_passes_hyphen_args() {
        let cli = Cli::try_parse_from(["hood", "curl", "-fsSL", "https://example.com"]).unwrap();
        match cli.command {
            Command::Curl { args } => {
                assert_eq!(args, vec!["-fsSL", "https://example.com"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn exec_requires_argv() {
        let result = Cli::try_parse_from(["hood", "exec"]);
        assert!(result.is_err());
    }

    #[test]
    fn exec_takes_full_command() {
        let cli = Cli::try_parse_from(["hood", "exec", "--", "ls", "-la"]).unwrap();
        match cli.command {
            Command::Exec { argv } => {
                assert_eq!(argv, vec![OsString::from("ls"), OsString::from("-la")]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn npm_with_install_args() {
        let cli = Cli::try_parse_from(["hood", "npm", "install", "lodash", "--save"]).unwrap();
        match cli.command {
            Command::Npm { args } => {
                assert_eq!(args, vec!["install", "lodash", "--save"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn safe_chain_gap_commands_parse_to_their_distinct_tools() {
        for (name, expected) in [
            ("npx", Tool::Npx),
            ("pnpx", Tool::Pnpx),
            ("rush", Tool::Rush),
            ("rushx", Tool::Rushx),
            ("bunx", Tool::Bunx),
            ("pip3", Tool::Pip3),
            ("uvx", Tool::Uvx),
            ("pdm", Tool::Pdm),
        ] {
            let cli = Cli::try_parse_from(["hood", name, "fixture"]).unwrap();
            let action = Action::try_from(cli.command).unwrap();
            let Action::Run { program, argv } = action else {
                panic!("{name} did not produce a run action");
            };
            assert_eq!(program, Program::Tool(expected), "{name}");
            assert_eq!(argv, vec![OsString::from("fixture")], "{name}");
        }
    }

    #[test]
    fn install_subcommand_parses() {
        let cli = Cli::try_parse_from(["hood", "install"]).unwrap();
        assert!(matches!(cli.command, Command::Install { force: false }));
        let cli = Cli::try_parse_from(["hood", "install", "--force"]).unwrap();
        assert!(matches!(cli.command, Command::Install { force: true }));
    }

    #[test]
    fn uninstall_subcommand_parses() {
        let cli = Cli::try_parse_from(["hood", "uninstall"]).unwrap();
        assert!(matches!(cli.command, Command::Uninstall));
    }

    // ----- argv[0] busybox dispatch ---------------------------------------

    fn os_vec(strs: &[&str]) -> Vec<OsString> {
        strs.iter().map(|s| OsString::from(*s)).collect()
    }

    #[test]
    fn rewrite_argv_passthrough_when_argv0_is_hood() {
        let argv = os_vec(&["hood", "curl", "https://x"]);
        assert_eq!(rewrite_argv_for_shim(argv.clone()), argv);
    }

    #[test]
    fn rewrite_argv_prepends_hood_and_tool_when_shimmed() {
        let argv = os_vec(&["/Users/t/.hood/bin/npm", "install", "lodash"]);
        let out = rewrite_argv_for_shim(argv);
        assert_eq!(out, os_vec(&["hood", "npm", "install", "lodash"]));
    }

    #[test]
    fn rewrite_argv_works_for_every_shimmable_tool() {
        for tool in hood::tools::Tool::SHIMMABLE {
            let argv = vec![OsString::from(tool.name()), OsString::from("--help")];
            let out = rewrite_argv_for_shim(argv);
            let expected = vec![
                OsString::from("hood"),
                OsString::from(tool.name()),
                OsString::from("--help"),
            ];
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn rewrite_argv_leaves_unknown_argv0_alone() {
        let argv = os_vec(&["rsync", "-a", "src", "dst"]);
        assert_eq!(rewrite_argv_for_shim(argv.clone()), argv);
    }

    #[test]
    fn rewrite_argv_handles_empty_input() {
        assert_eq!(rewrite_argv_for_shim(Vec::new()), Vec::<OsString>::new());
    }

    #[test]
    fn rewrite_argv_strips_path_components() {
        let argv = os_vec(&["./bin/cargo", "install", "ripgrep"]);
        let out = rewrite_argv_for_shim(argv);
        assert_eq!(out, os_vec(&["hood", "cargo", "install", "ripgrep"]));
    }

    #[test]
    fn rewrite_argv_strips_exe_suffix() {
        let argv = os_vec(&["npm.exe", "install"]);
        let out = rewrite_argv_for_shim(argv);
        assert_eq!(out, os_vec(&["hood", "npm", "install"]));
    }

    // ----- invocation rendering -------------------------------------------

    #[test]
    fn format_invocation_uses_tool_name_for_named_tools() {
        let argv = os_vec(&["-fsSL", "https://example.com"]);
        let s = format_invocation(&Program::Tool(Tool::Curl), &argv);
        assert_eq!(s, "curl -fsSL https://example.com");
    }

    #[test]
    fn format_invocation_uses_explicit_binary_for_exec() {
        let argv = os_vec(&["./bootstrap.sh"]);
        let program = Program::command("/usr/local/bin/bash").unwrap();
        let s = format_invocation(&program, &argv);
        assert!(s.starts_with("/usr/local/bin/bash"));
        assert!(s.contains("./bootstrap.sh"));
    }

    #[test]
    fn format_invocation_quotes_args_with_spaces() {
        let argv = vec![OsString::from("install"), OsString::from("name with space")];
        let s = format_invocation(&Program::Tool(Tool::Npm), &argv);
        assert_eq!(s, "npm install 'name with space'");
    }

    #[test]
    fn format_invocation_redacts_credentials() {
        let parsed = url::Url::parse("https://user:password@example.com/pkg?token=secret").unwrap();
        assert_eq!(parsed.host_str(), Some("example.com"));
        let (safe_url, _) =
            redact_invocation_arg("https://user:password@example.com/pkg?token=secret");
        assert!(!safe_url.contains("password"), "{safe_url}");
        let argv = os_vec(&[
            "-H",
            "Authorization: Bearer nation-state",
            "https://user:password@example.com/pkg?token=secret",
            "--registry-token=also-secret",
        ]);
        let rendered = format_invocation(&Program::Tool(Tool::Curl), &argv);
        assert!(!rendered.contains("nation-state"));
        assert!(!rendered.contains("password"), "{rendered}");
        assert!(!rendered.contains("secret"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn sh_quote_leaves_safe_input_alone() {
        assert_eq!(sh_quote("install"), "install");
        assert_eq!(sh_quote("/usr/local/bin/foo"), "/usr/local/bin/foo");
        assert_eq!(sh_quote("v1.2.3-rc.4"), "v1.2.3-rc.4");
    }

    #[test]
    fn sh_quote_escapes_special_input() {
        assert_eq!(sh_quote("with space"), "'with space'");
        assert_eq!(sh_quote("a$b"), "'a$b'");
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        assert_eq!(sh_quote(""), "''");
    }
}
