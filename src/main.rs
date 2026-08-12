//! `hood` — run a command behind a short-lived HTTPS-intercepting proxy that
//! scans every downloaded payload before it reaches the tool.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hood::go_bridge::GoBridge;
use hood::proxy::{Config, Proxy};
use hood::scanner::{AllowAll, AtomScanner, ScanPolicy, Scanner};
use hood::tools::{
    dispatch, prepare_child_env, resolve_real_binary, run_child, run_passthrough, Dispatch, Tool,
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
    /// Run `pnpm` (same intercept set as npm).
    Pnpm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `yarn` (same intercept set as npm).
    Yarn {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `bun`.
    Bun {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pip`. install/download/wheel are intercepted; everything else passes through.
    Pip {
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
    /// Run `poetry`.
    Poetry {
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
    let cli = parse_cli_with_argv0_dispatch();
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
    // Install/uninstall don't touch the proxy or scanner.
    match cli.command {
        Command::Install { force } => return hood::install::install(force),
        Command::Uninstall => return hood::install::uninstall(),
        _ => {}
    }

    let (tool, argv, bin_override) = command_to_tool(cli.command);
    let shim_dir = hood::install::shim_dir().ok();
    let invocation = format_invocation(tool, &argv, bin_override.as_deref());

    // Pass-through: skip proxy startup entirely for `npm test`, `cargo build`,
    // `go run`, etc. Hot path; no model load, no listener, no env injection.
    let args = match dispatch(tool, argv, cli.enable_scripts) {
        Dispatch::Passthrough(args) => {
            return run_passthrough(tool, bin_override.as_deref(), args, shim_dir.as_deref()).await;
        }
        Dispatch::Intercept(args) => args,
    };

    let policy = resolve_policy();

    // Setup the full scan/proxy pipeline. Only the top bypass tier
    // (`HOOD_BYPASS=3`) tolerates a startup failure by forwarding unscanned —
    // that level already forwards every verdict. Levels 1 and 2 promise to keep
    // *blocking* hostile/suspicious payloads; the scanner being down makes that
    // impossible, so an infrastructure failure fails closed like Strict rather
    // than silently downgrading to "download everything unscanned."
    let go_bridge = if cfg!(target_os = "macos") && tool == Tool::Go {
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

    let setup_result =
        setup_proxy(cli.model_dir.clone(), policy, invocation.clone(), go_bridge).await;
    let proxy_setup = match setup_result {
        Ok(setup) => setup,
        Err(e) if matches!(policy, ScanPolicy::Bypass) => {
            hood::output::emit_failsafe(&invocation, policy, &format!("{e:#}"));
            return run_passthrough(tool, bin_override.as_deref(), args, shim_dir.as_deref()).await;
        }
        Err(e) => return Err(e),
    };

    let exit_code = run_child(
        tool,
        bin_override.as_deref(),
        args,
        &proxy_setup.env,
        shim_dir.as_deref(),
    )
    .await?;
    proxy_setup.handle.stop().await;
    drop(proxy_setup.ca_tempdir);
    Ok(exit_code)
}

/// Everything `run` needs once the proxy is up. `ca_tempdir` must outlive the
/// child process — drop it after the child exits to remove the CA PEM file.
struct ProxySetup {
    handle: hood::proxy::Handle,
    env: hood::tools::ChildEnv,
    ca_tempdir: tempfile::TempDir,
}

/// Build the scanner, construct the proxy, spawn it, and prepare the child
/// env. Returns one struct holding everything the run loop needs.
async fn setup_proxy(
    model_dir: Option<PathBuf>,
    policy: ScanPolicy,
    invocation: String,
    go_bridge: Option<GoBridge>,
) -> Result<ProxySetup> {
    let scanner = build_scanner(model_dir, policy, invocation)?;
    let proxy = Proxy::new(scanner, Config::default()).context("build proxy")?;
    let ca_pem = proxy.ca_pem().to_owned();
    let go_bridge_token = proxy.go_bridge_token().to_owned();
    let handle = proxy.spawn().await.context("start proxy")?;
    tracing::debug!(addr = %handle.addr, "hood proxy listening");
    let (mut env, ca_tempdir) = prepare_child_env(handle.addr, &ca_pem)?;
    if let Some(go_bridge) = go_bridge {
        match go_bridge.child_env(handle.addr, &go_bridge_token) {
            Ok(go) => env.go = Some(go),
            Err(e) => {
                handle.stop().await;
                return Err(e).context("prepare macOS Go loopback bridge");
            }
        }
    }
    Ok(ProxySetup {
        handle,
        env,
        ca_tempdir,
    })
}

/// Build a single-line shell command that reproduces what the user typed.
/// Used inside the bypass hint so the user can copy/paste a working command.
fn format_invocation(tool: Tool, args: &[OsString], bin_override: Option<&Path>) -> String {
    let head: String = match (tool, bin_override) {
        (Tool::Exec, Some(bin)) => sh_quote(&bin.display().to_string()),
        _ => tool.name().to_owned(),
    };
    if args.is_empty() {
        return head;
    }
    let mut out = head;
    for a in args {
        out.push(' ');
        out.push_str(&sh_quote(&a.to_string_lossy()));
    }
    out
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

/// Unpack a `Command` into the tool, args, and (for `Exec`) the explicit
/// binary path the caller supplied.
fn command_to_tool(cmd: Command) -> (Tool, Vec<OsString>, Option<PathBuf>) {
    match cmd {
        Command::Curl { args } => (Tool::Curl, args, None),
        Command::Wget { args } => (Tool::Wget, args, None),
        Command::Npm { args } => (Tool::Npm, args, None),
        Command::Pnpm { args } => (Tool::Pnpm, args, None),
        Command::Yarn { args } => (Tool::Yarn, args, None),
        Command::Bun { args } => (Tool::Bun, args, None),
        Command::Pip { args } => (Tool::Pip, args, None),
        Command::Pipx { args } => (Tool::Pipx, args, None),
        Command::Uv { args } => (Tool::Uv, args, None),
        Command::Poetry { args } => (Tool::Poetry, args, None),
        Command::Go { args } => (Tool::Go, args, None),
        Command::Cargo { args } => (Tool::Cargo, args, None),
        Command::Brew { args } => (Tool::Brew, args, None),
        Command::Pacman { args } => (Tool::Pacman, args, None),
        Command::Yay { args } => (Tool::Yay, args, None),
        Command::Paru { args } => (Tool::Paru, args, None),
        Command::Makepkg { args } => (Tool::Makepkg, args, None),
        Command::Dnf { args } => (Tool::Dnf, args, None),
        Command::Yum { args } => (Tool::Yum, args, None),
        Command::Zypper { args } => (Tool::Zypper, args, None),
        Command::Rpm { args } => (Tool::Rpm, args, None),
        Command::Pkg { args } => (Tool::Pkg, args, None),
        Command::Apk { args } => (Tool::Apk, args, None),
        Command::Exec { mut argv } => {
            let bin = PathBuf::from(argv.remove(0));
            (Tool::Exec, argv, Some(bin))
        }
        Command::Install { .. } | Command::Uninstall => {
            // `run` matches these arms and returns before reaching this
            // function. Reaching this branch means a future refactor broke
            // that contract; panic is the right failure mode for a
            // violated invariant.
            unreachable!("install/uninstall must be handled before command_to_tool")
        }
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
        None | Some("") | Some("0") => ScanPolicy::Strict,
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
) -> Result<Arc<dyn Scanner>> {
    if std::env::var_os("HOOD_NO_SCAN").is_some_and(|v| !v.is_empty()) {
        tracing::warn!("HOOD_NO_SCAN set — payloads forwarded without inspection");
        return Ok(Arc::new(AllowAll));
    }
    Ok(Arc::new(
        AtomScanner::load(model_dir, policy, invocation).context("load scan scanner")?,
    ))
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
        let s = format_invocation(hood::tools::Tool::Curl, &argv, None);
        assert_eq!(s, "curl -fsSL https://example.com");
    }

    #[test]
    fn format_invocation_uses_explicit_binary_for_exec() {
        let argv = os_vec(&["./bootstrap.sh"]);
        let s = format_invocation(
            hood::tools::Tool::Exec,
            &argv,
            Some(std::path::Path::new("/usr/local/bin/bash")),
        );
        assert!(s.starts_with("/usr/local/bin/bash"));
        assert!(s.contains("./bootstrap.sh"));
    }

    #[test]
    fn format_invocation_quotes_args_with_spaces() {
        let argv = vec![OsString::from("install"), OsString::from("name with space")];
        let s = format_invocation(hood::tools::Tool::Npm, &argv, None);
        assert_eq!(s, "npm install 'name with space'");
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
