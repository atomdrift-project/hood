//! `hood` — run a command behind a short-lived HTTPS-intercepting proxy that
//! scans every downloaded payload before it reaches the tool.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hood::proxy::{Config, Proxy};
use hood::scanner::{AllowAll, LitmusScanner, ScanPolicy, Scanner};
use hood::tools::{dispatch, prepare_child_env, run_child, run_passthrough, Dispatch, Tool};

#[derive(Parser, Debug)]
#[command(name = "hood")]
#[command(version)]
#[command(about = "Scan HTTP(S) payloads before they reach package managers and installers")]
struct Cli {
    /// Override litmus model directory (default: auto-resolve via litmus models repo).
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

    // Pass-through: skip proxy startup entirely for `npm test`, `cargo build`,
    // `go run`, etc. Hot path; no model load, no listener, no env injection.
    let args = match dispatch(tool, argv, cli.enable_scripts) {
        Dispatch::Passthrough(args) => {
            return run_passthrough(tool, bin_override.as_deref(), args, shim_dir.as_deref())
                .await;
        }
        Dispatch::Intercept(args) => args,
    };

    let policy = resolve_policy();
    let scanner = build_scanner(cli.model_dir.clone(), policy)?;
    let proxy = Proxy::new(scanner, Config::default()).context("build proxy")?;
    let ca_pem = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await.context("start proxy")?;
    tracing::debug!(addr = %handle.addr, "hood proxy listening");

    let (env, _ca_tempdir) = prepare_child_env(handle.addr, &ca_pem)?;
    let exit_code = run_child(
        tool,
        bin_override.as_deref(),
        args,
        &env,
        shim_dir.as_deref(),
    )
    .await?;
    handle.stop().await;
    Ok(exit_code)
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

/// Map the `HOOD_BYPASS` env var to a policy:
///
/// - unset or `0` → `Strict` (block hostile and suspicious)
/// - `1` → `AllowSuspicious` (block only hostile)
/// - `2` → `Bypass` (forward everything; only log)
///
/// Any other value falls back to `Strict` with a WARN so typos don't silently
/// downgrade protection.
fn resolve_policy() -> ScanPolicy {
    match std::env::var("HOOD_BYPASS").ok().as_deref() {
        None | Some("") | Some("0") => ScanPolicy::Strict,
        Some("1") => ScanPolicy::AllowSuspicious,
        Some("2") => ScanPolicy::Bypass,
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
fn build_scanner(model_dir: Option<PathBuf>, policy: ScanPolicy) -> Result<Arc<dyn Scanner>> {
    if std::env::var_os("HOOD_NO_SCAN").is_some_and(|v| !v.is_empty()) {
        tracing::warn!("HOOD_NO_SCAN set — payloads forwarded without inspection");
        return Ok(Arc::new(AllowAll));
    }
    Ok(Arc::new(
        LitmusScanner::load(model_dir, policy).context("load litmus scanner")?,
    ))
}

fn init_logging(verbose: bool) {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::new("hood=debug,litmus=info,cleave=warn")
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
        let cli =
            Cli::try_parse_from(["hood", "curl", "-fsSL", "https://example.com"]).unwrap();
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
        let cli =
            Cli::try_parse_from(["hood", "npm", "install", "lodash", "--save"]).unwrap();
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
}
