//! `hood` — run a command behind a short-lived HTTPS-intercepting proxy that
//! scans every downloaded payload before it reaches the tool.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hood::proxy::{Config, Proxy, DEFAULT_MAX_BODY_BYTES};
use hood::scanner::{AllowAll, LitmusScanner, Scanner, SuspiciousPolicy};
use hood::tools::{prepare_child_env, rewrite_args, run_child, Tool};

const MIB: u64 = 1024 * 1024;

#[derive(Parser, Debug)]
#[command(name = "hood")]
#[command(version)]
#[command(about = "Scan HTTP(S) payloads before they reach package managers and installers")]
struct Cli {
    /// Override litmus model directory (default: auto-resolve via litmus models repo).
    #[arg(long, global = true)]
    model_dir: Option<PathBuf>,

    /// Disable scanning entirely; act as a transparent proxy. For debugging only.
    #[arg(long, global = true)]
    no_scan: bool,

    /// Forward suspicious payloads (with a warning) instead of blocking.
    #[arg(long, global = true)]
    allow_suspicious: bool,

    /// Maximum response body size buffered for scanning, in megabytes.
    #[arg(long, global = true, default_value_t = DEFAULT_MAX_BODY_BYTES / MIB)]
    max_body_mb: u64,

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
    /// Run `curl` with proxy + CA trust env vars set.
    Curl {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `wget` with proxy + CA trust env vars set.
    Wget {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `npm` (install/add/ci get `--ignore-scripts` by default).
    Npm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pnpm` (same trust model as npm).
    Pnpm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `pip` with proxy + `PIP_CERT` set.
    Pip {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run `go` with proxy + `SSL_CERT_FILE` + macOS fallback-roots `GODEBUG`.
    Go {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
    },
    /// Run an arbitrary command; hood injects every env var it knows.
    Exec {
        /// Binary to run, followed by its args.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true, num_args = 1..)]
        argv: Vec<OsString>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
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

async fn run(cli: Cli) -> Result<i32> {
    let suspicious = if cli.allow_suspicious {
        SuspiciousPolicy::Warn
    } else {
        SuspiciousPolicy::Block
    };

    let scanner: Arc<dyn Scanner> = if cli.no_scan {
        tracing::warn!("--no-scan: payloads will be forwarded without inspection");
        Arc::new(AllowAll)
    } else {
        Arc::new(
            LitmusScanner::load(cli.model_dir.clone(), suspicious)
                .context("load litmus scanner")?,
        )
    };

    let proxy_cfg = Config {
        max_body_bytes: cli.max_body_mb.saturating_mul(MIB),
        ..Config::default()
    };
    let proxy = Proxy::new(scanner, proxy_cfg).context("build proxy")?;
    let ca_pem = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await.context("start proxy")?;
    tracing::debug!(addr = %handle.addr, "hood proxy listening");

    let (env, _ca_tempdir) = prepare_child_env(handle.addr, &ca_pem)?;

    let (tool, argv, bin_override): (Tool, Vec<OsString>, Option<PathBuf>) = match cli.command {
        Command::Curl { args } => (Tool::Curl, args, None),
        Command::Wget { args } => (Tool::Wget, args, None),
        Command::Npm { args } => (Tool::Npm, args, None),
        Command::Pnpm { args } => (Tool::Pnpm, args, None),
        Command::Pip { args } => (Tool::Pip, args, None),
        Command::Go { args } => (Tool::Go, args, None),
        Command::Exec { mut argv } => {
            // argv[0] is the binary, the rest are its args.
            let bin = PathBuf::from(argv.remove(0));
            (Tool::Exec, argv, Some(bin))
        }
    };
    let argv = rewrite_args(tool, argv, cli.enable_scripts);

    let exit_code = run_child(tool, bin_override.as_deref(), argv, &env).await?;
    handle.stop().await;
    Ok(exit_code)
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
}
