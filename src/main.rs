//! `hood` — run a command behind a short-lived HTTPS-intercepting proxy that
//! scans every downloaded payload before it reaches the tool.

use std::ffi::OsString;
use std::io::Write;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use hood::go_bridge::GoBridge;
use hood::proxy::{Config, Proxy};
use hood::scanner::{AtomScanner, ScanPolicy, ScanStats};
use hood::tools::{
    Dispatch, PreparedChildEnv, Program, Tool, dispatch, prepare_child_env, resolve_real_binary,
    run_tool,
};

#[derive(Parser, Debug)]
#[command(name = "hood")]
#[command(version)]
#[command(about = "Scan HTTP(S) payloads before they reach package managers and installers")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// hood takes no options of its own before a tool's name, and passes every
/// argument after it to the tool verbatim, so a shimmed `npm -v` or
/// `curl --help` reaches npm or curl, not hood.
#[derive(Subcommand, Debug)]
enum Command {
    /// Run a supported tool through hood, as in `hood npm install`.
    /// Everything after the tool's name goes to it untouched.
    #[command(external_subcommand)]
    Tool(Vec<OsString>),
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
    /// Switch on isotope13 Enriched: approve the code shown at
    /// `dash.isotope13.io/device`. Afterwards hood checks downloads with the
    /// latest rules, the moment they clear QA, and sends the token to
    /// Beamline. To switch it off, delete the saved token file.
    Enrich,
    /// Show hood's version and which rules it checks downloads with.
    Version,
}

/// `sysexits.h`'s internal software error: hood itself failed, as opposed to
/// the tool it ran, whose own exit code is passed through.
const EX_SOFTWARE: u8 = 70;

fn main() {
    let code = hood_main();
    // End without C exit handlers. Once Security.framework has loaded trust
    // settings (macOS), CoreAnalytics registers one that waits up to ~300 ms
    // for analyticsd, which a busy machine starves. Everything hood owns has
    // dropped by now; only stdout may still hold buffered bytes.
    drop(std::io::stdout().flush());
    #[cfg(unix)]
    // SAFETY: `_exit` has no preconditions. What it skips, C exit handlers
    // and Rust destructors, is the point: hood's own state has dropped, and
    // stdout was flushed above.
    #[allow(unsafe_code)]
    unsafe {
        libc::_exit(code.into());
    };
    #[cfg(not(unix))]
    std::process::exit(code.into());
}

/// Run hood and return its exit status. The runtime, proxy and temporary
/// files all drop before this returns.
fn hood_main() -> u8 {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let cli = Cli::command()
        .after_help(format!("Tools: {}", tool_names()))
        .get_matches_from(rewrite_argv_for_shim(argv));
    let cli = Cli::from_arg_matches(&cli).unwrap_or_else(|e| e.exit());
    let verbose = verbose_from_env();
    init_logging(verbose);

    // Install Ring before rustls needs default crypto. An existing process-wide
    // provider is already usable.
    drop(rustls::crypto::ring::default_provider().install_default());

    // Hood proxies one command's traffic; scans and model loads run on the
    // blocking pool and rayon, not on async workers. Tokio's default of one
    // worker per core cost ~35 ms of thread start-up per run on 128 cores.
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get().min(4));
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hood: failed to start tokio runtime: {e:#}");
            return EX_SOFTWARE;
        }
    };

    match rt.block_on(run(cli.command, verbose)) {
        Ok(code) => u8::try_from(code).unwrap_or(1),
        Err(e) => {
            eprintln!("hood: {e:#}");
            EX_SOFTWARE
        }
    }
}

/// If `argv[0]` is a known tool shim, prepend `hood` and the canonical tool
/// name before clap parses it. Otherwise return the arguments unchanged.
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

async fn run(command: Command, verbose: bool) -> Result<i32> {
    let (program, initial_args) = match Action::try_from(command)? {
        Action::Run { program, argv } => (program, argv),
        Action::Install { force } => return hood::install::install(force).map(|()| 0),
        Action::Uninstall => return hood::install::uninstall().map(|()| 0),
        Action::Enrich => {
            // Blocking HTTP and a terminal read: off the async runtime.
            tokio::task::spawn_blocking(cleave::rule_update::enrich).await??;
            return Ok(0);
        }
        Action::Version => {
            // The rules a check would use right now, as a check decides them —
            // minus the refresh, because `version` reports and does not fetch.
            hood::scanner::select_rules();
            scan::traits_repo::prepare_runtime_env();
            // Loads the rule engines to count them: off the async runtime.
            let report = tokio::task::spawn_blocking(|| {
                cleave::version_report("hood", env!("CARGO_PKG_VERSION"))
            })
            .await?;
            println!("{report}");
            return Ok(0);
        }
    };
    let shim_dir = hood::install::shim_dir().ok();
    let invocation = format_invocation(&program, &initial_args);

    // Pass-through: skip proxy startup entirely for `npm test`, `cargo build`,
    // `go run`, etc. Hot path; no model load, no listener, no env injection.
    let dispatched = match program.tool() {
        Some(tool) => dispatch(tool, initial_args, scripts_chosen_in_env()),
        None => Dispatch::Intercept(initial_args),
    };
    let child_args = match dispatched {
        Dispatch::Passthrough(child_args) => {
            return run_tool(&program, child_args, None, shim_dir.as_deref()).await;
        }
        Dispatch::Intercept(child_args) => child_args,
    };

    let policy = resolve_policy();
    // Go reads SSL_CERT_FILE only on Unix systems other than macOS; macOS and
    // Windows consult the system store alone, so they get the loopback bridge.
    let go_bridge = cfg!(any(target_os = "macos", windows)) && program.tool() == Some(Tool::Go);
    // Zig cannot trust hood's CA on any platform; see `Tool::Zig`.
    let zig_clients = program.tool() == Some(Tool::Zig);

    let setup_result = async {
        let go_bridge = if go_bridge {
            let go = resolve_real_binary("go", shim_dir.as_deref())
                .context("no real `go` found on PATH (only the hood shim)")?;
            Some(
                GoBridge::query(&go)
                    .await
                    .context("read effective Go network settings")?,
            )
        } else {
            None
        };
        setup_proxy(
            policy,
            invocation.clone(),
            go_bridge,
            program.scan_limit(),
            zig_clients,
            verbose,
        )
        .await
    }
    .await;
    // Only the top bypass tier (`HOOD_BYPASS=3`) tolerates a startup failure
    // by forwarding unscanned — that level already forwards every verdict.
    // Levels 1 and 2 promise to keep *blocking* hostile/suspicious payloads;
    // the scanner being down makes that impossible, so an infrastructure
    // failure fails closed like Strict rather than silently downgrading to
    // "download everything unscanned."
    let proxy_setup = match setup_result {
        Ok(setup) => setup,
        Err(e) if matches!(policy, ScanPolicy::Bypass) => {
            hood::output::emit_failsafe(&invocation, policy, &format!("{e:#}"));
            return run_tool(&program, child_args, None, shim_dir.as_deref()).await;
        }
        Err(e) => return Err(e),
    };

    let exit_code = run_tool(
        &program,
        child_args,
        Some(&proxy_setup.env),
        shim_dir.as_deref(),
    )
    .await?;
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
    policy: ScanPolicy,
    invocation: String,
    go_bridge: Option<GoBridge>,
    scan_limit: Option<u64>,
    zig_clients: bool,
    show_passes: bool,
) -> Result<ProxySetup> {
    let stats = show_passes.then(|| Arc::new(ScanStats::default()));
    let scanner = {
        let stats = stats.clone();
        tokio::task::spawn_blocking(move || {
            // Network and disk: fetch what local analysis lacks up front.
            hood::scanner::prepare();
            AtomScanner::new(policy, invocation, stats)
        })
        .await
        .context("build scanner task")?
    };
    let config = Config::default()
        .with_scan_limit(scan_limit)?
        .with_zig_clients(zig_clients);
    let proxy = Proxy::new(Arc::new(scanner), config).context("build proxy")?;
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
    let mut out = match program {
        Program::Tool(tool) => tool.name().to_owned(),
        Program::Command(path) => sh_quote(&path.to_string()),
    };
    let curl = program.is_curl();
    let mut redact_next = false;
    for a in args {
        out.push(' ');
        if redact_next {
            out.push_str("'<redacted>'");
            redact_next = false;
            continue;
        }
        let (safe, takes_secret_value) = redact_invocation_arg(&a.to_string_lossy(), curl);
        redact_next = takes_secret_value;
        out.push_str(&sh_quote(&safe));
    }
    out
}

/// Flags, in any tool, whose next argument is a credential.
const SECRET_VALUE_FLAGS: &[&str] = &[
    "--header",
    "--user",
    "--proxy-user",
    "--oauth2-bearer",
    "--password",
    "--token",
    "--secret",
    "--auth",
];

/// curl's short spellings of `--header` and `--user`. Only curl's: to go and
/// apk, `-u` means update.
const CURL_SECRET_SHORT_FLAGS: [&str; 2] = ["-H", "-u"];

/// Redact a credential-bearing argument before an invocation is retained for
/// diagnostics, and say whether the argument after it is a credential too.
/// The real child argv is untouched. Deliberately broad: a less-copyable bypass
/// hint beats a registry token or Authorization header in terminal and CI logs.
fn redact_invocation_arg(arg: &str, curl: bool) -> (String, bool) {
    if SECRET_VALUE_FLAGS.contains(&arg) || (curl && CURL_SECRET_SHORT_FLAGS.contains(&arg)) {
        return (arg.to_owned(), true);
    }
    // curl also takes the value attached: `-uuser:pass`, `-HAuthorization: …`.
    if curl
        && let Some(flag) = CURL_SECRET_SHORT_FLAGS
            .into_iter()
            .find(|flag| arg.len() > flag.len() && arg.starts_with(flag))
    {
        return (format!("{flag}<redacted>"), false);
    }
    // Before `key=value`: a URL's query has `=` in it, but its userinfo
    // would survive redacting only the query.
    if let Some(url) = parse_http_url(arg) {
        return (redact_url(url).unwrap_or_else(|| arg.to_owned()), false);
    }
    if let Some((key, value)) = arg.split_once('=') {
        if is_sensitive_name(key) || SECRET_VALUE_FLAGS.contains(&key) {
            return (format!("{key}=<redacted>"), false);
        }
        // `--index-url=https://__token__:…@host/simple`
        if let Some(url) = parse_http_url(value).and_then(redact_url) {
            return (format!("{key}={url}"), false);
        }
    }
    (arg.to_owned(), false)
}

fn parse_http_url(raw: &str) -> Option<url::Url> {
    url::Url::parse(raw)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
}

/// `url` without its userinfo and with sensitive query values replaced, or
/// `None` when it carried neither.
fn redact_url(mut url: url::Url) -> Option<String> {
    let has_userinfo = !url.username().is_empty() || url.password().is_some();
    let has_secret_query = url.query_pairs().any(|(key, _)| is_sensitive_name(&key));
    if !has_userinfo && !has_secret_query {
        return None;
    }
    // An http(s) URL always has a host, so these cannot fail; if they ever
    // did, show nothing of it rather than its credentials.
    if url.set_username("").is_err() || url.set_password(None).is_err() {
        return Some("<redacted>".to_owned());
    }
    if has_secret_query {
        let pairs: Vec<(String, String)> = url
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
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    Some(url.into())
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
    Enrich,
    Version,
}

impl TryFrom<Command> for Action {
    type Error = anyhow::Error;

    fn try_from(command: Command) -> Result<Self> {
        match command {
            Command::Tool(argv) => {
                let mut argv = argv.into_iter();
                let name = argv.next().unwrap_or_default();
                let tool = name.to_str().and_then(Tool::from_name).with_context(|| {
                    format!(
                        "unknown command {}; hood runs: {}",
                        name.to_string_lossy(),
                        tool_names()
                    )
                })?;
                Ok(Self::Run {
                    program: tool.into(),
                    argv: argv.collect(),
                })
            }
            Command::Exec { argv } => {
                let mut argv = argv.into_iter();
                let program = argv.next().context("hood exec requires a command to run")?;
                Ok(Self::Run {
                    program: Program::command(program)?,
                    argv: argv.collect(),
                })
            }
            Command::Install { force } => Ok(Self::Install { force }),
            Command::Uninstall => Ok(Self::Uninstall),
            Command::Enrich => Ok(Self::Enrich),
            Command::Version => Ok(Self::Version),
        }
    }
}

/// Every tool hood runs, comma-separated, for help and errors.
fn tool_names() -> String {
    Tool::SHIMMABLE
        .iter()
        .map(|tool| tool.name())
        .collect::<Vec<_>>()
        .join(", ")
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

/// `HOOD_VERBOSE=1` prints a verdict per download and a summary. Any value but
/// `0` or `1` is reported and read as off.
fn verbose_from_env() -> bool {
    match std::env::var_os("HOOD_VERBOSE") {
        Some(value) if value == "1" => true,
        Some(value) if value != "0" => {
            eprintln!("hood: invalid HOOD_VERBOSE value ignored (expected 0 or 1)");
            false
        }
        _ => false,
    }
}

/// Whether the user already chose, in their own environment, whether package
/// lifecycle scripts run. hood then leaves `--ignore-scripts` to them; npm reads
/// its `npm_config_*` variables case-insensitively.
fn scripts_chosen_in_env() -> bool {
    std::env::vars_os().any(|(name, _)| {
        name.to_str().is_some_and(|name| {
            name.eq_ignore_ascii_case("npm_config_ignore_scripts") || name == "YARN_ENABLE_SCRIPTS"
        })
    })
}

fn init_logging(verbose: bool) {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::new("hood=debug,scan=info,cleave=warn")
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hood=info,warn"))
    };
    // Fails only if a global subscriber is already set, and nothing else in
    // hood sets one.
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
            Command::Tool(argv) => {
                assert_eq!(argv, vec!["curl", "-fsSL", "https://example.com"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn tool_flags_reach_the_tool_not_hood() {
        // A shim rewrites `npm -v` to `hood npm -v`; npm must receive it.
        for flag in ["-v", "--verbose", "--help", "-h", "--version", "-V"] {
            let cli = Cli::try_parse_from(["hood", "npm", flag, "x"]).unwrap();
            match cli.command {
                Command::Tool(argv) => assert_eq!(argv, vec!["npm", flag, "x"]),
                other => panic!("unexpected command: {other:?}"),
            }
        }
    }

    #[test]
    fn hood_takes_no_flags_before_the_tool() {
        for flag in ["-v", "--verbose", "--enable-scripts", "--model-dir"] {
            assert!(Cli::try_parse_from(["hood", flag, "npm", "install"]).is_err());
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
            Command::Tool(argv) => {
                assert_eq!(argv, vec!["npm", "install", "lodash", "--save"]);
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
    fn every_tool_parses_and_others_do_not() {
        for &tool in Tool::SHIMMABLE {
            let cli = Cli::try_parse_from(["hood", tool.name()]).unwrap();
            let Action::Run { program, .. } = Action::try_from(cli.command).unwrap() else {
                panic!("{tool} did not produce a run action");
            };
            assert_eq!(program, Program::Tool(tool));
        }
        let cli = Cli::try_parse_from(["hood", "rsync", "-a"]).unwrap();
        assert!(Action::try_from(cli.command).is_err());
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
        let argv = os_vec(&["/home/user/.hood/bin/npm", "install", "lodash"]);
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
    fn redaction_covers_every_spelling_of_a_credential() {
        let pip = |args: &[&str]| format_invocation(&Program::Tool(Tool::Pip), &os_vec(args));
        let curl = |args: &[&str]| format_invocation(&Program::Tool(Tool::Curl), &os_vec(args));
        assert_eq!(
            pip(&[
                "install",
                "--index-url=https://__token__:SECRET@pypi.corp/simple",
                "x"
            ]),
            "pip install --index-url=https://pypi.corp/simple x"
        );
        assert_eq!(
            curl(&["https://u:p@[::1]:8080/a?token=t&v=1"]),
            // The URL's own serialization percent-encodes the marker.
            "curl 'https://[::1]:8080/a?token=%3Credacted%3E&v=1'"
        );
        assert_eq!(curl(&["-uuser:pass", "x"]), "curl '-u<redacted>' x");
        assert_eq!(curl(&["-u", "user:pass", "x"]), "curl -u '<redacted>' x");
        // `-u` is update to go: its argument is a module, not a secret.
        assert_eq!(
            format_invocation(&Program::Tool(Tool::Go), &os_vec(&["get", "-u", "m"])),
            "go get -u m"
        );
    }

    #[test]
    fn format_invocation_redacts_credentials() {
        let (safe_url, _) =
            redact_invocation_arg("https://user:password@example.com/pkg?token=secret", false);
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
