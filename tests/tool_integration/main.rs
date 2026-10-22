//! Command-level integration tests for every command hood supports.
//!
//! Each test runs a real package-manager executable against a local registry
//! fixture, each time with fresh state: directly, then through the compiled
//! `hood` binary under each answer its assessment service can give:
//!
//! - known good: Beamline rates the payload benign. Hood must forward it
//!   without loading its models, in at most [`MAX_SLOWDOWN`] times the direct
//!   run (or [`TIMING_FLOOR`], if that was faster).
//! - known bad: Beamline rates it hostile. Hood must block it, the tool must
//!   fail, and nothing may be installed or run.
//! - private: Beamline has no assessment, so hood scans locally.
//! - quota exceeded: Beamline answers 429, so hood shows why and scans
//!   locally. Both local scans get [`LOCAL_SLOWDOWN`] plus
//!   [`LOCAL_SCAN_ALLOWANCE`] for the analyzer's start-up.
//!
//! Beamline is a local fake, so tests are hermetic: isolated caches, no
//! public registry. Local scans use the installed scan models, downloaded once
//! outside any timed run if missing.
//!
//! Missing tools are skipped during a normal `cargo test`; strict mode
//! (`HOOD_REQUIRE_TOOL_INTEGRATION`, set by `make test-tools` and CI) treats a
//! missing prerequisite as a failure. Distribution package managers run in CI
//! containers and VMs; see `.github/workflows/ci.yml` and `tests/distro/`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
// Modules share items with this crate root as `pub(crate)`; `pub` would trip
// `unreachable_pub` in a binary crate, which this nursery lint contradicts.
#![allow(clippy::redundant_pub_crate)]

mod alpine;
mod arch;
mod contract;
mod download;
mod freebsd;
mod node;
mod python;
mod rpm;
mod toolchain;

use std::collections::{BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::Digest;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::process::Command;

/// Printed or stored by fixture packages so tests can prove they ran.
const TOOL_MARKER: &str = "hood-tool-integration-ok";

/// The most hood may slow a command down relative to running it directly.
const MAX_SLOWDOWN: u32 = 2;

/// Direct runs faster than this are budgeted as if they took this long.
/// Hood's fixed cost is about 9 ms, most of it loading its own binary; for a
/// command that finishes in a few milliseconds a ratio would measure process
/// startup rather than interception.
const TIMING_FLOOR: Duration = Duration::from_millis(20);

/// The most a local scan may slow a command down, plus analyzer start-up.
const LOCAL_SLOWDOWN: u32 = 10;

/// Fixed time allowed for the analyzer's start-up in each hood process that
/// scans locally. Loading the ONNX models takes about 80 ms; warming cleave's
/// rule engine (`prefetch_cleave_resources`) and the first scan take 2-4 s on
/// an M-series Mac with a development traits checkout.
const LOCAL_SCAN_ALLOWANCE: Duration = Duration::from_secs(8);

/// Timed attempts before an overhead failure is reported. Each attempt
/// repeats both runs and the fastest of each is compared, so a single run
/// slowed by unrelated machine load cannot fail a test.
const TIMING_ATTEMPTS: usize = 3;

/// Upper bound for any single command.
const RUN_TIMEOUT: Duration = Duration::from_secs(180);

/// Serializes timed runs within this test binary so that parallel tests do
/// not distort each other's measurements.
static TIMING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Proxy variables stripped from direct runs, so a developer's own proxy
/// cannot slow or reroute the baseline.
const PROXY_VARS: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
];

/// The message a quota-exhausted Beamline sends, as `beamline.js` words it.
const QUOTA_MESSAGE: &str =
    "anonymous quota exceeded, visit https://dash.isotope13.io/ for a token";

/// How the fake Beamline answers lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Beamline {
    /// Every artifact is analyzed: hostile when marked, benign otherwise.
    Assesses,
    /// Nothing is analyzed, as for a private package.
    Unanalyzed,
    /// The caller's hourly quota is spent.
    QuotaExceeded,
}

#[derive(Debug, Default)]
struct BeamlineState {
    mode: Option<Beamline>,
    hostile: BTreeSet<String>,
}

/// A loopback stand-in for Beamline's `GET /v1/lookup?sha256=` route,
/// answering in its NDJSON assessment and JSON error shapes.
#[derive(Debug)]
struct FakeBeamline {
    addr: SocketAddr,
    state: Arc<Mutex<BeamlineState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeBeamline {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeBeamline {
    /// Must be called from within a Tokio runtime.
    fn spawn() -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind fake Beamline")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let listener = TcpListener::from_std(listener)?;
        let state: Arc<Mutex<BeamlineState>> = Arc::default();
        let served = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&served);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let response = Self::answer(&state, &req);
                        async move { Ok::<_, hyper::Error>(response) }
                    });
                    drop(
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await,
                    );
                });
            }
        });
        Ok(Self { addr, state, task })
    }

    fn answer(state: &Mutex<BeamlineState>, req: &Request<Incoming>) -> Response<Full<Bytes>> {
        let sha256 = req
            .uri()
            .query()
            .and_then(|query| {
                query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("sha256="))
            })
            .unwrap_or_default()
            .to_owned();
        let (mode, hostile) = {
            let state = state.lock().unwrap();
            (
                state.mode.unwrap_or(Beamline::Assesses),
                state.hostile.contains(&sha256),
            )
        };
        let (status, body) = match mode {
            Beamline::Assesses => {
                let severity = if hostile { "hostile" } else { "benign" };
                let assessment = serde_json::json!({
                    "status": "analyzed", "severity": severity, "sha256": sha256, "findings": [],
                });
                (StatusCode::OK, format!("{assessment}\n"))
            }
            Beamline::Unanalyzed => {
                let assessment = serde_json::json!({
                    "status": "unanalyzed", "severity": "unknown", "sha256": sha256,
                });
                (StatusCode::OK, format!("{assessment}\n"))
            }
            Beamline::QuotaExceeded => {
                let error = serde_json::json!({
                    "error": {"code": "quota_exceeded", "message": QUOTA_MESSAGE},
                });
                (StatusCode::TOO_MANY_REQUESTS, error.to_string())
            }
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/x-ndjson")
            .header("retry-after", "1800")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn set(&self, mode: Beamline, hostile: Option<String>) {
        let mut state = self.state.lock().unwrap();
        state.mode = Some(mode);
        state.hostile = hostile.into_iter().collect();
    }
}

/// The scan models for local analysis, installed once (downloading on first
/// use) outside any timed run.
async fn scan_models() -> Result<PathBuf> {
    static MODELS: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();
    MODELS
        .get_or_try_init(|| async {
            tokio::task::spawn_blocking(scan::models_repo::ensure_model_dir)
                .await
                .context("join scan model install")?
        })
        .await
        .cloned()
}

/// What a scenario downloads: the artifact the known-bad mode marks hostile,
/// and a fragment of the URL hood logs for it.
#[derive(Debug, Clone, Copy)]
struct Payload<'a> {
    bytes: &'a [u8],
    url: &'a str,
}

type Route = (String, Vec<u8>);
type Routes = Arc<Mutex<HashMap<String, Route>>>;

/// A loopback HTTP origin serving fixture files by path. Query strings are
/// ignored, so `/rpc?type=info` matches a `/rpc` route.
#[derive(Debug)]
struct TestOrigin {
    addr: SocketAddr,
    routes: Routes,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestOrigin {
    async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind tool-test origin")?;
        let addr = listener.local_addr().context("tool-test origin address")?;
        let routes: Routes = Arc::default();
        let served_routes = Arc::clone(&routes);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let routes = Arc::clone(&served_routes);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let route = routes.lock().unwrap().get(req.uri().path()).cloned();
                        async move {
                            let response = match route {
                                Some((content_type, body)) => Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", content_type)
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                                None => Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .header("content-type", "text/plain")
                                    .body(Full::new(Bytes::from_static(b"not found\n")))
                                    .unwrap(),
                            };
                            Ok::<_, hyper::Error>(response)
                        }
                    });
                    drop(
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await,
                    );
                });
            }
        });
        Ok(Self { addr, routes, task })
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The origin's URL spelled so a Go client routes it through `HTTP_PROXY`.
    ///
    /// Go never proxies `localhost` or a loopback IP, regardless of `NO_PROXY`,
    /// so a URL of `http://127.0.0.1:…` would reach the fixture directly and
    /// hood would see nothing. The unspecified address is not loopback to that
    /// rule, and a connection to `0.0.0.0:port` lands on the local listener on
    /// every Unix, so hood forwards to the same fixture.
    fn go_url(&self) -> String {
        format!("http://0.0.0.0:{}", self.addr.port())
    }

    fn add_route(&self, path: impl Into<String>, content_type: &str, body: Vec<u8>) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.into(), (content_type.to_owned(), body));
    }

    /// Serve every file below `dir` at `prefix/<relative path>`.
    fn add_dir(&self, prefix: &str, dir: &Path) -> Result<()> {
        for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let route = format!("{prefix}/{}", name.to_string_lossy());
            if path.is_dir() {
                self.add_dir(&route, &path)?;
            } else {
                self.add_route(route, "application/octet-stream", fs::read(&path)?);
            }
        }
        Ok(())
    }
}

/// A command to run, built fresh for each run by a test's prepare closure.
#[derive(Debug)]
struct Invocation {
    cwd: PathBuf,
    args: Vec<OsString>,
    envs: Vec<(String, OsString)>,
}

impl Invocation {
    fn new(cwd: &Path) -> Self {
        Self {
            cwd: cwd.to_path_buf(),
            args: Vec::new(),
            envs: Vec::new(),
        }
    }

    fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    fn env(mut self, key: &str, value: impl Into<OsString>) -> Self {
        self.envs.push((key.to_owned(), value.into()));
        self
    }
}

#[derive(Debug)]
struct Output {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

/// The hood run of a comparison and the directory its state lives in.
#[derive(Debug)]
struct Run {
    output: Output,
    dir: PathBuf,
}

#[derive(Debug)]
struct ToolHarness {
    root: TempDir,
    path: OsString,
    beamline: FakeBeamline,
    /// An empty model directory: any local scan attempted with it fails.
    no_models: PathBuf,
}

impl ToolHarness {
    fn new(tool_binary: &Path) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("hood-tool-integration-")
            .tempdir()
            .context("create tool integration tempdir")?;
        let tool_dir = tool_binary
            .parent()
            .ok_or_else(|| anyhow!("tool binary has no parent: {}", tool_binary.display()))?;
        // Drop installed hood shims so that tools a command spawns (a script
        // calling `npm`, a build step calling `curl`) are the real ones in
        // both runs; the direct baseline must not run hood.
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(tool_dir.to_path_buf())
                .chain(std::env::split_paths(&inherited).filter(|dir| !is_hood_shim_dir(dir))),
        )
        .context("construct integration-test PATH")?;
        let no_models = root.path().join("no-models");
        fs::create_dir_all(&no_models)?;
        Ok(Self {
            root,
            path,
            beamline: FakeBeamline::spawn()?,
            no_models,
        })
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// Run a scenario directly and through hood in every Beamline mode, each
    /// in a fresh directory handed to `prepare`, and return the known-good
    /// hood run for further assertions. `accepted` reports whether a run
    /// installed, saved, or executed the payload.
    async fn exercise<P, A>(
        &self,
        tool: &str,
        binary: &Path,
        prepare: P,
        payload: Payload<'_>,
        accepted: A,
    ) -> Result<Run>
    where
        P: Fn(&Path) -> Result<Invocation> + Sync,
        A: Fn(&Run) -> bool + Sync,
    {
        let (good, direct) = self.compare(tool, binary, &prepare).await?;
        assert_success(tool, &good.output);
        assert_forwarded(tool, &good.output, payload.url);
        assert!(
            accepted(&good),
            "{tool} did not accept the known-good payload:\n{}",
            good.output.stderr
        );

        self.beamline
            .set(Beamline::Assesses, Some(sha256_hex(payload.bytes)));
        let (bad, _) = self
            .run_hood(tool, "known-bad", &prepare, &self.no_models)
            .await?;
        assert_blocked(tool, &bad.output, payload.url);
        assert!(!accepted(&bad), "{tool} accepted a blocked payload");

        let models = match scan_models().await {
            Ok(models) => models,
            Err(error) => {
                skip::<()>(tool, &format!("scan models unavailable: {error:#}"))?;
                return Ok(good);
            }
        };
        let budget = direct.max(TIMING_FLOOR) * LOCAL_SLOWDOWN + LOCAL_SCAN_ALLOWANCE;
        for (mode, label, evidence) in [
            (
                Beamline::Unanalyzed,
                "private",
                "Beamline has no matching assessment; scanning locally".to_owned(),
            ),
            (
                Beamline::QuotaExceeded,
                "quota-exceeded",
                format!(
                    "Beamline returned HTTP 429 Too Many Requests: {QUOTA_MESSAGE} (retry after 1800s)"
                ),
            ),
        ] {
            self.beamline.set(mode, None);
            let run = self.timed(tool, label, &prepare, &models, budget).await?;
            assert_success(tool, &run.output);
            assert!(
                run.output.stderr.contains(&evidence),
                "hood+{tool} ({label}) did not report {evidence:?}:\n{}",
                run.output.stderr
            );
            assert!(
                run.output.stderr.contains("Atomdrift Hood scan passed"),
                "hood+{tool} ({label}) did not scan locally:\n{}",
                run.output.stderr
            );
            assert!(
                accepted(&run),
                "{tool} ({label}) did not accept the payload"
            );
        }
        self.beamline.set(Beamline::Assesses, None);
        Ok(good)
    }

    /// Run a scenario directly and through hood with Beamline rating
    /// everything benign, and return the first hood run and the fastest
    /// direct time. The direct run must succeed; a successful hood run must
    /// fit [`time_budget`].
    async fn compare<F>(&self, tool: &str, binary: &Path, prepare: F) -> Result<(Run, Duration)>
    where
        F: Fn(&Path) -> Result<Invocation> + Sync,
    {
        let _serial = TIMING.lock().await;
        self.beamline.set(Beamline::Assesses, None);
        let mut fastest_direct = Duration::MAX;
        let mut fastest_hood = Duration::MAX;
        let mut first = None;
        for attempt in 0..TIMING_ATTEMPTS {
            let dir = self.dir(&format!("{tool}-direct-{attempt}"));
            fs::create_dir_all(&dir)?;
            let invocation = prepare(&dir)?;
            let (output, direct) = self.direct(binary, &invocation).await?;
            if !output.status.success() {
                bail!(
                    "direct {tool} failed\nstdout:\n{}\nstderr:\n{}",
                    output.stdout,
                    output.stderr
                );
            }
            fastest_direct = fastest_direct.min(direct);

            let (run, hood) = self
                .run_hood(
                    tool,
                    &format!("known-good-{attempt}"),
                    &prepare,
                    &self.no_models,
                )
                .await?;
            let failed = !run.output.status.success();
            if first.is_none() {
                first = Some(run);
            }
            if failed {
                break;
            }
            fastest_hood = fastest_hood.min(hood);
            eprintln!("{tool} known-good attempt {attempt}: direct {direct:?}, hood {hood:?}");
            if fastest_hood <= time_budget(fastest_direct) {
                break;
            }
        }
        let run = first.ok_or_else(|| anyhow!("no {tool} run recorded"))?;
        if run.output.status.success() {
            assert!(
                fastest_hood <= time_budget(fastest_direct),
                "hood {tool} took {fastest_hood:?}, over {MAX_SLOWDOWN}x the direct {fastest_direct:?}",
            );
        }
        Ok((run, fastest_direct))
    }

    /// Run a scenario through hood until it fits `budget`, and return the
    /// first run.
    async fn timed<F>(
        &self,
        tool: &str,
        label: &str,
        prepare: F,
        models: &Path,
        budget: Duration,
    ) -> Result<Run>
    where
        F: Fn(&Path) -> Result<Invocation> + Sync,
    {
        let _serial = TIMING.lock().await;
        let mut fastest = Duration::MAX;
        let mut first = None;
        for attempt in 0..TIMING_ATTEMPTS {
            let (run, elapsed) = self
                .run_hood(tool, &format!("{label}-{attempt}"), &prepare, models)
                .await?;
            let failed = !run.output.status.success();
            if first.is_none() {
                first = Some(run);
            }
            if failed {
                break;
            }
            fastest = fastest.min(elapsed);
            eprintln!("{tool} {label} attempt {attempt}: hood {elapsed:?}, budget {budget:?}");
            if fastest <= budget {
                break;
            }
        }
        let run = first.ok_or_else(|| anyhow!("no {tool} run recorded"))?;
        if run.output.status.success() {
            assert!(
                fastest <= budget,
                "hood {tool} ({label}) took {fastest:?}, over its {budget:?} budget",
            );
        }
        Ok(run)
    }

    /// Run a scenario once through hood in a fresh directory named `label`.
    async fn run_hood<F>(
        &self,
        tool: &str,
        label: &str,
        prepare: F,
        models: &Path,
    ) -> Result<(Run, Duration)>
    where
        F: Fn(&Path) -> Result<Invocation> + Sync,
    {
        let dir = self.dir(&format!("{tool}-{label}"));
        fs::create_dir_all(&dir)?;
        let invocation = prepare(&dir)?;
        let (output, elapsed) = self.hood(tool, &invocation, models).await?;
        Ok((Run { output, dir }, elapsed))
    }

    async fn direct(&self, binary: &Path, invocation: &Invocation) -> Result<(Output, Duration)> {
        let mut command = Command::new(binary);
        command.args(&invocation.args);
        for key in PROXY_VARS {
            command.env_remove(key);
        }
        self.execute(command, invocation).await
    }

    /// Run `tool` through hood against the fake Beamline, scanning locally
    /// with `models` when Beamline gives no verdict.
    async fn hood(
        &self,
        tool: &str,
        invocation: &Invocation,
        models: &Path,
    ) -> Result<(Output, Duration)> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hood"));
        command
            .arg("--verbose")
            .arg("--model-dir")
            .arg(models)
            .arg(tool)
            .args(&invocation.args)
            .env("HOOD_HOME", self.dir("hood-home"))
            .env("HOOD_BEAMLINE_URL", self.beamline.url())
            .env("HOOD_BEAMLINE_CACHE_TTL_SECS", "0")
            .env("HOOD_NO_BLOOM", "1");
        for key in [
            "HOOD_LOCAL",
            "HOOD_NO_SCAN",
            "HOOD_BYPASS",
            "HOOD_BEAMLINE_TOKEN",
            "SCAN_MODELS_DIR",
        ] {
            command.env_remove(key);
        }
        self.execute(command, invocation).await
    }

    async fn execute(
        &self,
        mut command: Command,
        invocation: &Invocation,
    ) -> Result<(Output, Duration)> {
        command
            .env("PATH", &self.path)
            .current_dir(&invocation.cwd)
            .kill_on_drop(true);
        for (key, value) in &invocation.envs {
            command.env(key, value);
        }
        let started = Instant::now();
        let output = tokio::time::timeout(RUN_TIMEOUT, command.output())
            .await
            .context("integration command timed out")??;
        let elapsed = started.elapsed();
        Ok((
            Output {
                status: output.status,
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            },
            elapsed,
        ))
    }
}

/// The longest a hood run may take given the direct run's duration.
fn time_budget(direct: Duration) -> Duration {
    direct.max(TIMING_FLOOR) * MAX_SLOWDOWN
}

/// True for a PATH entry holding hood's shims (symlinks resolving to hood).
fn is_hood_shim_dir(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        entry.file_type().is_ok_and(|kind| kind.is_symlink()) && is_hood(&entry.path())
    })
}

fn is_hood(path: &Path) -> bool {
    path.canonicalize()
        .ok()
        .and_then(|path| path.file_name().map(OsStr::to_owned))
        .is_some_and(|file| file == "hood" || file == "hood.exe")
}

/// Locate a selected tool's real binary, skipping it when unavailable unless
/// strict mode requires it.
fn tool_binary(name: &str) -> Result<Option<PathBuf>> {
    if !tool_is_selected(name) {
        return Ok(None);
    }
    path_binary(name).map_or_else(|| missing_tool(name), |binary| Ok(Some(binary)))
}

/// Find `name` on PATH, skipping hood shims.
fn path_binary(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|dir| [dir.join(name), dir.join(format!("{name}.exe"))])
        .find(|candidate| candidate.is_file() && !is_hood(candidate))
}

fn missing_tool<T>(name: &str) -> Result<Option<T>> {
    skip(name, "executable unavailable")
}

/// Skip a test, or fail it when strict mode requires `name`.
fn skip<T>(name: &str, reason: &str) -> Result<Option<T>> {
    if tool_is_required(name) {
        bail!("required integration-test tool `{name}` cannot run: {reason}");
    }
    eprintln!("skipping {name} integration test: {reason}");
    Ok(None)
}

fn required_tools() -> Option<String> {
    std::env::var_os("HOOD_REQUIRE_TOOL_INTEGRATION").map(|value| value.to_string_lossy().into())
}

fn tool_is_required(name: &str) -> bool {
    required_tools().is_some_and(|required| list_names(&required, name))
}

fn tool_is_selected(name: &str) -> bool {
    required_tools().is_none_or(|selected| list_names(&selected, name))
}

fn list_names(list: &str, name: &str) -> bool {
    matches!(list, "1" | "all") || list.split(',').map(str::trim).any(|item| item == name)
}

/// True when running as root; system package managers need it to write
/// their lock files, while AUR tooling refuses it.
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|output| output.stdout.trim_ascii() == b"0")
}

fn assert_success(tool: &str, output: &Output) {
    assert!(
        output.status.success(),
        "hood+{tool} failed\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr,
    );
    assert!(
        output.stderr.contains("hood proxy listening"),
        "hood+{tool} did not start the proxy:\n{}",
        output.stderr,
    );
    assert!(
        !output
            .stderr
            .contains("certificate signed by unknown authority"),
        "hood+{tool} rejected hood's CA:\n{}",
        output.stderr,
    );
}

/// Assert hood logged a forward of a URL containing `url`.
fn assert_forwarded(tool: &str, output: &Output, url: &str) {
    assert!(
        output
            .stderr
            .lines()
            .any(|line| line.contains("forward") && line.contains(url)),
        "hood+{tool} reached {url} without a visible proxy forward:\n{}",
        output.stderr,
    );
}

/// Assert hood blocked a hostile download from a URL containing `url`, and
/// that the tool failed because of it.
fn assert_blocked(tool: &str, output: &Output, url: &str) {
    assert!(
        output.stderr.lines().any(|line| {
            line.contains("block") && line.contains(url) && line.contains("hostile")
        }),
        "hood+{tool} did not block the hostile payload from {url}:\n{}",
        output.stderr,
    );
    assert!(
        !output.status.success(),
        "{tool} succeeded despite the blocked payload\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr,
    );
}

/// Return the first file below `dir` whose name satisfies `matches`.
fn find_file(dir: &Path, matches: &dyn Fn(&str) -> bool) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .find_map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                find_file(&path, matches)
            } else {
                matches(&entry.file_name().to_string_lossy()).then_some(path)
            }
        })
}

fn tar_header(path: &str, mode: u32, len: usize) -> Result<tar::Header> {
    let mut header = tar::Header::new_gnu();
    header.set_path(path)?;
    header.set_size(u64::try_from(len)?);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_cksum();
    Ok(header)
}

/// Build a gzip-compressed tar of `(path, mode, contents)` entries.
fn tar_gz(files: &[(&str, u32, &[u8])]) -> Result<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, mode, body) in files {
        let mut header = tar_header(path, *mode, body.len())?;
        archive.append_data(&mut header, path, *body)?;
    }
    archive.finish()?;
    Ok(archive.into_inner()?.finish()?)
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    digest
        .iter()
        .fold(String::with_capacity(digest.len() * 2), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// Run a fixture-building helper command (`git`, `rpmbuild`, …) to completion.
async fn helper(program: &str, args: &[&OsStr], cwd: &Path) -> Result<String> {
    let output = tokio::time::timeout(
        RUN_TIMEOUT,
        Command::new(program)
            .args(args)
            .current_dir(cwd)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .with_context(|| format!("{program} timed out"))?
    .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {args:?} failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Every supported command must have a test here and be required by a CI job,
/// so no command can silently lose coverage.
#[test]
fn every_supported_command_is_tested_and_required_in_ci() {
    let tested: BTreeSet<&str> = [
        alpine::TOOLS,
        arch::TOOLS,
        download::TOOLS,
        freebsd::TOOLS,
        node::TOOLS,
        python::TOOLS,
        rpm::TOOLS,
        toolchain::TOOLS,
    ]
    .concat()
    .into_iter()
    .collect();
    let required = ci_required_tools(include_str!("../../.github/workflows/ci.yml"));
    for tool in hood::tools::Tool::SHIMMABLE {
        let name = tool.name();
        assert!(tested.contains(name), "no integration test for `{name}`");
        assert!(
            required.contains(name),
            "no CI job sets `{name}` in HOOD_REQUIRE_TOOL_INTEGRATION or require-tools",
        );
    }
}

/// Collect tool names from `HOOD_REQUIRE_TOOL_INTEGRATION` and `require-tools`
/// assignments (`KEY: list`, `KEY=list`) in a workflow.
fn ci_required_tools(workflow: &str) -> BTreeSet<&str> {
    let mut tools = BTreeSet::new();
    for key in ["HOOD_REQUIRE_TOOL_INTEGRATION", "require-tools"] {
        for (at, _) in workflow.match_indices(key) {
            let rest = workflow[at + key.len()..].trim_start_matches([':', '=', ' ', '"', '\'']);
            let list = rest
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == ','))
                .next()
                .unwrap_or_default();
            tools.extend(list.split(',').filter(|name| !name.is_empty()));
        }
    }
    tools
}

#[test]
fn ci_required_tools_reads_env_and_matrix_lists() {
    let workflow = "env:\n  HOOD_REQUIRE_TOOL_INTEGRATION: curl,npm\n  - require-tools: \"dnf,yum\"\nrun: HOOD_REQUIRE_TOOL_INTEGRATION=pacman cargo test\n  HOOD_REQUIRE_TOOL_INTEGRATION: ${{ matrix.x }}\n";
    let tools = ci_required_tools(workflow);
    assert_eq!(
        tools.into_iter().collect::<Vec<_>>(),
        ["curl", "dnf", "npm", "pacman", "yum"]
    );
}
