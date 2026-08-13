//! Command-level integration tests for package managers supported by hood.
//!
//! Each test launches the compiled `hood` binary, a real package-manager
//! executable, and a local registry/proxy fixture. Tests remain hermetic: they
//! use isolated caches and never depend on a public registry. Missing tools are
//! skipped during a normal `cargo test`; `make test-tools` enables strict mode
//! and treats a missing prerequisite as a failure.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha512};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::process::Command;

const GO_MODULE: &str = "example.com/hood-integration";
const GO_VERSION: &str = "v1.0.0";
const GO_SOURCE: &str = "package hoodintegration\n\nconst ThroughHood = true\n";
const NPM_PACKAGE: &str = "hood-integration-cli";
const PYPI_PACKAGE: &str = "hood-integration";
const PYPI_VERSION: &str = "1.0.0";
const TOOL_MARKER: &str = "hood-tool-integration-ok";

type Route = (String, Vec<u8>);
type Routes = Arc<Mutex<HashMap<String, Route>>>;

#[derive(Debug)]
struct TestOrigin {
    addr: SocketAddr,
    routes: Routes,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestOrigin {
    async fn spawn(routes: HashMap<String, Route>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind tool-test origin")?;
        let addr = listener.local_addr().context("tool-test origin address")?;
        let routes = Arc::new(Mutex::new(routes));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let served_routes = Arc::clone(&routes);
        let request_log = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let routes = Arc::clone(&served_routes);
                let requests = Arc::clone(&request_log);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let routes = Arc::clone(&routes);
                        let requests = Arc::clone(&requests);
                        async move {
                            let path = req.uri().path().to_owned();
                            requests.lock().unwrap().push(path.clone());
                            let route = routes.lock().unwrap().get(&path).cloned();
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
        Ok(Self {
            addr,
            routes,
            requests,
            task,
        })
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requested_paths(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn add_route(&self, path: impl Into<String>, content_type: &str, body: Vec<u8>) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.into(), (content_type.to_owned(), body));
    }
}

#[derive(Debug)]
struct ToolHarness {
    root: TempDir,
    path: OsString,
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
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(tool_dir.to_path_buf()).chain(std::env::split_paths(&inherited)),
        )
        .context("construct integration-test PATH")?;
        Ok(Self { root, path })
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    async fn hood(&self, tool: &str, args: &[&str], envs: &[(&str, OsString)]) -> Result<Output> {
        self.hood_in(self.root.path(), tool, args, envs).await
    }

    async fn hood_in(
        &self,
        cwd: &Path,
        tool: &str,
        args: &[&str],
        envs: &[(&str, OsString)],
    ) -> Result<Output> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hood"));
        command
            .arg("--verbose")
            .arg(tool)
            .args(args)
            .env("PATH", &self.path)
            .env("HOOD_HOME", self.dir("hood-home"))
            .env("HOOD_NO_SCAN", "1")
            .env("HOOD_NO_BLOOM", "1")
            .current_dir(cwd)
            .kill_on_drop(true);
        for (key, value) in envs {
            command.env(key, value);
        }
        let output = tokio::time::timeout(Duration::from_secs(30), command.output())
            .await
            .context("hood integration test timed out")??;
        Ok(Output {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Debug)]
struct Output {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

/// Locate the real Go binary behind any `go` shim already on PATH. Normal
/// developer test runs skip an unavailable ecosystem; strict runs fail so CI
/// cannot silently lose coverage.
async fn go_binary() -> Result<Option<PathBuf>> {
    if !tool_is_selected("go") {
        return Ok(None);
    }
    let output = Command::new("go").arg("env").arg("GOROOT").output().await;
    let Ok(output) = output else {
        return missing_tool("go");
    };
    if !output.status.success() {
        return missing_tool("go");
    }
    let goroot = String::from_utf8(output.stdout)
        .context("Go GOROOT is not UTF-8")?
        .trim()
        .to_owned();
    let binary = PathBuf::from(goroot).join("bin").join("go");
    if binary.is_file() {
        Ok(Some(binary))
    } else {
        missing_tool("go")
    }
}

fn tool_binary(name: &str) -> Result<Option<PathBuf>> {
    if !tool_is_selected(name) {
        return Ok(None);
    }
    let Some(path) = std::env::var_os("PATH") else {
        return missing_tool(name);
    };
    for dir in std::env::split_paths(&path) {
        for candidate in [dir.join(name), dir.join(format!("{name}.exe"))] {
            let is_hood_shim = candidate
                .canonicalize()
                .ok()
                .and_then(|path| path.file_name().map(std::ffi::OsStr::to_owned))
                .is_some_and(|file| file == "hood" || file == "hood.exe");
            if candidate.is_file() && !is_hood_shim {
                return Ok(Some(candidate));
            }
        }
    }
    missing_tool(name)
}

fn missing_tool(name: &str) -> Result<Option<PathBuf>> {
    if tool_is_required(name) {
        return Err(anyhow!(
            "required integration-test tool `{name}` is unavailable"
        ));
    }
    eprintln!("skipping {name} integration test: executable unavailable");
    Ok(None)
}

fn tool_is_required(name: &str) -> bool {
    let Some(required) = std::env::var_os("HOOD_REQUIRE_TOOL_INTEGRATION") else {
        return false;
    };
    let required = required.to_string_lossy();
    matches!(required.as_ref(), "1" | "all")
        || required
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == name)
}

fn tool_is_selected(name: &str) -> bool {
    let Some(selected) = std::env::var_os("HOOD_REQUIRE_TOOL_INTEGRATION") else {
        return true;
    };
    let selected = selected.to_string_lossy();
    matches!(selected.as_ref(), "1" | "all")
        || selected
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == name)
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

fn append_tar_file<W: Write>(
    archive: &mut tar::Builder<W>,
    path: &str,
    mode: u32,
    body: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(u64::try_from(body.len())?);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, path, body)?;
    Ok(())
}

fn npm_package_tarball(version: &str) -> Result<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let package_json = format!(
        r#"{{"name":"{NPM_PACKAGE}","version":"{version}","bin":{{"{NPM_PACKAGE}":"cli.js"}}}}"#,
    );
    append_tar_file(
        &mut archive,
        "package/package.json",
        0o644,
        package_json.as_bytes(),
    )?;
    append_tar_file(
        &mut archive,
        "package/cli.js",
        0o755,
        format!("#!/usr/bin/env node\nconsole.log('{TOOL_MARKER}')\n").as_bytes(),
    )?;
    archive.finish()?;
    Ok(archive.into_inner()?.finish()?)
}

async fn npm_origin() -> Result<(TestOrigin, String)> {
    let origin = TestOrigin::spawn(HashMap::new()).await?;
    let version = format!("1.0.{}", origin.addr.port());
    let tarball = npm_package_tarball(&version)?;
    let integrity = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tarball));
    let tarball_path = format!("/{NPM_PACKAGE}/-/{NPM_PACKAGE}-{version}.tgz");
    let metadata = format!(
        r#"{{"name":"{NPM_PACKAGE}","dist-tags":{{"latest":"{version}"}},"versions":{{"{version}":{{"name":"{NPM_PACKAGE}","version":"{version}","bin":{{"{NPM_PACKAGE}":"cli.js"}},"dist":{{"tarball":"{}{tarball_path}","integrity":"sha512-{integrity}"}}}}}}}}"#,
        origin.url(),
    );
    origin.add_route(
        format!("/{NPM_PACKAGE}"),
        "application/vnd.npm.install-v1+json",
        metadata.into_bytes(),
    );
    origin.add_route(tarball_path, "application/octet-stream", tarball);
    Ok((origin, version))
}

fn python_wheel() -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let dist_info = format!("hood_integration-{PYPI_VERSION}.dist-info");
    archive.start_file("hood_integration/__init__.py", options)?;
    archive.write_all(b"def main():\n    print(\"hood-tool-integration-ok\")\n")?;
    archive.start_file(format!("{dist_info}/METADATA"), options)?;
    archive.write_all(
        format!(
            "Metadata-Version: 2.1\nName: {PYPI_PACKAGE}\nVersion: {PYPI_VERSION}\nSummary: hood integration fixture\n"
        )
        .as_bytes(),
    )?;
    archive.start_file(format!("{dist_info}/WHEEL"), options)?;
    archive.write_all(
        b"Wheel-Version: 1.0\nGenerator: hood\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    )?;
    archive.start_file(format!("{dist_info}/entry_points.txt"), options)?;
    archive.write_all(b"[console_scripts]\nhood-integration=hood_integration:main\n")?;
    archive.start_file(format!("{dist_info}/RECORD"), options)?;
    Ok(archive.finish()?.into_inner())
}

async fn pypi_origin() -> Result<TestOrigin> {
    let origin = TestOrigin::spawn(HashMap::new()).await?;
    let filename = format!("hood_integration-{PYPI_VERSION}-py3-none-any.whl");
    let package_path = format!("/packages/{filename}");
    let wheel = python_wheel()?;
    let digest = sha2::Sha256::digest(&wheel);
    let hash = digest
        .iter()
        .fold(String::with_capacity(digest.len() * 2), |mut hash, byte| {
            let _ = write!(hash, "{byte:02x}");
            hash
        });
    let index = format!(
        "<!doctype html><a href=\"{}{package_path}#sha256={hash}\">{filename}</a>\n",
        origin.url(),
    );
    origin.add_route(
        format!("/simple/{PYPI_PACKAGE}/"),
        "text/html",
        index.into_bytes(),
    );
    origin.add_route(package_path, "application/octet-stream", wheel);
    Ok(origin)
}

fn assert_requested(origin: &TestOrigin, suffix: &str) {
    let requests = origin.requested_paths();
    assert!(
        requests.iter().any(|path| path.ends_with(suffix)),
        "missing request ending in {suffix}; got {requests:?}",
    );
}

fn assert_forwarded(tool: &str, output: &Output, origin: &TestOrigin) {
    assert!(
        output.stderr.contains(&origin.url()),
        "hood+{tool} reached the fixture without a visible proxy forward:\n{}",
        output.stderr,
    );
}

fn go_proxy_routes() -> Result<HashMap<String, (String, Vec<u8>)>> {
    let prefix = format!("/{GO_MODULE}/@v");
    let mut routes = HashMap::new();
    routes.insert(
        format!("{prefix}/{GO_VERSION}.info"),
        (
            "application/json".to_owned(),
            format!(r#"{{"Version":"{GO_VERSION}","Time":"2026-01-01T00:00:00Z"}}"#).into_bytes(),
        ),
    );
    routes.insert(
        format!("{prefix}/{GO_VERSION}.mod"),
        (
            "text/plain".to_owned(),
            format!("module {GO_MODULE}\n\ngo 1.20\n").into_bytes(),
        ),
    );
    routes.insert(
        format!("{prefix}/{GO_VERSION}.zip"),
        ("application/zip".to_owned(), go_module_zip()?),
    );
    Ok(routes)
}

fn go_module_zip() -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let root = format!("{GO_MODULE}@{GO_VERSION}");
    archive.start_file(format!("{root}/go.mod"), options)?;
    archive.write_all(format!("module {GO_MODULE}\n\ngo 1.20\n").as_bytes())?;
    archive.start_file(format!("{root}/hood_integration.go"), options)?;
    archive.write_all(GO_SOURCE.as_bytes())?;
    Ok(archive.finish()?.into_inner())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_mod_download_runs_through_hood() -> Result<()> {
    let Some(go) = go_binary().await? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&go)?;
    let origin = TestOrigin::spawn(go_proxy_routes()?).await?;
    let module_cache = harness.dir("gomodcache");
    let go_cache = harness.dir("gocache");
    let envs = [
        ("GOENV", OsString::from("off")),
        ("GOWORK", OsString::from("off")),
        ("GOFLAGS", OsString::new()),
        ("GOTOOLCHAIN", OsString::from("local")),
        ("GOPROXY", OsString::from(origin.url())),
        ("GOSUMDB", OsString::from("off")),
        ("GONOPROXY", OsString::new()),
        ("GOPRIVATE", OsString::new()),
        ("GONOSUMDB", OsString::new()),
        ("GOMODCACHE", module_cache.clone().into_os_string()),
        ("GOCACHE", go_cache.into_os_string()),
    ];
    let output = harness
        .hood(
            "go",
            &[
                "mod",
                "download",
                "-json",
                &format!("{GO_MODULE}@{GO_VERSION}"),
            ],
            &envs,
        )
        .await?;

    assert!(
        output.status.success(),
        "hood+go failed\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr,
    );
    assert!(output.stdout.contains(&format!(r#""Path": "{GO_MODULE}""#)));
    assert!(
        output
            .stdout
            .contains(&format!(r#""Version": "{GO_VERSION}""#))
    );
    assert!(output.stderr.contains("hood proxy listening"));
    let archive_url = format!("{}/{GO_MODULE}/@v/{GO_VERSION}.zip", origin.url());
    assert!(
        output.stderr.contains(&archive_url),
        "Go module archive was not visibly scanned:\n{}",
        output.stderr,
    );
    assert!(
        !output
            .stderr
            .contains("x509: certificate signed by unknown authority")
    );

    let source = module_cache
        .join(format!("{GO_MODULE}@{GO_VERSION}"))
        .join("hood_integration.go");
    assert_eq!(std::fs::read_to_string(source)?, GO_SOURCE);

    let requests = origin.requested_paths();
    for suffix in ["info", "mod", "zip"] {
        assert!(
            requests.contains(&format!("/{GO_MODULE}/@v/{GO_VERSION}.{suffix}")),
            "missing .{suffix} request; got {requests:?}",
        );
    }
    Ok(())
}

async fn npm_runner_download(tool: &str) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let (origin, version) = npm_origin().await?;
    let cache = harness.dir("npm-cache");
    let user_config = harness.dir("empty-npmrc");
    fs::write(&user_config, "")?;
    fs::write(
        harness.dir(".npmrc"),
        format!("registry={}\n", origin.url()),
    )?;
    let envs = [
        ("NPM_CONFIG_REGISTRY", OsString::from(origin.url())),
        ("npm_config_registry", OsString::from(origin.url())),
        ("BUN_CONFIG_REGISTRY", OsString::from(origin.url())),
        (
            "BUN_INSTALL_CACHE_DIR",
            harness.dir("bun-cache").into_os_string(),
        ),
        ("PNPM_CONFIG_REGISTRY", OsString::from(origin.url())),
        ("PNPM_HOME", harness.dir("pnpm-home").into_os_string()),
        (
            "pnpm_config_store_dir",
            harness.dir("pnpm-store").into_os_string(),
        ),
        ("COREPACK_ENABLE_DOWNLOAD_PROMPT", OsString::from("0")),
        ("npm_config_fetch_retries", OsString::from("0")),
        ("CI", OsString::from("true")),
        ("NPM_CONFIG_CACHE", cache.into_os_string()),
        (
            "NPM_CONFIG_USERCONFIG",
            user_config.as_os_str().to_os_string(),
        ),
    ];
    let spec = format!("{NPM_PACKAGE}@{version}");
    let args = if tool == "npx" {
        vec!["--yes", spec.as_str()]
    } else {
        vec![spec.as_str()]
    };
    let output = harness.hood(tool, &args, &envs).await?;
    assert_success(tool, &output);
    assert!(
        output.stdout.contains(TOOL_MARKER),
        "{tool} did not execute the fixture CLI:\n{}",
        output.stdout,
    );
    // Bun deliberately connects directly to loopback registries even when
    // HTTP_PROXY is set. Its documented HTTP(S)_PROXY support covers normal
    // remote registries; the hermetic fixture can still verify resolution,
    // download, extraction, and execution without pretending loopback passed
    // through hood.
    if tool != "bunx" {
        assert_forwarded(tool, &output, &origin);
    }
    assert_requested(&origin, &format!("{NPM_PACKAGE}-{version}.tgz"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn npx_downloads_and_runs_package_through_hood() -> Result<()> {
    npm_runner_download("npx").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pnpx_runs_inside_hood_proxy_environment() -> Result<()> {
    let Some(binary) = tool_binary("pnpx")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let output = harness.hood("pnpx", &["--", "--help"], &[]).await?;
    assert_success("pnpx", &output);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bunx_downloads_and_runs_package_through_hood() -> Result<()> {
    npm_runner_download("bunx").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rush_runs_inside_hood_proxy_environment() -> Result<()> {
    let Some(binary) = tool_binary("rush")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let output = harness.hood("rush", &["--", "--help"], &[]).await?;
    assert_success("rush", &output);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rushx_descendant_package_fetch_runs_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("rushx")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let (origin, version) = npm_origin().await?;
    let project = harness.dir("rush-project");
    fs::create_dir_all(&project)?;
    fs::write(
        project.join("package.json"),
        format!(
            r#"{{"name":"hood-rushx-test","version":"1.0.0","scripts":{{"hood-probe":"npm view {NPM_PACKAGE}@{version} version --registry {}"}}}}"#,
            origin.url(),
        ),
    )?;
    let envs = [
        ("NPM_CONFIG_REGISTRY", OsString::from(origin.url())),
        (
            "NPM_CONFIG_CACHE",
            harness.dir("npm-cache").into_os_string(),
        ),
    ];
    let output = harness
        .hood_in(&project, "rushx", &["hood-probe"], &envs)
        .await?;
    assert_success("rushx", &output);
    assert_forwarded("rushx", &output, &origin);
    assert_requested(&origin, &format!("/{NPM_PACKAGE}"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pip3_downloads_wheel_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("pip3")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let origin = pypi_origin().await?;
    let destination = harness.dir("pip-download");
    fs::create_dir_all(&destination)?;
    let index = format!("{}/simple", origin.url());
    let destination_arg = destination.to_string_lossy().into_owned();
    let requirement = format!("{PYPI_PACKAGE}=={PYPI_VERSION}");
    let output = harness
        .hood(
            "pip3",
            &[
                "download",
                "--disable-pip-version-check",
                "--no-deps",
                "--no-cache-dir",
                "--index-url",
                &index,
                "--dest",
                &destination_arg,
                &requirement,
            ],
            &[],
        )
        .await?;
    assert_success("pip3", &output);
    assert_forwarded("pip3", &output, &origin);
    assert!(
        destination
            .join(format!("hood_integration-{PYPI_VERSION}-py3-none-any.whl"))
            .is_file()
    );
    assert_requested(&origin, ".whl");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uvx_downloads_and_runs_wheel_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("uvx")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let origin = pypi_origin().await?;
    let index = format!("{}/simple", origin.url());
    let requirement = format!("{PYPI_PACKAGE}=={PYPI_VERSION}");
    let envs = [
        ("UV_INDEX_URL", OsString::from(index)),
        ("UV_NO_CACHE", OsString::from("1")),
        ("UV_PYTHON_DOWNLOADS", OsString::from("never")),
    ];
    let output = harness
        .hood("uvx", &["--from", &requirement, "hood-integration"], &envs)
        .await?;
    assert_success("uvx", &output);
    assert!(output.stdout.contains(TOOL_MARKER), "{}", output.stdout);
    assert_forwarded("uvx", &output, &origin);
    assert_requested(&origin, ".whl");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pdm_locks_dependency_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("pdm")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let origin = pypi_origin().await?;
    let project = harness.dir("pdm-project");
    fs::create_dir_all(&project)?;
    fs::write(
        project.join("pyproject.toml"),
        format!(
            "[project]\nname = \"hood-pdm-test\"\nversion = \"1.0.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"{PYPI_PACKAGE}=={PYPI_VERSION}\"]\n\n[[tool.pdm.source]]\nname = \"pypi\"\nurl = \"{}/simple\"\nverify_ssl = true\n",
            origin.url(),
        ),
    )?;
    let config = harness.dir("pdm-config.toml");
    fs::write(&config, "")?;
    let envs = [
        ("PDM_CONFIG_FILE", config.into_os_string()),
        ("PDM_CHECK_UPDATE", OsString::from("false")),
        ("PDM_IGNORE_STORED_INDEX", OsString::from("true")),
        ("PDM_CACHE_DIR", harness.dir("pdm-cache").into_os_string()),
    ];
    let output = harness.hood_in(&project, "pdm", &["lock"], &envs).await?;
    assert_success("pdm", &output);
    assert_forwarded("pdm", &output, &origin);
    assert!(project.join("pdm.lock").is_file());
    assert_requested(&origin, ".whl");
    Ok(())
}
