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
use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::process::Command;

const GO_MODULE: &str = "example.com/hood-integration";
const GO_VERSION: &str = "v1.0.0";
const GO_SOURCE: &str = "package hoodintegration\n\nconst ThroughHood = true\n";

#[derive(Debug)]
struct TestOrigin {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestOrigin {
    async fn spawn(routes: HashMap<String, (String, Vec<u8>)>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind tool-test origin")?;
        let addr = listener.local_addr().context("tool-test origin address")?;
        let routes = Arc::new(routes);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let routes = Arc::clone(&routes);
                let requests = Arc::clone(&request_log);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let routes = Arc::clone(&routes);
                        let requests = Arc::clone(&requests);
                        async move {
                            let path = req.uri().path().to_owned();
                            requests.lock().unwrap().push(path.clone());
                            let response = match routes.get(&path) {
                                Some((content_type, body)) => Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", content_type)
                                    .body(Full::new(Bytes::from(body.clone())))
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_hood"));
        command
            .arg("--verbose")
            .arg(tool)
            .args(args)
            .env("PATH", &self.path)
            .env("HOOD_HOME", self.dir("hood-home"))
            .env("HOOD_NO_SCAN", "1")
            .env("HOOD_NO_BLOOM", "1")
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

fn missing_tool(name: &str) -> Result<Option<PathBuf>> {
    if std::env::var_os("HOOD_REQUIRE_TOOL_INTEGRATION").is_some() {
        return Err(anyhow!(
            "required integration-test tool `{name}` is unavailable"
        ));
    }
    eprintln!("skipping {name} integration test: executable unavailable");
    Ok(None)
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
    assert!(output
        .stdout
        .contains(&format!(r#""Version": "{GO_VERSION}""#)));
    assert!(output.stderr.contains("hood proxy listening"));
    assert!(output.stderr.contains(&format!(
        "url={}/{GO_MODULE}/@v/{GO_VERSION}.zip",
        origin.url()
    )));
    assert!(!output
        .stderr
        .contains("x509: certificate signed by unknown authority"));

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
