//! Language toolchains: Go, Cargo, and Zig.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::process::Command;

use crate::{
    Invocation, Output, PROXY_VARS, Payload, TIMING, TOOL_MARKER, TestOrigin, ToolHarness,
    find_file, missing_tool, path_binary, sha256_hex, tar_gz, tool_binary, tool_is_selected,
};

pub(crate) const TOOLS: &[&str] = &["go", "cargo", "zig"];

const GO_MODULE: &str = "example.com/hood-integration";
const GO_VERSION: &str = "v1.0.0";
const GO_SOURCE: &str = "package hoodintegration\n\nconst ThroughHood = true\n";

/// Locate the real Go binary behind any `go` shim already on PATH.
async fn go_binary() -> Result<Option<PathBuf>> {
    if !tool_is_selected("go") {
        return Ok(None);
    }
    let Ok(output) = Command::new("go").args(["env", "GOROOT"]).output().await else {
        return missing_tool("go");
    };
    let binary = PathBuf::from(String::from_utf8(output.stdout)?.trim())
        .join("bin")
        .join("go");
    if output.status.success() && binary.is_file() {
        Ok(Some(binary))
    } else {
        missing_tool("go")
    }
}

fn go_module_zip() -> Result<Vec<u8>> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
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
    let origin = TestOrigin::spawn().await?;
    let prefix = format!("/{GO_MODULE}/@v/{GO_VERSION}");
    origin.add_route(
        format!("{prefix}.info"),
        "application/json",
        format!(r#"{{"Version":"{GO_VERSION}","Time":"2026-01-01T00:00:00Z"}}"#).into_bytes(),
    );
    origin.add_route(
        format!("{prefix}.mod"),
        "text/plain",
        format!("module {GO_MODULE}\n\ngo 1.20\n").into_bytes(),
    );
    let module = go_module_zip()?;
    origin.add_route(format!("{prefix}.zip"), "application/zip", module.clone());
    let url = format!("{}{prefix}.zip", origin.go_url());
    harness
        .exercise(
            "go",
            &go,
            |dir| {
                Ok(Invocation::new(dir)
                    .args([
                        "mod",
                        "download",
                        "-json",
                        &format!("{GO_MODULE}@{GO_VERSION}"),
                    ])
                    .env("GOENV", "off")
                    .env("GOWORK", "off")
                    .env("GOFLAGS", "-modcacherw")
                    .env("GOTOOLCHAIN", "local")
                    .env("GOPROXY", origin.go_url())
                    .env("GOSUMDB", "off")
                    .env("GONOPROXY", "")
                    .env("GOPRIVATE", "")
                    .env("GONOSUMDB", "")
                    .env("GOMODCACHE", dir.join("gomodcache"))
                    .env("GOCACHE", dir.join("gocache")))
            },
            Payload {
                bytes: &module,
                url: &url,
            },
            |run| {
                let source = run
                    .dir
                    .join("gomodcache")
                    .join(format!("{GO_MODULE}@{GO_VERSION}"))
                    .join("hood_integration.go");
                fs::read_to_string(source).is_ok_and(|source| source == GO_SOURCE)
            },
        )
        .await?;
    Ok(())
}

const CRATE: &str = "hoodint";
const CRATE_VERSION: &str = "1.0.0";

/// `cargo fetch` resolves a dependency from a sparse alternative registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cargo_fetches_crate_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("cargo")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let origin = TestOrigin::spawn().await?;
    let root = format!("{CRATE}-{CRATE_VERSION}");
    let manifest = format!(
        "[package]\nname = \"{CRATE}\"\nversion = \"{CRATE_VERSION}\"\nedition = \"2021\"\n"
    );
    let package = tar_gz(&[
        (&format!("{root}/Cargo.toml"), 0o644, manifest.as_bytes()),
        (
            &format!("{root}/src/lib.rs"),
            0o644,
            b"pub const THROUGH_HOOD: bool = true;\n",
        ),
    ])?;
    let entry = format!(
        r#"{{"name":"{CRATE}","vers":"{CRATE_VERSION}","deps":[],"cksum":"{}","features":{{}},"yanked":false}}"#,
        sha256_hex(&package),
    );
    origin.add_route(
        "/index/config.json",
        "application/json",
        format!(r#"{{"dl":"{}/dl"}}"#, origin.url()).into_bytes(),
    );
    origin.add_route(
        format!("/index/ho/od/{CRATE}"),
        "text/plain",
        entry.into_bytes(),
    );
    let download = format!("/dl/{CRATE}/{CRATE_VERSION}/download");
    origin.add_route(download.clone(), "application/gzip", package.clone());
    let index = format!("sparse+{}/index/", origin.url());
    let url = format!("{}{download}", origin.url());
    harness
        .exercise(
            "cargo",
            &binary,
            |dir| {
                fs::create_dir_all(dir.join("src"))?;
                fs::write(dir.join("src").join("lib.rs"), "")?;
                fs::write(
                    dir.join("Cargo.toml"),
                    format!(
                        "[package]\nname = \"hood-cargo-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{CRATE} = {{ version = \"{CRATE_VERSION}\", registry = \"hoodfix\" }}\n"
                    ),
                )?;
                Ok(Invocation::new(dir)
                    .arg("fetch")
                    .env("CARGO_HOME", dir.join("cargo-home"))
                    .env("CARGO_REGISTRIES_HOODFIX_INDEX", &index)
                    .env("CARGO_NET_RETRY", "0"))
            },
            Payload {
                bytes: &package,
                url: &url,
            },
            |run| {
                find_file(&run.dir.join("cargo-home"), &|name| {
                    name == format!("{CRATE}-{CRATE_VERSION}.crate")
                })
                .is_some()
            },
        )
        .await?;
    Ok(())
}

const ZIG_PACKAGE: &str = "hood_integration";
const ZIG_VERSION: &str = "1.0.0";
/// Zig fingerprints embed a CRC-32 of the package name in their upper half,
/// so each is valid only for the name it was minted with.
const ZIG_PACKAGE_FINGERPRINT: &str = "0x7cdd4dfe1f9b6709";
const ZIG_APP: &str = "hood_zig_app";
const ZIG_APP_FINGERPRINT: &str = "0xd2721cdb1f9b6709";

/// A Zig test fixture: the package origin, its tarball, URL, and content
/// hash, and the warm global cache every run shares.
struct ZigFixture {
    origin: TestOrigin,
    tarball: Vec<u8>,
    url: String,
    hash: String,
    cache: PathBuf,
}

impl ZigFixture {
    /// Serve a package and learn its hash with a direct, untimed fetch.
    ///
    /// The content is unique per run: Zig skips the network for any hash
    /// already in its global cache, which is kept across runs.
    async fn new(zig: &Path, harness: &ToolHarness) -> Result<Self> {
        let origin = TestOrigin::spawn().await?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let source = format!(
            "pub const through_hood = true;\n// fixture {nonce}-{}\n",
            origin.addr.port()
        );
        let manifest = format!(
            ".{{\n    .name = .{ZIG_PACKAGE},\n    .version = \"{ZIG_VERSION}\",\n    .fingerprint = {ZIG_PACKAGE_FINGERPRINT},\n    .paths = .{{\"\"}},\n}}\n"
        );
        let path = format!("/{ZIG_PACKAGE}-{ZIG_VERSION}.tar.gz");
        let tarball = tar_gz(&[
            (
                &format!("{ZIG_PACKAGE}/build.zig.zon"),
                0o644,
                manifest.as_bytes(),
            ),
            (&format!("{ZIG_PACKAGE}/root.zig"), 0o644, source.as_bytes()),
        ])?;
        origin.add_route(path.clone(), "application/gzip", tarball.clone());
        let url = format!("{}{path}", origin.url());
        let cache = zig_global_cache(zig, harness).await?;
        let _shared = TIMING.read().await;
        let mut fetch = Command::new(zig);
        fetch
            .args(["fetch", &url])
            .env("ZIG_GLOBAL_CACHE_DIR", &cache)
            .env("ZIG_LOCAL_CACHE_DIR", harness.dir("zig-local-cache"))
            .kill_on_drop(true);
        for key in PROXY_VARS {
            fetch.env_remove(key);
        }
        let output = fetch.output().await?;
        if !output.status.success() {
            bail!(
                "zig fetch fixture failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let hash = String::from_utf8(output.stdout)?.trim().to_owned();
        if !hash.starts_with(&format!("{ZIG_PACKAGE}-{ZIG_VERSION}-")) {
            bail!("unexpected Zig package hash {hash:?}");
        }
        Ok(Self {
            origin,
            tarball,
            url,
            hash,
            cache,
        })
    }

    /// Point Zig at the shared cache with this package evicted, so the next
    /// run must download it, and a run-local cache for project state.
    fn invocation(&self, dir: &Path) -> Result<Invocation> {
        for entry in fs::read_dir(self.cache.join("p"))?.filter_map(Result::ok) {
            if entry.file_name().to_string_lossy().starts_with(&self.hash) {
                let path = entry.path();
                if path.is_dir() {
                    fs::remove_dir_all(path)?;
                } else {
                    fs::remove_file(path)?;
                }
            }
        }
        Ok(Invocation::new(dir)
            .env("ZIG_GLOBAL_CACHE_DIR", &self.cache)
            .env("ZIG_LOCAL_CACHE_DIR", dir.join("zig-local-cache")))
    }

    fn payload(&self) -> Payload<'_> {
        Payload {
            bytes: &self.tarball,
            url: &self.url,
        }
    }

    fn cached(&self) -> bool {
        fs::read_dir(self.cache.join("p")).is_ok_and(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().starts_with(&self.hash))
        })
    }
}

/// Return a warm Zig global cache shared across runs.
///
/// On first use Zig compiles helper programs into its global cache, which
/// takes about a minute. Warm a persistent cache under Cargo's
/// integration-test temp dir by fetching a local directory, outside hood and
/// without network access. Zig locks its cache entries, so parallel tests may
/// share it.
async fn zig_global_cache(zig: &Path, harness: &ToolHarness) -> Result<PathBuf> {
    let cache = Path::new(env!("CARGO_TARGET_TMPDIR")).join("zig-global-cache");
    let warmup = harness.dir("zig-warmup");
    fs::create_dir_all(&warmup)?;
    fs::write(warmup.join("warmup.zig"), "")?;
    let _shared = TIMING.read().await;
    let output = tokio::time::timeout(
        Duration::from_secs(600),
        Command::new(zig)
            .arg("fetch")
            .arg(&warmup)
            .env("ZIG_GLOBAL_CACHE_DIR", &cache)
            .env("ZIG_LOCAL_CACHE_DIR", harness.dir("zig-local-cache"))
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("zig cache warmup timed out")??;
    if !output.status.success() {
        return Err(anyhow!(
            "zig cache warmup failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(cache)
}

/// Write a Zig project and return its `build.zig.zon` path.
fn write_zig_project(project: &Path, build_zig: &str, dependencies: &str) -> Result<PathBuf> {
    fs::write(project.join("build.zig"), build_zig)?;
    let manifest = project.join("build.zig.zon");
    fs::write(
        &manifest,
        format!(
            ".{{\n    .name = .{ZIG_APP},\n    .version = \"0.0.0\",\n    .fingerprint = {ZIG_APP_FINGERPRINT},\n    .dependencies = .{{{dependencies}}},\n    .paths = .{{\"\"}},\n}}\n"
        ),
    )?;
    Ok(manifest)
}

/// Zig never trusts hood's CA, so hood must refuse its CONNECT tunnel and
/// receive the absolute-form fallback. A MITM attempt shows up as a failed
/// TLS accept followed by a truncated HTTP response in Zig.
fn assert_zig_absolute_form(output: &Output) {
    assert!(
        output.stderr.contains("refuse Zig CONNECT"),
        "hood did not refuse Zig's tunnel:\n{}",
        output.stderr,
    );
    assert!(
        !output.stderr.contains("tls accept failed"),
        "hood attempted TLS interception of Zig:\n{}",
        output.stderr,
    );
}

const EMPTY_BUILD_ZIG: &str = "pub fn build(_: *@import(\"std\").Build) void {}\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zig_fetch_downloads_package_through_hood() -> Result<()> {
    let Some(zig) = tool_binary("zig")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&zig)?;
    let fixture = ZigFixture::new(&zig, &harness).await?;
    let run = harness
        .exercise(
            "zig",
            &zig,
            |dir| Ok(fixture.invocation(dir)?.args(["fetch", &fixture.url])),
            fixture.payload(),
            |run| run.output.stdout.trim() == fixture.hash && fixture.cached(),
        )
        .await?;
    assert_zig_absolute_form(&run.output);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zig_fetch_save_records_dependency_through_hood() -> Result<()> {
    let Some(zig) = tool_binary("zig")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&zig)?;
    let fixture = ZigFixture::new(&zig, &harness).await?;
    let saved_hash = format!(".hash = \"{}\"", fixture.hash);
    let run = harness
        .exercise(
            "zig",
            &zig,
            |dir| {
                write_zig_project(dir, EMPTY_BUILD_ZIG, "")?;
                Ok(fixture
                    .invocation(dir)?
                    .args(["fetch", "--save", &fixture.url]))
            },
            fixture.payload(),
            |run| {
                fs::read_to_string(run.dir.join("build.zig.zon"))
                    .is_ok_and(|saved| saved.contains(&saved_hash))
            },
        )
        .await?;
    assert_zig_absolute_form(&run.output);
    let saved = fs::read_to_string(run.dir.join("build.zig.zon"))?;
    for needle in [
        format!(".{ZIG_PACKAGE} = "),
        format!(".url = \"{}\"", fixture.url),
    ] {
        assert!(
            saved.contains(&needle),
            "build.zig.zon lacks {needle}:\n{saved}"
        );
    }
    Ok(())
}

/// `zig build` fetches missing `build.zig.zon` dependencies through hood,
/// while its build steps' own downloads keep working through the proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zig_build_fetches_dependencies_and_runs_build_step_downloads() -> Result<()> {
    let Some(zig) = tool_binary("zig")? else {
        return Ok(());
    };
    let Some(curl) = path_binary("curl") else {
        missing_tool::<()>("curl")?;
        return Ok(());
    };
    let harness = ToolHarness::new(&zig)?;
    let fixture = ZigFixture::new(&zig, &harness).await?;
    let probe_path = "/build-step-probe.txt";
    fixture
        .origin
        .add_route(probe_path, "text/plain", TOOL_MARKER.as_bytes().to_vec());
    let probe_url = format!("{}{probe_path}", fixture.origin.url());
    let dependency = format!(
        " .{ZIG_PACKAGE} = .{{ .url = {:?}, .hash = {:?} }} ",
        fixture.url, fixture.hash
    );
    let run = harness
        .exercise(
            "zig",
            &zig,
            |dir| {
                let build_zig = format!(
                    "const std = @import(\"std\");\npub fn build(b: *std.Build) void {{\n    _ = b.dependency(\"{ZIG_PACKAGE}\", .{{}});\n    const probe = b.addSystemCommand(&.{{ {:?}, \"-fsS\", \"-o\", {:?}, {probe_url:?} }});\n    b.getInstallStep().dependOn(&probe.step);\n}}\n",
                    curl.to_string_lossy(),
                    dir.join("probe.txt").to_string_lossy(),
                );
                write_zig_project(dir, &build_zig, &dependency)?;
                Ok(fixture.invocation(dir)?.arg("build"))
            },
            fixture.payload(),
            |run| {
                fs::read_to_string(run.dir.join("probe.txt")).is_ok_and(|probe| probe == TOOL_MARKER)
            },
        )
        .await?;
    assert_zig_absolute_form(&run.output);
    crate::assert_forwarded("zig", &run.output, &probe_url);
    Ok(())
}
