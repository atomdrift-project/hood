//! Python package managers.

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use anyhow::Result;

use crate::{
    Invocation, Payload, Run, TOOL_MARKER, TestOrigin, ToolHarness, sha256_hex, tool_binary,
};

pub(crate) const TOOLS: &[&str] = &["pip", "pip3", "pipx", "uv", "uvx", "poetry", "pdm"];

const PACKAGE: &str = "hood-integration";
const VERSION: &str = "1.0.0";

fn wheel() -> Result<Vec<u8>> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let dist_info = format!("hood_integration-{VERSION}.dist-info");
    archive.start_file("hood_integration/__init__.py", options)?;
    archive.write_all(format!("def main():\n    print(\"{TOOL_MARKER}\")\n").as_bytes())?;
    archive.start_file(format!("{dist_info}/METADATA"), options)?;
    archive.write_all(
        format!(
            "Metadata-Version: 2.1\nName: {PACKAGE}\nVersion: {VERSION}\nSummary: hood integration fixture\n"
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

/// A PEP 503 simple index serving one wheel.
struct Index {
    _origin: TestOrigin,
    url: String,
    wheel: Vec<u8>,
    wheel_url: String,
}

impl Index {
    async fn spawn() -> Result<Self> {
        let origin = TestOrigin::spawn().await?;
        let filename = format!("hood_integration-{VERSION}-py3-none-any.whl");
        let wheel_url = format!("{}/packages/{filename}", origin.url());
        let wheel = wheel()?;
        let page = format!(
            "<!doctype html><a href=\"{wheel_url}#sha256={}\">{filename}</a>\n",
            sha256_hex(&wheel),
        );
        origin.add_route(
            format!("/simple/{PACKAGE}/"),
            "text/html",
            page.into_bytes(),
        );
        origin.add_route(
            format!("/packages/{filename}"),
            "application/octet-stream",
            wheel.clone(),
        );
        Ok(Self {
            url: format!("{}/simple", origin.url()),
            _origin: origin,
            wheel,
            wheel_url,
        })
    }

    fn payload(&self) -> Payload<'_> {
        Payload {
            bytes: &self.wheel,
            url: &self.wheel_url,
        }
    }
}

fn requirement() -> String {
    format!("{PACKAGE}=={VERSION}")
}

/// Keep pip from reading user configuration or caches.
fn pip_env(invocation: Invocation, dir: &Path) -> Result<Invocation> {
    let config = dir.join("pip.conf");
    fs::write(&config, "")?;
    Ok(invocation
        .env("PIP_CONFIG_FILE", config)
        .env("PIP_NO_CACHE_DIR", "1")
        .env("PIP_DISABLE_PIP_VERSION_CHECK", "1"))
}

async fn pip_downloads(tool: &str) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let index = Index::spawn().await?;
    harness
        .exercise(
            tool,
            &binary,
            |dir| {
                pip_env(
                    Invocation::new(dir)
                        .args(["download", "--no-deps", "--index-url", &index.url, "--dest"])
                        .arg(dir.join("dist"))
                        .arg(requirement()),
                    dir,
                )
            },
            index.payload(),
            |run| {
                run.dir
                    .join("dist")
                    .join(format!("hood_integration-{VERSION}-py3-none-any.whl"))
                    .is_file()
            },
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pip_downloads_wheel_through_hood() -> Result<()> {
    pip_downloads("pip").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pip3_downloads_wheel_through_hood() -> Result<()> {
    pip_downloads("pip3").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipx_installs_application_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("pipx")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let index = Index::spawn().await?;
    harness
        .exercise(
            "pipx",
            &binary,
            |dir| {
                pip_env(
                    Invocation::new(dir)
                        .args(["install", "--index-url", &index.url])
                        .arg(requirement())
                        .env("PIPX_HOME", dir.join("pipx"))
                        .env("PIPX_BIN_DIR", dir.join("bin"))
                        .env("PIPX_MAN_DIR", dir.join("man")),
                    dir,
                )
            },
            index.payload(),
            |run| run.dir.join("bin").join(PACKAGE).exists(),
        )
        .await?;
    Ok(())
}

fn uv_env(invocation: Invocation, dir: &Path) -> Invocation {
    invocation
        .env("UV_CACHE_DIR", dir.join("uv-cache"))
        .env("UV_NO_CONFIG", "1")
        .env("UV_PYTHON_DOWNLOADS", "never")
        .env("UV_TOOL_DIR", dir.join("uv-tools"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uv_pip_installs_wheel_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("uv")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let index = Index::spawn().await?;
    harness
        .exercise(
            "uv",
            &binary,
            |dir| {
                Ok(uv_env(
                    Invocation::new(dir)
                        .args(["pip", "install", "--index-url", &index.url, "--target"])
                        .arg(dir.join("site"))
                        .arg(requirement()),
                    dir,
                ))
            },
            index.payload(),
            |run| {
                run.dir
                    .join("site")
                    .join("hood_integration")
                    .join("__init__.py")
                    .is_file()
            },
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uvx_downloads_and_runs_wheel_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("uvx")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let index = Index::spawn().await?;
    harness
        .exercise(
            "uvx",
            &binary,
            |dir| {
                Ok(uv_env(
                    Invocation::new(dir)
                        .args(["--index-url", &index.url, "--from"])
                        .arg(requirement())
                        .arg(PACKAGE),
                    dir,
                ))
            },
            index.payload(),
            |run| run.output.stdout.contains(TOOL_MARKER),
        )
        .await?;
    Ok(())
}

/// A project depending on the fixture; `tool_config` selects its index.
fn write_pyproject(dir: &Path, tool_config: &str) -> Result<()> {
    fs::write(
        dir.join("pyproject.toml"),
        format!(
            "[project]\nname = \"hood-python-test\"\nversion = \"1.0.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"{}\"]\n{tool_config}",
            requirement(),
        ),
    )?;
    Ok(())
}

fn locked(run: &Run, lockfile: &str) -> bool {
    run.output.status.success() && run.dir.join(lockfile).is_file()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poetry_locks_dependency_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("poetry")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let index = Index::spawn().await?;
    harness
        .exercise(
            "poetry",
            &binary,
            |dir| {
                write_pyproject(
                    dir,
                    &format!(
                        "\n[tool.poetry]\npackage-mode = false\n\n[[tool.poetry.source]]\nname = \"fixture\"\nurl = \"{}\"\npriority = \"primary\"\n",
                        index.url
                    ),
                )?;
                Ok(Invocation::new(dir)
                    .arg("lock")
                    .env("POETRY_CACHE_DIR", dir.join("poetry-cache"))
                    .env("POETRY_CONFIG_DIR", dir.join("poetry-config"))
                    .env("POETRY_DATA_DIR", dir.join("poetry-data"))
                    .env("POETRY_VIRTUALENVS_CREATE", "false"))
            },
            index.payload(),
            |run| locked(run, "poetry.lock"),
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pdm_locks_dependency_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("pdm")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let index = Index::spawn().await?;
    harness
        .exercise(
            "pdm",
            &binary,
            |dir| {
                write_pyproject(
                    dir,
                    &format!(
                        "\n[[tool.pdm.source]]\nname = \"pypi\"\nurl = \"{}\"\nverify_ssl = true\n",
                        index.url
                    ),
                )?;
                let config = dir.join("pdm-config.toml");
                fs::write(&config, "")?;
                Ok(Invocation::new(dir)
                    .arg("lock")
                    .env("PDM_CONFIG_FILE", config)
                    .env("PDM_CHECK_UPDATE", "false")
                    .env("PDM_IGNORE_STORED_INDEX", "true")
                    .env("PDM_CACHE_DIR", dir.join("pdm-cache")))
            },
            index.payload(),
            |run| locked(run, "pdm.lock"),
        )
        .await?;
    Ok(())
}
