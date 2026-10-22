//! Node package managers and runners.

use std::fs;
use std::path::Path;

use anyhow::Result;
use base64::Engine as _;
use sha2::{Digest, Sha512};

use crate::{
    Invocation, Payload, TOOL_MARKER, TestOrigin, ToolHarness, assert_success, tar_gz, tool_binary,
};

pub(crate) const TOOLS: &[&str] = &[
    "npm", "npx", "pnpm", "pnpx", "yarn", "rush", "rushx", "bun", "bunx",
];

const PACKAGE: &str = "hood-integration-cli";

/// A registry serving one CLI package.
struct Registry {
    _origin: TestOrigin,
    url: String,
    version: String,
    spec: String,
    tarball: Vec<u8>,
    tarball_url: String,
    metadata: Vec<u8>,
}

/// Serve a one-package npm registry. Bun ignores proxies for loopback
/// registries, so it is pointed at [`TestOrigin::go_url`].
async fn registry(bun: bool) -> Result<Registry> {
    let origin = TestOrigin::spawn().await?;
    let url = if bun { origin.go_url() } else { origin.url() };
    let version = format!("1.0.{}", origin.addr.port());
    let package_json =
        format!(r#"{{"name":"{PACKAGE}","version":"{version}","bin":{{"{PACKAGE}":"cli.js"}}}}"#);
    let cli = format!("#!/usr/bin/env node\nconsole.log('{TOOL_MARKER}')\n");
    let tarball = tar_gz(&[
        ("package/package.json", 0o644, package_json.as_bytes()),
        ("package/cli.js", 0o755, cli.as_bytes()),
    ])?;
    let integrity = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tarball));
    let tarball_path = format!("/{PACKAGE}/-/{PACKAGE}-{version}.tgz");
    let metadata = format!(
        r#"{{"name":"{PACKAGE}","dist-tags":{{"latest":"{version}"}},"versions":{{"{version}":{{"name":"{PACKAGE}","version":"{version}","bin":{{"{PACKAGE}":"cli.js"}},"dist":{{"tarball":"{url}{tarball_path}","integrity":"sha512-{integrity}"}}}}}}}}"#,
    )
    .into_bytes();
    origin.add_route(
        format!("/{PACKAGE}"),
        "application/vnd.npm.install-v1+json",
        metadata.clone(),
    );
    origin.add_route(
        tarball_path.clone(),
        "application/octet-stream",
        tarball.clone(),
    );
    Ok(Registry {
        spec: format!("{PACKAGE}@{version}"),
        tarball_url: format!("{url}{tarball_path}"),
        url,
        version,
        tarball,
        metadata,
        _origin: origin,
    })
}

/// Point every Node package manager at `registry` with caches under `dir`.
/// Retries are off so a blocked download fails at once.
fn registry_env(invocation: Invocation, dir: &Path, registry: &str) -> Result<Invocation> {
    let user_config = dir.join("empty-npmrc");
    fs::write(&user_config, "")?;
    // bunx caches packages under $TMPDIR, so each run needs its own.
    let tmp = dir.join("tmp");
    fs::create_dir_all(&tmp)?;
    fs::write(
        dir.join(".npmrc"),
        format!("registry={registry}\nfetch-retries=0\n"),
    )?;
    fs::write(dir.join(".yarnrc"), format!("registry \"{registry}\"\n"))?;
    Ok(invocation
        .env("NPM_CONFIG_REGISTRY", registry)
        .env("npm_config_registry", registry)
        .env("NPM_CONFIG_USERCONFIG", user_config)
        .env("NPM_CONFIG_CACHE", dir.join("npm-cache"))
        .env("npm_config_fetch_retries", "0")
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .env("npm_config_update_notifier", "false")
        .env("PNPM_CONFIG_REGISTRY", registry)
        .env("pnpm_config_fetch_retries", "0")
        .env("PNPM_HOME", dir.join("pnpm-home"))
        .env("pnpm_config_store_dir", dir.join("pnpm-store"))
        .env("pnpm_config_cache_dir", dir.join("pnpm-cache"))
        .env("YARN_REGISTRY", registry)
        .env("YARN_CACHE_FOLDER", dir.join("yarn-cache"))
        .env("BUN_CONFIG_REGISTRY", registry)
        .env("BUN_INSTALL_CACHE_DIR", dir.join("bun-cache"))
        .env("TMPDIR", tmp)
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .env("CI", "true"))
}

fn write_project(dir: &Path) -> Result<()> {
    fs::write(
        dir.join("package.json"),
        r#"{"name":"hood-node-test","version":"1.0.0","private":true}"#,
    )?;
    Ok(())
}

/// `npm install`/`pnpm add`/`yarn add`/`bun add` a package into a project.
async fn adds_package(tool: &str, verb: &str) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let registry = registry(tool == "bun").await?;
    harness
        .exercise(
            tool,
            &binary,
            |dir| {
                write_project(dir)?;
                registry_env(
                    Invocation::new(dir).args([verb, registry.spec.as_str()]),
                    dir,
                    &registry.url,
                )
            },
            Payload {
                bytes: &registry.tarball,
                url: &registry.tarball_url,
            },
            |run| {
                run.dir
                    .join("node_modules")
                    .join(PACKAGE)
                    .join("cli.js")
                    .is_file()
            },
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn npm_installs_package_through_hood() -> Result<()> {
    adds_package("npm", "install").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pnpm_adds_package_through_hood() -> Result<()> {
    adds_package("pnpm", "add").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yarn_adds_package_through_hood() -> Result<()> {
    adds_package("yarn", "add").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bun_adds_package_through_hood() -> Result<()> {
    adds_package("bun", "add").await
}

/// Package runners download a CLI and execute it.
async fn runs_package(tool: &str, flags: &[&str]) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let registry = registry(tool == "bunx").await?;
    harness
        .exercise(
            tool,
            &binary,
            |dir| {
                write_project(dir)?;
                registry_env(
                    Invocation::new(dir).args(flags).arg(&registry.spec),
                    dir,
                    &registry.url,
                )
            },
            Payload {
                bytes: &registry.tarball,
                url: &registry.tarball_url,
            },
            |run| run.output.stdout.contains(TOOL_MARKER),
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn npx_downloads_and_runs_package_through_hood() -> Result<()> {
    runs_package("npx", &["--yes"]).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pnpx_downloads_and_runs_package_through_hood() -> Result<()> {
    runs_package("pnpx", &[]).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bunx_downloads_and_runs_package_through_hood() -> Result<()> {
    runs_package("bunx", &[]).await
}

/// Rush provisions tools only from a full monorepo configuration, so this
/// checks that it starts and runs inside hood's proxy environment; the
/// stand-in contract test covers blocking for every command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rush_runs_inside_hood_proxy_environment() -> Result<()> {
    let Some(binary) = tool_binary("rush")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let (run, _) = harness
        .compare(
            "rush",
            &binary,
            |dir| Ok(Invocation::new(dir).arg("--help")),
        )
        .await?;
    assert_success("rush", &run.output);
    Ok(())
}

/// A project script run by `rushx` inherits hood's proxy, so its own
/// registry request is scanned too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rushx_descendant_package_fetch_runs_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("rushx")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let registry = registry(false).await?;
    let metadata_url = format!("{}/{PACKAGE}", registry.url);
    harness
        .exercise(
            "rushx",
            &binary,
            |dir| {
                fs::write(
                    dir.join("package.json"),
                    format!(
                        r#"{{"name":"hood-rushx-test","version":"1.0.0","scripts":{{"hood-probe":"npm view {} version --registry {}"}}}}"#,
                        registry.spec, registry.url,
                    ),
                )?;
                registry_env(Invocation::new(dir).arg("hood-probe"), dir, &registry.url)
            },
            Payload {
                bytes: &registry.metadata,
                url: &metadata_url,
            },
            |run| {
                run.output.status.success() && run.output.stdout.contains(&registry.version)
            },
        )
        .await?;
    Ok(())
}
