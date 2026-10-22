//! Node package managers and runners.

use std::fs;
use std::path::Path;

use anyhow::Result;
use base64::Engine as _;
use sha2::{Digest, Sha512};

use crate::{
    Invocation, Output, TOOL_MARKER, TestOrigin, ToolHarness, assert_forwarded, assert_requested,
    assert_success, tar_gz, tool_binary,
};

pub(crate) const TOOLS: &[&str] = &[
    "npm", "npx", "pnpm", "pnpx", "yarn", "rush", "rushx", "bun", "bunx",
];

const PACKAGE: &str = "hood-integration-cli";

/// A registry serving one CLI package, with its version and tarball URL.
struct Registry {
    origin: TestOrigin,
    url: String,
    spec: String,
    tarball: String,
}

/// Serve a one-package npm registry at `url`'s origin. Bun ignores proxies
/// for loopback registries, so it is pointed at [`TestOrigin::go_url`].
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
    );
    origin.add_route(
        format!("/{PACKAGE}"),
        "application/vnd.npm.install-v1+json",
        metadata.into_bytes(),
    );
    origin.add_route(tarball_path.clone(), "application/octet-stream", tarball);
    Ok(Registry {
        url: url.clone(),
        spec: format!("{PACKAGE}@{version}"),
        tarball: format!("{url}{tarball_path}"),
        origin,
    })
}

/// Point every Node package manager at `registry` with caches under `dir`.
fn registry_env(invocation: Invocation, dir: &Path, registry: &str) -> Result<Invocation> {
    let user_config = dir.join("empty-npmrc");
    fs::write(&user_config, "")?;
    fs::write(dir.join(".npmrc"), format!("registry={registry}\n"))?;
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
        .env("PNPM_HOME", dir.join("pnpm-home"))
        .env("pnpm_config_store_dir", dir.join("pnpm-store"))
        .env("pnpm_config_cache_dir", dir.join("pnpm-cache"))
        .env("YARN_REGISTRY", registry)
        .env("YARN_CACHE_FOLDER", dir.join("yarn-cache"))
        .env("BUN_CONFIG_REGISTRY", registry)
        .env("BUN_INSTALL_CACHE_DIR", dir.join("bun-cache"))
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

/// Bun connects to loopback registries directly even when proxied, so its
/// runs prove only that hood started; everything else must be forwarded.
fn assert_fetched(tool: &str, output: &Output, registry: &Registry) {
    assert_success(tool, output);
    if !tool.starts_with("bun") {
        assert_forwarded(tool, output, &registry.tarball);
    }
    assert_requested(&registry.origin, ".tgz");
}

/// `npm install`/`pnpm add`/`yarn add`/`bun add` a package into a project.
async fn adds_package(tool: &str, verb: &str) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let registry = registry(tool == "bun").await?;
    let run = harness
        .compare(tool, &binary, |dir| {
            write_project(dir)?;
            registry_env(
                Invocation::new(dir).args([verb, registry.spec.as_str()]),
                dir,
                &registry.url,
            )
        })
        .await?;
    assert_fetched(tool, &run.output, &registry);
    assert!(
        run.dir
            .join("node_modules")
            .join(PACKAGE)
            .join("cli.js")
            .is_file(),
        "{tool} did not install {PACKAGE}"
    );
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
    let run = harness
        .compare(tool, &binary, |dir| {
            write_project(dir)?;
            registry_env(
                Invocation::new(dir).args(flags).arg(&registry.spec),
                dir,
                &registry.url,
            )
        })
        .await?;
    assert_fetched(tool, &run.output, &registry);
    assert!(
        run.output.stdout.contains(TOOL_MARKER),
        "{tool} did not execute the fixture CLI:\n{}",
        run.output.stdout,
    );
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
/// checks that it starts and runs inside hood's proxy environment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rush_runs_inside_hood_proxy_environment() -> Result<()> {
    let Some(binary) = tool_binary("rush")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let run = harness
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
/// registry request is forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rushx_descendant_package_fetch_runs_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("rushx")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let registry = registry(false).await?;
    let run = harness
        .compare("rushx", &binary, |dir| {
            fs::write(
                dir.join("package.json"),
                format!(
                    r#"{{"name":"hood-rushx-test","version":"1.0.0","scripts":{{"hood-probe":"npm view {} version --registry {}"}}}}"#,
                    registry.spec, registry.url,
                ),
            )?;
            registry_env(Invocation::new(dir).arg("hood-probe"), dir, &registry.url)
        })
        .await?;
    assert_success("rushx", &run.output);
    assert_forwarded("rushx", &run.output, &format!("{}/{PACKAGE}", registry.url));
    assert_requested(&registry.origin, &format!("/{PACKAGE}"));
    Ok(())
}
