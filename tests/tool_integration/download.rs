//! Downloaders and Homebrew.

use std::fs;

use anyhow::Result;

use crate::{
    Invocation, TOOL_MARKER, TestOrigin, ToolHarness, assert_forwarded, assert_requested,
    assert_success, find_file, sha256_hex, tar_gz, tool_binary,
};

pub(crate) const TOOLS: &[&str] = &["curl", "wget", "brew"];

const FILE: &str = "/hood-download.txt";

async fn file_origin() -> Result<(TestOrigin, String)> {
    let origin = TestOrigin::spawn().await?;
    origin.add_route(FILE, "text/plain", TOOL_MARKER.as_bytes().to_vec());
    let url = format!("{}{FILE}", origin.url());
    Ok((origin, url))
}

async fn downloader(tool: &str, args: &[&str]) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let (origin, url) = file_origin().await?;
    let run = harness
        .compare(tool, &binary, |dir| {
            Ok(Invocation::new(dir)
                .args(args)
                .arg(dir.join("out.txt"))
                .arg(&url))
        })
        .await?;
    assert_success(tool, &run.output);
    assert_forwarded(tool, &run.output, &url);
    assert_eq!(fs::read_to_string(run.dir.join("out.txt"))?, TOOL_MARKER);
    assert_requested(&origin, FILE);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn curl_downloads_through_hood() -> Result<()> {
    downloader("curl", &["-fsS", "-o"]).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wget_downloads_through_hood() -> Result<()> {
    downloader("wget", &["--no-config", "-q", "-O"]).await
}

/// `brew fetch` downloads a formula's source archive. Homebrew loads formula
/// files outside a tap only in developer mode; the API is disabled so the
/// fixture is the only thing fetched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn brew_fetches_formula_source_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("brew")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let origin = TestOrigin::spawn().await?;
    let archive = tar_gz(&[("hoodfix-1.0.0/README", 0o644, TOOL_MARKER.as_bytes())])?;
    let sha256 = sha256_hex(&archive);
    let path = "/hoodfix-1.0.0.tar.gz";
    origin.add_route(path, "application/gzip", archive);
    let url = format!("{}{path}", origin.url());
    let formula = format!(
        "class Hoodfix < Formula\n  desc \"hood integration fixture\"\n  homepage \"{}\"\n  url \"{url}\"\n  sha256 \"{sha256}\"\n  license \"Apache-2.0\"\nend\n",
        origin.url(),
    );
    let run = harness
        .compare("brew", &binary, |dir| {
            let formula_path = dir.join("hoodfix.rb");
            fs::write(&formula_path, &formula)?;
            Ok(Invocation::new(dir)
                .args(["fetch", "--formula"])
                .arg(formula_path)
                .env("HOMEBREW_CACHE", dir.join("cache"))
                .env("HOMEBREW_DEVELOPER", "1")
                .env("HOMEBREW_NO_INSTALL_FROM_API", "1")
                .env("HOMEBREW_NO_AUTO_UPDATE", "1")
                .env("HOMEBREW_NO_ANALYTICS", "1")
                .env("HOMEBREW_NO_ENV_HINTS", "1"))
        })
        .await?;
    assert_success("brew", &run.output);
    assert_forwarded("brew", &run.output, &url);
    assert!(
        find_file(&run.dir.join("cache"), &|name| name
            .ends_with("hoodfix-1.0.0.tar.gz"))
        .is_some(),
        "brew did not cache the formula source"
    );
    Ok(())
}
