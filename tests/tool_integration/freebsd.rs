//! FreeBSD's `pkg`, run in CI's FreeBSD VM as root.

use std::ffi::OsStr;
use std::fs;

use anyhow::{Context, Result};

use crate::{
    Invocation, Payload, TestOrigin, ToolHarness, find_file, helper, is_root, skip, tool_binary,
};

pub(crate) const TOOLS: &[&str] = &["pkg"];

const MANIFEST: &str = r#"name: hoodfix
origin: misc/hoodfix
version: "1.0.0"
comment: "hood integration fixture"
desc: "hood integration fixture"
maintainer: "hood@example.invalid"
www: "https://example.invalid"
prefix: "/usr/local"
"#;

/// `pkg fetch` updates a fixture repository catalogue and downloads from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pkg_fetches_package_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("pkg")? else {
        return Ok(());
    };
    if !is_root() {
        skip::<()>("pkg", "requires root")?;
        return Ok(());
    }
    let harness = ToolHarness::new(&binary)?;
    let work = harness.dir("pkg-fixture");
    let repo = work.join("repo");
    let all = repo.join("All");
    fs::create_dir_all(&all)?;
    let manifest = work.join("manifest.ucl");
    fs::write(&manifest, MANIFEST)?;
    helper(
        "pkg",
        &[
            OsStr::new("create"),
            OsStr::new("-M"),
            manifest.as_os_str(),
            OsStr::new("-o"),
            all.as_os_str(),
        ],
        &work,
    )
    .await?;
    helper("pkg", &[OsStr::new("repo"), repo.as_os_str()], &work).await?;
    let built = find_file(&all, &|name| name.starts_with("hoodfix-1.0.0"))
        .context("pkg create wrote no package")?;
    let package = fs::read(&built)?;
    let origin = TestOrigin::spawn().await?;
    origin.add_dir("/repo", &repo)?;
    let url = format!("{}/repo", origin.url());
    let package_url = format!("{url}/All/hoodfix-1.0.0");
    harness
        .exercise(
            "pkg",
            &binary,
            |dir| {
                let repos = dir.join("repos");
                fs::create_dir_all(&repos)?;
                fs::create_dir_all(dir.join("db"))?;
                fs::write(
                    repos.join("hoodfix.conf"),
                    format!(
                        "hoodfix: {{ url: \"{url}\", signature_type: \"none\", mirror_type: \"none\", enabled: yes }}\n"
                    ),
                )?;
                Ok(Invocation::new(dir)
                    .args(["fetch", "-y", "-r", "hoodfix", "hoodfix"])
                    .env("REPOS_DIR", repos)
                    .env("PKG_CACHEDIR", dir.join("cache"))
                    .env("PKG_DBDIR", dir.join("db"))
                    .env("ASSUME_ALWAYS_YES", "yes"))
            },
            Payload {
                bytes: &package,
                url: &package_url,
            },
            |run| {
                find_file(&run.dir.join("cache"), &|name| name.starts_with("hoodfix-1.0.0"))
                    .is_some()
            },
        )
        .await?;
    Ok(())
}
