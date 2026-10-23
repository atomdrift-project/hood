//! Alpine's `apk`, run in CI's Alpine container as root.

use std::ffi::OsStr;
use std::fs;

use anyhow::Result;

use crate::{
    Invocation, Payload, TOOL_MARKER, TestOrigin, ToolHarness, assert_forwarded, gzip, helper,
    is_root, sha256_hex, skip, tar_gz, tar_header, tool_binary,
};

pub(crate) const TOOLS: &[&str] = &["apk"];

const PACKAGE_FILE: &str = "hoodfix-1.0.0-r0.apk";

/// Build an unsigned apk v2 package: a gzip control segment whose tar lacks
/// an end-of-archive marker, followed by a gzip data segment, so the two
/// streams read as one tar. `.PKGINFO` records the data segment's SHA-256.
/// `arch` is the repository's: apk fetches a package from the directory its
/// own arch names, so a `noarch` package under `x86_64/` is never found.
fn package(arch: &str) -> Result<Vec<u8>> {
    let data = tar_gz(&[("usr/share/hoodfix/README", 0o644, TOOL_MARKER.as_bytes())])?;
    let pkginfo = format!(
        "pkgname = hoodfix\npkgver = 1.0.0-r0\npkgdesc = hood integration fixture\nurl = https://example.invalid\nbuilddate = 0\npackager = hood\nsize = 0\narch = {arch}\norigin = hoodfix\nlicense = Apache-2.0\ndatahash = {}\n",
        sha256_hex(&data),
    );
    let mut control = tar_header(".PKGINFO", 0o644, pkginfo.len())?
        .as_bytes()
        .to_vec();
    control.extend_from_slice(pkginfo.as_bytes());
    control.resize(control.len().next_multiple_of(512), 0);
    let mut package = gzip(&control)?;
    package.extend_from_slice(&data);
    Ok(package)
}

/// `apk fetch` downloads a package from a fixture repository.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apk_fetches_package_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("apk")? else {
        return Ok(());
    };
    if !is_root() {
        skip::<()>("apk", "requires root")?;
        return Ok(());
    }
    let harness = ToolHarness::new(&binary)?;
    let arch = helper("apk", &[OsStr::new("--print-arch")], &harness.dir(""))
        .await?
        .trim()
        .to_owned();
    let repo = harness.dir("apk-repo");
    let arch_dir = repo.join(&arch);
    fs::create_dir_all(&arch_dir)?;
    let package = package(&arch)?;
    fs::write(arch_dir.join(PACKAGE_FILE), &package)?;
    helper(
        "apk",
        &[
            OsStr::new("index"),
            OsStr::new("--allow-untrusted"),
            OsStr::new("-o"),
            OsStr::new("APKINDEX.tar.gz"),
            OsStr::new(PACKAGE_FILE),
        ],
        &arch_dir,
    )
    .await?;
    let origin = TestOrigin::spawn().await?;
    origin.add_dir("/repo", &repo)?;
    let url = format!("{}/repo", origin.url());
    let package_url = format!("{url}/{arch}/{PACKAGE_FILE}");
    let run = harness
        .exercise(
            "apk",
            &binary,
            |dir| {
                Ok(Invocation::new(dir)
                    .args([
                        "fetch",
                        "--allow-untrusted",
                        "--no-cache",
                        "--repositories-file",
                        "/dev/null",
                        "--repository",
                        &url,
                        "--output",
                    ])
                    .arg(dir)
                    .arg("hoodfix"))
            },
            Payload {
                bytes: &package,
                url: &package_url,
            },
            |run| run.dir.join(PACKAGE_FILE).is_file(),
        )
        .await?;
    assert_forwarded("apk", &run.output, "APKINDEX.tar.gz");
    Ok(())
}
