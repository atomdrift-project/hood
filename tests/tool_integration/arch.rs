//! Arch Linux package tooling, run in CI's Arch container. `pacman` needs
//! root; `makepkg` and the AUR helpers refuse it, so CI runs this suite in
//! two passes (see `tests/distro/arch.sh`).

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::{
    Invocation, TOOL_MARKER, TestOrigin, ToolHarness, assert_forwarded, assert_requested,
    assert_success, helper, is_root, path_binary, sha256_hex, skip, tar_gz, tool_binary,
};

pub(crate) const TOOLS: &[&str] = &["pacman", "makepkg", "yay", "paru"];

const PACKAGE_FILE: &str = "hoodfix-1.0.0-1-any.pkg.tar.gz";
const SOURCE_FILE: &str = "hoodfix-src.tar.gz";

/// Skip unless the current user matches what `tool` requires.
fn runs_as(tool: &str, root: bool) -> Result<bool> {
    if is_root() == root {
        return Ok(true);
    }
    let reason = if root {
        "requires root"
    } else {
        "refuses to run as root"
    };
    skip::<()>(tool, reason)?;
    Ok(false)
}

/// `pacman -Syw` syncs a fixture repository and downloads its package.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pacman_syncs_and_downloads_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("pacman")? else {
        return Ok(());
    };
    if !runs_as("pacman", true)? {
        return Ok(());
    }
    if path_binary("repo-add").is_none() {
        skip::<()>("pacman", "repo-add unavailable to build the fixture")?;
        return Ok(());
    }
    let harness = ToolHarness::new(&binary)?;
    let repo = harness.dir("pacman-repo");
    fs::create_dir_all(&repo)?;
    let pkginfo = "pkgname = hoodfix\npkgbase = hoodfix\npkgver = 1.0.0-1\npkgdesc = hood integration fixture\nurl = https://example.invalid\nbuilddate = 0\npackager = hood\nsize = 0\narch = any\nlicense = Apache-2.0\n";
    let package = repo.join(PACKAGE_FILE);
    fs::write(
        &package,
        tar_gz(&[(".PKGINFO", 0o644, pkginfo.as_bytes())])?,
    )?;
    let db = repo.join("hoodfix.db.tar.gz");
    helper("repo-add", &[db.as_os_str(), package.as_os_str()], &repo).await?;
    let origin = TestOrigin::spawn().await?;
    origin.add_dir("/repo", &repo)?;
    let server = format!("{}/repo", origin.url());
    let run = harness
        .compare("pacman", &binary, |dir| {
            for sub in ["db", "cache", "gnupg"] {
                fs::create_dir_all(dir.join(sub))?;
            }
            let config = dir.join("pacman.conf");
            fs::write(
                &config,
                format!(
                    "[options]\nArchitecture = auto\nSigLevel = Never\nLocalFileSigLevel = Never\n\n[hoodfix]\nServer = {server}\n"
                ),
            )?;
            Ok(Invocation::new(dir)
                .arg("--config")
                .arg(config)
                .arg("--dbpath")
                .arg(dir.join("db"))
                .arg("--cachedir")
                .arg(dir.join("cache"))
                .arg("--gpgdir")
                .arg(dir.join("gnupg"))
                .arg("--logfile")
                .arg(dir.join("pacman.log"))
                .args(["--noconfirm", "-Syw", "hoodfix"]))
        })
        .await?;
    assert_success("pacman", &run.output);
    assert_forwarded("pacman", &run.output, "hoodfix.db");
    assert_forwarded("pacman", &run.output, PACKAGE_FILE);
    assert!(run.dir.join("cache").join(PACKAGE_FILE).is_file());
    Ok(())
}

/// `makepkg` downloads PKGBUILD sources through its curl download agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn makepkg_downloads_sources_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("makepkg")? else {
        return Ok(());
    };
    if !runs_as("makepkg", false)? {
        return Ok(());
    }
    let harness = ToolHarness::new(&binary)?;
    let origin = TestOrigin::spawn().await?;
    let source = tar_gz(&[("hoodfix/README", 0o644, TOOL_MARKER.as_bytes())])?;
    let sha256 = sha256_hex(&source);
    let path = format!("/{SOURCE_FILE}");
    origin.add_route(path.clone(), "application/gzip", source);
    let url = format!("{}{path}", origin.url());
    let run = harness
        .compare("makepkg", &binary, |dir| {
            fs::write(
                dir.join("PKGBUILD"),
                format!(
                    "pkgname=hoodfix\npkgver=1.0.0\npkgrel=1\npkgdesc='hood integration fixture'\narch=(any)\nlicense=(Apache-2.0)\nsource=(\"{url}\")\nsha256sums=('{sha256}')\npackage() {{ :; }}\n"
                ),
            )?;
            Ok(Invocation::new(dir)
                .args(["--nobuild", "--nodeps", "--noconfirm"])
                .env("SRCDEST", dir.join("src"))
                .env("BUILDDIR", dir.join("build"))
                .env("PKGDEST", dir.join("pkg"))
                .env("LOGDEST", dir.join("log")))
        })
        .await?;
    assert_success("makepkg", &run.output);
    assert_forwarded("makepkg", &run.output, &url);
    assert!(run.dir.join("src").join(SOURCE_FILE).is_file());
    Ok(())
}

/// Serve an AUR fixture: the RPC info endpoint and a git repository over
/// git's static ("dumb") HTTP protocol. Uses [`TestOrigin::go_url`] because
/// yay is a Go program; the address works for every client.
async fn aur_origin(tool: &str, harness: &ToolHarness) -> Result<Option<(TestOrigin, String)>> {
    if path_binary("git").is_none() {
        return skip(tool, "git unavailable to build the fixture");
    }
    let work = harness.dir("aur");
    let checkout = work.join("hoodfix");
    fs::create_dir_all(&checkout)?;
    fs::write(
        checkout.join("PKGBUILD"),
        "pkgname=hoodfix\npkgver=1.0.0\npkgrel=1\npkgdesc='hood integration fixture'\narch=(any)\nlicense=(Apache-2.0)\npackage() { :; }\n",
    )?;
    fs::write(
        checkout.join(".SRCINFO"),
        "pkgbase = hoodfix\n\tpkgdesc = hood integration fixture\n\tpkgver = 1.0.0\n\tpkgrel = 1\n\tarch = any\n\tlicense = Apache-2.0\n\npkgname = hoodfix\n",
    )?;
    git(&["init", "-q"], &checkout).await?;
    git(&["add", "PKGBUILD", ".SRCINFO"], &checkout).await?;
    git(&["commit", "-q", "-m", "hoodfix"], &checkout).await?;
    git(&["clone", "-q", "--bare", "hoodfix", "hoodfix.git"], &work).await?;
    git(&["update-server-info"], &work.join("hoodfix.git")).await?;

    let origin = TestOrigin::spawn().await?;
    origin.add_dir("/hoodfix.git", &work.join("hoodfix.git"))?;
    let info = r#"{"version":5,"type":"multiinfo","resultcount":1,"results":[{"ID":1,"Name":"hoodfix","PackageBaseID":1,"PackageBase":"hoodfix","Version":"1.0.0-1","Description":"hood integration fixture","URL":null,"NumVotes":0,"Popularity":0,"OutOfDate":null,"Maintainer":"hood","FirstSubmitted":0,"LastModified":0,"URLPath":"/cgit/aur.git/snapshot/hoodfix.tar.gz","Depends":[],"MakeDepends":[],"License":["Apache-2.0"],"Keywords":[]}]}"#;
    for path in ["/rpc", "/rpc/", "/rpc/v5/info", "/rpc/v5/info/hoodfix"] {
        origin.add_route(path, "application/json", info.as_bytes().to_vec());
    }
    let url = origin.go_url();
    Ok(Some((origin, url)))
}

/// Run git with a fixed identity, independent of user configuration.
async fn git(args: &[&str], cwd: &Path) -> Result<String> {
    let args: Vec<&OsStr> = [
        "-c",
        "user.name=hood",
        "-c",
        "user.email=hood@example.invalid",
        "-c",
        "init.defaultBranch=master",
    ]
    .iter()
    .chain(args)
    .map(OsStr::new)
    .collect();
    helper("git", &args, cwd).await
}

/// `yay -G` / `paru -G` query the AUR and clone the package's build files.
async fn aur_helper_clones(tool: &str) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    if !runs_as(tool, false)? {
        return Ok(());
    }
    let harness = ToolHarness::new(&binary)?;
    let Some((origin, aur)) = aur_origin(tool, &harness).await? else {
        return Ok(());
    };
    let run = harness
        .compare(tool, &binary, |dir| {
            Ok(Invocation::new(dir)
                .args(["-G", "--aururl", &aur, "hoodfix"])
                .env("XDG_CONFIG_HOME", dir.join("config"))
                .env("XDG_CACHE_HOME", dir.join("cache")))
        })
        .await?;
    assert_success(tool, &run.output);
    assert_forwarded(tool, &run.output, &format!("{aur}/rpc"));
    assert_forwarded(tool, &run.output, &format!("{aur}/hoodfix.git"));
    assert!(run.dir.join("hoodfix").join("PKGBUILD").is_file());
    assert_requested(&origin, "/info/refs");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yay_clones_aur_package_through_hood() -> Result<()> {
    aur_helper_clones("yay").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paru_clones_aur_package_through_hood() -> Result<()> {
    aur_helper_clones("paru").await
}
