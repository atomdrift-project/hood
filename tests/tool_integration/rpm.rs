//! RPM-family package managers. `dnf`, `yum`, and `zypper` run in CI
//! containers as root; `rpm` runs anywhere `rpmbuild` exists.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{
    Invocation, TestOrigin, ToolHarness, assert_forwarded, assert_requested, assert_success,
    find_file, helper, is_root, path_binary, skip, tool_binary,
};

pub(crate) const TOOLS: &[&str] = &["rpm", "dnf", "yum", "zypper"];

const RPM: &str = "hoodfix-1.0.0-1.noarch.rpm";

const SPEC: &str = "Name: hoodfix
Version: 1.0.0
Release: 1
Summary: hood integration fixture
License: Apache-2.0
BuildArch: noarch

%description
hood integration fixture

%files
";

/// Build the fixture RPM under `work` and return the directory holding it.
/// With `repo`, also generate repository metadata alongside it.
async fn build_rpm(tool: &str, work: &Path, repo: bool) -> Result<Option<PathBuf>> {
    if path_binary("rpmbuild").is_none() {
        return skip(tool, "rpmbuild unavailable to build the fixture");
    }
    if repo && path_binary("createrepo_c").is_none() {
        return skip(tool, "createrepo_c unavailable to build the fixture");
    }
    let out = work.join("repo");
    fs::create_dir_all(&out)?;
    let spec = work.join("hoodfix.spec");
    fs::write(&spec, SPEC)?;
    let define = |name: &str, value: &Path| format!("{name} {}", value.display());
    let topdir = define("_topdir", &work.join("rpmbuild"));
    let tmppath = define("_tmppath", &work.join("tmp"));
    let rpmdir = define("_rpmdir", &out);
    let name_fmt = format!("_build_name_fmt {RPM}");
    helper(
        "rpmbuild",
        &[
            OsStr::new("-bb"),
            OsStr::new("--define"),
            OsStr::new(&topdir),
            OsStr::new("--define"),
            OsStr::new(&tmppath),
            OsStr::new("--define"),
            OsStr::new(&rpmdir),
            OsStr::new("--define"),
            OsStr::new(&name_fmt),
            spec.as_os_str(),
        ],
        work,
    )
    .await?;
    if repo {
        helper("createrepo_c", &[out.as_os_str()], work).await?;
    }
    Ok(Some(out))
}

/// Serve the fixture RPM (and repository) at `/repo`; return its base URL.
async fn rpm_origin(
    tool: &str,
    harness: &ToolHarness,
    repo: bool,
) -> Result<Option<(TestOrigin, String)>> {
    let Some(out) = build_rpm(tool, &harness.dir("rpm-fixture"), repo).await? else {
        return Ok(None);
    };
    let origin = TestOrigin::spawn().await?;
    origin.add_dir("/repo", &out)?;
    let url = format!("{}/repo", origin.url());
    Ok(Some((origin, url)))
}

/// `rpm -qp` queries a package straight from a URL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpm_queries_remote_package_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("rpm")? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let Some((origin, base)) = rpm_origin("rpm", &harness, false).await? else {
        return Ok(());
    };
    let url = format!("{base}/{RPM}");
    let run = harness
        .compare("rpm", &binary, |dir| {
            Ok(Invocation::new(dir)
                .arg("--define")
                .arg(format!("_dbpath {}", dir.join("rpmdb").display()))
                .args(["-qp", "--qf", "%{NAME}-%{VERSION}\\n", &url]))
        })
        .await?;
    assert_success("rpm", &run.output);
    assert!(
        run.output.stdout.contains("hoodfix-1.0.0"),
        "rpm did not read the fixture:\n{}",
        run.output.stdout
    );
    assert_forwarded("rpm", &run.output, &url);
    assert_requested(&origin, RPM);
    Ok(())
}

/// `dnf download` (and `yum`, its alias on current Fedora) fetches a package
/// from a repository given on the command line.
async fn dnf_downloads(tool: &str) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    if !is_root() {
        skip::<()>(tool, "requires root")?;
        return Ok(());
    }
    let harness = ToolHarness::new(&binary)?;
    let Some((origin, repo)) = rpm_origin(tool, &harness, true).await? else {
        return Ok(());
    };
    let run = harness
        .compare(tool, &binary, |dir| {
            let cache = dir.join("cache");
            Ok(Invocation::new(dir)
                .arg("download")
                .arg(format!("--repofrompath=hoodfix,{repo}"))
                .args(["--repo=hoodfix", "--setopt=hoodfix.gpgcheck=0"])
                .arg(format!("--setopt=cachedir={}", cache.display()))
                .arg(format!("--setopt=system_cachedir={}", cache.display()))
                .arg(format!("--destdir={}", dir.join("dl").display()))
                .arg("hoodfix"))
        })
        .await?;
    assert_success(tool, &run.output);
    assert_forwarded(tool, &run.output, RPM);
    assert!(
        run.dir.join("dl").join(RPM).is_file(),
        "{tool} did not save {RPM}"
    );
    assert_requested(&origin, "repomd.xml");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dnf_downloads_package_through_hood() -> Result<()> {
    dnf_downloads("dnf").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yum_downloads_package_through_hood() -> Result<()> {
    dnf_downloads("yum").await
}

/// `zypper download` with only the fixture repository configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zypper_downloads_package_through_hood() -> Result<()> {
    let Some(binary) = tool_binary("zypper")? else {
        return Ok(());
    };
    if !is_root() {
        skip::<()>("zypper", "requires root")?;
        return Ok(());
    }
    let harness = ToolHarness::new(&binary)?;
    let Some((origin, repo)) = rpm_origin("zypper", &harness, true).await? else {
        return Ok(());
    };
    let run = harness
        .compare("zypper", &binary, |dir| {
            let repos = dir.join("repos.d");
            fs::create_dir_all(&repos)?;
            fs::write(
                repos.join("hoodfix.repo"),
                format!(
                    "[hoodfix]\nname=hoodfix\nbaseurl={repo}\nenabled=1\nautorefresh=1\ngpgcheck=0\ntype=rpm-md\n"
                ),
            )?;
            Ok(Invocation::new(dir)
                .args(["--non-interactive", "--no-gpg-checks", "--reposd-dir"])
                .arg(repos)
                .arg("--cache-dir")
                .arg(dir.join("cache"))
                .args(["download", "hoodfix"]))
        })
        .await?;
    assert_success("zypper", &run.output);
    assert_forwarded("zypper", &run.output, RPM);
    assert!(
        find_file(&run.dir.join("cache"), &|name| name == RPM).is_some(),
        "zypper did not save {RPM}"
    );
    assert_requested(&origin, "repomd.xml");
    Ok(())
}
