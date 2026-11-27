//! Downloaders and Homebrew.

use std::fs;

use anyhow::Result;

use crate::{Invocation, Payload, TOOL_MARKER, TestOrigin, ToolHarness, tool_binary};

pub(crate) const TOOLS: &[&str] = &["curl", "wget", "brew"];

const FILE: &str = "/hood-download.txt";

async fn downloader(tool: &str, args: &[&str]) -> Result<()> {
    let Some(binary) = tool_binary(tool)? else {
        return Ok(());
    };
    let harness = ToolHarness::new(&binary)?;
    let origin = TestOrigin::spawn().await?;
    origin.add_route(FILE, "text/plain", TOOL_MARKER.as_bytes().to_vec());
    let url = format!("{}{FILE}", origin.url());
    harness
        .exercise(
            tool,
            &binary,
            |dir| {
                Ok(Invocation::new(dir)
                    .args(args)
                    .arg(dir.join("out.txt"))
                    .arg(&url))
            },
            Payload {
                bytes: TOOL_MARKER.as_bytes(),
                url: &url,
            },
            |run| fs::read_to_string(run.dir.join("out.txt")).is_ok_and(|out| out == TOOL_MARKER),
        )
        .await?;
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

/// Homebrew runs only on Unix, and its fixture is built from symlinks.
#[cfg(unix)]
mod brew {
    use std::fs;
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};

    use crate::{
        Invocation, Payload, TOOL_MARKER, TestOrigin, ToolHarness, find_file, sha256_hex, tar_gz,
        tool_binary,
    };

    /// A Homebrew of the test's own: the installed brew's code under a
    /// temporary prefix, holding one trusted tap with one formula.
    ///
    /// brew loads formulae only from taps, and taps live inside its prefix, so
    /// a fixture formula needs a prefix to live in; this one keeps it out of
    /// the developer's real Homebrew. brew finds its prefix from where its
    /// launcher is, and its library through whatever that prefix links to.
    struct BrewPrefix {
        root: tempfile::TempDir,
    }

    impl BrewPrefix {
        const FORMULA: &str = "hood/fixture/hoodfix";

        async fn new(installed: &Path, formula: &str) -> Result<Self> {
            let launcher = installed.canonicalize()?;
            let library = launcher
                .parent()
                .and_then(Path::parent)
                .context("brew launcher is not in a bin directory")?
                .join("Library/Homebrew");
            let root = tempfile::Builder::new()
                .prefix("hood-brew-prefix-")
                .tempdir()?;
            let prefix = root.path().join("prefix");
            let tap = prefix.join("Library/Taps/hood/homebrew-fixture/Formula");
            fs::create_dir_all(&tap)?;
            fs::create_dir_all(prefix.join("bin"))?;
            fs::copy(&launcher, prefix.join("bin/brew"))?;
            std::os::unix::fs::symlink(library, prefix.join("Library/Homebrew"))?;
            fs::write(tap.join("hoodfix.rb"), formula)?;
            let brew = Self { root };
            // brew refuses formulae from a tap nobody trusted. A brew from before
            // that rule has no `trust` command and needs none, so its failure
            // here is not one; a brew that does need it fails the fetch plainly.
            let trust = brew
                .invocation(brew.root.path())?
                .arg("trust")
                .arg("hood/fixture");
            let mut command = tokio::process::Command::new(brew.binary());
            command.args(&trust.args).envs(trust.envs.iter().cloned());
            drop(command.output().await?);
            Ok(brew)
        }

        fn binary(&self) -> PathBuf {
            self.root.path().join("prefix/bin/brew")
        }

        /// A brew command whose every write stays under `dir` or this prefix.
        /// The API is disabled so that only the fixture is fetched; without it
        /// brew clones the whole homebrew/core tap (1.5 GB) on first use unless
        /// told, as its own `Homebrew::API.with_no_api_env` does, that the mode
        /// was set automatically.
        fn invocation(&self, dir: &Path) -> Result<Invocation> {
            // brew refuses a temporary directory that holds its prefix.
            let temp = dir.join("temp");
            fs::create_dir_all(&temp)?;
            let mut invocation = Invocation::new(dir)
                .env("HOMEBREW_CACHE", dir.join("cache"))
                .env("HOMEBREW_TEMP", temp)
                // Where brew keeps its trust list, and reads `brew.env` from.
                .env("XDG_CONFIG_HOME", self.root.path().join("config"))
                .env("HOMEBREW_NO_INSTALL_FROM_API", "1")
                .env("HOMEBREW_AUTOMATICALLY_SET_NO_INSTALL_FROM_API", "1")
                .env("HOMEBREW_NO_AUTO_UPDATE", "1")
                .env("HOMEBREW_NO_ANALYTICS", "1")
                .env("HOMEBREW_NO_ENV_HINTS", "1");
            // `brew shellenv` exports these; they would name the real prefix.
            for inherited in ["HOMEBREW_PREFIX", "HOMEBREW_CELLAR", "HOMEBREW_REPOSITORY"] {
                invocation = invocation.env(inherited, "");
            }
            Ok(invocation)
        }
    }

    /// `brew fetch` downloads a formula's source archive over HTTPS.
    ///
    /// brew discards every CA variable hood sets, so this is what proves its
    /// curl is still made to trust hood: the origin's certificate chains to a
    /// root only hood is given (`SSL_CERT_FILE`, which brew drops and hood's
    /// upstream verifier reads), while brew's own curl is given it only for the
    /// direct run's sake, through a `HOMEBREW_CURLRC` hood must then outrank.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn brew_fetches_formula_source_through_hood() -> Result<()> {
        let Some(installed) = tool_binary("brew")? else {
            return Ok(());
        };
        let origin = TestOrigin::spawn_tls().await?;
        let archive = tar_gz(&[("hoodfix-1.0.0/README", 0o644, TOOL_MARKER.as_bytes())])?;
        let path = "/hoodfix-1.0.0.tar.gz";
        let url = format!("{}{path}", origin.url());
        let formula = format!(
            "class Hoodfix < Formula\n  desc \"hood integration fixture\"\n  homepage \"{}\"\n  url \"{url}\"\n  sha256 \"{}\"\n  license \"Apache-2.0\"\nend\n",
            origin.url(),
            sha256_hex(&archive),
        );
        origin.add_route(path, "application/gzip", archive.clone());
        let brew = BrewPrefix::new(&installed, &formula).await?;
        let binary = brew.binary();
        let harness = ToolHarness::new(&binary)?;
        let origin_ca = harness.dir("origin-ca.pem");
        fs::write(&origin_ca, origin.ca_pem.as_deref().unwrap_or_default())?;
        let curlrc = harness.dir("curlrc");
        fs::write(&curlrc, format!("cacert = \"{}\"\n", origin_ca.display()))?;
        harness
            .exercise(
                "brew",
                &binary,
                |dir| {
                    Ok(brew
                        .invocation(dir)?
                        .args(["fetch", BrewPrefix::FORMULA])
                        .env("HOMEBREW_CURLRC", &curlrc)
                        .env("SSL_CERT_FILE", &origin_ca))
                },
                Payload {
                    bytes: &archive,
                    url: &url,
                },
                |run| {
                    find_file(&run.dir.join("cache"), &|name| {
                        name.ends_with("hoodfix-1.0.0.tar.gz")
                    })
                    .is_some()
                },
            )
            .await?;
        Ok(())
    }
}
