//! Portable contract tests for every supported command, using stand-ins.
//!
//! Each stand-in is a shell script named after a tool that records its argv
//! and downloads a file with curl through whatever proxy it inherited. This
//! proves, on any Unix, that `hood <tool>` intercepts a fetching invocation,
//! passes the argv through, gives the child a working proxy, and blocks a
//! download Beamline rates hostile. It cannot
//! prove the real tool honors that proxy; the tool-specific tests here and in
//! CI's distribution images do that.

use std::fs;

use anyhow::Result;
use hood::tools::Tool;

use crate::{
    Beamline, Invocation, TOOL_MARKER, TestOrigin, ToolHarness, assert_blocked, assert_forwarded,
    assert_success, path_binary, sha256_hex, skip,
};

/// A representative network-fetching invocation for each tool.
const fn fetching_args(tool: Tool) -> &'static [&'static str] {
    match tool {
        Tool::Curl | Tool::Wget => &["-O", "https://example.invalid/file"],
        Tool::Npm => &["install", "left-pad"],
        Tool::Pnpm | Tool::Yarn | Tool::Bun => &["add", "left-pad"],
        Tool::Npx | Tool::Pnpx | Tool::Bunx | Tool::Uvx => &["cowsay"],
        Tool::Rush => &["install"],
        Tool::Rushx => &["build"],
        Tool::Pip | Tool::Pip3 | Tool::Pipx => &["install", "requests"],
        Tool::Uv => &["pip", "install", "requests"],
        Tool::Poetry | Tool::Pdm => &["add", "requests"],
        Tool::Go => &["get", "example.com/module"],
        Tool::Cargo => &["fetch"],
        Tool::Zig => &["fetch", "https://example.invalid/pkg.tar.gz"],
        Tool::Pacman => &["-Syu"],
        Tool::Yay | Tool::Paru => &["-S", "hoodfix"],
        Tool::Makepkg => &["--syncdeps"],
        Tool::Brew | Tool::Dnf | Tool::Yum => &["install", "jq"],
        Tool::Zypper => &["download", "jq"],
        Tool::Rpm => &["-qp", "https://example.invalid/x.rpm"],
        Tool::Pkg => &["fetch", "jq"],
        Tool::Apk => &["add", "jq"],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_supported_command_is_intercepted_with_stand_ins() -> Result<()> {
    let Some(curl) = path_binary("curl") else {
        skip::<()>("curl", "the stand-ins download with curl")?;
        return Ok(());
    };
    let origin = TestOrigin::spawn().await?;
    origin.add_route("/stand-in", "text/plain", TOOL_MARKER.as_bytes().to_vec());
    let bin = tempfile::tempdir()?;
    // Each stand-in records the argv it was called with, then fetches the test
    // URL with the real curl. The `env` branch answers hood's Go bridge query
    // (`go env`) before the child runs. The file extension matters on Windows:
    // hood resolves a bare tool name through PATHEXT, and only a `.cmd` both
    // resolves and executes there.
    let (extension, script) = if cfg!(windows) {
        (
            ".cmd",
            format!(
                "@echo off\r\n\
                 if \"%~1\"==\"env\" (echo direct& echo off& exit /b 0)\r\n\
                 break>\"%HOOD_STAND_IN_ARGV%\"\r\n\
                 :args\r\n\
                 if \"%~1\"==\"\" goto fetch\r\n\
                 >>\"%HOOD_STAND_IN_ARGV%\" echo %~1\r\n\
                 shift\r\n\
                 goto args\r\n\
                 :fetch\r\n\
                 \"{}\" -fsS -o \"%HOOD_STAND_IN_OUT%\" \"%HOOD_STAND_IN_URL%\"\r\n",
                curl.display(),
            ),
        )
    } else {
        (
            "",
            format!(
                "#!/bin/sh\nif [ \"$1\" = env ]; then printf 'direct\\noff\\n'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$HOOD_STAND_IN_ARGV\"\nexec '{}' -fsS -o \"$HOOD_STAND_IN_OUT\" \"$HOOD_STAND_IN_URL\"\n",
                curl.display(),
            ),
        )
    };
    for tool in Tool::SHIMMABLE {
        let path = bin.path().join(format!("{}{extension}", tool.name()));
        fs::write(&path, &script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }
    }
    let harness = ToolHarness::new(&bin.path().join(format!("curl{extension}")))?;
    let invocation = |name: &str, args: &[&str], mode: &str, url: &str| -> Result<Invocation> {
        let dir = harness.dir(&format!("stand-in-{name}-{mode}"));
        fs::create_dir_all(&dir)?;
        Ok(Invocation::new(&dir)
            .args(args)
            .env("HOOD_STAND_IN_ARGV", dir.join("argv"))
            .env("HOOD_STAND_IN_OUT", dir.join("out"))
            .env("HOOD_STAND_IN_URL", url))
    };
    for tool in Tool::SHIMMABLE {
        let name = tool.name();
        let args = fetching_args(*tool);
        // hood routes `go` through the loopback bridge and exempts loopback
        // from the child's proxy, so a loopback stand-in cannot be intercepted.
        // macOS works around this with go_url()'s unspecified address; Windows
        // cannot connect to 0.0.0.0, so skip go there. Its interception is
        // covered by `toolchain::go_mod_download_runs_through_hood`.
        if *tool == Tool::Go && cfg!(windows) {
            continue;
        }
        let origin_url = if *tool == Tool::Go && cfg!(target_os = "macos") {
            origin.go_url()
        } else {
            origin.url()
        };
        let url = format!("{origin_url}/stand-in");

        harness
            .beamline
            .set(Beamline::Assesses, Some(sha256_hex(TOOL_MARKER.as_bytes())));
        let blocked = invocation(name, args, "known-bad", &url)?;
        let (output, _) = harness
            .hood(name, &blocked, &harness.no_models, None)
            .await?;
        assert_blocked(name, &output, &url, "hostile");
        assert!(
            !blocked.cwd.join("out").is_file(),
            "{name} saved a blocked payload"
        );

        harness.beamline.set(Beamline::Assesses, None);
        let allowed = invocation(name, args, "known-good", &url)?;
        let dir = allowed.cwd.clone();
        let (output, _) = harness
            .hood(name, &allowed, &harness.no_models, None)
            .await?;
        assert_success(name, &output);
        assert_forwarded(name, &output, &url);
        assert_eq!(fs::read_to_string(dir.join("out"))?, TOOL_MARKER, "{name}");
        let recorded = fs::read_to_string(dir.join("argv"))?;
        let received: Vec<&str> = recorded.lines().collect();
        assert!(
            received.starts_with(args),
            "{name} received {received:?}, expected it to start with {args:?}"
        );
    }
    Ok(())
}
