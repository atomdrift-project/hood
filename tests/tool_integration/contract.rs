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
    // Hood exempts loopback names from the proxy for Go's bridge on macOS;
    // the unspecified address is proxied for every tool.
    let url = format!("{}/stand-in", origin.go_url());
    let bin = tempfile::tempdir()?;
    // `go env` answers hood's macOS Go bridge query before the child runs.
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = env ]; then printf 'direct\\noff\\n'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$HOOD_STAND_IN_ARGV\"\nexec '{}' -fsS -o \"$HOOD_STAND_IN_OUT\" \"$HOOD_STAND_IN_URL\"\n",
        curl.display(),
    );
    for tool in Tool::SHIMMABLE {
        let path = bin.path().join(tool.name());
        fs::write(&path, &script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }
    }
    let harness = ToolHarness::new(&bin.path().join("curl"))?;
    let invocation = |name: &str, args: &[&str], mode: &str| -> Result<Invocation> {
        let dir = harness.dir(&format!("stand-in-{name}-{mode}"));
        fs::create_dir_all(&dir)?;
        Ok(Invocation::new(&dir)
            .args(args)
            .env("HOOD_STAND_IN_ARGV", dir.join("argv"))
            .env("HOOD_STAND_IN_OUT", dir.join("out"))
            .env("HOOD_STAND_IN_URL", &url))
    };
    for tool in Tool::SHIMMABLE {
        let name = tool.name();
        let args = fetching_args(*tool);

        harness
            .beamline
            .set(Beamline::Assesses, Some(sha256_hex(TOOL_MARKER.as_bytes())));
        let blocked = invocation(name, args, "known-bad")?;
        let (output, _) = harness
            .hood(name, &blocked, &harness.no_models, None)
            .await?;
        assert_blocked(name, &output, &url, "hostile");
        assert!(
            !blocked.cwd.join("out").is_file(),
            "{name} saved a blocked payload"
        );

        harness.beamline.set(Beamline::Assesses, None);
        let allowed = invocation(name, args, "known-good")?;
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
