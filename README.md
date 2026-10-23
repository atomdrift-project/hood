# hood

[![Status: experimental](https://img.shields.io/badge/status-experimental-E5A50A)](#why-hood) [![CI](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml/badge.svg)](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/atomdrift-project/hood/badge)](https://scorecard.dev/viewer/?uri=github.com/atomdrift-project/hood) [![License: Apache-2.0](https://img.shields.io/github/license/atomdrift-project/hood)](LICENSE)

> [!WARNING]
> This is experimental. It may eat your cat.

<p align="center"><img src="media/hood.jpg" alt="Handle chemicals under a fume hood" width="392"></p>

Hood stops supply-chain malware before it runs. It is a local proxy that scans every package, archive, and script your package managers and fetch tools download, and blocks hostile ones before the tool receives them, whether the command came from a developer, a CI job, or a misbehaving AI agent. It wraps the commands you already run on Linux, macOS, Windows, and FreeBSD; registries, lockfiles, and CI stay as they are. Other supply-chain tools check names against a list; Hood scans bytes, so private, vendored, and `curl`-fetched artifacts get the same scrutiny as the top of npm and PyPI.

## Why hood

- **Gap-free scanning.** No download is released without a decision. When neither the local filters nor the cloud tier can vouch for an artifact, Hood scans the bytes inline with static analysis and ML.
- **ClickFix protection.** A script fetched with `curl -fsSL https://example.com/install.sh | sh` is scanned before the shell receives it. Windows ClickFix campaigns fetch from inside PowerShell, which no shim can see.
- **Offline operation.** `HOOD_LOCAL=1` disables the cloud tier and `SCAN_NO_UPDATE=1` the daily rule download; local filters and analysis keep working.
- **Zero telemetry.** Hood sends no usage data, crash reports, or identifiers. Beamline, the cloud tier, receives a public package URL or a SHA-256 and nothing else: no file contents, download URLs, cookies, or registry tokens.
- **No root, no host changes.** Hood installs shims under `~/.hood/bin` and one marked block in your shell rc or PowerShell profile. Each intercepted command gets a fresh CA trusted only by that child process; the host trust store and system proxy settings are never touched.
- **Fails closed.** Suspicious and hostile verdicts block. `HOOD_BYPASS` relaxes that in steps (`1` forward on scanner error, `2` also forward suspicious, `3` forward everything); any other value is treated as strict and logged.

## Install (Rust 1.97+)

```sh
git clone https://github.com/atomdrift-project/hood.git && cd hood
make install && hood install
```

Restart your shell and use your tools as before. `hood -v <tool> …` or `HOOD_VERBOSE=1` prints a verdict per artifact and a summary; `hood uninstall` removes the shims and the rc block. On Windows, cmd.exe is not configured and `hood install` must be rerun after upgrading. For GitHub Actions, pin Hood to a reviewed commit, install it the same way, add `$HOME/.hood/bin` to `GITHUB_PATH`, and leave the existing `npm ci` or `pip install` steps alone.

## Supported commands

Commands that fetch are intercepted; local operations such as `go test`, `cargo build`, and `npm test` pass through. Anything else runs under `hood exec -- <command>`, which sets the proxy and CA environment for that process. npm and pnpm installs run with `--ignore-scripts`; `--enable-scripts` restores them.

| Ecosystem | Commands |
| --- | --- |
| Fetch tools | `curl`, `wget` |
| JavaScript | `npm`, `npx`, `pnpm`, `pnpx`, `yarn`, `bun`, `bunx`, `rush`, `rushx` |
| Python | `pip`, `pip3`, `pipx`, `uv`, `uvx`, `poetry`, `pdm` |
| Compiled languages | `go`, `cargo`, `zig` |
| System packages | `brew`, `pacman`, `yay`, `paru`, `makepkg`, `dnf`, `yum`, `zypper`, `rpm`, `apk`, `pkg` |

## How a download is decided

1. **Local Bloom filters** from Atomdrift Scan. Package URL and content hash must both be known good to skip inspection. Known-bad blocks at once.
2. **Beamline assessment.** Public packages are assessed by package URL, everything else by SHA-256. Verified results are cached for 30 days.
3. **Local analysis** for anything still unresolved, including API outages and rate limits. Downloads larger than `HOOD_MAX_SCAN_MB` (default 2 GB) follow the `HOOD_BYPASS` policy.

`hood login` enables the isotope13 Enriched rules; `ISOTOPE13_TOKEN` overrides the saved token, and a lapsed token is a warning, never a failed install. `HOOD_BEAMLINE_URL` points at an alternate API origin (HTTPS required except on loopback).
