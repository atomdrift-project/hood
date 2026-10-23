# hood

[![Status: experimental](https://img.shields.io/badge/status-experimental-E5A50A)](#what-it-does) [![CI](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml/badge.svg)](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/atomdrift-project/hood/badge)](https://scorecard.dev/viewer/?uri=github.com/atomdrift-project/hood) [![License: Apache-2.0](https://img.shields.io/github/license/atomdrift-project/hood)](LICENSE)

> [!WARNING]
> This is experimental. It may eat your cat.

<p align="center"><img src="media/hood.jpg" alt="Handle chemicals under a fume hood" width="560"></p>

## What it does

Hood is a local proxy that inspects what package managers and fetch tools download before the tool receives it. It wraps the commands you already run; registries, lockfiles, and CI stay as they are.

Most supply-chain tools check a package name against a list. Hood inspects the bytes. That matters to any organization whose critical packages are private, vendored, or fetched with `curl`: no list has seen them.

## Why hood

- **Gap-free scanning.** No download is released without a decision. When neither the local filters nor the cloud tier can vouch for an artifact, Hood scans the bytes itself with static analysis and ML, inline. Private packages, GitHub archives, new versions, and one-off URLs get the same inspection as the top of npm and PyPI.
- **ClickFix protection.** A script fetched with `curl -fsSL https://example.com/install.sh | sh` is scanned before the shell receives it. A pasted command faces the same check as a poisoned package. This covers macOS, Linux, and the BSDs; Windows ClickFix campaigns fetch from inside PowerShell, which no shim can see.
- **Offline operation.** `HOOD_LOCAL=1` disables the cloud tier; `SCAN_NO_UPDATE=1` also stops the daily rule download. Artifact contents, URLs, names, and credentials never leave the machine in either mode.
- **Minimal disclosure online.** Beamline, the cloud tier, receives a public package URL or a SHA-256 and nothing else: no file contents, download URLs, cookies, or registry tokens. Private and authenticated fetches are looked up by hash only. A package URL still reveals a dependency, and the source address can link requests.
- **No root, no host changes.** Hood installs shims under `~/.hood/bin` and one marked block in your shell rc or PowerShell profile, and that is all. Each intercepted command gets a fresh CA trusted only by that child process. The host trust store and system proxy settings are never touched.
- **Fails closed.** Suspicious and hostile verdicts block. `HOOD_BYPASS` relaxes that in strict steps (`1` forward on scanner error, `2` also forward suspicious, `3` forward everything); any other value is treated as strict and logged.

## Supported commands

Hood shims those of these on `PATH`. Commands that fetch are intercepted; local operations such as `go test`, `cargo build`, and `npm test` pass through. Hood runs on macOS, Linux, the BSDs, and Windows.

| Ecosystem | Commands |
| --- | --- |
| Fetch tools | `curl`, `wget` |
| JavaScript | `npm`, `npx`, `pnpm`, `pnpx`, `yarn`, `bun`, `bunx`, `rush`, `rushx` |
| Python | `pip`, `pip3`, `pipx`, `uv`, `uvx`, `poetry`, `pdm` |
| Compiled languages | `go`, `cargo`, `zig` |
| macOS and Linux | `brew` |
| Arch Linux | `pacman`, `yay`, `paru`, `makepkg` |
| RPM distributions | `dnf`, `yum`, `zypper`, `rpm` |
| Alpine and BSD | `apk`, `pkg` |

Anything else runs under `hood exec -- <command>`, which sets the proxy and CA environment for that process. npm and pnpm installs run with `--ignore-scripts`; `--enable-scripts` restores them.

## How a download is decided

1. **Local Bloom filters** from Atomdrift Scan. Both identities, package URL and content hash, must be known good to skip inspection; a trusted name cannot vouch for unknown bytes. Known-bad blocks at once. Bloom matches are probabilistic, which is why both must agree.
2. **Beamline assessment**, unless `HOOD_LOCAL=1`. Public packages are assessed by package URL, everything else by SHA-256. Verified results are cached for 30 days.
3. **Local analysis** for anything still unresolved, including API outages, rate limits, and oversized responses. The analyzer loads only when needed.

`hood login` enables the isotope13 Enriched rules. A lapsed token is a warning, never a failed install.

## Install — Rust 1.96+

```sh
git clone https://github.com/atomdrift-project/hood.git && cd hood
make install && hood install
```

Restart your shell and use your tools as before. `hood -v <tool> …` or `HOOD_VERBOSE=1` prints a verdict per artifact and a summary. `hood uninstall` removes the shims and the rc block. On Windows the shims live under `%USERPROFILE%\.hood\bin` and the PATH block goes in both PowerShell profiles; cmd.exe is not configured, and `hood install` should be run again after upgrading hood.

For GitHub Actions, pin Hood to a reviewed commit, install it the same way, add `$HOME/.hood/bin` to `GITHUB_PATH`, and leave the existing `npm ci` or `pip install` steps alone.

| Setting | Purpose |
| --- | --- |
| `HOOD_LOCAL=1` | Skip the cloud tier; local filters and local analysis only. |
| `SCAN_NO_UPDATE=1` | Skip the daily Bloom and rule refresh. |
| `HOOD_BYPASS=0..3` | Failure policy; unset is strict. |
| `HOOD_MAX_SCAN_MB` | Larger downloads follow the `HOOD_BYPASS` policy. |
| `HOOD_BEAMLINE_URL` | Alternate API origin; HTTPS required except on loopback. |
| `ISOTOPE13_TOKEN` | Enriched token; overrides the one saved by `hood login`. |
