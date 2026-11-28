# hood

[![Status: experimental](https://img.shields.io/badge/status-experimental-E5A50A)](#why-hood) [![CI](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml/badge.svg)](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/atomdrift-project/hood/badge)](https://scorecard.dev/viewer/?uri=github.com/atomdrift-project/hood) [![License: Apache-2.0](https://img.shields.io/github/license/atomdrift-project/hood)](LICENSE)

> [!WARNING]
> This is experimental. It may eat your cat.

<p align="center"><img src="media/hood.jpg" alt="Handle chemicals under a fume hood" width="392"></p>

Hood stops supply-chain malware before it runs. It is a local proxy that scans every package, archive, and script your package managers and fetch tools download, and blocks hostile ones before the tool receives them, whether the command came from a developer, a CI job, or a misbehaving AI agent. It wraps the commands you already run on Linux, macOS, Windows, and FreeBSD; registries, lockfiles, and CI stay as they are. Other supply-chain tools check names against a list; Hood scans bytes, so private, vendored, and `curl`-fetched artifacts get the same scrutiny as the top of npm and PyPI.

## Why hood

- **Gap-free scanning.** No download is released without a decision. When neither the local filters nor cloud analysis can vouch for an artifact, Hood scans the bytes inline with static analysis and ML.
- **ClickFix protection.** A script fetched with `curl -fsSL https://example.com/install.sh | sh` is scanned before the shell receives it. Windows ClickFix campaigns fetch from inside PowerShell, which no shim can see.
- **Local operation.** `hood --local` (or `HOOD_LOCAL=1`) keeps analysis on this machine by never asking for cloud analysis, and `HOOD_NO_UPDATE=1` skips the daily filter and rule downloads; local filters and analysis keep working.
- **Zero telemetry.** Hood sends no usage data, crash reports, or identifiers. Beamline, which runs cloud analysis, receives a public package URL or a SHA-256 and nothing else: no file contents, download URLs, cookies, or registry tokens. A download requested with credentials is not mentioned to it at all, nor is a body under 20 bytes, short enough to guess from its hash.
- **No root, no host changes.** Hood installs shims under `~/.hood/bin` and one marked block in your shell rc or PowerShell profile. Each intercepted command gets a fresh CA trusted only by that child process; the host trust store and system proxy settings are never touched.
- **Fails closed.** Suspicious and hostile verdicts block. `HOOD_BYPASS` relaxes that in steps (`1` forward on scanner error, `2` also forward suspicious, `3` forward everything); any other value is treated as strict and logged.

## Install (Rust 1.97+)

```sh
git clone https://github.com/atomdrift-project/hood.git && cd hood
make install && hood install
```

Restart your shell and use your tools as before. `HOOD_VERBOSE=1` prints a verdict per artifact and a summary; `hood uninstall` removes the shims and the rc block. On Windows, build with `cargo build --release` instead of `make`, then run `.\target\release\hood.exe install`; it wires both PowerShell profiles, cmd.exe is not configured, and `hood install` must be rerun after upgrading. For GitHub Actions, pin Hood to a reviewed commit, install it the same way, add `$HOME/.hood/bin` to `GITHUB_PATH`, and leave the existing `npm ci` or `pip install` steps alone.

## Supported commands

Commands that fetch are intercepted; local operations such as `go test`, `cargo build`, and `npm test` pass through. Anything else runs under `hood exec -- <command>`, which sets the proxy and CA environment for that process. npm, pnpm, yarn, and bun installs run with `--ignore-scripts` unless you already chose: any `--ignore-scripts` flag on the command (such as `npm install --ignore-scripts=false`), or `npm_config_ignore_scripts` or `YARN_ENABLE_SCRIPTS` in your environment, is left to the tool.

| Ecosystem | Commands |
| --- | --- |
| Fetch tools | `curl`, `wget` |
| JavaScript | `npm`, `npx`, `pnpm`, `pnpx`, `yarn`, `bun`, `bunx`, `rush`, `rushx` |
| Python | `pip`, `pip3`, `pipx`, `uv`, `uvx`, `poetry`, `pdm` |
| Compiled languages | `go`, `cargo`, `zig` |
| System packages | `brew`, `pacman`, `yay`, `paru`, `makepkg`, `dnf`, `yum`, `zypper`, `rpm`, `apk`, `pkg` |

## How a download is decided

1. **Local Bloom filters** from Atomdrift Scan. Package URL and content hash must both be known good to skip inspection. Known-bad blocks at once.
2. **Beamline assessment.** Public packages are assessed by package URL, starting when the download does; everything else by SHA-256. A download requested with an `Authorization` header, a cookie, or a password in its URL is decided on this machine alone. One threat feed's citation of a hash, with nothing found in the bytes, is a reason to analyze them locally rather than a verdict. Verified results are cached for 30 days, and a spent quota is left alone until it resets.
3. **Local analysis** for anything still unresolved, including API outages and rate limits, and for every body under 20 bytes: unrelated servers send the same `Not Found` or `{"success":true}`, so what is known of such a hash is known of some other download. A body under 4 bytes, such as `OK`, is shorter than any command that does harm and is forwarded as is. It starts beside a Beamline lookup that has not answered within a quarter of a second, and a pass is remembered for the same bytes at the same URL until the rules or models change. Package-manager downloads are always inspected in full. Downloads larger than 1 GB through `curl`, `wget`, or `hood exec` — ISOs, disk images, model weights — are forwarded unscanned, with a warning. A response compressed despite hood asking for `identity` follows the `HOOD_BYPASS` policy, because hood cannot inspect what the tool will decode. What Homebrew fetches with git (`brew update`, `brew tap`) passes uninspected, with a notice: brew leaves no way to make its git trust hood.

`hood login` signs this computer in to Atomdrift (its rule feeds, plus Beamline lookups as a subscriber), for cleave and atomscan too; `HOOD_TOKEN` overrides the saved sign-in, and a lapsed one is a warning, never a failed install. Checks use the best feed your plan opens — `zero-day`, `supporter` (72 hours behind), or `oss` (up to 8 days) — unless `hood --feed <name> <tool>` or `HOOD_FEED` (how shims get one) names a feed. `hood version` says which feed a check uses, why, and its revision.

## Environment

| Variable | Effect |
| --- | --- |
| `HOOD_BYPASS` | `1`, `2`, or `3` relaxes blocking as described above; any other value is strict. |
| `HOOD_VERBOSE` | `1` prints a verdict per artifact and a summary. |
| `HOOD_LOCAL` | `--local`: `1` never asks Beamline for cloud analysis. |
| `HOOD_TOKEN` | An Atomdrift sign-in token, in place of `hood login` (for CI). |
| `HOOD_FEED` | `--feed`: the rule feed (`auto`, the default, or `zero-day`, `supporter`, `oss`). |
| `HOOD_NO_UPDATE` | `1` skips the daily Bloom filter and rule downloads. |
| `HOOD_BEAMLINE_URL` | An alternate Beamline origin. HTTPS is required except on loopback, whose answers are never cached. |
