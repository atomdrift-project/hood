# hood

[![Status: experimental](https://img.shields.io/badge/status-experimental-E5A50A)](#what-it-does) [![CI](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml/badge.svg)](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/atomdrift-project/hood/badge)](https://scorecard.dev/viewer/?uri=github.com/atomdrift-project/hood) [![License: Apache-2.0](https://img.shields.io/github/license/atomdrift-project/hood)](LICENSE)

> [!WARNING]
> This is experimental. It may eat your cat.

<p align="center"><img src="media/hood.jpg" alt="Handle chemicals under a fume hood" width="560"></p>

## What it does

`hood` holds every download a developer tool or AI agent makes, decides whether the bytes are safe, and only then releases them to the tool. It wraps the tools you already use, so nothing about your workflow, your registries, or your CI changes.

Most supply-chain tools answer one question: *is this package name on a list?* Hood answers a harder one: *are these exact bytes safe?* That difference is what makes it fit for a campus or a carrier, where the packages that matter most are private, vendored, or fetched with `curl` and never appear on anyone's list.

## Why hood

- **Gap-free scanning.** A reputation lookup that comes back empty is not an answer. When hood does not already know an artifact is good or bad, it scans the bytes inline with local static analysis and ML before the tool sees them. Private packages, GitHub archives, freshly published versions, and one-off URLs are all covered, not just the top of npm and PyPI.
- **ClickFix protection for fetch tools.** `curl` and `wget` are wrapped too. The script behind `curl -fsSL https://example.com/install.sh | sh` is held and scanned before a single byte reaches the shell, so paste-this-command attacks hit the same wall as a poisoned package.
- **Fully offline mode.** `HOOD_LOCAL=1` uses only the local known-good/known-bad Bloom filters and the local analyzer. No artifact contents, URLs, credentials, or package names leave the machine. Air-gapped labs and regulated networks get the same protection as everyone else.
- **Minimal disclosure when online.** The optional cloud tier (Beamline) receives only a public package URL or a SHA-256, never file contents, download URLs, cookies, or registry tokens. Private and authenticated fetches are always looked up by hash.
- **No system changes.** Hood mints a fresh CA per intercepted command and trusts it only inside that child process. It never touches the host trust store, installs a system proxy, or needs root.
- **Fails the way you choose.** Suspicious and hostile verdicts block by default. `HOOD_BYPASS` is a strict ladder (`1` forward on scanner error, `2` also forward suspicious, `3` forward everything) so a typo can never silently downgrade protection.

## Supported commands

Hood installs user-level shims for whichever of these are on `PATH`. Local-only operations such as `go test`, `cargo build`, and `npm test` pass straight through; commands that fetch are intercepted.

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

Anything else runs under `hood exec -- <command>`, which injects the proxy and CA environment into an arbitrary process. npm and pnpm installs get `--ignore-scripts` by default; pass `--enable-scripts` to opt back in.

## How a download is decided

1. **Local Bloom filters** from Atomdrift Scan. Every identity hood has (package URL and content hash) must be blessed to skip inspection; a trusted name alone cannot bless unknown bytes. Known-bad blocks immediately.
2. **Beamline assessment** (skipped under `HOOD_LOCAL=1`). Public packages are analyzed by package URL; everything else is looked up by SHA-256. Verified results are cached locally for 30 days.
3. **Local analysis** for anything still unresolved, including API outages, rate limits, and oversized responses. The analyzer loads only when needed.

`hood login` adds isotope13 Enriched rules, refreshed the hour they clear QA. A lapsed token is a warning, never a failed install.

## Install — Rust 1.96+

```sh
git clone https://github.com/atomdrift-project/hood.git && cd hood
make install && hood install
```

Restart your shell and use your tools normally. `hood -v <tool> …` or `HOOD_VERBOSE=1` prints a per-artifact verdict and a run summary. `hood uninstall` removes the shims and shell configuration.

For GitHub Actions, pin hood to a reviewed commit, run `make install && hood install`, add `$HOME/.hood/bin` to `GITHUB_PATH`, and leave your existing `npm ci` or `pip install` steps untouched.

| Setting | Purpose |
| --- | --- |
| `HOOD_LOCAL=1` | Offline: local Bloom filters and local analysis only. |
| `HOOD_BYPASS=0..3` | Failure policy ladder; unset is strict. |
| `HOOD_MAX_SCAN_MB` | Downloads above this size follow the `HOOD_BYPASS` policy. |
| `HOOD_BEAMLINE_URL` | Alternate API origin; HTTPS required except on loopback. |
| `ISOTOPE13_TOKEN` | Enriched token; overrides the one saved by `hood login`. |
