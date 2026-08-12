# hood

[![Status: experimental](https://img.shields.io/badge/status-experimental-E5A50A)](#what) [![CI](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml/badge.svg)](https://github.com/atomdrift-project/hood/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/atomdrift-project/hood/badge)](https://scorecard.dev/viewer/?uri=github.com/atomdrift-project/hood) [![License: Apache-2.0](https://img.shields.io/github/license/atomdrift-project/hood)](LICENSE)

> [!WARNING] Evaluation software, not an enterprise endpoint control. Test in a VM before piloting it with developers.

<p align="center"><img src="media/hood.jpg" alt="Handle chemicals under a fume hood" width="560"></p>

## What
`hood` protects the tools developers and AI agents commonly use to fetch software—from `curl` and `npm` to language and system package managers. It is optimized for zero-day detection: unfamiliar public and private packages are analyzed locally before installation, without changing familiar commands or workflows.

## How it works
```mermaid
flowchart LR; A["Developer or agent<br/>original tool"] --> B["Loopback proxy<br/>ephemeral child-only CA"] --> C["Public/private registry<br/>or any URL"] -->|bytes| B; B --> D{"Known-good/bad<br/>hash or PURL?"}; D -->|good| E["Release to tool"]; D -->|bad| G["Block and explain"]; D -->|unknown| F["Local ML + static analysis"]; F -->|benign| E; F -->|suspicious/hostile| G
```
The host trust store is unchanged. Unknown bytes are analyzed locally by [Atomdrift Scan](https://github.com/atomdrift-project/scan); optional bloom filters fast-path known artifacts.

## Tool coverage
✅ = automatic wrapper; ◐ = experimental explicit command; — = unsupported. Matrix verified against each project's source (August 2026). `hood` also supports `hood exec -- <command>`; only `hood` locally classifies private artifact contents. Competitors may route private packages but decide from feeds or metadata.

| Tool | hood | [PMG](https://github.com/safedep/pmg) | [SCFW](https://github.com/DataDog/supply-chain-firewall) | [Safe Chain](https://github.com/AikidoSec/safe-chain) |
| --- | :---: | :---: | :---: | :---: |
| `curl` | ✅ | — | — | — |
| `wget` | ✅ | — | — | — |
| `npm` | ✅ | ✅ | ✅ | ✅ |
| `npx` | — | ✅ | — | ✅ |
| `pnpm` | ✅ | ✅ | — | ✅ |
| `pnpx` | — | ✅ | — | ✅ |
| `yarn` | ✅ | ✅ | — | ✅ |
| `rush` | — | — | — | ✅ |
| `rushx` | — | — | — | ✅ |
| `bun` | ✅ | ✅ | — | ✅ |
| `bunx` | — | — | — | ✅ |
| `pip` | ✅ | ✅ | ✅ | ✅ |
| `pip3` | — | ✅ | — | ✅ |
| `pipx` | ✅ | ✅ | — | ✅ |
| `uv` | ✅ | ✅ | — | ✅ |
| `uvx` | — | ✅ | — | ✅ |
| `poetry` | ✅ | ✅ | ✅ | ✅ |
| `pdm` | — | — | — | ✅ |
| `go` | ✅ | ◐ | — | — |
| `cargo` | ✅ | — | — | — |
| `brew` | ✅ | — | — | — |
| `pacman` | ✅ | — | — | — |
| `yay` | ✅ | — | — | — |
| `paru` | ✅ | — | — | — |
| `makepkg` | ✅ | — | — | — |
| `dnf` | ✅ | — | — | — |
| `yum` | ✅ | — | — | — |
| `zypper` | ✅ | — | — | — |
| `rpm` | ✅ | — | — | — |
| `apk` | ✅ | — | — | — |
| `pkg` | ✅ | — | — | — |

## Try it — Rust 1.94+
```sh
git clone https://github.com/atomdrift-project/hood.git
cd hood
make install
hood install
```
Restart your shell, then use supported commands normally.

## Uninstall
Run `hood uninstall` to remove Hood's shims and shell configuration.
