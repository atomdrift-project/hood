# hood

**Highly experimental** local supply-chain protection: a safety layer between your
package managers and the internet. Expect rough edges — try it in a VM first.

## The fume-hood metaphor

A chemist doesn't stop handling volatile reagents — they work under a **fume hood**
that pulls the dangerous vapors away before they reach their lungs. `hood` is that
for your terminal: you still run `npm install`, `pip install`, `curl | sh`, but hood
inspects what comes through before it reaches you.

## How it works

When you install something, hood:

1. spins up a short-lived HTTPS-intercepting proxy trusted only by that child process
   via an **ephemeral, throwaway CA** — nothing touches your system trust store;
2. checks each payload against atomscan's **bloom filters** first: a known-good hash
   skips the scan entirely (near-invisible), a known-bad hash or package coordinate is
   blocked on the spot with a link to its report at `lab.atomdrift.org`;
3. otherwise **scans the bytes** with an in-process ML classifier
   ([Atomdrift Scan](https://github.com/atomdrift-project/scan) + cleave) *before* they reach the tool;
4. **blocks** anything hostile with a panel explaining why — or forwards clean bytes.

Bloom filters are optional (populated by `atomscan update-rules`); without them, every
payload simply takes the full scan.

## What it protects

One wrapper per command; `hood install` only wires up the ones your platform has.
Non-fetching subcommands (`npm test`, `cargo build`, `pacman -Q`) pass through untouched.

- `curl` / `wget` — every fetch, including `curl … | sh` bootstrap scripts.
- `npm` / `pnpm` / `yarn` / `bun` — Node installs; lifecycle scripts off by default.
- `pip` / `pipx` — Python package installs.
- `uv` / `poetry` — modern Python installs, adds, and syncs.
- `go` — module fetches (`get`, `install`, `mod download`).
- `cargo` — Rust crate `install` / `add` / `update` / `fetch`.
- `brew` — Homebrew `install` / `upgrade` / `fetch` / `tap` / `bundle` (macOS & Linux).
- `pacman` — Arch sync / upgrade (`-S`, `-U`).
- `yay` / `paru` — Arch AUR helper installs & upgrades.
- `makepkg` — Arch/AUR builds from fetched sources.
- `dnf` / `yum` — Fedora/RHEL `install` / `upgrade` / `download`.
- `zypper` — openSUSE `install` / `dup` / `patch` / `refresh`.
- `rpm` — installs pulled from an `http(s)` / `ftp` URL.
- `apk` — Alpine `add` / `upgrade` / `fetch`.
- `pkg` — FreeBSD `install` / `add` / `upgrade` / `fetch`.

## Install

```sh
make install     # build the `hood` binary onto your PATH
hood install     # shim your tools + shell rc, then restart the shell
```

Run ad hoc without shimming anything: `hood npm install left-pad`, `hood exec -- ./setup.sh`.

## Override or remove

- **Let a payload through:** `HOOD_BYPASS=1` forwards on scan error, `=2` also on
  *suspicious*, `=3` on *everything*. `--enable-scripts` re-enables npm lifecycle scripts.
- **Skip hood for one run:** invoke the real binary by full path (e.g. `/usr/bin/npm`).
- **Remove one wrapper:** `rm ~/.hood/bin/<tool>`. **Remove all + shell rc:** `hood uninstall`.

## How it compares

- **Datadog GuardDog** — a rule-based (Semgrep) scanner limited to PyPI, npm, Go, and
  GitHub Actions packages, which you point at a manifest or package, mostly in CI. It
  never sees `curl | sh` or system package managers. hood needs nothing pointed at it
  and inspects the actual bytes at install time.
- **Aikido Safe-Chain** — shims only the npm family (`npm`/`npx`/`yarn`/`pnpm`) and
  matches names against a cloud feed of *known* malware: Node-only, blocklist-based.
  hood classifies intercepted payload bytes locally, including previously unknown
  files, across every ecosystem above. Package installation still needs the network,
  and Scan may refresh bundles or follow references unless configured otherwise.
