# Changelog

All notable changes to hood. Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0-beta.1 (unreleased)

### Security

- Treat responses encoded despite an identity request as uninspectable, so compressed payloads cannot pass as scanned.
- Refuse HTTPS-to-HTTP redirects through the Go loopback bridge, where Go cannot see the downgrade itself.
- Pin rules to the installed tree, so a checkout's own traits directory cannot supply detection rules.
- Strip credentials, queries and fragments from URLs in panels and logs, keeping presigned tokens out of CI.
- Replace Unicode bidi overrides in panels, blocking Trojan Source-style display spoofing.

### Features

- Rename isotope13 Enriched to Atomdrift Uplink; `hood enrich` still works as an alias.
- Disable Uplink rules with ATOMDRIFT_UPLINK=0 while keeping the saved token.
- Leave lifecycle scripts alone when the user already chose, by flag or npm and yarn environment variables.
- Breaking: forward downloads over 2 GB, such as ISOs, unscanned with a warning instead of blocking them.
- Breaking: drop hood's own -v, --model-dir and `--enable-scripts` flags; use HOOD_VERBOSE=1 for verbose output.
- Breaking: rename SCAN_NO_UPDATE to `HOOD_NO_UPDATE`, which now skips Bloom filter downloads too.
- Breaking: remove the HOOD_MAX_SCAN_MB, HOOD_MAX_BODY_MB, HOOD_HOME, HOOD_NO_SCAN, HOOD_NO_BLOOM and Beamline cache TTL settings.

### Fixes

- Insert `--ignore-scripts` before a double dash, so it reaches the package manager instead of the script.
- Fetch models, rules and Bloom filters before the command starts, so pacman and others don't abandon silent transfers.
- Reach origins addressed by IPv6 literals, including HTTPS tunnels whose clients send no SNI.
- Give `hood exec -- curl` the CA flag on Windows, as the curl shim already gets.

## 0.2.0 (2026-10-23)

### Security

- A known-good package name no longer skips scanning; name and content hash must both be known good.
- Downloads larger than `HOOD_MAX_SCAN_MB` are now blocked by default instead of forwarded unscanned.
- A hash with outside malware reports now forces a local scan, even under a known-good package name.
- Authenticated, cookie-bearing, and non-GET downloads are looked up by hash only, never disclosing the package URL.
- The isotope13 token is sent only to `api.isotope13.ai`, never to a custom `HOOD_BEAMLINE_URL`.
- Beamline requests require HTTPS outside loopback and refuse redirects, so identifiers and tokens cannot leak elsewhere.
- Server messages are stripped of control characters, so a hostile endpoint cannot inject terminal escapes.

### Features

- Beamline cloud assessment checks public packages by package URL and everything else by SHA-256.
- Beamline verdicts are cached on disk for 30 days; `HOOD_BEAMLINE_CACHE_TTL_SECS` adjusts or disables the cache.
- `HOOD_LOCAL=1` disables Beamline for fully offline operation.
- `hood login` enables isotope13 Enriched rules; a lapsed token falls back to the open-source rules.
- Bloom filters and rules refresh once a day; `SCAN_NO_UPDATE=1` turns refresh off.
- Known-bad blocks now show Beamline's reason and top findings when Beamline confirms the verdict.
- Windows support adds PowerShell 5.1 and 7 profiles, `PATHEXT` lookup, and Schannel-compatible curl and cargo.
- Go module downloads on Windows use the loopback bridge, because Go ignores `SSL_CERT_FILE` there.
- Zig support scans dependencies fetched by `zig build` and `zig fetch`.
- `zypper download` and `zypper source-download` are now intercepted.

### Fixes

- Flags after the tool name now reach the tool, so `npm -v` and `curl --help` work through shims.
- Plain `http://` requests tunneled through CONNECT, as pnpm and Zig send them, are now forwarded and scanned.
- Rerunning `hood install` on Windows now relinks hard-linked or copied shims after a hood upgrade.
- ARMv6 musl and illumos builds now link correctly.

### Optimizations

- The ML model loads only when local analysis is needed, so Bloom and Beamline verdicts skip it.
- Bloom filters load on the first download rather than at startup.
- TLS trust roots load in the background while the child starts, saving about 130 ms on macOS.
- Async worker threads are capped at four, saving about 35 ms of startup on many-core hosts.
- Hood exits without running C exit handlers, skipping a macOS analytics hook that could stall for 300 ms.
- The Go bridge skips running `go env` when `GOPROXY` and `GOSUMDB` are set, saving about 50 ms.

## 0.1.1 (2026-08-14)

- Fix rcget update breakage.

## 0.1.0 (2026-08-14)

Publish our supply-chain firewall experiment - look out for spectacular failures.
