//! `hood` runs a child command behind a short-lived HTTPS-intercepting proxy
//! so every download is scanned before it reaches the tool.
//!
//! - [`proxy`] — HTTP/1.1 forward proxy with transparent CONNECT interception.
//! - `ca` — ephemeral certificate authority the proxy intercepts TLS with.
//! - [`scanner`] — the [`scanner::Scanner`] trait, and the Bloom, Beamline,
//!   and local-analysis tiers that decide each download.
//! - [`go_bridge`] — loopback transport for Go modules and sumdb on macOS and
//!   Windows, where Go trusts only the system store.
//! - [`tools`] — per-tool interception rules and child environments.
//! - [`install`] — the shims and the shell-profile block that route tools
//!   through hood.
//! - [`output`] — the stderr panels that explain each decision.

pub(crate) mod beamline;
pub(crate) mod beamline_cache;
pub(crate) mod ca;
pub mod go_bridge;
pub mod install;
pub mod output;
pub mod proxy;
pub mod scanner;
pub mod tools;
