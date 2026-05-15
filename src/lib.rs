//! `hood` runs a child command behind a short-lived HTTPS-intercepting proxy
//! so every download is scanned before it reaches the tool.
//!
//! The library is structured around three pieces:
//!
//! - [`ca`] — ephemeral certificate authority used to MITM TLS.
//! - [`proxy`] — HTTP/1.1 forward proxy with transparent CONNECT interception.
//! - [`scanner`] — pluggable scanner trait + in-process litmus backend.
//!
//! Higher-level glue (env-var injection for child processes, per-tool subcommands)
//! lives in [`tools`].

pub mod ca;
pub mod proxy;
pub mod scanner;
pub mod tools;
