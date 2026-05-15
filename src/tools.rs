//! Tool-specific argv + env-var orchestration.
//!
//! Each [`Tool`] knows two things:
//!
//! 1. Which env vars to set in the child so it routes traffic through hood
//!    *and* trusts hood's ephemeral CA.
//! 2. Any argv tweaks needed for safe defaults (npm install gets
//!    `--ignore-scripts`).
//!
//! Spawning the child is delegated to [`run_child`], which writes the CA PEM
//! to a tempfile under the OS temp dir, runs the command, and cleans up on
//! exit (success or panic).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use tempfile::TempDir;
use tokio::process::Command;

/// Subcommands hood knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `curl <args...>` — libcurl, respects `CURL_CA_BUNDLE` / `SSL_CERT_FILE`.
    Curl,
    /// `wget <args...>` — gnutls/openssl, respects `SSL_CERT_FILE`.
    Wget,
    /// `npm <args...>` — Node, respects `NODE_EXTRA_CA_CERTS`. Also pnpm.
    Npm,
    /// `pnpm <args...>` — same trust model as npm; separate to allow distinct
    /// binary name resolution and future divergence.
    Pnpm,
    /// `pip <args...>` — pip uses bundled certifi by default; needs `PIP_CERT`.
    Pip,
    /// `go <args...>` — Go's `crypto/x509`; needs `SSL_CERT_FILE` plus the
    /// `GODEBUG=x509usefallbackroots=1` hatch on macOS.
    Go,
    /// `exec -- <cmd...>` — open-ended: sets every known env var.
    Exec,
}

impl Tool {
    /// Binary to invoke on the host, before any user-supplied first arg.
    #[must_use]
    pub const fn default_binary(self) -> Option<&'static str> {
        match self {
            Self::Curl => Some("curl"),
            Self::Wget => Some("wget"),
            Self::Npm => Some("npm"),
            Self::Pnpm => Some("pnpm"),
            Self::Pip => Some("pip"),
            Self::Go => Some("go"),
            // exec uses argv[0] supplied by the user.
            Self::Exec => None,
        }
    }
}

/// Per-tool runtime context: where the proxy listens, where the CA file lives.
#[derive(Debug)]
pub struct ChildEnv {
    /// Proxy listen address as `http://host:port`.
    pub proxy_url: String,
    /// Path the child process can pass to its TLS verifier.
    pub ca_pem_path: PathBuf,
}

impl ChildEnv {
    /// Build the env-var overlay for a given tool.
    #[must_use]
    pub fn vars_for(&self, tool: Tool) -> BTreeMap<&'static str, OsString> {
        let mut out = BTreeMap::new();
        let proxy = OsString::from(&self.proxy_url);
        let ca = OsString::from(&self.ca_pem_path);

        // Universal proxy env vars (lowercase per de-facto convention plus
        // uppercase for clients that only look at the latter).
        let proxy_keys: &[&str] = match tool {
            Tool::Exec => &[
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
            ],
            _ => &["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"],
        };
        for k in proxy_keys {
            out.insert(*k, proxy.clone());
        }

        match tool {
            Tool::Curl => {
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            Tool::Wget => {
                out.insert("SSL_CERT_FILE", ca);
            }
            Tool::Npm | Tool::Pnpm => {
                // npm reads its own *_config_* family too. Setting both
                // covers older npm and pnpm versions.
                out.insert("NODE_EXTRA_CA_CERTS", ca.clone());
                out.insert("npm_config_proxy", proxy.clone());
                out.insert("npm_config_https_proxy", proxy.clone());
                // `npm_config_cafile` is the documented alternative — keep
                // it for pnpm, which historically honored it.
                out.insert("npm_config_cafile", ca);
            }
            Tool::Pip => {
                // pip ignores SSL_CERT_FILE (uses bundled certifi); PIP_CERT
                // is the supported override.
                out.insert("PIP_CERT", ca);
            }
            Tool::Go => {
                out.insert("SSL_CERT_FILE", ca);
                // macOS Go uses the system keychain unless this is set.
                // Setting it unconditionally is harmless on other platforms.
                out.insert("GODEBUG", OsString::from("x509usefallbackroots=1"));
            }
            Tool::Exec => {
                // Set every flavor of CA env var we know about so whatever
                // the user runs has a reasonable shot at trusting us.
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("NODE_EXTRA_CA_CERTS", ca.clone());
                out.insert("PIP_CERT", ca.clone());
                out.insert("REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("npm_config_cafile", ca.clone());
                out.insert("npm_config_proxy", proxy.clone());
                out.insert("npm_config_https_proxy", proxy);
                out.insert("GODEBUG", OsString::from("x509usefallbackroots=1"));
                out.insert("CARGO_HTTP_CAINFO", ca);
            }
        }
        out
    }
}

/// Build a `ChildEnv` from a proxy address + CA pem written to a tempdir.
///
/// The returned [`TempDir`] must outlive the child process — drop it after the
/// child exits to remove the PEM file.
pub fn prepare_child_env(
    proxy_addr: SocketAddr,
    ca_pem: &str,
) -> Result<(ChildEnv, TempDir)> {
    let dir = tempfile::Builder::new()
        .prefix("hood-ca-")
        .tempdir()
        .context("create CA tempdir")?;
    let pem_path = dir.path().join("hood-ca.pem");
    let mut f = std::fs::File::create(&pem_path).context("create CA pem")?;
    f.write_all(ca_pem.as_bytes()).context("write CA pem")?;
    f.flush().context("flush CA pem")?;
    // Tighten permissions: world-readable for the child (which may run under
    // a sandbox/user), but no write access.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = f.metadata().context("stat CA pem")?.permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&pem_path, perms).context("chmod CA pem")?;
    }
    drop(f);

    let proxy_url = format!("http://{proxy_addr}");
    Ok((
        ChildEnv {
            proxy_url,
            ca_pem_path: pem_path,
        },
        dir,
    ))
}

/// Apply hood's argv-tweaking conventions for the chosen tool.
///
/// Today this only affects `npm`/`pnpm install*`, where we inject
/// `--ignore-scripts` (matching pnpm's default safety posture) unless the user
/// already specified it or explicitly opted out via `enable_scripts`.
#[must_use]
pub fn rewrite_args(tool: Tool, args: Vec<OsString>, enable_scripts: bool) -> Vec<OsString> {
    match tool {
        Tool::Npm | Tool::Pnpm => maybe_add_ignore_scripts(args, enable_scripts),
        _ => args,
    }
}

fn maybe_add_ignore_scripts(args: Vec<OsString>, enable_scripts: bool) -> Vec<OsString> {
    if enable_scripts {
        return args;
    }
    let is_install = args
        .iter()
        .find(|a| !a.to_string_lossy().starts_with('-'))
        .is_some_and(|a| {
            matches!(
                a.to_string_lossy().as_ref(),
                "install" | "i" | "add" | "ci" | "update" | "rebuild"
            )
        });
    if !is_install {
        return args;
    }
    let already = args.iter().any(|a| {
        let s = a.to_string_lossy();
        s == "--ignore-scripts" || s == "--ignore-scripts=true"
    });
    if already {
        return args;
    }
    let mut out = args;
    out.push(OsString::from("--ignore-scripts"));
    out
}

/// Spawn the child with the chosen tool's env overlay, wait for it, return the
/// exit code (or `1` if it was terminated by a signal).
///
/// `bin_override` lets `Tool::Exec` supply argv[0] (since there's no fixed
/// binary). For named tools, pass `None`.
pub async fn run_child(
    tool: Tool,
    bin_override: Option<&Path>,
    args: Vec<OsString>,
    env: &ChildEnv,
) -> Result<i32> {
    let bin: PathBuf = match (bin_override, tool.default_binary()) {
        (Some(p), _) => p.to_path_buf(),
        (None, Some(name)) => PathBuf::from(name),
        (None, None) => {
            return Err(anyhow::anyhow!(
                "hood exec requires a command to run (use `hood exec -- <cmd> [args]`)",
            ));
        }
    };

    let mut cmd = Command::new(&bin);
    cmd.args(&args);
    for (k, v) in env.vars_for(tool) {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?
        .wait()
        .await
        .with_context(|| format!("wait {}", bin.display()))?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fake_env() -> ChildEnv {
        ChildEnv {
            proxy_url: "http://127.0.0.1:12345".into(),
            ca_pem_path: PathBuf::from("/tmp/hood.pem"),
        }
    }

    #[test]
    fn curl_env_includes_curl_ca_bundle() {
        let env = fake_env();
        let v = env.vars_for(Tool::Curl);
        assert!(v.contains_key("CURL_CA_BUNDLE"));
        assert!(v.contains_key("SSL_CERT_FILE"));
        assert!(v.contains_key("http_proxy"));
    }

    #[test]
    fn npm_env_includes_node_extra_ca() {
        let env = fake_env();
        let v = env.vars_for(Tool::Npm);
        assert!(v.contains_key("NODE_EXTRA_CA_CERTS"));
        assert!(v.contains_key("npm_config_https_proxy"));
    }

    #[test]
    fn pip_env_uses_pip_cert_not_ssl_cert_file() {
        let env = fake_env();
        let v = env.vars_for(Tool::Pip);
        assert!(v.contains_key("PIP_CERT"));
        // pip ignores SSL_CERT_FILE so we don't bother setting it.
        assert!(!v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn go_env_sets_macos_fallback_roots_godebug() {
        let env = fake_env();
        let v = env.vars_for(Tool::Go);
        let godebug = v.get("GODEBUG").unwrap().to_string_lossy();
        assert!(godebug.contains("x509usefallbackroots=1"));
        assert!(v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn exec_env_is_superset() {
        let env = fake_env();
        let v = env.vars_for(Tool::Exec);
        for key in [
            "CURL_CA_BUNDLE",
            "SSL_CERT_FILE",
            "NODE_EXTRA_CA_CERTS",
            "PIP_CERT",
            "REQUESTS_CA_BUNDLE",
            "GODEBUG",
            "CARGO_HTTP_CAINFO",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        ] {
            assert!(v.contains_key(key), "missing {key} in exec env");
        }
    }

    #[test]
    fn npm_install_injects_ignore_scripts() {
        let args = vec![OsString::from("install"), OsString::from("lodash")];
        let out = rewrite_args(Tool::Npm, args, false);
        assert!(out.iter().any(|a| a == "--ignore-scripts"));
    }

    #[test]
    fn npm_install_respects_enable_scripts() {
        let args = vec![OsString::from("install"), OsString::from("lodash")];
        let out = rewrite_args(Tool::Npm, args, true);
        assert!(!out.iter().any(|a| a == "--ignore-scripts"));
    }

    #[test]
    fn npm_non_install_left_alone() {
        let args = vec![OsString::from("run"), OsString::from("test")];
        let out = rewrite_args(Tool::Npm, args.clone(), false);
        assert_eq!(out, args);
    }

    #[test]
    fn npm_install_with_existing_flag_not_duplicated() {
        let args = vec![
            OsString::from("install"),
            OsString::from("lodash"),
            OsString::from("--ignore-scripts"),
        ];
        let out = rewrite_args(Tool::Npm, args, false);
        let count = out.iter().filter(|a| **a == "--ignore-scripts").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn curl_args_passthrough_unchanged() {
        let args = vec![OsString::from("-fsSL"), OsString::from("https://example.com")];
        let out = rewrite_args(Tool::Curl, args.clone(), false);
        assert_eq!(out, args);
    }
}
