//! The environment that routes a child's traffic through hood and makes it
//! trust hood's CA.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tempfile::TempDir;

use super::{Program, Tool};
use crate::go_bridge::GoChildEnv;

/// TLS/proxy behavior shared by command aliases and tools built on the same
/// network stack. Keeping this separate from [`Tool`] prevents aliases such as
/// `pip3` and `uvx` from accumulating subtly different environment overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrustProfile {
    Curl,
    Wget,
    Node,
    Pip,
    Uv,
    Requests,
    Pdm,
    Go,
    Cargo,
    Brew,
    SystemCurl,
    Yay,
    Exec,
}

/// npm's `noproxy` for hood's children. A project's `.npmrc` can set
/// `noproxy` to send the registry around hood unscanned; the environment
/// outranks it, but npm ignores an empty variable, so the value is a name no
/// real host has (`.invalid` is reserved by RFC 6761).
const NPM_NOPROXY: &str = "invalid";

/// Universal proxy env vars, in both cases — some clients only consult one.
const PROXY_VARS: [&str; 6] = [
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
];

/// Per-tool runtime context: where the proxy listens, where the CA file lives.
#[derive(Debug)]
pub struct ChildEnv {
    /// Proxy listen address as `http://host:port`.
    proxy_url: String,
    /// Path the child process can pass to its TLS verifier.
    ca_pem_path: PathBuf,
    /// macOS Go module/sumdb bridge settings, when enabled for this run.
    go: Option<GoChildEnv>,
}

/// Child environment coupled to the temporary CA file it references.
///
/// Keeping both values under one owner prevents the CA file from being
/// deleted while a child still depends on it.
#[derive(Debug)]
pub struct PreparedChildEnv {
    pub(super) env: ChildEnv,
    _ca_dir: TempDir,
}

impl PreparedChildEnv {
    /// Add macOS Go bridge settings to the environment.
    pub fn set_go_bridge(&mut self, go: GoChildEnv) {
        self.env.go = Some(go);
    }
}

impl ChildEnv {
    /// Build the env-var overlay for a given tool.
    #[must_use]
    pub fn vars_for(&self, tool: Tool) -> BTreeMap<&'static str, OsString> {
        self.vars_for_profile(tool.trust_profile())
    }

    /// Command-line arguments appended for tools whose trust settings cannot
    /// be reached through the environment. Windows curl is Schannel: it
    /// ignores `CURL_CA_BUNDLE` and `SSL_CERT_FILE`, honors `--cacert`, and
    /// then fails hood's certificate for lacking a revocation endpoint unless
    /// told to tolerate that.
    pub(super) fn args_for_program(&self, program: &Program) -> Vec<OsString> {
        if cfg!(windows) && program.is_curl() {
            return vec![
                OsString::from("--cacert"),
                self.ca_pem_path.clone().into_os_string(),
                OsString::from("--ssl-revoke-best-effort"),
            ];
        }
        Vec::new()
    }

    pub(super) fn vars_for_program(&self, program: &Program) -> BTreeMap<&'static str, OsString> {
        self.vars_for_profile(program.trust_profile())
    }

    fn vars_for_profile(&self, profile: TrustProfile) -> BTreeMap<&'static str, OsString> {
        let mut out = BTreeMap::new();
        let proxy = OsString::from(&self.proxy_url);
        let ca = OsString::from(&self.ca_pem_path);

        for k in PROXY_VARS {
            out.insert(k, proxy.clone());
        }

        // Neutralize any inherited NO_PROXY exclusion list. A curl/Go/Node child
        // that inherits `NO_PROXY=*.internal` (or `NO_PROXY=*`) would route
        // matching hosts straight to the origin, bypassing the proxy entirely and
        // leaving those downloads unscanned. Setting it empty (both cases, since
        // clients differ on which they read) excludes no host, so everything is
        // forced through hood.
        for k in ["no_proxy", "NO_PROXY"] {
            out.insert(k, OsString::new());
        }

        match profile {
            TrustProfile::Curl => {
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Wget => {
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Node => {
                out.insert("NODE_EXTRA_CA_CERTS", ca.clone());
                out.insert("npm_config_proxy", proxy.clone());
                out.insert("npm_config_https_proxy", proxy);
                out.insert("npm_config_noproxy", OsString::from(NPM_NOPROXY));
                out.insert("npm_config_cafile", ca);
            }
            TrustProfile::Pip => {
                // pip uses certifi by default; PIP_CERT is the supported override.
                out.insert("PIP_CERT", ca);
            }
            TrustProfile::Uv => {
                // uv (Astral) honors SSL_CERT_FILE and also its own UV_CA_CERT.
                out.insert("UV_CA_CERT", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Requests => {
                // poetry uses requests under the hood and honors
                // POETRY_REQUESTS_CA_BUNDLE per-repo, but supports the bundled
                // env at runtime as well. Set both to be safe.
                out.insert("POETRY_REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("REQUESTS_CA_BUNDLE", ca);
            }
            TrustProfile::Pdm => {
                // PDM documents both variables as CA-bundle overrides. Keep
                // the user's index and credential configuration untouched.
                out.insert("REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
            }
            TrustProfile::Go => {
                if let Some(go) = &self.go {
                    out.insert("GOPROXY", OsString::from(&go.goproxy));
                    out.insert("GOSUMDB", OsString::from(&go.gosumdb));
                    // The Go bridge is an origin server on loopback. Make the
                    // bypass explicit so inherited proxy behavior cannot feed
                    // that request recursively back into this same listener.
                    let loopback = OsString::from("127.0.0.1,localhost");
                    out.insert("no_proxy", loopback.clone());
                    out.insert("NO_PROXY", loopback);
                } else {
                    // Go honors this on Unix systems other than macOS; macOS
                    // and Windows use the bridge instead.
                    out.insert("SSL_CERT_FILE", ca);
                }
            }
            TrustProfile::Cargo => {
                // CARGO_HTTP_CAINFO is the documented cargo override.
                // SSL_CERT_FILE covers git+https fetches that cargo invokes.
                out.insert("CARGO_HTTP_CAINFO", ca.clone());
                // Outranks `http.proxy` from a project's `.cargo/config.toml`.
                out.insert("CARGO_HTTP_PROXY", proxy);
                out.insert("SSL_CERT_FILE", ca);
                if cfg!(windows) {
                    // Schannel rejects hood's per-run certificate for lacking a
                    // revocation endpoint. Upstream verification is hood's own.
                    out.insert("CARGO_HTTP_CHECK_REVOKE", OsString::from("false"));
                }
            }
            TrustProfile::Brew => {
                // brew uses curl internally and respects CURL_CA_BUNDLE.
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca);
                // Most brew formulae build with curl; the env carries. Auto
                // update is declared, not suppressed.
                out.insert("HOMEBREW_NO_AUTO_UPDATE", OsString::from("0"));
            }
            // System package managers reach the network through one of a few
            // TLS backends: libcurl (pacman's libalpm, dnf's librepo, zypper's
            // libzypp, rpm) reads CURL_CA_BUNDLE/SSL_CERT_FILE; libfetch
            // (FreeBSD pkg, Alpine apk-tools) reads SSL_CA_CERT_FILE; makepkg
            // shells out to curl DLAGENTs. We set every CA-file var these
            // backends honor — each tool consults the one matching its stack
            // and ignores the rest, which keeps the overlay backend-agnostic.
            TrustProfile::SystemCurl => {
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("SSL_CA_CERT_FILE", ca);
            }
            TrustProfile::Yay => {
                // yay is Go: its AUR RPC uses crypto/tls (SSL_CERT_FILE, plus
                // the macOS fallback-roots knob), while package and source
                // downloads delegate to pacman and makepkg (libcurl / curl).
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("SSL_CA_CERT_FILE", ca);
                out.insert("GODEBUG", OsString::from("x509usefallbackroots=1"));
            }
            TrustProfile::Exec => {
                // Set every flavor we know about so whatever the user runs
                // has a reasonable shot at trusting us.
                out.insert("CURL_CA_BUNDLE", ca.clone());
                out.insert("SSL_CERT_FILE", ca.clone());
                out.insert("SSL_CA_CERT_FILE", ca.clone());
                out.insert("NODE_EXTRA_CA_CERTS", ca.clone());
                out.insert("PIP_CERT", ca.clone());
                out.insert("UV_CA_CERT", ca.clone());
                out.insert("REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("POETRY_REQUESTS_CA_BUNDLE", ca.clone());
                out.insert("CARGO_HTTP_CAINFO", ca.clone());
                out.insert("CARGO_HTTP_PROXY", proxy.clone());
                if cfg!(windows) {
                    // As for the cargo shim: Schannel has no revocation
                    // endpoint to check for hood's per-run certificate.
                    out.insert("CARGO_HTTP_CHECK_REVOKE", OsString::from("false"));
                }
                out.insert("npm_config_cafile", ca);
                out.insert("npm_config_proxy", proxy.clone());
                out.insert("npm_config_https_proxy", proxy);
                out.insert("npm_config_noproxy", OsString::from(NPM_NOPROXY));
                // Unix-only: Go reads neither SSL_CERT_FILE nor this GODEBUG on
                // macOS or Windows, where it trusts only the system store. The
                // `go` shim handles those through the loopback bridge, but an
                // arbitrary Go binary under `hood exec` on macOS/Windows cannot
                // be made to trust the per-run CA and is not covered.
                out.insert("GODEBUG", OsString::from("x509usefallbackroots=1"));
            }
        }
        out
    }
}

/// Build a child environment whose owner keeps its temporary CA file alive.
///
/// # Errors
///
/// Returns an error if the CA file cannot be created, secured, or written.
pub fn prepare_child_env(proxy_addr: SocketAddr, ca_pem: &str) -> Result<PreparedChildEnv> {
    let dir = tempfile::Builder::new()
        .prefix("hood-ca-")
        .tempdir()
        .context("create CA tempdir")?;
    let pem_path = dir.path().join("hood-ca.pem");
    let mut f = std::fs::File::create(&pem_path).context("create CA pem")?;
    f.write_all(ca_pem.as_bytes()).context("write CA pem")?;
    f.flush().context("flush CA pem")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = f.metadata().context("stat CA pem")?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&pem_path, perms).context("chmod CA pem")?;
    }
    drop(f);

    let proxy_url = format!("http://{proxy_addr}");
    Ok(PreparedChildEnv {
        env: ChildEnv {
            proxy_url,
            ca_pem_path: pem_path,
            go: None,
        },
        _ca_dir: dir,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn fake_env() -> ChildEnv {
        ChildEnv {
            proxy_url: "http://127.0.0.1:12345".into(),
            ca_pem_path: PathBuf::from("/tmp/hood.pem"),
            go: None,
        }
    }

    #[test]
    fn curl_env_includes_curl_ca_bundle() {
        let v = fake_env().vars_for(Tool::Curl);
        assert!(v.contains_key("CURL_CA_BUNDLE"));
        assert!(v.contains_key("SSL_CERT_FILE"));
        assert!(v.contains_key("http_proxy"));
    }

    #[test]
    fn npm_env_includes_node_extra_ca() {
        let v = fake_env().vars_for(Tool::Npm);
        assert!(v.contains_key("NODE_EXTRA_CA_CERTS"));
        assert!(v.contains_key("npm_config_https_proxy"));
    }

    #[test]
    fn command_aliases_share_their_ecosystem_trust_profile() {
        let node = fake_env().vars_for(Tool::Npm);
        for tool in [Tool::Npx, Tool::Pnpx, Tool::Rush, Tool::Rushx, Tool::Bunx] {
            assert_eq!(fake_env().vars_for(tool), node, "{tool:?}");
        }

        assert_eq!(
            fake_env().vars_for(Tool::Pip3),
            fake_env().vars_for(Tool::Pip)
        );
        assert_eq!(
            fake_env().vars_for(Tool::Uvx),
            fake_env().vars_for(Tool::Uv)
        );
    }

    #[test]
    fn pdm_env_uses_documented_ca_bundle_overrides() {
        let v = fake_env().vars_for(Tool::Pdm);
        assert!(v.contains_key("REQUESTS_CA_BUNDLE"));
        assert!(v.contains_key("CURL_CA_BUNDLE"));
        assert!(v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn pip_env_uses_pip_cert_not_ssl_cert_file() {
        let v = fake_env().vars_for(Tool::Pip);
        assert!(v.contains_key("PIP_CERT"));
        assert!(!v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn cargo_env_uses_cargo_http_cainfo() {
        let v = fake_env().vars_for(Tool::Cargo);
        assert!(v.contains_key("CARGO_HTTP_CAINFO"));
        assert!(v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn brew_env_uses_curl_ca_bundle() {
        let v = fake_env().vars_for(Tool::Brew);
        assert!(v.contains_key("CURL_CA_BUNDLE"));
    }

    #[test]
    fn go_env_uses_ssl_cert_file_without_bridge() {
        let v = fake_env().vars_for(Tool::Go);
        assert!(v.contains_key("SSL_CERT_FILE"));
        assert!(!v.contains_key("GODEBUG"));
        assert!(!v.contains_key("GOPROXY"));
    }

    #[test]
    fn go_bridge_replaces_ca_override_and_exempts_loopback() {
        let mut env = fake_env();
        env.go = Some(GoChildEnv {
            goproxy: "http://127.0.0.1:12345/__hood_go/token/proxy".into(),
            gosumdb: "sum.golang.org http://127.0.0.1:12345/__hood_go/token/sumdb".into(),
        });
        let v = env.vars_for(Tool::Go);
        assert_eq!(
            v.get("GOPROXY"),
            Some(&OsString::from(
                "http://127.0.0.1:12345/__hood_go/token/proxy"
            )),
        );
        assert!(v.contains_key("GOSUMDB"));
        assert!(!v.contains_key("SSL_CERT_FILE"));
        assert_eq!(
            v.get("NO_PROXY"),
            Some(&OsString::from("127.0.0.1,localhost")),
        );
    }

    /// `hood exec` may run any of the tools, so it carries every variable any
    /// tool's profile sets. Derived from the profiles, so a variable added to
    /// one cannot be forgotten here.
    #[test]
    fn exec_env_is_superset() {
        let env = fake_env();
        let exec = env.vars_for_program(&Program::command("/tmp/example").unwrap());
        for &tool in Tool::SHIMMABLE {
            for key in env.vars_for(tool).keys() {
                // Homebrew's own update policy, not a trust setting.
                if *key == "HOMEBREW_NO_AUTO_UPDATE" {
                    continue;
                }
                assert!(
                    exec.contains_key(key),
                    "exec env lacks {key}, which {tool:?} sets"
                );
            }
        }
    }

    #[test]
    fn wget_env_uses_ssl_cert_file_only() {
        let v = fake_env().vars_for(Tool::Wget);
        assert!(v.contains_key("SSL_CERT_FILE"));
        // wget doesn't use NODE/PIP variants.
        assert!(!v.contains_key("NODE_EXTRA_CA_CERTS"));
        assert!(!v.contains_key("PIP_CERT"));
    }

    #[test]
    fn yarn_and_bun_share_npm_env() {
        for tool in [Tool::Yarn, Tool::Bun, Tool::Pnpm] {
            let v = fake_env().vars_for(tool);
            assert!(
                v.contains_key("NODE_EXTRA_CA_CERTS"),
                "{tool:?} should set NODE_EXTRA_CA_CERTS",
            );
            assert!(v.contains_key("npm_config_https_proxy"));
        }
    }

    #[test]
    fn uv_env_uses_uv_ca_cert_and_ssl_cert_file() {
        let v = fake_env().vars_for(Tool::Uv);
        assert!(v.contains_key("UV_CA_CERT"));
        assert!(v.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn poetry_env_uses_poetry_and_requests_bundles() {
        let v = fake_env().vars_for(Tool::Poetry);
        assert!(v.contains_key("POETRY_REQUESTS_CA_BUNDLE"));
        assert!(v.contains_key("REQUESTS_CA_BUNDLE"));
    }

    #[test]
    fn pipx_env_matches_pip() {
        let v = fake_env().vars_for(Tool::Pipx);
        assert!(v.contains_key("PIP_CERT"));
    }

    #[test]
    fn zig_env_trusts_hood_for_any_build_step_tool() {
        let program = Program::command("/tmp/example").unwrap();
        let exec = fake_env().vars_for_program(&program);
        assert_eq!(fake_env().vars_for(Tool::Zig), exec);
    }

    #[test]
    fn project_config_cannot_route_around_the_proxy() {
        let npm = fake_env().vars_for(Tool::Npm);
        assert_eq!(
            npm.get("npm_config_noproxy"),
            Some(&OsString::from("invalid"))
        );
        let cargo = fake_env().vars_for(Tool::Cargo);
        assert_eq!(
            cargo.get("CARGO_HTTP_PROXY"),
            Some(&OsString::from("http://127.0.0.1:12345"))
        );
        let exec = fake_env().vars_for_program(&Program::command("/tmp/example").unwrap());
        assert!(exec.contains_key("CARGO_HTTP_PROXY") && exec.contains_key("npm_config_noproxy"));
    }

    #[test]
    fn no_proxy_is_neutralized_in_env() {
        // The overlay must blank out any inherited NO_PROXY so the child can't
        // route matching hosts around the proxy unscanned.
        let v = fake_env().vars_for(Tool::Curl);
        assert_eq!(v.get("NO_PROXY"), Some(&OsString::new()));
        assert_eq!(v.get("no_proxy"), Some(&OsString::new()));
    }

    #[test]
    fn libcurl_package_managers_set_curl_and_ssl_ca() {
        for tool in [
            Tool::Pacman,
            Tool::Paru,
            Tool::Makepkg,
            Tool::Dnf,
            Tool::Yum,
            Tool::Zypper,
            Tool::Rpm,
            Tool::Pkg,
            Tool::Apk,
        ] {
            let v = fake_env().vars_for(tool);
            assert!(v.contains_key("CURL_CA_BUNDLE"), "{tool:?} CURL_CA_BUNDLE");
            assert!(v.contains_key("SSL_CERT_FILE"), "{tool:?} SSL_CERT_FILE");
            assert!(
                v.contains_key("SSL_CA_CERT_FILE"),
                "{tool:?} SSL_CA_CERT_FILE (libfetch)",
            );
            assert!(v.contains_key("https_proxy"), "{tool:?} proxy");
        }
    }

    #[test]
    fn yay_sets_go_fallback_roots_and_ca() {
        let v = fake_env().vars_for(Tool::Yay);
        assert!(v.contains_key("SSL_CERT_FILE"));
        assert!(v.contains_key("CURL_CA_BUNDLE"));
        assert!(v.contains_key("SSL_CA_CERT_FILE"));
        assert!(
            v.get("GODEBUG")
                .is_some_and(|g| g.to_string_lossy().contains("x509usefallbackroots=1"))
        );
    }

    #[test]
    fn exec_superset_includes_libfetch_ca() {
        let program = Program::command("/tmp/example").unwrap();
        let v = fake_env().vars_for_program(&program);
        assert!(v.contains_key("SSL_CA_CERT_FILE"));
    }

    #[test]
    fn curl_args_follow_the_platform() {
        let env = fake_env();
        let shim = env.args_for_program(&Program::Tool(Tool::Curl));
        // `hood exec -- curl.exe` is curl too and needs the same flags, since
        // the exec env vars never reach Schannel.
        let exec_curl = env.args_for_program(&Program::command("curl.exe").unwrap());
        if cfg!(windows) {
            assert_eq!(shim[0], "--cacert");
            assert_eq!(shim[1], env.ca_pem_path.as_os_str());
            assert_eq!(shim[2], "--ssl-revoke-best-effort");
            assert_eq!(exec_curl, shim);
            assert!(
                env.vars_for(Tool::Cargo)
                    .contains_key("CARGO_HTTP_CHECK_REVOKE")
            );
        } else {
            assert!(shim.is_empty());
            assert!(exec_curl.is_empty());
            assert!(
                !env.vars_for(Tool::Cargo)
                    .contains_key("CARGO_HTTP_CHECK_REVOKE")
            );
        }
        assert!(env.args_for_program(&Program::Tool(Tool::Npm)).is_empty());
        // A non-curl exec target gets nothing, even on Windows.
        assert!(
            env.args_for_program(&Program::command("node.exe").unwrap())
                .is_empty()
        );
    }
}
