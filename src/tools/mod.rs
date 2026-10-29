//! The tools hood wraps: what each is, when an invocation of it fetches, the
//! environment that routes its traffic through hood and trusts hood's CA, and
//! running it.
//!
//! Each [`Tool`] is one row of the `tools!` table. `go get`, `npm install` and
//! `cargo install` fetch, so they run through the proxy; `go build`,
//! `npm test` and `cargo build` do not, so they run untouched.

mod dispatch;
mod env;
mod program;

pub use dispatch::{Dispatch, dispatch};
use env::TrustProfile;
pub use env::{ChildEnv, PreparedChildEnv, prepare_child_env};
pub(crate) use program::resolve_binary_in_path;
pub use program::{ExecutablePath, Program, resolve_real_binary, run_tool};

/// Where a tool can exist, matched against [`std::env::consts::OS`].
///
/// A coarse OS-family gate, not a distro check: it removes tools that cannot
/// belong on the platform at all (pacman on macOS, `pkg` on Linux) so the
/// installer neither advertises them nor shims a stray same-named binary.
/// Arch's pacman vs Fedora's dnf, both "linux", is left to the PATH probe.
#[derive(Debug, Clone, Copy)]
enum Platforms {
    Everywhere,
    MacosAndLinux,
    Linux,
    Bsd,
}

/// How hood tells an invocation that fetches from one that stays local.
#[derive(Debug, Clone, Copy)]
enum Fetch {
    /// Every invocation may fetch: downloaders, package runners, and script
    /// runners with no stable leading verb.
    Always,
    /// A positional verb fetches. `installs` also run the installed packages'
    /// lifecycle scripts, so hood adds `--ignore-scripts` to them; `fetches`
    /// only need the proxy. `bare` is what an invocation with no verb means.
    Verbs {
        installs: &'static [&'static str],
        fetches: &'static [&'static str],
        bare: Option<&'static str>,
    },
    /// `go`: its fetching verbs, and `go run` of a `pkg@version`.
    Go,
    /// pacman's operation flags (`-S`, `-U`, `-F`).
    Pacman,
    /// yay and paru: pacman's flags, a bare upgrade, and implicit AUR installs.
    AurHelper,
    /// Every makepkg build fetches its sources.
    Makepkg,
    /// Only a remote URL argument fetches.
    RemoteUrl,
}

impl Fetch {
    const fn verbs(fetches: &'static [&'static str]) -> Self {
        Self::Verbs {
            installs: &[],
            fetches,
            bare: None,
        }
    }
}

/// Everything hood knows about one tool.
#[derive(Debug, Clone, Copy)]
struct Spec {
    /// The binary hood runs, and the name in shim file names and log fields.
    name: &'static str,
    platforms: Platforms,
    trust: TrustProfile,
    fetch: Fetch,
}

/// npm's verbs that install, and so run lifecycle scripts: the commands and
/// the aliases and misspellings npm itself accepts for them.
const NPM_INSTALLS: &[&str] = &[
    "install",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
    "add",
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
    "it",
    "install-test",
    "cit",
    "clean-install-test",
    "sit",
    "install-ci-test",
    "update",
    "u",
    "up",
    "upgrade",
    "udpate",
    "rebuild",
    "dedupe",
    "ddp",
];

macro_rules! tools {
    ($( $(#[$doc:meta])* $variant:ident => $spec:expr, )*) => {
        /// The package managers and downloaders hood wraps.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Tool {
            $( $(#[$doc])* $variant, )*
        }

        impl Tool {
            /// Every tool, each eligible for a shim.
            pub const SHIMMABLE: &'static [Self] = &[$(Self::$variant),*];

            const fn spec(self) -> Spec {
                use Fetch::{Always, AurHelper, Makepkg, Pacman, RemoteUrl, Verbs};
                use Platforms::{Bsd, Everywhere, Linux, MacosAndLinux};
                match self {
                    $( Self::$variant => $spec, )*
                }
            }
        }
    };
}

const fn spec(name: &'static str, platforms: Platforms, trust: TrustProfile, fetch: Fetch) -> Spec {
    Spec {
        name,
        platforms,
        trust,
        fetch,
    }
}

tools! {
    /// libcurl; honors `CURL_CA_BUNDLE` / `SSL_CERT_FILE`.
    Curl => spec("curl", Everywhere, TrustProfile::Curl, Always),
    /// gnutls or openssl; honors `SSL_CERT_FILE`.
    Wget => spec("wget", Everywhere, TrustProfile::Wget, Always),
    /// Node; honors `NODE_EXTRA_CA_CERTS`.
    Npm => spec("npm", Everywhere, TrustProfile::Node, Verbs {
        installs: NPM_INSTALLS,
        fetches: &["exec", "x", "init", "create", "innit"],
        bare: None,
    }),
    /// npm's package-executable runner.
    Npx => spec("npx", Everywhere, TrustProfile::Node, Always),
    /// Same trust model as npm.
    Pnpm => spec("pnpm", Everywhere, TrustProfile::Node, Verbs {
        installs: &[
            "install", "i", "add", "ci", "clean-install", "ic", "install-clean", "it",
            "install-test", "update", "up", "upgrade", "rebuild", "dedupe",
        ],
        fetches: &["dlx", "create", "fetch", "import", "patch", "runtime", "rt", "env", "self-update"],
        bare: None,
    }),
    /// pnpm's package-executable runner.
    Pnpx => spec("pnpx", Everywhere, TrustProfile::Node, Always),
    /// Node, same trust as npm. A bare `yarn` installs.
    Yarn => spec("yarn", Everywhere, TrustProfile::Node, Verbs {
        installs: &["install", "i", "add", "ci", "update", "up", "upgrade", "rebuild"],
        fetches: &["create", "dlx", "global", "upgrade-interactive", "import"],
        bare: Some("install"),
    }),
    /// Rush monorepo manager; its commands may provision tools.
    Rush => spec("rush", Everywhere, TrustProfile::Node, Always),
    /// Rush's project-script runner; scripts may fetch dependencies.
    Rushx => spec("rushx", Everywhere, TrustProfile::Node, Always),
    /// Node-compatible toolchain.
    Bun => spec("bun", Everywhere, TrustProfile::Node, Verbs {
        installs: &["install", "i", "add", "a", "update", "upgrade"],
        fetches: &["x", "create", "c"],
        bare: None,
    }),
    /// Alias for `bun x`.
    Bunx => spec("bunx", Everywhere, TrustProfile::Node, Always),
    /// pip uses bundled certifi; needs `PIP_CERT`.
    Pip => spec("pip", Everywhere, TrustProfile::Pip, Fetch::verbs(PIP_FETCHES)),
    /// Python 3 spelling of pip.
    Pip3 => spec("pip3", Everywhere, TrustProfile::Pip, Fetch::verbs(PIP_FETCHES)),
    /// pip-based; inherits `PIP_CERT`.
    Pipx => spec("pipx", Everywhere, TrustProfile::Pip, Fetch::verbs(&[
        "install", "install-all", "upgrade", "upgrade-all", "upgrade-shared", "reinstall",
        "reinstall-all", "inject", "run", "runpip",
    ])),
    /// Astral's pip replacement; `SSL_CERT_FILE` works. Its pip and tool
    /// verbs are namespaced, so the group alone decides.
    Uv => spec("uv", Everywhere, TrustProfile::Uv, Fetch::verbs(&[
        "pip", "tool", "add", "remove", "sync", "lock", "run", "version", "export", "tree",
        "python", "venv", "build", "self", "init",
    ])),
    /// Alias for `uv tool run`.
    Uvx => spec("uvx", Everywhere, TrustProfile::Uv, Always),
    /// Python; honors `POETRY_REQUESTS_CA_BUNDLE`.
    Poetry => spec("poetry", Everywhere, TrustProfile::Requests, Fetch::verbs(&[
        "add", "remove", "install", "sync", "update", "lock", "publish", "self", "python",
    ])),
    /// Python package and project manager. Its project commands, script
    /// runner, self-management, and Python manager can all resolve or fetch.
    Pdm => spec("pdm", Everywhere, TrustProfile::Pdm, Fetch::verbs(&[
        "add", "remove", "install", "update", "sync", "lock", "run", "build", "publish", "self",
        "python", "use", "venv", "import",
    ])),
    /// Go toolchain. Uses `SSL_CERT_FILE` where supported and hood's loopback
    /// module/sumdb bridge on macOS and Windows.
    Go => spec("go", Everywhere, TrustProfile::Go, Fetch::Go),
    /// Rust; honors `CARGO_HTTP_CAINFO` and `SSL_CERT_FILE`. `cargo build` can
    /// fetch too, but only what `Cargo.lock` pins, so builds stay unproxied.
    Cargo => spec("cargo", Everywhere, TrustProfile::Cargo, Fetch::verbs(&[
        "install", "add", "update", "fetch", "search", "generate-lockfile", "vendor", "info",
        "binstall",
    ])),
    /// Zig toolchain. Its TLS stack reads only fixed system trust stores, so
    /// hood refuses tunnels from Zig's HTTP client and Zig falls back to
    /// absolute-form proxying, which hood fetches over verified TLS itself.
    /// `zig build` fetches missing `build.zig.zon` dependencies, and its steps
    /// may run any tool, so they get every trust variable.
    Zig => spec("zig", Everywhere, TrustProfile::Exec, Fetch::verbs(&["build", "fetch"])),
    /// Homebrew (curl-backed).
    Brew => spec("brew", MacosAndLinux, TrustProfile::Brew, Fetch::verbs(&[
        "install", "upgrade", "reinstall", "fetch", "tap", "bundle", "update", "up",
    ])),
    /// Arch Linux. libalpm links libcurl. The operation is a flag, not a verb.
    Pacman => spec("pacman", Linux, TrustProfile::SystemCurl, Pacman),
    /// Arch AUR helper (Go). Package downloads delegate to pacman and makepkg;
    /// its own AUR RPC uses Go's TLS stack.
    Yay => spec("yay", Linux, TrustProfile::Yay, AurHelper),
    /// Arch AUR helper (Rust). Same delegation model as yay.
    Paru => spec("paru", Linux, TrustProfile::SystemCurl, AurHelper),
    /// Arch source build; fetches PKGBUILD sources through curl DLAGENTs.
    Makepkg => spec("makepkg", Linux, TrustProfile::SystemCurl, Makepkg),
    /// Fedora/RHEL. librepo links libcurl.
    Dnf => spec("dnf", Linux, TrustProfile::SystemCurl, Fetch::verbs(DNF_FETCHES)),
    /// RHEL; dnf's verbs.
    Yum => spec("yum", Linux, TrustProfile::SystemCurl, Fetch::verbs(DNF_FETCHES)),
    /// openSUSE. libzypp links libcurl. Long verbs and their short aliases.
    Zypper => spec("zypper", Linux, TrustProfile::SystemCurl, Fetch::verbs(&[
        "install", "in", "remove-and-install", "update", "up", "dist-upgrade", "dup", "patch",
        "download", "source-download", "source-install", "si", "install-new-recommends", "inr",
        "refresh", "ref", "verify", "ve",
    ])),
    /// Low-level RPM; reaches the network only for an `http(s)`/`ftp` URL.
    Rpm => spec("rpm", Linux, TrustProfile::SystemCurl, RemoteUrl),
    /// FreeBSD. libfetch honors `SSL_CA_CERT_FILE` and the proxy variables.
    Pkg => spec("pkg", Bsd, TrustProfile::SystemCurl, Fetch::verbs(&[
        "install", "add", "upgrade", "fetch", "update", "bootstrap",
    ])),
    /// Alpine. apk-tools' libfetch honors `SSL_CA_CERT_FILE`.
    Apk => spec("apk", Linux, TrustProfile::SystemCurl, Fetch::verbs(&[
        "add", "upgrade", "update", "fetch", "fix", "cache",
    ])),
}

const PIP_FETCHES: &[&str] = &["install", "download", "wheel", "lock"];

/// dnf and yum share a verb vocabulary; these pull packages or metadata.
const DNF_FETCHES: &[&str] = &[
    "install",
    "in",
    "install-n",
    "install-na",
    "install-nevra",
    "reinstall",
    "upgrade",
    "upgrade-minimal",
    "update",
    "update-minimal",
    "up",
    "downgrade",
    "distro-sync",
    "dsync",
    "group",
    "groupinstall",
    "groupupdate",
    "localinstall",
    "swap",
    "download",
    "builddep",
    "module",
    "system-upgrade",
    "debuginfo-install",
    "makecache",
];

impl Tool {
    /// The canonical short name for this tool — the binary hood runs, and the
    /// name used in shim file names and log fields.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.spec().name
    }

    /// The tool named `name`, if hood wraps one.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::SHIMMABLE
            .iter()
            .copied()
            .find(|tool| tool.name() == name)
    }

    /// Whether this tool could plausibly exist on `os`, as
    /// [`std::env::consts::OS`] spells it; see [`Platforms`].
    #[must_use]
    pub fn plausible_on(self, os: &str) -> bool {
        match self.spec().platforms {
            Platforms::Everywhere => true,
            Platforms::MacosAndLinux => matches!(os, "macos" | "linux"),
            Platforms::Linux => os == "linux",
            Platforms::Bsd => matches!(os, "freebsd" | "dragonfly" | "netbsd" | "openbsd"),
        }
    }

    const fn trust_profile(self) -> TrustProfile {
        self.spec().trust
    }
}

impl std::fmt::Display for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_shimmable_tool_has_a_name() {
        for tool in Tool::SHIMMABLE {
            assert!(!tool.name().is_empty());
        }
    }

    #[test]
    fn plausible_on_gates_system_managers_by_os() {
        // Arch/RPM/Alpine managers are Linux-only.
        for t in [Tool::Pacman, Tool::Yay, Tool::Dnf, Tool::Rpm, Tool::Apk] {
            assert!(
                t.plausible_on("linux"),
                "{t:?} should be plausible on linux"
            );
            assert!(
                !t.plausible_on("macos"),
                "{t:?} must not be plausible on macos"
            );
            assert!(
                !t.plausible_on("windows"),
                "{t:?} must not be plausible on windows"
            );
        }
        // Homebrew: macOS and Linux, not BSD/Windows.
        assert!(Tool::Brew.plausible_on("macos"));
        assert!(Tool::Brew.plausible_on("linux"));
        assert!(!Tool::Brew.plausible_on("freebsd"));
        // pkgng: BSD only.
        assert!(Tool::Pkg.plausible_on("freebsd"));
        assert!(!Tool::Pkg.plausible_on("linux"));
        assert!(!Tool::Pkg.plausible_on("macos"));
        // Language toolchains and downloaders: everywhere.
        for t in [
            Tool::Curl,
            Tool::Npm,
            Tool::Cargo,
            Tool::Go,
            Tool::Pip,
            Tool::Zig,
        ] {
            for os in ["macos", "linux", "windows", "freebsd"] {
                assert!(t.plausible_on(os), "{t:?} should be plausible on {os}");
            }
        }
    }
}
