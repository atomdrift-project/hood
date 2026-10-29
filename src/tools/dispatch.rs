//! Whether an invocation fetches, and so runs behind the proxy.

use std::borrow::Cow;
use std::ffi::OsString;

use super::{Fetch, Tool};

/// Decision on whether to route a tool invocation through hood's proxy.
#[derive(Debug)]
pub enum Dispatch {
    /// Run the tool through the proxy with these (possibly rewritten) args.
    Intercept(Vec<OsString>),
    /// Exec the tool directly — no proxy needed for this subcommand.
    Passthrough(Vec<OsString>),
}

/// Classify a tool invocation: through the proxy, or straight through?
///
/// npm, pnpm, yarn and bun installs also get `--ignore-scripts`, unless the
/// user already chose: in `args`, or in their environment (`scripts_chosen`).
#[must_use]
pub fn dispatch(tool: Tool, args: Vec<OsString>, scripts_chosen: bool) -> Dispatch {
    let fetches = match tool.spec().fetch {
        Fetch::Always => true,
        Fetch::Verbs {
            installs,
            fetches,
            bare,
        } => {
            let known = |verb: &str| installs.contains(&verb) || fetches.contains(&verb);
            // Every positional counts, so a global option's value cannot hide
            // a later verb, as in `npm --prefix /tmp install`.
            let mut positionals = positionals(&args).peekable();
            match (positionals.peek(), bare) {
                // A help or version request stays local whatever it means.
                (None, Some(verb)) => known(verb) && !asks_about_itself(&args),
                _ => positionals.any(|arg| known(&arg)),
            }
        }
        Fetch::Go => go_fetches(&args),
        Fetch::Pacman => pacman_fetches(&args),
        Fetch::AurHelper => aur_helper_fetches(&args),
        Fetch::Makepkg => makepkg_fetches(&args),
        Fetch::RemoteUrl => args.iter().any(|arg| is_remote_url(&arg.to_string_lossy())),
    };
    if !fetches {
        return Dispatch::Passthrough(args);
    }
    if let Fetch::Verbs { installs, bare, .. } = tool.spec().fetch {
        let lead = if positionals(&args).next().is_none() {
            bare
        } else {
            leading_verb(&args, tool)
        };
        if lead.is_some_and(|verb| installs.contains(&verb)) {
            return Dispatch::Intercept(maybe_add_ignore_scripts(args, scripts_chosen));
        }
    }
    Dispatch::Intercept(args)
}

/// Whether the arguments ask a tool for its help or version.
fn asks_about_itself(args: &[OsString]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.to_str(),
            Some("-h" | "--help" | "-v" | "-V" | "--version")
        )
    })
}

/// The arguments that are neither options nor rustup-style `+toolchain`s.
fn positionals(args: &[OsString]) -> impl Iterator<Item = Cow<'_, str>> {
    args.iter()
        .map(|arg| arg.to_string_lossy())
        .filter(|arg| !arg.starts_with('-') && !arg.starts_with('+'))
}

/// The verb an invocation leads with: the first positional, skipping one that
/// follows an option and is no verb of `tool` — that is the option's value, as
/// `/tmp` is in `npm --prefix /tmp install`. Only the leading verb decides
/// whether scripts run, so `npm run install` stays a script run.
fn leading_verb(args: &[OsString], tool: Tool) -> Option<&'static str> {
    let Fetch::Verbs {
        installs, fetches, ..
    } = tool.spec().fetch
    else {
        return None;
    };
    let verb = |arg: &str| installs.iter().chain(fetches).copied().find(|&v| v == arg);
    let mut after_option = false;
    for arg in args {
        let arg = arg.to_string_lossy();
        if arg.starts_with('-') || arg.starts_with('+') {
            after_option = !arg.contains('=');
            continue;
        }
        match verb(&arg) {
            Some(verb) => return Some(verb),
            None if after_option => after_option = false,
            // A positional that is not a verb leads: `run`, a script name.
            None => return None,
        }
    }
    None
}

/// True for the `go` verbs that fetch modules, and for `go run pkg@version`,
/// which fetches the package outside the main module. A plain `go run`,
/// `go build` or `go test` fetches only what `go.sum` pins, so it stays local.
fn go_fetches(args: &[OsString]) -> bool {
    /// `go run` build flags that take a separate value, which is not the package.
    const VALUE_FLAGS: &[&str] = &[
        "-C",
        "-o",
        "-p",
        "-exec",
        "-tags",
        "-ldflags",
        "-gcflags",
        "-asmflags",
        "-mod",
        "-modfile",
        "-overlay",
        "-pgo",
        "-toolexec",
        "-buildmode",
        "-compiler",
        "-gccgoflags",
        "-installsuffix",
        "-pkgdir",
        "-covermode",
        "-coverpkg",
    ];
    let mut args = args.iter().map(|arg| arg.to_string_lossy());
    let Some(verb) = args.find(|arg| !arg.starts_with('-')) else {
        return false;
    };
    match verb.as_ref() {
        "get" | "install" | "mod" | "work" => true,
        "run" => {
            // The package is the first argument that is neither a flag nor a
            // flag's value; everything after it belongs to the program.
            let mut takes_value = false;
            for arg in args {
                if std::mem::take(&mut takes_value) {
                    continue;
                }
                if let Some(flag) = arg.strip_prefix('-') {
                    let name = flag.trim_start_matches('-');
                    takes_value = !flag.contains('=')
                        && VALUE_FLAGS
                            .iter()
                            .any(|v| v.trim_start_matches('-') == name);
                    continue;
                }
                return arg.contains('@');
            }
            false
        }
        _ => false,
    }
}

/// True when a `pacman` invocation performs a sync (`-S`) or upgrade (`-U`)
/// operation, or refreshes the files database (`-F`) — the operations that
/// reach the network. Query/remove/database ops (`-Q`/`-R`/`-D`) stay local.
///
/// pacman spells the operation as an uppercase letter inside a single-dash
/// flag group (`-Syu`), so we scan those groups for `S`/`U`/`F`. Case matters:
/// `-Rns` (remove) must not be mistaken for a sync.
fn pacman_fetches(args: &[OsString]) -> bool {
    args.iter().any(|a| {
        let s = a.to_string_lossy();
        if let Some(group) = short_flag_group(&s) {
            return group.chars().any(|c| matches!(c, 'S' | 'U' | 'F'));
        }
        matches!(s.as_ref(), "--sync" | "--upgrade" | "--files")
    })
}

/// True when a `yay`/`paru` invocation fetches. These pacman wrappers add
/// implicit operations: a bare invocation means `-Syu`, and a bare package
/// name means "search the AUR and install". So the rule inverts pacman's — we
/// intercept unless the command is unambiguously a local query/remove/database
/// operation or a help/version request.
fn aur_helper_fetches(args: &[OsString]) -> bool {
    // Bare `yay` / `paru` performs a full system upgrade.
    if args.is_empty() {
        return true;
    }
    let mut saw_positional = false;
    for a in args {
        let s = a.to_string_lossy();
        if let Some(group) = short_flag_group(&s) {
            if group.chars().any(|c| matches!(c, 'S' | 'U' | 'F')) {
                return true;
            }
            if group.chars().any(|c| matches!(c, 'Q' | 'R' | 'D' | 'T')) {
                return false;
            }
        } else if let Some(long) = s.strip_prefix("--") {
            match long {
                "sync" | "upgrade" | "files" => return true,
                "query" | "remove" | "database" | "deptest" | "help" | "version" => return false,
                _ => {}
            }
        } else if !s.starts_with('-') {
            saw_positional = true;
        }
    }
    // No explicit operation flag: a package name implies an AUR install.
    saw_positional
}

/// True when a `makepkg` invocation builds (and therefore downloads sources).
/// Only the pure informational flags stay offline; a bare `makepkg` builds the
/// PKGBUILD in the current directory.
fn makepkg_fetches(args: &[OsString]) -> bool {
    if args.is_empty() {
        return true;
    }
    !args.iter().all(|a| {
        matches!(
            a.to_string_lossy().as_ref(),
            "-h" | "--help" | "-V" | "--version" | "--packagelist" | "--printsrcinfo"
        )
    })
}

/// True when `s` begins with a remote URL scheme libcurl would fetch. URL
/// schemes are case-insensitive (RFC 3986 §3.1), so `HTTPS://` must match too —
/// matching only lowercase would let `rpm -i HTTPS://host/x.rpm` fetch unscanned.
fn is_remote_url(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once("://") else {
        return false;
    };
    !rest.is_empty()
        && ["http", "https", "ftp", "ftps"]
            .iter()
            .any(|p| scheme.eq_ignore_ascii_case(p))
}

/// Return the letters of a single-dash flag group (`-Syu` → `Syu`). Returns
/// `None` for long options (`--sync`), bare `-`, and positionals — anything
/// that isn't a classic short-flag cluster.
fn short_flag_group(arg: &str) -> Option<&str> {
    let rest = arg.strip_prefix('-')?;
    if rest.is_empty() || rest.starts_with('-') {
        return None;
    }
    Some(rest)
}

/// Add `--ignore-scripts` unless the user already chose either way, in the
/// environment or with any spelling of the flag (`--ignore-scripts=false`,
/// `--no-ignore-scripts`).
fn maybe_add_ignore_scripts(mut args: Vec<OsString>, scripts_chosen: bool) -> Vec<OsString> {
    let chosen_in_args = args.iter().any(|a| {
        a.to_str().is_some_and(|a| {
            a == "--ignore-scripts"
                || a == "--no-ignore-scripts"
                || a.starts_with("--ignore-scripts=")
        })
    });
    if !scripts_chosen && !chosen_in_args {
        // Before any `--`: what follows it is arguments, not the tool's options.
        let at = args.iter().position(|a| a == "--").unwrap_or(args.len());
        args.insert(at, OsString::from("--ignore-scripts"));
    }
    args
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn intercept_args(d: Dispatch) -> Vec<OsString> {
        match d {
            Dispatch::Intercept(a) => a,
            Dispatch::Passthrough(a) => panic!("expected Intercept, got Passthrough({a:?})"),
        }
    }

    fn passthrough_args(d: Dispatch) -> Vec<OsString> {
        match d {
            Dispatch::Passthrough(a) => a,
            Dispatch::Intercept(a) => panic!("expected Passthrough, got Intercept({a:?})"),
        }
    }

    /// How hood treats one invocation.
    #[derive(Debug, PartialEq, Eq)]
    enum Expect {
        /// Runs untouched.
        Local,
        /// Runs behind the proxy, argv untouched.
        Proxied,
        /// Runs behind the proxy with `--ignore-scripts` added.
        NoScripts,
    }

    fn expect(tool: Tool, line: &str) -> Expect {
        let args: Vec<OsString> = line.split_whitespace().map(OsString::from).collect();
        match dispatch(tool, args.clone(), false) {
            Dispatch::Passthrough(_) => Expect::Local,
            Dispatch::Intercept(out) if out == args => Expect::Proxied,
            Dispatch::Intercept(out) => {
                assert_eq!(out.len(), args.len() + 1, "{tool} {line}: {out:?}");
                assert!(
                    out.contains(&os("--ignore-scripts")),
                    "{tool} {line}: {out:?}"
                );
                Expect::NoScripts
            }
        }
    }

    #[test]
    fn verbs_decide_proxying_and_only_installs_lose_their_scripts() {
        use Expect::{Local, NoScripts, Proxied};
        for (tool, line, want) in [
            // A flag's value does not hide the verb that follows it.
            (Tool::Npm, "--prefix /tmp install lodash", NoScripts),
            (Tool::Pnpm, "--filter web add react", NoScripts),
            // npm's aliases and misspellings of install.
            (Tool::Npm, "isntall lodash", NoScripts),
            (Tool::Npm, "cit", NoScripts),
            // A leading script run stays a script run.
            (Tool::Npm, "run install", Proxied),
            (Tool::Npm, "test", Local),
            // Runners fetch, but are not installs.
            (Tool::Npm, "exec cowsay", Proxied),
            (Tool::Pnpm, "dlx create-vite", Proxied),
            (Tool::Bun, "create vite", Proxied),
            (Tool::Bun, "a left-pad", NoScripts),
            // A bare yarn installs; its help does not.
            (Tool::Yarn, "", NoScripts),
            (Tool::Yarn, "--frozen-lockfile", NoScripts),
            (Tool::Yarn, "--version", Local),
            (Tool::Yarn, "run build", Local),
            // `go run` fetches only a `pkg@version`.
            (Tool::Go, "run ./cmd/tool", Local),
            (
                Tool::Go,
                "run golang.org/x/tools/cmd/stringer@latest -type=T",
                Proxied,
            ),
            (Tool::Go, "run -tags netgo example.com/m@v1.2.3", Proxied),
            (Tool::Go, "run -C dir .", Local),
            (Tool::Go, "run main.go user@example.com", Local),
            (Tool::Go, "work sync", Proxied),
            // Newly covered fetchers elsewhere.
            (Tool::Cargo, "generate-lockfile", Proxied),
            (Tool::Cargo, "vendor", Proxied),
            (Tool::Cargo, "build", Local),
            (Tool::Uv, "venv --seed", Proxied),
            (Tool::Uv, "--help", Local),
            (Tool::Poetry, "sync", Proxied),
            (Tool::Pip, "lock -r requirements.txt", Proxied),
            (Tool::Pdm, "remove flask", Proxied),
            (Tool::Brew, "update", Proxied),
            (Tool::Brew, "list", Local),
            (Tool::Dnf, "builddep foo.spec", Proxied),
            (Tool::Zypper, "ve", Proxied),
            (Tool::Apk, "fix", Proxied),
        ] {
            assert_eq!(expect(tool, line), want, "{tool} {line}");
        }
    }

    #[test]
    fn ignore_scripts_goes_before_a_double_dash() {
        let args = intercept_args(dispatch(
            Tool::Npm,
            vec![os("install"), os("x"), os("--"), os("--flag")],
            false,
        ));
        assert_eq!(
            args,
            [
                os("install"),
                os("x"),
                os("--ignore-scripts"),
                os("--"),
                os("--flag")
            ]
        );
    }

    #[test]
    fn go_get_is_intercepted() {
        let d = dispatch(Tool::Go, vec![os("get"), os("example.com/x")], false);
        assert_eq!(intercept_args(d), vec![os("get"), os("example.com/x")]);
    }

    #[test]
    fn go_install_is_intercepted() {
        let d = dispatch(Tool::Go, vec![os("install"), os("./cmd/foo")], false);
        let _v = intercept_args(d);
    }

    #[test]
    fn go_run_is_passthrough() {
        let d = dispatch(Tool::Go, vec![os("run"), os("./cmd/foo")], false);
        let _v = passthrough_args(d);
    }

    #[test]
    fn go_test_is_passthrough() {
        let d = dispatch(Tool::Go, vec![os("test"), os("./...")], false);
        let _v = passthrough_args(d);
    }

    #[test]
    fn cargo_install_intercepted_cargo_build_passthrough() {
        let _v = intercept_args(dispatch(
            Tool::Cargo,
            vec![os("install"), os("ripgrep")],
            false,
        ));
        let _v = passthrough_args(dispatch(
            Tool::Cargo,
            vec![os("build"), os("--release")],
            false,
        ));
    }

    #[test]
    fn npm_install_intercepted_npm_test_passthrough() {
        let _v = intercept_args(dispatch(
            Tool::Npm,
            vec![os("install"), os("lodash")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Npm, vec![os("test")], false));
    }

    #[test]
    fn executable_runners_and_rush_always_intercept_without_rewriting() {
        for tool in [
            Tool::Npx,
            Tool::Pnpx,
            Tool::Rush,
            Tool::Rushx,
            Tool::Bunx,
            Tool::Uvx,
        ] {
            let args = vec![os("--flag"), os("package")];
            assert_eq!(intercept_args(dispatch(tool, args.clone(), false)), args);
        }
    }

    #[test]
    fn pip3_matches_pip_dispatch() {
        let install = vec![os("install"), os("example")];
        assert_eq!(
            intercept_args(dispatch(Tool::Pip3, install.clone(), false)),
            install,
        );
        let _v = passthrough_args(dispatch(Tool::Pip3, vec![os("list")], false));
    }

    #[test]
    fn pdm_fetching_commands_intercept_and_local_commands_pass_through() {
        for command in ["add", "install", "update", "sync", "lock", "run", "self"] {
            let _v = intercept_args(dispatch(Tool::Pdm, vec![os(command)], false));
        }
        let _v = passthrough_args(dispatch(Tool::Pdm, vec![os("info")], false));
        let _v = passthrough_args(dispatch(Tool::Pdm, vec![os("config")], false));
    }

    #[test]
    fn brew_install_intercepted_brew_list_passthrough() {
        let _v = intercept_args(dispatch(Tool::Brew, vec![os("install"), os("jq")], false));
        let _v = passthrough_args(dispatch(Tool::Brew, vec![os("list")], false));
    }

    #[test]
    fn curl_always_intercepted_regardless_of_args() {
        let _v = intercept_args(dispatch(
            Tool::Curl,
            vec![os("-fsSL"), os("https://x")],
            false,
        ));
        let _v = intercept_args(dispatch(Tool::Curl, vec![os("--help")], false));
    }

    #[test]
    fn pip_install_injects_nothing_but_is_intercepted() {
        let d = dispatch(Tool::Pip, vec![os("install"), os("flask")], false);
        let args = intercept_args(d);
        assert!(!args.contains(&os("--ignore-scripts")));
    }

    #[test]
    fn npm_install_injects_ignore_scripts_when_disabled() {
        let d = dispatch(Tool::Npm, vec![os("install"), os("lodash")], false);
        let args = intercept_args(d);
        assert!(args.contains(&os("--ignore-scripts")));
    }

    #[test]
    fn npm_install_respects_a_choice_made_in_the_environment() {
        let d = dispatch(Tool::Npm, vec![os("install"), os("lodash")], true);
        let args = intercept_args(d);
        assert!(!args.contains(&os("--ignore-scripts")));
    }

    #[test]
    fn npm_install_respects_a_choice_made_in_args() {
        for choice in ["--ignore-scripts=false", "--no-ignore-scripts"] {
            let args = vec![os("install"), os("lodash"), os(choice)];
            assert_eq!(
                intercept_args(dispatch(Tool::Npm, args.clone(), false)),
                args
            );
        }
    }

    #[test]
    fn npm_install_does_not_duplicate_ignore_scripts() {
        let d = dispatch(
            Tool::Npm,
            vec![os("install"), os("lodash"), os("--ignore-scripts")],
            false,
        );
        let args = intercept_args(d);
        let count = args
            .iter()
            .filter(|a| *a == &os("--ignore-scripts"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn bare_invocation_is_passthrough() {
        let _v = passthrough_args(dispatch(Tool::Npm, vec![], false));
        let _v = passthrough_args(dispatch(Tool::Cargo, vec![], false));
    }

    #[test]
    fn yarn_install_is_intercepted() {
        let _v = intercept_args(dispatch(Tool::Yarn, vec![os("install")], false));
        let _v = passthrough_args(dispatch(Tool::Yarn, vec![os("run"), os("test")], false));
    }

    #[test]
    fn bun_x_is_intercepted_but_bun_test_is_not() {
        let args = intercept_args(dispatch(Tool::Bun, vec![os("x"), os("create-app")], false));
        // `bun x` is exec, not install: --ignore-scripts would go to the executed
        // package and suppress nothing, so it must NOT be injected.
        assert!(
            !args.contains(&os("--ignore-scripts")),
            "bun x got {args:?}"
        );
        // But `bun install` is an install and does get the flag.
        let installed = intercept_args(dispatch(Tool::Bun, vec![os("install")], false));
        assert!(installed.contains(&os("--ignore-scripts")));
        let _v = passthrough_args(dispatch(Tool::Bun, vec![os("test")], false));
    }

    #[test]
    fn pipx_install_intercepted() {
        let _v = intercept_args(dispatch(Tool::Pipx, vec![os("install"), os("ruff")], false));
        let _v = passthrough_args(dispatch(Tool::Pipx, vec![os("list")], false));
    }

    #[test]
    fn uv_pip_group_intercepted() {
        let _v = intercept_args(dispatch(
            Tool::Uv,
            vec![os("pip"), os("install"), os("flask")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Uv, vec![os("--help")], false));
    }

    #[test]
    fn poetry_add_intercepted_run_passthrough() {
        let _v = intercept_args(dispatch(Tool::Poetry, vec![os("add"), os("flask")], false));
        let _v = passthrough_args(dispatch(Tool::Poetry, vec![os("run"), os("pytest")], false));
    }

    #[test]
    fn go_mod_download_intercepted() {
        let _v = intercept_args(dispatch(Tool::Go, vec![os("mod"), os("download")], false));
    }

    #[test]
    fn cargo_update_and_fetch_intercepted() {
        let _v = intercept_args(dispatch(Tool::Cargo, vec![os("update")], false));
        let _v = intercept_args(dispatch(Tool::Cargo, vec![os("fetch")], false));
    }

    #[test]
    fn zig_fetches_intercepted_local_commands_passthrough() {
        let url = "https://example.com/pkg.tar.gz";
        for args in [
            vec![os("fetch"), os(url)],
            vec![os("fetch"), os("--save"), os(url)],
            vec![os("build")],
            vec![os("build"), os("test"), os("-Doptimize=ReleaseFast")],
            vec![os("build"), os("--fetch")],
            vec![os("build"), os("--fetch=all")],
        ] {
            assert_eq!(
                intercept_args(dispatch(Tool::Zig, args.clone(), false)),
                args
            );
        }
        for args in [
            vec![],
            vec![os("run"), os("fetch.zig")],
            vec![os("run"), os("build.zig")],
            vec![os("test"), os("src/main.zig")],
            vec![os("cc"), os("-o"), os("a.out"), os("main.c")],
        ] {
            let _v = passthrough_args(dispatch(Tool::Zig, args, false));
        }
    }

    #[test]
    fn cargo_toolchain_selector_does_not_hide_the_subcommand() {
        // `+nightly` is a rustup toolchain selector, not the subcommand — the
        // install must still be intercepted, and the selector preserved in argv.
        let d = dispatch(
            Tool::Cargo,
            vec![os("+nightly"), os("install"), os("ripgrep")],
            false,
        );
        assert_eq!(
            intercept_args(d),
            vec![os("+nightly"), os("install"), os("ripgrep")],
        );
        // A toolchain selector in front of a non-fetching verb still passes through.
        let _v = passthrough_args(dispatch(
            Tool::Cargo,
            vec![os("+stable"), os("build")],
            false,
        ));
    }

    #[test]
    fn value_flag_before_subcommand_still_intercepts() {
        // A value-taking global flag (`--prefix /tmp`) pushes `install` out of
        // first position; the fetch must still be intercepted, not passed through.
        let d = dispatch(
            Tool::Npm,
            vec![os("--prefix"), os("/tmp"), os("install"), os("lodash")],
            false,
        );
        let _v = intercept_args(d);
        // And a non-fetching run with a flag value that isn't a verb stays local.
        let _v = passthrough_args(dispatch(Tool::Npm, vec![os("run"), os("test")], false));
    }

    #[test]
    fn brew_bundle_intercepted_brew_info_passthrough() {
        let _v = intercept_args(dispatch(
            Tool::Brew,
            vec![os("bundle"), os("install")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Brew, vec![os("info"), os("jq")], false));
    }

    #[test]
    fn pacman_sync_and_upgrade_intercepted_query_passthrough() {
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("-Syu")], false));
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("-S"), os("firefox")], false));
        let _v = intercept_args(dispatch(
            Tool::Pacman,
            vec![os("-U"), os("./p.pkg.tar.zst")],
            false,
        ));
        let _v = intercept_args(dispatch(Tool::Pacman, vec![os("--sync"), os("vim")], false));
        // Query/remove are local — and `-Rns` must not be read as a sync.
        let _v = passthrough_args(dispatch(Tool::Pacman, vec![os("-Q")], false));
        let _v = passthrough_args(dispatch(Tool::Pacman, vec![os("-Rns"), os("vim")], false));
        let _v = passthrough_args(dispatch(Tool::Pacman, vec![], false));
    }

    #[test]
    fn aur_helper_implicit_operations_intercepted() {
        // Bare invocation = -Syu; bare package name = AUR search+install.
        let _v = intercept_args(dispatch(Tool::Yay, vec![], false));
        let _v = intercept_args(dispatch(Tool::Yay, vec![os("firefox")], false));
        let _v = intercept_args(dispatch(Tool::Paru, vec![os("-Syu")], false));
        // Local ops and help pass through.
        let _v = passthrough_args(dispatch(Tool::Yay, vec![os("-Qi"), os("firefox")], false));
        let _v = passthrough_args(dispatch(Tool::Yay, vec![os("--help")], false));
        let _v = passthrough_args(dispatch(Tool::Paru, vec![os("-R"), os("vim")], false));
    }

    #[test]
    fn makepkg_builds_intercepted_info_flags_passthrough() {
        let _v = intercept_args(dispatch(Tool::Makepkg, vec![], false));
        let _v = intercept_args(dispatch(Tool::Makepkg, vec![os("-si")], false));
        let _v = passthrough_args(dispatch(Tool::Makepkg, vec![os("--printsrcinfo")], false));
        let _v = passthrough_args(dispatch(Tool::Makepkg, vec![os("--version")], false));
    }

    #[test]
    fn rpm_intercepts_urls_only() {
        let _v = intercept_args(dispatch(
            Tool::Rpm,
            vec![os("-Uvh"), os("https://example.com/x.rpm")],
            false,
        ));
        let _v = passthrough_args(dispatch(
            Tool::Rpm,
            vec![os("-ivh"), os("./local.rpm")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Rpm, vec![os("-q"), os("bash")], false));
        // URL schemes are case-insensitive: an uppercase scheme must still be
        // recognized as remote, not passed through unscanned.
        let _v = intercept_args(dispatch(
            Tool::Rpm,
            vec![os("-i"), os("HTTPS://example.com/x.rpm")],
            false,
        ));
        let _v = intercept_args(dispatch(
            Tool::Rpm,
            vec![os("-i"), os("FTPS://example.com/x.rpm")],
            false,
        ));
    }

    #[test]
    fn dnf_yum_install_intercepted_list_passthrough() {
        let _v = intercept_args(dispatch(
            Tool::Dnf,
            vec![os("install"), os("ripgrep")],
            false,
        ));
        let _v = intercept_args(dispatch(Tool::Yum, vec![os("upgrade")], false));
        let _v = passthrough_args(dispatch(
            Tool::Dnf,
            vec![os("list"), os("installed")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Yum, vec![os("remove"), os("nano")], false));
    }

    #[test]
    fn zypper_short_and_long_verbs_intercepted() {
        let _v = intercept_args(dispatch(Tool::Zypper, vec![os("in"), os("vim")], false));
        let _v = intercept_args(dispatch(Tool::Zypper, vec![os("dup")], false));
        let _v = intercept_args(dispatch(
            Tool::Zypper,
            vec![os("download"), os("vim")],
            false,
        ));
        let _v = passthrough_args(dispatch(Tool::Zypper, vec![os("search"), os("vim")], false));
    }

    #[test]
    fn pkg_and_apk_install_intercepted() {
        let _v = intercept_args(dispatch(Tool::Pkg, vec![os("install"), os("curl")], false));
        let _v = intercept_args(dispatch(Tool::Pkg, vec![os("upgrade")], false));
        let _v = passthrough_args(dispatch(Tool::Pkg, vec![os("info")], false));
        let _v = intercept_args(dispatch(Tool::Apk, vec![os("add"), os("curl")], false));
        let _v = passthrough_args(dispatch(Tool::Apk, vec![os("info")], false));
    }
}
