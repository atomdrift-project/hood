#!/bin/sh
# Arch Linux: pacman as root; makepkg and the AUR helpers refuse root, so
# they run in a second pass as an unprivileged user.
. "$(dirname "$0")/common.sh"

pacman -Syu --noconfirm --needed base-devel git rustup cmake clang curl sudo
useradd --create-home builder
echo 'builder ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/builder
install -d -o builder "$CARGO_TARGET_DIR"

as_builder() {
	runuser -u builder -- env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
		CARGO_TERM_COLOR=always CARGO_INCREMENTAL=0 RUST_BACKTRACE=1 \
		YRX_REGENERATE_MODULES_RS=false "$@"
}

# paru builds with cargo, which the rustup package provides.
as_builder rustup toolchain install stable --profile minimal
as_builder rustup default stable

# AUR helpers from pinned AUR commits; makepkg verifies the release archive
# each PKGBUILD names against its recorded checksum. paru builds from source:
# paru-bin 2.1.0, the latest, links libalpm.so.15, older than this image's.
build_aur() {
	# The package and commit reach the inner shell as arguments, not as text.
	# shellcheck disable=SC2016 # expanded by the inner shell, on purpose
	as_builder sh -euc 'cd /tmp && git clone -q "https://aur.archlinux.org/$1.git" \
		&& cd "$1" && git checkout -q "$2" && makepkg --syncdeps --install --noconfirm' \
		build_aur "$1" "$2"
}
build_aur yay-bin 13e0a4754d106a9252b7479bf1b370fbe454fc48
# "Add support for libalpm16"
build_aur paru 329be2113c590046cb29858c23d9b96a8d7bd586

root_tools=""
user_tools=""
for tool in $(echo "$HOOD_REQUIRE_TOOL_INTEGRATION" | tr ',' ' '); do
	case "$tool" in
	pacman) root_tools="$root_tools,$tool" ;;
	*) user_tools="$user_tools,$tool" ;;
	esac
done

# The unprivileged pass builds the suite; the root pass reuses that build. A
# pass with no tools to require is skipped, since an empty list is an error.
if [ -n "$user_tools" ]; then
	as_builder env HOOD_REQUIRE_TOOL_INTEGRATION="${user_tools#,}" \
		cargo test --locked --release --test tool_integration -- --test-threads=1
else
	as_builder cargo test --locked --release --test tool_integration --no-run
fi
if [ -n "$root_tools" ]; then
	RUSTUP_HOME=/home/builder/.rustup CARGO_HOME=/home/builder/.cargo \
		run_tests "${root_tools#,}"
fi
