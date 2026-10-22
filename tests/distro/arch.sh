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

# AUR helpers from pinned AUR commits; makepkg verifies the release archive
# each PKGBUILD names against its recorded checksum.
build_aur() {
	as_builder sh -euc "cd /tmp && git clone -q https://aur.archlinux.org/$1.git \
		&& cd $1 && git checkout -q $2 && makepkg --syncdeps --install --noconfirm"
}
build_aur yay-bin 13e0a4754d106a9252b7479bf1b370fbe454fc48
build_aur paru-bin 92a55429afbec4fceeb2cef843245105307444d2

as_builder rustup toolchain install stable --profile minimal
as_builder rustup default stable

root_tools=""
user_tools=""
for tool in $(echo "$HOOD_REQUIRE_TOOL_INTEGRATION" | tr ',' ' '); do
	case "$tool" in
	pacman) root_tools="$root_tools,$tool" ;;
	*) user_tools="$user_tools,$tool" ;;
	esac
done

# The unprivileged pass builds the suite; the root pass reuses that build.
as_builder env HOOD_REQUIRE_TOOL_INTEGRATION="${user_tools#,}" \
	cargo test --locked --release --test tool_integration -- --test-threads=1
RUSTUP_HOME=/home/builder/.rustup CARGO_HOME=/home/builder/.cargo \
	run_tests "${root_tools#,}"
