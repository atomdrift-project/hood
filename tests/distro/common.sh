# Shared by the distribution scripts, which CI runs as root inside each
# distribution's container with this checkout mounted read-only at /src:
#
#   docker run --rm -e HOOD_REQUIRE_TOOL_INTEGRATION -v "$PWD:/src:ro" -w /src \
#     IMAGE sh tests/distro/DISTRO.sh
#
# HOOD_REQUIRE_TOOL_INTEGRATION names the commands that must be tested.

set -eu

: "${HOOD_REQUIRE_TOOL_INTEGRATION:?set to the commands this image must test}"
export CARGO_TARGET_DIR=/tmp/target
export CARGO_TERM_COLOR=always CARGO_INCREMENTAL=0 RUST_BACKTRACE=1
export YRX_REGENERATE_MODULES_RS=false

# Install the stable toolchain with the distribution's rustup package, which
# ships either `rustup-init` or an uninitialized `rustup`.
install_rust() {
	if command -v rustup-init >/dev/null 2>&1; then
		rustup-init -y --profile minimal --default-toolchain stable --no-modify-path
	else
		rustup toolchain install stable --profile minimal
		rustup default stable
	fi
}

# Run the tool integration suite, requiring the named commands.
run_tests() {
	HOOD_REQUIRE_TOOL_INTEGRATION="$1" cargo test --locked --release \
		--test tool_integration -- --test-threads=1
}
