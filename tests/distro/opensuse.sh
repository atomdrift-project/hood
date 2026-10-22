#!/bin/sh
# openSUSE Tumbleweed: zypper, as root.
. "$(dirname "$0")/common.sh"

zypper --non-interactive install --no-recommends \
	gcc gcc-c++ make cmake clang perl git curl rustup rpm-build createrepo_c
install_rust
PATH="$HOME/.cargo/bin:$PATH"
run_tests "$HOOD_REQUIRE_TOOL_INTEGRATION"
