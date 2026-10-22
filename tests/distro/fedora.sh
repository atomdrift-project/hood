#!/bin/sh
# Fedora: dnf, yum (dnf5's alias), and rpm, as root.
. "$(dirname "$0")/common.sh"

dnf install -y --setopt=install_weak_deps=False \
	gcc gcc-c++ make cmake clang perl git curl rustup rpm-build createrepo_c
install_rust
PATH="$HOME/.cargo/bin:$PATH"
run_tests "$HOOD_REQUIRE_TOOL_INTEGRATION"
