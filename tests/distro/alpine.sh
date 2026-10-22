#!/bin/sh
# Alpine: apk, as root. The fixture is an apk v2 package indexed with
# `apk index`, so the image is pinned to an apk-tools 2 release.
. "$(dirname "$0")/common.sh"

apk add --no-cache build-base cmake clang perl git curl linux-headers rustup
install_rust
PATH="$HOME/.cargo/bin:$PATH"
run_tests "$HOOD_REQUIRE_TOOL_INTEGRATION"
