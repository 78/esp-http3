#!/usr/bin/env bash
set -euo pipefail
test_dir=$(cd "$(dirname "$0")" && pwd)
component=$(cd "$test_dir/../.." && pwd)
source_root=${HTTP3_CLIENT_SOURCE_ROOT:-$component}
header_root=${HTTP3_COMPONENT_HEADER_ROOT:-$source_root}
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/esp-http3-client-tests.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
"${CXX:-clang++}" -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -pthread \
  -I"$test_dir/stubs" -I"$source_root/include" -I"$header_root/include" \
  "$test_dir/client_lifetime_regression.cc" \
  "$source_root/src/client/http3_async_client.cc" \
  "$source_root/src/client/http3_async_scheduler.cc" -o "$build_dir/client_lifetime_regression"
"$build_dir/client_lifetime_regression" "${1:-all}"
