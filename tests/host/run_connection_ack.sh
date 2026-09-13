#!/usr/bin/env bash
set -euo pipefail
root=${ESP_HTTP3_TEST_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
test_dir=$(cd "$(dirname "$0")" && pwd)
source=${ESP_HTTP3_CONNECTION_SOURCE:-$root/src/core/quic_connection.cc}
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/esp-http3-connection-tests.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
# Compile actual production method bodies against a small connection fixture;
# avoid maintaining copies of the behavior under test or requiring ESP-IDF/TLS.
python3 - "$source" "$build_dir/connection_methods.inc" <<'PY'
from pathlib import Path
import re
import sys
source = Path(sys.argv[1]).read_text()
methods = ['SendStreamData', 'HandlePto', 'BeginBatch', 'EndBatch',
           'SendClientFinished', 'SendAckIfNeeded', 'SendCoalescedAcks']
result = []
for method in methods:
    match = re.search(r'^(?:bool|void) QuicConnection::Impl::' + method + r'\(', source, re.M)
    if match is None:
        raise SystemExit('Missing production method: ' + method)
    end = source.index('\n}\n', match.start()) + 3
    result.append(source[match.start():end])
Path(sys.argv[2]).write_text('\n'.join(result))
PY
"${CXX:-clang++}" -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$root/tests/host/stubs" -I"$root/include" -I"$build_dir" \
    "$test_dir/connection_ack_regression.cc" \
    "$root/src/core/ack_manager.cc" "$root/src/core/loss_detector.cc" "$root/src/core/flow_controller.cc" \
    "$root/src/quic/quic_frame.cc" "$root/src/quic/quic_varint.cc" "$root/src/quic/quic_types.cc" \
    -o "$build_dir/connection_ack_regression"
"$build_dir/connection_ack_regression" "${1:-all}"
