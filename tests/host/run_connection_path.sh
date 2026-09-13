#!/usr/bin/env bash
set -euo pipefail
root=${ESP_HTTP3_TEST_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
test_dir=$(cd "$(dirname "$0")" && pwd)
source=${ESP_HTTP3_CONNECTION_SOURCE:-$root/src/core/quic_connection.cc}
mode=${1:-all}
case "$mode" in
    all|challenge|unsolicited|response-loss|retire|limit|invalid-retire|cid-loss|retire-loss|batch-loss|retired-loss|retired-batch-loss|malformed|send-failure|history) ;;
    *) echo "Unknown connection path test: $mode" >&2; exit 2 ;;
esac
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/esp-http3-path-tests.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
# Extract production bodies at runtime: no copied dispatcher or CID behavior.
python3 - "$source" "$build_dir" "$root" <<'PY'
from pathlib import Path
import re
import sys
source = Path(sys.argv[1]).read_text()
packet_source = (Path(sys.argv[3]) / 'src/quic/quic_packet.cc').read_text()
begin = packet_source.index('size_t GetPacketNumberLength(')
end = packet_source.index('\n}\n', begin) + 3
(Path(sys.argv[2]) / 'packet_number_method.inc').write_text(packet_source[begin:end])
out = Path(sys.argv[2])
methods = ['ProcessFrames', 'OnFramePathChallenge', 'OnFramePathResponse',
           'SendPathChallenge', 'SendNewConnectionId', 'SendRetireConnectionId',
           'BeginBatch', 'EndBatch', 'SendStreamData', 'RetransmitLostPackets',
           'SendPtoProbe']
optional = ['InitializeLocalConnectionIds', 'EnsureLocalConnectionIdSupply',
            'OnFrameRetireConnectionId', 'PruneRetiredConnectionIdFrames']
result = []
features = []
for method in methods + optional:
    match = re.search(r'^(?:bool|void) QuicConnection::Impl::' + method + r'\(', source, re.M)
    if match is None:
        if method in optional:
            continue
        raise SystemExit('Missing production method: ' + method)
    features.append('#define HAS_' + method + ' 1')
    end = source.index('\n}\n', match.start()) + 3
    result.append(source[match.start():end])
(out / 'connection_path_features.inc').write_text('\n'.join(features))
(out / 'connection_path_methods.inc').write_text('\n'.join(result))
# Read the exact state layout too, so new production bookkeeping isn't duplicated.
state = []
for start, end in [('    // Connection IDs\n', '    // Crypto manager'),
                   ('    // Path Validation state\n', '    // DATAGRAM state'),
                   ('    struct BatchState {', '\n    BatchState batch_state_;')]:
    begin = source.index(start)
    finish = source.index(end, begin)
    state.append(source[begin:finish])
(out / 'connection_path_state.inc').write_text('\n'.join(state))
PY
"${CXX:-clang++}" -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$root/tests/host/stubs" -I"$root/include" -I"$build_dir" \
    "$test_dir/connection_path_regression.cc" \
    "$root/src/core/ack_manager.cc" "$root/src/core/loss_detector.cc" "$root/src/core/flow_controller.cc" \
    "$root/src/quic/quic_frame.cc" "$root/src/quic/quic_varint.cc" "$root/src/quic/quic_types.cc" \
    -o "$build_dir/connection_path_regression"
"$build_dir/connection_path_regression" "$mode"
