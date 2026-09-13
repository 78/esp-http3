#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/esp-http3-tests.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
mode=${1:-all}
case "$mode" in
    all|loss|frames|ack|packet|h3|connection|path|async) ;;
    *) echo "Usage: $0 [all|loss|frames|ack|packet|h3|connection|path|async]" >&2; exit 2 ;;
esac
if [[ "$mode" == "all" || "$mode" == "loss" || "$mode" == "frames" || "$mode" == "ack" ]]; then
"${CXX:-clang++}" -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$root/tests/host/stubs" -I"$root/include" \
    "$root/tests/host/transport_regression.cc" \
    "$root/src/core/ack_manager.cc" "$root/src/core/loss_detector.cc" \
    "$root/src/quic/quic_frame.cc" "$root/src/quic/quic_varint.cc" "$root/src/quic/quic_types.cc" \
    -o "$build_dir/transport_regression"
"$build_dir/transport_regression" "${1:-all}"

fi

if [[ "${1:-all}" == "all" || "${1:-all}" == "packet" ]]; then
    "${CXX:-clang++}" -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$root/tests/host/stubs" -I"$root/include" \
        "$root/tests/host/packet_regression.cc" "$root/src/quic/quic_packet.cc" \
        "$root/src/quic/quic_varint.cc" "$root/src/quic/quic_types.cc" \
        -o "$build_dir/packet_regression"
    "$build_dir/packet_regression"
fi

if [[ "${1:-all}" == "all" || "${1:-all}" == "h3" ]]; then
    "${CXX:-clang++}" -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$root/tests/host/stubs" -I"$root/include" \
        "$root/tests/host/h3_reassembly_regression.cc" \
        "$root/src/h3/h3_handler.cc" "$root/src/h3/h3_frame.cc" \
        "$root/src/quic/quic_varint.cc" "$root/src/quic/quic_types.cc" \
        -o "$build_dir/h3_reassembly_regression"
    "$build_dir/h3_reassembly_regression"
fi

if [[ "$mode" == "all" || "$mode" == "connection" ]]; then
    bash "$root/tests/host/run_connection_ack.sh"
fi

if [[ "$mode" == "all" || "$mode" == "async" ]]; then
    bash "$root/tests/client/run.sh"
fi

if [[ "$mode" == "all" || "$mode" == "path" ]]; then
    bash "$root/tests/host/run_connection_path.sh"
fi
