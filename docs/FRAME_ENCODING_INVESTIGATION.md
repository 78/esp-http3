# 2026-09-13 QUIC frame encoding investigation

The Caddy compatibility observation recorded seven FRAME_ENCODING_ERROR errors:
unknown frame types and one truncated STREAM frame (0x0e, EOF). These occur while
parsing decrypted QUIC payloads, unlike the earlier receive-key-update failure.
Ordinary reordering does not make a well-formed QUIC frame malformed, but it can
exercise defective loss recovery or generate many disjoint ACK ranges.

## Reproduced defects and fixes

1. `LossDetector::OnAckReceived` passed pointers into the sent-packet vector to
   its loss callback. `RetransmitLostPackets` appended each replacement packet
   into that same vector. Reallocation or pruning could invalidate pointers for
   the remaining lost packets. A host test reproduces heap-use-after-free with
   AddressSanitizer. The callback now receives pointers to owned snapshots;
   frame allocations are moved out of already-lost entries before the callback,
   avoiding copies of the payload buffers. Snapshot pointers are valid only for
   the duration of the callback, as before.
2. `BuildStreamFrame` and `BuildAckFrame` could return false after advancing the
   writer partway through a frame. Batch sending, optional ACK piggybacking and
   probe construction could subsequently send the partial frame. Both builders
   now check complete encoded size before writing, leaving the offset unchanged
   on failure. A failed STREAM write does not change flow-control offsets.
3. Sparse reception could exceed the small ACK buffer's capacity. ACK generation
   now retains the newest complete ranges that fit, including the range-count
   varint width in its budget. It never acknowledges missing packet numbers.

The loss callback defect and unbounded ACK construction also exist in component
1.5.1 (2e5e23f), so these are not defects introduced solely by the Caddy patch.
The exact seven production incidents remain unassigned: server error strings
alone cannot distinguish corrupted sender buffers from all other causes. Further
attribution requires the affected device's build and packet/serial diagnostics.

## Validation and deployment

See [host tests](../tests/host/README.md). Regression cases first failed on the
original implementation, then passed under ASan and UBSan after the fix. The
tests compile affected production implementation files, including their parsers.
The original frame investigation used host tests only. The subsequent release
review and current validation are recorded in
[1.6.2 release review](RELEASE_REVIEW_1.6.2.md). Deployed old firmware does not
receive these fixes until a new firmware containing the component is installed.
