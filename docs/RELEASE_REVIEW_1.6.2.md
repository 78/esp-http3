# esp-http3 1.6.2 release review

Reviewed on 2026-09-13, with a path-validation follow-up on 2026-09-14,
based on component 1.6.1 (`361154f`) plus the local
1.6.2 candidate. The existing version changes belong to the release preparation.
This review does not publish the component or update devices.

## Confirmed fixes

- Loss retransmission callbacks own snapshots while appending/pruning the packet
  tracker, preventing dangling packet/frame pointers. STREAM and ACK builders
  preflight complete frames; sparse outgoing ACKs retain only ranges that fit.
  See [frame investigation](FRAME_ENCODING_INVESTIGATION.md).
- Incoming ACK processing applies all ranges, not just the first one. Invalid
  range arithmetic is rejected before acknowledging packets. This avoids
  treating selectively acknowledged packets as outstanding during reordering.
- Initial packets size the header for the actual Retry token and reject an
  oversized token before copying it. The previous 256-byte allocation overflowed
  for normal larger opaque tokens. Handshake and 1-RTT builders check output
  capacity before writing their headers.
- Initial, Handshake and 1-RTT packets add enough PADDING for the full 16-byte
  header-protection sample at packet-number offset plus four. A one-byte PING
  with a one- or two-byte packet number previously produced a packet that a
  compliant receiver could not unprotect.

- Required STREAM, handshake Finished and PTO PING frames are written before
  optional ACK ranges. Application frame buffers reserve room for the encrypted
  packet header and authentication tag. ACK scheduling state is cleared only
  after the packet is successfully sent, including batch and handshake paths.
- Server unidirectional streams use offset-based reassembly before parsing their
  stream type or control frames. Retransmitted prefixes and out-of-order SETTINGS
  no longer corrupt the control buffer; QPACK streams retain absolute offsets
  after their buffers are drained.
- Stream objects are initialized before opening a request and registered before
  releasing the connection lock. Disconnect detaches old stream objects and
  clears queued writes. Instance validation prevents old handles from closing,
  finishing, writing to, or advancing flow control on a new stream with a reused
  ID. Callback and close paths serialize access to the stream registry.
- Upload queue write/FIN errors fail the affected stream instead of signaling a
  successful write. Completion notification remains inside the connection lock
  so an old connection cannot deliver it to a new stream with the same ID.
- The active receive dispatcher handles RETIRE_CONNECTION_ID, PATH_CHALLENGE
  and PATH_RESPONSE without dropping the rest of the packet. Challenges receive
  an exact eight-byte echo in a 1200-byte UDP datagram. Unsolicited responses
  cannot validate a path; duplicate packet numbers within the existing receive
  window do not repeat frame delivery.
- The handshake SCID is registered as sequence 0. A bounded supply of local CIDs
  respects the peer limit and replenishes retired IDs. Invalid retirement of an
  unissued sequence or the containing packet's DCID is rejected. NEW/RETIRE CID
  frames survive loss/PTO and request cancellation, including initialization
  batches; advertisements of retired local CIDs are removed from retransmission.
  See [path migration and device retest notes](PATH_MIGRATION.md).

## Validation

- `bash tests/host/run.sh`: all six suites passed with ASan and UBSan
  (transport, packet, H3 reassembly, connection ACK, client lifecycle and
  path/CID). The new suite covers 14 case groups. Challenge dispatch,
  unsolicited response, retirement/refill, CID limit and standalone/batched CID
  retransmission regressions were also observed failing on the pre-fix source.
- All patched source, test and documentation files were compared byte-for-byte
  with the validated staging copy after applying the patch to the component.
- ESP32-S3 cross-compilation passed for the affected translation units, including
  both clients and the asynchronous scheduler against the updated private API.
- Full Pocket Sage firmware build passed with ESP-IDF **6.0.2**, using
  `/Users/terrence/.espressif/tools/python/v6.0.2/venv/bin/python3` and that
  installation's `tools/idf.py build`. Compile, link and partition-size checks
  passed. Image size: `0x25b4d0` bytes; application partition has 20% free.
  SHA-256: `ba859432a8252069aa6b62b11d2a4e1af408a43e5ae9233f3550ecb110254301`.
- `git diff --check` passed. The parent's existing version and modem-debug
  changes are preserved; this follow-up changed no tracked parent files.

Tests compile production sources with host platform/crypto stand-ins where
necessary. Packet layout tests exercise memory copies and encoded bounds; they
do not validate AES-GCM itself. The concurrency fixture does not replace real
FreeRTOS scheduling, and the path fixture does not exercise real UDP or the
complete authenticated receive path. These fixes do not establish the exact
cause of every observed server frame error or 4G outage.

No commit, tag, component publication, firmware flash or OTA rollout was done.
Before broad deployment, run the resulting firmware on a device through repeated
cancel/new requests, Wi-Fi loss/reconnect, idle expiry and long streaming uploads.
Check for frame/decrypt errors, truncated uploads and heap regressions. This
review is a targeted release preflight, not exhaustive QUIC conformance testing.
