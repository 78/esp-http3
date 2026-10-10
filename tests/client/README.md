# Client lifecycle regressions

Run from the component root:

```sh
bash tests/client/run.sh
```

Requires Clang, AddressSanitizer and UndefinedBehaviorSanitizer. Compiles the
production asynchronous client and scheduler with deterministic QUIC and RTOS
adapters. No socket server, firmware build or hardware is required. The QUIC
adapter starts stream IDs at zero for each new connection, and test code drives
connection callbacks under the same mutex as the production event loop.

Cases:

- `registration`: A response arrives between transport request submission and
  receive-buffer allocation. Headers/body must reach the returned stream.
- `reconnect`: Writes and FIN from a previous connection must not target a reused
  stream ID, and stream handles may outlive the client.
- `reconnect_close`: Closing the old stream must neither reset nor unregister
  the new stream with the same ID.
- `detached`: A handle from a disconnected connection is safe to destroy after
  its client, including after a new stream has reused its ID.
- `write`: A rejected transport write must return an error to the caller and
  clear the queue, rather than reporting the body length as written.
- `finish`: Failure to send a queued FIN must mark the stream as failed.
- `close_fin`: Response FIN arrives under the transport lock while `Close()` is
  waiting to acquire it. Completion must remain observable after the handle is
  marked closed, and unregistering it must not reset the completed stream.
- `cancel`: Closing an unfinished response still resets that active stream.

Pass a case name to run it individually. The first six failed against the
earlier client and pass with the fixes. The close/FIN case also fails against
the client before its completion-race fix. These tests validate client lifetime and failure
reporting; the QUIC packet engine and FreeRTOS scheduling are outside this
harness. Build output is temporary and removed on exit.

Gzip response cases (production framing/decoding/client code; only the ESP ROM
tinfl and CRC boundary uses a host zlib adapter):

- `gzip_chunks`: 7-byte network chunks, a 53-byte receive ring and 17-byte reads
  exercise wire ring wrap, repeated 32 KiB decode history, compressed-byte flow
  control and metrics. Data is readable before FIN, while EOF waits for FIN;
  normal close preserves the connection and sends no reset.
- `gzip_members`: every header byte arrives separately, including extra data,
  filename, comment and header CRC; concatenated members produce one body.
- `gzip_errors`: every truncation offset, body CRC, ISIZE, header CRC, reserved
  flags, trailing garbage, expansion bounds and a valid empty body.
- `encoding`: identity/missing encoding, unsupported/chained/duplicate encodings,
  decoded identity bounds, blocking `Read()` and unchanged raw consumer behavior.
- `no_content`: HEAD, 204 and 304 responses complete on FIN without a decoder,
  even with encoding headers; unexpected body bytes fail.
- `gzip_legacy`: the adapter simulates miniz 1.15 trailer read-ahead with nonzero
  padding bits and DONE delayed to a later call. Tests include a split trailer
  with no current input at DONE, CRC failure and exact compressed-byte flow
  control. Chunking, members and truncations run in both legacy modes as well.

The runner also requires system zlib. Host timing is not an ESP32 performance
measurement; device decoding and memory usage must be verified on hardware.
