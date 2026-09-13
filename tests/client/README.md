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

Pass a case name to run it individually. All six failed against the pre-fix
client and pass with the fixes. These tests validate client lifetime and failure
reporting; the QUIC packet engine and FreeRTOS scheduling are outside this
harness. Build output is temporary and removed on exit.
