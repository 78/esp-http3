# Host regression tests

Run every suite from the component root:

```sh
bash tests/host/run.sh
```

Requires Clang with AddressSanitizer and UndefinedBehaviorSanitizer, Bash and
Python 3. Build output is temporary and removed on exit. The command does not
build or flash firmware.

Individual groups: `loss`, `frames`, `ack`, `packet`, `h3`, `connection`, `path`, `async`.
For example: `bash tests/host/run.sh packet`.

- Transport tests compile the actual ACK, loss detection, frame and varint
  sources with host logging, timer and heap adapters. They cover loss callbacks
  while the sender vector reallocates/compacts, atomic frame construction,
  sparse outgoing ACKs at capacities 0–300, all incoming ACK ranges and rejected
  range underflow without partial acknowledgement.
- Packet tests compile the real packet builders with deterministic AEAD/header
  protection stand-ins. They cover long Retry tokens, insufficient output
  capacity, and the required header-protection sample for all packet-number
  widths and plaintext lengths 0–4. They test packet layout and memory bounds,
  not cryptographic primitives.
- HTTP/3 tests compile the actual handler and codec. They cover reordered and
  retransmitted control prefixes, late offset-zero data, absolute QPACK offsets
  after buffer drainage, and request body/FIN reassembly.
- Connection tests extract seven actual production method bodies at test time,
  then compile them with real ACK/frame/tracker/flow implementations and a small
  transport fixture. They cover sparse STREAM, PTO, batch and Client Finished
  paths, ACK-free retransmission data, and pending ACK preservation after failed
  packet construction or socket sends. The extraction fails if a method cannot
  be found; it does not maintain copied production behavior.
- Path/CID tests extract the active `QuicConnection::Impl::ProcessFrames`, path
  response, CID lifecycle, batch and loss/PTO method bodies, plus their production
  state layout. They verify challenge echo, a 1200-byte response and continued
  STREAM parsing; unsolicited/mismatched/replayed responses; malformed path
  frames; CID 0 retirement and replenishment, duplicate/invalid retirement,
  peer/local CID limits; reliable NEW/RETIRE delivery through loss and PTO; mixed
  initialization STREAM/NEW batches; filtering retired CIDs while retaining
  STREAM data; control frames surviving stream-0 cleanup; and PATH_RESPONSE not
  being retransmitted; packet-build rollback versus reliable retry after socket
  send failure; and the ACK manager's bounded received-packet history/reset.
  Packet encryption and socket sends are stand-ins; the
  actual frame codecs, tracker and loss detector are compiled. The STREAM sink
  records dispatch using the real parser, without starting HTTP/3. This fixture
  enters after packet decryption and does not test packet-number deduplication,
  destination-CID authentication, socket-address migration or live networking.
  The handshake caller's close-on-initial-batch-failure branch is not extracted.
- [Client lifecycle tests](../client/README.md) compile the actual asynchronous
  client and scheduler with deterministic QUIC and FreeRTOS stand-ins. They
  cover response registration, reconnect identity, detached handles, and upload
  write/FIN failures.

Representative regressions first failed on the pre-fix implementations and pass
with the candidate under ASan/UBSan. These establish implementation defects and
repairs; they do not prove that every observed server error had the same cause,
replace ESP-IDF compilation, or validate real FreeRTOS scheduling and Wi-Fi.

The path/CID suite can be run alone with `bash tests/host/run.sh path`, or an
individual case with `bash tests/host/run_connection_path.sh challenge`. Cases
are listed in that runner. To compare an older connection implementation with
the current tests without editing source:

```sh
ESP_HTTP3_CONNECTION_SOURCE=/absolute/path/to/old/quic_connection.cc \
  bash tests/host/run_connection_path.sh challenge
```

The pre-fix connection fails the challenge dispatch, unsolicited response,
standalone CID retransmission and mixed initialization batch retransmission
cases. Older sources lacking the new CID initialization helper receive only the
fixture's handshake CID-0 state; the tests do not supply fallback CID lifecycle
or dispatch behavior.
