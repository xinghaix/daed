# Protocol Engineering Lessons

Frozen artifact for this review: `ae9f25d31dcf7f896774ec1a4eed03c9155a0921` plus the uncommitted lifecycle/header fixes in hysteria2, tuic, juicity, and trojanc.

These rules come from defects that were independently reproduced, not from style preference. A later change that violates one of them needs an explicit comment or test explaining why this protocol is different.

## 1. Ownership survives the last `Release`

A pooled datagram/buffer is not safe just because `Release`/`pool.Put` was called the right number of times. Any slice still aliased into that backing array is a use-after-release.

- Copy or take ownership of every field that outlives the pool buffer (`Addr`, `Data`, SOCKS address bytes, mapped packet payloads).
- Clear the original `Release` when the returned object no longer owns that buffer.
- Poison-on-release tests are the evidence. Counting `Release` calls is not.

Canonical case: hysteria2 fragment reassembly used to copy `Data`, call `releaseHeld()`, and return `m` whose `Addr` still aliased the trigger fragment. A later pool `Get` rewrote the UDP source address. The fix copies `Addr` first.

## 2. Frame boundaries are not optional

Length-prefixed or authenticated frames must either:

1. deliver exactly one complete frame into the caller buffer, or
2. drain/discard the remainder so the next read starts at the next frame, or
3. make the connection unusable with a sticky error.

Returning `"buffer too small"` after consuming the length prefix, then leaving the payload in the stream, permanently desynchronizes every later read.

Canonical cases:

- `protocol/vless/packet.go` and `protocol/vless/vision/packet.go` return on a short caller buffer without draining.
- `protocol/trojanc/packet.go` already discards the remainder; that is the required shape.
- `protocol/vmess/conn.go` leaves unread AEAD chunk tails in `leftToRead` and the packet-addr path can return them as a second datagram.

`ReadFrom` must never return `n > len(p)`. dae's UDP loop does `buf[:n]` (`control/udp_endpoint_watcher.go`).

## 3. Handshake/state commits happen after successful I/O

`onceWrite`, nonces, IVs, salts, and padding counters are protocol state. They must not advance until the corresponding bytes have actually left the process, or the connection must be marked dead so a retry cannot send a different transcript.

Do not:

- set `onceWrite = true` then `initWrite` then write
- `Encrypt`/`Seal`/advance nonce, ignore `Write`'s `n`, return `len(b)` on `err == nil`
- treat a short write with `err == nil` as success

Go's `io.Writer` contract says short writes should return an error, but underlays in this stack (TLS, ws, obfs, net.Conn wrappers) have historically returned `(n < len(b), nil)`. Framing code must loop or fail.

Canonical cases: Shadowsocks AEAD/2022/stream TCP, AnyTLS `writeFrameWithDeadline` / `writeConnLocked`.

## 4. Serialize one-shot handshake, not the steady-state copy

dae TCP relay is one reader plus one writer. UDP is one read loop plus writes.

- Header parse / first-write salt belongs in `sync.Once`, a one-shot mutex, or an atomic flag checked under the existing direction lock.
- Do **not** hold a mutex across every payload `Read`/`Write` unless that direction already owns reusable scratch (Shadowsocks nonce, packet write buffer).
- `atomic.Bool` for a one-bit handshake flag is enough for the opposite direction to observe it; do not make `Read` take `writeMutex`.

Canonical case: Juicity/Trojan server header used unsynchronized `readHeaderDone`. The fix is `headerOnce`. Trojan `onceWrite` moved to `atomic.Bool` so client `Read` no longer races `Write`. Steady-state payload I/O stays lock-free besides the write-side scratch mutex that already existed.

## 5. Close must unblock, and Close must be terminal

`netproxy.Conn` is consumed by dae's relay, which depends on `Close` / `SetReadDeadline` unblocking a blocked `Read`.

- If `Read` waits on a handshake context, `Close` must cancel that context even when the underlay is still nil.
- Logical HTTP/2 CONNECT streams must close the request pipe and response body. Skipping that because "the pooled conn is shared" leaks streams until `maxConcurrentStreams` forces extra physical connections.
- A closed client ring / dialer must refuse later `Dial`. Recreating a fresh client after `Close` contradicts teardown and leaks QUIC/UDP sockets across dae reload.

Canonical cases: `protocol/http.Conn.Close`, `protocol/infra/clientring.Ring.Close`.

## 6. Protocol errors have a protocol-sized blast radius

Classify errors by the RFC/spec recovery unit, not by whichever Go type is convenient.

- QPACK field-section decode failure is a connection error (`QPACK_DECOMPRESSION_FAILED`), not a stream cancel.
- QUIC `StatelessResetError.Temporary() == true` does not mean "retry `ReceiveDatagram` forever". After close, the datagram queue returns immediately; spin is a CPU bug. Exit via `quicConn.Context()`.
- `sync.Once` is not a publish/reload primitive. `InitDirectDialers` cannot apply a new `fallback_resolver` after the first call.

## 7. Tests must mirror the real evidence dimension

| Claim | Insufficient evidence | Required evidence |
| --- | --- | --- |
| buffer ownership | `Release` call count | poison backing array on `Release`, assert consumer still sees the original bytes |
| concurrent header parse | sequential header tests | two goroutines `Read` the same server conn; assert bytes delivered == payload, not 2×header |
| handshake flag race | `-race` on sequential tests | concurrent `Read`+`Write` on the client conn |
| close unblocks | `Close` returns nil | blocked `Read` returns after `Close` without a later `Write` |
| short write | happy-path roundtrip | underlay `Write` returns `(len/2, nil)` and `(n, err)` after sealing |
| datagram too large | only `maxSize > header` | `maxSize <= HeaderSize` must not panic |
| reload | first-boot init | second `Init*` with a different value is observed |

`go test -race` green on the old suite never proved the three bugs that started this work.

## 8. Performance guardrails

These are allowed costs:

- copy a short address (`< 64B`) when taking ownership of a pooled datagram
- one atomic load per Read after handshake completion (`sync.Once` / `atomic.Bool`)
- `Context().Err()` only on the temporary-error path

These are not:

- mutex around every payload Read
- busy-looping a closed datagram queue (measured ~3.6e6 iter/s)
- allocating a new 4KB buffer per HY2 UDP session when a pool already exists

If a correctness fix appears to require serializing the hot path, the fix is probably at the wrong layer (copy the alias, drain the frame, or fail sticky).
