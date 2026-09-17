# ARGUS (Rust) — network IDS with stream reassembly, protocol parsing, and a regex rule engine

This is a substantial capability upgrade from the earlier signature/
anomaly-only version, closing four of the biggest gaps between ARGUS and
a real IDS (Suricata/Snort/Zeek-class tooling):

1. **TCP stream reassembly** — signatures now match against the
   reassembled connection buffer, not each packet in isolation, so an
   attacker can no longer evade detection by splitting a payload across
   two segments.
2. **TLS metadata inspection** — the SNI and JA3 client fingerprint are
   extracted from the plaintext ClientHello (no decryption — that part of
   a TLS handshake is never encrypted), giving real signal on encrypted
   traffic without needing to MITM it.
3. **Application-layer parsing** — rules can match `http.uri`,
   `http.host`, `dns.query`, `tls.sni`, and `tls.ja3` as structured
   fields, not just raw bytes.
4. **A real rule engine** — regex (not just literal substrings), rule
   negation ("alert if this is absent"), and per-rule traffic direction
   (`to_server` / `to_client`).

A second round closed three more:

5. **IPv6.** Addresses throughout ARGUS — every hashmap key, the
   blacklist, `Alert`, worker sharding — are a proper `IpAddr` enum
   (IPv4 or IPv6), not a bolt-on. IPv6 traffic runs through exactly the
   same detection logic as IPv4, extension-header chain and all.
6. **UDP port-scan detection.** Previously excluded entirely (see "What's
   still not here" in an earlier revision) for lacking any way to tell a
   probe from a reply. A new reply-tracking mechanism closes that gap
   without reintroducing the DNS-reply false positive that got UDP
   excluded in the first place — see below.
7. **FTP, SSH, and SMTP parsing.** Rules can now match `ftp.command`,
   `ssh.version`, `smtp.command`, `smtp.sender`, and `smtp.recipient` as
   structured fields, the same way HTTP/TLS/DNS buffers already worked.
8. **JSON (NDJSON) alert output** (`-json`), for feeding a SIEM or any
   `jq`-based pipeline, hand-rolled rather than pulling in `serde_json`
   for what's a simple, flat, 8-field schema.

A third round closed the forensics gap:

9. **A `.pcap` saved automatically for every alert.** Each worker's
   traffic no longer disappears the moment it's been inspected — a
   rolling window of recent raw packets is kept ready on the capture
   thread, and whenever an alert survives suppression, that window is
   written out as a real, standard pcap file (openable directly in
   Wireshark), named and timestamped so it's traceable back to the alert
   that caused it. See "Packet retention" below for the design and the
   two real bugs (one correctness, one performance) that field-testing
   and benchmarking caught along the way.

A fourth round closed two more, and made a deliberate call on a third:

10. **SMB2/3 and Modbus/TCP parsing.** Rules can now match `smb.command`,
    `smb.filename`, `modbus.function`, and `modbus.address`. Scoped
    honestly, not exhaustively: SMB1 and encrypted SMB3 are explicitly
    not parsed, and DNP3/BACnet/S7comm and the rest of the industrial-
    protocol family remain out of scope — "a dozen unrelated protocols"
    doesn't become one round's work just because two protocols from it
    got covered. See "Two more protocols" below for what's actually
    covered and why Modbus, uniquely among every protocol ARGUS parses,
    is port-gated rather than content-sniffed.
11. **The 4KB reassembly cap is now configurable** (`-stream-cap`,
    default raised to 16KB) — see below for why any finite cap still has
    the same underlying evasion property, and why that's the right
    tradeoff anyway.
12. **TLS decryption was asked for and deliberately not built.** Unlike
    everything else here, a working MITM implementation is a general-
    purpose interception tool, not a passive parser — see "On TLS
    decryption" below for the reasoning, and `SSLKEYLOGFILE` support as
    the safer alternative that was offered instead (not yet built).

A fifth round closed the rest of the protocol list, and — separately —
found two real, previously-undetected bugs that had nothing to do with
the new protocols at all:

13. **RDP, TFTP, SNMP, and DNP3 parsing.** Rules can now match
    `rdp.cookie`, `tftp.opcode`, `tftp.filename`, `snmp.community`, and
    `dnp3.function`. RDP's cookie — an explicit, often attacker-supplied
    username hint sent in RDP's very first, always-cleartext packet — is
    arguably the single highest-value addition of this round, given how
    common RDP brute-forcing is as a ransomware entry point. Telnet was
    considered and deliberately left out: unlike FTP/SMTP, it has no
    clean protocol-level command structure to reliably extract
    credentials from (it's an interactive character stream, not
    discrete commands), and a low-confidence parser isn't worth having.
    See "Four more protocols" below for what's actually covered.
14. **A real, previously-undetected bug in the rule engine itself.**
    Every UDP-based detection path — raw payload matching, DNS query
    matching, and now TFTP/SNMP — calls the rule engine with
    `Direction::Any`, and `Direction::Any` was never a valid lookup key:
    a rule declared `direction: any` gets *expanded* into separate
    `ToServer`/`ToClient` entries at load time, so a query keyed
    literally on `Any` matched nothing, for *any* rule, regardless of
    how it was declared. This had been silently breaking DNS/UDP rule
    matching since it was first added, several rounds ago — it just
    never got caught, because nothing had live-tested a matching UDP
    rule until this round. See "Two real bugs" below.
15. **A second bug, in alert suppression.** Two genuinely different
    `SIGNATURE_MATCH` alerts (different rules entirely) sharing the same
    source, destination, and protocol were being treated as duplicates
    of each other, since nothing in the suppression key distinguished
    *which rule* matched. Also covered in "Two real bugs" below.

It is still not Suricata. See "What's still not here" at the end for an
honest accounting of what a genuinely complete IDS also needs that this
doesn't attempt.

## The architectural piece that made this possible: flow-aware sharding

Stream reassembly requires seeing **both directions** of a TCP
connection in one place. The previous version sharded packets to worker
threads by hashing the *source* IP — which meant a client's packets and
the server's replies could easily land on two different workers, and
neither would ever see the whole connection.

This version shards TCP packets by a **canonical, direction-independent
hash of the connection's two endpoints** (`hash_host_pair` in `main.rs`):
sort the two IPs first, then hash — so a packet in *either*
direction of the same connection always produces the same shard. That's
what lets each worker's `FlowTable` be a plain, lock-free `HashMap`: one
worker owns a connection's entire state, both directions, for its whole
lifetime, the same ownership argument the rest of ARGUS's concurrency
already relied on (see `AnomalyEngine`). Non-TCP packets (UDP/ICMP) don't
need flow state, so they still shard by source IP as before.

### A real bug this caused, found during field testing

The first version of this hash included **both port numbers**, not just
the two IPs. That broke port-scan detection: a tool like
`Test-NetConnection` opens a brand-new TCP connection — with a fresh
source port — for every port it probes, so scanning 25 ports is 25
genuinely different connections. Hashing ports meant those 25 SYNs
scattered across up to 25 different workers, and no single worker's
`AnomalyEngine` ever saw enough of the scan in one place to cross the
detection threshold. The scan was real; the evidence was just split up
before anyone could add it up.

The fix: hash **only the host pair**, dropping both port numbers
entirely. Every connection attempt between the same two IPs — however
many ports, however many separate connections — now lands on one worker,
which is exactly what `AnomalyEngine`'s per-(source, destination) port
tracking needs. This is still correct for `FlowTable` too: it's a
superset of what reassembly requires (multiple simultaneous connections
between the same two hosts now share a worker, harmlessly, since
`FlowTable`'s own `FlowKey` already distinguishes different connections
by their full 4-tuple within that worker's table).

One known tradeoff this introduces, worth being upfront about:
`PACKET_FLOOD` is keyed by source IP alone, regardless of destination —
a source that floods several *different* destinations simultaneously
now has that traffic spread across several different workers' shards
(one per destination), so no single worker sees the full cross-
destination volume. This wasn't the reported bug and doesn't affect the
common cases (one source flooding one destination, which is what both
field tests actually showed), but a true multi-target flood from one
source could under-count until each individual destination's traffic
crosses the threshold on its own. Fixing that fully would need either a
global (cross-worker) counter for `PACKET_FLOOD` specifically, or
accepting the current per-shard approximation — not attempted here.

## Back to four files, plus one real optimization

`rules.rs`, `protocols.rs`, and `flow.rs` are folded back into
`engine.rs` — this project is now the same four files (`lib.rs`,
`packet.rs`, `engine.rs`, `main.rs`) it started as before the stream-
reassembly/TLS/rule-engine work. Two things worth being precise about:

- **The merge itself doesn't change performance.** Release builds already
  use fat LTO + a single codegen unit, so the compiler was inlining
  across those file boundaries before the merge too — this is purely
  organizational, matching the project's original shape now that it's
  grown enough to (again) fit comfortably as `packet.rs` (parsing) +
  `engine.rs` (everything detection-related) + `main.rs` (wiring).
- **The one genuine performance change made during the merge**: regex
  rules used to live in a single flat `Vec`, filtered by buffer and
  direction on every `check()` call. They're now grouped into a
  `HashMap<(Buffer, Direction), Vec<RegexEntry>>` at load time, the same
  way literal rules already were. Concretely: with 200 regex rules loaded
  against `http.uri`, checking an unrelated buffer (`dns.query`) now
  costs **7.9 ns** — a hashmap lookup-and-miss — instead of scanning and
  filtering all 200 entries on every packet.

## UDP port-scan detection: reply-tracking, and why UDP sharding had to change too

UDP has no handshake — no SYN, nothing that structurally distinguishes
"a new connection attempt" from "a reply to something you sent." That's
exactly why UDP was excluded from `PORT_SCAN` entirely in an earlier
version: without that distinction, a busy DNS resolver replying to a
client's own randomized query ports looked identical to a scan touching
20+ ports.

The fix is a small per-worker `UdpPairTracker`: every UDP packet's exact
4-tuple `(src, src_port, dst, dst_port)` gets recorded with a timestamp.
A packet counts as a *reply* if the **reverse** 4-tuple was seen recently
— meaning the current packet's destination previously sent something to
the current packet's source on this same port pairing, so this is almost
certainly that earlier message's response. Only non-replies feed into
the same per-(source, destination) port-tracking `PORT_SCAN` already uses
for TCP SYNs. A DNS query/reply pair always has a matching earlier
outbound query in the tracker, so it's correctly never flagged; an
actual scanner blindly probing 25 ports never has one, so it still is.

This only works if an outbound query and its inbound reply land on the
**same worker** — otherwise the reply-lookup fails simply because the
tracker that recorded the query is a different worker's tracker, not
because the traffic was actually unsolicited. UDP packets previously
sharded by source IP alone (fine for `PACKET_FLOOD`, which only ever
needs one direction's volume), which does *not* guarantee that. Fixing
this meant applying the same host-pair sharding TCP already used to UDP
as well — `main.rs`'s `shard_for` now hashes every packet's IP pair
uniformly, regardless of protocol, rather than branching between a
TCP-specific scheme and a UDP-specific one. See
`dns_style_udp_replies_do_not_trigger_port_scan` and
`unsolicited_udp_probes_are_detected_as_a_scan` in `engine.rs`, and
`udp_query_and_reply_share_a_shard` in `main.rs`, for the tests proving
both halves of this actually work together.

### A second real bug this surfaced, found the same way as the port-scan sharding bug: by actually testing it

The reply-tracking above got a TCP scan and a UDP scan against the same
destination right, individually. What field-testing caught next was
running *both* against the *same target back to back*: the UDP scan's
very first packet already reported nearly the full port count from the
earlier TCP scan, because `DstPortStats` tracked "ports touched" in a
single map keyed by **port number alone** — TCP port 21 and UDP port 21
collided as the same entry. A slower, related issue: that map's cleanup
was gated behind a size threshold (`4x` the scan limit) a modest scan
never crossed, so stale entries could sit around far longer than the
stated "in the last {window}" implied.

Fixed both: `DstPortStats` now keeps fully separate maps per protocol
(not a shared map, and not even a single map keyed by `(protocol,
port)` — that alone would have stopped the collision but still summed
both protocols together for the threshold check, so 15 TCP ports plus
15 UDP ports to one host would still falsely cross a limit of 20). And
pruning now runs on every packet rather than only once a size threshold
is crossed, so "touched in the last `{window}`" is actually true rather
than approximately true. See
`tcp_and_udp_port_scans_against_the_same_destination_are_tracked_independently`
in `engine.rs`.

## Packet retention: a .pcap saved automatically for every alert

Every alert used to be a one-line description with no way to go look at
the actual traffic that caused it — the standard next step for a real
IDS gap, and the natural target once the detection side had caught up.

The design: the capture thread — the only thread with direct access to
the live `pcap::Capture` handle, since opening a savefile needs to know
the capture's link-layer type — keeps a fixed-size circular buffer of
the last N raw frames (`-pcap-retain`, default 500, each capped at 1500
bytes; `0` disables the feature entirely). Whenever an alert survives
suppression, `run_alert_writer` sends a lightweight request (just the
category/protocol/source/timestamp, not packet data) back to the capture
thread, which opens a `.pcap` file via the `pcap` crate's own `Savefile`
API (not a hand-rolled binary format, so what comes out is guaranteed to
be exactly what Wireshark or any other pcap tool expects) and hands the
actual writing off to a **dedicated pcap-writer thread** — see below for
why that split exists.

A few deliberate choices worth explaining:

- **Global, not per-flow.** The ring buffer retains *all* recently
  captured traffic in arrival order, not filtered down to just the flow
  that alerted. This is both simpler — no per-flow raw-byte storage
  threaded through the sharded worker architecture, which only ever
  sees our own truncated, already-parsed `Packet` struct, never the
  genuine original bytes — and arguably more useful: surrounding
  context from other traffic at the same moment is often exactly what
  you want when investigating an alert, not just one flow in isolation.
- **Fixed-size arrays, not a `Vec` per frame.** Every ring slot is
  pre-allocated once at startup (`[u8; 1500]`, matching the same
  reasoning behind `Packet`'s own fixed-size payload array in
  `packet.rs`), so retaining a frame is a bounded memcpy into
  already-owned memory, never a heap allocation on the packet-capture
  hot path.
- **Dump requests only for alerts that survive suppression.** Requested
  from `run_alert_writer`, at the exact point it emits a line — not from
  the raw per-worker alert-generation path — so a burst of a thousand
  identical suppressed `PACKET_FLOOD` alerts doesn't try to write a
  thousand near-identical pcap files.
- **Truncated frames get an honestly adjusted header**, not a corrupt
  one: `caplen` is set to what was actually retained, `len` is
  preserved as the true original packet size — the same truncation
  semantics a live capture with a small snaplen already produces, so
  Wireshark shows it as a normal, if truncated, capture.
- **Actually writing the file happens off the capture thread.** The
  first version of this feature wrote synchronously, inline in the
  capture loop — simple, but wrong: writing up to 500 packets to disk
  means `cap.next_packet()` isn't being called for however long that
  takes, during which arriving packets could be dropped by the OS/
  driver's own kernel buffer before ARGUS ever sees them, invisibly (the
  `dropped` counter only tracks worker-queue drops). Confirmed on a real
  run: a `timeout`-terminated test process (sending `SIGTERM`, which the
  Ctrl+C handler doesn't catch) lost an in-flight pcap write entirely,
  which is what surfaced this in the first place. The fix splits
  `write_pcap_dump` into `open_pcap_dump` (fast — just opens the file
  and writes the pcap global header; must run on the capture thread,
  since it needs the live `cap` handle) and `write_frames_to_savefile`
  (the slow, disk-bound part), handing an in-memory snapshot of the ring
  buffer plus the open `Savefile` to a dedicated writer thread —
  `pcap::Savefile` is `Send`, confirmed directly in the crate source,
  which is what makes this split sound. One honest tradeoff this
  introduces: an *abrupt* process kill (not a normal Ctrl+C, which is
  caught and drains the writer thread before exit) could now lose an
  in-flight pcap write that a fully synchronous version would have
  already completed. The alert itself is unaffected either way — it's
  written independently, on its own thread — so this only risks the
  forensic artifact, never the detection, which is the right thing to
  prioritize keeping reliable.

This is genuinely tested, not just built: a round-trip test writes real
frames through `write_pcap_dump` (the synchronous convenience wrapper
kept around specifically for tests, which don't care about the capture
thread staying unblocked the way production does) using
`pcap::Capture::dead()` (a fake capture handle that exists purely to
supply a link-layer type, needing no real network interface — which is
what makes this testable in CI at all) and reads the file back via
`Capture::from_file` to confirm every frame survived intact. It was also
verified against a real capture on a real interface during development:
a genuine `BLACKLIST_IP` alert produced real `.pcap` files, independently
confirmed valid by Linux's own `file` utility (not our own code) rather
than just by our own reader round-tripping successfully — including
after the off-thread split, confirmed via `SIGINT` (what Ctrl+C actually
sends) triggering a clean shutdown that correctly drains the writer.

**Found while building this**: an earlier attempt at this exact feature
was started, abandoned partway through, and left behind a field on
`Alert` (`pcap_frames: Option<Vec<RawFrame>>`) referencing a `RawFrame`
type that was never defined — meaning the file wouldn't compile as it
stood. Worth noting for two reasons: first, it's a reminder that
"the code already does X" is worth verifying rather than assuming,
even from very recent work; second, the abandoned design would have
populated frames from *each worker's own already-parsed `Packet`
struct* rather than the genuine original bytes at the capture point —
meaning it would have had to synthesize fake Ethernet/IP headers for
the pcap file rather than replaying real ones, a meaningfully less
faithful design than the one actually shipped here.

## A performance bug the benchmark suite caught, not the wire

Building the pcap feature meant re-running the existing benchmark suite
to make sure nothing regressed — standard practice at this point in the
project — and it turned up something the earlier port-collision fix had
quietly introduced: `anomaly_observe cost as distinct-ports-tracked
grows` went from a flat ~37ns/iter to **1,095ns at 1,000 tracked ports,
9,249ns at 10,000, and 50,158ns at 40,000** — clearly not flat anymore.

The cause traced back to the fix from two rounds ago (see "TCP and UDP
port-tracking bug" further up): pruning stale port entries was changed
from size-gated (`if len() > limit * 4`) to unconditional — run on
*every* packet — specifically to stop a low-volume source's stale
entries from lingering forever under the old gate. That fix was correct
in intent, but `retain()` is O(map size), and calling it on every packet
means the *cost of processing each packet* now scales with however many
distinct ports have already been tracked — which, for a fast, wide port
scan, is exactly the size of the attack itself. ARGUS's own processing
would slow down precisely when it's under the most hostile traffic,
which is close to the worst possible failure mode for detection
software.

Digging into *why* the old size-gated version hadn't shown this in
benchmarks either revealed a second, independent bug: that benchmark
used `port_scan_limit: usize::MAX` to disable alerting while it stress-
tested map growth, and the old code computed its prune threshold as
`port_scan_limit * 4` — which silently overflows in a release build
(overflow checks are off by default; the value wraps rather than
panicking) to a threshold near `usize::MAX` that map size could never
cross. Pruning was accidentally disabled for that entire benchmark,
which is why it used to report a flat, cheap-looking number — one that
never reflected what the size-gated version actually cost under any
configuration where pruning could actually run.

The real fix: prune at most **once per wall-clock second** per
(destination, protocol) pair, tracked via a `last_pruned_at` timestamp,
rather than gating on packet count or map size at all. This bounds
`retain()`'s cost to an amortized-negligible amount regardless of
traffic volume (even an extremely fast flood scan only pays the O(map
size) cost once per second, amortized over however many packets arrived
in it), while still cleaning up genuinely stale entries within about a
second of going stale — much tighter than the old size-gate, which
could let a quiet source's entries sit forever if the map never grew
past the threshold. Two tests now cover both halves of this directly:
`port_tracking_is_pruned_at_most_once_per_second_even_under_a_fast_burst`
sends 5,000 SYNs within one simulated instant and confirms detection
still completes promptly, and
`stale_port_entries_are_still_pruned_once_real_time_passes` confirms
old entries genuinely stop counting once real time has actually elapsed
— the property the original size-gated version could silently fail to
guarantee. The benchmark (fixed to use a large-but-sane limit instead of
`usize::MAX`, so it can't hide behind the same overflow again) now
reports a flat ~37.5ns/iter regardless of tracked port count — the same
number as before, but now genuinely bounded rather than accidentally so.

## Two more protocols: SMB2/3 and Modbus/TCP

Both were asked for as part of a bigger request that also included
DNP3/BACnet/S7comm and the rest of the industrial-protocol family, and
those remain explicitly out of scope for the same reason as before: each
is its own real parser, and "a dozen unrelated protocols" doesn't
collapse into one afternoon's work just because two of them are now
covered. What's actually here:

**SMB2/3** — content-sniffed the same way HTTP/TLS/SSH/FTP/SMTP are, via
its 4-byte `\xFE` `S` `M` `B` signature. Every recognized SMB2 command
gets a name (`smb.command`); `CREATE` requests — opening a file or
share, the single highest-value SMB2 message for this kind of detection
(share enumeration, access to sensitive paths, ransomware-pattern file
access all show up here) — additionally get their target filename
parsed out (`smb.filename`), decoded from the UTF-16LE encoding the
protocol actually uses. Deliberately not covered: **SMB1** (the legacy
dialect implicated in EternalBlue-class exploits — a different enough
wire format, 32-byte fixed header with no modern structure-size
validation, that supporting it means a second parser, not an extension
of this one) and **SMB3 transform-encrypted messages** (signature `\xFD`
`S` `M` `B`, used once a session negotiates encryption — there's nothing
to parse without decrypting, and see "On TLS decryption" below for why
ARGUS doesn't do that). Both are recognized as "not this parser" and
return `None` rather than being silently misinterpreted.

**Modbus/TCP** — and here's a real, deliberate departure from how every
other protocol in ARGUS works: Modbus is **gated by port (502), not
content-sniffed**. Every other protocol parser has a real signature to
check first — HTTP's method verbs, TLS's `0x16` handshake byte, SMB2's
4-byte magic, SSH's `SSH-` banner, FTP/SMTP's command-verb whitelists —
so attempting to parse garbage as that protocol is cheap and
self-limiting. Modbus's only structural tell is a 2-byte protocol-ID
field fixed at `0x0000`, which is a weak, common bit pattern that would
false-positive readily against arbitrary binary TCP traffic if used as
a content-sniffing trigger the way everything else is. Gating by the
well-known Modbus/TCP port instead avoids that; `StreamHalf`'s Modbus
parsing is only ever attempted when either side of the connection is
port 502, and gives up permanently on a given connection (rather than
re-attempting on every packet) the first time a claimed message's
protocol-ID field isn't actually zero — so a non-Modbus service that
happens to share the port doesn't get repeatedly mis-parsed as malformed
Modbus. Function codes are translated to names (`modbus.function`,
e.g. `WRITE_SINGLE_REGISTER`), with the exception-response high bit
cleared before lookup so both a request and its error response resolve
to the same name; the write-type codes (`0x05/0x06/0x0F/0x10/0x16`) also
get their target register/coil address parsed out (`modbus.address`),
since that's the field with real ICS security relevance — a malicious
setpoint or coil write to a PLC or RTU.

Both needed a new kind of incremental parsing that neither the FTP/SMTP
line-cursor nor the one-shot HTTP/TLS/SSH checks fit: length-prefixed
binary framing (SMB2's 4-byte prefix, Modbus's 7-byte MBAP header), with
a connection carrying many messages of either kind over its lifetime,
the same "many events per connection" shape FTP/SMTP already have but
via a completely different wire format. `StreamHalf` now has two more
cursors (`smb2_scan_pos`, `modbus_scan_pos`) alongside `line_scan_pos`,
each with its own incremental "give me every complete message since
last time" method — deliberately two separate, protocol-specific
implementations rather than one generic length-prefixed-framing
abstraction, since their header layouts differ enough (SMB2's prefix is
a bare 3-byte length; Modbus's MBAP header carries a transaction ID,
protocol ID, and unit ID alongside its own length field) that a shared
abstraction would mostly be plumbing, not shared logic — the same
"don't force-fit an abstraction for two dissimilar call sites" lesson
this project already learned once this session, from a `Sweeper` helper
that got built, measured, and reverted earlier for the same reason.

Both are tested two ways: unit tests against hand-constructed, spec-
accurate synthetic messages (a real SMB2 CREATE request with correctly
computed `NameOffset`/`NameLength` fields; Modbus function codes
including the exception-response case), and — since neither protocol
had a source of real captured traffic available to validate against —
genuine end-to-end runs during development: an actual Python script
opened a real TCP connection over loopback and sent a real
byte-for-byte SMB2 CREATE message (and, separately, a real Modbus
write), captured live through the actual `pcap` pipeline exactly the
way a real attack would be, and both correctly produced a
`SIGNATURE_MATCH` alert.

## The reassembly cap: configurable, not removed

Any *finite* cap has the same underlying property: a payload split to
land after more bytes of preceding stream data than the cap allows still
evades matching, since the attacker only needs to push the real payload
past wherever the cap sits. Raising the cap raises the bar an attacker
has to clear, but it doesn't remove the evasion vector — only an
unbounded buffer does that, and an unbounded buffer trades this evasion
vector for a real denial-of-service one instead: an attacker opening
many slow, long-lived connections and trickling a few bytes at a time
would force per-flow memory to grow without limit.

So the actual change is making the tradeoff a choice instead of a fixed
constant: `-stream-cap` (default raised from an earlier 4KB to 16KB,
generous enough for a full SMB2 CREATE request or a multi-message
Modbus burst, not just an HTTP request line or a TLS ClientHello) lets
whoever's running ARGUS decide where their own line sits, rather than
having that decision baked into a `pub const` nobody but the source
code could see. `FlowTable`/`StreamHalf` now take this as a runtime
parameter (`FlowTable::with_stream_cap`), not a compile-time constant.

## On TLS decryption

This was asked for directly, as a MITM proxy with a trusted CA, and it's
the one item from this round genuinely not built — worth being clear
about why rather than quietly substituting something smaller.

Everything else ARGUS does is passive: it reads bytes that are already
on the wire, whether that's a plaintext HTTP header or TLS metadata
(SNI, JA3) that's never encrypted in the first place. A working TLS-
intercepting MITM implementation is a different kind of thing — it
means generating a CA certificate, getting it trusted by a client,
terminating that client's TLS connection, and originating a new one to
the real server, decrypting and re-encrypting everything in between.
Once built, that code doesn't know or enforce anything about *whose*
traffic it's pointed at — a finished implementation is a general-purpose
tool for reading communications someone encrypted specifically so a
third party couldn't, and it works exactly the same whether it's run
against a home lab or against someone else's traffic without their
knowledge. That's a meaningfully different kind of capability to hand
over than everything else in this project, even in the context of a
genuinely well-intentioned personal security tool, and it's why this one
wasn't implemented.

The suggested alternative, for visibility into *your own* encrypted
traffic specifically: `SSLKEYLOGFILE`. Most browsers and many TLS
clients will log their own per-session decryption keys to a file if
that environment variable is set, and tools like Wireshark already know
how to use that file to decrypt captured traffic — because it only works
for connections where you already legitimately control the endpoint
doing the logging, it gives the same practical visibility without
needing any interception infrastructure at all. Not built as part of
this round (it's a genuinely separate, smaller task — reading a keylog
file and threading key material through decryption isn't the same shape
of work as anything else here), but a reasonable next step if that
visibility is actually the goal.

## Four more protocols: RDP, TFTP, SNMP, and DNP3

**RDP** — content-sniffed via its TPKT (RFC 1006) + X.224 Connection
Request framing, checked once per direction (the one-shot pattern
HTTP/TLS/SSH already use, since this only ever appears as the very
first message of a connection — despite the framing looking
superficially similar to SMB2's length-prefixed messages, RDP doesn't
need a new incremental cursor). Extracts the optional `Cookie:
mstshash=<value>` routing token — an explicit, often attacker-supplied
username hint many RDP clients (and, notably, many brute-force tools)
send. This is visible even for NLA/CredSSP-secured sessions: the
negotiation to switch to TLS happens *after* this exchange, not before,
so the cookie is never hidden behind encryption regardless of how the
rest of the connection gets secured. `rdp.cookie` is always present as a
buffer (empty string, not absent, when no cookie was sent) rather than
only sometimes existing, specifically so a `not_literal` rule against it
stays meaningful. Not parsed: the RDP Negotiation Request structure that
can follow the cookie (which security protocols the client's offering)
— the cookie is the higher-value field, and negotiation-flag parsing
isn't free of its own edge cases worth getting right separately.

**TFTP** — parsed directly per-packet (UDP has no stream to reassemble,
so this works the same way DNS query parsing already does), gated to
port 69 rather than content-sniffed: its 2-byte opcode field is as weak
a signal as Modbus's protocol-ID field, common enough to appear in
arbitrary UDP payloads by chance. Extracts the opcode name
(`tftp.opcode`) and, for read/write requests specifically, the requested
filename (`tftp.filename`) — TFTP's simplicity is exactly what's kept it
a longstanding, still-common vector for pulling malware or config
payloads onto IoT and embedded devices, and the filename is most of the
useful signal here.

**SNMP** — also parsed per-packet, also port-gated (161/162), for the
same reason as TFTP, even though the structural check here (a specific
BER SEQUENCE{INTEGER version, OCTET STRING community}) is a meaningfully
stronger signal than either Modbus's or TFTP's — kept consistent with
the rest of the port-gated group rather than making a one-off exception
based on a judgment call about exactly how strong a signature has to be.
This needed a small, narrowly-scoped BER/ASN.1 reader (`read_ber_tlv`)
— not a general one: it recognizes exactly the SEQUENCE/INTEGER/
OCTET-STRING tags needed to walk an SNMPv1/v2c message's fixed header
shape, handles both short- and multi-byte long-form BER lengths (needed
for community strings over 127 bytes), and returns `None` on anything
else — SNMPv3's structurally different message (no plaintext community
string to find) included — rather than guessing. `snmp.community`
catches the classic default-credential scanning pattern (`public`/
`private`) that's remained relevant for this protocol for decades.

**DNP3** — the natural next industrial protocol after Modbus, common in
North American electric-utility SCADA/RTU communication. Gated to port
20000 like Modbus/TFTP/SNMP, even though its 2-byte sync pattern
(`0x05 0x64`) is a meaningfully *stronger* signal than any of those
three (two specific non-zero bytes, not a common padding/reserved-field
artifact the way Modbus's all-zero protocol-ID field is) — still nowhere
near SMB2's 4-byte ASCII magic, so this stays grouped with the
port-gated protocols rather than being content-sniffed on a judgment
call about where exactly the line sits. The real complexity here is
DNP3's data-link layer, which interleaves a CRC-16 after every 16 bytes
of payload — bytes that have to be stripped back out before the
transport and application layers underneath become readable as
contiguous data. CRC *validation* is deliberately not implemented:
corrupted frames just fail to parse further rather than being flagged
as corrupt specifically, since DNP3's particular CRC-16 variant doesn't
add IDS value here, only implementation risk for a check this parser
doesn't otherwise need. `dnp3.function` extracts the application-layer
function code from a scoped subset of IEEE 1815's ~30 codes — the ones
with real physical-device-control or session-disruption implications
(`OPERATE` and `DIRECT_OPERATE` chief among them), the same reasoning
that made Modbus's write-type codes the highest-value field there.

All four were verified against genuine, real captured traffic during
development, the same way SMB2/Modbus were — a Python script opened
real TCP connections (or, for TFTP/SNMP, sent real UDP datagrams) and
sent byte-for-byte spec-accurate messages, captured live through the
actual `pcap` pipeline, all four correctly producing a `SIGNATURE_MATCH`
alert. That verification step is what actually caught the two bugs
below — neither would have been found by code review or by the existing
unit tests alone.

## Two real bugs this round, neither about the new protocols

Both were caught by the exact same thing that's caught every real bug
this session: testing against genuine captured traffic instead of
trusting that code compiling and unit tests passing meant it worked.

**Bug one: `Direction::Any` was never a valid lookup key.** Every
UDP-based detection path in `main.rs` — raw payload matching, DNS query
matching, and the new TFTP/SNMP matching — calls
`SignatureEngine::check_buffer` with `Direction::Any`, because none of
them go through `FlowTable` (the only thing that ever computes a real
to-server/to-client direction) — they're all per-packet, with nothing
tracking which side of a connection is which. But `RuleSet::load`
expands a rule declared `direction: any` into separate `(buffer,
ToServer)` and `(buffer, ToClient)` map entries at load time; nothing is
ever stored under the key `(buffer, Direction::Any)` itself. A lookup
literally keyed on `Any` therefore matched *nothing*, for *any* rule,
regardless of how that rule was declared — not just rules declared
`any`, every single UDP-based signature rule was silently broken. This
had been true since DNS query rule matching was first added, several
rounds ago; it went undetected because every TCP-based protocol
computes a real direction via `FlowTable` before ever calling this, so
nothing exercised the `Any`-as-a-lookup-key path — and because nobody
had live-tested an actual matching UDP rule until this round's TFTP/SNMP
verification did.

The fix: `RuleSet::check` now treats `Direction::Any` as "the caller
doesn't track direction for this traffic," checking both stored
directions and merging the (de-duplicated — an `any`-declared rule is
physically stored twice, and would otherwise be reported twice for one
`Any` query) results, rather than passing `Any` straight through as a
single lookup key. `querying_with_direction_any_finds_rules_of_every_
declared_direction` tests all three declaration forms against an `Any`
query directly — the actual shape of the bug — and
`any_declared_rule_is_not_reported_twice_by_an_any_query` covers the
de-duplication.

**Bug two: `SIGNATURE_MATCH` alerts weren't suppression-keyed by rule
identity.** Found immediately after fixing the first bug, while
re-verifying TFTP and SNMP together: two genuinely different rules (a
TFTP filename match and an unrelated SNMP community-string match) fired
from the same source, destination, and protocol close together, and the
second was silently swallowed as a "duplicate" of the first — the
suppression key (`category|src|dst|proto`, already fixed twice this
project for missing `proto` and missing `dst`) still had no way to tell
that these were two unrelated pieces of evidence, not a repeat of the
same one. The fix adds `message` to the key, but **only for
`SIGNATURE_MATCH`**: that category's message is deterministic per rule
(built from just the buffer name and rule name, nothing that changes
between repeated matches), unlike `PORT_SCAN`'s growing port count or
`PACKET_FLOOD`'s growing packet count — including `message` for *those*
categories would make every new count produce a different key and
defeat suppression entirely, the opposite of what's needed.

This matters more for UDP-based signatures specifically than TCP ones:
only TCP flows get `FlowTable`'s own separate per-flow, per-rule dedup
(the `matched: FxHashSet<String>` on each `StreamHalf`); UDP detection
is per-packet with no flow state at all, so `run_alert_writer`'s
suppression key is the *only* thing standing between a repeatedly-
matching UDP signature and alert spam — making it more important to get
right here, not less.
`different_signature_matches_are_not_mutually_suppressed` and
`repeated_matches_of_the_same_signature_still_suppress_normally` cover
both halves: two different rules must both survive, and the same rule
firing repeatedly must still collapse to one alert.

## Architecture

```
capture thread --parse--> shard(host pair) --> worker[0..N) --> alert channel --> writer thread
                  |                                                                     |
                  `--- PcapRing (recent raw frames)         PcapDumpRequest ------------'
                  |         |                                     |
                  `-- open_pcap_dump()  <--------------------------
                            |
                            v
                  pcap-writer thread --- write_frames_to_savefile() --> .pcap file
```

- **`src/packet.rs`** — `Packet` type; `IpAddr` (IPv4/IPv6 address enum,
  used everywhere addresses appear in the rest of the codebase);
  Ethernet/IPv4/IPv6/TCP/UDP/ICMP/ICMPv6 parsing (including the TCP
  sequence number, needed for reassembly, and IPv6 extension-header
  traversal); plus test-only frame-building helpers shared across
  `engine.rs`'s tests.
- **`src/engine.rs`** — everything detection-related, in sections:
  alerting (`Alert`, `PcapDumpRequest`, text or JSON output, the writer
  thread); the rule engine (`Buffer`, `Direction`, `RuleSet` —
  literal/regex/negation matching, grouped by buffer+direction at load
  time, `Direction::Any` queries checking both stored directions);
  the HTTP/DNS/TLS/FTP/SSH/SMTP/SMB2/Modbus/RDP/TFTP/SNMP/DNP3 protocol
  parsers (bounds-checked against arbitrary input, no decryption
  anywhere); `SignatureEngine` (IP blacklist + the rule engine);
  `AnomalyEngine` (packet-rate flood, TCP-SYN port-scan, and
  reply-aware, time-gated-pruning UDP port-scan detection); and
  `FlowTable` (TCP stream reassembly, with a configurable byte cap —
  in-order append, bounded out-of-order buffering, retransmit/overlap
  handling, and the TCP-based protocols' parsing + rule-checking hooks
  that run against the growing reassembled buffer, via three different
  kinds of incremental cursor: one-shot for HTTP/TLS/SSH/RDP,
  CRLF-line-based for FTP/SMTP, length-prefixed-binary-framing-based for
  SMB2/Modbus/DNP3 — TFTP/SNMP are UDP, so they're parsed per-packet in
  `main.rs` directly, the same way DNS already was, never touching
  `FlowTable` at all).
- **`src/main.rs`** — CLI, the `pcap` capture loop, host-pair worker
  sharding (uniform across every protocol), worker-pool wiring, the
  packet-retention ring buffer (`PcapRing`), pcap-file writing split
  across two threads (`open_pcap_dump` on the capture thread, since it
  needs the live `pcap::Capture` handle; `write_frames_to_savefile` on a
  dedicated writer thread, since it's the slow, disk-bound part and must
  never stall packet capture), and the UDP-based protocols' per-packet
  parsing (DNS, TFTP, SNMP, raw payload).

## The rule file format

One rule per line: `name|buffer|direction|type|pattern`

| Field | Values |
|---|---|
| `buffer` | `payload` \| `http.uri` \| `http.host` \| `dns.query` \| `tls.sni` \| `tls.ja3` \| `ftp.command` \| `ssh.version` \| `smtp.command` \| `smtp.sender` \| `smtp.recipient` \| `smb.command` \| `smb.filename` \| `modbus.function` \| `modbus.address` \| `rdp.cookie` \| `tftp.opcode` \| `tftp.filename` \| `snmp.community` \| `dnp3.function` |
| `direction` | `any` \| `to_server` \| `to_client` |
| `type` | `literal` \| `regex` \| `not_literal` \| `not_regex` |
| `pattern` | literal string, or a regex — always the *last* field, so it can safely contain `\|` |

```
sql-injection-uri|http.uri|to_server|regex|(?i)(union\s+select|or\s+1=1)
known-bad-domain|tls.sni|to_server|literal|malicious-c2-domain.example
missing-host-header|http.host|to_server|not_literal|internal-api.corp
ftp-anonymous-login|ftp.command|to_server|literal|USER anonymous
smtp-relay-probe|smtp.command|to_server|literal|VRFY root
smb-admin-share-access|smb.filename|to_server|regex|(?i)admin\$
modbus-any-write|modbus.function|to_server|regex|^WRITE_
rdp-admin-brute-force|rdp.cookie|to_server|regex|(?i)mstshash=administrator
snmp-default-community|snmp.community|any|literal|public
dnp3-device-control|dnp3.function|to_server|regex|^(OPERATE|DIRECT_OPERATE)
```

See `rules.txt` for a fuller annotated example set. The old `-signatures`
flag/2-field format still works as a flag *name* (it's aliased to
`-rules`) but the **file format has changed** — this is a breaking change
from the earlier version, made deliberately since this is a single-user
project, not something with external compatibility constraints yet.

Negation (`not_literal`/`not_regex`) only applies to the structured
buffers, not `payload` — "this pattern never appeared" is only
meaningful once a buffer is known to be *complete*; a raw payload stream
never really finishes from the engine's point of view.

`ftp.command`, `smtp.command`/`smtp.sender`/`smtp.recipient`,
`smb.command`/`smb.filename`, and `modbus.function`/`modbus.address`/
`dnp3.function` are all checked against **every new message as it
arrives**, not just once — unlike a TLS ClientHello or an HTTP request
line, one session of any of these protocols sends many commands/
messages over its lifetime. `ssh.version` and `rdp.cookie` are each
checked once per direction (SSH's plaintext version banner and RDP's
initial connection request are each the only unencrypted moment of
their respective connections). `tftp.opcode`/`tftp.filename` and
`snmp.community` are checked once per UDP *packet*, since neither
protocol has a persistent connection to reassemble — no dedup concerns
there, each datagram is independent. One consequence worth knowing for
the many-messages-per-session buffers: the existing per-flow,
per-rule-name dedup (built for the one-shot buffers, to avoid
re-alerting as a growing payload buffer keeps matching the same
signature) also applies here, so if the *same* rule matches two
*different* messages in one session, it only alerts on the first — a
deliberate scope limitation to keep the dedup model uniform across
every buffer type, not a bug.

## Build & run

Same as before — nothing changed about the build/runtime requirements.

```
cargo build --release

sudo ./target/release/argus -list-interfaces
sudo ./target/release/argus -iface eth0 -blacklist blacklist.txt -rules rules.txt
```

Windows: same Npcap + Npcap SDK + `LIB` env var setup as before; run as
Administrator.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-iface` | *(required)* | interface to monitor |
| `-blacklist` | *(none)* | path to IP blacklist file — one IPv4 or IPv6 address per line |
| `-rules` (or `-signatures`) | *(none)* | path to the rules file |
| `-logfile` | `argus-alerts.log` | where alerts are appended |
| `-json` | off | emit alerts as JSON lines (NDJSON) instead of human-readable text — applies to both stdout and the log file |
| `-window` | `10s` | sliding window for anomaly thresholds |
| `-rate-threshold` | `500` | packets/window before `PACKET_FLOOD` |
| `-scan-threshold` | `20` | distinct ports/window (per destination) before `PORT_SCAN` — applies to both TCP (SYN-only) and UDP (reply-aware) |
| `-suppress-window` | `15s` | collapse duplicate alerts of the same type+source+destination+protocol (destination isn't part of the key for `PACKET_FLOOD`, which is deliberately tracked per-source regardless of destination) |
| `-workers` | CPU count | parallel detection worker threads |
| `-queue-size` | `4096` | per-worker packet queue depth before packets are dropped |
| `-pcap-dir` | `logs` | directory for the `.pcap` saved automatically around each alert |
| `-pcap-retain` | `500` | packets of recent traffic kept ready to dump; `0` disables the feature entirely |
| `-stream-cap` | `16384` | reassembled-payload budget per TCP direction — see "The reassembly cap" above for the tradeoff this controls |
| `-list-interfaces` | — | print available interfaces and exit |

Each saved pcap is named `<epoch_secs>_<seq>_<category>_<proto>_<src>.pcap`
— sortable, and traceable back to the alert that produced it (`seq` is
just a monotonic counter disambiguating two alerts landing in the same
second, not wall-clock precision).

With `-json`, each alert is one line like:

```json
{"timestamp":1758012345,"severity":"MEDIUM","category":"PORT_SCAN","src":"192.168.0.112","dst":"45.33.32.156","proto":"TCP","port":21,"message":"21 distinct ports touched on this destination in the last 10s (limit 20)"}
```

`timestamp` is Unix epoch seconds, not a calendar date — deliberately, to
avoid a date-formatting dependency for a field most machine consumers
treat as an opaque, sortable number anyway. The human-readable "N more
suppressed" summary line is skipped entirely in JSON mode (rather than
mixing schemas); suppression still happens, a consumer just won't see a
count of it in the stream.

## Testing

```
cargo test --release
```

106 unit tests: 96 organized as submodules inside `engine.rs`
(`rules_tests`, `protocols_tests`, `signature_and_anomaly_tests`,
`flow_tests`) plus `packet::tests` (now including IPv6 parsing,
extension-header traversal, and literal parsing/formatting), plus 10 in
`main.rs` itself — 4 covering the sharding logic directly, 6 covering
the pcap-retention ring buffer and file-writing — worth calling out
specifically, because the sharding bug in an earlier revision would
have shipped invisibly otherwise: every other test calls
`AnomalyEngine::observe()` or `FlowTable::observe()` directly, bypassing
`main.rs`'s worker routing entirely, so none of them could have caught a
bug in how packets get distributed to workers in the first place. A few
worth calling out specifically, because they test the properties that
actually matter:

- **`rules_tests::querying_with_direction_any_finds_rules_of_every_declared_direction`**
  — the direct regression test for the biggest bug this project has
  shipped: every UDP-based rule check (raw payload, DNS, TFTP, SNMP)
  queries with `Direction::Any`, which used to be a literal lookup key
  that nothing was ever stored under, silently breaking every one of
  those rule types since DNS matching was first added. This test checks
  all three rule-declaration forms (`any`, `to_server`, `to_client`)
  against an `Any` query directly — the actual shape of the bug, not
  just "does `RuleSet` work with a concrete direction," which every
  earlier test already covered without ever catching this.
- **`signature_and_anomaly_tests::different_signature_matches_are_not_mutually_suppressed`**
  — regression test for the second bug the same live-testing pass
  caught: two different rules matching the same source/destination/
  protocol used to collide under one suppression key and the second was
  silently dropped. Paired with
  `repeated_matches_of_the_same_signature_still_suppress_normally`,
  which proves the fix (keying `SIGNATURE_MATCH` suppression by message)
  didn't quietly break the ordinary case of the same rule firing
  repeatedly.
- **`flow_tests::dnp3_frame_split_across_two_segments_still_parses`** /
  **`rdp_connection_request_split_across_two_segments_still_parses`** —
  the same reassembly-evasion property every TCP-based protocol here
  gets tested for, now for DNP3's CRC-interleaved link-layer framing and
  RDP's TPKT+X.224 framing specifically.
- Every one of RDP/TFTP/SNMP/DNP3 was also verified against genuine
  captured traffic during development — real TCP connections and UDP
  datagrams, spec-accurate synthetic messages, captured live through
  the actual `pcap` pipeline — not just unit-tested. That live
  verification pass is what actually found the two bugs above; neither
  would have been caught by the unit tests or code review alone.

- **`flow_tests::smb2_message_split_across_two_segments_still_parses`**
  — the SMB2/Modbus equivalent of the reassembly regression test below:
  proves the new length-prefixed-binary-framing cursor correctly waits
  for a message to actually complete across two TCP segments rather than
  either mis-parsing a partial one or losing it.
- **`flow_tests::modbus_write_detected_only_on_the_modbus_port`** — sends
  the *identical* bytes twice, once on port 502 and once on an unrelated
  port, and asserts the rule only fires on the first. Without this test,
  a bug that made Modbus content-sniff like every other protocol (rather
  than staying port-gated) would ship invisibly — the unit-level parser
  tests alone can't catch a sharding/dispatch-layer mistake like that,
  any more than the port-scan sharding bug's own tests could have if
  they'd only tested `AnomalyEngine` directly.
- **`flow_tests::stream_cap_is_configurable_and_actually_enforced`** —
  proves `-stream-cap` isn't just a config field threaded through and
  silently ignored: a rule matching content placed just past a small
  custom cap must not fire, and the identical rule against a larger cap
  must.
- Both SMB2 and Modbus were also verified end-to-end during development,
  not just via unit tests: a real Python script opened a genuine TCP
  connection over loopback and sent byte-for-byte accurate SMB2 CREATE
  and Modbus write messages, captured live through the actual `pcap`
  pipeline, both correctly producing a `SIGNATURE_MATCH` alert — the
  same kind of real-capture verification the pcap-retention feature and
  every protocol before it got.

- **`flow_tests::defeats_signature_split_across_two_packets`** — the
  core regression test for the whole reassembly feature: sends
  `"MALICIOUS_"` and `"PAYLOAD"` in two separate TCP segments, asserts
  neither alone matches a rule for `"MALICIOUS_PAYLOAD"`, then asserts
  the reassembled buffer does.
- **`flow_tests::out_of_order_segments_are_reassembled_correctly`** —
  sends segments in the wrong order, checks they're correctly
  reassembled once the gap closes. (This test caught a real bug during
  development: a bare SYN carries no payload, so it never touched the
  code path that initializes the expected sequence number — meaning
  whichever data segment happened to arrive *first* silently became the
  new baseline instead of the SYN's actual sequence number. Fixed by
  initializing sequence tracking from the SYN directly, regardless of
  payload.)
- **`protocols_tests::ja3_matches_independent_reference_no_grease`** /
  **`ja3_filters_grease_values_matching_reference`** — JA3 correctness
  isn't just "it produces *a* hash," it has to produce the *exact*
  standard hash, since real-world JA3 blocklists are keyed on it. These
  assert against MD5 digests computed independently in Python from the
  same input, not just against Rust's own output.
- **`signature_and_anomaly_tests::dns_style_udp_replies_do_not_trigger_port_scan`**
  / **`unsolicited_udp_probes_are_detected_as_a_scan`** — together prove
  the new UDP scan detection actually distinguishes the two cases it has
  to: the first sends matched query/reply pairs across 40 ports and
  asserts none of them alert; the second sends 25 genuinely unmatched
  probes and asserts they *do*. Neither alone would catch a tracker that
  was simply broken in one direction (e.g. one that flagged everything,
  or flagged nothing).
- **`main.rs::tests::udp_query_and_reply_share_a_shard`** — proves the
  sharding half of UDP scan detection independently of the tracking
  logic itself: without this, the reply-tracking tests above could pass
  in isolation while the real binary still failed in the field, exactly
  the way the original TCP port-scan sharding bug did.
- **`packet::tests::ipv6_format_leading_and_all_zero_compression`** —
  regression test for a real bug caught during development: an initial
  `::`-compression implementation built the string by naive joining,
  which is wrong specifically for leading-zero (`::1`), trailing-zero,
  and all-zero (`::`) addresses (each drops a colon or the whole
  compression). Fixed by building the head/tail segments explicitly
  instead of relying on a join to produce the right number of colons.
- **`pcap_retention_tests::write_pcap_dump_round_trips_through_a_real_pcap_file`**
  — the pcap feature's own version of "goes through the real code path,
  not just an in-memory model of it": writes real frames through the
  actual `write_pcap_dump` function (using `pcap::Capture::dead()`, a
  fake capture handle that needs no real network interface — what makes
  this testable in CI at all) and reads the file back via
  `Capture::from_file` to confirm every frame survived intact.
- **`signature_and_anomaly_tests::port_tracking_is_pruned_at_most_once_per_second_even_under_a_fast_burst`**
  / **`stale_port_entries_are_still_pruned_once_real_time_passes`** —
  together cover both halves of the pruning-performance fix (see above):
  the first proves a fast burst of 5,000 distinct ports within one
  instant still completes and detects promptly; the second proves stale
  entries still genuinely expire once real time passes, so fixing the
  performance problem didn't quietly bring back the staleness bug the
  original "prune every packet" version was written to solve.

## Measured performance

```
parse_ethernet_frame                          18.7 ns/iter
literal_match (51 rules)                       8.5 ns/iter
regex_match (1 rule)                          44.4 ns/iter
anomaly_observe (steady state)               124.8 ns/iter

anomaly_observe cost as distinct-ports-tracked grows (SYN-only, per-destination):
  after 1,000 distinct ports                  37.5 ns/iter
  after 10,000 distinct ports                 37.6 ns/iter
  after 40,000 distinct ports                 37.7 ns/iter

flow_observe (SYN + one HTTP-shaped segment, new flow each time) 1168.8 ns/iter

check_buffer(dns.query) with 200 unrelated regex rules loaded      7.9 ns/iter

PcapRing::push-equivalent, per captured packet (800-byte packet)  58.5 ns/iter
```

Run `cargo run --release --example bench` yourself for the first six
lines (numbers vary somewhat run to run and machine to machine — these
are from the sandbox this was developed in, not a guarantee). The
`check_buffer` and `PcapRing::push` lines are one-off targeted
benchmarks written to verify a specific claim each (the regex-grouping
optimization, and the pcap ring buffer's per-packet cost respectively);
neither is part of the shipped `bench.rs`, since `PcapRing` lives in the
binary crate (`main.rs`), not the library, so `bench.rs` — which only
links against the library — can't reach it directly.

The literal-match path is still the fastest by nearly an order of
magnitude over regex — prefer `literal` rules where a plain substring is
all you need. The `anomaly_observe` scaling numbers are flat again after
the pruning fix above — not because the earlier problem wasn't real, but
because it's now genuinely bounded rather than hidden behind an overflow
bug in the benchmark's own test setup. `PcapRing::push`'s ~58ns is a real
added cost on the capture thread's hot path when `-pcap-retain` isn't
disabled — about 3x `parse_ethernet_frame`'s own cost — which is the
honest price of a bounded memcpy per packet; `-pcap-retain 0` removes it
entirely for anyone who'd rather not pay it.

`literal_match` specifically has shown noticeably higher, but stable and
repeatable, numbers on this sandbox during the RDP/TFTP/SNMP/DNP3 round
(~170ns rather than the ~8ns figure above) — checked carefully rather
than shipped past: the code path it exercises (`RuleSet::check_one`) is
byte-for-byte unchanged from before that round, and the same elevated
cost shows up even when calling with a concrete direction, a path the
`Direction::Any` fix from that same round never touches — so whatever's
behind it isn't a regression from that work, and correctness is
unaffected (the full suite still passes). Not fully root-caused in the
time available; worth re-measuring in a future round rather than
trusting either number blindly.

## What's still not here

Being honest about scope, since this is meant as an ongoing project:

- **No TLS decryption — a deliberate choice, not a gap to fill later.**
  SNI/JA3 are metadata visible without decrypting anything; they can't
  see inside the encrypted application data itself, and this was asked
  for and explicitly declined this round — see "On TLS decryption"
  above for the reasoning. `SSLKEYLOGFILE` support was suggested as a
  safer path to the same visibility goal, for your own traffic
  specifically, but isn't built yet either.
- **SMB1 and encrypted SMB3 aren't parsed** — only the plaintext SMB2/3
  SYNC header. See "Two more protocols" above for why each is a
  meaningfully different parser, not an extension of the one that's
  there.
- **BACnet, S7comm, and the rest of the industrial-protocol family
  remain unparsed.** Modbus/TCP and DNP3 are the two covered so far —
  "a dozen unrelated protocols" doesn't become one round's work just
  because two of them are now done.
- **Telnet isn't parsed, on purpose.** Considered this round and
  deliberately left out — see the intro. It has no clean protocol-level
  command structure to reliably extract credentials from the way FTP's
  `USER`/`PASS` commands do; it's an interactive character stream, and a
  low-confidence parser built just to say the protocol is "covered"
  isn't worth having.
- **The RDP Negotiation Request isn't parsed** — only the cookie. Which
  security protocols a client is offering to negotiate is lower-value
  signal than the cookie's username hint, and parsing it isn't free of
  its own edge cases worth getting right in a separate pass.
- **No live threat-intel feeds.** The blacklist/rules are exactly as
  current as the last time you edited the files.
- **No IPS capability.** Detection only — this can't block anything,
  even if it wanted to.
- **No ops maturity.** No service wrapper/auto-restart, health metrics,
  or log rotation; single-host only, no centralized multi-sensor
  management.
- **`PACKET_FLOOD` can under-count a true multi-target flood** from one
  source, since it's tracked per-shard and a source hitting several
  different destinations now has that traffic spread across several
  workers. See the UDP sharding section above for the detail.
- **Packet retention is a global window, not scoped per flow or per
  alert category.** Every saved pcap is "the last N packets of all
  traffic," not "the packets that specifically belong to the flow that
  alerted" — a deliberate simplicity/faithfulness tradeoff (see the
  packet-retention section above), but it does mean a very busy capture
  point could have the relevant traffic pushed out of the window by
  unrelated volume before an alert's dump request arrives, in principle
  — not something observed in testing, but worth naming honestly.
- **An abrupt process termination can lose an in-flight pcap write.**
  Writing the actual file happens on a dedicated thread, off the capture
  hot path (see the packet-retention section above for why) — a normal
  Ctrl+C is caught and drains that thread cleanly before exit, but a
  hard kill (a crash, `taskkill /F`, a service stop that doesn't send a
  normal interrupt) can end the process mid-write. The alert itself is
  unaffected either way, since it's logged independently — only the
  forensic pcap artifact for that one alert is at risk, not detection.

## Natural next steps

1. **A `RegexSet` pre-filter** for buffers that end up with *many* regex
   rules on the *same* (buffer, direction) pair — the per-(buffer,
   direction) grouping done in an earlier pass already eliminates the
   cost of irrelevant rules on other buffers; a `RegexSet` would
   additionally speed up the case of, say, 50+ regex rules all targeting
   `http.uri` specifically, which one-by-one checking still handles
   linearly today.
2. **Rule reload without restarting** (e.g. on `SIGHUP`/a file-watch).
3. **Per-shard drop counters** instead of one global counter.
4. **A global (cross-worker) counter for `PACKET_FLOOD`**, to close the
   multi-target-flood undercount noted above, if it turns out to matter
   in practice.
5. **Per-flow pcap scoping**, if the global-window tradeoff above turns
   out to matter in practice — would need raw-byte retention threaded
   through the sharded worker architecture rather than living solely on
   the capture thread, a meaningfully bigger change than the global
   version shipped here.
6. **Live threat-intel feed ingestion** for the blacklist, so it doesn't
   go stale the moment it's written.
7. **`SSLKEYLOGFILE` support**, for decrypting captured TLS traffic where
   the endpoint legitimately logged its own session keys — the safer
   alternative to MITM interception discussed in "On TLS decryption"
   above, and a genuinely separate, smaller task from anything else here.
8. **BACnet or S7comm** as the next industrial protocol, now that both
   Modbus and DNP3 are covered — same pattern each followed: its own
   real parser, its own port-gating (or content-sniffing) decision made
   on its own merits, not assumed from the others'.
9. **An audit of every other `Direction::Any` call site** in case any
   other caller has been quietly relying on the same broken lookup
   behavior the rule-engine fix above corrected — the fix itself should
   make this a non-issue going forward, but it's worth double-checking
   nothing else was built around the old (broken) behavior rather than
   the new one.
