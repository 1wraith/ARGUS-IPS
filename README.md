# ARGUS

A network intrusion detection system written in Rust.

ARGUS reads packets from a live interface or a saved capture, reassembles
TCP streams and IP fragments, parses application protocols, and reports
what it finds through three independent detection layers: signature
matching, statistical anomaly detection, and cross-flow behavioural
analysis. It writes NDJSON alerts, optional connection records, and a
`.pcap` of the surrounding traffic for every alert it raises.

It is a single binary with no runtime dependencies beyond libpcap/Npcap,
no database, no daemon, and no configuration file.

```
argus -iface eth0 -rules rules.txt -json
```

---

## Contents

- [Quick start](#quick-start)
- [What it detects](#what-it-detects)
- [Protocol coverage](#protocol-coverage)
- [Writing rules](#writing-rules)
- [Importing Suricata and Emerging Threats rules](#importing-suricata-and-emerging-threats-rules)
- [Output](#output)
- [Command-line reference](#command-line-reference)
- [Architecture](#architecture)
- [Performance](#performance)
- [Testing and measurement](#testing-and-measurement)
- [Deployment notes](#deployment-notes)
- [Limitations](#limitations)
- [Project layout](#project-layout)

---

## Quick start

### Requirements

- Rust 1.70 or newer
- **Linux/macOS:** `libpcap` development headers (`libpcap-dev`,
  `libpcap-devel`, or `brew install libpcap`)
- **Windows:** [Npcap](https://npcap.com/) with the SDK, or WinPcap

### Build

```bash
cargo build --release
```

The binary lands at `target/release/argus`.

### Run

Capturing live traffic requires elevated privileges — `sudo` on
Unix, an Administrator shell on Windows.

```bash
# List capture-able interfaces
argus -list-interfaces

# Monitor an interface with the bundled rules
sudo argus -iface eth0 -rules rules.txt -json

# Replay a saved capture (no privileges needed)
argus -r capture.pcap -rules rules.txt -json
```

Replay runs the identical detection pipeline, timed by each packet's own
capture timestamp, and never drops a packet regardless of file size. One
file always yields exactly the same alerts, which makes it usable for
regression testing and for investigating an alert after the fact.

### A full-capability invocation

```bash
sudo argus \
  -iface eth0 \
  -rules rules.txt \
  -blacklist blacklist.txt \
  -json \
  -logfile argus-alerts.log \
  -flow-log argus-flows.log \
  -behavior-window 5m \
  -pcap-dir logs \
  -pcap-retain 500
```

---

## What it detects

Detection is split across three layers that ask different questions and
fail independently. A signature knows exactly what it is looking for and
nothing else; an anomaly detector knows nothing about content but
notices volume and spread; behavioural analysis sees across connections
that no single worker can. Each catches things the others structurally
cannot.

### 1. Signature matching

Content matching against reassembled TCP streams and parsed protocol
fields, with an Aho-Corasick prefilter so rule count scales sublinearly.
See [Writing rules](#writing-rules).

| Alert | Raised when |
|---|---|
| `SIGNATURE_MATCH` | A rule matched. Carries the rule's `sid`, name, severity and the buffer it matched in |
| `BLACKLIST_IP` | Either endpoint appears in the blacklist file |

Matching happens on the **reassembled** stream, not on individual
packets, so a signature split across TCP segments still matches, as does
one hidden behind out-of-order delivery or overlapping IP fragments.

### 2. Statistical anomaly detection

Per-worker, per-source sliding windows over packet rate and port spread.

| Alert | Raised when |
|---|---|
| `PORT_SCAN` | One source touched more than `-scan-threshold` distinct ports on one destination inside the window. TCP counts SYNs only; UDP is reply-aware, so a source that gets answers is not scanning |
| `PACKET_FLOOD` | One source exceeded `-rate-threshold` packets per second, summed across all its destinations |
| `PROTOCOL_ANOMALY` | A connection on a well-known port whose traffic never parsed as that port's protocol — a tunnel, a backdoor on a port chosen to look innocuous, or a misconfiguration |

`-rate-threshold` is a **rate**, in packets per second, and is
independent of `-window`. Widening the window to catch a slow scan does
not make the flood detector more sensitive.

### 3. Behavioural detection

Some questions cannot be answered inside a worker, because ARGUS shards
packets by host *pair* so that both directions of a connection land on
one thread. A source sweeping a subnet is spread across every worker, and
no single one of them sees more than a fraction of it. So workers emit
small `Observation` values — one per *event*, not per packet — to a
single aggregator thread that owns all cross-source state.

| Alert | Raised when |
|---|---|
| `HORIZONTAL_SCAN` | One source failed to get an answer from many distinct hosts **on the same port** |
| `HOST_SWEEP` | The same, spread across arbitrary ports — a higher bar |
| `BRUTE_FORCE` | Many authentication attempts to one service (FTP `USER`/`PASS`, SMTP `AUTH`, RDP cookies, SSH) |
| `BEACONING` | Repeated connections to one service at a regular interval with low jitter — the shape of an automated callback rather than a person |
| `DATA_EXFIL_VOLUME` | One source sent more than the configured volume outbound inside the window |
| `DATA_EXFIL_RATIO` | One source sent far more than it received, above a volume floor |
| `DNS_TUNNEL` | Many distinct high-entropy subdomains queried under one parent domain |
| `DNS_LONG_NAME` | A single question name both unusually long and high-entropy |

Scan detection counts **unanswered** connections specifically. "Many
destinations on one port" describes a port sweep and equally describes a
web browser; "many destinations on one port that never answered"
describes only the sweep. Multicast and broadcast destinations are
excluded from behavioural analysis entirely — service-discovery
protocols re-announce on a fixed timer by specification, which is
perfectly periodic by design and not evidence of anything.

---

## Protocol coverage

### Link and network layers

- Ethernet, raw IP, BSD loopback (`NULL`/`LOOP`), Linux cooked capture
  (`SLL`/`SLL2`)
- 802.1Q VLAN and QinQ stacking, up to 3 tags
- IPv4 and IPv6, including extension-header chains
- ICMP and ICMPv6
- **Tunnels:** IP-in-IP, 6in4, GRE (including Transparent Ethernet
  Bridging), VXLAN, decapsulated up to 4 layers deep. ESP is counted but
  not chased, since its payload is encrypted
- **IP fragment reassembly** for both IPv4 and IPv6, with a configurable
  overlap policy (`-frag-policy first|last`) so the sensor can be made to
  resolve overlapping fragments the way the hosts it protects do
- **Jumbo frames**, up to 9216 bytes of inspectable payload

### Transport

- TCP with full stream reassembly: out-of-order segments, retransmissions,
  and a configurable per-direction reassembly budget
- UDP, with reply tracking for scan detection
- ICMP/ICMPv6 conversation tracking

### Application

Parsers extract structured fields, which then become matchable buffers.
A parser that fails leaves its buffers empty rather than guessing, so a
rule scoped to `buffer:http.uri` implicitly means "traffic that actually
parsed as HTTP".

| Protocol | Extracted |
|---|---|
| HTTP | method, URI, host |
| DNS | question name (queries and responses) |
| TLS | SNI, JA3 client fingerprint |
| FTP | command lines |
| SSH | version banner |
| SMTP | command, sender, recipient |
| SMB2/3 | command, filename |
| Modbus/TCP | function name, register address |
| RDP | connection-request cookie |
| TFTP | opcode, filename |
| SNMP | community string |
| DNP3 | function code |

Structured parsers require **complete** input before they populate a
buffer. A truncated or split header is not parsed optimistically, so
splitting a request across TCP segments does not defeat a rule scoped to
a parsed field.

---

## Writing rules

ARGUS accepts two rule syntaxes in the same file. Both can be mixed
freely; blank lines and `#` comments are ignored.

### v1: one buffer, one pattern

A compact form for simple content checks.

```
name|buffer|direction|type|pattern
```

```
sqli-union|http.uri|to_server|regex|(?i)union\s+select
suspicious-tld|dns.query|any|regex|\.(zip|top|xyz)$
smb-exec|smb.filename|any|literal|svcctl
modbus-write|modbus.function|to_server|literal|WRITE_
```

- `buffer` — any name from the table below
- `direction` — `any`, `to_server`, or `to_client`
- `type` — `literal` or `regex`

### v2: header scoping, multiple contents, identity

A real signature is a **conjunction**: this protocol, to this port, from
outside this network, with this string near the start of the buffer *and*
that string somewhere after it — and it has an identity, so it can be
correlated downstream and tuned down without being deleted.

```
rule sid:1000001; name:"sqli-union-uri"; severity:high;
     proto:tcp; dst_port:80,443,8000-8100; src_ip:!10.0.0.0/8;
     direction:to_server; buffer:http.uri;
     content:"UNION"; nocase; offset:0; depth:200;
     content:"SELECT"; nocase;
```

(Shown across lines for legibility; a rule is one line in the file.)

| Option | Meaning |
|---|---|
| `sid:<n>` | **Required.** Rule id, emitted on every alert and in the JSON output |
| `name:` / `msg:` | Human-readable name; defaults to `sid-<n>` |
| `severity:` | `low` \| `medium` \| `high` (default `high`) |
| `rev:<n>` | Revision — accepted and ignored, so rules can carry it |
| `proto:` | `tcp` \| `udp` \| `icmp` \| `icmpv6` |
| `src_ip:` / `dst_ip:` | Comma-separated addresses or CIDRs, `!` to negate, `any` for any. IPv4 and IPv6 both; an IPv4 rule never silently matches IPv6 |
| `src_port:` / `dst_port:` | Comma-separated ports and `lo-hi` ranges, `!` to negate |
| `buffer:` | Any buffer name (default `payload`) |
| `direction:` / `flow:` | `any` \| `to_server` \| `to_client` (default `any`) |
| `content:"..."` | A literal that must be present. **Repeatable — all must match.** `!content:` inverts that term |
| `pcre:"..."` / `regex:"..."` | The same, as a regex |
| `offset:<n>` | Start searching this many bytes in — applies to the preceding `content` |
| `depth:<n>` | Search at most this many bytes from `offset` — applies to the preceding `content` |
| `nocase` | Case-insensitive — applies to the preceding `content` |

Content patterns support `\n` `\r` `\t` `\"` `\\` `\|` escapes and
`|hex|` blocks, with or without separating spaces, so signatures for
binary protocols can be written directly:

```
rule sid:1000002; name:"smb2-header"; proto:tcp; dst_port:445; content:"|FE 53 4D 42|"; offset:4; depth:4;
rule sid:1000003; name:"modbus-write-coils"; proto:tcp; dst_port:502; buffer:modbus.function; content:"WRITE_"; severity:medium;
rule sid:1000004; name:"dns-tunnel-shape"; proto:udp; dst_port:53; buffer:dns.query; pcre:"^[0-9a-f]{32}\.";
rule sid:1000005; name:"ftp-nonadmin-login"; buffer:ftp.command; content:"USER"; !content:"anonymous"; severity:low;
```

### Available buffers

| Buffer | Contents |
|---|---|
| `payload` | Reassembled stream payload, or the raw datagram for UDP/ICMP |
| `http.method` `http.uri` `http.host` | Parsed HTTP request fields |
| `dns.query` | Decoded DNS question name |
| `tls.sni` `tls.ja3` | TLS server name, and the JA3 client fingerprint |
| `ftp.command` | Full FTP command line |
| `ssh.version` | SSH version banner |
| `smtp.command` `smtp.sender` `smtp.recipient` | Parsed SMTP fields |
| `smb.command` `smb.filename` | SMB2/3 command and filename |
| `modbus.function` `modbus.address` | Modbus function name and register |
| `rdp.cookie` | RDP connection-request cookie |
| `tftp.opcode` `tftp.filename` | TFTP fields |
| `snmp.community` | SNMP community string |
| `dnp3.function` | DNP3 function code |

### Rules rejected at load time

Two shapes are refused rather than accepted and regretted: a rule with no
`content` or `pcre` at all (it would match every buffer of its type), and
a rule whose every term is negated (it would fire on essentially all
traffic). Both are the kind of mistake that buries an operator in alerts,
and both are cheaper to catch when the file loads than at 3am.

### Rule performance

Each `(buffer, direction)` group gets an Aho-Corasick prefilter built
from the longest required literal of every rule in it. One pass finds
which rules are even candidates; only those are fully evaluated. Header
terms are checked *before* content, so a rule scoped to `dst_port:502`
costs an integer comparison on traffic that isn't Modbus.

A rule with no usable literal — all-regex, or whose only literals are
negated — cannot be prefiltered and is evaluated against every buffer of
its type. Include at least one plain `content` in any rule that needs to
be fast.

---

## Importing Suricata and Emerging Threats rules

`tools/suricata.py` translates Suricata/Snort rules into ARGUS v2 rules.

```bash
python tools/suricata.py emerging-all.rules -o et-open.rules \
    --home-net 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12

argus -iface eth0 -rules et-open.rules
```

Against ET Open's 51,074 active rules, **26,691 convert — 52.3%.**

The governing rule is **skip anything that cannot be represented
faithfully.** A rule translated wrongly is worse than one skipped,
because it fails silently and in whichever direction the mistranslation
went. Dropping a `distance:` modifier, for instance, turns "this string
immediately after that one" into "both strings anywhere" — a looser rule
wearing the original's name and sid, which would then be trusted. Every
option is either mapped exactly or the whole rule is rejected with a
recorded reason.

```bash
python tools/suricata.py emerging-all.rules --stats
```

`--stats` prints the rejection reasons, so the coverage figure is
auditable rather than asserted.

### What converts

- **App-layer rule types.** `alert http` / `alert tls` / `alert dns` are
  not port-based in Suricata — they mean "traffic the app-layer parser
  identified as HTTP". ARGUS expresses the same thing differently: its
  buffers are populated *only* when its own parsers succeeded, so
  `buffer:http.uri` already carries that meaning
- **Transform idioms.** `dotprefix; content:".evil.com"; endswith` is the
  dominant modern pattern for domain matching, and is exactly the regex
  `(^|\.)evil\.com$`. `dotprefix`, `endswith`, `startswith` and the
  expressible case of `bsize` are all handled
- **Severity** from ET's `signature_severity` metadata, falling back to
  `classtype`
- **`$HOME_NET`/`$EXTERNAL_NET`** from `--home-net`; `$HTTP_PORTS` and
  friends from a built-in table

### What does not

The remaining blockers are capability gaps, each counted rather than
quietly approximated:

- Buffers ARGUS doesn't extract: `http.header`, `http.user_agent`,
  `http.request_body`, `file.data`, `tls.cert_subject`
- Options it can't express: `distance`/`within` relative positioning,
  `flowbits` cross-flow state, `byte_test`/`byte_jump`, `dsize`

### Cost

26,691 rules is not free. See [Performance](#performance). ET Open ships
as per-category files, and most deployments enable a fraction of them —
if throughput matters more than coverage, cut the ruleset rather than
tuning ARGUS.

---

## Output

### Alerts

Human-readable by default, NDJSON under `-json`. Both go to stdout and to
`-logfile` simultaneously.

```json
{"timestamp":1789746085,"severity":"MEDIUM","category":"PORT_SCAN","src":"192.168.0.112","dst":"192.168.0.1","proto":"TCP","port":21,"sid":0,"message":"21 distinct TCP ports touched on this destination in the last 60s (limit 20)"}
```

Duplicate alerts are collapsed within `-suppress-window`, keyed per
category so that the key matches what each category is actually about —
`PACKET_FLOOD` collapses across destinations because volume from one
source is one event, while `PORT_SCAN` does not, because two victims are
two events.

### Connection records

With `-flow-log`, every TCP, UDP and ICMP conversation writes an NDJSON
record as it completes:

```json
{"start":1789746085,"duration":2.140,"src":"192.168.0.112","src_port":51234,
 "dst":"93.184.216.34","dst_port":443,"proto":"TCP","state":"closed","vlan":0,
 "pkts_to_server":12,"pkts_to_client":9,"bytes_to_server":1840,"bytes_to_client":24120,
 "flags_to_server":"SAPF","flags_to_client":"SAPF","alerts":0,"tls_sni":"example.com",
 "tls_ja3":"e7d705a3286e19ea42f587b344ee6865"}
```

`state` is one of `reset`, `closed`, `half_closed`, `timeout` or `open`
(the last meaning the capture ended while the connection was live).
`http_host`, `http_uri`, `tls_sni`, `tls_ja3` and `ssh_version` appear
when the relevant parser succeeded.

Flow records are off by default. They are useful as a lightweight
netflow-style corpus and for post-hoc investigation, but on a busy link
they are the highest-volume output ARGUS produces.

### Packet capture around alerts

ARGUS keeps a ring of the most recent `-pcap-retain` frames and writes
them to a `.pcap` in `-pcap-dir` whenever an alert fires:

```
logs/1789746085_0003_PORT_SCAN_TCP_192.168.0.112.pcap
```

This is the difference between an alert you can investigate and an alert
you can only believe. It defaults to 500 packets live, and to disabled
under `-r`, where the capture is already on disk.

### Shutdown summary

On exit ARGUS prints what it saw and what it had to refuse:

```
argus: replay complete — 791615 frames read, 791613 packets decoded,
       0 fragments buffered, 2 frames undecoded; 291 alerts written, 3253 suppressed
argus: decode detail: 2 malformed IP header, 2 tunnel layers stripped
```

Every bounded table reports its refusals. A sensor that silently stops
tracking things under load is worse than one that says so.

---

## Command-line reference

Exactly one of `-iface` or `-r` is required, unless `-list-interfaces`.

### Input

| Flag | Default | Meaning |
|---|---|---|
| `-iface <name>` | — | Interface to monitor |
| `-r <file.pcap>` | — | Replay a capture instead (also `-read`) |
| `-filter <bpf>` | — | BPF filter applied in the kernel, before ARGUS sees anything |
| `-list-interfaces` | — | List capture-able interfaces and exit |

### Detection

| Flag | Default | Meaning |
|---|---|---|
| `-rules <path>` | — | Rule file (also `-signatures`) |
| `-blacklist <path>` | — | IP blacklist, one address per line |
| `-window <dur>` | `10s` | Sliding window for anomaly thresholds |
| `-rate-threshold <n>` | `500` | Packets **per second** before `PACKET_FLOOD`; independent of `-window` |
| `-scan-threshold <n>` | `20` | Distinct ports per window before `PORT_SCAN` |
| `-no-behavior` | off | Disable behavioural detection entirely |
| `-behavior-window <dur>` | `5m` | Window the behavioural detectors judge over |
| `-frag-policy first\|last` | `first` | Which copy wins when IP fragments overlap. `first` is BSD/Linux, `last` is Windows — match the hosts you protect |

### Output

| Flag | Default | Meaning |
|---|---|---|
| `-logfile <path>` | `argus-alerts.log` | Alert log |
| `-json` | off | NDJSON alerts instead of human-readable text |
| `-suppress-window <dur>` | `15s` | Collapse duplicate alerts within this window |
| `-flow-log <path>` | off | NDJSON connection records |
| `-pcap-dir <path>` | `logs` | Where per-alert captures are written |
| `-pcap-retain <n>` | `500` | Frames of recent traffic kept ready to dump; `0` disables |

### Resources

Every one of these is a hard bound. Under pressure ARGUS refuses new
entries and counts the refusal, rather than evicting a live one — if
pressure evicted live entries, an attacker could flood junk to push out
the state tracking a real attack, and a memory bound would have become an
evasion primitive.

| Flag | Default | Meaning |
|---|---|---|
| `-workers <n>` | CPU count | Parallel detection workers |
| `-packet-pool <n>` | `4096` | Recycled packet buffers. **This is what bounds packet memory**, independent of worker count |
| `-queue-size <n>` | `1024` | Per-worker queue depth; slots hold pooled handles, so a slot costs 8 bytes |
| `-alert-queue <n>` | `16384` | Alert channel depth before alerts are shed |
| `-payload-cap <bytes>` | `9216` | How much of each payload detection may see. Lowering it cuts CPU, not memory |
| `-stream-cap <bytes>` | `16384` | Reassembled-payload budget per TCP direction |
| `-max-flows <n>` | `65536` | Per-worker cap on tracked TCP connections |
| `-max-sources <n>` | `65536` | Per-worker cap on tracked source addresses |

---

## Architecture

```
                  ┌──────────────┐
   NIC / pcap ───►│   capture    │  single thread, libpcap
                  └──────┬───────┘
                         │  Box<Packet> from a fixed pool
                  ┌──────▼───────┐
                  │    decode    │  link type, VLAN, tunnels,
                  └──────┬───────┘  IP fragment reassembly
                         │
              shard by hash(host pair)
          ┌──────────┬───┴──────┬──────────┐
     ┌────▼────┐┌────▼────┐┌────▼────┐┌────▼────┐
     │ worker  ││ worker  ││ worker  ││ worker  │  TCP reassembly,
     └────┬────┘└────┬────┘└────┬────┘└────┬────┘  parsers, rules,
          │          │          │          │       anomaly windows
          ├──────────┴────┬─────┴──────────┤
          │ Observations  │     Alerts     │
     ┌────▼─────────┐     │      ┌─────────▼────────┐
     │  behaviour   │─────┴─────►│   alert writer   │
     │  aggregator  │   Alerts   │ suppress, log,   │
     └──────────────┘            │ dump pcap        │
                                 └──────────────────┘
```

### Host-pair sharding

Packets are dispatched to workers by a hash of the **host pair** that is
symmetric in the two endpoints. Both directions of a connection therefore
land on the same worker, which is what lets each worker own a
connection's entire reassembly state with no locking at all.

That choice has a direct consequence: `src=A,dst=B` and `src=A,dst=C`
hash to *different* workers, so a source sweeping a subnet is spread
across all of them and no single worker sees more than a fraction of it.
This cannot be fixed by raising a threshold — the evidence genuinely
isn't in one place. Coarsening the shard key to source alone isn't
available either, because TCP reassembly needs both directions together.

That is why behavioural detection is a separate stage fed by
`Observation` values rather than another check inside the worker.

### No allocation on the hot path

`Packet` is a fixed-size, pointer-free value. Packets are drawn from a
pool of pre-allocated `Box<Packet>` and returned to it, so the channel
moves an 8-byte pointer rather than copying a packet, and steady-state
capture performs no allocator work. Buffers are reset field-by-field
rather than zeroed, since memsetting a 9KB payload array per packet costs
more than parsing the headers.

Packet memory is therefore fixed by `-packet-pool` and does not grow with
`-workers`. Exhausting the pool sheds frames and reports the count; it
never allocates its way out of a flood.

### Single-consumer output

Both the behaviour aggregator and the alert writer are single threads
fed by channels. One consumer means no locks on the state they own, and
means suppression and flow-record ordering are deterministic.

---

## Performance

Measured on an 8-core desktop replaying `bigFlows.pcap` (791,615 frames
of real enterprise traffic).

| Ruleset | Rule load | Replay time | Throughput |
|---|---|---|---|
| 51 hand-written rules | instant | 1.4s | ~565k pps |
| 26,691 ET Open rules | 1.5s | 50.8s | ~16k pps |

A 35× slowdown for 500× the rules. The scaling is sublinear — 26× the
rules costs 8.9× the time — which is the Aho-Corasick prefilter doing its
job.

One detail matters enormously here. Anchoring a term forces it into a
regex, and a rule whose every term is a regex has no literal for the
prefilter to key on, so it falls into the "evaluate always" list and runs
against every buffer of every packet. The first working translation of
ET Open left 89% of rules unprefilterable; emitting the implied literal
alongside the anchored regex — semantically a no-op, since the regex
already requires those bytes — took that to 0%.

Decode rate on the same capture is **791,613 of 791,615 frames**, the two
exceptions being genuinely malformed IP headers.

---

## Testing and measurement

```bash
cargo test --release          # 209 unit and integration tests
python tools/corpus.py corpus # replay a directory of captures
python tools/detect.py        # graded detection against synthetic attacks
```

### `tools/corpus.py` — survival and noise

Replays a directory of captures and grades each on three axes: does it
survive, does it decode, does it detect. Exits non-zero on a crash, a
hang, or a capture that fails to decode. This is the test that answers
"does ARGUS handle real traffic without falling over or screaming?"

### `tools/detect.py` — detection floor

Public attack captures either arrive unlabelled or inside archives whose
password is published only as an image, deliberately, to stop
automation. So this constructs the labels instead: each case writes a
pcap containing exactly one attack, declares the alert category that
attack must produce, replays it through the real binary, and grades the
result.

```
port_scan          PORT_SCAN              DETECTED
horizontal_scan    HORIZONTAL_SCAN        DETECTED
packet_flood       PACKET_FLOOD           DETECTED
brute_force        BRUTE_FORCE            DETECTED
beaconing          BEACONING              DETECTED
exfil_ratio        DATA_EXFIL_RATIO       DETECTED
dns_tunnel         DNS_TUNNEL             DETECTED
dns_long_name      DNS_LONG_NAME          DETECTED
signature_dns      SIGNATURE_MATCH        DETECTED
signature_http     SIGNATURE_MATCH        DETECTED

detection rate: 10/10 (100%) on modelled attacks
```

**That 100% must not be read as "ARGUS detects 100% of attacks."** These
attacks are presented plainly: no packet loss, no retransmissions, no
evasion, no background traffic to hide in, and every threshold crossed
decisively rather than skirted. A real attacker tunes to sit just under
whatever line you drew.

What the number means is "all ten modelled attacks, presented plainly,
were detected" — a regression floor plus a published list of what is
modelled at all. It is worth having precisely because it can fall.

---

## Deployment notes

### Capture privileges

Live capture needs raw socket access: run as root, grant
`CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux, or use an Administrator shell on
Windows with Npcap installed.

### Use a BPF filter

`-filter` runs in the kernel, before ARGUS sees anything. On a busy link
it is by far the cheapest way to cut load — excluding your own management
traffic, or scoping to the segments you care about, costs nothing at all
in ARGUS.

### Tuning for your network

The shipped thresholds are tuned to be quiet on real traffic rather than
thorough, because a behavioural alert that fires on backup jobs and
monitoring checks trains its reader to ignore it, which is worse than not
having it. Expect to adjust:

- `-window` and `-scan-threshold` together for scan sensitivity
- `-behavior-window` — longer sees slower campaigns but holds more state
- `-suppress-window` for how chatty repeated alerts are allowed to be

Start by running with `-flow-log` for a day and reading what your network
actually looks like before changing thresholds.

### Beacons to known-good services

`BEACONING` reports a *shape*, and the shape of a chat client polling an
API every 60 seconds is identical to the shape of an implant checking in
every 60 seconds. No threshold separates them — only knowing something
about the far end does. Treat these as "worth a look" rather than
"confirmed", and resolve recurring ones by identifying the destination.

### JA3

The JA3 matching mechanism ships; the fingerprint list does not.
`ja3-blocklist.txt` is deliberately empty, because a JA3 blocklist is
only as good as its freshness and provenance, and shipping a stale one
would produce confident alerts on fingerprints that have since moved to
entirely legitimate software.

---

## Limitations

These are known and deliberate, listed so that nobody has to discover
them during an incident.

**It is an IDS, not an IPS.** ARGUS observes and reports. It does not
block, reset connections, or modify traffic.

**Detection is measured against synthetic attacks.** `tools/detect.py`
gives a floor across ten modelled attacks. Nothing here measures
detection of an attacker who tunes to sit just under a threshold, and
nothing measures categories not modelled at all. A labelled real-world
attack corpus remains the missing measurement.

**Roughly half of ET Open doesn't translate**, for reasons listed under
[Importing rules](#what-does-not) — missing buffers and inexpressible
options, each a real capability gap.

**No encrypted-traffic inspection.** TLS is identified, fingerprinted and
its SNI extracted, but not decrypted. ESP payloads are counted, not
inspected. QUIC and HTTP/2 are not parsed at all, which is a growing
blind spot as traffic moves to them.

**Brute force counts attempts, not failures.** ARGUS parses client
commands, not server replies, so it cannot see a rejection. The threshold
is set accordingly — a person does not try to authenticate twenty times a
minute even when they keep getting it wrong — but it remains a weaker
signal than a real failed-login counter.

**No threat-intelligence enrichment.** There is no reputation feed, no
domain intelligence, and no asset inventory. Alerts describe traffic, not
actors.

**Limited operational surface.** No rule hot-reload (restart to pick up
rule changes), no log rotation, no service wrapper, no metrics endpoint,
and no syslog or SIEM-native output. Alerts are NDJSON on stdout and in a
file; wiring that into anything else is currently your job.

**Single interface per process.** Monitoring several links means several
processes.

---

## Project layout

```
src/
  main.rs       capture, dispatch, packet pool, CLI, output plumbing
  decode.rs     link types, VLAN, tunnels, IP fragment reassembly
  packet.rs     the Packet value, link and IP parsing
  engine.rs     alerts, flow table, protocol parsers, anomaly detection
  rules.rs      the v2 rule language: parsing, prefilter, evaluation
  behavior.rs   cross-flow behavioural detection
  window.rs     sliding-window primitives shared by every detector

tools/
  corpus.py     replay a directory of captures; grade survival and noise
  detect.py     graded detection against synthetic attacks
  suricata.py   translate Suricata/Snort rules into ARGUS v2 rules

rules.txt          bundled example rules, v1 and v2
blacklist.txt      example IP blacklist
ja3-blocklist.txt  JA3 fingerprint list (ships empty, by design)
```

Roughly 12,400 lines of Rust across seven modules, about two thirds of
which are tests.
