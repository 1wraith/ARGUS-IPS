# ARGUS

A network intrusion detection system written in Rust.

ARGUS reads packets from live interfaces or a saved capture, reassembles
TCP streams and IP fragments, parses application protocols, and reports
what it finds through four independent layers: signature matching,
statistical anomaly detection, cross-flow behavioural analysis, and
reputation enrichment. It writes alerts as text, NDJSON or EVE-JSON to
files, stdout and syslog; exposes Prometheus metrics; reloads its rules
without dropping a packet; and saves a `.pcap` of the surrounding traffic
for every alert it raises.

It runs **99.8% of the Emerging Threats Open ruleset** (50,989 of 51,074
rules translate), is a single binary with no runtime dependencies beyond
libpcap/Npcap, and needs no database.

```
argus -config /etc/argus/argus.conf
```

---

## Contents

- [Quick start](#quick-start)
- [Running at full strength](#running-at-full-strength)
- [What it detects](#what-it-detects)
- [Protocol coverage](#protocol-coverage)
- [Writing rules](#writing-rules)
- [Importing Suricata and Emerging Threats rules](#importing-suricata-and-emerging-threats-rules)
- [Enrichment](#enrichment)
- [Output](#output)
- [Running as a service](#running-as-a-service)
- [Configuration reference](#configuration-reference)
- [Architecture](#architecture)
- [Performance](#performance)
- [Testing and measurement](#testing-and-measurement)
- [Limitations](#limitations)
- [Project layout](#project-layout)

---

## Quick start

### Requirements

- Rust 1.70 or newer
- **Linux/macOS:** `libpcap` development headers (`libpcap-dev`,
  `libpcap-devel`, or `brew install libpcap`)
- **Windows:** [Npcap](https://npcap.com/) installed, plus the Npcap SDK
  for building
- **Python 3** for the rule translator and the measurement tools (no
  packages needed)

### Build

```bash
cargo build --release
```

The binary is `target/release/argus` (`target\release\argus.exe` on
Windows). The rest of this document writes `argus`; use the full path, or
put it on your `PATH`.

### Run

Live capture needs elevated privileges: `sudo` on Unix, an Administrator
shell on Windows.

```bash
# List capture-able interfaces
argus -list-interfaces

# Monitor an interface
sudo argus -iface eth0 -rules rules.txt -json

# Monitor several interfaces in one process
sudo argus -iface eth0 -iface eth1 -rules rules.txt

# Replay a saved capture (no privileges needed)
argus -r capture.pcap -rules rules.txt -json
```

On Windows an interface is named like `\Device\NPF_{3F2A…}`; copy it from
`-list-interfaces` and quote it.

Replay runs the identical detection pipeline, timed by each packet's own
capture timestamp, and never drops a packet. **One file always yields
exactly the same alerts**, run after run, which makes it usable for
regression testing and for investigating an alert after the fact.

### Configuration file

Every option can live in a file instead. A config key **is** the flag
name without its leading dash, so there is one name per setting and
`-help` documents the file too.

```bash
argus -generate-config > argus.conf
```

```ini
# argus.conf
[capture]
iface  = eth0
iface  = eth1
filter = "not port 22"

[detection]
rules          = /etc/argus/et-open.rules
rate-threshold = 500
window         = 60s

[enrichment]
intel     = /etc/argus/intel.txt
allowlist = /etc/argus/allow.txt
home-net  = 192.168.0.0/16,10.0.0.0/8

[output]
format       = eve
logfile      = /var/log/argus/argus.eve
log-max-size = 100M
syslog       = tcp://siem.internal:514

[operations]
metrics = 127.0.0.1:9109
```

ARGUS looks for `./argus.conf` then `/etc/argus/argus.conf` when
`-config` is not given. A flag on the command line always overrides the
file, so one setting can be changed for one run without editing the
deployed configuration.

---

## Running at full strength

"Full strength" means the whole Emerging Threats ruleset, every detection
layer on, your own network described to it, and outputs and metrics wired
up. Four steps.

**1. Build.**

```bash
cargo build --release
```

**2. Get the rules and translate them.** Download the Emerging Threats
Open ruleset (`emerging-all.rules`, from rules.emergingthreats.net) and
translate it. `--home-net` should list *your* internal ranges, because ET
rules are written in terms of `$HOME_NET` and `$EXTERNAL_NET`. **Always pass it,
and always run `--validate`.** Without a home network `$EXTERNAL_NET` means
"any", and a rule written for traffic from outside fires on your own machines
(a live run alerted on a router's UPnP announcements for exactly that reason),
so the translator now defaults to the private ranges, as Suricata does, and
says so. And a rules file containing one rule ARGUS refuses is rejected whole
on reload (the previous rules stay in force), which `--validate` prevents.
`--validate` has ARGUS itself confirm every generated rule loads.

```bash
python tools/suricata.py emerging-all.rules -o et-open.rules \
    --home-net 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 \
    --validate target/release/argus
```

(On Windows use `target\release\argus.exe`.) Expect about 51,000 rules
converted and 0 refused. Re-run this whenever you download a newer
ruleset.

**3. Check the rules load.**

```bash
argus -check-rules et-open.rules
```

**4. Run.** From an elevated shell:

```bash
argus \
  -iface eth0 \
  -rules et-open.rules \
  -home-net 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 \
  -intel intel.txt \
  -allowlist allow.txt \
  -format eve -logfile /var/log/argus/argus.eve \
  -flow-log /var/log/argus/flows.ndjson \
  -metrics 127.0.0.1:9109 \
  -window 60s -behavior-window 5m \
  -stream-cap 65536 \
  -packet-pool 16384
```

What each choice buys:

| Flag | Why |
|---|---|
| `-rules et-open.rules` | The ~51,000 translated ET rules. Behavioural, anomaly and intel detection run regardless |
| `-home-net …` | Gives every alert an inbound/outbound/internal direction, and tells ET's `$HOME_NET` rules what "inside" is |
| `-intel` / `-allowlist` | Reputation feeds, and a way to make a verdict stick. Both are optional; create the files first if you use them |
| `-format eve` | The format a SIEM that already reads Suricata will ingest |
| `-flow-log` | One record per connection, with parsed fields (hostnames, users, file hashes) |
| `-metrics` | Prometheus endpoint at `/metrics`; bind to loopback or a management address |
| `-window 60s` | A wider window catches slow scans, at the cost of holding more state |
| `-stream-cap 65536` | How much of each direction is reassembled for matching; the default (16384) sees only the first 16 KB of each direction. Larger catches indicators deeper in a stream but uses more memory per busy connection |
| `-packet-pool 16384` | More recycled packet buffers, so a burst does not exhaust the pool. This is what bounds packet memory |

Leave `-workers` alone unless you want fewer than one per CPU core. Watch
`argus_*` counters (or the shutdown summary): if capture drops or pool
exhaustion are non-zero, raise `-packet-pool` and `-queue-size`.

On Windows, put the flags in a config file and let the packaged task run
it (see [Running as a service](#running-as-a-service)). On Linux, install
the systemd unit; `systemctl reload argus` re-reads rules with no dropped
packets.

To try it on a capture first, without privileges:

```bash
argus -r corpus/bigFlows.pcap -rules et-open.rules -json -logfile alerts.log
```

---

## What it detects

Detection is split across four layers that ask different questions and
fail independently. A signature knows exactly what it is looking for and
nothing else; an anomaly detector knows nothing about content but notices
volume and spread; behavioural analysis sees across connections that no
single worker can; enrichment knows things the packets never say. Each
catches what the others structurally cannot.

### 1. Signature matching

Content matching against reassembled TCP streams and parsed protocol
fields, with an Aho-Corasick prefilter so rule count scales sublinearly.
See [Writing rules](#writing-rules).

| Alert | Raised when |
|---|---|
| `SIGNATURE_MATCH` | A rule matched. Carries the rule's `sid`, name, severity and the buffer it matched in |
| `BLACKLIST_IP` | Either endpoint appears in the blacklist file |

Matching happens on the **reassembled** stream, so a signature split
across TCP segments still matches, as does one hidden behind out-of-order
delivery, overlapping segments, or overlapping IP fragments. All of these
are measured; see [Testing and measurement](#testing-and-measurement).

### 2. Statistical anomaly detection

Per-worker, per-source sliding windows over packet rate and port spread.

| Alert | Raised when |
|---|---|
| `PORT_SCAN` | One source touched more than `scan-threshold` distinct ports on one destination inside the window. TCP counts SYNs only; UDP is reply-aware, so a source that gets answers is not scanning |
| `PACKET_FLOOD` | One source exceeded `rate-threshold` packets **per second**, summed across its destinations **and across every worker**, over a fixed ten seconds |
| `PROTOCOL_ANOMALY` | A connection on a well-known port whose traffic never parsed as that port's protocol: a tunnel, a backdoor on a port chosen to look innocuous, or a misconfiguration |

`rate-threshold` is a rate and is independent of `window`, in both
directions: widening the window to catch a slow scan neither makes the flood
detector more sensitive nor averages a burst away. The flood is judged
over a fixed ten seconds, and on the *sum* across workers: packets are
sharded by host pair, so a source flooding several destinations is split
across workers and each sees a fraction of it. Each worker reports its
per-second count to the aggregator, which judges the total. (With
`-no-behavior` there is no aggregator, and each worker judges its own share.)

### 3. Behavioural detection

Some questions cannot be answered inside a worker, because ARGUS shards
packets by host *pair* so that both directions of a connection land on
one thread. A source sweeping a subnet is spread across every worker and
no single one sees more than a fraction of it. So workers emit small
`Observation` values, one per *event* and not per packet, to a single
aggregator thread that owns all cross-source state.

| Alert | Raised when |
|---|---|
| `HORIZONTAL_SCAN` | One source failed to get an answer from many distinct hosts **on the same port** |
| `HOST_SWEEP` | The same, spread across arbitrary ports, a higher bar |
| `BRUTE_FORCE` | Many authentication attempts to one service, **or** many the server *refused*: FTP 530, SMTP 535, HTTP 401, SMB logon failure, Kerberos `KRB-ERROR`, LDAP `invalidCredentials`. A refusal is the server's own testimony and is held to a far lower bar than an attempt |
| `BEACONING` | Repeated connections to one service at a regular interval with low jitter |
| `DATA_EXFIL_VOLUME` | One source sent more than the configured volume outbound inside the window |
| `DATA_EXFIL_RATIO` | One source sent far more than it received, above a volume floor. Judged while connections are open (each reports every 30 seconds), not only when they end |
| `DNS_TUNNEL` | Many distinct high-entropy subdomains queried under one parent domain |
| `DNS_LONG_NAME` | A single question name both unusually long and high-entropy |

Scan detection counts **unanswered** connections specifically. "Many
destinations on one port" describes a port sweep and equally describes a
web browser; "many destinations on one port that never answered"
describes only the sweep. Multicast and broadcast destinations are
excluded from behavioural analysis entirely: service-discovery protocols
re-announce on a fixed timer by specification, which is perfectly
periodic by design and not evidence of anything. So are directed
broadcasts of the private ranges (`192.168.0.255`): a sensor cannot know the
netmask, and on those ranges a host ending in 255 is overwhelmingly a
broadcast.

**Tuning on a real network.** Behavioural alerts describe a *shape*, and
the commonest benign shapes are yours: a chat or API client uploading a large
conversation (a big request, a small reply) reads as `DATA_EXFIL_RATIO`, and a
browser's keepalives read as `BEACONING`. Make the verdict stick with the
[allowlist](#allowlist), for example
`category:DATA_EXFIL_RATIO dst:160.79.104.10 dst_port:443`.

### 4. Reputation enrichment

| Alert | Raised when |
|---|---|
| `THREAT_INTEL` | An address, domain or TLS fingerprint matched a loaded feed |

See [Enrichment](#enrichment).

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
- **IP fragment reassembly** for IPv4 and IPv6, with a configurable
  overlap policy (`frag-policy first|last`) so the sensor resolves
  overlapping fragments the way the hosts it protects do
- **Jumbo frames**, up to 9216 bytes of inspectable payload

### Transport

- TCP with full stream reassembly: out-of-order segments, retransmissions,
  overlapping segments (first copy wins, and a held segment that later
  data overlaps is still delivered), and a configurable per-direction budget
- UDP, with reply tracking for scan detection
- ICMP/ICMPv6 conversation tracking
- **QUIC**, including decryption of the Initial packet, see below

### Application

Parsers extract structured fields, which become matchable buffers. A
parser that fails leaves its buffers empty rather than guessing, so a
rule scoped to `buffer:http.uri` implicitly means "traffic that actually
parsed as HTTP".

| Protocol | Extracted |
|---|---|
| HTTP request | method, URI (raw and percent-decoded), host, header block, header names, user agent, cookie, accept / accept-encoding / accept-language, referer, protocol version, body |
| HTTP response | status code and message, status line, header block, content type and length, `Server`, `Location`, `Set-Cookie`, body |
| DNS | question name (queries and responses) |
| TLS | SNI, JA3 client fingerprint; the server's chosen version and **JA3S** fingerprint (also under TLS 1.3, where the ServerHello is in the clear); and **the server's certificate** (subject, issuer, serial, raw DER) for TLS before 1.3 |
| **QUIC** | SNI and JA3 from the Initial packet, plus version and connection IDs |
| **SMB1/2/3** | command, filename, share path |
| **NTLM** | account, domain, workstation, wherever it is embedded |
| **Kerberos** | realm, client principal, requested service |
| **LDAP** | bind DN, search base, whether the bind was cleartext |
| **DCERPC** | interface UUID, with well-known services named |
| FTP | command lines |
| SSH | version banner |
| SMTP | command, sender, recipient |
| Modbus/TCP | function name, register address |
| RDP | connection-request cookie |
| TFTP | opcode, filename |
| SNMP | community string |
| DNP3 | function code |
| **Transferred files** | MD5, SHA-256, size, type by magic number, and a libmagic-style description (`Zip archive data`, `POSIX tar archive`), for request *and* response bodies, hashed as they stream so a download of any size is covered |

Structured parsers require **complete** input before they populate a
buffer, so splitting a request across TCP segments does not defeat a rule
scoped to a parsed field.

Each parser that recognises its protocol also records that fact on the
flow (as a flowbit named `app.rdp`, `app.smtp`, `app.ftp`, `app.ssh`,
`app.smb`, `app.tls` or `app.http`), so a rule can say "any traffic
ARGUS identified as RDP" without a buffer of its own.

### QUIC

A growing share of web traffic is no longer TLS-over-TCP; it is UDP on
port 443, and without this a QUIC conversation is a volume statistic.

ARGUS reads the **Initial** packet. That is possible by design, not by
attack: its keys are derived from the Destination Connection ID, which
the packet carries in the clear, using a salt published in RFC 9001. The
encryption exists to stop middleboxes *modifying* the handshake, not to
hide it, and what comes out is the ClientHello, which TLS-over-TCP sends
in plaintext anyway.

So ARGUS gets the SNI, the JA3, the version and the connection IDs, and
then sees volumes. Everything past the handshake is encrypted with
negotiated keys an observer never sees, which is the whole point of QUIC.
The implementation is checked against the worked example in RFC 9001
Appendix A and round-trips real packets in both QUIC v1 and v2.

### Lateral movement

The traffic that carries an intrusion *after* the first host falls is
different from the traffic that carries the first host falling: SMB,
NTLM, Kerberos, LDAP and DCERPC, on an internal network, very largely in
the clear. ARGUS reads the identities they carry.

```
rule sid:1; name:"service account from an unexpected host"; proto:tcp;
     buffer:ntlm.user; content:"svc_"; severity:high;

rule sid:2; name:"remote service creation"; proto:tcp; dst_port:135,445;
     buffer:dcerpc.interface; content:"367abb81-9844-35f1"; severity:high;
```

An NTLM `AUTHENTICATE` names the account, its domain and the workstation
it came from. A DCERPC bind names the interface, and several of them (the
Service Control Manager, the Task Scheduler, DRSUAPI) *are* the
remote-execution and credential-theft paths. Reaching them is itself the
event.

---

## Writing rules

ARGUS accepts two rule syntaxes in the same file. Both can be mixed;
blank lines and `#` comments are ignored.

### v1: one buffer, one pattern

```
name|buffer|direction|type|pattern
```

```
sqli-union|http.uri|to_server|regex|(?i)union\s+select
suspicious-tld|dns.query|any|regex|\.(zip|top|xyz)$
smb-exec|smb.filename|any|literal|svcctl
```

### v2: header scoping, ordered terms, identity

A real signature is a **conjunction**: this protocol, to this port, from
outside this network, with this string near the start of the buffer *and*
that string immediately after it, and it has an identity, so it can be
correlated downstream and tuned down without being deleted.

```
rule sid:1000001; name:"sqli-union-uri"; severity:high;
     proto:tcp; dst_port:80,443,8000-8100; src_ip:!10.0.0.0/8;
     direction:to_server; buffer:http.uri;
     content:"UNION"; nocase; offset:0; depth:200;
     content:"SELECT"; nocase; distance:0;
```

(Shown across lines for legibility; a rule is one line in the file.)

| Option | Meaning |
|---|---|
| `sid:<n>` | **Required.** Rule id, emitted on every alert |
| `name:` / `msg:` | Human-readable name; defaults to `sid-<n>` |
| `severity:` | `low` \| `medium` \| `high` (default `high`) |
| `rev:<n>` | Revision, accepted and ignored so rules can carry it |
| `proto:` | `tcp` \| `udp` \| `icmp` \| `icmpv6` |
| `src_ip:` / `dst_ip:` | Addresses or CIDRs, `!` to negate, `any` for any. IPv4 and IPv6 both; an IPv4 rule never silently matches IPv6 |
| `src_port:` / `dst_port:` | Ports and `lo-hi` ranges, `!` to negate |
| `buffer:` | A buffer name (default `payload`). **Repeatable**: a rule may inspect several buffers |
| `direction:` / `flow:` | `any` \| `to_server` \| `to_client` |
| `content:"..."` | A literal that must be present. **Repeatable, all must match.** `!content:` inverts that term |
| `pcre:"..."` | The same, as a regex, run on the linear engine with PCRE's byte semantics. Written without `/…/` delimiters |
| `pcre_bt:"..."` | A regex needing lookaround, backreferences, atomic groups or possessive quantifiers, run on a bounded backtracking engine |
| `relative` | Makes the preceding regex *resume* where the previous term ended (PCRE's `R` flag) |
| `offset:` / `depth:` | Window from the start of the buffer: the match starts at or after `offset` and lies within `depth` bytes of it |
| `distance:` / `within:` | **Relative** window. `distance` moves the start (and may be negative, to look back over the previous match); `within` bounds where the match must *end*. Both are measured from the end of the previous match. Either may name a [variable](#variables) |
| `nocase` | Case-insensitive (ASCII) |
| `transform:<name>` | Read the buffer after a change: `percent_decode`, `url_decode`, `header_lowercase`, `strip_whitespace`, `compress_whitespace`, or its digest (`sha1`, `md5`, `sha256`). Must come before the terms that read the buffer |
| `byte_extract:<n>,<off>,<name>[,mods]` | Read a number and remember it under a name, see [Variables](#variables) |
| `byte_math:bytes N, offset N, oper +, rvalue N\|name, result name[,mods]` | Do arithmetic on a number read from the buffer and remember the result |
| `base64_decode:[bytes N][,offset N][,relative]` | From here on, this rule's terms read the base64-decoded bytes |
| `xbits:<verb>,<name>,track <ip_src\|ip_dst\|ip_pair>[,expire S]` | State shared **between connections**, see [below](#state-across-connections) |
| `byte_test:<n>,<op>,<val>,<off>[,mods]` | Read a number out of the buffer and compare it. Operators `< > = != <= >= &`, and `!` to negate; `string,dec` reads ASCII digits, and a width of `0` reads every digit present |
| `byte_jump:<n>,<off>[,mods]` | Read a length field and move the cursor by it |
| `bsize:<test>` | Length of the buffer: `N`, `<N`, `>N`, `<=N`, `>=N`, or `A<>B` (exclusive at both ends, as in Suricata). Also how `urilen` translates |
| `isdataat:[!]N[,relative]` | Whether data exists `N` bytes on; `!` pins a value to the end of its field |
| `dsize:<test>` | Length of the *packet's* payload, not the stream, so it applies to raw-payload rules only |
| `flags:[!+*]<FSRPAUCE>[,<ignored>]` | TCP flags of the packet: exact, at least (`+`), any (`*`) or none (`!`) |
| `itype:` / `icode:` / `window:` / `ip_proto:` | ICMP type and code, TCP window, IP protocol number; the length-test forms (`N`, `<N`, `>N`, `A<>B`) |
| `stream_size:<server\|client\|both\|either>,<op>,<bytes>` | How much payload each side has sent so far |
| `flowbits:<verb>,<name>` | Per-connection state: `set`, `unset`, `toggle`, `isset`, `isnotset` |
| `flowbits:noalert` / `noalert` | Match and set state, but report nothing |
| `threshold:type <limit\|threshold\|both>,track <by_src\|by_dst\|by_both\|by_rule>,count N,seconds S` | Rate control, see [below](#rate-control) |
| `detection_filter:track <…>,count N,seconds S` | Stay silent until the count is exceeded, then report every match |

Content patterns support `\n` `\r` `\t` `\"` `\\` `\|` escapes and `|hex|`
blocks with or without separating spaces.

**Relative positioning** is what turns "both strings somewhere" into
"this string after that one":

```
rule sid:1000002; name:"tlv-record"; content:"|AA|"; byte_jump:1,0,relative; content:"TARGET"; distance:0;
```

### Regular expressions

Regexes run on one of two engines, and the difference matters.

**`pcre`** uses the linear-time engine: its cost is bounded by the input,
which is why it is the default. It runs with byte semantics, as PCRE does
in Suricata: `.` matches any byte but newline, `\w`, `\d` and `\b` are
ASCII, and case folding is ASCII. (The crate's own default is Unicode,
under which `.` refuses to match a byte that is not valid UTF-8, so a
pattern about binary traffic quietly failed to match the binary traffic.)

**`pcre_bt`** is for the constructs the linear engine cannot express by
design. A backtracking engine can be made to run for a very long time, and
the input is attacker-controlled, so it runs behind a hard step limit
(100,000). A match that exceeds it is abandoned and counted, exposed as
`argus_regex_backtrack_limit_total` and reported at shutdown, so a rule
that keeps being defeated by its input is visible. Two details keep this
honest. An abandoned match counts as *not matched*, and if the pattern is
negated it counts as *not failed to match*; otherwise a negated rule
would fire on exactly the input built to defeat it. And since the engine
reads text, each byte is read as the character with the same code, so a
rule's `\xFF` and a payload's 0xFF mean the same thing; all-ASCII input,
which is most of what crosses a network, is used in place without a copy.

**`relative`** resumes a regex where the previous term ended. It is a
start *offset* into the whole buffer, not a slice of it, so `^` does not
match there and `\b` and lookbehind see the bytes before it. Slicing
would give `\bbar` a word boundary between `foo` and `bar` in `foobar`
that the real stream does not have.

### Several buffers in one rule

A request URI *and* the status the server answered with, say, are written
by naming the buffers in turn:

```
rule sid:1000005; name:"exposed-git-config"; proto:tcp;
     buffer:http.uri; content:"/.git/config";
     buffer:http.stat_code; content:"200";
```

Each buffer is checked when it is parsed, and the rule fires once, when
the last of them has matched on the connection. A rule may name up to 15
buffers. Every part needs something to test (a content, a length test, or
a numeric test of the buffer's value), `distance`/`within` stay inside
their own buffer, and a buffer that exists on only one side of a
connection is evaluated on that side whatever the rule's `flow:` says. A
rule spanning buffers cannot complete on a datagram protocol, which has no
connection to record progress on.

Progress is a small record on the flow: a sorted list for the handful a
typical flow accumulates, switching to a table indexed by rule when a flow
opens many (an ordinary `GET` request is the first part of thousands of
rules).

A buffer may also hold **only negations**: `http.header_names;
content:!"|0d 0a|Accept|0d 0a|"` says "the request was parsed and sent no
`Accept` header", which is how a scripted client differs from a browser.
It is a real claim on a buffer that is parsed once per message, and it
fires only if the buffer exists. It is refused on the raw payload, which
is re-scanned as the stream grows: "does not contain X *yet*" is not a
claim a rule can make.

### Transforms

Rules are written against a *view* of a buffer. The same request URI is
`%2e%2e%2f` to one rule and `../` to another, so a rule says which it
wants:

```
rule sid:1000006; name:"traversal-after-decoding"; buffer:http.uri;
     transform:percent_decode; content:"../";
```

| Transform | Effect |
|---|---|
| `percent_decode` | `%HH` becomes the byte it names. `+` is untouched |
| `url_decode` | `%HH` decoded and `+` becomes a space |
| `header_lowercase` | Header *names* lower-cased, values untouched |
| `strip_whitespace` | Every space, tab and line break removed |
| `compress_whitespace` | Each run of whitespace becomes one space |
| `sha1` / `md5` / `sha256` | The buffer's raw digest, so a rule can name content by its hash (`content:"|a9 99 3e ...|"`) |

Rules are grouped by transform, and each group has its own prefilter over
the transformed bytes, so a literal that exists only after decoding is
still found. A buffer is transformed once per check however many rules
read it, and not at all when nothing in it changes.

### Packet-level rules

`buffer:packet` is one packet's own payload, before any reassembly. It is
what a rule about a single segment reads, and what a rule that has *only*
header conditions reads:

```
rule sid:1000007; name:"syn-to-ssh"; proto:tcp; dst_port:22; flags:S; buffer:packet;
rule sid:1000008; name:"icmp-echo";  proto:icmp; itype:8; buffer:packet;
```

A rule with a packet-level condition (`flags`, `itype`, `icode`,
`window`, `ip_proto`, `stream_size`) needs no content: the condition is
constraint enough. Packet rules cost a scan of every packet, so it is
done only when at least one is loaded.

### Variables

A rule can read a number out of a buffer, keep it, and use it later: a
length field that says how long the next field is, a count the rest of the
record has to agree with.

```
rule sid:1000009; name:"length-field-overrun"; content:"|AA|";
     byte_extract:1,0,len,relative; content:"END"; distance:0; within:len;
```

`byte_extract` reads a number (binary of any width up to 8 bytes, or ASCII
digits) and stores it under a name; `byte_math` reads one, applies `+ - * /
<< >>` against a number or another variable, and stores the result. Names
may then stand in for a number in `offset`, `depth`, `distance`, `within`,
the value or offset of a `byte_test`, and `isdataat`. A rule may name up to
eight, and they live for one evaluation of one buffer's part of a rule. A
variable nothing set means the term that needs it did not match.

Neither term moves the cursor, so a following `distance` measures from the
last *content* match, as in Suricata.

### Base64

`base64_decode` makes the terms after it read decoded bytes: the bytes are
taken from `offset` (from the cursor if `relative`) for `bytes` bytes, or to
the end of the buffer if that is zero. Decoding is tolerant, since these
rules are about encoded content that is rarely well-formed: characters
outside the alphabet (whitespace included) are skipped and decoding stops at
padding. Only literals *before* the decode can key the prefilter, because
the prefilter sees the raw buffer.

### State across connections

`xbits` is state that outlives a connection and is keyed on an address:
"this host asked an IP-check service a minute ago", so that a later,
otherwise unremarkable connection from it means something.

```
rule sid:1000010; name:"ip-check"; buffer:tls.sni; content:"myexternalip.com"; nocase;
     xbits:set,ipcheck,track ip_src,expire 300; noalert;
rule sid:1000011; name:"beacon-after-ip-check"; buffer:http.uri; content:"/gate.php";
     xbits:isset,ipcheck,track ip_src;
```

Verbs are `set`, `unset`, `toggle`, `isset` and `isnotset`; `track` is
`ip_src`, `ip_dst` or `ip_pair`; a bit lasts `expire` seconds (30 if
unstated). A rule's conditions are checked, and its effects applied, in the
same stage that counts `threshold`s. It cannot live on a flow and cannot live
in a worker (the two connections may be on different ones), and putting it
where every alert passes is also what keeps it deterministic: under replay
that stage processes alerts in capture-time order, so a bit set and read in
the same second gives the same answer on every run. A rule that only sets
state is never reported.

### Flowbits

**Flowbits** express "this only matters if that already happened", which
no single packet can say:

```
rule sid:1000003; name:"mark-vulnerable-server"; buffer:ssh.version; content:"OpenSSH_7.2"; flowbits:set,vuln; noalert;
rule sid:1000004; name:"exploit-against-vulnerable"; content:"|00 01 02|"; flowbits:isset,vuln; severity:high;
```

Rules that need a bit to be *set* are grouped by it, and a whole group is
skipped without scanning the buffer while the bit is unset.

### Available buffers

| Group | Buffers |
|---|---|
| Raw | `payload` |
| One packet | `packet` |
| HTTP request | `http.method` `http.uri` (percent-decoded, as Suricata normalises it) `http.host` `http.user_agent` `http.request_body` `http.request_line` `http.accept` `http.accept_enc` `http.accept_lang` `http.referer` |
| HTTP response | `http.stat_code` `http.stat_msg` `http.response_line` `http.server` `http.location` `http.content_type` `http.response_body` |
| HTTP either way | `http.header` (the header lines and their closing blank line, without the request or status line) `http.header_names` `http.start` `http.protocol` `http.connection` `http.content_len` `http.cookie` (on a response, `Set-Cookie`) |
| Files | `file.data` `file.md5` `file.sha256` `file.type` `file.magic` |
| DNS | `dns.query` |
| TLS/QUIC | `tls.sni` `tls.ja3` `tls.ja3s` (the server's fingerprint) `tls.version` (`1.0`–`1.3`, as the server chose it) |
| TLS certificate | `tls.cert_subject` `tls.cert_issuer` `tls.cert_serial` (the server's own certificate) and `tls.certs` (the raw DER of each certificate in the chain) |
| SMB | `smb.command` `smb.filename` `smb.share` |
| Windows auth | `ntlm.user` `ntlm.domain` `ntlm.workstation` |
| Kerberos | `krb5.realm` `krb5.principal` `krb5.service` |
| Directory | `ldap.dn` |
| RPC | `dcerpc.interface` |
| Mail / transfer | `smtp.command` `smtp.sender` `smtp.recipient` `ftp.command` `tftp.opcode` `tftp.filename` |
| Other | `ssh.version` `snmp.community` `rdp.cookie` `modbus.function` `modbus.address` `dnp3.function` |

### Rules rejected at load time

Three shapes are refused rather than accepted and regretted: a rule with
no content, no flowbit condition and no packet-level condition (it would
match everything); a rule whose every term is negated (same); and a
hand-written rule whose *first* content is relative (there is nothing for
it to be relative to, and Suricata's reading of that is indistinguishable
from `offset`; the translator makes that rewrite for you). All three are
the kind of mistake that buries an operator in alerts, and all three are
cheaper to catch when the file loads than at 3am. `argus -check-rules
FILE` lists everything ARGUS would refuse and why.

### Rule performance

Each `(buffer, direction)` group gets an Aho-Corasick prefilter, folding
ASCII case, built from the longest required literal of every rule in it.
One pass finds which rules are candidates; only those are fully evaluated.
Case-insensitive literals are matched directly (a first-byte scan and a
comparison) rather than through a regex, which is what made a 50,000-rule
set affordable. Within a rule, terms are checked cheapest-first: header
comparison, then flowbit state, then content.

A rule with no usable literal, meaning all-regex or one whose only literals
are negated, cannot be prefiltered and is evaluated against every buffer of
its type. Include at least one plain `content` in any rule that needs to
be fast.

---

## Importing Suricata and Emerging Threats rules

`tools/suricata.py` translates Suricata/Snort rules into ARGUS v2 rules.

```bash
python tools/suricata.py emerging-all.rules -o et-open.rules \
    --home-net 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 \
    --validate target/release/argus

argus -iface eth0 -rules et-open.rules
```

Against ET Open's 51,074 active rules, **50,989 convert: 99.8%.**

The governing rule is **skip anything that cannot be represented
faithfully.** A rule translated wrongly is worse than one skipped,
because it fails silently and in whichever direction the mistranslation
went. Every option is either mapped exactly or the whole rule is rejected
with a recorded reason.

```bash
python tools/suricata.py emerging-all.rules --stats
```

`--stats` prints the rejection reasons, so the coverage figure is
auditable rather than asserted. `--validate` asks ARGUS itself which of
the generated rules it will load and drops (and counts) the ones it will
not, so a single translation slip cannot stop the other 50,000 loading.

### What converts

- **Application-layer rule types.** `alert http` / `alert tls` /
  `alert dns` are not port-based in Suricata: they mean "traffic the
  app-layer parser identified as HTTP". A rule with a structured buffer
  already carries that meaning, since ARGUS's buffers are populated only
  when its own parsers succeeded. A rule about SMTP, RDP, FTP, SSH, SMB or
  TLS with no protocol buffer is scoped to flows ARGUS *identified* as that
  protocol. `alert dns` and `alert snmp`, which have no flow, are scoped by
  their well-known port (at either end, as two rules, when the rule names
  no direction)
- **Relative positioning**, `byte_test`, `byte_jump` and `flowbits`. A
  relative modifier with no earlier match in its buffer is measured from
  the buffer's start, as Suricata does, and translated to the equivalent
  window; a negative `distance` is kept
- **Rules spanning several buffers**, and the response-side buffers they
  are most often paired with
- **PCRE**, including the `R` flag, the legacy buffer flags (`/U`, `/P`,
  and so on), lookahead, lookbehind, backreferences, atomic groups and
  possessive quantifiers
- **Transforms:** `url_decode`, `header_lowercase`, `strip_whitespace`,
  `compress_whitespace`; `to_lowercase` and `to_uppercase` (which fold a
  whole buffer and so become case-insensitive matching; a content in the
  wrong case for its transform could never match, so that rule is refused
  rather than translated into one that can); and `strip_pseudo_headers`,
  which removes HTTP/2 pseudo-headers and so changes nothing on HTTP/1
- **The normalised URI.** `http.uri` is read after `percent_decode`;
  `http.uri.raw` is read as sent
- **Length and position tests:** `urilen`, `bsize`, `dsize`, `isdataat`,
  end-anchored `offset`/`depth`, and `endswith`
- **Packet-level rules:** `tcp-pkt`, `flags`, `itype`, `icode`, `window`,
  `ip_proto`, `stream_size`
- **Rate control:** `threshold` and `detection_filter`
- **Variables and decoding:** `byte_extract`, `byte_math`, `base64_decode`/`base64_data`
- **Cross-connection state:** `xbits` and `hostbits`
- **Server-side TLS:** `ja3s.hash`, and `tls.version:1.2` (an exact test that does not take over the buffer the following contents read)
- **Hashes and file types:** `to_sha1`, `to_md5`, `to_sha256`, and `file.magic`
- **The server's TLS certificate**, for TLS before 1.3
- **Bidirectional `<>` rules**, written both ways round
- **Idioms.** `dotprefix; content:".evil.com"; endswith` is the dominant
  modern pattern for domain matching, and is exactly the regex
  `(^|\.)evil\.com$`
- **Severity** from ET's `signature_severity` metadata, falling back to
  `classtype`

### What does not

What is left is 85 rules (0.2%), and each needs something ARGUS does not
have:

| Blocker | Rules | Why |
|---|---|---|
| `app-layer-protocol` | 12 | Almost all negated ("not TLS"), which is a claim about a flow *ever* being TLS, not about its first packet |
| `flowint` | 8 | Per-flow integer counters, a different mechanism from flowbits |
| PCRE that cannot be represented | ~10 | A letter its case transform removes (refused because the rule could never match), recursion, and the rarely used `/B` and `/G` flags |
| `asn1` | 4 | An ASN.1 decoder and its length checks |
| Protocols and headers ARGUS does not model | ~25 | `dcerpc`, `ftp-data` and `tcp-stream` rule types; `icmpv4.hdr`, `icmpv6.hdr`, `icmp_id`, `icmp_seq`; SSH banner buffers |
| The rest | ~25 | Single-rule cases: no `sid`, no content, `ftpbounce`, `app-layer-event`, `ja3.string` |

### Assumptions about Suricata

ARGUS has been checked against its own tests, not against Suricata, and a
translation is a claim that ARGUS behaves as Suricata does. These are the
readings I could not confirm against Suricata itself; each is plausible
and each could be wrong in a way the tests cannot show:

- `within` is measured from the end of the previous match, not from where
  `distance` moved the window's start
- A leading `distance`/`within` is measured from the start of the buffer
- `header_lowercase` folds header names only
- Percent-decoding alone approximates URI normalisation (dot segments are
  not collapsed, so paths containing `../` differ)
- `byte_test` with a width of 0 on a text number reads every digit
- `flags:!` means none of the listed flags are set
- `stream_size:server` counts payload bytes the server has sent
- `byte_extract` and `byte_math` do not move the cursor
- `xbits` lasts 30 seconds when a rule gives no `expire`
- `base64_decode` reads tolerantly whatever `mode` a rule names
- `file.magic` uses a short table of libmagic-style descriptions, not libmagic
- `tls.version` is the version the server chose, read from `supported_versions` under TLS 1.3

The way to settle all of them is a differential test: run Suricata and
ARGUS over the same labelled captures and compare the alerts.

### Lessons

The skip table counts each rule against its **first** blocker only, so
clearing one reveals the next, and a prediction made from it is a ceiling.
Over this project the predictions were wrong in both directions: one
overshot by an order of magnitude (a guard nobody had measured turned out
to exclude 1,600 legitimate rules), one undershot, and one blocker's label
described 10% of what was behind it. Measure before building, and again
after.

Two defects found by translating the rules were in ARGUS itself: its
`http.header` buffer had the request line in and the closing blank line
out, so every rule anchoring to the first header or the end of the block
silently never matched; and `within` was measured from the wrong point
whenever `distance` was also given.

---

### Rate control

`threshold` and `detection_filter` decide whether a *match is reported*, by
counting recent matches for the same source, destination, pair or rule. They
do not change what a rule matches, so they are applied by a stage of their own
between the workers and the writer rather than in the matcher.

| Form | Reports |
|---|---|
| `type limit` | The first `count` matches in each window, then none until it ends |
| `type threshold` | Every `count`th match |
| `type both` | One alert when the count is reached, then none until the window ends |
| `detection_filter` | Nothing until the count is exceeded, then every match |

The count has to live where every alert passes, because workers are sharded by
host pair and a per-worker counter would see one source's traffic in pieces.
Under replay the stage holds the alerts it must count and processes them in
capture-time order, so the same capture always gives the same alerts. Tracking
`by_flow` is not supported, and a rule that asks for it is refused.

---

## Enrichment

Every detector reports a *shape*. "Six connections sixty seconds apart
with two percent jitter" is a complete and correct description of the
traffic, and it is the same description whether the far end is a
command-and-control server or a chat client polling an API. No threshold
separates those, because the difference is not in the traffic. That is
the gap enrichment fills.

### Reputation

One indicator per line; the kind is inferred from its shape, because
every published feed is already a bare list of one kind of thing.

```
# /etc/argus/intel.txt
203.0.113.0/24                      # cobalt-strike c2
evil.example.com                    ; phishing kit
e7d705a3286e19ea42f587b344ee6865    # known implant JA3
ip:198.51.100.7                     # explicit prefix also accepted
```

Checks happen where each indicator first becomes *known*: addresses when
a flow is created, a domain when a Host header, TLS SNI, QUIC SNI or DNS
question parses, a JA3 when a ClientHello does. None is on the per-packet
path, which is what makes reputation affordable. Matching uses sorted,
merged ranges searched binarily; domains match on label boundaries, so
`evil.com` matches `a.b.evil.com` but never `notevil.com`.

### Home network

```
home-net = 192.168.0.0/16,10.0.0.0/8
```

Gives every alert a `flow_direction` of `inbound`, `outbound`, `internal`
or `external`. "Inbound from the internet" and "internal to internal" are
different incidents even when the detector is identical, and without a
notion of inside there is no way to say which one this is. Absent a
`home-net`, the field is omitted rather than guessed.

### Allowlist

Makes a verdict *stick*. Once an operator has established that a
particular beacon is a backup agent, the sensor should stop asking, and
deleting the rule is the wrong fix, because it disables the detector
everywhere.

```
# /etc/argus/allow.txt
category:BEACONING dst:172.64.0.0/13 dst_port:443  # CDN API poller, ticket #4412
category:HORIZONTAL_SCAN src:10.0.5.20             # the vulnerability scanner
```

Every field is optional and an absent field matches anything, so an entry
is exactly as narrow as the operator chose. Allowlisted alerts are
**counted**, not silently dropped: an allowlist quietly eating a whole
category should be a number somebody can see.

---

## Output

### Formats

`text` for a human, `json` for a pipeline, `eve` for a SIEM that already
ingests Suricata. Any sink can use any format, and each format is
rendered at most once per alert however many sinks want it.

```json
{"timestamp":"2026-09-18T15:41:25.000000+0000","event_type":"alert",
 "src_ip":"192.168.0.112","dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP",
 "alert":{"signature_id":1000001,"rev":1,"signature":"...","category":"THREAT_INTEL","severity":1},
 "flow_direction":"outbound","dst_intel":"cobalt-strike c2"}
```

### Destinations

```
logfile      = /var/log/argus/argus.eve   # the main log
alert-output = json:/var/log/argus/argus.ndjson   # extra sinks, repeatable
syslog       = tcp://siem.internal:514    # RFC5424, UDP or TCP
no-stdout    = true                       # for a service with no console
```

ARGUS refuses to start if every destination is disabled: a sensor with
nowhere to report fails silently, which is the worst way to fail.

### Rotation

Two mechanisms, because the platforms differ.

- **Unix:** `logrotate` renames the file and signals; `SIGHUP` or
  `SIGUSR1` makes ARGUS reopen the path. A `logrotate` fragment is in
  `packaging/argus.logrotate`.
- **Anywhere, including Windows:** `log-max-size` and `log-keep` make
  ARGUS rotate itself.

Both can be enabled at once; reopening a path is idempotent.

### Connection records

With `flow-log`, every TCP, UDP and ICMP conversation writes an NDJSON
record as it completes, carrying whatever the parsers extracted:

```json
{"start":1789746085,"duration":2.140,"src":"10.0.0.5","src_port":51234,
 "dst":"10.0.0.9","dst_port":445,"proto":"TCP","state":"closed",
 "pkts_to_server":12,"pkts_to_client":9,"bytes_to_server":1840,"bytes_to_client":24120,
 "flags_to_server":"SAPF","flags_to_client":"SAPF","alerts":0,
 "auth_user":"svc_backup","rpc_interface":"svcctl (Service Control Manager)"}
```

### Metrics

```
metrics = 127.0.0.1:9109
```

Serves Prometheus text at `/metrics` and liveness at `/healthz`. Every
counter ARGUS tracks internally (frames read, packets decoded, capture
drops, pool exhaustion, queue pressure, every bounded table's refusals,
alerts emitted and suppressed, rule reloads) is exposed live rather than
only in the shutdown summary. A sensor you have to stop in order to find
out how it is doing is a sensor you will not check.

Bind it to a loopback or management address: statistics about a network
are information about that network.

### Packet capture around alerts

ARGUS keeps a ring of the most recent `pcap-retain` frames and writes
them to a `.pcap` in `pcap-dir` whenever an alert fires. This is the
difference between an alert you can investigate and an alert you can only
believe.

---

## Running as a service

### Linux

```bash
sudo install -m755 target/release/argus /usr/local/bin/argus
sudo install -m644 packaging/argus.service /etc/systemd/system/
sudo install -m644 packaging/argus.logrotate /etc/logrotate.d/argus
sudo useradd --system --no-create-home argus
sudo mkdir -p /etc/argus /var/log/argus && sudo chown argus:argus /var/log/argus
sudo systemctl enable --now argus
```

The unit grants `CAP_NET_RAW`/`CAP_NET_ADMIN` rather than running as
root, and hardens everything else: `ProtectSystem=strict`, a
`SystemCallFilter`, no new privileges. If ARGUS is ever compromised
through a packet it parsed, the attacker inherits the ability to read the
network, which they already had.

**`systemctl reload argus` costs no dropped packets.** `SIGHUP` re-reads
the rule and enrichment files and reopens the logs; a failed reload
leaves the previous rules in place and increments a counter, because a
typo in a rule file must not be able to take detection down.

### Windows

```powershell
.\packaging\install-windows-service.ps1 -ExePath C:\argus\argus.exe -ConfigPath C:\argus\argus.conf
```

Registers a scheduled task running at startup as SYSTEM. ARGUS is a
console program and does not implement the Service Control Manager
protocol, so `sc.exe create` pointed at it would produce a service the
SCM kills after its start timeout; the script says so and points at NSSM
or WinSW if true service integration is wanted. There is no `SIGHUP` on
Windows, so rules reload from disk changes (`reload-interval`) and logs
rotate by size.

### Hot reload

Rules and enrichment files are watched for changes and re-read without
restarting, on every platform. Workers pick up the new set with one
relaxed atomic load per packet: a generation counter, checked and
almost always unchanged, so the steady-state cost is a predictable
branch. Rate-control (`threshold`) settings follow the reload too.

---

## Configuration reference

Every key below is also a command-line flag with a leading dash. Run
`argus -help` for the same list, or `argus -generate-config` for an
annotated file.

### Input

| Key | Default | Meaning |
|---|---|---|
| `iface` | none | Interface to monitor. **Repeatable** |
| `r` | none | Replay a capture instead (also `read`) |
| `filter` | none | BPF filter, applied in the kernel (also `bpf`) |
| `list-interfaces` | none | List capture-able interfaces and exit |

### Detection

| Key | Default | Meaning |
|---|---|---|
| `rules` | none | Rule file, v1 and v2 (also `signatures`) |
| `blacklist` | none | IP blacklist, one address per line |
| `window` | `10s` | Sliding window for anomaly thresholds |
| `rate-threshold` | `500` | Packets **per second** before `PACKET_FLOOD` |
| `scan-threshold` | `20` | Distinct ports per window before `PORT_SCAN` |
| `no-behavior` | `false` | Disable behavioural detection |
| `behavior-window` | `5m` | Window the behavioural detectors judge over |
| `frag-policy` | `first` | Overlapping-fragment policy: `first` (BSD/Linux) or `last` (Windows) |

### Enrichment

| Key | Default | Meaning |
|---|---|---|
| `intel` | none | Reputation feed. **Repeatable** |
| `allowlist` | none | Alerts to stop reporting. **Repeatable** |
| `home-net` | none | CIDRs considered inside. **Repeatable**, comma-separated |

### Output

| Key | Default | Meaning |
|---|---|---|
| `format` | `text` | `text`, `json` or `eve` |
| `json` | `false` | Shorthand for `format = json` |
| `logfile` | `argus-alerts.log` | Alert log |
| `log-format` | none | Format for the log, when it differs from `format` |
| `log-max-size` | `0` | Self-rotate at this size; accepts `100M` |
| `log-keep` | `5` | Rotated generations to keep |
| `no-stdout` | `false` | Do not write alerts to stdout |
| `alert-output` | none | Extra sink as `<format>:<path>`. **Repeatable** |
| `syslog` | none | `[udp\|tcp]://host:port` |
| `syslog-format` | `json` | Format for syslog messages |
| `syslog-facility` | `16` | Facility number (16 = local0) |
| `suppress-window` | `15s` | Collapse duplicate alerts within this window |
| `flow-log` | none | NDJSON connection records |
| `pcap-dir` | `logs` | Where per-alert captures go |
| `pcap-retain` | `500` | Frames kept ready to dump; `0` disables |

### Operations

| Key | Default | Meaning |
|---|---|---|
| `config` | none | Config file; otherwise `./argus.conf` then `/etc/argus/argus.conf` |
| `generate-config` | none | Print an annotated config file and exit |
| `check-rules` | none | Validate a rule file, print every rule ARGUS would refuse and why, and exit |
| `metrics` | none | `host:port` for the Prometheus endpoint |
| `reload-interval` | `5s` | How often to check rule and intel files; `0` disables |

### Resources

Every one of these is a hard bound. Under pressure ARGUS refuses new
entries and counts the refusal rather than evicting a live one: if
pressure evicted live entries, an attacker could flood junk to push out
the state tracking a real attack, and a memory bound would have become an
evasion primitive.

| Key | Default | Meaning |
|---|---|---|
| `workers` | CPU count | Parallel detection workers |
| `packet-pool` | `4096` | Recycled packet buffers. **This is what bounds packet memory** |
| `queue-size` | `1024` | Per-worker queue depth; a slot holds a pointer |
| `alert-queue` | `16384` | Alert channel depth before alerts are shed |
| `payload-cap` | `9216` | How much of each payload detection may see |
| `stream-cap` | `16384` | Reassembled-payload budget per TCP direction |
| `max-flows` | `65536` | Per-worker cap on tracked TCP connections |
| `max-sources` | `65536` | Per-worker cap on tracked source addresses |

---

## Architecture

```
   NIC(s) / pcap ──►  capture threads  ──► decode ──┐
                      (one per iface)               │ link type, VLAN,
                                                    │ tunnels, defrag
                                shard by hash(host pair)
                       ┌──────────┬───┴──────┬──────────┐
                  ┌────▼────┐┌────▼────┐┌────▼────┐┌────▼────┐
                  │ worker  ││ worker  ││ worker  ││ worker  │  reassembly,
                  └────┬────┘└────┬────┘└────┬────┘└────┬────┘  parsers, rules,
                       │          │          │          │       anomaly windows
                       ├──────────┴────┬─────┴──────────┤
                       │ Observations  │     Alerts     │
                  ┌────▼─────────┐     │      ┌─────────▼────────┐
                  │  behaviour   │─────┴─────►│  threshold gate  │
                  │  aggregator  │   Alerts   │ rate control,    │
                  └──────────────┘            │ xbits            │
                                              └─────────┬────────┘
                                              ┌─────────▼────────┐
   ┌───────────┐   ┌──────────┐               │  alert writer    │──► sinks
   │ reloader  │   │ metrics  │               │  allowlist,      │    text/json/eve
   │ SIGHUP +  │   │ :9109    │               │  enrich,         │    file/stdout/syslog
   │ file watch│   └──────────┘               │  suppress, dump  │
   └───────────┘                              └──────────────────┘
```

### Host-pair sharding

Packets are dispatched to workers by a hash of the **host pair** that is
symmetric in the two endpoints. Both directions of a connection land on
the same worker, which is what lets each worker own a connection's entire
reassembly state with no locking.

That choice has a direct consequence: `src=A,dst=B` and `src=A,dst=C`
hash to *different* workers, so a source sweeping a subnet, or flooding
several destinations, is spread across all of them. This cannot be fixed by
raising a threshold: the evidence genuinely isn't in one place. Coarsening
the shard key to source alone isn't available either, because TCP
reassembly needs both directions together. That is why behavioural
detection, the flood total, rate control and cross-connection state are
separate stages fed from every worker.

Several interfaces share one worker pool and one packet pool, so a
conversation seen on two links still lands on one worker and is
reassembled once.

### No allocation on the hot path

`Packet` is a fixed-size, pointer-free value drawn from a pool of
pre-allocated `Box<Packet>`, so the channel moves an 8-byte pointer and
steady-state capture performs no allocator work. Buffers are reset
field-by-field rather than zeroed. Packet memory is fixed by
`packet-pool` and does not grow with `workers`.

### Single-consumer stages

The behaviour aggregator, the threshold gate and the alert writer are
single threads fed by channels. One consumer means no locks on the state
they own, and deterministic suppression, counting and record ordering.

Replay is reproducible: the same capture gives byte-identical alerts on
every run. Suppression is a pure function of the alerts and their
timestamps, not of which worker's alert arrived first; under replay the
behaviour aggregator and the threshold gate process their input in
capture-time order. A live capture cannot wait for the end, so the
aggregator holds observations for two seconds of capture time and orders
within that window, which removes worker-scheduling skew; a long flow
that finishes after the window has closed is still handled on arrival.

---

## Performance

Measured on an 8-core desktop replaying `bigFlows.pcap` (791,615 frames
of real enterprise traffic).

| Ruleset | Rule load | Replay | Throughput |
|---|---|---|---|
| ~60 hand-written rules | instant | 1.4s | ~565k pps |
| 51,073 ET Open rules | 3.2s | 12s | ~66k pps |

Peak memory replaying that capture is about 1 GB with the full ruleset (140 MB with the small one); the rules, not the traffic, are what it holds. A 7× slowdown for roughly 850× the rules. The scaling is sublinear: the
Aho-Corasick prefilter finds which rules are even candidates, and within
a rule terms are checked cheapest-first (header, then flowbit state, then
content), so a rule scoped to a port it does not match never touches the
payload.

Three costs dominated an early full-ruleset run, and all were invisible
until the whole set was loaded:

- **Case-insensitive literals compiled to regexes.** Most of a real
  ruleset is `nocase`, and a regex call costs about twenty times a direct
  search on the short buffers rules read. Matching them directly, and
  letting them key the prefilter, took the same replay from 150s to 37s
  with byte-identical alerts.
- **Re-scanning the stream.** Raw-payload rules are matched against the
  whole reassembled stream on every new segment, which is what defeats a
  signature split across packets, and scanning it whole each time made a
  connection's cost quadratic in its length. The scan now covers only the
  new bytes plus enough of the old to catch a literal straddling the join;
  the rules already found are remembered and still evaluated against the
  whole stream. That took the same replay from 38s to 12s, and a unit test
  checks that every way of cutting a stream into segments finds exactly
  what scanning it whole finds.
- **Per-flow progress for multi-buffer rules.** A `GET` request is the
  first part of thousands of rules, so one request could open thousands of
  progress records. A sorted list and then a table indexed by rule keep
  that linear.

Anchoring forces a term into a regex, and a rule whose every term is a
regex has no literal for the prefilter, so it lands in the "evaluate
always" list. The first working ET translation left 89% of rules
unprefilterable; emitting the implied literal alongside the anchored
regex, semantically a no-op, took that to 0%.

Decode rate on 805,876 frames across the corpus is **100.0%**, the 20
exceptions being genuinely malformed or non-IP frames.

---

## Testing and measurement

```bash
cargo test --release                        # 480 unit and integration tests
python tools/test_suricata.py               # 113 translator tests
python tools/detect.py --survive corpus     # survival and noise on real captures
python tools/detect.py                      # graded detection
python tools/detect.py --evasion            # attacks shaped to evade
python tools/detect.py --fp-rate corpus     # alerts per hour of benign traffic
```

The detection tools build to a private directory (`target-verify`), so
running them never touches a binary that a live sensor holds open.

### Detection

Public attack captures either arrive unlabelled or inside archives whose
password is published only as an image, deliberately, to stop automation.
So the harness constructs the labels: each case writes a pcap containing
exactly one attack, declares the alert category it must produce, replays
it through the real binary, and grades the result.

```
port_scan                PORT_SCAN              DETECTED
horizontal_scan          HORIZONTAL_SCAN        DETECTED
packet_flood             PACKET_FLOOD           DETECTED
brute_force              BRUTE_FORCE            DETECTED
beaconing                BEACONING              DETECTED
exfil_ratio              DATA_EXFIL_RATIO       DETECTED
dns_tunnel               DNS_TUNNEL             DETECTED
dns_long_name            DNS_LONG_NAME          DETECTED
signature_dns            SIGNATURE_MATCH        DETECTED
signature_http           SIGNATURE_MATCH        DETECTED
ntlm_auth                SIGNATURE_MATCH        DETECTED
dcerpc_svcctl            SIGNATURE_MATCH        DETECTED
file_upload              SIGNATURE_MATCH        DETECTED
threat_intel_dns         THREAT_INTEL           DETECTED
quic_sni                 THREAT_INTEL           DETECTED
brute_force_refused      BRUTE_FORCE            DETECTED   (10 logins, all refused)
http_401_brute           BRUTE_FORCE            DETECTED   (12 requests, all 401)
executable_download      SIGNATURE_MATCH        DETECTED   (40KB, past the buffer)
request_and_response     SIGNATURE_MATCH        DETECTED   (URI + status in one rule)
translated_rule          SIGNATURE_MATCH        DETECTED   (Suricata rule, /R + lookahead, translated then run)
case_transform           SIGNATURE_MATCH        DETECTED   (to_lowercase rule against a mixed-case URI)
missing_header           SIGNATURE_MATCH        DETECTED   (gate page requested with no Accept header)
urilen                   SIGNATURE_MATCH        DETECTED   (POST to a twelve-byte path)
dsize                    SIGNATURE_MATCH        DETECTED   (40-byte datagram against dsize:>20)
isdataat                 SIGNATURE_MATCH        DETECTED   (value ending four bytes after its key)

detection rate: 25/25 (100%) on modelled attacks
```

### Evasion

The plain cases cross their thresholds decisively, which a real attacker
would not. `--evasion` runs attacks shaped the way someone who knows the
thresholds would shape them:

```
split_signature          SIGNATURE_MATCH        DETECTED   (one byte per segment)
out_of_order_signature   SIGNATURE_MATCH        DETECTED   (segments reversed)
fragmented_signature     SIGNATURE_MATCH        DETECTED   (split across IP fragments)
overlapped_pending       SIGNATURE_MATCH        DETECTED   (held segment overlapped by the one that fills the gap)
spread_flood             PACKET_FLOOD           DETECTED   (1200pps split across 60 destinations, and so across workers)
slow_port_scan           PORT_SCAN              DETECTED   (40 ports at 3s intervals)
jittered_beacon          BEACONING              DETECTED   (60s beacon, 12% jitter)
split_response           SIGNATURE_MATCH        DETECTED   (response, one byte per segment)

evasion-resistance: 8/8 detected
```

`overlapped_pending` exists because a targeted test found a real bug: a
segment held back for a gap, then overlapped by the data that filled it,
was never delivered, so one out-of-order segment plus one overlap made the
sensor stop following a stream. Its unit tests failed before the fix.

`spread_flood` found a weakness in the design it was written for: the
harness runs evasion cases with `-window 5m`, and a flood judged over the
configured window averaged a 1,200 pps burst down to 40 pps. The flood is now
judged over a fixed ten seconds.

A `MISSED` here would be a documented limit rather than a bug.

### False positives

The number a detection rate cannot give. A sensor that detects everything
and also alerts on everything is not useful, and the trade between the
two is the only thing worth tracking over time.

```
bigFlows.pcap              162 alerts over    300s
smallFlows.pcap             14 alerts over    299s

176 alerts over 599 seconds of benign traffic = 1059 alerts/hour
  HIGH       0  =      0/hour
  MEDIUM    71  =    427/hour
  LOW      105  =    632/hour
```

(That is the shipped rules.) Every one is a false positive by construction:
the corpus contains no attack. The **HIGH** row is the one that matters,
because it is what somebody has to look at.

Measuring this immediately changed the shipped rules. Three of them were
82% of the total: a v1 rule matching SNMP's default `public` community
fired at HIGH on every monitoring poll on the network, 2,400 an hour from
one line. They are now v2 rules with the severity and scoping the finding
actually warrants: a default community is an exposure, not an intrusion.

The same measurement with the **full ET ruleset** (50,907 rules) over the
same corpus gives about 270 signature alerts, nearly all LOW (ICMP pings,
SNMP `public`, Dropbox and Skype chatter), and two HIGH: a JA3 hash match
(a class of rule known to collide with benign clients), and "PHP Possible
https Local File Inclusion Attempt", which fires on a URL-encoded
`=https%3A%2F%2F` redirect once the URI is percent-decoded. Suricata
normalises the URI the same way, so that is the rule behaving as written.
This is on traffic that is 15 years old and contains little for ET to
object to; a modern network will be noisier and should be measured the
same way before trusting the number.

---

## Limitations

These are known and deliberate, listed so nobody discovers them during an
incident.

**It is an IDS, not an IPS.** ARGUS observes and reports. It does not
block, reset connections, or modify traffic.

**Detection is measured against synthetic attacks.** The harness grades
twenty-five modelled attacks and eight evasions. That is a regression floor
and a published list of what is modelled, not a real-world detection
rate. A labelled real-world attack corpus, and a differential run against
Suricata, remain the missing measurements.

**A translated rule is a claim, not a proof.** 99.8% of ET Open loads, but
"loads" is not "behaves as Suricata does". See
[Assumptions about Suricata](#assumptions-about-suricata).

**Response parsing is HTTP-first, and shallow after the first response.**
ARGUS parses HTTP responses and the refusal codes of FTP, SMTP, SMB,
Kerberos and LDAP. It parses only the *first* HTTP response on a
connection, so a tool that brute-forces over one keep-alive connection is
undercounted (one 401 per connection is seen, not one per request), and
file hashing likewise covers one body per direction per connection.
Compressed bodies are hashed as sent, not decoded. SSH and RDP replies are
encrypted, so their brute force is still counted by attempts.

**Encrypted traffic is identified, not decrypted.** TLS yields SNI, JA3,
JA3S and the server's version, and the server's certificate before TLS 1.3
(from 1.3 on it is encrypted with keys a passive observer never has, so
certificate rules find nothing there); QUIC yields SNI and
JA3 from its Initial packet; ESP is counted. HTTP/2 is only visible as
cleartext `h2c`, which is rare in practice.

**Live behavioural ordering is best-effort past two seconds.** A flow's
observation is stamped with its start and sent when it ends, so a long
flow reaches the aggregator after the reorder window has closed and is
handled on arrival. Replay has no such limit. This cannot be closed live
without holding every observation until the capture ends.

**Single process, single machine.** No clustering and no shared state
between sensors: `xbits` state is per sensor, and is lost when rules reload.

**Not tested at line rate or over long runs.** Replay runs at about 66k
packets per second with the full ruleset on one machine, which is roughly
500 Mbit/s of typical traffic; gigabit is beyond what has been measured. Every
table is bounded by design, but memory over hours of live traffic has not
been observed.

---

## Project layout

```
src/
  main.rs        capture, dispatch, packet pool, CLI, config, reload wiring
  config.rs      the configuration file and the shared option table
  decode.rs      link types, VLAN, tunnels, IP fragment reassembly
  packet.rs      the Packet value, link and IP parsing
  engine.rs      alerts, flow table, TCP reassembly, protocol parsers, anomaly detection
  rules.rs       the v2 rule language: parsing, transforms, prefilter, evaluation
  threshold.rs   rate control and cross-connection state: threshold, detection_filter, xbits
  tlscert.rs     the server's TLS certificate, version and JA3S, out of the handshake
  behavior.rs    cross-flow behavioural detection
  window.rs      sliding-window primitives shared by every detector
  intel.rs       reputation, home network, allowlist
  enterprise.rs  SMB1, NTLM, Kerberos, LDAP, DCERPC
  quic.rs        QUIC Initial decryption and ClientHello extraction
  files.rs       file identity: type, size, MD5, SHA-256
  output.rs      formats, sinks, rotation, syslog
  metrics.rs     counters and the Prometheus endpoint
  reload.rs      hot reload, file watching, signals

tools/
  detect.py         graded detection, evasion, false-positive rate, and real-capture survival (--survive)
  suricata.py       translate Suricata/Snort rules into ARGUS v2 rules
  test_suricata.py  the translator's tests

packaging/
  argus.service              hardened systemd unit
  argus.logrotate            logrotate fragment
  install-windows-service.ps1

rules.txt          bundled rules, v1 and v2
blacklist.txt      example IP blacklist
ja3-blocklist.txt  JA3 fingerprint list (ships empty, by design)
```

Roughly 23,000 lines of Rust across eighteen source files.
