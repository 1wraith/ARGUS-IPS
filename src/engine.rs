use aho_corasick::AhoCorasick;
use md5::{Digest, Md5};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::intel::{Indicator, Intel, IntelSeen, Tags};
use crate::rules::FlowBits;
use crate::metrics::Metrics;
use crate::output::{Output, FLUSH_INTERVAL};
use crate::packet::{IpAddr, Packet, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG};
pub use crate::rules::{MatchScratch, RuleHit};

// =======================================================================
// Alerts
// =======================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }
}

#[derive(Clone)]
pub struct Alert {
    pub timestamp: SystemTime,
    pub severity: Severity,
    pub category: &'static str,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: &'static str,
    pub port: u16,
    pub message: String,
    /// Rule id for a `SIGNATURE_MATCH` from a v2 rule, 0 otherwise.
    ///
    /// Emitted so a downstream consumer can correlate, rank, and
    /// suppress by rule rather than by parsing the message text — which
    /// was the only option when every signature alert was
    /// indistinguishable `HIGH` with a name buried in prose.
    pub sid: u32,
}


/// Escapes a string for embedding in a JSON string literal. Only the
/// characters JSON actually requires escaping — this isn't a general
/// JSON serializer, just enough to safely embed `category`/`message`
/// (the only fields with content ARGUS didn't itself construct from a
/// closed set of values).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Builds a `SIGNATURE_MATCH` alert for a rule that fired against a given
/// buffer. Shared by both the direct per-packet path (UDP/ICMP payload,
/// DNS query, in `main.rs`) and the flow-based path (TCP payload/HTTP/
/// TLS/FTP/SSH/SMTP, in `FlowTable::observe` below).
pub fn signature_alert(p: &Packet, buffer: Buffer, hit: &RuleHit, now: SystemTime) -> Alert {
    Alert {
        timestamp: now,
        // The rule's own severity, not a hardcoded `High`. Every
        // signature match used to be `HIGH`, which makes the field
        // useless for triage: if everything is urgent, nothing is.
        severity: hit.severity,
        category: "SIGNATURE_MATCH",
        src: p.src,
        dst: p.dst,
        proto: p.proto_name(),
        port: p.dst_port,
        message: if hit.sid == 0 {
            format!("{:?} matched signature {:?} (buffer: {})", buffer, hit.name, buffer.as_str())
        } else {
            format!("{:?} matched signature {:?} (sid {}, buffer: {})", buffer, hit.name, hit.sid, buffer.as_str())
        },
        sid: hit.sid,
    }
}

/// A request to dump the recent raw-packet window around an alert to a
/// `.pcap` file, sent by `run_alert_writer` (see below) back to the
/// capture thread — the only place that has access to both the live
/// `pcap::Capture` handle (needed to open a savefile with the right
/// link-layer type) and the retained raw frames themselves. Carries only
/// identifying info, not packet data, since the capture thread already
/// holds the actual bytes in its own ring buffer.
#[derive(Clone)]
pub struct PcapDumpRequest {
    pub timestamp: SystemTime,
    pub category: &'static str,
    pub proto: &'static str,
    pub src: IpAddr,
}

/// What one run of [`run_alert_writer`] actually wrote out, returned
/// when the alert channel closes and the writer thread finishes.
///
/// Exists mainly for the sake of offline replay (`-r`), where "how many
/// alerts did this capture produce" is the entire result of the run and
/// needs to be reported once at the end — a live capture has no natural
/// end at which to print it, and reads the alert log as it streams
/// instead. `suppressed` counts every alert collapsed into an earlier
/// one by the suppression window, so `emitted + suppressed` is the total
/// number of alerts detection actually raised.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct AlertStats {
    pub emitted: u64,
    pub suppressed: u64,
    /// Times the suppression table was cleared because the live key
    /// space exceeded its cap. Non-zero means some duplicate alerts got
    /// through — worth reporting, since the alternative reading of a
    /// sudden burst of near-identical alerts is a detection bug.
    pub suppression_resets: u64,
    /// Alerts an allowlist entry dropped. Counted rather than silently
    /// discarded: an allowlist quietly eating a whole category should be
    /// a number somebody can see, not an absence they have to notice.
    pub allowlisted: u64,
}

/// Runs on its own thread as the sole consumer of the alert channel. Being
/// single-threaded lets it dedupe bursts of identical alerts without any
/// locking — "share memory by communicating" instead of a mutex-guarded
/// logger. When `json` is set, every emitted line is a single JSON
/// object (NDJSON); the human-readable "N more suppressed" summary line
/// is skipped in that mode (rather than mixing schemas) — suppression
/// still happens, a consumer just won't see a count of it.
///
/// `pcap_tx`, if given, receives one [`PcapDumpRequest`] for every alert
/// that actually makes it past suppression and gets written out —
/// deliberately *not* one per raw alert generated, since a suppressed
/// duplicate has nothing new to show and dumping a pcap for every one of
/// a thousand identical suppressed `PACKET_FLOOD` alerts would be pure
/// waste.
pub struct AlertWriterConfig {
    pub suppress_window: Duration,
    pub pcap_tx: Option<crossbeam_channel::Sender<PcapDumpRequest>>,
    pub intel: Arc<Intel>,
    pub metrics: Arc<Metrics>,
    /// Set by the signal handler; the writer reopens its files at the
    /// next convenient moment rather than inside the handler, where
    /// almost nothing is safe to call.
    pub reopen: Arc<AtomicBool>,
}

impl AlertWriterConfig {
    /// The shape tests want: suppression and nothing else.
    pub fn plain(suppress_window: Duration) -> AlertWriterConfig {
        AlertWriterConfig {
            suppress_window,
            pcap_tx: None,
            intel: Arc::new(Intel::default()),
            metrics: Arc::new(Metrics::default()),
            reopen: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_pcap(mut self, tx: crossbeam_channel::Sender<PcapDumpRequest>) -> AlertWriterConfig {
        self.pcap_tx = Some(tx);
        self
    }
}

pub fn run_alert_writer(rx: crossbeam_channel::Receiver<Alert>, mut out: Output, cfg: AlertWriterConfig) -> AlertStats {
    /// Cap on distinct suppression keys held at once.
    ///
    /// These two maps were the last unbounded table in the pipeline, and
    /// they were missed because the memory-bounds pass went through the
    /// *workers* — where the detection state lives — and the writer is a
    /// different thread with state of its own. Keys are heap `String`s
    /// built from category, source, destination, protocol, and (for
    /// signature matches) the message, so the key space is the number of
    /// distinct alerting tuples: a scan across a /16 is 65k keys, and a
    /// flood from spoofed sources is unbounded. Nothing ever pruned
    /// them, not even entries far older than the suppression window they
    /// exist to implement.
    const MAX_SUPPRESSION_KEYS: usize = 65536;

    let AlertWriterConfig { suppress_window, pcap_tx, intel, metrics, reopen } = cfg;
    let enrich = !intel.is_empty();

    let mut last_seen: FxHashMap<String, SystemTime> = FxHashMap::default();
    let mut suppressed: FxHashMap<String, u32> = FxHashMap::default();
    let mut stats = AlertStats::default();
    let mut last_pruned: Option<SystemTime> = None;
    let mut newest: Option<SystemTime> = None;
    let mut key = String::with_capacity(96);
    let no_tags = Tags::none();

    loop {
        // A timeout rather than a blocking receive, so that buffered
        // output reaches disk on a quiet link. Without it the last few
        // alerts before a lull can sit in a `BufWriter` indefinitely —
        // exactly backwards, since the quieter the sensor the more each
        // alert matters.
        let alert = match rx.recv_timeout(FLUSH_INTERVAL) {
            Ok(a) => a,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if reopen.swap(false, Ordering::AcqRel) {
                    out.reopen();
                }
                out.flush();
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        if reopen.swap(false, Ordering::AcqRel) {
            out.reopen();
        }

        // Allowlisting happens before suppression, and before enrichment.
        // Before suppression because an allowlisted alert must not occupy
        // a suppression slot that a real one could use; before enrichment
        // because there is no point describing something nobody will see.
        // It is counted, not silently dropped: an allowlist that is
        // quietly eating everything should be visible as a number.
        if !intel.allow.is_empty() {
            if intel.allow.matched(alert.category, &alert.src, &alert.dst, alert.port).is_some() {
                stats.allowlisted += 1;
                Metrics::inc(&metrics.alerts_allowlisted);
                continue;
            }
        }

        // Pruning exists to bound memory, and is therefore done only when
        // there is memory to bound.
        //
        // It used to run every second on the *arriving alert's* timestamp,
        // which is not a safe clock. Alerts reach this thread from every
        // worker in whatever order the scheduler ran them, so a fast
        // worker's alert stamped a minute ahead would prune an entry that
        // a slower worker's older alert still needed to be suppressed by.
        // The same capture then produced different alerts on different
        // runs — an alert present in one and absent in the next — which
        // contradicts the guarantee replay exists to give. A doubled
        // window as a "margin for out-of-order arrivals" was never enough:
        // the skew between workers has no bound to size a margin against.
        //
        // So nothing is pruned until the table is half full, and then by
        // the newest timestamp seen and a generous ten windows, which only
        // ever discards entries far older than anything still in flight.
        // Below that, suppression is a pure function of the alerts and
        // their timestamps, whatever order they arrive in.
        newest = Some(newest.map_or(alert.timestamp, |n| n.max(alert.timestamp)));
        let due = last_seen.len() >= MAX_SUPPRESSION_KEYS / 2
            && last_pruned.is_none_or(|t| alert.timestamp.duration_since(t).unwrap_or_default() >= Duration::from_secs(1));
        if due {
            last_pruned = Some(alert.timestamp);
            let horizon = newest.unwrap_or(alert.timestamp);
            let cutoff = suppress_window.saturating_mul(10);
            last_seen.retain(|_, &mut t| horizon.duration_since(t).unwrap_or_default() < cutoff);
            suppressed.retain(|k, &mut n| n > 0 && last_seen.contains_key(k));

            // Still over the cap after pruning means the *live* key space
            // is genuinely that large — a wide scan or a spoofed-source
            // flood. Here, unlike the flow and fragment tables, clearing
            // is the right answer rather than refusing: losing
            // suppression state costs duplicate alerts, which is noise,
            // whereas losing flow state would cost a missed detection.
            // Same bound, opposite policy, because the data means
            // something different.
            if last_seen.len() > MAX_SUPPRESSION_KEYS {
                last_seen.clear();
                suppressed.clear();
                stats.suppression_resets += 1;
                Metrics::inc(&metrics.suppression_resets);
            }
        }

        // Includes `proto` deliberately: without it, a UDP PORT_SCAN
        // alert and a TCP PORT_SCAN alert from the same source — two
        // genuinely different events — would collide under one
        // suppression key, and the second would be silently swallowed as
        // if it were a duplicate of the first. Same collision class as
        // the TCP/UDP port-tracking bug fixed earlier, one layer up: that
        // fix stopped the two protocols' *detection* from colliding, but
        // left this *output* dedup key still coarse enough to collide.
        //
        // Also includes `dst` for every category except PACKET_FLOOD.
        // Found in the field: a port scan against the local gateway and,
        // moments later, a port scan against a completely different
        // remote host — from the same source — landed 15 seconds apart,
        // right at the edge of the (also 15s) suppression window. The
        // second only survived by luck of timing; without `dst` in the
        // key, a source scanning two different targets in quick
        // succession would have the second target's alert silently
        // swallowed as if it were a duplicate of the first — even though
        // they're two genuinely different victims. PACKET_FLOOD is the
        // deliberate exception: it's tracked per-source regardless of
        // destination by design (see AnomalyEngine::observe), so
        // suppressing it per-source here matches that, not per-pair.
        //
        // SIGNATURE_MATCH additionally includes the alert's own
        // `message` — which, for this category only, is deterministic
        // per rule (built from just the buffer + rule name, nothing
        // that changes between repeated matches, unlike PORT_SCAN's
        // growing port count or PACKET_FLOOD's growing packet count —
        // *those* categories must never get message-keyed, since a
        // constantly-changing count would defeat suppression entirely).
        // Found the same way as the fixes above: two genuinely different
        // rules (a TFTP filename match and an unrelated SNMP community
        // match) fired from the same source/destination/protocol close
        // together in a live test, and the second was silently
        // swallowed as if it were a duplicate of the first, purely
        // because neither PORT_SCAN's nor PACKET_FLOOD's problem
        // (missing proto, missing dst) was the actual gap here — it was
        // that nothing distinguished *which rule* matched at all. This
        // matters more for UDP-based signatures specifically (raw
        // payload, DNS, TFTP, SNMP) than TCP ones, since only TCP flows
        // get FlowTable's own separate per-flow, per-rule dedup — UDP
        // detection is per-packet with no flow state, so this
        // suppression key is the *only* thing standing between a
        // repeatedly-matching UDP signature and alert spam, making it
        // more important to get right here, not less.
        suppression_key(&alert, &mut key);
        if let Some(&last) = last_seen.get(&key) {
            if alert.timestamp.duration_since(last).unwrap_or(Duration::MAX) < suppress_window {
                *suppressed.entry(std::mem::take(&mut key)).or_insert(0) += 1;
                stats.suppressed += 1;
                Metrics::inc(&metrics.alerts_suppressed);
                continue;
            }
        }
        if let Some(n) = suppressed.get_mut(&key) {
            if *n > 0 {
                let note = format!(
                    "[...] {:<6} {:<16} src={:<15} ({} more suppressed in the last {:?})",
                    alert.severity.as_str(),
                    alert.category,
                    alert.src,
                    n,
                    suppress_window
                );
                out.write_note(&note);
                *n = 0;
            }
        }
        last_seen.insert(key.clone(), alert.timestamp);

        let tags = if enrich { intel.tag(&alert.src, &alert.dst) } else { no_tags.clone() };
        out.write(&alert, &tags);
        stats.emitted += 1;
        Metrics::inc(&metrics.alerts_emitted);

        if let Some(tx) = &pcap_tx {
            // Best-effort: a full or disconnected channel just means this
            // one alert doesn't get a pcap — never worth blocking or
            // losing the alert itself over.
            let _ = tx.send(PcapDumpRequest { timestamp: alert.timestamp, category: alert.category, proto: alert.proto, src: alert.src });
        }
    }

    out.flush();
    for (sink, failures) in out.failures() {
        eprintln!("argus: {} write failures to {}", failures, sink);
    }
    stats
}

/// Builds the suppression key into a reusable buffer.
///
/// Separated from the writer loop so the reasoning above sits next to the
/// decision rather than in the middle of a hundred-line function, and so
/// the key can be tested directly.
fn suppression_key(alert: &Alert, out: &mut String) {
    use std::fmt::Write as _;
    out.clear();
    match alert.category {
        "PACKET_FLOOD" => {
            let _ = write!(out, "{}|{}|{}", alert.category, alert.src, alert.proto);
        }
        "SIGNATURE_MATCH" => {
            let _ = write!(out, "{}|{}|{}|{}|{}", alert.category, alert.src, alert.dst, alert.proto, alert.message);
        }
        _ => {
            let _ = write!(out, "{}|{}|{}|{}", alert.category, alert.src, alert.dst, alert.proto);
        }
    }
}

// =======================================================================
// Flow records
// =======================================================================

/// One completed TCP connection, emitted when the flow leaves
/// [`FlowTable`].
///
/// ARGUS previously emitted alerts and nothing else, which makes it a
/// tripwire rather than a sensor: after an alert fires you have a pcap
/// and a line of text, but no record of what else that host was doing,
/// what else talked to it, or whether the connection carried 2KB or
/// 2GB. That context is usually the difference between "an alert fired"
/// and "I understand what happened", and it's also what makes the
/// *absence* of an alert informative — a connection log lets you ask
/// questions nobody wrote a rule for, which is exactly the class of
/// question that matters after the fact.
///
/// Deliberately close to Zeek's `conn.log` in spirit, since that shape
/// is what existing tooling already knows how to read.
#[derive(Clone)]
pub struct FlowRecord {
    pub start: SystemTime,
    pub end: SystemTime,
    /// The connection *originator* — whichever endpoint ARGUS first saw
    /// send, which for a connection observed from its SYN is the real
    /// client.
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
    /// `TCP`, `UDP` or `ICMP`. Was hardcoded to TCP when only
    /// `FlowTable` produced records.
    pub proto: &'static str,
    pub vlan_id: u16,
    pub pkts_to_server: u64,
    pub pkts_to_client: u64,
    /// Wire bytes, i.e. captured frame lengths.
    ///
    /// Frame length rather than payload length on purpose: `payload_len`
    /// is bounded by `-payload-cap`, so counting it would silently
    /// under-report volume by however much the cap truncated — and
    /// volume is the whole reason to record bytes at all. Frame length is
    /// what actually crossed the wire.
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,
    /// Union of TCP flags seen in each direction, which is what makes a
    /// scan legible in the log itself: a SYN with only an RST back, or a
    /// SYN with no reply at all, looks nothing like a real session.
    pub flags_to_server: u8,
    pub flags_to_client: u8,
    /// How the connection ended, as far as ARGUS could tell.
    pub state: &'static str,
    /// Application metadata the protocol parsers already extracted —
    /// free to record here, and the field most often wanted next after
    /// an alert.
    pub http_host: Option<String>,
    pub http_uri: Option<String>,
    pub tls_sni: Option<String>,
    pub tls_ja3: Option<String>,
    pub auth_user: Option<String>,
    pub rpc_interface: Option<String>,
    pub file_md5: Option<String>,
    pub file_sha256: Option<String>,
    pub file_type: Option<String>,
    pub file_size: Option<usize>,
    pub ssh_version: Option<String>,
    /// Signature matches raised on this flow, so a record can be tied
    /// back to the alerts it produced.
    pub alerts: u32,
}

impl FlowRecord {
    fn duration_secs(&self) -> f64 {
        self.end.duration_since(self.start).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    }

    pub fn to_json(&self) -> String {
        fn opt(name: &str, v: &Option<String>) -> String {
            match v {
                Some(x) => format!(",\"{}\":\"{}\"", name, json_escape(x)),
                None => String::new(),
            }
        }
        format!(
            "{{\"start\":{},\"duration\":{:.3},\"src\":\"{}\",\"src_port\":{},\"dst\":\"{}\",\"dst_port\":{},\"proto\":\"{}\",\"state\":\"{}\",\"vlan\":{},\"pkts_to_server\":{},\"pkts_to_client\":{},\"bytes_to_server\":{},\"bytes_to_client\":{},\"flags_to_server\":\"{}\",\"flags_to_client\":\"{}\",\"alerts\":{}{}{}{}{}{}{}{}{}{}{}{}}}",
            self.start.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            self.duration_secs(),
            self.src,
            self.src_port,
            self.dst,
            self.dst_port,
            self.proto,
            self.state,
            self.vlan_id,
            self.pkts_to_server,
            self.pkts_to_client,
            self.bytes_to_server,
            self.bytes_to_client,
            tcp_flags_str(self.flags_to_server),
            tcp_flags_str(self.flags_to_client),
            self.alerts,
            opt("http_host", &self.http_host),
            opt("http_uri", &self.http_uri),
            opt("tls_sni", &self.tls_sni),
            opt("tls_ja3", &self.tls_ja3),
            opt("auth_user", &self.auth_user),
            opt("rpc_interface", &self.rpc_interface),
            opt("file_md5", &self.file_md5),
            opt("file_sha256", &self.file_sha256),
            opt("file_type", &self.file_type),
            match self.file_size {
                Some(n) => format!(",\"file_size\":{}", n),
                None => String::new(),
            },
            opt("ssh_version", &self.ssh_version),
        )
    }
}

/// Renders a TCP flag union as the conventional letter set, so a log
/// line is readable without decoding a bitmask by hand.
fn tcp_flags_str(flags: u8) -> String {
    let mut out = String::new();
    for (bit, ch) in [(TCP_SYN, 'S'), (TCP_ACK, 'A'), (TCP_FIN, 'F'), (TCP_RST, 'R'), (TCP_PSH, 'P'), (TCP_URG, 'U')] {
        if flags & bit != 0 {
            out.push(ch);
        }
    }
    out
}

/// Drains completed flow records to a writer, on its own thread, for the
/// same reason the alert writer has one: a single consumer needs no
/// locking, and disk I/O must not sit on the detection path.
pub fn run_flow_writer(rx: crossbeam_channel::Receiver<FlowRecord>, mut out: Box<dyn std::io::Write + Send>) -> u64 {
    use std::io::Write;
    let mut written = 0u64;
    for rec in rx.iter() {
        if writeln!(out, "{}", rec.to_json()).is_ok() {
            written += 1;
        }
    }
    let _ = out.flush();
    written
}

// =======================================================================
// Rule engine: buffers, direction scoping, literal + regex + negation
// =======================================================================
//
// Rule file format, one per line: `name|buffer|direction|type|pattern`
//   buffer:    payload | http.uri | http.host | dns.query | tls.sni |
//              tls.ja3 | ftp.command | ssh.version | smtp.command |
//              smtp.sender | smtp.recipient | smb.command |
//              smb.filename | modbus.function | modbus.address |
//              rdp.cookie | tftp.opcode | tftp.filename | snmp.community |
//              dnp3.function
//   direction: any | to_server | to_client
//   type:      literal | regex | not_literal | not_regex
//   pattern:   the literal string or regex (may itself contain `|` — the
//              line is split into at most 5 fields, so the pattern field
//              always gets everything remaining on the line)
//
// Literal rules compile into per-(buffer,direction) Aho-Corasick
// automatons. Regex rules (including negated ones, which internally reuse
// the regex engine via `regex::escape` for plain literals) are also
// grouped by (buffer,direction) at load time, so a buffer with no regex
// rules costs one hashmap lookup-and-miss to check, not a scan of every
// regex rule in the file.

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Buffer {
    Payload,
    /// One packet's own payload, before any reassembly.
    PacketPayload,
    HttpUri,
    HttpHost,
    HttpMethod,
    HttpHeader,
    HttpUserAgent,
    HttpCookie,
    HttpRequestBody,
    HttpStatCode,
    HttpStatMsg,
    HttpResponseBody,
    HttpContentType,
    HttpServer,
    HttpLocation,
    HttpHeaderNames,
    HttpRequestLine,
    HttpAccept,
    HttpReferer,
    HttpConnection,
    HttpContentLen,
    HttpStart,
    HttpAcceptEnc,
    HttpAcceptLang,
    HttpProtocol,
    HttpResponseLine,
    FileData,
    FileMd5,
    FileSha256,
    FileType,
    FileMagic,
    DnsQuery,
    TlsSni,
    TlsJa3,
    TlsCertSubject,
    TlsCertIssuer,
    TlsCertSerial,
    TlsCerts,
    TlsJa3s,
    TlsVersion,
    FtpCommand,
    SshVersion,
    SmtpCommand,
    SmtpSender,
    SmtpRecipient,
    SmbCommand,
    SmbFilename,
    ModbusFunction,
    ModbusAddress,
    RdpCookie,
    TftpOpcode,
    TftpFilename,
    SnmpCommunity,
    Dnp3Function,
    SmbShare,
    NtlmUser,
    NtlmDomain,
    NtlmWorkstation,
    KerberosRealm,
    KerberosPrincipal,
    KerberosService,
    LdapDn,
    DcerpcInterface,
}

impl Buffer {
    /// The one direction this buffer is populated from, when there is
    /// only one.
    ///
    /// A request URI is only ever seen going to the server and a status
    /// code only coming back, so a rule that names both must evaluate each
    /// part on its own side rather than forcing the rule's `flow:` onto
    /// both. Buffers filled from either side (`http.header`,
    /// `http.cookie`, `file.data`) return `None` and take the rule's.
    pub fn side(self) -> Option<Direction> {
        match self {
            Buffer::HttpMethod | Buffer::HttpUri | Buffer::HttpHost | Buffer::HttpUserAgent | Buffer::HttpRequestBody | Buffer::HttpRequestLine | Buffer::HttpAccept | Buffer::HttpReferer | Buffer::HttpAcceptEnc | Buffer::HttpAcceptLang => Some(Direction::ToServer),
            Buffer::HttpStatCode | Buffer::HttpStatMsg | Buffer::HttpResponseBody | Buffer::HttpServer | Buffer::HttpLocation | Buffer::HttpResponseLine | Buffer::TlsCertSubject | Buffer::TlsCertIssuer | Buffer::TlsCertSerial | Buffer::TlsCerts | Buffer::TlsJa3s | Buffer::TlsVersion => Some(Direction::ToClient),
            _ => None,
        }
    }

    /// Single source of truth for the name<->variant mapping, used by
    /// both `parse` and `as_str` — replaces what used to be two
    /// hand-written match statements that had to be kept in sync by eye.
    const NAMES: &'static [(&'static str, Buffer)] = &[
        ("payload", Buffer::Payload),
        ("packet", Buffer::PacketPayload),
        ("http.uri", Buffer::HttpUri),
        ("http.host", Buffer::HttpHost),
        ("http.method", Buffer::HttpMethod),
        ("http.header", Buffer::HttpHeader),
        ("http.user_agent", Buffer::HttpUserAgent),
        ("http.cookie", Buffer::HttpCookie),
        ("http.request_body", Buffer::HttpRequestBody),
        ("http.stat_code", Buffer::HttpStatCode),
        ("http.stat_msg", Buffer::HttpStatMsg),
        ("http.response_body", Buffer::HttpResponseBody),
        ("http.content_type", Buffer::HttpContentType),
        ("http.server", Buffer::HttpServer),
        ("http.location", Buffer::HttpLocation),
        ("http.header_names", Buffer::HttpHeaderNames),
        ("http.request_line", Buffer::HttpRequestLine),
        ("http.accept", Buffer::HttpAccept),
        ("http.referer", Buffer::HttpReferer),
        ("http.connection", Buffer::HttpConnection),
        ("http.content_len", Buffer::HttpContentLen),
        ("http.start", Buffer::HttpStart),
        ("http.accept_enc", Buffer::HttpAcceptEnc),
        ("http.accept_lang", Buffer::HttpAcceptLang),
        ("http.protocol", Buffer::HttpProtocol),
        ("http.response_line", Buffer::HttpResponseLine),
        // `file.data` in a published ruleset means "the body of whatever
        // is being transferred". ARGUS extracts that for HTTP requests
        // and nothing else yet, so the two are the same buffer here —
        // which is honest as far as it goes, and stated rather than
        // silently approximated: a `file.data` rule about an SMTP
        // attachment will not fire, because ARGUS cannot see one.
        ("file.data", Buffer::FileData),
        // A hash is the most portable indicator there is: it is shared
        // by every feed and every sandbox report, and unlike a content
        // signature it does not care how the file was packed.
        ("file.md5", Buffer::FileMd5),
        ("file.sha256", Buffer::FileSha256),
        // What the content's own leading bytes say it is, which is not
        // what its name or its Content-Type claim.
        ("file.type", Buffer::FileType),
        ("file.magic", Buffer::FileMagic),
        ("smb.share", Buffer::SmbShare),
        ("ntlm.user", Buffer::NtlmUser),
        ("ntlm.domain", Buffer::NtlmDomain),
        ("ntlm.workstation", Buffer::NtlmWorkstation),
        ("krb5.realm", Buffer::KerberosRealm),
        ("krb5.principal", Buffer::KerberosPrincipal),
        ("krb5.service", Buffer::KerberosService),
        ("ldap.dn", Buffer::LdapDn),
        ("dcerpc.interface", Buffer::DcerpcInterface),
        ("dns.query", Buffer::DnsQuery),
        ("tls.sni", Buffer::TlsSni),
        ("tls.ja3", Buffer::TlsJa3),
        ("tls.cert_subject", Buffer::TlsCertSubject),
        ("tls.cert_issuer", Buffer::TlsCertIssuer),
        ("tls.cert_serial", Buffer::TlsCertSerial),
        ("tls.certs", Buffer::TlsCerts),
        ("tls.ja3s", Buffer::TlsJa3s),
        ("tls.version", Buffer::TlsVersion),
        ("ftp.command", Buffer::FtpCommand),
        ("ssh.version", Buffer::SshVersion),
        ("smtp.command", Buffer::SmtpCommand),
        ("smtp.sender", Buffer::SmtpSender),
        ("smtp.recipient", Buffer::SmtpRecipient),
        ("smb.command", Buffer::SmbCommand),
        ("smb.filename", Buffer::SmbFilename),
        ("modbus.function", Buffer::ModbusFunction),
        ("modbus.address", Buffer::ModbusAddress),
        ("rdp.cookie", Buffer::RdpCookie),
        ("tftp.opcode", Buffer::TftpOpcode),
        ("tftp.filename", Buffer::TftpFilename),
        ("snmp.community", Buffer::SnmpCommunity),
        ("dnp3.function", Buffer::Dnp3Function),
    ];

    pub fn parse_name(s: &str) -> anyhow::Result<Self> {
        Self::NAMES.iter().find(|(name, _)| *name == s).map(|(_, b)| *b).ok_or_else(|| {
            let expected: Vec<&str> = Self::NAMES.iter().map(|(n, _)| *n).collect();
            anyhow::anyhow!("unknown buffer {:?} (expected {})", s, expected.join("/"))
        })
    }

    pub fn as_str(&self) -> &'static str {
        Self::NAMES.iter().find(|(_, b)| b == self).map(|(n, _)| *n).expect("every Buffer variant has an entry in NAMES")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Direction {
    Any,
    ToServer,
    ToClient,
}

impl Direction {
    pub fn parse_name(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "any" => Direction::Any,
            "to_server" => Direction::ToServer,
            "to_client" => Direction::ToClient,
            other => anyhow::bail!("unknown direction {:?} (expected any/to_server/to_client)", other),
        })
    }
}

struct RegexEntry {
    name: String,
    re: regex::bytes::Regex,
    negate: bool,
}

pub struct RuleSet {
    literal: FxHashMap<(Buffer, Direction), (AhoCorasick, Vec<String>)>,
    regex: FxHashMap<(Buffer, Direction), Vec<RegexEntry>>,
    /// v2 rules, kept in their own matcher rather than lowered into the
    /// v1 structures. Lowering isn't possible in general — a v1 entry has
    /// one pattern and no header scoping — and keeping them separate
    /// means the v1 path is untouched, so an existing rules file behaves
    /// exactly as it did.
    v2: crate::rules::RuleSetV2,
}

impl RuleSet {
    pub fn empty() -> Self {
        RuleSet { literal: FxHashMap::default(), regex: FxHashMap::default(), v2: crate::rules::RuleSetV2::default() }
    }

    /// Whether any rule inspects a file hash or type.
    ///
    /// Hashing a body costs a pass over it, so it is done only when a
    /// rule could use the result — the same reasoning as `record_flows`,
    /// and the same shape: work that nothing consumes is not done.
    pub fn wants_file_identity(&self) -> bool {
        self.wants(&[Buffer::FileMd5, Buffer::FileSha256, Buffer::FileType, Buffer::FileMagic])
    }

    /// Whether any loaded rule is about a single packet, which costs a
    /// scan of every packet's payload and so is done only when asked for.
    pub fn wants_packet_rules(&self) -> bool {
        self.v2.has_packet_rules()
    }

    /// Whether any loaded rule reads the server's ServerHello.
    pub fn wants_server_hello(&self) -> bool {
        self.wants(&[Buffer::TlsJa3s, Buffer::TlsVersion])
    }

    /// Whether any loaded rule inspects the server's certificate. Reading
    /// one costs a pass over the handshake, so it is done only if asked for.
    pub fn wants_tls_certs(&self) -> bool {
        self.wants(&[Buffer::TlsCertSubject, Buffer::TlsCertIssuer, Buffer::TlsCertSerial, Buffer::TlsCerts])
    }

    fn wants(&self, wanted: &[Buffer]) -> bool {
        let wanted = &wanted;
        // All three stores, because a v1 rule is as entitled to ask for
        // a hash as a v2 one — and checking only `v2` made this quietly
        // false for every hand-written ruleset.
        self.literal.keys().any(|(b, _)| wanted.contains(b)) || self.regex.keys().any(|(b, _)| wanted.contains(b)) || self.v2.uses_any(wanted)
    }

    /// Records that this flow is `app` (`"app.rdp"`, ...) for rules that
    /// are about a protocol rather than a buffer.
    pub fn mark_app(&self, bits: &mut crate::rules::FlowBits, app: &str) {
        self.v2.mark_app(bits, app);
    }

    /// The cross-connection state operations of a rule, if it has any.
    pub fn xbits_for(&self, sid: u32) -> Option<crate::threshold::XbitSpec> {
        self.v2.xbits_for(sid)
    }

    /// The rate control on a rule, if it has any. Only v2 rules can.
    pub fn threshold_for(&self, sid: u32) -> Option<crate::threshold::Threshold> {
        self.v2.threshold_for(sid)
    }

    /// How many v2 rules loaded, for the startup banner.
    pub fn v2_len(&self) -> usize {
        self.v2.len()
    }

    /// Every rule, both syntaxes, for the `rules_loaded` gauge. Counts
    /// patterns rather than file lines: one v1 line is one pattern, and
    /// that is what the matcher actually holds.
    pub fn total_len(&self) -> usize {
        let v1: usize = self.literal.values().map(|(_, names)| names.len()).sum::<usize>() + self.regex.values().map(|v| v.len()).sum::<usize>();
        v1 + self.v2.len()
    }

    pub fn load(path: &str) -> anyhow::Result<Self> {
        Ok(Self::load_inner(path, false)?.0)
    }

    /// Loads what it can, returning every rule it had to refuse and why.
    /// Used by `-check-rules`, and by the translator to drop the rules
    /// ARGUS itself will not accept.
    pub fn load_lenient(path: &str) -> anyhow::Result<(Self, Vec<String>)> {
        Self::load_inner(path, true)
    }

    fn load_inner(path: &str, lenient: bool) -> anyhow::Result<(Self, Vec<String>)> {
        let mut literal_patterns: FxHashMap<(Buffer, Direction), Vec<(String, Vec<u8>)>> = FxHashMap::default();
        let mut regex_patterns: FxHashMap<(Buffer, Direction), Vec<RegexEntry>> = FxHashMap::default();

        // One registry for the whole file: a flowbit is only useful if
        // the rule that sets it and the rule that tests it agree on which
        // bit they mean, which they can only do by interning together.
        let mut flowbits = crate::rules::FlowbitRegistry::default();
        let mut v2_rules = Vec::new();
        let mut composites = Vec::new();

        // Each line is handled by a closure so that a lenient load can
        // note a bad rule and carry on. A hand-written file should fail at
        // its first mistake, but a generated one has thirty thousand rules
        // and one translator slip must not stop the other 29,999 loading.
        let mut errors: Vec<String> = Vec::new();
        let mut handle = |i: usize, line: &str| -> anyhow::Result<()> {
            // The grammar is chosen by the line's own leading keyword, so
            // both can live in one file and an existing rules file needs
            // no migration at all.
            if crate::rules::is_v2_line(line) {
                match crate::rules::parse_any(line, &mut flowbits).map_err(|e| anyhow::anyhow!("rules file line {}: {}", i + 1, e))? {
                    crate::rules::Parsed::Single(r) => v2_rules.push(r),
                    crate::rules::Parsed::Composite { composite, parts } => {
                        composites.push(composite);
                        v2_rules.extend(parts);
                    }
                }
                return Ok(());
            }
            let parts: Vec<&str> = line.splitn(5, '|').collect();
            if parts.len() != 5 {
                anyhow::bail!(
                    "rules file line {}: expected 'name|buffer|direction|type|pattern' (5 fields), got {}",
                    i + 1,
                    parts.len()
                );
            }
            let name = parts[0].trim().to_string();
            let buffer = Buffer::parse_name(parts[1].trim()).map_err(|e| anyhow::anyhow!("rules file line {}: {}", i + 1, e))?;
            let direction = Direction::parse_name(parts[2].trim()).map_err(|e| anyhow::anyhow!("rules file line {}: {}", i + 1, e))?;
            let kind = parts[3].trim();
            let pattern = parts[4].trim();

            let negate = matches!(kind, "not_literal" | "not_regex");
            if negate && buffer == Buffer::Payload {
                anyhow::bail!(
                    "rules file line {}: {:?} rules aren't supported on the 'payload' buffer — \
                     \"absent so far\" isn't meaningful for a buffer that's still growing. \
                     Use a structured buffer instead.",
                    i + 1,
                    kind
                );
            }

            match kind {
                "literal" => {
                    for d in expand_direction(direction) {
                        literal_patterns.entry((buffer, d)).or_default().push((name.clone(), pattern.as_bytes().to_vec()));
                    }
                }
                "regex" | "not_literal" | "not_regex" => {
                    let re = if kind == "not_literal" {
                        regex::bytes::Regex::new(&regex::escape(pattern))
                    } else {
                        regex::bytes::Regex::new(pattern)
                    }
                    .map_err(|e| anyhow::anyhow!("rules file line {}: bad pattern: {}", i + 1, e))?;
                    for d in expand_direction(direction) {
                        regex_patterns.entry((buffer, d)).or_default().push(RegexEntry { name: name.clone(), re: re.clone(), negate });
                    }
                }
                other => anyhow::bail!("rules file line {}: unknown match type {:?} (expected literal/regex/not_literal/not_regex)", i + 1, other),
            }
            Ok(())
        };
        for (i, raw_line) in fs::read_to_string(path)?.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Err(e) = handle(i, line) {
                if lenient {
                    errors.push(e.to_string());
                } else {
                    return Err(e);
                }
            }
        }

        let mut literal = FxHashMap::default();
        for ((buffer, direction), items) in literal_patterns {
            let names: Vec<String> = items.iter().map(|(n, _)| n.clone()).collect();
            let pats: Vec<&[u8]> = items.iter().map(|(_, p)| p.as_slice()).collect();
            let ac = AhoCorasick::new(&pats)?;
            literal.insert((buffer, direction), (ac, names));
        }

        Ok((RuleSet { literal, regex: regex_patterns, v2: crate::rules::RuleSetV2::build_full(v2_rules, composites, flowbits)? }, errors))
    }

    /// Checks `data` (the contents of `buffer`, seen in traffic flowing
    /// `direction`) against every applicable rule, appending any matched
    /// rule names to `out`.
    ///
    /// Passing `Direction::Any` here means "the caller doesn't know or
    /// track a direction for this traffic" (every UDP-based detection
    /// path in `main.rs` — raw payload, DNS, TFTP, SNMP — is in exactly
    /// this position, since none of them go through `FlowTable`, which
    /// is the only thing that determines a real to-server/to-client
    /// direction) — it is *not* a third storage key. `RuleSet::load`
    /// expands a rule declared `direction: any` into both `ToServer` and
    /// `ToClient` entries at load time; nothing is ever stored under the
    /// key `(buffer, Direction::Any)` itself. A caller passing
    /// `Direction::Any` straight through to a single keyed lookup — as
    /// an earlier version of this method did — would therefore never
    /// match *any* rule, regardless of how that rule was declared, and
    /// this went undetected because every TCP-based protocol computes a
    /// real direction before ever calling this, so nothing exercised the
    /// `Any`-as-a-lookup-key path until live UDP testing caught it. So
    /// `Any` here checks both stored directions and merges the results
    /// (de-duplicated, since an `any`-declared rule is stored in both
    /// and would otherwise be reported twice for a single `Any` check).
    #[allow(clippy::too_many_arguments)]
    pub fn check(&self, p: &Packet, buffer: Buffer, direction: Direction, data: &[u8], scratch: &mut MatchScratch, mut bits: Option<&mut FlowBits>, out: &mut Vec<RuleHit>) {
        match direction {
            Direction::Any => {
                // `Direction::Any` is two different things at once, and
                // conflating them was a bug. As a *storage key* it has to
                // expand into both concrete directions, because nothing
                // is ever stored under `Any` itself. As a statement about
                // the traffic it means "the caller has no flow state and
                // does not know which way this is going" — every UDP path
                // is in exactly that position.
                //
                // v2 header terms care about the difference: `src`/`dst`
                // in a rule mean client/server, so a `to_client` packet
                // has its addresses compared swapped. Passing the
                // *lookup* direction through as the *evaluation*
                // direction therefore made the `ToClient` half of an
                // `Any` check swap the addresses of a packet whose
                // orientation was unknown — so a rule reading
                // `proto:udp; dst_port:53` matched DNS *replies*, whose
                // source port is 53, as though 53 were their destination.
                // The field name said one thing and the matcher did
                // another.
                //
                // So: expand for lookup, but evaluate headers against the
                // literal packet fields.
                let mut both = Vec::new();
                self.check_one(p, buffer, Direction::ToServer, Direction::Any, data, scratch, bits.as_deref_mut(), &mut both);
                self.check_one(p, buffer, Direction::ToClient, Direction::Any, data, scratch, bits.as_deref_mut(), &mut both);
                for hit in both {
                    if !out.iter().any(|h| h.name == hit.name && h.sid == hit.sid) {
                        out.push(hit);
                    }
                }
            }
            _ => self.check_one(p, buffer, direction, direction, data, scratch, bits, out),
        }
    }

    /// Names only, for the v1 rule-engine tests.
    ///
    /// Those tests predate rule identity entirely and are about *lookup*
    /// behaviour — which `(buffer, direction)` key a rule lands under,
    /// and whether an `Any` query finds it — not about what a hit
    /// reports. Keeping them on names means they still fail for the
    /// reasons they were written for (see
    /// `querying_with_direction_any_finds_rules_of_every_declared_direction`,
    /// the regression test for the worst bug this project has shipped)
    /// rather than being rewritten around a richer return type they
    /// don't care about.
    #[cfg(test)]
    pub fn check_names(&self, buffer: Buffer, direction: Direction, data: &[u8], out: &mut Vec<String>) {
        let mut hits = Vec::new();
        let mut scratch = MatchScratch::default();
        self.check(&Packet::default(), buffer, direction, data, &mut scratch, None, &mut hits);
        out.extend(hits.into_iter().map(|h| h.name));
    }

    /// The actual single-keyed-lookup check — both the literal and regex
    /// paths are one hashmap lookup keyed on `(buffer, direction)`,
    /// `direction` always a concrete `ToServer`/`ToClient` here.
    #[allow(clippy::too_many_arguments)]
    /// As `check` for the raw stream of one side of a connection, which only
    /// grows, so what was already scanned is not scanned again.
    #[allow(clippy::too_many_arguments)]
    pub fn check_stream(&self, p: &Packet, direction: Direction, data: &[u8], scan: &mut crate::rules::StreamScan, scratch: &mut MatchScratch, bits: Option<&mut FlowBits>, out: &mut Vec<RuleHit>) {
        if let Some((ac, names)) = self.literal.get(&(Buffer::Payload, direction)) {
            if let Some(m) = ac.find(data) {
                out.push(RuleHit { name: names[m.pattern().as_usize()].clone(), sid: 0, severity: Severity::High });
            }
        }
        if let Some(entries) = self.regex.get(&(Buffer::Payload, direction)) {
            for entry in entries {
                if entry.re.is_match(data) != entry.negate {
                    out.push(RuleHit { name: entry.name.clone(), sid: 0, severity: Severity::High });
                }
            }
        }
        if !self.v2.is_empty() {
            self.v2.check_stream(p, Buffer::Payload, direction, data, scan, scratch, bits, out);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_one(&self, p: &Packet, buffer: Buffer, lookup: Direction, evaluate: Direction, data: &[u8], scratch: &mut MatchScratch, bits: Option<&mut FlowBits>, out: &mut Vec<RuleHit>) {
        let direction = lookup;
        // v1 rules have no identity of their own, so they report sid 0
        // and the original hardcoded `High` — unchanged behaviour for an
        // unchanged rules file.
        if let Some((ac, names)) = self.literal.get(&(buffer, direction)) {
            if let Some(m) = ac.find(data) {
                out.push(RuleHit { name: names[m.pattern().as_usize()].clone(), sid: 0, severity: Severity::High });
            }
        }
        if let Some(entries) = self.regex.get(&(buffer, direction)) {
            for entry in entries {
                if entry.re.is_match(data) != entry.negate {
                    out.push(RuleHit { name: entry.name.clone(), sid: 0, severity: Severity::High });
                }
            }
        }
        if !self.v2.is_empty() {
            self.v2.check(p, direction, evaluate, buffer, data, scratch, bits, out);
        }
    }
}

fn expand_direction(d: Direction) -> Vec<Direction> {
    match d {
        Direction::Any => vec![Direction::ToServer, Direction::ToClient],
        other => vec![other],
    }
}

// =======================================================================
// Protocol parsers: HTTP, DNS, TLS (ClientHello -> SNI + JA3), FTP, SSH
// (banner), SMTP
// =======================================================================
//
// None of these try to be a complete implementation of their protocol —
// they extract exactly the fields the rule buffers above need, bail out
// to `None` on anything that doesn't look well-formed, and never panic or
// index out of bounds on attacker-controlled bytes (every read goes
// through the bounds-checked `Cur` cursor, for the binary TLS parser, or
// plain safe string/slice operations for the line-based text protocols).
//
// SMB and industrial protocols (Modbus, DNP3, BACnet, S7comm, ...) are
// deliberately NOT included here. SMB is a complex, versioned binary
// protocol; "industrial protocols" is really a dozen unrelated protocols
// each needing its own dedicated parser. Either done properly is its own
// multi-day project — shipping a rushed, partially-correct parser for
// either would be worse than not having it. See the README.

struct Cur<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cur { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn u24(&mut self) -> Option<u32> {
        if self.remaining() < 3 {
            return None;
        }
        let v = ((self.buf[self.pos] as u32) << 16) | ((self.buf[self.pos + 1] as u32) << 8) | (self.buf[self.pos + 2] as u32);
        self.pos += 3;
        Some(v)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.remaining() < n {
            return None;
        }
        self.pos += n;
        Some(())
    }
}

// --- HTTP ---

pub struct HttpInfo {
    pub method: String,
    pub uri: String,
    pub host: Option<String>,
    /// The raw header block, terminator excluded, request line included.
    ///
    /// Kept whole rather than split into a map because that is the shape
    /// rules actually want: `http.header` in every published ruleset
    /// means "search the headers as text", and a rule looking for an
    /// unusual header *name* has nowhere else to look. Reconstructing
    /// this from a parsed map would also lose ordering and original
    /// spelling, both of which are signal — malware fingerprints show up
    /// in header order at least as often as in header values.
    pub headers: String,
    pub user_agent: Option<String>,
    pub cookie: Option<String>,
    /// Bytes after the header terminator, as far as the buffer goes.
    ///
    /// Raw bytes rather than text, because a request body is very often
    /// not text: an upload of an image, an archive or an executable is
    /// exactly the body worth inspecting.
    ///
    /// Not necessarily the whole body: the reassembly budget bounds it,
    /// and that bound is deliberate. A rule wanting the start of an
    /// upload gets it; one wanting a 40MB file does not, because holding
    /// 40MB per connection is how a sensor is turned into a memory
    /// exhaustion primitive.
    pub body: Option<Vec<u8>>,
    /// How the body is delimited, so a hash can cover all of it rather
    /// than the little that fits in the reassembly buffer.
    pub content_length: Option<u64>,
    pub chunked: bool,
    /// Where the body starts in the buffer that was parsed.
    pub body_offset: usize,
}

const HTTP_METHODS: [&str; 9] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

/// Suricata's `http.header_names`: the names of the headers, in the order
/// they were sent, each between CRLFs, with a blank line at the end.
///
/// ```text
/// <CRLF>Host<CRLF>User-Agent<CRLF>Accept<CRLF><CRLF>
/// ```
///
/// Order and presence are signal in their own right. A browser sends its
/// headers in a characteristic sequence, a scripting library in another,
/// and a hand-rolled implant in a third; a rule keyed on "no `Accept`
/// header" or "`Host` after `User-Agent`" is describing a client, not a
/// payload. The values are deliberately absent so a rule about shape does
/// not have to guess around them.
fn header_names_buffer(headers: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(headers.len() / 2 + 8);
    out.extend_from_slice(b"\r\n");
    // The first line is the request or status line, which is not a header.
    for line in headers.split("\r\n").skip(1) {
        if let Some((name, _)) = line.split_once(':') {
            out.extend_from_slice(name.trim_end().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Suricata's `http.header`: the header lines, without the request or
/// status line, ending with the blank line that closes them.
///
/// Rules are written against exactly that shape. `startswith` on
/// `Host: ` and a trailing `|0d 0a 0d 0a|` are both common, and with the
/// request line left in (and the terminator left off) neither could ever
/// match, so those rules were silently dead.
fn header_block(headers: &str) -> String {
    match headers.split_once("\r\n") {
        Some((_, rest)) => format!("{}\r\n\r\n", rest),
        None => "\r\n".to_string(),
    }
}

/// Buffers that are one named header's value, or the header block whole.
///
/// Each is filled by the same rule on both sides of an exchange, so the
/// request and response dispatch share one list instead of a copy per
/// header. `Accept` and `Referer` only ever appear in requests; asking
/// a response for them simply finds nothing.
const HEADER_VALUE_BUFFERS: &[(Buffer, &str)] = &[
    (Buffer::HttpAccept, "accept"),
    (Buffer::HttpReferer, "referer"),
    (Buffer::HttpConnection, "connection"),
    (Buffer::HttpContentLen, "content-length"),
    (Buffer::HttpAcceptEnc, "accept-encoding"),
    (Buffer::HttpAcceptLang, "accept-language"),
];

/// The value of the first header called `name` (any case), trimmed.
/// The first line is the request or status line and is skipped.
fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.split("
").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim_end().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Finds a byte pattern. Used where the haystack may not be text.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parses an HTTP/1.x request line and Host header out of a (possibly
/// stream-reassembled) client-to-server buffer. Requires the first line
/// to start with a recognized method, to avoid mis-parsing arbitrary
/// binary traffic that happens to contain a CRLF as if it were HTTP.
///
/// Returns `None` until the request's **header block is complete** —
/// until the `CRLF CRLF` that HTTP/1.x ends it with has actually
/// arrived. That requirement is the whole reason this function is worth
/// reading twice, and it is not a nicety.
///
/// An earlier version parsed whatever it was handed, because
/// `split(CRLF).next()` on a buffer containing no CRLF yet returns the
/// *entire buffer* as though it were a finished request line. Fed the
/// first segment of a request split mid-URI — `GET /cgi-bin/../` — it
/// duly returned `uri: "/cgi-bin/../"` and `host: None`: both entirely
/// plausible, both wrong. `FlowTable::observe` then latched its
/// one-shot `scanned_http` flag on that partial parse and never looked
/// at the buffer again, so the request's real URI and its Host header
/// were never checked against a single rule.
///
/// The net effect was that splitting a request across two TCP segments
/// defeated every `http.uri` and `http.host` rule outright — the exact
/// evasion TCP stream reassembly exists to defeat, reintroduced one
/// layer *above* reassembly, which had been working correctly all
/// along. Nothing caught it for the same reason the `Direction::Any`
/// bug survived so long: every unit test feeds a whole request in one
/// call, so none of them ever exercised the partial-input path. It took
/// replaying byte-for-byte identical requests, one whole and one split,
/// to see it — the whole one matched, the split one produced no alerts
/// at all.
///
/// Requiring the terminator gives up the ability to match a request
/// whose header block never completes, or which overruns `-stream-cap`.
/// That is the right trade: such a request has no trustworthy URI or
/// Host to match *against* in the first place, and `Buffer::Payload` —
/// re-scanned across the whole reassembled buffer on every new segment
/// — still covers those same bytes.
pub fn parse_http_request(buf: &[u8]) -> Option<HttpInfo> {
    // The whole reassembled buffer, which `-stream-cap` already bounds.
    //
    // This used to stop at 4096 bytes, and that limit was doing real
    // damage: a request whose header block ends past it never finds its
    // terminator, so it never parses at all — no `http.uri` match, no
    // `http.host` match, and a spurious `PROTOCOL_ANOMALY` for good
    // measure. Requests that large are not exotic; a few sizeable
    // cookies will do it. Replaying 791k frames of real enterprise
    // traffic produced 67 such alerts, every one of them for a request
    // of 4142-5284 bytes, which is what made the cause obvious.
    // The terminator is found in the *bytes*, and only the header block
    // is then required to be text.
    //
    // Requiring the whole buffer to be UTF-8 — which is what this did —
    // meant that any request with a binary body failed to parse at all:
    // no `http.uri`, no `http.host`, no `file.data`, and a spurious
    // `PROTOCOL_ANOMALY` instead. Binary bodies are not an edge case,
    // they are every upload of an image, an archive or an executable,
    // which is to say precisely the requests worth inspecting. Found by
    // the detection harness, whose "executable posted as a .txt" case
    // could not be detected because the request was never parsed.
    let sep = find_subsequence(buf, b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&buf[..sep]).ok()?;

    let mut lines = headers.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    if !HTTP_METHODS.contains(&method) {
        return None;
    }
    let uri = parts.next()?.to_string();

    // No `is_empty` break needed any more: `headers` stops at the blank
    // line by construction.
    // One pass for every header of interest. Matched case-insensitively
    // on the name only: HTTP header names are case-insensitive by
    // specification, and a client that writes `user-agent` is not
    // thereby invisible.
    let mut host = None;
    let mut user_agent = None;
    let mut cookie = None;
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host.get_or_insert_with(|| value.to_string());
        } else if name.eq_ignore_ascii_case("user-agent") {
            user_agent.get_or_insert_with(|| value.to_string());
        } else if name.eq_ignore_ascii_case("cookie") {
            cookie.get_or_insert_with(|| value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = content_length.or_else(|| value.parse().ok());
        } else if name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }

    // The body is whatever follows the terminator, as raw bytes: it may
    // be an executable, and it is the rule engine's job to decide what
    // to make of it, not this parser's.
    let body_start = sep + 4;
    let body = buf.get(body_start..).filter(|b| !b.is_empty()).map(|b| b.to_vec());

    Some(HttpInfo { method: method.to_string(), uri, host, headers: headers.to_string(), user_agent, cookie, body, content_length, chunked, body_offset: body_start })
}

/// What an HTTP response says about itself.
#[derive(Debug, Clone)]
pub struct HttpResponseInfo {
    /// The three-digit status, as text, because that is what rules match.
    pub code: String,
    pub message: String,
    pub headers: String,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub location: Option<String>,
    /// Every `Set-Cookie`, joined, since a response may set several.
    pub set_cookie: Option<String>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub connection_close: bool,
    pub body_offset: usize,
    pub body: Option<Vec<u8>>,
}

/// Parses an HTTP/1.x response out of a server-to-client stream.
///
/// Like the request parser it requires the complete header block, and
/// for the same reason: parsing a partial one latches a one-shot flag on
/// something that will change when the rest arrives.
pub fn parse_http_response(buf: &[u8]) -> Option<HttpResponseInfo> {
    if !buf.starts_with(b"HTTP/1.") {
        return None;
    }
    let sep = find_subsequence(buf, b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&buf[..sep]).ok()?;
    let mut lines = headers.split("\r\n");
    let mut status = lines.next()?.splitn(3, ' ');
    let _version = status.next()?;
    let code = status.next()?;
    let message = status.next().unwrap_or("");
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let (mut content_type, mut server, mut location) = (None, None, None);
    let mut cookies: Vec<&str> = Vec::new();
    let mut content_length: Option<u64> = None;
    let (mut chunked, mut connection_close) = (false, false);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-type") {
            content_type.get_or_insert_with(|| value.to_string());
        } else if name.eq_ignore_ascii_case("server") {
            server.get_or_insert_with(|| value.to_string());
        } else if name.eq_ignore_ascii_case("location") {
            location.get_or_insert_with(|| value.to_string());
        } else if name.eq_ignore_ascii_case("set-cookie") {
            cookies.push(value);
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = content_length.or_else(|| value.parse().ok());
        } else if name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        } else if name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close") {
            connection_close = true;
        }
    }

    let body_offset = sep + 4;
    Some(HttpResponseInfo {
        code: code.to_string(),
        message: message.to_string(),
        headers: headers.to_string(),
        content_type,
        server,
        location,
        set_cookie: (!cookies.is_empty()).then(|| cookies.join("; ")),
        content_length,
        chunked,
        connection_close,
        body_offset,
        body: buf.get(body_offset..).filter(|b| !b.is_empty()).map(|b| b.to_vec()),
    })
}

/// A server's own words about a login attempt, as a service name.
///
/// This is what turns brute-force detection from "N attempts" into "N
/// attempts that were refused". Only the codes that mean *credentials
/// rejected* are counted: 530 for FTP, 535 for SMTP AUTH. A 421 or a 550
/// says something else entirely.
fn auth_failure_line(line: &str, server_port: u16) -> Option<&'static str> {
    match server_port {
        21 if line.starts_with("530") => Some("FTP"),
        25 | 587 if line.starts_with("535") => Some("SMTP"),
        _ => None,
    }
}

/// SMB2 statuses that mean a logon was refused.
///
/// LOGON_FAILURE and WRONG_PASSWORD are the ordinary wrong-credentials
/// answers; ACCOUNT_LOCKED_OUT is what a successful brute force *causes*,
/// which makes it the surest sign one is under way.
fn smb_status_is_auth_failure(status: u32) -> bool {
    matches!(status, 0xC000_006D | 0xC000_006A | 0xC000_0234 | 0xC000_0072)
}

// --- DNS ---

/// Extracts the first question's name from a DNS message (query or
/// response — both echo the question section). Follows compression
/// pointers with a small hop limit to avoid looping on malformed input.
pub fn parse_dns_query(msg: &[u8]) -> Option<String> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    parse_dns_name(msg, 12)
}

fn parse_dns_name(msg: &[u8], mut pos: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if jumps > 5 {
                return None;
            }
            let b2 = *msg.get(pos + 1)?;
            pos = (((len & 0x3F) as usize) << 8) | (b2 as usize);
            jumps += 1;
            continue;
        }
        let len = len as usize;
        pos += 1;
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

// --- TLS: ClientHello -> SNI + JA3 ---

#[derive(Clone, Debug)]
pub struct ClientHelloInfo {
    pub sni: Option<String>,
    pub ja3: String,
}

/// GREASE values (RFC 8701) are reserved placeholder values TLS clients
/// insert to test server robustness against unknown values — e.g.
/// `0x0a0a`, `0x2a2a`, ... any `0xXaXa` where both bytes match. JA3
/// excludes them from its cipher/extension/curve lists, since different
/// runs of the same client emit different (random) GREASE values, which
/// would otherwise make the same client fingerprint differently every
/// connection.
fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

fn join_filtered(vals: &[u16], filter_grease: bool) -> String {
    vals.iter().filter(|&&v| !filter_grease || !is_grease(v)).map(|v| v.to_string()).collect::<Vec<_>>().join("-")
}

/// Computes the standard JA3 client fingerprint: `MD5("version,ciphers,
/// extensions,curves,point_formats")`, GREASE-filtered on the three list
/// fields (not the version, not point formats — matching the widely-
/// implemented convention, since GREASE values are 2-byte and point
/// formats are 1-byte).
pub fn compute_ja3(version: u16, ciphers: &[u16], extensions: &[u16], curves: &[u16], point_formats: &[u16]) -> String {
    let ja3_str = format!(
        "{},{},{},{},{}",
        version,
        join_filtered(ciphers, true),
        join_filtered(extensions, true),
        join_filtered(curves, true),
        join_filtered(point_formats, false),
    );
    let mut hasher = Md5::new();
    hasher.update(ja3_str.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Parses a TLS record that should be a ClientHello (the very first
/// bytes a client sends once the TCP handshake completes), extracting
/// the SNI (if present) and computing the JA3 fingerprint. This reads
/// only the plaintext handshake header — nothing here requires or
/// performs any decryption, since ClientHello is never encrypted.
pub fn parse_tls_client_hello(buf: &[u8]) -> Option<ClientHelloInfo> {
    const RECORD_HEADER_LEN: usize = 5; // type(1) + version(2) + length(2)

    let mut c = Cur::new(buf);
    if c.u8()? != 0x16 {
        return None;
    }
    let _record_version = c.u16()?;
    let record_len = c.u16()? as usize;
    // Both declared lengths are *checked* here rather than read and
    // thrown away, which is what an earlier version did — and that
    // omission is precisely what made a split ClientHello parse as a
    // complete one. With the extensions block still in flight, the
    // `c.remaining() >= 2` test below simply found nothing, so this
    // returned `Some` with `sni: None` and a JA3 fingerprint computed
    // from a truncated extension list. `FlowTable::observe` latched
    // `scanned_tls` on that and never re-examined the buffer, so
    // splitting a ClientHello defeated every `tls.sni` rule — and, worse
    // than merely losing the SNI, produced a JA3 that was silently
    // *wrong* rather than absent, for a value whose entire purpose is
    // fingerprinting known-bad clients. See `parse_http_request` for the
    // same bug in its text-protocol form and how it was found.
    if buf.len() < RECORD_HEADER_LEN + record_len {
        return None; // record still in flight
    }
    // The record layer is TLS-over-TCP's. QUIC carries the same
    // handshake message with no record wrapper at all, so everything
    // below the record check is factored out and shared — one parser,
    // and therefore one JA3 computation, for both transports.
    parse_client_hello_body(&buf[RECORD_HEADER_LEN..])
}

/// Parses a TLS `ClientHello` handshake message, with no record layer.
///
/// This is the form QUIC delivers in its CRYPTO frames, and the form
/// TLS-over-TCP reaches after its record header is stripped.
pub fn parse_client_hello_body(buf: &[u8]) -> Option<ClientHelloInfo> {
    const HANDSHAKE_HEADER_LEN: usize = 4; // type(1) + length(3)

    let mut c = Cur::new(buf);
    if c.u8()? != 0x01 {
        return None;
    }
    let msg_len = c.u24()? as usize;
    if buf.len() < HANDSHAKE_HEADER_LEN + msg_len {
        return None; // handshake message still in flight
    }

    let client_version = c.u16()?;
    c.skip(32)?;

    let sess_id_len = c.u8()? as usize;
    c.skip(sess_id_len)?;

    let cs_len = c.u16()? as usize;
    let cipher_bytes = c.bytes(cs_len)?;
    let ciphers: Vec<u16> = cipher_bytes.chunks_exact(2).map(|ch| u16::from_be_bytes([ch[0], ch[1]])).collect();

    let comp_len = c.u8()? as usize;
    c.skip(comp_len)?;

    let mut sni = None;
    let mut ext_types = Vec::new();
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();

    if c.remaining() >= 2 {
        let ext_total_len = (c.u16()? as usize).min(c.remaining());
        let ext_bytes = c.bytes(ext_total_len)?;
        let mut ec = Cur::new(ext_bytes);
        while ec.remaining() >= 4 {
            let ext_type = match ec.u16() {
                Some(v) => v,
                None => break,
            };
            let ext_len = match ec.u16() {
                Some(v) => v as usize,
                None => break,
            };
            let ext_data = match ec.bytes(ext_len) {
                Some(v) => v,
                None => break,
            };
            ext_types.push(ext_type);

            match ext_type {
                0x0000 => sni = parse_sni_extension(ext_data),
                0x000a => curves = parse_u16_list_ext(ext_data),
                0x000b => point_formats = parse_u8_list_ext(ext_data),
                _ => {}
            }
        }
    }

    let ja3 = compute_ja3(client_version, &ciphers, &ext_types, &curves, &point_formats);
    Some(ClientHelloInfo { sni, ja3 })
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    let mut c = Cur::new(data);
    let mut remaining = c.u16()? as usize;
    while remaining >= 3 && c.remaining() >= 3 {
        let name_type = c.u8()?;
        let name_len = c.u16()? as usize;
        let name_bytes = c.bytes(name_len)?;
        remaining = remaining.saturating_sub(3 + name_len);
        if name_type == 0 {
            return Some(String::from_utf8_lossy(name_bytes).into_owned());
        }
    }
    None
}

fn parse_u16_list_ext(data: &[u8]) -> Vec<u16> {
    let mut c = Cur::new(data);
    let mut out = Vec::new();
    if let Some(list_len) = c.u16() {
        for _ in 0..(list_len / 2) {
            match c.u16() {
                Some(v) => out.push(v),
                None => break,
            }
        }
    }
    out
}

fn parse_u8_list_ext(data: &[u8]) -> Vec<u16> {
    let mut c = Cur::new(data);
    let mut out = Vec::new();
    if let Some(list_len) = c.u8() {
        for _ in 0..list_len {
            match c.u8() {
                Some(v) => out.push(v as u16),
                None => break,
            }
        }
    }
    out
}

// --- FTP: control-channel commands ---

const FTP_COMMANDS: [&str; 21] = [
    "USER", "PASS", "RETR", "STOR", "LIST", "NLST", "CWD", "CDUP", "DELE", "MKD", "RMD", "PORT", "PASV", "QUIT", "SYST", "TYPE", "NOOP", "REIN",
    "ABOR", "APPE", "RNFR",
];

/// Returns `Some(line)` if `line` looks like an FTP control-channel
/// command (a known verb, optionally followed by an argument) — e.g.
/// `"USER anonymous"`, `"RETR secrets.txt"`. Checked against every new
/// complete line as it arrives, since one FTP session sends many
/// commands over its lifetime (unlike a TLS ClientHello or HTTP request
/// line, which happen once).
fn parse_ftp_line(line: &str) -> Option<String> {
    let verb = line.split(' ').next()?.to_uppercase();
    if FTP_COMMANDS.contains(&verb.as_str()) {
        Some(line.to_string())
    } else {
        None
    }
}

// --- SSH: version banner only ---

/// The only plaintext part of an SSH connection is the initial version
/// banner both sides exchange before the encrypted transport begins —
/// e.g. `"SSH-2.0-OpenSSH_8.9"`. Everything after that first line is
/// binary/encrypted, so this is checked once per direction, not per line.
fn parse_ssh_banner(line: &str) -> Option<String> {
    if line.starts_with("SSH-") {
        Some(line.to_string())
    } else {
        None
    }
}

// --- SMTP: control-channel commands + sender/recipient addresses ---

struct SmtpInfo {
    command: String,
    sender: Option<String>,
    recipient: Option<String>,
}

const SMTP_BARE_COMMANDS: [&str; 8] = ["HELO", "EHLO", "DATA", "QUIT", "RSET", "VRFY", "AUTH", "STARTTLS"];

fn parse_smtp_line(line: &str) -> Option<SmtpInfo> {
    let upper = line.to_uppercase();
    if let Some(rest) = upper.strip_prefix("MAIL FROM:") {
        let sender = extract_angle_addr(&line[line.len() - rest.len()..]);
        return Some(SmtpInfo { command: line.to_string(), sender, recipient: None });
    }
    if let Some(rest) = upper.strip_prefix("RCPT TO:") {
        let recipient = extract_angle_addr(&line[line.len() - rest.len()..]);
        return Some(SmtpInfo { command: line.to_string(), sender: None, recipient });
    }
    let verb = upper.split(' ').next()?;
    if SMTP_BARE_COMMANDS.contains(&verb) {
        return Some(SmtpInfo { command: line.to_string(), sender: None, recipient: None });
    }
    None
}

/// Extracts the address out of `<user@example.com>`-style SMTP envelope
/// syntax (also tolerates a bare address with no angle brackets).
fn extract_angle_addr(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.strip_prefix('<').unwrap_or(s);
    let s = s.split('>').next().unwrap_or(s).trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// --- SMB2/3: message command + CREATE-request filename ---
//
// Only the plaintext SMB2/3 "SYNC" header (signature `\xFE` `S` `M` `B`)
// is recognized. SMB1 (`\xFF SMB`, the legacy dialect implicated in
// EternalBlue-class exploits) and SMB3 transform-encrypted messages
// (`\xFD SMB`, used once a session has negotiated encryption) are both
// out of scope — this returns `None` for either rather than
// misinterpreting them as something else. SMB1's own header format is
// different enough (32-byte fixed header, different field layout, no
// modern structure-size validation) that supporting it properly would
// mean a second parser, not a small extension of this one.

pub struct Smb2Info {
    pub command: &'static str,
    pub filename: Option<String>,
    /// NTSTATUS from the header. Zero in a request; in a response it says
    /// whether the operation succeeded, which is how a refused logon shows.
    pub status: u32,
}

const SMB2_COMMANDS: [(u16, &str); 19] = [
    (0x0000, "NEGOTIATE"),
    (0x0001, "SESSION_SETUP"),
    (0x0002, "LOGOFF"),
    (0x0003, "TREE_CONNECT"),
    (0x0004, "TREE_DISCONNECT"),
    (0x0005, "CREATE"),
    (0x0006, "CLOSE"),
    (0x0007, "FLUSH"),
    (0x0008, "READ"),
    (0x0009, "WRITE"),
    (0x000A, "LOCK"),
    (0x000B, "IOCTL"),
    (0x000C, "CANCEL"),
    (0x000D, "ECHO"),
    (0x000E, "QUERY_DIRECTORY"),
    (0x000F, "CHANGE_NOTIFY"),
    (0x0010, "QUERY_INFO"),
    (0x0011, "SET_INFO"),
    (0x0012, "OPLOCK_BREAK"),
];

/// Parses one SMB2 message (the bytes after its 4-byte length prefix —
/// see `StreamHalf::new_smb2_messages`), returning its command name and,
/// for a CREATE request specifically, the filename being opened —
/// CREATE is the highest-value SMB2 message for IDS purposes (share
/// enumeration, access to sensitive paths, ransomware-pattern file
/// access all show up here), so it's the only command body this parses
/// beyond the fixed header; every other command is recognized by name
/// but not parsed further.
pub fn parse_smb2_message(msg: &[u8]) -> Option<Smb2Info> {
    if msg.len() < 64 || &msg[0..4] != b"\xFESMB" {
        return None;
    }
    let structure_size = u16::from_le_bytes([msg[4], msg[5]]);
    if structure_size != 64 {
        return None; // not a well-formed SMB2 SYNC header
    }
    let command_code = u16::from_le_bytes([msg[12], msg[13]]);
    let command = SMB2_COMMANDS.iter().find(|(c, _)| *c == command_code).map(|(_, name)| *name).unwrap_or("UNKNOWN");
    let filename = if command_code == 0x0005 { parse_smb2_create_filename(msg) } else { None };
    let status = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    Some(Smb2Info { command, filename, status })
}

/// The CREATE request body (starting right after the 64-byte fixed SMB2
/// header) carries a fixed part followed by a variable-length filename.
/// `NameOffset`/`NameLength` are explicit fields — per MS-SMB2,
/// `NameOffset` is measured from the start of the SMB2 header (`msg[0]`,
/// not the body), so both are read directly off `msg` rather than
/// assuming any fixed position for the filename.
fn parse_smb2_create_filename(msg: &[u8]) -> Option<String> {
    let body = msg.get(64..)?;
    if body.len() < 48 {
        return None;
    }
    let name_offset = u16::from_le_bytes([body[44], body[45]]) as usize;
    let name_length = u16::from_le_bytes([body[46], body[47]]) as usize;
    if name_length == 0 {
        return None; // e.g. opening the share root itself, not an error
    }
    let end = name_offset.checked_add(name_length)?;
    let raw = msg.get(name_offset..end)?;
    if raw.len() % 2 != 0 {
        return None; // UTF-16 code units are 2 bytes each
    }
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(&units))
}

// --- Modbus/TCP: function code + write address ---
//
// Unlike every other protocol parsed here, Modbus has no distinguishing
// signature bytes worth content-sniffing on — its only structural tell
// (a 2-byte protocol-ID field fixed at zero) is a weak, common pattern
// that would false-positive readily against arbitrary binary traffic.
// So this is deliberately gated by port (502, the well-known Modbus/TCP
// port) in `FlowTable::observe`, not attempted universally the way
// HTTP/TLS/SMB2/SSH/FTP/SMTP are.

pub struct ModbusInfo {
    pub function: String,
    /// Starting register/coil address — only present for the write-type
    /// function codes, since that's the field with real security
    /// relevance (a malicious setpoint or coil write to a PLC/RTU) and
    /// the read-type codes don't carry one in the same position.
    pub address: Option<u16>,
}

const MODBUS_FUNCTIONS: [(u8, &str); 10] = [
    (0x01, "READ_COILS"),
    (0x02, "READ_DISCRETE_INPUTS"),
    (0x03, "READ_HOLDING_REGISTERS"),
    (0x04, "READ_INPUT_REGISTERS"),
    (0x05, "WRITE_SINGLE_COIL"),
    (0x06, "WRITE_SINGLE_REGISTER"),
    (0x0F, "WRITE_MULTIPLE_COILS"),
    (0x10, "WRITE_MULTIPLE_REGISTERS"),
    (0x16, "MASK_WRITE_REGISTER"),
    (0x17, "READ_WRITE_MULTIPLE_REGISTERS"),
];

/// Parses a Modbus/TCP PDU (the bytes after the 7-byte MBAP header — see
/// `StreamHalf::new_modbus_messages`): the function code (translated to
/// a name where recognized, the high exception-response bit cleared
/// first so `0x86` and `0x06` both read as `WRITE_SINGLE_REGISTER`), and
/// the starting address for write-type codes.
pub fn parse_modbus_pdu(pdu: &[u8]) -> Option<ModbusInfo> {
    let code = *pdu.first()?;
    let base_code = code & 0x7F;
    let function = MODBUS_FUNCTIONS.iter().find(|(c, _)| *c == base_code).map(|(_, name)| name.to_string()).unwrap_or_else(|| format!("0x{:02X}", base_code));
    let address = match base_code {
        0x05 | 0x06 | 0x0F | 0x10 | 0x16 if pdu.len() >= 3 => Some(u16::from_be_bytes([pdu[1], pdu[2]])),
        _ => None,
    };
    Some(ModbusInfo { function, address })
}

// --- RDP: connection-request cookie/username hint ---
//
// Content-sniffed via the TPKT+X.224 Connection Request structure — this
// is only ever the very first message of an RDP connection, so it fits
// the one-shot HTTP/TLS/SSH pattern (checked once per direction, not the
// FTP/SMTP-style "many messages" pattern), even though the underlying
// framing (TPKT length-prefix, X.224 TPDU) looks superficially similar
// to SMB2's. No new incremental cursor needed.

/// Extracted from an RDP Connection Request. `cookie` is always
/// present but may be empty — see `check_and_alert` call site in
/// `FlowTable::observe` for why an empty string is checked too rather
/// than skipped: it's what makes a `not_literal` rule against this
/// buffer ("alert if there's no recognizable cookie") meaningful.
pub struct RdpInfo {
    pub cookie: String,
}

/// Parses an RDP Connection Request: a 4-byte TPKT header (RFC 1006)
/// wrapping an X.224 CR TPDU. Extracts the optional `Cookie:
/// mstshash=<value>` routing token many RDP clients send — an explicit,
/// attacker-controlled username hint, genuinely useful for spotting
/// brute-force attempts (the same signal real IDS tools use RDP cookie
/// extraction for). The RDP Negotiation Request structure that can
/// follow the cookie (requested security protocols) is deliberately not
/// parsed this round — the cookie is the higher-value field, and adding
/// it isn't free of its own edge cases worth getting right separately.
pub fn parse_rdp_connection_request(buf: &[u8]) -> Option<RdpInfo> {
    // TPKT's length covers its own 4-byte header plus the TPDU, and the
    // X.224 CR TPDU's fixed part is 7 bytes (LI, code, DST-REF, SRC-REF,
    // CLASS-OPTION), so anything shorter than 11 is malformed.
    const TPKT_HEADER_LEN: usize = 4;
    const X224_CR_FIXED_LEN: usize = 7;

    let mut c = Cur::new(buf);
    if c.u8()? != 3 {
        return None; // TPKT version, always 3
    }
    c.skip(1)?; // TPKT reserved byte
    let tpkt_len = c.u16()? as usize;
    // Checked, not discarded — for the same reason as the TLS record
    // length above. An earlier version read this field and threw it
    // away, then took the cookie from whatever bytes happened to have
    // arrived, so a request split mid-cookie yielded a truncated cookie
    // that `FlowTable::observe` latched `scanned_rdp` on and never
    // revisited. `rdp.cookie` rules — the mstshash= brute-force signal,
    // the highest-value field this parser exists to extract — were
    // therefore defeated by segmentation alone.
    if tpkt_len < TPKT_HEADER_LEN + X224_CR_FIXED_LEN || buf.len() < tpkt_len {
        return None; // malformed, or the TPDU is still in flight
    }

    let _li = c.u8()?; // X.224 length indicator
    let code = c.u8()?;
    if code & 0xF0 != 0xE0 {
        return None; // not a Connection Request (CR) TPDU
    }
    c.skip(4)?; // DST-REF (2) + SRC-REF (2)
    c.skip(1)?; // CLASS-OPTION

    // The CR TPDU's variable/user-data part, where the cookie lives.
    // Bounded by the TPKT-declared length rather than running to the end
    // of the buffer, so a cookie can't absorb bytes belonging to
    // whatever the client pipelined after the connection request.
    let rest = &buf[c.pos..tpkt_len];
    let text = String::from_utf8_lossy(rest);
    let cookie = text
        .find("Cookie: ")
        .map(|start| {
            let after = &text[start + "Cookie: ".len()..];
            after.split("\r\n").next().unwrap_or(after).trim().to_string()
        })
        .unwrap_or_default();
    Some(RdpInfo { cookie })
}

// --- TFTP: request opcode + filename ---
//
// Like Modbus, gated by port (69, the well-known TFTP port) rather than
// content-sniffed in `main.rs` — TFTP's 2-byte opcode field alone is as
// weak a signal as Modbus's protocol-ID field, common enough to appear
// in arbitrary UDP payloads by chance. UDP has no stream reassembly, so
// unlike RDP/SMB2/Modbus this is parsed directly per-packet, the same
// way DNS already is.

pub struct TftpInfo {
    pub opcode: &'static str,
    /// Only present for RRQ/WRQ (read/write requests) — DATA/ACK/ERROR/
    /// OACK don't carry a filename.
    pub filename: Option<String>,
}

const TFTP_OPCODES: [(u16, &str); 6] = [(1, "RRQ"), (2, "WRQ"), (3, "DATA"), (4, "ACK"), (5, "ERROR"), (6, "OACK")];

/// Parses a TFTP packet (RFC 1350): a 2-byte big-endian opcode, then for
/// RRQ/WRQ specifically a null-terminated ASCII filename followed by a
/// null-terminated ASCII transfer mode. TFTP's simplicity is exactly
/// what makes it worth covering: it's a longstanding, still-common
/// vector for pulling malware/config payloads onto IoT and embedded
/// devices, and seeing the requested filename is most of the useful
/// signal here.
pub fn parse_tftp_packet(msg: &[u8]) -> Option<TftpInfo> {
    let mut c = Cur::new(msg);
    let opcode_val = c.u16()?;
    let opcode = TFTP_OPCODES.iter().find(|(v, _)| *v == opcode_val).map(|(_, name)| *name)?;

    let filename = if opcode_val == 1 || opcode_val == 2 {
        let rest = &msg[c.pos..];
        let nul = rest.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&rest[..nul]).into_owned())
    } else {
        None
    };

    Some(TftpInfo { opcode, filename })
}

// --- SNMP v1/v2c: community string ---
//
// Also gated by port (161/162) rather than content-sniffed, for the
// same reason as Modbus/TFTP, even though the structural check here
// (a specific BER SEQUENCE{INTEGER version, OCTET STRING community})
// is a meaningfully stronger signal than either — kept consistent with
// the rest of the port-gated protocols rather than making a one-off
// exception.
//
// This is a narrowly-scoped BER/ASN.1 reader, not a general one: it
// recognizes exactly the SEQUENCE/INTEGER/OCTET-STRING tags needed to
// walk an SNMPv1/v2c message's fixed header shape, handles both short-
// and the common multi-byte long-form BER lengths, and bails to `None`
// on anything else (SNMPv3's different structure included) rather than
// guessing.

/// Reads one BER TLV starting at `pos`, returning `(tag, value, next_pos)`.
fn read_ber_tlv(buf: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *buf.get(pos)?;
    let len_byte = *buf.get(pos + 1)?;
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let num_len_bytes = (len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return None; // indefinite-length or implausibly large; not supported
        }
        let mut len = 0usize;
        for i in 0..num_len_bytes {
            len = (len << 8) | (*buf.get(pos + 2 + i)? as usize);
        }
        (len, 2 + num_len_bytes)
    };
    let value_start = pos + header_len;
    let value_end = value_start.checked_add(len)?;
    let value = buf.get(value_start..value_end)?;
    Some((tag, value, value_end))
}

/// Extracts the community string from an SNMPv1/v2c message. Returns
/// `None` for SNMPv3 (a structurally different message — its "version"
/// field is 3, not 0 or 1 — with no plaintext community string to find)
/// or anything that doesn't match the expected shape.
pub fn parse_snmp_community(msg: &[u8]) -> Option<String> {
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_OCTET_STRING: u8 = 0x04;

    let (outer_tag, outer_value, _) = read_ber_tlv(msg, 0)?;
    if outer_tag != TAG_SEQUENCE {
        return None;
    }
    let (version_tag, version_value, next) = read_ber_tlv(outer_value, 0)?;
    if version_tag != TAG_INTEGER {
        return None;
    }
    match version_value.first() {
        Some(0) | Some(1) => {} // v1 or v2c
        _ => return None,
    }
    let (community_tag, community_value, _) = read_ber_tlv(outer_value, next)?;
    if community_tag != TAG_OCTET_STRING {
        return None;
    }
    Some(String::from_utf8_lossy(community_value).into_owned())
}

// --- DNP3: application-layer function code ---
//
// DNP3 (IEEE 1815) is common in North American electric-utility SCADA/
// RTU communication — the natural next industrial protocol after
// Modbus. Gated by port (20000, DNP3's well-known TCP port) like
// Modbus/TFTP/SNMP, even though its 2-byte sync pattern (`0x05 0x64`)
// is a meaningfully stronger signal than any of those three (two
// specific non-zero bytes, not a common padding/reserved-field
// artifact the way Modbus's all-zero protocol-ID field is) — it's still
// nowhere near as strong as SMB2's 4-byte ASCII magic, so this stays
// consistent with the port-gated group rather than making a one-off
// exception based on a judgment call about "how strong is strong enough".
//
// The data link layer interleaves a CRC-16 after every 16 bytes of
// payload, which has to be stripped out before the transport and
// application layers underneath become readable as contiguous bytes.
// CRC *validation* is deliberately not implemented — corrupted frames
// just fail to parse further rather than being flagged as corrupt
// specifically; DNP3's particular CRC-16 variant doesn't add IDS value
// here, only implementation risk for a check this parser doesn't
// otherwise need.

pub struct Dnp3Info {
    pub function: &'static str,
}

const DNP3_FUNCTIONS: [(u8, &str); 13] = [
    (0x00, "CONFIRM"),
    (0x01, "READ"),
    (0x02, "WRITE"),
    (0x03, "SELECT"),
    (0x04, "OPERATE"),
    (0x05, "DIRECT_OPERATE"),
    (0x06, "DIRECT_OPERATE_NR"),
    (0x0D, "COLD_RESTART"),
    (0x0E, "WARM_RESTART"),
    (0x14, "ENABLE_UNSOLICITED"),
    (0x15, "DISABLE_UNSOLICITED"),
    (0x81, "RESPONSE"),
    (0x82, "UNSOLICITED_RESPONSE"),
]; // a subset of IEEE 1815's ~30 function codes — the ones with real
   // "command a physical device" or session-disruption implications,
   // matching how Modbus's own function table is scoped to the
   // security-relevant subset rather than being exhaustive.

/// Parses one whole raw DNP3 data-link frame (starting at its `0x05
/// 0x64` sync bytes — see `StreamHalf::new_dnp3_frames`, which computes
/// each frame's total on-wire size from the link header's length field
/// so the cursor knows where one frame ends and the next begins):
/// validates the sync pattern, de-interleaves the per-16-byte CRC-16
/// blocks to recover the contiguous transport+application-layer bytes,
/// and extracts the application-layer function code — `OPERATE` and
/// `DIRECT_OPERATE` are the ones with real physical-device-control
/// implications, the same reasoning that made Modbus's write-type codes
/// the highest-value field there.
pub fn parse_dnp3_message(msg: &[u8]) -> Option<Dnp3Info> {
    if msg.len() < 10 || msg[0] != 0x05 || msg[1] != 0x64 {
        return None;
    }
    let length = msg[2] as usize; // control+dest+src+user-data, NOT counting the header's own CRC or any per-block CRCs
    if length < 5 {
        return None; // must at least cover control(1)+dest(2)+src(2)
    }
    let user_data_len = length - 5;

    // De-block: the 8-byte header (sync 2 + length 1 + control 1 + dest
    // 2 + src 2) is followed by its own CRC-16 (2 bytes) at msg[8..10],
    // then user data in up-to-16-byte chunks, each followed by its own
    // CRC-16.
    let mut deblocked = Vec::with_capacity(user_data_len);
    let mut pos: usize = 10;
    let mut remaining = user_data_len;
    while remaining > 0 {
        let chunk = remaining.min(16);
        let end = pos.checked_add(chunk)?;
        let block = msg.get(pos..end)?;
        deblocked.extend_from_slice(block);
        pos = end.checked_add(2)?; // skip this block's CRC-16
        remaining -= chunk;
    }

    // deblocked[0] = transport-layer header (FIN/FIR/SEQUENCE, 1 byte);
    // deblocked[1] = application-layer control byte (FIR/FIN/CON/UNS/
    // SEQUENCE, 1 byte); deblocked[2] = the function code we actually want.
    let function_code = *deblocked.get(2)?;
    let function = DNP3_FUNCTIONS.iter().find(|(c, _)| *c == function_code).map(|(_, name)| *name).unwrap_or("UNKNOWN");
    Some(Dnp3Info { function })
}



pub struct SignatureEngine {
    pub(crate) blacklist: FxHashSet<IpAddr>,
    pub rules: RuleSet,
}

impl SignatureEngine {
    pub fn load(blacklist_path: Option<&str>, rules_path: Option<&str>) -> anyhow::Result<Self> {
        let mut blacklist = FxHashSet::default();
        if let Some(path) = blacklist_path {
            for line in fs::read_to_string(path)?.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let addr = IpAddr::parse(line).ok_or_else(|| anyhow::anyhow!("blacklist: invalid IP address {:?}", line))?;
                blacklist.insert(addr);
            }
        }

        let rules = match rules_path {
            Some(path) => RuleSet::load(path)?,
            None => RuleSet::empty(),
        };

        Ok(SignatureEngine { blacklist, rules })
    }

    /// The IP-blacklist check runs on every packet regardless of protocol
    /// or flow state — it's independent of the buffer-matching rule engine.
    #[inline]
    pub fn inspect_blacklist(&self, p: &Packet, now: SystemTime, out: &mut Vec<Alert>) {
        if self.blacklist.contains(&p.src) {
            out.push(Alert {
                timestamp: now,
                severity: Severity::High,
                category: "BLACKLIST_IP",
                src: p.src,
                dst: p.dst,
                proto: p.proto_name(),
                port: p.dst_port,
                message: "traffic from a blacklisted source address".to_string(),
                sid: 0,
            });
        }
        if self.blacklist.contains(&p.dst) {
            out.push(Alert {
                timestamp: now,
                severity: Severity::Medium,
                category: "BLACKLIST_IP",
                src: p.src,
                dst: p.dst,
                proto: p.proto_name(),
                port: p.dst_port,
                message: "traffic to a blacklisted destination address".to_string(),
                sid: 0,
            });
        }
    }

    /// Checks one buffer's content against the rule set, returning
    /// matched rule names (no dedup — callers with flow state, like
    /// `FlowTable`, are responsible for not re-alerting on a match
    /// they've already reported for that flow).
    /// Appends hits to `out`, reusing `scratch`. The form to use on the
    /// packet path: it allocates nothing per call.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn check_buffer_into(&self, p: &Packet, buffer: Buffer, direction: Direction, data: &[u8], scratch: &mut MatchScratch, bits: Option<&mut FlowBits>, out: &mut Vec<RuleHit>) {
        self.rules.check(p, buffer, direction, data, scratch, bits, out);
    }

    /// The raw stream, scanned incrementally; see [`crate::rules::StreamScan`].
    #[allow(clippy::too_many_arguments)]
    pub fn check_stream_into(&self, p: &Packet, direction: Direction, data: &[u8], scan: &mut crate::rules::StreamScan, scratch: &mut MatchScratch, bits: Option<&mut FlowBits>, out: &mut Vec<RuleHit>) {
        self.rules.check_stream(p, direction, data, scan, scratch, bits, out);
    }

    /// Allocating convenience form, for tests and one-off callers.
    #[inline]
    pub fn check_buffer(&self, p: &Packet, buffer: Buffer, direction: Direction, data: &[u8]) -> Vec<RuleHit> {
        let mut out = Vec::new();
        let mut scratch = MatchScratch::default();
        self.rules.check(p, buffer, direction, data, &mut scratch, None, &mut out);
        out
    }
}

// =======================================================================
// Anomaly engine: per-source packet-rate flood detection, plus
// (source, destination)-scoped port-scan detection for both TCP
// (SYN-only) and UDP (reply-aware)
// =======================================================================

#[derive(Clone, Copy)]
pub struct AnomalyConfig {
    pub window: Duration,
    /// Flood threshold in **packets per second**, not packets per window.
    ///
    /// It was a per-window count, and that made it silently depend on
    /// `window`: widening the window to 60s to catch slow port scans —
    /// which is exactly what the scan detector wants — left the same
    /// 5000 standing over six times as long, so the flood threshold fell
    /// from 500pps to 83pps without anyone touching it. 83pps is one
    /// video stream, and a live run duly produced eight `PACKET_FLOOD`
    /// alerts against CDN addresses. Two knobs that multiply each other
    /// is a trap regardless of where the numbers are set; a rate doesn't
    /// move when the window does.
    pub packet_rate_pps: u32,
    /// Report per-second packet counts to the aggregator instead of judging
    /// the flood here. A worker only sees the destinations sharded to it,
    /// so its own count is a fraction of a source that floods several.
    pub flood_via_observations: bool,
    pub port_scan_limit: usize,
    /// Hard cap on tracked source addresses, per worker.
    ///
    /// Every table in this file is keyed by something an attacker
    /// chooses, and all of them were previously bounded only by a
    /// *recency* sweep — which is no bound at all under the traffic this
    /// code exists to detect. The sweep here drops sources not seen
    /// within `window`; during a flood from spoofed source addresses
    /// every entry is fresh every time it runs, so nothing is ever
    /// dropped and the map grows with the attack. At a few hundred bytes
    /// per source (two `Vec`s plus a `HashMap`) and ordinary flood
    /// rates, that reaches gigabytes in minutes. The sensor that exists
    /// to notice the flood was the thing the flood killed.
    pub max_sources: usize,
    /// Hard cap on destinations tracked per source. Bounds the
    /// second dimension: one source touching endless destinations.
    pub max_destinations_per_source: usize,
    /// Hard cap on remembered UDP 4-tuples, used for reply detection.
    pub max_udp_pairs: usize,
    /// Minimum gap between anomaly alerts for the same source (flood) or
    /// source/destination pair (scan).
    ///
    /// `PACKET_FLOOD` used to push an alert for *every packet* once over
    /// threshold, leaving `run_alert_writer` to discard the duplicates.
    /// That works, but it puts the heaviest load on the alert channel at
    /// exactly the moment the sensor is already struggling: a 50k pps
    /// flood meant 50k alerts a second allocated, queued, and thrown
    /// away. Suppressing at the source costs one integer comparison and
    /// makes the flood path cheaper than the ordinary path, which is the
    /// right way round.
    pub alert_min_interval_secs: i64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        AnomalyConfig {
            window: Duration::from_secs(10),
            // 500 packets per 10 seconds is 50 per second, which is not a
            // flood — it is one file transfer, or one busy page load.
            // Replaying real enterprise traffic produced 141 alerts, all
            // of them reading "501 packets ... (limit 500)", i.e. all of
            // them ordinary hosts brushing a threshold that had only ever
            // been tried against synthetic captures. 500 per second
            // still catches anything worth the name.
            packet_rate_pps: 500,
            flood_via_observations: false,
            port_scan_limit: 20,
            // 65536 sources x ~400 bytes is roughly 25MB per worker,
            // which is a real bound rather than a comfortable one, and
            // far more distinct sources than a legitimate segment shows.
            max_sources: 65536,
            max_destinations_per_source: 4096,
            max_udp_pairs: 131072,
            alert_min_interval_secs: 1,
        }
    }
}

struct DstPortStats {
    /// Separate maps per protocol, not one map keyed by port number
    /// alone — TCP port 80 and UDP port 80 are different probes and
    /// must not collide, or count toward the same threshold. (Found via
    /// field testing: a TCP scan followed by a UDP scan against the same
    /// destination shared one port-number-keyed map, so the UDP scan's
    /// very first packet already looked like it had crossed the
    /// threshold, having inherited the earlier TCP scan's port entries.
    /// A single combined map keyed by `(protocol, port)` would have
    /// fixed the collision but still summed both protocols together for
    /// the threshold check — 15 TCP ports plus 15 UDP ports to the same
    /// host would falsely cross a limit of 20 even though neither
    /// protocol individually did. Fully separate maps avoid both.)
    tcp_ports_seen: FxHashMap<u16, i64>,
    udp_ports_seen: FxHashMap<u16, i64>,
    /// Wall-clock second each map was last pruned, gating how often
    /// `retain()` actually runs — see `AnomalyEngine::observe` for why
    /// this is time-gated rather than size-gated or unconditional.
    tcp_last_pruned_at: i64,
    udp_last_pruned_at: i64,
    last_seen_at: i64,
    /// Capture-time second of the last `PORT_SCAN` alert raised for this
    /// destination, so a scan in progress doesn't re-alert per packet.
    ///
    /// `Option` rather than an `i64::MIN` sentinel meaning "never". The
    /// sentinel version of this shipped for about ten minutes and broke
    /// every anomaly test at once: the gate computes
    /// `now_sec - last >= interval`, and `now_sec - i64::MIN` overflows,
    /// which in a release build (`panic = "abort"`, overflow checks off)
    /// wraps to a large negative number — so the comparison was false
    /// forever and *no* `PACKET_FLOOD` or `PORT_SCAN` alert could ever
    /// fire again. A sentinel that gets arithmetic done to it is a trap;
    /// `Option` makes "never" unrepresentable as a number.
    last_scan_alert_at: Option<i64>,
}

struct SrcStats {
    buckets: Vec<u32>,
    bucket_sec: Vec<i64>,
    /// Ports touched, scoped **per destination** and restricted to
    /// packets that look like connection *attempts* — see
    /// `AnomalyEngine::observe` for what that means for TCP vs UDP.
    dst_ports: FxHashMap<IpAddr, DstPortStats>,
    last_seen_at: i64,
    /// As `last_scan_alert_at`, for `PACKET_FLOOD`, which is tracked per
    /// source regardless of destination — and `Option` for the same
    /// overflow reason.
    last_flood_alert_at: Option<i64>,
    /// Packets counted in `vol_sec` and not yet reported to the aggregator.
    vol_sec: i64,
    vol_count: u32,
}

/// Recognizes whether an inbound UDP packet is a *reply* to something
/// its recipient recently sent, or looks unsolicited. UDP has no
/// handshake (unlike TCP's SYN), so this is the only way to distinguish
/// "a DNS resolver replying to a query you made" from "someone probing
/// you on 40 ports you never contacted" without this degenerating into
/// exactly the false-positive class that got UDP excluded from scan
/// detection entirely in an earlier version.
///
/// The model: every UDP packet's exact 4-tuple gets recorded with a
/// timestamp. A packet is a reply if the *reverse* 4-tuple (same two
/// endpoints, ports swapped) was seen recently — meaning the current
/// packet's destination previously sent something to the current
/// packet's source on this same port pairing, so this is very likely
/// that earlier message's response.
struct UdpPairTracker {
    seen: FxHashMap<(IpAddr, u16, IpAddr, u16), i64>,
    since_sweep: u32,
    max_pairs: usize,
    /// Pairs not recorded because the table was full. Counted rather
    /// than silently discarded: a reply that wasn't recorded can't be
    /// recognised later, so this is the rate at which UDP scan detection
    /// is losing accuracy, which is worth being able to see.
    dropped: u64,
}

impl UdpPairTracker {
    fn new(max_pairs: usize) -> Self {
        UdpPairTracker { seen: FxHashMap::default(), since_sweep: 0, max_pairs: max_pairs.max(1), dropped: 0 }
    }

    /// Records this packet's 4-tuple and returns whether it looks like a
    /// reply to an earlier one. Must be called for every UDP packet
    /// (not just ones under consideration for scan detection), since
    /// future reply-lookups depend on every prior packet having been
    /// recorded.
    fn observe_and_check_reply(&mut self, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16, now_sec: i64, window_secs: i64) -> bool {
        let reverse_key = (dst, dst_port, src, src_port);
        let is_reply = self.seen.get(&reverse_key).is_some_and(|&t| now_sec - t <= window_secs);

        let key = (src, src_port, dst, dst_port);
        // Sweep before inserting when full, then refuse rather than
        // evict. Refusing loses reply-detection accuracy for new pairs;
        // evicting would let a flood of junk 4-tuples push out the
        // record of a real outbound query, turning the bound into a
        // false-positive generator (the resolver's reply would then look
        // unsolicited and count toward a port scan).
        if self.seen.len() >= self.max_pairs && !self.seen.contains_key(&key) {
            let cutoff = now_sec - window_secs;
            self.seen.retain(|_, &mut t| t > cutoff);
            if self.seen.len() >= self.max_pairs {
                self.dropped += 1;
                return is_reply;
            }
        }
        self.seen.insert(key, now_sec);

        self.since_sweep += 1;
        if self.since_sweep >= 4096 {
            self.since_sweep = 0;
            let cutoff = now_sec - window_secs;
            self.seen.retain(|_, &mut t| t > cutoff);
        }

        is_reply
    }
}

/// Owned exclusively by one worker thread for its shard of source IPs —
/// no `Mutex`, no `Arc`, no atomics anywhere in this type.
/// What an engine had to give up on because a bound was reached.
/// Surfaced at shutdown: a sensor silently ceasing to track new sources
/// is materially different from a quiet network, and the difference
/// should be visible.
#[derive(Default, Clone, Copy, Debug)]
pub struct AnomalyLimitStats {
    pub sources_refused: u64,
    pub destinations_refused: u64,
    pub udp_pairs_refused: u64,
}

pub struct AnomalyEngine {
    cfg: AnomalyConfig,
    /// `cfg.packet_rate_pps * window`, precomputed.
    flood_limit: u32,
    /// Sources with packets counted but not yet reported, and the newest
    /// second this engine has seen.
    volume_active: Vec<IpAddr>,
    latest_sec: i64,
    flushed_sec: i64,
    num_buckets: i64,
    stats: FxHashMap<IpAddr, SrcStats>,
    udp_tracker: UdpPairTracker,
    since_sweep: u32,
    limits_hit: AnomalyLimitStats,
    /// Probes seen, for the behavioural aggregator.
    ///
    /// Emitted here rather than in the worker because this is where a
    /// "connection attempt" is already decided: a bare SYN for TCP, and
    /// for UDP a datagram that `UdpPairTracker` says isn't a reply to
    /// something the recipient sent. Recomputing that in the worker would
    /// duplicate the tracker, and getting it wrong is how UDP scan
    /// detection produced DNS-reply false positives in the first place.
    observations: Vec<crate::behavior::Observation>,
    observe_enabled: bool,
}

impl AnomalyEngine {
    pub fn new(cfg: AnomalyConfig) -> Self {
        let num_buckets = (cfg.window.as_secs() as i64).max(1);
        // The rate is the configured quantity; the per-window count is
        // derived from it once here rather than recomputed per packet.
        let flood_limit = (cfg.packet_rate_pps as u64).saturating_mul(num_buckets as u64).min(u32::MAX as u64) as u32;
        AnomalyEngine {
            cfg,
            flood_limit,
            volume_active: Vec::new(),
            latest_sec: 0,
            flushed_sec: 0,
            num_buckets,
            stats: FxHashMap::default(),
            udp_tracker: UdpPairTracker::new(cfg.max_udp_pairs),
            since_sweep: 0,
            limits_hit: AnomalyLimitStats::default(),
            observations: Vec::new(),
            observe_enabled: false,
        }
    }

    pub fn enable_observations(&mut self) {
        self.observe_enabled = true;
    }

    pub fn take_observations(&mut self, out: &mut Vec<crate::behavior::Observation>) {
        // Once a second, report the counts of every second that has ended,
        // including for a source that has since gone quiet: a burst is
        // exactly the thing that stops.
        if self.cfg.flood_via_observations && self.latest_sec != self.flushed_sec {
            self.flushed_sec = self.latest_sec;
            self.flush_volume(false);
        }
        out.append(&mut self.observations);
    }

    /// Reports counted packets. `all` includes the second still in progress,
    /// which is what shutdown wants.
    pub fn flush_volume(&mut self, all: bool) {
        let latest = self.latest_sec;
        let mut still: Vec<IpAddr> = Vec::new();
        for src in std::mem::take(&mut self.volume_active) {
            let Some(st) = self.stats.get_mut(&src) else { continue };
            if st.vol_count == 0 {
                continue;
            }
            if all || st.vol_sec < latest {
                self.observations.push(crate::behavior::Observation::Volume { ts_sec: st.vol_sec, src, packets: st.vol_count });
                st.vol_count = 0;
            } else {
                still.push(src);
            }
        }
        self.volume_active = still;
    }

    pub fn limit_stats(&self) -> AnomalyLimitStats {
        let mut s = self.limits_hit;
        s.udp_pairs_refused = self.udp_tracker.dropped;
        s
    }

    pub fn tracked_sources(&self) -> usize {
        self.stats.len()
    }

    #[inline]
    pub fn observe(&mut self, p: &Packet, now: SystemTime, out: &mut Vec<Alert>) {
        let now_sec = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let cutoff = now_sec - self.cfg.window.as_secs() as i64;

        // UDP reply-tracking must run for every UDP packet, unconditionally,
        // so the tracker's state stays complete for future lookups — do
        // this before anything else touches `self`.
        let window_secs = self.cfg.window.as_secs() as i64;
        let udp_is_reply = if p.protocol == PROTO_UDP && p.dst_port != 0 {
            self.udp_tracker.observe_and_check_reply(p.src, p.src_port, p.dst, p.dst_port, now_sec, window_secs)
        } else {
            false
        };

        // Sweep, then refuse, when the source table is full — the same
        // policy as every other bounded table here, for the same reason:
        // evicting on pressure would let a spoofed-source flood push out
        // the entry belonging to a real attacker mid-scan, which turns a
        // memory bound into an evasion primitive.
        if self.stats.len() >= self.cfg.max_sources && !self.stats.contains_key(&p.src) {
            self.stats.retain(|_, s| s.last_seen_at > cutoff);
            if self.stats.len() >= self.cfg.max_sources {
                self.limits_hit.sources_refused += 1;
                return;
            }
        }

        let num_buckets = self.num_buckets;
        let st = self.stats.entry(p.src).or_insert_with(|| SrcStats {
            buckets: vec![0; num_buckets as usize],
            bucket_sec: vec![0; num_buckets as usize],
            dst_ports: FxHashMap::default(),
            last_seen_at: now_sec,
            last_flood_alert_at: None,
            vol_sec: now_sec,
            vol_count: 0,
        });
        st.last_seen_at = now_sec;

        let idx = (now_sec.rem_euclid(num_buckets)) as usize;
        if st.bucket_sec[idx] != now_sec {
            st.bucket_sec[idx] = now_sec;
            st.buckets[idx] = 0;
        }
        st.buckets[idx] += 1;

        // PACKET_FLOOD stays scoped to the source alone, deliberately:
        // raw volume from one address is worth flagging regardless of how
        // many destinations it's spread across.
        let total: u32 = st.bucket_sec.iter().zip(st.buckets.iter()).filter(|(&sec, _)| sec > cutoff).map(|(_, &c)| c).sum();

        // Gated to at most one alert per `alert_min_interval_secs` per
        // source. Previously this pushed an alert for every packet over
        // threshold and let the writer discard them, which meant peak
        // alert-channel pressure coincided exactly with peak traffic.
        if self.cfg.flood_via_observations {
            if st.vol_count > 0 && st.vol_sec != now_sec {
                self.observations.push(crate::behavior::Observation::Volume { ts_sec: st.vol_sec, src: p.src, packets: st.vol_count });
                st.vol_count = 0;
            }
            if st.vol_count == 0 {
                self.volume_active.push(p.src);
            }
            st.vol_sec = now_sec;
            st.vol_count = st.vol_count.saturating_add(1);
            self.latest_sec = self.latest_sec.max(now_sec);
        }
        let flood_gated = self.cfg.flood_via_observations || st.last_flood_alert_at.is_some_and(|t| now_sec.saturating_sub(t) < self.cfg.alert_min_interval_secs);
        if total > self.flood_limit && !flood_gated {
            st.last_flood_alert_at = Some(now_sec);
            out.push(Alert {
                timestamp: now,
                severity: Severity::High,
                category: "PACKET_FLOOD",
                src: p.src,
                dst: p.dst,
                proto: p.proto_name(),
                port: p.dst_port,
                message: format!(
                    "{} packets from this source in the last {:?} (limit {} = {}/s)",
                    total, self.cfg.window, self.flood_limit, self.cfg.packet_rate_pps
                ),
                sid: 0,
            });
        }

        // PORT_SCAN: scoped per (source, destination) pair, and restricted
        // to packets that look like connection *attempts*:
        //   - TCP: a bare SYN (SYN set, ACK not set) — the actual
        //     technical signature of "attempting a new connection."
        //   - UDP: a packet that does NOT look like a reply to something
        //     its recipient recently sent (see UdpPairTracker above). This
        //     is what makes UDP scan detection possible at all without
        //     reintroducing the DNS-reply false positive that got UDP
        //     excluded entirely in an earlier version — a resolver
        //     replying to your own queries always has a matching earlier
        //     outbound query in the tracker, so it's correctly never
        //     treated as a probe.
        // Copied out before `st`/`dst_st` are borrowed mutably below,
        // since reading `self.cfg` through `self` while holding those
        // borrows won't compile.
        let max_destinations = self.cfg.max_destinations_per_source;
        let alert_min_interval = self.cfg.alert_min_interval_secs;
        let port_scan_limit = self.cfg.port_scan_limit;
        let scan_window = self.cfg.window;

        let looks_like_connection_attempt = match p.protocol {
            PROTO_TCP => (p.tcp_flags & TCP_SYN != 0) && (p.tcp_flags & TCP_ACK == 0),
            PROTO_UDP => !udp_is_reply,
            _ => false,
        };

        if looks_like_connection_attempt && p.dst_port != 0 {
            if st.dst_ports.len() >= max_destinations && !st.dst_ports.contains_key(&p.dst) {
                st.dst_ports.retain(|_, d| d.last_seen_at > cutoff);
                if st.dst_ports.len() >= max_destinations {
                    // Written straight to the counter rather than to a
                    // local tallied at the end of the function: this path
                    // returns early, so an accumulator down there never
                    // sees it. (Disjoint-field borrows make this fine
                    // even while `st` holds `self.stats`.)
                    self.limits_hit.destinations_refused += 1;
                    return;
                }
            }
            let dst_st = st.dst_ports.entry(p.dst).or_insert_with(|| DstPortStats {
                tcp_ports_seen: FxHashMap::default(),
                udp_ports_seen: FxHashMap::default(),
                tcp_last_pruned_at: 0,
                udp_last_pruned_at: 0,
                last_seen_at: now_sec,
                last_scan_alert_at: None,
            });
            dst_st.last_seen_at = now_sec;
            let (ports_seen, last_pruned_at) =
                if p.protocol == PROTO_TCP { (&mut dst_st.tcp_ports_seen, &mut dst_st.tcp_last_pruned_at) } else { (&mut dst_st.udp_ports_seen, &mut dst_st.udp_last_pruned_at) };
            ports_seen.insert(p.dst_port, now_sec);
            // Pruned at most once per wall-clock second, not on every
            // packet and not gated by map size — either of those got
            // this wrong in an earlier version. Size-gating (only prune
            // once past some multiple of port_scan_limit) let a
            // low-volume source's stale entries linger indefinitely
            // below that threshold, so "distinct ports in the last
            // {window}" quietly stopped being true. Pruning
            // unconditionally on every packet fixed that, but has
            // genuinely unbounded per-packet cost: a fast, wide scan
            // (the exact traffic pattern this code exists to catch)
            // makes `retain()`'s O(map size) cost scale with the size of
            // the very attack being detected, so ARGUS's own processing
            // slows down precisely when it's under the most hostile
            // traffic. Time-gating gives both: real time passing is what
            // actually makes an entry stale, so gating on time (rather
            // than a packet count that a fast scanner controls) keeps
            // staleness bounded to about a second regardless of volume,
            // while capping retain() to at most once per second bounds
            // its cost to an amortized-negligible amount no matter how
            // many packets arrive within that second.
            if now_sec > *last_pruned_at {
                *last_pruned_at = now_sec;
                ports_seen.retain(|_, &mut t| t > cutoff);
            }
            let scan_gated = dst_st.last_scan_alert_at.is_some_and(|t| now_sec.saturating_sub(t) < alert_min_interval);
            if ports_seen.len() > port_scan_limit && !scan_gated {
                dst_st.last_scan_alert_at = Some(now_sec);
                out.push(Alert {
                    timestamp: now,
                    severity: Severity::Medium,
                    category: "PORT_SCAN",
                    src: p.src,
                    dst: p.dst,
                    proto: p.proto_name(),
                    port: p.dst_port,
                    message: format!(
                        "{} distinct {} ports touched on this destination in the last {:?} (limit {})",
                        ports_seen.len(),
                        p.proto_name(),
                        scan_window,
                        port_scan_limit
                    ),
                    sid: 0,
                });
            }

        }

        self.since_sweep += 1;
        if self.since_sweep >= 4096 {
            self.since_sweep = 0;
            self.stats.retain(|_, s| s.last_seen_at > cutoff);
        }
    }
}

// =======================================================================
// TCP stream reassembly: FlowTable
// =======================================================================
//
// The piece that defeats the classic evasion technique of splitting a
// malicious payload across two packets so a single-packet signature
// match never sees it whole. Each TCP connection gets a canonical
// FlowKey — built from its two endpoints in a fixed (address, port)-
// sorted order — so packets in *either* direction of the same connection
// always hash to the same key, and therefore (see `main.rs`'s sharding)
// always land on the same worker thread. That's what lets `FlowTable` be
// a plain `FxHashMap` with no locking: one worker owns a connection's
// entire state, both directions, for its whole lifetime.
//
// Reassembly itself is a simplified sliding window: in-order bytes are
// appended directly; out-of-order segments are stashed (bounded) until
// the gap closes; pure retransmits are dropped; partial overlaps are
// trimmed to just their new tail. Buffers are capped (`-stream-cap`,
// default `DEFAULT_STREAM_CAP`) since we only need enough to see headers/handshakes/typical exploit
// payloads, not to reconstruct entire file transfers.

/// Default reassembled-payload budget per direction, when `-stream-cap`
/// isn't given. Any finite cap has the same fundamental property: a
/// payload split to land after more than this many bytes of preceding
/// stream data still evades signature matching, since the attacker just
/// needs to push the real payload past whatever the cap is — raising the
/// cap raises the bar, it doesn't remove it. Truly removing it means an
/// unbounded buffer, which trades that evasion vector for a real DoS
/// one instead (an attacker opening many slow, long-lived connections to
/// force unbounded per-flow memory growth). 16KB — up from an earlier
/// 4KB default — comfortably covers a full SMB2 CREATE request or a
/// multi-message Modbus burst, not just an HTTP request line or TLS
/// ClientHello, while staying configurable (`-stream-cap`) for anyone
/// who wants to make a different call on this tradeoff.
pub const DEFAULT_STREAM_CAP: usize = 16384;
const MAX_OOO_SEGMENTS: usize = 16;

/// How often an open connection reports the bytes it has moved.
const INTERIM_REPORT_SECS: i64 = 30;
const FLOW_IDLE_TIMEOUT_SECS: i64 = 300;

/// Per-worker cap on concurrently tracked TCP connections.
///
/// The sweep below was previously the only limit, and a recency sweep is
/// not a limit at all against the traffic this code exists to watch: it
/// keeps any flow seen within `FLOW_IDLE_TIMEOUT_SECS` (300), and a SYN
/// flood from spoofed sources creates a brand-new `Flow` per packet,
/// every one of them fresh. Nothing was ever evicted, the sweep ran
/// every 4096 packets and freed nothing, and each entry carries two
/// `StreamHalf`s. At 100k pps that is tens of millions of flows inside
/// the timeout window — several GB, from one of the most ordinary
/// attacks there is.
///
/// 65536 flows per worker is far more than a busy segment holds
/// concurrently, and with `-workers` at a typical core count the total
/// is comfortably bounded.
pub const DEFAULT_MAX_FLOWS: usize = 65536;

/// How aggressively to expire flows when the table is full: a flow idle
/// for this long is dropped even though the ordinary timeout hasn't
/// elapsed. Under pressure, a connection that has said nothing for 10
/// seconds is a far better eviction candidate than refusing to track a
/// new one.
const FLOW_PRESSURE_IDLE_SECS: i64 = 10;

/// How long to wait before calling an unanswered connection attempt
/// dead.
///
/// A flow the far end never responded to isn't going to become
/// interesting, and it's the raw material for scan detection — which
/// needs it promptly, not after the 300-second idle timeout a real
/// session gets. Ten seconds is comfortably past any plausible
/// round-trip while still making a sweep visible almost immediately.
const UNANSWERED_TIMEOUT_SECS: i64 = 10;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Endpoint(IpAddr, u16);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey(Endpoint, Endpoint);

impl FlowKey {
    pub fn new(a_ip: IpAddr, a_port: u16, b_ip: IpAddr, b_port: u16) -> Self {
        let a = Endpoint(a_ip, a_port);
        let b = Endpoint(b_ip, b_port);
        if (a.0, a.1) <= (b.0, b.1) {
            FlowKey(a, b)
        } else {
            FlowKey(b, a)
        }
    }
}

/// TCP sequence numbers wrap around; comparisons need to use the
/// standard signed-difference trick (as in RFC 1323) rather than a plain
/// `<`/`>`, or a wraparound makes a very-old segment look "newest".
#[inline]
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Hashes one HTTP body as its segments arrive.
///
/// Installed once a request or response has been parsed, so it sees every
/// byte after the headers regardless of how many the reassembly buffer
/// could hold. See `files::FileHasher` for why this is done by streaming.
struct BodyTap {
    hasher: crate::files::FileHasher,
    /// Bytes still owed by a `Content-Length` body. `None` means the body
    /// is chunked, or runs until the connection closes.
    remaining: Option<u64>,
    chunk: Option<crate::files::Dechunker>,
    done: bool,
    /// Bytes were lost before hashing began, so the digest describes
    /// something other than the file.
    incomplete: bool,
}

impl BodyTap {
    fn feed(&mut self, data: &[u8]) {
        if self.done {
            return;
        }
        if let Some(ch) = &mut self.chunk {
            let h = &mut self.hasher;
            ch.feed(data, |b| h.update(b));
            if ch.bad {
                self.incomplete = true;
            }
            self.done = ch.done;
        } else if let Some(rem) = &mut self.remaining {
            let take = (*rem).min(data.len() as u64) as usize;
            self.hasher.update(&data[..take]);
            *rem -= take as u64;
            self.done = *rem == 0;
        } else {
            self.hasher.update(data);
        }
    }

    fn finish(self) -> Option<crate::files::FileInfo> {
        // A digest of garbled chunking is a digest of nothing, and so is
        // one whose opening bytes were dropped before hashing began: it
        // describes a file that never existed, and reporting it would
        // put a confident, wrong hash in front of a feed lookup.
        if self.incomplete || self.chunk.as_ref().is_some_and(|c| c.bad) {
            return None;
        }
        self.hasher.finish(false)
    }
}

struct StreamHalf {
    buffer: Vec<u8>,
    stream_cap: usize,
    next_seq: Option<u32>,
    out_of_order: BTreeMap<u32, Vec<u8>>,
    scanned_http: bool,
    scanned_tls: bool,
    scanned_certs: bool,
    scanned_server_hello: bool,
    /// What the raw-payload prefilter has already seen of this stream.
    payload_scan: crate::rules::StreamScan,
    scanned_ssh: bool,
    scanned_rdp: bool,
    /// One flag per enterprise protocol, latched on the first successful
    /// parse.
    ///
    /// Each of those parsers scans the whole reassembled buffer, so
    /// re-running them on every segment would be quadratic in the length
    /// of a connection — bounded by the reassembly budget, but wasteful
    /// in exactly the sessions that matter, since an SMB session is long
    /// and its interesting message is near the start. Separate flags
    /// rather than one shared flag because NTLM is carried *inside* SMB:
    /// latching them together would mean the SMB parse silently
    /// suppressed the NTLM one.
    scanned_smb1: bool,
    scanned_ntlm: bool,
    scanned_krb: bool,
    scanned_ldap: bool,
    scanned_rpc: bool,
    scanned_http_resp: bool,
    /// Bytes of this direction dropped because the buffer was full. A tap
    /// installed after any were dropped has missed part of the body.
    dropped: u64,
    tap: Option<BodyTap>,
    /// A body whose hash completed, waiting to be checked against rules.
    finished_file: Option<crate::files::FileInfo>,
    /// How much of `buffer` has already been split into complete lines
    /// and checked for FTP/SMTP commands — unlike the HTTP/TLS/SSH
    /// checks (which each fire once per direction), a single connection
    /// carries *many* FTP/SMTP commands over its lifetime, so this is a
    /// cursor that advances as new complete lines appear, rather than a
    /// one-shot boolean flag.
    line_scan_pos: usize,
    /// Same idea as `line_scan_pos`, but for SMB2's length-prefixed
    /// binary framing (a connection carries many SMB2 messages) rather
    /// than CRLF-delimited lines.
    smb2_scan_pos: usize,
    /// Same idea again, for Modbus/TCP's MBAP-header framing. Separate
    /// from `smb2_scan_pos` since a connection is only ever one of these
    /// protocols in practice, but nothing stops both cursors existing —
    /// each just never advances past 0 on a connection that isn't its
    /// protocol.
    modbus_scan_pos: usize,
    /// Set once a Modbus-port connection's traffic fails the protocol-ID
    /// structural check (see `new_modbus_messages`), so a non-Modbus
    /// service that happens to run on port 502 doesn't get re-checked
    /// against a malformed-looking header on every single packet.
    modbus_abandoned: bool,
    /// Same idea as `smb2_scan_pos`/`modbus_scan_pos`, for DNP3's
    /// data-link framing.
    dnp3_scan_pos: usize,
    /// Same idea as `modbus_abandoned`, for a DNP3-port connection whose
    /// traffic fails the `0x05 0x64` sync-pattern check.
    dnp3_abandoned: bool,
    matched: FxHashSet<String>,
}

impl StreamHalf {
    fn new(stream_cap: usize) -> Self {
        StreamHalf {
            buffer: Vec::new(),
            stream_cap,
            next_seq: None,
            out_of_order: BTreeMap::new(),
            scanned_http: false,
            scanned_tls: false,
            scanned_certs: false,
            scanned_server_hello: false,
            payload_scan: Default::default(),
            scanned_smb1: false,
            scanned_ntlm: false,
            scanned_krb: false,
            scanned_ldap: false,
            scanned_rpc: false,
            scanned_http_resp: false,
            dropped: 0,
            tap: None,
            finished_file: None,
            scanned_ssh: false,
            scanned_rdp: false,
            line_scan_pos: 0,
            smb2_scan_pos: 0,
            modbus_scan_pos: 0,
            modbus_abandoned: false,
            dnp3_scan_pos: 0,
            dnp3_abandoned: false,
            matched: FxHashSet::default(),
        }
    }

    /// Feeds one segment in at its sequence number. Returns `true` if new
    /// bytes landed at the end of `buffer` (i.e. detection should re-run).
    fn feed(&mut self, seq: u32, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let next = *self.next_seq.get_or_insert(seq);
        let mut appended = false;

        if seq == next {
            self.append(data);
            appended = true;
            self.drain_out_of_order();
        } else if seq_after(seq, next) {
            // First data wins, the same as for a segment that arrives in
            // order: a second copy at the same sequence number must not
            // replace the first, or the bytes the sensor sees would depend
            // on delivery order, which is the thing an attacker controls.
            // A longer copy keeps the first's bytes and adds only the extra.
            let room = self.out_of_order.len() < MAX_OOO_SEGMENTS;
            match self.out_of_order.get_mut(&seq) {
                Some(held) => {
                    if data.len() > held.len() {
                        held.extend_from_slice(&data[held.len()..]);
                    }
                }
                None if room => {
                    self.out_of_order.insert(seq, data.to_vec());
                }
                None => {}
            }
        } else {
            let seq_end = seq.wrapping_add(data.len() as u32);
            if seq_after(seq_end, next) {
                let skip = next.wrapping_sub(seq) as usize;
                if skip < data.len() {
                    self.append(&data[skip..]);
                    appended = true;
                    self.drain_out_of_order();
                }
            }
        }
        appended
    }

    /// Establishes the expected starting sequence number from a SYN's
    /// ISN (the SYN itself consumes one sequence number, so the first
    /// data byte is at `isn + 1`) — called regardless of whether the SYN
    /// carries a payload, since a bare SYN otherwise never touches
    /// `feed()` at all and `next_seq` would stay uninitialized until
    /// whichever data segment happened to arrive *first*, which is wrong
    /// whenever that first-arriving segment is out of order.
    fn init_seq_from_syn(&mut self, isn: u32) {
        if self.next_seq.is_none() {
            self.next_seq = Some(isn.wrapping_add(1));
        }
    }

    fn append(&mut self, data: &[u8]) {
        let room = self.stream_cap.saturating_sub(self.buffer.len());
        let take = data.len().min(room);
        self.buffer.extend_from_slice(&data[..take]);
        self.dropped += (data.len() - take) as u64;
        if let Some(n) = &mut self.next_seq {
            *n = n.wrapping_add(data.len() as u32);
        }
        // The tap sees the whole segment, not the part the buffer kept.
        if let Some(tap) = &mut self.tap {
            tap.feed(data);
            if tap.done {
                self.finished_file = self.tap.take().and_then(BodyTap::finish);
            }
        }
    }

    /// Starts hashing a body that begins at `body_offset` in the buffer.
    ///
    /// `content_length` and `chunked` say how it ends; with neither, it
    /// ends when the connection does (see `finish_tap_on_close`).
    fn install_tap(&mut self, body_offset: usize, content_length: Option<u64>, chunked: bool) {
        if content_length == Some(0) && !chunked {
            return;
        }
        let mut tap = BodyTap {
            hasher: crate::files::FileHasher::default(),
            remaining: if chunked { None } else { content_length },
            chunk: chunked.then(crate::files::Dechunker::default),
            done: false,
            incomplete: self.dropped > 0,
        };
        // What is already buffered past the headers is the start of the
        // body.
        if let Some(prefix) = self.buffer.get(body_offset..) {
            tap.feed(prefix);
        }
        if tap.done {
            self.finished_file = tap.finish();
        } else {
            self.tap = Some(tap);
        }
    }

    /// Ends a body that had no length: it was everything up to the FIN.
    fn finish_tap_on_close(&mut self) {
        if let Some(tap) = self.tap.take() {
            self.finished_file = tap.finish();
        }
    }

    /// Delivers held segments that the stream has now reached.
    ///
    /// A held segment may start exactly where the stream now is, or
    /// *before* it: in-order data that filled the gap can run past the
    /// start of a segment that was waiting. An exact lookup on the next
    /// sequence number misses that case, leaving the segment stranded, so
    /// everything after it would wait for bytes that have already been
    /// consumed. Sending one segment out of order and then overlapping it
    /// was a way to make the sensor stop reassembling a stream at will.
    /// Only the part past the current position is new.
    fn drain_out_of_order(&mut self) {
        loop {
            let next = self.next_seq.expect("next_seq set before drain is ever called");
            let Some(start) = self.out_of_order.keys().copied().find(|&k| !seq_after(k, next)) else { break };
            let Some(data) = self.out_of_order.remove(&start) else { break };
            let end = start.wrapping_add(data.len() as u32);
            if seq_after(end, next) {
                let skip = next.wrapping_sub(start) as usize;
                self.append(&data[skip..]);
            }
        }
    }

    /// Returns every complete (CRLF- or LF-terminated) line that's
    /// arrived since the last call, advancing the scan cursor past them.
    /// Any trailing partial line (no terminator yet) is left for next
    /// time, so a command split across two packets is only ever
    /// processed once it's actually complete.
    fn new_lines(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        let slice = &self.buffer[self.line_scan_pos..];
        let mut start = 0;
        let mut i = 0;
        while i < slice.len() {
            if slice[i] == b'\n' {
                let mut end = i;
                if end > start && slice[end - 1] == b'\r' {
                    end -= 1;
                }
                lines.push(String::from_utf8_lossy(&slice[start..end]).into_owned());
                start = i + 1;
            }
            i += 1;
        }
        self.line_scan_pos += start;
        lines
    }

    /// Returns the raw SMB2 message (everything after its 4-byte length
    /// prefix — see `parse_smb2_message`) for every complete SMB2 message
    /// that's arrived since the last call, advancing the cursor past
    /// them. SMB2's "direct TCP transport" framing prefixes every
    /// message with 4 bytes: a reserved zero byte, then a 24-bit
    /// big-endian length. Any incomplete prefix or message body is left
    /// for next time — the same incremental-cursor idea as `new_lines`,
    /// just for length-prefixed binary framing instead of CRLF-delimited
    /// text, since a single SMB connection carries many messages over
    /// its lifetime, not just one.
    fn new_smb2_messages(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let pos = self.smb2_scan_pos;
            if self.buffer.len() < pos + 4 {
                break;
            }
            let prefix = &self.buffer[pos..pos + 4];
            let msg_len = ((prefix[1] as usize) << 16) | ((prefix[2] as usize) << 8) | (prefix[3] as usize);
            let total = 4 + msg_len;
            if self.buffer.len() < pos + total {
                break; // wait for the rest of this message
            }
            out.push(self.buffer[pos + 4..pos + total].to_vec());
            self.smb2_scan_pos += total;
        }
        out
    }

    /// Returns the PDU (function code + data — everything *after* the
    /// 7-byte MBAP header, see `parse_modbus_pdu`) for every complete
    /// Modbus/TCP message that's arrived since the last call, advancing
    /// the cursor past them. Bails out permanently (`modbus_abandoned`)
    /// the first time a claimed message's protocol-ID field isn't the
    /// fixed value `0x0000` every real Modbus message uses — since this
    /// is only ever attempted on port-502 traffic in the first place
    /// (Modbus has no distinguishing signature bytes worth content-
    /// sniffing on, unlike HTTP/TLS/SMB2/SSH/FTP/SMTP), that check is
    /// what keeps a non-Modbus service that happens to share the port
    /// from being mis-parsed as malformed Modbus on every packet.
    fn new_modbus_messages(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.modbus_abandoned {
            return out;
        }
        loop {
            let pos = self.modbus_scan_pos;
            if self.buffer.len() < pos + 7 {
                break;
            }
            let protocol_id = u16::from_be_bytes([self.buffer[pos + 2], self.buffer[pos + 3]]);
            if protocol_id != 0 {
                self.modbus_abandoned = true;
                break;
            }
            let length = u16::from_be_bytes([self.buffer[pos + 4], self.buffer[pos + 5]]) as usize;
            if length == 0 {
                self.modbus_abandoned = true; // malformed: PDU is always at least 1 byte (the function code)
                break;
            }
            let total = 6 + length;
            if self.buffer.len() < pos + total {
                break; // wait for the rest of this message
            }
            out.push(self.buffer[pos + 7..pos + total].to_vec());
            self.modbus_scan_pos += total;
        }
        out
    }

    /// Returns each complete raw DNP3 data-link frame (the *whole* frame,
    /// sync bytes and all — `parse_dnp3_message` does its own header
    /// validation and CRC-block de-interleaving, so unlike the SMB2/
    /// Modbus cursors above this one doesn't strip anything itself, just
    /// figures out where each frame starts and ends) that's arrived
    /// since the last call. Bails out permanently (`dnp3_abandoned`) the
    /// first time a claimed frame doesn't start with the `0x05 0x64`
    /// sync pattern, for the same reason `new_modbus_messages` does:
    /// this is only ever attempted on port-20000 traffic, so a
    /// non-DNP3 service sharing that port shouldn't get re-checked
    /// against a malformed-looking header on every packet.
    fn new_dnp3_frames(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.dnp3_abandoned {
            return out;
        }
        loop {
            let pos = self.dnp3_scan_pos;
            if self.buffer.len() < pos + 10 {
                break;
            }
            if self.buffer[pos] != 0x05 || self.buffer[pos + 1] != 0x64 {
                self.dnp3_abandoned = true;
                break;
            }
            let length = self.buffer[pos + 2] as usize;
            if length < 5 {
                self.dnp3_abandoned = true; // malformed: must cover control+dest+src
                break;
            }
            let user_data_len = length - 5;
            let num_blocks = user_data_len.div_ceil(16);
            let total = 10 + user_data_len + num_blocks * 2;
            if self.buffer.len() < pos + total {
                break; // wait for the rest of this frame
            }
            out.push(self.buffer[pos..pos + total].to_vec());
            self.dnp3_scan_pos += total;
        }
        out
    }
}

struct Flow {
    client: Endpoint,
    server: Endpoint,
    /// The account named by an NTLM, Kerberos or LDAP exchange.
    auth_user: Option<String>,
    /// The DCERPC interface reached, when it is one worth naming.
    rpc_interface: Option<&'static str>,
    /// Identity of content carried in a request body.
    file: Option<crate::files::FileInfo>,
    /// The request was HEAD, so its response carries headers describing a
    /// body that never follows. Hashing "the body" would consume the next
    /// response instead and produce a confident, wrong digest.
    head_request: bool,
    /// Per-connection rule state, for `flowbits`.
    ///
    /// Lazily allocated inside `FlowBits`, so a connection that never
    /// trips a `set` costs one null pointer. That matters at 65,536
    /// flows per worker: a fixed bitset sized to a real ruleset's
    /// several hundred bits would be tens of megabytes of mostly zeroes.
    bits: FlowBits,
    to_server: StreamHalf,
    to_client: StreamHalf,
    last_seen: i64,
    closed: bool,
    reset: bool,
    /// FIN seen in each direction.
    ///
    /// A connection isn't over when one side says it is. Closing on the
    /// *first* FIN — as this did — ends the record before the peer's own
    /// FIN, the final ACKs, and any data still in flight behind that
    /// FIN, all of which a real connection log reports. Half-close is
    /// also a legitimate state a client can sit in for a long time.
    fin_to_server: bool,
    fin_to_client: bool,
    /// Whether a client SYN was observed for this connection.
    ///
    /// A capture that starts mid-conversation has flows whose first
    /// observed byte is somewhere in the middle of a TLS record or an
    /// HTTP body, and nothing about that is anomalous — ARGUS simply
    /// joined late. Distinguishing the two is the difference between a
    /// useful protocol check and 548 false positives on 791k frames of
    /// ordinary enterprise traffic, which is exactly what the first
    /// corpus run produced.
    saw_syn: bool,
    first_ts: SystemTime,
    last_ts: SystemTime,
    vlan_id: u16,
    pkts_to_server: u64,
    pkts_to_client: u64,
    bytes_to_server: u64,
    /// How much of each direction has already been reported to the
    /// aggregator while the connection was open, and when.
    reported_out: u64,
    reported_in: u64,
    last_report_sec: i64,
    bytes_to_client: u64,
    flags_to_server: u8,
    flags_to_client: u8,
    http_host: Option<String>,
    http_uri: Option<String>,
    tls_sni: Option<String>,
    tls_ja3: Option<String>,
    ssh_version: Option<String>,
    alerts: u32,
}

impl Flow {
    /// How the connection ended, as far as could be observed.
    fn state(&self, timed_out: bool) -> &'static str {
        if self.reset {
            "reset"
        } else if self.fin_to_server && self.fin_to_client {
            "closed"
        } else if self.fin_to_server || self.fin_to_client {
            // One side finished and the other never did. Worth
            // distinguishing from a clean close: it's what an aborted
            // transfer and a long-lived half-open session both look like.
            "half_closed"
        } else if timed_out {
            "timeout"
        } else {
            "open"
        }
    }

    /// Did the far end ever say anything?
    ///
    /// This is the discriminator scan detection actually needs. "Many
    /// destinations on one port" describes a port sweep and also
    /// describes a web browser; "many destinations on one port that
    /// never answered" describes only the sweep.
    fn answered(&self) -> bool {
        self.pkts_to_client > 0
    }

    fn to_observation(&self, now_sec: i64) -> crate::behavior::Observation {
        crate::behavior::Observation::Flow {
            ts_sec: self.first_ts.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(now_sec),
            src: self.client.0,
            dst: self.server.0,
            dst_port: self.server.1,
            // Only what has not been reported already.
            bytes_out: self.bytes_to_server.saturating_sub(self.reported_out),
            bytes_in: self.bytes_to_client.saturating_sub(self.reported_in),
            answered: self.answered(),
        }
    }

    /// Flags a connection on a well-known port whose traffic never
    /// parsed as that port's protocol.
    ///
    /// The parsers have always been able to tell the difference and never
    /// said so: they return `None` on anything malformed and the caller
    /// simply moved on, so "port 443 carrying something that is not TLS"
    /// — a tunnel, a backdoor on a port chosen to look innocuous, a
    /// misconfigured service — produced no signal at all. This is the
    /// cheapest possible protocol-anomaly check: it runs once per flow at
    /// close, using metadata already recorded for the flow log.
    ///
    /// Gated on how much *application-layer* data the client actually
    /// sent, taken from the reassembled buffer rather than from the flow's
    /// frame-byte counter.
    ///
    /// Frame bytes were the first attempt and were far too loose: they
    /// include every header, so a handful of packets clears any sensible
    /// threshold and a connection carrying 32 bytes of payload was
    /// reported as a malformed protocol. Replaying a capture with ten
    /// small keepalive-shaped connections on port 443 produced nine
    /// spurious anomalies. The reassembled buffer is the honest measure:
    /// it is exactly the bytes the parsers were given and failed to make
    /// sense of.
    fn protocol_anomaly(&self, now_sec: i64) -> Option<Alert> {
        const MIN_APP_BYTES: usize = 256;
        // Only judge connections whose beginning was actually observed.
        // Without this the check fires on every flow a capture joined
        // mid-stream, because the reassembled buffer starts partway
        // through a record rather than at a ClientHello or a request
        // line. On a real capture that was the overwhelming majority of
        // what it reported.
        if !self.saw_syn {
            return None;
        }
        let app_bytes = self.to_server.buffer.len();
        if app_bytes < MIN_APP_BYTES {
            return None;
        }
        let expected = match self.server.1 {
            80 | 8080 | 8000 if self.http_uri.is_none() => "HTTP",
            443 | 8443 if self.tls_ja3.is_none() => "TLS",
            22 if self.ssh_version.is_none() => "SSH",
            _ => return None,
        };
        Some(Alert {
            timestamp: UNIX_EPOCH + Duration::from_secs(now_sec.max(0) as u64),
            severity: Severity::Medium,
            category: "PROTOCOL_ANOMALY",
            src: self.client.0,
            dst: self.server.0,
            proto: "TCP",
            port: self.server.1,
            message: format!(
                "{} bytes of application data to port {} never parsed as {} — the port's traffic is not the port's protocol",
                app_bytes, self.server.1, expected
            ),
            sid: 0,
        })
    }

    fn to_record(&self, timed_out: bool) -> FlowRecord {
        FlowRecord {
            start: self.first_ts,
            end: self.last_ts,
            src: self.client.0,
            src_port: self.client.1,
            dst: self.server.0,
            dst_port: self.server.1,
            proto: "TCP",
            vlan_id: self.vlan_id,
            pkts_to_server: self.pkts_to_server,
            pkts_to_client: self.pkts_to_client,
            bytes_to_server: self.bytes_to_server,
            bytes_to_client: self.bytes_to_client,
            flags_to_server: self.flags_to_server,
            flags_to_client: self.flags_to_client,
            state: self.state(timed_out),
            http_host: self.http_host.clone(),
            http_uri: self.http_uri.clone(),
            tls_sni: self.tls_sni.clone(),
            tls_ja3: self.tls_ja3.clone(),
            auth_user: self.auth_user.clone(),
            rpc_interface: self.rpc_interface.map(str::to_string),
            file_md5: self.file.as_ref().map(|f| f.md5.clone()),
            file_sha256: self.file.as_ref().map(|f| f.sha256.clone()),
            file_type: self.file.as_ref().and_then(|f| f.kind).map(str::to_string),
            file_size: self.file.as_ref().map(|f| f.size),
            ssh_version: self.ssh_version.clone(),
            alerts: self.alerts,
        }
    }
}

/// Owned exclusively by one worker thread, just like `AnomalyEngine` —
/// no locking needed, because flow sharding (`main.rs`) guarantees both
/// directions of any one connection are always processed by this same
/// worker.
/// How many `(src, dst)` pairs a worker remembers having already
/// reported on. Small: the point is to collapse a burst about one
/// conversation, not to remember a whole day.
const INTEL_SEEN_CAP: usize = 8192;

/// Raises `THREAT_INTEL` when an indicator matches a loaded feed.
///
/// Deduplicated per endpoint pair, because the alternative is one alert
/// per packet to a known-bad address — which is the traffic pattern most
/// likely to occur in volume, so the naive version turns a true positive
/// into a denial of service against its own reader.
///
/// The check is placed at each point where its indicator first becomes
/// *known*: addresses when a flow is created, a domain when a host header
/// or SNI parses, a JA3 when a ClientHello does. None of them is on the
/// per-packet path, which is what makes reputation affordable at all —
/// a binary search per packet would cost more than the rule engine.
fn intel_alert(intel: &Intel, seen: &mut IntelSeen, what: Indicator<'_>, p: &Packet, now: SystemTime, kind: &'static str, out: &mut Vec<Alert>) -> bool {
    let Some(tag) = intel.check(what) else { return false };
    if !seen.first_time(p.src, p.dst) {
        return true;
    }
    out.push(Alert {
        timestamp: now,
        severity: Severity::High,
        category: "THREAT_INTEL",
        src: p.src,
        dst: p.dst,
        proto: p.proto_name(),
        port: p.dst_port,
        message: format!("{} matches a loaded indicator: {}", kind, tag),
        sid: 0,
    });
    true
}

pub struct FlowTable {
    flows: FxHashMap<FlowKey, Flow>,
    stream_cap: usize,
    max_flows: usize,
    since_sweep: u32,
    last_swept_at: i64,
    flows_refused: u64,
    /// Records for flows that have left the table, waiting to be drained
    /// by the worker.
    ///
    /// Buffered here rather than handed out through `observe`'s signature
    /// because `observe` already has seven parameters and is called from
    /// a dozen tests; a `take_completed` drain keeps the change to the
    /// one caller that actually wants records. The worker drains after
    /// every packet, so this holds at most the flows that expired since
    /// the last one.
    completed: Vec<FlowRecord>,
    /// Reused rule-matching buffers, so matching a packet's buffers
    /// allocates nothing. Owned per table (and so per worker), which is
    /// what lets it be plain mutable state with no locking.
    scratch: ScanScratch,
    /// Observations for the behavioural aggregator, drained like
    /// `completed`. Opt-in for the same reason and with the same history
    /// — see `record_flows`.
    observations: Vec<crate::behavior::Observation>,
    observe_enabled: bool,
    /// Whether to build records at all.
    ///
    /// Opt-in, and the reason is a bug that shipped for about an hour:
    /// `expire` pushed a record for every departing flow unconditionally,
    /// while the only code that drained `completed` ran behind
    /// `if flow_tx.is_some()` — so with `-flow-log` unset, which is the
    /// **default**, records accumulated forever. One `FlowRecord` per
    /// completed connection, each carrying up to five `Option<String>`s,
    /// on a table that turns over constantly. Precisely the failure this
    /// round's memory-bounds work existed to eliminate, reintroduced two
    /// sections later by the feature that came after it, which is a
    /// useful reminder that "bounded" is a property of a whole pipeline
    /// and not of a data structure. Now the records aren't built unless
    /// something is listening, which also saves the clones.
    record_flows: bool,
    /// Reputation, checked where indicators appear. Empty by default, and
    /// checked for emptiness before any lookup, so a deployment without
    /// feeds pays nothing.
    intel: Arc<Intel>,
    intel_seen: IntelSeen,
    intel_hits: u64,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::with_stream_cap(DEFAULT_STREAM_CAP)
    }

    pub fn with_stream_cap(stream_cap: usize) -> Self {
        Self::with_limits(stream_cap, DEFAULT_MAX_FLOWS)
    }

    pub fn with_limits(stream_cap: usize, max_flows: usize) -> Self {
        FlowTable {
            flows: FxHashMap::default(),
            stream_cap: stream_cap.max(1),
            max_flows: max_flows.max(1),
            since_sweep: 0,
            last_swept_at: 0,
            flows_refused: 0,
            completed: Vec::new(),
            scratch: ScanScratch::default(),
            observations: Vec::new(),
            observe_enabled: false,
            record_flows: false,
            intel: Arc::new(Intel::default()),
            intel_seen: IntelSeen::new(INTEL_SEEN_CAP),
            intel_hits: 0,
        }
    }

    /// Installs a reputation set. Called once per worker at startup and
    /// again after a reload.
    pub fn set_intel(&mut self, intel: Arc<Intel>) {
        self.intel = intel;
    }

    pub fn intel_hits(&self) -> u64 {
        self.intel_hits
    }

    /// Starts emitting [`crate::behavior::Observation`]s for the
    /// behavioural aggregator.
    pub fn enable_observations(&mut self) {
        self.observe_enabled = true;
    }

    pub fn take_observations(&mut self, out: &mut Vec<crate::behavior::Observation>) {
        out.append(&mut self.observations);
    }

    /// Starts building [`FlowRecord`]s for departing flows. Off by
    /// default — see `record_flows`.
    pub fn enable_flow_records(&mut self) {
        self.record_flows = true;
    }

    /// How many completed-flow records are buffered and undrained.
    pub fn pending_records(&self) -> usize {
        self.completed.len()
    }

    /// Takes the records for flows that have completed since the last
    /// call.
    pub fn take_completed(&mut self, out: &mut Vec<FlowRecord>) {
        out.append(&mut self.completed);
    }

    /// Emits records for every flow still open. Called once when a
    /// worker shuts down, so a long-lived connection that never closed
    /// still appears in the log rather than vanishing — the state field
    /// says `open`, which is the truth about what was observed.
    pub fn flush_open_flows(&mut self, out: &mut Vec<FlowRecord>, alerts: &mut Vec<Alert>) {
        let record = self.record_flows;
        let observe = self.observe_enabled;
        let completed = &mut self.completed;
        let observations = &mut self.observations;
        for (_, f) in self.flows.drain() {
            Self::retire(&f, f.last_seen, false, record, observe, completed, observations, alerts);
        }
        out.append(&mut self.completed);
    }

    /// New connections not tracked because the table was full. A sensor
    /// that has stopped following new connections is not the same thing
    /// as a quiet network, so this is reported at shutdown.
    pub fn flows_refused(&self) -> u64 {
        self.flows_refused
    }

    pub fn tracked_flows(&self) -> usize {
        self.flows.len()
    }

    /// Emits everything a departing flow owes: a protocol-anomaly alert
    /// if it earned one, a flow record, and a behavioural observation.
    ///
    /// One function so the three exits from the table — closing, timing
    /// out, and shutdown — cannot disagree about what a departing flow
    /// produces. They did: the shutdown path emitted records but not
    /// observations and skipped the anomaly check entirely, so a
    /// connection that happened to leave by that route was silently
    /// worth less than an identical one that left by a sweep.
    fn retire(
        f: &Flow,
        now_sec: i64,
        timed_out: bool,
        record: bool,
        observe: bool,
        completed: &mut Vec<FlowRecord>,
        observations: &mut Vec<crate::behavior::Observation>,
        out: &mut Vec<Alert>,
    ) {
        if let Some(alert) = f.protocol_anomaly(now_sec) {
            out.push(alert);
        }
        if record {
            completed.push(f.to_record(timed_out));
        }
        if observe {
            observations.push(f.to_observation(now_sec));
        }
    }

    /// Drops flows that are idle past `idle_secs`, retiring each on the
    /// way out.
    fn expire(&mut self, now_sec: i64, idle_secs: i64, out: &mut Vec<Alert>) {
        let cutoff = now_sec - idle_secs;
        let completed = &mut self.completed;
        let observations = &mut self.observations;
        let record = self.record_flows;
        let observe = self.observe_enabled;
        let unanswered_cutoff = now_sec - UNANSWERED_TIMEOUT_SECS;
        self.flows.retain(|_, f| {
            let dead = f.closed
                || f.last_seen <= cutoff
                // Never answered, and long enough ago that it never will be.
                || (!f.answered() && f.last_seen <= unanswered_cutoff);
            if dead {
                Self::retire(f, now_sec, !f.closed, record, observe, completed, observations, out);
            }
            !dead
        });
    }

    pub fn observe(&mut self, p: &Packet, now: SystemTime, now_sec: i64, sig: &SignatureEngine, out: &mut Vec<Alert>) {
        debug_assert_eq!(p.protocol, PROTO_TCP);

        let key = FlowKey::new(p.src, p.src_port, p.dst, p.dst_port);

        // At capacity: expire aggressively, then refuse. Refusing rather
        // than evicting an arbitrary victim is the same call made in
        // `Defragmenter::offer` and `AnomalyEngine::observe`, for the
        // same reason — if pressure evicted live entries, an attacker
        // could flood junk connections specifically to push out the
        // reassembly state of a real one, and a memory bound would have
        // become an evasion primitive. Refusing degrades visibly (and is
        // counted) instead of degrading in the attacker's favour.
        if self.flows.len() >= self.max_flows && !self.flows.contains_key(&key) {
            self.expire(now_sec, FLOW_PRESSURE_IDLE_SECS, out);
            if self.flows.len() >= self.max_flows {
                self.flows_refused += 1;
                return;
            }
        }

        // A bare ACK carrying nothing does not start a flow.
        //
        // Without this, the final ACK of a normal close — sent *after*
        // both FINs, so after the flow has already retired — creates a
        // second, empty entry under the same key, which then sits until
        // it times out as never-answered. Every completed connection was
        // producing a phantom unanswered flow behind it, and that is not
        // a cosmetic doubling of the flow log:
        //
        //   - `HORIZONTAL_SCAN` counts unanswered destinations, so
        //     ordinary successful connections were donating exactly the
        //     evidence a sweep is recognised by.
        //   - the phantom retires later than the connection that spawned
        //     it but reports that connection's *start* time, so
        //     observations reach the aggregator out of chronological
        //     order. `Periodicity` then measures a gap against a rewound
        //     clock, and a run of unrelated sequential connections comes
        //     out as a flawless fixed-interval beacon. The synthetic
        //     brute-force case duly produced "8 connections spaced 10s
        //     apart with 0.0% jitter" inside a 20-second capture.
        //
        // An empty ACK has no payload to inspect and no handshake to
        // interpret, so nothing is lost by ignoring one that belongs to
        // no known flow. A mid-stream pickup still works: the first
        // segment with data creates the flow.
        if p.tcp_flags & (TCP_SYN | TCP_FIN | TCP_RST) == 0 && p.payload().is_empty() && !self.flows.contains_key(&key) {
            return;
        }

        // Reputation on the addresses is asked once, when the flow is
        // created — the only moment at which "this host started talking to
        // that one" is a new fact.
        if !self.intel.reputation.is_empty() && !self.flows.contains_key(&key) {
            let hit = intel_alert(&self.intel, &mut self.intel_seen, Indicator::Address(&p.dst), p, now, "destination address", out)
                || intel_alert(&self.intel, &mut self.intel_seen, Indicator::Address(&p.src), p, now, "source address", out);
            if hit {
                self.intel_hits += 1;
            }
        }

        let stream_cap = self.stream_cap;
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            client: Endpoint(p.src, p.src_port),
            server: Endpoint(p.dst, p.dst_port),
            to_server: StreamHalf::new(stream_cap),
            to_client: StreamHalf::new(stream_cap),
            last_seen: now_sec,
            closed: false,
            reset: false,
            fin_to_server: false,
            fin_to_client: false,
            saw_syn: false,
            first_ts: p.ts,
            last_ts: p.ts,
            vlan_id: p.vlan_id,
            pkts_to_server: 0,
            pkts_to_client: 0,
            bytes_to_server: 0,
            reported_out: 0,
            reported_in: 0,
            last_report_sec: now_sec,
            bytes_to_client: 0,
            flags_to_server: 0,
            flags_to_client: 0,
            http_host: None,
            http_uri: None,
            tls_sni: None,
            tls_ja3: None,
            auth_user: None,
            rpc_interface: None,
            file: None,
            head_request: false,
            bits: FlowBits::default(),
            ssh_version: None,
            alerts: 0,
        });
        flow.last_seen = now_sec;
        flow.last_ts = p.ts;

        let direction = if p.src == flow.client.0 && p.src_port == flow.client.1 { Direction::ToServer } else { Direction::ToClient };

        flow.bits.add_stream_bytes(direction == Direction::ToServer, p.payload_len as u64);
        if direction == Direction::ToServer {
            flow.pkts_to_server += 1;
            flow.bytes_to_server += p.frame_len as u64;
            flow.flags_to_server |= p.tcp_flags;
        } else {
            flow.pkts_to_client += 1;
            flow.bytes_to_client += p.frame_len as u64;
            flow.flags_to_client |= p.tcp_flags;
        }

        if direction == Direction::ToServer && p.tcp_flags & TCP_SYN != 0 && p.tcp_flags & TCP_ACK == 0 {
            flow.saw_syn = true;
        }
        // Report the bytes moved so far now and then, so that a connection
        // that lasts an hour is not invisible to volume detection for the hour.
        if now_sec - flow.last_report_sec >= INTERIM_REPORT_SECS {
            let (out_delta, in_delta) = (flow.bytes_to_server - flow.reported_out, flow.bytes_to_client - flow.reported_in);
            flow.last_report_sec = now_sec;
            if out_delta + in_delta > 0 {
                flow.reported_out = flow.bytes_to_server;
                flow.reported_in = flow.bytes_to_client;
                self.observations.push(crate::behavior::Observation::Traffic { ts_sec: now_sec, src: flow.client.0, dst: flow.server.0, dst_port: flow.server.1, bytes_out: out_delta, bytes_in: in_delta });
            }
        }
        if p.tcp_flags & TCP_RST != 0 {
            flow.reset = true;
        }
        if p.tcp_flags & TCP_FIN != 0 {
            if direction == Direction::ToServer {
                flow.fin_to_server = true;
            } else {
                flow.fin_to_client = true;
            }
        }
        // Both directions, or a reset. A single FIN leaves the flow in
        // the table so the peer's FIN and the final ACKs are still
        // counted; the idle sweep collects it either way.
        flow.closed = flow.reset || (flow.fin_to_server && flow.fin_to_client);

        let appended = {
            let half = if direction == Direction::ToServer { &mut flow.to_server } else { &mut flow.to_client };
            if p.tcp_flags & TCP_SYN != 0 {
                half.init_seq_from_syn(p.tcp_seq);
            }
            half.feed(p.tcp_seq, p.payload())
        };

        // A body with no declared length ends when the server closes, so
        // its hash can only be finished here. A FIN carries no payload and
        // never reaches the reassembly path below.
        if p.tcp_flags & TCP_FIN != 0 {
            let Flow { to_server, to_client, bits: flow_bits, .. } = &mut *flow;
            let half = if direction == Direction::ToServer { to_server } else { to_client };
            half.finish_tap_on_close();
            if let Some(f) = half.finished_file.take() {
                let f = report_file(f, sig, direction, p, now, &mut half.matched, &mut self.scratch, Some(flow_bits), out);
                if flow.file.is_none() {
                    flow.file = Some(f);
                }
            }
        }

        if appended {
            // Disjoint field borrows: `scratch`, the intel fields and
            // `flows` are separate fields of `self`, so these coexist
            // with the `flow` borrow taken above.
            let scratch = &mut self.scratch;
            let intel = &*self.intel;
            let intel_seen = &mut self.intel_seen;
            let intel_hits = &mut self.intel_hits;
            let alerts_before = out.len();
            // Collected into locals inside the borrow of one stream half,
            // then written to the flow-level fields once that borrow
            // ends — the parsers below already produce exactly these
            // values for rule matching, so recording them costs a clone
            // rather than a second parse.
            let mut seen_host = None;
            let mut seen_uri = None;
            let mut seen_sni = None;
            let mut seen_ja3 = None;
            let mut seen_ssh = None;
            let mut auth_service: Option<&'static str> = None;
            // Recorded on the flow, so a connection record says who
            // authenticated and what was reached — the two questions a
            // responder asks first about lateral movement.
            let mut seen_auth_user: Option<String> = None;
            let mut seen_rpc_interface: Option<&'static str> = None;
            let mut seen_file: Option<crate::files::FileInfo> = None;

            // Destructured rather than `&mut flow.to_server`, so the
            // compiler can see that the chosen half and the flowbits are
            // different fields and can lend both at once.
            let Flow { to_server, to_client, bits: flow_bits, head_request, .. } = &mut *flow;
            let half = if direction == Direction::ToServer { to_server } else { to_client };
            // Failures the server reported in this segment, kept as a list
            // because one segment can carry several replies.
            let mut auth_failures: Vec<&'static str> = Vec::new();

            // A body that finished hashing while this segment was being
            // reassembled.
            if let Some(f) = half.finished_file.take() {
                seen_file = Some(report_file(f, sig, direction, p, now, &mut half.matched, scratch, Some(flow_bits), out));
            }

            // Each of these three parsers now returns `None` while its
            // structure is still in flight, so the one-shot flag only
            // latches once the data behind it is complete — that's what
            // stops a split request from being parsed as a whole one
            // (see `parse_http_request` for the full account). The
            // trailing `stream_cap` arms are the necessary other half:
            // once the buffer has hit its reassembly budget it can never
            // grow again, so a structure that hasn't completed by then
            // never will, and re-parsing it on every subsequent segment
            // would be pure waste. Same shape as the SSH banner's
            // give-up below.
            if !half.scanned_http {
                if let Some(info) = parse_http_request(&half.buffer) {
                    half.scanned_http = true;
                    sig.rules.mark_app(flow_bits, "app.http");
                    seen_uri = Some(info.uri.clone());
                    seen_host = info.host.clone();
                    // The method was always parsed and never exposed. It
                    // is the single most-used buffer in a real ruleset
                    // after the URI — 8,868 of ET Open's rules inspect
                    // it, which was the largest remaining blocker when
                    // translating them.
                    check_and_alert(sig, Buffer::HttpMethod, direction, info.method.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    check_and_alert(sig, Buffer::HttpUri, direction, info.uri.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    check_and_alert(sig, Buffer::HttpHeader, direction, header_block(&info.headers).as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    if let Some(request_line) = info.headers.split("\r\n").next() {
                        check_and_alert(sig, Buffer::HttpRequestLine, direction, request_line.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    check_and_alert(sig, Buffer::HttpHeaderNames, direction, &header_names_buffer(&info.headers), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    for (buffer, name) in HEADER_VALUE_BUFFERS {
                        if let Some(v) = header_value(&info.headers, name) {
                            check_and_alert(sig, *buffer, direction, v.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        }
                    }
                    check_and_alert(sig, Buffer::HttpStart, direction, format!("{}\r\n\r\n", info.headers).as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    // The version is the last word of the request line.
                    if let Some(version) = info.headers.split("\r\n").next().and_then(|l| l.rsplit(' ').next()).filter(|v| v.starts_with("HTTP/")) {
                        check_and_alert(sig, Buffer::HttpProtocol, direction, version.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    if let Some(ua) = &info.user_agent {
                        check_and_alert(sig, Buffer::HttpUserAgent, direction, ua.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    if let Some(c) = &info.cookie {
                        check_and_alert(sig, Buffer::HttpCookie, direction, c.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    if let Some(body) = &info.body {
                        check_and_alert(sig, Buffer::HttpRequestBody, direction, body, p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        check_and_alert(sig, Buffer::FileData, direction, body, p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        // Hashing costs a pass over the body, so it is
                        // done only when a rule could use the result.
                        if sig.rules.wants_file_identity() && info.content_length.is_none() && !info.chunked {
                            if let Some(f) = crate::files::inspect(body) {
                                check_and_alert(sig, Buffer::FileMd5, direction, f.md5.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                                check_and_alert(sig, Buffer::FileSha256, direction, f.sha256.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                                if let Some(kind) = f.kind {
                                    check_and_alert(sig, Buffer::FileType, direction, kind.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                                }
                                if let Some(magic) = f.magic {
                                    check_and_alert(sig, Buffer::FileMagic, direction, magic.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                                }
                                seen_file = Some(f);
                            }
                        }
                    }
                    *head_request = info.method == "HEAD";
                    // A framed body is hashed as it streams in, so the
                    // digest covers all of it and not just what fits in
                    // the reassembly buffer. An unframed one (invalid, but
                    // seen) falls back to the buffered prefix above.
                    if sig.rules.wants_file_identity() && (info.content_length.is_some() || info.chunked) {
                        half.install_tap(info.body_offset, info.content_length, info.chunked);
                        if let Some(f) = half.finished_file.take() {
                            seen_file = Some(report_file(f, sig, direction, p, now, &mut half.matched, scratch, Some(flow_bits), out));
                        }
                    }
                    if let Some(host) = &info.host {
                        check_and_alert(sig, Buffer::HttpHost, direction, host.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        // A Host header names where the client believes it
                        // is going, which is the thing a domain feed knows
                        // about — and it is visible even when the address
                        // behind it is a shared CDN the feed cannot name.
                        if !intel.domains.is_empty() {
                            let host = host.split(':').next().unwrap_or(host);
                            if intel_alert(intel, intel_seen, Indicator::Domain(host), p, now, "HTTP host", out) {
                                *intel_hits += 1;
                            }
                        }
                    }
                } else if half.buffer.len() >= half.stream_cap {
                    half.scanned_http = true;
                }
            }
            // The other half of every HTTP exchange. ARGUS reassembled
            // this direction all along; it simply had no parser for it.
            if !half.scanned_http_resp {
                let parsed = parse_http_response(&half.buffer);
                if parsed.is_some() || half.buffer.len() >= half.stream_cap || (half.buffer.len() >= 5 && !half.buffer.starts_with(b"HTTP/")) {
                    half.scanned_http_resp = true;
                }
                if let Some(r) = parsed {
                    sig.rules.mark_app(flow_bits, "app.http");
                    let m = &mut half.matched;
                    check_and_alert(sig, Buffer::HttpStatCode, direction, r.code.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    check_and_alert(sig, Buffer::HttpStatMsg, direction, r.message.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    check_and_alert(sig, Buffer::HttpHeader, direction, header_block(&r.headers).as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    check_and_alert(sig, Buffer::HttpHeaderNames, direction, &header_names_buffer(&r.headers), p, now, m, scratch, Some(flow_bits), out);
                    for (buffer, name) in HEADER_VALUE_BUFFERS {
                        if let Some(v) = header_value(&r.headers, name) {
                            check_and_alert(sig, *buffer, direction, v.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                        }
                    }
                    check_and_alert(sig, Buffer::HttpStart, direction, format!("{}\r\n\r\n", r.headers).as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    if let Some(status_line) = r.headers.split("\r\n").next() {
                        check_and_alert(sig, Buffer::HttpResponseLine, direction, status_line.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                        if let Some(version) = status_line.split(' ').next().filter(|v| v.starts_with("HTTP/")) {
                            check_and_alert(sig, Buffer::HttpProtocol, direction, version.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                        }
                    }
                    if let Some(v) = &r.content_type {
                        check_and_alert(sig, Buffer::HttpContentType, direction, v.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    }
                    if let Some(v) = &r.server {
                        check_and_alert(sig, Buffer::HttpServer, direction, v.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    }
                    if let Some(v) = &r.location {
                        check_and_alert(sig, Buffer::HttpLocation, direction, v.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    }
                    if let Some(v) = &r.set_cookie {
                        check_and_alert(sig, Buffer::HttpCookie, direction, v.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    }
                    if let Some(body) = &r.body {
                        check_and_alert(sig, Buffer::HttpResponseBody, direction, body, p, now, m, scratch, Some(flow_bits), out);
                        check_and_alert(sig, Buffer::FileData, direction, body, p, now, m, scratch, Some(flow_bits), out);
                    }
                    // A 401 is the server refusing a credential.
                    if r.code == "401" {
                        auth_failures.push("HTTP");
                    }
                    // Only a body whose end is known is hashed. One with no
                    // length that the server will close on is the exception;
                    // anything else would swallow whatever follows it. HEAD
                    // and the bodiless statuses have headers but no body.
                    let bodiless = *head_request || r.code.starts_with('1') || r.code == "204" || r.code == "304";
                    let framed = r.content_length.is_some() || r.chunked || r.connection_close;
                    if !bodiless && framed && sig.rules.wants_file_identity() {
                        half.install_tap(r.body_offset, r.content_length, r.chunked);
                        if let Some(f) = half.finished_file.take() {
                            seen_file = Some(report_file(f, sig, direction, p, now, &mut half.matched, scratch, Some(flow_bits), out));
                        }
                    }
                }
            }

            if !half.scanned_tls {
                if let Some(info) = parse_tls_client_hello(&half.buffer) {
                    half.scanned_tls = true;
                    sig.rules.mark_app(flow_bits, "app.tls");
                    seen_sni = info.sni.clone();
                    seen_ja3 = Some(info.ja3.clone());
                    if let Some(sni) = &info.sni {
                        check_and_alert(sig, Buffer::TlsSni, direction, sni.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        if !intel.domains.is_empty() && intel_alert(intel, intel_seen, Indicator::Domain(sni), p, now, "TLS SNI", out) {
                            *intel_hits += 1;
                        }
                    }
                    check_and_alert(sig, Buffer::TlsJa3, direction, info.ja3.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    // A JA3 describes the client software rather than the
                    // destination, so it survives the implant changing
                    // address, which is the usual thing an implant does.
                    if !intel.ja3.is_empty() && intel_alert(intel, intel_seen, Indicator::Ja3(&info.ja3), p, now, "TLS client fingerprint", out) {
                        *intel_hits += 1;
                    }
                } else if half.buffer.len() >= half.stream_cap {
                    half.scanned_tls = true;
                }
            }
            // The server's chosen version and fingerprint, likewise from the
            // other half, and available even where the certificate is not.
            if direction == Direction::ToClient && !half.scanned_server_hello && sig.rules.wants_server_hello() {
                if let Some(hello) = crate::tlscert::server_hello(&half.buffer) {
                    half.scanned_server_hello = true;
                    let m = &mut half.matched;
                    check_and_alert(sig, Buffer::TlsVersion, direction, hello.version.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                    check_and_alert(sig, Buffer::TlsJa3s, direction, hello.ja3s.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                } else if half.buffer.len() >= half.stream_cap {
                    half.scanned_server_hello = true;
                }
            }
            // The server's certificate, which is on the other half of the
            // connection from the ClientHello above.
            if direction == Direction::ToClient && !half.scanned_certs && sig.rules.wants_tls_certs() {
                match crate::tlscert::scan(&half.buffer) {
                    crate::tlscert::Scan::Found(chain) => {
                        half.scanned_certs = true;
                        let m = &mut half.matched;
                        // Subject, issuer and serial are the server's own,
                        // which is the first certificate; pairing a leaf's
                        // subject with an intermediate's issuer would make
                        // rules about one certificate match another.
                        if let Some(leaf) = chain.first() {
                            check_and_alert(sig, Buffer::TlsCertSubject, direction, leaf.subject.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                            check_and_alert(sig, Buffer::TlsCertIssuer, direction, leaf.issuer.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                            check_and_alert(sig, Buffer::TlsCertSerial, direction, leaf.serial.as_bytes(), p, now, m, scratch, Some(flow_bits), out);
                        }
                        for c in &chain {
                            check_and_alert(sig, Buffer::TlsCerts, direction, &c.der, p, now, m, scratch, Some(flow_bits), out);
                        }
                    }
                    crate::tlscert::Scan::None => half.scanned_certs = true,
                    crate::tlscert::Scan::Incomplete => {
                        if half.buffer.len() >= half.stream_cap {
                            half.scanned_certs = true;
                        }
                    }
                }
            }
            if !half.scanned_rdp {
                if let Some(info) = parse_rdp_connection_request(&half.buffer) {
                    half.scanned_rdp = true;
                    sig.rules.mark_app(flow_bits, "app.rdp");
                    // An RDP cookie carries an attempted username, so a
                    // connection bearing one is a login attempt.
                    if !info.cookie.is_empty() {
                        auth_service = Some("RDP");
                    }
                    // Checked even when empty — see RdpInfo's doc comment
                    // for why that's what makes a not_literal rule here
                    // ("no recognizable cookie") meaningful.
                    check_and_alert(sig, Buffer::RdpCookie, direction, info.cookie.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                } else if half.buffer.len() >= half.stream_cap {
                    half.scanned_rdp = true;
                }
            }

            // SSH's banner and FTP/SMTP's commands are both line-based,
            // so they share one incremental line cursor (`new_lines`)
            // instead of SSH separately re-scanning the buffer from byte
            // 0 on every packet until its one-shot check succeeds, the
            // way an earlier version did — strictly more work for the
            // same result, and duplicated the line-splitting logic
            // `new_lines` already has to do anyway for FTP/SMTP.
            let new_lines = half.new_lines();
            if !half.scanned_ssh {
                if let Some(first) = new_lines.first() {
                    half.scanned_ssh = true; // only ever the connection's first line
                    if let Some(banner) = parse_ssh_banner(first) {
                        seen_ssh = Some(banner.clone());
                        sig.rules.mark_app(flow_bits, "app.ssh");
                        check_and_alert(sig, Buffer::SshVersion, direction, banner.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                } else if half.buffer.len() >= half.stream_cap {
                    half.scanned_ssh = true; // buffer full, no line terminator ever showed up
                }
            }
            for line in &new_lines {
                if direction == Direction::ToClient {
                    if let Some(service) = auth_failure_line(line, p.src_port) {
                        auth_failures.push(service);
                    }
                }
                if let Some(cmd) = parse_ftp_line(line) {
                    sig.rules.mark_app(flow_bits, "app.ftp");
                    // `USER`/`PASS` are the credential-bearing commands;
                    // counting them per service is what brute-force
                    // detection is built on. Recorded as *attempts*, since
                    // ARGUS parses commands and not server replies and so
                    // cannot see a rejection.
                    if cmd.starts_with("USER") || cmd.starts_with("PASS") {
                        auth_service = Some("FTP");
                    }
                    check_and_alert(sig, Buffer::FtpCommand, direction, cmd.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                }
                if let Some(info) = parse_smtp_line(line) {
                    sig.rules.mark_app(flow_bits, "app.smtp");
                    if info.command.starts_with("AUTH") {
                        auth_service = Some("SMTP");
                    }
                    check_and_alert(sig, Buffer::SmtpCommand, direction, info.command.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    if let Some(sender) = &info.sender {
                        check_and_alert(sig, Buffer::SmtpSender, direction, sender.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    if let Some(recipient) = &info.recipient {
                        check_and_alert(sig, Buffer::SmtpRecipient, direction, recipient.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                }
            }

            // SMB2, like FTP/SMTP, is content-sniffed universally rather
            // than port-gated — its 4-byte `\xFE SMB` signature is a
            // strong enough tell (unlike Modbus below).
            for msg in half.new_smb2_messages() {
                if let Some(info) = parse_smb2_message(&msg) {
                    sig.rules.mark_app(flow_bits, "app.smb");
                    if direction == Direction::ToClient && info.command == "SESSION_SETUP" && smb_status_is_auth_failure(info.status) {
                        auth_failures.push("SMB");
                    }
                    check_and_alert(sig, Buffer::SmbCommand, direction, info.command.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    if let Some(filename) = &info.filename {
                        check_and_alert(sig, Buffer::SmbFilename, direction, filename.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                }
            }

            // SMB1, NTLM, Kerberos, LDAP and DCERPC: the protocols a
            // lateral intrusion actually moves through, and the ones
            // that carry identities in the clear.
            //
            // Each parse is latched once it succeeds, or once the buffer
            // has reached its reassembly budget and so can never grow
            // again. Without that, every one of these would re-scan the
            // whole reassembled buffer on every arriving segment, which
            // is quadratic in the length of a connection — and an SMB
            // session is long while its interesting message is near the
            // start.
            //
            // The parse result is taken by value before any flag is set,
            // so the immutable borrow of the buffer ends before the
            // mutable borrow of the flags begins.
            //
            // Each is gated differently, and each gate is chosen the same
            // way: run the parser only where a false positive would be
            // cheap and a miss would be expensive.

            // SMB1 has the same kind of strong signature as SMB2, so it
            // is content-sniffed rather than port-gated.
            if !half.scanned_smb1 {
                let parsed = crate::enterprise::parse_smb1_message(&half.buffer);
                let give_up = parsed.is_none() && half.buffer.len() >= half.stream_cap;
                if parsed.is_some() || give_up {
                    half.scanned_smb1 = true;
                }
                if let Some(info) = parsed {
                    check_and_alert(sig, Buffer::SmbCommand, direction, info.command.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    if let Some(path) = &info.path {
                        check_and_alert(sig, Buffer::SmbShare, direction, path.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                }
            }

            // NTLM travels inside SMB, HTTP and RPC alike, so it is found
            // by its signature wherever it is embedded rather than by its
            // container.
            if !half.scanned_ntlm {
                let parsed = crate::enterprise::parse_ntlm(&half.buffer);
                let give_up = parsed.is_none() && half.buffer.len() >= half.stream_cap;
                if parsed.is_some() || give_up {
                    half.scanned_ntlm = true;
                }
                if let Some(ntlm) = parsed {
                    if let Some(user) = &ntlm.user {
                        check_and_alert(sig, Buffer::NtlmUser, direction, user.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        seen_auth_user = Some(user.clone());
                    }
                    if let Some(domain) = &ntlm.domain {
                        check_and_alert(sig, Buffer::NtlmDomain, direction, domain.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    if let Some(ws) = &ntlm.workstation {
                        check_and_alert(sig, Buffer::NtlmWorkstation, direction, ws.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    // An NTLM AUTHENTICATE is a login attempt that names
                    // its account — a strictly better signal than the
                    // command-shaped guesses the other protocols give the
                    // brute-force detector.
                    if ntlm.message == "AUTHENTICATE" {
                        auth_service = Some("NTLM");
                    }
                }
            }

            // The remaining three are port-gated: their framing is ASN.1
            // or a single version byte, neither distinctive enough to
            // content-sniff against arbitrary TCP without false positives.
            if (p.src_port == 88 || p.dst_port == 88) && !half.scanned_krb {
                let parsed = crate::enterprise::parse_kerberos(&half.buffer);
                let give_up = parsed.is_none() && half.buffer.len() >= half.stream_cap;
                if parsed.is_some() || give_up {
                    half.scanned_krb = true;
                }
                if let Some(krb) = parsed {
                    if let Some(realm) = &krb.realm {
                        check_and_alert(sig, Buffer::KerberosRealm, direction, realm.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    if let Some(client) = &krb.client {
                        check_and_alert(sig, Buffer::KerberosPrincipal, direction, client.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        seen_auth_user = Some(client.clone());
                    }
                    if let Some(service) = &krb.service {
                        check_and_alert(sig, Buffer::KerberosService, direction, service.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    if krb.message == "AS-REQ" || krb.message == "TGS-REQ" {
                        auth_service = Some("Kerberos");
                    }
                    if direction == Direction::ToClient && krb.error_code.is_some_and(crate::enterprise::kerberos_error_is_auth_failure) {
                        auth_failures.push("Kerberos");
                    }
                }
            }

            if (matches!(p.src_port, 389 | 3268) || matches!(p.dst_port, 389 | 3268)) && !half.scanned_ldap {
                let parsed = crate::enterprise::parse_ldap(&half.buffer);
                let give_up = parsed.is_none() && half.buffer.len() >= half.stream_cap;
                if parsed.is_some() || give_up {
                    half.scanned_ldap = true;
                }
                if let Some(ldap) = parsed {
                    if let Some(dn) = &ldap.dn {
                        check_and_alert(sig, Buffer::LdapDn, direction, dn.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        if ldap.operation == "bindRequest" {
                            seen_auth_user = Some(dn.clone());
                        }
                    }
                    // A simple bind puts a password on the wire, so it
                    // counts as an authentication attempt whether or not
                    // it names a DN.
                    if ldap.simple_bind {
                        auth_service = Some("LDAP");
                    }
                    // 49 is invalidCredentials.
                    if direction == Direction::ToClient && ldap.result_code == Some(49) {
                        auth_failures.push("LDAP");
                    }
                }
            }

            // The endpoint mapper, plus RPC over a named pipe, which is
            // how the interesting interfaces are actually reached.
            if (p.src_port == 135 || p.dst_port == 135 || p.src_port == 445 || p.dst_port == 445) && !half.scanned_rpc {
                let parsed = crate::enterprise::parse_dcerpc(&half.buffer);
                let give_up = parsed.is_none() && half.buffer.len() >= half.stream_cap;
                if parsed.is_some() || give_up {
                    half.scanned_rpc = true;
                }
                if let Some(rpc) = parsed {
                    if let Some(iface) = &rpc.interface {
                        check_and_alert(sig, Buffer::DcerpcInterface, direction, iface.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                    seen_rpc_interface = rpc.interface_name;
                }
            }

            // Modbus, unlike everything else here, has no distinguishing
            // signature bytes worth content-sniffing on — gated by the
            // well-known port (502) instead, on either side, so it
            // still fires however the connection happens to be sharded.
            if p.src_port == 502 || p.dst_port == 502 {
                for pdu in half.new_modbus_messages() {
                    if let Some(info) = parse_modbus_pdu(&pdu) {
                        check_and_alert(sig, Buffer::ModbusFunction, direction, info.function.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        if let Some(addr) = info.address {
                            check_and_alert(sig, Buffer::ModbusAddress, direction, addr.to_string().as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                        }
                    }
                }
            }

            // DNP3: same port-gating reasoning as Modbus, on its own
            // well-known port (20000) — see `new_dnp3_frames`.
            if p.src_port == 20000 || p.dst_port == 20000 {
                for frame in half.new_dnp3_frames() {
                    if let Some(info) = parse_dnp3_message(&frame) {
                        check_and_alert(sig, Buffer::Dnp3Function, direction, info.function.as_bytes(), p, now, &mut half.matched, scratch, Some(flow_bits), out);
                    }
                }
            }

            // Re-run raw payload matching against the *whole reassembled
            // buffer* on every new segment, not just the newest packet in
            // isolation — this is what actually defeats an attacker
            // splitting a signature across two packets.
            check_stream_and_alert(sig, direction, &half.buffer, &mut half.payload_scan, p, now, &mut half.matched, scratch, Some(flow_bits), out);

            // The stream-half borrow ends here, so the flow-level record
            // fields can be filled in. First value wins for each: a
            // connection's first request is the one that characterises
            // it, and these are one-shot parses anyway.
            if flow.http_uri.is_none() {
                flow.http_uri = seen_uri;
            }
            if flow.http_host.is_none() {
                flow.http_host = seen_host;
            }
            if flow.tls_sni.is_none() {
                flow.tls_sni = seen_sni;
            }
            if flow.tls_ja3.is_none() {
                flow.tls_ja3 = seen_ja3;
            }
            if flow.ssh_version.is_none() {
                flow.ssh_version = seen_ssh;
            }
            // The two questions a responder asks first about lateral
            // movement — who authenticated, and what did they reach —
            // answered in the connection record rather than only in an
            // alert, so they are there whether or not a rule fired.
            if flow.auth_user.is_none() {
                flow.auth_user = seen_auth_user;
            }
            if flow.rpc_interface.is_none() {
                flow.rpc_interface = seen_rpc_interface;
            }
            if flow.file.is_none() {
                flow.file = seen_file;
            }
            flow.alerts += (out.len() - alerts_before) as u32;

            if self.observe_enabled {
                // The failing packet came from the server, so the attempt
                // was made by the *destination* of this packet.
                for service in auth_failures {
                    self.observations.push(crate::behavior::Observation::AuthFailure {
                        ts_sec: now_sec,
                        src: p.dst,
                        dst: p.src,
                        dst_port: p.src_port,
                        service,
                    });
                }
            }
            if let (true, Some(service)) = (self.observe_enabled, auth_service) {
                self.observations.push(crate::behavior::Observation::AuthAttempt {
                    ts_sec: now_sec,
                    src: p.src,
                    dst: p.dst,
                    dst_port: p.dst_port,
                    service,
                });
            }
        }

        // A finished connection is retired immediately rather than left
        // for the next sweep.
        //
        // Waiting cost real detections. The sweep is time-gated to once
        // per capture second, so a flow that closed in the *same* second
        // as the last sweep sat in the table until either another second
        // of traffic arrived on its shard or the process shut down. On a
        // replay, or on a quiet shard, that meant its record and its
        // behavioural observation arrived late or not at all — a 5MB
        // lopsided upload produced a flow record and no exfiltration
        // alert, because the observation only appeared during shutdown.
        if self.flows.get(&key).is_some_and(|f| f.closed) {
            if let Some(f) = self.flows.remove(&key) {
                let record = self.record_flows;
                let observe = self.observe_enabled;
                let completed = &mut self.completed;
                let observations = &mut self.observations;
                Self::retire(&f, now_sec, false, record, observe, completed, observations, out);
            }
        }

        // Gated on both a packet count and the clock. Count alone meant
        // a quiet worker held closed and idle flows until another 4096
        // packets happened to arrive, which on a low-traffic shard could
        // be a very long time.
        self.since_sweep += 1;
        if self.since_sweep >= 4096 || now_sec > self.last_swept_at {
            self.since_sweep = 0;
            self.last_swept_at = now_sec;
            self.expire(now_sec, FLOW_IDLE_TIMEOUT_SECS, out);
        }
    }
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

/// How long a datagram conversation may be idle before it's considered
/// over. UDP and ICMP have no close, so a timeout is the only end there
/// is — much shorter than TCP's, because without a handshake there is no
/// such thing as an established-but-quiet datagram session.
const DATAGRAM_IDLE_TIMEOUT_SECS: i64 = 60;

struct DatagramFlow {
    client: Endpoint,
    server: Endpoint,
    proto: &'static str,
    vlan_id: u16,
    first_ts: SystemTime,
    last_ts: SystemTime,
    last_seen: i64,
    pkts_to_server: u64,
    pkts_to_client: u64,
    bytes_to_server: u64,
    bytes_to_client: u64,
}

/// Connection records for UDP and ICMP.
///
/// `FlowTable` is TCP-only by assertion — it exists to reassemble
/// streams, and datagram protocols have none — so everything that wasn't
/// TCP produced no flow record at all. That left a conspicuous hole in
/// the connection log: DNS, NTP, SNMP, ICMP and every UDP-based
/// application were invisible to it, which is most of the traffic on a
/// typical segment and a large share of what matters after an incident.
///
/// Accounting only: no reassembly, no protocol buffers, no parsing. The
/// point is the record, and the record is who talked to whom, how much,
/// for how long.
pub struct DatagramFlows {
    flows: FxHashMap<FlowKey, DatagramFlow>,
    max_flows: usize,
    record: bool,
    observe_enabled: bool,
    completed: Vec<FlowRecord>,
    observations: Vec<crate::behavior::Observation>,
    last_swept: i64,
    refused: u64,
}

impl DatagramFlows {
    pub fn new(max_flows: usize) -> Self {
        DatagramFlows {
            flows: FxHashMap::default(),
            max_flows: max_flows.max(1),
            record: false,
            observe_enabled: false,
            completed: Vec::new(),
            observations: Vec::new(),
            last_swept: 0,
            refused: 0,
        }
    }

    pub fn enable_flow_records(&mut self) {
        self.record = true;
    }

    pub fn enable_observations(&mut self) {
        self.observe_enabled = true;
    }

    /// Nothing is built unless something is draining it — the same
    /// opt-in as `FlowTable`, for the same reason: a producer with no
    /// consumer is an unbounded buffer.
    fn enabled(&self) -> bool {
        self.record || self.observe_enabled
    }

    pub fn take_completed(&mut self, out: &mut Vec<FlowRecord>) {
        out.append(&mut self.completed);
    }

    pub fn take_observations(&mut self, out: &mut Vec<crate::behavior::Observation>) {
        out.append(&mut self.observations);
    }

    pub fn flows_refused(&self) -> u64 {
        self.refused
    }

    pub fn tracked_flows(&self) -> usize {
        self.flows.len()
    }

    pub fn observe(&mut self, p: &Packet, now_sec: i64) {
        if !self.enabled() {
            return;
        }
        let key = FlowKey::new(p.src, p.src_port, p.dst, p.dst_port);
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            self.refused += 1;
            return;
        }
        let f = self.flows.entry(key).or_insert_with(|| DatagramFlow {
            client: Endpoint(p.src, p.src_port),
            server: Endpoint(p.dst, p.dst_port),
            proto: p.proto_name(),
            vlan_id: p.vlan_id,
            first_ts: p.ts,
            last_ts: p.ts,
            last_seen: now_sec,
            pkts_to_server: 0,
            pkts_to_client: 0,
            bytes_to_server: 0,
            bytes_to_client: 0,
        });
        f.last_seen = now_sec;
        f.last_ts = p.ts;
        if p.src == f.client.0 && p.src_port == f.client.1 {
            f.pkts_to_server += 1;
            f.bytes_to_server += p.frame_len as u64;
        } else {
            f.pkts_to_client += 1;
            f.bytes_to_client += p.frame_len as u64;
        }

        if now_sec > self.last_swept {
            self.last_swept = now_sec;
            self.expire(now_sec);
        }
    }

    fn expire(&mut self, now_sec: i64) {
        let cutoff = now_sec - DATAGRAM_IDLE_TIMEOUT_SECS;
        let completed = &mut self.completed;
        let observations = &mut self.observations;
        let record = self.record;
        let observe = self.observe_enabled;
        self.flows.retain(|_, f| {
            if f.last_seen > cutoff {
                return true;
            }
            if record {
                completed.push(f.to_record());
            }
            if observe {
                observations.push(crate::behavior::Observation::Flow {
                    ts_sec: f.first_ts.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(now_sec),
                    src: f.client.0,
                    dst: f.server.0,
                    dst_port: f.server.1,
                    bytes_out: f.bytes_to_server,
                    bytes_in: f.bytes_to_client,
                    answered: f.pkts_to_client > 0,
                });
            }
            false
        });
    }

    /// Flushes everything still tracked, for shutdown.
    pub fn flush(&mut self, out: &mut Vec<FlowRecord>) {
        // See `FlowTable::flush_open_flows`: observations have to be
        // emitted here too, or the last conversation on each key is
        // missing from behavioural analysis.
        let record = self.record;
        let observe = self.observe_enabled;
        for (_, f) in self.flows.drain() {
            if observe {
                self.observations.push(crate::behavior::Observation::Flow {
                    ts_sec: f.first_ts.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(f.last_seen),
                    src: f.client.0,
                    dst: f.server.0,
                    dst_port: f.server.1,
                    bytes_out: f.bytes_to_server,
                    bytes_in: f.bytes_to_client,
                    answered: f.pkts_to_client > 0,
                });
            }
            if record {
                out.push(f.to_record());
            }
        }
        out.append(&mut self.completed);
    }
}

impl DatagramFlow {
    fn to_record(&self) -> FlowRecord {
        FlowRecord {
            start: self.first_ts,
            end: self.last_ts,
            src: self.client.0,
            src_port: self.client.1,
            dst: self.server.0,
            dst_port: self.server.1,
            proto: self.proto,
            vlan_id: self.vlan_id,
            pkts_to_server: self.pkts_to_server,
            pkts_to_client: self.pkts_to_client,
            bytes_to_server: self.bytes_to_server,
            bytes_to_client: self.bytes_to_client,
            // Datagram protocols have no flags and no close, so the
            // state is simply that the conversation went quiet. Saying
            // "closed" would imply a teardown that never happened.
            flags_to_server: 0,
            flags_to_client: 0,
            state: "expired",
            http_host: None,
            http_uri: None,
            tls_sni: None,
            tls_ja3: None,
            ssh_version: None,
            // A datagram conversation has no reassembled stream, so
            // none of the stream-derived identities can exist for one.
            auth_user: None,
            rpc_interface: None,
            file_md5: None,
            file_sha256: None,
            file_type: None,
            file_size: None,
            alerts: 0,
        }
    }
}

/// Working memory for one worker's rule matching, reused across every
/// buffer of every packet so that matching allocates nothing.
#[derive(Default)]
pub struct ScanScratch {
    pub hits: Vec<RuleHit>,
    pub matcher: MatchScratch,
}

/// Checks one buffer, alerts on any rule match not already reported for
/// this flow-direction (`matched` dedup set), and records new matches so
/// a signature that stays present as the buffer keeps growing (e.g. a
/// payload match early in a long-lived connection) only alerts once.
/// Note this means a repeated FTP/SMTP command that matches the *same*
/// rule twice in one session only alerts the first time — a deliberate
/// scope limitation to keep the dedup model uniform across every buffer
/// type, not a bug.
#[allow(clippy::too_many_arguments)]
/// Checks a finished file's identity against the rules that ask for it.
#[allow(clippy::too_many_arguments)]
fn report_file(
    f: crate::files::FileInfo,
    sig: &SignatureEngine,
    direction: Direction,
    p: &Packet,
    now: SystemTime,
    matched: &mut FxHashSet<String>,
    scratch: &mut ScanScratch,
    mut bits: Option<&mut FlowBits>,
    out: &mut Vec<Alert>,
) -> crate::files::FileInfo {
    check_and_alert(sig, Buffer::FileMd5, direction, f.md5.as_bytes(), p, now, matched, scratch, bits.as_deref_mut(), out);
    check_and_alert(sig, Buffer::FileSha256, direction, f.sha256.as_bytes(), p, now, matched, scratch, bits.as_deref_mut(), out);
    if let Some(kind) = f.kind {
        check_and_alert(sig, Buffer::FileType, direction, kind.as_bytes(), p, now, matched, scratch, bits.as_deref_mut(), out);
    }
    if let Some(magic) = f.magic {
        check_and_alert(sig, Buffer::FileMagic, direction, magic.as_bytes(), p, now, matched, scratch, bits, out);
    }
    f
}

/// As [`check_and_alert`], for the raw stream.
#[allow(clippy::too_many_arguments)]
fn check_stream_and_alert(
    sig: &SignatureEngine,
    direction: Direction,
    data: &[u8],
    scan: &mut crate::rules::StreamScan,
    p: &Packet,
    now: SystemTime,
    matched: &mut FxHashSet<String>,
    scratch: &mut ScanScratch,
    bits: Option<&mut FlowBits>,
    out: &mut Vec<Alert>,
) {
    scratch.hits.clear();
    sig.check_stream_into(p, direction, data, scan, &mut scratch.matcher, bits, &mut scratch.hits);
    for hit in scratch.hits.drain(..) {
        let key = format!("{}|{}", hit.sid, hit.name);
        if matched.insert(key) {
            out.push(signature_alert(p, Buffer::Payload, &hit, now));
        }
    }
}

fn check_and_alert(
    sig: &SignatureEngine,
    buffer: Buffer,
    direction: Direction,
    data: &[u8],
    p: &Packet,
    now: SystemTime,
    matched: &mut FxHashSet<String>,
    scratch: &mut ScanScratch,
    bits: Option<&mut FlowBits>,
    out: &mut Vec<Alert>,
) {
    scratch.hits.clear();
    sig.check_buffer_into(p, buffer, direction, data, &mut scratch.matcher, bits, &mut scratch.hits);
    for hit in scratch.hits.drain(..) {
        // Keyed on name and sid together: two rules may share a name
        // (nothing enforces uniqueness), and deduping on name alone would
        // silently drop one of them — the same coarse-key mistake as the
        // suppression bugs in `run_alert_writer`.
        let key = format!("{}|{}", hit.sid, hit.name);
        if matched.insert(key) {
            out.push(signature_alert(p, buffer, &hit, now));
        }
    }
}

// =======================================================================
// Tests
// =======================================================================

/// Shared helpers for the test modules below.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Writes `contents` to a uniquely-named temp file and loads it as a
    /// [`RuleSet`], cleaning the file up afterwards.
    ///
    /// The name mixes the process id with a monotonic counter. Two
    /// earlier copies of this helper (one per test module) instead keyed
    /// the name on `contents.len()`, which meant any two tests whose
    /// rule text happened to be the same number of bytes raced on one
    /// shared path: whichever finished first deleted the file out from
    /// under the other, which then failed to load it. That made the
    /// suite fail intermittently — a different one to four tests per run
    /// — under `cargo test`'s default thread-per-core parallelism, while
    /// passing every time under `--test-threads=1`, which is the most
    /// misleading shape a test bug can have: it looks like flaky
    /// *product* behaviour under concurrency, which is exactly the class
    /// of bug this project's whole sharding design exists to avoid, so
    /// it costs real time to rule out. A counter also makes the helper
    /// correct by construction rather than by luck, since nothing about
    /// it now depends on the *content* of the rules being unique.
    pub(super) fn ruleset_from(contents: &str) -> RuleSet {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("argus_test_rules_{}_{}.txt", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        let rs = RuleSet::load(path.to_str().unwrap()).unwrap();
        fs::remove_file(&path).ok();
        rs
    }

    /// A complete, well-formed TLS ClientHello record carrying `hostname`
    /// in an SNI extension, plus a supported-groups extension so the JA3
    /// inputs aren't degenerate.
    ///
    /// Shared rather than rebuilt per module specifically so the
    /// truncation tests can assert against the *same* bytes the
    /// happy-path test parses — the bug these exist for was precisely
    /// that a prefix of this record parsed as though it were the whole
    /// thing.
    pub(crate) fn client_hello(hostname: &[u8]) -> Vec<u8> {
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id_len
        let ciphers: [u16; 2] = [0x1301, 0xc02f];
        hs_body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            hs_body.extend_from_slice(&c.to_be_bytes());
        }
        hs_body.push(1); // compression_methods_len
        hs_body.push(0); // null compression

        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((hostname.len() + 3) as u16).to_be_bytes());
        sni_data.push(0); // name_type: host_name
        sni_data.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(hostname);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);
        let groups: [u16; 2] = [0x001d, 0x0017];
        extensions.extend_from_slice(&0x000au16.to_be_bytes()); // supported_groups
        extensions.extend_from_slice(&(((groups.len() * 2) + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for g in groups {
            extensions.extend_from_slice(&g.to_be_bytes());
        }

        hs_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&extensions);

        let mut handshake = vec![0x01];
        let len = hs_body.len() as u32;
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&hs_body);

        let mut record = vec![0x16];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// How many trailing bytes of [`client_hello`]'s output make up the
    /// extensions block (its 2-byte length prefix included) — i.e. the
    /// split point at which a truncated ClientHello used to parse
    /// "successfully" with no SNI and a JA3 computed from an empty
    /// extension list.
    pub(super) fn client_hello_extensions_len(hostname: &[u8]) -> usize {
        // server_name: 4 bytes of ext header + list length (2) + type (1)
        // + name length (2) + the name itself.
        let sni_ext = 4 + 2 + 1 + 2 + hostname.len();
        let groups_ext = 4 + 2 + 4; // ext header + list length + two groups
        2 + sni_ext + groups_ext
    }

    /// A TPKT-framed X.224 Connection Request, optionally carrying a
    /// `Cookie:` routing token. Replaces two byte-identical copies of
    /// this builder that had drifted into separate test modules.
    pub(super) fn rdp_connection_request(cookie: Option<&str>) -> Vec<u8> {
        let mut variable = Vec::new();
        if let Some(c) = cookie {
            variable.extend_from_slice(format!("Cookie: {}\r\n", c).as_bytes());
        }
        let li = (6 + variable.len()) as u8;
        let mut x224 = vec![li, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00];
        x224.extend_from_slice(&variable);
        let tpkt_len = (4 + x224.len()) as u16;
        let mut tpkt = vec![3, 0, (tpkt_len >> 8) as u8, tpkt_len as u8];
        tpkt.extend_from_slice(&x224);
        tpkt
    }
}

#[cfg(test)]
mod rules_tests {
    use super::*;
    use super::test_support::ruleset_from;

    #[test]
    fn literal_rule_matches_and_respects_buffer() {
        let rs = ruleset_from("sqli|http.uri|to_server|literal|UNION SELECT\n");
        let mut out = Vec::new();
        rs.check_names(Buffer::HttpUri, Direction::ToServer, b"/search?q=UNION SELECT * FROM users", &mut out);
        assert_eq!(out, vec!["sqli".to_string()]);

        out.clear();
        rs.check_names(Buffer::Payload, Direction::ToServer, b"UNION SELECT", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn direction_scoping_is_enforced() {
        let rs = ruleset_from("resp-only|payload|to_client|literal|malware-signature\n");
        let mut out = Vec::new();
        rs.check_names(Buffer::Payload, Direction::ToServer, b"malware-signature", &mut out);
        assert!(out.is_empty(), "should not match on the wrong direction");
        out.clear();
        rs.check_names(Buffer::Payload, Direction::ToClient, b"malware-signature", &mut out);
        assert_eq!(out, vec!["resp-only".to_string()]);
    }

    #[test]
    fn any_direction_literal_matches_both_ways() {
        let rs = ruleset_from("either-way|payload|any|literal|badstring\n");
        for dir in [Direction::ToServer, Direction::ToClient] {
            let mut out = Vec::new();
            rs.check_names(Buffer::Payload, dir, b"badstring", &mut out);
            assert_eq!(out, vec!["either-way".to_string()], "direction {:?}", dir);
        }
    }

    #[test]
    fn querying_with_direction_any_finds_rules_of_every_declared_direction() {
        // Regression test for a real, previously-undetected bug: every
        // UDP-based detection path in main.rs (raw payload, DNS, TFTP,
        // SNMP — none of them go through FlowTable, so none of them
        // ever compute a real to-server/to-client direction) calls
        // `check` with `Direction::Any` directly. But `Direction::Any`
        // was never a real storage key — a rule declared `direction:
        // any` gets expanded into separate ToServer and ToClient
        // entries at load time, so a lookup literally keyed on `(buffer,
        // Any)` matched nothing, regardless of how the rule was
        // declared. This went undetected because every TCP-based
        // protocol (which does compute a real direction via FlowTable)
        // never exercised this path — it took an actual live capture
        // with a real payload rule to catch it, not code review or a
        // unit test that only checked `RuleSet` with concrete
        // directions. This test checks all three declaration forms
        // against a Direction::Any query, the exact shape of the bug.
        let rs = ruleset_from(
            "declared-any|payload|any|literal|needle-any\n\
             declared-to-server|payload|to_server|literal|needle-server\n\
             declared-to-client|payload|to_client|literal|needle-client\n",
        );

        let mut out = Vec::new();
        rs.check_names(Buffer::Payload, Direction::Any, b"needle-any", &mut out);
        assert_eq!(out, vec!["declared-any".to_string()], "an any-declared rule must be found by an Any query, not just once loaded");

        out.clear();
        rs.check_names(Buffer::Payload, Direction::Any, b"needle-server", &mut out);
        assert_eq!(out, vec!["declared-to-server".to_string()], "a to_server rule must still be found by a caller that doesn't track direction");

        out.clear();
        rs.check_names(Buffer::Payload, Direction::Any, b"needle-client", &mut out);
        assert_eq!(out, vec!["declared-to-client".to_string()], "a to_client rule must still be found by a caller that doesn't track direction");
    }

    #[test]
    fn any_declared_rule_is_not_reported_twice_by_an_any_query() {
        // The flip side of the fix above: an any-declared rule is
        // physically stored as two entries (ToServer and ToClient), so
        // checking both and naively concatenating would report it
        // twice for one matching packet.
        let rs = ruleset_from("either-way|payload|any|literal|badstring\n");
        let mut out = Vec::new();
        rs.check_names(Buffer::Payload, Direction::Any, b"badstring", &mut out);
        assert_eq!(out, vec!["either-way".to_string()], "should appear exactly once, not once per stored direction");
    }

    #[test]
    fn regex_rule_matches() {
        let rs = ruleset_from("path-traversal|http.uri|any|regex|\\.\\./\\.\\./\n");
        let mut out = Vec::new();
        rs.check_names(Buffer::HttpUri, Direction::ToServer, b"/files?path=../../etc/passwd", &mut out);
        assert_eq!(out, vec!["path-traversal".to_string()]);
    }

    #[test]
    fn regex_pattern_may_contain_pipe_characters() {
        let rs = ruleset_from("alt-hosts|http.host|any|regex|^(evil1|evil2)\\.example\\.com$\n");
        let mut out = Vec::new();
        rs.check_names(Buffer::HttpHost, Direction::ToServer, b"evil2.example.com", &mut out);
        assert_eq!(out, vec!["alt-hosts".to_string()]);
    }

    #[test]
    fn not_literal_fires_only_when_pattern_absent() {
        let rs = ruleset_from("missing-host-header|http.host|to_server|not_literal|internal.corp\n");
        let mut out = Vec::new();
        rs.check_names(Buffer::HttpHost, Direction::ToServer, b"internal.corp", &mut out);
        assert!(out.is_empty(), "should not fire when the pattern IS present");

        out.clear();
        rs.check_names(Buffer::HttpHost, Direction::ToServer, b"some-other-host.com", &mut out);
        assert_eq!(out, vec!["missing-host-header".to_string()]);
    }

    #[test]
    fn negation_on_payload_buffer_is_rejected_at_load_time() {
        let path = std::env::temp_dir().join(format!("argus_test_rules_negpayload_{}.txt", std::process::id()));
        fs::write(&path, "bogus|payload|any|not_literal|whatever\n").unwrap();
        let result = RuleSet::load(path.to_str().unwrap());
        fs::remove_file(&path).ok();
        assert!(result.is_err(), "negation on the raw payload buffer should be rejected at load time, not silently ignored");
    }

    #[test]
    fn ja3_blocklist_style_literal_match() {
        let rs = ruleset_from("known-bad-ja3|tls.ja3|to_server|literal|e7d705a3286e19ea42f587b344ee6865\n");
        let mut out = Vec::new();
        rs.check_names(Buffer::TlsJa3, Direction::ToServer, b"e7d705a3286e19ea42f587b344ee6865", &mut out);
        assert_eq!(out, vec!["known-bad-ja3".to_string()]);
    }

    #[test]
    fn new_buffer_types_are_accepted_in_rule_files() {
        let rs = ruleset_from(
            "ftp-rule|ftp.command|to_server|literal|RETR secret.txt\n\
             ssh-rule|ssh.version|any|regex|SSH-1\\.\n\
             smtp-rule|smtp.sender|to_server|literal|spammer@evil.example\n",
        );
        let mut out = Vec::new();
        rs.check_names(Buffer::FtpCommand, Direction::ToServer, b"RETR secret.txt", &mut out);
        assert_eq!(out, vec!["ftp-rule".to_string()]);

        out.clear();
        rs.check_names(Buffer::SshVersion, Direction::ToServer, b"SSH-1.5-old-client", &mut out);
        assert_eq!(out, vec!["ssh-rule".to_string()]);

        out.clear();
        rs.check_names(Buffer::SmtpSender, Direction::ToServer, b"spammer@evil.example", &mut out);
        assert_eq!(out, vec!["smtp-rule".to_string()]);
    }
}

#[cfg(test)]
mod protocols_tests {
    use super::*;
    use super::test_support::{client_hello, client_hello_extensions_len, rdp_connection_request};

    #[test]
    fn ja3_matches_independent_reference_no_grease() {
        let version = 771;
        let ciphers = [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53];
        let extensions = [0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 21];
        let curves = [29, 23, 24];
        let point_formats = [0];
        let ja3 = compute_ja3(version, &ciphers, &extensions, &curves, &point_formats);
        assert_eq!(ja3, "1d714db2228763eab228fc28ce7f8e4f");
    }

    #[test]
    fn ja3_filters_grease_values_matching_reference() {
        let version = 771;
        let ciphers = [2570, 4865, 4866, 4867, 49195, 49199];
        let extensions = [2570, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 21, 6682];
        let curves = [2570, 29, 23, 24];
        let point_formats = [0];
        let ja3 = compute_ja3(version, &ciphers, &extensions, &curves, &point_formats);
        assert_eq!(ja3, "a3bac184d63dba98fedfefeb9cb6cffc");
    }

    #[test]
    fn is_grease_identifies_known_grease_values() {
        for v in [0x0a0a, 0x1a1a, 0x2a2a, 0xfafa] {
            assert!(is_grease(v), "{:#06x} should be GREASE", v);
        }
        for v in [4865u16, 0, 23, 443] {
            assert!(!is_grease(v), "{:#06x} should not be GREASE", v);
        }
    }

    #[test]
    fn parses_sni_from_synthetic_client_hello() {
        let record = client_hello(b"example.com");
        let info = parse_tls_client_hello(&record).expect("should parse");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.ja3.len(), 32);
    }

    #[test]
    fn parses_http_request_line_and_host() {
        let req = b"GET /admin/../../etc/passwd HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n";
        let info = parse_http_request(req).expect("should parse");
        assert_eq!(info.method, "GET");
        assert_eq!(info.uri, "/admin/../../etc/passwd");
        assert_eq!(info.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn rejects_non_http_binary_as_not_http() {
        let junk = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02];
        assert!(parse_http_request(&junk).is_none());
    }

    /// No prefix of a request may parse — only the whole thing.
    ///
    /// The specific regression: `GET /cgi-bin/../` used to return
    /// `Some(uri: "/cgi-bin/../")`, because splitting on CRLF in a
    /// buffer with no CRLF yet hands back the entire buffer as a
    /// finished request line. `FlowTable` latched its one-shot
    /// `scanned_http` flag on that and never re-read the buffer, so
    /// splitting a request across TCP segments defeated every
    /// `http.uri` and `http.host` rule. Looping over *every* prefix
    /// rather than a hand-picked one matters: the equivalent RDP test
    /// happened to split at a byte offset where the partial parse
    /// errored out cleanly, which is exactly why this class of bug
    /// survived there too.
    #[test]
    fn http_request_does_not_parse_until_its_header_block_is_complete() {
        let req = b"GET /admin/../../etc/passwd HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n";
        for n in 0..req.len() {
            assert!(parse_http_request(&req[..n]).is_none(), "a {}-byte prefix must not parse as a complete request", n);
        }
        let info = parse_http_request(req).expect("the complete request should parse");
        assert_eq!(info.uri, "/admin/../../etc/passwd");
        assert_eq!(info.host.as_deref(), Some("example.com"));
    }

    /// Same property for TLS. The prefix that matters most is the one
    /// ending just before the extensions block: that one used to return
    /// `Some` with `sni: None` and a JA3 computed from an empty
    /// extension list — silently *wrong* rather than absent, for a value
    /// whose whole purpose is fingerprinting clients. It's covered by
    /// the loop, and asserted separately below to keep the intent
    /// explicit.
    #[test]
    fn tls_client_hello_does_not_parse_until_the_whole_record_arrives() {
        let hello = client_hello(b"example.com");
        for n in 0..hello.len() {
            assert!(parse_tls_client_hello(&hello[..n]).is_none(), "a {}-byte prefix must not parse as a complete ClientHello", n);
        }

        let before_extensions = hello.len() - client_hello_extensions_len(b"example.com");
        assert!(
            parse_tls_client_hello(&hello[..before_extensions]).is_none(),
            "a ClientHello truncated right before its extensions must not yield a JA3 at all"
        );

        let info = parse_tls_client_hello(&hello).expect("the complete record should parse");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.ja3.len(), 32);
    }

    /// And for RDP, where the discarded length field was `_tpkt_len`.
    #[test]
    fn rdp_connection_request_does_not_parse_until_the_tpkt_length_is_satisfied() {
        let msg = rdp_connection_request(Some("mstshash=Administrator"));
        for n in 0..msg.len() {
            assert!(parse_rdp_connection_request(&msg[..n]).is_none(), "a {}-byte prefix must not parse as a complete CR", n);
        }
        assert_eq!(parse_rdp_connection_request(&msg).expect("complete CR should parse").cookie, "mstshash=Administrator");
    }

    /// The cookie is bounded by TPKT's declared length, so a client that
    /// pipelines more data straight after the connection request can't
    /// have those bytes absorbed into the cookie it reports.
    ///
    /// Deliberately built the way round that actually distinguishes the
    /// two behaviours: the CR itself carries *no* cookie, and the
    /// pipelined bytes do. Reading to the end of the buffer, as an
    /// earlier version did, therefore reports a cookie this connection
    /// request never sent — worse than a truncated one, because it
    /// attributes an attacker-controlled value to the wrong message. The
    /// obvious-looking version of this test, a real cookie followed by a
    /// pipelined one, passes either way: the old code stopped at the
    /// first CRLF and so never reached the second cookie. Same trap as
    /// the RDP split test one module down — a fixture that looks like it
    /// covers the case while quietly not exercising it.
    #[test]
    fn rdp_cookie_stops_at_the_tpkt_declared_length() {
        let mut msg = rdp_connection_request(None);
        msg.extend_from_slice(b"Cookie: mstshash=pipelined-should-not-be-seen\r\n");
        let info = parse_rdp_connection_request(&msg).expect("should parse the cookieless CR");
        assert_eq!(info.cookie, "", "a cookie from pipelined data must not be attributed to this CR");
    }

    #[test]
    fn parses_dns_query_name() {
        let mut msg = vec![0u8; 12];
        msg[4..6].copy_from_slice(&1u16.to_be_bytes());
        msg.push(3);
        msg.extend_from_slice(b"www");
        msg.push(7);
        msg.extend_from_slice(b"example");
        msg.push(3);
        msg.extend_from_slice(b"com");
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());

        assert_eq!(parse_dns_query(&msg).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn dns_query_with_no_questions_returns_none() {
        let msg = vec![0u8; 12];
        assert!(parse_dns_query(&msg).is_none());
    }

    #[test]
    fn parses_ftp_commands() {
        assert_eq!(parse_ftp_line("USER anonymous").as_deref(), Some("USER anonymous"));
        assert_eq!(parse_ftp_line("RETR secret.txt").as_deref(), Some("RETR secret.txt"));
        assert!(parse_ftp_line("this is not an ftp command").is_none());
    }

    #[test]
    fn parses_ssh_banner() {
        assert_eq!(parse_ssh_banner("SSH-2.0-OpenSSH_8.9").as_deref(), Some("SSH-2.0-OpenSSH_8.9"));
        assert!(parse_ssh_banner("not an ssh banner").is_none());
    }

    #[test]
    fn parses_smtp_mail_from_and_rcpt_to() {
        let mail = parse_smtp_line("MAIL FROM:<attacker@evil.example>").expect("should parse");
        assert_eq!(mail.sender.as_deref(), Some("attacker@evil.example"));
        assert!(mail.recipient.is_none());

        let rcpt = parse_smtp_line("RCPT TO:<victim@example.com>").expect("should parse");
        assert_eq!(rcpt.recipient.as_deref(), Some("victim@example.com"));

        let helo = parse_smtp_line("EHLO mail.example.com").expect("should parse");
        assert!(helo.sender.is_none() && helo.recipient.is_none());

        assert!(parse_smtp_line("not smtp at all").is_none());
    }

    fn build_smb2_message(command: u16, body: &[u8]) -> Vec<u8> {
        let mut msg = vec![0u8; 64];
        msg[0..4].copy_from_slice(b"\xFESMB");
        msg[4..6].copy_from_slice(&64u16.to_le_bytes());
        msg[12..14].copy_from_slice(&command.to_le_bytes());
        msg.extend_from_slice(body);
        msg
    }

    fn build_smb2_create_body(filename: &str) -> Vec<u8> {
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        let name_utf16: Vec<u8> = filename.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_offset: u16 = 64 + 56; // right after the header + this fixed body
        body[44..46].copy_from_slice(&name_offset.to_le_bytes());
        body[46..48].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        body.extend_from_slice(&name_utf16);
        body
    }

    #[test]
    fn parses_smb2_create_command_and_filename() {
        let msg = build_smb2_message(0x0005, &build_smb2_create_body("secret.txt"));
        let info = parse_smb2_message(&msg).expect("should parse");
        assert_eq!(info.command, "CREATE");
        assert_eq!(info.filename.as_deref(), Some("secret.txt"));
    }

    #[test]
    fn parses_smb2_non_create_command_without_filename() {
        let msg = build_smb2_message(0x0003, &[]); // TREE_CONNECT
        let info = parse_smb2_message(&msg).expect("should parse");
        assert_eq!(info.command, "TREE_CONNECT");
        assert!(info.filename.is_none());
    }

    #[test]
    fn unrecognized_smb2_command_code_reports_unknown_not_none() {
        let msg = build_smb2_message(0x00FF, &[]);
        let info = parse_smb2_message(&msg).expect("should still parse a well-formed header");
        assert_eq!(info.command, "UNKNOWN");
    }

    #[test]
    fn rejects_non_smb2_signature() {
        let mut msg = vec![0u8; 64];
        msg[0..4].copy_from_slice(b"\xFFSMB"); // SMB1 signature, deliberately not supported
        assert!(parse_smb2_message(&msg).is_none());
    }

    #[test]
    fn rejects_short_smb2_message() {
        assert!(parse_smb2_message(&[0xFE, b'S', b'M', b'B']).is_none());
    }

    #[test]
    fn parses_modbus_read_holding_registers() {
        let pdu = [0x03, 0x00, 0x10, 0x00, 0x02]; // function 3, start addr 0x0010, count 2
        let info = parse_modbus_pdu(&pdu).expect("should parse");
        assert_eq!(info.function, "READ_HOLDING_REGISTERS");
        assert!(info.address.is_none(), "read-type codes don't carry an address in this position");
    }

    #[test]
    fn parses_modbus_write_single_register_with_address() {
        let pdu = [0x06, 0x00, 0x2A, 0x00, 0x64]; // function 6, addr 0x002A, value 0x0064
        let info = parse_modbus_pdu(&pdu).expect("should parse");
        assert_eq!(info.function, "WRITE_SINGLE_REGISTER");
        assert_eq!(info.address, Some(0x002A));
    }

    #[test]
    fn modbus_exception_response_high_bit_is_cleared_before_lookup() {
        let pdu = [0x86, 0x02]; // exception response to function 6 (WRITE_SINGLE_REGISTER)
        let info = parse_modbus_pdu(&pdu).expect("should parse");
        assert_eq!(info.function, "WRITE_SINGLE_REGISTER");
    }

    #[test]
    fn unrecognized_modbus_function_code_reports_hex_not_none() {
        let pdu = [0x2B]; // a real Modbus code (device identification) not in our lookup table
        let info = parse_modbus_pdu(&pdu).expect("should parse");
        assert_eq!(info.function, "0x2B");
    }

    #[test]
    fn parses_rdp_cookie_from_connection_request() {
        let msg = rdp_connection_request(Some("mstshash=Administrator"));
        let info = parse_rdp_connection_request(&msg).expect("should parse");
        assert_eq!(info.cookie, "mstshash=Administrator");
    }

    #[test]
    fn rdp_connection_request_without_a_cookie_gives_empty_string_not_none() {
        let msg = rdp_connection_request(None);
        let info = parse_rdp_connection_request(&msg).expect("should still parse a valid CR with no cookie");
        assert_eq!(info.cookie, "", "empty, not absent — this is what makes a not_literal rule against rdp.cookie meaningful");
    }

    #[test]
    fn rejects_wrong_tpkt_version() {
        let mut msg = rdp_connection_request(Some("mstshash=x"));
        msg[0] = 4; // TPKT version must be 3
        assert!(parse_rdp_connection_request(&msg).is_none());
    }

    #[test]
    fn rejects_non_connection_request_x224_code() {
        let mut msg = rdp_connection_request(Some("mstshash=x"));
        msg[5] = 0xD0; // not a CR TPDU (high nibble must be 0xE)
        assert!(parse_rdp_connection_request(&msg).is_none());
    }

    fn build_tftp_request(opcode: u16, filename: &str, mode: &str) -> Vec<u8> {
        let mut msg = opcode.to_be_bytes().to_vec();
        msg.extend_from_slice(filename.as_bytes());
        msg.push(0);
        msg.extend_from_slice(mode.as_bytes());
        msg.push(0);
        msg
    }

    #[test]
    fn parses_tftp_read_request_with_filename() {
        let msg = build_tftp_request(1, "boot.img", "octet");
        let info = parse_tftp_packet(&msg).expect("should parse");
        assert_eq!(info.opcode, "RRQ");
        assert_eq!(info.filename.as_deref(), Some("boot.img"));
    }

    #[test]
    fn parses_tftp_write_request() {
        let msg = build_tftp_request(2, "config.bin", "netascii");
        let info = parse_tftp_packet(&msg).expect("should parse");
        assert_eq!(info.opcode, "WRQ");
        assert_eq!(info.filename.as_deref(), Some("config.bin"));
    }

    #[test]
    fn tftp_data_packet_has_no_filename() {
        let mut msg = 3u16.to_be_bytes().to_vec(); // DATA
        msg.extend_from_slice(&1u16.to_be_bytes()); // block number
        msg.extend_from_slice(b"some file bytes");
        let info = parse_tftp_packet(&msg).expect("should parse");
        assert_eq!(info.opcode, "DATA");
        assert!(info.filename.is_none());
    }

    #[test]
    fn unrecognized_tftp_opcode_returns_none() {
        let msg = 99u16.to_be_bytes();
        assert!(parse_tftp_packet(&msg).is_none());
    }

    fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 128 {
            out.push(value.len() as u8);
        } else {
            out.push(0x82); // long form: 2 length bytes follow
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(value);
        out
    }

    fn build_snmp_message(version: u8, community: &str) -> Vec<u8> {
        let mut inner = ber_tlv(0x02, &[version]);
        inner.extend_from_slice(&ber_tlv(0x04, community.as_bytes()));
        ber_tlv(0x30, &inner)
    }

    #[test]
    fn parses_snmp_v1_community_string() {
        let msg = build_snmp_message(0, "public");
        assert_eq!(parse_snmp_community(&msg).as_deref(), Some("public"));
    }

    #[test]
    fn parses_snmp_v2c_community_string() {
        let msg = build_snmp_message(1, "private");
        assert_eq!(parse_snmp_community(&msg).as_deref(), Some("private"));
    }

    #[test]
    fn snmp_v3_has_no_plaintext_community_and_is_rejected() {
        let msg = build_snmp_message(3, "irrelevant"); // v3 wouldn't really encode this way, but the version check alone should reject it
        assert!(parse_snmp_community(&msg).is_none());
    }

    #[test]
    fn snmp_long_form_ber_length_is_handled() {
        // Forces the 2-byte long-form length path in read_ber_tlv (community >= 128 bytes).
        let long_community = "x".repeat(200);
        let msg = build_snmp_message(0, &long_community);
        assert_eq!(parse_snmp_community(&msg).as_deref(), Some(long_community.as_str()));
    }

    #[test]
    fn malformed_snmp_message_does_not_panic() {
        assert!(parse_snmp_community(&[]).is_none());
        assert!(parse_snmp_community(&[0x30]).is_none());
        assert!(parse_snmp_community(&[0x30, 0x05, 0x02]).is_none());
    }

    /// Builds a single, complete raw DNP3 data-link frame (sync through
    /// the last block's CRC) carrying `user_data` as its application
    /// payload, correctly de-interleaving a CRC-16 placeholder (value
    /// doesn't matter — `parse_dnp3_message` never validates it) after
    /// every 16 bytes, exactly matching real DNP3 framing.
    fn build_dnp3_frame(user_data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x05, 0x64, (5 + user_data.len()) as u8];
        frame.push(0xC4); // control byte, arbitrary
        frame.extend_from_slice(&[0x01, 0x00]); // destination address
        frame.extend_from_slice(&[0x02, 0x00]); // source address
        frame.extend_from_slice(&[0, 0]); // header CRC placeholder (unvalidated)
        for chunk in user_data.chunks(16) {
            frame.extend_from_slice(chunk);
            frame.extend_from_slice(&[0, 0]); // this block's CRC placeholder
        }
        frame
    }

    #[test]
    fn parses_dnp3_operate_function_code() {
        let user_data = [0xC0, 0xC0, 0x04]; // transport hdr, app control, function = OPERATE
        let frame = build_dnp3_frame(&user_data);
        let info = parse_dnp3_message(&frame).expect("should parse");
        assert_eq!(info.function, "OPERATE");
    }

    #[test]
    fn unrecognized_dnp3_function_code_reports_unknown_not_none() {
        let user_data = [0xC0, 0xC0, 0xFF]; // not a real IEEE 1815 function code
        let frame = build_dnp3_frame(&user_data);
        let info = parse_dnp3_message(&frame).expect("should still parse a well-formed frame");
        assert_eq!(info.function, "UNKNOWN");
    }

    #[test]
    fn rejects_non_dnp3_sync_pattern() {
        let mut frame = build_dnp3_frame(&[0xC0, 0xC0, 0x04]);
        frame[0] = 0x00; // corrupt the sync bytes
        assert!(parse_dnp3_message(&frame).is_none());
    }

    #[test]
    fn rejects_short_dnp3_frame() {
        assert!(parse_dnp3_message(&[0x05, 0x64, 0x08]).is_none());
    }

    #[test]
    fn dnp3_function_code_survives_crc_block_deinterleaving() {
        // The function code sits at user-data offset 2, safely within
        // the *first* 16-byte block regardless of how much data follows
        // — so this alone wouldn't catch a bug in how later blocks get
        // de-interleaved. What actually proves the multi-block math is
        // right: pad user_data past 16 bytes (forcing a second CRC
        // block) and confirm the parser still gets the right answer,
        // and — the real proof — that build_dnp3_frame's own chunking
        // (used by every DNP3 test, including the cursor-level ones
        // below) round-trips through `parse_dnp3_message`'s
        // de-interleaving without corruption for a frame that
        // genuinely spans multiple blocks.
        let mut user_data = vec![0xC0, 0xC0, 0x04]; // OPERATE
        user_data.extend(std::iter::repeat(0xABu8).take(30)); // push well past one 16-byte block
        let frame = build_dnp3_frame(&user_data);
        let info = parse_dnp3_message(&frame).expect("should parse");
        assert_eq!(info.function, "OPERATE");
    }
}

#[cfg(test)]
mod signature_and_anomaly_tests {
    use super::*;
    use crate::output::Format;
    use crate::packet::{build_tcp_frame, parse_ethernet_frame, TCP_PSH};

    fn parse(frame: &[u8]) -> Packet {
        let mut pkt = Packet::default();
        assert!(parse_ethernet_frame(frame, &mut pkt));
        pkt
    }

    fn udp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Packet {
        let mut pkt = parse(&build_tcp_frame(src, dst, src_port, dst_port, 1, 0, &[]));
        pkt.protocol = crate::packet::PROTO_UDP;
        pkt
    }

    /// Config for the detection tests.
    ///
    /// Sets `alert_min_interval_secs: 0`, i.e. no rate limiting,
    /// deliberately: production gates repeated `PACKET_FLOOD` and
    /// `PORT_SCAN` alerts to at most one per second per source so a
    /// flood doesn't flood the alert channel too, but these tests feed
    /// every packet at the same synthetic timestamp and are checking
    /// *whether a threshold is crossed*, not how often crossing it is
    /// reported. Leaving the gate on would make them pass or fail on the
    /// rate limiter instead of on the detection logic they name, which
    /// is a worse test even when it's a green one. Rate limiting gets
    /// its own test below.
    fn test_cfg(window_secs: u64, packet_rate_pps: u32, port_scan_limit: usize) -> AnomalyConfig {
        AnomalyConfig {
            window: Duration::from_secs(window_secs),
            packet_rate_pps,
            port_scan_limit,
            alert_min_interval_secs: 0,
            ..AnomalyConfig::default()
        }
    }

    #[test]
    fn blacklist_alerts_on_matching_source() {
        let se = SignatureEngine { blacklist: [IpAddr::V4([10, 0, 0, 99])].into_iter().collect(), rules: RuleSet::empty() };
        let pkt = parse(&build_tcp_frame([10, 0, 0, 99], [10, 0, 0, 1], 4444, 80, 1, TCP_ACK, &[]));
        let mut alerts = Vec::new();
        se.inspect_blacklist(&pkt, SystemTime::now(), &mut alerts);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, "BLACKLIST_IP");
    }

    #[test]
    fn blacklist_accepts_ipv6_entries() {
        let addr = IpAddr::parse("2001:db8::1").unwrap();
        let se = SignatureEngine { blacklist: [addr].into_iter().collect(), rules: RuleSet::empty() };
        let mut pkt = Packet::default();
        pkt.src = addr;
        pkt.dst = IpAddr::V4([10, 0, 0, 1]);
        let mut alerts = Vec::new();
        se.inspect_blacklist(&pkt, SystemTime::now(), &mut alerts);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn port_scan_detected_over_threshold() {
        let mut ae = AnomalyEngine::new(test_cfg(5, 100_000, 5));
        let now = SystemTime::now();
        let mut last_alerts = Vec::new();
        for port in 1u16..=10 {
            let pkt = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, port, 1, TCP_SYN, &[]));
            last_alerts.clear();
            ae.observe(&pkt, now, &mut last_alerts);
        }
        assert!(last_alerts.iter().any(|a| a.category == "PORT_SCAN"));
    }

    #[test]
    fn ordinary_multi_service_traffic_does_not_trigger_port_scan() {
        let mut ae = AnomalyEngine::new(test_cfg(10, 100_000, 20));
        let now = SystemTime::now();
        let mut alerts = Vec::new();

        for host in 0u8..30 {
            for port in [53u16, 443] {
                let pkt = parse(&build_tcp_frame([192, 168, 0, 112], [10, 0, host, 1], 51234, port, 1, TCP_ACK, &[]));
                alerts.clear();
                ae.observe(&pkt, now, &mut alerts);
                assert!(!alerts.iter().any(|a| a.category == "PORT_SCAN"), "false positive at host {} port {}", host, port);
            }
        }

        let mut last_alerts = Vec::new();
        for port in 1u16..=25 {
            let pkt = parse(&build_tcp_frame([192, 168, 0, 112], [10, 0, 99, 1], 51234, port, 1, TCP_SYN, &[]));
            last_alerts.clear();
            ae.observe(&pkt, now, &mut last_alerts);
        }
        assert!(last_alerts.iter().any(|a| a.category == "PORT_SCAN"), "a real single-target scan should still be detected");
    }

    #[test]
    fn dns_style_udp_replies_do_not_trigger_port_scan() {
        // The scenario that originally got UDP excluded entirely: a
        // resolver replying to a client's own randomized query ports.
        // Now that UDP scan detection is reply-aware, this must first
        // see the OUTBOUND queries (so the tracker has something to
        // match replies against), then the inbound replies, and never
        // fire.
        let mut ae = AnomalyEngine::new(test_cfg(10, 100_000, 20));
        let now = SystemTime::now();
        let mut alerts = Vec::new();
        let client = [192, 168, 0, 112];
        let resolver = [194, 168, 4, 100];

        for client_port in 40000u16..40040 {
            // Outbound query: client -> resolver:53.
            let query = udp(client, resolver, client_port, 53);
            alerts.clear();
            ae.observe(&query, now, &mut alerts);
            // Inbound reply: resolver:53 -> client (same port pairing).
            let reply = udp(resolver, client, 53, client_port);
            alerts.clear();
            ae.observe(&reply, now, &mut alerts);
            assert!(!alerts.iter().any(|a| a.category == "PORT_SCAN"), "reply on port {} falsely triggered PORT_SCAN", client_port);
        }
    }

    #[test]
    fn unsolicited_udp_probes_are_detected_as_a_scan() {
        // No matching outbound query ever happened here — this is what
        // an actual UDP port scan against a victim looks like on the
        // wire, and must still be caught.
        let mut ae = AnomalyEngine::new(test_cfg(10, 100_000, 20));
        let now = SystemTime::now();
        let scanner = [203, 0, 113, 50];
        let victim = [192, 168, 0, 112];
        let mut last_alerts = Vec::new();
        for port in 1u16..=25 {
            let probe = udp(scanner, victim, 40000, port);
            last_alerts.clear();
            ae.observe(&probe, now, &mut last_alerts);
        }
        assert!(last_alerts.iter().any(|a| a.category == "PORT_SCAN"), "unsolicited UDP probes across 25 ports should be detected");
    }

    #[test]
    fn tcp_and_udp_port_scans_against_the_same_destination_are_tracked_independently() {
        // Regression test for a real bug found in the field: a TCP scan
        // (via Test-NetConnection) followed by a UDP scan against the
        // *same* destination shared one port-number-keyed map, so TCP
        // port 21 and UDP port 21 collided as "the same port already
        // seen" — the UDP scan's very first packet already inherited
        // enough leftover entries from the earlier TCP scan to look like
        // it had crossed the threshold immediately.
        let mut ae = AnomalyEngine::new(test_cfg(10, 100_000, 20));
        let now = SystemTime::now();
        let scanner = [192, 168, 0, 112];
        let victim = [45, 33, 32, 156];

        // First, a TCP scan that crosses the threshold (ports 1..=25).
        let mut alerts = Vec::new();
        for port in 1u16..=25 {
            let syn = parse(&build_tcp_frame(scanner, victim, 51234, port, 1, TCP_SYN, &[]));
            alerts.clear();
            ae.observe(&syn, now, &mut alerts);
        }
        assert!(alerts.iter().any(|a| a.category == "PORT_SCAN" && a.proto == "TCP"));

        // Now a UDP scan against the identical destination, starting
        // from port 1 again. The very first UDP packet must NOT already
        // report anywhere near the threshold just because TCP port 1 was
        // seen earlier — it should build up fresh, independently.
        let first_udp = udp(scanner, victim, 40000, 1);
        alerts.clear();
        ae.observe(&first_udp, now, &mut alerts);
        assert!(alerts.is_empty(), "a single UDP probe must not immediately trigger PORT_SCAN just because TCP ports were seen earlier");

        // It should still correctly detect a genuine UDP scan on its own
        // merits once enough distinct UDP ports are actually touched.
        let mut last_alerts = Vec::new();
        for port in 2u16..=25 {
            let probe = udp(scanner, victim, 40000, port);
            last_alerts.clear();
            ae.observe(&probe, now, &mut last_alerts);
        }
        assert!(last_alerts.iter().any(|a| a.category == "PORT_SCAN" && a.proto == "UDP"), "a real UDP scan should still be detected on its own");
    }

    /// The bound that matters most, and the one that didn't exist: a
    /// flood from endlessly-varying spoofed source addresses must not
    /// grow the source table without limit.
    ///
    /// The old sweep kept anything seen within `window`, so during such
    /// a flood every entry was fresh whenever it ran and nothing was
    /// ever released — the table grew with the attack, and the sensor
    /// built to notice the flood was what the flood killed.
    #[test]
    fn the_source_table_is_bounded_under_a_spoofed_source_flood() {
        let cfg = AnomalyConfig { max_sources: 64, alert_min_interval_secs: 0, ..AnomalyConfig::default() };
        let mut ae = AnomalyEngine::new(cfg);
        let now = SystemTime::now();
        let mut alerts = Vec::new();

        // 5000 distinct sources, all at the same instant, so recency can
        // never release any of them.
        for i in 0..5000u32 {
            let octets = i.to_be_bytes();
            let mut p = Packet::default();
            p.src = IpAddr::V4([10, octets[1], octets[2], octets[3]]);
            p.dst = IpAddr::V4([192, 168, 0, 1]);
            p.protocol = PROTO_TCP;
            p.tcp_flags = TCP_SYN;
            p.dst_port = 80;
            ae.observe(&p, now, &mut alerts);
        }

        assert!(ae.tracked_sources() <= 64, "tracked {} sources against a cap of 64", ae.tracked_sources());
        assert!(ae.limit_stats().sources_refused > 0, "refusals should be counted, not silent");
    }

    /// The other dimension: one source touching endless destinations.
    #[test]
    fn destinations_per_source_are_bounded() {
        let cfg = AnomalyConfig { max_destinations_per_source: 32, alert_min_interval_secs: 0, ..AnomalyConfig::default() };
        let mut ae = AnomalyEngine::new(cfg);
        let now = SystemTime::now();
        let mut alerts = Vec::new();
        for i in 0..2000u32 {
            let octets = i.to_be_bytes();
            let mut p = Packet::default();
            p.src = IpAddr::V4([10, 0, 0, 9]);
            p.dst = IpAddr::V4([172, octets[1], octets[2], octets[3]]);
            p.protocol = PROTO_TCP;
            p.tcp_flags = TCP_SYN;
            p.dst_port = 443;
            ae.observe(&p, now, &mut alerts);
        }
        assert!(ae.limit_stats().destinations_refused > 0);
    }

    /// Rate limiting, tested on its own rather than left to distort the
    /// detection tests: one alert per source per interval, however many
    /// packets cross the threshold.
    #[test]
    fn flood_alerts_are_rate_limited_at_the_source() {
        let cfg = AnomalyConfig {
            window: Duration::from_secs(10),
            packet_rate_pps: 5,
            port_scan_limit: 100_000,
            alert_min_interval_secs: 1,
            ..AnomalyConfig::default()
        };
        let mut ae = AnomalyEngine::new(cfg);
        let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut alerts = Vec::new();

        let mut p = Packet::default();
        p.src = IpAddr::V4([10, 0, 0, 5]);
        p.dst = IpAddr::V4([10, 0, 0, 1]);
        p.protocol = PROTO_UDP;
        p.dst_port = 9999;

        // 200 packets inside one second, all well past the limit of 5.
        for _ in 0..200 {
            ae.observe(&p, base, &mut alerts);
        }
        let floods = alerts.iter().filter(|a| a.category == "PACKET_FLOOD").count();
        assert_eq!(floods, 1, "expected one alert for the whole second, got {}", floods);

        // A second later, the same condition is worth reporting again.
        alerts.clear();
        ae.observe(&p, base + Duration::from_secs(2), &mut alerts);
        assert_eq!(alerts.iter().filter(|a| a.category == "PACKET_FLOOD").count(), 1, "a continuing flood should still be reported periodically");
    }

    #[test]
    fn port_tracking_is_pruned_at_most_once_per_second_even_under_a_fast_burst() {
        // Regression test for a real performance issue found via the
        // benchmark suite, not the wire: an earlier version pruned
        // ports_seen unconditionally on *every* packet (the fix for the
        // test above), which is correct but has genuinely unbounded
        // per-packet cost — a fast, wide scan (thousands of distinct
        // ports within the same second, exactly the traffic this code
        // exists to catch) made retain()'s O(map size) cost scale with
        // the size of the attack itself. This sends 5,000 SYNs to
        // distinct ports all at the identical `now`, simulating a fast
        // burst within one second, and just needs to complete quickly
        // and behave correctly — not itself a precise timing assertion
        // (timing assertions are flaky), but the fact that a debug-mode
        // run of this test doesn't take noticeably long is itself a
        // sanity check on the fix.
        let mut ae = AnomalyEngine::new(test_cfg(10, 100_000, 20));
        let now = SystemTime::now();
        let scanner = [203, 0, 113, 77];
        let victim = [192, 168, 0, 112];
        let mut last_alerts = Vec::new();
        for port in 1u16..5000 {
            let probe = parse(&build_tcp_frame(scanner, victim, 51234, port, 1, TCP_SYN, &[]));
            last_alerts.clear();
            ae.observe(&probe, now, &mut last_alerts);
        }
        assert!(last_alerts.iter().any(|a| a.category == "PORT_SCAN"), "a genuinely fast, wide scan should still be detected");
    }

    #[test]
    fn stale_port_entries_are_still_pruned_once_real_time_passes() {
        // The other half of the same fix: time-gating pruning (instead
        // of pruning every packet) must not silently bring back the
        // *original* problem this was meant to solve — a low-volume
        // source's stale entries lingering forever. A few ports touched
        // once, long enough ago to be outside the window, must not
        // still count once enough wall-clock time has genuinely passed.
        let mut ae = AnomalyEngine::new(test_cfg(10, 100_000, 5));
        let t0 = SystemTime::now();
        let src = [10, 0, 0, 9];
        let dst = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        // Three ports touched at t0 — under the limit, no alert.
        for port in 1u16..=3 {
            let syn = parse(&build_tcp_frame(src, dst, 51234, port, 1, TCP_SYN, &[]));
            alerts.clear();
            ae.observe(&syn, t0, &mut alerts);
        }
        assert!(alerts.is_empty());

        // Long after the window has elapsed, three *more* ports arrive.
        // If the three from t0 were still (wrongly) counted, this would
        // total 6 and cross the limit of 5 — it must not, since those
        // three are long stale by now.
        let t1 = t0 + Duration::from_secs(60);
        let mut last_alerts = Vec::new();
        for port in 4u16..=6 {
            let syn = parse(&build_tcp_frame(src, dst, 51234, port, 1, TCP_SYN, &[]));
            last_alerts.clear();
            ae.observe(&syn, t1, &mut last_alerts);
        }
        assert!(!last_alerts.iter().any(|a| a.category == "PORT_SCAN"), "stale entries from 60s ago should not still be counted");
    }

    #[test]
    fn packet_flood_detected_over_threshold() {
        // 1 packet/s over a 5s window is a limit of 5; 10 packets crosses it.
        let mut ae = AnomalyEngine::new(test_cfg(5, 1, 100_000));
        let now = SystemTime::now();
        let pkt = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, 80, 1, TCP_ACK, &[]));
        let mut last_alerts = Vec::new();
        for _ in 0..10 {
            last_alerts.clear();
            ae.observe(&pkt, now, &mut last_alerts);
        }
        assert!(last_alerts.iter().any(|a| a.category == "PACKET_FLOOD"));
    }

    /// With the aggregator in charge, a worker reports how many packets it
    /// saw each second instead of judging them, and says nothing itself.
    #[test]
    fn a_worker_reports_per_second_counts_when_the_aggregator_judges_the_flood() {
        let mut ae = AnomalyEngine::new(AnomalyConfig { flood_via_observations: true, ..test_cfg(5, 1, 100_000) });
        let pkt = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, 80, 1, TCP_ACK, &[]));
        let (t0, t1) = (UNIX_EPOCH + Duration::from_secs(1_700_000_000), UNIX_EPOCH + Duration::from_secs(1_700_000_001));
        let mut alerts = Vec::new();
        for _ in 0..10 {
            ae.observe(&pkt, t0, &mut alerts);
        }
        for _ in 0..4 {
            ae.observe(&pkt, t1, &mut alerts);
        }
        assert!(alerts.iter().all(|a| a.category != "PACKET_FLOOD"), "the worker does not judge it");
        let mut obs = Vec::new();
        ae.take_observations(&mut obs);
        let counts: Vec<u32> = obs.iter().filter_map(|o| if let crate::behavior::Observation::Volume { packets, .. } = o { Some(*packets) } else { None }).collect();
        assert_eq!(counts, [10], "the finished second, and not the one still counting");
        // Shutdown reports what is left.
        ae.flush_volume(true);
        obs.clear();
        ae.take_observations(&mut obs);
        assert!(obs.iter().any(|o| matches!(o, crate::behavior::Observation::Volume { packets: 4, .. })));
    }

    /// A burst that then stops is the thing most worth reporting, and no
    /// later packet from that source will ever push it out.
    #[test]
    fn a_burst_from_a_source_that_then_goes_quiet_is_still_reported() {
        let mut ae = AnomalyEngine::new(AnomalyConfig { flood_via_observations: true, ..test_cfg(5, 1, 100_000) });
        let burst = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, 80, 1, TCP_ACK, &[]));
        let other = parse(&build_tcp_frame([10, 0, 0, 9], [10, 0, 0, 1], 51234, 80, 1, TCP_ACK, &[]));
        let mut alerts = Vec::new();
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for _ in 0..50 {
            ae.observe(&burst, t0, &mut alerts);
        }
        // Another source's traffic, later, moves time on. The first never speaks again.
        ae.observe(&other, t0 + Duration::from_secs(2), &mut alerts);
        let mut obs = Vec::new();
        ae.take_observations(&mut obs);
        assert!(obs.iter().any(|o| matches!(o, crate::behavior::Observation::Volume { packets: 50, .. })), "{:?}", obs.len());
    }

    /// The regression this rename exists for: a CDN download that is fine
    /// at the default window must stay fine when the window is widened
    /// for scan detection.
    ///
    /// The threshold used to be a count per window, so `-window 60s` cut
    /// the effective flood rate from 500pps to 83pps — below an ordinary
    /// video stream — and a live run produced eight false `PACKET_FLOOD`
    /// alerts against Meta and Fastly addresses. Same traffic, same
    /// threshold, two windows: neither may alert.
    #[test]
    fn flood_sensitivity_does_not_change_when_the_window_widens() {
        // 200pps sustained: a large download, not a flood, against the
        // default 500pps threshold.
        let feed = |window_secs: u64| {
            let cfg = AnomalyConfig { window: Duration::from_secs(window_secs), alert_min_interval_secs: 0, ..AnomalyConfig::default() };
            let mut ae = AnomalyEngine::new(cfg);
            let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
            let pkt = parse(&build_tcp_frame([151, 101, 1, 1], [10, 0, 0, 5], 443, 51234, 1, TCP_ACK, &[]));
            let mut alerts = Vec::new();
            for sec in 0..120 {
                for _ in 0..200 {
                    ae.observe(&pkt, base + Duration::from_secs(sec), &mut alerts);
                }
            }
            alerts.iter().filter(|a| a.category == "PACKET_FLOOD").count()
        };
        assert_eq!(feed(10), 0, "200pps is under the 500pps default");
        assert_eq!(feed(60), 0, "and widening the window must not change that");
    }

    #[test]
    fn signature_alert_message_includes_buffer_name() {
        let pkt = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 1234, 80, 1, TCP_PSH, &[]));
        let hit = RuleHit { name: "test-rule".to_string(), sid: 0, severity: Severity::High };
        let a = signature_alert(&pkt, Buffer::HttpUri, &hit, SystemTime::now());
        assert!(a.message.contains("http.uri"));
        assert!(a.message.contains("test-rule"));

        // A v2 rule's identity has to survive into the alert, since that
        // is the whole point of having it: the sid is what a downstream
        // consumer correlates and tunes on.
        let v2 = RuleHit { name: "scoped-rule".to_string(), sid: 1000042, severity: Severity::Low };
        let a2 = signature_alert(&pkt, Buffer::HttpUri, &v2, SystemTime::now());
        assert_eq!(a2.sid, 1000042);
        assert_eq!(a2.severity, Severity::Low, "a rule's own severity must win over the old hardcoded HIGH");
        assert!(a2.message.contains("sid 1000042"));
        assert!(crate::output::render_alert(&a2, &Tags::none(), Format::Json).contains("\"sid\":1000042"));
    }

    #[test]
    fn alert_json_output_is_well_formed_and_parses_back() {
        let a = Alert {
            timestamp: SystemTime::now(),
            severity: Severity::High,
            category: "SIGNATURE_MATCH",
            src: IpAddr::V4([10, 0, 0, 5]),
            dst: IpAddr::parse("2001:db8::1").unwrap(),
            proto: "TCP",
            port: 80,
            message: "payload matched signature \"weird \\ quote\" test".to_string(),
            sid: 0,
        };
        let json = crate::output::render_alert(&a, &Tags::none(), Format::Json);
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"src\":\"10.0.0.5\""));
        assert!(json.contains("\"dst\":\"2001:db8::1\""));
        assert!(json.contains("\"severity\":\"HIGH\""));
        // The embedded quote and backslash must be escaped, not break the JSON.
        assert!(json.contains("\\\"weird \\\\ quote\\\""));
    }

    /// The alert writer's suppression state must not grow without bound.
    ///
    /// It was the last unbounded table in the pipeline, and it was missed
    /// because the memory-bounds work went through the *workers* — where
    /// detection state lives — while the writer is a separate thread with
    /// state of its own. Keys are heap `String`s per distinct alerting
    /// tuple, so a wide scan is tens of thousands and a spoofed-source
    /// flood is unbounded, and nothing pruned them — not even entries
    /// older than the very window they implement.
    #[test]
    fn suppression_state_is_bounded_and_stale_entries_are_pruned() {
        let (tx, rx) = crossbeam_channel::unbounded::<Alert>();
        let handle = std::thread::spawn(move || run_alert_writer(rx, Output::single(Box::new(std::io::sink()), Format::Json), AlertWriterConfig::plain(Duration::from_secs(1))));

        let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // 40_000 alerts, each from a different source, spread over enough
        // capture time that pruning runs repeatedly. Every key goes stale
        // long before the run ends.
        for i in 0..40_000u32 {
            let o = i.to_be_bytes();
            tx.send(Alert {
                timestamp: base + Duration::from_secs((i / 500) as u64),
                severity: Severity::Medium,
                category: "PORT_SCAN",
                src: IpAddr::V4([10, o[1], o[2], o[3]]),
                dst: IpAddr::V4([192, 168, 0, 1]),
                proto: "TCP",
                port: 80,
                message: "synthetic".to_string(),
                sid: 0,
            })
            .unwrap();
        }
        drop(tx);
        let stats = handle.join().unwrap();

        // All distinct, so all emitted; the point is that the writer
        // didn't retain 40_000 keys to get there.
        assert_eq!(stats.emitted, 40_000);
        assert_eq!(stats.suppressed, 0);
        assert_eq!(stats.suppression_resets, 0, "pruning stale keys should have been enough; no reset needed");
    }

    /// The same capture must give the same alerts.
    ///
    /// Alerts reach the writer from many worker threads in scheduling
    /// order. Here a later alert from another worker (stamped a hundred
    /// seconds ahead) arrives *between* two alerts for the same event.
    /// Pruning on that arrival used to discard the first alert's entry, so
    /// the second was reported as though it were new: a suppression
    /// outcome that depended on thread timing rather than on the alerts.
    #[test]
    fn a_late_alert_from_another_worker_does_not_defeat_suppression() {
        fn alert_at(src: u8, secs: u64) -> Alert {
            Alert {
                timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs),
                severity: Severity::Low,
                category: "SIGNATURE_MATCH",
                src: IpAddr::V4([10, 0, 0, src]),
                dst: IpAddr::V4([192, 168, 0, 1]),
                proto: "TCP",
                port: 80,
                message: "same rule".to_string(),
                sid: 1,
            }
        }
        let (tx, rx) = crossbeam_channel::unbounded::<Alert>();
        let handle = std::thread::spawn(move || run_alert_writer(rx, Output::single(Box::new(std::io::sink()), Format::Json), AlertWriterConfig::plain(Duration::from_secs(15))));
        tx.send(alert_at(1, 0)).unwrap();
        tx.send(alert_at(2, 100)).unwrap(); // another worker, far ahead
        tx.send(alert_at(1, 1)).unwrap(); // a second report of the first event
        drop(tx);
        let stats = handle.join().unwrap();
        assert_eq!(stats.emitted, 2, "the first event once, and the unrelated alert");
        assert_eq!(stats.suppressed, 1, "the repeat is within the window of the first, whatever arrived between");
    }

    /// And when the *live* key space really is larger than the cap, the
    /// table resets rather than growing — which costs duplicate alerts,
    /// not missed detections, and says so in the stats.
    #[test]
    fn an_oversized_live_key_space_resets_suppression_instead_of_growing() {
        let (tx, rx) = crossbeam_channel::unbounded::<Alert>();
        let handle = std::thread::spawn(move || run_alert_writer(rx, Output::single(Box::new(std::io::sink()), Format::Json), AlertWriterConfig::plain(Duration::from_secs(3600))));

        let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // A one-hour suppression window means nothing goes stale, so the
        // cap is the only thing that can bound this.
        for i in 0..200_000u32 {
            let o = i.to_be_bytes();
            tx.send(Alert {
                timestamp: base + Duration::from_secs((i / 1000) as u64),
                severity: Severity::Medium,
                category: "PORT_SCAN",
                src: IpAddr::V4([10, o[1], o[2], o[3]]),
                dst: IpAddr::V4([192, 168, 0, 1]),
                proto: "TCP",
                port: 80,
                message: "synthetic".to_string(),
                sid: 0,
            })
            .unwrap();
        }
        drop(tx);
        let stats = handle.join().unwrap();
        assert!(stats.suppression_resets > 0, "the cap should have engaged");
    }

    #[test]
    fn alert_writer_suppresses_duplicate_bursts() {
        use std::io::{Cursor, Write};
        use std::sync::{Arc, Mutex};

        let (tx, rx) = crossbeam_channel::unbounded();
        let buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let buf2 = Arc::clone(&buf);

        struct CountingWriter(Arc<Mutex<Cursor<Vec<u8>>>>);
        impl Write for CountingWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let handle = std::thread::spawn(move || {
            run_alert_writer(rx, Output::single(Box::new(CountingWriter(buf2)), Format::Text), AlertWriterConfig::plain(Duration::from_secs(60)));
        });

        let a = Alert {
            timestamp: SystemTime::now(),
            severity: Severity::High,
            category: "TEST",
            src: IpAddr::V4([1, 2, 3, 4]),
            dst: IpAddr::V4([0, 0, 0, 0]),
            proto: "TCP",
            port: 0,
            message: "x".to_string(),
            sid: 0,
        };
        tx.send(a.clone()).unwrap();
        tx.send(a).unwrap();
        drop(tx);
        handle.join().unwrap();

        let b = buf.lock().unwrap();
        let text = String::from_utf8_lossy(b.get_ref());
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn alerts_of_different_protocols_are_not_mutually_suppressed() {
        // Regression test for a real bug found in the field: a UDP
        // PORT_SCAN alert followed shortly by a TCP PORT_SCAN alert from
        // the same source — two genuinely different events — used to
        // collide under one suppression key (category+src, no protocol),
        // so the second alert was silently swallowed as if it were a
        // duplicate of the first. Both must appear.
        use std::io::{Cursor, Write};
        use std::sync::{Arc, Mutex};

        let (tx, rx) = crossbeam_channel::unbounded();
        let buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let buf2 = Arc::clone(&buf);

        struct CountingWriter(Arc<Mutex<Cursor<Vec<u8>>>>);
        impl Write for CountingWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let handle = std::thread::spawn(move || {
            run_alert_writer(rx, Output::single(Box::new(CountingWriter(buf2)), Format::Text), AlertWriterConfig::plain(Duration::from_secs(60)));
        });

        let base = Alert {
            timestamp: SystemTime::now(),
            severity: Severity::Medium,
            category: "PORT_SCAN",
            src: IpAddr::V4([192, 168, 0, 112]),
            dst: IpAddr::V4([45, 33, 32, 156]),
            proto: "UDP",
            port: 21,
            message: "25 distinct UDP ports touched on this destination in the last 10s (limit 20)".to_string(),
            sid: 0,
        };
        let mut tcp_alert = base.clone();
        tcp_alert.proto = "TCP";
        tcp_alert.message = "21 distinct TCP ports touched on this destination in the last 10s (limit 20)".to_string();

        tx.send(base).unwrap();
        tx.send(tcp_alert).unwrap();
        drop(tx);
        handle.join().unwrap();

        let b = buf.lock().unwrap();
        let text = String::from_utf8_lossy(b.get_ref());
        assert_eq!(text.lines().count(), 2, "both the UDP and TCP scan alerts should appear, not just one: {}", text);
        assert!(text.contains("proto=UDP"));
        assert!(text.contains("proto=TCP"));
    }

    #[test]
    fn alerts_against_different_destinations_are_not_mutually_suppressed() {
        // Regression test for a real bug found in the field: a port scan
        // against the local gateway, followed moments later by a port
        // scan against a completely different remote host — same
        // source, same category, same protocol — landed 15 seconds
        // apart in a live run, right at the edge of the (also 15s)
        // suppression window. The second alert only survived by luck of
        // timing: the key didn't include the destination at all, so a
        // source scanning two different targets in quick succession
        // would have the second target's alert silently swallowed as a
        // "duplicate" of the first, even though they're two genuinely
        // different victims.
        use std::io::{Cursor, Write};
        use std::sync::{Arc, Mutex};

        let (tx, rx) = crossbeam_channel::unbounded();
        let buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let buf2 = Arc::clone(&buf);

        struct CountingWriter(Arc<Mutex<Cursor<Vec<u8>>>>);
        impl Write for CountingWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let handle = std::thread::spawn(move || {
            run_alert_writer(rx, Output::single(Box::new(CountingWriter(buf2)), Format::Text), AlertWriterConfig::plain(Duration::from_secs(60)));
        });

        let gateway_scan = Alert {
            timestamp: SystemTime::now(),
            severity: Severity::Medium,
            category: "PORT_SCAN",
            src: IpAddr::V4([192, 168, 0, 112]),
            dst: IpAddr::V4([192, 168, 0, 1]),
            proto: "TCP",
            port: 21,
            message: "21 distinct TCP ports touched on this destination in the last 90s (limit 20)".to_string(),
            sid: 0,
        };
        let mut remote_scan = gateway_scan.clone();
        remote_scan.dst = IpAddr::V4([45, 33, 32, 156]);

        // Sent back-to-back, well within any suppression window —
        // unlike the live run, this test doesn't rely on lucky timing.
        tx.send(gateway_scan).unwrap();
        tx.send(remote_scan).unwrap();
        drop(tx);
        handle.join().unwrap();

        let b = buf.lock().unwrap();
        let text = String::from_utf8_lossy(b.get_ref());
        assert_eq!(text.lines().count(), 2, "both destinations' alerts should appear, not just one: {}", text);
        assert!(text.contains("dst=192.168.0.1 "));
        assert!(text.contains("dst=45.33.32.156"));
    }

    #[test]
    fn packet_flood_suppression_stays_per_source_regardless_of_destination() {
        // The deliberate exception to the fix above: PACKET_FLOOD is
        // tracked per-source regardless of destination by design (see
        // AnomalyEngine::observe) — a source flooding several different
        // destinations is still meant to collapse to one alert stream,
        // not one per destination, or the exact alert-spam problem
        // suppression exists to prevent would reappear for this category.
        use std::io::{Cursor, Write};
        use std::sync::{Arc, Mutex};

        let (tx, rx) = crossbeam_channel::unbounded();
        let buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let buf2 = Arc::clone(&buf);

        struct CountingWriter(Arc<Mutex<Cursor<Vec<u8>>>>);
        impl Write for CountingWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let handle = std::thread::spawn(move || {
            run_alert_writer(rx, Output::single(Box::new(CountingWriter(buf2)), Format::Text), AlertWriterConfig::plain(Duration::from_secs(60)));
        });

        let flood_a = Alert {
            timestamp: SystemTime::now(),
            severity: Severity::High,
            category: "PACKET_FLOOD",
            src: IpAddr::V4([203, 0, 113, 9]),
            dst: IpAddr::V4([192, 168, 0, 112]),
            proto: "TCP",
            port: 443,
            message: "501 packets from this source in the last 10s (limit 500)".to_string(),
            sid: 0,
        };
        let mut flood_b = flood_a.clone();
        flood_b.dst = IpAddr::V4([192, 168, 0, 50]); // a different destination, same flooding source

        tx.send(flood_a).unwrap();
        tx.send(flood_b).unwrap();
        drop(tx);
        handle.join().unwrap();

        let b = buf.lock().unwrap();
        let text = String::from_utf8_lossy(b.get_ref());
        assert_eq!(text.lines().count(), 1, "PACKET_FLOOD should still collapse across destinations from the same source: {}", text);
    }

    #[test]
    fn different_signature_matches_are_not_mutually_suppressed() {
        // Regression test for a real bug found in the field: two
        // genuinely different SIGNATURE_MATCH alerts (a TFTP filename
        // rule and an unrelated SNMP community-string rule, in the
        // actual live test that caught this) sharing the same source,
        // destination, and protocol got treated as "duplicates" of each
        // other, since the suppression key didn't distinguish *which
        // rule* matched — only the second alert's identical
        // category/src/dst/proto mattered to the old key, and the
        // second one vanished. Two different rule names, otherwise
        // identical envelope, must both survive.
        use std::io::{Cursor, Write};
        use std::sync::{Arc, Mutex};

        let (tx, rx) = crossbeam_channel::unbounded();
        let buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let buf2 = Arc::clone(&buf);

        struct CountingWriter(Arc<Mutex<Cursor<Vec<u8>>>>);
        impl Write for CountingWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let handle = std::thread::spawn(move || {
            run_alert_writer(rx, Output::single(Box::new(CountingWriter(buf2)), Format::Text), AlertWriterConfig::plain(Duration::from_secs(60)));
        });

        let tftp_match = Alert {
            timestamp: SystemTime::now(),
            severity: Severity::High,
            category: "SIGNATURE_MATCH",
            src: IpAddr::V4([127, 0, 0, 1]),
            dst: IpAddr::V4([127, 0, 0, 1]),
            proto: "UDP",
            port: 69,
            message: "TftpFilename matched signature \"tftp-config-pull\" (buffer: tftp.filename)".to_string(),
            sid: 0,
        };
        let mut snmp_match = tftp_match.clone();
        snmp_match.port = 161;
        snmp_match.message = "SnmpCommunity matched signature \"snmp-default-community\" (buffer: snmp.community)".to_string();

        tx.send(tftp_match).unwrap();
        tx.send(snmp_match).unwrap();
        drop(tx);
        handle.join().unwrap();

        let b = buf.lock().unwrap();
        let text = String::from_utf8_lossy(b.get_ref());
        assert_eq!(text.lines().count(), 2, "two different rule matches should both appear, not just one: {}", text);
        assert!(text.contains("tftp-config-pull"));
        assert!(text.contains("snmp-default-community"));
    }

    #[test]
    fn repeated_matches_of_the_same_signature_still_suppress_normally() {
        // The flip side of the fix above: including `message` in the
        // SIGNATURE_MATCH suppression key only works because the
        // message is deterministic per rule (built from just the buffer
        // + rule name) — it must not defeat suppression for the
        // ordinary case of the *same* rule matching repeatedly, the way
        // it deliberately would for PORT_SCAN/PACKET_FLOOD if their
        // growing-count messages were used the same way.
        use std::io::{Cursor, Write};
        use std::sync::{Arc, Mutex};

        let (tx, rx) = crossbeam_channel::unbounded();
        let buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let buf2 = Arc::clone(&buf);

        struct CountingWriter(Arc<Mutex<Cursor<Vec<u8>>>>);
        impl Write for CountingWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let handle = std::thread::spawn(move || {
            run_alert_writer(rx, Output::single(Box::new(CountingWriter(buf2)), Format::Text), AlertWriterConfig::plain(Duration::from_secs(60)));
        });

        let a = Alert {
            timestamp: SystemTime::now(),
            severity: Severity::High,
            category: "SIGNATURE_MATCH",
            src: IpAddr::V4([127, 0, 0, 1]),
            dst: IpAddr::V4([127, 0, 0, 1]),
            proto: "UDP",
            port: 161,
            message: "SnmpCommunity matched signature \"snmp-default-community\" (buffer: snmp.community)".to_string(),
            sid: 0,
        };

        tx.send(a.clone()).unwrap();
        tx.send(a.clone()).unwrap();
        tx.send(a).unwrap();
        drop(tx);
        handle.join().unwrap();

        let b = buf.lock().unwrap();
        let text = String::from_utf8_lossy(b.get_ref());
        assert_eq!(text.lines().count(), 1, "three identical matches of the same rule should still collapse to one: {}", text);
    }

    #[test]
    fn pcap_dump_requested_only_for_alerts_that_survive_suppression() {
        use std::io::{Cursor, Write};
        use std::sync::{Arc, Mutex};

        let (tx, rx) = crossbeam_channel::unbounded();
        let (pcap_tx, pcap_rx) = crossbeam_channel::unbounded();
        let buf = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let buf2 = Arc::clone(&buf);

        struct CountingWriter(Arc<Mutex<Cursor<Vec<u8>>>>);
        impl Write for CountingWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let handle = std::thread::spawn(move || {
            run_alert_writer(rx, Output::single(Box::new(CountingWriter(buf2)), Format::Text), AlertWriterConfig::plain(Duration::from_secs(60)).with_pcap(pcap_tx));
        });

        let a = Alert {
            timestamp: SystemTime::now(),
            severity: Severity::High,
            category: "PACKET_FLOOD",
            src: IpAddr::V4([9, 9, 9, 9]),
            dst: IpAddr::V4([0, 0, 0, 0]),
            proto: "TCP",
            port: 0,
            message: "x".to_string(),
            sid: 0,
        };
        // Three identical alerts: only the first should survive
        // suppression and generate a dump request — dumping a pcap for
        // every one of a burst of suppressed duplicates would be waste,
        // and they'd all show the same traffic window anyway.
        tx.send(a.clone()).unwrap();
        tx.send(a.clone()).unwrap();
        tx.send(a).unwrap();
        drop(tx);
        handle.join().unwrap();

        let requests: Vec<PcapDumpRequest> = pcap_rx.try_iter().collect();
        assert_eq!(requests.len(), 1, "expected exactly one dump request for the one alert that wasn't suppressed");
        assert_eq!(requests[0].category, "PACKET_FLOOD");
        assert_eq!(requests[0].src, IpAddr::V4([9, 9, 9, 9]));
    }
}

#[cfg(test)]
mod flow_tests {
    use super::*;
    use crate::packet::{build_tcp_frame, parse_ethernet_frame, TCP_ACK, TCP_PSH, TCP_SYN};
    use super::test_support::{client_hello, client_hello_extensions_len, rdp_connection_request, ruleset_from};

    // --- enrichment -----------------------------------------------------

    fn intel_from(text: &str) -> Arc<Intel> {
        // A counter, not a hash of the contents: two tests may legitimately
        // load the same feed, and colliding on the filename would make them
        // race.
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("argus-intel-{}-{}.txt", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, text).unwrap();
        let sources = crate::intel::IntelSources { reputation: vec![path.to_string_lossy().into_owned()], ..Default::default() };
        let intel = Arc::new(Intel::load(&sources).unwrap());
        let _ = std::fs::remove_file(&path);
        intel
    }

    fn table_with_intel(text: &str) -> FlowTable {
        let mut t = FlowTable::new();
        t.set_intel(intel_from(text));
        t
    }

    fn sig() -> SignatureEngine {
        SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() }
    }

    /// A connection to a listed address is reported when the flow is
    /// created — the moment "this host started talking to that one"
    /// becomes a new fact.
    /// Builds a request from its lines, so the test reads as the wire
    /// format rather than as a wall of escapes — and so a stray literal
    /// newline can't quietly turn a CRLF protocol into something else.
    fn http_request(head: &[&str], body: &str) -> Vec<u8> {
        let mut out = String::new();
        for line in head {
            out.push_str(line);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.push_str(body);
        out.into_bytes()
    }

    /// Every header buffer must come from one parse, and each must carry
    /// only its own field — a rule scoped to `http.user_agent` that also
    /// saw the cookie would be a rule that silently means something else.
    #[test]
    fn the_header_buffers_are_populated_and_separate() {
        let rules = ruleset_from(concat!(
            "ua|http.user_agent|to_server|literal|BadBot\n",
            "cookie|http.cookie|to_server|literal|sessid=\n",
            "hdr|http.header|to_server|literal|X-Odd-Header\n",
            "body|http.request_body|to_server|literal|secret=\n",
            "file|file.data|to_server|literal|secret=\n",
        ));
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let mut alerts = Vec::new();
        let req = http_request(
            &["POST /login HTTP/1.1", "Host: victim", "User-Agent: BadBot/1.0", "X-Odd-Header: 1", "Cookie: sessid=abc"],
            "secret=hunter2",
        );
        let pkt = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, 80, 1000, TCP_PSH | TCP_ACK, &req));
        table.observe(&pkt, SystemTime::now(), 1_000_000, &sig, &mut alerts);
        let names: Vec<&str> = alerts.iter().map(|a| a.message.as_str()).collect();
        for want in ["ua", "cookie", "hdr", "body", "file"] {
            assert!(names.iter().any(|m| m.contains(want)), "{} did not fire: {:?}", want, names);
        }
    }

    /// The body is what follows the terminator and the header block is
    /// what precedes it. Neither may include the other.
    #[test]
    fn the_body_and_header_buffers_do_not_overlap() {
        let req = http_request(&["POST /x HTTP/1.1", "Host: h"], "BODYBYTES");
        let info = parse_http_request(&req).expect("a complete request parses");
        assert_eq!(info.body.as_deref(), Some(&b"BODYBYTES"[..]));
        assert!(info.headers.contains("Host: h"));
        assert!(!info.headers.contains("BODYBYTES"), "the header block stops at the terminator");
        assert_eq!(info.user_agent, None);
    }

    /// HTTP header names are case-insensitive by specification, so a
    /// client writing `user-agent` is not thereby invisible.
    #[test]
    fn header_names_are_matched_without_regard_to_case() {
        let req = http_request(&["GET / HTTP/1.1", "user-agent: curl", "COOKIE: a=b", "hOsT: h"], "");
        let info = parse_http_request(&req).unwrap();
        assert_eq!(info.user_agent.as_deref(), Some("curl"));
        assert_eq!(info.cookie.as_deref(), Some("a=b"));
        assert_eq!(info.host.as_deref(), Some("h"));
    }

    /// An upload of an image, an archive or an executable is exactly the
    /// body worth inspecting, and none of them is text. Requiring the
    /// whole buffer to be UTF-8 meant every one of them failed to parse
    /// as HTTP at all.
    #[test]
    fn a_binary_body_does_not_defeat_header_parsing() {
        let mut req = http_request(&["POST /upload.txt HTTP/1.1", "Host: victim"], "");
        req.extend_from_slice(&[0x4D, 0x5A, 0x90, 0x00, 0xFF, 0xFE, 0x00, 0x01]);
        let info = parse_http_request(&req).expect("a binary body must not stop the headers parsing");
        assert_eq!(info.uri, "/upload.txt");
        assert_eq!(info.host.as_deref(), Some("victim"));
        assert_eq!(info.body.as_deref(), Some(&[0x4D, 0x5A, 0x90, 0x00, 0xFF, 0xFE, 0x00, 0x01][..]));
    }

    #[test]
    fn a_request_with_no_body_reports_none_rather_than_an_empty_string() {
        let req = http_request(&["GET / HTTP/1.1", "Host: h"], "");
        let info = parse_http_request(&req).unwrap();
        assert_eq!(info.body, None, "an absent body and an empty one are different facts");
    }

    // --- lateral-movement protocols -------------------------------------

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// An NTLM AUTHENTICATE message, which is the one carrying an
    /// identity. Built here rather than imported so this test fails if
    /// the wire layout is misread, not merely if a helper changes.
    fn ntlm_auth(domain: &str, user: &str, workstation: &str) -> Vec<u8> {
        let (d, u, w) = (utf16(domain), utf16(user), utf16(workstation));
        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\x00");
        m.extend_from_slice(&3u32.to_le_bytes());
        let mut off = 64usize;
        for len in [0, 0, d.len(), u.len(), w.len(), 0] {
            m.extend_from_slice(&(len as u16).to_le_bytes());
            m.extend_from_slice(&(len as u16).to_le_bytes());
            m.extend_from_slice(&(off as u32).to_le_bytes());
            off += len;
        }
        m.extend_from_slice(&0u32.to_le_bytes());
        m.extend_from_slice(&d);
        m.extend_from_slice(&u);
        m.extend_from_slice(&w);
        m
    }

    fn observe_once(rules_text: &str, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<Alert> {
        let sig = SignatureEngine { blacklist: Default::default(), rules: ruleset_from(rules_text) };
        let mut table = FlowTable::new();
        let mut alerts = Vec::new();
        let pkt = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], src_port, dst_port, 1000, TCP_PSH | TCP_ACK, payload));
        table.observe(&pkt, SystemTime::now(), 1_000_000, &sig, &mut alerts);
        alerts
    }

    /// The single most directly actionable thing on an internal network:
    /// which account authenticated, from which machine, in the clear.
    #[test]
    fn an_ntlm_authentication_is_matchable_by_account_and_workstation() {
        let alerts = observe_once(
            concat!("who|ntlm.user|any|literal|svc_backup\n", "whence|ntlm.workstation|any|literal|ATTACKER\n", "dom|ntlm.domain|any|literal|CORP\n"),
            51234,
            445,
            &ntlm_auth("CORP", "svc_backup", "ATTACKER"),
        );
        let msgs: Vec<&str> = alerts.iter().map(|a| a.message.as_str()).collect();
        for want in ["who", "whence", "dom"] {
            assert!(msgs.iter().any(|m| m.contains(want)), "{} did not fire: {:?}", want, msgs);
        }
    }

    /// NTLM is found by its signature wherever it is embedded, so it
    /// must be reachable through an SMB session setup and not only on
    /// its own.
    #[test]
    fn ntlm_inside_an_smb_session_setup_is_still_found() {
        let mut msg = vec![0xFF];
        msg.extend_from_slice(b"SMB");
        msg.push(0x73); // SESSION_SETUP_ANDX
        msg.extend_from_slice(&[0u8; 5]);
        msg.extend_from_slice(&0x8000u16.to_le_bytes()); // unicode strings
        msg.extend_from_slice(&[0u8; 20]);
        let data = ntlm_auth("CORP", "admin", "WK1");
        msg.push(12); // word count
        msg.extend_from_slice(&[0u8; 24]);
        msg.extend_from_slice(&(data.len() as u16).to_le_bytes());
        msg.extend_from_slice(&data);

        let alerts = observe_once("who|ntlm.user|any|literal|admin\ncmd|smb.command|any|literal|SESSION_SETUP\n", 51234, 445, &msg);
        let msgs: Vec<&str> = alerts.iter().map(|a| a.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("who")), "the embedded NTLM must be reachable: {:?}", msgs);
        assert!(msgs.iter().any(|m| m.contains("cmd")), "and the SMB1 command with it: {:?}", msgs);
    }

    /// Reaching the Service Control Manager over RPC is how remote
    /// execution is done, so the interface is worth a rule of its own.
    #[test]
    fn a_dcerpc_bind_to_the_service_manager_is_matchable() {
        let mut m = vec![5, 0, 11, 3];
        m.extend_from_slice(&[0x10, 0, 0, 0]);
        m.extend_from_slice(&[0u8; 8]);
        m.extend_from_slice(&[0u8; 8]);
        m.extend_from_slice(&[1, 0, 0, 0]);
        m.extend_from_slice(&[0, 0, 1, 0]);
        m.extend_from_slice(&[0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03]);
        m.extend_from_slice(&[0u8; 4]);

        let alerts = observe_once("svcctl|dcerpc.interface|any|literal|367abb81-9844-35f1\n", 51234, 135, &m);
        assert!(alerts.iter().any(|a| a.message.contains("svcctl")), "got {:?}", alerts.iter().map(|a| &a.message).collect::<Vec<_>>());
    }

    /// Port-gated protocols must not fire off their port: an ASN.1
    /// structure is not distinctive enough to content-sniff, which is
    /// the whole reason the gate exists.
    #[test]
    fn port_gated_protocols_do_not_fire_on_other_ports() {
        let mut op = vec![0x02, 0x01, 0x03];
        let dn = b"CN=admin,DC=corp";
        op.push(0x04);
        op.push(dn.len() as u8);
        op.extend_from_slice(dn);
        op.extend_from_slice(&[0x80, 0x03]);
        op.extend_from_slice(b"pwd");
        let mut body = vec![0x02, 0x01, 0x01, 0x60, op.len() as u8];
        body.extend_from_slice(&op);
        let mut msg = vec![0x30, body.len() as u8];
        msg.extend_from_slice(&body);

        let rules = "dn|ldap.dn|any|literal|CN=admin\n";
        assert!(
            observe_once(rules, 51234, 389, &msg).iter().any(|a| a.message.contains("dn")),
            "an LDAP bind on 389 must be parsed"
        );
        assert!(
            !observe_once(rules, 51234, 12345, &msg).iter().any(|a| a.message.contains("dn")),
            "the same bytes on an unrelated port must not be"
        );
    }

    // --- file identity ---------------------------------------------------

    /// A hash is the most portable indicator there is; this is the whole
    /// point of extracting one.
    #[test]
    fn an_uploaded_file_is_matchable_by_hash_and_by_type() {
        // "abc" has a published MD5, so the rule can name it exactly.
        let req = http_request(&["POST /upload HTTP/1.1", "Host: victim"], "abc");
        let alerts = observe_once("known-sample|file.md5|to_server|literal|900150983cd24fb0d6963f7d28e17f72\n", 51234, 80, &req);
        assert!(alerts.iter().any(|a| a.message.contains("known-sample")), "got {:?}", alerts.iter().map(|a| &a.message).collect::<Vec<_>>());
    }

    /// The magic number is the point: the filename and the Content-Type
    /// are both chosen by whoever is uploading, and the leading bytes
    /// are not.
    #[test]
    fn an_executable_uploaded_as_a_text_file_is_still_identified() {
        let req = http_request(&["POST /upload.txt HTTP/1.1", "Host: victim", "Content-Type: text/plain"], "MZ\u{0090}\u{0000}payload");
        let alerts = observe_once("exe-upload|file.type|to_server|literal|dos/pe-executable\n", 51234, 80, &req);
        assert!(alerts.iter().any(|a| a.message.contains("exe-upload")), "got {:?}", alerts.iter().map(|a| &a.message).collect::<Vec<_>>());
    }

    /// Hashing costs a pass over the body, so it must not happen when no
    /// rule could use the answer.
    #[test]
    fn file_identity_is_not_computed_when_no_rule_asks_for_it() {
        let with = ruleset_from("h|file.md5|to_server|literal|abc\n");
        assert!(with.wants_file_identity());
        let without = ruleset_from("u|http.uri|to_server|literal|/x\n");
        assert!(!without.wants_file_identity());
    }

    // --- the response side ----------------------------------------------

    const CLIENT: [u8; 4] = [10, 0, 0, 5];
    const SERVER: [u8; 4] = [10, 0, 0, 1];

    /// One HTTP exchange through a table: the request goes to the server,
    /// then each response segment comes back. The request goes first so
    /// the connection's orientation is right, as it is on a real network.
    struct Exchange {
        table: FlowTable,
        sig: SignatureEngine,
        alerts: Vec<Alert>,
        c_seq: u32,
        s_seq: u32,
        server_port: u16,
    }

    impl Exchange {
        fn new(rules: &str, stream_cap: usize, server_port: u16) -> Exchange {
            let sig = SignatureEngine { blacklist: Default::default(), rules: ruleset_from(rules) };
            Exchange { table: FlowTable::with_limits(stream_cap, 1000), sig, alerts: Vec::new(), c_seq: 1000, s_seq: 5000, server_port }
        }

        fn to_server(&mut self, data: &[u8]) {
            let f = parse(&build_tcp_frame(CLIENT, SERVER, 51234, self.server_port, self.c_seq, TCP_PSH | TCP_ACK, data));
            self.c_seq += data.len() as u32;
            self.table.observe(&f, SystemTime::now(), 2_000_000, &self.sig, &mut self.alerts);
        }

        fn to_client(&mut self, data: &[u8]) {
            let f = parse(&build_tcp_frame(SERVER, CLIENT, self.server_port, 51234, self.s_seq, TCP_PSH | TCP_ACK, data));
            self.s_seq += data.len() as u32;
            self.table.observe(&f, SystemTime::now(), 2_000_000, &self.sig, &mut self.alerts);
        }

        fn fin_from_server(&mut self) {
            let f = parse(&build_tcp_frame(SERVER, CLIENT, self.server_port, 51234, self.s_seq, TCP_FIN | TCP_ACK, &[]));
            self.table.observe(&f, SystemTime::now(), 2_000_000, &self.sig, &mut self.alerts);
        }

        fn names(&self) -> Vec<&str> {
            self.alerts.iter().map(|a| a.message.as_str()).collect()
        }

        fn fired(&self, what: &str) -> bool {
            self.names().iter().any(|m| m.contains(what))
        }
    }

    fn response(head: &[&str], body: &[u8]) -> Vec<u8> {
        let mut out = http_request(head, "");
        out.extend_from_slice(body);
        out
    }

    fn get(path: &str) -> Vec<u8> {
        http_request(&[&format!("GET {} HTTP/1.1", path), "Host: victim"], "")
    }

    fn md5_of(data: &[u8]) -> String {
        crate::files::inspect(data).unwrap().md5
    }

    #[test]
    fn every_response_buffer_is_matchable() {
        let mut x = Exchange::new(
            concat!(
                "code|http.stat_code|to_client|literal|404\n",
                "msg|http.stat_msg|to_client|literal|Not Found\n",
                "ctype|http.content_type|to_client|literal|application/x-msdownload\n",
                "srv|http.server|to_client|literal|EvilServer\n",
                "loc|http.location|to_client|literal|/moved\n",
                "setck|http.cookie|to_client|literal|sid=abc\n",
                "rbody|http.response_body|to_client|literal|SECRETBODY\n",
            ),
            16384,
            80,
        );
        x.to_server(&get("/x"));
        x.to_client(&response(
            &["HTTP/1.1 404 Not Found", "Content-Type: application/x-msdownload", "Server: EvilServer", "Location: /moved", "Set-Cookie: sid=abc; Path=/", "Content-Length: 10"],
            b"SECRETBODY",
        ));
        for want in ["code", "msg", "ctype", "srv", "loc", "setck", "rbody"] {
            assert!(x.fired(want), "{} did not fire: {:?}", want, x.names());
        }
    }

    /// The reason multi-buffer rules and the response parser belong
    /// together: "this URI got this answer" is the shape of most probing.
    #[test]
    fn one_rule_can_span_a_request_and_its_response() {
        let mut x = Exchange::new(r#"rule sid:900; name:"git-probe-hit"; proto:tcp; buffer:http.uri; content:"/.git/config"; buffer:http.stat_code; content:"200";"#, 16384, 80);
        x.to_server(&get("/.git/config"));
        assert!(!x.fired("git-probe-hit"), "a request alone is not the rule");
        x.to_client(&response(&["HTTP/1.1 200 OK", "Content-Length: 4"], b"[cor"));
        assert!(x.fired("git-probe-hit"), "got {:?}", x.names());
    }

    #[test]
    fn a_rule_spanning_request_and_response_stays_quiet_on_the_wrong_status() {
        let mut x = Exchange::new(r#"rule sid:901; name:"git-probe-hit"; proto:tcp; buffer:http.uri; content:"/.git/config"; buffer:http.stat_code; content:"200";"#, 16384, 80);
        x.to_server(&get("/.git/config"));
        x.to_client(&response(&["HTTP/1.1 404 Not Found", "Content-Length: 0"], b""));
        assert!(!x.fired("git-probe-hit"), "a 404 is the probe failing: {:?}", x.names());
    }

    /// The point of streaming: a download far larger than the reassembly
    /// buffer is still hashed in full, and the hash is the real one.
    #[test]
    fn a_download_larger_than_the_reassembly_cap_is_hashed_in_full() {
        let body: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let want = md5_of(&body);
        let mut x = Exchange::new(&format!("dl|file.md5|to_client|literal|{}\n", want), 256, 80);
        x.to_server(&get("/big.bin"));
        let head = response(&["HTTP/1.1 200 OK", "Content-Length: 5000"], &body[..100]);
        x.to_client(&head);
        for chunk in body[100..].chunks(1400) {
            x.to_client(chunk);
        }
        assert!(x.fired("dl"), "the whole body must be hashed, not the 256 bytes the buffer held: {:?}", x.names());
    }

    #[test]
    fn a_chunked_download_is_hashed_decoded() {
        let body: Vec<u8> = (0..3000u32).map(|i| (i % 199) as u8).collect();
        let want = md5_of(&body);
        let mut wire = Vec::new();
        for c in body.chunks(1000) {
            wire.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
            wire.extend_from_slice(c);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");

        let mut x = Exchange::new(&format!("dl|file.md5|to_client|literal|{}\n", want), 256, 80);
        x.to_server(&get("/chunked.bin"));
        let head = response(&["HTTP/1.1 200 OK", "Transfer-Encoding: chunked"], &wire[..50]);
        x.to_client(&head);
        for chunk in wire[50..].chunks(700) {
            x.to_client(chunk);
        }
        assert!(x.fired("dl"), "the hash must be of the payload, not the framing: {:?}", x.names());
    }

    /// A body with no length that the server closes on ends at the FIN.
    #[test]
    fn a_close_delimited_body_is_hashed_when_the_server_closes() {
        let body = vec![0x41u8; 900];
        let want = md5_of(&body);
        let mut x = Exchange::new(&format!("dl|file.md5|to_client|literal|{}\n", want), 4096, 80);
        x.to_server(&get("/stream"));
        x.to_client(&response(&["HTTP/1.1 200 OK", "Connection: close"], &body[..300]));
        x.to_client(&body[300..]);
        assert!(!x.fired("dl"), "not finished until the connection closes");
        x.fin_from_server();
        assert!(x.fired("dl"), "got {:?}", x.names());
    }

    /// If the start of a body was dropped before hashing could begin, the
    /// digest would describe a file that never existed, so none is given.
    #[test]
    fn a_body_whose_start_was_lost_is_not_hashed() {
        let body = vec![0x42u8; 400];
        let mut x = Exchange::new("any|file.sha256|to_client|regex|.\n", 128, 80);
        x.to_server(&get("/x"));
        // One segment bigger than the 128-byte buffer: the head of the
        // body is gone by the time the headers can be parsed.
        x.to_client(&response(&["HTTP/1.1 200 OK", "Content-Length: 400"], &body));
        assert!(!x.fired("any"), "{:?}", x.names());
    }

    /// A HEAD response carries the headers of a body that never follows.
    /// Hashing "the body" would swallow the next response instead and
    /// produce a confident, wrong digest.
    #[test]
    fn a_head_response_is_not_hashed_as_though_it_had_a_body() {
        let mut x = Exchange::new("any|file.sha256|to_client|regex|.\n", 16384, 80);
        x.to_server(&http_request(&["HEAD /x HTTP/1.1", "Host: victim"], ""));
        x.to_client(&response(&["HTTP/1.1 200 OK", "Content-Length: 500"], b""));
        x.to_client(&vec![b'Z'; 500]);
        assert!(!x.fired("any"), "nothing was downloaded: {:?}", x.names());
    }

    #[test]
    fn a_304_is_not_hashed() {
        let mut x = Exchange::new("any|file.sha256|to_client|regex|.\n", 16384, 80);
        x.to_server(&get("/cached"));
        x.to_client(&response(&["HTTP/1.1 304 Not Modified", "Content-Length: 500"], b""));
        x.to_client(&vec![b'Z'; 500]);
        assert!(!x.fired("any"), "{:?}", x.names());
    }

    #[test]
    fn a_response_that_is_not_http_is_never_parsed_as_one() {
        let mut x = Exchange::new("code|http.stat_code|to_client|regex|.\n", 16384, 80);
        x.to_server(&get("/x"));
        x.to_client(b"SSH-2.0-OpenSSH_9.6\r\n");
        assert!(!x.fired("code"), "{:?}", x.names());
    }

    // --- observed authentication failures ------------------------------

    fn failures(x: &mut Exchange) -> usize {
        let mut obs = Vec::new();
        x.table.take_observations(&mut obs);
        obs.iter().filter(|o| matches!(o, crate::behavior::Observation::AuthFailure { .. })).count()
    }

    #[test]
    fn an_ftp_530_is_an_observed_failure() {
        let mut x = Exchange::new("", 16384, 21);
        x.table.enable_observations();
        x.to_server(b"USER admin\r\n");
        x.to_client(b"331 Password required\r\n");
        x.to_server(b"PASS hunter2\r\n");
        x.to_client(b"530 Login incorrect.\r\n");
        assert_eq!(failures(&mut x), 1);
    }

    /// One segment can carry several replies, and each is a refusal.
    #[test]
    fn several_refusals_in_one_segment_are_each_counted() {
        let mut x = Exchange::new("", 16384, 21);
        x.table.enable_observations();
        x.to_server(b"USER a\r\nPASS b\r\nUSER c\r\nPASS d\r\n");
        x.to_client(b"530 no\r\n530 no\r\n");
        assert_eq!(failures(&mut x), 2);
    }

    #[test]
    fn an_http_401_is_an_observed_failure() {
        let mut x = Exchange::new("", 16384, 80);
        x.table.enable_observations();
        x.to_server(&get("/admin"));
        x.to_client(&response(&["HTTP/1.1 401 Unauthorized", "WWW-Authenticate: Basic", "Content-Length: 0"], b""));
        assert_eq!(failures(&mut x), 1);
    }

    /// A 530 is only a refused login on the FTP port.
    #[test]
    fn a_530_on_another_port_is_not_a_login_refusal() {
        let mut x = Exchange::new("", 16384, 8080);
        x.table.enable_observations();
        x.to_server(b"anything\r\n");
        x.to_client(b"530 something else entirely\r\n");
        assert_eq!(failures(&mut x), 0);
    }

    #[test]
    fn a_successful_login_is_not_a_failure() {
        let mut x = Exchange::new("", 16384, 21);
        x.table.enable_observations();
        x.to_server(b"USER admin\r\nPASS good\r\n");
        x.to_client(b"230 Login successful.\r\n");
        assert_eq!(failures(&mut x), 0);
    }

    // --- header names and the request line --------------------------------

    /// Order and presence are signal: a browser, a scripting library and an
    /// implant each send their headers in a recognisably different shape.
    #[test]
    fn header_names_are_the_names_in_order_between_crlfs() {
        let head = "GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8\r\nAccept: */*";
        assert_eq!(header_names_buffer(head), b"\r\nHost\r\nUser-Agent\r\nAccept\r\n\r\n");
    }

    #[test]
    fn header_names_exclude_the_request_line_and_every_value() {
        let names = header_names_buffer("POST /login?x=1 HTTP/1.1\r\nHost: secret.example\r\nCookie: sid=abc");
        assert!(!names.windows(5).any(|w| w == b"login"), "the request line is not a header");
        assert!(!names.windows(6).any(|w| w == b"secret"), "values are not header names");
    }

    #[test]
    fn a_rule_can_key_on_header_order() {
        let rules = "rule sid:1; name:\"ua-before-host\"; proto:tcp; direction:to_server; buffer:http.header_names; content:\"|0d 0a|User-Agent|0d 0a|Host|0d 0a|\";\n";
        let mut x = Exchange::new(rules, 16384, 80);
        x.to_server(&http_request(&["GET / HTTP/1.1", "User-Agent: implant", "Host: victim"], ""));
        assert!(x.fired("ua-before-host"), "{:?}", x.names());

        // The same headers in a browser's order do not match.
        let mut y = Exchange::new(rules, 16384, 80);
        y.to_server(&http_request(&["GET / HTTP/1.1", "Host: victim", "User-Agent: Mozilla"], ""));
        assert!(!y.fired("ua-before-host"), "{:?}", y.names());
    }

    #[test]
    fn the_request_line_is_matchable_whole() {
        let mut x = Exchange::new("rl|http.request_line|to_server|literal|GET /admin HTTP/1.1\n", 16384, 80);
        x.to_server(&get("/admin"));
        assert!(x.fired("rl"), "{:?}", x.names());
    }

    #[test]
    fn response_header_names_are_populated_too() {
        let rules = "rule sid:2; name:\"hn\"; proto:tcp; direction:to_client; buffer:http.header_names; content:\"|0d 0a|Server|0d 0a|\";\n";
        let mut x = Exchange::new(rules, 16384, 80);
        x.to_server(&get("/x"));
        x.to_client(&response(&["HTTP/1.1 200 OK", "Server: nginx", "Content-Length: 0"], b""));
        assert!(x.fired("hn"), "{:?}", x.names());
    }

    #[test]
    fn a_named_header_is_its_own_buffer() {
        let rules = concat!(
            "acc|http.accept|to_server|literal|text/x-evil
",
            "ref|http.referer|to_server|literal|bad.example
",
            "cl|http.content_len|to_client|literal|1234
",
            "conn|http.connection|to_server|literal|Upgrade
",
        );
        let mut x = Exchange::new(rules, 16384, 80);
        x.to_server(&http_request(&["GET / HTTP/1.1", "Host: h", "accept: text/x-evil", "Referer: http://bad.example/x", "Connection: Upgrade"], ""));
        x.to_client(&response(&["HTTP/1.1 200 OK", "Content-Length: 1234"], b""));
        for name in ["acc", "ref", "cl", "conn"] {
            assert!(x.fired(name), "{name}: {:?}", x.names());
        }
    }

    #[test]
    fn a_header_value_is_found_whatever_its_case_and_spacing() {
        let head = "GET / HTTP/1.1
HOST :  h 
Accept:*/*";
        assert_eq!(header_value(head, "host"), Some("h"));
        assert_eq!(header_value(head, "accept"), Some("*/*"));
        assert_eq!(header_value(head, "referer"), None);
        // The request line is not a header, even when it looks like one.
        assert_eq!(header_value("Accept: x", "accept"), None);
    }

    #[test]
    fn the_start_of_a_message_includes_the_blank_line() {
        let mut x = Exchange::new("rule sid:3; name:\"st\"; proto:tcp; direction:to_server; buffer:http.start; content:\"Host: h|0d 0a 0d 0a|\";
", 16384, 80);
        x.to_server(&http_request(&["GET / HTTP/1.1", "Host: h"], ""));
        assert!(x.fired("st"), "{:?}", x.names());
    }

    #[test]
    fn a_server_certificate_is_matchable_by_subject_issuer_and_serial() {
        let rules = concat!(
            "rule sid:41; name:\"subj\"; proto:tcp; direction:to_client; buffer:tls.cert_subject; content:\"CN=evil.example\";
",
            "rule sid:42; name:\"iss\"; proto:tcp; direction:to_client; buffer:tls.cert_issuer; content:\"CN=Fake CA\";
",
            "rule sid:43; name:\"ser\"; proto:tcp; direction:to_client; buffer:tls.cert_serial; content:\"0E:7F:A1\";
",
            "rule sid:44; name:\"der\"; proto:tcp; direction:to_client; buffer:tls.certs; content:\"|55 04 03|\";
",
            "rule sid:45; name:\"other\"; proto:tcp; direction:to_client; buffer:tls.cert_subject; content:\"CN=good.example\";
",
        );
        let mut x = Exchange::new(rules, 16384, 443);
        // The first packet decides which side is the client.
        x.to_server(b"hello");
        x.to_client(&crate::tlscert::fixture::server_flight("evil.example", "Fake CA", &[0x0e, 0x7f, 0xa1]));
        for name in ["subj", "iss", "ser", "der"] {
            assert!(x.fired(name), "{name}: {:?}", x.names());
        }
        assert!(!x.fired("other"), "a different subject must not match");
    }

    #[test]
    fn a_certificate_arriving_in_pieces_is_read_once_whole() {
        let mut x = Exchange::new("rule sid:41; name:\"subj\"; proto:tcp; direction:to_client; buffer:tls.cert_subject; content:\"CN=evil.example\";
", 16384, 443);
        x.to_server(b"hello");
        let flight = crate::tlscert::fixture::server_flight("evil.example", "CA", &[1]);
        let (a, b) = flight.split_at(flight.len() / 2);
        x.to_client(a);
        assert!(!x.fired("subj"), "half a handshake is not a certificate");
        x.to_client(b);
        assert!(x.fired("subj"), "{:?}", x.names());
    }

    /// A rule about "any traffic identified as SSH" is a payload rule
    /// gated on the identity the SSH parser records.
    #[test]
    fn a_rule_scoped_to_an_identified_protocol_fires_only_on_that_protocol() {
        let rules = "rule sid:51; name:\"ssh-only\"; proto:tcp; direction:to_server; buffer:payload; content:\"OpenSSH\"; flowbits:isset,app.ssh;
";
        let mut ssh = Exchange::new(rules, 16384, 22);
        ssh.to_server(b"SSH-2.0-OpenSSH_8.9
");
        assert!(ssh.fired("ssh-only"), "{:?}", ssh.names());

        // The same bytes to a service that is not SSH do not identify it.
        let mut other = Exchange::new(rules, 16384, 9000);
        other.to_server(b"hello OpenSSH
");
        assert!(!other.fired("ssh-only"), "{:?}", other.names());
    }

    #[test]
    fn protocol_version_and_response_line_are_buffers() {
        let rules = concat!(
            "enc|http.accept_enc|to_server|literal|gzip\n",
            "lang|http.accept_lang|to_server|literal|xx-EVIL\n",
            "ver|http.protocol|to_server|literal|HTTP/1.0\n",
            "rver|http.protocol|to_client|literal|HTTP/1.1\n",
            "rline|http.response_line|to_client|literal|HTTP/1.1 404 Not Found\n",
        );
        let mut x = Exchange::new(rules, 16384, 80);
        x.to_server(&http_request(&["GET / HTTP/1.0", "Host: h", "Accept-Encoding: gzip", "Accept-Language: xx-EVIL"], ""));
        x.to_client(&response(&["HTTP/1.1 404 Not Found", "Content-Length: 0"], b""));
        for name in ["enc", "lang", "ver", "rver", "rline"] {
            assert!(x.fired(name), "{name}: {:?}", x.names());
        }
    }

    #[test]
    fn the_header_buffer_is_the_header_lines_and_their_terminator() {
        assert_eq!(header_block("GET / HTTP/1.1\r\nHost: h\r\nAccept: */*"), "Host: h\r\nAccept: */*\r\n\r\n");
        assert_eq!(header_block("GET / HTTP/1.1"), "\r\n", "no headers: only the closing blank line");
    }

    /// Rules anchor to the first header and to the blank line that ends
    /// the block; both were impossible while the request line was in the
    /// buffer and the terminator was not.
    #[test]
    fn a_rule_can_anchor_to_the_first_header_and_to_the_end_of_the_block() {
        let rules = concat!(
            "rule sid:61; name:\"first\"; proto:tcp; direction:to_server; buffer:http.header; content:\"Host: h\"; offset:0; depth:7;\n",
            "rule sid:62; name:\"end\"; proto:tcp; direction:to_server; buffer:http.header; content:\"|0d 0a 0d 0a|\"; isdataat:!1,relative;\n",
            "rule sid:63; name:\"no-request-line\"; proto:tcp; direction:to_server; buffer:http.header; content:\"GET\";\n",
        );
        let mut x = Exchange::new(rules, 16384, 80);
        x.to_server(&http_request(&["GET / HTTP/1.1", "Host: h", "Accept: */*"], ""));
        assert!(x.fired("first"), "{:?}", x.names());
        assert!(x.fired("end"), "{:?}", x.names());
        assert!(!x.fired("no-request-line"), "the request line is not a header");
    }

    #[test]
    fn stream_size_measures_what_each_side_has_sent() {
        let rules = "rule sid:71; name:\"big-reply\"; proto:tcp; direction:to_server; buffer:payload; content:\"X marks\"; stream_size:server,>,5;\n";
        let mut x = Exchange::new(rules, 16384, 9000);
        x.to_server(b"hello");
        x.to_client(b"12345678");
        x.to_server(b"X marks");
        assert!(x.fired("big-reply"), "{:?}", x.names());

        let mut quiet = Exchange::new(rules, 16384, 9000);
        quiet.to_server(b"hello");
        quiet.to_client(b"123");
        quiet.to_server(b"X marks");
        assert!(!quiet.fired("big-reply"), "the server sent only 3 bytes: {:?}", quiet.names());
    }

    // --- lenient loading ----------------------------------------------------

    fn temp_rules(text: &str) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("argus-lenient-{}-{}.txt", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, text).unwrap();
        path
    }

    /// A generated file has tens of thousands of rules, and one bad one
    /// must not stop the rest loading.
    #[test]
    fn a_lenient_load_skips_bad_rules_and_reports_each() {
        let path = temp_rules(concat!(
            "good-one|payload|to_server|literal|abc\n",
            "rule sid:1; name:\"broken\"; content:\"x\"; pcre:\"(unclosed\";\n",
            "rule sid:2; name:\"fine\"; content:\"y\";\n",
            "nonsense line with no structure\n",
        ));
        let (set, errors) = RuleSet::load_lenient(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(set.total_len(), 2, "the two good rules load");
        assert_eq!(errors.len(), 2, "each bad one is reported: {:?}", errors);
        assert!(errors[0].contains("line 2"), "{:?}", errors);
        assert!(errors[1].contains("line 4"), "{:?}", errors);
    }

    /// The strict load is unchanged: a hand-written file fails at its
    /// first mistake, which is what an author wants to be told.
    #[test]
    fn a_strict_load_still_fails_at_the_first_mistake() {
        let path = temp_rules("good|payload|any|literal|abc\nrule sid:1; name:\"broken\"; content:\"x\"; pcre:\"(unclosed\";\n");
        let strict = RuleSet::load(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        assert!(strict.is_err());
    }

    /// A composite that fails validation must not leave a hole in the id
    /// sequence, or every later composite would be refused for it.
    #[test]
    fn a_rejected_multi_buffer_rule_does_not_break_the_ones_after_it() {
        let path = temp_rules(concat!(
            "rule sid:1; name:\"a\"; buffer:http.uri; content:\"x\"; buffer:payload; !content:\"y\";\n",
            "rule sid:2; name:\"b\"; buffer:http.uri; content:\"x\"; buffer:http.header; content:\"y\";\n",
        ));
        let (set, errors) = RuleSet::load_lenient(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_eq!(set.total_len(), 1);
    }

    #[test]
    fn a_connection_to_a_listed_address_raises_threat_intel() {
        let mut table = table_with_intel("203.0.113.0/24 # cobalt-strike c2
");
        let mut alerts = Vec::new();
        let syn = parse(&build_tcp_frame([10, 0, 0, 5], [203, 0, 113, 9], 51234, 443, 1000, TCP_SYN, &[]));
        table.observe(&syn, SystemTime::now(), 1_000_000, &sig(), &mut alerts);
        let hit = alerts.iter().find(|a| a.category == "THREAT_INTEL").expect("a listed destination must be reported");
        assert!(hit.message.contains("cobalt-strike c2"), "the feed's own reason must survive into the alert: {}", hit.message);
        assert_eq!(hit.severity, Severity::High);
    }

    /// One bad destination must not produce one alert per packet: the
    /// traffic most likely to arrive in volume is exactly the traffic
    /// worth reporting, so the naive version denies service to its reader.
    #[test]
    fn repeated_traffic_to_one_listed_address_is_reported_once() {
        let mut table = table_with_intel("203.0.113.9 # c2
");
        let mut alerts = Vec::new();
        for i in 0..20u32 {
            let p = parse(&build_tcp_frame([10, 0, 0, 5], [203, 0, 113, 9], 51234 + i as u16, 443, 1000, TCP_SYN, &[]));
            table.observe(&p, SystemTime::now(), 1_000_000, &sig(), &mut alerts);
        }
        assert_eq!(alerts.iter().filter(|a| a.category == "THREAT_INTEL").count(), 1, "got {:?}", alerts.iter().map(|a| &a.message).collect::<Vec<_>>());
    }

    #[test]
    fn traffic_to_an_unlisted_address_is_silent() {
        let mut table = table_with_intel("203.0.113.0/24 # c2
");
        let mut alerts = Vec::new();
        let syn = parse(&build_tcp_frame([10, 0, 0, 5], [198, 51, 100, 9], 51234, 443, 1000, TCP_SYN, &[]));
        table.observe(&syn, SystemTime::now(), 1_000_000, &sig(), &mut alerts);
        assert!(!alerts.iter().any(|a| a.category == "THREAT_INTEL"));
    }

    /// The case an address feed structurally cannot catch: the
    /// destination is a shared CDN address, and only the name is
    /// distinguishing.
    #[test]
    fn a_listed_domain_is_caught_in_the_tls_sni() {
        let mut table = table_with_intel("evil.example.com ; phishing kit
");
        let mut alerts = Vec::new();
        let now = SystemTime::now();
        let client = [10, 0, 0, 5];
        let server = [151, 101, 1, 1];
        let syn = parse(&build_tcp_frame(client, server, 51234, 443, 1000, TCP_SYN, &[]));
        table.observe(&syn, now, 1_000_000, &sig(), &mut alerts);
        let hello = client_hello(b"a.evil.example.com");
        let pkt = parse(&build_tcp_frame(client, server, 51234, 443, 1001, TCP_PSH | TCP_ACK, &hello));
        alerts.clear();
        table.observe(&pkt, now, 1_000_000, &sig(), &mut alerts);
        let hit = alerts.iter().find(|a| a.category == "THREAT_INTEL").expect("a listed domain in SNI must be reported");
        assert!(hit.message.contains("TLS SNI") && hit.message.contains("phishing kit"), "{}", hit.message);
    }

    /// A JA3 describes the client software, so it survives the implant
    /// changing address — which is the usual thing an implant does.
    #[test]
    fn a_listed_ja3_is_caught_regardless_of_destination() {
        // Learn the fingerprint this helper produces, then list it.
        let hello = client_hello(b"ordinary.example.com");
        let info = parse_tls_client_hello(&hello).expect("the helper must produce a parseable ClientHello");
        let mut table = table_with_intel(&format!("{} # known implant
", info.ja3));
        let mut alerts = Vec::new();
        let pkt = parse(&build_tcp_frame([10, 0, 0, 5], [198, 51, 100, 9], 51234, 443, 1001, TCP_PSH | TCP_ACK, &hello));
        table.observe(&pkt, SystemTime::now(), 1_000_000, &sig(), &mut alerts);
        let hit = alerts.iter().find(|a| a.category == "THREAT_INTEL").expect("a listed JA3 must be reported");
        assert!(hit.message.contains("client fingerprint") && hit.message.contains("known implant"), "{}", hit.message);
    }

    /// With no feeds loaded, none of the above costs anything: the
    /// lookups are guarded by an emptiness check, and nothing is raised.
    #[test]
    fn without_feeds_enrichment_is_entirely_absent() {
        let mut table = FlowTable::new();
        let mut alerts = Vec::new();
        let syn = parse(&build_tcp_frame([10, 0, 0, 5], [203, 0, 113, 9], 51234, 443, 1000, TCP_SYN, &[]));
        table.observe(&syn, SystemTime::now(), 1_000_000, &sig(), &mut alerts);
        assert!(alerts.is_empty());
        assert_eq!(table.intel_hits(), 0);
    }

    fn parse(frame: &[u8]) -> Packet {
        let mut pkt = Packet::default();
        assert!(parse_ethernet_frame(frame, &mut pkt));
        pkt
    }

    #[test]
    fn defeats_signature_split_across_two_packets() {
        let rules = ruleset_from("split-sig|payload|any|literal|MALICIOUS_PAYLOAD\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 1_000_000i64;
        let mut alerts = Vec::new();

        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 1000, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);
        assert!(alerts.is_empty());

        let seg1 = parse(&build_tcp_frame(client, server, 51234, 80, 1001, TCP_PSH | TCP_ACK, b"MALICIOUS_"));
        alerts.clear();
        table.observe(&seg1, now, now_sec, &sig, &mut alerts);
        assert!(alerts.is_empty(), "half the signature alone should not match");

        let seg2 = parse(&build_tcp_frame(client, server, 51234, 80, 1011, TCP_PSH | TCP_ACK, b"PAYLOAD"));
        alerts.clear();
        table.observe(&seg2, now, now_sec, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "reassembled buffer should match the split signature");
    }

    /// A normal close must leave nothing behind.
    ///
    /// The final ACK arrives after both FINs, i.e. after the flow has
    /// already retired, and it used to create a fresh entry under the
    /// same key — an empty flow that nothing would ever answer. Every
    /// completed connection trailed one, which mattered because
    /// `HORIZONTAL_SCAN` is counted in unanswered destinations: ordinary
    /// successful traffic was donating the evidence a sweep is
    /// identified by.
    #[test]
    fn the_final_ack_of_a_close_does_not_resurrect_the_flow() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 3_000_000i64;
        let mut alerts = Vec::new();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        for (from_client, flags, payload) in [
            (true, TCP_SYN, &b""[..]),
            (false, TCP_SYN | TCP_ACK, &b""[..]),
            (true, TCP_ACK, &b""[..]),
            (true, TCP_PSH | TCP_ACK, &b"hello"[..]),
            (true, TCP_FIN | TCP_ACK, &b""[..]),
            (false, TCP_FIN | TCP_ACK, &b""[..]),
        ] {
            let pkt = if from_client {
                parse(&build_tcp_frame(client, server, 51234, 80, 1000, flags, payload))
            } else {
                parse(&build_tcp_frame(server, client, 80, 51234, 5000, flags, payload))
            };
            table.observe(&pkt, now, now_sec, &sig, &mut alerts);
        }
        // Both FINs seen: the connection is closed and the entry gone.
        assert_eq!(table.tracked_flows(), 0, "a closed connection should not be retained");

        let final_ack = parse(&build_tcp_frame(client, server, 51234, 80, 1006, TCP_ACK, &[]));
        table.observe(&final_ack, now, now_sec, &sig, &mut alerts);
        assert_eq!(table.tracked_flows(), 0, "the trailing ACK must not create a phantom flow");
    }

    /// The other half of the rule above: a capture that starts
    /// mid-connection still gets a flow, because the first segment with
    /// data creates one.
    #[test]
    fn a_mid_stream_segment_with_data_still_creates_a_flow() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        let mut alerts = Vec::new();
        let pkt = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, 80, 9000, TCP_ACK, b"GET / HTTP/1.1\r\n"));
        table.observe(&pkt, SystemTime::now(), 3_100_000, &sig, &mut alerts);
        assert_eq!(table.tracked_flows(), 1, "picking a connection up mid-stream must still work");
    }

    #[test]
    fn out_of_order_segments_are_reassembled_correctly() {
        let rules = ruleset_from("reordered|payload|any|literal|HELLOWORLD\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 2_000_000i64;
        let mut alerts = Vec::new();

        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 5000, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let seg2 = parse(&build_tcp_frame(client, server, 51234, 80, 5006, TCP_PSH | TCP_ACK, b"WORLD"));
        alerts.clear();
        table.observe(&seg2, now, now_sec, &sig, &mut alerts);
        assert!(alerts.is_empty(), "out-of-order segment alone should not match or crash anything");

        let seg1 = parse(&build_tcp_frame(client, server, 51234, 80, 5001, TCP_PSH | TCP_ACK, b"HELLO"));
        alerts.clear();
        table.observe(&seg1, now, now_sec, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "should reassemble in correct order once the gap closes");
    }

    /// Delivers one segment of a stream from a fixed client, returning any
    /// alerts. Sequence numbers are absolute so a test can overlap them.
    fn overlapping_stream(rules: &str, segments: &[(u32, &[u8])]) -> Vec<Alert> {
        let sig = SignatureEngine { blacklist: Default::default(), rules: ruleset_from(rules) };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let mut alerts = Vec::new();
        let (client, server) = ([10, 0, 0, 5], [10, 0, 0, 1]);
        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 999, TCP_SYN, &[]));
        table.observe(&syn, now, 2_000_000, &sig, &mut alerts);
        for (seq, data) in segments {
            let f = parse(&build_tcp_frame(client, server, 51234, 80, *seq, TCP_PSH | TCP_ACK, data));
            table.observe(&f, now, 2_000_000, &sig, &mut alerts);
        }
        alerts
    }

    /// A segment held back for a gap, then overlapped by data that fills
    /// the gap and runs past its start. Only the tail is new, and it must
    /// not be left stranded: the pending segment starts *before* the byte
    /// the stream now expects, so it can never be picked up by an exact
    /// sequence-number lookup, and everything after it would stall.
    #[test]
    fn a_pending_segment_overlapped_by_in_order_data_still_delivers_its_tail() {
        let rules = "tail|payload|any|literal|ATTACKDATA
";
        // Stream bytes 1000..: "xxxxx" + "ATTACKDATA". Deliver the second
        // half first, then a first segment that overlaps its start.
        let alerts = overlapping_stream(rules, &[(1008, b"ACKDATA"), (1000, b"xxxxxATTA")]);
        // "xxxxxATTA" ends at 1009, one byte past the pending segment's
        // start (1008): its first byte is a duplicate, and the remaining
        // "CKDATA" is the tail that has to be delivered.
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "the overlapped tail was never appended: {:?}", alerts.iter().map(|a| &a.message).collect::<Vec<_>>());
    }

    #[test]
    fn a_pending_segment_wholly_covered_by_later_data_is_discarded_cleanly() {
        let rules = "after|payload|any|literal|MARKER
";
        // The stranded segment sits inside the range the next one covers;
        // the stream carries on to the marker.
        let alerts = overlapping_stream(rules, &[(1003, b"cd"), (1000, b"abcdefMARKER")]);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "{:?}", alerts.len());
    }

    /// First data wins on a retransmission with different bytes, as it does
    /// for a segment that arrives in order. A pending segment must not be
    /// replaceable by a later copy, or which bytes the sensor sees would
    /// depend on delivery order.
    #[test]
    fn a_second_copy_of_a_pending_segment_does_not_replace_the_first() {
        let rules = "orig|payload|any|literal|GOODGOOD
";
        let alerts = overlapping_stream(rules, &[(1004, b"GOOD"), (1004, b"EVIL"), (1000, b"GOOD")]);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "the first copy should have been kept");
    }

    #[test]
    fn duplicate_matches_in_same_flow_alert_only_once() {
        let rules = ruleset_from("dup|payload|any|literal|REPEATED\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 3_000_000i64;

        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 9000, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let seg1 = parse(&build_tcp_frame(client, server, 51234, 80, 9001, TCP_PSH | TCP_ACK, b"REPEATED"));
        alerts.clear();
        table.observe(&seg1, now, now_sec, &sig, &mut alerts);
        assert_eq!(alerts.iter().filter(|a| a.category == "SIGNATURE_MATCH").count(), 1);

        let seg2 = parse(&build_tcp_frame(client, server, 51234, 80, 9009, TCP_PSH | TCP_ACK, b" more data"));
        alerts.clear();
        table.observe(&seg2, now, now_sec, &sig, &mut alerts);
        assert_eq!(alerts.iter().filter(|a| a.category == "SIGNATURE_MATCH").count(), 0, "should not re-alert for the same flow+signature");
    }

    #[test]
    fn http_uri_and_host_rules_match_via_reassembly() {
        let rules = ruleset_from("admin-panel|http.uri|to_server|literal|/admin\ninternal-host|http.host|to_server|literal|internal.corp\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 4_000_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 1, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let req = b"GET /admin HTTP/1.1\r\nHost: internal.corp\r\n\r\n";
        let seg = parse(&build_tcp_frame(client, server, 51234, 80, 2, TCP_PSH | TCP_ACK, req));
        alerts.clear();
        table.observe(&seg, now, now_sec, &sig, &mut alerts);

        let categories: Vec<_> = alerts.iter().map(|a| a.message.clone()).collect();
        assert_eq!(alerts.len(), 2, "expected both the URI and Host rule to match: {:?}", categories);
    }

    #[test]
    fn ftp_multiple_commands_in_one_session_all_get_checked() {
        let rules = ruleset_from("ftp-retr|ftp.command|to_server|regex|^RETR\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 5_000_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 21, 1, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let cmds = b"USER anonymous\r\nPASS x\r\nRETR file1.txt\r\nRETR file2.txt\r\n";
        let seg = parse(&build_tcp_frame(client, server, 51234, 21, 2, TCP_PSH | TCP_ACK, cmds));
        alerts.clear();
        table.observe(&seg, now, now_sec, &sig, &mut alerts);

        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH" && a.message.contains("ftp-retr")));
    }

    #[test]
    fn ssh_banner_matches_and_is_only_checked_once() {
        let rules = ruleset_from("old-ssh|ssh.version|to_server|regex|SSH-1\\.\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 6_000_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 22, 1, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let banner = b"SSH-1.5-legacy_client\r\n";
        let seg = parse(&build_tcp_frame(client, server, 51234, 22, 2, TCP_PSH | TCP_ACK, banner));
        alerts.clear();
        table.observe(&seg, now, now_sec, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"));
    }

    #[test]
    fn rdp_cookie_detected_via_reassembly() {
        let rules = ruleset_from("rdp-admin-attempt|rdp.cookie|to_server|regex|(?i)mstshash=administrator\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 10_000_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 3389, 1, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let frame = rdp_connection_request(Some("mstshash=Administrator"));
        let seg = parse(&build_tcp_frame(client, server, 51234, 3389, 2, TCP_PSH | TCP_ACK, &frame));
        alerts.clear();
        table.observe(&seg, now, now_sec, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "should detect the attempted-username cookie");
    }

    #[test]
    fn rdp_connection_request_split_across_two_segments_still_parses() {
        let rules = ruleset_from("rdp-cookie-seen|rdp.cookie|to_server|regex|mstshash\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 10_100_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 3389, 1, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let frame = rdp_connection_request(Some("mstshash=root"));
        let (first, second) = frame.split_at(10);

        let seg1 = parse(&build_tcp_frame(client, server, 51234, 3389, 2, TCP_PSH | TCP_ACK, first));
        alerts.clear();
        table.observe(&seg1, now, now_sec, &sig, &mut alerts);
        assert!(alerts.is_empty(), "an incomplete RDP CR must not match yet");

        let seg2 = parse(&build_tcp_frame(client, server, 51234, 3389, 2 + first.len() as u32, TCP_PSH | TCP_ACK, second));
        alerts.clear();
        table.observe(&seg2, now, now_sec, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "should match once the split message is complete");
    }

    /// Feeds `segments` as consecutive PSH/ACK payloads on one
    /// connection, returning the alerts raised by the final segment.
    fn alerts_for_split_stream(rules: RuleSet, port: u16, segments: &[&[u8]]) -> Vec<Alert> {
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 12_000_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, port, 1000, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let mut seq = 1001u32;
        for (i, seg) in segments.iter().enumerate() {
            let pkt = parse(&build_tcp_frame(client, server, 51234, port, seq, TCP_PSH | TCP_ACK, seg));
            alerts.clear();
            table.observe(&pkt, now, now_sec, &sig, &mut alerts);
            if i + 1 < segments.len() {
                assert!(alerts.is_empty(), "segment {} is incomplete and must not match yet", i);
            }
            seq += seg.len() as u32;
        }
        alerts
    }

    /// The headline regression: an HTTP request split *mid-URI* must
    /// still match both `http.uri` and `http.host`.
    ///
    /// Before the fix this produced no alerts whatsoever. The first
    /// segment parsed as a complete request with `uri: "/cgi-bin/../"`
    /// and no Host header, `scanned_http` latched on it, and the real
    /// URI and Host were never checked against anything — TCP
    /// segmentation alone defeating the very evasion that stream
    /// reassembly exists to defeat. Proven in the field by replaying
    /// byte-for-byte identical requests, one whole and one split.
    /// The method is its own buffer, so a rule can scope to it without
    /// resorting to an anchored match on the raw payload.
    #[test]
    fn the_http_method_is_matchable_as_its_own_buffer() {
        let rules = ruleset_from("post-only|http.method|to_server|literal|POST\n");
        let alerts = alerts_for_split_stream(rules, 80, &[b"POST /submit HTTP/1.1\r\nHost: h.example\r\n\r\n"]);
        assert!(alerts.iter().any(|a| a.message.contains("post-only")), "got {:?}", alerts.iter().map(|a| a.message.as_str()).collect::<Vec<_>>());

        let rules2 = ruleset_from("post-only|http.method|to_server|literal|POST\n");
        let alerts2 = alerts_for_split_stream(rules2, 80, &[b"GET /submit HTTP/1.1\r\nHost: h.example\r\n\r\n"]);
        assert!(alerts2.is_empty(), "a GET must not match a POST rule");
    }

    #[test]
    fn http_request_split_mid_uri_still_matches_uri_and_host() {
        let rules = ruleset_from(
            "trav-uri|http.uri|to_server|regex|\\.\\./\\.\\./\nbad-host|http.host|to_server|literal|evil-host.example\n",
        );
        let alerts = alerts_for_split_stream(
            rules,
            80,
            &[b"GET /cgi-bin/../", b"../etc/passwd HTTP/1.1\r\nHost: evil-host.example\r\n\r\n"],
        );
        let matched: Vec<&str> = alerts.iter().map(|a| a.message.as_str()).collect();
        assert!(matched.iter().any(|m| m.contains("trav-uri")), "http.uri should match the reassembled URI, got {:?}", matched);
        assert!(matched.iter().any(|m| m.contains("bad-host")), "http.host should match the reassembled Host, got {:?}", matched);
    }

    /// Same, for a ClientHello split immediately before its extensions —
    /// the split point at which the old parser returned a complete-looking
    /// result with no SNI and a JA3 built from an empty extension list.
    #[test]
    fn tls_client_hello_split_before_its_extensions_still_yields_the_sni() {
        let hostname = b"malicious-c2-domain.example";
        let hello = client_hello(hostname);
        let split_at = hello.len() - client_hello_extensions_len(hostname);
        let rules = ruleset_from("bad-sni|tls.sni|to_server|literal|malicious-c2-domain.example\n");
        let alerts = alerts_for_split_stream(rules, 443, &[&hello[..split_at], &hello[split_at..]]);
        assert!(
            alerts.iter().any(|a| a.message.contains("bad-sni")),
            "tls.sni should match once the whole ClientHello has arrived, got {:?}",
            alerts.iter().map(|a| a.message.as_str()).collect::<Vec<_>>()
        );
    }

    /// Same again for RDP, split *inside* the cookie.
    ///
    /// Note the existing `rdp_connection_request_split_across_two_segments_still_parses`
    /// above splits at byte 10, which lands in the X.224 fixed header —
    /// there the partial parse fails cleanly, the one-shot flag never
    /// latches, and the test passes even with the bug present. Splitting
    /// one byte later, inside the cookie, is what exposes it: that
    /// prefix parsed "successfully" with a truncated cookie. The
    /// difference between the two is the whole lesson.
    #[test]
    fn rdp_connection_request_split_mid_cookie_still_matches() {
        let msg = rdp_connection_request(Some("mstshash=Administrator"));
        let split_at = msg.windows(8).position(|w| w == b"mstshash").expect("cookie present") + 5;
        let rules = ruleset_from("rdp-admin|rdp.cookie|to_server|regex|(?i)mstshash=administrator\n");
        let alerts = alerts_for_split_stream(rules, 3389, &[&msg[..split_at], &msg[split_at..]]);
        assert!(
            alerts.iter().any(|a| a.message.contains("rdp-admin")),
            "rdp.cookie should match the reassembled cookie, got {:?}",
            alerts.iter().map(|a| a.message.as_str()).collect::<Vec<_>>()
        );
    }

    /// The accepted cost of requiring completeness, pinned down so it
    /// stays a deliberate trade rather than a surprise: a request whose
    /// header block overruns the reassembly budget never yields an
    /// `http.uri` match at all — there is no trustworthy URI to match
    /// against — but the raw `payload` buffer still covers those bytes,
    /// which is what keeps the trade acceptable.
    #[test]
    fn http_headers_overrunning_the_stream_cap_lose_http_buffers_but_not_payload() {
        let rules = ruleset_from("uri-rule|http.uri|to_server|literal|/secret\npayload-rule|payload|any|literal|X-Filler\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::with_stream_cap(512);
        let now = SystemTime::now();
        let now_sec = 13_000_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 1000, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        // A request line plus a header block far larger than the cap, so
        // the terminating blank line can never land in the buffer.
        let mut req = b"GET /secret HTTP/1.1\r\n".to_vec();
        while req.len() < 2048 {
            req.extend_from_slice(b"X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        let mut seq = 1001u32;
        for chunk in req.chunks(200) {
            let pkt = parse(&build_tcp_frame(client, server, 51234, 80, seq, TCP_PSH | TCP_ACK, chunk));
            table.observe(&pkt, now, now_sec, &sig, &mut alerts);
            seq += chunk.len() as u32;
        }

        let messages: Vec<&str> = alerts.iter().map(|a| a.message.as_str()).collect();
        assert!(messages.iter().any(|m| m.contains("payload-rule")), "the payload buffer should still match, got {:?}", messages);
        assert!(!messages.iter().any(|m| m.contains("uri-rule")), "an unterminated header block must not produce an http.uri match");
    }

    /// A SYN flood from spoofed sources creates a fresh `Flow` per
    /// packet, and every one of them is recent — so the idle sweep, which
    /// was the only limit here, released nothing and the table grew with
    /// the attack. At tens of millions of flows inside the 300-second
    /// timeout that is several GB, produced by one of the most ordinary
    /// attacks there is.
    #[test]
    fn the_flow_table_is_bounded_under_a_spoofed_source_syn_flood() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::with_limits(DEFAULT_STREAM_CAP, 128);
        let now = SystemTime::now();
        let now_sec = 5_000_000i64;
        let mut alerts = Vec::new();

        // 10_000 distinct source addresses, all at the same instant, so
        // recency can never release any of them.
        for i in 0..10_000u32 {
            let o = i.to_be_bytes();
            let syn = parse(&build_tcp_frame([o[1], o[2], o[3], 7], [10, 0, 0, 1], 40000, 80, 1000, TCP_SYN, &[]));
            table.observe(&syn, now, now_sec, &sig, &mut alerts);
        }

        assert!(table.tracked_flows() <= 128, "tracked {} flows against a cap of 128", table.tracked_flows());
        assert!(table.flows_refused() > 0, "refusals should be counted, not silent");
    }

    /// Refusal, not eviction, is the policy — and it matters which.
    /// If pressure evicted live entries, a flood of junk connections
    /// could push out the reassembly state of a real one, and the memory
    /// bound would have become an evasion primitive. Here an established
    /// flow keeps matching after the table has been hammered.
    #[test]
    fn pressure_does_not_evict_an_active_flow_mid_reassembly() {
        let rules = ruleset_from("split-sig|payload|any|literal|MALICIOUS_PAYLOAD\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::with_limits(DEFAULT_STREAM_CAP, 64);
        let now = SystemTime::now();
        let now_sec = 6_000_000i64;
        let mut alerts = Vec::new();

        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 1000, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);
        let seg1 = parse(&build_tcp_frame(client, server, 51234, 80, 1001, TCP_PSH | TCP_ACK, b"MALICIOUS_"));
        table.observe(&seg1, now, now_sec, &sig, &mut alerts);

        // Now fill the table well past its cap with unrelated junk.
        for i in 0..5_000u32 {
            let o = i.to_be_bytes();
            let junk = parse(&build_tcp_frame([o[1], o[2], o[3], 9], [10, 0, 0, 2], 40000, 80, 1, TCP_SYN, &[]));
            table.observe(&junk, now, now_sec, &sig, &mut alerts);
        }

        // The real connection's second half must still complete the match.
        alerts.clear();
        let seg2 = parse(&build_tcp_frame(client, server, 51234, 80, 1011, TCP_PSH | TCP_ACK, b"PAYLOAD"));
        table.observe(&seg2, now, now_sec, &sig, &mut alerts);
        assert!(
            alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"),
            "an in-progress flow must survive table pressure, or the bound becomes an evasion"
        );
    }

    /// Flow records must not be built when nothing is consuming them.
    ///
    /// `expire` pushed one unconditionally while the only drain sat
    /// behind `if flow_tx.is_some()`, so with `-flow-log` unset — the
    /// default — records accumulated forever: one per completed
    /// connection, each holding up to five `Option<String>`s, on a table
    /// that turns over constantly. The memory-bounds work earlier in the
    /// same round existed to remove exactly this failure mode, and the
    /// feature added two sections later put it back, which is why this
    /// test asserts on the pipeline's behaviour rather than on the
    /// bound of any single structure.
    #[test]
    fn flow_records_are_not_built_when_nothing_is_draining_them() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let mut alerts = Vec::new();

        // 3000 connections that each open and immediately close (FIN),
        // so every one of them leaves the table via `expire`. Nothing
        // ever calls `take_completed` — exactly what production does
        // when `-flow-log` is not passed, which is the default.
        for i in 0..3000u32 {
            let o = i.to_be_bytes();
            let src = [10, o[1], o[2], o[3]];
            let now_sec = 7_000_000i64 + i as i64;
            let syn = parse(&build_tcp_frame(src, [10, 0, 0, 1], 40000, 80, 1000, TCP_SYN, &[]));
            table.observe(&syn, now, now_sec, &sig, &mut alerts);
            let fin = parse(&build_tcp_frame(src, [10, 0, 0, 1], 40000, 80, 1001, TCP_FIN | TCP_ACK, &[]));
            table.observe(&fin, now, now_sec, &sig, &mut alerts);
        }

        assert_eq!(
            table.pending_records(),
            0,
            "undrained flow records accumulated ({}), which is an unbounded leak in the default configuration",
            table.pending_records()
        );
    }

    /// On a path with no flow state, a rule's `dst_port` must mean the
    /// packet's actual destination port.
    ///
    /// `Direction::Any` has to expand into both concrete directions for
    /// *lookup*, since nothing is stored under `Any` itself — but passing
    /// that expansion through as the *evaluation* direction made the
    /// `ToClient` half swap the addresses of a packet whose orientation
    /// was unknown. A rule reading `proto:udp; dst_port:53` therefore
    /// fired on DNS replies, where 53 is the source port: the field name
    /// said one thing and the matcher did another. Every UDP detection
    /// path is in this position, so this was the common case, not an
    /// edge one.
    #[test]
    fn a_rules_dst_port_is_not_swapped_when_the_caller_has_no_direction() {
        use crate::rules::{parse_rule, RuleSetV2};
        let set = RuleSetV2::build(vec![parse_rule(r#"rule sid:1; name:"dns53"; proto:udp; dst_port:53; buffer:dns.query; content:"evil";"#).unwrap()]).unwrap();

        // A DNS *reply*: source port 53, destination the client's port.
        let mut reply = Packet::default();
        reply.protocol = PROTO_UDP;
        reply.src = IpAddr::V4([10, 0, 0, 53]);
        reply.src_port = 53;
        reply.dst = IpAddr::V4([10, 0, 0, 5]);
        reply.dst_port = 51500;

        let mut out = Vec::new();
        // This is how every UDP path calls it: Direction::Any.
        for dir in [Direction::ToServer, Direction::ToClient] {
            set.check(&reply, dir, Direction::Any, Buffer::DnsQuery, b"evil.example", &mut MatchScratch::default(), None, &mut out);
        }
        assert!(out.is_empty(), "a dst_port:53 rule matched a packet whose *source* port is 53: {:?}", out);
    }

    /// Volumes, state and per-direction flags on a completed connection.
    ///
    /// Flow records had no unit tests at all when they landed — verified
    /// only end-to-end through a replay, which proves the output exists
    /// but not that the accounting is right.
    #[test]
    fn a_completed_flow_records_its_volumes_state_and_flags() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        table.enable_flow_records();
        let now = SystemTime::now();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 1000, TCP_SYN, &[]));
        table.observe(&syn, now, 1_000, &sig, &mut alerts);
        let req = parse(&build_tcp_frame(client, server, 51234, 80, 1001, TCP_PSH | TCP_ACK, b"GET / HTTP/1.1\r\nHost: h.example\r\n\r\n"));
        table.observe(&req, now, 1_000, &sig, &mut alerts);
        let resp = parse(&build_tcp_frame(server, client, 80, 51234, 5000, TCP_PSH | TCP_ACK, b"HTTP/1.1 200 OK"));
        table.observe(&resp, now, 1_001, &sig, &mut alerts);
        // Both directions must FIN before the connection counts as
        // closed — closing on the first one used to end the record early,
        // losing the peer's FIN and the final ACKs.
        let fin = parse(&build_tcp_frame(client, server, 51234, 80, 1100, TCP_FIN | TCP_ACK, &[]));
        table.observe(&fin, now, 1_002, &sig, &mut alerts);
        let fin_back = parse(&build_tcp_frame(server, client, 80, 51234, 5100, TCP_FIN | TCP_ACK, &[]));
        table.observe(&fin_back, now, 1_003, &sig, &mut alerts);
        // A later packet on another flow drives the time-gated sweep.
        let tick = parse(&build_tcp_frame([10, 0, 0, 77], server, 40077, 80, 1, TCP_SYN, &[]));
        table.observe(&tick, now, 1_004, &sig, &mut alerts);

        let mut records = Vec::new();
        table.take_completed(&mut records);
        assert_eq!(records.len(), 1, "a closed connection should produce exactly one record");
        let r = &records[0];

        // The originator is whoever ARGUS saw send first, which for a
        // connection observed from its SYN is the real client.
        assert_eq!(r.src, IpAddr::V4(client));
        assert_eq!(r.src_port, 51234);
        assert_eq!(r.dst_port, 80);
        assert_eq!(r.state, "closed");
        assert_eq!(r.pkts_to_server, 3, "SYN + request + FIN");
        assert_eq!(r.pkts_to_client, 2, "response + the peer's FIN, which a first-FIN close would have missed");
        // Frame bytes, not payload bytes: payload is capped by
        // -payload-cap and would under-report volume.
        assert_eq!(r.bytes_to_server, (syn.frame_len + req.frame_len + fin.frame_len) as u64);
        assert_eq!(r.bytes_to_client, (resp.frame_len + fin_back.frame_len) as u64);
        assert!(r.flags_to_server & TCP_SYN != 0 && r.flags_to_server & TCP_FIN != 0);
        assert_eq!(r.http_host.as_deref(), Some("h.example"));
        assert_eq!(r.http_uri.as_deref(), Some("/"));
    }

    /// A reset connection reports `reset`, not `closed` — the difference
    /// is exactly what distinguishes a refused probe from a real session.
    #[test]
    fn a_reset_connection_is_recorded_as_reset() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        table.enable_flow_records();
        let now = SystemTime::now();
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 40000, 81, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 2_000, &sig, &mut alerts);
        let rst = parse(&build_tcp_frame([10, 0, 0, 1], [10, 0, 0, 5], 81, 40000, 1, TCP_RST | TCP_ACK, &[]));
        table.observe(&rst, now, 2_000, &sig, &mut alerts);
        // A closed flow's record is emitted by the next sweep, which is
        // time-gated to at most once per capture-time second, so the
        // record materialises on the following second rather than the
        // instant the RST arrives. That's a deliberate property of the
        // sweep, not of the record — but it does mean a connection log
        // entry lags its connection by up to a second.
        let unrelated = parse(&build_tcp_frame([10, 0, 0, 9], [10, 0, 0, 1], 40009, 81, 1, TCP_SYN, &[]));
        table.observe(&unrelated, now, 2_001, &sig, &mut alerts);

        let mut records = Vec::new();
        table.take_completed(&mut records);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, "reset");
        assert_eq!(records[0].pkts_to_client, 1, "the RST came back from the server");
    }

    /// An idle connection times out and says so, rather than vanishing.
    #[test]
    fn an_idle_connection_is_recorded_as_a_timeout() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        table.enable_flow_records();
        let now = SystemTime::now();
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 40001, 82, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 3_000, &sig, &mut alerts);
        // A later packet on an unrelated flow drives the time-gated sweep
        // past the idle timeout.
        let other = parse(&build_tcp_frame([10, 0, 0, 6], [10, 0, 0, 1], 40002, 83, 1, TCP_SYN, &[]));
        table.observe(&other, now, 3_000 + FLOW_IDLE_TIMEOUT_SECS + 1, &sig, &mut alerts);

        let mut records = Vec::new();
        table.take_completed(&mut records);
        assert_eq!(records.len(), 1, "the idle flow should have been swept");
        assert_eq!(records[0].state, "timeout");
        assert_eq!(records[0].src_port, 40001);
    }

    /// Connections still open at shutdown are facts about the capture
    /// too, so they're flushed with `open` rather than dropped.
    #[test]
    fn open_flows_are_flushed_at_shutdown() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        table.enable_flow_records();
        let now = SystemTime::now();
        let mut alerts = Vec::new();
        let syn = parse(&build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 40003, 84, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 4_000, &sig, &mut alerts);

        let mut records = Vec::new();
        let mut flush_alerts = Vec::new();
        table.flush_open_flows(&mut records, &mut flush_alerts);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, "open");
    }

    /// The record's JSON has to carry the fields a consumer pivots on.
    #[test]
    fn flow_record_json_is_well_formed_and_carries_the_metadata() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        table.enable_flow_records();
        let now = SystemTime::now();
        let mut alerts = Vec::new();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        let syn = parse(&build_tcp_frame(client, server, 51299, 80, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 5_000, &sig, &mut alerts);
        let req = parse(&build_tcp_frame(client, server, 51299, 80, 2, TCP_PSH | TCP_ACK, b"GET /a?b=c HTTP/1.1\r\nHost: json.example\r\n\r\n"));
        table.observe(&req, now, 5_000, &sig, &mut alerts);
        let fin = parse(&build_tcp_frame(client, server, 51299, 80, 50, TCP_FIN | TCP_ACK, &[]));
        table.observe(&fin, now, 5_000, &sig, &mut alerts);
        let fin_back = parse(&build_tcp_frame(server, client, 80, 51299, 900, TCP_FIN | TCP_ACK, &[]));
        table.observe(&fin_back, now, 5_000, &sig, &mut alerts);
        // See the note in `a_reset_connection_is_recorded_as_reset`:
        // the sweep that emits the record runs at most once per second.
        let unrelated = parse(&build_tcp_frame([10, 0, 0, 9], server, 40009, 80, 1, TCP_SYN, &[]));
        table.observe(&unrelated, now, 5_001, &sig, &mut alerts);

        let mut records = Vec::new();
        table.take_completed(&mut records);
        assert_eq!(records.len(), 1, "expected the closed flow's record");
        let json = records[0].to_json();
        for needle in [
            "\"src\":\"10.0.0.5\"",
            "\"dst_port\":80",
            "\"proto\":\"TCP\"",
            "\"state\":\"closed\"",
            "\"http_host\":\"json.example\"",
            "\"http_uri\":\"/a?b=c\"",
            "\"flags_to_server\":\"S",
        ] {
            assert!(json.contains(needle), "missing {:?} in {}", needle, json);
        }
        // Absent metadata must be omitted rather than emitted as null,
        // so a consumer can test for presence.
        assert!(!json.contains("tls_sni"), "unset fields should be omitted: {}", json);
    }

    /// One side finished and the other never did. Distinct from a clean
    /// close, and worth reporting as such: it's what an aborted transfer
    /// and a long-lived half-open session both look like.
    #[test]
    fn a_one_sided_fin_is_recorded_as_half_closed_after_the_timeout() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        table.enable_flow_records();
        let now = SystemTime::now();
        let mut alerts = Vec::new();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        let syn = parse(&build_tcp_frame(client, server, 51301, 80, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 6_000, &sig, &mut alerts);
        let fin = parse(&build_tcp_frame(client, server, 51301, 80, 2, TCP_FIN | TCP_ACK, &[]));
        table.observe(&fin, now, 6_000, &sig, &mut alerts);

        // Still tracked: the peer might yet reply, which is the whole
        // point of not closing on the first FIN.
        let mut records = Vec::new();
        table.take_completed(&mut records);
        assert!(records.is_empty(), "a half-closed flow is not finished");

        // Only the idle timeout collects it.
        let tick = parse(&build_tcp_frame([10, 0, 0, 78], server, 40078, 80, 1, TCP_SYN, &[]));
        table.observe(&tick, now, 6_000 + FLOW_IDLE_TIMEOUT_SECS + 1, &sig, &mut alerts);
        table.take_completed(&mut records);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, "half_closed");
    }

    /// Traffic on a well-known port that never parses as that port's
    /// protocol is itself a finding.
    ///
    /// The parsers could always tell — they return `None` on anything
    /// malformed — and nothing ever said so, so a tunnel or a backdoor
    /// listening on 443 produced no signal at all.
    #[test]
    fn traffic_that_is_not_its_ports_protocol_is_flagged() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let mut alerts = Vec::new();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        // 400 bytes of something that is emphatically not a TLS
        // ClientHello, to port 443.
        let syn = parse(&build_tcp_frame(client, server, 51400, 443, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 7_000, &sig, &mut alerts);
        let junk = vec![0x41u8; 400];
        let data = parse(&build_tcp_frame(client, server, 51400, 443, 2, TCP_PSH | TCP_ACK, &junk));
        table.observe(&data, now, 7_000, &sig, &mut alerts);
        // The RST closes the connection, and a closed flow is retired on
        // the spot rather than at the next sweep — so the alert arrives
        // with this packet.
        alerts.clear();
        let rst = parse(&build_tcp_frame(client, server, 51400, 443, 402, TCP_RST, &[]));
        table.observe(&rst, now, 7_000, &sig, &mut alerts);
        assert!(
            alerts.iter().any(|a| a.category == "PROTOCOL_ANOMALY" && a.port == 443),
            "expected a protocol anomaly on 443, got {:?}",
            alerts.iter().map(|a| a.category).collect::<Vec<_>>()
        );
    }

    /// And must not fire on a connection that genuinely spoke the
    /// protocol, nor on one that carried almost nothing.
    #[test]
    fn a_well_formed_or_empty_connection_is_not_a_protocol_anomaly() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let mut alerts = Vec::new();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        // A real HTTP request to port 80, padded past the byte floor.
        let syn = parse(&build_tcp_frame(client, server, 51401, 80, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 8_000, &sig, &mut alerts);
        let mut req = b"GET /ok HTTP/1.1\r\nHost: fine.example\r\nX-Pad: ".to_vec();
        req.extend_from_slice(&[b'p'; 200]);
        req.extend_from_slice(b"\r\n\r\n");
        let data = parse(&build_tcp_frame(client, server, 51401, 80, 2, TCP_PSH | TCP_ACK, &req));
        table.observe(&data, now, 8_000, &sig, &mut alerts);

        // A refused connection to 443: SYN and RST only, no payload.
        let syn2 = parse(&build_tcp_frame(client, server, 51402, 443, 1, TCP_SYN, &[]));
        table.observe(&syn2, now, 8_000, &sig, &mut alerts);
        let rst2 = parse(&build_tcp_frame(server, client, 443, 51402, 1, TCP_RST | TCP_ACK, &[]));
        table.observe(&rst2, now, 8_000, &sig, &mut alerts);

        alerts.clear();
        let tick = parse(&build_tcp_frame([10, 0, 0, 80], server, 40080, 80, 1, TCP_SYN, &[]));
        table.observe(&tick, now, 8_000 + FLOW_IDLE_TIMEOUT_SECS + 1, &sig, &mut alerts);
        assert!(
            !alerts.iter().any(|a| a.category == "PROTOCOL_ANOMALY"),
            "got {:?}",
            alerts.iter().map(|a| (a.category, a.port)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn smtp_sender_and_recipient_buffers_match_independently() {
        let rules = ruleset_from("bad-sender|smtp.sender|to_server|literal|spammer@evil.example\nbad-recipient|smtp.recipient|to_server|literal|admin@internal.corp\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 7_000_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 25, 1, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let cmds = b"EHLO evil.example\r\nMAIL FROM:<spammer@evil.example>\r\nRCPT TO:<admin@internal.corp>\r\n";
        let seg = parse(&build_tcp_frame(client, server, 51234, 25, 2, TCP_PSH | TCP_ACK, cmds));
        alerts.clear();
        table.observe(&seg, now, now_sec, &sig, &mut alerts);

        assert_eq!(alerts.iter().filter(|a| a.category == "SIGNATURE_MATCH").count(), 2, "expected both sender and recipient rules to match");
    }

    fn wrap_smb2_frame(msg: &[u8]) -> Vec<u8> {
        let len = msg.len();
        let mut framed = vec![0u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        framed.extend_from_slice(msg);
        framed
    }

    fn build_smb2_create_message(filename: &str) -> Vec<u8> {
        let mut msg = vec![0u8; 64];
        msg[0..4].copy_from_slice(b"\xFESMB");
        msg[4..6].copy_from_slice(&64u16.to_le_bytes());
        msg[12..14].copy_from_slice(&0x0005u16.to_le_bytes()); // CREATE
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        let name_utf16: Vec<u8> = filename.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_offset: u16 = 64 + 56;
        body[44..46].copy_from_slice(&name_offset.to_le_bytes());
        body[46..48].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        body.extend_from_slice(&name_utf16);
        msg.extend_from_slice(&body);
        msg
    }

    fn build_modbus_frame(pdu: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 7];
        frame[0..2].copy_from_slice(&1u16.to_be_bytes()); // transaction id, arbitrary
        // protocol id (bytes 2..4) left as 0, as every real Modbus message has it
        let length = (1 + pdu.len()) as u16; // unit id + pdu
        frame[4..6].copy_from_slice(&length.to_be_bytes());
        frame[6] = 1; // unit id, arbitrary
        frame.extend_from_slice(pdu);
        frame
    }

    #[test]
    fn smb2_create_detected_via_reassembly() {
        let rules = ruleset_from("smb-sensitive-share|smb.filename|to_server|regex|(?i)admin\\$\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 8_000_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 445, 1, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let frame = wrap_smb2_frame(&build_smb2_create_message("ADMIN$\\evil.exe"));
        let seg = parse(&build_tcp_frame(client, server, 51234, 445, 2, TCP_PSH | TCP_ACK, &frame));
        alerts.clear();
        table.observe(&seg, now, now_sec, &sig, &mut alerts);

        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "should detect access to the ADMIN$ share via the SMB2 filename buffer");
    }

    #[test]
    fn smb2_message_split_across_two_segments_still_parses() {
        // The same evasion-resistance property FTP/SMTP and raw payload
        // matching already have, now for SMB2's length-prefixed binary
        // framing: a message split mid-frame across two TCP segments
        // must still be recognized once it's complete, not silently
        // dropped because neither segment alone looked like a full
        // SMB2 message.
        let rules = ruleset_from("smb-create|smb.command|to_server|literal|CREATE\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let now_sec = 8_100_000i64;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 445, 1, TCP_SYN, &[]));
        table.observe(&syn, now, now_sec, &sig, &mut alerts);

        let frame = wrap_smb2_frame(&build_smb2_create_message("file.txt"));
        let (first, second) = frame.split_at(30);

        let seg1 = parse(&build_tcp_frame(client, server, 51234, 445, 2, TCP_PSH | TCP_ACK, first));
        alerts.clear();
        table.observe(&seg1, now, now_sec, &sig, &mut alerts);
        assert!(alerts.is_empty(), "an incomplete SMB2 message must not match yet");

        let seg2 = parse(&build_tcp_frame(client, server, 51234, 445, 2 + first.len() as u32, TCP_PSH | TCP_ACK, second));
        alerts.clear();
        table.observe(&seg2, now, now_sec, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "should match once the split message is complete");
    }

    #[test]
    fn modbus_write_detected_only_on_the_modbus_port() {
        let rules = ruleset_from("modbus-write|modbus.function|to_server|literal|WRITE_SINGLE_REGISTER\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let now = SystemTime::now();
        let pdu = [0x06, 0x00, 0x2A, 0x00, 0x64]; // WRITE_SINGLE_REGISTER, addr 0x2A
        let frame = build_modbus_frame(&pdu);

        // On port 502 (Modbus's well-known port): should fire.
        let mut table = FlowTable::new();
        let mut alerts = Vec::new();
        let syn = parse(&build_tcp_frame(client, server, 51234, 502, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 8_200_000, &sig, &mut alerts);
        let seg = parse(&build_tcp_frame(client, server, 51234, 502, 2, TCP_PSH | TCP_ACK, &frame));
        alerts.clear();
        table.observe(&seg, now, 8_200_000, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "identical bytes on port 502 should be recognized as Modbus");

        // Identical bytes on an unrelated port: should NOT fire — Modbus
        // has no signature worth content-sniffing on, so this is
        // deliberately gated by port, unlike every other protocol here.
        let mut table2 = FlowTable::new();
        let mut alerts2 = Vec::new();
        let syn2 = parse(&build_tcp_frame(client, server, 51234, 8080, 1, TCP_SYN, &[]));
        table2.observe(&syn2, now, 8_300_000, &sig, &mut alerts2);
        let seg2 = parse(&build_tcp_frame(client, server, 51234, 8080, 2, TCP_PSH | TCP_ACK, &frame));
        alerts2.clear();
        table2.observe(&seg2, now, 8_300_000, &sig, &mut alerts2);
        assert!(!alerts2.iter().any(|a| a.category == "SIGNATURE_MATCH"), "identical bytes on a non-Modbus port should not be parsed as Modbus");
    }

    #[test]
    fn modbus_address_buffer_matches_the_write_target() {
        let rules = ruleset_from("critical-register|modbus.address|to_server|literal|42\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 502, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 8_400_000, &sig, &mut alerts);

        let pdu = [0x06, 0x00, 0x2A, 0x00, 0x64]; // address 0x2A = 42 decimal
        let frame = build_modbus_frame(&pdu);
        let seg = parse(&build_tcp_frame(client, server, 51234, 502, 2, TCP_PSH | TCP_ACK, &frame));
        alerts.clear();
        table.observe(&seg, now, 8_400_000, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "should match a rule against the decimal-formatted write address");
    }

    fn build_dnp3_frame(user_data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x05, 0x64, (5 + user_data.len()) as u8];
        frame.push(0xC4);
        frame.extend_from_slice(&[0x01, 0x00]);
        frame.extend_from_slice(&[0x02, 0x00]);
        frame.extend_from_slice(&[0, 0]);
        for chunk in user_data.chunks(16) {
            frame.extend_from_slice(chunk);
            frame.extend_from_slice(&[0, 0]);
        }
        frame
    }

    #[test]
    fn dnp3_operate_detected_only_on_the_dnp3_port() {
        let rules = ruleset_from("dnp3-operate|dnp3.function|to_server|literal|OPERATE\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let now = SystemTime::now();
        let frame = build_dnp3_frame(&[0xC0, 0xC0, 0x04]); // OPERATE

        // On port 20000 (DNP3's well-known port): should fire.
        let mut table = FlowTable::new();
        let mut alerts = Vec::new();
        let syn = parse(&build_tcp_frame(client, server, 51234, 20000, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 8_500_000, &sig, &mut alerts);
        let seg = parse(&build_tcp_frame(client, server, 51234, 20000, 2, TCP_PSH | TCP_ACK, &frame));
        alerts.clear();
        table.observe(&seg, now, 8_500_000, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "identical bytes on port 20000 should be recognized as DNP3");

        // Identical bytes on an unrelated port: should NOT fire — same
        // port-gating reasoning as Modbus.
        let mut table2 = FlowTable::new();
        let mut alerts2 = Vec::new();
        let syn2 = parse(&build_tcp_frame(client, server, 51234, 8080, 1, TCP_SYN, &[]));
        table2.observe(&syn2, now, 8_600_000, &sig, &mut alerts2);
        let seg2 = parse(&build_tcp_frame(client, server, 51234, 8080, 2, TCP_PSH | TCP_ACK, &frame));
        alerts2.clear();
        table2.observe(&seg2, now, 8_600_000, &sig, &mut alerts2);
        assert!(!alerts2.iter().any(|a| a.category == "SIGNATURE_MATCH"), "identical bytes on a non-DNP3 port should not be parsed as DNP3");
    }

    #[test]
    fn dnp3_frame_split_across_two_segments_still_parses() {
        let rules = ruleset_from("dnp3-operate|dnp3.function|to_server|literal|OPERATE\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let mut table = FlowTable::new();
        let now = SystemTime::now();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let mut alerts = Vec::new();

        let syn = parse(&build_tcp_frame(client, server, 51234, 20000, 1, TCP_SYN, &[]));
        table.observe(&syn, now, 8_700_000, &sig, &mut alerts);

        let frame = build_dnp3_frame(&[0xC0, 0xC0, 0x04]); // OPERATE
        let (first, second) = frame.split_at(6);

        let seg1 = parse(&build_tcp_frame(client, server, 51234, 20000, 2, TCP_PSH | TCP_ACK, first));
        alerts.clear();
        table.observe(&seg1, now, 8_700_000, &sig, &mut alerts);
        assert!(alerts.is_empty(), "an incomplete DNP3 frame must not match yet");

        let seg2 = parse(&build_tcp_frame(client, server, 51234, 20000, 2 + first.len() as u32, TCP_PSH | TCP_ACK, second));
        alerts.clear();
        table.observe(&seg2, now, 8_700_000, &sig, &mut alerts);
        assert!(alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "should match once the split frame is complete");
    }

    #[test]
    fn stream_cap_is_configurable_and_actually_enforced() {
        // Proves -stream-cap isn't just a config field that gets
        // threaded through and ignored: reassembly with a small custom
        // cap must genuinely stop retaining bytes at that boundary, not
        // the default.
        let rules = ruleset_from("late-signature|payload|any|literal|FOUND_ME\n");
        let sig = SignatureEngine { blacklist: Default::default(), rules };
        let now = SystemTime::now();
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        let mut padding = vec![b'A'; 100];
        padding.extend_from_slice(b"FOUND_ME");

        // With a cap smaller than the padding, the signature (which only
        // appears after it) must never be seen.
        let mut small_cap_table = FlowTable::with_stream_cap(50);
        let mut alerts = Vec::new();
        let syn = parse(&build_tcp_frame(client, server, 51234, 80, 1, TCP_SYN, &[]));
        small_cap_table.observe(&syn, now, 9_000_000, &sig, &mut alerts);
        let seg = parse(&build_tcp_frame(client, server, 51234, 80, 2, TCP_PSH | TCP_ACK, &padding));
        alerts.clear();
        small_cap_table.observe(&seg, now, 9_000_000, &sig, &mut alerts);
        assert!(!alerts.iter().any(|a| a.category == "SIGNATURE_MATCH"), "a small stream cap should genuinely cut off the buffer before the signature");

        // With a cap larger than the padding, it must be seen.
        let mut large_cap_table = FlowTable::with_stream_cap(1024);
        let mut alerts2 = Vec::new();
        let syn2 = parse(&build_tcp_frame(client, server, 51234, 80, 1, TCP_SYN, &[]));
        large_cap_table.observe(&syn2, now, 9_100_000, &sig, &mut alerts2);
        let seg2 = parse(&build_tcp_frame(client, server, 51234, 80, 2, TCP_PSH | TCP_ACK, &padding));
        alerts2.clear();
        large_cap_table.observe(&seg2, now, 9_100_000, &sig, &mut alerts2);
        assert!(alerts2.iter().any(|a| a.category == "SIGNATURE_MATCH"), "a large enough stream cap should still catch the same signature");
    }

    /// A connection that outlasts the window must be judged while it runs.
    #[test]
    fn a_long_connection_reports_its_bytes_while_it_is_open_and_never_twice() {
        let sig = SignatureEngine { blacklist: Default::default(), rules: RuleSet::empty() };
        let mut table = FlowTable::new();
        table.enable_flow_records();
        let mut alerts = Vec::new();
        let (client, server) = ([10, 0, 0, 5], [10, 0, 0, 1]);
        let base = 2_000_000i64;
        let at = |sec: i64| UNIX_EPOCH + Duration::from_secs(sec as u64);
        let syn = parse(&build_tcp_frame(client, server, 51234, 443, 1000, TCP_SYN, &[]));
        table.observe(&syn, at(base), base, &sig, &mut alerts);
        // Two minutes of steady upload: one 1400-byte segment a second.
        let mut seq = 1001u32;
        for i in 1..=120 {
            let f = parse(&build_tcp_frame(client, server, 51234, 443, seq, TCP_PSH | TCP_ACK, &[b'x'; 1400]));
            seq += 1400;
            table.observe(&f, at(base + i), base + i, &sig, &mut alerts);
        }
        let mut obs = Vec::new();
        table.take_observations(&mut obs);
        let mid: u64 = obs.iter().filter_map(|o| if let crate::behavior::Observation::Traffic { bytes_out, .. } = o { Some(*bytes_out) } else { None }).sum();
        assert!(mid > 100_000, "reported while still open: {} bytes", mid);
        assert!(!obs.iter().any(|o| matches!(o, crate::behavior::Observation::Flow { .. })), "the connection has not ended");

        // When it ends, the final report carries only the remainder: the
        // whole is counted exactly once.
        let mut records = Vec::new();
        table.flush_open_flows(&mut records, &mut alerts);
        table.take_observations(&mut obs);
        let total: u64 = obs
            .iter()
            .map(|o| match o {
                crate::behavior::Observation::Traffic { bytes_out, .. } | crate::behavior::Observation::Flow { bytes_out, .. } => *bytes_out,
                _ => 0,
            })
            .sum();
        let sent = records.iter().map(|r| r.bytes_to_server).sum::<u64>();
        assert_eq!(total, sent, "every byte reported once");
    }

}