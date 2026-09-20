use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argus::behavior::{run_behavior_engine, BehaviorConfig, Observation};
use argus::engine::ScanScratch;
use argus::engine::{AlertWriterConfig, Severity, 
    parse_dns_query, parse_snmp_community, parse_tftp_packet, run_alert_writer, run_flow_writer, signature_alert, Alert, AlertStats, AnomalyConfig,
    AnomalyEngine, Buffer, DatagramFlows, Direction, FlowRecord, FlowTable, PcapDumpRequest, SignatureEngine,
};
use argus::config;
use argus::decode::{DecodeStats, Decoded, Decoder, DefragLimits, FragPolicy, LinkType, DEFAULT_PAYLOAD_CAP};
use argus::intel::{Intel, IntelSeen, IntelSources};
use argus::metrics::{Metrics, MetricsServer};
use argus::output::{FileSink, Format, Output, Sink, SyslogSink, WriterSink};
use argus::reload::{Cached, Hot, Signals, Watch};
use argus::packet::{IpAddr, Packet, MAX_INSPECT_BYTES, PROTO_TCP, PROTO_UDP};
use argus::quic::{looks_like_quic_initial, QuicSessions};

struct Args {
    /// Interfaces to monitor. Repeatable: one process, one worker pool,
    /// several links. Mutually exclusive with `pcap_file`.
    ifaces: Vec<String>,
    /// A saved capture to replay instead of listening on a live
    /// interface (`-r`). Mutually exclusive with `ifaces`; exactly one of
    /// the two is required.
    pcap_file: Option<String>,
    /// Whether `-pcap-retain` was passed explicitly, as opposed to left
    /// at its default. Only consulted in replay mode, which defaults
    /// pcap-on-alert *off* — see `main`.
    pcap_retain_explicit: bool,
    /// BPF capture filter, compiled by libpcap and applied in the kernel.
    filter: Option<String>,
    /// How much of each packet's payload detection may see.
    payload_cap: usize,
    /// Per-worker caps on the tables an attacker can grow.
    max_sources: usize,
    max_flows: usize,
    /// Alert-channel depth. Bounded, so an alert storm can't grow memory
    /// without limit.
    alert_queue: usize,
    /// Where to write the connection log (NDJSON), if anywhere.
    flow_log: Option<String>,
    /// Behavioural detection: scans across hosts, brute force, beaconing,
    /// exfiltration volume, DNS tunnelling.
    behavior: bool,
    /// Sliding window the behavioural detectors judge over.
    behavior_window: Duration,
    /// How many packet buffers are recycled between the capture thread
    /// and the workers. This, not the queue depth, is what bounds packet
    /// memory now.
    packet_pool: usize,
    /// Which copy wins when fragments overlap.
    frag_policy: FragPolicy,
    blacklist: Option<String>,
    rules: Option<String>,
    window: Duration,
    rate_threshold: u32,
    scan_threshold: usize,
    suppress_window: Duration,
    workers: usize,
    queue_size: usize,
    stream_cap: usize,
    list_interfaces: bool,
    /// A rule file to validate rather than run.
    check_rules: Option<String>,
    pcap_dir: String,
    pcap_retain: usize,

    // --- output ---
    /// Format for stdout, and the default for the alert log.
    format: Format,
    logfile: String,
    /// Format for the alert log, when it should differ from `format`.
    log_format: Option<Format>,
    /// Bytes before the alert log rotates itself. 0 leaves rotation to
    /// an external tool plus `SIGHUP`.
    log_max_size: u64,
    log_keep: usize,
    /// Suppress the stdout sink, for a service with nowhere to print.
    no_stdout: bool,
    /// Extra `<format>:<path>` sinks.
    alert_outputs: Vec<String>,
    /// `[udp|tcp]://host:port`.
    syslog: Option<String>,
    syslog_format: Format,
    syslog_facility: u8,

    // --- operations ---
    /// `host:port` for the Prometheus endpoint.
    metrics: Option<String>,
    /// Config file, or `None` to search the conventional locations.
    config: Option<String>,
    generate_config: bool,
    /// How often watched files are checked for changes. 0 disables
    /// file-driven reloads, leaving only `SIGHUP`.
    reload_interval: Duration,

    // --- enrichment ---
    intel: Vec<String>,
    allowlist: Vec<String>,
    home_net: Vec<String>,
}

impl Default for Args {
    fn default() -> Self {
        let default_anom = AnomalyConfig::default();
        Args {
            ifaces: Vec::new(),
            pcap_file: None,
            pcap_retain_explicit: false,
            filter: None,
            payload_cap: DEFAULT_PAYLOAD_CAP,
            max_sources: default_anom.max_sources,
            max_flows: 65536,
            alert_queue: 16384,
            flow_log: None,
            behavior: true,
            behavior_window: Duration::from_secs(300),
            packet_pool: 4096,
            frag_policy: FragPolicy::FirstWins,
            blacklist: None,
            rules: None,
            window: default_anom.window,
            rate_threshold: default_anom.packet_rate_pps,
            scan_threshold: default_anom.port_scan_limit,
            suppress_window: Duration::from_secs(15),
            workers: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
            queue_size: 1024,
            stream_cap: 16384,
            list_interfaces: false,
            check_rules: None,
            pcap_dir: "logs".to_string(),
            pcap_retain: 500,

            format: Format::Text,
            logfile: "argus-alerts.log".to_string(),
            log_format: None,
            log_max_size: 0,
            log_keep: 5,
            no_stdout: false,
            alert_outputs: Vec::new(),
            syslog: None,
            syslog_format: Format::Json,
            syslog_facility: 16,

            metrics: None,
            config: None,
            generate_config: false,
            reload_interval: Duration::from_secs(5),

            intel: Vec::new(),
            allowlist: Vec::new(),
            home_net: Vec::new(),
        }
    }
}

/// Whether an option consumes the next argument.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// `-flag`, or `flag = true` in a config file.
    Flag,
    /// `-key value`, or `key = value`.
    Value,
}

/// Every option: its name, whether it takes a value, its default as it
/// would be written in a config file, and what it does.
///
/// One table, four consumers — the command-line parser, the config-file
/// loader, `-help`, and `-generate-config`. The alternative is four
/// lists that drift, and the way they drift is that an option works on
/// the command line and silently does nothing in the file.
const OPTIONS: &[(&str, Kind, &str, &str)] = &[
    // --- input ---
    ("iface", Kind::Value, "", "interface to monitor; repeatable to watch several links in one process"),
    ("r", Kind::Value, "", "replay a saved capture instead of listening live (also -read)"),
    ("filter", Kind::Value, "", "BPF filter, applied in the kernel before ARGUS sees anything (also -bpf)"),
    ("list-interfaces", Kind::Flag, "", "list capture-able interfaces and exit"),
    ("check-rules", Kind::Value, "", "validate a rule file, print every rule ARGUS would refuse and why, and exit"),
    // --- detection ---
    ("rules", Kind::Value, "", "rule file, v1 and v2 syntax (also -signatures)"),
    ("blacklist", Kind::Value, "", "IP blacklist, one address per line"),
    ("window", Kind::Value, "10s", "sliding window for anomaly thresholds"),
    ("rate-threshold", Kind::Value, "500", "packets per SECOND before PACKET_FLOOD; independent of -window"),
    ("scan-threshold", Kind::Value, "20", "distinct ports per window before PORT_SCAN"),
    ("no-behavior", Kind::Flag, "false", "disable behavioural detection (scans, brute force, beaconing, exfil, DNS tunnels)"),
    ("behavior-window", Kind::Value, "5m", "window the behavioural detectors judge over"),
    ("frag-policy", Kind::Value, "first", "which copy wins when IP fragments overlap: 'first' (BSD/Linux) or 'last' (Windows)"),
    // --- enrichment ---
    ("intel", Kind::Value, "", "reputation feed: addresses, CIDRs, domains or JA3 hashes. Repeatable"),
    ("allowlist", Kind::Value, "", "alerts to stop reporting, one entry per line. Repeatable"),
    ("home-net", Kind::Value, "", "CIDRs considered inside, for alert direction. Repeatable, comma-separated"),
    // --- output ---
    ("format", Kind::Value, "text", "stdout and default log format: text, json or eve"),
    ("json", Kind::Flag, "false", "shorthand for -format json"),
    ("logfile", Kind::Value, "argus-alerts.log", "alert log path"),
    ("log-format", Kind::Value, "", "format for the alert log, when it differs from -format"),
    ("log-max-size", Kind::Value, "0", "bytes before the alert log rotates itself; 0 leaves rotation to logrotate"),
    ("log-keep", Kind::Value, "5", "rotated generations to keep"),
    ("no-stdout", Kind::Flag, "false", "do not write alerts to stdout"),
    ("alert-output", Kind::Value, "", "an extra sink as <format>:<path>, e.g. eve:/var/log/argus.eve. Repeatable"),
    ("syslog", Kind::Value, "", "syslog collector as [udp|tcp]://host:port"),
    ("syslog-format", Kind::Value, "json", "format for syslog messages"),
    ("syslog-facility", Kind::Value, "16", "syslog facility number (16 = local0)"),
    ("suppress-window", Kind::Value, "15s", "collapse duplicate alerts within this window"),
    ("flow-log", Kind::Value, "", "NDJSON connection record for every TCP, UDP and ICMP conversation"),
    ("pcap-dir", Kind::Value, "logs", "directory for the .pcap saved around each alert"),
    ("pcap-retain", Kind::Value, "500", "packets of recent traffic kept ready to dump; 0 disables"),
    // --- operations ---
    ("config", Kind::Value, "", "configuration file; otherwise ./argus.conf then /etc/argus/argus.conf"),
    ("generate-config", Kind::Flag, "", "print an annotated configuration file and exit"),
    ("metrics", Kind::Value, "", "host:port for the Prometheus endpoint, e.g. 127.0.0.1:9109"),
    ("reload-interval", Kind::Value, "5s", "how often to check rule and intel files for changes; 0 disables"),
    // --- resources ---
    ("workers", Kind::Value, "", "parallel detection workers (default: CPU count)"),
    ("packet-pool", Kind::Value, "4096", "recycled packet buffers; this is what bounds packet memory"),
    ("queue-size", Kind::Value, "1024", "per-worker queue depth; a slot holds a pointer, not a packet"),
    ("alert-queue", Kind::Value, "16384", "alert channel depth before alerts are shed"),
    ("payload-cap", Kind::Value, "9216", "how much of each payload detection may see; lowering it cuts CPU, not memory"),
    ("stream-cap", Kind::Value, "16384", "reassembled-payload budget per TCP direction"),
    ("max-flows", Kind::Value, "65536", "per-worker cap on tracked TCP connections"),
    ("max-sources", Kind::Value, "65536", "per-worker cap on tracked source addresses"),
];

/// Spellings kept working because they were once the only spelling, or
/// because people type them.
const ALIASES: &[(&str, &str)] = &[("read", "r"), ("signatures", "rules"), ("bpf", "filter"), ("home_net", "home-net")];

fn canonical(key: &str) -> &str {
    ALIASES.iter().find(|(from, _)| *from == key).map(|(_, to)| *to).unwrap_or(key)
}

fn option(key: &str) -> Option<&'static (&'static str, Kind, &'static str, &'static str)> {
    OPTIONS.iter().find(|(name, ..)| *name == key)
}

/// Applies one setting, whatever it came from.
///
/// `val` is `None` only for a bare command-line flag; a config file
/// always supplies one, and a flag there is written `key = true`.
fn apply(a: &mut Args, key: &str, val: Option<&str>) -> anyhow::Result<()> {
    let key = canonical(key);
    let Some((_, kind, ..)) = option(key) else {
        anyhow::bail!("unknown option {:?} (see -help)", key);
    };

    // A flag with a value is a config file saying `key = true`; a flag
    // without one is the command line. Both mean the same thing.
    let on = || -> anyhow::Result<bool> {
        match val {
            None => Ok(true),
            Some(v) => config::parse_bool(v),
        }
    };
    let v = || -> anyhow::Result<&str> {
        match val {
            Some(v) => Ok(v),
            None => anyhow::bail!("-{} requires a value", key),
        }
    };
    if *kind == Kind::Value && val.is_none() {
        anyhow::bail!("-{} requires a value", key);
    }

    match key {
        "iface" => a.ifaces.push(v()?.to_string()),
        "r" => a.pcap_file = Some(v()?.to_string()),
        "filter" => a.filter = Some(v()?.to_string()),
        "list-interfaces" => a.list_interfaces = on()?,
        "check-rules" => a.check_rules = Some(v()?.to_string()),

        "rules" => a.rules = Some(v()?.to_string()),
        "blacklist" => a.blacklist = Some(v()?.to_string()),
        "window" => a.window = parse_duration(v()?)?,
        "rate-threshold" => a.rate_threshold = v()?.parse()?,
        "scan-threshold" => a.scan_threshold = v()?.parse()?,
        "no-behavior" => a.behavior = !on()?,
        "behavior-window" => a.behavior_window = parse_duration(v()?)?,
        "frag-policy" => a.frag_policy = FragPolicy::parse(v()?)?,

        "intel" => a.intel.push(v()?.to_string()),
        "allowlist" => a.allowlist.push(v()?.to_string()),
        "home-net" => a.home_net.push(v()?.to_string()),

        "format" => a.format = Format::parse(v()?)?,
        "json" => {
            if on()? {
                a.format = Format::Json;
            }
        }
        "logfile" => a.logfile = v()?.to_string(),
        "log-format" => a.log_format = Some(Format::parse(v()?)?),
        "log-max-size" => a.log_max_size = parse_size(v()?)?,
        "log-keep" => a.log_keep = v()?.parse()?,
        "no-stdout" => a.no_stdout = on()?,
        "alert-output" => a.alert_outputs.push(v()?.to_string()),
        "syslog" => a.syslog = Some(v()?.to_string()),
        "syslog-format" => a.syslog_format = Format::parse(v()?)?,
        "syslog-facility" => a.syslog_facility = v()?.parse()?,
        "suppress-window" => a.suppress_window = parse_duration(v()?)?,
        "flow-log" => a.flow_log = Some(v()?.to_string()),
        "pcap-dir" => a.pcap_dir = v()?.to_string(),
        "pcap-retain" => {
            a.pcap_retain = v()?.parse()?;
            a.pcap_retain_explicit = true;
        }

        "config" => a.config = Some(v()?.to_string()),
        "generate-config" => a.generate_config = on()?,
        "metrics" => a.metrics = Some(v()?.to_string()),
        "reload-interval" => a.reload_interval = parse_duration(v()?)?,

        "workers" => a.workers = v()?.parse()?,
        "packet-pool" => a.packet_pool = v()?.parse()?,
        "queue-size" => a.queue_size = v()?.parse()?,
        "alert-queue" => a.alert_queue = v()?.parse()?,
        "payload-cap" => a.payload_cap = v()?.parse()?,
        "stream-cap" => a.stream_cap = v()?.parse()?,
        "max-flows" => a.max_flows = v()?.parse()?,
        "max-sources" => a.max_sources = v()?.parse()?,

        other => anyhow::bail!("option {:?} is in the table but not handled — this is a bug", other),
    }
    Ok(())
}

/// Sizes may be written `10485760`, `10M` or `10MB`, because nobody
/// wants to count zeroes into a log-rotation setting.
fn parse_size(s: &str) -> anyhow::Result<u64> {
    let t = s.trim();
    let upper = t.to_ascii_uppercase();
    let (digits, scale) = match upper.strip_suffix("B").unwrap_or(&upper) {
        d if d.ends_with('K') => (&d[..d.len() - 1], 1024u64),
        d if d.ends_with('M') => (&d[..d.len() - 1], 1024 * 1024),
        d if d.ends_with('G') => (&d[..d.len() - 1], 1024 * 1024 * 1024),
        d => (d, 1),
    };
    Ok(digits.trim().parse::<u64>()? * scale)
}

/// Defaults, then the config file, then the command line.
///
/// The command line is applied last and therefore wins, which is what
/// makes a deployed config file safe: one setting can always be
/// overridden for one run without editing it.
fn parse_args() -> anyhow::Result<Args> {
    let cli: Vec<String> = std::env::args().skip(1).collect();

    // The config path itself can only come from the command line or the
    // environment, so it is resolved in a first pass before the file is
    // read — a file cannot name itself.
    let mut a = Args::default();
    let mut explicit_config = None;
    let mut it = cli.iter().peekable();
    while let Some(arg) = it.next() {
        if arg == "-config" || arg == "--config" {
            explicit_config = it.next().cloned();
        }
    }

    let config_path = match explicit_config {
        Some(p) => Some(p),
        None => config::ConfigFile::find_default(),
    };
    if let Some(path) = &config_path {
        let file = config::ConfigFile::load(path)?;
        for e in &file.entries {
            apply(&mut a, &e.key, Some(&e.value)).map_err(|err| anyhow::anyhow!("{}:{}: {}", file.path, e.line, err))?;
        }
        a.config = Some(path.clone());
    }

    let mut it = cli.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "-help" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-V" | "-version" | "--version" => {
                println!("argus {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => {}
        }
        let key = arg.trim_start_matches('-');
        anyhow::ensure!(arg.starts_with('-'), "unexpected argument {:?} (options start with '-')", arg);
        let takes_value = option(canonical(key)).map(|(_, k, ..)| *k == Kind::Value).unwrap_or(false);
        let value = if takes_value { it.next() } else { None };
        apply(&mut a, key, value.as_deref())?;
    }
    Ok(a)
}

fn print_usage() {
    println!(
        "argus - a network intrusion detection system with TCP stream reassembly,\n\
         protocol parsing, a regex-capable rule engine, behavioural detection,\n\
         and a .pcap saved automatically around every alert\n\n\
         USAGE:\n  argus -iface <name> [options]        monitor an interface (repeatable)\n\
         \x20 argus -r <file.pcap> [options]      replay a saved capture\n\n\
         Every option below may also be set in a configuration file, as the same\n\
         name without its leading dash. A flag on the command line overrides the\n\
         file. Run -generate-config for an annotated example.\n\n\
         OPTIONS:"
    );
    for (name, kind, default, help) in OPTIONS {
        let arg = if *kind == Kind::Value { " <v>" } else { "" };
        let shown = format!("-{}{}", name, arg);
        if default.is_empty() {
            println!("  {:<22} {}", shown, help);
        } else {
            println!("  {:<22} {} (default {})", shown, help, default);
        }
    }
    println!("\n  {}", Signals::description());
}

fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("ms") {
        return Ok(Duration::from_millis(n.parse()?));
    }
    if let Some(n) = s.strip_suffix('s') {
        return Ok(Duration::from_secs_f64(n.parse()?));
    }
    if let Some(n) = s.strip_suffix('m') {
        return Ok(Duration::from_secs_f64(n.parse::<f64>()? * 60.0));
    }
    Ok(Duration::from_secs(s.parse()?))
}


fn list_interfaces() -> anyhow::Result<()> {
    for dev in pcap::Device::list()? {
        let desc = dev.desc.unwrap_or_else(|| "(no description)".to_string());
        let addrs: Vec<String> = dev.addresses.iter().map(|a| a.addr.to_string()).collect();
        println!("{:<40} {}", dev.name, desc);
        if !addrs.is_empty() {
            println!("{:<40} addresses: {}", "", addrs.join(", "));
        }
    }
    Ok(())
}

/// Canonical (direction-independent) FNV-1a hash of two IP endpoints —
/// sorted first (using `IpAddr`'s own `Ord`, which orders IPv4 before
/// IPv6 and then by address bytes), so a packet in *either* direction of
/// the same conversation always produces the same shard, and applied
/// **uniformly to every protocol, not just TCP**.
///
/// This uses only the two IP addresses, deliberately ignoring port
/// numbers — two things depend on that:
///
/// - **TCP stream reassembly** needs both directions of a connection on
///   one worker. Hashing ports too would put different *connections*
///   between the same two hosts on different workers — harmless for
///   reassembly (each connection's `FlowKey` already includes ports), but
///   see the next point for why it matters anyway.
/// - **Port-scan detection (TCP and UDP)** needs every connection
///   attempt between one source and one destination on the *same*
///   worker, regardless of which ports each attempt used — a tool like
///   `Test-NetConnection` opens a fresh source port per port it probes,
///   so a 25-port scan is 25 different connections. An earlier version
///   of this hash included ports and that scattered a real scan's
///   evidence across up to 25 different workers, so no single worker's
///   `AnomalyEngine` ever saw enough of it to cross the alert threshold.
/// - **UDP reply-tracking** (see `AnomalyEngine`'s `UdpPairTracker`)
///   needs an outbound query and its inbound reply on the same worker to
///   recognize the reply as one — this only works if UDP shards by host
///   pair the same way TCP does, which is why this function doesn't
///   special-case UDP to shard by source IP alone the way an earlier
///   version did.
fn hash_host_pair(a: IpAddr, b: IpAddr) -> u32 {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h: u32 = 2166136261;
    let mut mix = |bytes: &[u8]| {
        for &byte in bytes {
            h ^= byte as u32;
            h = h.wrapping_mul(16777619);
        }
    };
    mix(&[if lo.is_v4() { 4 } else { 6 }]);
    mix(lo.as_bytes());
    mix(&[if hi.is_v4() { 4 } else { 6 }]);
    mix(hi.as_bytes());
    h
}

fn shard_for(p: &Packet, workers: usize) -> usize {
    (hash_host_pair(p.src, p.dst) as usize) % workers
}

// =======================================================================
// Packet retention: a rolling window of recent raw traffic, saved to a
// .pcap file automatically whenever an alert fires
// =======================================================================
//
// Lives entirely on the capture thread — the only thread with direct
// access to the live `pcap::Capture` handle needed to open a savefile
// with the right link-layer type — so it needs no locking. Deliberately
// global rather than per-flow: it retains a window of ALL recently
// captured traffic in arrival order, not filtered to just the flow that
// alerted. That's both simpler (no per-flow raw-byte storage threaded
// through the sharded worker architecture, which only ever sees our own
// truncated, already-parsed `Packet` struct, not the genuine original
// bytes) and arguably more useful for forensics — surrounding context
// from other traffic at the same moment is often exactly what you want
// to see, not just the one flow in isolation.

/// How many bytes of each frame to retain. 1500 covers a standard
/// Ethernet MTU in full — enough for complete headers and most small
/// payloads/handshakes; larger frames are truncated, with the saved
/// header's `caplen` adjusted to match what was actually kept and `len`
/// preserved as the true original size, exactly matching ordinary pcap
/// truncation semantics (so Wireshark shows it as a normal, honestly
/// truncated capture, not a corrupt one).
const PCAP_RETAIN_BYTES: usize = 1500;

#[derive(Clone, Copy)]
struct RetainedFrame {
    header: pcap::PacketHeader,
    data: [u8; PCAP_RETAIN_BYTES],
    data_len: usize,
}

/// A fixed-size circular buffer of the most recently captured raw
/// frames. Pre-allocated once at startup — every slot is a fixed-size
/// array, not a `Vec` — specifically so that retaining a frame is a
/// bounded memcpy into already-owned memory, never a heap allocation on
/// the packet-capture hot path (the same reasoning behind `Packet`'s own
/// fixed-size payload array in `packet.rs`).
struct PcapRing {
    frames: Vec<Option<RetainedFrame>>,
    write_idx: usize,
}

impl PcapRing {
    fn new(capacity: usize) -> Self {
        PcapRing { frames: vec![None; capacity.max(1)], write_idx: 0 }
    }

    fn push(&mut self, header: pcap::PacketHeader, data: &[u8]) {
        let n = data.len().min(PCAP_RETAIN_BYTES);
        let mut buf = [0u8; PCAP_RETAIN_BYTES];
        buf[..n].copy_from_slice(&data[..n]);
        let slot = self.write_idx;
        self.frames[slot] = Some(RetainedFrame { header, data: buf, data_len: n });
        self.write_idx = (self.write_idx + 1) % self.frames.len();
    }

    /// Retained frames in chronological (oldest-first) order — `write_idx`
    /// always points at the oldest entry once the ring has wrapped at
    /// least once (it's the slot about to be overwritten next), and at
    /// the *start* of the valid entries before that, so a single
    /// rotation starting there is correct in both cases; empty slots
    /// (only possible before the very first wrap) are filtered out.
    fn ordered(&self) -> Vec<&RetainedFrame> {
        let n = self.frames.len();
        (0..n).map(|i| (self.write_idx + i) % n).filter_map(|idx| self.frames[idx].as_ref()).collect()
    }
}

/// Makes a string safe to embed in a filename on every platform ARGUS
/// targets — specifically Windows, which rejects `:` (present in every
/// IPv6 literal) among other characters Linux filesystems happily
/// accept. Not just an IPv6 special-case: anything outside a small safe
/// set gets replaced, defensively, even though today only `:` from an
/// IPv6 `IpAddr::Display` ever actually triggers it.
fn sanitize_for_filename(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' }).collect()
}

/// Opens a new `.pcap` savefile for an alert dump, named so it sorts
/// chronologically and is traceable back to the alert that caused it:
/// `<epoch_secs>_<seq>_<category>_<proto>_<src>.pcap` (`seq` is a simple
/// monotonic counter, not wall-clock precision, added purely so two
/// alerts landing in the same second still get distinct filenames).
/// This is the one part of dumping a pcap that genuinely must run on the
/// thread that owns `cap`, since it needs the capture's own link-layer
/// type. It's fast (just opens a file and writes the global pcap
/// header, no packet data yet) — the actual per-frame writing is
/// `write_frames_to_savefile`, deliberately kept separate so it can run
/// *off* the capture thread — see `main`'s dedicated pcap-writer thread
/// below, and why this split exists at all.
fn open_pcap_dump<T: pcap::Activated>(cap: &pcap::Capture<T>, req: &PcapDumpRequest, dump_dir: &std::path::Path, seq: u64) -> anyhow::Result<(pcap::Savefile, std::path::PathBuf)> {
    let epoch = req.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let filename = format!("{}_{:04}_{}_{}_{}.pcap", epoch, seq, req.category, req.proto, sanitize_for_filename(&req.src.to_string()));
    let path = dump_dir.join(filename);
    let savefile = cap.savefile(&path)?;
    Ok((savefile, path))
}

/// Writes retained frames to an already-open savefile and flushes it —
/// the slow, disk-bound part of dumping a pcap. `Savefile` is `Send`
/// (confirmed in the `pcap` crate source), which is what makes it sound
/// to open it on the capture thread but do the actual writing elsewhere.
fn write_frames_to_savefile(savefile: &mut pcap::Savefile, frames: &[RetainedFrame]) -> anyhow::Result<()> {
    for frame in frames {
        let header = pcap::PacketHeader { caplen: frame.data_len as u32, ..frame.header };
        let pkt = pcap::Packet { header: &header, data: &frame.data[..frame.data_len] };
        savefile.write(&pkt);
    }
    savefile.flush()?;
    Ok(())
}

/// Combines both steps synchronously. Used by tests, which don't care
/// about keeping the capture thread unblocked the way production code
/// does — see `main`, which does the two steps separately, handing the
/// slow half off to a dedicated writer thread instead of calling this.
#[cfg(test)]
fn write_pcap_dump<T: pcap::Activated>(cap: &pcap::Capture<T>, ring: &PcapRing, req: &PcapDumpRequest, dump_dir: &std::path::Path, seq: u64) -> anyhow::Result<std::path::PathBuf> {
    let (mut savefile, path) = open_pcap_dump(cap, req, dump_dir, seq)?;
    let frames: Vec<RetainedFrame> = ring.ordered().into_iter().copied().collect();
    write_frames_to_savefile(&mut savefile, &frames)?;
    Ok(path)
}

/// A pending pcap write, handed from the capture thread to the dedicated
/// pcap-writer thread: the file is already open (fast, done on the
/// capture thread, where it has to be), and `frames` is an owned
/// snapshot of the ring buffer at request time (a bounded, in-memory
/// copy — cheap relative to the disk I/O this defers) — this thread
/// hands off before any of the actual slow writing happens.
/// Converts a libpcap packet header's capture timestamp into a
/// `SystemTime`.
///
/// `tv_sec`/`tv_usec` are `i64` on Linux but `i32` on Windows (where C's
/// `long` stays 32-bit even in 64-bit builds), so both are read through
/// `i64` casts rather than assuming either width — the same portability
/// point the `pcap_retention_tests` header fixture already had to make.
fn timeval_to_systemtime(tv: &libc::timeval) -> SystemTime {
    let secs = tv.tv_sec as i64;
    let usecs = (tv.tv_usec as i64).clamp(0, 999_999) as u32;
    if secs < 0 {
        return UNIX_EPOCH; // nonsense timestamp; don't underflow
    }
    UNIX_EPOCH + Duration::new(secs as u64, usecs * 1000)
}

/// Reports the capture's link type, and warns when it's one ARGUS can't
/// strip.
///
/// This used to warn on anything that wasn't Ethernet, because Ethernet
/// was the only thing `parse_ethernet_frame` could handle. Several link
/// types are now decoded properly (see [`LinkType`]), so the warning is
/// reserved for the genuinely unsupported ones — where the symptom is a
/// run that looks perfectly healthy and reports zero alerts, which is
/// also exactly what a clean network looks like. Worth saying out loud
/// rather than leaving to be inferred from silence, and worth saying
/// especially under `-r`, where the link type is whatever the machine
/// that took the capture used rather than anything the local host picked.
fn report_link_type(link: LinkType, source: &str) {
    if link.is_supported() {
        println!("argus: {} link type: {}", source, link.name());
    } else {
        eprintln!(
            "argus: WARNING: {} has {} — ARGUS cannot strip that link header, so every frame will fail \
             to decode and no detection will run.",
            source,
            link.name()
        );
    }
}

/// Prints what the per-worker packet queues actually reserve.
///
/// Worth a line at startup because the number is not small and not
/// obvious: `Packet` carries an inline MTU-sized payload array so it can
/// cross a channel as a plain memcpy, so queue memory is
/// `size_of::<Packet>() x -queue-size x -workers` and grows with all
/// three. It was previously invisible, which is how a 256-byte payload
/// cap survived as long as it did — the cost of raising it was unstated,
/// so the benefit never got weighed against anything.
fn report_queue_memory(pool_size: usize, workers: usize, queue_size: usize) {
    let per_packet = std::mem::size_of::<Packet>();
    let total = per_packet.saturating_mul(pool_size);
    println!(
        "argus: packet pool reserves {:.0}MB ({} buffers x {} bytes); queues hold handles ({} deep x {} workers)",
        total as f64 / (1024.0 * 1024.0),
        pool_size,
        per_packet,
        queue_size,
        workers
    );
}

/// Reports libpcap's own view of what it dropped.
///
/// Distinct from, and more important than, ARGUS's worker-queue drop
/// counter: these are packets the kernel or driver discarded before
/// ARGUS ever saw them, so nothing downstream can know they existed.
/// `Capture::stats()` was never called before, which meant the single
/// most basic question a sensor operator has — "am I actually seeing all
/// the traffic?" — had no answer at all. Offline captures have no such
/// statistics, and saying so is better than printing zeros that look
/// like a clean bill of health.
fn report_capture_drops<T: pcap::Activated>(cap: &mut pcap::Capture<T>, metrics: &Metrics) {
    match cap.stats() {
        Ok(s) => {
            println!("argus: libpcap: {} received, {} dropped by the kernel, {} dropped by the interface", s.received, s.dropped, s.if_dropped);
            Metrics::add(&metrics.capture_dropped, s.dropped as u64);
            Metrics::add(&metrics.capture_iface_dropped, s.if_dropped as u64);
            if s.dropped > 0 || s.if_dropped > 0 {
                println!(
                    "argus: those drops happened before ARGUS saw them — nothing downstream can detect what they contained. \
                     Consider a narrower -filter, more -workers, or a deeper -queue-size."
                );
            }
        }
        Err(e) => println!("argus: libpcap capture statistics unavailable ({})", e),
    }
}

/// Everything the capture thread needs to service pcap-on-alert dump
/// requests: the request channel from the alert writer, the ring of
/// recent frames, and the handoff channel to the pcap-writer thread.
///
/// Bundled into one type mostly so [`run_capture`] can stay generic over
/// live vs. offline captures without taking half a dozen loose
/// parameters, but it also puts the "open here, write over there" split
/// in one place instead of spreading it across `main`.
struct DumpService {
    rx: crossbeam_channel::Receiver<PcapDumpRequest>,
    write_tx: crossbeam_channel::Sender<PcapWriteJob>,
    ring: PcapRing,
    dir: std::path::PathBuf,
    seq: u64,
}

impl DumpService {
    /// Opens a savefile for one request and hands the slow per-frame
    /// writing off to the pcap-writer thread. Only the open happens
    /// here, since that's the one step that needs `cap`'s own
    /// link-layer type.
    fn start<T: pcap::Activated>(&mut self, cap: &pcap::Capture<T>, req: PcapDumpRequest) {
        self.seq += 1;
        match open_pcap_dump(cap, &req, &self.dir, self.seq) {
            Ok((savefile, path)) => {
                let frames: Vec<RetainedFrame> = self.ring.ordered().into_iter().copied().collect();
                let _ = self.write_tx.send(PcapWriteJob { savefile, frames, path, req });
            }
            Err(e) => eprintln!("argus: failed to open pcap dump file: {}", e),
        }
    }

    /// Services whatever requests are pending right now, without
    /// blocking — called every capture-loop iteration.
    fn service<T: pcap::Activated>(&mut self, cap: &pcap::Capture<T>) {
        while let Ok(req) = self.rx.try_recv() {
            self.start(cap, req);
        }
    }

    /// Services requests until the alert writer hangs up, blocking as
    /// needed.
    ///
    /// Called once, after the capture loop ends and the worker senders
    /// have been dropped. Without it every dump still in flight at
    /// shutdown was simply lost: requests arrive from the *writer*
    /// thread, and the only code that ever drained them ran inside the
    /// capture loop, so anything queued after the last iteration had
    /// nobody left to serve it. Barely visible on a live capture, where
    /// alerts and dumps interleave continuously and only a final
    /// straggler or two goes missing on Ctrl-C — but total under `-r`,
    /// where the file is consumed long before the workers finish
    /// draining their queues, so *every* alert's dump would have been
    /// dropped.
    ///
    /// Terminates on channel disconnect: the sender lives in the alert
    /// writer, which exits once every worker's `alert_tx` clone is
    /// dropped, which happens once the workers finish — so this can't
    /// hang, provided the worker senders really were dropped first.
    fn drain_remaining<T: pcap::Activated>(&mut self, cap: &pcap::Capture<T>) {
        while let Ok(req) = self.rx.recv() {
            self.start(cap, req);
        }
    }
}

/// Per-worker tally of everything a bound made the engine stop tracking.
///
/// Collected at shutdown rather than sampled live, so the hot path pays
/// nothing for it: each worker owns its counters outright (no atomics in
/// `AnomalyEngine` or `FlowTable`, which is the whole point of the
/// sharded design) and hands them over once, when it finishes.
#[derive(Default, Clone, Copy)]
struct WorkerLimits {
    sources_refused: u64,
    destinations_refused: u64,
    udp_pairs_refused: u64,
    flows_refused: u64,
}

/// Both ends of the recycled packet-buffer pool.
///
/// `Packet` carries an inline payload array, so sending it through a
/// channel *by value* meant memcpy'ing the whole struct for every packet
/// and reserving `queue-size x workers x sizeof(Packet)` whether or not
/// it was in use. Both scale the wrong way — the copy with packet size,
/// the memory with worker count — and together they are why the payload
/// array couldn't be sized for jumbo frames.
///
/// Passing round `Box<Packet>` from a fixed pool fixes all three: the
/// channel moves a pointer, the memory is `-packet-pool` buffers
/// regardless of workers or queue depth, and buffers are reused so the
/// steady state has no allocator traffic at all.
///
/// The free list is deliberately **unbounded**, so returning a buffer
/// can never block. A worker blocking on the return path would deadlock
/// against a capture thread waiting for a buffer — the kind of cycle
/// this session has already produced twice by other means.
struct PacketPool {
    free: crossbeam_channel::Receiver<Box<Packet>>,
    give: crossbeam_channel::Sender<Box<Packet>>,
}

impl PacketPool {
    fn new(size: usize) -> Self {
        let (give, free) = crossbeam_channel::unbounded::<Box<Packet>>();
        for _ in 0..size {
            let _ = give.send(Box::new(Packet::default()));
        }
        PacketPool { free, give }
    }

    /// A sender for handing buffers back, cloned per worker.
    fn returner(&self) -> crossbeam_channel::Sender<Box<Packet>> {
        self.give.clone()
    }

    fn recycle(&self, buf: Box<Packet>) {
        let _ = self.give.send(buf);
    }
}

/// What one capture run saw at the pipeline level. The *reasons* frames
/// didn't decode live in `DecodeStats` on the `Decoder`, broken out by
/// cause — "this link is full of ARP" and "every frame is tagged and I
/// can't read them" are both a gap between `read` and `decoded`, and
/// they mean completely different things.
#[derive(Default, Clone, Copy)]
struct CaptureStats {
    read: u64,
    decoded: u64,
    /// Frames shed because no pooled buffer was free. Distinct from
    /// `dropped`, which is one worker's queue being full: this is the
    /// pipeline as a whole being behind.
    pool_exhausted: u64,
    /// Packets shed because a worker queue was full. Only possible on
    /// the live path; replay blocks instead.
    dropped: u64,
    /// Fragments absorbed into the reassembly table, which produce no
    /// packet of their own and so are neither decoded nor lost.
    buffered: u64,
}

impl CaptureStats {
    /// Sums two capture threads' totals. Every field is a count of
    /// independent events, so addition is the whole of it.
    fn merged(self, other: CaptureStats) -> CaptureStats {
        CaptureStats {
            read: self.read + other.read,
            decoded: self.decoded + other.decoded,
            pool_exhausted: self.pool_exhausted + other.pool_exhausted,
            dropped: self.dropped + other.dropped,
            buffered: self.buffered + other.buffered,
        }
    }
}

/// Opens a live capture, with the BPF filter installed in the kernel so
/// that filtered traffic never crosses into ARGUS at all — the only kind
/// of filtering that also saves the copy.
fn open_live(iface: &str, filter: Option<&str>, announce: bool) -> anyhow::Result<pcap::Capture<pcap::Active>> {
    let mut cap = pcap::Capture::from_device(iface)?.promisc(true).snaplen(65535).timeout(500).open()?;
    if let Some(expr) = filter {
        cap.filter(expr, true)?;
        if announce {
            println!("argus: BPF filter active: {}", expr);
        }
    }
    Ok(cap)
}

/// True when nothing at all was configured, so the banner can stay quiet.
fn intel_stats_is_empty(s: &argus::intel::IntelStats) -> bool {
    s.addresses == 0 && s.domains == 0 && s.ja3 == 0 && s.allow == 0 && s.home_net == 0
}

/// Watches the rule and enrichment files and republishes them on change.
///
/// Returns `None` when there is nothing to watch, so the thread is not
/// spawned merely to sleep. A reload that fails leaves the running
/// configuration untouched and is counted: a typo in a rule file must
/// not be able to take detection down.
#[allow(clippy::too_many_arguments)]
fn start_reloader(
    args: &Args,
    sources: &IntelSources,
    rules: Arc<Hot<SignatureEngine>>,
    intel: Arc<Hot<Intel>>,
    metrics: Arc<Metrics>,
    reload_flag: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let mut watched: Vec<String> = Vec::new();
    if args.reload_interval > Duration::ZERO {
        watched.extend(args.rules.iter().cloned());
        watched.extend(args.blacklist.iter().cloned());
        watched.extend(sources.files().cloned());
    }
    // With no files to watch, only a signal can ask for a reload — and on
    // a platform without one, nothing can.
    let signal_only = watched.is_empty();
    if signal_only && !cfg!(unix) {
        return None;
    }

    let rules_path = args.rules.clone();
    let blacklist_path = args.blacklist.clone();
    let sources = sources.clone();
    let interval = if args.reload_interval > Duration::ZERO { args.reload_interval } else { Duration::from_secs(1) };

    std::thread::Builder::new()
        .name("argus-reload".into())
        .spawn(move || {
            let mut watch = Watch::new(watched);
            while running.load(Ordering::SeqCst) {
                // A slice of the interval at a time, so shutdown does not
                // wait out a long reload interval.
                let deadline = std::time::Instant::now() + interval;
                while std::time::Instant::now() < deadline && running.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(200).min(interval));
                }
                let asked = reload_flag.swap(false, Ordering::AcqRel);
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                if !asked && !watch.changed() {
                    continue;
                }

                match SignatureEngine::load(blacklist_path.as_deref(), rules_path.as_deref()) {
                    Ok(engine) => {
                        let n = engine.rules.total_len();
                        rules.store(engine);
                        metrics.rules_loaded.store(n as u64, Ordering::Relaxed);
                        Metrics::inc(&metrics.rule_reloads);
                        println!("argus: reloaded {} rules", n);
                    }
                    Err(e) => {
                        Metrics::inc(&metrics.rule_reload_failures);
                        eprintln!("argus: rule reload failed, keeping the previous rules: {}", e);
                    }
                }

                if !sources.is_empty() {
                    match Intel::load(&sources) {
                        Ok(fresh) => {
                            let st = fresh.stats();
                            intel.store(fresh);
                            metrics.intel_entries.store((st.addresses + st.domains + st.ja3) as u64, Ordering::Relaxed);
                            println!("argus: reloaded enrichment — {} addresses, {} domains, {} JA3, {} allowlist entries", st.addresses, st.domains, st.ja3, st.allow);
                        }
                        Err(e) => {
                            Metrics::inc(&metrics.rule_reload_failures);
                            eprintln!("argus: enrichment reload failed, keeping the previous set: {}", e);
                        }
                    }
                }
            }
        })
        .ok()
}

/// The capture loop, generic over live (`Active`) and offline
/// (`Offline`) captures — both implement `pcap::Activated`, and the
/// whole point of `-r` is that a replay goes through this identical
/// path, not a parallel one that could drift from it.
///
/// Consumes `worker_txs` so it can drop them itself, before the final
/// dump drain: dropping them is what lets the workers finish, which lets
/// the alert writer exit, which is what `drain_remaining` waits on.
#[allow(clippy::too_many_arguments)]
fn run_capture<T: pcap::Activated>(
    cap: &mut pcap::Capture<T>,
    worker_txs: Vec<crossbeam_channel::Sender<Box<Packet>>>,
    running: &AtomicBool,
    dumps: &mut Option<DumpService>,
    decoder: &mut Decoder,
    pool: &PacketPool,
    replay: bool,
    metrics: &Metrics,
) -> CaptureStats {
    let workers = worker_txs.len();
    let mut stats = CaptureStats::default();

    while running.load(Ordering::SeqCst) {
        // Serviced at the top of the iteration rather than the bottom:
        // the decode arms below `continue` past the rest of the loop body
        // for a buffered fragment or an undecodable frame, and inside the
        // `Ok(raw)` arm `cap` is already mutably borrowed by `raw`.
        // Either way dump latency stays one iteration, including on
        // iterations that only timed out with no packet at all.
        if let Some(d) = dumps.as_mut() {
            d.service(cap);
        }

        match cap.next_packet() {
            Ok(raw) => {
                stats.read += 1;
                Metrics::inc(&metrics.frames_read);
                Metrics::add(&metrics.bytes_captured, raw.header.len as u64);
                if let Some(d) = dumps.as_mut() {
                    d.ring.push(*raw.header, raw.data);
                }
                // `ts` is set from the capture header, not read off the
                // clock here or in the worker — see `Packet::ts`.
                let ts = timeval_to_systemtime(&raw.header.ts);
                let now_sec = ts.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

                // In replay, wait for a buffer: a file isn't going
                // anywhere, and shedding frames would make results
                // unreproducible. Live capture must never block here, so
                // an exhausted pool sheds the frame and counts it — the
                // pool is the backpressure signal, and a counted shed is
                // honest where a stalled capture thread is an invisible
                // kernel-side drop.
                let mut pkt = if replay {
                    match pool.free.recv() {
                        Ok(b) => b,
                        Err(_) => break,
                    }
                } else {
                    match pool.free.try_recv() {
                        Ok(b) => b,
                        Err(_) => {
                            stats.pool_exhausted += 1;
                            Metrics::inc(&metrics.pool_exhausted);
                            continue;
                        }
                    }
                };
                pkt.ts = ts;
                // Decoding — link-layer dispatch, VLAN stripping, IP
                // fragment reassembly, payload capping — happens here on
                // the capture thread, ahead of sharding, because a
                // fragment has no ports until it's whole and sharding
                // and detection both need ports to mean something.
                match decoder.decode(raw.data, ts, now_sec, &mut pkt) {
                    Decoded::Buffered => {
                        stats.buffered += 1;
                        pool.recycle(pkt);
                        continue;
                    }
                    Decoded::Skipped => {
                        pool.recycle(pkt);
                        continue;
                    }
                    Decoded::Packet => {}
                }
                {
                    stats.decoded += 1;
                    let tx = &worker_txs[shard_for(&pkt, workers)];
                    if replay {
                        // Blocking send, unlike the live path below. A
                        // live capture must never block here: stalling
                        // `next_packet()` lets the kernel/driver drop
                        // arriving packets before ARGUS ever sees them,
                        // so shedding load at the queue is the lesser
                        // evil. A file, though, isn't going anywhere
                        // while we wait — and dropping packets from one
                        // would defeat the entire purpose of replay,
                        // whose value is that the same file always
                        // produces the same alerts. Silently thinning
                        // the input by however far the reader happened
                        // to outrun the workers would make every result
                        // both incomplete and unreproducible.
                        if tx.send(pkt).is_err() {
                            break; // workers gone; nothing left to feed
                        }
                    } else if let Err(e) = tx.try_send(pkt) {
                        stats.dropped += 1;
                        Metrics::inc(&metrics.queue_full);
                        // Recycled rather than dropped: a sustained run
                        // of backpressure would otherwise bleed the pool
                        // dry and turn one full queue into a pipeline
                        // stall.
                        pool.recycle(e.into_inner());
                    }
                }
            }
            // An offline capture ends; a live one just times out with
            // nothing to report and goes round again.
            Err(pcap::Error::NoMorePackets) => break,
            Err(pcap::Error::TimeoutExpired) => {}
            // A read error on a file won't fix itself on the next
            // attempt the way a transient live-capture error might, and
            // spinning on one forever would hang the process.
            Err(_) if replay => break,
            Err(_) => {}
        }
    }

    drop(worker_txs);
    if let Some(d) = dumps.as_mut() {
        d.drain_remaining(cap);
    }

    stats
}

struct PcapWriteJob {
    savefile: pcap::Savefile,
    frames: Vec<RetainedFrame>,
    path: std::path::PathBuf,
    req: PcapDumpRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Packet {
        let mut p = Packet::default();
        p.src = IpAddr::V4(src);
        p.dst = IpAddr::V4(dst);
        p.protocol = PROTO_TCP;
        p.src_port = src_port;
        p.dst_port = dst_port;
        p
    }

    fn udp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Packet {
        let mut p = tcp_packet(src, dst, src_port, dst_port);
        p.protocol = PROTO_UDP;
        p
    }

    /// Regression test for the real bug this caused: a port scan (or any
    /// tool that opens a fresh connection — and therefore a fresh source
    /// port — per attempt) touching 25 different destination ports used
    /// to scatter across up to 25 different workers, so no single
    /// worker's AnomalyEngine ever saw enough of the scan to detect it.
    /// Every one of these must land on the identical shard.
    #[test]
    fn many_connections_same_host_pair_share_one_shard() {
        let workers = 16;
        let client = [192, 168, 0, 112];
        let server = [45, 33, 32, 156];

        let first_shard = shard_for(&tcp_packet(client, server, 50000, 1), workers);
        for port in 1u16..=25 {
            let src_port = 50000 + port;
            let pkt = tcp_packet(client, server, src_port, port);
            assert_eq!(shard_for(&pkt, workers), first_shard, "port {} landed on a different shard", port);
        }
    }

    /// Both directions of one connection must still land together — the
    /// property this sharding scheme was originally built to guarantee.
    #[test]
    fn both_directions_of_one_connection_share_a_shard() {
        let workers = 16;
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];

        let to_server = tcp_packet(client, server, 51234, 80);
        let to_client = tcp_packet(server, client, 80, 51234);

        assert_eq!(shard_for(&to_server, workers), shard_for(&to_client, workers));
    }

    /// UDP now needs the same host-pair sharding as TCP: an outbound
    /// query and its inbound reply must land on the same worker for
    /// `AnomalyEngine`'s reply-tracking to recognize the reply as one —
    /// otherwise UDP scan detection would reintroduce the exact
    /// DNS-reply false positive it was built to avoid.
    #[test]
    fn udp_query_and_reply_share_a_shard() {
        let workers = 16;
        let client = [192, 168, 0, 112];
        let resolver = [194, 168, 4, 100];

        let query = udp_packet(client, resolver, 51000, 53);
        let reply = udp_packet(resolver, client, 53, 51000);
        assert_eq!(shard_for(&query, workers), shard_for(&reply, workers));

        // And, like TCP, different UDP "connections" (different client
        // ports) to the same destination must also share a shard.
        let first_shard = shard_for(&udp_packet(client, resolver, 51000, 53), workers);
        for port in 51001u16..51026 {
            let pkt = udp_packet(client, resolver, port, 53);
            assert_eq!(shard_for(&pkt, workers), first_shard, "client port {} landed on a different shard", port);
        }
    }

    #[test]
    fn ipv6_pair_hashes_consistently_regardless_of_direction() {
        let workers = 16;
        let a = IpAddr::parse("2001:db8::1").unwrap();
        let b = IpAddr::parse("2001:db8::2").unwrap();
        let mut pkt_ab = Packet::default();
        pkt_ab.src = a;
        pkt_ab.dst = b;
        pkt_ab.protocol = PROTO_TCP;
        let mut pkt_ba = Packet::default();
        pkt_ba.src = b;
        pkt_ba.dst = a;
        pkt_ba.protocol = PROTO_TCP;

        assert_eq!(shard_for(&pkt_ab, workers), shard_for(&pkt_ba, workers));
    }
}

#[cfg(test)]
mod pcap_retention_tests {
    use super::*;

    /// `libc::timeval`'s `tv_sec`/`tv_usec` field width is platform-
    /// dependent — `i64` on Linux, but `i32` (`c_long`, since Windows
    /// keeps C's `long` 32-bit even in 64-bit builds) on Windows. Taking
    /// `i64` here and casting with `as _` lets the compiler target
    /// whatever the real field type is on whichever platform this is
    /// actually compiled on, rather than this test fixture silently
    /// assuming Linux's width and failing to build on Windows.
    fn header(sec: i64, usec: i64, len: usize) -> pcap::PacketHeader {
        pcap::PacketHeader { ts: libc::timeval { tv_sec: sec as _, tv_usec: usec as _ }, caplen: len as u32, len: len as u32 }
    }

    #[test]
    fn ring_returns_frames_in_chronological_order_before_wrapping() {
        let mut ring = PcapRing::new(5);
        for i in 0..3 {
            ring.push(header(i, 0, 4), &[i as u8; 4]);
        }
        let ordered = ring.ordered();
        assert_eq!(ordered.len(), 3);
        let secs: Vec<i64> = ordered.iter().map(|f| f.header.ts.tv_sec as i64).collect();
        assert_eq!(secs, vec![0, 1, 2], "should come back in the order they were pushed");
    }

    #[test]
    fn ring_drops_oldest_frame_once_full() {
        // Regression-style test for the wraparound math itself: with
        // capacity 3, pushing 5 frames must leave exactly the 3 most
        // recent (seconds 2, 3, 4), oldest-first.
        let mut ring = PcapRing::new(3);
        for i in 0..5 {
            ring.push(header(i, 0, 4), &[0u8; 4]);
        }
        let secs: Vec<i64> = ring.ordered().iter().map(|f| f.header.ts.tv_sec as i64).collect();
        assert_eq!(secs, vec![2, 3, 4]);
    }

    #[test]
    fn ring_truncates_oversized_frames_and_tracks_the_truncated_length() {
        let mut ring = PcapRing::new(2);
        let big = vec![0xABu8; PCAP_RETAIN_BYTES + 500];
        ring.push(header(0, 0, big.len()), &big);
        let ordered = ring.ordered();
        assert_eq!(ordered[0].data_len, PCAP_RETAIN_BYTES, "retained data should be capped at PCAP_RETAIN_BYTES");
        // The *original* header's `len` (true packet size) must survive
        // untouched — only `caplen` gets adjusted at write time, in
        // write_pcap_dump, to match what was actually retained.
        assert_eq!(ordered[0].header.len, big.len() as u32);
    }

    #[test]
    fn filename_sanitizer_replaces_ipv6_colons() {
        let addr = IpAddr::parse("2001:db8::1").unwrap();
        let sanitized = sanitize_for_filename(&addr.to_string());
        assert!(!sanitized.contains(':'), "Windows filenames can't contain ':': {}", sanitized);
        assert_eq!(sanitized, "2001-db8--1");
    }

    #[test]
    fn filename_sanitizer_leaves_ipv4_untouched() {
        let addr = IpAddr::V4([192, 168, 0, 112]);
        assert_eq!(sanitize_for_filename(&addr.to_string()), "192.168.0.112");
    }

    /// End-to-end: write real frames through `write_pcap_dump` using a
    /// "dead" capture handle (a fake `pcap_t` that exists purely to
    /// supply a link-layer type for `savefile()` — no real network
    /// interface needed, which is what makes this testable at all), then
    /// read the file back with `Capture::from_file` and confirm every
    /// frame survived the round trip intact. This is the test that would
    /// have caught a wrong `caplen`/`len` mix-up or a malformed header
    /// that a pure in-memory `PcapRing` test could never catch, since it
    /// goes through the exact same libpcap file-writing code path
    /// production uses.
    #[test]
    fn write_pcap_dump_round_trips_through_a_real_pcap_file() {
        let dead = pcap::Capture::dead(pcap::Linktype::ETHERNET).expect("dead capture should always succeed");

        let mut ring = PcapRing::new(10);
        let payloads: [&[u8]; 3] = [b"first frame payload", b"second frame, a bit longer than the first one", b"third"];
        for (i, payload) in payloads.iter().enumerate() {
            ring.push(header(1_700_000_000 + i as i64, i as i64 * 1000, payload.len()), payload);
        }

        let dir = std::env::temp_dir().join(format!("argus_pcap_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let req = PcapDumpRequest { timestamp: SystemTime::now(), category: "TEST_CATEGORY", proto: "TCP", src: IpAddr::V4([10, 0, 0, 5]) };

        let path = write_pcap_dump(&dead, &ring, &req, &dir, 7).expect("dump should succeed");
        assert!(path.file_name().unwrap().to_str().unwrap().contains("TEST_CATEGORY"));
        assert!(path.file_name().unwrap().to_str().unwrap().contains("0007"), "sequence number should appear in the filename");

        let mut reader = pcap::Capture::from_file(&path).expect("the written file should be a valid, readable pcap");
        let mut recovered = Vec::new();
        while let Ok(pkt) = reader.next_packet() {
            recovered.push(pkt.data.to_vec());
        }
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(recovered.len(), payloads.len(), "every retained frame should come back out");
        for (got, want) in recovered.iter().zip(payloads.iter()) {
            assert_eq!(got.as_slice(), *want);
        }
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;

    /// A minimal Ethernet + IPv4 + TCP frame. `packet.rs`'s own frame
    /// builders are `#[cfg(test)] pub(crate)`, which makes them
    /// unreachable from here: `main.rs` is a separate crate from the
    /// library it links against, so neither the `cfg(test)` build nor
    /// the crate-internal visibility carries across.
    fn tcp_frame(src: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        let ip_len = 20 + 20 + payload.len();
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&[10, 0, 0, 200]);
        let mut tcp = vec![0u8; 20 + payload.len()];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[12] = 5 << 4; // data offset
        tcp[13] = 0x02; // SYN
        tcp[20..].copy_from_slice(payload);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame
    }

    /// An ARP frame — a well-formed Ethernet frame ARGUS deliberately
    /// cannot decode, included so the read-vs-decoded accounting has
    /// something real to count.
    fn arp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 28]);
        frame
    }

    fn header(sec: i64, usec: i64, len: usize) -> pcap::PacketHeader {
        pcap::PacketHeader { ts: libc::timeval { tv_sec: sec as _, tv_usec: usec as _ }, caplen: len as u32, len: len as u32 }
    }

    /// Writes `frames` (each with its own capture timestamp) to a real
    /// `.pcap` file and returns its path.
    fn write_pcap(name: &str, frames: &[(i64, i64, Vec<u8>)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("argus_replay_{}_{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("in.pcap");
        let dead = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
        let mut savefile = dead.savefile(&path).unwrap();
        for (sec, usec, frame) in frames {
            let h = header(*sec, *usec, frame.len());
            savefile.write(&pcap::Packet { header: &h, data: frame });
        }
        savefile.flush().unwrap();
        drop(savefile);
        path
    }

    /// Runs `run_capture` in replay mode over `path` and returns its
    /// stats plus every packet that reached a worker queue.
    fn replay(path: &std::path::Path, workers: usize, queue_size: usize) -> (CaptureStats, Vec<Packet>) {
        // One collector thread per queue, started *before* the replay
        // and standing in for the real worker threads. They have to run
        // concurrently: replay uses a blocking send, so with a queue
        // smaller than the capture and nothing draining it, the reader
        // would simply wedge once the first queue filled. Draining
        // concurrently is also what production does, which is the point
        // — it's the arrangement under which "never drops a packet"
        // actually means something.
        // Packets travel as pooled handles now, so the collectors take
        // ownership of the buffers and simply drop them — the test isn't
        // measuring pool reuse, only what was delivered.
        let pool = PacketPool::new(queue_size * workers + 64);
        let mut txs = Vec::with_capacity(workers);
        let mut collectors = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = crossbeam_channel::bounded::<Box<Packet>>(queue_size);
            txs.push(tx);
            collectors.push(std::thread::spawn(move || rx.iter().map(|b| *b).collect::<Vec<Packet>>()));
        }
        let mut cap = pcap::Capture::from_file(path).unwrap();
        let running = AtomicBool::new(true);
        let mut dumps = None;
        let mut decoder = Decoder::new(LinkType::from_dlt(cap.get_datalink().0), DEFAULT_PAYLOAD_CAP, DefragLimits::default());
        // `run_capture` drops the senders itself, which is what lets the
        // collectors' `rx.iter()` terminate below.
        let stats = run_capture(&mut cap, txs, &running, &mut dumps, &mut decoder, &pool, true, &Metrics::default());
        let delivered: Vec<Packet> = collectors.into_iter().flat_map(|h| h.join().unwrap()).collect();
        (stats, delivered)
    }

    /// The two properties that make a replay worth trusting: it loses
    /// nothing, and every packet carries the time it was *captured*.
    ///
    /// Both are easy to get wrong in ways nothing else would catch. The
    /// live path deliberately sheds packets with `try_send` when a
    /// worker queue is full, which is right for a live capture (blocking
    /// there lets the kernel drop packets instead) and completely wrong
    /// for a file, where it would silently thin the input by however far
    /// the reader happened to outrun the workers — making every result
    /// both incomplete and unreproducible, which defeats the entire
    /// purpose. And an earlier version read `SystemTime::now()` inside
    /// the worker instead of taking the capture header's timestamp,
    /// which for a replay means every detection window and every alert
    /// is stamped with wall-clock time at file-read speed rather than
    /// the traffic's real timing.
    #[test]
    fn replay_delivers_every_decodable_packet_with_its_own_capture_timestamp() {
        const BASE: i64 = 1_700_000_000;
        let mut frames: Vec<(i64, i64, Vec<u8>)> = Vec::new();
        // Distinct source addresses so packets spread across shards, and
        // a distinct destination port per packet so each one can be
        // matched back to the timestamp it was written with.
        for i in 0..40i64 {
            frames.push((BASE + i, i * 1000, tcp_frame([10, 0, 1, i as u8], 1000 + i as u16, b"x")));
        }
        frames.push((BASE, 0, arp_frame()));

        let path = write_pcap("all", &frames);
        // A queue far smaller than the packet count: with a blocking
        // send that's fine, but it's exactly the condition under which
        // the live path's `try_send` would start dropping.
        let (stats, delivered) = replay(&path, 4, 4);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(stats.read, 41, "every frame in the file should be read");
        assert_eq!(stats.decoded, 40, "the ARP frame is the only one that shouldn't decode");
        assert_eq!(stats.dropped, 0, "a replay must never drop a packet, however small the queues");
        assert_eq!(delivered.len(), 40, "every decoded packet should reach a worker");

        for pkt in &delivered {
            let i = (pkt.dst_port - 1000) as i64;
            let want = UNIX_EPOCH + Duration::new((BASE + i) as u64, (i * 1000 * 1000) as u32);
            assert_eq!(pkt.ts, want, "packet with dst_port {} carried the wrong capture timestamp", pkt.dst_port);
        }
    }

    /// An empty capture is a legitimate input, not an error, and must
    /// terminate on `NoMorePackets` rather than spinning.
    #[test]
    fn replay_of_an_empty_capture_reads_nothing_and_returns() {
        let path = write_pcap("empty", &[]);
        let (stats, delivered) = replay(&path, 2, 8);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert_eq!((stats.read, stats.decoded, stats.dropped), (0, 0, 0));
        assert!(delivered.is_empty());
    }

    /// Sub-second precision has to survive the `timeval` round trip:
    /// truncating to whole seconds would quietly coarsen every detection
    /// window, and the field widths differ per platform (`i64` on Linux,
    /// `i32` on Windows), so this is worth pinning down directly.
    #[test]
    fn timeval_conversion_keeps_microseconds_and_rejects_nonsense() {
        let tv = libc::timeval { tv_sec: 1_700_000_000 as _, tv_usec: 123_456 as _ };
        assert_eq!(timeval_to_systemtime(&tv), UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000));

        let negative = libc::timeval { tv_sec: -5 as _, tv_usec: 0 as _ };
        assert_eq!(timeval_to_systemtime(&negative), UNIX_EPOCH, "a negative timestamp shouldn't underflow");

        let overflowing = libc::timeval { tv_sec: 1_700_000_000 as _, tv_usec: 9_999_999 as _ };
        assert_eq!(
            timeval_to_systemtime(&overflowing),
            UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_000),
            "an out-of-range tv_usec should clamp, not overflow the nanosecond field"
        );
    }
}

/// Assembles every alert destination from the flags.
///
/// Order matters only for readability of the startup banner; the writer
/// renders once per distinct format regardless of how many sinks want
/// it. A deployment with stdout text, an EVE file and a syslog collector
/// costs two renderings per alert, not three.
fn build_output(args: &Args) -> anyhow::Result<Output> {
    let mut sinks: Vec<Box<dyn Sink>> = Vec::new();

    if !args.no_stdout {
        sinks.push(Box::new(WriterSink::stdout(args.format)));
    }
    if !args.logfile.is_empty() {
        let format = args.log_format.unwrap_or(args.format);
        sinks.push(Box::new(FileSink::open(std::path::Path::new(&args.logfile), format, args.log_max_size, args.log_keep)?));
    }
    for spec in &args.alert_outputs {
        // `<format>:<path>`. Split on the first colon only, so a Windows
        // drive letter in the path survives.
        let (fmt, path) = spec
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("-alert-output {:?} should be <format>:<path>, e.g. eve:/var/log/argus.eve", spec))?;
        let format = Format::parse(fmt)?;
        sinks.push(Box::new(FileSink::open(std::path::Path::new(path), format, args.log_max_size, args.log_keep)?));
    }
    if let Some(spec) = &args.syslog {
        sinks.push(Box::new(SyslogSink::connect(spec, args.syslog_format, args.syslog_facility)?));
    }

    // A sensor with nowhere to report is almost certainly a
    // misconfiguration rather than an intent, and it fails silently —
    // detection runs, alerts are raised, and nothing is ever seen.
    anyhow::ensure!(!sinks.is_empty(), "no alert destination: -no-stdout was given with no -logfile, -alert-output or -syslog");
    Ok(Output::new(sinks))
}

fn main() -> anyhow::Result<()> {
    let args = parse_args()?;

    if args.generate_config {
        let rows: Vec<(&str, &str, String)> = OPTIONS.iter().map(|(n, _, d, h)| (*n, *h, d.to_string())).collect();
        print!("{}", config::generate(&rows));
        return Ok(());
    }
    if let Some(path) = &args.check_rules {
        let (set, errors) = argus::engine::RuleSet::load_lenient(path)?;
        for e in &errors {
            println!("{}", e);
        }
        println!("argus: {} rules accepted, {} refused", set.total_len(), errors.len());
        std::process::exit(if errors.is_empty() { 0 } else { 1 });
    }
    if args.list_interfaces {
        return list_interfaces();
    }
    let replay_path = args.pcap_file.clone();
    let ifaces = args.ifaces.clone();
    match (ifaces.is_empty(), &replay_path) {
        (false, Some(_)) => anyhow::bail!("-iface and -r are mutually exclusive: monitor interfaces or replay a file, not both"),
        (true, None) => anyhow::bail!("one of -iface or -r is required (use -list-interfaces to see options; -help for usage)"),
        _ => {}
    }
    let replaying = replay_path.is_some();
    let workers = args.workers.max(1);

    let metrics = Metrics::new();

    // Rules and enrichment both live behind `Hot`, because both are
    // reloadable and workers read both on the packet path. Loading them
    // here rather than inside the reload path means a bad file is a
    // startup failure, which is the right moment to find out.
    let sig_engine = Hot::new(SignatureEngine::load(args.blacklist.as_deref(), args.rules.as_deref())?);
    Metrics::add(&metrics.rules_loaded, sig_engine.load().rules.total_len() as u64);

    let intel_sources = IntelSources {
        reputation: args.intel.clone(),
        allow: args.allowlist.clone(),
        home_net: args.home_net.clone(),
    };
    let intel = Hot::new(Intel::load(&intel_sources)?);
    let intel_stats = intel.load().stats();
    Metrics::add(&metrics.intel_entries, (intel_stats.addresses + intel_stats.domains + intel_stats.ja3) as u64);

    let signals = Signals::default();
    signals.install()?;

    let anom_cfg = AnomalyConfig {
        window: args.window,
        packet_rate_pps: args.rate_threshold,
        port_scan_limit: args.scan_threshold,
        max_sources: args.max_sources.max(1),
        ..AnomalyConfig::default()
    };

    // --- pcap-on-alert setup ---
    // Replaying a file defaults pcap-on-alert *off*. Two reasons:
    // dumping slices of a capture you already have on disk is close to
    // pure waste, and the slices wouldn't even line up with their
    // alerts. The reader runs ahead of the workers by up to a full queue
    // depth per worker (4096 x N by default, against a 500-frame ring),
    // so by the time an alert comes back the ring holds frames from
    // further along the file rather than the ones around the alert.
    // Still honoured if asked for explicitly — that caveat is the only
    // thing wrong with it, and it's worth having for anyone who wants
    // the dump files themselves.
    // Capturing several interfaces turns pcap-on-alert off. Each
    // capture thread holds its own ring of recent frames, and an alert
    // does not carry the interface it came from — behavioural alerts
    // genuinely span interfaces, so it could not. Dumping from an
    // arbitrary ring would produce a file that looks like context and
    // isn't, which is worse than no file.
    let multi_iface = ifaces.len() > 1;
    let pcap_enabled = args.pcap_retain > 0 && (!replaying || args.pcap_retain_explicit) && !multi_iface;
    if multi_iface && args.pcap_retain > 0 {
        println!("argus: pcap-on-alert disabled — it needs a single interface to know which traffic to save");
    }
    if pcap_enabled {
        std::fs::create_dir_all(&args.pcap_dir)?;
    }
    let (pcap_tx, pcap_rx) = if pcap_enabled {
        let (tx, rx) = crossbeam_channel::unbounded::<PcapDumpRequest>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    // The actual disk writing (opening a file is fast; writing up to
    // `-pcap-retain` packets and flushing is not) happens on its own
    // thread, not the capture thread — the capture thread only opens the
    // file (the one part that needs its live `cap` handle) and hands off
    // an in-memory snapshot of the ring buffer. Doing the slow part
    // inline on the capture thread would stall `cap.next_packet()` for
    // however long the write takes, during which arriving packets could
    // be dropped by the OS/driver's own kernel buffer before ARGUS ever
    // sees them — invisible to the `dropped` counter below, which only
    // tracks worker-queue drops, and exactly the wrong failure mode
    // right after a real alert (busy traffic) is when a stall is most
    // likely to actually lose something.
    let (pcap_write_tx, pcap_writer_join) = if pcap_enabled {
        let (tx, rx) = crossbeam_channel::unbounded::<PcapWriteJob>();
        let handle = std::thread::spawn(move || {
            for mut job in rx.iter() {
                match write_frames_to_savefile(&mut job.savefile, &job.frames) {
                    Ok(()) => println!("argus: saved {} ({} alert, src {})", job.path.display(), job.req.category, job.req.src),
                    Err(e) => eprintln!("argus: failed to write pcap dump: {}", e),
                }
            }
        });
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };

    // --- pipeline setup ---
    let pool = Arc::new(PacketPool::new(args.packet_pool.max(workers * 2).max(64)));

    // Bounded, and sent to with `try_send`. An unbounded alert channel
    // is unbounded memory growth under precisely the conditions that
    // produce the most alerts: the detection path allocates a `String`
    // per alert and never blocks, so a storm outruns the single writer
    // thread and the backlog grows until something dies. Shedding alerts
    // at a known depth, and saying how many were shed, is strictly
    // better than an unbounded queue that fails opaquely.
    let (alert_tx, gate_rx) = crossbeam_channel::bounded::<Alert>(args.alert_queue.max(1));
    // Between the workers and the writer, so that a rule's `threshold` is
    // counted where every alert passes and not once per worker.
    let (out_tx, alert_rx) = crossbeam_channel::bounded::<Alert>(args.alert_queue.max(1));
    let gate_join = {
        let rules = Arc::clone(&sig_engine);
        let ordered = replay_path.is_some();
        std::thread::spawn(move || argus::threshold::run_threshold_gate(gate_rx, out_tx, rules, ordered))
    };
    let alerts_shed = Arc::new(AtomicU64::new(0));
    let output = build_output(&args)?;
    let sink_descriptions = output.describe_all();
    let writer_cfg = AlertWriterConfig {
        suppress_window: args.suppress_window,
        pcap_tx,
        intel: intel.load(),
        metrics: Arc::clone(&metrics),
        reopen: Arc::clone(&signals.reopen),
    };
    let writer_handle = std::thread::spawn(move || run_alert_writer(alert_rx, output, writer_cfg));

    let limit_report: Arc<std::sync::Mutex<Vec<WorkerLimits>>> = Arc::new(std::sync::Mutex::new(Vec::with_capacity(workers)));

    // Bounded like the alert channel, and for the same reason: flow
    // records are produced by detection and consumed by disk, so an
    // unbounded queue just relocates a disk bottleneck into memory.
    let (flow_tx, flow_writer_join) = match &args.flow_log {
        Some(path) => {
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            let (tx, rx) = crossbeam_channel::bounded::<FlowRecord>(args.alert_queue.max(1));
            let handle = std::thread::spawn(move || run_flow_writer(rx, Box::new(file)));
            println!("argus: writing flow records to {}", path);
            (Some(tx), Some(handle))
        }
        None => (None, None),
    };
    let flows_shed = Arc::new(AtomicU64::new(0));

    // The behavioural aggregator. Its own thread with a single
    // consumer, like the alert writer, because the state it owns is
    // cross-source and therefore cannot live in a worker — see
    // `behavior.rs` for why sharding rules that out.
    let (behavior_tx, behavior_join) = if args.behavior {
        let cfg = BehaviorConfig { window: args.behavior_window, ..BehaviorConfig::default() };
        let (tx, rx) = crossbeam_channel::bounded::<Observation>(args.alert_queue.max(1));
        let alert_tx = alert_tx.clone();
        let ordered = replay_path.is_some();
        let handle = std::thread::spawn(move || run_behavior_engine(rx, alert_tx, cfg, ordered));
        println!("argus: behavioural detection active (window {:?})", args.behavior_window);
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };
    let observations_shed = Arc::new(AtomicU64::new(0));

    let mut worker_txs = Vec::with_capacity(workers);
    let mut worker_handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (tx, rx) = crossbeam_channel::bounded::<Box<Packet>>(args.queue_size);
        worker_txs.push(tx);
        let sig_engine = Arc::clone(&sig_engine);
        let intel_hot = Arc::clone(&intel);
        let alert_tx = alert_tx.clone();
        let metrics = Arc::clone(&metrics);
        let cfg = anom_cfg;
        let stream_cap = args.stream_cap;
        let max_flows = args.max_flows;
        let alerts_shed = Arc::clone(&alerts_shed);
        let flows_shed = Arc::clone(&flows_shed);
        let limit_report = Arc::clone(&limit_report);
        let flow_tx = flow_tx.clone();
        let behavior_tx = behavior_tx.clone();
        let observations_shed = Arc::clone(&observations_shed);
        let free_tx = pool.returner();
        worker_handles.push(std::thread::spawn(move || {
            // Both owned exclusively by this thread, no locks: this
            // worker's shard guarantees it alone sees every packet for
            // its set of source/destination pairs (AnomalyEngine) and
            // TCP connections (FlowTable).
            let mut anom_engine = AnomalyEngine::new(cfg);
            let mut flow_table = FlowTable::with_limits(stream_cap, max_flows);
            let mut datagram_flows = DatagramFlows::new(max_flows);
            // Nothing is built unless something drains it.
            if flow_tx.is_some() {
                flow_table.enable_flow_records();
                datagram_flows.enable_flow_records();
            }
            if behavior_tx.is_some() {
                flow_table.enable_observations();
                datagram_flows.enable_observations();
                anom_engine.enable_observations();
            }
            let mut alerts = Vec::new();
            let mut flow_records: Vec<FlowRecord> = Vec::new();
            let mut observations: Vec<Observation> = Vec::new();
            // The datagram paths below match rules directly rather than
            // through `FlowTable`, so they need their own reused buffers
            // — same reasoning, same zero allocations per packet.
            let mut scratch = ScanScratch::default();
            // The datagram paths below check reputation directly, since
            // they have no flow table to hang it on.
            let mut datagram_intel = intel_hot.load();
            let mut datagram_seen = IntelSeen::new(4096);
            let mut quic_sessions = QuicSessions::new(2048);
            // The worker's own view of the rule set. Checking it costs a
            // relaxed atomic load per packet and a branch that is taken
            // once per reload; see `reload::Cached`.
            let mut rules = Cached::new(&sig_engine);
            // Enrichment is versioned separately from rules: an operator
            // adding an allowlist entry should not reload the rule set,
            // and a feed refreshed hourly should not either.
            let mut intel = Cached::new(&intel_hot);
            let mut intel_generation = 0u64;
            let mut packets_since_report: u32 = 0;

            for boxed in rx.iter() {
                let sig_engine = &**rules.get(&sig_engine);
                // Installed on the tables rather than passed per packet,
                // and only when it has actually changed.
                if intel_hot.generation() != intel_generation {
                    let fresh = Arc::clone(intel.get(&intel_hot));
                    intel_generation = intel_hot.generation();
                    flow_table.set_intel(Arc::clone(&fresh));
                    datagram_intel = fresh;
                }
                let pkt = &*boxed;

                // Occupancy gauges are sampled rather than updated per
                // packet: they are a rough picture of pressure, and
                // paying an atomic store per packet for a number nobody
                // reads more than once a second is a poor trade.
                packets_since_report = packets_since_report.wrapping_add(1);
                if packets_since_report % 4096 == 0 {
                    metrics.flows_tracked.store(flow_table.tracked_flows() as u64, Ordering::Relaxed);
                }
                // The packet's own capture time, not the clock right
                // now — see `Packet::ts` for what reading the clock here
                // instead used to break.
                let now = pkt.ts;
                let now_sec = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
                alerts.clear();

                sig_engine.inspect_blacklist(&pkt, now, &mut alerts);
                anom_engine.observe(&pkt, now, &mut alerts);

                // Rules about one packet, not the stream it belongs to: a
                // segment as it arrived, an ICMP type, a SYN. Skipped unless a
                // loaded rule asks, since it costs a scan of every packet.
                if sig_engine.rules.wants_packet_rules() && !pkt.is_fragment {
                    scratch.hits.clear();
                    sig_engine.check_buffer_into(&pkt, Buffer::PacketPayload, Direction::Any, pkt.payload(), &mut scratch.matcher, None, &mut scratch.hits);
                    for hit in scratch.hits.drain(..) {
                        alerts.push(signature_alert(&pkt, Buffer::PacketPayload, &hit, now));
                    }
                }

                if pkt.protocol == PROTO_TCP {
                    flow_table.observe(&pkt, now, now_sec, &sig_engine, &mut alerts);
                } else {
                    // Accounting-only records for datagram protocols,
                    // which `FlowTable` cannot produce: it exists to
                    // reassemble streams, and there are none here.
                    datagram_flows.observe(&pkt, now_sec);
                    if pkt.payload_len > 0 {
                        scratch.hits.clear();
                        sig_engine.check_buffer_into(&pkt, Buffer::Payload, Direction::Any, pkt.payload(), &mut scratch.matcher, None, &mut scratch.hits);
                        for hit in scratch.hits.drain(..) {
                            alerts.push(signature_alert(&pkt, Buffer::Payload, &hit, now));
                        }
                    }
                    if pkt.protocol == PROTO_UDP && (pkt.src_port == 53 || pkt.dst_port == 53) {
                        if let Some(query) = parse_dns_query(pkt.payload()) {
                            // The query name is already parsed for rule
                            // matching, so tunnel-shape analysis costs
                            // only the copy into the observation.
                            if let Some(tx) = &behavior_tx {
                                if tx.try_send(Observation::dns(now_sec, pkt.src, pkt.dst, &query)).is_err() {
                                    observations_shed.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            // A DNS question names the destination before
                            // any connection to it exists, which makes it
                            // the earliest point at which a domain feed
                            // can say anything — and the only one that
                            // still works when the answer is a CDN address
                            // no address feed will ever list.
                            if !datagram_intel.domains.is_empty() && pkt.dst_port == 53 {
                                if let Some(tag) = datagram_intel.domains.lookup(&query) {
                                    if datagram_seen.first_time(pkt.src, pkt.dst) {
                                        alerts.push(Alert {
                                            timestamp: now,
                                            severity: Severity::High,
                                            category: "THREAT_INTEL",
                                            src: pkt.src,
                                            dst: pkt.dst,
                                            proto: "UDP",
                                            port: pkt.dst_port,
                                            message: format!("DNS query for {} matches a loaded indicator: {}", query, tag),
                                            sid: 0,
                                        });
                                        Metrics::inc(&metrics.intel_hits);
                                    }
                                }
                            }
                            scratch.hits.clear();
                            sig_engine.check_buffer_into(&pkt, Buffer::DnsQuery, Direction::Any, query.as_bytes(), &mut scratch.matcher, None, &mut scratch.hits);
                            for hit in scratch.hits.drain(..) {
                                alerts.push(signature_alert(&pkt, Buffer::DnsQuery, &hit, now));
                            }
                        }
                    }
                    // Kerberos over UDP, which is the transport most clients
                    // try first. Port-gated: its framing is ASN.1, which is
                    // not distinctive enough to sniff for.
                    if pkt.protocol == PROTO_UDP && (pkt.src_port == 88 || pkt.dst_port == 88) {
                        if let Some(krb) = argus::enterprise::parse_kerberos(pkt.payload()) {
                            for (buffer, value) in [
                                (Buffer::KerberosRealm, &krb.realm),
                                (Buffer::KerberosPrincipal, &krb.client),
                                (Buffer::KerberosService, &krb.service),
                            ] {
                                if let Some(v) = value {
                                    scratch.hits.clear();
                                    sig_engine.check_buffer_into(&pkt, buffer, Direction::Any, v.as_bytes(), &mut scratch.matcher, None, &mut scratch.hits);
                                    for hit in scratch.hits.drain(..) {
                                        alerts.push(signature_alert(&pkt, buffer, &hit, now));
                                    }
                                }
                            }
                            // A refusal comes from the KDC, so the attempt
                            // was made by the *destination* of this packet.
                            if pkt.src_port == 88 && krb.error_code.is_some_and(argus::enterprise::kerberos_error_is_auth_failure) {
                                if let Some(tx) = &behavior_tx {
                                    let obs = Observation::AuthFailure { ts_sec: now_sec, src: pkt.dst, dst: pkt.src, dst_port: 88, service: "Kerberos" };
                                    if tx.try_send(obs).is_err() {
                                        observations_shed.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }
                    // QUIC. Gated on a cheap shape check rather than a
                    // port, because QUIC is not bound to 443 — and
                    // deliberately *not* on the port alone, since the
                    // work behind this check is real cryptography and
                    // must not run on every UDP datagram.
                    if pkt.protocol == PROTO_UDP && looks_like_quic_initial(pkt.payload()) {
                        // Keyed by connection id, because a ClientHello
                        // too large for one datagram arrives spread over
                        // several and only the id ties them together.
                        // The addresses would not: a client may migrate.
                        if let Some(info) = quic_sessions.parse(pkt.payload()) {
                            if let Some(hello) = &info.hello {
                                if let Some(sni) = &hello.sni {
                                    scratch.hits.clear();
                                    sig_engine.check_buffer_into(&pkt, Buffer::TlsSni, Direction::Any, sni.as_bytes(), &mut scratch.matcher, None, &mut scratch.hits);
                                    for hit in scratch.hits.drain(..) {
                                        alerts.push(signature_alert(&pkt, Buffer::TlsSni, &hit, now));
                                    }
                                    // The same enrichment a TLS-over-TCP
                                    // connection gets. A QUIC handshake
                                    // that was previously invisible now
                                    // answers the same questions.
                                    if !datagram_intel.domains.is_empty() {
                                        if let Some(tag) = datagram_intel.domains.lookup(sni) {
                                            if datagram_seen.first_time(pkt.src, pkt.dst) {
                                                alerts.push(Alert {
                                                    timestamp: now,
                                                    severity: Severity::High,
                                                    category: "THREAT_INTEL",
                                                    src: pkt.src,
                                                    dst: pkt.dst,
                                                    proto: "UDP",
                                                    port: pkt.dst_port,
                                                    message: format!("QUIC server name {} matches a loaded indicator: {}", sni, tag),
                                                    sid: 0,
                                                });
                                                Metrics::inc(&metrics.intel_hits);
                                            }
                                        }
                                    }
                                }
                                scratch.hits.clear();
                                sig_engine.check_buffer_into(&pkt, Buffer::TlsJa3, Direction::Any, hello.ja3.as_bytes(), &mut scratch.matcher, None, &mut scratch.hits);
                                for hit in scratch.hits.drain(..) {
                                    alerts.push(signature_alert(&pkt, Buffer::TlsJa3, &hit, now));
                                }
                                if !datagram_intel.ja3.is_empty() {
                                    if let Some(tag) = datagram_intel.ja3.lookup(&hello.ja3) {
                                        if datagram_seen.first_time(pkt.src, pkt.dst) {
                                            alerts.push(Alert {
                                                timestamp: now,
                                                severity: Severity::High,
                                                category: "THREAT_INTEL",
                                                src: pkt.src,
                                                dst: pkt.dst,
                                                proto: "UDP",
                                                port: pkt.dst_port,
                                                message: format!("QUIC client fingerprint matches a loaded indicator: {}", tag),
                                                sid: 0,
                                            });
                                            Metrics::inc(&metrics.intel_hits);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Both TFTP and SNMP are gated by their well-known
                    // ports rather than content-sniffed, matching
                    // Modbus's precedent: neither has a strong enough
                    // signature byte pattern to safely content-sniff
                    // against arbitrary UDP traffic. UDP has no stream
                    // reassembly, so both are parsed directly per-packet
                    // here, the same way DNS already is, rather than
                    // through FlowTable.
                    if pkt.protocol == PROTO_UDP && (pkt.src_port == 69 || pkt.dst_port == 69) {
                        if let Some(info) = parse_tftp_packet(pkt.payload()) {
                            scratch.hits.clear();
                            sig_engine.check_buffer_into(&pkt, Buffer::TftpOpcode, Direction::Any, info.opcode.as_bytes(), &mut scratch.matcher, None, &mut scratch.hits);
                            for hit in scratch.hits.drain(..) {
                                alerts.push(signature_alert(&pkt, Buffer::TftpOpcode, &hit, now));
                            }
                            if let Some(filename) = &info.filename {
                                scratch.hits.clear();
                                sig_engine.check_buffer_into(&pkt, Buffer::TftpFilename, Direction::Any, filename.as_bytes(), &mut scratch.matcher, None, &mut scratch.hits);
                                for hit in scratch.hits.drain(..) {
                                    alerts.push(signature_alert(&pkt, Buffer::TftpFilename, &hit, now));
                                }
                            }
                        }
                    }
                    if pkt.protocol == PROTO_UDP && (pkt.src_port == 161 || pkt.dst_port == 161 || pkt.src_port == 162 || pkt.dst_port == 162) {
                        if let Some(community) = parse_snmp_community(pkt.payload()) {
                            scratch.hits.clear();
                            sig_engine.check_buffer_into(&pkt, Buffer::SnmpCommunity, Direction::Any, community.as_bytes(), &mut scratch.matcher, None, &mut scratch.hits);
                            for hit in scratch.hits.drain(..) {
                                alerts.push(signature_alert(&pkt, Buffer::SnmpCommunity, &hit, now));
                            }
                        }
                    }
                }

                if let Some(tx) = &flow_tx {
                    flow_table.take_completed(&mut flow_records);
                    datagram_flows.take_completed(&mut flow_records);
                    for rec in flow_records.drain(..) {
                        if tx.try_send(rec).is_err() {
                            flows_shed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                if let Some(tx) = &behavior_tx {
                    anom_engine.take_observations(&mut observations);
                    flow_table.take_observations(&mut observations);
                    datagram_flows.take_observations(&mut observations);
                    for obs in observations.drain(..) {
                        if tx.try_send(obs).is_err() {
                            observations_shed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                for a in alerts.drain(..) {
                    // Never block a worker on the writer: a full channel
                    // means the writer is already behind, and stalling
                    // detection would push the loss upstream to the
                    // capture queue where it costs whole packets rather
                    // than individual alerts.
                    if alert_tx.try_send(a).is_err() {
                        alerts_shed.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Back to the pool. Dropping it would work, but would
                // turn a recycled buffer into an allocate/free pair per
                // packet — the cost this exists to avoid.
                let _ = free_tx.send(boxed);
            }

            // Connections still open when the worker stops are still
            // facts about what was observed, so they're written with
            // state `open` rather than dropped.
            //
            // Flushed unconditionally: the tables themselves know whether
            // records and observations are wanted, and gating the flush on
            // `-flow-log` meant that with behavioural detection on but the
            // flow log off, nothing was flushed at all.
            alerts.clear();
            flow_table.flush_open_flows(&mut flow_records, &mut alerts);
            datagram_flows.flush(&mut flow_records);
            if let Some(tx) = &flow_tx {
                for rec in flow_records.drain(..) {
                    if tx.try_send(rec).is_err() {
                        flows_shed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            } else {
                flow_records.clear();
            }
            if let Some(tx) = &behavior_tx {
                flow_table.take_observations(&mut observations);
                datagram_flows.take_observations(&mut observations);
                anom_engine.take_observations(&mut observations);
                for obs in observations.drain(..) {
                    if tx.try_send(obs).is_err() {
                        observations_shed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            // Alerts raised by the flush (protocol anomalies on flows
            // that were still open) still have somewhere to go.
            for a in alerts.drain(..) {
                if alert_tx.try_send(a).is_err() {
                    alerts_shed.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Reported once per worker at shutdown. Each of these means
            // detection quietly stopped covering something.
            Metrics::add(&metrics.intel_hits, flow_table.intel_hits());
            Metrics::add(&metrics.flows_refused, flow_table.flows_refused());
            let anom = anom_engine.limit_stats();
            Metrics::add(&metrics.sources_refused, anom.sources_refused);
            Metrics::add(&metrics.destinations_refused, anom.destinations_refused);
            limit_report.lock().map(|mut r| r.push(WorkerLimits {
                sources_refused: anom.sources_refused,
                destinations_refused: anom.destinations_refused,
                udp_pairs_refused: anom.udp_pairs_refused,
                flows_refused: flow_table.flows_refused(),
            })).ok();
        }));
    }
    // Both dropped here, immediately after spawning, not at shutdown:
    // each worker holds its own clone, so these originals only serve to
    // keep the channels open past the point where anything still writes
    // to them. Holding `behavior_tx` to the end deadlocked shutdown —
    // see the note above this line's history in the README.
    drop(alert_tx);
    drop(behavior_tx);

    println!(
        "argus: {} with {} workers (window={:?} rate-limit={}/s scan-limit={}{})",
        match &replay_path {
            Some(path) => format!("replaying {}", path),
            None => format!("listening on {}", ifaces.join(", ")),
        },
        workers,
        args.window,
        args.rate_threshold,
        args.scan_threshold,
        match args.format {
            Format::Text => "",
            Format::Json => ", json output",
            Format::Eve => ", eve output",
        }
    );
    {
        let loaded = sig_engine.load();
        if loaded.rules.v2_len() > 0 {
            println!("argus: {} v2 rules loaded (header-scoped, multi-content)", loaded.rules.v2_len());
        }
    }
    println!("argus: alerts to {}", sink_descriptions.join(", "));
    if let Some(path) = &args.config {
        println!("argus: configuration from {}", path);
    }
    if !intel_stats_is_empty(&intel_stats) {
        println!(
            "argus: enrichment loaded — {} addresses, {} domains, {} JA3, {} allowlist entries, {} home-net ranges",
            intel_stats.addresses, intel_stats.domains, intel_stats.ja3, intel_stats.allow, intel_stats.home_net
        );
    }
    report_queue_memory(args.packet_pool.max(workers * 2).max(64), workers, args.queue_size);
    if pcap_enabled {
        println!("argus: saving a .pcap to {}/ for each alert (last {} packets of traffic)", args.pcap_dir, args.pcap_retain);
    } else if replaying {
        println!("argus: pcap-on-alert disabled (replaying a capture; pass -pcap-retain <n> to force it on)");
    } else {
        println!("argus: pcap-on-alert disabled (-pcap-retain 0)");
    }

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        ctrlc::set_handler(move || {
            println!("\nargus: shutting down...");
            running.store(false, Ordering::SeqCst);
        })?;
    }

    // Both are `Some` exactly when `pcap_enabled`, so this covers every
    // reachable case.
    let mut dumps = match (pcap_rx, pcap_write_tx) {
        (Some(rx), Some(write_tx)) => Some(DumpService {
            rx,
            write_tx,
            ring: PcapRing::new(args.pcap_retain),
            dir: std::path::PathBuf::from(&args.pcap_dir),
            seq: 0,
        }),
        _ => None,
    };

    // The one genuinely mode-specific step: `from_file` yields a
    // `Capture<Offline>` and `from_device(..).open()` a
    // `Capture<Active>`. Both implement `pcap::Activated`, so from here
    // on a replay runs the byte-identical detection path a live capture
    // does — `run_capture` is generic rather than duplicated precisely
    // so the two can't drift apart.
    let payload_cap = args.payload_cap.clamp(1, MAX_INSPECT_BYTES);
    if payload_cap != args.payload_cap {
        println!("argus: -payload-cap clamped to {} (the per-packet array size)", payload_cap);
    }
    let defrag_limits = DefragLimits { policy: args.frag_policy, ..DefragLimits::default() };
    println!("argus: overlapping fragments resolve {}", args.frag_policy.name());

    // --- operational services ---
    let metrics_server = match &args.metrics {
        Some(spec) => {
            let server = MetricsServer::start(spec, Arc::clone(&metrics))?;
            println!("argus: metrics on http://{}/metrics", server.addr);
            Some(server)
        }
        None => None,
    };

    // Watching only makes sense against a live capture: a replay is over
    // in seconds and must produce identical results every time, which a
    // mid-run rule change would break.
    let reloader = if replaying {
        None
    } else {
        start_reloader(&args, &intel_sources, Arc::clone(&sig_engine), Arc::clone(&intel), Arc::clone(&metrics), Arc::clone(&signals.reload), Arc::clone(&running))
    };

    let (stats, decode_stats) = match &replay_path {
        Some(path) => {
            let mut cap = pcap::Capture::from_file(path)?;
            let link = LinkType::from_dlt(cap.get_datalink().0);
            report_link_type(link, path);
            if let Some(expr) = &args.filter {
                cap.filter(expr, true)?;
            }
            let mut decoder = Decoder::new(link, payload_cap, defrag_limits);
            let stats = run_capture(&mut cap, worker_txs, &running, &mut dumps, &mut decoder, &pool, true, &metrics);
            (stats, decoder.stats)
        }
        None if ifaces.len() == 1 => {
            let iface = ifaces[0].clone();
            let mut cap = open_live(&iface, args.filter.as_deref(), true)?;
            let link = LinkType::from_dlt(cap.get_datalink().0);
            report_link_type(link, &iface);
            let mut decoder = Decoder::new(link, payload_cap, defrag_limits);
            let stats = run_capture(&mut cap, worker_txs, &running, &mut dumps, &mut decoder, &pool, false, &metrics);
            report_capture_drops(&mut cap, &metrics);
            (stats, decoder.stats)
        }
        None => {
            // One capture thread per interface, all feeding the same
            // worker pool and the same packet pool.
            //
            // Sharing the pool is the point: the workers shard by host
            // pair, so a conversation seen on two interfaces still lands
            // on one worker and is reassembled once. Giving each
            // interface its own pool and workers would instead give each
            // a partial view of the same traffic.
            //
            // The main thread keeps `dumps` and services nothing, so
            // pcap-on-alert is off in this mode — see the check above.
            let mut handles = Vec::with_capacity(ifaces.len());
            for iface in ifaces.iter().cloned() {
                let txs = worker_txs.clone();
                let running = Arc::clone(&running);
                let filter = args.filter.clone();
                let pool = Arc::clone(&pool);
                let metrics = Arc::clone(&metrics);
                handles.push(std::thread::Builder::new().name(format!("argus-cap-{}", iface)).spawn(move || -> (CaptureStats, DecodeStats) {
                    let mut cap = match open_live(&iface, filter.as_deref(), false) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("argus: {}: {}", iface, e);
                            return (CaptureStats::default(), DecodeStats::default());
                        }
                    };
                    let link = LinkType::from_dlt(cap.get_datalink().0);
                    report_link_type(link, &iface);
                    let mut decoder = Decoder::new(link, payload_cap, defrag_limits);
                    let mut none = None;
                    let stats = run_capture(&mut cap, txs, &running, &mut none, &mut decoder, &pool, false, &metrics);
                    report_capture_drops(&mut cap, &metrics);
                    (stats, decoder.stats)
                })?);
            }
            // The clones each thread took are what keep the workers
            // alive; this original would otherwise hold them open past
            // the last capture thread finishing.
            drop(worker_txs);
            handles.into_iter().fold((CaptureStats::default(), DecodeStats::default()), |(cs, ds), h| {
                let (c, d) = h.join().unwrap_or_default();
                (cs.merged(c), ds.merged(d))
            })
        }
    };

    // `run_capture` already dropped the worker senders and (if dumping
    // is on) waited for the alert writer to hang up, so both of these
    // have finished or are about to.
    for h in worker_handles {
        let _ = h.join();
    }
    // The aggregator is a *producer* on the alert channel, so it has to
    // finish before the alert writer can. Its own channel closed when
    // the last worker dropped its clone.
    let behavior_stats = behavior_join.map(|h| h.join().unwrap_or_default());
    let gate_stats = gate_join.join().unwrap_or_default();
    let alerts: AlertStats = writer_handle.join().unwrap_or_default();
    // Dropped after the workers have finished, so the flow writer's
    // channel closes and its thread can end.
    drop(flow_tx);
    let flows_written = flow_writer_join.map(|h| h.join().unwrap_or(0)).unwrap_or(0);

    if let Some(h) = reloader {
        let _ = h.join();
    }
    drop(metrics_server);

    drop(dumps); // drops the write channel, so the pcap writer can finish
    if let Some(h) = pcap_writer_join {
        let _ = h.join();
    }

    println!(
        "argus: {} — {} frames read, {} packets decoded, {} fragments buffered, {} frames undecoded; {} alerts written, {} suppressed",
        if replaying { "replay complete" } else { "capture stopped" },
        stats.read,
        stats.decoded,
        stats.buffered,
        decode_stats.undecoded(),
        alerts.emitted,
        alerts.suppressed
    );
    if let Some(detail) = decode_stats.detail() {
        println!("argus: decode detail: {}", detail);
    }
    if stats.read > 0 && stats.decoded == 0 {
        println!("argus: nothing decoded at all — check the capture's link type reported above, and the decode detail");
    }
    if stats.dropped > 0 {
        println!("argus: dropped {} packets due to worker backpressure (raise -queue-size or -workers)", stats.dropped);
    }
    if stats.pool_exhausted > 0 {
        println!(
            "argus: shed {} frames with no free packet buffer — the whole pipeline was behind (raise -packet-pool, or -workers)",
            stats.pool_exhausted
        );
    }

    if alerts.suppression_resets > 0 {
        println!(
            "argus: alert suppression state was reset {} times — more distinct alerting sources than the table holds,              so some duplicate alerts got through",
            alerts.suppression_resets
        );
    }
    let shed = alerts_shed.load(Ordering::Relaxed);
    if shed > 0 {
        println!("argus: shed {} alerts — the alert channel was full (raise -alert-queue)", shed);
        Metrics::add(&metrics.alert_queue_full, shed);
    }
    let abandoned = argus::rules::backtrack_limit_hits();
    if abandoned > 0 {
        println!(
            "argus: {} regex matches were abandoned for exceeding their backtrack limit — a rule using `pcre_bt` is being defeated by its input, or is too greedy",
            abandoned
        );
    }
    if gate_stats.withheld > 0 {
        println!("argus: {} alerts withheld by rule thresholds", gate_stats.withheld);
    }
    if alerts.allowlisted > 0 {
        println!("argus: {} alerts dropped by allowlist entries", alerts.allowlisted);
    }
    if let Some(b) = behavior_stats {
        println!("argus: behavioural detection saw {} observations and raised {} alerts", b.observations, b.alerts);
        let obs_shed = observations_shed.load(Ordering::Relaxed);
        if obs_shed > 0 {
            println!("argus: shed {} behavioural observations — the aggregator was behind (raise -alert-queue)", obs_shed);
        }
        if b.sources_refused > 0 || b.pairs_refused > 0 || b.dns_domains_refused > 0 {
            println!(
                "argus: behavioural state hit its caps ({} sources, {} pairs, {} DNS domains refused) — detection was degraded",
                b.sources_refused, b.pairs_refused, b.dns_domains_refused
            );
        }
    }
    if args.flow_log.is_some() {
        println!("argus: wrote {} flow records", flows_written);
        let fshed = flows_shed.load(Ordering::Relaxed);
        if fshed > 0 {
            println!("argus: shed {} flow records — the flow channel was full (raise -alert-queue)", fshed);
        }
    }

    // Every one of these means detection stopped covering something.
    // Printed only when non-zero: on an ordinary run they all are, and a
    // wall of zeros trains people to skip the summary.
    let totals = limit_report.lock().map(|r| {
        r.iter().fold(WorkerLimits::default(), |mut acc, w| {
            acc.sources_refused += w.sources_refused;
            acc.destinations_refused += w.destinations_refused;
            acc.udp_pairs_refused += w.udp_pairs_refused;
            acc.flows_refused += w.flows_refused;
            acc
        })
    }).unwrap_or_default();
    let mut hit = Vec::new();
    if totals.sources_refused > 0 {
        hit.push(format!("{} source addresses untracked (-max-sources)", totals.sources_refused));
    }
    if totals.flows_refused > 0 {
        hit.push(format!("{} TCP connections untracked (-max-flows)", totals.flows_refused));
    }
    if totals.destinations_refused > 0 {
        hit.push(format!("{} destinations untracked per-source", totals.destinations_refused));
    }
    if totals.udp_pairs_refused > 0 {
        hit.push(format!("{} UDP reply-tracking entries dropped", totals.udp_pairs_refused));
    }
    if !hit.is_empty() {
        println!("argus: capacity limits reached — {}", hit.join(", "));
        println!("argus: detection was degraded for the traffic above, not merely slower. Raise the relevant cap or add workers.");
    }

    Ok(())
}