//! Behavioural detection: the questions that can only be answered by
//! looking across many flows, or across one source's whole footprint.
//!
//! # Why this is a separate stage
//!
//! Packets are sharded to workers by a canonical hash of the *host pair*
//! (see `main.rs`'s `hash_host_pair`), which is what lets each worker own
//! a connection's whole state with no locking. That sharding is also why
//! none of the detection here can live in a worker: `src=A, dst=B` and
//! `src=A, dst=C` hash to *different* shards, so a source sweeping a /24
//! is spread across every worker and no single one of them ever sees more
//! than a fraction of it. Raising a threshold cannot fix that; the
//! evidence genuinely isn't in one place.
//!
//! This is the same failure the project already hit once, when port-scan
//! evidence was scattered by 4-tuple sharding — fixed then by coarsening
//! the shard key from 4-tuple to host pair. Coarsening again, to source
//! alone, isn't available: TCP stream reassembly needs both directions of
//! a connection on one worker, and both directions only share a shard
//! because the key is symmetric in the two endpoints.
//!
//! So instead of moving the packets, the workers send small
//! [`Observation`]s — one per *event* (a probe, a completed flow, a DNS
//! question), not one per packet — to a single aggregator thread that
//! owns all cross-source state. One consumer means no locks, exactly as
//! with the alert writer.
//!
//! # What it does not do
//!
//! Nothing here is a signature. Every detector reports a *shape* —
//! "this source touched 300 hosts on one port", "this destination is
//! being contacted every 60 seconds to within a few percent" — and a
//! shape is evidence, not a verdict. They are tuned to be quiet rather
//! than thorough, because a behavioural alert that fires on backup jobs
//! and monitoring checks trains its reader to ignore it, which is worse
//! than not having it.

use rustc_hash::FxHashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::engine::{Alert, Severity};
use crate::packet::IpAddr;
use crate::window::{shannon_entropy, AlertGate, Periodicity, RateWindow, WindowSet};

/// Longest DNS name carried in an observation. Names longer than this
/// are truncated, which costs nothing that matters: the detectors use
/// length and entropy, and a name this long is already past every
/// threshold.
pub const DNS_NAME_MAX: usize = 128;

// =======================================================================
// Observations
// =======================================================================

/// One thing a worker noticed, cheap enough to send per event.
///
/// `Copy` and pointer-free for the same reason `Packet` is: it crosses a
/// channel as a plain memcpy with no allocator involvement on the
/// detection path.
#[derive(Clone, Copy)]
pub enum Observation {
    /// A credential-bearing command was seen — an FTP `USER`, an SMTP
    /// `AUTH`, an RDP cookie, an SSH banner exchange. This counts
    /// *attempts*. For the protocols whose replies ARGUS parses, the
    /// server's refusal arrives separately as [`Observation::AuthFailure`],
    /// which is the stronger signal; attempts remain the only evidence for
    /// protocols whose replies are encrypted (SSH, RDP), so the threshold
    /// stays high — a human does not try to authenticate twenty times a
    /// minute even when they keep getting it wrong.
    AuthAttempt { ts_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, service: &'static str },

    /// How many packets one worker saw from a source in one second.
    ///
    /// Packets are sharded by host *pair*, so a source flooding several
    /// destinations is split across workers and each sees a fraction of
    /// it. Only the sum is the flood, so the workers report their
    /// counts here and the sum is judged in one place.
    Volume { ts_sec: i64, src: IpAddr, packets: u32 },

    /// Bytes moved by a connection that is still open.
    ///
    /// A [`Observation::Flow`] is sent when a connection ends, so a
    /// long one (a download, a tunnel, a streaming upload) was invisible
    /// to the volume detectors for its whole life: a live run reported
    /// an exfiltration alert forty minutes after it began. This carries
    /// what has moved since the last report, feeds the volume
    /// detectors only, and does not count as a connection (which the scan
    /// and beacon detectors count from `Flow`).
    Traffic { ts_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, bytes_out: u64, bytes_in: u64 },

    /// The server *refused* a credential: an FTP 530, an SMTP 535, an HTTP
    /// 401, an SMB logon failure. `src` is the client that tried.
    ///
    /// This is the observation `AuthAttempt` was always standing in for.
    /// ARGUS long parsed only client commands, so brute force could count
    /// tries and never rejections, and a person mistyping twenty times is
    /// indistinguishable from a tool at that level. A rejection is the
    /// server's own testimony.
    AuthFailure { ts_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, service: &'static str },

    /// A connection finished, one way or another.
    ///
    /// This is now the *only* observation the scan detectors use. They
    /// were originally fed a `Probe` per TCP SYN, which turned out to be
    /// unusable: "many destinations on one port" describes a port sweep
    /// and equally describes a web browser, and a real capture duly
    /// produced 31 `HORIZONTAL_SCAN` alerts for one host visiting web
    /// servers. The distinguishing fact is `answered` — a sweep's
    /// destinations mostly don't reply — and that isn't known until the
    /// connection resolves. Waiting for it also cut observation volume
    /// from one per SYN to one per flow.
    Flow { ts_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, bytes_out: u64, bytes_in: u64, answered: bool },

    /// A DNS question, for tunnel-shape analysis.
    DnsQuery { ts_sec: i64, src: IpAddr, dst: IpAddr, name: [u8; DNS_NAME_MAX], name_len: u8 },
}

impl Observation {
    pub fn dns(ts_sec: i64, src: IpAddr, dst: IpAddr, qname: &str) -> Observation {
        let bytes = qname.as_bytes();
        let n = bytes.len().min(DNS_NAME_MAX);
        let mut name = [0u8; DNS_NAME_MAX];
        name[..n].copy_from_slice(&bytes[..n]);
        Observation::DnsQuery { ts_sec, src, dst, name, name_len: n as u8 }
    }

    /// A total order: time first, then every other field.
    ///
    /// Two runs that saw the same observations in different arrival orders
    /// sort to the same sequence, which is the whole point. Nothing else
    /// about them is compared for meaning; ties on time are broken by
    /// content only so that the result does not depend on which one a
    /// thread happened to send first.
    pub fn total_cmp(&self, other: &Observation) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }

    #[allow(clippy::type_complexity)]
    fn sort_key(&self) -> (i64, u8, (u8, [u8; 16]), (u8, [u8; 16]), u16, u64, u64, &[u8]) {
        fn ip(a: &IpAddr) -> (u8, [u8; 16]) {
            let mut out = [0u8; 16];
            match a {
                IpAddr::V4(b) => {
                    out[..4].copy_from_slice(b);
                    (4, out)
                }
                IpAddr::V6(b) => (6, *b),
            }
        }
        match self {
            Observation::AuthAttempt { ts_sec, src, dst, dst_port, service } => (*ts_sec, 0, ip(src), ip(dst), *dst_port, 0, 0, service.as_bytes()),
            Observation::Volume { ts_sec, src, packets } => (*ts_sec, 4, ip(src), ip(&IpAddr::UNSPECIFIED), 0, *packets as u64, 0, &[]),
            Observation::Traffic { ts_sec, src, dst, dst_port, bytes_out, bytes_in } => (*ts_sec, 5, ip(src), ip(dst), *dst_port, *bytes_out, *bytes_in, &[]),
            Observation::AuthFailure { ts_sec, src, dst, dst_port, service } => (*ts_sec, 1, ip(src), ip(dst), *dst_port, 0, 0, service.as_bytes()),
            Observation::Flow { ts_sec, src, dst, dst_port, bytes_out, bytes_in, answered } => {
                (*ts_sec, 2, ip(src), ip(dst), *dst_port, *bytes_out, (bytes_in << 1) | *answered as u64, &[])
            }
            Observation::DnsQuery { ts_sec, src, dst, name, name_len } => (*ts_sec, 3, ip(src), ip(dst), 0, 0, 0, &name[..*name_len as usize]),
        }
    }

    fn ts_sec(&self) -> i64 {
        match self {
            Observation::AuthAttempt { ts_sec, .. }
            | Observation::AuthFailure { ts_sec, .. }
            | Observation::Flow { ts_sec, .. }
            | Observation::Volume { ts_sec, .. }
            | Observation::Traffic { ts_sec, .. }
            | Observation::DnsQuery { ts_sec, .. } => *ts_sec,
        }
    }
}

/// Group addresses and broadcasts, including the directed broadcast of a
/// private network (`192.168.0.255`).
///
/// A directed broadcast cannot be recognised without knowing the netmask,
/// which a sensor does not. On the private ranges a host address ending in
/// 255 is overwhelmingly a broadcast (a /24 is the common case), and
/// treating one as a beacon target is the far more expensive mistake: a live
/// run flagged an application announcing itself to `192.168.0.255` every six
/// seconds, which is exactly what such an announcement is.
fn is_broadcast_like(dst: &IpAddr) -> bool {
    if dst.is_multicast_or_broadcast() {
        return true;
    }
    match dst {
        IpAddr::V4(o) => o[3] == 255 && (o[0] == 10 || (o[0] == 172 && (16..32).contains(&o[1])) || (o[0] == 192 && o[1] == 168)),
        _ => false,
    }
}

// =======================================================================
// Configuration
// =======================================================================

#[derive(Clone, Copy)]
pub struct BehaviorConfig {
    pub window: Duration,
    /// Minimum gap between repeats of the same behavioural alert.
    /// Longer than the anomaly engine's, because these describe ongoing
    /// campaigns rather than instantaneous conditions.
    pub alert_min_interval_secs: i64,

    /// Distinct destination hosts that **failed to answer** on the same
    /// port before `HORIZONTAL_SCAN`.
    ///
    /// Both halves matter. Keyed on the port, because a sweep asks many
    /// hosts about the *same* service while a browser asks many hosts
    /// about many things. Counting only unanswered destinations, because
    /// a browser's connections succeed and a sweep's mostly don't —
    /// without that second half this fires on ordinary web browsing, as
    /// a real capture demonstrated.
    pub horizontal_scan_hosts: usize,
    /// Distinct unanswered destinations on any port at all, a higher bar,
    /// to catch a sweep spread across ports.
    pub horizontal_scan_hosts_any_port: usize,

    /// Authentication attempts to one service before `BRUTE_FORCE`.
    pub brute_force_attempts: u64,
    /// Refusals from the server before `BRUTE_FORCE`. Far lower than the
    /// attempt limit, because a refusal is evidence and an attempt is only
    /// activity: a handful of rejected logins in a few minutes is not what
    /// a person does.
    pub brute_force_failures: u64,

    /// Ignore beacon candidates faster than this: sub-second regularity
    /// is what normal protocols look like (keepalives, polling), not
    /// what makes C2 interesting.
    pub beacon_min_mean_secs: f64,
    /// Coefficient of variation at or below which recurrence counts as
    /// machine-timed. 0.15 admits ~15% jitter, which covers the jitter
    /// most implants use while excluding human-driven traffic.
    pub beacon_max_cv: f64,
    /// Minimum gap between beacon alerts for the same destination.
    ///
    /// Separate from, and much longer than, the general alert interval.
    /// Using the general one meant a 60-second beacon re-alerted every 60
    /// seconds, because each new beacon arrives exactly one gate-interval
    /// later — the gate and the signal had the same period, so it never
    /// suppressed anything. A beacon is an ongoing condition worth
    /// restating occasionally, not every time it ticks.
    pub beacon_alert_interval_secs: i64,

    /// Outbound bytes from one source within the window before
    /// `DATA_EXFIL_VOLUME`.
    pub exfil_bytes: u64,
    /// Out:in ratio, with a floor on the absolute volume, before
    /// `DATA_EXFIL_RATIO`. Ratio alone flags every upload of anything;
    /// volume alone flags every legitimate backup. Together they
    /// describe the actual shape of interest: a lot of data leaving a
    /// host that normally receives.
    pub exfil_ratio: f64,
    pub exfil_ratio_min_bytes: u64,

    /// A single DNS name this long is worth noticing on its own.
    pub dns_name_len: usize,
    /// Minimum Shannon entropy (bits/byte) of the subdomain part for it
    /// to count as encoded rather than named.
    pub dns_min_entropy: f64,
    /// Distinct high-entropy subdomains under one parent domain before
    /// `DNS_TUNNEL`. The count is the real signal — one long random
    /// label is a CDN cache key, hundreds of them is a channel.
    pub dns_distinct_subdomains: usize,

    /// Caps. Per-key state here is keyed on attacker-chosen values, so
    /// the same rules apply as everywhere else in the pipeline.
    pub max_sources: usize,
    pub max_pairs: usize,
    pub max_dns_domains: usize,
    /// The flood limit, judged on the sum across every worker: packets
    /// from one source inside `flood_window_secs`.
    pub flood_limit: u64,
    pub flood_window_secs: i64,
    pub flood_min_interval_secs: i64,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        BehaviorConfig {
            window: Duration::from_secs(300),
            alert_min_interval_secs: 60,
            horizontal_scan_hosts: 25,
            horizontal_scan_hosts_any_port: 200,
            brute_force_attempts: 15,
            brute_force_failures: 8,
            beacon_min_mean_secs: 5.0,
            beacon_max_cv: 0.15,
            beacon_alert_interval_secs: 900,
            exfil_bytes: 100 * 1024 * 1024,
            exfil_ratio: 20.0,
            exfil_ratio_min_bytes: 5 * 1024 * 1024,
            dns_name_len: 100,
            dns_min_entropy: 3.2,
            dns_distinct_subdomains: 40,
            max_sources: 16384,
            max_pairs: 65536,
            max_dns_domains: 16384,
            flood_limit: 5000,
            flood_window_secs: 10,
            flood_min_interval_secs: 10,
        }
    }
}

// =======================================================================
// Per-key state
// =======================================================================

struct SrcState {
    /// Distinct hosts that never answered, per destination port.
    unanswered_by_port: FxHashMap<u16, WindowSet<IpAddr>>,
    /// Distinct hosts that never answered, on any port.
    unanswered_any: WindowSet<IpAddr>,
    bytes_out: RateWindow,
    bytes_in: RateWindow,
    scan_gate: AlertGate,
    /// Packets from this source in the flood window, over all workers.
    packets: RateWindow,
    flood_gate: AlertGate,
    scan_any_gate: AlertGate,
    exfil_gate: AlertGate,
    ratio_gate: AlertGate,
    last_seen: i64,
}

struct PairState {
    auth_attempts: RateWindow,
    auth_gate: AlertGate,
    auth_failures: RateWindow,
    failure_gate: AlertGate,
    beacon: Periodicity,
    beacon_gate: AlertGate,
    last_seen: i64,
}

struct DnsState {
    subdomains: WindowSet<u64>,
    gate: AlertGate,
    long_name_gate: AlertGate,
    last_seen: i64,
}

#[derive(Default, Clone, Copy, Debug)]
pub struct BehaviorStats {
    pub observations: u64,
    pub alerts: u64,
    pub sources_refused: u64,
    pub pairs_refused: u64,
    pub dns_domains_refused: u64,
}

// =======================================================================
// The engine
// =======================================================================

pub struct BehaviorEngine {
    cfg: BehaviorConfig,
    sources: FxHashMap<IpAddr, SrcState>,
    pairs: FxHashMap<(IpAddr, IpAddr, u16), PairState>,
    dns: FxHashMap<(IpAddr, u64), DnsState>,
    last_swept: i64,
    stats: BehaviorStats,
}

impl BehaviorEngine {
    pub fn new(cfg: BehaviorConfig) -> Self {
        BehaviorEngine {
            cfg,
            sources: FxHashMap::default(),
            pairs: FxHashMap::default(),
            dns: FxHashMap::default(),
            last_swept: 0,
            stats: BehaviorStats::default(),
        }
    }

    pub fn stats(&self) -> BehaviorStats {
        self.stats
    }

    fn window_secs(&self) -> i64 {
        self.cfg.window.as_secs() as i64
    }

    /// Releases state for keys not seen within the window. Time-gated,
    /// and the hard caps below are what actually bound the tables — this
    /// only keeps them from sitting at the cap indefinitely.
    fn sweep(&mut self, now_sec: i64) {
        if now_sec <= self.last_swept {
            return;
        }
        self.last_swept = now_sec;
        let cutoff = now_sec - self.window_secs();
        self.sources.retain(|_, s| s.last_seen > cutoff);
        self.pairs.retain(|_, p| p.last_seen > cutoff);
        self.dns.retain(|_, d| d.last_seen > cutoff);
    }

    pub fn observe(&mut self, obs: &Observation, out: &mut Vec<Alert>) {
        let now_sec = obs.ts_sec();
        self.sweep(now_sec);
        self.stats.observations += 1;
        let before = out.len();

        match obs {
            Observation::AuthAttempt { src, dst, dst_port, service, .. } => self.on_auth(now_sec, *src, *dst, *dst_port, service, out),
            Observation::AuthFailure { src, dst, dst_port, service, .. } => self.on_auth_failure(now_sec, *src, *dst, *dst_port, service, out),
            Observation::Flow { src, dst, dst_port, bytes_out, bytes_in, answered, .. } => {
                if !answered {
                    self.on_failed_connection(now_sec, *src, *dst, *dst_port, out);
                }
                self.on_flow(now_sec, *src, *dst, *dst_port, *bytes_out, *bytes_in, out)
            }
            Observation::Volume { src, packets, .. } => self.on_volume(now_sec, *src, *packets, out),
            Observation::Traffic { src, dst, dst_port, bytes_out, bytes_in, .. } => {
                if !is_broadcast_like(dst) {
                    self.on_bytes(now_sec, *src, *dst, *dst_port, *bytes_out, *bytes_in, out)
                }
            }
            Observation::DnsQuery { src, dst, name, name_len, .. } => self.on_dns(now_sec, *src, *dst, &name[..*name_len as usize], out),
        }

        self.stats.alerts += (out.len() - before) as u64;
    }

    /// A worker's per-second packet count for one source.
    fn on_volume(&mut self, now_sec: i64, src: IpAddr, packets: u32, out: &mut Vec<Alert>) {
        let (limit, interval, window) = (self.cfg.flood_limit, self.cfg.flood_min_interval_secs, self.cfg.flood_window_secs.max(1));
        let Some(s) = self.source(src, now_sec) else { return };
        let total = s.packets.add(now_sec, packets as u64);
        if total > limit && s.flood_gate.allow(now_sec, interval) {
            out.push(Alert {
                timestamp: to_time(now_sec),
                severity: Severity::High,
                category: "PACKET_FLOOD",
                src,
                dst: IpAddr::UNSPECIFIED,
                proto: "IP",
                port: 0,
                message: format!("{} packets from this source in the last {}s across all destinations (limit {})", total, window, limit),
                sid: 0,
            });
        }
    }

    /// Borrows (or creates) per-source state, refusing past the cap.
    fn source(&mut self, src: IpAddr, now_sec: i64) -> Option<&mut SrcState> {
        let window = self.window_secs();
        if !self.sources.contains_key(&src) && self.sources.len() >= self.cfg.max_sources {
            self.stats.sources_refused += 1;
            return None;
        }
        let cap = self.cfg.max_pairs;
        let cfg_flood_window = self.cfg.flood_window_secs.max(1);
        let s = self.sources.entry(src).or_insert_with(|| SrcState {
            unanswered_by_port: FxHashMap::default(),
            unanswered_any: WindowSet::new(cap),
            bytes_out: RateWindow::new(window),
            bytes_in: RateWindow::new(window),
            scan_gate: AlertGate::default(),
            packets: RateWindow::new(cfg_flood_window),
            flood_gate: AlertGate::default(),
            scan_any_gate: AlertGate::default(),
            exfil_gate: AlertGate::default(),
            ratio_gate: AlertGate::default(),
            last_seen: now_sec,
        });
        s.last_seen = now_sec;
        Some(s)
    }

    // --- horizontal scan ---------------------------------------------

    /// A connection attempt that the far end never answered.
    fn on_failed_connection(&mut self, now_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, out: &mut Vec<Alert>) {
        let cfg = self.cfg;
        let window = self.window_secs();
        let proto = "TCP";
        let Some(s) = self.source(src, now_sec) else { return };

        // Per-port sweep: many unanswered hosts, one service.
        let per_port = s
            .unanswered_by_port
            .entry(dst_port)
            .or_insert_with(|| WindowSet::new(cfg.max_pairs))
            .insert(dst, now_sec, window);
        // Bound the per-port map itself, not just each set inside it.
        if s.unanswered_by_port.len() > 1024 {
            s.unanswered_by_port.retain(|_, w| !w.is_empty());
        }

        let any_port = s.unanswered_any.insert(dst, now_sec, window);

        if per_port > cfg.horizontal_scan_hosts && s.scan_gate.allow(now_sec, cfg.alert_min_interval_secs) {
            out.push(Alert {
                timestamp: to_time(now_sec),
                severity: Severity::High,
                category: "HORIZONTAL_SCAN",
                src,
                dst,
                proto,
                port: dst_port,
                message: format!(
                    "{} distinct hosts probed on port {} without answering in the last {:?} (limit {}) — a sweep for one service across the network",
                    per_port, dst_port, cfg.window, cfg.horizontal_scan_hosts
                ),
                sid: 0,
            });
        }

        if any_port > cfg.horizontal_scan_hosts_any_port && s.scan_any_gate.allow(now_sec, cfg.alert_min_interval_secs) {
            out.push(Alert {
                timestamp: to_time(now_sec),
                severity: Severity::Medium,
                category: "HOST_SWEEP",
                src,
                dst,
                proto,
                port: dst_port,
                message: format!(
                    "{} distinct hosts contacted without answering in the last {:?} (limit {}) — a sweep spread across ports",
                    any_port, cfg.window, cfg.horizontal_scan_hosts_any_port
                ),
                sid: 0,
            });
        }
    }

    // --- brute force and beaconing (per source/destination/service) ---

    fn pair(&mut self, key: (IpAddr, IpAddr, u16), now_sec: i64) -> Option<&mut PairState> {
        let window = self.window_secs();
        if !self.pairs.contains_key(&key) && self.pairs.len() >= self.cfg.max_pairs {
            self.stats.pairs_refused += 1;
            return None;
        }
        let p = self.pairs.entry(key).or_insert_with(|| PairState {
            auth_attempts: RateWindow::new(window),
            auth_gate: AlertGate::default(),
            auth_failures: RateWindow::new(window),
            failure_gate: AlertGate::default(),
            beacon: Periodicity::default(),
            beacon_gate: AlertGate::default(),
            last_seen: now_sec,
        });
        p.last_seen = now_sec;
        Some(p)
    }

    fn on_auth(&mut self, now_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, service: &'static str, out: &mut Vec<Alert>) {
        let cfg = self.cfg;
        let Some(p) = self.pair((src, dst, dst_port), now_sec) else { return };
        let attempts = p.auth_attempts.add(now_sec, 1);
        if attempts > cfg.brute_force_attempts && p.auth_gate.allow(now_sec, cfg.alert_min_interval_secs) {
            out.push(Alert {
                timestamp: to_time(now_sec),
                severity: Severity::High,
                category: "BRUTE_FORCE",
                src,
                dst,
                proto: "TCP",
                port: dst_port,
                message: format!(
                    "{} {} authentication attempts in the last {:?} (limit {}) — note these are attempts, not observed failures",
                    attempts, service, cfg.window, cfg.brute_force_attempts
                ),
                sid: 0,
            });
        }
    }

    fn on_auth_failure(&mut self, now_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, service: &'static str, out: &mut Vec<Alert>) {
        let cfg = self.cfg;
        let Some(p) = self.pair((src, dst, dst_port), now_sec) else { return };
        let failures = p.auth_failures.add(now_sec, 1);
        if failures > cfg.brute_force_failures && p.failure_gate.allow(now_sec, cfg.alert_min_interval_secs) {
            out.push(Alert {
                timestamp: to_time(now_sec),
                severity: Severity::High,
                category: "BRUTE_FORCE",
                src,
                dst,
                proto: "TCP",
                port: dst_port,
                message: format!(
                    "{} {} authentications refused by the server in the last {:?} (limit {}) — observed failures, not merely attempts",
                    failures, service, cfg.window, cfg.brute_force_failures
                ),
                sid: 0,
            });
        }
    }

    fn on_flow(&mut self, now_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, bytes_out: u64, bytes_in: u64, out: &mut Vec<Alert>) {
        let cfg = self.cfg;

        // Beaconing is judged on connection *starts* to one service.
        //
        // Multicast and broadcast destinations are excluded outright, not
        // merely tuned around. Service-discovery protocols — SSDP/UPnP on
        // 239.255.255.250:1900, mDNS, NetBIOS — re-announce on a fixed
        // timer because the specification says to, so they are perfectly
        // periodic *by design*, and "perfectly periodic" is the whole of
        // the beacon signal. A live run flagged 239.255.255.250:1900 at
        // 0.0% jitter: the detector was right about the traffic and wrong
        // about what it meant. No threshold fixes that, because a beacon
        // to a group address isn't covert command-and-control in the
        // first place — nothing is listening in particular.
        //
        // The return skips the volume checks below as well, which is
        // deliberate: those are per-source totals, and group traffic is
        // almost never answered, so counting it would push every host's
        // out/in ratio up for reasons that have nothing to do with
        // exfiltration. You cannot exfiltrate to a multicast group off
        // the local segment anyway.
        if is_broadcast_like(&dst) {
            return;
        }
        if let Some(p) = self.pair((src, dst, dst_port), now_sec) {
            if let Some((mean, cv)) = p.beacon.observe(now_sec) {
                let regular = cv <= cfg.beacon_max_cv && mean >= cfg.beacon_min_mean_secs;
                if regular && p.beacon_gate.allow(now_sec, cfg.beacon_alert_interval_secs) {
                    let samples = p.beacon.samples();
                    out.push(Alert {
                        timestamp: to_time(now_sec),
                        severity: Severity::Medium,
                        category: "BEACONING",
                        src,
                        dst,
                        proto: "TCP",
                        port: dst_port,
                        message: format!(
                            "{} connections spaced {:.0}s apart with {:.1}% jitter — machine-timed recurrence, not human traffic",
                            samples,
                            mean,
                            cv * 100.0
                        ),
                        sid: 0,
                    });
                }
            }
        }

        self.on_bytes(now_sec, src, dst, dst_port, bytes_out, bytes_in, out);
    }

    /// Volume is judged per source across all its flows, and across a
    /// flow's life: both a finished connection and an open one report here.
    #[allow(clippy::too_many_arguments)]
    fn on_bytes(&mut self, now_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16, bytes_out: u64, bytes_in: u64, out: &mut Vec<Alert>) {
        let cfg = self.cfg;
        let Some(s) = self.source(src, now_sec) else { return };
        let total_out = s.bytes_out.add(now_sec, bytes_out);
        let total_in = s.bytes_in.add(now_sec, bytes_in);

        if total_out > cfg.exfil_bytes && s.exfil_gate.allow(now_sec, cfg.alert_min_interval_secs) {
            out.push(Alert {
                timestamp: to_time(now_sec),
                severity: Severity::Medium,
                category: "DATA_EXFIL_VOLUME",
                src,
                dst,
                proto: "TCP",
                port: dst_port,
                message: format!("{} MB sent in the last {:?} (limit {} MB)", total_out / 1_048_576, cfg.window, cfg.exfil_bytes / 1_048_576),
                sid: 0,
            });
        }

        // Ratio needs a volume floor, or it fires on every small upload.
        if total_out > cfg.exfil_ratio_min_bytes {
            let ratio = total_out as f64 / total_in.max(1) as f64;
            if ratio > cfg.exfil_ratio && s.ratio_gate.allow(now_sec, cfg.alert_min_interval_secs) {
                out.push(Alert {
                    timestamp: to_time(now_sec),
                    severity: Severity::Medium,
                    category: "DATA_EXFIL_RATIO",
                    src,
                    dst,
                    proto: "TCP",
                    port: dst_port,
                    message: format!(
                        "sent {:.0}x more than received ({} MB out, {} MB in) in the last {:?}",
                        ratio,
                        total_out / 1_048_576,
                        total_in / 1_048_576,
                        cfg.window
                    ),
                    sid: 0,
                });
            }
        }
    }

    // --- DNS tunnelling ----------------------------------------------

    fn on_dns(&mut self, now_sec: i64, src: IpAddr, dst: IpAddr, name: &[u8], out: &mut Vec<Alert>) {
        let cfg = self.cfg;
        let window = self.window_secs();
        let (parent, sub) = split_dns_name(name);
        let parent_hash = fnv1a(parent);

        if !self.dns.contains_key(&(src, parent_hash)) && self.dns.len() >= cfg.max_dns_domains {
            self.stats.dns_domains_refused += 1;
            return;
        }
        let entry = self.dns.entry((src, parent_hash)).or_insert_with(|| DnsState {
            subdomains: WindowSet::new(cfg.max_pairs),
            gate: AlertGate::default(),
            long_name_gate: AlertGate::default(),
            last_seen: now_sec,
        });
        entry.last_seen = now_sec;

        // A single very long name is worth one low-severity note. Cheap,
        // and the thing a human would notice first in a packet capture.
        if name.len() >= cfg.dns_name_len && entry.long_name_gate.allow(now_sec, cfg.alert_min_interval_secs) {
            out.push(Alert {
                timestamp: to_time(now_sec),
                severity: Severity::Low,
                category: "DNS_LONG_NAME",
                src,
                dst,
                proto: "UDP",
                port: 53,
                message: format!("{}-byte DNS name queried (limit {})", name.len(), cfg.dns_name_len),
                sid: 0,
            });
        }

        // The real signal: many *distinct, high-entropy* subdomains under
        // one parent. Encoded tunnel payloads are near-uniform over their
        // alphabet; hostnames are not. Entropy is checked before counting
        // so that a site with thousands of ordinary subdomains doesn't
        // accumulate toward the threshold.
        if sub.len() >= 8 && shannon_entropy(sub) >= cfg.dns_min_entropy {
            let distinct = entry.subdomains.insert(fnv1a(sub), now_sec, window);
            if distinct > cfg.dns_distinct_subdomains && entry.gate.allow(now_sec, cfg.alert_min_interval_secs) {
                out.push(Alert {
                    timestamp: to_time(now_sec),
                    severity: Severity::High,
                    category: "DNS_TUNNEL",
                    src,
                    dst,
                    proto: "UDP",
                    port: 53,
                    message: format!(
                        "{} distinct high-entropy subdomains under {:?} in the last {:?} (limit {}) — consistent with data carried over DNS",
                        distinct,
                        String::from_utf8_lossy(parent),
                        cfg.window,
                        cfg.dns_distinct_subdomains
                    ),
                    sid: 0,
                });
            }
        }
    }
}

/// Splits a DNS name into its registrable-ish parent (last two labels)
/// and everything to the left of it.
///
/// Two labels is a deliberate simplification: a real public-suffix list
/// would be needed to get `co.uk` right, and shipping one is a data
/// dependency that goes stale. The cost of being wrong is bounded — a
/// tunnel under `foo.co.uk` gets grouped under `co.uk` along with every
/// other `.co.uk` domain, which makes the count *more* likely to trip,
/// not less. Over-grouping loses precision about which domain; it does
/// not lose the detection.
fn split_dns_name(name: &[u8]) -> (&[u8], &[u8]) {
    let dots: Vec<usize> = name.iter().enumerate().filter(|(_, &b)| b == b'.').map(|(i, _)| i).collect();
    if dots.len() < 2 {
        return (name, &[]);
    }
    let cut = dots[dots.len() - 2];
    (&name[cut + 1..], &name[..cut])
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn to_time(sec: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(sec.max(0) as u64)
}

/// How many observations replay holds back to sort before processing.
///
/// A replay's observations are small and one per flow, so this is never
/// reached by an ordinary capture (the 800,000-frame test capture makes
/// about 35,000). It exists so a very large capture cannot hold memory
/// without limit: past it, the held observations are sorted and
/// processed as a batch, and ordering holds within each batch only.
/// How much capture time a live capture holds observations for.
pub const LIVE_REORDER_SECS: i64 = 2;

pub const MAX_ORDERED_OBSERVATIONS: usize = 2_000_000;

/// Runs the aggregator on its own thread, draining observations and
/// pushing alerts into the ordinary alert channel so they suppress, log
/// and dump exactly like any other alert.
///
/// # Ordered mode
///
/// Observations arrive from every worker in whatever order the scheduler
/// ran them, and several detectors are *online*: the exfiltration ratio is
/// tested as each observation lands, so a large upload arriving a moment
/// before the download it was answered by is a transient spike, and the
/// reverse order is not. Replay of one file therefore produced different
/// alerts on different runs, which is precisely what replay exists not to
/// do.
///
/// With `ordered` set the aggregator holds observations until the capture
/// ends and processes them in capture-time order. That is also simply the
/// more correct order: a flow's observation carries its *start* time but
/// is sent when it *finishes*, so arrival order was never chronological.
///
/// A live capture cannot wait for the end, so it holds observations for
/// [`LIVE_REORDER_SECS`] of capture time and orders within that window. That
/// removes worker-scheduling skew, which is milliseconds; it does not
/// reorder a long flow that ended after the window closed.
pub fn run_behavior_engine(
    rx: crossbeam_channel::Receiver<Observation>,
    alert_tx: crossbeam_channel::Sender<Alert>,
    cfg: BehaviorConfig,
    ordered: bool,
) -> BehaviorStats {
    let mut engine = BehaviorEngine::new(cfg);
    let mut alerts = Vec::new();

    let mut process = |engine: &mut BehaviorEngine, obs: &Observation| {
        alerts.clear();
        engine.observe(obs, &mut alerts);
        for a in alerts.drain(..) {
            // Best-effort, like every other producer on this channel: a
            // full channel means the writer is behind, and blocking here
            // would stall the aggregator and back up into the workers.
            if alert_tx.try_send(a).is_err() {
                break;
            }
        }
    };

    if !ordered {
        // Live: a short reorder window rather than the whole capture.
        //
        // Workers run in whatever order the scheduler chose, so two
        // observations from the same instant reach this thread in either
        // order, and the online detectors are sensitive to it. Holding
        // each for `LIVE_REORDER_SECS` of capture time and processing in
        // time order removes that skew. A flow's observation is stamped
        // with its *start* and sent when it *ends*, so a long flow still
        // arrives later than the window and is handled on arrival, as
        // before; the window is for scheduling skew, not for that.
        let mut held: Vec<Observation> = Vec::new();
        let mut newest = i64::MIN;
        let mut oldest_held = i64::MAX;
        loop {
            let flush_all = match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(obs) => {
                    let ts = obs.ts_sec();
                    newest = newest.max(ts);
                    oldest_held = oldest_held.min(ts);
                    held.push(obs);
                    false
                }
                // Quiet: nothing more is coming to be ordered against.
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => true,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    held.sort_unstable_by(Observation::total_cmp);
                    for o in &held {
                        process(&mut engine, o);
                    }
                    return engine.stats();
                }
            };
            let cutoff = newest.saturating_sub(LIVE_REORDER_SECS);
            if !held.is_empty() && (flush_all || oldest_held <= cutoff) {
                held.sort_unstable_by(Observation::total_cmp);
                let ready = if flush_all { held.len() } else { held.partition_point(|o| o.ts_sec() <= cutoff) };
                for o in held.drain(..ready) {
                    process(&mut engine, &o);
                }
                oldest_held = held.iter().map(Observation::ts_sec).min().unwrap_or(i64::MAX);
            }
        }
    }

    let mut held: Vec<Observation> = Vec::new();
    let mut warned = false;
    for obs in rx.iter() {
        held.push(obs);
        if held.len() >= MAX_ORDERED_OBSERVATIONS {
            if !warned {
                eprintln!("argus: more than {} observations in one replay; behavioural ordering holds within batches of that size only", MAX_ORDERED_OBSERVATIONS);
                warned = true;
            }
            held.sort_unstable_by(Observation::total_cmp);
            for o in held.drain(..) {
                process(&mut engine, &o);
            }
        }
    }
    held.sort_unstable_by(Observation::total_cmp);
    for o in &held {
        process(&mut engine, o);
    }
    engine.stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4([a, b, c, d])
    }

    fn engine() -> BehaviorEngine {
        BehaviorEngine::new(BehaviorConfig::default())
    }

    /// A connection attempt the far end never answered — the raw
    /// material for scan detection.
    fn unanswered(ts_sec: i64, src: IpAddr, dst: IpAddr, dst_port: u16) -> Observation {
        Observation::Flow { ts_sec, src, dst, dst_port, bytes_out: 60, bytes_in: 0, answered: false }
    }

    fn cats(alerts: &[Alert]) -> Vec<&'static str> {
        alerts.iter().map(|a| a.category).collect()
    }

    /// The headline gap this module exists for: one port swept across
    /// many hosts. The per-destination port-scan counter cannot see this
    /// at all, however its threshold is set, because each destination
    /// contributes exactly one port.
    /// A sweep: many hosts on one port, none of which answered.
    #[test]
    fn a_sweep_of_one_port_across_many_hosts_is_detected() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for host in 1..=40u8 {
            e.observe(&unanswered(1_000, v4(10, 0, 0, 1), v4(192, 168, 0, host), 445), &mut alerts);
        }
        assert!(cats(&alerts).contains(&"HORIZONTAL_SCAN"), "got {:?}", cats(&alerts));
    }

    /// The case that made the first version of this detector unusable.
    ///
    /// One host connecting to many servers on port 80 is a web browser,
    /// and counting connection *attempts* cannot tell it apart from a
    /// sweep. Replaying 14k frames of ordinary enterprise traffic
    /// produced four `HORIZONTAL_SCAN` alerts for exactly this, and a
    /// 791k-frame capture produced 31. The distinguishing fact is that a
    /// browser's connections are answered.
    #[test]
    fn a_browser_visiting_many_web_servers_is_not_a_sweep() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for host in 1..=60u8 {
            e.observe(
                &Observation::Flow {
                    ts_sec: 1_500,
                    src: v4(192, 168, 3, 131),
                    dst: v4(203, 0, 113, host),
                    dst_port: 80,
                    bytes_out: 800,
                    bytes_in: 12_000,
                    answered: true,
                },
                &mut alerts,
            );
        }
        assert!(!cats(&alerts).contains(&"HORIZONTAL_SCAN"), "got {:?}", cats(&alerts));
        assert!(!cats(&alerts).contains(&"HOST_SWEEP"), "got {:?}", cats(&alerts));
    }

    /// And must stay quiet for ordinary fan-out: a client talking to many
    /// hosts on many *different* ports is a browser, not a scanner.
    #[test]
    fn ordinary_fan_out_to_many_hosts_on_different_ports_is_not_a_sweep() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for host in 1..=40u8 {
            // A different service each time.
            e.observe(&unanswered(1_000, v4(10, 0, 0, 2), v4(203, 0, 113, host), 1000 + host as u16), &mut alerts);
        }
        assert!(!cats(&alerts).contains(&"HORIZONTAL_SCAN"), "got {:?}", cats(&alerts));
    }

    /// A sweep spread across ports still trips the coarser counter, but
    /// only at a much higher bar.
    #[test]
    fn a_wide_sweep_across_ports_trips_the_host_sweep_counter() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for i in 0..300u32 {
            let o = i.to_be_bytes();
            e.observe(&unanswered(2_000, v4(10, 0, 0, 3), v4(172, o[1], o[2], o[3]), 1024 + (i % 500) as u16), &mut alerts);
        }
        assert!(cats(&alerts).contains(&"HOST_SWEEP"), "got {:?}", cats(&alerts));
    }

    #[test]
    fn repeated_authentication_attempts_to_one_service_are_flagged() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for _ in 0..30 {
            e.observe(
                &Observation::AuthAttempt { ts_sec: 3_000, src: v4(10, 0, 0, 4), dst: v4(10, 0, 0, 9), dst_port: 21, service: "FTP" },
                &mut alerts,
            );
        }
        assert!(cats(&alerts).contains(&"BRUTE_FORCE"), "got {:?}", cats(&alerts));
        // Gated: one alert for the burst, not one per attempt past the
        // threshold.
        assert_eq!(alerts.iter().filter(|a| a.category == "BRUTE_FORCE").count(), 1);
    }

    #[test]
    fn a_few_authentication_attempts_are_not_a_brute_force() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for i in 0..5i64 {
            e.observe(
                &Observation::AuthAttempt { ts_sec: 4_000 + i * 10, src: v4(10, 0, 0, 5), dst: v4(10, 0, 0, 9), dst_port: 22, service: "SSH" },
                &mut alerts,
            );
        }
        assert!(alerts.is_empty(), "a handful of logins is a person, got {:?}", cats(&alerts));
    }

    #[test]
    fn regularly_spaced_connections_are_flagged_as_beaconing() {
        let mut e = engine();
        let mut alerts = Vec::new();
        let mut t = 5_000i64;
        for _ in 0..8 {
            e.observe(
                &Observation::Flow { ts_sec: t, src: v4(10, 0, 0, 6), dst: v4(203, 0, 113, 50), dst_port: 443, bytes_out: 400, bytes_in: 900, answered: true },
                &mut alerts,
            );
            t += 60;
        }
        assert!(cats(&alerts).contains(&"BEACONING"), "got {:?}", cats(&alerts));
    }

    /// Identical timing to the test above, only the destination differs:
    /// SSDP/UPnP discovery on 239.255.255.250:1900 re-announces on a
    /// fixed timer because the protocol says to. A live run flagged it at
    /// 0.0% jitter, which was a correct reading of the traffic and the
    /// wrong conclusion about it.
    #[test]
    fn multicast_service_discovery_is_not_beaconing() {
        let mut e = engine();
        let mut alerts = Vec::new();
        let mut t = 5_000i64;
        for _ in 0..8 {
            e.observe(
                &Observation::Flow { ts_sec: t, src: v4(192, 168, 0, 112), dst: v4(239, 255, 255, 250), dst_port: 1900, bytes_out: 400, bytes_in: 0, answered: false },
                &mut alerts,
            );
            t += 120;
        }
        assert!(alerts.is_empty(), "multicast discovery is not behaviour worth alerting on, got {:?}", cats(&alerts));
    }

    #[test]
    fn irregular_browsing_is_not_beaconing() {
        let mut e = engine();
        let mut alerts = Vec::new();
        let mut t = 6_000i64;
        for gap in [3i64, 1, 220, 7, 900, 2, 15, 1400] {
            t += gap;
            e.observe(
                &Observation::Flow { ts_sec: t, src: v4(10, 0, 0, 7), dst: v4(203, 0, 113, 51), dst_port: 443, bytes_out: 500, bytes_in: 40_000, answered: true },
                &mut alerts,
            );
        }
        assert!(!cats(&alerts).contains(&"BEACONING"), "got {:?}", cats(&alerts));
    }

    /// Sub-second regularity is what normal protocols look like, so it
    /// must not be reported as a beacon.
    #[test]
    fn fast_regular_traffic_is_not_reported_as_a_beacon() {
        let mut e = engine();
        let mut alerts = Vec::new();
        let mut t = 7_000i64;
        for _ in 0..10 {
            e.observe(
                &Observation::Flow { ts_sec: t, src: v4(10, 0, 0, 8), dst: v4(10, 0, 0, 20), dst_port: 3306, bytes_out: 200, bytes_in: 200, answered: true },
                &mut alerts,
            );
            t += 1;
        }
        assert!(!cats(&alerts).contains(&"BEACONING"), "got {:?}", cats(&alerts));
    }

    #[test]
    fn a_large_outbound_transfer_is_flagged_by_volume() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for i in 0..20i64 {
            e.observe(
                &Observation::Flow {
                    ts_sec: 8_000 + i,
                    src: v4(10, 0, 0, 11),
                    dst: v4(198, 51, 100, 7),
                    dst_port: 443,
                    bytes_out: 10 * 1024 * 1024,
                    bytes_in: 8 * 1024 * 1024,
                    answered: true,
                },
                &mut alerts,
            );
        }
        assert!(cats(&alerts).contains(&"DATA_EXFIL_VOLUME"), "got {:?}", cats(&alerts));
    }

    /// Lopsided *and* large. Ratio alone would fire on every small
    /// upload, which is why there's a volume floor.
    #[test]
    fn a_lopsided_transfer_is_flagged_by_ratio_but_a_small_one_is_not() {
        let mut e = engine();
        let mut alerts = Vec::new();
        e.observe(
            &Observation::Flow { ts_sec: 9_000, src: v4(10, 0, 0, 12), dst: v4(198, 51, 100, 8), dst_port: 443, bytes_out: 50 * 1024 * 1024, bytes_in: 1024, answered: true },
            &mut alerts,
        );
        assert!(cats(&alerts).contains(&"DATA_EXFIL_RATIO"), "got {:?}", cats(&alerts));

        let mut e2 = engine();
        let mut a2 = Vec::new();
        e2.observe(
            &Observation::Flow { ts_sec: 9_000, src: v4(10, 0, 0, 13), dst: v4(198, 51, 100, 9), dst_port: 443, bytes_out: 200 * 1024, bytes_in: 512, answered: true },
            &mut a2,
        );
        assert!(!cats(&a2).contains(&"DATA_EXFIL_RATIO"), "a 200KB upload is not exfiltration, got {:?}", cats(&a2));
    }

    /// Base32-shaped labels, which is what the common DNS-tunnel tools
    /// actually emit. An earlier version of this test used 16 hex
    /// characters and failed: hex over a short label with leading zeros
    /// scores around 2.7 bits/byte, below the threshold. That was the
    /// test being unrealistic rather than the detector being wrong —
    /// worth keeping in mind that entropy is weak on short strings,
    /// which is exactly why the detector pairs it with a *count* of
    /// distinct labels instead of trusting any single one.
    #[test]
    fn many_high_entropy_subdomains_under_one_parent_look_like_a_tunnel() {
        const B32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut e = engine();
        let mut alerts = Vec::new();
        let mut state: u64 = 0x2545F4914F6CDD1D;
        for _ in 0..60 {
            let mut label = String::new();
            for _ in 0..32 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                label.push(B32[(state % 32) as usize] as char);
            }
            let name = format!("{}.tunnel.example", label);
            e.observe(&Observation::dns(10_000, v4(10, 0, 0, 14), v4(10, 0, 0, 53), &name), &mut alerts);
        }
        assert!(cats(&alerts).contains(&"DNS_TUNNEL"), "got {:?}", cats(&alerts));
    }

    /// Hex encoding works too, provided the label is long enough to have
    /// measurable entropy — the practical lower bound on this detector.
    #[test]
    fn long_hex_encoded_subdomains_also_look_like_a_tunnel() {
        let mut e = engine();
        let mut alerts = Vec::new();
        let mut state: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..60 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let name = format!("{:016x}{:016x}.hex.example", state, state.rotate_left(29));
            e.observe(&Observation::dns(15_000, v4(10, 0, 0, 17), v4(10, 0, 0, 53), &name), &mut alerts);
        }
        assert!(cats(&alerts).contains(&"DNS_TUNNEL"), "got {:?}", cats(&alerts));
    }

    /// Ordinary DNS — a handful of readable hostnames under a domain —
    /// must not trip it, and neither must many *low*-entropy subdomains.
    #[test]
    fn ordinary_dns_traffic_is_not_a_tunnel() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for host in ["www", "mail", "api", "cdn", "static", "login", "images", "search"] {
            e.observe(&Observation::dns(11_000, v4(10, 0, 0, 15), v4(10, 0, 0, 53), &format!("{}.example.com", host)), &mut alerts);
        }
        for i in 0..200 {
            e.observe(&Observation::dns(11_000, v4(10, 0, 0, 15), v4(10, 0, 0, 53), &format!("node{}.example.com", i)), &mut alerts);
        }
        assert!(!cats(&alerts).contains(&"DNS_TUNNEL"), "got {:?}", cats(&alerts));
    }

    #[test]
    fn a_very_long_dns_name_is_noted_on_its_own() {
        let mut e = engine();
        let mut alerts = Vec::new();
        let long = format!("{}.example.com", "a1b2c3d4e5".repeat(12));
        e.observe(&Observation::dns(12_000, v4(10, 0, 0, 16), v4(10, 0, 0, 53), &long), &mut alerts);
        assert!(cats(&alerts).contains(&"DNS_LONG_NAME"), "got {:?}", cats(&alerts));
    }

    #[test]
    fn dns_name_splitting_handles_short_and_long_names() {
        assert_eq!(split_dns_name(b"a.b.example.com"), (&b"example.com"[..], &b"a.b"[..]));
        assert_eq!(split_dns_name(b"example.com"), (&b"example.com"[..], &b""[..]));
        assert_eq!(split_dns_name(b"localhost"), (&b"localhost"[..], &b""[..]));
    }

    /// All state here is keyed on attacker-chosen values, so the same
    /// rule applies as everywhere else: capped, and counted when it
    /// refuses.
    #[test]
    fn state_is_bounded_under_a_flood_of_distinct_sources() {
        let cfg = BehaviorConfig { max_sources: 128, ..BehaviorConfig::default() };
        let mut e = BehaviorEngine::new(cfg);
        let mut alerts = Vec::new();
        for i in 0..20_000u32 {
            let o = i.to_be_bytes();
            e.observe(&unanswered(13_000, v4(10, o[1], o[2], o[3]), v4(10, 0, 0, 1), 80), &mut alerts);
        }
        assert!(e.sources.len() <= 128, "held {} sources against a cap of 128", e.sources.len());
        assert!(e.stats().sources_refused > 0, "refusals must be counted");
    }

    /// An observation stream that never repeats a key must not grow the
    /// tables forever: sweeping is driven by observation timestamps.
    #[test]
    fn state_is_released_as_capture_time_advances() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for i in 0..500i64 {
            let o = (i as u32).to_be_bytes();
            e.observe(&unanswered(14_000 + i * 10, v4(10, o[1], o[2], o[3]), v4(10, 0, 0, 1), 80), &mut alerts);
        }
        // The window is 300s and the stream spans 5000s, so most of the
        // early sources must have been released.
        assert!(e.sources.len() < 100, "held {} sources after the window should have expired most", e.sources.len());
    }
    fn refused(t: i64, service: &'static str) -> Observation {
        Observation::AuthFailure { ts_sec: t, src: v4(10, 0, 0, 5), dst: v4(10, 0, 0, 9), dst_port: 21, service }
    }

    /// Ten refusals is what a tool produces and a person does not, and it
    /// is the server that says so.
    #[test]
    fn repeated_server_refusals_are_a_brute_force() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for i in 0..10 {
            e.observe(&refused(8_000 + i * 5, "FTP"), &mut alerts);
        }
        let hit = alerts.iter().find(|a| a.category == "BRUTE_FORCE").expect("ten refusals must alert");
        assert!(hit.message.contains("refused"), "the alert must say these were observed failures: {}", hit.message);
    }

    #[test]
    fn a_few_refusals_are_a_typo_not_an_attack() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for i in 0..4 {
            e.observe(&refused(9_000 + i * 20, "FTP"), &mut alerts);
        }
        assert!(alerts.is_empty(), "got {:?}", cats(&alerts));
    }

    /// Attempts and refusals are counted apart: twenty attempts that all
    /// succeed is a busy client, and is not what the failure counter says.
    #[test]
    fn refusals_are_counted_separately_from_attempts() {
        let mut e = engine();
        let mut alerts = Vec::new();
        for i in 0..6 {
            e.observe(&Observation::AuthAttempt { ts_sec: 9_500 + i, src: v4(10, 0, 0, 5), dst: v4(10, 0, 0, 9), dst_port: 21, service: "FTP" }, &mut alerts);
            e.observe(&refused(9_500 + i, "FTP"), &mut alerts);
        }
        assert!(alerts.is_empty(), "six of each is under both limits, got {:?}", cats(&alerts));
    }

    /// The reason ordered mode exists. A large upload and the download that
    /// answers it, in the same second: taken in one arrival order the
    /// running ratio spikes past the threshold, in the other it does not.
    fn exfil_pair() -> Vec<Observation> {
        let src = v4(67, 217, 64, 99);
        vec![
            Observation::Flow { ts_sec: 5_000, src, dst: v4(172, 16, 0, 2), dst_port: 443, bytes_out: 6 * 1024 * 1024, bytes_in: 0, answered: true },
            Observation::Flow { ts_sec: 5_000, src, dst: v4(172, 16, 0, 3), dst_port: 443, bytes_out: 0, bytes_in: 6 * 1024 * 1024, answered: true },
        ]
    }

    fn run_ordered(order: &[Observation], ordered: bool) -> Vec<&'static str> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let (atx, arx) = crossbeam_channel::unbounded();
        for o in order {
            tx.send(*o).unwrap();
        }
        drop(tx);
        run_behavior_engine(rx, atx, BehaviorConfig::default(), ordered);
        arx.try_iter().map(|a| a.category).collect()
    }

    #[test]
    fn the_online_detectors_really_are_sensitive_to_order() {
        // Established directly on the engine, so the tests below mean
        // something: with no ordering at all, the two orders disagree.
        let run = |order: &[Observation]| {
            let mut engine = BehaviorEngine::new(BehaviorConfig::default());
            let mut out = Vec::new();
            for o in order {
                engine.observe(o, &mut out);
            }
            out.iter().map(|a| a.category).collect::<Vec<_>>()
        };
        let pair = exfil_pair();
        let reversed: Vec<Observation> = pair.iter().rev().copied().collect();
        assert_ne!(run(&pair), run(&reversed));
    }

    #[test]
    fn live_mode_orders_within_its_window() {
        let pair = exfil_pair();
        let reversed: Vec<Observation> = pair.iter().rev().copied().collect();
        assert_eq!(run_ordered(&pair, false), run_ordered(&reversed, false));
    }

    /// The window is for scheduling skew. An observation far older than
    /// the newest one (a long flow that has only just ended) is handled
    /// rather than dropped or held for ever.
    #[test]
    fn a_late_old_observation_is_still_processed() {
        let src = v4(67, 217, 64, 99);
        let old = Observation::Flow { ts_sec: 100, src, dst: v4(172, 16, 0, 2), dst_port: 443, bytes_out: 6 * 1024 * 1024, bytes_in: 0, answered: true };
        let new = Observation::Flow { ts_sec: 500, src, dst: v4(172, 16, 0, 9), dst_port: 443, bytes_out: 10, bytes_in: 10, answered: true };
        let (tx, rx) = crossbeam_channel::unbounded();
        let (atx, arx) = crossbeam_channel::unbounded();
        tx.send(new).unwrap();
        tx.send(old).unwrap();
        drop(tx);
        let stats = run_behavior_engine(rx, atx, BehaviorConfig::default(), false);
        assert_eq!(stats.observations, 2);
        drop(arx);
    }

    #[test]
    fn ordered_mode_gives_the_same_alerts_whatever_the_arrival_order() {
        let pair = exfil_pair();
        let reversed: Vec<Observation> = pair.iter().rev().copied().collect();
        assert_eq!(run_ordered(&pair, true), run_ordered(&reversed, true));
    }

    /// Every permutation of a mixed batch sorts to one sequence.
    #[test]
    fn the_sort_order_is_total_over_every_field() {
        let mut all = exfil_pair();
        all.push(unanswered(5_000, v4(10, 0, 0, 1), v4(10, 0, 0, 2), 445));
        all.push(Observation::AuthFailure { ts_sec: 5_000, src: v4(10, 0, 0, 1), dst: v4(10, 0, 0, 2), dst_port: 21, service: "FTP" });
        all.push(Observation::AuthFailure { ts_sec: 5_000, src: v4(10, 0, 0, 1), dst: v4(10, 0, 0, 2), dst_port: 21, service: "SMTP" });
        let sorted = |mut v: Vec<Observation>| {
            v.sort_unstable_by(Observation::total_cmp);
            v.iter().map(|o| format!("{:?}", o.sort_key())).collect::<Vec<_>>()
        };
        let forward = sorted(all.clone());
        let mut backward = all.clone();
        backward.reverse();
        assert_eq!(forward, sorted(backward));
    }

    #[test]
    fn earlier_observations_sort_first_regardless_of_arrival() {
        let early = unanswered(100, v4(10, 0, 0, 1), v4(10, 0, 0, 2), 80);
        let late = unanswered(200, v4(10, 0, 0, 1), v4(10, 0, 0, 2), 80);
        assert_eq!(late.total_cmp(&early), std::cmp::Ordering::Greater);
    }

    /// The reason volume is judged here: no single worker sees enough.
    #[test]
    fn a_flood_split_across_workers_is_seen_as_one() {
        let src = v4(198, 51, 100, 7);
        let cfg = BehaviorConfig { flood_limit: 1000, flood_window_secs: 10, ..BehaviorConfig::default() };
        let mut engine = BehaviorEngine::new(cfg);
        let mut out = Vec::new();
        // Four workers each saw 300 packets in the same second: 1,200 in all,
        // and no worker's own count reaches the limit.
        for _ in 0..4 {
            engine.observe(&Observation::Volume { ts_sec: 5_000, src, packets: 300 }, &mut out);
        }
        assert_eq!(out.iter().filter(|a| a.category == "PACKET_FLOOD").count(), 1);
    }

    #[test]
    fn volume_below_the_limit_is_not_a_flood_and_a_lull_resets_it() {
        let src = v4(198, 51, 100, 7);
        let cfg = BehaviorConfig { flood_limit: 1000, flood_window_secs: 10, ..BehaviorConfig::default() };
        let mut engine = BehaviorEngine::new(cfg);
        let mut out = Vec::new();
        engine.observe(&Observation::Volume { ts_sec: 5_000, src, packets: 600 }, &mut out);
        // Twenty seconds later the first count has left the window.
        engine.observe(&Observation::Volume { ts_sec: 5_020, src, packets: 600 }, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn one_alert_per_interval_however_many_counts_arrive() {
        let src = v4(198, 51, 100, 7);
        let cfg = BehaviorConfig { flood_limit: 100, flood_window_secs: 10, flood_min_interval_secs: 10, ..BehaviorConfig::default() };
        let mut engine = BehaviorEngine::new(cfg);
        let mut out = Vec::new();
        for s in 0..5 {
            engine.observe(&Observation::Volume { ts_sec: 5_000 + s, src, packets: 500 }, &mut out);
        }
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn a_directed_broadcast_on_a_private_network_is_not_a_beacon_target() {
        assert!(is_broadcast_like(&v4(192, 168, 0, 255)));
        assert!(is_broadcast_like(&v4(10, 4, 9, 255)));
        assert!(is_broadcast_like(&v4(172, 20, 1, 255)));
        assert!(!is_broadcast_like(&v4(192, 168, 0, 254)));
        assert!(!is_broadcast_like(&v4(8, 8, 8, 255)), "a public address ending in 255 is an ordinary host");
        assert!(!is_broadcast_like(&v4(172, 32, 1, 255)), "outside 172.16/12");
    }

    #[test]
    fn a_connection_that_is_still_open_counts_towards_volume_as_it_goes() {
        let src = v4(192, 168, 0, 112);
        let mut engine = BehaviorEngine::new(BehaviorConfig { exfil_ratio_min_bytes: 1_000_000, ..BehaviorConfig::default() });
        let mut out = Vec::new();
        // 6 MB up and nothing back, reported while the connection is open.
        engine.observe(&Observation::Traffic { ts_sec: 5_000, src, dst: v4(203, 0, 113, 9), dst_port: 443, bytes_out: 6_000_000, bytes_in: 10_000 }, &mut out);
        assert!(out.iter().any(|a| a.category == "DATA_EXFIL_RATIO"), "seen while it is happening, not at the end");
    }

    #[test]
    fn an_open_connection_is_not_counted_as_a_connection() {
        // Beaconing counts connection starts; a byte report is not one.
        let src = v4(10, 0, 0, 1);
        let mut engine = BehaviorEngine::new(BehaviorConfig::default());
        let mut out = Vec::new();
        for i in 0..30 {
            engine.observe(&Observation::Traffic { ts_sec: 5_000 + i * 60, src, dst: v4(203, 0, 113, 9), dst_port: 443, bytes_out: 10, bytes_in: 10 }, &mut out);
        }
        assert!(out.iter().all(|a| a.category != "BEACONING"), "{:?}", out.iter().map(|a| a.category).collect::<Vec<_>>());
    }

}

