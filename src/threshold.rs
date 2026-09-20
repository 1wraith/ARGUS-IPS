//! Per-rule rate control: `threshold` and `detection_filter`.
//!
//! These are not match conditions. A rule with `threshold:type limit,
//! track by_src, count 1, seconds 60` matches exactly what it would match
//! without it; the option decides *whether a match is reported*, by
//! counting how many there have been recently for the same source. That
//! is why it lives in a stage of its own rather than in the matcher.
//!
//! # Where the state has to live
//!
//! The workers are sharded by host pair, so two matches from one source to
//! two destinations are seen by two different workers, and a counter kept
//! per worker would count each source's traffic in pieces. The count has
//! to be kept where every alert passes: a single thread between the
//! workers and the writer.
//!
//! # Determinism
//!
//! Alerts reach that thread in scheduling order, and a windowed count is
//! sensitive to order: whether a match is the third or the fourth in its
//! window depends on which of two near-simultaneous matches came first.
//! As with the behavioural aggregator, replay therefore holds the alerts
//! it must count and processes them in capture-time order. A live capture
//! cannot wait, so it counts in arrival order.

use crate::engine::Alert;
use crate::packet::IpAddr;
use rustc_hash::FxHashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// What is done with the matches in a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Report the first `count` matches in a window, then none until it ends.
    Limit,
    /// Report every `count`th match.
    Every,
    /// Report once, when the count is reached, then none until the window ends.
    Both,
    /// Report nothing until the count is exceeded, then every match. The
    /// `detection_filter` keyword: the rule stays silent until something
    /// is happening often enough to matter.
    Over,
}

/// Which matches are counted together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Track {
    Src,
    Dst,
    /// Per (source, destination) pair.
    Pair,
    /// One count for the rule, whoever it fires on.
    Rule,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threshold {
    pub kind: Kind,
    pub track: Track,
    pub count: u32,
    pub seconds: u32,
}

impl Threshold {
    /// `type limit|threshold|both, track by_src|by_dst|by_both|by_rule, count N, seconds S`
    pub fn parse(value: &str) -> anyhow::Result<Threshold> {
        let mut kind = None;
        let mut fields = Fields::default();
        for part in value.split(',') {
            let (key, val) = part.trim().split_once(char::is_whitespace).map(|(k, v)| (k, v.trim())).unwrap_or((part.trim(), ""));
            match key.to_ascii_lowercase().as_str() {
                "type" => {
                    kind = Some(match val.to_ascii_lowercase().as_str() {
                        "limit" => Kind::Limit,
                        "threshold" => Kind::Every,
                        "both" => Kind::Both,
                        other => anyhow::bail!("unknown threshold type {:?}", other),
                    })
                }
                _ => fields.take(key, val)?,
            }
        }
        let kind = kind.ok_or_else(|| anyhow::anyhow!("threshold needs a type"))?;
        fields.finish(kind)
    }

    /// `track by_src|by_dst|by_both|by_rule, count N, seconds S`
    pub fn parse_detection_filter(value: &str) -> anyhow::Result<Threshold> {
        let mut fields = Fields::default();
        for part in value.split(',') {
            let (key, val) = part.trim().split_once(char::is_whitespace).map(|(k, v)| (k, v.trim())).unwrap_or((part.trim(), ""));
            fields.take(key, val)?;
        }
        fields.finish(Kind::Over)
    }
}

#[derive(Default)]
struct Fields {
    track: Option<Track>,
    count: Option<u32>,
    seconds: Option<u32>,
}

impl Fields {
    fn take(&mut self, key: &str, val: &str) -> anyhow::Result<()> {
        match key.to_ascii_lowercase().as_str() {
            "track" => {
                self.track = Some(match val.to_ascii_lowercase().as_str() {
                    "by_src" => Track::Src,
                    "by_dst" => Track::Dst,
                    "by_both" => Track::Pair,
                    "by_rule" => Track::Rule,
                    other => anyhow::bail!("unsupported threshold tracking {:?}", other),
                })
            }
            "count" => self.count = Some(val.parse()?),
            "seconds" => self.seconds = Some(val.parse()?),
            other => anyhow::bail!("unknown threshold field {:?}", other),
        }
        Ok(())
    }

    fn finish(self, kind: Kind) -> anyhow::Result<Threshold> {
        let track = self.track.ok_or_else(|| anyhow::anyhow!("threshold needs 'track'"))?;
        let count = self.count.ok_or_else(|| anyhow::anyhow!("threshold needs 'count'"))?;
        let seconds = self.seconds.ok_or_else(|| anyhow::anyhow!("threshold needs 'seconds'"))?;
        anyhow::ensure!(count > 0, "threshold count must be at least 1");
        anyhow::ensure!(seconds > 0, "threshold seconds must be at least 1");
        Ok(Threshold { kind, track, count, seconds })
    }
}

/// What an `xbits` option does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XbitVerb {
    Set,
    Unset,
    Toggle,
    IsSet,
    IsNotSet,
}

/// One `xbits:<verb>,<name>,track <ip_src|ip_dst|ip_pair>[,expire <secs>]`.
///
/// State that outlives a connection and is keyed on an address: "this host
/// asked an IP-check service a minute ago", so that a later, otherwise
/// unremarkable connection from it means something. It cannot live on a
/// flow, and it cannot live in a worker (the two connections may be on
/// different ones), so like rate control it lives in the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbitOp {
    pub verb: XbitVerb,
    pub name: String,
    pub track: Track,
    pub expire_secs: u32,
}

/// How long a bit lasts when the rule does not say.
const DEFAULT_XBIT_EXPIRE: u32 = 30;

impl XbitOp {
    pub fn parse(value: &str) -> anyhow::Result<XbitOp> {
        let mut parts = value.split(',').map(str::trim);
        let verb = match parts.next().unwrap_or("").to_ascii_lowercase().as_str() {
            "set" => XbitVerb::Set,
            "unset" => XbitVerb::Unset,
            "toggle" => XbitVerb::Toggle,
            "isset" => XbitVerb::IsSet,
            "isnotset" => XbitVerb::IsNotSet,
            other => anyhow::bail!("unknown xbits verb {:?}", other),
        };
        let name = parts.next().filter(|n| !n.is_empty()).ok_or_else(|| anyhow::anyhow!("xbits needs a name"))?.to_string();
        let mut track = None;
        let mut expire_secs = DEFAULT_XBIT_EXPIRE;
        for p in parts {
            let (k, v) = p.split_once(char::is_whitespace).map(|(k, v)| (k, v.trim())).unwrap_or((p, ""));
            match k.to_ascii_lowercase().as_str() {
                "track" => {
                    track = Some(match v.to_ascii_lowercase().as_str() {
                        "ip_src" => Track::Src,
                        "ip_dst" => Track::Dst,
                        "ip_pair" => Track::Pair,
                        other => anyhow::bail!("unsupported xbits tracking {:?}", other),
                    })
                }
                "expire" => {
                    expire_secs = v.parse()?;
                    anyhow::ensure!(expire_secs > 0, "xbits expire must be at least 1");
                }
                other => anyhow::bail!("unknown xbits field {:?}", other),
            }
        }
        Ok(XbitOp { verb, name, track: track.ok_or_else(|| anyhow::anyhow!("xbits needs 'track'"))?, expire_secs })
    }
}

/// A rule's cross-connection state operations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XbitSpec {
    pub ops: Vec<XbitOp>,
    /// The rule exists only to set state, so its match is not reported.
    pub noalert: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Src(IpAddr),
    Dst(IpAddr),
    Pair(IpAddr, IpAddr),
    Rule,
}

struct Window {
    start_ms: u64,
    count: u32,
    reported: bool,
}

/// Past this many tracked (rule, source) pairs, windows that have ended
/// are discarded. A scan can name millions of sources, and each would
/// otherwise keep an entry for as long as the process runs.
const MAX_WINDOWS: usize = 200_000;

/// The counting itself, free of threads so it can be tested directly.
#[derive(Default)]
pub struct Gate {
    windows: FxHashMap<(u32, Key), Window>,
    newest_ms: u64,
    /// Bits that are set, and when each stops being.
    bits: FxHashMap<(String, Key), u64>,
}

fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

impl Gate {
    fn bit_key(alert: &Alert, op: &XbitOp) -> (String, Key) {
        let key = match op.track {
            Track::Src => Key::Src(alert.src),
            Track::Dst => Key::Dst(alert.dst),
            Track::Pair => Key::Pair(alert.src, alert.dst),
            Track::Rule => Key::Rule,
        };
        (op.name.clone(), key)
    }

    fn bit_is_set(&self, alert: &Alert, op: &XbitOp) -> bool {
        let now = millis(alert.timestamp);
        self.bits.get(&Gate::bit_key(alert, op)).is_some_and(|&until| now < until)
    }

    /// Whether every condition (`isset`, `isnotset`) of a rule holds.
    pub fn xbits_hold(&self, alert: &Alert, spec: &XbitSpec) -> bool {
        spec.ops.iter().all(|op| match op.verb {
            XbitVerb::IsSet => self.bit_is_set(alert, op),
            XbitVerb::IsNotSet => !self.bit_is_set(alert, op),
            _ => true,
        })
    }

    /// Applies a matching rule's effects (`set`, `unset`, `toggle`).
    pub fn xbits_apply(&mut self, alert: &Alert, spec: &XbitSpec) {
        let now = millis(alert.timestamp);
        self.newest_ms = self.newest_ms.max(now);
        if self.bits.len() >= MAX_WINDOWS {
            let horizon = self.newest_ms;
            self.bits.retain(|_, &mut until| until > horizon);
        }
        for op in &spec.ops {
            let key = Gate::bit_key(alert, op);
            match op.verb {
                XbitVerb::Set => {
                    self.bits.insert(key, now + op.expire_secs as u64 * 1000);
                }
                XbitVerb::Unset => {
                    self.bits.remove(&key);
                }
                XbitVerb::Toggle => {
                    if self.bit_is_set(alert, op) {
                        self.bits.remove(&key);
                    } else {
                        self.bits.insert(key, now + op.expire_secs as u64 * 1000);
                    }
                }
                XbitVerb::IsSet | XbitVerb::IsNotSet => {}
            }
        }
    }

    /// Whether this alert is to be reported, counting it.
    pub fn admit(&mut self, alert: &Alert, rule: &Threshold) -> bool {
        let now = millis(alert.timestamp);
        self.newest_ms = self.newest_ms.max(now);
        if self.windows.len() >= MAX_WINDOWS {
            let horizon = self.newest_ms;
            // Whatever the rule, a window that closed before the newest
            // alert cannot affect any later count. `retain` cannot see
            // each entry's own length, so use the longest a window can be.
            self.windows.retain(|_, w| horizon.saturating_sub(w.start_ms) < 86_400_000);
        }
        let key = match rule.track {
            Track::Src => Key::Src(alert.src),
            Track::Dst => Key::Dst(alert.dst),
            Track::Pair => Key::Pair(alert.src, alert.dst),
            Track::Rule => Key::Rule,
        };
        let span = rule.seconds as u64 * 1000;
        let w = self.windows.entry((alert.sid, key)).or_insert(Window { start_ms: now, count: 0, reported: false });
        if now >= w.start_ms + span {
            *w = Window { start_ms: now, count: 0, reported: false };
        }
        w.count += 1;
        match rule.kind {
            Kind::Limit => w.count <= rule.count,
            Kind::Every => {
                if w.count >= rule.count {
                    w.count = 0;
                    true
                } else {
                    false
                }
            }
            Kind::Both => {
                if w.count >= rule.count && !w.reported {
                    w.reported = true;
                    true
                } else {
                    false
                }
            }
            Kind::Over => w.count > rule.count,
        }
    }
}

/// The order alerts are counted in under replay: time first, then every
/// field, so that two arrival orders sort to one sequence.
fn order(a: &Alert, b: &Alert) -> std::cmp::Ordering {
    (a.timestamp, a.sid, a.src, a.dst, a.port, &a.message).cmp(&(b.timestamp, b.sid, b.src, b.dst, b.port, &b.message))
}

/// How many alerts replay holds before counting them in a batch.
pub const MAX_HELD: usize = 2_000_000;

/// What the gate did, for the shutdown summary.
#[derive(Default, Debug, Clone, Copy)]
pub struct GateStats {
    pub passed: u64,
    pub withheld: u64,
}

/// Sits between the workers and the writer. Alerts from rules with no
/// threshold pass straight through; the rest are counted.
///
/// `rules` is consulted afresh whenever the ruleset is reloaded, so an
/// edited threshold takes effect without a restart.
pub fn run_threshold_gate(
    rx: crossbeam_channel::Receiver<Alert>,
    tx: crossbeam_channel::Sender<Alert>,
    rules: std::sync::Arc<crate::reload::Hot<crate::engine::SignatureEngine>>,
    ordered: bool,
) -> GateStats {
    let mut gate = Gate::default();
    let mut stats = GateStats::default();
    let mut generation = rules.generation();
    let mut current = rules.load();
    let mut held: Vec<Alert> = Vec::new();

    fn settle(gate: &mut Gate, stats: &mut GateStats, tx: &crossbeam_channel::Sender<Alert>, rule: Option<Threshold>, bits: Option<XbitSpec>, alert: Alert) {
        // State first: a rule whose conditions fail did not match, and one
        // that matches has its effects whether or not it is then reported.
        if let Some(spec) = &bits {
            if !gate.xbits_hold(&alert, spec) {
                stats.withheld += 1;
                return;
            }
            gate.xbits_apply(&alert, spec);
            if spec.noalert {
                return;
            }
        }
        let admitted = rule.is_none_or(|t| gate.admit(&alert, &t));
        if admitted {
            stats.passed += 1;
            let _ = tx.send(alert);
        } else {
            stats.withheld += 1;
        }
    }

    for alert in rx.iter() {
        if rules.generation() != generation {
            generation = rules.generation();
            current = rules.load();
            gate = Gate::default();
        }
        let rule = current.rules.threshold_for(alert.sid);
        let bits = current.rules.xbits_for(alert.sid);
        if rule.is_none() && bits.is_none() {
            settle(&mut gate, &mut stats, &tx, None, None, alert);
        } else if ordered {
            held.push(alert);
            if held.len() >= MAX_HELD {
                eprintln!("argus: more than {} threshold-tracked alerts in one replay; counting holds within batches of that size only", MAX_HELD);
                held.sort_unstable_by(order);
                for a in held.drain(..) {
                    let (t, b) = (current.rules.threshold_for(a.sid), current.rules.xbits_for(a.sid));
                    settle(&mut gate, &mut stats, &tx, t, b, a);
                }
            }
        } else {
            settle(&mut gate, &mut stats, &tx, rule, bits, alert);
        }
    }
    held.sort_unstable_by(order);
    for a in held {
        let (t, b) = (current.rules.threshold_for(a.sid), current.rules.xbits_for(a.sid));
        settle(&mut gate, &mut stats, &tx, t, b, a);
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Severity;
    use std::time::Duration;

    fn alert(sid: u32, src: u8, dst: u8, secs: u64) -> Alert {
        Alert {
            timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs),
            severity: Severity::Low,
            category: "SIGNATURE_MATCH",
            src: IpAddr::V4([10, 0, 0, src]),
            dst: IpAddr::V4([10, 0, 1, dst]),
            proto: "TCP",
            port: 80,
            message: "m".into(),
            sid,
        }
    }

    fn t(kind: Kind, track: Track, count: u32, seconds: u32) -> Threshold {
        Threshold { kind, track, count, seconds }
    }

    fn run(rule: Threshold, alerts: &[Alert]) -> Vec<bool> {
        let mut gate = Gate::default();
        alerts.iter().map(|a| gate.admit(a, &rule)).collect()
    }

    #[test]
    fn parses_the_suricata_forms() {
        let x = Threshold::parse("type limit, track by_src, count 1, seconds 60").unwrap();
        assert_eq!(x, t(Kind::Limit, Track::Src, 1, 60));
        let y = Threshold::parse("track by_dst,count 5,seconds 10,type both").unwrap();
        assert_eq!(y, t(Kind::Both, Track::Dst, 5, 10));
        let z = Threshold::parse_detection_filter("track by_src, count 30, seconds 60").unwrap();
        assert_eq!(z, t(Kind::Over, Track::Src, 30, 60));
    }

    #[test]
    fn refuses_what_it_cannot_honour() {
        assert!(Threshold::parse("type limit, track by_flow, count 1, seconds 1").is_err(), "by_flow is not a thing ARGUS tracks");
        assert!(Threshold::parse("type limit, track by_src, count 0, seconds 1").is_err());
        assert!(Threshold::parse("type limit, track by_src, count 1").is_err(), "seconds is required");
        assert!(Threshold::parse("track by_src, count 1, seconds 1").is_err(), "type is required");
    }

    #[test]
    fn limit_reports_the_first_n_in_a_window_and_no_more() {
        let a: Vec<Alert> = (0..5).map(|i| alert(1, 1, 1, i)).collect();
        assert_eq!(run(t(Kind::Limit, Track::Src, 2, 60), &a), [true, true, false, false, false]);
    }

    #[test]
    fn a_new_window_starts_the_count_afresh() {
        let a = [alert(1, 1, 1, 0), alert(1, 1, 1, 1), alert(1, 1, 1, 61), alert(1, 1, 1, 62)];
        assert_eq!(run(t(Kind::Limit, Track::Src, 1, 60), &a), [true, false, true, false]);
    }

    #[test]
    fn every_reports_each_nth_match() {
        let a: Vec<Alert> = (0..6).map(|i| alert(1, 1, 1, i)).collect();
        assert_eq!(run(t(Kind::Every, Track::Src, 3, 60), &a), [false, false, true, false, false, true]);
    }

    #[test]
    fn both_reports_once_when_the_count_is_reached() {
        let a: Vec<Alert> = (0..6).map(|i| alert(1, 1, 1, i)).collect();
        assert_eq!(run(t(Kind::Both, Track::Src, 3, 60), &a), [false, false, true, false, false, false]);
    }

    #[test]
    fn a_detection_filter_is_silent_until_the_count_is_exceeded() {
        let a: Vec<Alert> = (0..5).map(|i| alert(1, 1, 1, i)).collect();
        assert_eq!(run(t(Kind::Over, Track::Src, 3, 60), &a), [false, false, false, true, true]);
    }

    #[test]
    fn tracking_by_source_counts_each_source_separately() {
        let a = [alert(1, 1, 1, 0), alert(1, 2, 1, 0), alert(1, 1, 1, 1), alert(1, 2, 1, 1)];
        assert_eq!(run(t(Kind::Limit, Track::Src, 1, 60), &a), [true, true, false, false]);
        // By destination, the same four alerts share one target.
        assert_eq!(run(t(Kind::Limit, Track::Dst, 1, 60), &a), [true, false, false, false]);
    }

    #[test]
    fn a_rule_is_counted_separately_from_every_other() {
        let a = [alert(1, 1, 1, 0), alert(2, 1, 1, 0)];
        let mut gate = Gate::default();
        let rule = t(Kind::Limit, Track::Src, 1, 60);
        assert!(gate.admit(&a[0], &rule));
        assert!(gate.admit(&a[1], &rule), "sid 2 has its own count");
    }

    #[test]
    fn counting_by_rule_ignores_who_it_fired_on() {
        let a = [alert(1, 1, 1, 0), alert(1, 9, 9, 0)];
        assert_eq!(run(t(Kind::Limit, Track::Rule, 1, 60), &a), [true, false]);
    }

    /// The reason replay sorts: the fourth match in a window is only the
    /// fourth if the others were seen first.
    #[test]
    fn counting_in_capture_order_is_independent_of_arrival_order() {
        let mut a: Vec<Alert> = (0..5).map(|i| alert(1, 1, 1, i * 20)).collect();
        let rule = t(Kind::Limit, Track::Src, 1, 60);
        let count_sorted = |mut v: Vec<Alert>| {
            v.sort_unstable_by(order);
            let mut gate = Gate::default();
            v.iter().filter(|x| gate.admit(x, &rule)).map(|x| x.timestamp).collect::<Vec<_>>()
        };
        let forward = count_sorted(a.clone());
        a.reverse();
        assert_eq!(forward, count_sorted(a));
    }
    fn engine_with(rule: &str) -> std::sync::Arc<crate::reload::Hot<crate::engine::SignatureEngine>> {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("argus-gate-{}-{}.txt", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::write(&path, rule).unwrap();
        let engine = crate::engine::SignatureEngine::load(None, path.to_str()).unwrap();
        let _ = std::fs::remove_file(&path);
        crate::reload::Hot::new(engine)
    }

    fn through_the_gate(rules: &str, ordered: bool, alerts: Vec<Alert>) -> Vec<(u32, u64)> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let (out_tx, out_rx) = crossbeam_channel::unbounded();
        for a in alerts {
            tx.send(a).unwrap();
        }
        drop(tx);
        run_threshold_gate(rx, out_tx, engine_with(rules), ordered);
        out_rx.try_iter().map(|a| (a.sid, millis(a.timestamp) / 1000 - 1_700_000_000)).collect()
    }

    const LIMIT_ONE: &str = "rule sid:7; name:\"x\"; content:\"a\"; threshold:type limit,track by_src,count 1,seconds 60;
";

    #[test]
    fn a_rule_loaded_with_a_threshold_is_limited_and_others_pass() {
        let alerts = vec![alert(7, 1, 1, 0), alert(7, 1, 1, 1), alert(8, 1, 1, 0), alert(8, 1, 1, 1)];
        let out = through_the_gate(LIMIT_ONE, false, alerts);
        assert_eq!(out, [(7, 0), (8, 0), (8, 1)], "sid 7 limited to one, sid 8 has no threshold");
    }

    /// The alert kept is the *earliest*, whichever arrived first.
    #[test]
    fn replay_keeps_the_earliest_alert_whatever_the_arrival_order() {
        let mut alerts = vec![alert(7, 1, 1, 30), alert(7, 1, 1, 0), alert(7, 1, 1, 10)];
        assert_eq!(through_the_gate(LIMIT_ONE, true, alerts.clone()), [(7, 0)]);
        alerts.reverse();
        assert_eq!(through_the_gate(LIMIT_ONE, true, alerts.clone()), [(7, 0)]);
        // Live counting, by contrast, keeps whichever came first.
        assert_eq!(through_the_gate(LIMIT_ONE, false, alerts), [(7, 10)]);
    }

    fn spec(ops: &[&str], noalert: bool) -> XbitSpec {
        XbitSpec { ops: ops.iter().map(|o| XbitOp::parse(o).unwrap()).collect(), noalert }
    }

    /// Applies a rule the way the gate does: conditions, then effects.
    fn fire(gate: &mut Gate, a: &Alert, s: &XbitSpec) -> bool {
        if !gate.xbits_hold(a, s) {
            return false;
        }
        gate.xbits_apply(a, s);
        true
    }

    #[test]
    fn xbits_parse_their_forms() {
        let op = XbitOp::parse("set,ET.ipcheck,track ip_src,expire 10").unwrap();
        assert_eq!(op, XbitOp { verb: XbitVerb::Set, name: "ET.ipcheck".into(), track: Track::Src, expire_secs: 10 });
        assert_eq!(XbitOp::parse("isset,a,track ip_pair").unwrap().expire_secs, 30, "the default lifetime");
        assert!(XbitOp::parse("set,a").is_err(), "tracking is required");
        assert!(XbitOp::parse("set,a,track flow").is_err());
        assert!(XbitOp::parse("frob,a,track ip_src").is_err());
    }

    #[test]
    fn a_bit_set_by_one_connection_is_seen_by_another_from_the_same_host() {
        let mut gate = Gate::default();
        let setter = spec(&["set,seen,track ip_src,expire 60"], true);
        let reader = spec(&["isset,seen,track ip_src"], false);
        assert!(!fire(&mut gate, &alert(2, 1, 9, 5), &reader), "nothing set yet");
        assert!(fire(&mut gate, &alert(1, 1, 5, 10), &setter));
        assert!(fire(&mut gate, &alert(2, 1, 9, 20), &reader), "same source, a different destination");
        assert!(!fire(&mut gate, &alert(2, 3, 9, 21), &reader), "a different source");
    }

    #[test]
    fn a_bit_lapses_after_its_expiry() {
        let mut gate = Gate::default();
        fire(&mut gate, &alert(1, 1, 5, 0), &spec(&["set,b,track ip_src,expire 10"], true));
        let reader = spec(&["isset,b,track ip_src"], false);
        assert!(fire(&mut gate, &alert(2, 1, 9, 9), &reader));
        assert!(!fire(&mut gate, &alert(2, 1, 9, 11), &reader));
    }

    #[test]
    fn unset_toggle_and_isnotset() {
        let mut gate = Gate::default();
        let a = alert(1, 1, 5, 0);
        let not_set = spec(&["isnotset,b,track ip_src"], false);
        assert!(fire(&mut gate, &a, &not_set));
        fire(&mut gate, &a, &spec(&["toggle,b,track ip_src,expire 60"], true));
        assert!(!fire(&mut gate, &a, &not_set), "toggled on");
        fire(&mut gate, &a, &spec(&["toggle,b,track ip_src,expire 60"], true));
        assert!(fire(&mut gate, &a, &not_set), "toggled off");
        fire(&mut gate, &a, &spec(&["set,b,track ip_src"], true));
        fire(&mut gate, &a, &spec(&["unset,b,track ip_src"], true));
        assert!(fire(&mut gate, &a, &not_set));
    }

    #[test]
    fn tracking_by_pair_distinguishes_destinations() {
        let mut gate = Gate::default();
        fire(&mut gate, &alert(1, 1, 5, 0), &spec(&["set,b,track ip_pair,expire 60"], true));
        let reader = spec(&["isset,b,track ip_pair"], false);
        assert!(fire(&mut gate, &alert(2, 1, 5, 1), &reader));
        assert!(!fire(&mut gate, &alert(2, 1, 6, 1), &reader));
    }

    #[test]
    fn different_names_do_not_interfere() {
        let mut gate = Gate::default();
        fire(&mut gate, &alert(1, 1, 5, 0), &spec(&["set,one,track ip_src"], true));
        assert!(!fire(&mut gate, &alert(1, 1, 5, 1), &spec(&["isset,two,track ip_src"], false)));
    }

    const SETTER: &str = "rule sid:7; name:\"mark\"; content:\"a\"; xbits:set,seen,track ip_src,expire 60; noalert;\n";
    const READER: &str = "rule sid:8; name:\"use\"; content:\"b\"; xbits:isset,seen,track ip_src;\n";

    fn both(ordered: bool, alerts: Vec<Alert>) -> Vec<(u32, u64)> {
        through_the_gate(&format!("{}{}", SETTER, READER), ordered, alerts)
    }

    #[test]
    fn a_setter_is_never_reported_and_a_reader_needs_it() {
        // The reader alone: nothing set, so it did not match.
        assert!(both(false, vec![alert(8, 1, 5, 0)]).is_empty());
        // Set, then read from the same source: only the reader is reported.
        assert_eq!(both(false, vec![alert(7, 1, 5, 0), alert(8, 1, 9, 1)]), [(8, 1)]);
    }

    /// The reason the state lives here: in replay the two alerts may
    /// reach the gate in either order, and the answer must not depend on it.
    #[test]
    fn replay_gives_the_same_answer_whatever_the_arrival_order() {
        let forward = vec![alert(7, 1, 5, 0), alert(8, 1, 9, 1)];
        let mut backward = forward.clone();
        backward.reverse();
        assert_eq!(both(true, forward), [(8, 1)]);
        assert_eq!(both(true, backward), [(8, 1)]);
    }

}
