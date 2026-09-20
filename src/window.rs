//! Sliding-window primitives shared by every detector.
//!
//! Every behavioural question ARGUS asks has the same three shapes
//! underneath it: *how many distinct X in the last N seconds*, *how much
//! of Y in the last N seconds*, and *how regularly does Z recur*. Those
//! were open-coded in `AnomalyEngine` — a hand-rolled bucket ring, a
//! hand-rolled time-gated prune, a hand-rolled alert gate — and each new
//! detector would have re-derived them, along with every mistake already
//! made and fixed once.
//!
//! Three of those mistakes are baked into the types here rather than
//! left to be rediscovered:
//!
//! - **Pruning is gated on time, not on size or on every insert.**
//!   Size-gating lets a low-volume source's stale entries linger
//!   indefinitely, so "distinct in the last N seconds" quietly stops
//!   being true. Pruning on every insert is unbounded per-packet work
//!   that scales with the size of the very attack being detected.
//! - **Every table has a hard cap and counts refusals.** A recency sweep
//!   is not a bound: under a flood from varying keys, every entry is
//!   fresh whenever the sweep runs, so nothing is released and the table
//!   grows with the attack.
//! - **"Never happened" is `Option`, never a sentinel.** An `i64::MIN`
//!   sentinel in an alert gate overflowed on `now - last` and silently
//!   disabled every anomaly alert in release builds.

use rustc_hash::FxHashMap;
use std::hash::Hash;

/// How often, at most, a windowed structure prunes itself: once per
/// wall-clock second of capture time.
const PRUNE_INTERVAL_SECS: i64 = 1;

// =======================================================================
// WindowSet: distinct keys seen in a sliding window
// =======================================================================

/// Counts *distinct* keys seen within a sliding window, bounded.
///
/// This is the shape behind port-scan detection ("distinct ports touched
/// on this host"), horizontal-scan detection ("distinct hosts probed by
/// this source"), and DNS-tunnel detection ("distinct subdomains queried
/// under this parent").
#[derive(Default)]
pub struct WindowSet<K: Eq + Hash + Copy> {
    seen: FxHashMap<K, i64>,
    last_pruned: i64,
    cap: usize,
    refused: u64,
}

impl<K: Eq + Hash + Copy> WindowSet<K> {
    pub fn new(cap: usize) -> Self {
        WindowSet { seen: FxHashMap::default(), last_pruned: 0, cap: cap.max(1), refused: 0 }
    }

    /// Records `key` and returns how many distinct keys are live in the
    /// window.
    ///
    /// Refuses rather than evicts when full: evicting on pressure would
    /// let a flood of junk keys push out the evidence of a real one,
    /// which turns a memory bound into an evasion primitive.
    pub fn insert(&mut self, key: K, now_sec: i64, window_secs: i64) -> usize {
        if now_sec - self.last_pruned >= PRUNE_INTERVAL_SECS {
            self.last_pruned = now_sec;
            let cutoff = now_sec - window_secs;
            self.seen.retain(|_, &mut t| t > cutoff);
        }
        if self.seen.len() >= self.cap && !self.seen.contains_key(&key) {
            self.refused += 1;
            return self.seen.len();
        }
        self.seen.insert(key, now_sec);
        self.seen.len()
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// Whether `key` is live in the window, without recording it.
    pub fn contains(&self, key: &K, now_sec: i64, window_secs: i64) -> bool {
        self.seen.get(key).is_some_and(|&t| now_sec - t <= window_secs)
    }
}

// =======================================================================
// RateWindow: quantity per sliding window
// =======================================================================

/// A ring of per-second buckets summing a quantity over a sliding
/// window.
///
/// Used for packet-rate flood detection and for outbound byte volume.
/// A ring rather than a timestamp list because the memory is fixed by
/// the window length and independent of the rate — which matters when
/// the rate is the thing under attack.
pub struct RateWindow {
    buckets: Vec<u64>,
    secs: Vec<i64>,
}

impl RateWindow {
    pub fn new(window_secs: i64) -> Self {
        let n = window_secs.max(1) as usize;
        RateWindow { buckets: vec![0; n], secs: vec![i64::MIN; n] }
    }

    /// Adds `amount` for `now_sec` and returns the window total.
    pub fn add(&mut self, now_sec: i64, amount: u64) -> u64 {
        let n = self.buckets.len() as i64;
        let idx = now_sec.rem_euclid(n) as usize;
        // A bucket whose stamp isn't this second is a full lap stale, so
        // it's reset rather than accumulated into.
        if self.secs[idx] != now_sec {
            self.secs[idx] = now_sec;
            self.buckets[idx] = 0;
        }
        self.buckets[idx] += amount;
        self.total(now_sec)
    }

    /// Sum of buckets still inside the window.
    pub fn total(&self, now_sec: i64) -> u64 {
        let cutoff = now_sec - self.buckets.len() as i64;
        self.secs.iter().zip(self.buckets.iter()).filter(|(&s, _)| s > cutoff).map(|(_, &c)| c).sum()
    }
}

// =======================================================================
// AlertGate: minimum interval between repeats
// =======================================================================

/// Rate-limits a repeating alert at the point of detection.
///
/// Emitting per-packet and letting the writer dedupe is correct output
/// but puts peak alert-channel pressure exactly where the sensor is
/// already struggling. `Option` rather than a sentinel because
/// `now - i64::MIN` overflows, which once silently disabled every
/// anomaly alert in release builds.
#[derive(Default, Clone, Copy)]
pub struct AlertGate {
    last: Option<i64>,
}

impl AlertGate {
    /// Returns true (and arms the gate) if enough time has passed.
    pub fn allow(&mut self, now_sec: i64, min_interval_secs: i64) -> bool {
        let blocked = self.last.is_some_and(|t| now_sec.saturating_sub(t) < min_interval_secs);
        if blocked {
            return false;
        }
        self.last = Some(now_sec);
        true
    }
}

// =======================================================================
// Periodicity: does this recur on a clock?
// =======================================================================

/// How many inter-arrival gaps to remember. Small on purpose: this lives
/// per tracked pair, and eight intervals is enough to tell a scheduled
/// callback from human-driven traffic.
const PERIODICITY_SAMPLES: usize = 8;

/// How many gaps are needed before regularity means anything.
///
/// This was four, and four is not evidence: with only four intervals,
/// ordinary traffic lands under any reasonable variance threshold purely
/// by chance. Replaying real traffic produced 111 "beacons", **every one
/// of them at exactly four samples**, mostly page loads and application
/// polling 15-35 seconds apart. Six is enough that consistent spacing
/// has to be deliberate, and still well inside the eight-gap ring.
const MIN_PERIODICITY_GAPS: usize = 6;

/// Detects regularly-spaced recurrence — the signature of an automated
/// callback rather than a person.
///
/// Malware C2 beacons on a timer, usually with jitter; humans and normal
/// applications don't. The discriminator is **relative** dispersion of
/// the gaps (coefficient of variation), not absolute: a 60-second beacon
/// with 5 seconds of jitter and a 3600-second beacon with 300 seconds of
/// jitter are equally regular, and an absolute threshold would catch one
/// and miss the other.
#[derive(Default)]
pub struct Periodicity {
    last_seen: Option<i64>,
    gaps: [i64; PERIODICITY_SAMPLES],
    count: usize,
    next: usize,
}

impl Periodicity {
    /// Records an occurrence. Returns the mean gap and its coefficient
    /// of variation once enough samples exist to say anything.
    pub fn observe(&mut self, now_sec: i64) -> Option<(f64, f64)> {
        if let Some(prev) = self.last_seen {
            let gap = now_sec - prev;
            // Zero-second gaps are the same burst, not a new beacon; they
            // would otherwise drag the CV to zero and make any burst look
            // perfectly periodic.
            if gap > 0 {
                self.gaps[self.next] = gap;
                self.next = (self.next + 1) % PERIODICITY_SAMPLES;
                self.count += 1;
            }
            if gap < 0 {
                // Out of order: keep the later timestamp rather than
                // rewinding to this one. Observations are not guaranteed
                // to arrive in time order — they are produced when a flow
                // *retires*, which can be long after it started — and a
                // clock that walks backwards manufactures the exact
                // signal this is looking for. One rewind turns the next
                // ordinary sample into a gap the size of the rewind, and
                // a steady trickle of them produces a run of identical
                // large gaps: a perfect beacon assembled out of
                // unrelated traffic. Dropping the sample loses nothing;
                // its interval was already counted from the other side.
                return self.verdict();
            }
        }
        self.last_seen = Some(now_sec);
        self.verdict()
    }

    fn verdict(&self) -> Option<(f64, f64)> {

        let n = self.count.min(PERIODICITY_SAMPLES);
        if n < MIN_PERIODICITY_GAPS {
            return None; // too few gaps to distinguish regular from lucky
        }
        let sample = &self.gaps[..n];
        let mean = sample.iter().sum::<i64>() as f64 / n as f64;
        if mean <= 0.0 {
            return None;
        }
        let variance = sample.iter().map(|&g| (g as f64 - mean).powi(2)).sum::<f64>() / n as f64;
        Some((mean, variance.sqrt() / mean))
    }

    pub fn samples(&self) -> usize {
        self.count.min(PERIODICITY_SAMPLES)
    }
}

// =======================================================================
// Shannon entropy, for name-shaped data
// =======================================================================

/// Shannon entropy of a byte string, in bits per byte.
///
/// Used on DNS labels: an encoded tunnel payload is close to uniformly
/// random over its alphabet and lands near the theoretical maximum,
/// while real hostnames are English-ish and sit far below it. Entropy
/// alone is a weak signal on short strings, which is why the DNS
/// detector pairs it with length rather than trusting it by itself.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    -counts.iter().filter(|&&c| c > 0).map(|&c| c as f64 / len).map(|p| p * p.log2()).sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_set_counts_distinct_keys_and_forgets_stale_ones() {
        let mut w: WindowSet<u16> = WindowSet::new(1000);
        for port in 1..=10u16 {
            w.insert(port, 100, 10);
        }
        assert_eq!(w.len(), 10);
        // Re-inserting an existing key doesn't inflate the count.
        assert_eq!(w.insert(5, 100, 10), 10);
        // Well past the window, the old keys are pruned on next insert.
        let live = w.insert(99, 200, 10);
        assert_eq!(live, 1, "everything older than the window should be gone");
    }

    /// Pruning must be time-gated, not per-insert: per-insert pruning is
    /// O(size) work per packet, and the size is what an attacker controls.
    #[test]
    fn window_set_prunes_at_most_once_per_second() {
        let mut w: WindowSet<u32> = WindowSet::new(100_000);
        for i in 0..5_000u32 {
            w.insert(i, 1_000, 10);
        }
        assert_eq!(w.len(), 5_000);
        // All at the same second, so exactly one prune can have run.
        // (If it pruned per insert this would still be 5000 — the
        // observable difference is cost, which the bench suite covers;
        // what's asserted here is that gating doesn't lose entries.)
        assert_eq!(w.insert(99_999, 1_000, 10), 5_001);
    }

    #[test]
    fn window_set_is_capped_and_counts_refusals() {
        let mut w: WindowSet<u32> = WindowSet::new(64);
        for i in 0..1_000u32 {
            w.insert(i, 500, 10);
        }
        assert!(w.len() <= 64, "held {} against a cap of 64", w.len());
        assert!(w.refused() > 0, "refusals must be counted, not silent");
    }

    #[test]
    fn rate_window_sums_within_the_window_and_drops_old_buckets() {
        let mut r = RateWindow::new(10);
        for s in 0..10i64 {
            r.add(1_000 + s, 5);
        }
        assert_eq!(r.total(1_009), 50);
        // A full lap later, every old bucket is stale.
        assert_eq!(r.add(1_100, 1), 1);
    }

    #[test]
    fn rate_window_memory_is_fixed_by_window_not_by_rate() {
        let mut r = RateWindow::new(4);
        for _ in 0..100_000 {
            r.add(2_000, 1);
        }
        assert_eq!(r.total(2_000), 100_000, "the count grows; the structure does not");
    }

    #[test]
    fn alert_gate_allows_once_per_interval() {
        let mut g = AlertGate::default();
        assert!(g.allow(1_000, 5), "the first occurrence is never gated");
        assert!(!g.allow(1_001, 5));
        assert!(!g.allow(1_004, 5));
        assert!(g.allow(1_005, 5));
    }

    /// The bug this type exists to make unrepresentable: an `i64::MIN`
    /// sentinel overflowed `now - last` and, in a release build, wrapped
    /// negative — so the gate never opened and no anomaly alert could
    /// ever fire again.
    #[test]
    fn alert_gate_never_overflows_on_a_first_call() {
        let mut g = AlertGate::default();
        assert!(g.allow(i64::MIN + 1, i64::MAX));
        let mut g2 = AlertGate::default();
        assert!(g2.allow(0, i64::MAX));
    }

    #[test]
    fn periodicity_recognises_a_regular_beacon() {
        let mut p = Periodicity::default();
        let mut t = 1_000i64;
        let mut last = None;
        for _ in 0..8 {
            last = p.observe(t);
            t += 60;
        }
        let (mean, cv) = last.expect("enough samples by now");
        assert!((mean - 60.0).abs() < 0.001, "mean gap {}", mean);
        assert!(cv < 0.01, "a perfectly regular beacon should have near-zero CV, got {}", cv);
    }

    #[test]
    fn periodicity_tolerates_jitter_but_rejects_human_traffic() {
        // A beacon with ~10% jitter is still clearly periodic.
        let mut p = Periodicity::default();
        let mut t = 0i64;
        let mut out = None;
        for gap in [60, 63, 57, 61, 59, 64, 58, 60] {
            t += gap;
            out = p.observe(t);
        }
        let (_, cv) = out.unwrap();
        assert!(cv < 0.15, "jittered beacon CV {}", cv);

        // Human-shaped traffic: bursty, wildly uneven gaps.
        let mut h = Periodicity::default();
        let mut t = 0i64;
        let mut out = None;
        for gap in [2, 1, 240, 3, 900, 1, 5, 1800] {
            t += gap;
            out = h.observe(t);
        }
        let (_, cv) = out.unwrap();
        assert!(cv > 0.5, "irregular traffic should not look periodic, CV {}", cv);
    }

    /// Six *gaps* is the minimum, which takes seven observations — the
    /// first establishes a starting point and produces no gap at all.
    ///
    /// The bar used to be four, and four turned out to be chance rather
    /// than evidence: real traffic produced 111 "beacons", every one at
    /// exactly four samples.
    #[test]
    fn periodicity_needs_several_samples_before_it_will_say_anything() {
        let mut p = Periodicity::default();
        let mut t = 100i64;
        for gap in 0..MIN_PERIODICITY_GAPS {
            assert!(p.observe(t).is_none(), "{} gaps is not yet enough", gap);
            t += 60;
        }
        assert!(p.observe(t).is_some(), "{} gaps", MIN_PERIODICITY_GAPS);
    }

    /// A burst at one timestamp must not read as a perfect beacon.
    #[test]
    fn periodicity_ignores_zero_length_gaps() {
        let mut p = Periodicity::default();
        for _ in 0..20 {
            assert!(p.observe(500).is_none(), "same-second repeats carry no timing information");
        }
    }

    /// An out-of-order sample must not rewind the clock and manufacture
    /// a beacon out of unrelated traffic.
    ///
    /// Observations are produced when a flow *retires*, not when it
    /// starts, so they can arrive late carrying an early timestamp. When
    /// a rewind was allowed, the next ordinary sample measured its gap
    /// from the rewound point: a trickle of late arrivals turned twenty
    /// unrelated one-second-apart connections into "8 connections spaced
    /// 10s apart with 0.0% jitter".
    #[test]
    fn out_of_order_samples_do_not_manufacture_a_beacon() {
        let mut p = Periodicity::default();
        let mut verdict = None;
        // Connections one second apart, each trailed by a late
        // observation reporting a timestamp ten seconds in the past.
        for i in 0..20i64 {
            let t = 1000 + i;
            if let Some(v) = p.observe(t) {
                verdict = Some(v);
            }
            if let Some(v) = p.observe(t - 10) {
                verdict = Some(v);
            }
        }
        let (mean, cv) = verdict.expect("twenty samples is plenty to form a verdict");
        assert!((mean - 1.0).abs() < 0.01, "gaps are one second, not ten: mean was {}", mean);
        assert!(cv < 0.01, "and perfectly regular at that spacing: cv was {}", cv);
    }

    #[test]
    fn entropy_separates_random_looking_labels_from_real_hostnames() {
        let random = b"a8f3c92e1b7d4056af83c21e9b5d7f04";
        let hostname = b"mail";
        assert!(shannon_entropy(random) > 3.5, "{}", shannon_entropy(random));
        assert!(shannon_entropy(hostname) < 2.5, "{}", shannon_entropy(hostname));
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaaaaaa"), 0.0, "a single repeated symbol carries no information");
    }
}
