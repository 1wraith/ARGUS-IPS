//! Enrichment: what ARGUS knows that the packets don't say.
//!
//! Every detector in this project reports a *shape*. "Six connections
//! sixty seconds apart with two percent jitter" is a complete and correct
//! description of the traffic, and it is the same description whether the
//! far end is a command-and-control server or a chat client polling an
//! API. No threshold separates those, because the difference is not in
//! the traffic at all — it is in who the far end is. That is the gap this
//! module fills.
//!
//! Three kinds of outside knowledge, each with a different job:
//!
//! - **Reputation** ([`IpSet`], [`DomainSet`], [`Ja3Set`]) turns "this
//!   host talked to 203.0.113.9" into "this host talked to a known C2
//!   address", which is an alert rather than a statistic.
//! - **Home network** ([`Intel::home_net`]) gives every alert a
//!   direction. "Inbound from the internet" and "internal to internal"
//!   are different incidents even when the detector is identical, and
//!   without a notion of inside there is no way to say which one this is.
//! - **Allowlist** ([`Allowlist`]) makes a verdict *stick*. Once an
//!   operator has established that a particular beacon is a backup agent,
//!   the sensor should stop asking. Deleting the rule is the wrong fix —
//!   it disables the detector everywhere. An allowlist entry disables it
//!   for exactly the traffic that was investigated.
//!
//! # Why matching is range-based rather than tree-based
//!
//! A reputation feed is tens to hundreds of thousands of entries, loaded
//! once and then read on every new flow. A radix trie is the textbook
//! structure, but a sorted array of merged `[start, end]` ranges answers
//! the same question with better constants: one binary search over
//! contiguous memory, no pointer chasing, and — because ranges are merged
//! at build time — a smaller working set than the source data. Feeds
//! overlap heavily in practice (the same /24 appearing under three
//! categories), so merging typically shrinks the table rather than
//! growing it.

use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::sync::Arc;

use crate::packet::IpAddr;

// =======================================================================
// Tags: what enrichment concluded about one alert
// =======================================================================

/// Which way an alert's traffic crosses the home-network boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlowDirection {
    /// Outside to inside — the shape of an attack against you.
    Inbound,
    /// Inside to outside — the shape of a compromised host calling home.
    Outbound,
    /// Both ends inside: lateral movement, or ordinary internal traffic.
    Internal,
    /// Neither end inside. Usually means `home_net` isn't configured, or
    /// the sensor is watching a transit link.
    External,
}

impl FlowDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            FlowDirection::Inbound => "inbound",
            FlowDirection::Outbound => "outbound",
            FlowDirection::Internal => "internal",
            FlowDirection::External => "external",
        }
    }
}

/// Enrichment attached to one alert at write time.
///
/// Tags are `Arc<str>` rather than borrowed slices so that this carries
/// no lifetime, which keeps it out of the signature of everything that
/// touches an alert. The cost is a refcount bump per tagged alert, which
/// is invisible at any alert rate a human would tolerate.
#[derive(Clone, Default)]
pub struct Tags {
    pub direction: Option<FlowDirection>,
    pub src_intel: Option<Arc<str>>,
    pub dst_intel: Option<Arc<str>>,
}

impl Tags {
    pub fn none() -> Tags {
        Tags::default()
    }

    pub fn is_empty(&self) -> bool {
        self.direction.is_none() && self.src_intel.is_none() && self.dst_intel.is_none()
    }

    /// Appended to a JSON object that is still open — hence the leading
    /// comma on each field and no braces.
    pub fn write_json(&self, out: &mut String) {
        use std::fmt::Write as _;
        if let Some(d) = self.direction {
            let _ = write!(out, ",\"flow_direction\":\"{}\"", d.as_str());
        }
        if let Some(t) = &self.src_intel {
            out.push_str(",\"src_intel\":\"");
            crate::output::json_escape_into(t, out);
            out.push('"');
        }
        if let Some(t) = &self.dst_intel {
            out.push_str(",\"dst_intel\":\"");
            crate::output::json_escape_into(t, out);
            out.push('"');
        }
    }

    pub fn write_text(&self, out: &mut String) {
        use std::fmt::Write as _;
        if let Some(d) = self.direction {
            let _ = write!(out, " [{}]", d.as_str());
        }
        if let Some(t) = &self.src_intel {
            let _ = write!(out, " [src: {}]", t);
        }
        if let Some(t) = &self.dst_intel {
            let _ = write!(out, " [dst: {}]", t);
        }
    }
}

// =======================================================================
// IpSet: merged ranges, binary searched
// =======================================================================

/// A set of addresses and CIDR blocks, with a tag per entry.
///
/// v4 and v6 are kept apart rather than mapped into a common 128-bit
/// space. Mapping would let an IPv4 rule silently match an IPv4-mapped
/// IPv6 address, which is the sort of accidental equivalence that makes
/// a sensor wrong in a direction nobody notices.
#[derive(Default)]
pub struct IpSet {
    v4: Vec<Range<u32>>,
    v6: Vec<Range<u128>>,
}

struct Range<T> {
    start: T,
    end: T,
    tag: Arc<str>,
}

impl IpSet {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Parses `addr`, `addr/len`, or a bare address, with an optional
    /// tag. Returns the range rather than inserting, so the caller can
    /// batch and sort once.
    fn push(&mut self, spec: &str, tag: Arc<str>) -> anyhow::Result<()> {
        let (addr_s, prefix_s) = match spec.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (spec, None),
        };
        let addr = IpAddr::parse(addr_s).ok_or_else(|| anyhow::anyhow!("bad address {:?}", addr_s))?;
        match addr {
            IpAddr::V4(b) => {
                let bits: u32 = match prefix_s {
                    Some(p) => p.parse()?,
                    None => 32,
                };
                anyhow::ensure!(bits <= 32, "prefix /{} is out of range for IPv4", bits);
                let base = u32::from_be_bytes(b);
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                self.v4.push(Range { start: base & mask, end: (base & mask) | !mask, tag });
            }
            IpAddr::V6(b) => {
                let bits: u32 = match prefix_s {
                    Some(p) => p.parse()?,
                    None => 128,
                };
                anyhow::ensure!(bits <= 128, "prefix /{} is out of range for IPv6", bits);
                let base = u128::from_be_bytes(b);
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                self.v6.push(Range { start: base & mask, end: (base & mask) | !mask, tag });
            }
        }
        Ok(())
    }

    /// Sorts and merges. Called once after loading; lookups assume it has
    /// run, which is why it is not public — [`IntelBuilder`] owns the
    /// order of operations.
    fn finish(&mut self) {
        fn merge<T: Ord + Copy>(v: &mut Vec<Range<T>>) {
            v.sort_by(|a, b| a.start.cmp(&b.start));
            let mut out: Vec<Range<T>> = Vec::with_capacity(v.len());
            for r in v.drain(..) {
                match out.last_mut() {
                    // Only merge when the tags agree. Two feeds covering
                    // the same block for different reasons are two facts,
                    // and collapsing them would silently pick one reason
                    // to report.
                    Some(last) if r.start <= last.end && *last.tag == *r.tag => {
                        if r.end > last.end {
                            last.end = r.end;
                        }
                    }
                    _ => out.push(r),
                }
            }
            *v = out;
        }
        merge(&mut self.v4);
        merge(&mut self.v6);
    }

    /// The tag of the first covering range, or `None`.
    ///
    /// `partition_point` finds the last range whose start is at or below
    /// the address; because ranges are sorted and merged, that is the
    /// only candidate, so this is one binary search and one comparison.
    pub fn lookup(&self, addr: &IpAddr) -> Option<&Arc<str>> {
        fn find<T: Ord + Copy>(v: &[Range<T>], key: T) -> Option<&Arc<str>> {
            let i = v.partition_point(|r| r.start <= key);
            v[..i].iter().rev().find(|r| key <= r.end).map(|r| &r.tag)
        }
        match addr {
            IpAddr::V4(b) => find(&self.v4, u32::from_be_bytes(*b)),
            IpAddr::V6(b) => find(&self.v6, u128::from_be_bytes(*b)),
        }
    }

    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.lookup(addr).is_some()
    }
}

// =======================================================================
// DomainSet: suffix matching
// =======================================================================

/// Domains, matched on label boundaries.
///
/// An entry for `evil.com` matches `evil.com` and `a.b.evil.com` but not
/// `notevil.com` — the distinction substring matching gets wrong, and
/// gets wrong in the direction that produces confident false positives.
///
/// Lookup walks the candidate's own suffixes rather than the table, so
/// cost is the number of labels in the query (rarely above five) and not
/// the size of the feed.
#[derive(Default)]
pub struct DomainSet {
    by_name: FxHashMap<String, Arc<str>>,
}

impl DomainSet {
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    fn push(&mut self, name: &str, tag: Arc<str>) {
        self.by_name.insert(name.trim_matches('.').to_ascii_lowercase(), tag);
    }

    pub fn lookup(&self, name: &str) -> Option<&Arc<str>> {
        let name = name.trim_matches('.');
        if name.is_empty() {
            return None;
        }
        // Lowercase once into a reusable stack buffer when it fits, which
        // it does for every real hostname; DNS caps a name at 253 bytes.
        let mut buf = [0u8; 256];
        let lowered: &str = if name.len() <= buf.len() && name.bytes().any(|b| b.is_ascii_uppercase()) {
            buf[..name.len()].copy_from_slice(name.as_bytes());
            buf[..name.len()].make_ascii_lowercase();
            std::str::from_utf8(&buf[..name.len()]).unwrap_or(name)
        } else {
            name
        };

        let mut rest = lowered;
        loop {
            if let Some(tag) = self.by_name.get(rest) {
                return Some(tag);
            }
            match rest.split_once('.') {
                // Stop before the bare TLD: an entry for "com" would
                // match the entire internet, and a feed that contains one
                // is a broken feed rather than an instruction.
                Some((_, tail)) if tail.contains('.') => rest = tail,
                _ => return None,
            }
        }
    }
}

// =======================================================================
// Ja3Set
// =======================================================================

/// JA3 fingerprints, stored as the 16 raw bytes of the MD5 rather than
/// the 32-character hex, which halves the table and makes comparison a
/// single 16-byte compare.
#[derive(Default)]
pub struct Ja3Set {
    by_hash: FxHashMap<[u8; 16], Arc<str>>,
}

impl Ja3Set {
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    fn push(&mut self, hex: &str, tag: Arc<str>) -> anyhow::Result<()> {
        self.by_hash.insert(parse_md5_hex(hex).ok_or_else(|| anyhow::anyhow!("bad JA3 hash {:?}", hex))?, tag);
        Ok(())
    }

    pub fn lookup(&self, hex: &str) -> Option<&Arc<str>> {
        self.by_hash.get(&parse_md5_hex(hex)?)
    }
}

fn parse_md5_hex(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in b.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

// =======================================================================
// Allowlist
// =======================================================================

/// One "stop telling me about this" decision.
///
/// Every field is optional and an absent field matches anything, so an
/// entry is as narrow as the operator chose to make it. A bare
/// `category:BEACONING` disables beaconing entirely, which is a thing
/// somebody might want and is at least *visible* in a file, unlike the
/// alternative of quietly raising a threshold until the alert stops.
pub struct AllowEntry {
    category: Option<String>,
    src: Option<IpSet>,
    dst: Option<IpSet>,
    port: Option<u16>,
    comment: String,
}

impl AllowEntry {
    fn matches(&self, category: &str, src: &IpAddr, dst: &IpAddr, port: u16) -> bool {
        if let Some(c) = &self.category {
            if !c.eq_ignore_ascii_case(category) {
                return false;
            }
        }
        if let Some(s) = &self.src {
            if !s.contains(src) {
                return false;
            }
        }
        if let Some(d) = &self.dst {
            if !d.contains(dst) {
                return false;
            }
        }
        if let Some(p) = self.port {
            if p != port {
                return false;
            }
        }
        true
    }
}

#[derive(Default)]
pub struct Allowlist {
    entries: Vec<AllowEntry>,
}

impl Allowlist {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The comment of the first matching entry, for the suppression
    /// counter's benefit — an allowlisted alert is counted and
    /// attributed, never silently dropped.
    pub fn matched(&self, category: &str, src: &IpAddr, dst: &IpAddr, port: u16) -> Option<&str> {
        self.entries.iter().find(|e| e.matches(category, src, dst, port)).map(|e| e.comment.as_str())
    }

    /// `category:BEACONING dst:172.64.0.0/13 dst_port:443 # cdn poller`
    fn parse_line(&mut self, line: &str) -> anyhow::Result<()> {
        let (body, comment) = match line.split_once('#') {
            Some((b, c)) => (b, c.trim().to_string()),
            None => (line, String::new()),
        };
        let mut e = AllowEntry { category: None, src: None, dst: None, port: None, comment };
        let mut any = false;
        for tok in body.split_whitespace() {
            let (k, v) = tok.split_once(':').ok_or_else(|| anyhow::anyhow!("allowlist token {:?} is not key:value", tok))?;
            any = true;
            match k {
                "category" | "cat" => e.category = Some(v.to_string()),
                "src" | "src_ip" => {
                    let mut s = IpSet::default();
                    s.push(v, Arc::from(""))?;
                    s.finish();
                    e.src = Some(s);
                }
                "dst" | "dst_ip" => {
                    let mut s = IpSet::default();
                    s.push(v, Arc::from(""))?;
                    s.finish();
                    e.dst = Some(s);
                }
                "port" | "dst_port" => e.port = Some(v.parse()?),
                other => anyhow::bail!("unknown allowlist key {:?}", other),
            }
        }
        // An entry with no terms would match every alert ever raised.
        // Refusing it at load time is the same call the rule parser makes
        // about an all-negated rule, for the same reason.
        anyhow::ensure!(any, "an allowlist entry needs at least one term");
        if e.comment.is_empty() {
            e.comment = "allowlisted".to_string();
        }
        self.entries.push(e);
        Ok(())
    }
}

// =======================================================================
// Intel: the whole enrichment set
// =======================================================================

/// Counts of what loaded, for the startup banner and for `/metrics`.
#[derive(Default, Clone, Copy)]
pub struct IntelStats {
    pub addresses: usize,
    pub domains: usize,
    pub ja3: usize,
    pub allow: usize,
    pub home_net: usize,
}

#[derive(Default)]
pub struct Intel {
    pub reputation: IpSet,
    pub domains: DomainSet,
    pub ja3: Ja3Set,
    pub allow: Allowlist,
    pub home_net: IpSet,
}

impl Intel {
    pub fn stats(&self) -> IntelStats {
        IntelStats {
            addresses: self.reputation.len(),
            domains: self.domains.len(),
            ja3: self.ja3.len(),
            allow: self.allow.len(),
            home_net: self.home_net.len(),
        }
    }

    /// Whether anything at all was configured. Used to skip enrichment
    /// entirely rather than walk empty tables per alert.
    pub fn is_empty(&self) -> bool {
        self.reputation.is_empty() && self.domains.is_empty() && self.ja3.is_empty() && self.allow.is_empty() && self.home_net.is_empty()
    }

    pub fn direction(&self, src: &IpAddr, dst: &IpAddr) -> Option<FlowDirection> {
        if self.home_net.is_empty() {
            return None;
        }
        Some(match (self.home_net.contains(src), self.home_net.contains(dst)) {
            (true, true) => FlowDirection::Internal,
            (true, false) => FlowDirection::Outbound,
            (false, true) => FlowDirection::Inbound,
            (false, false) => FlowDirection::External,
        })
    }

    /// Everything enrichment can say about one alert's endpoints.
    pub fn tag(&self, src: &IpAddr, dst: &IpAddr) -> Tags {
        Tags {
            direction: self.direction(src, dst),
            src_intel: self.reputation.lookup(src).cloned(),
            dst_intel: self.reputation.lookup(dst).cloned(),
        }
    }

    /// Loads a set of files. Any of them may be absent, in which case
    /// that source simply contributes nothing.
    pub fn load(sources: &IntelSources) -> anyhow::Result<Intel> {
        let mut b = IntelBuilder::default();
        for path in &sources.reputation {
            b.load_reputation(path)?;
        }
        for path in &sources.allow {
            b.load_allowlist(path)?;
        }
        for spec in &sources.home_net {
            b.add_home_net(spec)?;
        }
        Ok(b.finish())
    }
}

/// Where enrichment comes from, kept separate from [`Intel`] so that a
/// reload knows what to re-read.
#[derive(Default, Clone)]
pub struct IntelSources {
    pub reputation: Vec<String>,
    pub allow: Vec<String>,
    pub home_net: Vec<String>,
}

impl IntelSources {
    pub fn is_empty(&self) -> bool {
        self.reputation.is_empty() && self.allow.is_empty() && self.home_net.is_empty()
    }

    /// Every file that, if it changes on disk, should trigger a reload.
    pub fn files(&self) -> impl Iterator<Item = &String> {
        self.reputation.iter().chain(self.allow.iter())
    }
}

#[derive(Default)]
struct IntelBuilder {
    intel: Intel,
}

impl IntelBuilder {
    /// One indicator per line, with an optional tag after `#` or `;`.
    ///
    /// The kind is inferred rather than declared, because every published
    /// feed is already a bare list of one kind of thing and requiring a
    /// prefix would mean preprocessing every feed before use. An explicit
    /// `ja3:`/`ip:`/`domain:` prefix is still accepted for the cases
    /// inference would get wrong.
    ///
    /// ```text
    /// 203.0.113.0/24      # cobalt-strike c2
    /// evil.example.com    ; phishing kit
    /// ja3:e7d705a3286e19ea42f587b344ee6865  # known implant
    /// ```
    fn load_reputation(&mut self, path: &str) -> anyhow::Result<()> {
        let text = read_if_present(path)?;
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let (value, tag) = split_tag(line);
            let tag: Arc<str> = Arc::from(if tag.is_empty() { "listed" } else { tag });
            let res = match value.split_once(':') {
                Some(("ja3", v)) => self.intel.ja3.push(v, tag),
                Some(("ip", v)) => self.intel.reputation.push(v, tag),
                Some(("domain", v)) => {
                    self.intel.domains.push(v, tag);
                    Ok(())
                }
                // A bare value: an address or CIDR if it parses as one, a
                // 32-char hex string if it looks like a JA3, a domain
                // otherwise.
                _ => {
                    if looks_like_ip(value) {
                        self.intel.reputation.push(value, tag)
                    } else if parse_md5_hex(value).is_some() {
                        self.intel.ja3.push(value, tag)
                    } else {
                        self.intel.domains.push(value, tag);
                        Ok(())
                    }
                }
            };
            res.map_err(|e| anyhow::anyhow!("{}:{}: {}", path, n + 1, e))?;
        }
        Ok(())
    }

    fn load_allowlist(&mut self, path: &str) -> anyhow::Result<()> {
        let text = read_if_present(path)?;
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.intel.allow.parse_line(line).map_err(|e| anyhow::anyhow!("{}:{}: {}", path, n + 1, e))?;
        }
        Ok(())
    }

    fn add_home_net(&mut self, spec: &str) -> anyhow::Result<()> {
        for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            self.intel.home_net.push(part, Arc::from("home"))?;
        }
        Ok(())
    }

    fn finish(mut self) -> Intel {
        self.intel.reputation.finish();
        self.intel.home_net.finish();
        self.intel
    }
}

fn read_if_present(path: &str) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(anyhow::anyhow!("{}: {}", path, e)),
    }
}

fn split_tag(line: &str) -> (&str, &str) {
    let cut = line.find(['#', ';']).unwrap_or(line.len());
    (line[..cut].trim(), line[cut..].trim_start_matches(['#', ';']).trim())
}

/// Cheap enough to run before attempting a parse: an address or CIDR is
/// all hex digits, dots, colons and at most one slash.
fn looks_like_ip(s: &str) -> bool {
    let body = s.split('/').next().unwrap_or(s);
    !body.is_empty() && body.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':') && (body.contains('.') || body.contains(':'))
}

/// Indicator kinds, used by the worker-side checks so that a lookup
/// against the wrong table is a compile error rather than a silent miss.
pub enum Indicator<'a> {
    Address(&'a IpAddr),
    Domain(&'a str),
    Ja3(&'a str),
}

impl Intel {
    /// One reputation question, whatever the kind.
    pub fn check(&self, what: Indicator<'_>) -> Option<&Arc<str>> {
        match what {
            Indicator::Address(a) => self.reputation.lookup(a),
            Indicator::Domain(d) => self.domains.lookup(d),
            Indicator::Ja3(j) => self.ja3.lookup(j),
        }
    }
}

/// Deduplicates reputation alerts so that one bad destination does not
/// produce one alert per packet to it.
///
/// Separate from the alert writer's suppression deliberately: that is
/// time-windowed and exists to collapse a repeating condition, whereas
/// this is "we already said this about this pair" and wants to hold for
/// as long as the conversation does.
pub struct IntelSeen {
    seen: HashSet<(IpAddr, IpAddr)>,
    cap: usize,
}

impl IntelSeen {
    pub fn new(cap: usize) -> IntelSeen {
        IntelSeen { seen: HashSet::new(), cap }
    }

    /// True the first time a pair is offered, false afterwards. Clears
    /// rather than refuses at the cap, because the cost of forgetting is
    /// a duplicate alert and the cost of refusing is a missed one.
    pub fn first_time(&mut self, src: IpAddr, dst: IpAddr) -> bool {
        if self.seen.len() >= self.cap {
            self.seen.clear();
        }
        self.seen.insert((src, dst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4([a, b, c, d])
    }

    fn ipset(specs: &[(&str, &str)]) -> IpSet {
        let mut s = IpSet::default();
        for (spec, tag) in specs {
            s.push(spec, Arc::from(*tag)).unwrap();
        }
        s.finish();
        s
    }

    #[test]
    fn cidr_membership_covers_the_block_and_stops_at_its_edges() {
        let s = ipset(&[("10.1.2.0/24", "c2")]);
        assert!(s.contains(&v4(10, 1, 2, 0)));
        assert!(s.contains(&v4(10, 1, 2, 255)));
        assert!(!s.contains(&v4(10, 1, 1, 255)));
        assert!(!s.contains(&v4(10, 1, 3, 0)));
        assert_eq!(&**s.lookup(&v4(10, 1, 2, 7)).unwrap(), "c2");
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        let s = ipset(&[("192.0.2.5", "bad")]);
        assert!(s.contains(&v4(192, 0, 2, 5)));
        assert!(!s.contains(&v4(192, 0, 2, 6)));
    }

    /// An IPv4 entry must never match an IPv6 address, however it is
    /// written — the two families are kept in separate tables precisely
    /// so that no mapped-address equivalence can creep in.
    #[test]
    fn address_families_do_not_cross() {
        let s = ipset(&[("0.0.0.0/0", "everything-v4")]);
        assert!(s.contains(&v4(8, 8, 8, 8)));
        assert!(!s.contains(&IpAddr::V6([0; 16])));
    }

    #[test]
    fn ipv6_prefixes_match_on_the_prefix_only() {
        let s = ipset(&[("2001:db8::/32", "doc")]);
        let mut inside = [0u8; 16];
        inside[0] = 0x20;
        inside[1] = 0x01;
        inside[2] = 0x0d;
        inside[3] = 0xb8;
        inside[15] = 9;
        assert!(s.contains(&IpAddr::V6(inside)));
        let mut outside = inside;
        outside[3] = 0xb9;
        assert!(!s.contains(&IpAddr::V6(outside)));
    }

    /// Overlapping entries with the same tag merge; with different tags
    /// they stay distinct, because they are two different facts.
    #[test]
    fn overlapping_ranges_merge_only_when_they_mean_the_same_thing() {
        let same = ipset(&[("10.0.0.0/24", "c2"), ("10.0.0.128/25", "c2")]);
        assert_eq!(same.len(), 1, "one fact about one range");
        let different = ipset(&[("10.0.0.0/24", "c2"), ("10.0.0.128/25", "phishing")]);
        assert_eq!(different.len(), 2, "two reasons must not collapse into one");
    }

    #[test]
    fn domains_match_on_label_boundaries_not_substrings() {
        let mut d = DomainSet::default();
        d.push("evil.com", Arc::from("bad"));
        assert!(d.lookup("evil.com").is_some());
        assert!(d.lookup("a.b.evil.com").is_some());
        assert!(d.lookup("EVIL.COM").is_some(), "matching is case-insensitive");
        assert!(d.lookup("notevil.com").is_none(), "a substring is not a subdomain");
        assert!(d.lookup("evil.com.au").is_none(), "a longer TLD is a different domain");
    }

    /// A feed containing a bare TLD would otherwise match everything
    /// under it. Walking stops before the last label so it cannot.
    #[test]
    fn a_bare_tld_entry_cannot_match_every_domain() {
        let mut d = DomainSet::default();
        d.push("com", Arc::from("oops"));
        assert!(d.lookup("example.com").is_none());
        assert!(d.lookup("com").is_some(), "an exact query still matches exactly");
    }

    #[test]
    fn ja3_hashes_round_trip_through_hex() {
        let mut j = Ja3Set::default();
        j.push("e7d705a3286e19ea42f587b344ee6865", Arc::from("implant")).unwrap();
        assert!(j.lookup("e7d705a3286e19ea42f587b344ee6865").is_some());
        assert!(j.lookup("E7D705A3286E19EA42F587B344EE6865").is_some(), "hex is case-insensitive, and feeds are inconsistent about it");
        assert!(j.lookup("short").is_none());
        assert!(j.push("nothex", Arc::from("x")).is_err());
    }

    #[test]
    fn home_net_gives_every_alert_a_direction() {
        let mut b = IntelBuilder::default();
        b.add_home_net("10.0.0.0/8,192.168.0.0/16").unwrap();
        let intel = b.finish();
        let inside = v4(10, 1, 1, 1);
        let outside = v4(8, 8, 8, 8);
        assert_eq!(intel.direction(&outside, &inside), Some(FlowDirection::Inbound));
        assert_eq!(intel.direction(&inside, &outside), Some(FlowDirection::Outbound));
        assert_eq!(intel.direction(&inside, &v4(192, 168, 1, 1)), Some(FlowDirection::Internal));
        assert_eq!(intel.direction(&outside, &v4(1, 1, 1, 1)), Some(FlowDirection::External));
    }

    /// Without a home network there is no inside, so claiming a direction
    /// would be an invention.
    #[test]
    fn direction_is_absent_rather_than_guessed_when_home_net_is_unset() {
        let intel = Intel::default();
        assert_eq!(intel.direction(&v4(1, 1, 1, 1), &v4(2, 2, 2, 2)), None);
    }

    fn allowlist(lines: &[&str]) -> Allowlist {
        let mut a = Allowlist::default();
        for l in lines {
            a.parse_line(l).unwrap();
        }
        a
    }

    #[test]
    fn an_allowlist_entry_silences_exactly_what_it_names() {
        let a = allowlist(&["category:BEACONING dst:172.64.0.0/13 dst_port:443 # cdn poller"]);
        assert_eq!(a.matched("BEACONING", &v4(10, 0, 0, 5), &v4(172, 64, 146, 215), 443), Some("cdn poller"));
        // Same destination, different category: still reported.
        assert!(a.matched("PORT_SCAN", &v4(10, 0, 0, 5), &v4(172, 64, 146, 215), 443).is_none());
        // Same category, different destination: still reported.
        assert!(a.matched("BEACONING", &v4(10, 0, 0, 5), &v4(203, 0, 113, 9), 443).is_none());
        // Same everything but the port: still reported.
        assert!(a.matched("BEACONING", &v4(10, 0, 0, 5), &v4(172, 64, 146, 215), 8443).is_none());
    }

    #[test]
    fn an_allowlist_entry_with_no_terms_is_refused() {
        let mut a = Allowlist::default();
        assert!(a.parse_line("# just a comment").is_err(), "an entry matching everything is a mistake, not a policy");
        assert!(a.parse_line("nonsense").is_err());
        assert!(a.parse_line("unknown_key:1").is_err());
    }

    #[test]
    fn indicator_kinds_are_inferred_from_their_shape() {
        let dir = std::env::temp_dir().join(format!("argus-intel-{}.txt", std::process::id()));
        std::fs::write(
            &dir,
            "# a feed\n203.0.113.0/24 # c2\nevil.example.com ; phishing\ne7d705a3286e19ea42f587b344ee6865 # implant\nja3:0123456789abcdef0123456789abcdef # explicit\nip:198.51.100.7 # explicit too\n",
        )
        .unwrap();
        let mut b = IntelBuilder::default();
        b.load_reputation(dir.to_str().unwrap()).unwrap();
        let intel = b.finish();
        assert_eq!(&**intel.reputation.lookup(&v4(203, 0, 113, 9)).unwrap(), "c2");
        assert_eq!(&**intel.reputation.lookup(&v4(198, 51, 100, 7)).unwrap(), "explicit too");
        assert_eq!(&**intel.domains.lookup("a.evil.example.com").unwrap(), "phishing");
        assert_eq!(&**intel.ja3.lookup("e7d705a3286e19ea42f587b344ee6865").unwrap(), "implant");
        assert_eq!(intel.ja3.len(), 2);
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn a_missing_feed_file_is_not_an_error() {
        let mut b = IntelBuilder::default();
        b.load_reputation("definitely-not-a-real-path.txt").unwrap();
        assert!(b.finish().is_empty());
    }

    #[test]
    fn repeated_intel_alerts_for_one_pair_are_reported_once() {
        let mut seen = IntelSeen::new(8);
        assert!(seen.first_time(v4(10, 0, 0, 1), v4(203, 0, 113, 9)));
        assert!(!seen.first_time(v4(10, 0, 0, 1), v4(203, 0, 113, 9)));
        assert!(seen.first_time(v4(10, 0, 0, 2), v4(203, 0, 113, 9)), "a different source is a different event");
    }

    #[test]
    fn tags_render_into_both_output_shapes() {
        let t = Tags { direction: Some(FlowDirection::Outbound), src_intel: None, dst_intel: Some(Arc::from("c2")) };
        let mut s = String::new();
        t.write_json(&mut s);
        assert_eq!(s, ",\"flow_direction\":\"outbound\",\"dst_intel\":\"c2\"");
        s.clear();
        t.write_text(&mut s);
        assert_eq!(s, " [outbound] [dst: c2]");
    }
}
