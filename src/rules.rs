//! Rule language v2: header scoping, multiple ANDed content matches with
//! positional anchoring, and per-rule identity (sid/severity).
//!
//! The v1 format — `name|buffer|direction|type|pattern` — is one buffer,
//! one pattern, no scoping, no identity. Every match is `HIGH`, nothing
//! can be tuned down, and there is no rule id to correlate on downstream.
//! Most real-world signatures simply can't be written in it, because a
//! real signature is a *conjunction*: this protocol, to this port, with
//! this string near the start, **and** that string after it.
//!
//! v1 still loads and behaves exactly as before (see `engine::RuleSet`);
//! this is an additional grammar, chosen per line by its leading keyword.
//!
//! ```text
//! rule sid:1000001; name:"sqli-union"; severity:high; proto:tcp;
//!      dst_port:80,443,8000-8100; src_ip:!10.0.0.0/8;
//!      direction:to_server; buffer:http.uri;
//!      content:"UNION"; nocase; offset:0; depth:200;
//!      content:"SELECT"; nocase;
//! ```
//!
//! Semantics, in one paragraph: every `content`/`pcre` in a rule must
//! match for the rule to fire (AND, not OR — `!content` inverts that one
//! term). `offset`/`depth`/`nocase` modify the content they follow,
//! which is the Suricata convention and the reason options are ordered
//! rather than a map. Header terms (`proto`, `src_ip`, `dst_ip`,
//! `src_port`, `dst_port`) are tested against the packet before any
//! content is examined, so a rule scoped to one port costs almost
//! nothing on traffic to any other port.

use aho_corasick::AhoCorasick;
use rustc_hash::FxHashMap;

use crate::engine::{Buffer, Direction, Severity};
use crate::packet::{IpAddr, Packet, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

// =======================================================================
// Header matching
// =======================================================================

/// A set of CIDR prefixes, optionally negated.
#[derive(Clone, Debug)]
pub struct IpMatch {
    negate: bool,
    /// (address bytes, prefix length in bits). IPv4 and IPv6 entries can
    /// coexist; an address only ever compares against its own family.
    prefixes: Vec<(IpAddr, u8)>,
}

impl IpMatch {
    pub fn parse(spec: &str) -> anyhow::Result<IpMatch> {
        let (negate, body) = match spec.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, spec),
        };
        let mut prefixes = Vec::new();
        for item in body.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if item == "any" {
                // `any` with no negation matches everything, so an empty
                // prefix list plus `negate: false` is handled by `matches`.
                continue;
            }
            let (addr_str, bits) = match item.split_once('/') {
                Some((a, b)) => (a, Some(b.parse::<u8>()?)),
                None => (item, None),
            };
            let addr = IpAddr::parse(addr_str).ok_or_else(|| anyhow::anyhow!("invalid IP address {:?}", addr_str))?;
            let full = if addr.is_v4() { 32 } else { 128 };
            let bits = bits.unwrap_or(full);
            if bits > full {
                anyhow::bail!("prefix /{} is too long for {}", bits, addr_str);
            }
            prefixes.push((addr, bits));
        }
        Ok(IpMatch { negate, prefixes })
    }

    fn contains(&self, addr: IpAddr) -> bool {
        self.prefixes.iter().any(|(net, bits)| prefix_eq(*net, addr, *bits))
    }

    fn matches(&self, addr: IpAddr) -> bool {
        if self.prefixes.is_empty() {
            // "any", or "!any" which matches nothing.
            return !self.negate;
        }
        self.contains(addr) != self.negate
    }
}

/// Compares the first `bits` bits of two addresses. Returns false across
/// families, which is the honest answer: an IPv4 rule doesn't silently
/// apply to IPv6 traffic (a mistake that would be invisible until the
/// day it mattered).
fn prefix_eq(net: IpAddr, addr: IpAddr, bits: u8) -> bool {
    let (a, b) = match (net, addr) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (a.to_vec(), b.to_vec()),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.to_vec(), b.to_vec()),
        _ => return false,
    };
    let full_bytes = (bits / 8) as usize;
    if a[..full_bytes] != b[..full_bytes] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    a[full_bytes] & mask == b[full_bytes] & mask
}

/// A set of ports and inclusive ranges, optionally negated.
#[derive(Clone, Debug)]
pub struct PortMatch {
    negate: bool,
    ranges: Vec<(u16, u16)>,
}

impl PortMatch {
    pub fn parse(spec: &str) -> anyhow::Result<PortMatch> {
        let (negate, body) = match spec.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, spec),
        };
        let mut ranges = Vec::new();
        for item in body.split(',') {
            let item = item.trim();
            if item.is_empty() || item == "any" {
                continue;
            }
            match item.split_once('-') {
                Some((lo, hi)) => {
                    let lo: u16 = lo.trim().parse()?;
                    let hi: u16 = hi.trim().parse()?;
                    if lo > hi {
                        anyhow::bail!("port range {}-{} is inverted", lo, hi);
                    }
                    ranges.push((lo, hi));
                }
                None => {
                    let p: u16 = item.parse()?;
                    ranges.push((p, p));
                }
            }
        }
        Ok(PortMatch { negate, ranges })
    }

    fn matches(&self, port: u16) -> bool {
        if self.ranges.is_empty() {
            return !self.negate;
        }
        self.ranges.iter().any(|(lo, hi)| port >= *lo && port <= *hi) != self.negate
    }
}

/// A comparison of a length against constants, written as Suricata's
/// `urilen`, `dsize` and `bsize` write it: `N`, `<N`, `>N`, `<=N`, `>=N`,
/// or `A<>B`.
///
/// `A<>B` is *exclusive* at both ends, which is how Suricata reads it and
/// differs from what a reader might assume. `10<>20` matches 11 through
/// 19, so a rule translated with an inclusive range would match two
/// lengths it should not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LenTest {
    Eq(u64),
    Lt(u64),
    Gt(u64),
    Le(u64),
    Ge(u64),
    /// Strictly between.
    Between(u64, u64),
}

impl LenTest {
    pub fn parse(spec: &str) -> anyhow::Result<LenTest> {
        let t = spec.trim();
        let num = |s: &str| -> anyhow::Result<u64> { Ok(s.trim().parse::<u64>()?) };
        if let Some((a, b)) = t.split_once("<>") {
            let (a, b) = (num(a)?, num(b)?);
            anyhow::ensure!(a < b, "the range {}<>{} is empty", a, b);
            return Ok(LenTest::Between(a, b));
        }
        Ok(if let Some(r) = t.strip_prefix("<=") {
            LenTest::Le(num(r)?)
        } else if let Some(r) = t.strip_prefix(">=") {
            LenTest::Ge(num(r)?)
        } else if let Some(r) = t.strip_prefix('<') {
            LenTest::Lt(num(r)?)
        } else if let Some(r) = t.strip_prefix('>') {
            LenTest::Gt(num(r)?)
        } else {
            LenTest::Eq(num(t.strip_prefix('=').unwrap_or(t))?)
        })
    }

    #[inline]
    pub fn holds(self, len: usize) -> bool {
        let n = len as u64;
        match self {
            LenTest::Eq(a) => n == a,
            LenTest::Lt(a) => n < a,
            LenTest::Gt(a) => n > a,
            LenTest::Le(a) => n <= a,
            LenTest::Ge(a) => n >= a,
            LenTest::Between(a, b) => n > a && n < b,
        }
    }
}

/// `isdataat:[!]N[,relative]`: does a byte exist N bytes on?
///
/// "Exists" means index `base + N` is inside the buffer, so `isdataat:4`
/// is true when at least five bytes remain from the base, and the negated
/// form is the useful one: `isdataat:!4,relative` after a content says
/// "at most four bytes follow it", which is how a rule pins a value to the
/// end of a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataAt {
    offset: usize,
    /// The distance comes from a variable (`isdataat:!length`).
    var: Option<u8>,
    relative: bool,
    negate: bool,
}

impl DataAt {
    fn parse(spec: &str, vars: &VarTable) -> anyhow::Result<DataAt> {
        let mut parts = spec.split(',').map(str::trim);
        let first = parts.next().unwrap_or("");
        let (negate, digits) = match first.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, first),
        };
        let (offset, var) = match digits.parse::<usize>() {
            Ok(n) => (n, None),
            Err(_) => (0, Some(vars.lookup(digits)?)),
        };
        let mut relative = false;
        for m in parts {
            match m.to_ascii_lowercase().as_str() {
                "relative" => relative = true,
                "" => {}
                other => anyhow::bail!("unknown isdataat modifier {:?}", other),
            }
        }
        Ok(DataAt { offset, var, relative, negate })
    }

    #[inline]
    fn holds(self, len: usize, cursor: usize, vars: &Vars) -> bool {
        let base = if self.relative { cursor } else { 0 };
        let Some(offset) = resolve(self.offset as i64, self.var, vars) else { return self.negate };
        (base.saturating_add(offset.max(0) as usize) < len) != self.negate
    }
}

/// `flags:` — the TCP flags of a packet.
///
/// `flags:S` means exactly SYN; `+` means "at least these"; `*` means "any
/// of these"; `!` means "none of these". A second argument names flags to
/// leave out of the comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpFlagTest {
    mode: FlagMode,
    flags: u8,
    ignore: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlagMode {
    Exact,
    All,
    Any,
    None,
}

impl TcpFlagTest {
    pub fn parse(spec: &str) -> anyhow::Result<TcpFlagTest> {
        let (list, ignore) = match spec.split_once(',') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (spec.trim(), ""),
        };
        let (mode, letters) = match list.chars().next() {
            Some('+') => (FlagMode::All, &list[1..]),
            Some('*') => (FlagMode::Any, &list[1..]),
            Some('!') => (FlagMode::None, &list[1..]),
            _ => (FlagMode::Exact, list),
        };
        fn bits(letters: &str) -> anyhow::Result<u8> {
            let mut out = 0u8;
            for c in letters.chars() {
                out |= match c.to_ascii_uppercase() {
                    'F' => 0x01,
                    'S' => 0x02,
                    'R' => 0x04,
                    'P' => 0x08,
                    'A' => 0x10,
                    'U' => 0x20,
                    'E' | '2' => 0x40,
                    'C' | '1' => 0x80,
                    '0' => 0,
                    other => anyhow::bail!("unknown TCP flag {:?}", other),
                };
            }
            Ok(out)
        }
        Ok(TcpFlagTest { mode, flags: bits(letters)?, ignore: bits(ignore)? })
    }

    fn holds(self, p: &Packet) -> bool {
        if p.protocol != PROTO_TCP {
            return false;
        }
        let seen = p.tcp_flags & !self.ignore;
        let want = self.flags & !self.ignore;
        match self.mode {
            FlagMode::Exact => seen == want,
            FlagMode::All => seen & want == want,
            FlagMode::Any => seen & want != 0,
            FlagMode::None => seen & want == 0,
        }
    }
}

/// `stream_size:<side>,<op>,<bytes>`: how much of the connection has been
/// seen. "Server" is what the server has sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamTest {
    side: StreamSide,
    op: StreamOp,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamSide {
    Server,
    Client,
    Both,
    Either,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamOp {
    Lt,
    Gt,
    Eq,
    Ne,
    Le,
    Ge,
}

impl StreamTest {
    pub fn parse(spec: &str) -> anyhow::Result<StreamTest> {
        let mut it = spec.split(',').map(str::trim);
        let side = match it.next().unwrap_or("").to_ascii_lowercase().as_str() {
            "server" => StreamSide::Server,
            "client" => StreamSide::Client,
            "both" => StreamSide::Both,
            "either" => StreamSide::Either,
            other => anyhow::bail!("stream_size needs server, client, both or either, not {:?}", other),
        };
        let op = match it.next().unwrap_or("") {
            "<" => StreamOp::Lt,
            ">" => StreamOp::Gt,
            "=" => StreamOp::Eq,
            "!=" => StreamOp::Ne,
            "<=" => StreamOp::Le,
            ">=" => StreamOp::Ge,
            other => anyhow::bail!("stream_size operator {:?} is not one of < > = != <= >=", other),
        };
        let bytes = it.next().ok_or_else(|| anyhow::anyhow!("stream_size needs a byte count"))?.parse()?;
        Ok(StreamTest { side, op, bytes })
    }

    fn holds(self, bits: Option<&FlowBits>) -> bool {
        // A datagram has no stream, so there is nothing to measure.
        let Some(bits) = bits else { return false };
        let (to_server, to_client) = bits.stream_bytes();
        let cmp = |n: u64| match self.op {
            StreamOp::Lt => n < self.bytes,
            StreamOp::Gt => n > self.bytes,
            StreamOp::Eq => n == self.bytes,
            StreamOp::Ne => n != self.bytes,
            StreamOp::Le => n <= self.bytes,
            StreamOp::Ge => n >= self.bytes,
        };
        match self.side {
            StreamSide::Server => cmp(to_client),
            StreamSide::Client => cmp(to_server),
            StreamSide::Both => cmp(to_client) && cmp(to_server),
            StreamSide::Either => cmp(to_client) || cmp(to_server),
        }
    }
}

/// Conditions on a packet's headers beyond addresses and ports. Rare, so
/// kept behind one pointer rather than widening every rule.
#[derive(Clone, Default, Debug)]
pub struct PacketTests {
    pub icmp_type: Option<LenTest>,
    pub icmp_code: Option<LenTest>,
    pub window: Option<LenTest>,
    pub ip_proto: Option<LenTest>,
    pub flags: Option<TcpFlagTest>,
    pub stream: Option<StreamTest>,
}

impl PacketTests {
    fn holds(&self, p: &Packet) -> bool {
        let icmp = p.protocol == PROTO_ICMP || p.protocol == PROTO_ICMPV6;
        self.icmp_type.is_none_or(|t| icmp && t.holds(p.icmp_type as usize))
            && self.icmp_code.is_none_or(|t| icmp && t.holds(p.icmp_code as usize))
            && self.window.is_none_or(|t| p.protocol == PROTO_TCP && t.holds(p.tcp_window as usize))
            && self.ip_proto.is_none_or(|t| t.holds(p.protocol as usize))
            && self.flags.is_none_or(|t| t.holds(p))
    }
}

/// The packet-header conditions a rule is scoped to. All `None` means
/// "any", which is how a v1 rule behaves.
#[derive(Clone, Default, Debug)]
pub struct HeaderMatch {
    /// Flags, ICMP type and code, window, and connection size.
    pub extra: Option<Box<PacketTests>>,
    pub proto: Option<u8>,
    pub src_ip: Option<IpMatch>,
    pub dst_ip: Option<IpMatch>,
    pub src_port: Option<PortMatch>,
    pub dst_port: Option<PortMatch>,
    /// `dsize`: the size of *this packet's* payload, not of the reassembled
    /// stream. It belongs with the header checks, not the content terms,
    /// because it says nothing about any buffer: it is a fact about one
    /// packet, and is tested before any buffer is searched.
    pub payload_len: Option<LenTest>,
}

impl HeaderMatch {
    /// Tested before any content is examined, which is most of the point:
    /// a rule scoped to `dst_port:502` costs one integer comparison on
    /// every packet that isn't Modbus, instead of a substring search.
    ///
    /// `direction` matters because "source" and "destination" in a rule
    /// mean client and server, not whichever way this particular packet
    /// happens to be travelling. For a `to_client` packet the addresses
    /// are therefore compared swapped — without that, a rule written
    /// `src_ip:10.0.0.0/8; dst_port:80` would silently fail to match the
    /// server's replies within the very connection it was scoped to.
    ///
    /// `Direction::Any` means the caller has no flow state and genuinely
    /// does not know the orientation, which every UDP path is the case
    /// for. There the literal packet fields are used with no swap:
    /// inventing an orientation made a `dst_port:53` rule fire on DNS
    /// replies, where 53 is the *source* port.
    pub fn matches(&self, p: &Packet, direction: Direction) -> bool {
        if let Some(proto) = self.proto {
            if p.protocol != proto {
                return false;
            }
        }
        if let Some(t) = self.payload_len {
            if !t.holds(p.payload().len()) {
                return false;
            }
        }
        if let Some(x) = &self.extra {
            if !x.holds(p) {
                return false;
            }
        }
        let swapped = direction == Direction::ToClient;
        let (src, src_port, dst, dst_port) = if swapped {
            (p.dst, p.dst_port, p.src, p.src_port)
        } else {
            (p.src, p.src_port, p.dst, p.dst_port)
        };
        if let Some(m) = &self.src_ip {
            if !m.matches(src) {
                return false;
            }
        }
        if let Some(m) = &self.dst_ip {
            if !m.matches(dst) {
                return false;
            }
        }
        if let Some(m) = &self.src_port {
            if !m.matches(src_port) {
                return false;
            }
        }
        if let Some(m) = &self.dst_port {
            if !m.matches(dst_port) {
                return false;
            }
        }
        true
    }

    pub fn is_any(&self) -> bool {
        self.proto.is_none()
            && self.src_ip.is_none()
            && self.dst_ip.is_none()
            && self.src_port.is_none()
            && self.dst_port.is_none()
            && self.payload_len.is_none()
            && self.extra.is_none()
    }
}

// =======================================================================
// Content matching
// =======================================================================

/// Backtracking steps one match attempt may take before it is abandoned.
///
/// The linear engine is the default precisely because it cannot be made to
/// run long: its cost is bounded by the input. A backtracking engine can
/// be, and the input is attacker-controlled, so this is a hard ceiling
/// rather than a tuning knob. A pattern that hits it is treated as "did
/// not match" (and, if negated, as "did not fail to match"), and the hit
/// is counted so a rule that keeps blowing its budget is visible.
pub const BACKTRACK_LIMIT: usize = 100_000;

static BACKTRACK_LIMIT_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Match attempts abandoned for exceeding [`BACKTRACK_LIMIT`], since start.
pub fn backtrack_limit_hits() -> u64 {
    BACKTRACK_LIMIT_HITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// PCRE constructs the linear engine lacks — lookaround, backreferences,
/// atomic groups, possessive quantifiers — behind a step limit.
///
/// `fancy-regex` works on `&str`, and packet payloads are bytes. Rather
/// than reject anything that is not UTF-8, each byte is read as the
/// character with the same code (Latin-1), so a rule's `\xNN` escapes and
/// a payload's bytes mean the same thing. All-ASCII input, which is most
/// of what crosses a network, is used in place with no copy.
#[derive(Clone, Debug)]
pub struct Backtracking(fancy_regex::Regex);

impl Backtracking {
    fn new(pattern: &str) -> anyhow::Result<Backtracking> {
        let re = fancy_regex::RegexBuilder::new(pattern).backtrack_limit(BACKTRACK_LIMIT).build().map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok(Backtracking(re))
    }

    /// The first match at or after byte `from`, in `hay`'s own offsets.
    /// `Err` means the attempt was abandoned.
    fn find_from(&self, hay: &[u8], from: usize) -> Result<Option<(usize, usize)>, ()> {
        let from = from.min(hay.len());
        if hay.is_ascii() {
            // Valid UTF-8 by construction, and offsets are identical.
            return match std::str::from_utf8(hay) {
                Ok(text) => self.run(text, from),
                Err(_) => Err(()),
            };
        }
        let text: String = hay.iter().map(|&b| b as char).collect();
        // Every high byte became two UTF-8 bytes, so offsets shift by
        // however many precede them, in both directions.
        let high_before = hay[..from].iter().filter(|b| **b >= 0x80).count();
        let found = self.run(&text, from + high_before)?;
        Ok(found.map(|(a, b)| (text[..a].chars().count(), text[..b].chars().count())))
    }

    fn run(&self, text: &str, pos: usize) -> Result<Option<(usize, usize)>, ()> {
        match self.0.find_from_pos(text, pos) {
            Ok(m) => Ok(m.map(|m| (m.start(), m.end()))),
            Err(_) => {
                BACKTRACK_LIMIT_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(())
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Pattern {
    Literal(Vec<u8>),
    /// A literal matched without regard to ASCII case, held lower-cased.
    ///
    /// This used to be compiled to a `(?i-u)` regex, which is correct and
    /// roughly twenty times slower on the short buffers rules read. Most
    /// of a real ruleset is `nocase`, so that was the dominant cost of
    /// running one.
    NoCase(Vec<u8>),
    Regex(regex::bytes::Regex),
    Backtrack(Backtracking),
}

/// One content term. A rule's terms are ANDed, and evaluated in order.
#[derive(Clone, Debug)]
pub struct ContentMatch {
    pattern: Pattern,
    negate: bool,
    /// Start searching this many bytes in, from the start of the buffer.
    offset: usize,
    /// Search at most this many bytes from `offset`. `None` means to the
    /// end of the buffer.
    depth: Option<usize>,
    /// Start searching this many bytes past the end of the previous
    /// term's match. Makes the term *relative*.
    distance: Option<i64>,
    /// Search at most this many bytes past the end of the previous
    /// term's match. Also makes the term relative.
    within: Option<usize>,
    /// A regex that *resumes* where the previous term ended, PCRE's `R`
    /// flag. Distinct from `distance:0` in one way that matters: the
    /// search starts at an offset into the *whole* buffer rather than at
    /// the front of a slice of it, so `^` does not match there and `\b`
    /// and lookbehind can see the bytes before it. Slicing would give
    /// `\bfoo` a word boundary it does not have in the real stream.
    resume: bool,
    /// `offset`, `depth`, `distance` or `within` taken from a variable.
    vars: [Option<u8>; 4],
}

impl ContentMatch {
    fn is_relative(&self) -> bool {
        self.distance.is_some() || self.within.is_some() || self.resume || self.vars[2].is_some() || self.vars[3].is_some()
    }

    /// What a regex that gave up counts as: not a match, unless negated,
    /// in which case "not a match" would make the rule fire on the very
    /// input that defeated it.
    fn gave_up(&self, at: usize) -> Option<(usize, usize)> {
        self.negate.then_some((at, at))
    }

    /// The absolute window this term may look at.
    ///
    /// Anchoring is not a micro-optimisation — it is what makes a rule
    /// specific enough to be safe. "`/bin/sh` anywhere in the stream" is
    /// a false-positive generator; "`/bin/sh` within the first 40 bytes
    /// of the URI" is a signature. Relative anchoring is the stronger
    /// form of the same idea: "this string immediately after that one"
    /// is a statement about structure, not about coincidence.
    fn bounds(&self, len: usize, cursor: usize, vars: &Vars) -> Option<(usize, usize)> {
        let [v_offset, v_depth, v_distance, v_within] = self.vars;
        let distance = resolve(self.distance.unwrap_or(0), v_distance, vars)?;
        let within = match self.within {
            Some(w) => Some(resolve(w as i64, v_within, vars)?.max(0) as usize),
            None if v_within.is_some() => Some(resolve(0, v_within, vars)?.max(0) as usize),
            None => None,
        };
        let offset = resolve(self.offset as i64, v_offset, vars)?.max(0) as usize;
        let depth = match self.depth {
            Some(d) => Some(resolve(d as i64, v_depth, vars)?.max(0) as usize),
            None if v_depth.is_some() => Some(resolve(0, v_depth, vars)?.max(0) as usize),
            None => None,
        };
        Some(if self.is_relative() {
            // `distance` moves the start of the window, and may be negative
            // to look back over what was just matched. `within` bounds where
            // the match must *end*, measured from the end of the previous
            // match, not from wherever `distance` put the start: with
            // `distance:2; within:5` the match must lie inside the five
            // bytes after the previous match and begin no earlier than the
            // third. (That is what the field's own doc says, what the
            // ordinary case `distance:0` cannot tell apart, and what
            // Suricata does.)
            let start = (cursor as i64).saturating_add(distance).clamp(0, len as i64) as usize;
            let end = match within {
                Some(w) => cursor.saturating_add(w).min(len),
                None => len,
            };
            (start, end)
        } else {
            let start = offset.min(len);
            let end = match depth {
                Some(d) => start.saturating_add(d).min(len),
                None => len,
            };
            (start, end)
        })
    }

    /// Where this term matches, in absolute buffer coordinates.
    fn find(&self, data: &[u8], cursor: usize, vars: &Vars) -> Option<(usize, usize)> {
        if self.resume {
            let from = cursor.min(data.len());
            return match &self.pattern {
                Pattern::Regex(re) => re.find_at(data, from).map(|m| (m.start(), m.end())),
                Pattern::Backtrack(bt) => match bt.find_from(data, from) {
                    Ok(found) => found,
                    Err(()) => self.gave_up(from),
                },
                Pattern::Literal(_) | Pattern::NoCase(_) => None,
            };
        }
        let (start, end) = self.bounds(data.len(), cursor, vars)?;
        if start > end {
            return None;
        }
        let window = &data[start..end];
        match &self.pattern {
            Pattern::Literal(needle) => find_subslice(window, needle).map(|i| (start + i, start + i + needle.len())),
            Pattern::NoCase(needle) => find_nocase(window, needle).map(|i| (start + i, start + i + needle.len())),
            Pattern::Regex(re) => re.find(window).map(|m| (start + m.start(), start + m.end())),
            Pattern::Backtrack(bt) => match bt.find_from(window, 0) {
                Ok(found) => found.map(|(a, b)| (start + a, start + b)),
                Err(()) => self.gave_up(start),
            },
        }
    }

    /// The literal this term requires, when it has one and isn't negated
    /// — used to build the multi-pattern prefilter.
    fn prefilter_literal(&self) -> Option<&[u8]> {
        match (&self.pattern, self.negate) {
            (Pattern::Literal(p), false) | (Pattern::NoCase(p), false) if !p.is_empty() => Some(p),
            _ => None,
        }
    }
}

/// Finds `needle` (already lower-cased) in `haystack`, ignoring ASCII case.
///
/// Scans for the needle's first byte in both cases and confirms from
/// there, so the work is proportional to how often that byte appears
/// rather than to building and running an automaton for every call.
fn find_nocase(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let m = needle.len();
    if m == 0 || m > haystack.len() {
        return None;
    }
    let (lower, upper) = (needle[0], needle[0].to_ascii_uppercase());
    let last_start = haystack.len() - m;
    let mut at = 0;
    while at <= last_start {
        let window = &haystack[at..=last_start];
        let found = if lower == upper { memchr::memchr(lower, window) } else { memchr::memchr2(lower, upper, window) };
        let i = at + found?;
        if haystack[i..i + m].eq_ignore_ascii_case(needle) {
            return Some(i);
        }
        at = i + 1;
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// =======================================================================
// Numeric terms
// =======================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOp {
    Less,
    Greater,
    Equal,
    NotEqual,
    LessEqual,
    GreaterEqual,
    /// Bitwise AND: true when every bit in the value is set.
    And,
    /// Bitwise OR: true when any bit in the value is set.
    Or,
}

impl ByteOp {
    fn parse(s: &str) -> anyhow::Result<ByteOp> {
        Ok(match s.trim() {
            "<" => ByteOp::Less,
            ">" => ByteOp::Greater,
            "=" | "==" => ByteOp::Equal,
            "!=" | "!" => ByteOp::NotEqual,
            "<=" => ByteOp::LessEqual,
            ">=" => ByteOp::GreaterEqual,
            "&" => ByteOp::And,
            "^" => ByteOp::Or,
            other => anyhow::bail!("unknown byte_test operator {:?}", other),
        })
    }

    fn eval(self, read: u64, value: u64) -> bool {
        match self {
            ByteOp::Less => read < value,
            ByteOp::Greater => read > value,
            ByteOp::Equal => read == value,
            ByteOp::NotEqual => read != value,
            ByteOp::LessEqual => read <= value,
            ByteOp::GreaterEqual => read >= value,
            ByteOp::And => read & value == value,
            ByteOp::Or => read & value != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endian {
    Big,
    Little,
}

/// How a number is encoded in the buffer.
///
/// Binary is the common case. `string` exists because a great many
/// protocols carry their lengths as ASCII digits — HTTP's
/// `Content-Length`, SIP, and most line-oriented protocols — and a rule
/// that wants to compare one has no other way to reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NumberFormat {
    Binary(Endian),
    /// ASCII digits in the given radix.
    Text(u32),
}

impl NumberFormat {
    /// Reads a number at `at`, returning it and the offset just past it.
    ///
    /// Text mode consumes as many digits as are available up to `bytes`,
    /// which is what makes it usable against a field whose width is not
    /// known in advance.
    fn read(self, data: &[u8], at: usize, bytes: usize) -> Option<(u64, usize)> {
        match self {
            NumberFormat::Binary(endian) => {
                if bytes == 0 || bytes > 8 || at.checked_add(bytes)? > data.len() {
                    return None;
                }
                let slice = &data[at..at + bytes];
                let mut v: u64 = 0;
                match endian {
                    Endian::Big => {
                        for &b in slice {
                            v = (v << 8) | b as u64;
                        }
                    }
                    Endian::Little => {
                        for &b in slice.iter().rev() {
                            v = (v << 8) | b as u64;
                        }
                    }
                }
                Some((v, at + bytes))
            }
            NumberFormat::Text(radix) => {
                if at >= data.len() {
                    return None;
                }
                let end = (at + bytes).min(data.len());
                let mut v: u64 = 0;
                let mut used = at;
                for &b in &data[at..end] {
                    let Some(d) = (b as char).to_digit(radix) else { break };
                    v = v.checked_mul(radix as u64)?.checked_add(d as u64)?;
                    used += 1;
                }
                (used > at).then_some((v, used))
            }
        }
    }
}

/// How many named values a rule may extract.
pub const MAX_VARS: usize = 8;

/// The values a rule's `byte_extract` and `byte_math` terms have produced
/// so far in one evaluation. `None` is a variable nothing has set.
type Vars = [Option<i64>; MAX_VARS];

/// The names a rule has defined, in order. A name is its index.
#[derive(Default)]
struct VarTable {
    names: Vec<String>,
}

impl VarTable {
    fn define(&mut self, name: &str) -> anyhow::Result<u8> {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "a variable needs a name");
        if let Some(i) = self.names.iter().position(|n| n == name) {
            return Ok(i as u8);
        }
        anyhow::ensure!(self.names.len() < MAX_VARS, "a rule may name at most {} variables", MAX_VARS);
        self.names.push(name.to_string());
        Ok((self.names.len() - 1) as u8)
    }

    fn lookup(&self, name: &str) -> anyhow::Result<u8> {
        let name = name.trim();
        self.names.iter().position(|n| n == name).map(|i| i as u8).ok_or_else(|| anyhow::anyhow!("{:?} is neither a number nor a variable this rule has extracted", name))
    }

    /// A literal number, or the variable that will supply one.
    fn number_or_var(&self, raw: &str) -> anyhow::Result<(i64, Option<u8>)> {
        match parse_integer(raw) {
            Ok(v) => Ok((v as i64, None)),
            Err(_) => match raw.trim().parse::<i64>() {
                Ok(v) => Ok((v, None)),
                Err(_) => Ok((0, Some(self.lookup(raw)?))),
            },
        }
    }
}

/// The value of a term's argument: its literal, or the variable it names.
#[inline]
fn resolve(literal: i64, var: Option<u8>, vars: &Vars) -> Option<i64> {
    match var {
        Some(v) => vars[v as usize],
        None => Some(literal),
    }
}

/// `byte_extract`: read a number and remember it under a name, for the
/// terms after it to use as a length, an offset or a limit. Rules that
/// parse a length field and then check something against it are written
/// this way.
#[derive(Clone, Debug)]
pub struct ByteExtract {
    bytes: usize,
    offset: i64,
    relative: bool,
    format: NumberFormat,
    multiplier: i64,
    var: u8,
}

impl ByteExtract {
    fn eval(&self, data: &[u8], cursor: usize, vars: &mut Vars) -> bool {
        let base = if self.relative { cursor } else { 0 };
        let Some(at) = shift(base, self.offset) else { return false };
        let Some((v, _)) = self.format.read(data, at, self.bytes) else { return false };
        let Some(v) = i64::try_from(v).ok().and_then(|v| v.checked_mul(self.multiplier)) else { return false };
        vars[self.var as usize] = Some(v);
        true
    }
}

/// `byte_math`: read a number, do arithmetic on it, and remember the result.
#[derive(Clone, Debug)]
pub struct ByteMath {
    bytes: usize,
    offset: i64,
    relative: bool,
    format: NumberFormat,
    oper: char,
    rvalue: i64,
    rvalue_var: Option<u8>,
    var: u8,
}

impl ByteMath {
    fn eval(&self, data: &[u8], cursor: usize, vars: &mut Vars) -> bool {
        let base = if self.relative { cursor } else { 0 };
        let Some(at) = shift(base, self.offset) else { return false };
        let Some((v, _)) = self.format.read(data, at, self.bytes) else { return false };
        let (Ok(lhs), Some(rhs)) = (i64::try_from(v), resolve(self.rvalue, self.rvalue_var, vars)) else { return false };
        let out = match self.oper {
            '+' => lhs.checked_add(rhs),
            '-' => lhs.checked_sub(rhs),
            '*' => lhs.checked_mul(rhs),
            '/' => lhs.checked_div(rhs),
            '<' => u32::try_from(rhs).ok().and_then(|n| lhs.checked_shl(n)),
            '>' => u32::try_from(rhs).ok().and_then(|n| lhs.checked_shr(n)),
            _ => None,
        };
        match out {
            Some(r) => {
                vars[self.var as usize] = Some(r);
                true
            }
            None => false,
        }
    }
}

/// `base64_decode`: from here on, the rule's terms read the decoded bytes.
///
/// The bytes are taken from `offset` (from the cursor if `relative`) for
/// `bytes` bytes, or to the end of the buffer if that is zero. Characters
/// outside the base64 alphabet, whitespace included, are skipped, and
/// decoding stops at padding: the tolerant reading, since these rules are
/// about encoded content that is rarely well-formed.
#[derive(Clone, Debug)]
pub struct Base64Decode {
    bytes: usize,
    offset: i64,
    relative: bool,
}

impl Base64Decode {
    fn eval(&self, data: &[u8], cursor: usize) -> Option<Vec<u8>> {
        let base = if self.relative { cursor } else { 0 };
        let start = shift(base, self.offset)?.min(data.len());
        let end = if self.bytes == 0 { data.len() } else { start.saturating_add(self.bytes).min(data.len()) };
        Some(base64_decode(&data[start..end]))
    }
}

fn base64_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in input {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// `byte_test`: read a number out of the buffer and compare it.
#[derive(Clone, Debug)]
pub struct ByteTest {
    bytes: usize,
    op: ByteOp,
    value: u64,
    /// The value comes from a variable rather than the rule text.
    value_var: Option<u8>,
    offset: i64,
    offset_var: Option<u8>,
    relative: bool,
    format: NumberFormat,
    negate: bool,
}

/// `byte_jump`: read a number and move the cursor by it.
///
/// This is what makes length-prefixed binary protocols expressible at
/// all. Without it a rule can say "these bytes appear somewhere"; with
/// it a rule can say "follow this length field and check what it points
/// at", which is the difference between describing a payload and parsing
/// one.
#[derive(Clone, Debug)]
pub struct ByteJump {
    bytes: usize,
    offset: i64,
    relative: bool,
    format: NumberFormat,
    multiplier: u64,
    /// Round the destination up to the next 4-byte boundary, as several
    /// record formats require.
    align: bool,
    post_offset: i64,
    /// Jump from the start of the buffer rather than from the value's
    /// own end.
    from_beginning: bool,
}

/// Applies a signed delta to an offset, refusing to wrap.
fn shift(base: usize, delta: i64) -> Option<usize> {
    if delta >= 0 {
        base.checked_add(delta as usize)
    } else {
        base.checked_sub(delta.unsigned_abs() as usize)
    }
}

impl ByteTest {
    fn eval(&self, data: &[u8], cursor: usize, vars: &Vars) -> bool {
        let base = if self.relative { cursor } else { 0 };
        let (Some(offset), Some(value)) = (resolve(self.offset, self.offset_var, vars), resolve(self.value as i64, self.value_var, vars)) else { return self.negate };
        let Some(at) = shift(base, offset) else { return self.negate };
        let hit = match self.format.read(data, at, self.bytes) {
            Some((v, _)) => self.op.eval(v, value as u64),
            // A test that cannot read its bytes has not passed. Treating
            // a truncated buffer as a match would make every rule using
            // byte_test fire on runt packets.
            None => false,
        };
        hit != self.negate
    }
}

impl ByteJump {
    /// The new cursor, or `None` if the jump cannot be resolved.
    fn eval(&self, data: &[u8], cursor: usize) -> Option<usize> {
        let base = if self.relative { cursor } else { 0 };
        let at = shift(base, self.offset)?;
        let (value, after) = self.format.read(data, at, self.bytes)?;
        let jump = value.checked_mul(self.multiplier)?;
        let from = if self.from_beginning { 0 } else { after };
        let mut target = from.checked_add(usize::try_from(jump).ok()?)?;
        if self.align {
            target = target.div_ceil(4) * 4;
        }
        let target = shift(target, self.post_offset)?;
        // A jump past the end is not a match; clamping would silently
        // turn "points somewhere real" into "points at the end", and
        // every subsequent relative term would then match nothing for
        // the wrong reason.
        (target <= data.len()).then_some(target)
    }
}

// =======================================================================
// Terms
// =======================================================================

/// One step in a rule's ordered evaluation.
///
/// Order matters because `distance`, `within` and `relative` are all
/// defined against "the previous match", so a rule is a small program
/// over a cursor rather than a set of independent predicates.
/// A change made to a buffer before a rule's terms look at it.
///
/// Rules are written against a *view* of a buffer, not the buffer: the
/// same request URI is `%2e%2e%2f` to one rule and `../` to another, and a
/// rule that wants the second has to say so. Each variant is what
/// Suricata's transform of the same name does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transform {
    /// `%HH` to the byte it names. The normalisation Suricata applies to
    /// a URI before it is matched; `+` is left alone, since in a path it
    /// is a plus.
    PercentDecode,
    /// `%HH` to its byte and `+` to a space, as a form decoder does.
    UrlDecode,
    /// Header *names* in lower case, values untouched.
    HeaderLowercase,
    /// Every space, tab and line break removed.
    StripWhitespace,
    /// Every run of whitespace reduced to one space.
    CompressWhitespace,
    /// The buffer's raw digest, so a rule can name content by its hash.
    Sha1,
    Md5,
    Sha256,
}

impl Transform {
    pub fn parse(name: &str) -> anyhow::Result<Transform> {
        Ok(match name.trim().to_ascii_lowercase().as_str() {
            "percent_decode" => Transform::PercentDecode,
            "url_decode" => Transform::UrlDecode,
            "header_lowercase" => Transform::HeaderLowercase,
            "strip_whitespace" => Transform::StripWhitespace,
            "compress_whitespace" => Transform::CompressWhitespace,
            "sha1" => Transform::Sha1,
            "md5" => Transform::Md5,
            "sha256" => Transform::Sha256,
            other => anyhow::bail!("unknown transform {:?}", other),
        })
    }

    /// The transformed bytes, or `None` when the transform changes
    /// nothing, so that the common case (a URI with no escapes in it)
    /// copies nothing.
    pub fn apply(self, data: &[u8]) -> Option<Vec<u8>> {
        fn hex(b: u8) -> Option<u8> {
            (b as char).to_digit(16).map(|d| d as u8)
        }
        let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c);
        match self {
            Transform::PercentDecode | Transform::UrlDecode => {
                let plus = self == Transform::UrlDecode;
                if !data.iter().any(|&b| b == b'%' || (plus && b == b'+')) {
                    return None;
                }
                let mut out = Vec::with_capacity(data.len());
                let mut i = 0;
                while i < data.len() {
                    match data[i] {
                        b'%' if i + 2 < data.len() && hex(data[i + 1]).is_some() && hex(data[i + 2]).is_some() => {
                            out.push(hex(data[i + 1]).unwrap_or(0) << 4 | hex(data[i + 2]).unwrap_or(0));
                            i += 3;
                        }
                        b'+' if plus => {
                            out.push(b' ');
                            i += 1;
                        }
                        b => {
                            out.push(b);
                            i += 1;
                        }
                    }
                }
                (out != data).then_some(out)
            }
            Transform::HeaderLowercase => {
                let mut out = data.to_vec();
                let mut start = 0;
                while start < out.len() {
                    let end = out[start..].iter().position(|&b| b == b'\n').map_or(out.len(), |n| start + n);
                    if let Some(colon) = out[start..end].iter().position(|&b| b == b':') {
                        out[start..start + colon].make_ascii_lowercase();
                    }
                    start = end + 1;
                }
                (out != data).then_some(out)
            }
            Transform::StripWhitespace => data.iter().any(|&b| is_ws(b)).then(|| data.iter().copied().filter(|&b| !is_ws(b)).collect()),
            Transform::Sha1 => Some(crate::files::sha1(data).to_vec()),
            Transform::Md5 => Some(crate::files::md5_raw(data)),
            Transform::Sha256 => Some(crate::files::sha256_raw(data)),
            Transform::CompressWhitespace => {
                let mut out = Vec::with_capacity(data.len());
                for &b in data {
                    if is_ws(b) {
                        if out.last() != Some(&b' ') {
                            out.push(b' ');
                        }
                    } else {
                        out.push(b);
                    }
                }
                (out != data).then_some(out)
            }
        }
    }
}

/// Applies each transform in turn.
fn apply_transforms<'a>(transforms: &[Transform], data: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
    let mut cur = std::borrow::Cow::Borrowed(data);
    for t in transforms {
        if let Some(next) = t.apply(&cur) {
            cur = std::borrow::Cow::Owned(next);
        }
    }
    cur
}

/// Separates the leading `transform:` terms of a part from the rest.
fn split_transforms(terms: Vec<Term>) -> (Vec<Transform>, Vec<Term>) {
    let mut transforms = Vec::new();
    let mut rest = Vec::with_capacity(terms.len());
    for t in terms {
        match t {
            Term::Transform(x) => transforms.push(x),
            other => rest.push(other),
        }
    }
    (transforms, rest)
}

#[derive(Clone, Debug)]
enum Term {
    /// Not a test: a change to the buffer that the tests after it see.
    Transform(Transform),
    /// Remembers a number under a name for later terms.
    Extract(ByteExtract),
    Math(ByteMath),
    /// From here on the terms read the base64-decoded bytes.
    Base64(Base64Decode),
    Content(ContentMatch),
    Test(ByteTest),
    Jump(ByteJump),
    /// `bsize`: the length of the buffer the term sits in.
    Len(LenTest),
    DataAt(DataAt),
}

// =======================================================================
// Flowbits
// =======================================================================

/// What a rule does to per-connection state.
///
/// Flowbits are how a ruleset expresses "this only matters if that
/// already happened" — a response is interesting because of the request
/// that preceded it, an exploit attempt because of the version banner
/// seen earlier in the same connection. No single packet carries that;
/// it lives across the flow, which is exactly where ARGUS already keeps
/// reassembly state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowbitOp {
    Set,
    Unset,
    Toggle,
    IsSet,
    IsNotSet,
}

#[derive(Clone, Copy, Debug)]
pub struct Flowbit {
    pub op: FlowbitOp,
    /// Index into the rule set's name registry, resolved at load time so
    /// matching never touches a string.
    pub bit: u32,
}

/// Per-connection flowbit storage.
///
/// Lazily allocated: the overwhelming majority of connections never set
/// a bit, and a fixed bitset per flow would cost every one of them the
/// size of the whole registry. A flow that sets nothing holds `None`.
#[derive(Default, Clone, Debug)]
pub struct FlowBits {
    words: Option<Box<[u64]>>,
    /// `(composite id, parts matched so far)`, sorted by id; see
    /// [`Composite`]. Most flows hold none and a few hold a handful.
    partials: Vec<(u32, u16)>,
    /// Progress indexed by composite id, used once a flow has more
    /// partials than a sorted list stays cheap for.
    ///
    /// A request's first part (`http.method: GET`) belongs to thousands of
    /// rules, so a single ordinary request can open thousands of records.
    /// As a sorted list that is a quadratic amount of shifting per flow;
    /// as a table it is one byte each and a store.
    dense: Option<Box<[u16]>>,
    /// Payload bytes seen so far, to the server and to the client, for
    /// `stream_size`. Kept with the flow's other rule-visible state so a
    /// rule can read it without the matcher knowing about flows.
    stream: [u64; 2],
}

/// Past this many records a flow switches to the table.
const DENSE_AFTER: usize = 64;

impl FlowBits {
    pub fn is_set(&self, bit: u32) -> bool {
        let (w, b) = (bit as usize / 64, bit as usize % 64);
        self.words.as_ref().and_then(|ws| ws.get(w)).is_some_and(|word| word & (1 << b) != 0)
    }

    pub fn set(&mut self, bit: u32, on: bool, registry_len: usize) {
        if self.words.is_none() {
            if !on {
                return; // clearing a bit in an empty set is already true
            }
            self.words = Some(vec![0u64; registry_len.div_ceil(64).max(1)].into_boxed_slice());
        }
        let Some(ws) = self.words.as_mut() else { return };
        let (w, b) = (bit as usize / 64, bit as usize % 64);
        let Some(word) = ws.get_mut(w) else { return };
        if on {
            *word |= 1 << b;
        } else {
            *word &= !(1 << b);
        }
    }

    pub fn toggle(&mut self, bit: u32, registry_len: usize) {
        let now = self.is_set(bit);
        self.set(bit, !now, registry_len);
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_none() && self.partials.is_empty() && self.dense.is_none() && self.stream == [0, 0]
    }

    /// Counts payload bytes travelling to the server (`true`) or the client.
    pub fn add_stream_bytes(&mut self, to_server: bool, n: u64) {
        self.stream[usize::from(!to_server)] += n;
    }

    /// Payload bytes seen so far: `(to server, to client)`.
    pub fn stream_bytes(&self) -> (u64, u64) {
        (self.stream[0], self.stream[1])
    }

    /// Records that part `idx` of composite `id` matched. Returns true
    /// exactly once: when this completes the set of `total` parts.
    pub fn mark_part(&mut self, id: u32, idx: u8, total: u8, composites: usize) -> bool {
        let full = (1u16 << total) - 1;
        let mask: &mut u16 = if let Some(table) = self.dense.as_mut() {
            &mut table[id as usize]
        } else if self.partials.len() >= DENSE_AFTER && self.partials.binary_search_by_key(&id, |(c, _)| *c).is_err() {
            let mut table = vec![0u16; composites.max(id as usize + 1)].into_boxed_slice();
            for (c, m) in self.partials.drain(..) {
                table[c as usize] = m;
            }
            &mut self.dense.insert(table)[id as usize]
        } else {
            let slot = match self.partials.binary_search_by_key(&id, |(c, _)| *c) {
                Ok(i) => i,
                Err(i) => {
                    self.partials.insert(i, (id, 0));
                    i
                }
            };
            &mut self.partials[slot].1
        };
        if *mask & PART_DONE != 0 {
            return false;
        }
        *mask |= 1u16 << idx;
        if *mask & full == full {
            *mask |= PART_DONE;
            return true;
        }
        false
    }
}

// =======================================================================
// Rules
// =======================================================================

#[derive(Clone, Debug)]
pub struct Rule {
    pub sid: u32,
    pub name: String,
    pub severity: Severity,
    pub buffer: Buffer,
    pub direction: Direction,
    pub header: HeaderMatch,
    terms: Vec<Term>,
    /// Applied to the buffer before `terms` are tested.
    pub transforms: Vec<Transform>,
    /// Conditions and effects on per-connection state.
    pub flowbits: Vec<Flowbit>,
    /// `flowbits:noalert` — the rule exists to set state, not to report.
    /// Common in ET, where one rule marks a protocol and a dozen others
    /// depend on the mark.
    pub noalert: bool,
    /// Set when this rule is one buffer's share of a multi-buffer rule:
    /// the composite it belongs to, and which of its parts this is.
    pub part: Option<(u32, u8)>,
    /// `threshold` or `detection_filter`: how often a match is reported.
    pub threshold: Option<crate::threshold::Threshold>,
    /// `xbits`/`hostbits`: state shared between connections.
    pub xbits: Vec<crate::threshold::XbitOp>,
}

/// A rule that inspects more than one buffer, e.g. a request URI *and* a
/// response status.
///
/// ARGUS matches one buffer at a time, as it is parsed, so a rule spanning
/// buffers is lowered into one ordinary rule per buffer (which keeps the
/// prefilter and the cheapest-first ordering) plus this record. Each part
/// that matches marks its bit in the flow's progress record; the alert
/// fires when the last one lands, once per flow.
///
/// This is deliberately not built on flowbits. A real ruleset has ~4,600
/// such rules, and a flowbit per part would size every flow's bitset to
/// thousands of hidden bits. Progress is instead a sparse list of
/// `(composite, mask)` pairs, which for a typical flow is empty.
#[derive(Clone, Debug)]
pub struct Composite {
    pub id: u32,
    pub sid: u32,
    pub name: String,
    pub severity: Severity,
    pub parts: u8,
    pub threshold: Option<crate::threshold::Threshold>,
    pub xbits: Vec<crate::threshold::XbitOp>,
    /// `set`/`unset`/`toggle` effects, applied on completion.
    pub effects: Vec<Flowbit>,
    pub noalert: bool,
}

/// At most this many buffers per rule: progress is sixteen bits, and the
/// top bit records that the rule has already fired on this flow.
pub const MAX_PARTS: usize = 15;
const PART_DONE: u16 = 0x8000;

fn apply_effects(effects: &[Flowbit], bits: &mut FlowBits, registry_len: usize) {
    for f in effects {
        match f.op {
            FlowbitOp::Set => bits.set(f.bit, true, registry_len),
            FlowbitOp::Unset => bits.set(f.bit, false, registry_len),
            FlowbitOp::Toggle => bits.toggle(f.bit, registry_len),
            FlowbitOp::IsSet | FlowbitOp::IsNotSet => {}
        }
    }
}

impl Rule {
    /// Walks the terms in order against a cursor.
    ///
    /// The cursor starts at zero and advances to the end of each
    /// positive content match, so a following relative term measures
    /// from there. A *negated* term deliberately does not move it: "X is
    /// not here" has no end position to measure from, and pretending
    /// otherwise would make the next term's window depend on where
    /// something absent would have been.
    pub fn content_matches(&self, data: &[u8]) -> bool {
        let mut cursor = 0usize;
        let mut vars: Vars = [None; MAX_VARS];
        // What the terms read. It is the buffer until a `base64_decode`,
        // and the decoded bytes after it.
        let mut view: std::borrow::Cow<[u8]> = std::borrow::Cow::Borrowed(data);
        for term in &self.terms {
            let data: &[u8] = &view;
            match term {
                Term::Content(c) => match c.find(data, cursor, &vars) {
                    Some((_, end)) => {
                        if c.negate {
                            return false;
                        }
                        cursor = end;
                    }
                    None => {
                        if !c.negate {
                            return false;
                        }
                    }
                },
                Term::Test(t) => {
                    if !t.eval(data, cursor, &vars) {
                        return false;
                    }
                }
                Term::Jump(j) => match j.eval(data, cursor) {
                    Some(next) => cursor = next,
                    None => return false,
                },
                Term::Len(t) => {
                    if !t.holds(data.len()) {
                        return false;
                    }
                }
                Term::DataAt(d) => {
                    if !d.holds(data.len(), cursor, &vars) {
                        return false;
                    }
                }
                Term::Extract(e) => {
                    if !e.eval(data, cursor, &mut vars) {
                        return false;
                    }
                }
                Term::Math(m) => {
                    if !m.eval(data, cursor, &mut vars) {
                        return false;
                    }
                }
                Term::Base64(b) => match b.eval(data, cursor) {
                    Some(decoded) => {
                        view = std::borrow::Cow::Owned(decoded);
                        cursor = 0;
                    }
                    None => return false,
                },
                // Applied before evaluation, by the rule set.
                Term::Transform(_) => {}
            }
        }
        true
    }

    /// `stream_size`, which needs the connection and so cannot be part of
    /// the header match.
    pub fn stream_holds(&self, bits: Option<&FlowBits>) -> bool {
        self.header.extra.as_ref().and_then(|x| x.stream).is_none_or(|t| t.holds(bits))
    }

    /// Whether this rule's `isset`/`isnotset` conditions hold.
    ///
    /// Separate from `content_matches` because it is cheap and can fail
    /// the rule before any buffer is searched.
    pub fn flowbits_hold(&self, bits: Option<&FlowBits>) -> bool {
        self.flowbits.iter().all(|f| match f.op {
            FlowbitOp::IsSet => bits.is_some_and(|b| b.is_set(f.bit)),
            // With no flow state at all — a UDP datagram, say — nothing
            // is set, so `isnotset` holds. That is the honest reading:
            // the condition asks whether a bit is absent, and it is.
            FlowbitOp::IsNotSet => !bits.is_some_and(|b| b.is_set(f.bit)),
            _ => true,
        })
    }

    /// Applies this rule's `set`/`unset`/`toggle` effects.
    pub fn apply_flowbits(&self, bits: &mut FlowBits, registry_len: usize) {
        apply_effects(&self.flowbits, bits, registry_len);
    }

    pub fn sets_flowbits(&self) -> bool {
        self.flowbits.iter().any(|f| matches!(f.op, FlowbitOp::Set | FlowbitOp::Unset | FlowbitOp::Toggle))
    }

    /// Contents that read the buffer as it is, which is all a prefilter
    /// can see: anything after a `base64_decode` reads decoded bytes that
    /// the prefilter never has.
    fn prefilter_contents(&self) -> impl Iterator<Item = &ContentMatch> {
        self.terms.iter().take_while(|t| !matches!(t, Term::Base64(_))).filter_map(|t| match t {
            Term::Content(c) => Some(c),
            _ => None,
        })
    }

}

/// What fired, with enough identity to be acted on downstream.
///
/// v1 had only a name; a rule id and a severity are what let a SIEM
/// correlate, a dashboard rank, and an operator tune one noisy rule down
/// without deleting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleHit {
    pub name: String,
    pub sid: u32,
    pub severity: Severity,
}

// =======================================================================
// Parsing
// =======================================================================

/// True if a line should be parsed as v2 rather than the v1 pipe format.
pub fn is_v2_line(line: &str) -> bool {
    line.trim_start().starts_with("rule ") || line.trim_start().starts_with("rule\t")
}

/// Splits an option list on `;`, respecting double-quoted values so a
/// pattern may contain semicolons.
fn split_options(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in body.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                escaped = true;
                cur.push(ch);
            }
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ';' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Strips surrounding quotes and resolves the escapes a **content**
/// pattern may use: `\n`, `\r`, `\t`, `\"`, `\\`,
/// `\|`, and `|hex|` blocks.
///
/// Deliberately *not* used for `pcre` patterns. Running this over a
/// regex first both mangles valid patterns and rejects ordinary ones —
/// `\.` is not a content escape, so an otherwise fine rule failed to
/// load with `unknown escape`. A regex pattern has exactly one correct
/// interpreter of its backslashes, and it isn't this function.
///
/// `|AA BB|` hex blocks are supported because a signature for binary
/// traffic (and most industrial-protocol signatures are binary) can't be
/// written as text at all.
fn unquote(value: &str) -> anyhow::Result<Vec<u8>> {
    let v = value.trim();
    let inner = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') { &v[1..v.len() - 1] } else { v };

    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('"') => out.push(b'"'),
                Some('\\') => out.push(b'\\'),
                Some('|') => out.push(b'|'),
                Some(other) => anyhow::bail!("unknown escape \\{}", other),
                None => anyhow::bail!("pattern ends with a lone backslash"),
            },
            '|' => {
                // A hex block, e.g. |FE 53 4D 42|.
                let mut hex = String::new();
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '|' {
                        closed = true;
                        break;
                    }
                    hex.push(c);
                }
                if !closed {
                    anyhow::bail!("unterminated |hex| block");
                }
                // Each whitespace-separated token is a run of hex pairs,
                // not necessarily a single byte: `|FE 53 4D 42|` and
                // `|FE534D42|` are both valid and mean the same thing.
                // Assuming one byte per token rejected the second form,
                // which a real ruleset uses freely.
                for token in hex.split_whitespace() {
                    if token.len() % 2 != 0 {
                        anyhow::bail!("hex run {:?} has an odd number of digits", token);
                    }
                    for pair in token.as_bytes().chunks(2) {
                        let pair = std::str::from_utf8(pair).unwrap_or("");
                        out.push(u8::from_str_radix(pair, 16).map_err(|_| anyhow::anyhow!("invalid hex byte {:?}", pair))?);
                    }
                }
            }
            other => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    Ok(out)
}

fn parse_severity(v: &str) -> anyhow::Result<Severity> {
    match v.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        other => anyhow::bail!("unknown severity {:?} (expected low/medium/high)", other),
    }
}

fn parse_proto(v: &str) -> anyhow::Result<u8> {
    match v.trim().to_ascii_lowercase().as_str() {
        "tcp" => Ok(PROTO_TCP),
        "udp" => Ok(PROTO_UDP),
        "icmp" => Ok(PROTO_ICMP),
        "icmpv6" | "icmp6" => Ok(PROTO_ICMPV6),
        other => anyhow::bail!("unknown protocol {:?} (expected tcp/udp/icmp/icmpv6)", other),
    }
}

/// Interns flowbit names so matching compares integers, not strings.
///
/// Shared across a whole rule file, because a flowbit is only useful if
/// the rule that sets it and the rule that tests it agree on which bit
/// they mean.
#[derive(Default, Debug)]
pub struct FlowbitRegistry {
    composites: u32,
    names: Vec<String>,
    index: FxHashMap<String, u32>,
}

impl FlowbitRegistry {
    pub fn intern(&mut self, name: &str) -> u32 {
        if let Some(&i) = self.index.get(name) {
            return i;
        }
        let i = self.names.len() as u32;
        self.names.push(name.to_string());
        self.index.insert(name.to_string(), i);
        i
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// The id of a name some rule uses, if any does.
    pub fn lookup(&self, name: &str) -> Option<u32> {
        self.index.get(name).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Hands out dense composite ids, shared across a whole rule file for
    /// the same reason flowbit names are.
    pub fn next_composite(&mut self) -> u32 {
        self.composites += 1;
        self.composites - 1
    }

    pub fn name(&self, bit: u32) -> Option<&str> {
        self.names.get(bit as usize).map(String::as_str)
    }
}

/// What one rule line turned into.
pub enum Parsed {
    Single(Rule),
    /// A rule spanning several buffers: the per-buffer parts, and the
    /// record that says when they have all matched.
    Composite { composite: Composite, parts: Vec<Rule> },
}

/// Parses one single-buffer v2 rule line without flowbit support, for
/// callers that have no registry to intern into.
pub fn parse_rule(line: &str) -> anyhow::Result<Rule> {
    let mut reg = FlowbitRegistry::default();
    parse_rule_with(line, &mut reg)
}

/// Parses one single-buffer v2 rule line. A rule naming several buffers
/// is an error here; the loader uses [`parse_any`].
pub fn parse_rule_with(line: &str, flowbits: &mut FlowbitRegistry) -> anyhow::Result<Rule> {
    match parse_any(line, flowbits)? {
        Parsed::Single(r) => Ok(r),
        Parsed::Composite { .. } => anyhow::bail!("rule names several buffers; load it through parse_any"),
    }
}

/// Parses one v2 rule line, whatever it inspects.
pub fn parse_any(line: &str, flowbits: &mut FlowbitRegistry) -> anyhow::Result<Parsed> {
    let body = line.trim().strip_prefix("rule").ok_or_else(|| anyhow::anyhow!("not a v2 rule line"))?;

    let mut sid = None;
    let mut name = None;
    let mut severity = Severity::High;
    let mut buffer = Buffer::Payload;
    let mut direction = Direction::Any;
    let mut header = HeaderMatch::default();
    let mut terms: Vec<Term> = Vec::new();
    let mut finished: Vec<(Buffer, Vec<Term>)> = Vec::new();
    let mut bits: Vec<Flowbit> = Vec::new();
    let mut noalert = false;
    let mut threshold = None;
    let mut xbits: Vec<crate::threshold::XbitOp> = Vec::new();
    let mut vars = VarTable::default();

    // `content` and friends push; the modifiers that follow one need to
    // reach back to it.
    macro_rules! last_content {
        ($what:literal) => {
            terms
                .iter_mut()
                .rev()
                .find_map(|t| match t {
                    Term::Content(c) => Some(c),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!(concat!("'", $what, "' must follow a content")))?
        };
    }

    for opt in split_options(body) {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        // Bare (valueless) modifiers first.
        if opt.eq_ignore_ascii_case("relative") {
            let last = last_content!("relative");
            anyhow::ensure!(!matches!(last.pattern, Pattern::Literal(_) | Pattern::NoCase(_)), "'relative' resumes a regex where the previous term ended; a literal takes distance");
            last.resume = true;
            last.distance = Some(0);
            continue;
        }
        if opt.eq_ignore_ascii_case("noalert") {
            noalert = true;
            continue;
        }
        if opt.eq_ignore_ascii_case("nocase") {
            let last = last_content!("nocase");
            // Implemented by recompiling the literal as a case-insensitive
            // regex rather than by lowercasing the haystack on every
            // check: the pattern is transformed once at load time, and
            // the hot path stays a single match call.
            //
            // Every byte becomes an explicit `\xNN` escape rather than
            // going through `String::from_utf8` first. The UTF-8 route
            // rejected any content with a non-UTF-8 byte in it, which
            // sounds reasonable until you try to load a real ruleset:
            // `nocase` on binary content is both legal and common
            // (ASCII letters embedded in a binary protocol still have
            // case), and ET Open's very first such rule refused to load.
            // `(?i-u)` gives ASCII case folding without requiring the
            // haystack to be valid UTF-8 either.
            if let Pattern::Literal(bytes) = &last.pattern {
                last.pattern = Pattern::NoCase(bytes.to_ascii_lowercase());
            }
            continue;
        }

        let (key, value) = opt.split_once(':').ok_or_else(|| anyhow::anyhow!("option {:?} is missing a ':value'", opt))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match key.as_str() {
            "sid" => sid = Some(value.parse::<u32>()?),
            "name" | "msg" => name = Some(String::from_utf8_lossy(&unquote(value)?).into_owned()),
            "severity" | "priority" => severity = parse_severity(value)?,
            "rev" => {
                value.parse::<u32>()?;
            }
            "buffer" => {
                let next = Buffer::parse_name(&unquote_plain(value))?;
                // A second `buffer:` after content starts a new part, as
                // a sticky buffer does in Suricata. Modifiers such as
                // `distance` attach to the content within their own part.
                if !terms.is_empty() {
                    finished.push((buffer, std::mem::take(&mut terms)));
                }
                buffer = next;
            }
            "direction" | "flow" => direction = Direction::parse_name(&unquote_plain(value))?,
            "proto" => header.proto = Some(parse_proto(value)?),
            "src_ip" | "src" => header.src_ip = Some(IpMatch::parse(value)?),
            "dst_ip" | "dst" => header.dst_ip = Some(IpMatch::parse(value)?),
            "src_port" | "sport" => header.src_port = Some(PortMatch::parse(value)?),
            "dst_port" | "dport" => header.dst_port = Some(PortMatch::parse(value)?),
            "content" | "!content" => terms.push(Term::Content(ContentMatch {
                pattern: Pattern::Literal(unquote(value)?),
                negate: key == "!content",
                offset: 0,
                depth: None,
                distance: None,
                within: None,
                resume: false,
                vars: [None; 4],
            })),
            "pcre" | "regex" | "!pcre" | "!regex" => {
                // Quotes stripped, but *no* escape processing: a regex
                // has its own escape semantics, and running the content
                // unescaper over it first would both mangle valid
                // patterns and reject ordinary ones (`\.` is not a
                // content escape, so it was an error). The regex
                // compiler is the right and only interpreter of a regex
                // pattern's backslashes.
                let text = unquote_plain(value);
                terms.push(Term::Content(ContentMatch {
                    pattern: Pattern::Regex(regex::bytes::Regex::new(&text)?),
                    negate: key.starts_with('!'),
                    offset: 0,
                    depth: None,
                    distance: None,
                    within: None,
                    resume: false,
                    vars: [None; 4],
                }));
            }
            "pcre_bt" | "!pcre_bt" => {
                // The same, for a pattern the linear engine cannot express.
                // Named separately so a rule author chooses the slower,
                // bounded engine knowingly; `relative` resumes it too.
                let text = unquote_plain(value);
                terms.push(Term::Content(ContentMatch {
                    pattern: Pattern::Backtrack(Backtracking::new(&text)?),
                    negate: key.starts_with('!'),
                    offset: 0,
                    depth: None,
                    distance: None,
                    within: None,
                    resume: false,
                    vars: [None; 4],
                }));
            }
            // Each of these takes a number, or the name of a variable an
            // earlier `byte_extract` or `byte_math` defined.
            "offset" => match value.parse::<usize>() {
                Ok(n) => last_content!("offset").offset = n,
                Err(_) => last_content!("offset").vars[0] = Some(vars.lookup(value)?),
            },
            "depth" => match value.parse::<usize>() {
                Ok(n) => last_content!("depth").depth = Some(n),
                Err(_) => last_content!("depth").vars[1] = Some(vars.lookup(value)?),
            },
            "distance" => match value.parse::<i64>() {
                Ok(n) => last_content!("distance").distance = Some(n),
                Err(_) => last_content!("distance").vars[2] = Some(vars.lookup(value)?),
            },
            "within" => match value.parse::<usize>() {
                Ok(n) => last_content!("within").within = Some(n),
                Err(_) => last_content!("within").vars[3] = Some(vars.lookup(value)?),
            },
            "byte_extract" => terms.push(Term::Extract(parse_byte_extract(value, &mut vars)?)),
            "byte_math" => terms.push(Term::Math(parse_byte_math(value, &mut vars)?)),
            "base64_decode" => terms.push(Term::Base64(parse_base64_decode(value)?)),

            "xbits" | "hostbits" => xbits.push(crate::threshold::XbitOp::parse(value)?),
            "threshold" => threshold = Some(crate::threshold::Threshold::parse(value)?),
            "detection_filter" => threshold = Some(crate::threshold::Threshold::parse_detection_filter(value)?),
            "dsize" => header.payload_len = Some(LenTest::parse(value)?),
            "itype" => header.extra.get_or_insert_with(Default::default).icmp_type = Some(LenTest::parse(value)?),
            "icode" => header.extra.get_or_insert_with(Default::default).icmp_code = Some(LenTest::parse(value)?),
            "window" => header.extra.get_or_insert_with(Default::default).window = Some(LenTest::parse(value)?),
            "ip_proto" => header.extra.get_or_insert_with(Default::default).ip_proto = Some(LenTest::parse(value)?),
            "flags" => header.extra.get_or_insert_with(Default::default).flags = Some(TcpFlagTest::parse(value)?),
            "stream_size" => header.extra.get_or_insert_with(Default::default).stream = Some(StreamTest::parse(value)?),
            "transform" => {
                anyhow::ensure!(terms.iter().all(|t| matches!(t, Term::Transform(_))), "a transform applies to the whole buffer, so it must come before the terms that read it");
                terms.push(Term::Transform(Transform::parse(&unquote_plain(value))?));
            }
            "bsize" => terms.push(Term::Len(LenTest::parse(value)?)),
            "isdataat" => terms.push(Term::DataAt(DataAt::parse(value, &vars)?)),
            "byte_test" => terms.push(Term::Test(parse_byte_test(value, &vars)?)),
            "byte_jump" => terms.push(Term::Jump(parse_byte_jump(value)?)),

            "flowbits" => {
                // `flowbits:noalert` has no name; every other form does.
                let mut parts = value.split(',').map(str::trim);
                let verb = parts.next().unwrap_or("").to_ascii_lowercase();
                if verb == "noalert" {
                    noalert = true;
                    continue;
                }
                let name = parts.next().ok_or_else(|| anyhow::anyhow!("flowbits:{} needs a name", verb))?;
                let op = match verb.as_str() {
                    "set" => FlowbitOp::Set,
                    "unset" => FlowbitOp::Unset,
                    "toggle" => FlowbitOp::Toggle,
                    "isset" => FlowbitOp::IsSet,
                    "isnotset" => FlowbitOp::IsNotSet,
                    other => anyhow::bail!("unknown flowbits verb {:?}", other),
                };
                bits.push(Flowbit { op, bit: flowbits.intern(name) });
            }
            other => anyhow::bail!("unknown option {:?}", other),
        }
    }

    if !terms.is_empty() && !finished.is_empty() {
        finished.push((buffer, std::mem::take(&mut terms)));
    }
    if finished.len() > 1 {
        let sid = sid.ok_or_else(|| anyhow::anyhow!("rule is missing 'sid'"))?;
        let name = name.unwrap_or_else(|| format!("sid-{}", sid));
        return lower_composite(sid, name, severity, direction, header, finished, bits, noalert, threshold, xbits, flowbits);
    }
    if let Some((b, t)) = finished.pop() {
        buffer = b;
        terms = t;
    }

    let positive_contents = terms.iter().filter(|t| matches!(t, Term::Content(c) if !c.negate)).count();
    let has_content = terms.iter().any(|t| matches!(t, Term::Content(_)));

    // A rule with no content terms would match every buffer of its type,
    // which is never what anyone means and is the kind of mistake that
    // buries an operator in alerts. Rejected at load time instead.
    //
    // The exception is a rule that only tests flowbit state: `isset` is
    // itself a strong condition, and ET uses exactly this shape to make
    // a follow-up rule conditional on an earlier one. A rule with
    // neither content nor a flowbit condition still matches everything.
    let tests_flowbits = bits.iter().any(|f| matches!(f.op, FlowbitOp::IsSet | FlowbitOp::IsNotSet));
    // A packet-level condition (TCP flags, ICMP type, connection size) is
    // likewise a strong condition in itself.
    let tests_packet = header.extra.is_some();
    if !has_content && !tests_flowbits && !tests_packet {
        anyhow::bail!("rule has no content/pcre terms, so it would match all traffic");
    }
    // Likewise all-negated: "this buffer does not contain X" fires on
    // essentially everything, and as a whole rule that's a footgun. One
    // negated term alongside a positive one is the useful case.
    if has_content && positive_contents == 0 && !tests_flowbits && !tests_packet {
        anyhow::bail!("rule has only negated terms, so it would match nearly all traffic; add a positive content");
    }
    // A relative term with nothing before it has no previous match to
    // measure from. Suricata treats this as "from the start", which is
    // indistinguishable from `offset` and makes the rule's intent
    // ambiguous; saying so at load time is cheaper than a rule that
    // quietly means something else.
    if let Some(Term::Content(c)) = terms.iter().find(|t| !matches!(t, Term::Transform(_))) {
        if c.is_relative() {
            anyhow::bail!("the first content is relative (distance/within) but has nothing to be relative to");
        }
    }
    let sid = sid.ok_or_else(|| anyhow::anyhow!("rule is missing 'sid'"))?;
    let name = name.unwrap_or_else(|| format!("sid-{}", sid));

    let (transforms, terms) = split_transforms(terms);
    Ok(Parsed::Single(Rule { sid, name, severity, buffer, direction, header, terms, transforms, flowbits: bits, noalert, part: None, threshold, xbits }))
}

/// Lowers a multi-buffer rule into per-buffer parts plus a [`Composite`].
#[allow(clippy::too_many_arguments)]
fn lower_composite(
    sid: u32,
    name: String,
    severity: Severity,
    direction: Direction,
    header: HeaderMatch,
    parts: Vec<(Buffer, Vec<Term>)>,
    bits: Vec<Flowbit>,
    noalert: bool,
    threshold: Option<crate::threshold::Threshold>,
    xbits: Vec<crate::threshold::XbitOp>,
    reg: &mut FlowbitRegistry,
) -> anyhow::Result<Parsed> {
    anyhow::ensure!(parts.len() <= MAX_PARTS, "a rule may inspect at most {} buffers, this one names {}", MAX_PARTS, parts.len());

    // Conditions gate each part, where they are cheap; effects wait for
    // completion, since a rule that has not fully matched has done nothing.
    let is_cond = |f: &Flowbit| matches!(f.op, FlowbitOp::IsSet | FlowbitOp::IsNotSet);
    let conditions: Vec<Flowbit> = bits.iter().copied().filter(is_cond).collect();
    let effects: Vec<Flowbit> = bits.iter().copied().filter(|f| !is_cond(f)).collect();

    // Validated before an id is taken. Ids must stay dense across a
    // file, and a lenient load that skips a bad rule would otherwise leave
    // a hole where its id was.
    let positive = |terms: &Vec<Term>| terms.iter().any(|t| matches!(t, Term::Content(c) if !c.negate));
    // Something in the rule must still say what to look for, or it would
    // match every request.
    anyhow::ensure!(parts.iter().any(|(_, t)| positive(t)), "no part has a positive content, so the rule would match all traffic");

    for (buffer, terms) in &parts {
        // A part may consist only of negations — "there is no `Accept`
        // header" — on a buffer that is parsed once per message. That is a
        // real claim about a real, complete buffer, and ET has about 1,500
        // of them on `http.header_names` alone.
        //
        // It is refused on the raw payload, which is re-scanned as the
        // stream grows: "does not contain X *yet*" is not a claim a rule
        // can make, and would fire on the first segment of every
        // connection. A part with no content term at all is refused
        // everywhere, since it would run against every buffer of its type.
        if !positive(terms) {
            // A length test ("the URI is exactly 12 bytes") or a numeric
            // test of the buffer's value (a `Content-Length` over some
            // size) is a constraint in its own right, so a part made of one
            // is not a footgun.
            anyhow::ensure!(
                terms.iter().any(|t| matches!(t, Term::Content(_) | Term::Len(_) | Term::Test(_))),
                "the part inspecting {} has no content, so it would match all traffic",
                buffer.as_str()
            );
            anyhow::ensure!(
                *buffer != Buffer::Payload,
                "the part inspecting the raw payload has only negated content; \"absent so far\" is not meaningful on a stream that is still growing"
            );
        }
        if let Some(Term::Content(c)) = terms.iter().find(|t| !matches!(t, Term::Transform(_))) {
            anyhow::ensure!(!c.is_relative(), "the first content for {} is relative but has nothing to be relative to", buffer.as_str());
        }
    }

    let id = reg.next_composite();
    let total = parts.len() as u8;
    let mut rules = Vec::with_capacity(parts.len());
    for (i, (buffer, terms)) in parts.into_iter().enumerate() {
        // A buffer that only exists on one side of a connection pins the
        // part to that side, whatever the rule as a whole says: a request
        // URI is only ever seen going to the server.
        let dir = buffer.side().unwrap_or(direction);
        let (transforms, terms) = split_transforms(terms);
        rules.push(Rule {
            sid,
            name: name.clone(),
            severity,
            buffer,
            direction: dir,
            header: header.clone(),
            terms,
            transforms,
            flowbits: conditions.clone(),
            noalert: true,
            part: Some((id, i as u8)),
            threshold: None,
            xbits: Vec::new(),
        });
    }
    Ok(Parsed::Composite { composite: Composite { id, sid, name, severity, parts: total, threshold, xbits, effects, noalert }, parts: rules })
}

/// Shared tail of `byte_test` and `byte_jump`: the comma-separated
/// modifiers that follow their positional arguments.
struct NumericModifiers {
    relative: bool,
    format: NumberFormat,
    multiplier: u64,
    align: bool,
    post_offset: i64,
    from_beginning: bool,
    negate: bool,
}

fn parse_numeric_modifiers<'a, I: Iterator<Item = &'a str>>(rest: I) -> anyhow::Result<NumericModifiers> {
    let mut m = NumericModifiers {
        relative: false,
        format: NumberFormat::Binary(Endian::Big),
        multiplier: 1,
        align: false,
        post_offset: 0,
        from_beginning: false,
        negate: false,
    };
    // `string` and the radix keywords may arrive in either order, so the
    // radix is remembered and applied at the end.
    let mut string_mode = false;
    let mut radix = 10u32;
    let mut endian = Endian::Big;

    let mut rest = rest.peekable();
    while let Some(tok) = rest.next() {
        let t = tok.trim();
        match t.to_ascii_lowercase().as_str() {
            "" => {}
            "relative" => m.relative = true,
            "big" => endian = Endian::Big,
            "little" => endian = Endian::Little,
            "string" => string_mode = true,
            "hex" => radix = 16,
            "dec" => radix = 10,
            "oct" => radix = 8,
            "align" => m.align = true,
            "from_beginning" => m.from_beginning = true,
            "multiplier" => {
                let v = rest.next().ok_or_else(|| anyhow::anyhow!("'multiplier' needs a value"))?;
                m.multiplier = v.trim().parse()?;
            }
            "post_offset" => {
                let v = rest.next().ok_or_else(|| anyhow::anyhow!("'post_offset' needs a value"))?;
                m.post_offset = v.trim().parse()?;
            }
            // Written as its own token by some rulesets.
            other if other.starts_with("multiplier ") => m.multiplier = other[11..].trim().parse()?,
            other if other.starts_with("post_offset ") => m.post_offset = other[12..].trim().parse()?,
            other => anyhow::bail!("unknown byte_test/byte_jump modifier {:?}", other),
        }
    }
    m.format = if string_mode { NumberFormat::Text(radix) } else { NumberFormat::Binary(endian) };
    Ok(m)
}

/// A byte count of zero is meaningful only for text, where it means "every
/// digit that is there": a field whose width is not known in advance, such
/// as a `Content-Length`. Binary needs a width to know what to read. Twenty
/// digits is the most that fit a `u64`, so it is also a bound.
fn digits_to_read(bytes: usize, format: NumberFormat, what: &str) -> anyhow::Result<usize> {
    match (bytes, format) {
        (0, NumberFormat::Text(_)) => Ok(20),
        (0, _) => anyhow::bail!("{} byte count must be at least 1 unless the number is text", what),
        _ => Ok(bytes),
    }
}

/// `byte_test:<bytes>,<op>,<value>,<offset>[,modifiers...]`
fn parse_byte_test(value: &str, vars: &VarTable) -> anyhow::Result<ByteTest> {
    let mut parts = value.split(',').map(str::trim);
    let bytes: usize = parts.next().ok_or_else(|| anyhow::anyhow!("byte_test needs a byte count"))?.parse()?;
    let op_raw = parts.next().ok_or_else(|| anyhow::anyhow!("byte_test needs an operator"))?;
    let value_raw = parts.next().ok_or_else(|| anyhow::anyhow!("byte_test needs a value"))?;
    let (offset, offset_var) = vars.number_or_var(parts.next().ok_or_else(|| anyhow::anyhow!("byte_test needs an offset"))?)?;

    // A leading '!' negates the whole test, and is written attached to
    // the operator.
    let (negate, op_str) = match op_raw.strip_prefix('!') {
        Some(rest) if !rest.is_empty() => (true, rest),
        _ => (false, op_raw),
    };
    let op = ByteOp::parse(op_str)?;
    let (cmp, value_var) = match parse_integer(value_raw) {
        Ok(v) => (v, None),
        Err(_) => (0, Some(vars.lookup(value_raw)?)),
    };
    let m = parse_numeric_modifiers(parts)?;
    let bytes = digits_to_read(bytes, m.format, "byte_test")?;
    anyhow::ensure!(
        matches!(m.format, NumberFormat::Text(_)) || bytes <= 8,
        "byte_test can read at most 8 binary bytes, got {}",
        bytes
    );
    Ok(ByteTest { bytes, op, value: cmp, value_var, offset, offset_var, relative: m.relative, format: m.format, negate: negate || m.negate })
}

/// `byte_extract:<bytes>,<offset>,<name>[,modifiers...]`
fn parse_byte_extract(value: &str, vars: &mut VarTable) -> anyhow::Result<ByteExtract> {
    let mut parts = value.split(',').map(str::trim);
    let bytes: usize = parts.next().ok_or_else(|| anyhow::anyhow!("byte_extract needs a byte count"))?.parse()?;
    let offset: i64 = parts.next().ok_or_else(|| anyhow::anyhow!("byte_extract needs an offset"))?.parse()?;
    let name = parts.next().ok_or_else(|| anyhow::anyhow!("byte_extract needs a variable name"))?;
    let m = parse_numeric_modifiers(parts)?;
    let bytes = digits_to_read(bytes, m.format, "byte_extract")?;
    anyhow::ensure!(matches!(m.format, NumberFormat::Text(_)) || bytes <= 8, "byte_extract can read at most 8 binary bytes, got {}", bytes);
    anyhow::ensure!(!m.align && m.post_offset == 0 && !m.from_beginning, "byte_extract does not take align, post_offset or from_beginning");
    let var = vars.define(name)?;
    Ok(ByteExtract { bytes, offset, relative: m.relative, format: m.format, multiplier: i64::try_from(m.multiplier)?, var })
}

/// `byte_math:bytes N, offset N, oper +, rvalue N|name, result name[, relative][, endian big|little][, string dec]`
fn parse_byte_math(value: &str, vars: &mut VarTable) -> anyhow::Result<ByteMath> {
    let (mut bytes, mut offset, mut oper, mut rvalue, mut result) = (None, None, None, None, None);
    let mut modifiers: Vec<String> = Vec::new();
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (key, val) = part.split_once(char::is_whitespace).map(|(k, v)| (k, v.trim())).unwrap_or((part, ""));
        match key.to_ascii_lowercase().as_str() {
            "bytes" => bytes = Some(val.parse::<usize>()?),
            "offset" => offset = Some(val.parse::<i64>()?),
            "oper" => oper = Some(val.to_string()),
            "rvalue" => rvalue = Some(val.to_string()),
            "result" => result = Some(val.to_string()),
            "relative" | "big" | "little" | "hex" | "dec" | "oct" | "string" => modifiers.push(key.to_string()),
            "endian" => modifiers.push(val.to_string()),
            other => anyhow::bail!("unsupported byte_math field {:?}", other),
        }
    }
    let bytes = bytes.ok_or_else(|| anyhow::anyhow!("byte_math needs 'bytes'"))?;
    let offset = offset.ok_or_else(|| anyhow::anyhow!("byte_math needs 'offset'"))?;
    let oper = match oper.ok_or_else(|| anyhow::anyhow!("byte_math needs 'oper'"))?.as_str() {
        "+" => '+',
        "-" => '-',
        "*" => '*',
        "/" => '/',
        "<<" => '<',
        ">>" => '>',
        other => anyhow::bail!("unknown byte_math operator {:?}", other),
    };
    let (rvalue, rvalue_var) = vars.number_or_var(&rvalue.ok_or_else(|| anyhow::anyhow!("byte_math needs 'rvalue'"))?)?;
    let m = parse_numeric_modifiers(modifiers.iter().map(String::as_str))?;
    let bytes = digits_to_read(bytes, m.format, "byte_math")?;
    anyhow::ensure!(matches!(m.format, NumberFormat::Text(_)) || bytes <= 8, "byte_math can read at most 8 binary bytes, got {}", bytes);
    let var = vars.define(&result.ok_or_else(|| anyhow::anyhow!("byte_math needs 'result'"))?)?;
    Ok(ByteMath { bytes, offset, relative: m.relative, format: m.format, oper, rvalue, rvalue_var, var })
}

/// `base64_decode:[bytes N][,offset N][,relative][,mode ...]`
fn parse_base64_decode(value: &str) -> anyhow::Result<Base64Decode> {
    let (mut bytes, mut offset, mut relative) = (0usize, 0i64, false);
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (key, val) = part.split_once(char::is_whitespace).map(|(k, v)| (k, v.trim())).unwrap_or((part, ""));
        match key.to_ascii_lowercase().as_str() {
            "bytes" => bytes = val.parse()?,
            "offset" => offset = val.parse()?,
            "relative" => relative = true,
            // Every mode is read tolerantly; see `Base64Decode`.
            "mode" => {}
            other => anyhow::bail!("unsupported base64_decode field {:?}", other),
        }
    }
    Ok(Base64Decode { bytes, offset, relative })
}

/// `byte_jump:<bytes>,<offset>[,modifiers...]`
fn parse_byte_jump(value: &str) -> anyhow::Result<ByteJump> {
    let mut parts = value.split(',').map(str::trim);
    let bytes: usize = parts.next().ok_or_else(|| anyhow::anyhow!("byte_jump needs a byte count"))?.parse()?;
    let offset: i64 = parts.next().ok_or_else(|| anyhow::anyhow!("byte_jump needs an offset"))?.parse()?;
    let m = parse_numeric_modifiers(parts)?;
    let bytes = digits_to_read(bytes, m.format, "byte_jump")?;
    anyhow::ensure!(
        matches!(m.format, NumberFormat::Text(_)) || bytes <= 8,
        "byte_jump can read at most 8 binary bytes, got {}",
        bytes
    );
    Ok(ByteJump {
        bytes,
        offset,
        relative: m.relative,
        format: m.format,
        multiplier: m.multiplier.max(1),
        align: m.align,
        post_offset: m.post_offset,
        from_beginning: m.from_beginning,
    })
}

/// Accepts decimal, or `0x`-prefixed hex, which rulesets use freely for
/// protocol constants.
fn parse_integer(s: &str) -> anyhow::Result<u64> {
    let t = s.trim();
    let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16)?,
        None => t.parse()?,
    };
    Ok(v)
}

fn unquote_plain(v: &str) -> String {
    let t = v.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

// =======================================================================
// The matcher
// =======================================================================

/// Where a matched rule lives, so its flowbit effects can be applied
/// after every rule in the pass has been evaluated against the state as
/// it was on entry.
/// Evaluates one rule, pushing a hit if it fires. Returns whether the
/// rule has flowbit effects still to apply.
///
/// The order of the three tests is the whole performance story: a header
/// comparison is a few integer compares, a flowbit condition is one bit
/// test, and a content search walks the buffer. Cheapest first means a
/// rule scoped to a port it does not match never touches the payload.
fn evaluate_rule(rule: &Rule, p: &Packet, evaluate: Direction, data: &[u8], bits: Option<&FlowBits>, out: &mut Vec<RuleHit>) -> bool {
    // A part records progress on the connection, so with no connection
    // (a datagram) there is nowhere to record it and the rule cannot
    // complete. Skipping it here is cheaper than matching to no effect.
    if rule.part.is_some() && bits.is_none() {
        return false;
    }
    if !rule.header.matches(p, evaluate) || !rule.stream_holds(bits) || !rule.flowbits_hold(bits) || !rule.content_matches(data) {
        return false;
    }
    // A rule that only sets cross-connection state still has to reach
    // the stage that holds it; that stage decides it is not reported.
    if !rule.noalert || !rule.xbits.is_empty() {
        out.push(RuleHit { name: rule.name.clone(), sid: rule.sid, severity: rule.severity });
    }
    rule.sets_flowbits() || rule.part.is_some()
}

/// The rules that see a buffer in one particular form.
///
/// Rules are grouped by the transforms they apply, because a group shares
/// one transformed copy of the buffer and one prefilter over that copy: a
/// literal that only appears once a URI is decoded cannot be found by a
/// prefilter that reads the raw bytes.
struct RuleGroup {
    /// Rules reachable through the prefilter, and the literal each one
    /// requires. Parallel to the automaton's pattern ids.
    prefiltered: Vec<Rule>,
    prefilter: Option<AhoCorasick>,
    /// Which rule each prefilter pattern belongs to.
    pattern_owner: Vec<usize>,
    /// Rules that must be evaluated unconditionally.
    always: Vec<Rule>,
    /// The longest prefilter literal, in bytes.
    max_pattern: usize,
}

impl RuleGroup {
    fn build(group: Vec<Rule>) -> anyhow::Result<RuleGroup> {
        let mut prefiltered = Vec::new();
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_owner = Vec::new();
        let mut always = Vec::new();
        for rule in group {
            // The longest required literal is the most selective one
            // available, so it makes the best prefilter key.
            let literal = rule.prefilter_contents().filter_map(|c| c.prefilter_literal()).max_by_key(|l| l.len()).map(|l| l.to_vec());
            match literal {
                Some(lit) => {
                    let idx = prefiltered.len();
                    prefiltered.push(rule);
                    patterns.push(lit);
                    pattern_owner.push(idx);
                }
                None => always.push(rule),
            }
        }
        // Case-insensitive so that a `nocase` literal can be a key too.
        // For a case-sensitive rule this only admits extra candidates,
        // each of which is then checked exactly.
        let prefilter = if patterns.is_empty() { None } else { Some(AhoCorasick::builder().ascii_case_insensitive(true).build(&patterns)?) };
        let max_pattern = patterns.iter().map(Vec::len).max().unwrap_or(0);
        Ok(RuleGroup { prefiltered, prefilter, pattern_owner, always, max_pattern })
    }
}

/// v2 rules for one `(buffer, direction)` pair, with a multi-pattern
/// prefilter.
///
/// The prefilter is the reason this scales past a handful of rules.
/// Checking N rules one at a time means N substring searches per buffer;
/// instead, one Aho-Corasick pass finds which of the rules' required
/// literals are present anywhere in the buffer, and only those rules get
/// fully evaluated. Rules with no usable literal (all-regex, or whose
/// only literals are negated) can't be prefiltered and are always
/// evaluated â€” which is a good reason to write at least one plain
/// `content` in a rule that needs to be fast.
struct BufferRules {
    groups: Vec<RuleSlice>,
}

/// One group of rules that share the way they see the buffer and the
/// state they need before they can fire.
struct RuleSlice {
    /// Applied to the buffer before these rules read it.
    transforms: Vec<Transform>,
    /// A flowbit every rule here requires to be *set*. While it is not,
    /// none of them can match, so the whole group is skipped without
    /// scanning the buffer. A ruleset full of `flowbits:isset` rules
    /// (ET is) would otherwise search every buffer for rules that cannot
    /// yet apply.
    gate: Option<u32>,
    rules: RuleGroup,
}

/// What has been learned about one direction of one connection's stream by
/// scanning it as it grew.
///
/// The raw payload is matched against the *whole* reassembled stream on
/// every new segment, which is what defeats a signature split across
/// packets. Doing that by scanning the whole stream again each time makes
/// the cost of a connection quadratic in its length, and it was the largest
/// single cost of running a real ruleset. But a scan only needs to look at
/// the new bytes (and enough of the old to catch a literal straddling the
/// join): the rules whose literals were found earlier are remembered, and
/// each is still evaluated against the whole stream, as before.
#[derive(Default)]
pub struct StreamScan {
    slices: Vec<SliceScan>,
}

#[derive(Default)]
struct SliceScan {
    /// How much of the stream has been scanned.
    upto: usize,
    /// Which rules of the group have had a literal found, as a bit set and
    /// as a list (the list is what is evaluated).
    seen: Vec<u64>,
    hits: Vec<u32>,
}

/// Reusable working memory for matching, owned by whatever is doing the
/// matching (a worker, or a `FlowTable`) and handed in per check.
///
/// Matching used to allocate a `Vec` for prefilter candidates on every
/// check — that is once per buffer per packet, so a `malloc`/`free` pair
/// on the hottest path in the program — and then deduplicate candidates
/// with a linear `contains`, which is quadratic in the number of rules
/// that matched the prefilter. Neither shows at a few dozen rules; both
/// do at a few thousand, which is the size a real rule set reaches.
///
/// `seen` replaces the linear scan with a generation stamp per rule:
/// bumping `generation` invalidates every entry at once, so there is no
/// clearing pass either.
#[derive(Default)]
pub struct MatchScratch {
    candidates: Vec<usize>,
    seen: Vec<u64>,
    generation: u64,
}

impl MatchScratch {
    fn begin(&mut self, rules: usize) {
        self.candidates.clear();
        if self.seen.len() < rules {
            self.seen.resize(rules, 0);
        }
        self.generation += 1;
    }

    /// True the first time `idx` is offered this round.
    fn first_time(&mut self, idx: usize) -> bool {
        if self.seen[idx] == self.generation {
            return false;
        }
        self.seen[idx] = self.generation;
        true
    }
}

#[derive(Default)]
pub struct RuleSetV2 {
    by_buffer: FxHashMap<(Buffer, Direction), BufferRules>,
    count: usize,
    /// Names interned while parsing, kept so `FlowBits` knows how wide to
    /// allocate and so a diagnostic can name a bit.
    flowbits: FlowbitRegistry,
    /// Indexed by composite id.
    composites: Vec<Composite>,
    /// Rate control by rule id. Applied after matching, by a stage that
    /// sees every alert, so it is kept here only to be looked up.
    thresholds: FxHashMap<u32, crate::threshold::Threshold>,
    /// Whether any rule reads the per-packet buffer. Asked once per packet,
    /// so it is worked out at load.
    packet_rules: bool,
    /// Cross-connection state operations by rule id, applied by the gate.
    xbits: FxHashMap<u32, crate::threshold::XbitSpec>,
}

impl RuleSetV2 {
    /// The `xbits` operations of a rule, if it has any.
    pub fn xbits_for(&self, sid: u32) -> Option<crate::threshold::XbitSpec> {
        self.xbits.get(&sid).cloned()
    }

    pub fn has_packet_rules(&self) -> bool {
        self.packet_rules
    }

    /// Records that a flow has been recognised as speaking `app`.
    ///
    /// Application identity is carried as an ordinary flowbit named
    /// `app.<name>`, set by the parsers when they recognise a protocol, so
    /// that a rule about "any traffic ARGUS identified as RDP" needs no
    /// machinery of its own. Nothing is recorded unless a loaded rule asks
    /// about that protocol, so a ruleset with no such rules pays nothing.
    pub fn mark_app(&self, bits: &mut FlowBits, app: &str) {
        if let Some(id) = self.flowbits.lookup(app) {
            bits.set(id, true, self.flowbits.len());
        }
    }

    /// The `threshold` or `detection_filter` of a rule, if it has one.
    pub fn threshold_for(&self, sid: u32) -> Option<crate::threshold::Threshold> {
        self.thresholds.get(&sid).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn len(&self) -> usize {
        self.count
    }

    /// Groups rules by `(buffer, direction)` and builds each group's
    /// prefilter. A `direction:any` rule is stored under both concrete
    /// directions, exactly as v1 does — see `engine::RuleSet::check` for
    /// the bug that convention exists to prevent.
    /// How many distinct flowbits the loaded rules use. Zero means the
    /// whole mechanism can be skipped.
    /// Whether any loaded rule inspects one of these buffers.
    ///
    /// Lets a caller skip building a buffer nothing asks about, which is
    /// how file hashing stays free for the deployments that do not use
    /// it.
    pub fn uses_any(&self, buffers: &[Buffer]) -> bool {
        self.by_buffer.keys().any(|(b, _)| buffers.contains(b))
    }

    pub fn flowbit_count(&self) -> usize {
        self.flowbits.len()
    }

    pub fn flowbit_name(&self, bit: u32) -> Option<&str> {
        self.flowbits.name(bit)
    }

    pub fn build(rules: Vec<Rule>) -> anyhow::Result<RuleSetV2> {
        RuleSetV2::build_with(rules, FlowbitRegistry::default())
    }

    pub fn build_with(rules: Vec<Rule>, flowbits: FlowbitRegistry) -> anyhow::Result<RuleSetV2> {
        RuleSetV2::build_full(rules, Vec::new(), flowbits)
    }

    /// Builds from single rules, the parts of multi-buffer rules, and the
    /// composites that tie those parts together.
    pub fn build_full(rules: Vec<Rule>, mut composites: Vec<Composite>, flowbits: FlowbitRegistry) -> anyhow::Result<RuleSetV2> {
        composites.sort_by_key(|c| c.id);
        for (i, c) in composites.iter().enumerate() {
            anyhow::ensure!(c.id as usize == i, "composite ids must be dense (expected {}, got {})", i, c.id);
        }
        // A part with no composite would index out of bounds the first
        // time it matched, on the packet path. Refusing at load is cheaper.
        for r in &rules {
            if let Some((cid, idx)) = r.part {
                let c = composites.get(cid as usize).ok_or_else(|| anyhow::anyhow!("rule sid {} is part of composite {} which was not supplied", r.sid, cid))?;
                anyhow::ensure!(idx < c.parts, "rule sid {} claims part {} of a {}-part rule", r.sid, idx, c.parts);
            }
        }
        let mut grouped: FxHashMap<(Buffer, Direction), Vec<Rule>> = FxHashMap::default();
        // Logical rules: parts of one multi-buffer rule count once, via
        // its composite.
        let count = rules.iter().filter(|r| r.part.is_none()).count() + composites.len();
        let thresholds: FxHashMap<u32, crate::threshold::Threshold> =
            rules.iter().filter_map(|r| r.threshold.map(|t| (r.sid, t))).chain(composites.iter().filter_map(|c| c.threshold.map(|t| (c.sid, t)))).collect();
        let rules_xbits: FxHashMap<u32, crate::threshold::XbitSpec> = rules
            .iter()
            .filter(|r| !r.xbits.is_empty())
            .map(|r| (r.sid, crate::threshold::XbitSpec { ops: r.xbits.clone(), noalert: r.noalert }))
            .chain(composites.iter().filter(|c| !c.xbits.is_empty()).map(|c| (c.sid, crate::threshold::XbitSpec { ops: c.xbits.clone(), noalert: c.noalert })))
            .collect();
        for rule in rules {
            let dirs: &[Direction] = match rule.direction {
                Direction::Any => &[Direction::ToServer, Direction::ToClient],
                Direction::ToServer => &[Direction::ToServer],
                Direction::ToClient => &[Direction::ToClient],
            };
            for d in dirs {
                grouped.entry((rule.buffer, *d)).or_default().push(rule.clone());
            }
        }

        let mut by_buffer = FxHashMap::default();
        for (key, group) in grouped {
            let mut slices: Vec<(Vec<Transform>, Option<u32>, Vec<Rule>)> = Vec::new();
            for rule in group {
                let gate = rule.flowbits.iter().find(|f| f.op == FlowbitOp::IsSet).map(|f| f.bit);
                match slices.iter_mut().find(|(t, g, _)| *t == rule.transforms && *g == gate) {
                    Some((_, _, rules)) => rules.push(rule),
                    None => slices.push((rule.transforms.clone(), gate, vec![rule])),
                }
            }
            let groups = slices.into_iter().map(|(transforms, gate, rules)| Ok(RuleSlice { transforms, gate, rules: RuleGroup::build(rules)? })).collect::<anyhow::Result<Vec<_>>>()?;
            by_buffer.insert(key, BufferRules { groups });
        }
        let xbits: FxHashMap<u32, crate::threshold::XbitSpec> = rules_xbits;
        let packet_rules = by_buffer.keys().any(|(b, _)| *b == Buffer::PacketPayload);
        Ok(RuleSetV2 { by_buffer, count, flowbits, composites, thresholds, packet_rules, xbits })
    }

    /// Evaluates every applicable rule against one buffer.
    /// `lookup` selects the rule group; `evaluate` is what header terms
    /// are judged against. They differ only for a caller with no flow
    /// state, which passes `Direction::Any` as `evaluate` — see
    /// `engine::RuleSet::check` for why conflating the two was wrong.
    /// Matches `data` against every rule for this buffer and direction.
    ///
    /// `bits` is the connection's flowbit state, where there is one.
    /// UDP and ICMP pass `None`, which is not a limitation so much as an
    /// accurate statement: a datagram has no connection to carry state
    /// across, so `isset` cannot hold for it and `set` has nowhere to go.
    pub fn check(
        &self,
        p: &Packet,
        lookup: Direction,
        evaluate: Direction,
        buffer: Buffer,
        data: &[u8],
        scratch: &mut MatchScratch,
        bits: Option<&mut FlowBits>,
        out: &mut Vec<RuleHit>,
    ) {
        let Some(group) = self.by_buffer.get(&(buffer, lookup)) else {
            return;
        };
        let registry_len = self.flowbits.len();
        let mut pending: Vec<&Rule> = Vec::new();
        {
            // Which groups apply is decided before any of them runs, and
            // every one reads the same read-only view of the state.
            let state: Option<&FlowBits> = bits.as_deref();
            for slice in group.groups.iter().filter(|g| g.gate.is_none_or(|bit| state.is_some_and(|b| b.is_set(bit)))) {
                if slice.transforms.is_empty() {
                    self.run_group(&slice.rules, p, evaluate, data, scratch, state, &mut pending, out);
                } else {
                    let view = apply_transforms(&slice.transforms, data);
                    self.run_group(&slice.rules, p, evaluate, &view, scratch, state, &mut pending, out);
                }
            }
        }
        if let Some(bits) = bits {
            for rule in pending {
                rule.apply_flowbits(bits, registry_len);
                if let Some((cid, idx)) = rule.part {
                    let c = &self.composites[cid as usize];
                    if bits.mark_part(cid, idx, c.parts, self.composites.len()) {
                        apply_effects(&c.effects, bits, registry_len);
                        if !c.noalert || !c.xbits.is_empty() {
                            out.push(RuleHit { name: c.name.clone(), sid: c.sid, severity: c.severity });
                        }
                    }
                }
            }
        }
    }

    /// Evaluates one group of rules against the buffer as they see it,
    /// recording the rules that matched and still have an effect to apply.
    ///
    /// Effects are applied by the caller once every group has run, because
    /// a rule that sets a bit must not change the answer for another rule
    /// matching the same buffer in the same pass. Suricata has the same
    /// ordering problem and resolves it the same way: within one
    /// evaluation, every rule sees the state as it was on entry.
    #[allow(clippy::too_many_arguments)]
    fn run_group<'a>(&self, group: &'a RuleGroup, p: &Packet, evaluate: Direction, data: &[u8], scratch: &mut MatchScratch, bits: Option<&FlowBits>, pending: &mut Vec<&'a Rule>, out: &mut Vec<RuleHit>) {
        if let (Some(ac), false) = (&group.prefilter, group.prefiltered.is_empty()) {
            scratch.begin(group.prefiltered.len());
            for m in ac.find_overlapping_iter(data) {
                let owner = group.pattern_owner[m.pattern().as_usize()];
                if scratch.first_time(owner) {
                    scratch.candidates.push(owner);
                }
            }
            // Indexed rather than iterated: `scratch` is borrowed mutably
            // above and the rules live in `group`.
            for i in 0..scratch.candidates.len() {
                let idx = scratch.candidates[i];
                if evaluate_rule(&group.prefiltered[idx], p, evaluate, data, bits, out) {
                    pending.push(&group.prefiltered[idx]);
                }
            }
        }
        for rule in &group.always {
            if evaluate_rule(rule, p, evaluate, data, bits, out) {
                pending.push(rule);
            }
        }
    }
}

impl RuleSetV2 {
    /// As [`RuleSetV2::check`], for a buffer that only ever grows (the
    /// reassembled stream), scanning just what is new. `direction` is a
    /// concrete side, since a stream always has one.
    #[allow(clippy::too_many_arguments)]
    pub fn check_stream(&self, p: &Packet, buffer: Buffer, direction: Direction, data: &[u8], scan: &mut StreamScan, scratch: &mut MatchScratch, bits: Option<&mut FlowBits>, out: &mut Vec<RuleHit>) {
        let Some(group) = self.by_buffer.get(&(buffer, direction)) else {
            return;
        };
        let registry_len = self.flowbits.len();
        let mut pending: Vec<&Rule> = Vec::new();
        {
            let state: Option<&FlowBits> = bits.as_deref();
            for (i, slice) in group.groups.iter().enumerate() {
                if !slice.gate.is_none_or(|bit| state.is_some_and(|b| b.is_set(bit))) {
                    continue;
                }
                if !slice.transforms.is_empty() {
                    // Rare on a raw stream; read it whole.
                    let view = apply_transforms(&slice.transforms, data);
                    self.run_group(&slice.rules, p, direction, &view, scratch, state, &mut pending, out);
                    continue;
                }
                if scan.slices.len() <= i {
                    scan.slices.resize_with(group.groups.len(), SliceScan::default);
                }
                self.run_group_stream(&slice.rules, p, direction, data, &mut scan.slices[i], state, &mut pending, out);
            }
        }
        if let Some(bits) = bits {
            for rule in pending {
                rule.apply_flowbits(bits, registry_len);
                if let Some((cid, idx)) = rule.part {
                    let c = &self.composites[cid as usize];
                    if bits.mark_part(cid, idx, c.parts, self.composites.len()) {
                        apply_effects(&c.effects, bits, registry_len);
                        if !c.noalert || !c.xbits.is_empty() {
                            out.push(RuleHit { name: c.name.clone(), sid: c.sid, severity: c.severity });
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_group_stream<'a>(&self, group: &'a RuleGroup, p: &Packet, evaluate: Direction, data: &[u8], scan: &mut SliceScan, bits: Option<&FlowBits>, pending: &mut Vec<&'a Rule>, out: &mut Vec<RuleHit>) {
        if let (Some(ac), false) = (&group.prefilter, group.prefiltered.is_empty()) {
            // A stream that shrank is a different stream: start again.
            if scan.upto > data.len() {
                *scan = SliceScan::default();
            }
            let words = group.prefiltered.len().div_ceil(64);
            if scan.seen.len() != words {
                scan.seen.clear();
                scan.seen.resize(words, 0);
                scan.hits.clear();
                scan.upto = 0;
            }
            // Back up far enough that a literal spanning the old end and the
            // new bytes is still found whole.
            let start = scan.upto.saturating_sub(group.max_pattern.saturating_sub(1));
            for m in ac.find_overlapping_iter(&data[start..]) {
                let owner = group.pattern_owner[m.pattern().as_usize()];
                let (w, b) = (owner / 64, owner % 64);
                if scan.seen[w] & (1 << b) == 0 {
                    scan.seen[w] |= 1 << b;
                    scan.hits.push(owner as u32);
                }
            }
            scan.upto = data.len();
            for &idx in &scan.hits {
                let rule = &group.prefiltered[idx as usize];
                if evaluate_rule(rule, p, evaluate, data, bits, out) {
                    pending.push(rule);
                }
            }
        }
        for rule in &group.always {
            if evaluate_rule(rule, p, evaluate, data, bits, out) {
                pending.push(rule);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(proto: u8, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Packet {
        let mut p = Packet::default();
        p.protocol = proto;
        p.src = IpAddr::V4(src);
        p.src_port = sport;
        p.dst = IpAddr::V4(dst);
        p.dst_port = dport;
        p
    }

    /// Passes `dir` as both the lookup key and the evaluation direction,
    /// which is what a caller with real flow state does.
    fn hits(set: &RuleSetV2, p: &Packet, buffer: Buffer, dir: Direction, data: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        set.check(p, dir, dir, buffer, data, &mut MatchScratch::default(), None, &mut out);
        out.into_iter().map(|h| h.name).collect()
    }

    fn build(lines: &[&str]) -> RuleSetV2 {
        // One registry for the whole set, as the real loader does, so
        // rules that share a flowbit name share its index.
        let mut reg = FlowbitRegistry::default();
        let (mut rules, mut composites) = (Vec::new(), Vec::new());
        for l in lines {
            match parse_any(l, &mut reg).expect("rule should parse") {
                Parsed::Single(r) => rules.push(r),
                Parsed::Composite { composite, parts } => {
                    composites.push(composite);
                    rules.extend(parts);
                }
            }
        }
        RuleSetV2::build_full(rules, composites, reg).unwrap()
    }

    /// As `hits`, but carrying connection state across calls, which is
    /// the only way a flowbit can mean anything.
    fn hits_with_bits(set: &RuleSetV2, p: &Packet, buffer: Buffer, dir: Direction, data: &[u8], bits: &mut FlowBits) -> Vec<String> {
        let mut out = Vec::new();
        set.check(p, dir, dir, buffer, data, &mut MatchScratch::default(), Some(bits), &mut out);
        out.into_iter().map(|h| h.name).collect()
    }

    /// The headline capability: a rule is a conjunction, not a single
    /// pattern. Both contents must be present.
    #[test]
    fn multiple_contents_are_anded_not_ored() {
        let set = build(&[r#"rule sid:1; name:"both"; buffer:payload; content:"alpha"; content:"omega";"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"alpha and omega"), vec!["both"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"alpha only").is_empty(), "one of two contents must not be enough");
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"omega only").is_empty());
    }

    #[test]
    fn offset_and_depth_anchor_a_content() {
        let set = build(&[r#"rule sid:2; name:"anchored"; buffer:payload; content:"NEEDLE"; offset:0; depth:10;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"NEEDLE here"), vec!["anchored"]);
        assert!(
            hits(&set, &p, Buffer::Payload, Direction::ToServer, b"aaaaaaaaaaaaaaaaaaaaNEEDLE").is_empty(),
            "past the depth window it must not match — this is what makes a rule specific instead of noisy"
        );
    }

    #[test]
    fn header_scoping_restricts_by_protocol_port_and_network() {
        let set = build(&[r#"rule sid:3; name:"scoped"; proto:tcp; dst_port:80,443; src_ip:10.0.0.0/8; buffer:payload; content:"x";"#]);
        assert_eq!(hits(&set, &pkt(PROTO_TCP, [10, 1, 2, 3], 5, [8, 8, 8, 8], 443), Buffer::Payload, Direction::ToServer, b"x"), vec!["scoped"]);
        assert!(hits(&set, &pkt(PROTO_TCP, [10, 1, 2, 3], 5, [8, 8, 8, 8], 8080), Buffer::Payload, Direction::ToServer, b"x").is_empty(), "wrong port");
        assert!(hits(&set, &pkt(PROTO_UDP, [10, 1, 2, 3], 5, [8, 8, 8, 8], 443), Buffer::Payload, Direction::ToServer, b"x").is_empty(), "wrong proto");
        assert!(hits(&set, &pkt(PROTO_TCP, [192, 168, 1, 1], 5, [8, 8, 8, 8], 443), Buffer::Payload, Direction::ToServer, b"x").is_empty(), "wrong source net");
    }

    #[test]
    fn port_ranges_and_negation_work() {
        let set = build(&[r#"rule sid:4; name:"ranged"; dst_port:8000-8100; buffer:payload; content:"x";"#]);
        let hit = |port| !hits(&set, &pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], port), Buffer::Payload, Direction::ToServer, b"x").is_empty();
        assert!(hit(8000) && hit(8050) && hit(8100));
        assert!(!hit(7999) && !hit(8101));

        let neg = build(&[r#"rule sid:5; name:"not22"; dst_port:!22; buffer:payload; content:"x";"#]);
        let nhit = |port| !hits(&neg, &pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], port), Buffer::Payload, Direction::ToServer, b"x").is_empty();
        assert!(nhit(80));
        assert!(!nhit(22));
    }

    /// `src`/`dst` in a rule mean client/server, not "whichever way this
    /// packet is going". Without swapping on `to_client`, a rule scoped
    /// to a client network would silently miss the server's replies
    /// inside the very connection it was written for.
    #[test]
    fn header_addresses_are_relative_to_the_connection_not_the_packet() {
        let set = build(&[r#"rule sid:6; name:"reply"; src_ip:10.0.0.0/8; dst_port:80; direction:to_client; buffer:payload; content:"y";"#]);
        // A server->client packet: source is the server, dest the client.
        let reply = pkt(PROTO_TCP, [8, 8, 8, 8], 80, [10, 0, 0, 7], 51000);
        assert_eq!(hits(&set, &reply, Buffer::Payload, Direction::ToClient, b"y"), vec!["reply"]);
    }

    #[test]
    fn negated_content_excludes_alongside_a_positive_one() {
        let set = build(&[r#"rule sid:7; name:"login-not-admin"; buffer:ftp.command; content:"USER"; !content:"admin";"#]);
        let p = pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], 21);
        assert_eq!(hits(&set, &p, Buffer::FtpCommand, Direction::ToServer, b"USER bob"), vec!["login-not-admin"]);
        assert!(hits(&set, &p, Buffer::FtpCommand, Direction::ToServer, b"USER admin").is_empty());
    }

    #[test]
    fn nocase_matches_regardless_of_case() {
        let set = build(&[r#"rule sid:8; name:"ci"; buffer:http.uri; content:"UNION SELECT"; nocase;"#]);
        let p = pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/x?q=union select 1"), vec!["ci"]);
    }

    /// `nocase` on binary content. The first implementation converted
    /// the literal via `String::from_utf8` and rejected anything that
    /// wasn't valid UTF-8, which blocked loading a real ruleset at its
    /// first binary `nocase` rule.
    #[test]
    fn nocase_works_on_binary_content() {
        let set = build(&[r#"rule sid:20; name:"bin-ci"; buffer:payload; content:"|FF FE|Admin|00|"; nocase;"#]);
        let p = pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], 445);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xff\xfeADMIN\x00"), vec!["bin-ci"]);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xff\xfeadmin\x00"), vec!["bin-ci"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xff\xfeadmim\x00").is_empty());
    }

    #[test]
    fn hex_blocks_let_a_rule_target_binary_traffic() {
        let set = build(&[r#"rule sid:9; name:"smb-magic"; buffer:payload; content:"|FE 53 4D 42|";"#]);
        let p = pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], 445);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xFESMB rest"), vec!["smb-magic"]);
    }

    /// Both hex spellings mean the same bytes. Assuming one byte per
    /// whitespace token rejected the contiguous form, which real rules
    /// use freely.
    #[test]
    fn hex_runs_may_be_contiguous_or_space_separated() {
        for spelling in ["|FE 53 4D 42|", "|FE534D42|", "|FE53 4D42|"] {
            let rule = format!(r#"rule sid:21; name:"h"; buffer:payload; content:"{}";"#, spelling);
            let set = build(&[rule.as_str()]);
            let p = pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], 445);
            assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xFESMB rest"), vec!["h"], "spelling {}", spelling);
        }
        assert!(parse_rule(r#"rule sid:22; name:"odd"; buffer:payload; content:"|FE5|";"#).is_err());
    }

    #[test]
    fn sid_and_severity_reach_the_hit() {
        let set = build(&[r#"rule sid:1000042; name:"tuned"; severity:low; buffer:payload; content:"q";"#]);
        let p = pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], 80);
        let mut out = Vec::new();
        set.check(&p, Direction::ToServer, Direction::ToServer, Buffer::Payload, b"q", &mut MatchScratch::default(), None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sid, 1000042);
        assert_eq!(out[0].severity, Severity::Low, "a rule must be able to be tuned down without being deleted");
    }

    #[test]
    fn a_rule_with_no_content_is_rejected_at_load_time() {
        let err = parse_rule(r#"rule sid:10; name:"empty"; buffer:payload;"#).unwrap_err().to_string();
        assert!(err.contains("no content"), "got: {}", err);
    }

    #[test]
    fn an_all_negated_rule_is_rejected_at_load_time() {
        let err = parse_rule(r#"rule sid:11; name:"neg"; buffer:http.uri; !content:"a";"#).unwrap_err().to_string();
        assert!(err.contains("only negated"), "got: {}", err);
    }

    #[test]
    fn a_rule_without_sid_is_rejected() {
        let err = parse_rule(r#"rule name:"nosid"; buffer:payload; content:"a";"#).unwrap_err().to_string();
        assert!(err.contains("sid"), "got: {}", err);
    }

    /// A pattern may contain the option separator, so quoting has to be
    /// respected when splitting.
    #[test]
    fn a_quoted_pattern_may_contain_semicolons() {
        let rule = parse_rule(r#"rule sid:12; name:"semi"; buffer:payload; content:"a;b;c";"#).unwrap();
        assert!(rule.content_matches(b"xxa;b;cxx"));
        assert!(!rule.content_matches(b"abc"));
    }

    /// `direction:any` must be stored under both concrete directions, not
    /// under `Any` as a third key — the same convention v1 needs, for the
    /// same reason.
    #[test]
    fn direction_any_is_expanded_to_both_concrete_directions() {
        let set = build(&[r#"rule sid:13; name:"either"; direction:any; buffer:payload; content:"z";"#]);
        let p = pkt(PROTO_TCP, [1, 1, 1, 1], 1, [2, 2, 2, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"z"), vec!["either"]);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToClient, b"z"), vec!["either"]);
    }

    /// Rules with no prefilterable literal still have to be evaluated.
    #[test]
    fn regex_only_rules_are_always_evaluated() {
        let set = build(&[r#"rule sid:14; name:"re"; buffer:dns.query; pcre:"[0-9a-f]{32}\.example\.com";"#]);
        let p = pkt(PROTO_UDP, [1, 1, 1, 1], 1, [2, 2, 2, 2], 53);
        let name = "0123456789abcdef0123456789abcdef.example.com";
        assert_eq!(hits(&set, &p, Buffer::DnsQuery, Direction::ToServer, name.as_bytes()), vec!["re"]);
    }

    #[test]
    fn cidr_matching_does_not_leak_across_address_families() {
        let m = IpMatch::parse("10.0.0.0/8").unwrap();
        assert!(m.matches(IpAddr::V4([10, 1, 1, 1])));
        assert!(!m.matches(IpAddr::V4([11, 1, 1, 1])));
        assert!(!m.matches(IpAddr::parse("2001:db8::1").unwrap()), "an IPv4 rule must not silently apply to IPv6");

        let m6 = IpMatch::parse("2001:db8::/32").unwrap();
        assert!(m6.matches(IpAddr::parse("2001:db8:1234::5").unwrap()));
        assert!(!m6.matches(IpAddr::parse("2001:dba8::5").unwrap()));
    }

    #[test]
    fn non_byte_aligned_prefixes_are_masked_correctly() {
        let m = IpMatch::parse("192.168.4.0/22").unwrap();
        assert!(m.matches(IpAddr::V4([192, 168, 4, 1])));
        assert!(m.matches(IpAddr::V4([192, 168, 7, 255])));
        assert!(!m.matches(IpAddr::V4([192, 168, 8, 1])));
    }
    // --- relative content positioning ------------------------------------

    /// `distance` is what turns "both strings somewhere" into "this
    /// string after that one", which is the difference between a rule
    /// that describes a payload and one that merely mentions it.
    #[test]
    fn distance_requires_the_second_content_to_follow_the_first() {
        let set = build(&[r#"rule sid:1; name:"ordered"; content:"AA"; content:"BB"; distance:0;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"xxAAyyBBzz"), vec!["ordered"]);
        // The same two strings in the wrong order: no match, where an
        // unordered rule would have fired.
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"xxBByyAAzz").is_empty());
    }

    #[test]
    fn distance_counts_from_the_end_of_the_previous_match() {
        let set = build(&[r#"rule sid:1; name:"gap"; content:"AA"; content:"BB"; distance:3;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"AAxxxBB"), vec!["gap"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"AAxBB").is_empty(), "too close");
        assert_eq!(
            hits(&set, &p, Buffer::Payload, Direction::ToServer, b"AAxxxxxxBB"),
            vec!["gap"],
            "distance is a minimum, not an exact position"
        );
    }

    /// `within` is the upper bound `distance` is not.
    #[test]
    fn within_bounds_how_far_past_the_previous_match_to_look() {
        let set = build(&[r#"rule sid:1; name:"near"; content:"AA"; content:"BB"; within:4;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"AAxBB"), vec!["near"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"AAxxxxxxxxBB").is_empty(), "past the window");
    }

    #[test]
    fn a_leading_relative_content_is_rejected_rather_than_reinterpreted() {
        // Suricata treats this as measuring from zero, which is exactly
        // what `offset` means — so the author meant one of two different
        // things and the file does not say which.
        let err = match parse_rule(r#"rule sid:1; name:"x"; content:"AA"; distance:4;"#) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a leading relative content should be refused"),
        };
        assert!(err.contains("nothing to be relative to"), "{}", err);
    }

    // --- byte_test / byte_jump -------------------------------------------

    #[test]
    fn byte_test_compares_a_binary_field() {
        let set = build(&[r#"rule sid:1; name:"big-len"; content:"|CA FE|"; byte_test:2,>,256,0,relative;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        // 0x0200 = 512, which is greater than 256.
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, &[0xCA, 0xFE, 0x02, 0x00]), vec!["big-len"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, &[0xCA, 0xFE, 0x00, 0x01]).is_empty());
    }

    #[test]
    fn byte_test_honours_endianness() {
        let big = build(&[r#"rule sid:1; name:"b"; content:"|CA|"; byte_test:2,=,258,0,relative,big;"#]);
        let little = build(&[r#"rule sid:2; name:"l"; content:"|CA|"; byte_test:2,=,258,0,relative,little;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        // 0x0102 big-endian is 258; the same bytes little-endian are 513.
        assert_eq!(hits(&big, &p, Buffer::Payload, Direction::ToServer, &[0xCA, 0x01, 0x02]), vec!["b"]);
        assert!(hits(&little, &p, Buffer::Payload, Direction::ToServer, &[0xCA, 0x01, 0x02]).is_empty());
        assert_eq!(hits(&little, &p, Buffer::Payload, Direction::ToServer, &[0xCA, 0x02, 0x01]), vec!["l"]);
    }

    /// Text mode is what reaches an ASCII length field, which is how
    /// every line-oriented protocol carries one.
    #[test]
    fn byte_test_can_read_ascii_numbers() {
        let set = build(&[r#"rule sid:1; name:"long-body"; content:"Content-Length: "; byte_test:6,>,1000,0,relative,string,dec;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"Content-Length: 65536\r\n"), vec!["long-body"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"Content-Length: 12\r\n").is_empty());
    }

    #[test]
    fn an_end_anchored_regex_matches_at_the_end_of_a_buffer_ending_in_crlf() {
        let set = build(&[r#"rule sid:1; name:"end"; buffer:http.header; content:"Host"; pcre:"(?-u)\x0d\x0a\x0d\x0a$";"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::HttpHeader, Direction::ToServer, b"Host: h\r\n\r\n"), vec!["end"]);
        assert!(hits(&set, &p, Buffer::HttpHeader, Direction::ToServer, b"Host: h\r\n\r\nx").is_empty());
    }

    #[test]
    fn percent_decoding_reads_escapes_and_leaves_the_rest() {
        let d = |t: Transform, s: &[u8]| t.apply(s).map(|v| String::from_utf8_lossy(&v).into_owned());
        assert_eq!(d(Transform::PercentDecode, b"/a/%2e%2E%2f"), Some("/a/../".into()));
        assert_eq!(d(Transform::PercentDecode, b"/a+b"), None, "a plus in a path is a plus, and nothing changes");
        assert_eq!(d(Transform::UrlDecode, b"a+b%20c"), Some("a b c".into()));
        // Not escapes: left as written rather than guessed at.
        assert_eq!(d(Transform::PercentDecode, b"100%"), None);
        assert_eq!(d(Transform::PercentDecode, b"%zz%4"), None);
        assert_eq!(d(Transform::PercentDecode, b"%41"), Some("A".into()));
    }

    #[test]
    fn header_lowercase_changes_names_and_not_values() {
        let out = Transform::HeaderLowercase.apply(b"Content-Length: 5\r\nX-Token: AbC\r\n\r\n").unwrap();
        assert_eq!(out, b"content-length: 5\r\nx-token: AbC\r\n\r\n");
        assert!(Transform::HeaderLowercase.apply(b"already: lower\r\n").is_none());
    }

    #[test]
    fn whitespace_transforms() {
        assert_eq!(Transform::StripWhitespace.apply(b"a b\t\r\nc").unwrap(), b"abc");
        assert_eq!(Transform::CompressWhitespace.apply(b"a  b\r\n\tc").unwrap(), b"a b c");
    }

    /// The reason groups have their own prefilter: the literal a rule
    /// needs exists only after the transform, so a prefilter that read
    /// the raw bytes would never let the rule be evaluated.
    #[test]
    fn a_transformed_rule_is_found_by_a_literal_that_exists_only_once_decoded() {
        let set = build(&[
            r#"rule sid:1; name:"decoded"; buffer:http.uri; transform:percent_decode; content:"../";"#,
            r#"rule sid:2; name:"raw"; buffer:http.uri; content:"../";"#,
        ]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/a/%2e%2e%2f"), vec!["decoded"]);
        let mut both = hits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/a/../");
        both.sort();
        assert_eq!(both, vec!["decoded", "raw"]);
    }

    #[test]
    fn a_transform_after_a_term_is_refused() {
        assert!(parse_any(r#"rule sid:1; name:"x"; buffer:http.uri; content:"a"; transform:url_decode;"#, &mut FlowbitRegistry::default()).is_err());
        assert!(parse_any(r#"rule sid:1; name:"x"; buffer:http.uri; transform:nonsense; content:"a";"#, &mut FlowbitRegistry::default()).is_err());
    }

    #[test]
    fn a_multi_buffer_rule_transforms_each_part_on_its_own() {
        let set = build(&[r#"rule sid:1; name:"both"; buffer:http.uri; transform:percent_decode; content:"../"; buffer:http.header; content:"Host";"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        assert!(hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/%2e%2e%2f", &mut bits).is_empty());
        assert_eq!(hits_with_bits(&set, &p, Buffer::HttpHeader, Direction::ToServer, b"Host: h\r\n\r\n", &mut bits), vec!["both"]);
    }

    fn tcp_with_flags(flags: u8) -> Packet {
        let mut p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        p.tcp_flags = flags;
        p
    }

    #[test]
    fn a_rule_can_be_about_nothing_but_a_packets_flags() {
        let set = build(&[r#"rule sid:1; name:"syn"; proto:tcp; buffer:packet; flags:S;"#]);
        let hit = |flags| hits(&set, &tcp_with_flags(flags), Buffer::PacketPayload, Direction::ToServer, b"");
        assert_eq!(hit(0x02), vec!["syn"]);
        assert!(hit(0x12).is_empty(), "SYN|ACK is not exactly SYN");
        assert!(hit(0x10).is_empty());
    }

    #[test]
    fn flag_modifiers_and_ignored_bits() {
        let test = |spec: &str, flags: u8| {
            let set = build(&[&format!(r#"rule sid:1; name:"f"; proto:tcp; buffer:packet; flags:{};"#, spec)]);
            !hits(&set, &tcp_with_flags(flags), Buffer::PacketPayload, Direction::ToServer, b"").is_empty()
        };
        assert!(test("+S", 0x12), "at least SYN");
        assert!(!test("+SA", 0x02));
        assert!(test("*SA", 0x10), "any of SYN, ACK");
        assert!(test("!S", 0x10), "SYN not set");
        assert!(!test("!S", 0x02));
        // The reserved bits named after the comma are left out of the comparison.
        assert!(test("S,12", 0x02 | 0x40 | 0x80));
        assert!(!test("S", 0x02 | 0x40));
        // A UDP datagram has no flags.
        let set = build(&[r#"rule sid:1; name:"f"; buffer:packet; flags:S;"#]);
        let udp = pkt(PROTO_UDP, [10, 0, 0, 1], 1, [10, 0, 0, 2], 2);
        assert!(hits(&set, &udp, Buffer::PacketPayload, Direction::ToServer, b"").is_empty());
    }

    #[test]
    fn icmp_type_and_code_are_header_tests() {
        let set = build(&[r#"rule sid:1; name:"echo"; buffer:packet; itype:8; icode:0;"#]);
        let mut p = pkt(PROTO_ICMP, [10, 0, 0, 1], 0, [10, 0, 0, 2], 0);
        p.icmp_type = 8;
        assert_eq!(hits(&set, &p, Buffer::PacketPayload, Direction::ToServer, b""), vec!["echo"]);
        p.icmp_code = 1;
        assert!(hits(&set, &p, Buffer::PacketPayload, Direction::ToServer, b"").is_empty());
        let mut tcp = pkt(PROTO_TCP, [10, 0, 0, 1], 1, [10, 0, 0, 2], 2);
        tcp.icmp_type = 8;
        assert!(hits(&set, &tcp, Buffer::PacketPayload, Direction::ToServer, b"").is_empty(), "a TCP segment is not ICMP");
    }

    #[test]
    fn a_rule_about_a_packet_still_needs_something_to_test() {
        assert!(parse_rule(r#"rule sid:1; name:"all"; buffer:packet;"#).is_err(), "nothing constrains it");
    }

    /// `within` is measured from the end of the previous match, not from
    /// where `distance` moved the start of the window.
    #[test]
    fn within_counts_from_the_previous_match_not_from_the_distance() {
        let set = build(&[r#"rule sid:1; name:"w"; content:"AA"; content:"BB"; distance:2; within:5;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        // "BB" ends 4 bytes after "AA": inside the 5.
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"AAxxBB"), vec!["w"]);
        // Ends 6 bytes after: past the 5, though it is within 5 of the *start* of the window.
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"AAxxxxBB").is_empty());
        // Begins before the distance allows.
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"AAxBB").is_empty());
    }

    #[test]
    fn a_negative_distance_looks_back_over_the_previous_match() {
        let set = build(&[r#"rule sid:1; name:"back"; content:"CD"; content:"BC"; distance:-3;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        // "CD" ends at 4; three bytes back is 1, where "BC" starts.
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"aBCDe"), vec!["back"]);
        // Never before the start of the buffer.
        let clamp = build(&[r#"rule sid:2; name:"clamp"; content:"AB"; content:"AB"; distance:-100;"#]);
        assert_eq!(hits(&clamp, &p, Buffer::Payload, Direction::ToServer, b"AB"), vec!["clamp"]);
    }

    #[test]
    fn a_case_insensitive_search_finds_any_spelling_at_any_position() {
        assert_eq!(find_nocase(b"xxABcx", b"abc"), Some(2));
        assert_eq!(find_nocase(b"abc", b"abc"), Some(0), "at the very start and end");
        assert_eq!(find_nocase(b"zzzaBC", b"abc"), Some(3), "flush with the end");
        assert_eq!(find_nocase(b"ab", b"abc"), None, "needle longer than the buffer");
        assert_eq!(find_nocase(b"", b"a"), None);
        // A first byte that has no case is searched for once, not twice.
        assert_eq!(find_nocase(b"x/A-B", b"/a-b"), Some(1));
        // A false start does not hide a later true one.
        assert_eq!(find_nocase(b"aaabAB", b"ab"), Some(2));
        assert_eq!(find_nocase(b"abxAb", b"axb"), None);
    }

    #[test]
    fn nocase_matches_binary_content_without_folding_non_ascii_bytes() {
        let set = build(&[r#"rule sid:1; name:"n"; content:"|de ad|Ab"; nocase;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xde\xadaB"), vec!["n"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xdf\xadaB").is_empty(), "0xde is not 0xdf");
    }

    #[test]
    fn a_rule_can_name_content_by_its_hash() {
        let set = build(&[r#"rule sid:1; name:"known-page"; buffer:http.response_body; transform:sha1; content:"|a9 99 3e 36 47 06 81 6a ba 3e 25 71 78 50 c2 6c 9c d0 d8 9d|";"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::HttpResponseBody, Direction::ToClient, b"abc"), vec!["known-page"]);
        assert!(hits(&set, &p, Buffer::HttpResponseBody, Direction::ToClient, b"abd").is_empty());
    }

    /// A width of zero means "every digit there", for a field whose width
    /// is not known in advance. It has no meaning for binary.
    #[test]
    fn a_zero_byte_count_reads_every_digit_of_a_text_number() {
        let set = build(&[r#"rule sid:1; name:"big"; content:"Length: "; byte_test:0,>,450,0,relative,string,dec;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"Length: 4500000
"), vec!["big"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"Length: 449
").is_empty());
        assert!(parse_rule(r#"rule sid:2; name:"x"; content:"a"; byte_test:0,>,1,0,relative;"#).is_err(), "binary needs a width");
    }

    /// A truncated buffer must fail the test rather than pass it: the
    /// opposite would make every byte_test rule fire on runt packets.
    #[test]
    fn a_byte_test_that_cannot_read_its_bytes_does_not_match() {
        let set = build(&[r#"rule sid:1; name:"t"; content:"|CA FE|"; byte_test:4,>,0,0,relative;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, &[0xCA, 0xFE, 0x01]).is_empty());
    }

    /// The point of byte_jump: follow a length field to what it points
    /// at, which is the only way to express a rule about a
    /// length-prefixed record.
    #[test]
    fn byte_jump_follows_a_length_field() {
        let set = build(&[r#"rule sid:1; name:"tlv"; content:"|AA|"; byte_jump:1,0,relative; content:"TARGET"; distance:0;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        // Marker, a length of 3, three bytes to skip, then the target.
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, &[0xAA, 0x03, b'x', b'y', b'z', b'T', b'A', b'R', b'G', b'E', b'T']), vec!["tlv"]);
        // Same bytes, a length of 5: the jump lands past the target.
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, &[0xAA, 0x05, b'x', b'y', b'z', b'T', b'A', b'R', b'G', b'E', b'T']).is_empty());
    }

    #[test]
    fn byte_jump_past_the_end_fails_rather_than_clamping() {
        let set = build(&[r#"rule sid:1; name:"j"; content:"|AA|"; byte_jump:1,0,relative; content:"X"; distance:0;"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, &[0xAA, 0xFF, b's', b'h', b'o', b'r', b't']).is_empty());
    }

    // --- flowbits --------------------------------------------------------

    fn stateful_pair() -> RuleSetV2 {
        build(&[
            r#"rule sid:1; name:"mark"; content:"HELLO"; flowbits:set,greeted; noalert;"#,
            r#"rule sid:2; name:"after"; content:"SECRET"; flowbits:isset,greeted;"#,
        ])
    }

    /// The shape ET uses constantly: one rule marks the connection, a
    /// second only fires on connections that were marked.
    #[test]
    fn a_flowbit_carries_state_from_one_packet_to_the_next() {
        let set = stateful_pair();
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();

        // The marking rule is `noalert`, so it reports nothing itself.
        assert!(hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"HELLO", &mut bits).is_empty());
        assert_eq!(hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"SECRET", &mut bits), vec!["after"]);
    }

    #[test]
    fn a_dependent_rule_stays_quiet_until_its_bit_is_set() {
        let set = stateful_pair();
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        assert!(hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"SECRET", &mut bits).is_empty());
    }

    /// State belongs to one connection. A second connection starts clean,
    /// which is the whole reason the bits live on the flow.
    #[test]
    fn flowbits_do_not_leak_between_connections() {
        let set = stateful_pair();
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut first = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"HELLO", &mut first);
        let mut second = FlowBits::default();
        assert!(hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"SECRET", &mut second).is_empty());
    }

    #[test]
    fn unset_and_toggle_do_what_they_say() {
        let set = build(&[
            r#"rule sid:1; name:"on"; content:"ON"; flowbits:set,b; noalert;"#,
            r#"rule sid:2; name:"off"; content:"OFF"; flowbits:unset,b; noalert;"#,
            r#"rule sid:3; name:"flip"; content:"FLIP"; flowbits:toggle,b; noalert;"#,
            r#"rule sid:4; name:"test"; content:"T"; flowbits:isset,b;"#,
        ]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"ON", &mut bits);
        assert_eq!(hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"T", &mut bits), vec!["test"]);
        hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"OFF", &mut bits);
        assert!(hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"T", &mut bits).is_empty());
        hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"FLIP", &mut bits);
        assert_eq!(hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"T", &mut bits), vec!["test"]);
    }

    /// A rule setting a bit must not change the answer for another rule
    /// evaluated in the same pass, or the outcome would depend on the
    /// order the prefilter happened to return candidates in.
    #[test]
    fn a_bit_set_in_one_pass_is_not_visible_to_that_same_pass() {
        let set = build(&[
            r#"rule sid:1; name:"setter"; content:"AB"; flowbits:set,b; noalert;"#,
            r#"rule sid:2; name:"tester"; content:"AB"; flowbits:isset,b;"#,
        ]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        assert!(
            hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"AB", &mut bits).is_empty(),
            "the tester must not see the setter's effect yet"
        );
        assert_eq!(
            hits_with_bits(&set, &p, Buffer::Payload, Direction::ToServer, b"AB", &mut bits),
            vec!["tester"],
            "but the next pass sees it"
        );
    }

    /// A datagram has no connection to carry state, so `isnotset` holds
    /// and `isset` cannot. That is an accurate reading, not a limitation.
    #[test]
    fn without_flow_state_isset_is_false_and_isnotset_is_true() {
        let set = build(&[
            r#"rule sid:1; name:"needs-bit"; content:"X"; flowbits:isset,b;"#,
            r#"rule sid:2; name:"needs-no-bit"; content:"X"; flowbits:isnotset,b;"#,
        ]);
        let p = pkt(PROTO_UDP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 53);
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"X"), vec!["needs-no-bit"]);
    }

    /// A rule with no content normally matches everything and is refused
    /// — but `isset` is itself a strong condition, and ET relies on
    /// exactly this shape.
    #[test]
    fn a_flowbit_condition_alone_is_enough_to_make_a_rule_specific() {
        assert!(parse_rule(r#"rule sid:1; name:"state-only"; flowbits:isset,b;"#).is_ok());
        assert!(
            parse_rule(r#"rule sid:2; name:"nothing"; flowbits:set,b;"#).is_err(),
            "setting a bit is an effect, not a condition"
        );
    }

    /// Bits are only allocated by a flow that actually sets one; every
    /// other connection pays a null pointer.
    #[test]
    fn flowbit_storage_is_not_allocated_until_something_sets_a_bit() {
        let mut bits = FlowBits::default();
        assert!(bits.is_empty());
        bits.set(3, false, 64);
        assert!(bits.is_empty(), "clearing an unset bit is already true and must not allocate");
        bits.set(3, true, 64);
        assert!(!bits.is_empty());
        assert!(bits.is_set(3) && !bits.is_set(4));
    }

    // --- multi-buffer rules ----------------------------------------------

    fn two_buffer_set() -> RuleSetV2 {
        build(&[r#"rule sid:1; name:"uri-and-agent"; proto:tcp; buffer:http.uri; content:"/admin"; buffer:http.user_agent; content:"sqlmap";"#])
    }

    /// The whole point: each part is checked when *its* buffer is, and the
    /// rule fires only when every part has matched on the connection.
    #[test]
    fn a_multi_buffer_rule_fires_only_when_every_buffer_has_matched() {
        let set = two_buffer_set();
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        assert!(hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/admin/login", &mut bits).is_empty(), "one buffer is not enough");
        assert_eq!(hits_with_bits(&set, &p, Buffer::HttpUserAgent, Direction::ToServer, b"sqlmap/1.7", &mut bits), vec!["uri-and-agent"]);
    }

    #[test]
    fn multi_buffer_parts_may_arrive_in_either_order() {
        let set = two_buffer_set();
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        assert!(hits_with_bits(&set, &p, Buffer::HttpUserAgent, Direction::ToServer, b"sqlmap", &mut bits).is_empty());
        assert_eq!(hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/admin", &mut bits), vec!["uri-and-agent"]);
    }

    #[test]
    fn a_multi_buffer_rule_fires_once_per_connection() {
        let set = two_buffer_set();
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/admin", &mut bits);
        assert_eq!(hits_with_bits(&set, &p, Buffer::HttpUserAgent, Direction::ToServer, b"sqlmap", &mut bits).len(), 1);
        assert!(hits_with_bits(&set, &p, Buffer::HttpUserAgent, Direction::ToServer, b"sqlmap", &mut bits).is_empty(), "already reported on this flow");
    }

    /// Progress belongs to one connection, exactly as flowbits do.
    #[test]
    fn multi_buffer_progress_does_not_leak_between_connections() {
        let set = two_buffer_set();
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut first = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/admin", &mut first);
        let mut second = FlowBits::default();
        assert!(hits_with_bits(&set, &p, Buffer::HttpUserAgent, Direction::ToServer, b"sqlmap", &mut second).is_empty());
    }

    /// A request URI is only ever seen going to the server and a status
    /// code only coming back, so one rule can span both without the
    /// rule's own `flow:` being forced onto either.
    #[test]
    fn parts_are_pinned_to_the_side_their_buffer_exists_on() {
        let set = build(&[r#"rule sid:2; name:"req-and-resp"; proto:tcp; buffer:http.uri; content:"/download"; buffer:http.stat_code; content:"200";"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        assert!(hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/download/x", &mut bits).is_empty());
        assert_eq!(hits_with_bits(&set, &p, Buffer::HttpStatCode, Direction::ToClient, b"200", &mut bits), vec!["req-and-resp"]);
        // The status code checked on the wrong side is not a match.
        let mut wrong = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/download/x", &mut wrong);
        assert!(hits_with_bits(&set, &p, Buffer::HttpStatCode, Direction::ToServer, b"200", &mut wrong).is_empty());
    }

    /// A datagram has no connection to record progress on.
    #[test]
    fn a_multi_buffer_rule_cannot_complete_without_flow_state() {
        let set = two_buffer_set();
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        assert!(hits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/admin").is_empty());
        assert!(hits(&set, &p, Buffer::HttpUserAgent, Direction::ToServer, b"sqlmap").is_empty());
    }

    #[test]
    fn distance_stays_within_its_own_buffer() {
        let set = build(&[r#"rule sid:3; name:"d"; buffer:http.uri; content:"a"; content:"b"; distance:0; buffer:http.header; content:"H";"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let mut bits = FlowBits::default();
        assert!(hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"b then a", &mut bits).is_empty(), "wrong order within the part");
        assert!(hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"a then b", &mut bits).is_empty(), "the header part is still outstanding");
        assert_eq!(hits_with_bits(&set, &p, Buffer::HttpHeader, Direction::ToServer, b"H", &mut bits), vec!["d"]);
    }

    /// A rule with no positive content anywhere would match everything.
    #[test]
    fn a_rule_with_no_positive_part_is_refused() {
        let mut reg = FlowbitRegistry::default();
        assert!(parse_any(r#"rule sid:4; name:"x"; buffer:http.uri; !content:"a"; buffer:http.header; !content:"b";"#, &mut reg).is_err());
    }

    /// "There is no Accept header" is a claim about a complete, per-message
    /// buffer, and a large family of ET rules is exactly that.
    #[test]
    fn a_part_may_say_only_what_its_buffer_must_not_contain() {
        let set = build(&[r#"rule sid:12; name:"no-accept"; proto:tcp; buffer:http.uri; content:"/gate.php"; buffer:http.header_names; !content:"|0d 0a|Accept|0d 0a|";"#]);
        let p = tcp_pkt();
        let mut with_accept = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/gate.php", &mut with_accept);
        assert!(
            hits_with_bits(&set, &p, Buffer::HttpHeaderNames, Direction::ToServer, b"\r\nHost\r\nAccept\r\n\r\n", &mut with_accept).is_empty(),
            "the header is present, so the negation fails"
        );

        let mut without = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/gate.php", &mut without);
        assert_eq!(hits_with_bits(&set, &p, Buffer::HttpHeaderNames, Direction::ToServer, b"\r\nHost\r\n\r\n", &mut without), vec!["no-accept"]);
    }

    /// If the buffer never appears there is nothing to have failed to
    /// contain, so the rule stays quiet rather than firing on silence.
    #[test]
    fn a_negation_only_part_needs_its_buffer_to_exist() {
        let set = build(&[r#"rule sid:13; name:"no-ua"; proto:tcp; buffer:http.uri; content:"/x"; buffer:http.user_agent; !content:"Mozilla";"#]);
        let mut bits = FlowBits::default();
        assert!(hits_with_bits(&set, &tcp_pkt(), Buffer::HttpUri, Direction::ToServer, b"/x", &mut bits).is_empty());
    }

    #[test]
    fn a_negation_only_part_is_refused_on_the_raw_payload() {
        let mut reg = FlowbitRegistry::default();
        assert!(parse_any(r#"rule sid:14; name:"x"; buffer:http.uri; content:"a"; buffer:payload; !content:"b";"#, &mut reg).is_err());
    }

    #[test]
    fn a_leading_relative_content_in_a_later_part_is_refused() {
        let mut reg = FlowbitRegistry::default();
        assert!(parse_any(r#"rule sid:5; name:"x"; buffer:http.uri; content:"a"; buffer:http.header; content:"b"; distance:1;"#, &mut reg).is_err());
    }

    #[test]
    fn a_composite_counts_as_one_rule() {
        let set = build(&[r#"rule sid:6; name:"a"; buffer:http.uri; content:"x"; buffer:http.header; content:"y";"#, r#"rule sid:7; name:"b"; content:"z";"#]);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_part_without_its_composite_is_refused_at_load() {
        let mut reg = FlowbitRegistry::default();
        let parsed = parse_any(r#"rule sid:8; name:"x"; buffer:http.uri; content:"a"; buffer:http.header; content:"b";"#, &mut reg).unwrap();
        let Parsed::Composite { parts, .. } = parsed else { panic!("expected a composite") };
        assert!(RuleSetV2::build_full(parts, Vec::new(), reg).is_err());
    }

    // --- resumable regexes (PCRE's R flag) ---------------------------------

    fn tcp_pkt() -> Packet {
        pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80)
    }

    fn matches_payload(set: &RuleSetV2, data: &[u8]) -> bool {
        !hits(set, &tcp_pkt(), Buffer::Payload, Direction::ToServer, data).is_empty()
    }

    /// The point of `R`: the regex looks only *after* the previous match.
    #[test]
    fn a_resumed_regex_looks_only_past_the_previous_match() {
        let set = build(&[r#"rule sid:1; name:"r"; content:"AA"; pcre:"B+"; relative;"#]);
        assert!(matches_payload(&set, b"xxAAyyB"), "a B after the AA");
        assert!(!matches_payload(&set, b"BBxxAAyy"), "the only Bs are before it");
    }

    /// Resuming is a start *offset* into the whole buffer, not a slice of
    /// it. Slicing would give `\bbar` a word boundary at the cut that the
    /// real stream does not have.
    #[test]
    fn a_resumed_regex_sees_the_bytes_before_where_it_starts() {
        let set = build(&[r#"rule sid:2; name:"r"; content:"foo"; pcre:"\bbar"; relative;"#]);
        assert!(!matches_payload(&set, b"foobar"), "no boundary between foo and bar");
        assert!(matches_payload(&set, b"foo bar"), "a space makes one");
    }

    /// `^` means the true start of the subject, however far in the search
    /// began.
    #[test]
    fn a_resumed_anchor_does_not_match_mid_buffer() {
        let set = build(&[r#"rule sid:3; name:"r"; content:"AA"; pcre:"^B"; relative;"#]);
        assert!(!matches_payload(&set, b"AAB"));
    }

    #[test]
    fn relative_on_a_literal_is_refused() {
        assert!(parse_rule(r#"rule sid:4; name:"x"; content:"A"; content:"B"; relative;"#).is_err());
    }

    #[test]
    fn a_leading_resumed_regex_is_refused() {
        assert!(parse_rule(r#"rule sid:5; name:"x"; pcre:"B"; relative;"#).is_err());
    }

    // --- bounded backtracking ---------------------------------------------

    #[test]
    fn negative_lookahead_is_expressible() {
        let set = build(&[r#"rule sid:6; name:"la"; content:"foo"; pcre_bt:"foo(?!bar)";"#]);
        assert!(matches_payload(&set, b"foobaz"));
        assert!(!matches_payload(&set, b"foobar"));
    }

    #[test]
    fn a_backreference_is_expressible() {
        let set = build(&[r#"rule sid:7; name:"br"; content:"b"; pcre_bt:"(a+)b\1";"#]);
        assert!(matches_payload(&set, b"xaabaa"));
        // "aba" would match with a one-letter capture, so the negative case
        // must have no `a` after the b at all.
        assert!(!matches_payload(&set, b"xaabx"));
    }

    /// Bytes and characters must mean the same thing, or a rule's `\xFF`
    /// would silently never match the byte it names.
    #[test]
    fn the_backtracking_engine_matches_non_ascii_bytes() {
        let set = build(&[r#"rule sid:8; name:"hi"; content:"x"; pcre_bt:"\xFFx(?!y)";"#]);
        assert!(matches_payload(&set, &[0xFF, b'x']));
        assert!(!matches_payload(&set, &[0xFF, b'x', b'y']));
    }

    /// Offsets come back in bytes of the *buffer*, not of the widened
    /// text, so a term after it starts in the right place.
    #[test]
    fn offsets_survive_the_widening_of_high_bytes() {
        let set = build(&[r#"rule sid:9; name:"o"; content:"x"; pcre_bt:"x(?!y)"; content:"z"; distance:0;"#]);
        assert!(matches_payload(&set, &[0xFF, 0xFF, b'x', b'z']));
        // `distance:0` is a minimum, so a gap before the z is fine.
        assert!(matches_payload(&set, &[0xFF, 0xFF, b'x', b'q', b'z']));
        assert!(!matches_payload(&set, &[0xFF, 0xFF, b'x', b'q']), "no z after the match");
        assert!(matches_payload(&set, &[0xFF, b'x', b'z', 0xFF]));
    }

    /// A hostile input must not be able to hold a worker: the step limit
    /// abandons the attempt, and the abandonment is counted.
    #[test]
    fn a_catastrophic_pattern_is_abandoned_not_run_to_completion() {
        let set = build(&[r#"rule sid:10; name:"boom"; content:"a"; pcre_bt:"^(a+)+\1b";"#]);
        let before = backtrack_limit_hits();
        let started = std::time::Instant::now();
        let mut data = vec![b'a'; 40];
        data.push(b'!');
        assert!(!matches_payload(&set, &data));
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "must not run away");
        assert!(backtrack_limit_hits() > before, "the abandonment must be counted");
    }

    /// If "did not match" were the answer for a pattern that gave up, a
    /// negated one would fire on exactly the input built to defeat it.
    #[test]
    fn a_negated_pattern_that_gives_up_does_not_fire() {
        let set = build(&[r#"rule sid:11; name:"neg"; content:"a"; !pcre_bt:"^(a+)+\1b";"#]);
        let mut data = vec![b'a'; 40];
        data.push(b'!');
        assert!(!matches_payload(&set, &data));
    }

    // --- length tests, isdataat and dsize ------------------------------------

    #[test]
    fn length_tests_parse_every_form_suricata_writes() {
        assert_eq!(LenTest::parse("12").unwrap(), LenTest::Eq(12));
        assert_eq!(LenTest::parse("<5").unwrap(), LenTest::Lt(5));
        assert_eq!(LenTest::parse(">5").unwrap(), LenTest::Gt(5));
        assert_eq!(LenTest::parse("< 5").unwrap(), LenTest::Lt(5), "ET writes a space after the operator");
        assert_eq!(LenTest::parse("<=5").unwrap(), LenTest::Le(5));
        assert_eq!(LenTest::parse(">=5").unwrap(), LenTest::Ge(5));
        assert_eq!(LenTest::parse("3<>9").unwrap(), LenTest::Between(3, 9));
        assert!(LenTest::parse("abc").is_err());
        assert!(LenTest::parse("9<>3").is_err(), "an empty range is a mistake, not a rule that never fires");
    }

    /// `A<>B` is exclusive at both ends, as Suricata reads it. An inclusive
    /// reading would match two lengths the rule does not mean.
    #[test]
    fn a_range_is_exclusive_at_both_ends() {
        let t = LenTest::parse("10<>20").unwrap();
        assert!(!t.holds(10) && t.holds(11) && t.holds(19) && !t.holds(20));
    }

    #[test]
    fn bsize_tests_the_length_of_its_own_buffer() {
        let set = build(&[r#"rule sid:20; name:"len"; proto:tcp; buffer:http.uri; content:"/a"; bsize:<8;"#]);
        let p = tcp_pkt();
        assert_eq!(hits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/a/b"), vec!["len"]);
        assert!(hits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/a/long/uri").is_empty(), "11 bytes is not under 8");
    }

    /// The reason to implement it generally: `bsize:N` with a content that
    /// does not span the whole buffer, which the translator could not
    /// express before.
    #[test]
    fn bsize_with_a_content_shorter_than_the_buffer() {
        let set = build(&[r#"rule sid:21; name:"exact"; proto:tcp; buffer:http.uri; content:"/a"; bsize:6;"#]);
        let p = tcp_pkt();
        assert_eq!(hits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/a/xyz"), vec!["exact"]);
        assert!(hits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/a/xy").is_empty());
    }

    #[test]
    fn a_length_only_part_constrains_a_multi_buffer_rule() {
        let set = build(&[r#"rule sid:22; name:"cnc"; proto:tcp; buffer:http.method; content:"POST"; buffer:http.uri; bsize:12;"#]);
        let p = tcp_pkt();
        let mut bits = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::HttpMethod, Direction::ToServer, b"POST", &mut bits);
        assert_eq!(hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/mobile-home", &mut bits), vec!["cnc"]);
        let mut wrong = FlowBits::default();
        hits_with_bits(&set, &p, Buffer::HttpMethod, Direction::ToServer, b"POST", &mut wrong);
        assert!(hits_with_bits(&set, &p, Buffer::HttpUri, Direction::ToServer, b"/other", &mut wrong).is_empty());
    }

    /// `isdataat:!4,relative` after a content: at most four bytes follow.
    #[test]
    fn a_negated_isdataat_pins_a_value_to_the_end() {
        let set = build(&[r#"rule sid:23; name:"tail"; content:"KEY="; isdataat:!4,relative;"#]);
        let p = tcp_pkt();
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"xxKEY=abcd"), vec!["tail"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"xxKEY=abcde").is_empty(), "five bytes follow");
    }

    #[test]
    fn isdataat_says_whether_a_byte_exists_that_far_on() {
        let set = build(&[r#"rule sid:24; name:"more"; content:"HDR"; isdataat:4,relative;"#]);
        let p = tcp_pkt();
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"HDR12345"), vec!["more"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"HDR1234").is_empty(), "index 4 is past the end");
    }

    #[test]
    fn an_absolute_isdataat_measures_from_the_start() {
        let set = build(&[r#"rule sid:25; name:"abs"; content:"A"; isdataat:!10;"#]);
        let p = tcp_pkt();
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"A123456789"), vec!["abs"], "exactly ten bytes: nothing at index 10");
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"A1234567890").is_empty());
    }

    #[test]
    fn a_variable_in_isdataat_is_refused_rather_than_read_as_zero() {
        let mut reg = FlowbitRegistry::default();
        assert!(parse_any(r#"rule sid:26; name:"x"; content:"A"; isdataat:!length,relative;"#, &mut reg).is_err());
    }

    /// `dsize` is about the packet, not the stream.
    #[test]
    fn dsize_tests_the_payload_of_the_packet_being_examined() {
        let set = build(&[r#"rule sid:27; name:"big"; proto:udp; dsize:>10; content:"x";"#]);
        let mut p = pkt(PROTO_UDP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 53);
        p.payload_len = 20;
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"xxxx"), vec!["big"]);
        p.payload_len = 4;
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"xxxx").is_empty(), "the packet is small, whatever the buffer holds");
    }

    fn tcp() -> Packet {
        pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80)
    }

    /// The commonest use: a length field says how long the next field is.
    #[test]
    fn an_extracted_length_can_bound_the_next_content() {
        let set = build(&[r#"rule sid:1; name:"len"; content:"|AA|"; byte_extract:1,0,n,relative; content:"END"; distance:0; within:n;"#]);
        let p = tcp();
        // After 0xAA comes a limit of 6, and END must end within 6 bytes of it.
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xAA\x06xxEND"), vec!["len"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xAA\x06xxxEND").is_empty(), "ends past the extracted limit");
    }

    #[test]
    fn a_variable_can_be_the_value_of_a_byte_test() {
        // The second byte must not equal the first: a rule about a repeated byte.
        let set = build(&[r#"rule sid:1; name:"differs"; content:"|08|"; byte_extract:1,0,first,relative; byte_test:1,!=,first,1,relative;"#]);
        let p = tcp();
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\x08\x05\x06"), vec!["differs"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\x08\x05\x05").is_empty());
    }

    #[test]
    fn byte_math_computes_a_variable_and_isdataat_can_read_it() {
        // "the record claims N bytes plus 2, and that much data is not there"
        let set = build(&[r#"rule sid:1; name:"truncated"; content:"|A1|"; byte_math:bytes 1, offset 0, oper +, rvalue 2, result length, relative; isdataat:!length,relative;"#]);
        let p = tcp();
        assert_eq!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xA1\x03xxxx"), vec!["truncated"]);
        assert!(hits(&set, &p, Buffer::Payload, Direction::ToServer, b"\xA1\x03xxxxxxxx").is_empty());
    }

    #[test]
    fn using_a_variable_nothing_defined_is_an_error() {
        assert!(parse_rule(r#"rule sid:1; name:"x"; content:"a"; content:"b"; within:nope;"#).is_err());
        assert!(parse_rule(r#"rule sid:1; name:"x"; content:"a"; byte_test:1,>,nope,0;"#).is_err());
    }

    #[test]
    fn an_unset_variable_means_the_term_did_not_match() {
        // The extraction cannot read its byte, so its variable stays unset.
        let set = build(&[r#"rule sid:1; name:"x"; content:"|AA|"; byte_extract:1,5,n,relative; content:"Z"; within:n;"#]);
        assert!(hits(&set, &tcp(), Buffer::Payload, Direction::ToServer, b"\xAAZ").is_empty());
    }

    #[test]
    fn base64_decoding_is_tolerant_and_stops_at_padding() {
        assert_eq!(base64_decode(b"aGVsbG8="), b"hello");
        assert_eq!(base64_decode(b"aGVs\r\nbG8="), b"hello", "line breaks are skipped");
        assert_eq!(base64_decode(b"aGVsbG8"), b"hello", "missing padding is tolerated");
        assert_eq!(base64_decode(b"aGVsbG8=trailing"), b"hello", "nothing after padding");
        assert_eq!(base64_decode(b""), b"");
        assert_eq!(base64_decode(b"++//"), vec![0xfb, 0xef, 0xff]);
    }

    #[test]
    fn a_rule_can_match_inside_decoded_content() {
        let set = build(&[r#"rule sid:1; name:"b64"; buffer:http.response_body; content:"data="; base64_decode:bytes 0,relative; content:"secret";"#]);
        let p = tcp();
        // "c2VjcmV0" is base64 for "secret".
        assert_eq!(hits(&set, &p, Buffer::HttpResponseBody, Direction::ToClient, b"data=c2VjcmV0"), vec!["b64"]);
        assert!(hits(&set, &p, Buffer::HttpResponseBody, Direction::ToClient, b"data=bm90aGluZw==").is_empty());
        // The plain text is not enough: the term reads decoded bytes.
        assert!(hits(&set, &p, Buffer::HttpResponseBody, Direction::ToClient, b"data=secret").is_empty());
    }

    /// The prefilter sees the raw buffer, so a literal that exists only
    /// once decoded must not be used to key it.
    #[test]
    fn a_literal_after_a_decode_does_not_key_the_prefilter() {
        let set = build(&[r#"rule sid:1; name:"b64"; buffer:http.response_body; base64_decode:bytes 0; content:"secret";"#]);
        assert_eq!(hits(&set, &tcp(), Buffer::HttpResponseBody, Direction::ToClient, b"c2VjcmV0"), vec!["b64"]);
    }

    fn scan_all(set: &RuleSetV2, chunks: &[&[u8]]) -> Vec<String> {
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let (mut scan, mut scratch, mut out) = (StreamScan::default(), MatchScratch::default(), Vec::new());
        let mut stream = Vec::new();
        for c in chunks {
            stream.extend_from_slice(c);
            set.check_stream(&p, Buffer::Payload, Direction::ToServer, &stream, &mut scan, &mut scratch, None, &mut out);
        }
        let mut names: Vec<String> = out.into_iter().map(|h| h.name).collect();
        names.sort();
        names.dedup();
        names
    }

    /// The optimisation must not change the answer: any way of cutting a
    /// stream into segments finds what scanning it whole finds.
    #[test]
    fn scanning_incrementally_finds_what_scanning_the_whole_stream_finds() {
        let set = build(&[
            r#"rule sid:1; name:"exact"; content:"NEEDLE";"#,
            r#"rule sid:2; name:"nocase"; content:"secret"; nocase;"#,
            r#"rule sid:3; name:"two"; content:"AAAA"; content:"BBBB"; distance:0;"#,
        ]);
        let whole: &[u8] = b"xx NEEDLE yy SeCrEt zz AAAA gap BBBB end";
        let baseline = scan_all(&set, &[whole]);
        assert_eq!(baseline, ["exact", "nocase", "two"]);
        // Every possible cut into two, and one-byte-at-a-time.
        for cut in 0..=whole.len() {
            assert_eq!(scan_all(&set, &[&whole[..cut], &whole[cut..]]), baseline, "cut at {}", cut);
        }
        let bytes: Vec<&[u8]> = whole.chunks(1).collect();
        assert_eq!(scan_all(&set, &bytes), baseline);
    }

    #[test]
    fn a_literal_straddling_two_segments_is_found_by_the_overlap() {
        let set = build(&[r#"rule sid:1; name:"straddle"; content:"ABCDEFGH";"#]);
        assert_eq!(scan_all(&set, &[b"...ABCD", b"EFGH..."]), ["straddle"]);
    }

    #[test]
    fn a_stream_that_shrinks_is_scanned_afresh() {
        let set = build(&[r#"rule sid:1; name:"n"; content:"NEEDLE";"#]);
        let p = pkt(PROTO_TCP, [10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
        let (mut scan, mut scratch, mut out) = (StreamScan::default(), MatchScratch::default(), Vec::new());
        set.check_stream(&p, Buffer::Payload, Direction::ToServer, b"aaaaaaaaaaaaaaaa", &mut scan, &mut scratch, None, &mut out);
        set.check_stream(&p, Buffer::Payload, Direction::ToServer, b"NEEDLE", &mut scan, &mut scratch, None, &mut out);
        assert_eq!(out.len(), 1);
    }

}
