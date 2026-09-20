//! The decode layer: link-layer dispatch, IP fragment reassembly, and
//! the per-packet payload cap.
//!
//! Everything here runs on the capture thread, before sharding, and is
//! therefore single-threaded and lock-free by construction. That
//! placement isn't incidental: fragment reassembly has to happen before
//! a packet can be assigned to a worker, because until a datagram is
//! whole it has no ports — and `AnomalyEngine`'s port-scan tracking and
//! `FlowTable`'s connection keys both need ports to mean something.
//!
//! The other reason this module exists at all is honesty. Every way a
//! frame can fail to decode used to collapse into a single `false`
//! return that nobody counted, so a sensor watching traffic it couldn't
//! parse produced exactly the same output as a sensor watching a quiet
//! network: nothing. [`DecodeStats`] breaks that silence into named
//! reasons, reported at shutdown and on every replay.

use std::time::SystemTime;

use crate::packet::{
    ethernet_payload, ethernet_vlan_id, ipv4_fragment, ipv6_fragment, parse_ip_by_ethertype, IpAddr, Packet, MAX_INSPECT_BYTES,
};

/// Default `-payload-cap`: the whole array, i.e. don't truncate below
/// what a full Ethernet frame can carry.
pub const DEFAULT_PAYLOAD_CAP: usize = MAX_INSPECT_BYTES;

// =======================================================================
// Link types
// =======================================================================

/// The link-layer encapsulations ARGUS knows how to strip.
///
/// Previously there was no such concept: a 14-byte Ethernet header was
/// assumed unconditionally, and `Capture::get_datalink()` was never
/// consulted. On anything else — a Linux `any`-interface capture
/// (LINUX_SLL), a raw-IP tunnel capture, a BSD loopback capture — every
/// single frame failed to decode, and the result was indistinguishable
/// from a clean network. That's the whole reason the `Unsupported`
/// variant carries its number: an unparseable capture should say which
/// link type defeated it, not just decline to work.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkType {
    /// DLT_EN10MB (1) — plus any stack of VLAN tags.
    Ethernet,
    /// DLT_RAW (101) / DLT_IPV4 (228) / DLT_IPV6 (229): a bare IP
    /// datagram with no link header at all.
    RawIp,
    /// DLT_NULL (0): 4-byte BSD loopback header, host byte order.
    Null,
    /// DLT_LOOP (108): the same, but always big-endian.
    Loop,
    /// DLT_LINUX_SLL (113): 16-byte cooked header, ethertype at 14.
    LinuxSll,
    /// DLT_LINUX_SLL2 (276): 20-byte cooked header, ethertype at 0.
    LinuxSll2,
    Unsupported(i32),
}

impl LinkType {
    pub fn from_dlt(dlt: i32) -> LinkType {
        match dlt {
            1 => LinkType::Ethernet,
            101 | 228 | 229 => LinkType::RawIp,
            0 => LinkType::Null,
            108 => LinkType::Loop,
            113 => LinkType::LinuxSll,
            276 => LinkType::LinuxSll2,
            other => LinkType::Unsupported(other),
        }
    }

    pub fn name(&self) -> String {
        match self {
            LinkType::Ethernet => "Ethernet".to_string(),
            LinkType::RawIp => "raw IP".to_string(),
            LinkType::Null => "BSD loopback (DLT_NULL)".to_string(),
            LinkType::Loop => "BSD loopback (DLT_LOOP)".to_string(),
            LinkType::LinuxSll => "Linux cooked (SLL)".to_string(),
            LinkType::LinuxSll2 => "Linux cooked v2 (SLL2)".to_string(),
            LinkType::Unsupported(n) => format!("unsupported DLT {}", n),
        }
    }

    pub fn is_supported(&self) -> bool {
        !matches!(self, LinkType::Unsupported(_))
    }
}

/// AF_INET / AF_INET6 as they appear in a BSD loopback header. AF_INET
/// is 2 everywhere; AF_INET6 is famously not (24 on macOS, 28 on
/// FreeBSD, 10 on Linux), so all three are accepted rather than picking
/// one and being wrong on the other two platforms.
fn af_to_ethertype(af: u32) -> Option<u16> {
    match af {
        2 => Some(0x0800),
        10 | 24 | 28 | 30 => Some(0x86DD),
        _ => None,
    }
}

// =======================================================================
// Outcomes and statistics
// =======================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decoded {
    /// `out` holds a complete packet ready for detection.
    Packet,
    /// A fragment was absorbed into the reassembly table; there is
    /// nothing to inspect yet, and the caller should not forward `out`.
    Buffered,
    /// Nothing usable came out of this frame. Already counted in
    /// [`DecodeStats`] under the specific reason.
    Skipped,
}

/// Why frames didn't turn into packets, counted separately rather than
/// lumped together, because the answers mean completely different
/// things: "this link is full of ARP" is normal, "every frame is
/// VLAN-tagged and I can't read them" is a misconfigured sensor, and
/// "fragments are being dropped" is either an attack or a tuning
/// problem.
#[derive(Default, Clone, Copy, Debug)]
pub struct DecodeStats {
    pub decoded: u64,
    pub vlan_tagged: u64,
    pub fragments_seen: u64,
    pub datagrams_reassembled: u64,
    pub fragments_dropped: u64,
    pub incomplete_datagrams_expired: u64,
    /// Layers of tunnel encapsulation stripped.
    pub tunnelled: u64,
    /// Packets whose payload is IPsec ESP: visible, but encrypted, so
    /// there is nothing to descend into.
    pub esp_encrypted: u64,
    pub non_ip: u64,
    pub short_frame: u64,
    pub unsupported_link: u64,
    pub bad_ip_header: u64,
}

impl DecodeStats {
    /// Sums two decoders' totals, for a capture spread over several
    /// interfaces. Every field counts independent events.
    pub fn merged(self, o: DecodeStats) -> DecodeStats {
        DecodeStats {
            decoded: self.decoded + o.decoded,
            vlan_tagged: self.vlan_tagged + o.vlan_tagged,
            fragments_seen: self.fragments_seen + o.fragments_seen,
            datagrams_reassembled: self.datagrams_reassembled + o.datagrams_reassembled,
            fragments_dropped: self.fragments_dropped + o.fragments_dropped,
            incomplete_datagrams_expired: self.incomplete_datagrams_expired + o.incomplete_datagrams_expired,
            tunnelled: self.tunnelled + o.tunnelled,
            esp_encrypted: self.esp_encrypted + o.esp_encrypted,
            non_ip: self.non_ip + o.non_ip,
            short_frame: self.short_frame + o.short_frame,
            unsupported_link: self.unsupported_link + o.unsupported_link,
            bad_ip_header: self.bad_ip_header + o.bad_ip_header,
        }
    }

    /// Frames that produced no packet, for whatever reason.
    pub fn undecoded(&self) -> u64 {
        self.non_ip + self.short_frame + self.unsupported_link + self.bad_ip_header
    }

    /// A one-line summary, or `None` when there is nothing to report
    /// beyond the plain decoded count.
    pub fn detail(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.non_ip > 0 {
            parts.push(format!("{} non-IP", self.non_ip));
        }
        if self.short_frame > 0 {
            parts.push(format!("{} truncated", self.short_frame));
        }
        if self.unsupported_link > 0 {
            parts.push(format!("{} unsupported link header", self.unsupported_link));
        }
        if self.bad_ip_header > 0 {
            parts.push(format!("{} malformed IP header", self.bad_ip_header));
        }
        if self.vlan_tagged > 0 {
            parts.push(format!("{} VLAN-tagged", self.vlan_tagged));
        }
        if self.tunnelled > 0 {
            parts.push(format!("{} tunnel layers stripped", self.tunnelled));
        }
        if self.esp_encrypted > 0 {
            parts.push(format!("{} IPsec ESP (encrypted, not inspectable)", self.esp_encrypted));
        }
        if self.fragments_seen > 0 {
            parts.push(format!("{} fragments -> {} datagrams reassembled", self.fragments_seen, self.datagrams_reassembled));
        }
        if self.fragments_dropped > 0 {
            parts.push(format!("{} fragments dropped", self.fragments_dropped));
        }
        if self.incomplete_datagrams_expired > 0 {
            parts.push(format!("{} incomplete datagrams expired", self.incomplete_datagrams_expired));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    }
}

// =======================================================================
// Fragment reassembly
// =======================================================================

/// Bounds on the reassembly table. Every one of these exists because
/// fragmentation is attacker-controlled: an unbounded table is a
/// trivially exploitable memory sink (send first-fragments that never
/// complete), which would trade one evasion for a denial of service.
/// Which copy wins when two fragments claim the same bytes with
/// different content.
///
/// This is the second half of the classic fragmentation evasion, and
/// there is no universally correct answer: target operating systems
/// genuinely differ, so an attacker who knows the target's behaviour can
/// craft a datagram that reads one way to the sensor and another way to
/// the host. The policy used to be fixed at first-wins and documented as
/// such; making it selectable at least lets a sensor be configured to
/// match the hosts it is actually watching.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FragPolicy {
    /// Bytes from the earliest-arriving fragment are kept. Matches the
    /// common BSD/Linux behaviour.
    FirstWins,
    /// Later fragments overwrite earlier ones. Closer to the historical
    /// Windows behaviour.
    LastWins,
}

impl FragPolicy {
    pub fn parse(s: &str) -> anyhow::Result<FragPolicy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "first" | "first-wins" | "bsd" => Ok(FragPolicy::FirstWins),
            "last" | "last-wins" | "windows" => Ok(FragPolicy::LastWins),
            other => anyhow::bail!("unknown fragment policy {:?} (expected first/last)", other),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            FragPolicy::FirstWins => "first-wins (BSD/Linux)",
            FragPolicy::LastWins => "last-wins (Windows)",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DefragLimits {
    pub max_datagrams: usize,
    pub max_fragments_per_datagram: usize,
    pub max_bytes_per_datagram: usize,
    pub timeout_secs: i64,
    pub policy: FragPolicy,
}

impl Default for DefragLimits {
    fn default() -> Self {
        DefragLimits {
            max_datagrams: 1024,
            max_fragments_per_datagram: 128,
            // The protocol maximum. A datagram claiming more than this
            // is malformed by definition.
            max_bytes_per_datagram: 65535,
            // RFC 1122 suggests 60-120s; real stacks use far less, and a
            // shorter window means a smaller table and a smaller window
            // for an attacker to keep entries alive. 30s is comfortably
            // longer than any legitimate path's fragment spread.
            timeout_secs: 30,
            policy: FragPolicy::FirstWins,
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
struct FragKey {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    protocol: u8,
}

struct Partial {
    /// The pieces, kept as (offset, bytes) rather than written into one
    /// sparse buffer, so a datagram claiming a huge offset costs one
    /// small entry instead of a 64KB allocation.
    pieces: Vec<(usize, Vec<u8>)>,
    bytes: usize,
    /// Total payload length, known only once the final fragment (the one
    /// with "more fragments" clear) has arrived.
    total: Option<usize>,
    /// Rebuild material: the first fragment's IP header (v4) or the
    /// 40-byte fixed header plus the inner next-header (v6).
    header: Vec<u8>,
    v6_next_header: Option<u8>,
    first_seen: i64,
}

impl Partial {
    /// Reassembles if every byte from 0 to `total` is covered,
    /// resolving overlaps per [`FragPolicy`].
    fn assemble(&self, policy: FragPolicy) -> Option<Vec<u8>> {
        let total = self.total?;
        let mut buf = vec![0u8; total];
        let mut covered = vec![false; total];
        // `pieces` is in arrival order, so applying it in that order and
        // skipping already-covered bytes gives first-wins; applying it in
        // reverse gives last-wins. Nothing is sorted by offset: doing so
        // would make the outcome depend on offsets rather than on arrival
        // order, which is neither policy.
        let arrival: Vec<&(usize, Vec<u8>)> = match policy {
            FragPolicy::FirstWins => self.pieces.iter().collect(),
            FragPolicy::LastWins => self.pieces.iter().rev().collect(),
        };
        for (off, data) in arrival {
            for (i, b) in data.iter().enumerate() {
                let at = off + i;
                if at >= total {
                    break;
                }
                if !covered[at] {
                    buf[at] = *b;
                    covered[at] = true;
                }
            }
        }
        if covered.iter().all(|c| *c) {
            Some(buf)
        } else {
            None
        }
    }
}

/// Reassembles fragmented IPv4 and IPv6 datagrams.
///
/// Fragmentation is the oldest documented way to slip past a signature
/// engine (`fragroute`, 1998): split the payload so that no single
/// packet contains a matchable pattern, and a sensor that inspects
/// packets individually never sees it. ARGUS reassembled TCP *streams*
/// but not IP *datagrams*, which left the technique open for UDP-based
/// detection entirely, and — worse than an evasion — caused active false
/// positives, since every fragment after the first had its payload
/// misread as a transport header.
pub struct Defragmenter {
    limits: DefragLimits,
    table: std::collections::HashMap<FragKey, Partial>,
    last_swept: i64,
}

impl Defragmenter {
    pub fn new(limits: DefragLimits) -> Self {
        Defragmenter { limits, table: std::collections::HashMap::new(), last_swept: 0 }
    }

    fn sweep(&mut self, now_sec: i64, stats: &mut DecodeStats) {
        if now_sec <= self.last_swept {
            return;
        }
        self.last_swept = now_sec;
        let cutoff = now_sec - self.limits.timeout_secs;
        let before = self.table.len();
        self.table.retain(|_, p| p.first_seen > cutoff);
        stats.incomplete_datagrams_expired += (before - self.table.len()) as u64;
    }

    /// Absorbs one fragment. Returns the reassembled datagram payload
    /// once the last hole closes, or `None` while pieces are missing.
    #[allow(clippy::too_many_arguments)]
    fn offer(
        &mut self,
        key: FragKey,
        offset: usize,
        more: bool,
        payload: &[u8],
        header: &[u8],
        v6_next_header: Option<u8>,
        now_sec: i64,
        stats: &mut DecodeStats,
    ) -> Option<Vec<u8>> {
        if offset + payload.len() > self.limits.max_bytes_per_datagram {
            stats.fragments_dropped += 1;
            return None;
        }
        // Refusing new datagrams when full, rather than evicting an
        // existing one, is deliberate: eviction would let a flood of
        // junk first-fragments push out a real datagram mid-reassembly,
        // turning a memory bound into an evasion primitive.
        if !self.table.contains_key(&key) && self.table.len() >= self.limits.max_datagrams {
            stats.fragments_dropped += 1;
            return None;
        }

        let limits = self.limits;
        let entry = self.table.entry(key).or_insert_with(|| Partial {
            pieces: Vec::new(),
            bytes: 0,
            total: None,
            header: Vec::new(),
            v6_next_header: None,
            first_seen: now_sec,
        });

        if entry.pieces.len() >= limits.max_fragments_per_datagram || entry.bytes + payload.len() > limits.max_bytes_per_datagram {
            stats.fragments_dropped += 1;
            return None;
        }

        // The first fragment is the only one carrying the transport
        // header and (for v6) the post-fragment next-header value, so its
        // header is what the rebuilt datagram must use.
        if offset == 0 {
            entry.header = header.to_vec();
            entry.v6_next_header = v6_next_header;
        }
        if !more {
            entry.total = Some(offset + payload.len());
        }
        entry.pieces.push((offset, payload.to_vec()));
        entry.bytes += payload.len();

        if entry.total.is_none() || entry.header.is_empty() {
            return None; // still missing the tail, or the head
        }
        let assembled = entry.assemble(limits.policy)?;
        let head = entry.header.clone();
        let v6_nh = entry.v6_next_header;
        self.table.remove(&key);
        stats.datagrams_reassembled += 1;

        Some(rebuild_datagram(&head, v6_nh, &assembled))
    }

    pub fn pending(&self) -> usize {
        self.table.len()
    }
}

/// Splices a reassembled payload back onto its IP header, so the result
/// can go through the ordinary `parse_ipv4_packet`/`parse_ipv6_packet`
/// path rather than needing a second, parallel parser that could drift
/// from it.
fn rebuild_datagram(header: &[u8], v6_next_header: Option<u8>, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + payload.len());
    match v6_next_header {
        None => {
            // IPv4: keep the original header (options included), then fix
            // total length and clear the fragment fields so the result
            // reads as the whole datagram it now is.
            out.extend_from_slice(header);
            let total = (header.len() + payload.len()).min(u16::MAX as usize) as u16;
            out[2..4].copy_from_slice(&total.to_be_bytes());
            out[6] = 0;
            out[7] = 0;
        }
        Some(next_header) => {
            // IPv6: the fixed 40-byte header only, pointed straight at
            // the fragment's inner protocol — see `Ipv6Fragment` for why
            // the unfragmentable extension headers are dropped rather
            // than rebuilt.
            out.extend_from_slice(&header[..40.min(header.len())]);
            if out.len() == 40 {
                out[4..6].copy_from_slice(&(payload.len().min(u16::MAX as usize) as u16).to_be_bytes());
                out[6] = next_header;
            }
        }
    }
    out.extend_from_slice(payload);
    out
}

// =======================================================================
// Tunnels
// =======================================================================

/// IP protocol numbers for the encapsulations worth following.
const PROTO_IPIP: u8 = 4;
const PROTO_IPV6_IN_IP: u8 = 41;
const PROTO_GRE: u8 = 47;
const PROTO_ESP: u8 = 50;
const PROTO_UDP_NUM: u8 = 17;
/// The standard VXLAN port.
const VXLAN_PORT: u16 = 4789;
/// GRE's "Transparent Ethernet Bridging" payload type: the inner payload
/// is a whole Ethernet frame rather than an IP datagram.
const GRE_TEB: u16 = 0x6558;

/// How many layers of encapsulation to follow. Tunnels nest in practice
/// (VXLAN inside IPsec inside a provider tunnel), but they nest by
/// construction, so a bound is needed or a crafted packet could loop for
/// as long as it has bytes.
const MAX_TUNNEL_DEPTH: usize = 4;

/// Where an IP datagram's payload starts, and what protocol it carries.
///
/// Only the fixed-header case is handled for IPv6: a tunnel behind a
/// chain of extension headers is vanishingly rare, and guessing at
/// attacker-supplied header lengths to chase it is not worth the risk.
fn ip_payload(ether_type: u16, ip: &[u8]) -> Option<(u8, &[u8])> {
    match ether_type {
        0x0800 => {
            if ip.len() < 20 || ip[0] >> 4 != 4 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            if ihl < 20 || ip.len() < ihl {
                return None;
            }
            let mut total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            if total > ip.len() || total < ihl {
                total = ip.len();
            }
            Some((ip[9], &ip[ihl..total]))
        }
        0x86DD => {
            if ip.len() < 40 || ip[0] >> 4 != 6 {
                return None;
            }
            let declared = u16::from_be_bytes([ip[4], ip[5]]) as usize;
            let end = if 40 + declared <= ip.len() { 40 + declared } else { ip.len() };
            Some((ip[6], &ip[40..end]))
        }
        _ => None,
    }
}

/// Length of a GRE header, given its flag word.
fn gre_header_len(gre: &[u8]) -> Option<usize> {
    if gre.len() < 4 {
        return None;
    }
    let flags = u16::from_be_bytes([gre[0], gre[1]]);
    let mut len = 4;
    if flags & 0x8000 != 0 {
        len += 4; // checksum + reserved
    }
    if flags & 0x2000 != 0 {
        len += 4; // key
    }
    if flags & 0x1000 != 0 {
        len += 4; // sequence
    }
    if gre.len() < len {
        return None;
    }
    Some(len)
}

/// Follows tunnel encapsulations down to the innermost IP datagram.
///
/// Tunnelled traffic was previously counted as undecodable and dropped,
/// which is the worst of both outcomes: the packets were neither
/// inspected nor obviously missing. On any network with an overlay —
/// which is most of them now — that is a large blind spot that looks
/// exactly like a quiet link.
///
/// ESP is the one encapsulation deliberately not followed: its payload
/// is encrypted, so there is nothing to descend into. It's counted
/// separately rather than lumped in with "malformed", because "I can see
/// this and cannot read it" is a different fact from "I could not parse
/// this".
fn decapsulate<'a>(mut ether_type: u16, mut ip: &'a [u8], stats: &mut DecodeStats) -> (u16, &'a [u8]) {
    for _ in 0..MAX_TUNNEL_DEPTH {
        let Some((proto, payload)) = ip_payload(ether_type, ip) else { break };
        let (inner_type, inner): (u16, &[u8]) = match proto {
            PROTO_IPIP => (0x0800, payload),
            PROTO_IPV6_IN_IP => (0x86DD, payload),
            PROTO_GRE => {
                let Some(hdr) = gre_header_len(payload) else { break };
                let declared = u16::from_be_bytes([payload[2], payload[3]]);
                let body = &payload[hdr..];
                match declared {
                    0x0800 => (0x0800, body),
                    0x86DD => (0x86DD, body),
                    GRE_TEB => {
                        // The payload is an Ethernet frame, so strip it
                        // (VLAN tags included) the same way the outer one
                        // was.
                        let Some((et, off, _)) = ethernet_payload(body) else { break };
                        (et, &body[off.min(body.len())..])
                    }
                    _ => break,
                }
            }
            PROTO_UDP_NUM => {
                if payload.len() < 16 {
                    break;
                }
                let dport = u16::from_be_bytes([payload[2], payload[3]]);
                let sport = u16::from_be_bytes([payload[0], payload[1]]);
                if dport != VXLAN_PORT && sport != VXLAN_PORT {
                    break; // ordinary UDP, not an overlay
                }
                // 8-byte UDP header, 8-byte VXLAN header, then an
                // Ethernet frame.
                let body = &payload[16..];
                let Some((et, off, _)) = ethernet_payload(body) else { break };
                (et, &body[off.min(body.len())..])
            }
            PROTO_ESP => {
                stats.esp_encrypted += 1;
                break;
            }
            _ => break,
        };
        if inner.is_empty() {
            break;
        }
        stats.tunnelled += 1;
        ether_type = inner_type;
        ip = inner;
    }
    (ether_type, ip)
}

// =======================================================================
// The decoder
// =======================================================================

pub struct Decoder {
    link: LinkType,
    payload_cap: usize,
    defrag: Defragmenter,
    pub stats: DecodeStats,
}

impl Decoder {
    pub fn new(link: LinkType, payload_cap: usize, limits: DefragLimits) -> Self {
        Decoder { link, payload_cap: payload_cap.clamp(1, MAX_INSPECT_BYTES), defrag: Defragmenter::new(limits), stats: DecodeStats::default() }
    }

    pub fn link(&self) -> LinkType {
        self.link
    }

    pub fn pending_fragments(&self) -> usize {
        self.defrag.pending()
    }

    /// Strips the link header, returning the inner ethertype and the
    /// offset of the IP datagram.
    fn link_payload(&self, raw: &[u8]) -> Option<(u16, usize, usize)> {
        match self.link {
            LinkType::Ethernet => ethernet_payload(raw),
            LinkType::RawIp => {
                let v = raw.first()? >> 4;
                let et = match v {
                    4 => 0x0800,
                    6 => 0x86DD,
                    _ => return None,
                };
                Some((et, 0, 0))
            }
            LinkType::Null | LinkType::Loop => {
                if raw.len() < 4 {
                    return None;
                }
                let bytes = [raw[0], raw[1], raw[2], raw[3]];
                let af = if self.link == LinkType::Loop {
                    u32::from_be_bytes(bytes)
                } else {
                    // DLT_NULL is host byte order. Big-endian values land
                    // absurdly large, which is the practical way to tell.
                    let le = u32::from_le_bytes(bytes);
                    if le <= 0xFFFF {
                        le
                    } else {
                        u32::from_be_bytes(bytes)
                    }
                };
                Some((af_to_ethertype(af)?, 4, 0))
            }
            LinkType::LinuxSll => {
                if raw.len() < 16 {
                    return None;
                }
                Some((u16::from_be_bytes([raw[14], raw[15]]), 16, 0))
            }
            LinkType::LinuxSll2 => {
                if raw.len() < 20 {
                    return None;
                }
                Some((u16::from_be_bytes([raw[0], raw[1]]), 20, 0))
            }
            LinkType::Unsupported(_) => None,
        }
    }

    /// Turns one captured frame into a `Packet`, or explains why it
    /// couldn't. `now_sec` is the capture time in epoch seconds, used
    /// only for fragment ageing — deliberately the packet's own time, so
    /// replaying a capture expires fragments on the same schedule the
    /// live sensor would have.
    pub fn decode(&mut self, raw: &[u8], ts: SystemTime, now_sec: i64, out: &mut Packet) -> Decoded {
        // Before anything else, and regardless of what this frame turns
        // out to be: a half-assembled datagram ages out on the clock, not
        // on the arrival of another fragment. Sweeping from inside
        // `Defragmenter::offer` (as this first did) meant a sensor that
        // saw one first-fragment and then no further fragments held that
        // entry forever — exactly the state an attacker targeting the
        // table would aim for, and the sweep is time-gated to once per
        // second anyway, so doing it here costs a comparison.
        self.defrag.sweep(now_sec, &mut self.stats);

        if !self.link.is_supported() {
            self.stats.unsupported_link += 1;
            return Decoded::Skipped;
        }
        let (ether_type, offset, tags) = match self.link_payload(raw) {
            Some(v) => v,
            None => {
                self.stats.short_frame += 1;
                return Decoded::Skipped;
            }
        };
        if tags > 0 {
            self.stats.vlan_tagged += 1;
        }
        if ether_type != 0x0800 && ether_type != 0x86DD {
            self.stats.non_ip += 1;
            return Decoded::Skipped;
        }
        let ip = &raw[offset.min(raw.len())..];
        let vlan_id = if self.link == LinkType::Ethernet { ethernet_vlan_id(raw) } else { 0 };

        // --- fragments ---
        let reassembled: Option<Vec<u8>> = if ether_type == 0x0800 {
            match ipv4_fragment(ip) {
                None => None,
                Some(f) => {
                    self.stats.fragments_seen += 1;
                    let key = FragKey { src: IpAddr::V4(ip[12..16].try_into().unwrap()), dst: IpAddr::V4(ip[16..20].try_into().unwrap()), id: f.id as u32, protocol: f.protocol };
                    match self.defrag.offer(key, f.offset, f.more, f.payload, f.header, None, now_sec, &mut self.stats) {
                        Some(datagram) => Some(datagram),
                        None => return Decoded::Buffered,
                    }
                }
            }
        } else {
            match ipv6_fragment(ip) {
                None => None,
                Some(f) => {
                    self.stats.fragments_seen += 1;
                    let key = FragKey {
                        src: IpAddr::V6(ip[8..24].try_into().unwrap()),
                        dst: IpAddr::V6(ip[24..40].try_into().unwrap()),
                        id: f.id,
                        protocol: f.next_header,
                    };
                    let header = &ip[..f.unfragmentable.min(ip.len())];
                    match self.defrag.offer(key, f.offset, f.more, f.payload, header, Some(f.next_header), now_sec, &mut self.stats) {
                        Some(datagram) => Some(datagram),
                        None => return Decoded::Buffered,
                    }
                }
            }
        };

        // Decapsulation happens *after* reassembly: the outer datagram
        // may itself be fragmented, and an inner header split across
        // fragments can't be read until the outer one is whole.
        let outer: &[u8] = match &reassembled {
            Some(datagram) => datagram,
            None => ip,
        };
        let (ether_type, innermost) = decapsulate(ether_type, outer, &mut self.stats);
        let parsed = parse_ip_by_ethertype(ether_type, innermost, out);
        if !parsed {
            self.stats.bad_ip_header += 1;
            return Decoded::Skipped;
        }

        out.ts = ts;
        out.vlan_id = vlan_id;
        out.frame_len = raw.len();
        // A reassembled datagram is a whole datagram by definition, and
        // its rebuilt header says so — but assert the intent rather than
        // relying on the header rewrite having got it right.
        if reassembled.is_some() {
            out.is_fragment = false;
        }
        if (out.payload_len as usize) > self.payload_cap {
            out.payload_len = self.payload_cap as u16;
        }
        self.stats.decoded += 1;
        Decoded::Packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&ether_type.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn vlan_eth(vlan_id: u16, inner: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&0x8100u16.to_be_bytes());
        f.extend_from_slice(&vlan_id.to_be_bytes());
        f.extend_from_slice(&inner.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Builds an IPv4 datagram, optionally as a fragment.
    fn ipv4(proto: u8, id: u16, frag_offset: usize, more: bool, payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let total = 20 + payload.len();
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&id.to_be_bytes());
        let field = ((frag_offset / 8) as u16 & 0x1FFF) | if more { 0x2000 } else { 0 };
        ip[6..8].copy_from_slice(&field.to_be_bytes());
        ip[8] = 64;
        ip[9] = proto;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(payload);
        ip
    }

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&sport.to_be_bytes());
        u[2..4].copy_from_slice(&dport.to_be_bytes());
        u[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        u.extend_from_slice(payload);
        u
    }

    /// An IPv4 datagram carrying an arbitrary protocol number, for the
    /// tunnel tests.
    fn ipv4_proto(proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = proto;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(payload);
        ip
    }

    /// Builds the inner Ethernet frame a bridged tunnel carries.
    fn inner_eth(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&ether_type.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Tunnelled traffic used to be counted as undecodable and dropped —
    /// neither inspected nor obviously missing, which on any network with
    /// an overlay looks exactly like a quiet link.
    #[test]
    fn ip_in_ip_tunnels_are_followed_to_the_inner_datagram() {
        let mut d = decoder();
        let mut p = Packet::default();
        let inner = ipv4(17, 1, 0, false, &udp(1000, 53, b"tunnelled"));
        // Protocol 4: IPv4 inside IPv4.
        let frame = eth(0x0800, &ipv4_proto(4, &inner));
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.dst_port, 53, "ports must come from the inner datagram");
        assert_eq!(p.payload(), b"tunnelled");
        assert_eq!(d.stats.tunnelled, 1);
    }

    #[test]
    fn gre_tunnels_are_followed_including_the_bridged_ethernet_form() {
        // GRE carrying IPv4 directly: flags 0, protocol 0x0800.
        let mut d = decoder();
        let mut p = Packet::default();
        let inner = ipv4(17, 2, 0, false, &udp(2000, 69, b"gre-ip"));
        let mut gre = vec![0x00, 0x00, 0x08, 0x00];
        gre.extend_from_slice(&inner);
        let frame = eth(0x0800, &ipv4_proto(47, &gre));
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.dst_port, 69);

        // GRE Transparent Ethernet Bridging: the payload is a whole
        // Ethernet frame, which has to be stripped again.
        let mut d2 = decoder();
        let mut p2 = Packet::default();
        let inner2 = ipv4(17, 3, 0, false, &udp(3000, 161, b"gre-teb"));
        let mut teb = vec![0x00, 0x00, 0x65, 0x58];
        teb.extend_from_slice(&inner_eth(0x0800, &inner2));
        let frame2 = eth(0x0800, &ipv4_proto(47, &teb));
        assert_eq!(d2.decode(&frame2, SystemTime::now(), 0, &mut p2), Decoded::Packet);
        assert_eq!(p2.dst_port, 161);
    }

    /// GRE's optional fields change the header length, so the flag word
    /// has to be honoured rather than assuming the minimum.
    #[test]
    fn gre_optional_fields_shift_the_header_length() {
        let mut d = decoder();
        let mut p = Packet::default();
        let inner = ipv4(17, 4, 0, false, &udp(4000, 123, b"keyed"));
        // Checksum + key + sequence present: 4 + 4 + 4 + 4 = 16 bytes.
        let mut gre = vec![0xB0, 0x00, 0x08, 0x00];
        gre.extend_from_slice(&[0u8; 12]);
        gre.extend_from_slice(&inner);
        let frame = eth(0x0800, &ipv4_proto(47, &gre));
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.dst_port, 123, "a shorter assumed header would have mis-parsed this");
    }

    #[test]
    fn vxlan_overlays_are_followed() {
        let mut d = decoder();
        let mut p = Packet::default();
        let inner = ipv4(6, 5, 0, false, &[0u8; 20]);
        let mut vx = vec![0u8; 8]; // VXLAN header
        vx[0] = 0x08; // VNI-present flag
        let mut body = vx;
        body.extend_from_slice(&inner_eth(0x0800, &inner));
        let frame = eth(0x0800, &ipv4_proto(17, &udp(12345, 4789, &body)));
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.protocol, 6, "the inner datagram is TCP");
        assert_eq!(d.stats.tunnelled, 1);
    }

    /// Ordinary UDP must not be mistaken for an overlay.
    #[test]
    fn ordinary_udp_is_not_treated_as_a_tunnel() {
        let mut d = decoder();
        let mut p = Packet::default();
        let frame = eth(0x0800, &ipv4(17, 6, 0, false, &udp(1000, 53, b"plain dns")));
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.dst_port, 53);
        assert_eq!(d.stats.tunnelled, 0);
    }

    /// ESP is visible but encrypted. Counted separately, because "I can
    /// see this and cannot read it" is a different fact from "I could not
    /// parse this".
    #[test]
    fn ipsec_esp_is_counted_rather_than_chased() {
        let mut d = decoder();
        let mut p = Packet::default();
        let frame = eth(0x0800, &ipv4_proto(50, &[0xAAu8; 64]));
        d.decode(&frame, SystemTime::now(), 0, &mut p);
        assert_eq!(d.stats.esp_encrypted, 1);
        assert_eq!(d.stats.tunnelled, 0);
    }

    /// Nesting is bounded: the encapsulations nest by construction, so a
    /// crafted packet could otherwise loop for as long as it has bytes.
    #[test]
    fn tunnel_nesting_is_bounded() {
        let mut d = decoder();
        let mut p = Packet::default();
        let mut payload = ipv4(17, 7, 0, false, &udp(5000, 53, b"deep"));
        for _ in 0..12 {
            payload = ipv4_proto(4, &payload);
        }
        let frame = eth(0x0800, &payload);
        // Whatever it decodes to, it must terminate and must not have
        // stripped more than the limit.
        d.decode(&frame, SystemTime::now(), 0, &mut p);
        assert!(d.stats.tunnelled <= MAX_TUNNEL_DEPTH as u64, "stripped {} layers", d.stats.tunnelled);
    }

    /// Overlap resolution is selectable, because real target operating
    /// systems disagree about it and the sensor should be able to match
    /// the hosts it watches.
    #[test]
    fn fragment_overlap_policy_selects_which_copy_wins() {
        for (policy, expect) in [(FragPolicy::FirstWins, b"AAAAAAAA"), (FragPolicy::LastWins, b"XXXXXXXX")] {
            let limits = DefragLimits { policy, ..Default::default() };
            let mut d = Decoder::new(LinkType::Ethernet, DEFAULT_PAYLOAD_CAP, limits);
            let mut p = Packet::default();
            // First piece covers 0..16 (8-byte UDP header + 8 bytes of
            // 'A'); a later piece re-claims 8..24 starting with 'X'.
            let first = udp(1111, 9999, b"AAAAAAAA");
            let f1 = eth(0x0800, &ipv4(17, 200, 0, true, &first));
            let f2 = eth(0x0800, &ipv4(17, 200, 8, true, b"XXXXXXXXYYYYYYYY"));
            let f3 = eth(0x0800, &ipv4(17, 200, 24, false, b"ZZZZZZZZ"));
            assert_eq!(d.decode(&f1, SystemTime::now(), 0, &mut p), Decoded::Buffered);
            assert_eq!(d.decode(&f2, SystemTime::now(), 0, &mut p), Decoded::Buffered);
            assert_eq!(d.decode(&f3, SystemTime::now(), 0, &mut p), Decoded::Packet);
            assert_eq!(&p.payload()[..8], expect, "policy {:?}", policy);
        }
    }

    #[test]
    fn fragment_policy_parses_its_aliases() {
        assert_eq!(FragPolicy::parse("first").unwrap(), FragPolicy::FirstWins);
        assert_eq!(FragPolicy::parse("BSD").unwrap(), FragPolicy::FirstWins);
        assert_eq!(FragPolicy::parse("last").unwrap(), FragPolicy::LastWins);
        assert_eq!(FragPolicy::parse("windows").unwrap(), FragPolicy::LastWins);
        assert!(FragPolicy::parse("sideways").is_err());
    }

    fn decoder() -> Decoder {
        Decoder::new(LinkType::Ethernet, DEFAULT_PAYLOAD_CAP, DefragLimits::default())
    }

    /// The single largest blind spot before this module existed: a
    /// tagged frame decoded to nothing at all, silently, which is what
    /// most frames look like on the trunk or SPAN port a sensor is
    /// normally attached to.
    #[test]
    fn vlan_tagged_frames_decode_and_are_counted() {
        let mut d = decoder();
        let mut p = Packet::default();
        let frame = vlan_eth(42, 0x0800, &ipv4(17, 1, 0, false, &udp(1000, 53, b"query")));
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.dst_port, 53);
        assert_eq!(p.vlan_id, 42, "the VLAN id should survive onto the packet");
        assert_eq!(d.stats.vlan_tagged, 1);
        assert_eq!(p.payload(), b"query");
    }

    #[test]
    fn qinq_double_tagged_frames_decode() {
        let mut d = decoder();
        let mut p = Packet::default();
        let inner = vlan_eth(7, 0x0800, &ipv4(17, 1, 0, false, &udp(1000, 53, b"x")));
        // Re-tag: replace the outer TPID with 0x88A8 and wrap again.
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x88A8u16.to_be_bytes());
        frame.extend_from_slice(&100u16.to_be_bytes());
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&inner[14..]);
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.dst_port, 53);
    }

    #[test]
    fn non_ip_and_unsupported_link_are_counted_separately() {
        let mut d = decoder();
        let mut p = Packet::default();
        assert_eq!(d.decode(&eth(0x0806, &[0u8; 28]), SystemTime::now(), 0, &mut p), Decoded::Skipped);
        assert_eq!(d.stats.non_ip, 1);

        let mut bad = Decoder::new(LinkType::Unsupported(999), DEFAULT_PAYLOAD_CAP, DefragLimits::default());
        assert_eq!(bad.decode(&eth(0x0800, &[0u8; 20]), SystemTime::now(), 0, &mut p), Decoded::Skipped);
        assert_eq!(bad.stats.unsupported_link, 1);
        assert_eq!(bad.stats.non_ip, 0, "an unreadable link header is not the same thing as non-IP traffic");
    }

    /// The headline fragment property: a UDP payload split across two IP
    /// fragments must be inspectable as one datagram.
    #[test]
    fn fragmented_udp_datagram_is_reassembled() {
        let mut d = decoder();
        let mut p = Packet::default();

        let full = udp(4444, 69, b"AAAAAAAABBBBBBBB");
        let (head, tail) = full.split_at(16); // 8-byte aligned, as required
        let f1 = eth(0x0800, &ipv4(17, 77, 0, true, head));
        let f2 = eth(0x0800, &ipv4(17, 77, 16, false, tail));

        assert_eq!(d.decode(&f1, SystemTime::now(), 0, &mut p), Decoded::Buffered, "a lone first fragment has nothing to inspect yet");
        assert_eq!(d.decode(&f2, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.dst_port, 69, "ports come from the reassembled datagram");
        assert_eq!(p.payload(), b"AAAAAAAABBBBBBBB");
        assert!(!p.is_fragment);
        assert_eq!(d.stats.datagrams_reassembled, 1);
        assert_eq!(d.stats.fragments_seen, 2);
    }

    /// Order shouldn't matter — the tail can arrive first.
    #[test]
    fn fragments_reassemble_out_of_order() {
        let mut d = decoder();
        let mut p = Packet::default();
        let full = udp(4444, 69, b"0123456789abcdef");
        let (head, tail) = full.split_at(16);
        let f2 = eth(0x0800, &ipv4(17, 78, 16, false, tail));
        let f1 = eth(0x0800, &ipv4(17, 78, 0, true, head));
        assert_eq!(d.decode(&f2, SystemTime::now(), 0, &mut p), Decoded::Buffered);
        assert_eq!(d.decode(&f1, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.payload(), b"0123456789abcdef");
    }

    /// The false-positive half of the bug, not just the evasion half: a
    /// non-first fragment must never have its payload read as a TCP
    /// header. This one's payload begins with bytes that would decode as
    /// a SYN to port 80 — enough to trip `PORT_SCAN`.
    #[test]
    fn a_lone_non_first_fragment_never_invents_ports_or_flags() {
        let mut d = decoder();
        let mut p = Packet::default();
        let mut fake_tcp_header = vec![0u8; 20];
        fake_tcp_header[0..2].copy_from_slice(&31337u16.to_be_bytes());
        fake_tcp_header[2..4].copy_from_slice(&80u16.to_be_bytes());
        fake_tcp_header[12] = 5 << 4;
        fake_tcp_header[13] = 0x02; // SYN
        let frame = eth(0x0800, &ipv4(6, 79, 1480, false, &fake_tcp_header));

        // Buffered (waiting for offset 0), and nothing is forwarded.
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Buffered);

        // And the raw parse on its own must not invent anything either.
        let mut direct = Packet::default();
        assert!(crate::packet::parse_ethernet_frame(&frame, &mut direct));
        assert!(direct.is_fragment);
        assert_eq!(direct.dst_port, 0, "a fragment's payload must not be read as a transport header");
        assert_eq!(direct.tcp_flags, 0, "...and must not invent a SYN that PORT_SCAN would count");
    }

    #[test]
    fn the_fragment_table_is_bounded_and_counts_what_it_drops() {
        let limits = DefragLimits { max_datagrams: 4, ..Default::default() };
        let mut d = Decoder::new(LinkType::Ethernet, DEFAULT_PAYLOAD_CAP, limits);
        let mut p = Packet::default();
        // Ten distinct datagrams that never complete: only 4 may be held.
        for id in 0..10u16 {
            let frame = eth(0x0800, &ipv4(17, id, 0, true, &udp(1, 2, b"12345678")));
            d.decode(&frame, SystemTime::now(), 0, &mut p);
        }
        assert_eq!(d.pending_fragments(), 4, "the table must not grow past its limit");
        assert_eq!(d.stats.fragments_dropped, 6);
    }

    #[test]
    fn incomplete_datagrams_expire_on_capture_time() {
        let mut d = decoder();
        let mut p = Packet::default();
        let frame = eth(0x0800, &ipv4(17, 90, 0, true, &udp(1, 2, b"12345678")));
        d.decode(&frame, SystemTime::now(), 1_000, &mut p);
        assert_eq!(d.pending_fragments(), 1);
        // A later packet, well past the timeout, triggers the sweep.
        let other = eth(0x0800, &ipv4(17, 91, 0, false, &udp(1, 2, b"x")));
        d.decode(&other, SystemTime::now(), 1_000 + 31, &mut p);
        assert_eq!(d.pending_fragments(), 0);
        assert_eq!(d.stats.incomplete_datagrams_expired, 1);
    }

    #[test]
    fn payload_cap_truncates_without_affecting_decode() {
        let mut d = Decoder::new(LinkType::Ethernet, 4, DefragLimits::default());
        let mut p = Packet::default();
        let frame = eth(0x0800, &ipv4(17, 1, 0, false, &udp(1000, 53, b"0123456789")));
        assert_eq!(d.decode(&frame, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.payload(), b"0123", "the cap bounds what detection sees");
        assert_eq!(p.dst_port, 53, "...but not whether the packet parsed");
    }

    #[test]
    fn raw_ip_and_linux_cooked_links_decode() {
        let datagram = ipv4(17, 1, 0, false, &udp(1000, 53, b"hi"));

        let mut raw = Decoder::new(LinkType::RawIp, DEFAULT_PAYLOAD_CAP, DefragLimits::default());
        let mut p = Packet::default();
        assert_eq!(raw.decode(&datagram, SystemTime::now(), 0, &mut p), Decoded::Packet);
        assert_eq!(p.dst_port, 53);

        let mut sll_frame = vec![0u8; 14];
        sll_frame.extend_from_slice(&0x0800u16.to_be_bytes());
        sll_frame.extend_from_slice(&datagram);
        let mut sll = Decoder::new(LinkType::LinuxSll, DEFAULT_PAYLOAD_CAP, DefragLimits::default());
        let mut p2 = Packet::default();
        assert_eq!(sll.decode(&sll_frame, SystemTime::now(), 0, &mut p2), Decoded::Packet);
        assert_eq!(p2.dst_port, 53, "a Linux `any`-interface capture is SLL, not Ethernet");
    }

    #[test]
    fn link_type_names_are_reported_for_unsupported_dlts() {
        assert_eq!(LinkType::from_dlt(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_dlt(113), LinkType::LinuxSll);
        assert_eq!(LinkType::from_dlt(9999), LinkType::Unsupported(9999));
        assert!(LinkType::from_dlt(9999).name().contains("9999"), "the number matters: it's how someone finds out what their capture is");
    }
}
