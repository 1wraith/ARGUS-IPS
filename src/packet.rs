//! Packet parsing: turns a raw captured frame into a [`Packet`].
//!
//! `Packet` is `Copy` and pointer-free (the payload is an inline
//! fixed-size array, not a `Vec`/slice into the capture buffer), so
//! passing it through a channel to a worker thread is a plain memcpy —
//! no allocator, no refcounting, no lifetime to track.
//!
//! Both IPv4 and IPv6 are supported. Addresses are represented by
//! [`IpAddr`], a small enum wrapping either a 4-byte or 16-byte address —
//! this is the one type change that had to ripple through the rest of
//! the program (hashmap keys, the blacklist, `Alert`, worker sharding)
//! to add real IPv6 support rather than just "parse it and drop it."

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROTO_ICMP: u8 = 1; // ICMPv4
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
/// 802.1Q customer VLAN tag, and 802.1ad ("QinQ") service-provider tag.
/// Both are 4 bytes — 2 of TCI, then the inner ethertype — and both can
/// nest, so stripping them is a loop rather than a special case.
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_QINQ: u16 = 0x88A8;
/// How many stacked tags to strip before giving up. Two covers ordinary
/// QinQ; a third is slack for the occasional triple-tagged frame. A
/// bound is needed at all because the tag ethertypes nest by
/// construction, so a crafted frame could otherwise loop as long as it
/// has bytes.
const MAX_VLAN_TAGS: usize = 3;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

/// Upper bound on how much application-layer payload is copied out of a
/// single packet. A fixed inline array rather than a `Vec` or a slice
/// into the capture buffer, so a `Packet` stays `Copy` and pointer-free
/// and can cross a worker channel as a plain memcpy.
///
/// Sized to cover a full Ethernet MTU, because **this bounds stream
/// reassembly as well as the per-packet check**, which an earlier
/// comment here denied: `FlowTable::observe` feeds `p.payload()` into
/// `StreamHalf::feed`, so whatever is dropped here never reaches
/// reassembly at all. At the old value of 256 bytes that quietly broke
/// a headline feature — a real TLS ClientHello is 500+ bytes (517 from
/// Windows/Schannel to a Cloudflare host), so its extensions never
/// reached `parse_tls_client_hello` and SNI/JA3 extraction returned
/// nothing on live traffic, having appeared to work throughout because
/// every test fed it a small synthetic record. `-stream-cap` governs
/// how many of these chunks accumulate per direction; this governs how
/// much of any one packet survives to be accumulated.
///
/// Sized for a jumbo frame (9000-byte MTU plus headers), which it could
/// not previously afford to be. When a `Packet` travelled through the
/// worker channels *by value*, the array multiplied out by
/// `-queue-size` x `-workers` and a jumbo-sized one would have reserved
/// gigabytes. Packets now travel as pooled `Box<Packet>` handles — the
/// channel moves a pointer — so the memory is `-packet-pool` x this,
/// independent of both queue depth and worker count. At the defaults
/// that is about 37MB, less than the 33MB the 1600-byte version
/// reserved at 20 workers, and it no longer grows when workers are
/// added.
///
/// Nothing is copied that isn't there: `copy_payload` copies
/// `min(actual, cap)`, so an ordinary 1500-byte frame costs the same as
/// it did. `-payload-cap` can lower the effective value to trade
/// inspection depth for CPU, and cannot raise it past this array.
pub const MAX_INSPECT_BYTES: usize = 9216;

pub type Ipv4 = [u8; 4];
pub type Ipv6 = [u8; 16];

/// An IPv4 or IPv6 address. `Copy`, hashable, orderable (so it can key a
/// `HashMap`, sit in an `Alert`, and be canonicalized for worker
/// sharding) without caring which family it is at most call sites.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum IpAddr {
    V4(Ipv4),
    V6(Ipv6),
}

impl IpAddr {
    pub const UNSPECIFIED: IpAddr = IpAddr::V4([0, 0, 0, 0]);

    pub fn is_v4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }

    /// Multicast (224.0.0.0/4, ff00::/8) or the all-ones broadcast.
    ///
    /// Traffic to a group address is addressed to whoever is listening
    /// rather than to a host, which makes several behavioural questions
    /// meaningless when asked about it — see the beaconing check in
    /// `behavior.rs`.
    pub fn is_multicast_or_broadcast(&self) -> bool {
        match self {
            IpAddr::V4(a) => a[0] & 0xf0 == 224 || *a == [255, 255, 255, 255],
            IpAddr::V6(a) => a[0] == 0xff,
        }
    }

    /// Raw address bytes (4 for IPv4, 16 for IPv6) — used by `main.rs`'s
    /// worker-sharding hash, which needs to mix the address generically
    /// without caring which family it is.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            IpAddr::V4(a) => a.as_slice(),
            IpAddr::V6(a) => a.as_slice(),
        }
    }

    /// Parses a dotted-decimal IPv4 or colon-hex IPv6 literal, used for
    /// the blacklist file. Deliberately simple (no zone IDs, no embedded
    /// IPv4-in-IPv6) — this is for exact-match blocklisting, not a
    /// general-purpose address parser.
    pub fn parse(s: &str) -> Option<IpAddr> {
        if s.contains(':') {
            parse_ipv6_literal(s).map(IpAddr::V6)
        } else {
            parse_ipv4_literal(s).map(IpAddr::V4)
        }
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddr::V4(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            IpAddr::V6(a) => write!(f, "{}", format_ipv6(a)),
        }
    }
}

#[inline]
pub fn ip_to_string(a: IpAddr) -> String {
    a.to_string()
}

fn parse_ipv4_literal(s: &str) -> Option<Ipv4> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for slot in out.iter_mut() {
        *slot = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None; // more than 4 octets
    }
    Some(out)
}

/// Parses a standard colon-hex IPv6 literal, including `::` zero
/// compression (at most one occurrence, per RFC 4291).
fn parse_ipv6_literal(s: &str) -> Option<Ipv6> {
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let parse_groups = |part: &str| -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        part.split(':').map(|g| u16::from_str_radix(g, 16).ok()).collect()
    };
    let head_groups = parse_groups(head)?;
    let tail_groups = match tail {
        Some(t) => parse_groups(t)?,
        None => Vec::new(),
    };

    let mut groups = [0u16; 8];
    if tail.is_some() {
        if head_groups.len() + tail_groups.len() > 8 {
            return None;
        }
        for (i, g) in head_groups.iter().enumerate() {
            groups[i] = *g;
        }
        let tail_start = 8 - tail_groups.len();
        for (i, g) in tail_groups.iter().enumerate() {
            groups[tail_start + i] = *g;
        }
    } else {
        if head_groups.len() != 8 {
            return None;
        }
        groups.copy_from_slice(&head_groups);
    }

    let mut out = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        out[i * 2] = (g >> 8) as u8;
        out[i * 2 + 1] = (g & 0xff) as u8;
    }
    Some(out)
}

/// Formats an IPv6 address with `::` zero-run compression, matching the
/// common representation (leftmost-longest run of >=2 zero groups
/// compressed, per RFC 5952's tie-breaking rule).
fn format_ipv6(a: &Ipv6) -> String {
    let mut groups = [0u16; 8];
    for i in 0..8 {
        groups[i] = ((a[i * 2] as u16) << 8) | (a[i * 2 + 1] as u16);
    }

    let mut best_start = None;
    let mut best_len = 0;
    let mut i = 0;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            let len = i - start;
            if len > best_len {
                best_len = len;
                best_start = Some(start);
            }
        } else {
            i += 1;
        }
    }
    if best_len < 2 {
        best_start = None;
    }

    match best_start {
        None => groups.iter().map(|g| format!("{:x}", g)).collect::<Vec<_>>().join(":"),
        Some(start) => {
            let end = start + best_len;
            let head: Vec<String> = groups[..start].iter().map(|g| format!("{:x}", g)).collect();
            let tail: Vec<String> = groups[end..].iter().map(|g| format!("{:x}", g)).collect();
            format!("{}::{}", head.join(":"), tail.join(":"))
        }
    }
}

#[derive(Clone, Copy)]
pub struct Packet {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    /// TCP sequence number of the *first byte of this segment's payload*
    /// (i.e. already offset past the SYN's own sequence number). Used by
    /// `engine.rs`'s `FlowTable` for stream reassembly. Meaningless for
    /// non-TCP packets.
    pub tcp_seq: u32,
    pub tcp_window: u16,
    /// ICMP type and code; zero for anything else.
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub payload_len: u16,
    pub payload: [u8; MAX_INSPECT_BYTES],
    pub frame_len: usize,
    /// 802.1Q VLAN id of the outermost tag, or 0 when untagged.
    pub vlan_id: u16,
    /// Set when this packet is a piece of a fragmented IP datagram whose
    /// transport header therefore hasn't been parsed — see
    /// `parse_ipv4_packet`. `decode.rs` reassembles these; anything that
    /// reaches a worker with this set is a fragment that could not be
    /// reassembled, and must not be trusted to have ports or flags.
    pub is_fragment: bool,
    /// When libpcap says this packet was actually captured — *not* when
    /// a worker got around to processing it.
    ///
    /// Every detection window in `engine.rs` (the flood bucket ring, the
    /// port-scan window, `UdpPairTracker`'s reply window, `FlowTable`'s
    /// idle timeout) and every emitted `Alert`'s timestamp derive from
    /// this. Reading the clock inside the worker instead — as an earlier
    /// version did — silently conflated two different times: under any
    /// queue backlog, alerts got stamped with when they were *noticed*,
    /// and a burst that arrived inside one window could be measured
    /// across two. It also made replaying a saved capture meaningless,
    /// since file-read time has no relation to the traffic's real
    /// timing.
    ///
    /// Assignment order doesn't matter: `parse_ethernet_frame` preserves
    /// this across the IP parsers, which each reset `*out` wholesale.
    pub ts: SystemTime,
}

impl Default for Packet {
    fn default() -> Self {
        Packet {
            src: IpAddr::UNSPECIFIED,
            dst: IpAddr::UNSPECIFIED,
            protocol: 0,
            src_port: 0,
            dst_port: 0,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_window: 0,
            icmp_type: 0,
            icmp_code: 0,
            payload_len: 0,
            payload: [0; MAX_INSPECT_BYTES],
            frame_len: 0,
            vlan_id: 0,
            is_fragment: false,
            ts: UNIX_EPOCH,
        }
    }
}

impl Packet {
    /// Clears the header fields, leaving the payload array untouched.
    ///
    /// The array is deliberately not zeroed. `payload()` is bounded by
    /// `payload_len`, so bytes beyond it are unreachable — and the
    /// parsers used to reset a packet by assigning a whole fresh
    /// `Packet { ..Default::default() }` over it, which memsets the
    /// entire array on every single packet. At 1600 bytes that was
    /// already more work than the parse itself; at a jumbo-capable 9216
    /// it would have dwarfed everything. `ts` is preserved, since the
    /// capture loop sets it before decoding.
    #[inline]
    pub fn reset(&mut self) {
        self.src = IpAddr::UNSPECIFIED;
        self.dst = IpAddr::UNSPECIFIED;
        self.protocol = 0;
        self.src_port = 0;
        self.dst_port = 0;
        self.tcp_flags = 0;
        self.tcp_seq = 0;
        self.tcp_window = 0;
        self.icmp_type = 0;
        self.icmp_code = 0;
        self.payload_len = 0;
        self.frame_len = 0;
        self.vlan_id = 0;
        self.is_fragment = false;
    }

    #[inline]
    pub fn proto_name(&self) -> &'static str {
        match self.protocol {
            PROTO_TCP => "TCP",
            PROTO_UDP => "UDP",
            PROTO_ICMP => "ICMP",
            PROTO_ICMPV6 => "ICMPv6",
            _ => "OTHER",
        }
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    #[inline]
    pub fn is_syn_only(&self) -> bool {
        self.protocol == PROTO_TCP && (self.tcp_flags & TCP_SYN != 0) && (self.tcp_flags & TCP_ACK == 0)
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{} {} :{}", self.src, self.dst, self.proto_name(), self.dst_port)
    }
}

/// Finds the real (innermost) ethertype of an Ethernet frame and where
/// its payload starts, stripping any stack of 802.1Q/802.1ad VLAN tags
/// on the way. Returns `(ethertype, payload_offset, tags_stripped)`.
///
/// Worth its own function because the missing version of it was ARGUS's
/// single largest blind spot: `parse_ethernet_frame` used to read the
/// ethertype at a fixed offset 12 and send anything that wasn't
/// `0x0800`/`0x86DD` to `_ => false`. A VLAN-tagged frame carries
/// `0x8100` there, so on a trunk or SPAN port — which is exactly where
/// a sensor is normally placed, and where most frames are tagged —
/// every packet failed to decode, silently, with no error and no
/// counter. A capture full of traffic and an empty alert log look
/// identical from the outside.
pub fn ethernet_payload(raw: &[u8]) -> Option<(u16, usize, usize)> {
    if raw.len() < 14 {
        return None;
    }
    let mut ether_type = u16::from_be_bytes([raw[12], raw[13]]);
    let mut offset = 14;
    let mut tags = 0;
    while (ether_type == ETHER_TYPE_VLAN || ether_type == ETHER_TYPE_QINQ) && tags < MAX_VLAN_TAGS {
        if raw.len() < offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
        tags += 1;
    }
    Some((ether_type, offset, tags))
}

/// The VLAN id (12 bits of the first tag's TCI) of a tagged frame, or 0
/// if untagged. Reported on alerts, since "which VLAN" is part of
/// identifying what a sensor on a trunk actually saw.
pub fn ethernet_vlan_id(raw: &[u8]) -> u16 {
    if raw.len() < 16 {
        return 0;
    }
    let ether_type = u16::from_be_bytes([raw[12], raw[13]]);
    if ether_type != ETHER_TYPE_VLAN && ether_type != ETHER_TYPE_QINQ {
        return 0;
    }
    u16::from_be_bytes([raw[14], raw[15]]) & 0x0FFF
}

/// Dispatches on `ether_type`, parsing the IP datagram at `payload`.
pub fn parse_ip_by_ethertype(ether_type: u16, payload: &[u8], out: &mut Packet) -> bool {
    match ether_type {
        ETHER_TYPE_IPV4 => parse_ipv4_packet(payload, out),
        ETHER_TYPE_IPV6 => parse_ipv6_packet(payload, out),
        _ => false, // ARP, LLDP, MPLS, PPPoE, ...
    }
}

/// Parses a full Ethernet frame (14-byte header, plus any VLAN tags,
/// plus an IPv4 or IPv6 payload) — what libpcap/Npcap hand back on a
/// normal Ethernet-datalink capture, on both Linux and Windows.
#[inline]
pub fn parse_ethernet_frame(raw: &[u8], out: &mut Packet) -> bool {
    if raw.len() < 14 {
        return false;
    }
    // No ts save/restore any more: the IP parsers clear the header
    // fields through `Packet::reset`, which leaves `ts` alone, so a
    // timestamp set before decoding survives. (They used to assign a
    // whole fresh `Packet` over `*out`, which clobbered it — and zeroed
    // the payload array while it was at it.)
    let (ether_type, offset, _tags) = match ethernet_payload(raw) {
        Some(v) => v,
        None => return false,
    };
    let vlan_id = ethernet_vlan_id(raw);
    if !parse_ip_by_ethertype(ether_type, &raw[offset..], out) {
        return false;
    }
    out.vlan_id = vlan_id;
    out.frame_len = raw.len();
    true
}

/// Parses a buffer starting at an IPv4 header (no link-layer header).
/// Malformed/truncated input returns `false` rather than panicking —
/// this is attacker-controlled input by definition.
#[inline]
pub fn parse_ipv4_packet(ip: &[u8], out: &mut Packet) -> bool {
    if ip.len() < 20 {
        return false;
    }
    let ver_ihl = ip[0];
    if ver_ihl >> 4 != 4 {
        return false;
    }
    let ihl = ((ver_ihl & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return false;
    }

    let mut total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_len > ip.len() || total_len < ihl {
        total_len = ip.len(); // truncated capture; use what we actually have
    }

    // Bytes 6-7: 3 flag bits then a 13-bit fragment offset in 8-byte
    // units. An earlier version read neither and called `parse_transport`
    // on every fragment unconditionally, which is worse than merely
    // failing to reassemble: for any fragment after the first, the first
    // 20 payload bytes are ordinary application data, and interpreting
    // them as a TCP header invents source and destination ports, invents
    // flags (so a byte with 0x02 set reads as a SYN and can trip
    // `PORT_SCAN`), and feeds a garbage sequence number into
    // `FlowTable`. So fragmentation wasn't only the oldest IDS evasion
    // left open here, it was an active source of false positives.
    let frag_field = u16::from_be_bytes([ip[6], ip[7]]);
    let frag_offset = ((frag_field & 0x1FFF) as usize) * 8;
    let more_fragments = frag_field & 0x2000 != 0;

    out.reset();
    out.src = IpAddr::V4([ip[12], ip[13], ip[14], ip[15]]);
    out.dst = IpAddr::V4([ip[16], ip[17], ip[18], ip[19]]);
    out.protocol = ip[9];
    out.frame_len = ip.len();
    out.is_fragment = more_fragments || frag_offset > 0;

    // Only a whole datagram (or the reassembled result `decode.rs` hands
    // back) gets its transport header parsed.
    if !out.is_fragment {
        parse_transport(out.protocol, &ip[ihl..total_len], out);
    }
    true
}

/// What `decode.rs` needs to reassemble an IPv4 fragment: the datagram's
/// identity and this piece's place in it. `None` for a packet that isn't
/// a fragment at all, so the fast path costs one field read and a test.
pub struct Ipv4Fragment<'a> {
    pub id: u16,
    pub offset: usize,
    pub more: bool,
    pub protocol: u8,
    /// The IP header, reused verbatim when rebuilding the datagram.
    pub header: &'a [u8],
    pub payload: &'a [u8],
}

pub fn ipv4_fragment(ip: &[u8]) -> Option<Ipv4Fragment<'_>> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let frag_field = u16::from_be_bytes([ip[6], ip[7]]);
    let offset = ((frag_field & 0x1FFF) as usize) * 8;
    let more = frag_field & 0x2000 != 0;
    if !more && offset == 0 {
        return None; // a whole datagram, not a fragment
    }
    let mut total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_len > ip.len() || total_len < ihl {
        total_len = ip.len();
    }
    Some(Ipv4Fragment { id: u16::from_be_bytes([ip[4], ip[5]]), offset, more, protocol: ip[9], header: &ip[..ihl], payload: &ip[ihl..total_len] })
}

/// Parses a buffer starting at an IPv6 fixed header (no link-layer
/// header), following the extension-header chain (Hop-by-Hop, Routing,
/// Destination Options, Fragment, Authentication) to find the real
/// transport protocol. Stops (treating the payload as opaque) on ESP or
/// any extension type it doesn't recognize — a hop-count guard prevents
/// looping on malformed chains.
pub fn parse_ipv6_packet(ip: &[u8], out: &mut Packet) -> bool {
    if ip.len() < 40 {
        return false;
    }
    if ip[0] >> 4 != 6 {
        return false;
    }
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let mut next_header = ip[6];

    out.reset();
    out.src = IpAddr::V6(ip[8..24].try_into().unwrap());
    out.dst = IpAddr::V6(ip[24..40].try_into().unwrap());
    out.frame_len = ip.len();

    let mut end = 40 + payload_len;
    if end > ip.len() || end < 40 {
        end = ip.len(); // truncated capture; use what we actually have
    }

    let mut pos = 40;
    let mut hops = 0;
    loop {
        match next_header {
            0 | 43 | 60 => {
                // Hop-by-Hop Options / Routing / Destination Options:
                // byte0 = next header, byte1 = extra length in 8-byte
                // units (not counting the first 8 bytes).
                if pos + 2 > end || hops > 8 {
                    return true; // give up cleanly; protocol stays "unknown"
                }
                let ext_next = ip[pos];
                let ext_len = (ip[pos + 1] as usize + 1) * 8;
                if pos + ext_len > end {
                    return true;
                }
                next_header = ext_next;
                pos += ext_len;
                hops += 1;
            }
            44 => {
                // Fragment header: 8 bytes — next header, reserved, then
                // a 13-bit offset with the M ("more") flag in the low
                // bit, then a 32-bit identification.
                //
                // An earlier version read only the next-header byte and
                // walked straight past, so a non-first fragment's
                // payload got parsed as a transport header exactly the
                // way IPv4's did — see `parse_ipv4_packet` for why that
                // invents ports and flags rather than merely missing
                // data.
                if pos + 8 > end || hops > 8 {
                    return true;
                }
                let frag_field = u16::from_be_bytes([ip[pos + 2], ip[pos + 3]]);
                let offset = ((frag_field >> 3) as usize) * 8;
                let more = frag_field & 1 != 0;
                if more || offset > 0 {
                    out.is_fragment = true;
                }
                next_header = ip[pos];
                pos += 8;
                hops += 1;
            }
            51 => {
                // Authentication Header: byte1 = length in 4-byte units,
                // minus 2 (per RFC 4302).
                if pos + 2 > end || hops > 8 {
                    return true;
                }
                let ext_next = ip[pos];
                let ext_len = (ip[pos + 1] as usize + 2) * 4;
                if pos + ext_len > end {
                    return true;
                }
                next_header = ext_next;
                pos += ext_len;
                hops += 1;
            }
            _ => break, // TCP/UDP/ICMPv6/ESP/anything else: stop chasing headers
        }
    }

    out.protocol = next_header;
    if pos <= end && !out.is_fragment {
        parse_transport(next_header, &ip[pos..end], out);
    }
    true
}

/// The IPv6 counterpart of [`ipv4_fragment`]. Walking the extension
/// chain to find the fragment header is unavoidable here, since unlike
/// IPv4 the fragment fields aren't at a fixed offset.
///
/// `unfragmentable` is the run of headers before the fragment header:
/// per RFC 8200 those belong to every fragment and are not part of the
/// reassembled payload. `decode.rs` rebuilds a datagram from the fixed
/// 40-byte header plus the reassembled payload, pointing next-header
/// straight at `next_header` — so any Hop-by-Hop or Routing header that
/// sat in `unfragmentable` is dropped rather than reconstructed. That
/// costs nothing for detection (no rule buffer reads those) and avoids
/// hand-rebuilding a header chain from attacker-supplied lengths.
pub struct Ipv6Fragment<'a> {
    pub id: u32,
    pub offset: usize,
    pub more: bool,
    /// Protocol carried inside the fragment (TCP/UDP/...).
    pub next_header: u8,
    pub unfragmentable: usize,
    pub payload: &'a [u8],
}

pub fn ipv6_fragment(ip: &[u8]) -> Option<Ipv6Fragment<'_>> {
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let mut end = 40 + payload_len;
    if end > ip.len() || end < 40 {
        end = ip.len();
    }

    let mut next = ip[6];
    let mut pos = 40;
    let mut hops = 0;
    while hops <= 8 {
        match next {
            44 => {
                if pos + 8 > end {
                    return None;
                }
                let frag_field = u16::from_be_bytes([ip[pos + 2], ip[pos + 3]]);
                let offset = ((frag_field >> 3) as usize) * 8;
                let more = frag_field & 1 != 0;
                if !more && offset == 0 {
                    return None; // an "atomic" fragment: not really fragmented
                }
                let id = u32::from_be_bytes([ip[pos + 4], ip[pos + 5], ip[pos + 6], ip[pos + 7]]);
                return Some(Ipv6Fragment { id, offset, more, next_header: ip[pos], unfragmentable: pos, payload: &ip[pos + 8..end] });
            }
            0 | 43 | 60 => {
                if pos + 2 > end {
                    return None;
                }
                let ext_len = (ip[pos + 1] as usize + 1) * 8;
                if pos + ext_len > end {
                    return None;
                }
                next = ip[pos];
                pos += ext_len;
            }
            51 => {
                if pos + 2 > end {
                    return None;
                }
                let ext_len = (ip[pos + 1] as usize + 2) * 4;
                if pos + ext_len > end {
                    return None;
                }
                next = ip[pos];
                pos += ext_len;
            }
            _ => return None, // no fragment header in the chain
        }
        hops += 1;
    }
    None
}

/// Parses the transport-layer header (TCP/UDP/ICMP/ICMPv6) shared by
/// both the IPv4 and IPv6 paths, since the wire format of each transport
/// protocol doesn't depend on which IP version carried it.
fn parse_transport(protocol: u8, transport: &[u8], out: &mut Packet) {
    match protocol {
        PROTO_TCP => {
            if transport.len() < 20 {
                return;
            }
            out.src_port = u16::from_be_bytes([transport[0], transport[1]]);
            out.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
            out.tcp_seq = u32::from_be_bytes([transport[4], transport[5], transport[6], transport[7]]);
            out.tcp_flags = transport[13];
            out.tcp_window = u16::from_be_bytes([transport[14], transport[15]]);
            let data_offset = ((transport[12] >> 4) as usize) * 4;
            if data_offset >= 20 && transport.len() > data_offset {
                copy_payload(out, &transport[data_offset..]);
            }
        }
        PROTO_UDP => {
            if transport.len() < 8 {
                return;
            }
            out.src_port = u16::from_be_bytes([transport[0], transport[1]]);
            out.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
            if transport.len() > 8 {
                copy_payload(out, &transport[8..]);
            }
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            if transport.len() >= 2 {
                out.icmp_type = transport[0];
                out.icmp_code = transport[1];
            }
            if transport.len() > 8 {
                copy_payload(out, &transport[8..]);
            }
        }
        _ => {}
    }
}

#[inline]
fn copy_payload(out: &mut Packet, data: &[u8]) {
    let n = data.len().min(MAX_INSPECT_BYTES);
    out.payload[..n].copy_from_slice(&data[..n]);
    out.payload_len = n as u16;
}

#[cfg(test)]
pub(crate) fn build_tcp_frame(src: Ipv4, dst: Ipv4, src_port: u16, dst_port: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut eth = vec![0u8; 14];
    eth[12..14].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
    let tcp_len = 20 + payload.len();
    let ip_len = 20 + tcp_len;
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[9] = PROTO_TCP;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    let mut tcp = vec![0u8; tcp_len];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[20..].copy_from_slice(payload);
    let mut frame = eth;
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

#[cfg(test)]
pub(crate) fn build_udp_frame(src: Ipv4, dst: Ipv4, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut eth = vec![0u8; 14];
    eth[12..14].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[9] = PROTO_UDP;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let mut frame = eth;
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

#[cfg(test)]
pub(crate) fn build_udp6_frame(src: Ipv6, dst: Ipv6, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut eth = vec![0u8; 14];
    eth[12..14].copy_from_slice(&ETHER_TYPE_IPV6.to_be_bytes());
    let udp_len = 8 + payload.len();
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60; // version 6
    ip[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    ip[6] = PROTO_UDP; // next header
    ip[7] = 64; // hop limit
    ip[8..24].copy_from_slice(&src);
    ip[24..40].copy_from_slice(&dst);
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let mut frame = eth;
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_packet() {
        let frame = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, 80, 1000, TCP_SYN, &[]);
        let mut pkt = Packet::default();
        assert!(parse_ethernet_frame(&frame, &mut pkt));
        assert_eq!(pkt.src, IpAddr::V4([10, 0, 0, 5]));
        assert_eq!(pkt.dst, IpAddr::V4([10, 0, 0, 1]));
        assert_eq!(pkt.src_port, 51234);
        assert_eq!(pkt.dst_port, 80);
        assert_eq!(pkt.tcp_flags, TCP_SYN);
        assert_eq!(pkt.tcp_seq, 1000);
    }

    #[test]
    fn truncated_frame_does_not_panic() {
        let mut pkt = Packet::default();
        assert!(!parse_ethernet_frame(&[0x00, 0x01, 0x02], &mut pkt));
    }

    #[test]
    fn payload_is_truncated_to_max_inspect_bytes() {
        let big = vec![b'A'; MAX_INSPECT_BYTES + 500];
        let frame = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 1234, 80, 1, TCP_PSH, &big);
        let mut pkt = Packet::default();
        assert!(parse_ethernet_frame(&frame, &mut pkt));
        assert_eq!(pkt.payload_len as usize, MAX_INSPECT_BYTES);
    }

    #[test]
    fn rejects_unknown_ethertype() {
        let mut frame = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 1234, 80, 1, TCP_ACK, &[]);
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP ethertype
        let mut pkt = Packet::default();
        assert!(!parse_ethernet_frame(&frame, &mut pkt));
    }

    #[test]
    fn is_syn_only_detects_bare_syn() {
        let frame = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 1234, 80, 1, TCP_SYN, &[]);
        let mut pkt = Packet::default();
        parse_ethernet_frame(&frame, &mut pkt);
        assert!(pkt.is_syn_only());

        let frame2 = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 1234, 80, 1, TCP_SYN | TCP_ACK, &[]);
        let mut pkt2 = Packet::default();
        parse_ethernet_frame(&frame2, &mut pkt2);
        assert!(!pkt2.is_syn_only());
    }

    #[test]
    fn parses_udp_dns_frame_end_to_end() {
        let frame = build_udp_frame([194, 168, 4, 100], [192, 168, 0, 112], 53, 40000, b"not a real DNS message, just checking the parse plumbing");
        let mut pkt = Packet::default();
        assert!(parse_ethernet_frame(&frame, &mut pkt));
        assert_eq!(pkt.protocol, PROTO_UDP);
        assert_eq!(pkt.src_port, 53);
        assert_eq!(pkt.dst_port, 40000);
        assert!(pkt.payload().starts_with(b"not a real DNS"));
    }

    // --- IPv6 ---

    #[test]
    fn parses_ipv6_udp_packet() {
        let src: Ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst: Ipv6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let frame = build_udp6_frame(src, dst, 53, 12345, b"hello ipv6");
        let mut pkt = Packet::default();
        assert!(parse_ethernet_frame(&frame, &mut pkt));
        assert_eq!(pkt.src, IpAddr::V6(src));
        assert_eq!(pkt.dst, IpAddr::V6(dst));
        assert_eq!(pkt.protocol, PROTO_UDP);
        assert_eq!(pkt.src_port, 53);
        assert_eq!(pkt.dst_port, 12345);
        assert_eq!(pkt.payload(), b"hello ipv6");
    }

    #[test]
    fn ipv6_hop_by_hop_extension_header_is_skipped() {
        // Base header with next_header = 0 (Hop-by-Hop), followed by an
        // 8-byte hop-by-hop header (next_header=UDP, len=0 => 8 bytes
        // total), followed by a UDP datagram.
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        let udp_payload = b"past the extension header";
        let udp_len = 8 + udp_payload.len();
        let hbh_len = 8;
        ip[4..6].copy_from_slice(&((hbh_len + udp_len) as u16).to_be_bytes());
        ip[6] = 0; // next header: Hop-by-Hop Options
        ip[7] = 64;
        ip[8..24].copy_from_slice(&[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip[24..40].copy_from_slice(&[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let mut hbh = vec![0u8; hbh_len];
        hbh[0] = PROTO_UDP; // next header after this extension
        hbh[1] = 0; // ext len = (0+1)*8 = 8 bytes total

        let mut udp = vec![0u8; udp_len];
        udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[8..].copy_from_slice(udp_payload);

        let mut raw = ip;
        raw.extend_from_slice(&hbh);
        raw.extend_from_slice(&udp);

        let mut pkt = Packet::default();
        assert!(parse_ipv6_packet(&raw, &mut pkt));
        assert_eq!(pkt.protocol, PROTO_UDP);
        assert_eq!(pkt.src_port, 5353);
        assert_eq!(pkt.dst_port, 53);
        assert_eq!(pkt.payload(), udp_payload);
    }

    #[test]
    fn ipv6_literal_roundtrip() {
        let cases = ["2001:db8::1", "fe80::1", "::1", "2001:db8:0:0:1:0:0:1", "::"];
        for s in cases {
            let addr = IpAddr::parse(s).expect(s);
            assert!(matches!(addr, IpAddr::V6(_)), "{} should parse as v6", s);
        }
    }

    #[test]
    fn ipv6_format_compresses_zero_runs() {
        let addr = IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(addr.to_string(), "2001:db8::1");
    }

    #[test]
    fn ipv6_format_leading_and_all_zero_compression() {
        // These are exactly the cases a naive string-join compression
        // approach gets wrong (missing a colon, or dropping "::"
        // entirely) — caught during development, see format_ipv6.
        assert_eq!(IpAddr::V6([0; 16]).to_string(), "::");
        let loopback = IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(loopback.to_string(), "::1");
        let trailing = IpAddr::V6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(trailing.to_string(), "2001:db8::");
    }

    #[test]
    fn ipv4_literal_parses() {
        let addr = IpAddr::parse("192.168.0.112").unwrap();
        assert_eq!(addr, IpAddr::V4([192, 168, 0, 112]));
    }
}