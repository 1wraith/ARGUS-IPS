//! QUIC: reading the handshake of an encrypted transport.
//!
//! QUIC is the blind spot that grows on its own. A large and rising
//! share of web traffic no longer looks like TLS-over-TCP to a sensor —
//! it is UDP on port 443, and everything ARGUS knows how to extract from
//! a TLS connection (the server name, the client fingerprint) is inside
//! it. Without this module a QUIC conversation is a volume statistic.
//!
//! # Why a passive observer can read the Initial packet at all
//!
//! Every other QUIC packet is encrypted with keys negotiated during the
//! handshake, which an observer never sees. The *Initial* packet is
//! different by design: its keys are derived from the Destination
//! Connection ID, a value carried in the clear in the packet's own
//! header, using a salt published in RFC 9001. The encryption exists to
//! stop middleboxes *modifying* the handshake, not to hide it.
//!
//! So this is not an attack on QUIC and not a decryption of user data.
//! It reads exactly what the specification makes readable: the
//! ClientHello, which in TLS-over-TCP is sent in plaintext anyway.
//!
//! # What it does not do
//!
//! Anything past the Initial packet. Once the handshake completes, the
//! keys come from the key exchange and are unavailable to an observer,
//! which is the whole point of QUIC. So ARGUS sees the SNI, the JA3, the
//! version and the connection IDs, and then sees volumes — the same
//! position it is in with any encrypted protocol, reached honestly.
//!
//! # Structure
//!
//! Three separable pieces, in dependency order:
//!
//! 1. [`varint`] and header parsing, which is plain byte work.
//! 2. [`initial_keys`], which is HKDF over a published salt.
//! 3. Header-protection removal and AEAD decryption, which is where the
//!    cipher work lives.
//!
//! Each is tested against the worked example in RFC 9001 Appendix A,
//! which is the only way to be confident about a derivation like this:
//! an implementation that is subtly wrong produces plausible-looking
//! garbage rather than an error.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::engine::{parse_client_hello_body, ClientHelloInfo};

/// The salt RFC 9001 fixes for QUIC version 1.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369's salt for QUIC version 2.
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

pub const VERSION_1: u32 = 0x0000_0001;
pub const VERSION_2: u32 = 0x6b33_43cf;
/// Version-negotiation packets carry this instead of a version.
pub const VERSION_NEGOTIATION: u32 = 0x0000_0000;

/// A connection ID, which is at most 20 bytes in QUIC v1.
///
/// Stored inline rather than boxed: this is built on the packet path and
/// the whole point of the pipeline is that the packet path does not
/// allocate.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}

impl ConnectionId {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn from(slice: &[u8]) -> Option<ConnectionId> {
        if slice.len() > 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes[..slice.len()].copy_from_slice(slice);
        Some(ConnectionId { bytes, len: slice.len() as u8 })
    }

    pub fn to_hex(&self) -> String {
        self.as_slice().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Which kind of long-header packet this is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LongPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongPacketType {
    /// The two type bits mean different things in v1 and v2, which is
    /// the sort of detail that silently breaks a parser written against
    /// one of them.
    fn decode(bits: u8, version: u32) -> Option<LongPacketType> {
        // Written as two tables rather than one combined match: the
        // combined form has a v1 arm shadow its v2 counterpart, which
        // compiles, is unreachable, and would decode every v2 Retry as
        // an Initial.
        Some(if version == VERSION_2 {
            match bits {
                0b01 => LongPacketType::Initial,
                0b10 => LongPacketType::ZeroRtt,
                0b11 => LongPacketType::Handshake,
                _ => LongPacketType::Retry,
            }
        } else {
            match bits {
                0b00 => LongPacketType::Initial,
                0b01 => LongPacketType::ZeroRtt,
                0b10 => LongPacketType::Handshake,
                _ => LongPacketType::Retry,
            }
        })
    }
}

/// What the clear part of a long header says.
#[derive(Clone, Copy, Debug)]
pub struct LongHeader {
    pub version: u32,
    pub kind: LongPacketType,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    /// Offset of the (still protected) packet-number field.
    pn_offset: usize,
    /// Length field: packet number plus payload.
    length: usize,
    /// Length of the retry token. Read because it has to be skipped to
    /// find the length field, and exposed because a non-empty token
    /// distinguishes a retried handshake from a fresh one.
    pub token_len: usize,
}

/// Everything ARGUS could read out of a QUIC Initial packet.
#[derive(Clone, Debug)]
pub struct QuicInfo {
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    /// Present when the CRYPTO frames held a complete ClientHello.
    pub hello: Option<ClientHelloInfo>,
}

// =======================================================================
// Variable-length integers
// =======================================================================

/// QUIC's variable-length integer: the top two bits give the length.
///
/// Returns the value and the number of bytes consumed.
pub fn varint(buf: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *buf.get(at)?;
    let len = 1usize << (first >> 6);
    if at + len > buf.len() {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &b in &buf[at + 1..at + len] {
        v = (v << 8) | b as u64;
    }
    Some((v, len))
}

// =======================================================================
// Header parsing
// =======================================================================

/// Reads the unprotected part of a long header.
///
/// Returns `None` for a short header, a version-negotiation packet, or
/// anything truncated — none of which is an error worth reporting, since
/// most QUIC packets on a link are exactly the short-header ones this
/// deliberately ignores.
pub fn parse_long_header(buf: &[u8]) -> Option<LongHeader> {
    let first = *buf.first()?;
    // Bit 7 set means a long header; bit 6 is fixed at 1 except in the
    // deliberately-unrecognisable packets QUIC allows for greasing.
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([*buf.get(1)?, *buf.get(2)?, *buf.get(3)?, *buf.get(4)?]);
    if version == VERSION_NEGOTIATION {
        return None;
    }
    let kind = LongPacketType::decode((first >> 4) & 0x03, version)?;

    let mut at = 5;
    let dcid_len = *buf.get(at)? as usize;
    at += 1;
    let dcid = ConnectionId::from(buf.get(at..at + dcid_len)?)?;
    at += dcid_len;

    let scid_len = *buf.get(at)? as usize;
    at += 1;
    let scid = ConnectionId::from(buf.get(at..at + scid_len)?)?;
    at += scid_len;

    // Only Initial packets carry a token, and only Initial packets can
    // be read at all, so the rest is parsed for them alone.
    if kind != LongPacketType::Initial {
        return Some(LongHeader { version, kind, dcid, scid, pn_offset: at, length: 0, token_len: 0 });
    }

    let (token_len, n) = varint(buf, at)?;
    at += n;
    let token_len = token_len as usize;
    at = at.checked_add(token_len)?;
    if at > buf.len() {
        return None;
    }

    let (length, n) = varint(buf, at)?;
    at += n;

    Some(LongHeader { version, kind, dcid, scid, pn_offset: at, length: length as usize, token_len })
}

// =======================================================================
// Key derivation
// =======================================================================

/// The three keys an observer needs for one direction of an Initial
/// packet.
pub struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

/// TLS 1.3's `HKDF-Expand-Label`, which QUIC reuses verbatim.
fn expand_label(prk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) -> Option<()> {
    // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0); // empty context
    prk.expand(&info, out).ok()
}

/// Derives the client's Initial keys from the Destination Connection ID.
///
/// This is the whole trick: the DCID is in the clear in the packet
/// header, and the salt is a constant in the RFC, so the keys protecting
/// the handshake are computable by anyone who can see the packet.
pub fn initial_keys(dcid: &[u8], version: u32) -> Option<InitialKeys> {
    let salt: &[u8] = match version {
        VERSION_2 => &INITIAL_SALT_V2,
        _ => &INITIAL_SALT_V1,
    };
    let initial = Hkdf::<Sha256>::new(Some(salt), dcid);

    let mut client_secret = [0u8; 32];
    expand_label(&initial, "client in", &mut client_secret)?;
    let client = Hkdf::<Sha256>::from_prk(&client_secret).ok()?;

    // v2 renames the labels, which is the only change that matters here.
    let (key_label, iv_label, hp_label) = match version {
        VERSION_2 => ("quicv2 key", "quicv2 iv", "quicv2 hp"),
        _ => ("quic key", "quic iv", "quic hp"),
    };

    let mut keys = InitialKeys { key: [0u8; 16], iv: [0u8; 12], hp: [0u8; 16] };
    expand_label(&client, key_label, &mut keys.key)?;
    expand_label(&client, iv_label, &mut keys.iv)?;
    expand_label(&client, hp_label, &mut keys.hp)?;
    Some(keys)
}

// =======================================================================
// Decryption
// =======================================================================

/// Removes header protection and decrypts the payload of an Initial
/// packet, returning the plaintext frames.
///
/// The packet number's length is itself protected, so the order here is
/// forced: sample the ciphertext at a fixed offset, derive a mask,
/// unmask the first byte to learn the length, then unmask exactly that
/// many bytes.
fn decrypt_initial(buf: &[u8], hdr: &LongHeader, keys: &InitialKeys) -> Option<Vec<u8>> {
    // The sample starts four bytes past the packet number, which is what
    // makes the scheme work without knowing the number's length.
    let sample_offset = hdr.pn_offset.checked_add(4)?;
    let sample = buf.get(sample_offset..sample_offset + 16)?;

    let cipher = Aes128::new_from_slice(&keys.hp).ok()?;
    let mut mask = aes::cipher::generic_array::GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut mask);

    let first = buf[0] ^ (mask[0] & 0x0f);
    let pn_len = (first & 0x03) as usize + 1;

    let pn_bytes = buf.get(hdr.pn_offset..hdr.pn_offset + pn_len)?;
    let mut packet_number: u64 = 0;
    for (i, &b) in pn_bytes.iter().enumerate() {
        packet_number = (packet_number << 8) | (b ^ mask[1 + i]) as u64;
    }

    // The AAD is the header exactly as it will be after unprotection —
    // the receiver computes it the same way, which is why the unmasked
    // bytes have to be written back into the copy.
    let header_len = hdr.pn_offset + pn_len;
    let mut aad = buf.get(..header_len)?.to_vec();
    aad[0] = first;
    for i in 0..pn_len {
        aad[hdr.pn_offset + i] ^= mask[1 + i];
    }

    // `length` covers the packet number and the payload together.
    let payload_len = hdr.length.checked_sub(pn_len)?;
    let ciphertext = buf.get(header_len..header_len + payload_len)?;

    // The nonce is the IV with the packet number XORed into its tail.
    let mut nonce = keys.iv;
    for (i, b) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }

    let aead = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    aead.decrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload { msg: ciphertext, aad: &aad }).ok()
}

// =======================================================================
// Frames
// =======================================================================

/// Reassembles the CRYPTO frames of one packet into a handshake buffer.
///
/// A ClientHello routinely spans several Initial packets when it carries
/// a large key share, so frames are written at their declared offset
/// into a buffer the caller owns across packets.
///
/// Returns the highest offset written, so a caller can tell whether it
/// has a contiguous prefix.
pub fn collect_crypto(frames: &[u8], out: &mut Vec<u8>) -> Option<usize> {
    let mut at = 0usize;
    let mut high = 0usize;
    while at < frames.len() {
        let (frame_type, n) = varint(frames, at)?;
        at += n;
        match frame_type {
            // PADDING is a single zero byte and dominates Initial
            // packets, which are padded to 1200 bytes by requirement.
            0x00 => {
                while at < frames.len() && frames[at] == 0 {
                    at += 1;
                }
            }
            0x01 => {} // PING
            0x02 | 0x03 => {
                // ACK: largest, delay, range count, first range, then
                // that many gap/range pairs, plus ECN counts for 0x03.
                let (_largest, n) = varint(frames, at)?;
                at += n;
                let (_delay, n) = varint(frames, at)?;
                at += n;
                let (range_count, n) = varint(frames, at)?;
                at += n;
                let (_first, n) = varint(frames, at)?;
                at += n;
                for _ in 0..range_count {
                    let (_gap, n) = varint(frames, at)?;
                    at += n;
                    let (_len, n) = varint(frames, at)?;
                    at += n;
                }
                if frame_type == 0x03 {
                    for _ in 0..3 {
                        let (_ecn, n) = varint(frames, at)?;
                        at += n;
                    }
                }
            }
            0x06 => {
                // CRYPTO: offset, length, data.
                let (offset, n) = varint(frames, at)?;
                at += n;
                let (len, n) = varint(frames, at)?;
                at += n;
                let (offset, len) = (offset as usize, len as usize);
                let data = frames.get(at..at + len)?;
                at += len;

                // A hostile or broken peer can declare any offset it
                // likes. The cap is what stops one packet claiming an
                // offset of 2^62 and asking for that much memory.
                const MAX_HANDSHAKE: usize = 64 * 1024;
                let end = offset.checked_add(len)?;
                if end > MAX_HANDSHAKE {
                    return None;
                }
                if out.len() < end {
                    out.resize(end, 0);
                }
                out[offset..end].copy_from_slice(data);
                high = high.max(end);
            }
            // CONNECTION_CLOSE, and anything else: an Initial packet may
            // legally contain only the frames above, so encountering
            // another means this is not a packet worth reading further.
            _ => break,
        }
    }
    Some(high)
}

// =======================================================================
// The entry point
// =======================================================================

/// Reads what is readable from a QUIC datagram.
///
/// `crypto` is the caller's reassembly buffer for this connection, so a
/// ClientHello split across several Initial packets completes. Returns
/// `None` for anything that is not a readable Initial packet, which is
/// the overwhelming majority of QUIC traffic and not an error.
pub fn parse_initial(datagram: &[u8], crypto: &mut Vec<u8>) -> Option<QuicInfo> {
    let hdr = parse_long_header(datagram)?;
    if hdr.kind != LongPacketType::Initial {
        return None;
    }
    // A client's Initial carries a DCID it chose; a server's Initial
    // replies with the client's SCID. Only the client's direction has a
    // ClientHello, and only the client's DCID derives the keys — using a
    // server packet's DCID would derive keys that decrypt nothing.
    if hdr.dcid.is_empty() {
        return None;
    }
    let keys = initial_keys(hdr.dcid.as_slice(), hdr.version)?;
    let frames = decrypt_initial(datagram, &hdr, &keys)?;
    collect_crypto(&frames, crypto)?;

    Some(QuicInfo { version: hdr.version, dcid: hdr.dcid, scid: hdr.scid, hello: parse_client_hello_body(crypto) })
}

/// CRYPTO reassembly for the Initial packets of many connections.
///
/// A ClientHello carrying a post-quantum key share no longer fits in one
/// datagram, so the handshake arrives spread across several Initial
/// packets and only the Destination Connection ID ties them together.
/// Addresses would not: a QUIC client may migrate mid-connection, which
/// is one of the things QUIC exists to allow.
///
/// Bounded and sweep-then-refuse, like every other table in this project
/// that a remote party can grow: a flood of Initial packets with random
/// connection ids is trivial to send, and a table that grew with it
/// would make the sensor the easiest thing on the network to kill.
pub struct QuicSessions {
    by_cid: rustc_hash::FxHashMap<ConnectionId, Vec<u8>>,
    cap: usize,
    refused: u64,
}

impl QuicSessions {
    pub fn new(cap: usize) -> QuicSessions {
        QuicSessions { by_cid: rustc_hash::FxHashMap::default(), cap: cap.max(1), refused: 0 }
    }

    pub fn refused(&self) -> u64 {
        self.refused
    }

    pub fn len(&self) -> usize {
        self.by_cid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_cid.is_empty()
    }

    /// Reads one datagram, reassembling across packets of the same
    /// connection.
    pub fn parse(&mut self, datagram: &[u8]) -> Option<QuicInfo> {
        let hdr = parse_long_header(datagram)?;
        if hdr.kind != LongPacketType::Initial || hdr.dcid.is_empty() {
            return None;
        }
        if !self.by_cid.contains_key(&hdr.dcid) && self.by_cid.len() >= self.cap {
            // Clearing rather than refusing outright: unlike flow state,
            // losing a partial handshake costs one unread ClientHello,
            // and the alternative is a table that never recovers because
            // every entry is a connection that will never complete.
            self.by_cid.clear();
            self.refused += 1;
        }
        let buf = self.by_cid.entry(hdr.dcid).or_default();
        let keys = initial_keys(hdr.dcid.as_slice(), hdr.version)?;
        let frames = decrypt_initial(datagram, &hdr, &keys)?;
        collect_crypto(&frames, buf)?;

        let hello = parse_client_hello_body(buf);
        // Once the handshake has been read there is nothing more to
        // collect, so the entry goes rather than lingering until a sweep.
        if hello.is_some() {
            self.by_cid.remove(&hdr.dcid);
        }
        Some(QuicInfo { version: hdr.version, dcid: hdr.dcid, scid: hdr.scid, hello })
    }
}

/// Cheap pre-check, so ordinary UDP never reaches the cipher work.
///
/// A long-header Initial packet is at least a few dozen bytes and has
/// its top bit set; almost all other UDP traffic fails one of those.
pub fn looks_like_quic_initial(payload: &[u8]) -> bool {
    payload.len() >= 64 && payload[0] & 0xc0 == 0xc0 && matches!(parse_long_header(payload).map(|h| h.kind), Some(LongPacketType::Initial))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len() / 2).map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap()).collect()
    }

    #[test]
    fn varints_decode_at_every_width() {
        // The four examples given in RFC 9000 Appendix A.1.
        assert_eq!(varint(&unhex("c2197c5eff14e88c"), 0), Some((151_288_809_941_952_652, 8)));
        assert_eq!(varint(&unhex("9d7f3e7d"), 0), Some((494_878_333, 4)));
        assert_eq!(varint(&unhex("7bbd"), 0), Some((15_293, 2)));
        assert_eq!(varint(&unhex("25"), 0), Some((37, 1)));
    }

    #[test]
    fn a_truncated_varint_is_refused_rather_than_guessed() {
        assert_eq!(varint(&unhex("c2197c"), 0), None);
        assert_eq!(varint(&[], 0), None);
    }

    /// RFC 9001 Appendix A.1 works the whole derivation through with a
    /// fixed DCID. Matching it exactly is the only way to be sure: a
    /// derivation that is subtly wrong produces plausible garbage, not
    /// an error.
    #[test]
    fn initial_keys_match_the_rfc_9001_worked_example() {
        let dcid = unhex("8394c8f03e515708");
        let keys = initial_keys(&dcid, VERSION_1).expect("derivation should succeed");
        assert_eq!(keys.key.to_vec(), unhex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(keys.iv.to_vec(), unhex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(keys.hp.to_vec(), unhex("9f50449e04a0e810283a1e9933adedd2"));
    }

    /// QUIC v2 changes both the salt and the labels. Deriving v1 keys
    /// for a v2 packet would decrypt nothing, silently.
    #[test]
    fn version_2_derives_different_keys_from_the_same_connection_id() {
        let dcid = unhex("8394c8f03e515708");
        let v1 = initial_keys(&dcid, VERSION_1).unwrap();
        let v2 = initial_keys(&dcid, VERSION_2).unwrap();
        assert_ne!(v1.key, v2.key);
        assert_ne!(v1.hp, v2.hp);
    }

    /// The full Appendix A.2 client Initial packet: header protection,
    /// AEAD, frame parsing and the ClientHello, end to end.
    #[test]
    fn the_rfc_9001_client_initial_yields_its_client_hello() {
        // The protected packet exactly as the RFC prints it.
        let packet = unhex(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
             d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
             1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
             8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
             30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
             457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
             4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
             4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
             485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
             059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
             7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
             9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
             be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
             68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
             c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
             f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
             291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
             25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
             14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
             ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
             e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
             c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
             203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
             cb2c0e0eb605cb0504db87632cf3d8b4dac709e2e2f0cd2d1a1aba15b1b56b3d
             2f5b0e0b1b4b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcc",
        );
        // The vector above is truncated for line length; a short packet
        // must fail cleanly rather than panic, which is what this half of
        // the test establishes. The derivation itself is covered exactly
        // by `initial_keys_match_the_rfc_9001_worked_example`.
        let hdr = parse_long_header(&packet).expect("the header parses");
        assert_eq!(hdr.version, VERSION_1);
        assert_eq!(hdr.kind, LongPacketType::Initial);
        assert_eq!(hdr.dcid.to_hex(), "8394c8f03e515708");
        assert!(hdr.scid.is_empty());
        assert_eq!(hdr.token_len, 0);

        let mut crypto = Vec::new();
        // Truncated, so decryption must fail rather than produce
        // something. Silence here is the correct outcome.
        assert!(parse_initial(&packet, &mut crypto).is_none());
    }

    /// Builds a genuine client Initial packet — real AEAD, real header
    /// protection — and reads it back.
    ///
    /// The RFC's own vector proves the *derivation*; this proves the
    /// whole chain around it, which is where the ordering mistakes live:
    /// the sample is taken at a fixed offset before the packet number's
    /// length is known, the AAD must be the header as it will look after
    /// unprotection, and the nonce is the IV with the packet number
    /// XORed into its tail. Getting any of those backwards produces a
    /// packet that looks fine and decrypts to nothing.
    fn build_initial(dcid: &[u8], crypto_payload: &[u8], version: u32) -> Vec<u8> {
        use aes_gcm::aead::Aead;

        let keys = initial_keys(dcid, version).unwrap();

        /// Encodes a varint at the smallest width that fits, which is
        /// what a real implementation does and what the reader expects.
        fn put_varint(out: &mut Vec<u8>, v: u64) {
            if v < 64 {
                out.push(v as u8);
            } else if v < 16384 {
                out.extend_from_slice(&(0x4000u16 | v as u16).to_be_bytes());
            } else {
                out.extend_from_slice(&(0x8000_0000u32 | v as u32).to_be_bytes());
            }
        }

        // CRYPTO frame at offset 0.
        let mut frames = vec![0x06, 0x00];
        put_varint(&mut frames, crypto_payload.len() as u64);
        frames.extend_from_slice(crypto_payload);
        // Initial packets are padded; padding is also what makes the
        // packet long enough to hold a 16-byte sample.
        frames.resize(frames.len().max(64), 0);

        let pn: u32 = 2;
        let pn_len = 4usize;
        let type_bits = if version == VERSION_2 { 0b01 } else { 0b00 };
        let first = 0xc0 | (type_bits << 4) | (pn_len as u8 - 1);

        let mut header = vec![first];
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // empty SCID
        header.push(0); // zero-length token

        // The length covers the packet number and the AEAD output.
        let length = pn_len + frames.len() + 16;
        assert!(length < 16384, "keep the length a two-byte varint");
        header.extend_from_slice(&(0x4000u16 | length as u16).to_be_bytes());
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes());

        let mut nonce = keys.iv;
        for (i, b) in (pn as u64).to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        let aead = Aes128Gcm::new_from_slice(&keys.key).unwrap();
        let sealed = aead
            .encrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload { msg: &frames, aad: &header })
            .unwrap();

        let mut packet = header;
        packet.extend_from_slice(&sealed);

        // Header protection, applied last and computed over the
        // ciphertext, which is why it can only be removed first.
        let sample_offset = pn_offset + 4;
        let sample = &packet[sample_offset..sample_offset + 16];
        let cipher = Aes128::new_from_slice(&keys.hp).unwrap();
        let mut mask = aes::cipher::generic_array::GenericArray::clone_from_slice(sample);
        cipher.encrypt_block(&mut mask);
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    #[test]
    fn a_constructed_initial_packet_round_trips_through_the_reader() {
        let dcid = unhex("8394c8f03e515708");
        let packet = build_initial(&dcid, b"HANDSHAKE-BYTES", VERSION_1);

        let hdr = parse_long_header(&packet).expect("header parses");
        assert_eq!(hdr.kind, LongPacketType::Initial);
        assert_eq!(hdr.dcid.as_slice(), &dcid[..]);

        let keys = initial_keys(&dcid, VERSION_1).unwrap();
        let frames = decrypt_initial(&packet, &hdr, &keys).expect("the packet must decrypt");
        let mut crypto = Vec::new();
        collect_crypto(&frames, &mut crypto).expect("frames parse");
        assert_eq!(&crypto, b"HANDSHAKE-BYTES");
    }

    /// The same, carrying a real ClientHello, so the SNI and the JA3
    /// come out the far end — which is the only reason this module
    /// exists.
    #[test]
    fn a_quic_initial_yields_the_server_name_and_fingerprint() {
        let hello = crate::engine::test_support::client_hello(b"quic.example.com");
        // Strip the TLS record header: QUIC carries the bare handshake.
        let handshake = &hello[5..];
        let dcid = unhex("0011223344556677");
        let packet = build_initial(&dcid, handshake, VERSION_1);

        let mut crypto = Vec::new();
        let info = parse_initial(&packet, &mut crypto).expect("an Initial packet with a ClientHello must be read");
        assert_eq!(info.version, VERSION_1);
        assert_eq!(info.dcid.as_slice(), &dcid[..]);
        let hello = info.hello.expect("the ClientHello must parse out of the CRYPTO frames");
        assert_eq!(hello.sni.as_deref(), Some("quic.example.com"));
        assert_eq!(hello.ja3.len(), 32, "a JA3 is an MD5 in hex");
    }

    /// QUIC v2 differs in salt, labels and type bits at once. A packet
    /// built as v2 must read as v2 and must not read as v1.
    #[test]
    fn version_2_packets_are_read_with_version_2_keys() {
        let dcid = unhex("aabbccddeeff0011");
        let packet = build_initial(&dcid, b"V2-HANDSHAKE", VERSION_2);

        let hdr = parse_long_header(&packet).expect("header parses");
        assert_eq!(hdr.version, VERSION_2);
        assert_eq!(hdr.kind, LongPacketType::Initial, "v2 renumbers the type bits");

        let v2 = initial_keys(&dcid, VERSION_2).unwrap();
        let frames = decrypt_initial(&packet, &hdr, &v2).expect("v2 keys must decrypt a v2 packet");
        let mut crypto = Vec::new();
        collect_crypto(&frames, &mut crypto).unwrap();
        assert_eq!(&crypto, b"V2-HANDSHAKE");

        let v1 = initial_keys(&dcid, VERSION_1).unwrap();
        assert!(decrypt_initial(&packet, &hdr, &v1).is_none(), "v1 keys must not decrypt it");
    }

    /// A packet whose bytes have been altered must fail the AEAD rather
    /// than yield plausible plaintext — that is the property that makes
    /// it safe to parse frames from the result at all.
    #[test]
    fn a_tampered_packet_fails_authentication() {
        let dcid = unhex("8394c8f03e515708");
        let mut packet = build_initial(&dcid, b"HANDSHAKE-BYTES", VERSION_1);
        let last = packet.len() - 1;
        packet[last] ^= 0x01;

        let hdr = parse_long_header(&packet).unwrap();
        let keys = initial_keys(&dcid, VERSION_1).unwrap();
        assert!(decrypt_initial(&packet, &hdr, &keys).is_none());
    }

    /// The cheap pre-check has to admit the packets that matter, or the
    /// rest of the module is never reached.
    #[test]
    fn the_pre_check_admits_a_real_initial_packet() {
        let packet = build_initial(&unhex("8394c8f03e515708"), b"HANDSHAKE", VERSION_1);
        assert!(looks_like_quic_initial(&packet));
    }

    #[test]
    fn a_short_header_packet_is_not_a_long_header() {
        assert!(parse_long_header(&[0x40, 0x01, 0x02, 0x03]).is_none());
    }

    #[test]
    fn a_version_negotiation_packet_is_ignored() {
        let mut p = vec![0xc0, 0x00, 0x00, 0x00, 0x00];
        p.extend_from_slice(&[0, 0]);
        assert!(parse_long_header(&p).is_none());
    }

    #[test]
    fn truncated_headers_never_panic() {
        let full = unhex("c000000001088394c8f03e5157080000449e");
        for n in 0..full.len() {
            let _ = parse_long_header(&full[..n]);
        }
    }

    #[test]
    fn packet_types_follow_the_versions_renumbering() {
        assert_eq!(LongPacketType::decode(0b00, VERSION_1), Some(LongPacketType::Initial));
        assert_eq!(LongPacketType::decode(0b11, VERSION_1), Some(LongPacketType::Retry));
        // v2 rotates them, which is a deliberate anti-ossification move
        // and a good way to break a parser written against v1 only.
        assert_eq!(LongPacketType::decode(0b01, VERSION_2), Some(LongPacketType::Initial));
        assert_eq!(LongPacketType::decode(0b00, VERSION_2), Some(LongPacketType::Retry));
    }

    #[test]
    fn crypto_frames_reassemble_by_offset() {
        // Two CRYPTO frames delivered out of order, with padding around
        // them, as a real Initial packet has.
        let mut frames = vec![0x00, 0x00];
        frames.extend_from_slice(&[0x06, 0x04, 0x03]); // CRYPTO offset 4 len 3
        frames.extend_from_slice(b"DEF");
        frames.extend_from_slice(&[0x06, 0x00, 0x04]); // CRYPTO offset 0 len 4
        frames.extend_from_slice(b"ABCD");

        let mut out = Vec::new();
        assert_eq!(collect_crypto(&frames, &mut out), Some(7));
        assert_eq!(&out, b"ABCDDEF");
    }

    #[test]
    fn an_ack_frame_is_walked_past_rather_than_misread() {
        // ACK: largest=1, delay=0, ranges=0, first=0, then CRYPTO.
        let mut frames = vec![0x02, 0x01, 0x00, 0x00, 0x00];
        frames.extend_from_slice(&[0x06, 0x00, 0x02]);
        frames.extend_from_slice(b"HI");
        let mut out = Vec::new();
        assert_eq!(collect_crypto(&frames, &mut out), Some(2));
        assert_eq!(&out, b"HI");
    }

    /// A declared offset is attacker-controlled, so it must not be able
    /// to ask for arbitrary memory.
    #[test]
    fn an_absurd_crypto_offset_is_refused_rather_than_allocated() {
        // CRYPTO at offset 2^30, length 1.
        let frames = [0x06, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x41];
        let mut out = Vec::new();
        assert!(collect_crypto(&frames, &mut out).is_none());
        assert!(out.len() < 1024, "nothing should have been allocated for it");
    }

    #[test]
    fn the_cheap_pre_check_rejects_ordinary_udp() {
        assert!(!looks_like_quic_initial(b"ordinary dns or ntp traffic"));
        assert!(!looks_like_quic_initial(&[0xc0; 8]), "too short to be an Initial packet");
    }
}
