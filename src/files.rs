//! File identity: type, size and hash, for content crossing the wire.
//!
//! A rule can already say "this byte sequence appeared in a request
//! body". What it could not say is "this *file* crossed the network",
//! which is a different and usually better question: a sample's hash is
//! the most portable indicator there is, shared between every feed and
//! every sandbox report, and unlike a content signature it does not care
//! how the file was packed or where in the stream it appeared.
//!
//! # What this can and cannot see
//!
//! ARGUS hashes HTTP bodies in both directions: uploads and webshell
//! drops going to a server, and downloads coming back. It cannot see
//! anything inside TLS, and it hashes what was sent — a body with a
//! `Content-Encoding` is hashed compressed, since that is what crossed the
//! wire. The limits are stated here and in the README rather than left for
//! someone to discover during an incident.
//!
//! # Streaming, not buffering
//!
//! A download can be any size and the reassembly buffer holds 16KB, so
//! inspecting a buffer would only ever hash the first sliver of a file.
//! [`FileHasher`] keeps a running digest instead, fed by every segment as
//! it arrives, which costs about two hundred bytes per transfer however
//! large the file is.
//!
//! # Why the hash is bounded and the bound is visible
//!
//! Hashing is bounded in CPU rather than memory: a hostile server can
//! otherwise hand a sensor an endless response and keep it hashing
//! forever, so there is a cap — and, more importantly, a *flag* saying the cap was
//! hit. A truncated hash that is silently reported as a file hash would
//! be worse than no hash at all: it would never match a feed, and
//! nobody would know why.

use md5::{Digest, Md5};
use sha2::Sha256;

/// How many bytes of one transfer are hashed.
///
/// Well past the size of the scripts, executables and archives that a
/// content-matching sensor is realistically going to be asked about, and
/// small enough that a worker's peak memory stays predictable.
pub const MAX_HASHED_BYTES: usize = 1024 * 1024;

/// What was learned about one piece of transferred content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileInfo {
    /// Bytes seen, which is not necessarily the file's real length —
    /// see `truncated`.
    pub size: usize,
    pub md5: String,
    pub sha256: String,
    /// The content ran past [`MAX_HASHED_BYTES`], so the hashes describe
    /// a prefix and will not match a published hash of the whole file.
    ///
    /// Reported rather than hidden: a hash that silently describes
    /// something other than what it claims is worse than no hash.
    pub truncated: bool,
    /// The type the content's own leading bytes say it is, when they say
    /// anything recognisable.
    pub kind: Option<&'static str>,
    /// What libmagic would call it (`Zip archive data, ...`), for the
    /// types worth naming. Rules written for Suricata's `file.magic`
    /// match on these descriptions.
    pub magic: Option<&'static str>,
}

/// Magic-number signatures, most specific first.
///
/// Deliberately short: this exists to answer "is an executable being
/// uploaded to this web server", not to be a file-type database. Each
/// entry is a type whose appearance in HTTP traffic is itself worth
/// noticing.
const MAGIC: &[(&[u8], &str)] = &[
    (b"MZ", "dos/pe-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"\xca\xfe\xba\xbe", "java-class-or-macho-fat"),
    (b"\xfe\xed\xfa\xce", "mach-o"),
    (b"\xfe\xed\xfa\xcf", "mach-o-64"),
    (b"PK\x03\x04", "zip-or-office"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7-zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ", "xz"),
    (b"%PDF-", "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole-compound (legacy office)"),
    (b"#!", "script-with-shebang"),
    (b"<?php", "php-source"),
    (b"<%@", "jsp-or-asp-source"),
    (b"\x89PNG", "png"),
    (b"GIF8", "gif"),
    (b"\xff\xd8\xff", "jpeg"),
];

/// libmagic-style descriptions: `(offset, signature, description)`.
///
/// A handful, chosen for the descriptions detection rules quote. The text
/// is the front of what `file` prints, which is what a substring match
/// (`content:"Zip archive"`) needs.
const DESCRIPTIONS: &[(usize, &[u8], &str)] = &[
    (0, b"PK\x03\x04", "Zip archive data, at least v2.0 to extract"),
    (257, b"ustar\x00", "POSIX tar archive"),
    (257, b"ustar  \x00", "POSIX tar archive (GNU)"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-zip archive data, version 0.4"),
    (0, b"Rar!\x1a\x07", "RAR archive data"),
    (0, b"\x1f\x8b", "gzip compressed data"),
    (0, b"BZh", "bzip2 compressed data"),
    (0, b"\xfd7zXZ", "XZ compressed data"),
    (0, b"%PDF-", "PDF document"),
    (0, b"\x7fELF", "ELF"),
    (0, b"MZ", "PE32 executable"),
    (0, b"\x89PNG", "PNG image data"),
    (0, b"GIF8", "GIF image data"),
    (0, b"\xff\xd8\xff", "JPEG image data"),
];

/// The libmagic-style description of content, from its leading bytes.
pub fn describe(data: &[u8]) -> Option<&'static str> {
    DESCRIPTIONS.iter().find(|(at, sig, _)| data.get(*at..).is_some_and(|rest| rest.starts_with(sig))).map(|(_, _, d)| *d)
}

/// SHA-1, for the rules that identify content by it. Not used for anything
/// that needs to resist an attacker; it is the digest those rules name.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// An MD5 as lower-case hex.
pub fn md5_hex(data: &[u8]) -> String {
    hex(&Md5::digest(data))
}

/// Raw MD5 and SHA-256 digests, for the same rules.
pub fn md5_raw(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}

pub fn sha256_raw(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Identifies content by its leading bytes.
///
/// Extension-free and claim-free on purpose: a `Content-Type` header and
/// a filename are both chosen by whoever is uploading, and the whole
/// value of this check is that the magic number is not.
pub fn identify(data: &[u8]) -> Option<&'static str> {
    MAGIC.iter().find(|(sig, _)| data.starts_with(sig)).map(|(_, name)| *name)
}

/// Hashes and identifies one piece of content.
///
/// Returns `None` for an empty body, which is not a file.
pub fn inspect(data: &[u8]) -> Option<FileInfo> {
    if data.is_empty() {
        return None;
    }
    let truncated = data.len() > MAX_HASHED_BYTES;
    let hashed = &data[..data.len().min(MAX_HASHED_BYTES)];

    let md5 = hex(&Md5::digest(hashed));
    let sha256 = hex(&Sha256::digest(hashed));

    Some(FileInfo { size: data.len(), md5, sha256, truncated, kind: identify(data), magic: describe(data) })
}

/// How much of one transfer is hashed when streaming.
///
/// Streaming hashing holds no body in memory, so the only thing being
/// bounded is CPU: a hostile server can otherwise hand a sensor an
/// endless response and keep it hashing forever. Past this the hashes
/// describe a prefix, and say so.
pub const MAX_STREAM_HASH: u64 = 64 * 1024 * 1024;

/// Hashes a body as it arrives, without buffering it.
///
/// The reassembly budget (`-stream-cap`, 16KB by default) is far too
/// small to hold a real download, and raising it to hold one would turn
/// the sensor into a memory exhaustion target. A running digest needs
/// about two hundred bytes however large the file is, which is why file
/// hashing is done this way rather than by inspecting a buffer.
/// Leading bytes kept for typing: enough to reach a tar header's magic.
const HEAD_BYTES: usize = 264;

pub struct FileHasher {
    md5: Md5,
    sha256: Sha256,
    size: u64,
    head: [u8; HEAD_BYTES],
    head_len: usize,
    truncated: bool,
}

impl Default for FileHasher {
    fn default() -> Self {
        FileHasher { md5: Md5::new(), sha256: Sha256::new(), size: 0, head: [0; HEAD_BYTES], head_len: 0, truncated: false }
    }
}

impl FileHasher {
    pub fn update(&mut self, data: &[u8]) {
        if self.truncated || data.is_empty() {
            return;
        }
        let room = MAX_STREAM_HASH - self.size;
        let take = (data.len() as u64).min(room) as usize;
        let data_in = &data[..take];
        if self.head_len < self.head.len() {
            let n = (self.head.len() - self.head_len).min(data_in.len());
            self.head[self.head_len..self.head_len + n].copy_from_slice(&data_in[..n]);
            self.head_len += n;
        }
        self.md5.update(data_in);
        self.sha256.update(data_in);
        self.size += take as u64;
        if take < data.len() {
            self.truncated = true;
        }
    }

    /// `incomplete` marks a body whose leading bytes were never seen (a
    /// mid-stream pickup, or bytes lost before hashing began), so the
    /// digest describes something other than the file.
    pub fn finish(self, incomplete: bool) -> Option<FileInfo> {
        if self.size == 0 {
            return None;
        }
        Some(FileInfo {
            size: self.size as usize,
            md5: hex(&self.md5.finalize()),
            sha256: hex(&self.sha256.finalize()),
            truncated: self.truncated || incomplete,
            kind: identify(&self.head[..self.head_len]),
            magic: describe(&self.head[..self.head_len]),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkState {
    /// Reading the hex chunk size.
    Size,
    /// Skipping a chunk extension up to the end of the size line.
    Extension,
    Data(u64),
    /// The CRLF that follows chunk data; how many bytes are left of it.
    DataEnd(u8),
}

/// Decodes `Transfer-Encoding: chunked` incrementally.
///
/// A great many downloads are chunked, and a hash of the wire bytes would
/// include the size lines: a digest that matches nothing anyone has ever
/// published. The decoder yields only the payload.
pub struct Dechunker {
    state: ChunkState,
    size: u64,
    seen_digit: bool,
    pub done: bool,
    /// The stream stopped being valid chunked encoding.
    pub bad: bool,
}

impl Default for Dechunker {
    fn default() -> Self {
        Dechunker { state: ChunkState::Size, size: 0, seen_digit: false, done: false, bad: false }
    }
}

impl Dechunker {
    pub fn feed(&mut self, data: &[u8], mut sink: impl FnMut(&[u8])) {
        let mut i = 0;
        while i < data.len() && !self.done {
            match self.state {
                ChunkState::Size | ChunkState::Extension => {
                    let b = data[i];
                    i += 1;
                    match b {
                        b'\n' => {
                            if !self.seen_digit {
                                self.fail();
                            } else if self.size == 0 {
                                // The last chunk. Trailers may follow, and
                                // none of them is body.
                                self.done = true;
                            } else {
                                self.state = ChunkState::Data(self.size);
                            }
                        }
                        b'\r' => {}
                        b';' => self.state = ChunkState::Extension,
                        _ if self.state == ChunkState::Extension => {}
                        _ => match (b as char).to_digit(16) {
                            Some(d) => {
                                // No legitimate chunk approaches 4GB, and
                                // refusing here also rules out overflow.
                                self.size = match self.size.checked_mul(16).and_then(|v| v.checked_add(d as u64)) {
                                    Some(v) if v <= u32::MAX as u64 => v,
                                    _ => {
                                        self.fail();
                                        return;
                                    }
                                };
                                self.seen_digit = true;
                            }
                            None => self.fail(),
                        },
                    }
                }
                ChunkState::Data(n) => {
                    let take = (n as usize).min(data.len() - i);
                    sink(&data[i..i + take]);
                    i += take;
                    let left = n - take as u64;
                    self.state = if left == 0 { ChunkState::DataEnd(2) } else { ChunkState::Data(left) };
                }
                ChunkState::DataEnd(k) => {
                    i += 1;
                    if k <= 1 {
                        self.state = ChunkState::Size;
                        self.size = 0;
                        self.seen_digit = false;
                    } else {
                        self.state = ChunkState::DataEnd(k - 1);
                    }
                }
            }
        }
    }

    fn fail(&mut self) {
        self.bad = true;
        self.done = true;
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against the published vectors, because a hash implementation that
    /// is subtly wrong produces a plausible-looking string that simply
    /// never matches a feed — the most useless possible failure.
    #[test]
    fn hashes_match_the_published_vectors() {
        let info = inspect(b"abc").unwrap();
        assert_eq!(info.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(info.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(info.size, 3);
        assert!(!info.truncated);
    }

    #[test]
    fn an_empty_body_is_not_a_file() {
        assert!(inspect(b"").is_none());
    }

    /// The flag is the point: a hash of a prefix will not match a
    /// published hash of the whole file, and the reader has to be able
    /// to tell that is why.
    #[test]
    fn oversized_content_is_hashed_as_a_prefix_and_says_so() {
        let big = vec![b'A'; MAX_HASHED_BYTES + 1000];
        let info = inspect(&big).unwrap();
        assert!(info.truncated);
        assert_eq!(info.size, MAX_HASHED_BYTES + 1000, "the real size is still reported");

        // The hash is of exactly the prefix, not of the whole buffer.
        let prefix_only = inspect(&big[..MAX_HASHED_BYTES]).unwrap();
        assert_eq!(info.md5, prefix_only.md5);
        assert!(!prefix_only.truncated);
    }

    #[test]
    fn executables_are_identified_by_their_magic_numbers() {
        assert_eq!(identify(b"MZ\x90\x00\x03"), Some("dos/pe-executable"));
        assert_eq!(identify(b"\x7fELF\x02\x01"), Some("elf-executable"));
        assert_eq!(identify(b"PK\x03\x04\x14"), Some("zip-or-office"));
        assert_eq!(identify(b"%PDF-1.7"), Some("pdf"));
        assert_eq!(identify(b"#!/bin/sh\n"), Some("script-with-shebang"));
    }

    /// The magic number is the point: a filename and a `Content-Type`
    /// are both chosen by the uploader, and the leading bytes are not.
    #[test]
    fn content_claiming_to_be_text_is_still_identified_as_what_it_is() {
        let info = inspect(b"MZ\x90\x00this was uploaded as report.txt").unwrap();
        assert_eq!(info.kind, Some("dos/pe-executable"));
    }

    #[test]
    fn unrecognised_content_reports_no_type_rather_than_guessing() {
        assert_eq!(identify(b"just some ordinary form data"), None);
        assert_eq!(inspect(b"just some ordinary form data").unwrap().kind, None);
    }

    #[test]
    fn a_one_byte_body_is_still_a_file() {
        let info = inspect(b"x").unwrap();
        assert_eq!(info.size, 1);
        assert_eq!(info.md5.len(), 32);
        assert_eq!(info.sha256.len(), 64);
    }
    #[test]
    fn streaming_and_one_shot_hashing_agree() {
        let whole = inspect(b"the quick brown fox").unwrap();
        let mut h = FileHasher::default();
        for chunk in [&b"the qu"[..], b"ick br", b"own fox"] {
            h.update(chunk);
        }
        let streamed = h.finish(false).unwrap();
        assert_eq!((&streamed.md5, &streamed.sha256, streamed.size), (&whole.md5, &whole.sha256, whole.size));
    }

    #[test]
    fn a_streaming_hash_of_a_body_it_only_partly_saw_says_so() {
        let mut h = FileHasher::default();
        h.update(b"abc");
        assert!(h.finish(true).unwrap().truncated);
    }

    #[test]
    fn chunked_bodies_are_decoded_before_hashing() {
        let wire = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut d = Dechunker::default();
        let mut body = Vec::new();
        d.feed(wire, |b| body.extend_from_slice(b));
        assert_eq!(body, b"hello world");
        assert!(d.done && !d.bad);
    }

    /// Segments split anywhere, including inside a size line.
    #[test]
    fn a_chunked_body_split_at_every_byte_decodes_the_same() {
        let wire = b"a;ext=1\r\n0123456789\r\n3\r\nabc\r\n0\r\n\r\n";
        let mut d = Dechunker::default();
        let mut body = Vec::new();
        for b in wire.chunks(1) {
            d.feed(b, |x| body.extend_from_slice(x));
        }
        assert_eq!(body, b"0123456789abc");
        assert!(d.done && !d.bad);
    }

    #[test]
    fn malformed_chunking_stops_rather_than_hashing_garbage() {
        let mut d = Dechunker::default();
        d.feed(b"zz\r\n", |_| panic!("no payload was delivered"));
        assert!(d.bad && d.done);
    }

    #[test]
    fn sha1_matches_the_published_vectors() {
        let hex_of = |d: [u8; 20]| d.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(hex_of(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex_of(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex_of(sha1(b"The quick brown fox jumps over the lazy dog")), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
        // Across the 55/56/64-byte padding boundaries.
        assert_eq!(hex_of(sha1(&[b'a'; 56])), "c2db330f6083854c99d4b5bfb6e8f29f201be699");
        assert_eq!(hex_of(sha1(&[b'a'; 64])), "0098ba824b5c16427bd7a1122a5a442a25ec644d");
        assert_eq!(hex_of(sha1(&[b'a'; 1000])), "291e9a6c66994949b57ba5e650361e98fc36b1ba");
    }

    #[test]
    fn descriptions_name_the_types_rules_quote() {
        assert!(describe(b"PK\x03\x04rest").unwrap().starts_with("Zip archive"));
        let mut tar = vec![0u8; 300];
        tar[257..263].copy_from_slice(b"ustar\x00");
        assert!(describe(&tar).unwrap().starts_with("POSIX tar archive"));
        assert!(describe(b"7z\xbc\xaf\x27\x1c\x00\x04").unwrap().starts_with("7-zip archive"));
        assert_eq!(describe(b"plain text"), None);
        assert_eq!(describe(&[0u8; 10]), None, "a short buffer is not a tar header");
    }

}
