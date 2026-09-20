//! The certificate a TLS server sends, read out of the handshake.
//!
//! Before TLS 1.3 the server's certificate chain crosses the wire in the
//! clear, and it is the most useful thing a passive sensor can read about
//! a server it has never heard of: who it says it is, who vouched for it,
//! and under which serial. A great many rules are written about exactly
//! that, because a command-and-control server's certificate is often more
//! stable than its address.
//!
//! This reads only what rules ask about: the subject, the issuer, the
//! serial and the raw DER of each certificate. It does not validate
//! anything, and says nothing about whether the chain is trustworthy.
//! From TLS 1.3 on, certificates are encrypted and this finds nothing.

/// One certificate of the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    pub subject: String,
    pub issuer: String,
    /// Upper-case hex pairs joined by `:`, as rule authors write it.
    pub serial: String,
    /// The certificate exactly as sent.
    pub der: Vec<u8>,
}

/// What reading a server's handshake found so far.
#[derive(Debug, PartialEq, Eq)]
pub enum Scan {
    /// The handshake is still arriving; try again with more.
    Incomplete,
    /// This stream carries no readable certificate, and never will.
    None,
    Found(Vec<Cert>),
}

const HANDSHAKE: u8 = 0x16;
const CERTIFICATE: u8 = 11;

/// Reads the certificate chain from a server-to-client TLS stream.
///
/// The handshake messages are reassembled across records first, because a
/// chain of several certificates is routinely larger than one record and
/// is not required to start on a record boundary.
pub fn scan(stream: &[u8]) -> Scan {
    if stream.is_empty() {
        return Scan::Incomplete;
    }
    let mut handshake: Vec<u8> = Vec::new();
    let mut at = 0;
    let mut cut_off = false;
    while at < stream.len() {
        if stream.len() - at < 5 {
            cut_off = true;
            break;
        }
        let kind = stream[at];
        let len = u16::from_be_bytes([stream[at + 3], stream[at + 4]]) as usize;
        // The first record that is not handshake is a change of cipher
        // or application data: whatever certificate there was has passed.
        if kind != HANDSHAKE {
            return finish(&handshake, false);
        }
        if stream.len() - at - 5 < len {
            cut_off = true;
            break;
        }
        handshake.extend_from_slice(&stream[at + 5..at + 5 + len]);
        at += 5 + len;
    }
    finish(&handshake, cut_off)
}

/// `more` is whether the stream is known to continue past what is here.
fn finish(handshake: &[u8], more: bool) -> Scan {
    let mut at = 0;
    while handshake.len() - at >= 4 {
        let kind = handshake[at];
        let len = u32::from_be_bytes([0, handshake[at + 1], handshake[at + 2], handshake[at + 3]]) as usize;
        let body = at + 4;
        if handshake.len() - body < len {
            return Scan::Incomplete;
        }
        if kind == CERTIFICATE {
            return match certificate_list(&handshake[body..body + len]) {
                Some(chain) => Scan::Found(chain),
                None => Scan::None,
            };
        }
        at = body + len;
    }
    if more || handshake.len() - at > 0 {
        Scan::Incomplete
    } else {
        // Handshake messages all read, none of them a certificate: the
        // server is resuming a session, or is not sending one.
        Scan::None
    }
}

fn certificate_list(body: &[u8]) -> Option<Vec<Cert>> {
    if body.len() < 3 {
        return None;
    }
    let total = u32::from_be_bytes([0, body[0], body[1], body[2]]) as usize;
    let mut list = body.get(3..3 + total)?;
    let mut chain = Vec::new();
    while list.len() >= 3 {
        let n = u32::from_be_bytes([0, list[0], list[1], list[2]]) as usize;
        let der = list.get(3..3 + n)?;
        if let Some(cert) = parse_certificate(der) {
            chain.push(cert);
        }
        list = &list[3 + n..];
    }
    (!chain.is_empty()).then_some(chain)
}

/// A DER element: its tag, and the bytes of its contents.
struct Der<'a> {
    tag: u8,
    body: &'a [u8],
}

/// Reads one element from the front, returning it and what follows.
fn element(buf: &[u8]) -> Option<(Der<'_>, &[u8])> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        // Four length bytes is 4 GiB, more than any certificate; more
        // than that is a malformed or hostile encoding.
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in buf.get(2..2 + n)? {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };
    let body = buf.get(header..header.checked_add(len)?)?;
    Some((Der { tag, body }, &buf[header + len..]))
}

fn parse_certificate(der: &[u8]) -> Option<Cert> {
    let (cert, _) = element(der)?;
    let (tbs, _) = element(cert.body)?;
    let mut rest = tbs.body;
    let (mut e, mut after) = element(rest)?;
    // The version is an optional explicit [0]; the serial follows it.
    if e.tag == 0xa0 {
        rest = after;
        (e, after) = element(rest)?;
    }
    if e.tag != 0x02 {
        return None;
    }
    let serial = format_serial(e.body);
    let (_signature, after) = element(after)?;
    let (issuer, after) = element(after)?;
    let (_validity, after) = element(after)?;
    let (subject, _) = element(after)?;
    Some(Cert { subject: name(subject.body), issuer: name(issuer.body), serial, der: der.to_vec() })
}

fn format_serial(raw: &[u8]) -> String {
    // A serial with its top bit set is written with a leading zero byte so
    // it stays positive; that byte is an encoding detail, not part of the
    // number people quote.
    let raw = if raw.len() > 1 && raw[0] == 0 { &raw[1..] } else { raw };
    raw.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
}

/// A distinguished name as `C=US, O=Example, CN=host`, in encoded order.
fn name(mut rdns: &[u8]) -> String {
    let mut parts = Vec::new();
    while let Some((set, next)) = element(rdns) {
        let mut avas = set.body;
        while let Some((seq, more)) = element(avas) {
            if let Some((oid, tail)) = element(seq.body) {
                if let Some((value, _)) = element(tail) {
                    parts.push(format!("{}={}", attribute(oid.body), text(&value)));
                }
            }
            avas = more;
        }
        rdns = next;
    }
    parts.join(", ")
}

/// The short name of an attribute, or its dotted OID when it has none.
fn attribute(oid: &[u8]) -> String {
    match oid {
        [0x55, 0x04, last] => match last {
            3 => "CN",
            4 => "SN",
            5 => "serialNumber",
            6 => "C",
            7 => "L",
            8 => "ST",
            9 => "street",
            10 => "O",
            11 => "OU",
            12 => "title",
            17 => "postalCode",
            _ => return dotted(oid),
        }
        .to_string(),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress".to_string(),
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC".to_string(),
        _ => dotted(oid),
    }
}

fn dotted(oid: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut value: u64 = 0;
    for (i, b) in oid.iter().enumerate() {
        value = (value << 7) | (*b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if i == oid.len() - 1 || !parts.is_empty() {
                parts.push(value.to_string());
            } else {
                // The first byte packs two arcs.
                parts.push((value / 40).min(2).to_string());
                parts.push((value - 40 * (value / 40).min(2)).to_string());
            }
            value = 0;
        }
    }
    parts.join(".")
}

fn text(v: &Der<'_>) -> String {
    match v.tag {
        // BMPString is UTF-16, big endian.
        0x1e => {
            let units: Vec<u16> = v.body.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(v.body).into_owned(),
    }
}

/// Builders for handshakes, shared with the engine's tests.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;

    pub(crate) fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else {
            out.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]);
        }
        out.extend_from_slice(body);
        out
    }

    pub(crate) fn attr(oid: &[u8], value: &str) -> Vec<u8> {
        tlv(0x31, &tlv(0x30, &[tlv(0x06, oid), tlv(0x0c, value.as_bytes())].concat()))
    }

    pub(crate) const CN: &[u8] = &[0x55, 0x04, 0x03];
    pub(crate) const C: &[u8] = &[0x55, 0x04, 0x06];
    pub(crate) const O: &[u8] = &[0x55, 0x04, 0x0a];

    /// A certificate with just the fields this reads, in the right order.
    pub(crate) fn cert(serial: &[u8], issuer: &[u8], subject: &[u8]) -> Vec<u8> {
        let tbs = [
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, serial),
            tlv(0x30, &tlv(0x06, &[0x2a])),
            tlv(0x30, issuer),
            tlv(0x30, &[]),
            tlv(0x30, subject),
        ]
        .concat();
        tlv(0x30, &tlv(0x30, &tbs))
    }

    pub(crate) fn sample() -> Vec<u8> {
        cert(
            &[0x00, 0x89, 0xbf, 0x80],
            &[attr(C, "US"), attr(O, "Let's Encrypt"), attr(CN, "R3")].concat(),
            &[attr(CN, "evil.example")].concat(),
        )
    }

    pub(crate) fn message(certs: &[Vec<u8>]) -> Vec<u8> {
        let list: Vec<u8> = certs.iter().flat_map(|c| [&[0u8, (c.len() >> 8) as u8, c.len() as u8][..], c].concat()).collect();
        let mut body = vec![0, (list.len() >> 8) as u8, list.len() as u8];
        body.extend(list);
        let mut msg = vec![CERTIFICATE, 0, (body.len() >> 8) as u8, body.len() as u8];
        msg.extend(body);
        msg
    }

    pub(crate) fn record(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![HANDSHAKE, 3, 3, (payload.len() >> 8) as u8, payload.len() as u8];
        out.extend_from_slice(payload);
        out
    }


    /// A server's flight: one record holding a certificate message.
    pub(crate) fn server_flight(subject: &str, issuer: &str, serial: &[u8]) -> Vec<u8> {
        let c = cert(serial, &attr(CN, issuer), &attr(CN, subject));
        record(&message(&[c]))
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    fn found(scan: Scan) -> Vec<Cert> {
        match scan {
            Scan::Found(c) => c,
            other => panic!("expected certificates, got {:?}", other),
        }
    }

    #[test]
    fn reads_subject_issuer_and_serial() {
        let c = &found(scan(&record(&message(&[sample()]))))[0];
        assert_eq!(c.subject, "CN=evil.example");
        assert_eq!(c.issuer, "C=US, O=Let's Encrypt, CN=R3");
        // The leading zero that keeps a DER integer positive is not part of it.
        assert_eq!(c.serial, "89:BF:80");
        assert_eq!(c.der, sample());
    }

    #[test]
    fn a_chain_yields_each_certificate_in_order() {
        let a = sample();
        let b = cert(&[1], &attr(CN, "Root"), &attr(CN, "Intermediate"));
        let chain = found(scan(&record(&message(&[a, b]))));
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].subject, "CN=Intermediate");
    }

    #[test]
    fn a_message_split_across_records_is_reassembled() {
        let msg = message(&[sample()]);
        let (x, y) = msg.split_at(msg.len() / 2);
        let stream = [record(x), record(y)].concat();
        assert_eq!(found(scan(&stream))[0].subject, "CN=evil.example");
    }

    #[test]
    fn a_certificate_after_other_handshake_messages_is_found() {
        let hello = [vec![2u8, 0, 0, 4], vec![3, 3, 0, 0]].concat();
        let stream = record(&[hello, message(&[sample()])].concat());
        assert_eq!(found(scan(&stream))[0].serial, "89:BF:80");
    }

    #[test]
    fn a_partial_handshake_is_incomplete_at_every_length() {
        let stream = record(&message(&[sample()]));
        for n in 0..stream.len() {
            assert_eq!(scan(&stream[..n]), Scan::Incomplete, "a {}-byte prefix is not a whole handshake", n);
        }
    }

    #[test]
    fn application_data_ends_the_search() {
        let mut stream = record(&[2, 0, 0, 4, 3, 3, 0, 0]);
        stream.extend_from_slice(&[0x17, 3, 3, 0, 1, 0]);
        assert_eq!(scan(&stream), Scan::None);
    }

    #[test]
    fn a_bmp_string_and_an_unknown_attribute_are_rendered() {
        let bmp = tlv(0x31, &tlv(0x30, &[tlv(0x06, CN), tlv(0x1e, &[0, b'h', 0, b'i'])].concat()));
        let odd = attr(&[0x2b, 0x06, 0x01], "x");
        let c = cert(&[1], &attr(CN, "i"), &[bmp, odd].concat());
        assert_eq!(found(scan(&record(&message(&[c]))))[0].subject, "CN=hi, 1.3.6.1=x");
    }

    #[test]
    fn hostile_encodings_do_not_panic() {
        // A length that claims more than there is, and one that is absurd.
        for junk in [vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff], vec![0x30, 0x80], vec![0x30, 0x05, 1, 2], vec![]] {
            assert!(parse_certificate(&junk).is_none());
        }
        let stream = record(&message(&[vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff]]));
        assert_eq!(scan(&stream), Scan::None);
    }
}
