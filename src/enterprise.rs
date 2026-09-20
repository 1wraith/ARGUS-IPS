//! The cleartext protocols an intruder actually moves through.
//!
//! Everything ARGUS parsed before this module is either a client talking
//! to the internet (HTTP, DNS, TLS) or an industrial protocol. The
//! traffic that carries a *lateral* intrusion — the part after the first
//! host falls — is different: SMB, NTLM, Kerberos, LDAP and DCERPC, on
//! an internal network, very largely in the clear.
//!
//! That last point is what makes this worth doing. A sensor watching an
//! internal segment can read an NTLM authentication in full, including
//! the account and workstation names, because the protocol was designed
//! before anyone assumed the network was hostile. Those names are the
//! most directly actionable thing on the wire: "this workstation just
//! authenticated as a service account it has never used" is an incident,
//! and no volume statistic will ever say it.
//!
//! # Scope, stated rather than implied
//!
//! Each parser here extracts identifying fields and stops. None of them
//! reassembles a whole session, follows a DCERPC bind to its operation,
//! or decrypts anything. A Kerberos exchange that has moved to
//! encrypted timestamps yields a realm and a principal and nothing more;
//! an SMB session with signing and encryption negotiated yields the
//! negotiation and then goes dark. That is the honest ceiling for a
//! passive observer, and each parser is written to reach it and then
//! return `None` rather than guess.
//!
//! # Why one module
//!
//! These five share a shape: a small amount of framing, then a
//! length-prefixed or ASN.1-tagged structure, from which one or two
//! strings are worth extracting. They also share failure modes —
//! attacker-controlled lengths, nested structures, strings in UTF-16 —
//! and the helpers for those live here once rather than five times.

// =======================================================================
// Shared primitives
// =======================================================================

/// Reads a UTF-16LE string of `bytes` bytes, lossily.
///
/// Windows protocols carry names in UTF-16LE, and a malformed pair is
/// not a reason to discard an otherwise readable field: an intruder
/// choosing an unpaired surrogate to hide a username would be a cheap
/// evasion, and the replacement character is still a distinguishable
/// name.
fn utf16le(buf: &[u8]) -> String {
    let units: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Bounds every string this module will produce.
///
/// A length field in any of these protocols is attacker-chosen. The cap
/// is well past any legitimate account, host or path name, and it is the
/// difference between a parser and an allocation primitive.
const MAX_FIELD: usize = 1024;

fn field_at(buf: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    if len == 0 || len > MAX_FIELD {
        return None;
    }
    buf.get(offset..offset.checked_add(len)?)
}

/// Finds a byte pattern, for the protocols that embed one structure
/// inside another without saying where.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// =======================================================================
// NTLM
// =======================================================================

/// What an NTLM message says about who is authenticating.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NtlmInfo {
    /// NEGOTIATE, CHALLENGE or AUTHENTICATE.
    pub message: &'static str,
    /// The account, from an AUTHENTICATE message.
    pub user: Option<String>,
    /// The domain the account belongs to.
    pub domain: Option<String>,
    /// The machine the client claims to be.
    pub workstation: Option<String>,
    /// The server's name, from a CHALLENGE message.
    pub server: Option<String>,
}

/// NTLMSSP messages are embedded in SMB session setup, in HTTP
/// `Authorization: NTLM` headers, and in several RPC transports. They
/// are found by their signature rather than by their container, so one
/// parser serves all of them.
pub const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

/// Parses an NTLMSSP message found anywhere in `buf`.
///
/// The three message types are structurally different and only the third
/// carries an identity, which is the one worth having: an AUTHENTICATE
/// message names the account, its domain and the workstation it came
/// from, all in the clear, in a protocol still in daily use.
pub fn parse_ntlm(buf: &[u8]) -> Option<NtlmInfo> {
    let start = find(buf, NTLMSSP_SIGNATURE)?;
    let msg = &buf[start..];
    if msg.len() < 12 {
        return None;
    }
    let message_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);

    // Every variable field is the same shape: length, allocated length,
    // then an offset from the start of the NTLMSSP message.
    let read_field = |at: usize| -> Option<String> {
        let len = u16::from_le_bytes([*msg.get(at)?, *msg.get(at + 1)?]) as usize;
        let offset = u32::from_le_bytes([*msg.get(at + 4)?, *msg.get(at + 5)?, *msg.get(at + 6)?, *msg.get(at + 7)?]) as usize;
        let raw = field_at(msg, offset, len)?;
        let s = utf16le(raw);
        // A field present but empty is not an identity, and neither is
        // one that decoded to nothing readable.
        (!s.is_empty()).then_some(s)
    };

    Some(match message_type {
        1 => NtlmInfo { message: "NEGOTIATE", domain: read_field(16), workstation: read_field(24), ..Default::default() },
        2 => NtlmInfo { message: "CHALLENGE", server: read_field(12), ..Default::default() },
        3 => NtlmInfo {
            message: "AUTHENTICATE",
            domain: read_field(28),
            user: read_field(36),
            workstation: read_field(44),
            ..Default::default()
        },
        _ => return None,
    })
}

// =======================================================================
// SMB1
// =======================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Smb1Info {
    pub command: &'static str,
    /// The path from a TREE_CONNECT, or the name from an OPEN.
    pub path: Option<String>,
    /// An NTLM message carried inside SESSION_SETUP.
    pub ntlm: Option<NtlmInfo>,
}

/// The commands worth naming. SMB1 has around eighty; these are the ones
/// that carry identity, move files, or appear in the exploit traffic the
/// protocol is now mostly known for.
const SMB1_COMMANDS: [(u8, &str); 14] = [
    (0x72, "NEGOTIATE"),
    (0x73, "SESSION_SETUP_ANDX"),
    (0x74, "LOGOFF_ANDX"),
    (0x75, "TREE_CONNECT_ANDX"),
    (0x71, "TREE_DISCONNECT"),
    (0x2d, "OPEN_ANDX"),
    (0xa2, "NT_CREATE_ANDX"),
    (0x2e, "READ_ANDX"),
    (0x2f, "WRITE_ANDX"),
    (0x04, "CLOSE"),
    (0x25, "TRANSACTION"),
    (0x32, "TRANSACTION2"),
    (0xa0, "NT_TRANSACT"),
    (0x06, "DELETE"),
];

/// Parses an SMB1 message.
///
/// SMB1 is disabled by default on current Windows and still present on a
/// great many networks, which is exactly why it is worth parsing: the
/// hosts still speaking it are the ones least likely to be patched, and
/// SMB1 is the protocol EternalBlue and every worm built on it use.
pub fn parse_smb1_message(msg: &[u8]) -> Option<Smb1Info> {
    // 0xFF 'SMB' and a 32-byte header.
    if msg.len() < 33 || msg[0] != 0xFF || &msg[1..4] != b"SMB" {
        return None;
    }
    let code = msg[4];
    let command = SMB1_COMMANDS.iter().find(|(c, _)| *c == code).map(|(_, n)| *n).unwrap_or("UNKNOWN");

    // Flags2 bit 15 says strings are UTF-16LE rather than OEM bytes.
    let flags2 = u16::from_le_bytes([msg[10], msg[11]]);
    let unicode = flags2 & 0x8000 != 0;

    // The parameter block is counted in 16-bit words, then a byte count,
    // then the data. Everything interesting is in the data.
    let word_count = msg[32] as usize;
    let data_offset = 33 + word_count * 2;
    let byte_count = u16::from_le_bytes([*msg.get(data_offset)?, *msg.get(data_offset + 1)?]) as usize;
    let data = msg.get(data_offset + 2..(data_offset + 2).checked_add(byte_count)?)?;

    let ntlm = parse_ntlm(data);
    let path = match code {
        // TREE_CONNECT_ANDX ends with the share path, which names what
        // is being reached: IPC$ for a named-pipe session, ADMIN$ for
        // the kind of access a tool like PsExec needs.
        0x75 => last_string(data, unicode),
        0xa2 | 0x2d => first_string(data, unicode),
        _ => None,
    };
    Some(Smb1Info { command, path, ntlm })
}

/// The first NUL-terminated string in a data block.
fn first_string(data: &[u8], unicode: bool) -> Option<String> {
    if unicode {
        // Strings are two-byte aligned relative to the message, and the
        // pad byte is not counted anywhere — so both alignments are
        // tried rather than assumed.
        for skip in [0usize, 1] {
            let body = data.get(skip..)?;
            let end = body.chunks_exact(2).position(|c| c == [0, 0]).map(|i| i * 2).unwrap_or(body.len() & !1);
            if end > 0 {
                let s = utf16le(&body[..end.min(MAX_FIELD)]);
                if s.chars().all(|c| !c.is_control()) && !s.is_empty() {
                    return Some(s);
                }
            }
        }
        None
    } else {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        let s = String::from_utf8_lossy(&data[..end.min(MAX_FIELD)]).into_owned();
        (!s.is_empty()).then_some(s)
    }
}

/// The last NUL-terminated string, which is where TREE_CONNECT keeps the
/// share path — the service type follows it as plain ASCII.
fn last_string(data: &[u8], unicode: bool) -> Option<String> {
    if unicode {
        // Scan backwards for a run of printable UTF-16, which is more
        // robust than counting the variable-length fields before it.
        let mut best: Option<String> = None;
        for skip in [0usize, 1] {
            let body = data.get(skip..)?;
            let mut at = 0usize;
            while at + 1 < body.len() {
                let end = body[at..].chunks_exact(2).position(|c| c == [0, 0]).map(|i| at + i * 2).unwrap_or(body.len() & !1);
                if end > at {
                    let s = utf16le(&body[at..end.min(at + MAX_FIELD)]);
                    if s.starts_with("\\\\") || s.contains('$') {
                        best = Some(s);
                    }
                }
                at = end + 2;
            }
            if best.is_some() {
                return best;
            }
        }
        best
    } else {
        data.split(|&b| b == 0)
            .filter(|s| !s.is_empty() && s.len() <= MAX_FIELD)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .find(|s| s.starts_with("\\\\") || s.contains('$'))
    }
}

// =======================================================================
// Minimal ASN.1 / DER, for Kerberos and LDAP
// =======================================================================

/// One DER element: tag, and the bytes of its contents.
struct Der<'a> {
    tag: u8,
    value: &'a [u8],
    /// Total bytes consumed, including the header.
    total: usize,
}

/// Reads one DER element.
///
/// Long-form lengths are supported up to four bytes, which is far past
/// anything legitimate in these protocols, and indefinite-length
/// encoding is refused: it is not valid DER, and accepting it would mean
/// scanning forward for a terminator an attacker chooses.
fn der(buf: &[u8], at: usize) -> Option<Der<'_>> {
    let tag = *buf.get(at)?;
    let first_len = *buf.get(at + 1)? as usize;
    let (len, header) = if first_len < 0x80 {
        (first_len, 2)
    } else {
        let n = first_len & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | *buf.get(at + 2 + i)? as usize;
        }
        (v, 2 + n)
    };
    let start = at.checked_add(header)?;
    let value = buf.get(start..start.checked_add(len)?)?;
    Some(Der { tag, value, total: header + len })
}

/// Walks a DER structure depth-first, calling `f` for every element.
///
/// Bounded in depth, because nesting is attacker-controlled and an
/// unbounded recursive descent over hostile input is a stack overflow
/// waiting to be triggered.
fn der_walk(buf: &[u8], depth: usize, f: &mut impl FnMut(u8, &[u8])) {
    const MAX_DEPTH: usize = 24;
    if depth > MAX_DEPTH {
        return;
    }
    let mut at = 0usize;
    while at < buf.len() {
        let Some(e) = der(buf, at) else { return };
        f(e.tag, e.value);
        // Bit 6 of the tag marks a constructed element, whose contents
        // are themselves DER.
        if e.tag & 0x20 != 0 {
            der_walk(e.value, depth + 1, f);
        }
        let Some(next) = at.checked_add(e.total.max(1)) else { return };
        at = next;
    }
}

// =======================================================================
// Kerberos
// =======================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KerberosInfo {
    pub message: &'static str,
    pub realm: Option<String>,
    /// The client principal, for an AS-REQ or TGS-REQ.
    pub client: Option<String>,
    /// The service being requested, e.g. `krbtgt/EXAMPLE.COM` or
    /// `cifs/fileserver`.
    pub service: Option<String>,
    /// From a KRB-ERROR: what the KDC said went wrong.
    pub error_code: Option<i64>,
}

/// KRB-ERROR codes that mean a credential was refused.
///
/// 24 is a wrong password (pre-authentication failed), 6 is an account
/// that does not exist — which is user *enumeration*, and is what a
/// spraying tool produces — and 18 is an account locked or revoked, the
/// surest sign a guessing run has been going on.
pub fn kerberos_error_is_auth_failure(code: i64) -> bool {
    matches!(code, 24 | 6 | 18)
}

/// Kerberos over TCP prefixes every message with a four-byte length,
/// which UDP does not. Without stripping it, a TCP exchange begins with
/// bytes that are not a Kerberos application tag and parses as nothing.
fn strip_tcp_record_mark(msg: &[u8]) -> &[u8] {
    const APP_TAGS: [u8; 6] = [0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x7e];
    if msg.len() > 5 && !APP_TAGS.contains(&msg[0]) && APP_TAGS.contains(&msg[4]) {
        let declared = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        // The declared length must fit what arrived; a wildly larger one
        // is not a record mark, it is coincidence.
        if declared <= msg.len() - 4 {
            return &msg[4..4 + declared];
        }
    }
    msg
}

/// Reads the `error-code` field of a KRB-ERROR: context tag 6 inside the
/// message's SEQUENCE.
fn krb_error_code(msg: &[u8]) -> Option<i64> {
    let app = der(msg, 0)?;
    let seq = der(app.value, 0)?;
    let mut at = 0;
    while at < seq.value.len() {
        let e = der(seq.value, at)?;
        if e.tag == 0xa6 {
            let int = der(e.value, 0)?;
            if int.tag == 0x02 && !int.value.is_empty() && int.value.len() <= 8 {
                return Some(int.value.iter().fold(if int.value[0] & 0x80 != 0 { -1i64 } else { 0 }, |acc, &b| (acc << 8) | b as i64));
            }
        }
        at += e.total.max(1);
    }
    None
}

/// Parses a Kerberos message.
///
/// The value here is the principal names, which are in the clear even
/// when everything else in the exchange is encrypted. A TGS-REQ names
/// the service being requested, which is what makes Kerberoasting and
/// unusual service-ticket requests visible at all.
pub fn parse_kerberos(msg: &[u8]) -> Option<KerberosInfo> {
    let msg = strip_tcp_record_mark(msg);
    // Application tags: AS-REQ 10, AS-REP 11, TGS-REQ 12, TGS-REP 13,
    // AP-REQ 14, KRB-ERROR 30.
    let first = *msg.first()?;
    let message = match first {
        0x6a => "AS-REQ",
        0x6b => "AS-REP",
        0x6c => "TGS-REQ",
        0x6d => "TGS-REP",
        0x6e => "AP-REQ",
        0x7e => "KRB-ERROR",
        _ => return None,
    };
    // Sanity-check the outer length before walking, so a truncated
    // datagram is refused rather than half-parsed.
    der(msg, 0)?;

    // GeneralString (tag 0x1b) holds every name in the structure; the
    // realm is conventionally the one in upper case with a dot, and the
    // principal components come before it.
    let mut strings: Vec<String> = Vec::new();
    der_walk(msg, 0, &mut |tag, value| {
        if tag == 0x1b && !value.is_empty() && value.len() <= MAX_FIELD {
            strings.push(String::from_utf8_lossy(value).into_owned());
        }
    });
    if strings.is_empty() {
        return None;
    }

    // A realm is all upper case and usually dotted; anything else is a
    // principal component. This is a convention rather than a rule, so
    // the fallback keeps the raw order instead of inventing structure.
    let realm = strings.iter().find(|s| s.contains('.') && s.chars().all(|c| !c.is_lowercase())).cloned();
    let names: Vec<&String> = strings.iter().filter(|s| Some(s.as_str()) != realm.as_deref()).collect();

    let (client, service) = match message {
        // An AS-REQ names the client first, then the service it wants
        // (nearly always krbtgt).
        "AS-REQ" | "TGS-REQ" => (names.first().map(|s| (*s).clone()), names.get(1..).map(|rest| rest.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("/")).filter(|s| !s.is_empty())),
        _ => (names.first().map(|s| (*s).clone()), None),
    };

    let error_code = if message == "KRB-ERROR" { krb_error_code(msg) } else { None };
    Some(KerberosInfo { message, realm, client, service, error_code })
}

// =======================================================================
// LDAP
// =======================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LdapInfo {
    pub operation: &'static str,
    /// The distinguished name being bound as, or searched from.
    pub dn: Option<String>,
    /// Whether a bind carried a password in the clear. Simple binds are
    /// still common on internal networks and are exactly the credential
    /// an intruder wants.
    pub simple_bind: bool,
    /// From a bindResponse: 0 is success, 49 is invalidCredentials.
    pub result_code: Option<u32>,
}

/// Parses an LDAP message.
///
/// A bind DN names an account, and a search base names what is being
/// enumerated — which is how directory reconnaissance looks on the wire.
pub fn parse_ldap(msg: &[u8]) -> Option<LdapInfo> {
    // LDAPMessage ::= SEQUENCE { messageID, protocolOp, ... }
    let outer = der(msg, 0)?;
    if outer.tag != 0x30 {
        return None;
    }
    let body = outer.value;
    let id = der(body, 0)?;
    if id.tag != 0x02 {
        return None;
    }
    let op = der(body, id.total)?;
    let operation = match op.tag {
        0x60 => "bindRequest",
        0x61 => "bindResponse",
        0x63 => "searchRequest",
        0x64 => "searchResEntry",
        0x66 => "modifyRequest",
        0x68 => "addRequest",
        0x6a => "delRequest",
        0x77 => "extendedReq",
        _ => return None,
    };

    let mut info = LdapInfo { operation, ..Default::default() };
    match op.tag {
        0x60 => {
            // BindRequest ::= SEQUENCE { version INTEGER, name LDAPDN,
            //                            authentication AuthenticationChoice }
            let version = der(op.value, 0)?;
            let name = der(op.value, version.total)?;
            if name.tag == 0x04 && !name.value.is_empty() && name.value.len() <= MAX_FIELD {
                info.dn = Some(String::from_utf8_lossy(name.value).into_owned());
            }
            // Context tag 0 is a simple (cleartext) password.
            if let Some(auth) = der(op.value, version.total + name.total) {
                info.simple_bind = auth.tag == 0x80;
            }
        }
        0x61 => {
            // BindResponse ::= SEQUENCE { resultCode ENUMERATED, ... }
            if let Some(rc) = der(op.value, 0) {
                if rc.tag == 0x0a && !rc.value.is_empty() && rc.value.len() <= 4 {
                    info.result_code = Some(rc.value.iter().fold(0u32, |a, &b| (a << 8) | b as u32));
                }
            }
        }
        0x63 | 0x64 => {
            let base = der(op.value, 0)?;
            if base.tag == 0x04 && !base.value.is_empty() && base.value.len() <= MAX_FIELD {
                info.dn = Some(String::from_utf8_lossy(base.value).into_owned());
            }
        }
        _ => {
            if let Some(first) = der(op.value, 0) {
                if first.tag == 0x04 && !first.value.is_empty() && first.value.len() <= MAX_FIELD {
                    info.dn = Some(String::from_utf8_lossy(first.value).into_owned());
                }
            }
        }
    }
    Some(info)
}

// =======================================================================
// DCERPC
// =======================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DcerpcInfo {
    pub packet_type: &'static str,
    /// The interface UUID a BIND is asking for, as text.
    ///
    /// This is the identity that matters: the UUID says which service is
    /// being reached, and several of them — the Service Control Manager,
    /// the Task Scheduler, DRSUAPI — are the remote-execution and
    /// credential-theft paths every intrusion toolkit uses.
    pub interface: Option<String>,
    /// A friendly name when the UUID is one of the well-known ones.
    pub interface_name: Option<&'static str>,
    pub opnum: Option<u16>,
}

const DCERPC_TYPES: [(u8, &str); 8] = [
    (0, "request"),
    (2, "response"),
    (3, "fault"),
    (11, "bind"),
    (12, "bind_ack"),
    (13, "bind_nak"),
    (14, "alter_context"),
    (15, "alter_context_resp"),
];

/// The interfaces worth naming, because reaching them is itself the
/// event. Written little-endian-first, as they appear on the wire.
const WELL_KNOWN_INTERFACES: [(&str, &str); 8] = [
    ("367abb81-9844-35f1-ad32-98f038001003", "svcctl (Service Control Manager)"),
    ("338cd001-2244-31f1-aaaa-900038001003", "winreg (Remote Registry)"),
    ("86d35949-83c9-4044-b424-db363231fd0c", "itaskschedulerservice"),
    ("1ff70682-0a51-30e8-076d-740be8cee98b", "atsvc (Task Scheduler)"),
    ("e3514235-4b06-11d1-ab04-00c04fc2dcd2", "drsuapi (Directory Replication)"),
    ("12345778-1234-abcd-ef00-0123456789ab", "lsarpc"),
    ("12345778-1234-abcd-ef00-0123456789ac", "samr"),
    ("4b324fc8-1670-01d3-1278-5a47bf6ee188", "srvsvc"),
];

/// Formats a DCERPC interface UUID, which is mixed-endian on the wire.
fn uuid_text(b: &[u8]) -> Option<String> {
    if b.len() < 16 {
        return None;
    }
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10..16].iter().map(|x| format!("{:02x}", x)).collect::<String>()
    ))
}

/// Parses a DCERPC (MS-RPCE) PDU.
pub fn parse_dcerpc(msg: &[u8]) -> Option<DcerpcInfo> {
    // Version 5.x, then the packet type.
    if msg.len() < 24 || msg[0] != 5 {
        return None;
    }
    let ptype = msg[2];
    let packet_type = DCERPC_TYPES.iter().find(|(t, _)| *t == ptype).map(|(_, n)| *n)?;

    let mut info = DcerpcInfo { packet_type, ..Default::default() };
    match ptype {
        11 | 14 => {
            // The layout, counted rather than guessed, because being
            // four bytes out here yields a plausible-looking UUID that
            // simply never matches anything:
            //
            //   common header                        16
            //   max_xmit(2) max_recv(2) assoc_group(4)  8  -> 24
            //   n_context_elem(1) reserved(3)           4  -> 28
            //   p_cont_id(2) n_transfer_syn(1) rsvd(1)  4  -> 32
            //   if_uuid                                16  -> 48
            const UUID_OFFSET: usize = 32;
            let uuid = msg.get(UUID_OFFSET..UUID_OFFSET + 16)?;
            let text = uuid_text(uuid)?;
            info.interface_name = WELL_KNOWN_INTERFACES.iter().find(|(u, _)| *u == text).map(|(_, n)| *n);
            info.interface = Some(text);
        }
        0 => {
            // request: the operation number lives at offset 22.
            info.opnum = Some(u16::from_le_bytes([msg[22], msg[23]]));
        }
        _ => {}
    }
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Builds an NTLM AUTHENTICATE message, which is the one carrying an
    /// identity.
    fn ntlm_authenticate(domain: &str, user: &str, workstation: &str) -> Vec<u8> {
        let (d, u, w) = (utf16_bytes(domain), utf16_bytes(user), utf16_bytes(workstation));
        // Header is 64 bytes: signature(8) type(4) then six field
        // descriptors of 8 bytes each, then flags.
        let base = 64usize;
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE);
        msg.extend_from_slice(&3u32.to_le_bytes());

        let mut offset = base;
        let field = |len: usize, off: &mut usize, out: &mut Vec<u8>| {
            out.extend_from_slice(&(len as u16).to_le_bytes());
            out.extend_from_slice(&(len as u16).to_le_bytes());
            out.extend_from_slice(&(*off as u32).to_le_bytes());
            *off += len;
        };
        field(0, &mut offset, &mut msg); // LM response
        field(0, &mut offset, &mut msg); // NT response
        field(d.len(), &mut offset, &mut msg);
        field(u.len(), &mut offset, &mut msg);
        field(w.len(), &mut offset, &mut msg);
        field(0, &mut offset, &mut msg); // session key
        msg.extend_from_slice(&0u32.to_le_bytes()); // flags
        assert_eq!(msg.len(), base);
        msg.extend_from_slice(&d);
        msg.extend_from_slice(&u);
        msg.extend_from_slice(&w);
        msg
    }

    /// The single most directly actionable thing on an internal network:
    /// who authenticated, from where, in the clear.
    #[test]
    fn an_ntlm_authenticate_names_the_account_and_the_machine() {
        let msg = ntlm_authenticate("CORP", "svc_backup", "WKSTN-42");
        let info = parse_ntlm(&msg).expect("an AUTHENTICATE message must parse");
        assert_eq!(info.message, "AUTHENTICATE");
        assert_eq!(info.domain.as_deref(), Some("CORP"));
        assert_eq!(info.user.as_deref(), Some("svc_backup"));
        assert_eq!(info.workstation.as_deref(), Some("WKSTN-42"));
    }

    /// NTLM travels inside SMB, HTTP and RPC alike, so it is found by
    /// its signature rather than by its container.
    #[test]
    fn ntlm_is_found_wherever_it_is_embedded() {
        let mut wrapped = b"some preceding protocol bytes".to_vec();
        wrapped.extend_from_slice(&ntlm_authenticate("D", "u", "w"));
        assert_eq!(parse_ntlm(&wrapped).unwrap().user.as_deref(), Some("u"));
    }

    #[test]
    fn a_field_offset_past_the_message_is_refused_rather_than_read() {
        let mut msg = ntlm_authenticate("CORP", "user", "WK");
        // Point the user field a long way past the end.
        msg[36 + 4..36 + 8].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        let info = parse_ntlm(&msg).expect("the message still parses");
        assert_eq!(info.user, None, "an unreachable field is absent, not invented");
    }

    #[test]
    fn a_non_ntlm_buffer_is_not_mistaken_for_one() {
        assert!(parse_ntlm(b"NTLMSSP").is_none(), "the signature includes its NUL");
        assert!(parse_ntlm(b"ordinary traffic").is_none());
    }

    fn smb1_message(command: u8, unicode: bool, words: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = vec![0xFF];
        m.extend_from_slice(b"SMB");
        m.push(command);
        m.extend_from_slice(&[0u8; 5]); // status, flags
        let flags2: u16 = if unicode { 0x8000 } else { 0 };
        m.extend_from_slice(&flags2.to_le_bytes());
        m.extend_from_slice(&[0u8; 20]); // the rest of the 32-byte header
        assert_eq!(m.len(), 32);
        m.push((words.len() / 2) as u8);
        m.extend_from_slice(words);
        m.extend_from_slice(&(data.len() as u16).to_le_bytes());
        m.extend_from_slice(data);
        m
    }

    #[test]
    fn an_smb1_tree_connect_names_the_share() {
        let mut data = vec![0u8]; // password byte
        data.extend_from_slice(b"\\\\SERVER\\ADMIN$\0");
        data.extend_from_slice(b"?????\0");
        let msg = smb1_message(0x75, false, &[0u8; 8], &data);
        let info = parse_smb1_message(&msg).expect("SMB1 must parse");
        assert_eq!(info.command, "TREE_CONNECT_ANDX");
        assert_eq!(info.path.as_deref(), Some("\\\\SERVER\\ADMIN$"));
    }

    #[test]
    fn an_smb1_session_setup_surfaces_its_ntlm() {
        let data = ntlm_authenticate("CORP", "admin", "ATTACKER");
        let msg = smb1_message(0x73, true, &[0u8; 24], &data);
        let info = parse_smb1_message(&msg).expect("SMB1 must parse");
        assert_eq!(info.command, "SESSION_SETUP_ANDX");
        let ntlm = info.ntlm.expect("the embedded NTLM must be found");
        assert_eq!(ntlm.user.as_deref(), Some("admin"));
        assert_eq!(ntlm.workstation.as_deref(), Some("ATTACKER"));
    }

    #[test]
    fn smb2_traffic_is_not_parsed_as_smb1() {
        let mut m = vec![0xFE];
        m.extend_from_slice(b"SMB");
        m.extend_from_slice(&[0u8; 60]);
        assert!(parse_smb1_message(&m).is_none());
    }

    #[test]
    fn a_truncated_smb1_message_never_panics() {
        let mut data = vec![0u8];
        data.extend_from_slice(b"\\\\S\\C$\0");
        let full = smb1_message(0x75, false, &[0u8; 8], &data);
        for n in 0..full.len() {
            let _ = parse_smb1_message(&full[..n]);
        }
    }

    // --- DER --------------------------------------------------------------

    #[test]
    fn der_reads_short_and_long_form_lengths() {
        let short = [0x04, 0x03, b'a', b'b', b'c'];
        let e = der(&short, 0).unwrap();
        assert_eq!((e.tag, e.value, e.total), (0x04, &b"abc"[..], 5));

        let mut long = vec![0x04, 0x81, 130];
        long.extend(std::iter::repeat_n(b'x', 130));
        let e = der(&long, 0).unwrap();
        assert_eq!(e.value.len(), 130);
        assert_eq!(e.total, 133);
    }

    /// Indefinite-length encoding is not valid DER, and accepting it
    /// would mean scanning forward for a terminator an attacker chooses.
    #[test]
    fn indefinite_and_absurd_lengths_are_refused() {
        assert!(der(&[0x30, 0x80, 0x00, 0x00], 0).is_none());
        assert!(der(&[0x04, 0x85, 1, 2, 3, 4, 5], 0).is_none());
        assert!(der(&[0x04, 0x7f], 0).is_none(), "a length past the buffer is not readable");
    }

    /// Nesting is attacker-controlled, so the walk is depth-bounded.
    #[test]
    fn deeply_nested_der_does_not_overflow_the_stack() {
        // 100 nested SEQUENCEs, with real long-form lengths — a
        // truncated length byte would make the input invalid DER and the
        // test would pass for the wrong reason.
        let mut buf = vec![0x04, 0x00];
        for _ in 0..100 {
            let len = buf.len();
            let mut next = vec![0x30];
            if len < 0x80 {
                next.push(len as u8);
            } else if len < 0x100 {
                next.extend_from_slice(&[0x81, len as u8]);
            } else {
                next.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
            }
            next.extend_from_slice(&buf);
            buf = next;
        }
        // Valid all the way down, so an unbounded walk would recurse 100
        // deep; the bound stops it well before that.
        assert!(der(&buf, 0).is_some(), "the test input must itself be valid DER");
        let mut seen = 0;
        der_walk(&buf, 0, &mut |_, _| seen += 1);
        assert!(seen > 0 && seen <= 32, "the walk is depth-bounded: {}", seen);
    }

    // --- Kerberos ---------------------------------------------------------

    fn general_string(s: &str) -> Vec<u8> {
        let mut v = vec![0x1b, s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    #[test]
    fn a_kerberos_request_names_its_realm_and_principals() {
        // An AS-REQ wrapper around the names, which is all this extracts.
        let mut inner = Vec::new();
        inner.extend_from_slice(&general_string("alice"));
        inner.extend_from_slice(&general_string("EXAMPLE.COM"));
        inner.extend_from_slice(&general_string("krbtgt"));
        let mut msg = vec![0x6a, inner.len() as u8];
        msg.extend_from_slice(&inner);

        let info = parse_kerberos(&msg).expect("an AS-REQ must parse");
        assert_eq!(info.message, "AS-REQ");
        assert_eq!(info.realm.as_deref(), Some("EXAMPLE.COM"));
        assert_eq!(info.client.as_deref(), Some("alice"));
        assert_eq!(info.service.as_deref(), Some("krbtgt"));
    }

    #[test]
    fn a_non_kerberos_buffer_is_refused() {
        assert!(parse_kerberos(b"GET / HTTP/1.1").is_none());
        assert!(parse_kerberos(&[0x6a]).is_none(), "an application tag alone is not a message");
    }

    // --- LDAP -------------------------------------------------------------

    fn ldap_bind(dn: &str, simple: bool) -> Vec<u8> {
        let mut op = vec![0x02, 0x01, 0x03]; // version 3
        op.push(0x04);
        op.push(dn.len() as u8);
        op.extend_from_slice(dn.as_bytes());
        if simple {
            op.extend_from_slice(&[0x80, 0x06]);
            op.extend_from_slice(b"secret");
        } else {
            op.extend_from_slice(&[0xa3, 0x00]);
        }
        let mut body = vec![0x02, 0x01, 0x01]; // messageID 1
        body.push(0x60);
        body.push(op.len() as u8);
        body.extend_from_slice(&op);
        let mut msg = vec![0x30, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn an_ldap_bind_names_the_account_and_says_whether_it_was_cleartext() {
        let info = parse_ldap(&ldap_bind("CN=admin,DC=corp,DC=local", true)).expect("a bind must parse");
        assert_eq!(info.operation, "bindRequest");
        assert_eq!(info.dn.as_deref(), Some("CN=admin,DC=corp,DC=local"));
        assert!(info.simple_bind, "a simple bind carries the password in the clear, which is the point");

        let sasl = parse_ldap(&ldap_bind("CN=admin,DC=corp,DC=local", false)).unwrap();
        assert!(!sasl.simple_bind);
    }

    #[test]
    fn a_non_ldap_buffer_is_refused() {
        assert!(parse_ldap(b"\x16\x03\x01\x00\x00").is_none(), "a TLS record is not an LDAPMessage");
        assert!(parse_ldap(&[0x30, 0x02, 0x02, 0x00]).is_none());
    }

    // --- DCERPC -----------------------------------------------------------

    fn dcerpc_bind(uuid_le: [u8; 16]) -> Vec<u8> {
        let mut m = vec![5, 0, 11, 3]; // version 5.0, bind, flags
        m.extend_from_slice(&[0x10, 0, 0, 0]); // representation
        m.extend_from_slice(&[0u8; 8]); // lengths, call id
        m.extend_from_slice(&[0u8; 8]); // max xmit/recv, assoc group
        m.extend_from_slice(&[1, 0, 0, 0]); // one context item
        m.extend_from_slice(&[0, 0, 1, 0]); // context id, counts
        m.extend_from_slice(&uuid_le);
        m.extend_from_slice(&[0u8; 4]); // interface version
        m
    }

    /// Reaching the Service Control Manager over RPC is how remote
    /// execution is done; naming the interface is what makes it visible.
    #[test]
    fn a_dcerpc_bind_names_a_well_known_interface() {
        // svcctl, in the mixed-endian form the wire uses.
        let uuid = [0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03];
        let info = parse_dcerpc(&dcerpc_bind(uuid)).expect("a bind must parse");
        assert_eq!(info.packet_type, "bind");
        assert_eq!(info.interface.as_deref(), Some("367abb81-9844-35f1-ad32-98f038001003"));
        assert_eq!(info.interface_name, Some("svcctl (Service Control Manager)"));
    }

    #[test]
    fn an_unknown_interface_still_reports_its_uuid() {
        let info = parse_dcerpc(&dcerpc_bind([0xAA; 16])).unwrap();
        assert!(info.interface.is_some());
        assert_eq!(info.interface_name, None, "an unrecognised UUID is reported, not named");
    }

    #[test]
    fn a_dcerpc_request_reports_its_operation_number() {
        let mut m = vec![5, 0, 0, 3];
        m.extend_from_slice(&[0x10, 0, 0, 0]);
        m.extend_from_slice(&[0u8; 14]);
        m.extend_from_slice(&42u16.to_le_bytes());
        assert_eq!(parse_dcerpc(&m).unwrap().opnum, Some(42));
    }

    #[test]
    fn non_dcerpc_traffic_is_refused() {
        assert!(parse_dcerpc(b"GET / HTTP/1.1\r\n\r\nxxxxxxxxxx").is_none());
        assert!(parse_dcerpc(&[5, 0, 99, 0]).is_none(), "an unknown packet type is not a PDU");
    }
    fn krb_error(code: u8) -> Vec<u8> {
        // KRB-ERROR ::= [APPLICATION 30] SEQUENCE { [0] pvno, [1] msg-type, ..., [6] error-code, ... }
        let mut names = general_string("EXAMPLE.COM");
        names.extend_from_slice(&general_string("alice"));
        let mut seq = vec![0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x1e];
        seq.extend_from_slice(&[0xa6, 0x03, 0x02, 0x01, code]);
        seq.extend_from_slice(&names);
        let mut body = vec![0x30, seq.len() as u8];
        body.extend_from_slice(&seq);
        let mut msg = vec![0x7e, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn a_krb_error_reports_why_the_kdc_refused() {
        let info = parse_kerberos(&krb_error(24)).expect("a KRB-ERROR must parse");
        assert_eq!(info.message, "KRB-ERROR");
        assert_eq!(info.error_code, Some(24));
        assert!(kerberos_error_is_auth_failure(24));
        assert!(kerberos_error_is_auth_failure(6), "an unknown principal is user enumeration");
        assert!(!kerberos_error_is_auth_failure(25), "PREAUTH_REQUIRED is the ordinary first answer, not a refusal");
    }

    /// Over TCP every Kerberos message carries a four-byte length. Without
    /// stripping it the message began with bytes that are not a Kerberos
    /// tag, so a real TCP exchange parsed as nothing at all.
    #[test]
    fn kerberos_over_tcp_is_read_through_its_length_prefix() {
        let msg = krb_error(24);
        let mut framed = (msg.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        let info = parse_kerberos(&framed).expect("the record mark must be stripped");
        assert_eq!(info.error_code, Some(24));
        assert_eq!(info.client.as_deref(), Some("alice"));
    }

    #[test]
    fn a_length_prefix_larger_than_the_data_is_not_treated_as_one() {
        let mut framed = 0x7fff_ffffu32.to_be_bytes().to_vec();
        framed.extend_from_slice(&krb_error(24));
        assert!(parse_kerberos(&framed).is_none());
    }

    fn ldap_bind_response(code: u8) -> Vec<u8> {
        let op = vec![0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00];
        let mut body = vec![0x02, 0x01, 0x01, 0x61, op.len() as u8];
        body.extend_from_slice(&op);
        let mut msg = vec![0x30, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn an_ldap_bind_response_reports_its_result() {
        assert_eq!(parse_ldap(&ldap_bind_response(49)).unwrap().result_code, Some(49));
        assert_eq!(parse_ldap(&ldap_bind_response(0)).unwrap().result_code, Some(0));
    }

}
