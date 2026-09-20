#!/usr/bin/env python3
"""Detection-rate measurement against synthetic attacks with known ground truth.

Every other measurement in this project answers "does ARGUS survive real
traffic, and does it stay quiet on it?" — replay the benign corpus, count
crashes and false positives. That is half a sensor's job. The other half,
"does it fire when something is actually happening?", was asserted rather
than measured, because measuring it needs labelled attack traffic and
public attack captures either come without labels or come in
password-protected archives.

So this constructs the labels instead. Each case below writes a pcap
containing exactly one attack, declares the alert category that attack
must produce, replays it through the real binary, and grades the result.
The output is a detection rate over a fixed, versioned set of cases.

WHAT THIS MEASURES, AND WHAT IT DOES NOT

It measures that each detector fires on a clean textbook instance of the
thing it is named after, and keeps doing so as the code changes. That is
a regression floor, and it is the thing that was missing.

It is NOT a real-world detection rate. Synthetic traffic is exactly what
the detector expects: no packet loss, no retransmissions, no evasion, no
background noise to hide in, and — the part that matters most — thresholds
crossed decisively rather than skirted. A real attacker tunes to sit just
under whatever line you drew. Reading "100%" here as "ARGUS detects 100%
of attacks" would be a straightforward misreading; it means "all N modelled
attacks, presented plainly, were detected". The honest use is as a floor
that must not fall, plus a list of what is modelled at all.

Usage:
    python tools/detect.py                     # build, run, grade
    python tools/detect.py --keep              # leave the pcaps for inspection
    python tools/detect.py --case port_scan    # one case
    python tools/detect.py --survive corpus    # replay real captures: survival, decode, noise
"""

import argparse
import collections
import glob
import json
import math
import os
import random
import struct
import subprocess
import sys
import tempfile
import time
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# --------------------------------------------------------------------------
# packet construction
# --------------------------------------------------------------------------

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"


def ip4(s):
    return bytes(int(x) for x in s.split("."))


def _csum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4(src, dst, proto, payload, ident=0):
    total_len = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0, 64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack(">H", _csum(hdr)) + hdr[12:]
    return hdr + payload


def _l4_csum(src, dst, proto, seg):
    pseudo = src + dst + struct.pack(">BBH", 0, proto, len(seg))
    return _csum(pseudo + seg)


def eth(payload):
    return MAC_A + MAC_B + b"\x08\x00" + payload


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    """One Ethernet-framed TCP segment, checksummed."""
    seg = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    seg = seg[:16] + struct.pack(">H", _l4_csum(src, dst, 6, seg)) + seg[18:]
    return eth(_ipv4(src, dst, 6, seg))


def udp(src, dst, sport, dport, payload):
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    seg = seg[:6] + struct.pack(">H", _l4_csum(src, dst, 17, seg)) + seg[8:]
    return eth(_ipv4(src, dst, 17, seg))


def dns_query(src, dst, sport, txid, name):
    """A DNS question, wire-encoded."""
    q = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split(".")) + b"\x00"
    body = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
    return udp(src, dst, sport, 53, body)


def _ipv4_frag(src, dst, proto, payload, ident, offset, more):
    """An IPv4 packet that is one fragment of a larger datagram.

    `offset` is in 8-byte units, as the wire format counts it.
    """
    flags_frag = (0x2000 if more else 0) | (offset & 0x1FFF)
    total_len = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, ident, flags_frag, 64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack(">H", _csum(hdr)) + hdr[12:]
    return hdr + payload


def http_request(method, uri, headers, body=b""):
    """An HTTP/1.1 request, built from parts so no escape can go astray."""
    out = method + b" " + uri + b" HTTP/1.1\r\n"
    for k, v in headers.items():
        out += k + b": " + v + b"\r\n"
    return out + b"\r\n" + body


def _utf16(s):
    return s.encode("utf-16-le")


def ntlm_authenticate(domain, user, workstation):
    """An NTLMSSP AUTHENTICATE message: the one that names an account."""
    d, u, w = _utf16(domain), _utf16(user), _utf16(workstation)
    out = b"NTLMSSP\x00" + struct.pack("<I", 3)
    off = 64
    for length in (0, 0, len(d), len(u), len(w), 0):
        out += struct.pack("<HHI", length, length, off)
        off += length
    out += struct.pack("<I", 0)  # flags
    assert len(out) == 64
    return out + d + u + w


def smb_session_setup(domain, user, workstation):
    """An SMB1 SESSION_SETUP_ANDX carrying an NTLM logon."""
    data = ntlm_authenticate(domain, user, workstation)
    msg = b"\xffSMB" + bytes([0x73]) + b"\x00" * 5
    msg += struct.pack("<H", 0x8000)  # unicode strings
    msg += b"\x00" * 20
    assert len(msg) == 32
    msg += bytes([12]) + b"\x00" * 24
    msg += struct.pack("<H", len(data)) + data
    # NetBIOS session framing, which is how SMB rides on 445.
    return struct.pack(">I", len(msg))[1:] + b"\x00" + msg if False else msg


SVCCTL_UUID = bytes([0x81, 0xBB, 0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35, 0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03])


def dcerpc_bind(uuid_le):
    """A DCERPC bind to one interface."""
    m = bytes([5, 0, 11, 3]) + bytes([0x10, 0, 0, 0]) + b"\x00" * 8
    m += b"\x00" * 8  # max xmit/recv, assoc group
    m += bytes([1, 0, 0, 0])  # one context element
    m += bytes([0, 0, 1, 0])  # context id, transfer syntax count
    return m + uuid_le + b"\x00" * 4


def quic_initial(server_name):
    """A QUIC v1 client Initial packet carrying a ClientHello.

    Built with the real key schedule, because a packet ARGUS cannot
    decrypt would make this case pass or fail for the wrong reason.
    Requires `cryptography`; the case is skipped when it is absent.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    from cryptography.hazmat.primitives import hashes, hmac as _hmac

    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    dcid = bytes.fromhex("0011223344556677")

    def extract(salt, ikm):
        h = _hmac.HMAC(salt, hashes.SHA256())
        h.update(ikm)
        return h.finalize()

    def expand_label(secret, label, length):
        info = struct.pack(">H", length) + bytes([6 + len(label)]) + b"tls13 " + label.encode() + b"\x00"
        return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)

    initial_secret = extract(salt, dcid)
    client_secret = expand_label(initial_secret, "client in", 32)
    key = expand_label(client_secret, "quic key", 16)
    iv = expand_label(client_secret, "quic iv", 12)
    hp = expand_label(client_secret, "quic hp", 16)

    hello = client_hello(server_name)
    crypto = b"\x06\x00" + (bytes([len(hello)]) if len(hello) < 64 else struct.pack(">H", 0x4000 | len(hello))) + hello
    frames = crypto + b"\x00" * max(0, 64 - len(crypto))

    pn, pn_len = 2, 4
    first = 0xC0 | (pn_len - 1)
    header = bytes([first]) + struct.pack(">I", 1) + bytes([len(dcid)]) + dcid + b"\x00\x00"
    length = pn_len + len(frames) + 16
    header += struct.pack(">H", 0x4000 | length)
    pn_offset = len(header)
    header += struct.pack(">I", pn)

    nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + struct.pack(">Q", pn)))
    sealed = AESGCM(key).encrypt(nonce, frames, header)
    packet = bytearray(header + sealed)

    sample = bytes(packet[pn_offset + 4 : pn_offset + 20])
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]
    return bytes(packet)


def client_hello(server_name):
    """A minimal TLS ClientHello handshake message, with an SNI."""
    sni_host = server_name
    sni = struct.pack(">BH", 0, len(sni_host)) + sni_host
    sni_ext = struct.pack(">HHH", 0, len(sni) + 2, len(sni)) + sni
    body = struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
    body += struct.pack(">H", 2) + struct.pack(">H", 0x1301)
    body += b"\x01\x00"
    body += struct.pack(">H", len(sni_ext)) + sni_ext
    return b"\x01" + struct.pack(">I", len(body))[1:] + body


class Cap:
    """Accumulates (timestamp, frame) pairs and writes a libpcap file."""

    def __init__(self, start=1_700_000_000.0):
        self.t = start
        self.pkts = []

    def add(self, frame, dt=0.0):
        self.t += dt
        self.pkts.append((self.t, frame))
        return self

    def at(self, ts):
        self.t = ts
        return self

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            for ts, frame in self.pkts:
                sec = int(ts)
                usec = int(round((ts - sec) * 1_000_000))
                if usec >= 1_000_000:
                    sec, usec = sec + 1, usec - 1_000_000
                f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                f.write(frame)
        return path


def connection(cap, src, dst, sport, dport, ts, payload=b"", answered=True, resp=b""):
    """A complete TCP conversation, so the flow retires and is observed.

    Behavioural detection is driven by retired flows, not by packets: an
    unanswered SYN only becomes evidence of a scan once it has failed to
    be answered. So every case that wants a behavioural verdict has to
    open and close its connections properly rather than spraying SYNs.
    """
    cap.at(ts)
    cap.add(tcp(src, dst, sport, dport, 1000, 0, SYN), 0.0)
    if not answered:
        return
    cap.add(tcp(dst, src, dport, sport, 5000, 1001, SYN | ACK), 0.001)
    cap.add(tcp(src, dst, sport, dport, 1001, 5001, ACK), 0.001)
    seq = 1001
    for i in range(0, len(payload), 1400):
        chunk = payload[i : i + 1400]
        cap.add(tcp(src, dst, sport, dport, seq, 5001, PSH | ACK, chunk), 0.001)
        seq += len(chunk)
    if resp:
        rseq = 5001
        for i in range(0, len(resp), 1400):
            chunk = resp[i : i + 1400]
            cap.add(tcp(dst, src, dport, sport, rseq, seq, PSH | ACK, chunk), 0.001)
            rseq += len(chunk)
    cap.add(tcp(src, dst, sport, dport, seq, 5001 + len(resp), FIN | ACK), 0.001)
    cap.add(tcp(dst, src, dport, sport, 5001 + len(resp), seq + 1, FIN | ACK), 0.001)
    cap.add(tcp(src, dst, sport, dport, seq + 1, 5002 + len(resp), ACK), 0.001)


# --------------------------------------------------------------------------
# the cases: one attack each, with the category it must produce
# --------------------------------------------------------------------------

ATTACKER = ip4("10.66.0.66")
VICTIM = ip4("10.0.0.10")
SERVER = ip4("203.0.113.50")
RESOLVER = ip4("10.0.0.1")


def c_port_scan(cap):
    """40 ports on one host: vertical scan, default threshold is 20."""
    for i, port in enumerate(range(20, 60)):
        cap.add(tcp(ATTACKER, VICTIM, 40000 + i, port, 1, 0, SYN), 0.01)


def c_horizontal_scan(cap):
    """One port across 30 hosts, none answering. Threshold is 25."""
    for i in range(30):
        connection(cap, ATTACKER, ip4("10.0.0.%d" % (20 + i)), 41000 + i, 445, cap.t + 0.05, answered=False)


def c_packet_flood(cap):
    """12000 packets in 10s = 1200pps, against a 500pps default."""
    for i in range(12000):
        cap.add(tcp(ATTACKER, VICTIM, 50000, 80, i, 1, ACK, b"x" * 100), 10.0 / 12000)


def c_brute_force(cap):
    """20 FTP logins to one service. Threshold is 15 attempts."""
    for i in range(20):
        connection(cap, ATTACKER, VICTIM, 42000 + i, 21, cap.t + 1.0, payload=b"USER admin\r\nPASS hunter%d\r\n" % i, resp=b"220 ready\r\n530 denied\r\n")


def c_beaconing(cap):
    """8 connections to one service, 60s apart, no jitter."""
    t = cap.t
    for i in range(8):
        connection(cap, VICTIM, SERVER, 43000 + i, 443, t, payload=b"ping" * 20, resp=b"pong" * 20)
        t += 60.0


def c_exfil_ratio(cap):
    """6MB out, almost nothing back: the out:in ratio case (floor is 5MB)."""
    connection(cap, VICTIM, SERVER, 44000, 443, cap.t + 1.0, payload=os.urandom(6 * 1024 * 1024), resp=b"ok")


def c_dns_tunnel(cap):
    """45 distinct high-entropy subdomains under one parent. Threshold is 40."""
    rnd = random.Random(7)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(45):
        label = "".join(rnd.choice(alphabet) for _ in range(40))
        cap.add(dns_query(VICTIM, RESOLVER, 45000 + i, i, "%s.tunnel.example.com" % label), 0.5)


def c_dns_long_name(cap):
    """A single question longer than 100 bytes with high entropy."""
    rnd = random.Random(11)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    labels = [".".join("".join(rnd.choice(alphabet) for _ in range(50)) for _ in range(3))]
    cap.add(dns_query(VICTIM, RESOLVER, 46000, 1, "%s.example.com" % labels[0]), 0.1)


def c_signature_dns(cap):
    """rules.txt: suspicious-tld, /\\.(zip|top|xyz)$/ on dns.query."""
    cap.add(dns_query(VICTIM, RESOLVER, 47000, 1, "payload-delivery.xyz"), 0.1)


def c_brute_force_refused(cap):
    """Ten FTP logins, every one refused by the server.

    Ten is under the attempt limit of 15, so nothing but the server's own
    530 replies can raise this: it grades the response side specifically.
    """
    for i in range(10):
        connection(cap, ATTACKER, VICTIM, 42100 + i, 21, cap.t + 1.0, payload=b"USER admin\r\nPASS pw%d\r\n" % i, resp=b"331 Password required\r\n530 Login incorrect.\r\n")


def c_http_401_brute(cap):
    """Twelve requests to a protected page, each answered 401.

    HTTP contributes no attempt observations at all, so only the 401s can
    raise this.
    """
    for i in range(12):
        req = http_request(b"GET", b"/admin", {b"Host": b"victim", b"Authorization": b"Basic dXNlcjpwdw=="})
        connection(cap, ATTACKER, VICTIM, 43100 + i, 80, cap.t + 1.0, payload=req, resp=b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n")


def c_executable_download(cap):
    """A 40KB Windows executable downloaded from a web server.

    Well past the 16KB reassembly buffer, so it is only seen at all if the
    body is hashed as it streams rather than inspected from a buffer.
    """
    body = b"MZ\x90\x00" + bytes(range(256)) * 160
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    connection(cap, VICTIM, SERVER, 44100, 80, cap.t + 1.0, payload=http_request(b"GET", b"/update.exe", {b"Host": b"cdn.example"}), resp=resp)


def c_request_and_response(cap):
    """A probe for an exposed file, and the server saying yes."""
    connection(cap, ATTACKER, VICTIM, 45100, 80, cap.t + 1.0, payload=http_request(b"GET", b"/.git/config", {b"Host": b"victim"}), resp=b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n[cor")


def e_split_response(cap):
    """The same exposure, with the response delivered one byte per segment.

    A response parser that accepts a partial header block would latch on
    the first bytes and never see the status line complete.
    """
    cap.at(cap.t + 1.0)
    cap.add(tcp(ATTACKER, VICTIM, 49300, 80, 1000, 0, SYN), 0.0)
    cap.add(tcp(VICTIM, ATTACKER, 80, 49300, 5000, 1001, SYN | ACK), 0.001)
    cap.add(tcp(ATTACKER, VICTIM, 49300, 80, 1001, 5001, ACK), 0.001)
    req = http_request(b"GET", b"/.git/config", {b"Host": b"victim"})
    cap.add(tcp(ATTACKER, VICTIM, 49300, 80, 1001, 5001, PSH | ACK, req), 0.001)
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n[cor"
    seq = 5001
    for i in range(len(resp)):
        cap.add(tcp(VICTIM, ATTACKER, 80, 49300, seq, 1001 + len(req), PSH | ACK, resp[i : i + 1]), 0.001)
        seq += 1


def c_translated_rule(cap):
    """A request carrying the header the translated rule looks for."""
    req = http_request(b"GET", b"/api", {b"Host": b"victim", b"X-Token": b"deadbeef"})
    connection(cap, ATTACKER, VICTIM, 46100, 80, cap.t + 1.0, payload=req, resp=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")


def c_case_transform(cap):
    """A request whose URI differs from the rule only in case."""
    req = http_request(b"GET", b"/ADMIN/Login", {b"Host": b"victim"})
    connection(cap, ATTACKER, VICTIM, 46200, 80, cap.t + 1.0, payload=req, resp=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")


def c_missing_header(cap):
    """A request to the gate page with no Accept header."""
    req = http_request(b"GET", b"/gate.php", {b"Host": b"victim", b"User-Agent": b"implant"})
    connection(cap, ATTACKER, VICTIM, 46300, 80, cap.t + 1.0, payload=req, resp=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")


def c_urilen(cap):
    """A POST to a twelve-byte path."""
    req = http_request(b"POST", b"/mobile-home", {b"Host": b"victim", b"Content-Length": b"0"})
    connection(cap, ATTACKER, VICTIM, 46400, 80, cap.t + 1.0, payload=req, resp=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")


def c_dsize(cap):
    """A 40-byte datagram to a port where only large ones are of interest."""
    cap.add(udp(ATTACKER, VICTIM, 40400, 4444, b"\xde\xad\xbe\xef" + b"\x00" * 36), 0.1)


def c_isdataat(cap):
    """A value that ends exactly four bytes after its key."""
    connection(cap, ATTACKER, VICTIM, 46500, 9000, cap.t + 1.0, payload=b"xxKEY=abcd", resp=b"ok")


def c_signature_http(cap):
    """A directory-traversal URI, which the shipped rules cover."""
    req = b"GET /cgi-bin/../../../../etc/passwd HTTP/1.1\r\nHost: victim\r\n\r\n"
    connection(cap, ATTACKER, VICTIM, 48000, 80, cap.t + 1.0, payload=req, resp=b"HTTP/1.1 404 Not Found\r\n\r\n")


def c_ntlm_auth(cap):
    """An NTLM logon carrying an account name, in the clear, over SMB."""
    connection(cap, ATTACKER, VICTIM, 49001, 445, cap.t + 1.0, payload=smb_session_setup("CORP", "svc_backup", "ATTACKER"), resp=b"\x00")


def c_dcerpc_svcctl(cap):
    """A bind to the Service Control Manager: remote execution."""
    connection(cap, ATTACKER, VICTIM, 49002, 135, cap.t + 1.0, payload=dcerpc_bind(SVCCTL_UUID), resp=b"\x00")


def c_file_upload(cap):
    """A Windows executable POSTed to a web server."""
    body = b"MZ\x90\x00" + b"A" * 200
    req = http_request(b"POST", b"/upload.txt", {b"Host": b"victim", b"Content-Type": b"text/plain"}, body)
    connection(cap, ATTACKER, VICTIM, 49003, 80, cap.t + 1.0, payload=req, resp=b"HTTP/1.1 200 OK\r\n\r\n")


def c_threat_intel_dns(cap):
    """A lookup of a domain on the loaded feed."""
    cap.add(dns_query(VICTIM, RESOLVER, 49004, 7, "malware.test-indicator.example"), 0.1)


def c_quic_sni(cap):
    """A QUIC Initial packet naming a listed server."""
    cap.add(udp(VICTIM, SERVER, 49005, 443, quic_initial(b"malware.test-indicator.example")), 0.1)


# Cases that are deliberately *hard*: each is a real attack shaped the way
# an attacker who knows the thresholds would shape it.
def e_split_signature(cap):
    """A signature split across TCP segments, defeating per-packet matching."""
    cap.at(cap.t + 1.0)
    cap.add(tcp(ATTACKER, VICTIM, 49100, 80, 1000, 0, SYN), 0.0)
    cap.add(tcp(VICTIM, ATTACKER, 80, 49100, 5000, 1001, SYN | ACK), 0.001)
    cap.add(tcp(ATTACKER, VICTIM, 49100, 80, 1001, 5001, ACK), 0.001)
    req = b"GET /cgi-bin/../../../../etc/passwd HTTP/1.1\r\nHost: victim\r\n\r\n"
    seq = 1001
    # One byte at a time: no single segment contains the pattern.
    for i in range(len(req)):
        cap.add(tcp(ATTACKER, VICTIM, 49100, 80, seq, 5001, PSH | ACK, req[i : i + 1]), 0.001)
        seq += 1
    cap.add(tcp(ATTACKER, VICTIM, 49100, 80, seq, 5001, FIN | ACK), 0.001)
    cap.add(tcp(VICTIM, ATTACKER, 80, 49100, 5001, seq + 1, FIN | ACK), 0.001)


def e_out_of_order_signature(cap):
    """The same, delivered backwards, so only reassembly can see it."""
    cap.at(cap.t + 1.0)
    cap.add(tcp(ATTACKER, VICTIM, 49101, 80, 2000, 0, SYN), 0.0)
    cap.add(tcp(VICTIM, ATTACKER, 80, 49101, 6000, 2001, SYN | ACK), 0.001)
    cap.add(tcp(ATTACKER, VICTIM, 49101, 80, 2001, 6001, ACK), 0.001)
    req = b"GET /cgi-bin/../../../../etc/passwd HTTP/1.1\r\nHost: victim\r\n\r\n"
    chunks = [(2001 + i, req[i : i + 8]) for i in range(0, len(req), 8)]
    for seq, data in reversed(chunks):
        cap.add(tcp(ATTACKER, VICTIM, 49101, 80, seq, 6001, PSH | ACK, data), 0.001)


def e_overlapped_pending_segment(cap):
    """A segment held for a gap, then overlapped by the data that fills it.

    The tail of the request sits ahead of the stream; the segment that
    closes the gap runs one byte past its start. A reassembler that looks
    the held segment up by exact sequence number never finds it again and
    stops following the stream, which is a way to make it look away."""
    cap.at(cap.t + 1.0)
    cap.add(tcp(ATTACKER, VICTIM, 49102, 80, 2000, 0, SYN), 0.0)
    cap.add(tcp(VICTIM, ATTACKER, 80, 49102, 6000, 2001, SYN | ACK), 0.001)
    cap.add(tcp(ATTACKER, VICTIM, 49102, 80, 2001, 6001, ACK), 0.001)
    req = b"GET /cgi-bin/../../../../etc/passwd HTTP/1.1\r\nHost: victim\r\n\r\n"
    cut = 20
    cap.add(tcp(ATTACKER, VICTIM, 49102, 80, 2001 + cut - 1, 6001, PSH | ACK, req[cut - 1 :]), 0.001)
    cap.add(tcp(ATTACKER, VICTIM, 49102, 80, 2001, 6001, PSH | ACK, req[:cut]), 0.001)


def e_slow_port_scan(cap):
    """A scan paced to stay under a 10-second window."""
    # 40 ports at 3s apart spans two minutes: invisible to the default
    # window, visible to a wider one. Whether this is detected depends
    # entirely on -window, which is the point of measuring it.
    for i, port in enumerate(range(20, 60)):
        cap.add(tcp(ATTACKER, VICTIM, 45000 + i, port, 1, 0, SYN), 3.0)


def e_jittered_beacon(cap):
    """A beacon with the jitter an implant would actually use."""
    rnd = random.Random(3)
    t = cap.t
    for i in range(10):
        connection(cap, VICTIM, SERVER, 46000 + i, 443, t, payload=b"ping" * 20, resp=b"pong" * 20)
        # 12% jitter: under the detector's 15% ceiling, which is where a
        # careful implant would sit.
        t += 60.0 * (1.0 + rnd.uniform(-0.12, 0.12))


def e_fragmented_signature(cap):
    """A UDP signature split across IP fragments."""
    name = "payload-delivery.xyz"
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    body = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
    seg = struct.pack(">HHHH", 49200, 53, 8 + len(body), 0) + body
    seg = seg[:6] + struct.pack(">H", _l4_csum(VICTIM, RESOLVER, 17, seg)) + seg[8:]
    # Two fragments of 8 bytes each plus the tail, so neither contains
    # the whole question.
    first, rest = seg[:8], seg[8:]
    cap.add(eth(_ipv4_frag(VICTIM, RESOLVER, 17, first, ident=0x4242, offset=0, more=True)), 0.01)
    cap.add(eth(_ipv4_frag(VICTIM, RESOLVER, 17, rest, ident=0x4242, offset=1, more=False)), 0.01)


CASES = [
    # (name, builder, expected category, what it models)
    ("port_scan", c_port_scan, "PORT_SCAN", "40 ports on one host"),
    ("horizontal_scan", c_horizontal_scan, "HORIZONTAL_SCAN", "port 445 across 30 unanswering hosts"),
    ("packet_flood", c_packet_flood, "PACKET_FLOOD", "1200pps from one source"),
    ("brute_force", c_brute_force, "BRUTE_FORCE", "20 FTP logins"),
    ("beaconing", c_beaconing, "BEACONING", "8 connections 60s apart, no jitter"),
    ("exfil_ratio", c_exfil_ratio, "DATA_EXFIL_RATIO", "6MB out, 2 bytes in"),
    ("dns_tunnel", c_dns_tunnel, "DNS_TUNNEL", "45 random subdomains of one parent"),
    ("dns_long_name", c_dns_long_name, "DNS_LONG_NAME", "152-byte high-entropy question"),
    ("signature_dns", c_signature_dns, "SIGNATURE_MATCH", "suspicious TLD lookup"),
    ("signature_http", c_signature_http, "SIGNATURE_MATCH", "directory traversal in a URI"),
    ("ntlm_auth", c_ntlm_auth, "SIGNATURE_MATCH", "NTLM logon naming an account"),
    ("dcerpc_svcctl", c_dcerpc_svcctl, "SIGNATURE_MATCH", "RPC bind to the service manager"),
    ("file_upload", c_file_upload, "SIGNATURE_MATCH", "PE executable posted as a .txt"),
    ("brute_force_refused", c_brute_force_refused, "BRUTE_FORCE", "10 FTP logins, all answered 530"),
    ("http_401_brute", c_http_401_brute, "BRUTE_FORCE", "12 requests, all answered 401"),
    ("executable_download", c_executable_download, "SIGNATURE_MATCH", "40KB PE download, past the buffer"),
    ("request_and_response", c_request_and_response, "SIGNATURE_MATCH", "exposed file probe answered 200"),
    ("translated_rule", c_translated_rule, "SIGNATURE_MATCH", "Suricata rule with /R and lookahead, translated"),
    ("case_transform", c_case_transform, "SIGNATURE_MATCH", "to_lowercase rule against a mixed-case URI"),
    ("missing_header", c_missing_header, "SIGNATURE_MATCH", "gate page requested with no Accept header"),
    ("urilen", c_urilen, "SIGNATURE_MATCH", "POST to a twelve-byte path"),
    ("dsize", c_dsize, "SIGNATURE_MATCH", "40-byte datagram against dsize:>20"),
    ("isdataat", c_isdataat, "SIGNATURE_MATCH", "value ending four bytes after its key"),
    ("threat_intel_dns", c_threat_intel_dns, "THREAT_INTEL", "lookup of a listed domain"),
    ("quic_sni", c_quic_sni, "THREAT_INTEL", "QUIC handshake to a listed server"),
]

# Attacks shaped the way an attacker who knows the thresholds would shape
# them. These are the cases the plain set deliberately does not cover, and
# the ones whose results are worth reading carefully: a MISSED here is not
# a bug, it is a documented limit.
EVASIONS = [
    ("split_signature", e_split_signature, "SIGNATURE_MATCH", "pattern delivered one byte per segment"),
    ("out_of_order_signature", e_out_of_order_signature, "SIGNATURE_MATCH", "segments delivered in reverse"),
    ("fragmented_signature", e_fragmented_signature, "SIGNATURE_MATCH", "DNS question split across IP fragments"),
    ("overlapped_pending", e_overlapped_pending_segment, "SIGNATURE_MATCH", "held segment overlapped by the one that fills the gap"),
    ("slow_port_scan", e_slow_port_scan, "PORT_SCAN", "40 ports at 3s intervals"),
    ("jittered_beacon", e_jittered_beacon, "BEACONING", "60s beacon with 12% jitter"),
    ("split_response", e_split_response, "SIGNATURE_MATCH", "response delivered one byte per segment"),
]


# --------------------------------------------------------------------------
# running and grading
# --------------------------------------------------------------------------


def binary():
    """Build to a private target directory.

    Deliberately not `target/release`: a live capture holds that binary
    open, and on Windows the link step then fails outright. Grading a
    build must never be able to disturb a running sensor.
    """
    exe = "argus.exe" if os.name == "nt" else "argus"
    target = os.environ.get("ARGUS_TARGET_DIR", os.path.join(ROOT, "target-verify"))
    env = dict(os.environ, CARGO_TARGET_DIR=target)
    print("building...", flush=True)
    subprocess.run(["cargo", "build", "--release"], cwd=ROOT, check=True, env=env,
                   stdout=subprocess.DEVNULL)
    return os.path.join(target, "release", exe)


# Rules the graded cases need beyond the shipped set. Written out with
# the pcaps so that a failure can be reproduced by hand from the files
# the harness leaves behind under --keep.
EXTRA_RULES = """
# --- lateral movement -------------------------------------------------
rule sid:9000001; name:"ntlm-service-account"; proto:tcp; buffer:ntlm.user; content:"svc_"; severity:high;
rule sid:9000002; name:"rpc-service-manager"; proto:tcp; buffer:dcerpc.interface; content:"367abb81-9844-35f1"; severity:high;
# --- file identity ----------------------------------------------------
rule sid:9000003; name:"executable-upload"; proto:tcp; direction:to_server; buffer:file.type; content:"dos/pe-executable"; severity:high;
rule sid:9000004; name:"executable-download"; proto:tcp; direction:to_client; buffer:file.type; content:"dos/pe-executable"; severity:high;
# --- a rule spanning a request and its response -------------------------
rule sid:9000005; name:"git-exposure"; proto:tcp; buffer:http.uri; content:"/.git/config"; buffer:http.stat_code; content:"200"; severity:high;
"""

# A feed for the enrichment cases, so THREAT_INTEL has something to fire
# on. The domain is under .example, which cannot resolve.
EXTRA_INTEL = """
malware.test-indicator.example  # graded detection case
"""


# A genuine Suricata rule, translated by tools/suricata.py at run time.
#
# It uses two things only the newest translator handles: the `R` flag,
# which resumes the regex where the previous content ended, and a negative
# lookahead, which needs the bounded backtracking engine. Running it
# through the whole chain — translate, load, match — is what shows the
# three agree; each passing its own tests does not.
SURICATA_RULE = (
    'alert http any any -> any any (msg:"harness translated rule"; flow:established,to_server; '
    'http.header; content:"X-Token:"; pcre:"/\\s*(?!guest)[a-f0-9]{8}/R"; sid:9100001; rev:1;)'
)


SURICATA_RULES = [
    SURICATA_RULE,
    # A buffer transform: the URI is folded to lower case before matching.
    'alert http any any -> any any (msg:"harness case transform"; flow:established,to_server; '
    'http.uri; to_lowercase; content:"/admin/login"; sid:9100002; rev:1;)',
    # An absence: a request to a known gate page that sends no Accept header,
    # which is how a scripted client differs from a browser.
    'alert http any any -> any any (msg:"harness no accept header"; flow:established,to_server; '
    'http.uri; content:"/gate.php"; http.header_names; content:!"|0d 0a|Accept|0d 0a|"; sid:9100003; rev:1;)',
    # A length test on the URI: the C2 check-in this models always requests
    # a path of exactly twelve bytes.
    'alert http any any -> any any (msg:"harness urilen"; flow:established,to_server; '
    'http.method; content:"POST"; http.uri; content:"/mobile-home"; urilen:12; sid:9100004; rev:1;)',
    # dsize is about the packet, not the stream, so it needs a datagram.
    'alert udp any any -> any 4444 (msg:"harness dsize"; dsize:>20; content:"|de ad be ef|"; sid:9100005; rev:1;)',
    # A value pinned to the end of a field.
    'alert tcp any any -> any any (msg:"harness isdataat"; flow:established,to_server; '
    'content:"KEY="; isdataat:!4,relative; sid:9100006; rev:1;)',
]


def translated_rules():
    sys.path.insert(0, HERE)
    import suricata

    out = []
    for text in SURICATA_RULES:
        rule, why = suricata.convert(text, "192.168.0.0/16")
        if rule is None:
            raise RuntimeError("a harness Suricata rule no longer translates: %s" % why)
        out.append(rule)
    return out


def write_support_files(workdir):
    """Writes the rule and intel files the graded cases need."""
    rules = os.path.join(workdir, "detect-rules.txt")
    with open(os.path.join(ROOT, "rules.txt"), encoding="utf-8") as f:
        shipped = f.read()
    with open(rules, "w", encoding="utf-8") as f:
        f.write(shipped)
        f.write(EXTRA_RULES)
        f.write("\n" + "\n".join(translated_rules()) + "\n")
    intel = os.path.join(workdir, "detect-intel.txt")
    with open(intel, "w", encoding="utf-8") as f:
        f.write(EXTRA_INTEL)
    return rules, intel


def replay(exe, pcap_path, workdir, rules, intel, window="10s"):
    """Run one capture and return the alert categories produced."""
    log = os.path.join(workdir, "alerts.log")
    cmd = [
        exe,
        "-r", pcap_path,
        "-rules", rules,
        "-intel", intel,
        "-logfile", log,
        "-json",
        "-window", window,
        # The behavioural window has to span the capture, or evidence
        # spread over minutes is judged in ten-second slices.
        "-behavior-window", "10m",
        "-pcap-dir", workdir,
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600)
    cats, sevs = [], []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            a = json.loads(line)
            cats.append(a["category"])
            sevs.append(a.get("severity", "HIGH"))
        except (ValueError, KeyError):
            pass
    proc.severities = sevs
    return cats, proc


def run_set(exe, workdir, rules, intel, cases, window="10s"):
    """Builds, replays and grades one set of cases."""
    results = []
    for name, build, expect, description in cases:
        cap = Cap()
        try:
            build(cap)
        except ImportError as e:
            print("%-24s %-22s SKIPPED  (%s)" % (name, expect, e), flush=True)
            continue
        path = cap.write(os.path.join(workdir, name + ".pcap"))
        cats, proc = replay(exe, path, workdir, rules, intel, window)
        hit = expect in cats
        extra = sorted(set(c for c in cats if c != expect))
        results.append((name, expect, hit, len(cap.pkts), extra, description))
        print(
            "%-24s %-22s %s  (%d pkts)%s"
            % (name, expect, "DETECTED" if hit else "MISSED  ", len(cap.pkts), ("  also: " + ",".join(extra)) if extra else ""),
            flush=True,
        )
        if not hit and proc.returncode != 0:
            print("    exit %d: %s" % (proc.returncode, proc.stderr.strip()[:300]))
    return results


def false_positive_rate(exe, workdir, rules, intel, corpus_dir):
    """Alerts per hour of benign traffic.

    The number the plain detection rate cannot give: a sensor that
    detects everything and also alerts on everything is not useful, and
    the trade between the two is the only thing worth tracking over time.
    """
    caps = sorted(glob.glob(os.path.join(corpus_dir, "*.pcap")) + glob.glob(os.path.join(corpus_dir, "*.pcapng")))
    if not caps:
        return None
    total_alerts, total_seconds, rows = 0, 0.0, []
    by_severity = collections.Counter()
    for path in caps:
        cats, proc = replay(exe, path, workdir, rules, intel)
        span = capture_span(path)
        total_alerts += len(cats)
        total_seconds += span
        by_severity.update(getattr(proc, "severities", []))
        rows.append((os.path.basename(path), len(cats), span, collections.Counter(cats)))
    return total_alerts, total_seconds, rows, by_severity


def capture_span(path):
    """Wall-clock seconds the capture covers, from its own timestamps."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            return 0.0
        little = magic == b"\xd4\xc3\xb2\xa1"
        end = "<" if little else ">"
        f.read(20)
        first = last = None
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            sec, usec, caplen, _ = struct.unpack(end + "IIII", hdr)
            t = sec + usec / 1e6
            first = t if first is None else first
            last = t
            f.seek(caplen, 1)
        return (last - first) if (first is not None and last is not None) else 0.0


# ---------------------------------------------------------------- survival on real captures
#



def capture_files(paths):
    """Every pcap under the given files/directories, sorted for stable runs."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                out += [os.path.join(root, f) for f in files if f.lower().endswith((".pcap", ".pcapng", ".cap"))]
        else:
            out.append(p)
    return sorted(set(out))


def survive_one(exe, path, rules, timeout):
    """Replay one capture. Returns a result dict; never raises."""
    log = path + ".alerts.jsonl"
    cmd = [exe, "-r", path, "-json", "-logfile", log, "-flow-log", os.devnull]
    if rules:
        cmd += ["-rules", rules]
    started = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out, err, code, status = p.stdout, p.stderr, p.returncode, "ok"
    except subprocess.TimeoutExpired:
        out, err, code, status = "", "", -1, "TIMEOUT"
    elapsed = time.time() - started

    r = {"file": path, "status": status, "secs": elapsed, "read": 0, "decoded": 0,
         "undecoded": 0, "alerts": collections.Counter(), "detail": "", "note": ""}

    # A panic is the headline failure: `panic = "abort"` means the whole
    # sensor dies, so it is never merely a warning.
    if "panicked at" in err or "panicked at" in out:
        r["status"] = "PANIC"
        r["note"] = next((l.strip() for l in (err + out).splitlines() if "panicked at" in l), "")
    elif status == "ok" and code != 0:
        r["status"] = "EXIT %d" % code
        r["note"] = (err.strip().splitlines() or [""])[-1][:160]

    for line in out.splitlines():
        if "replay complete" in line:
            # "... N frames read, N packets decoded, N fragments buffered, N frames undecoded; ..."
            # Split on ';' as well as ',': the counts are comma-separated
            # but the clause after them is introduced by a semicolon, so
            # splitting on commas alone makes "0 frames undecoded; 10
            # alerts written" read as 10 undecoded frames.
            for part in line.replace(";", ",").split(","):
                for key, field in (("read", "frames read"), ("decoded", "packets decoded"), ("undecoded", "frames undecoded")):
                    if field in part:
                        r[key] = int("".join(c for c in part if c.isdigit()) or 0)
        elif "decode detail:" in line:
            r["detail"] = line.split("decode detail:", 1)[1].strip()

    if os.path.exists(log):
        with open(log, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    r["alerts"][json.loads(line)["category"]] += 1
                except (ValueError, KeyError):
                    pass
        os.remove(log)

    if r["status"] == "ok" and r["read"] > 0 and r["decoded"] == 0:
        r["status"] = "NO DECODE"
    return r


def survive(exe, args):
    files = capture_files(args.survive)
    if not files:
        print("no .pcap/.pcapng/.cap files found")
        return 1

    print("%-44s %9s %9s %7s %8s  %s" % ("file", "read", "decoded", "undec", "secs", "status"))
    print("-" * 104)

    totals = collections.Counter()
    alerts = collections.Counter()
    bad = []
    for path in files:
        r = survive_one(exe, path, args.rules if os.path.exists(args.rules) else None, args.timeout)
        name = os.path.basename(r["file"])[:44]
        print("%-44s %9d %9d %7d %8.1f  %s" % (name, r["read"], r["decoded"], r["undecoded"], r["secs"], r["status"]))
        if r["note"]:
            print("    ! %s" % r["note"])
        if r["detail"]:
            print("    decode: %s" % r["detail"])
        if r["alerts"]:
            print("    alerts: %s" % ", ".join("%s x%d" % kv for kv in sorted(r["alerts"].items())))
        for k in ("read", "decoded", "undecoded"):
            totals[k] += r[k]
        alerts += r["alerts"]
        if r["status"] != "ok":
            bad.append((name, r["status"]))

    print("-" * 104)
    pct = 100.0 * totals["decoded"] / totals["read"] if totals["read"] else 0.0
    print("%d files | %d frames read | %d decoded (%.1f%%) | %d undecoded" % (
        len(files), totals["read"], totals["decoded"], pct, totals["undecoded"]))
    if alerts:
        print("alerts: %s" % ", ".join("%s x%d" % kv for kv in sorted(alerts.items(), key=lambda kv: -kv[1])))
    else:
        print("alerts: none")
    if bad:
        print("\nFAILURES (%d):" % len(bad))
        for name, why in bad:
            print("  %-44s %s" % (name, why))
        return 1
    print("\nno crashes, hangs, or wholly-undecoded files")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", help="run a single case by name")
    ap.add_argument("--keep", action="store_true", help="keep generated pcaps")
    ap.add_argument("--evasion", action="store_true", help="also run the evasion cases")
    ap.add_argument("--survive", nargs="+", metavar="PATH", help="replay real captures (files or directories); grade survival, decode and noise")
    ap.add_argument("--rules", default="rules.txt", help="rules file for --survive")
    ap.add_argument("--timeout", type=int, default=300, help="per-capture timeout for --survive")
    ap.add_argument("--fp-rate", metavar="DIR", help="measure alerts per hour over a directory of benign captures")
    args = ap.parse_args()

    if args.survive:
        return survive(binary(), args)

    cases = [c for c in CASES if not args.case or c[0] == args.case]
    evasions = [c for c in EVASIONS if not args.case or c[0] == args.case]
    if not cases and not evasions:
        known = ", ".join(c[0] for c in CASES + EVASIONS)
        sys.exit("no such case: %s (have: %s)" % (args.case, known))

    exe = binary()
    workdir = tempfile.mkdtemp(prefix="argus-detect-")
    try:
        rules, intel = write_support_files(workdir)

        results = run_set(exe, workdir, rules, intel, cases)
        detected = sum(1 for r in results if r[2])
        total = len(results)
        if total:
            print("\ndetection rate: %d/%d (%.0f%%) on modelled attacks" % (detected, total, 100.0 * detected / total))
            missed = [r[0] for r in results if not r[2]]
            if missed:
                print("missed: %s" % ", ".join(missed))

        evaded = []
        if args.evasion and evasions:
            print("\n--- evasion: attacks shaped to sit under the thresholds ---")
            # A wider window, because that is what an operator watching
            # for a slow scan would actually configure; the point is to
            # measure what the sensor can do, not what its defaults do.
            ev = run_set(exe, workdir, rules, intel, evasions, window="5m")
            got = sum(1 for r in ev if r[2])
            evaded = [r[0] for r in ev if not r[2]]
            print("\nevasion-resistance: %d/%d detected" % (got, len(ev)))
            if evaded:
                print("evaded: %s" % ", ".join(evaded))
            print("A MISSED here is a documented limit, not a bug. Read it as\n"
                  "'an attacker who does this is not seen', and decide whether\n"
                  "that matters for your link.")

        if args.fp_rate:
            print("\n--- false positives: alerts per hour of benign traffic ---")
            fp = false_positive_rate(exe, workdir, rules, intel, args.fp_rate)
            if fp is None:
                print("no captures found in %s" % args.fp_rate)
            else:
                alerts, seconds, rows, by_severity = fp
                for name, n, span, by_cat in rows:
                    top = ", ".join("%s x%d" % (k, v) for k, v in by_cat.most_common(4))
                    print("%-24s %5d alerts over %6.0fs   %s" % (name, n, span, top))
                def rate_per_hour(n):
                    return n / seconds * 3600.0 if seconds > 0 else 0.0

                print("\n%d alerts over %.0f seconds of benign traffic = %.0f alerts/hour" % (alerts, seconds, rate_per_hour(alerts)))
                # The breakdown matters more than the total. An operator
                # triages by severity, so "how many HIGH alerts an hour"
                # is the number that decides whether this log gets read
                # at all — a hundred LOW findings about default SNMP
                # communities is an inventory report, not an incident.
                for sev in ("HIGH", "MEDIUM", "LOW"):
                    n = by_severity.get(sev, 0)
                    print("  %-6s %5d  = %6.0f/hour" % (sev, n, rate_per_hour(n)))
                print("\nEvery one of these is a false positive by construction:\n"
                      "the corpus contains no attack. Read the HIGH row: that is\n"
                      "what somebody actually has to look at.")
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print("\npcaps kept in %s" % workdir)

    print("\nThe detection rate is a floor, not a real-world rate: the plain\n"
          "cases cross their thresholds decisively. --evasion measures the\n"
          "other end, and --fp-rate measures the cost.")
    return 1 if any(not r[2] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
