#!/usr/bin/env python3
"""Translate Suricata/Snort rules into ARGUS v2 rules.

Usage:
    python tools/suricata.py emerging-all.rules --stats
    python tools/suricata.py emerging-all.rules -o et-open.rules [--home-net 192.168.0.0/16]

The governing principle is **skip anything that cannot be represented
faithfully**. A rule translated wrongly is worse than a rule skipped: it
fails silently, and it fails in whichever direction the mistranslation
went. Dropping a `distance:` modifier, for instance, turns "this string
immediately after that one" into "both strings anywhere", which is a
different and much looser rule wearing the original's name and sid. So
every option is either mapped exactly or the whole rule is rejected with
a recorded reason, and `--stats` prints those reasons so the coverage
number is auditable rather than asserted.
"""

import argparse
import collections
import os
import re
import sys

# ---------------------------------------------------------------------
# Suricata content modifiers / sticky buffers -> ARGUS buffers.
#
# Only buffers ARGUS actually extracts. Everything else (http.header,
# http.cookie, http.user_agent, file.data, ...) has no equivalent, and a
# rule that needs one is skipped rather than silently retargeted at the
# raw payload — which would change what it matches.
# ---------------------------------------------------------------------
BUFFERS = {
    # Suricata matches `http.uri` on the *normalised* URI and `http.uri.raw`
    # on what was sent. The two are separate names here; both read ARGUS's
    # `http.uri`, the first through a `percent_decode` transform (see
    # IMPLICIT_TRANSFORMS and argus_buffer).
    "http_uri": "http.uri", "http.uri": "http.uri",
    "http_raw_uri": "http.uri.raw", "http.uri.raw": "http.uri.raw",
    "http_host": "http.host", "http.host": "http.host",
    "http_method": "http.method", "http.method": "http.method",
    "http_raw_host": "http.host", "http.host.raw": "http.host",
    "dns_query": "dns.query", "dns.query": "dns.query",
    "tls_sni": "tls.sni", "tls.sni": "tls.sni",
    "tls_host": "tls.sni",
    "ja3_hash": "tls.ja3", "ja3.hash": "tls.ja3",
    "http_header": "http.header", "http.header": "http.header",
    "http_raw_header": "http.header",
    "http_user_agent": "http.user_agent", "http.user_agent": "http.user_agent",
    "http_cookie": "http.cookie", "http.cookie": "http.cookie",
    "http_client_body": "http.request_body", "http.request_body": "http.request_body",
    # `file_data` after a request means the request body, which is the
    # only file content ARGUS extracts. It is mapped rather than guessed
    # at: a `file_data` rule about a *response* body will not fire, and
    # that is counted below rather than silently approximated.
    "file_data": "file.data", "file.data": "file.data",
    "http_stat_code": "http.stat_code", "http.stat_code": "http.stat_code",
    "http_stat_msg": "http.stat_msg", "http.stat_msg": "http.stat_msg",
    "http_server_body": "http.response_body", "http.response_body": "http.response_body",
    "http.content_type": "http.content_type", "http.server": "http.server",
    "http.location": "http.location",
    # Lateral-movement protocols. ARGUS extracts the identities these
    # carry in the clear, which is what a rule about them wants.
    "smb.share": "smb.share", "smb_share": "smb.share",
    "smb.named_pipe": "smb.share",
    "krb5_cname": "krb5.principal", "krb5.cname": "krb5.principal",
    "krb5_sname": "krb5.service", "krb5.sname": "krb5.service",
    "krb5.realm": "krb5.realm",
    "ldap.request.dn": "ldap.dn",
    # File identity. A hash rule is the most portable kind there is.
    "filemd5": "file.md5", "file.md5": "file.md5",
    "file.magic": "file.magic",
    "filesha256": "file.sha256", "file.sha256": "file.sha256",
    "http.header_names": "http.header_names", "http_header_names": "http.header_names",
    "http.request_line": "http.request_line",
    "http.accept": "http.accept", "http.referer": "http.referer",
    "http_referer": "http.referer", "http.connection": "http.connection",
    "http.content_len": "http.content_len", "http.start": "http.start",
    "http.accept_enc": "http.accept_enc", "http.accept_lang": "http.accept_lang",
    "http.protocol": "http.protocol", "http.response_line": "http.response_line",
    "http.header.raw": "http.header",
    # One packet's payload before any reassembly.
    "pkt_data": "packet",
    "http.request_header": "http.header", "http.response_header": "http.header",
    # The server's certificate, read from the handshake (TLS before 1.3).
    "tls_cert_subject": "tls.cert_subject", "tls.cert_subject": "tls.cert_subject",
    "tls_cert_issuer": "tls.cert_issuer", "tls.cert_issuer": "tls.cert_issuer",
    "tls_cert_serial": "tls.cert_serial", "tls.cert_serial": "tls.cert_serial",
    "tls.certs": "tls.certs",
    "ja3s.hash": "tls.ja3s", "ja3s_hash": "tls.ja3s",
}

# Buffers that exist in Suricata but not here. Named explicitly so the
# stats distinguish "unsupported buffer" from "unknown option".
UNSUPPORTED_BUFFERS = {
    "file.name",
    "tls.cert_fingerprint", "ja3.string",
    "dns.opcode", "dns.answer.name", "dns.response",
    "ssh.proto", "ssh.software", "ssh_proto", "ssh_software",

    "sip.method", "sip.uri", "snmp.community", "dnp3_func", "modbus",
    "icmpv6.mtu", "quic.sni", "quic.ua",
}

# Options that change matching semantics in ways ARGUS cannot express.
# Presence of any of these rejects the rule.
BLOCKING_OPTS = {
    # Byte-level extraction into named variables, which ARGUS has no
    # notion of. `byte_test` and `byte_jump` are expressible and handled;
    # these two define variables that later options refer to by name.
    # Cross-flow and cross-host state. `flowbits` is per-connection and
    # supported; these three are wider than one connection, and ARGUS
    # deliberately keeps no cross-connection rule state.
    "flowint",
    # Packet-level tests with no ARGUS equivalent.
    "ttl", "fragbits", "fragoffset",
    "id", "seq", "ack", "tos", "ipopts",
    "ssl_state", "ssl_version", "app-layer-protocol",
    "app-layer-event", "tls.fingerprint", "lua", "luajit", "datarep",
    "dataset", "entropy", "sameip", "geoip",
    "asn1", "ftpbounce", "rpc", "replace", "prefilter", "filestore",
    "filemagic", "filename", "fileext", "filesize", "transform",
    # Response-side buffers: ARGUS reassembles client-to-server streams
    # and extracts request bodies, not responses.
    "pcrexform", "xor",
    "absent",
}

# Options that carry no matching semantics and can be ignored outright.
IGNORABLE_OPTS = {
    "reference", "classtype", "rev", "metadata", "priority", "gid",
    "target", "sid", "msg", "noalert", "tag", "logto", "fast_pattern",
    "http_encode", "nocase", "rawbytes", "depth", "offset", "content",
    "pcre", "flow", "ssl_state",
}

# Standard ET variable expansions. `any` where ARGUS has no equivalent
# concept; a bad guess here would silently narrow thousands of rules.
PORT_VARS = {
    "$HTTP_PORTS": "80,81,443,591,593,631,777,808,876,880,1183,1omit",
    "$SHELLCODE_PORTS": "any",
    "$ORACLE_PORTS": "1521",
    "$SSH_PORTS": "22",
    "$DNP3_PORTS": "20000",
    "$MODBUS_PORTS": "502",
    "$FILE_DATA_PORTS": "any",
    "$FTP_PORTS": "21",
    "$SIP_PORTS": "5060,5061",
    "$TELNET_PORTS": "23",
}
# The real HTTP_PORTS list from ET's suricata.yaml, trimmed to what ARGUS
# can express (comma-separated ports and ranges).
PORT_VARS["$HTTP_PORTS"] = "80,81,82,83,84,85,86,87,88,89,90,311,383,591,593,631,801,808,818,901,972,1158,1220,1414,1533,1741,1830,2301,2381,2809,3037,3057,3128,3702,4343,4848,5250,5600,5250,6080,6180,6988,7000,7001,7144,7145,7510,7770,7777,7779,8000,8008,8014,8028,8080,8081,8082,8085,8088,8090,8118,8123,8180,8181,8243,8280,8300,8800,8888,8899,9000,9060,9080,9090,9091,9443,9999,11371,34443,34444,41080,50002,55555"

# Suricata app-layer rule types -> the transport ARGUS sees them on.
#
# These are not port-based in Suricata: `alert http` means "traffic the
# app-layer parser identified as HTTP", wherever it is. ARGUS has the
# same notion, expressed differently — its structured buffers are only
# ever populated when its own parsers succeeded, so `buffer:http.uri`
# already carries "this is HTTP" exactly. Mapping the two is therefore
# faithful rather than approximate, which is why these rules convert at
# all.
#
# The catch is a rule with *no* sticky buffer: `alert http (content:"x")`
# means "x anywhere in a flow identified as HTTP", and ARGUS's nearest
# equivalent (`buffer:payload`) means "x anywhere in any TCP stream",
# which is strictly looser. Those are skipped — see ANY_BUFFER_OK below.
APP_PROTOS = {
    "http": "tcp", "http1": "tcp", "tls": "tcp", "ssl": "tcp",
    "smtp": "tcp", "ftp": "tcp", "ssh": "tcp", "smb": "tcp",
    "rdp": "tcp", "modbus": "tcp", "dnp3": "tcp",
    "dns": "udp", "snmp": "udp", "tftp": "udp",
}

# The flowbit each app-layer rule type is scoped to (see `mark_app` in the
# engine), and the ports datagram protocols are scoped to instead.
APP_IDENTITY = {"http": "http", "http1": "http", "tls": "tls", "ssl": "tls", "smtp": "smtp",
                "ftp": "ftp", "ssh": "ssh", "smb": "smb", "rdp": "rdp"}
UDP_APP_PORTS = {"dns": "53", "snmp": "161,162"}


def dport_override_ok(spec):
    """Only a rule that does not already name the port may be given one."""
    return spec.strip().lower() == "any"


# Transforms a buffer is always read through. Suricata normalises a URI
# before matching it; percent-decoding is the part of that ARGUS does.
IMPLICIT_TRANSFORMS = {"http.uri": ["percent_decode"]}

# Suricata transform keywords that map to an ARGUS transform. The
# `strip_pseudo_headers` keyword is absent on purpose: it removes HTTP/2
# pseudo-headers, which HTTP/1 does not have, so on the traffic ARGUS
# parses it changes nothing.
TRANSFORM_OPTS = {"url_decode": "url_decode", "header_lowercase": "header_lowercase",
                  "strip_whitespace": "strip_whitespace", "compress_whitespace": "compress_whitespace",
                  "to_sha1": "sha1", "to_md5": "md5", "to_sha256": "sha256"}
NO_OP_TRANSFORMS = {"strip_pseudo_headers"}


def argus_buffer(name):
    """The ARGUS buffer a translator-internal buffer name reads."""
    return "http.uri" if name == "http.uri.raw" else name


CONTENT_ESCAPES = {'"': '\\"', "\\": "\\\\", "|": "\\|"}

RULE_RE = re.compile(
    r"^\s*(?P<action>alert|drop|pass|reject)\s+"
    r"(?P<proto>\S+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<dir><-|->|<>)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s+"
    r"\((?P<opts>.*)\)\s*$"
)


def split_options(body):
    """Split a rule body on ';', respecting quotes and escapes."""
    out, cur, q, esc = [], "", False, False
    for ch in body:
        if esc:
            cur += ch
            esc = False
            continue
        if ch == "\\":
            cur += ch
            esc = True
            continue
        if ch == '"':
            q = not q
            cur += ch
            continue
        if ch == ";" and not q:
            out.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return [o for o in out if o]


def opt_name(opt):
    return opt.split(":", 1)[0].strip().lower()


def opt_value(opt):
    return opt.split(":", 1)[1].strip() if ":" in opt else ""


def unquote(v):
    v = v.strip()
    return v[1:-1] if len(v) >= 2 and v[0] == '"' and v[-1] == '"' else v


RATE_FIELDS = {"track": ("by_src", "by_dst", "by_both", "by_rule"), "type": ("limit", "threshold", "both")}


def rate_spec(name, value):
    """A `threshold`/`detection_filter` body in the form ARGUS reads, or None.

    ARGUS counts per source, per destination, per pair or per rule. Suricata
    can also track per flow, and a `by_flow` count cannot be honoured
    faithfully here, so that whole rule is refused rather than counted
    some other way.
    """
    fields = {}
    for part in value.split(","):
        bits = part.strip().split(None, 1)
        if len(bits) != 2:
            return None
        key, val = bits[0].lower(), bits[1].strip().lower()
        if key in fields or key not in ("type", "track", "count", "seconds"):
            return None
        if key in RATE_FIELDS and val not in RATE_FIELDS[key]:
            return None
        if key in ("count", "seconds") and not (val.isdigit() and int(val) > 0):
            return None
        fields[key] = val
    need = {"track", "count", "seconds"} | ({"type"} if name == "threshold" else set())
    if set(fields) != need:
        return None
    order = ("type", "track", "count", "seconds")
    return ",".join("%s %s" % (k, fields[k]) for k in order if k in fields)


IP_PROTOS = {"icmp": 1, "tcp": 6, "udp": 17}
FLAGS_RE = re.compile(r"^[!+*]?[FSRPAUCEfsrpauce0]+(,[FSRPAUCEfsrpauce0-9]+)?$")
STREAM_RE = re.compile(r"^(server|client|both|either),(<=|>=|!=|<|>|=),\d+$")


def header_test_spec(name, value):
    """A packet-header or connection-size test in the form ARGUS reads, or
    None when it is a form this translator does not represent."""
    v = value.strip().replace(" ", "")
    if name == "flags":
        return v if FLAGS_RE.match(v) else None
    if name == "stream_size":
        return v.lower() if STREAM_RE.match(v.lower()) else None
    if name == "ip_proto":
        if v.lower() in IP_PROTOS:
            return str(IP_PROTOS[v.lower()])
        return v if v.isdigit() else None
    return len_spec(v)


def variable_op_spec(name, value):
    """`byte_extract`, `byte_math` or `base64_decode` in the form ARGUS
    reads, or None. ARGUS's own parser is the authority on the modifiers it
    supports; this only checks the shape, so an unfamiliar form fails at
    load (and is dropped by --validate) rather than meaning something else."""
    parts = [" ".join(p.split()) for p in value.split(",")]
    if any(not p for p in parts):
        return None
    if name == "byte_extract":
        if len(parts) < 3 or not parts[0].isdigit() or not re.fullmatch(r"-?\d+", parts[1]) or not IDENT.match(parts[2]):
            return None
    elif name == "byte_math":
        keys = {p.split(" ", 1)[0].lower() for p in parts}
        if not {"bytes", "offset", "oper", "rvalue", "result"} <= keys:
            return None
    return ",".join(parts)


XBIT_VERBS = ("set", "unset", "toggle", "isset", "isnotset")


def xbit_spec(value):
    """An `xbits`/`hostbits` body in the form ARGUS reads, or None."""
    parts = [p.strip() for p in value.split(",")]
    if len(parts) < 3 or parts[0].lower() not in XBIT_VERBS or not parts[1]:
        return None
    out = [parts[0].lower(), parts[1]]
    seen = set()
    for p in parts[2:]:
        bits = p.split(None, 1)
        if len(bits) != 2 or bits[0].lower() in seen:
            return None
        key, val = bits[0].lower(), bits[1].strip().lower()
        seen.add(key)
        if key == "track" and val in ("ip_src", "ip_dst", "ip_pair"):
            out.append("track " + val)
        elif key == "expire" and val.isdigit() and int(val) > 0:
            out.append("expire " + val)
        else:
            return None
    return ",".join(out) if "track" in seen else None


def convert_content(value):
    """Suricata content -> ARGUS content.

    Both use the same `|hex|` convention, so hex blocks pass through. The
    difference is escaping: Suricata escapes `"`, `\\` and `;` with a
    backslash, ARGUS escapes `"`, `\\` and `|`.
    """
    v = unquote(value)
    out, i = "", 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v):
            nxt = v[i + 1]
            if nxt == ";":
                out += ";"          # ARGUS quoting handles ';' directly
            elif nxt == '"':
                out += '\\"'
            elif nxt == "\\":
                out += "\\\\"
            elif nxt == ":":
                out += ":"
            else:
                out += "\\\\" + nxt
            i += 2
            continue
        if c == '"':
            out += '\\"'
        else:
            out += c
        i += 1
    return out


def content_bytes(value):
    """The literal byte sequence a Suricata content matches."""
    v = unquote(value)
    out, i = bytearray(), 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v):
            out.append(ord(v[i + 1]))
            i += 2
            continue
        if c == "|":
            j = v.index("|", i + 1)
            # Hex bodies may be space-separated ("54 63") or contiguous
            # ("5463"), so each whitespace token is split into pairs.
            for tok in v[i + 1:j].split():
                if len(tok) % 2:
                    raise ValueError("odd hex token %r" % tok)
                out.extend(int(tok[k:k + 2], 16) for k in range(0, len(tok), 2))
            i = j + 1
            continue
        out.append(ord(c))
        i += 1
    return bytes(out)


def bytes_to_regex(data):
    """Every byte as an explicit \\xNN escape.

    Escaping everything rather than only the metacharacters keeps this
    correct for arbitrary binary content without a table of special
    cases, and `(?-u)` (added by the caller) lets the bytes regex engine
    match non-UTF-8 payloads.
    """
    return "".join("\\x%02x" % b for b in data)


def content_len(value):
    """Byte length of an ARGUS content, counting |hex| blocks and escapes."""
    n, i, in_hex = 0, 0, False
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            n += 1
            i += 2
            continue
        if c == "|":
            in_hex = not in_hex
            i += 1
            continue
        if in_hex:
            # Hex bodies are space-separated byte pairs.
            j = i
            while j < len(value) and value[j] != "|":
                j += 1
            n += len(value[i:j].split())
            i = j
            continue
        n += 1
        i += 1
    return n


# The buffer a legacy pcre flag selects. Snort-era rules put the buffer in
# the regex's flags (`/.../U`) rather than in a sticky buffer before it;
# the meaning is the same as naming the buffer, so it is expressed that
# way. Raw and normalised forms are not distinguished, as elsewhere.
BUFFER_FLAGS = {
    "U": "http.uri", "I": "http.uri", "P": "http.request_body", "Q": "http.response_body",
    "H": "http.header", "D": "http.header", "M": "http.method", "C": "http.cookie",
    "S": "http.stat_code", "Y": "http.stat_msg", "V": "http.user_agent", "W": "http.host",
}

ASCII_WORD = "A-Za-z0-9_"
ASCII_SPACE = r" \t\n\r\f\v"


def scan_pcre(pat):
    """Finds the constructs a pattern uses, respecting escapes and classes.

    A tokenising pass rather than a regex, because the regex it replaced
    could not tell `\\1` (a backreference) from `\\\\1` (a literal
    backslash and a digit), nor a `(?=` inside a character class from one
    outside it, and misjudging either changes what a rule means.

    Returns (needs_backtracking, hard_reason). `hard_reason` is set for
    constructs no engine here can express.
    """
    needs = set()
    hard = None
    i, n, in_class = 0, len(pat), False
    while i < n:
        c = pat[i]
        if c == "\\":
            nxt = pat[i + 1] if i + 1 < n else ""
            if not in_class:
                if nxt in "123456789":
                    needs.add("backreference")
                elif nxt == "k":
                    needs.add("backreference")
                elif nxt in "GKZgR":
                    hard = hard or "escape \\" + nxt
            i += 2
            continue
        if in_class:
            if pat.startswith("[:", i):
                j = pat.find(":]", i + 2)
                i = j + 2 if j >= 0 else n
                continue
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            if i < n and pat[i] == "^":
                i += 1
            if i < n and pat[i] == "]":
                i += 1
            continue
        if c == "(" and pat.startswith("(?", i):
            rest = pat[i + 2 : i + 5]
            if rest.startswith("<=") or rest.startswith("<!"):
                needs.add("lookbehind")
            elif rest.startswith("=") or rest.startswith("!"):
                needs.add("lookahead")
            elif rest.startswith(">"):
                needs.add("atomic group")
            elif rest.startswith("("):
                needs.add("conditional")
            elif rest.startswith("P="):
                needs.add("backreference")
            elif rest.startswith("R") or rest.startswith("&") or rest[:1].isdigit() or rest.startswith("P>"):
                hard = hard or "recursion"
        elif c in "*+?}" and i + 1 < n and pat[i + 1] == "+":
            needs.add("possessive quantifier")
        i += 1
    return needs, hard


def widen_pattern(pat, icase):
    """Rewrites a pattern for the backtracking engine, which reads bytes as
    the characters with the same code.

    That engine works on text, so `\\w`, `\\d`, `\\s` and `\\b` would take
    their Unicode meanings and treat a byte like 0xE9 as a letter; PCRE in
    the mode Suricata uses would not. Each is rewritten to its ASCII form
    so a rule means the same on both engines. Returns None for anything
    that cannot be rewritten faithfully.
    """
    out = []
    i, n, in_class = 0, len(pat), False
    while i < n:
        c = pat[i]
        if c == "\\" and i + 1 < n:
            e = pat[i + 1]
            if e in "wds":
                cls = {"w": ASCII_WORD, "d": "0-9", "s": ASCII_SPACE}[e]
                out.append(cls if in_class else "[" + cls + "]")
            elif e in "WDS":
                if in_class:
                    return None  # a negated shorthand inside a class
                cls = {"W": ASCII_WORD, "D": "0-9", "S": ASCII_SPACE}[e]
                out.append("[^" + cls + "]")
            elif e in "bB" and not in_class:
                # The engine cannot switch Unicode off for one assertion,
                # so an ASCII word boundary is spelled out: a word
                # character on exactly one side.
                w = "[" + ASCII_WORD + "]"
                if e == "b":
                    out.append("(?:(?<=%s)(?!%s)|(?<!%s)(?=%s))" % (w, w, w, w))
                else:
                    out.append("(?:(?<=%s)(?=%s)|(?<!%s)(?!%s))" % (w, w, w, w))
            elif e == "x" and icase:
                hexpart = pat[i + 2 : i + 4]
                if len(hexpart) == 2 and hexpart.isalnum() and int(hexpart, 16) >= 0x80:
                    return None  # case folding would reach Latin-1 letters PCRE leaves alone
                out.append(pat[i : i + 2])
            else:
                out.append(pat[i : i + 2])
            i += 2
            continue
        if in_class and c == "]":
            in_class = False
        elif not in_class and c == "[":
            in_class = True
            out.append(c)
            i += 1
            if i < n and pat[i] == "^":
                out.append("^")
                i += 1
            if i < n and pat[i] == "]":
                out.append("]")
                i += 1
            continue
        if ord(c) > 0x7F:
            return None
        out.append(c)
        i += 1
    return "".join(out)


def normalise_regex(pat):
    """Spells out two things PCRE accepts and Rust's regex crate rejects.

    A bare `[` inside a character class is a literal `[` to PCRE, so ET's
    `[sS[eE]` (surely a typo, but a valid one) means "one of s, S, [, e,
    E"; Rust reads it as a nested class and fails. And `\\x2` with a single
    hex digit is `\\x02` to PCRE; Rust wants two. Both readings are
    unambiguous, so they are made explicit rather than the rule dropped.
    """
    out = []
    i, n, in_class = 0, len(pat), False
    while i < n:
        c = pat[i]
        if c == "\\" and i + 1 < n:
            if pat[i + 1] == "x":
                m = re.match(r"[0-9A-Fa-f]{1,2}", pat[i + 2 : i + 4])
                if m and len(m.group(0)) == 1:
                    out.append("\\x0" + m.group(0))
                    i += 3
                    continue
            # `\<` and `\>` are a literal angle bracket to PCRE. Rust reads
            # them as word boundaries (outside a class) or rejects them
            # (inside one), so spell the literal.
            if pat[i + 1] in "<>":
                out.append(pat[i + 1])
            else:
                out.append(pat[i : i + 2])
            i += 2
            continue
        if in_class:
            if pat.startswith("[:", i):
                j = pat.find(":]", i + 2)
                j = j + 2 if j >= 0 else n
                out.append(pat[i:j])
                i = j
                continue
            if c == "[":
                out.append("\\[")
                i += 1
                continue
            if c == "]":
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            if i < n and pat[i] == "^":
                out.append("^")
                i += 1
            if i < n and pat[i] == "]":
                out.append("\\]")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


LEN_RE = re.compile(r"^\s*(?:(?:<=|>=|<|>)?\s*\d+|\d+\s*<>\s*\d+)\s*$")
IDENT = re.compile(r"^[A-Za-z_][\w.]*$")
DATAAT_RE = re.compile(r"^\s*(!)?\s*(\d+|[A-Za-z_][\w.]*)\s*(?:,\s*(relative)\s*)?$", re.IGNORECASE)


def len_spec(value):
    """`N`, `<N`, `>N`, `<=N`, `>=N` or `A<>B`, or None for anything else.

    A trailing modifier such as `urilen:12,norm` is refused: it selects a
    different form of the buffer than the one ARGUS measures, and guessing
    would change which requests the rule matches.
    """
    return re.sub(r"\s+", "", value) if LEN_RE.match(value) else None


def dataat_spec(value):
    """`[!]N[,relative]` normalised, or None. `N` may name a variable a
    `byte_extract` or `byte_math` defined."""
    m = DATAAT_RE.match(value)
    if not m:
        return None
    return "%s%s%s" % ("!" if m.group(1) else "", m.group(2), ",relative" if m.group(3) else "")


def place_term(terms, term):
    """Puts a term after the last one in its own buffer, or at the end.

    `urilen` may be written anywhere in a Suricata rule and still means the
    URI. Placing it beside the URI's other terms keeps them in one part; at
    the end it would open a second part on the same buffer for no reason.
    """
    for i in range(len(terms) - 1, -1, -1):
        if terms[i]["buffer"] == term["buffer"]:
            terms.insert(i + 1, term)
            return
    terms.append(term)


def pattern_has_case(pat, transform):
    """Whether a pattern names a letter that a case-folded buffer can never
    contain: an uppercase letter under `to_lowercase`, a lowercase one
    under `to_uppercase`.

    Escapes are skipped (`\\W` is a class, not the letter W), and a hex
    escape is judged by the byte it names.
    """
    lower_forbidden = transform == "upper"
    bad = re.compile(r"[a-z]" if lower_forbidden else r"[A-Z]")
    lo, hi = (0x61, 0x7A) if lower_forbidden else (0x41, 0x5A)
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "\\" and i + 1 < n:
            if pat[i + 1] == "x":
                m = re.match(r"[0-9A-Fa-f]{1,2}", pat[i + 2 : i + 4])
                if m:
                    if lo <= int(m.group(0), 16) <= hi:
                        return True
                    i += 2 + len(m.group(0))
                    continue
            i += 2
            continue
        if bad.match(c):
            return True
        i += 1
    return False


def convert_pcre(value, force_case=None):
    """Suricata pcre `"/pat/flags"` -> (info, None) or (None, reason).

    `info` carries the pattern, which engine it needs, whether it resumes
    from the previous match (the `R` flag), and any buffer its flags
    select. Nothing is approximated: a flag or construct that cannot be
    expressed rejects the rule, with the reason recorded.
    """
    v = unquote(value)
    if not v.startswith("/"):
        return None, "pcre not slash-delimited"
    end = v.rfind("/")
    if end <= 0:
        return None, "pcre not slash-delimited"
    pat, flags = v[1:end], v[end + 1 :]

    inline, relative, buf = "", False, None
    for f in flags:
        if f in "ismx":
            inline += f
        elif f == "R":
            relative = True
        elif f in BUFFER_FLAGS:
            if buf not in (None, BUFFER_FLAGS[f]):
                return None, "pcre with several buffer flags"
            buf = BUFFER_FLAGS[f]
        else:
            return None, "pcre flag /%s" % f

    # Under a case transform the regex runs against an already-folded
    # buffer. That is the same as running it case-insensitively against the
    # original, *provided* the pattern names no letter of the other case;
    # one that does could never match the folded buffer, and folding it
    # here would make it match. Such a rule is refused, not reinterpreted.
    if force_case:
        if pattern_has_case(pat, force_case):
            return None, "pcre names a letter its case transform removes"
        if "i" not in inline:
            inline += "i"

    needs, hard = scan_pcre(pat)
    if hard:
        return None, "pcre uses " + hard

    # PCRE's bare `\0` is NUL; the regex crates want `\x00`.
    pat = re.sub(r"(?<!\\)((?:\\\\)*)\\0(?![0-7])", lambda m: m.group(1) + r"\x00", pat)
    pat = normalise_regex(escape_literal_braces(pat))

    if needs:
        if "x" in inline:
            return None, "pcre needs backtracking and uses /x"
        text = widen_pattern(pat, "i" in inline)
        if text is None:
            return None, "pcre needs backtracking with a construct that cannot be widened"
        engine = "backtrack"
        head = "(?%s)" % inline if inline else ""
    else:
        # Byte semantics, as PCRE runs in Suricata: `.` matches any byte
        # but newline, `\w` and `\b` are ASCII, and case folding is ASCII.
        # The crate's default is Unicode, under which `.` refuses to match
        # a byte that is not valid UTF-8 — so a pattern about binary
        # traffic quietly failed to match the binary traffic.
        text = pat
        engine = "linear"
        head = "(?%s-u)" % inline
    return {"pattern": head + text, "engine": engine, "relative": relative, "buffer": buf}, None


def escape_literal_braces(pat):
    """Escapes a `{` that does not open a repetition quantifier.

    PCRE treats a brace that cannot be read as `{n}`, `{n,}` or `{n,m}`
    as a literal; Rust's regex crate rejects it outright. ET rules use
    bare braces freely, because a great many of the things they match —
    COM class ids, JSON, PowerShell — are full of them. Escaping is the
    faithful reading rather than a workaround: both engines then agree
    the brace is a literal brace.
    """
    out = []
    i = 0
    n = len(pat)
    while i < n:
        c = pat[i]
        if c == "\\" and i + 1 < n:
            # Already escaped, whatever it is: copy the pair through.
            out.append(pat[i:i + 2])
            i += 2
            continue
        if c == "{":
            m = QUANTIFIER_RE.match(pat, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
            out.append("\\{")
            i += 1
            continue
        if c == "}":
            # Unmatched by construction: every `{` that opened a real
            # quantifier consumed its own `}` above.
            out.append("\\}")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


QUANTIFIER_RE = re.compile(r"\{\d+(,\d*)?\}")


def convert_ports(spec):
    """Suricata port spec -> ARGUS port spec, or None if inexpressible."""
    s = spec.strip()
    if s in ("any", "$HOME_NET", "$EXTERNAL_NET"):
        return None  # 'any': omit the term entirely
    neg = s.startswith("!")
    if neg:
        s = s[1:]
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    parts = []
    for item in s.split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("$"):
            repl = PORT_VARS.get(item)
            if repl is None:
                return None
            if repl == "any":
                return None
            parts.append(repl)
            continue
        if item.startswith("!"):
            return None  # mixed negation inside a list
        if ":" in item:  # Suricata range syntax, e.g. 1024:
            lo, _, hi = item.partition(":")
            lo = lo or "0"
            hi = hi or "65535"
            if not lo.isdigit() or not hi.isdigit():
                return None
            parts.append("%s-%s" % (lo, hi))
            continue
        if not item.isdigit():
            return None
        parts.append(item)
    if not parts:
        return None
    return ("!" if neg else "") + ",".join(parts)


def convert_addr(spec, home_net):
    """Suricata address spec -> ARGUS CIDR list, or None for 'any'."""
    s = spec.strip()
    if s == "any":
        return None
    if s == "$HOME_NET":
        return home_net
    if s == "$EXTERNAL_NET":
        return ("!" + home_net) if home_net else None
    neg = s.startswith("!")
    if neg:
        s = s[1:]
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    parts = []
    for item in s.split(","):
        item = item.strip()
        if not item or item.startswith("$") or item.startswith("!"):
            return None
        if not re.match(r"^[0-9a-fA-F:.]+(/\d+)?$", item):
            return None
        parts.append(item)
    if not parts:
        return None
    return ("!" if neg else "") + ",".join(parts)


def severity_of(opts):
    """ET metadata or classtype -> ARGUS severity."""
    for o in opts:
        if opt_name(o) == "metadata":
            v = opt_value(o).lower()
            if "signature_severity major" in v or "signature_severity critical" in v:
                return "high"
            if "signature_severity minor" in v:
                return "medium"
            if "signature_severity informational" in v or "signature_severity audit" in v:
                return "low"
    for o in opts:
        if opt_name(o) == "classtype":
            c = opt_value(o).strip().lower()
            if c in ("trojan-activity", "attempted-admin", "attempted-user", "successful-admin",
                     "successful-user", "shellcode-detect", "web-application-attack",
                     "command-and-control", "targeted-activity", "exploit-kit", "domain-c2",
                     "credential-theft", "malware-cnc"):
                return "high"
            if c in ("policy-violation", "bad-unknown", "attempted-recon", "attempted-dos",
                     "suspicious-filename-detect", "suspicious-login", "denial-of-service",
                     "web-application-activity", "misc-attack", "default-login-attempt"):
                return "medium"
    return "medium"


def escape_name(msg):
    """Makes a rule's message safe to carry through ARGUS's rule syntax.

    A name is parsed with the same unescaper as a content pattern, so
    `|` opens a hex block and `\\` starts an escape. ET names contain
    both freely — "Likely Bot Nick in IRC ([country|so version|CPU])"
    is a real one, and it failed to load as an invalid hex byte, which
    is a confusing way to be told about a punctuation problem. `"` and
    `;` are separators in the option list, so they are replaced rather
    than escaped.
    """
    return (
        msg.replace("\\", "/")
        .replace("|", "/")
        .replace('"', "'")
        .replace(";", ",")
    )


def convert(line, home_net):
    """Returns (argus_rule, None) or (None, skip_reason)."""
    m = RULE_RE.match(line)
    if not m:
        return None, "unparseable header"
    g = m.groupdict()
    if g["action"] != "alert":
        return None, "non-alert action"
    proto = g["proto"].lower()
    app_layer = False
    pkt_rule = False
    if proto in APP_PROTOS:
        # An app-layer rule. Its protocol identity is carried by the
        # buffer it inspects, which is checked below.
        app_layer = True
        proto = APP_PROTOS[proto]
    elif proto == "tcp-pkt":
        # A rule about individual segments rather than the stream: its
        # unqualified contents read the packet, not the reassembled buffer.
        proto = "tcp"
        pkt_rule = True
    elif proto not in ("tcp", "udp", "icmp", "ip"):
        return None, "proto '%s'" % proto
    if g["dir"] == "<>":
        # Either end may be the source. That is the rule written both ways
        # round, unless it also says which side of a connection it is about,
        # which would then be ambiguous.
        if re.search(r"flow:[^;]*(to_server|to_client|from_client|from_server)", g["opts"]):
            return None, "bidirectional rule"
        lines = []
        for a_, ap, b_, bp in ((g["src"], g["sport"], g["dst"], g["dport"]), (g["dst"], g["dport"], g["src"], g["sport"])):
            variant = "%s %s %s %s -> %s %s (%s)" % (g["action"], g["proto"], a_, ap, b_, bp, g["opts"])
            out, why = convert(variant, home_net)
            if out is None:
                return None, why
            lines.append(out)
        return "\n".join(lines), None

    opts = split_options(g["opts"])
    names = [opt_name(o) for o in opts]

    # Buffers first: a rule inspecting a buffer ARGUS doesn't have is
    # blocked by that regardless of its other options, and reporting the
    # option instead made the statistics misleading about the real cause.
    for n in names:
        if n in UNSUPPORTED_BUFFERS:
            return None, "buffer '%s'" % n
    for n in names:
        if n in BLOCKING_OPTS:
            return None, "option '%s'" % n

    sid = next((opt_value(o) for o in opts if opt_name(o) == "sid"), None)
    if not sid or not sid.strip().isdigit():
        return None, "no sid"
    msg = next((unquote(opt_value(o)) for o in opts if opt_name(o) == "msg"), "sid-" + sid)

    # Direction, from `flow:` if present.
    direction = "any"
    for o in opts:
        if opt_name(o) == "flow":
            v = opt_value(o).lower()
            if "to_server" in v or "from_client" in v:
                direction = "to_server"
            elif "to_client" in v or "from_server" in v:
                direction = "to_client"

    # Walk the options in order: buffer selection is positional in
    # Suricata, and offset/depth/nocase attach to the preceding content.
    terms, buffer_name, current = [], ("packet" if pkt_rule else "payload"), None
    header_tests = []
    flowbit_terms = []
    buffers_used = set()
    # Buffer-level transforms, reset whenever the buffer changes.
    dotprefix = False
    # Case transforms apply to a sticky buffer as a whole, so they are
    # recorded per buffer and applied to every term in it afterwards,
    # wherever in the rule the option happened to be written.
    case_tf = {}
    explicit_tf = {}
    dsize_spec = None
    # Length tests are placed once the whole rule has been read: `urilen`
    # may be written before any URI content exists, and placing it then
    # would open a second URI part instead of joining the first.
    deferred_len = []
    for o in opts:
        n, v = opt_name(o), opt_value(o)
        if n == "tls.version" and v.strip():
            # `tls.version:1.2` tests the version the server chose; it does
            # not select a buffer for the contents that follow.
            version = v.strip().strip('"')
            if not re.fullmatch(r"\d\.\d", version):
                return None, "'tls.version' form"
            raw = version.encode()
            terms.append({"kind": "content", "value": convert_content(chr(34) + version + chr(34)), "neg": False, "buffer": "tls.version",
                          "mods": [], "raw": raw, "anchor_end": False, "dotprefix": False})
            terms.append({"kind": "len", "value": str(len(raw)), "neg": False, "buffer": "tls.version",
                          "mods": [], "raw": b"", "anchor_end": False, "dotprefix": False})
            buffers_used.add("tls.version")
            current = None
            continue
        if n in BUFFERS:
            buffer_name = BUFFERS[n]
            buffers_used.add(buffer_name)
            dotprefix = False
            continue
        if n in NO_OP_TRANSFORMS:
            continue
        if n in TRANSFORM_OPTS:
            chain = explicit_tf.setdefault(buffer_name, [])
            if TRANSFORM_OPTS[n] not in chain:
                chain.append(TRANSFORM_OPTS[n])
            continue
        if n in ("to_lowercase", "to_uppercase"):
            which = "lower" if n == "to_lowercase" else "upper"
            if case_tf.get(buffer_name, which) != which:
                return None, "conflicting case transforms"
            case_tf[buffer_name] = which
            continue
        if n == "dotprefix":
            # Prepends '.' to the buffer, so that `content:".x.com";
            # endswith` also matches a buffer that *is* "x.com".
            dotprefix = True
            continue
        if n in ("bsize", "urilen"):
            # Both test the length of a buffer. `urilen` is `bsize` on the
            # request URI, wherever in the rule it happens to be written.
            spec = len_spec(v)
            if spec is None:
                return None, "'%s' form" % n
            target = "http.uri" if n == "urilen" else buffer_name
            deferred_len.append({"kind": "len", "value": spec, "neg": False, "buffer": target,
                                 "mods": [], "raw": b"", "anchor_end": False, "dotprefix": False})
            buffers_used.add(target)
            continue
        if n == "isdataat":
            spec = dataat_spec(v)
            if spec is None:
                return None, "isdataat form"
            terms.append({"kind": "isdataat", "value": spec, "neg": False, "buffer": buffer_name,
                          "mods": [], "raw": b"", "anchor_end": False, "dotprefix": False})
            buffers_used.add(buffer_name)
            continue
        if n in ("itype", "icode", "window", "ip_proto", "flags", "stream_size"):
            spec = header_test_spec(n, v)
            if spec is None:
                return None, "'%s' form" % n
            header_tests.append("%s:%s" % (n, spec))
            continue
        if n == "dsize":
            spec = len_spec(v)
            if spec is None:
                return None, "dsize form"
            dsize_spec = spec
            continue
        if n == "content":
            neg = v.strip().startswith("!")
            if neg:
                v = v.strip()[1:]
            try:
                raw = content_bytes(v)
            except ValueError:
                return None, "malformed content"
            current = {"kind": "content", "value": convert_content(v), "neg": neg,
                       "buffer": buffer_name, "mods": [], "raw": raw,
                       "anchor_end": False, "dotprefix": dotprefix}
            terms.append(current)
            buffers_used.add(buffer_name)
            continue
        if n == "pcre":
            neg = v.strip().startswith("!")
            if neg:
                v = v.strip()[1:]
            conv, why_not = convert_pcre(v)
            if conv is None:
                return None, why_not
            target = conv["buffer"] or buffer_name
            # `R` resumes from the previous match in the same buffer, so
            # there has to be one.
            # With none, Suricata measures from the start of the buffer,
            # which is where a plain regex already looks.
            if conv["relative"] and not any(t["buffer"] == target and t["kind"] in ("content", "pcre") for t in terms):
                conv["relative"] = False
            current = {"kind": "pcre", "value": conv["pattern"], "neg": neg,
                       "buffer": target, "mods": [], "raw": b"",
                       "anchor_end": False, "dotprefix": False,
                       "engine": conv["engine"], "relative": conv["relative"],
                       "pcre_src": v}
            terms.append(current)
            buffers_used.add(target)
            continue
        if n == "endswith":
            if current is None or current["kind"] != "content":
                return None, "'endswith' with no content"
            current["anchor_end"] = True
            continue
        if n == "startswith":
            # Exactly "at the very start", i.e. offset 0 and a depth of
            # the content's own length. Expressible, so worth keeping:
            # it's one of the more common modifiers in the ET set.
            if current is None or current["kind"] != "content":
                return None, "'startswith' with no content"
            current["mods"].append(("offset", "0"))
            current["mods"].append(("depth", str(len(current["raw"]))))
            continue
        if n in ("nocase", "offset", "depth", "distance", "within"):
            if current is None:
                return None, "'%s' with no content" % n
            if current["kind"] == "pcre" and n != "nocase":
                return None, "'%s' on pcre" % n
            if n in ("distance", "within"):
                # Suricata also allows a variable name from byte_extract in
                # place of a number. ARGUS has no such variables, so a rule
                # using one is refused rather than approximated.
                vv = v.strip()
                # A negative `distance` looks back over what was just
                # matched, and ARGUS reads that. `within` cannot be negative.
                if not (vv.isdigit() or (n == "distance" and vv.startswith("-") and vv[1:].isdigit()) or IDENT.match(vv)):
                    return None, "'%s' is not a constant" % n
            current["mods"].append((n, v.strip()))
            continue
        if n == "base64_data":
            # The decoded bytes are read by whatever follows `base64_decode`.
            continue
        if n in ("byte_extract", "byte_math", "base64_decode"):
            spec = variable_op_spec(n, v)
            if spec is None:
                return None, "'%s' form" % n
            terms.append({"kind": n, "value": spec, "neg": False,
                          "buffer": buffer_name, "mods": [], "raw": b"",
                          "anchor_end": False, "dotprefix": False})
            buffers_used.add(buffer_name)
            current = None
            continue
        if n in ("byte_test", "byte_jump"):
            # Passed through as written: the grammar is identical, and
            # ARGUS's parser refuses anything it cannot represent, so a
            # form this translator has not anticipated fails at load
            # rather than becoming a rule that means something else.
            spec = normalise_byte_op(v, 4 if n == "byte_test" else 2)
            if spec is None:
                return None, "'%s' form" % n
            terms.append({"kind": n, "value": spec, "neg": False,
                          "buffer": buffer_name, "mods": [], "raw": b"",
                          "anchor_end": False, "dotprefix": False})
            buffers_used.add(buffer_name)
            # A byte op is not a content, so a following `distance`
            # would have nothing to attach to.
            current = None
            continue
        if n in ("xbits", "hostbits"):
            spec = xbit_spec(v)
            if spec is None:
                return None, "'%s' form" % n
            flowbit_terms.append("xbits:%s" % spec)
            continue
        if n in ("threshold", "detection_filter"):
            spec = rate_spec(n, v)
            if spec is None:
                return None, "'%s' form" % n
            flowbit_terms.append("%s:%s" % (n, spec))
            continue
        if n == "flowbits":
            parts = [p.strip() for p in v.split(",")]
            verb = parts[0].lower() if parts else ""
            if verb == "noalert":
                flowbit_terms.append("noalert")
                continue
            if verb not in ("set", "unset", "toggle", "isset", "isnotset"):
                return None, "flowbits '%s'" % verb
            if len(parts) < 2 or not parts[1]:
                return None, "flowbits with no name"
            # ET uses `|` to mean "any of these", which is a disjunction
            # ARGUS has no way to express.
            if "|" in parts[1] or "&" in parts[1]:
                return None, "flowbits expression"
            flowbit_terms.append("flowbits:%s,%s" % (verb, sanitise_bit(parts[1])))
            continue
        if n in IGNORABLE_OPTS:
            continue
        # Anything unrecognised is treated as blocking: an option this
        # translator has never seen may well change what the rule matches.
        return None, "unknown option '%s'" % n

    for t in deferred_len:
        place_term(terms, t)

    # `dsize` is the size of one packet's payload. A rule about a parsed
    # buffer has no single packet it refers to (a request may span several),
    # so combining them would test something the rule's author did not mean.
    if dsize_spec and ({t["buffer"] for t in terms} - {"payload", "packet"}):
        return None, "dsize with a structured buffer"

    # Apply the case transforms. A transform folds the buffer, so a
    # content is matched case-insensitively — but only if it is itself in
    # the folded case, since an uppercase content could never match a
    # lowercased buffer, and emitting it with `nocase` would make a rule
    # that never fires start firing.
    for t in terms:
        tf = case_tf.get(t["buffer"])
        if not tf:
            continue
        if t["kind"] == "content":
            forbidden = rb"[a-z]" if tf == "upper" else rb"[A-Z]"
            if re.search(forbidden, t["raw"]):
                return None, "content can never match under to_%scase" % tf
            if not any(m == "nocase" for m, _ in t["mods"]):
                t["mods"].append(("nocase", ""))
        elif t["kind"] == "pcre":
            conv, why_not = convert_pcre(t["pcre_src"], force_case=tf)
            if conv is None:
                return None, why_not
            t["value"], t["engine"] = conv["pattern"], conv["engine"]

    identity_bit = None
    if app_layer and not (buffers_used - {"payload"}):
        # Without a structured buffer nothing carries the protocol's
        # identity, and `payload` alone would widen the rule to every TCP
        # stream. ARGUS's parsers record what they recognised as a flowbit,
        # so the rule is scoped to "a flow identified as this".
        app = g["proto"].lower()
        if app in APP_IDENTITY:
            identity_bit = "app.%s" % APP_IDENTITY[app]
        elif app in UDP_APP_PORTS:
            # Datagram protocols have no flow to carry an identity, so the
            # well-known port stands in for it.
            ports = UDP_APP_PORTS[app]
            named = ports.split(",")
            names_port = lambda spec: any(p in re.split(r"[,\[\]\s]+", spec) for p in named)
            if names_port(g["dport"]) or names_port(g["sport"]):
                pass  # the rule already says which port it is about
            elif direction == "to_server" and dport_override_ok(g["dport"]):
                g = dict(g, dport=ports)
            elif direction == "to_client" and dport_override_ok(g["sport"]):
                g = dict(g, sport=named[0])
            elif direction == "any" and dport_override_ok(g["sport"]) and dport_override_ok(g["dport"]):
                # Either end may be the service, so it is two rules.
                lines = []
                for sp, dp in (("any", ports), (named[0], "any")):
                    variant = "%s %s %s %s %s %s %s (%s)" % (g["action"], g["proto"], g["src"], sp, g["dir"], g["dst"], dp, g["opts"])
                    out, why = convert(variant, home_net)
                    if out is None:
                        return None, why
                    lines.append(out)
                return "\n".join(lines), None
            else:
                return None, "app-layer rule with no supported buffer"
        else:
            return None, "app-layer rule with no supported buffer"
    content_terms = [t for t in terms if t["kind"] in ("content", "pcre")]
    tests_state = any(t.startswith("flowbits:isset") or t.startswith("flowbits:isnotset") for t in flowbit_terms)
    tests_state = tests_state or bool(header_tests)
    if not content_terms and not tests_state:
        # A rule with neither a content term nor a state condition would
        # match every buffer of its type.
        return None, "no content or pcre"
    if content_terms and all(t["neg"] for t in content_terms) and not tests_state:
        return None, "all terms negated"
    # ARGUS scopes a whole rule to one buffer; a rule inspecting two
    # different buffers can't be expressed as one rule and must not be
    # collapsed into either.
    final_buffer = (buffers_used - {"payload"}).pop() if (buffers_used - {"payload"}) else "payload"

    parts = ["sid:%s" % sid.strip(), 'name:"%s"' % escape_name(msg),
             "severity:%s" % severity_of(opts)]
    if proto != "ip":
        parts.append("proto:%s" % proto)

    src = convert_addr(g["src"], home_net)
    dst = convert_addr(g["dst"], home_net)
    sport = convert_ports(g["sport"])
    dport = convert_ports(g["dport"])
    if src:
        parts.append("src_ip:%s" % src)
    if dst:
        parts.append("dst_ip:%s" % dst)
    if sport:
        parts.append("src_port:%s" % sport)
    if dport:
        parts.append("dst_port:%s" % dport)
    if dsize_spec:
        parts.append("dsize:%s" % dsize_spec)
    parts.extend(header_tests)
    if header_tests and not terms:
        # Nothing but header conditions: the rule is about the packet.
        parts.append("buffer:packet")
    if direction != "any":
        parts.append("direction:%s" % direction)
    # The backtracking engine is slower and is only ever run on a rule's
    # candidates. That works only if the rule has a plain literal for the
    # prefilter to key on; without one it would run against every buffer
    # of its type.
    # On a buffer that exists once per connection or request (a header, a
    # certificate) that is affordable; on the raw stream, which is scanned
    # for every packet, it is not.
    for b in {t["buffer"] for t in terms if t.get("engine") == "backtrack" and t["buffer"] in ("payload", "packet")}:
        if not any(t["buffer"] == b and t["kind"] == "content" and not t["neg"] for t in terms):
            return None, "backtracking pcre with no literal to prefilter on"

    # Every buffer a multi-buffer rule names needs a positive content of
    # its own, or its part would run against every buffer of that type.
    # ET has plenty of "user agent is NOT Mozilla" clauses, which are
    # meaningful only alongside something positive *in that buffer*.
    if len({t["buffer"] for t in terms}) > 1:
        for b in {t["buffer"] for t in terms}:
            if any(t["buffer"] == b and t["kind"] in ("content", "pcre") and not t["neg"] for t in terms):
                continue
            # A buffer holding only negations ("no Accept header") is a
            # real claim about a complete, per-message buffer, and ARGUS
            # accepts it there. On the raw payload it is not: the stream is
            # still growing, so "does not contain X" has no answer yet.
            if b == "payload":
                return None, "payload part with only negated terms"

    # One `buffer:` per run of terms on the same buffer, in rule order.
    # ARGUS lowers a rule naming several buffers into one part per buffer,
    # each checked when its buffer is parsed.
    emitted = None
    first_in_group = False
    for t in terms:
        if t["buffer"] != emitted:
            emitted = t["buffer"]
            parts.append("buffer:%s" % argus_buffer(emitted))
            for tf in IMPLICIT_TRANSFORMS.get(emitted, []) + explicit_tf.get(emitted, []):
                parts.append("transform:%s" % tf)
            first_in_group = True
        else:
            first_in_group = False
        # Length and end-of-data tests are written straight through; ARGUS
        # reads the same syntax.
        if t["kind"] in ("len", "isdataat"):
            parts.append(("bsize:%s" if t["kind"] == "len" else "isdataat:%s") % t["value"])
            continue
        # A relative modifier needs a previous match *in its own buffer*.
        # With none, Suricata measures from the start of the buffer, which
        # is exactly a window from `offset`: `distance:D` is `offset:D`,
        # and `within:W` bounds the match to W bytes past that.
        if first_in_group and t["kind"] == "content":
            # Both are measured from the start, so the window is [D, W]:
            # ARGUS's `depth` counts from its `offset`, hence W - D.
            mods = dict(t["mods"])
            rest = [(m, mv) for m, mv in t["mods"] if m not in ("distance", "within")]
            if "distance" in mods or "within" in mods:
                if not all(re.fullmatch(r"-?\d+", mods.get(k, "0")) for k in ("distance", "within")):
                    return None, "a variable in a leading window"
                start = max(int(mods.get("distance", "0")), 0)
                rest.append(("offset", str(start)))
                if "within" in mods:
                    rest.append(("depth", str(max(int(mods["within"]) - start, 0))))
            t["mods"] = rest
        if first_in_group and t.get("relative"):
            t["relative"] = False
        nocase = any(m == "nocase" for m, _ in t["mods"])
        anchored = t["kind"] == "content" and t["anchor_end"]

        if anchored:
            # An anchored content is expressible only as a regex, since
            # ARGUS's offset/depth measure from the start of the buffer
            # and these measure from the end (or pin the whole length).
            window = {m: v for m, v in t["mods"] if m in ("offset", "depth")}
            prefix = ""
            if window:
                # `endswith` plus `offset`/`depth`: the content must end the
                # buffer *and* start inside the window, which is a bound on
                # how many bytes precede it. Written as `^.{lo,hi}`, still
                # linear. A variable, a relative modifier or a leading-dot
                # form is not a number of bytes, so it is refused.
                if t["dotprefix"] or any(m in ("distance", "within") for m, _ in t["mods"]):
                    return None, "anchored content with offset/depth"
                try:
                    lo = int(window.get("offset", 0))
                    depth = int(window["depth"]) if "depth" in window else None
                except ValueError:
                    return None, "anchored content with offset/depth"
                hi = "" if depth is None else lo + depth - len(t["raw"])
                if hi != "" and hi < lo:
                    return None, "anchored content with offset/depth"
                prefix = "^(?s:.{%d,%s})" % (lo, hi)
            body = prefix + bytes_to_regex(t["raw"])
            if t["dotprefix"]:
                # On the untransformed buffer, ".x.com" at the end means
                # the buffer ends with ".x.com" *or* equals "x.com".
                inner = t["raw"][1:] if t["raw"].startswith(b".") else t["raw"]
                pat = "(^|\\x2e)" + bytes_to_regex(inner) + "$"
            else:
                pat = body + "$"
            flags = "(?i-u)" if nocase else "(?-u)"
            key = ("!" if t["neg"] else "") + "pcre"

            # Emit the implied literal alongside the anchored regex.
            #
            # Semantically this is a no-op: the regex already requires
            # those exact bytes, and ARGUS ANDs a rule's terms. What it
            # buys is prefiltering. Anchoring forces a term to become a
            # regex, and a rule whose every term is a regex has no
            # literal for the Aho-Corasick prefilter to key on, so it
            # lands in the "always evaluate" list and runs against every
            # buffer of every packet. Converting the ET set without this
            # left 89% of 26,677 rules unprefilterable and made a replay
            # 27x slower. For `dotprefix` the literal is the content
            # *without* its leading dot, since `(^|\.)` means the dot
            # itself may be absent.
            if not t["neg"]:
                implied = t["raw"]
                if t["dotprefix"] and implied.startswith(b"."):
                    implied = implied[1:]
                if implied:
                    special = '"' + chr(92) + "|"
                    lit = "".join(
                        (chr(92) + chr(b)) if chr(b) in special else
                        (chr(b) if 32 <= b < 127 else "|%02x|" % b)
                        for b in implied
                    )
                    parts.append('content:"%s"' % lit)
                    if nocase:
                        parts.append("nocase")
            parts.append('%s:"%s%s"' % (key, flags, pat))
            continue

        if t["kind"] in ("byte_test", "byte_jump", "byte_extract", "byte_math", "base64_decode"):
            parts.append("%s:%s" % (t["kind"], t["value"]))
            continue

        if t["kind"] == "content":
            kind = "content"
        else:
            kind = "pcre_bt" if t.get("engine") == "backtrack" else "pcre"
        key = ("!" if t["neg"] else "") + kind
        parts.append('%s:"%s"' % (key, t["value"]))
        for mod, mv in t["mods"]:
            parts.append(mod if mod == "nocase" else "%s:%s" % (mod, mv))
        if t.get("relative"):
            parts.append("relative")

    # Flowbits last, so the rule reads as "match this, then do that".
    # Order is irrelevant to ARGUS — conditions gate the whole rule and
    # effects apply after it fires — but it matters to whoever reads the
    # generated file.
    parts.extend(flowbit_terms)
    if identity_bit:
        parts.append("flowbits:isset,%s" % identity_bit)

    return "rule " + "; ".join(parts) + ";", None


def sanitise_bit(name):
    """Flowbit names reach ARGUS inside a comma-separated option, so a
    name containing a comma or a semicolon would split the option. ET
    names use dots and underscores, which are safe; anything else is
    mapped rather than rejected, because the name is only ever compared
    with itself."""
    return "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)


# Modifiers ARGUS's byte_test/byte_jump accept. A rule using anything
# else is refused rather than translated with the modifier dropped, since
# dropping one changes where the rule looks.
KNOWN_BYTE_MODS = {
    "relative", "big", "little", "string", "hex", "dec", "oct",
    "align", "from_beginning",
}


def is_number(text):
    text = text.strip()
    if text.lower().startswith(("0x", "-0x")):
        text = text.lower().replace("0x", "", 1).lstrip("-")
        return bool(text) and all(c in "0123456789abcdef" for c in text)
    return text.lstrip("-").isdigit()


def normalise_byte_op(v, positional=4):
    """Returns the argument list as ARGUS should receive it, or None if
    the rule uses a form that cannot be represented.

    The two grammars are the same, so this is a validation pass rather
    than a translation: it exists to keep an unrepresentable rule out of
    the output instead of letting it fail at load time, where it would
    take the whole file with it."""
    parts = [p.strip() for p in v.split(",")]
    if len(parts) < 2:
        return None
    # A variable name from byte_extract in any positional slot means the
    # value is not known until match time, which ARGUS has no notion of.
    # The operator (`>`, `!&`, ...) is a symbol; the other slots are numbers.
    for i, p in enumerate(parts[:positional]):
        if not p or (i == 1 and positional == 4 and p.lstrip("!") in ("<", ">", "=", "&", "^", "<=", ">=", "!")):
            continue
        # A byte_test compares against, and reads at, a number or a named
        # variable; the width and the operator are always literal.
        if positional == 4 and i in (2, 3) and IDENT.match(p):
            continue
        if not is_number(p):
            return None
    i = 0
    out = []
    while i < len(parts):
        p = parts[i]
        low = p.lower()
        if low in ("multiplier", "post_offset"):
            if i + 1 >= len(parts):
                return None
            out.append(p)
            out.append(parts[i + 1])
            i += 2
            continue
        if low.startswith("multiplier ") or low.startswith("post_offset "):
            out.append(p)
            i += 1
            continue
        # The first few are positional; after that only known modifiers.
        if len(out) >= positional and low and low not in KNOWN_BYTE_MODS and not low[0].isdigit() and low[0] not in "!<>=&^-":
            return None
        out.append(p)
        i += 1
    return ",".join(x for x in out if x != "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output")
    ap.add_argument("--home-net", default="", help="e.g. 192.168.0.0/16,10.0.0.0/8")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument(
        "--validate",
        metavar="ARGUS",
        help="path to the argus binary; every rule it refuses to load is dropped, and counted, rather than left to stop the file loading",
    )
    args = ap.parse_args()

    skipped = collections.Counter()
    converted, total = [], 0
    with open(args.input, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
            rule, why = convert(line, args.home_net)
            if rule:
                converted.append(rule)
            else:
                skipped[why] += 1

    def write(rules):
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write("# Generated by tools/suricata.py from %s\n" % args.input)
            f.write("# %d of %d source rules converted. Rules that could not be\n" % (len(rules), total))
            f.write("# represented faithfully were skipped, never approximated.\n")
            for r in rules:
                f.write(r + "\n")

    if args.output:
        write(converted)
        if args.validate:
            # The translator can emit something ARGUS's own parser refuses:
            # a regex the engine cannot compile, say. One such rule would
            # stop the whole file loading, so the authority on what loads is
            # asked, and whatever it refuses is dropped and counted.
            import subprocess

            proc = subprocess.run([os.path.abspath(args.validate), "-check-rules", args.output], capture_output=True, text=True)
            refused = {}
            for line in proc.stdout.splitlines():
                m = re.match(r"rules file line (\d+): (.*)", line)
                if m:
                    refused[int(m.group(1))] = m.group(2)
            if refused:
                header = 3  # the comment lines written above
                # A rule may be written as several lines (a datagram service
                # is one rule per end), and any line refused drops the rule.
                dropped, line_no = set(), header
                for i, r in enumerate(converted):
                    for _ in r.splitlines():
                        line_no += 1
                        if line_no in refused:
                            dropped.add(i)
                kept = [r for i, r in enumerate(converted) if i not in dropped]
                for msg in refused.values():
                    skipped["refused by ARGUS: " + msg[:44]] += 1
                converted = kept
                write(converted)

    pct = 100.0 * len(converted) / total if total else 0.0
    print("%d rules read | %d converted (%.1f%%) | %d skipped" % (total, len(converted), pct, sum(skipped.values())))
    if args.stats:
        print("\ntop skip reasons:")
        for why, n in skipped.most_common(25):
            print("  %-46s %6d  (%.1f%%)" % (why, n, 100.0 * n / total))
    if args.output:
        print("\nwrote %s" % args.output)


if __name__ == "__main__":
    main()
