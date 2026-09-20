//! Alert output: formats, destinations, rotation.
//!
//! Detection produces an [`Alert`]; everything between that and a line
//! arriving somewhere useful lives here. The split matters because the
//! two halves have genuinely different failure modes — a detector that
//! is wrong reports the wrong thing, whereas a sink that is wrong loses
//! things silently — and because "which format" and "which destination"
//! are independent choices that were previously one `bool`.
//!
//! # Rendering once per format, not once per sink
//!
//! A deployment commonly wants human-readable text on stdout *and*
//! EVE-JSON in a file *and* RFC5424 to a syslog collector. Those are
//! three destinations but only three renderings at most, and usually
//! fewer, since several sinks often share a format. [`Output`] renders
//! each distinct format at most once per alert into a reusable buffer
//! and hands the same `&str` to every sink that wants it.
//!
//! That reuse is the reason the formatters here write into a
//! `&mut String` rather than returning one. At alert volumes this is
//! not a hot path in the way packet parsing is, but an alert storm is
//! exactly when the process is already under load, and a formatter that
//! allocates three times per alert is an allocator spike that coincides
//! with the thing it is reporting on.
//!
//! # Rotation
//!
//! Two mechanisms, because the platforms differ. On Unix, `logrotate`
//! renames the file and signals the process, which must then reopen the
//! path — [`Output::reopen`], wired to `SIGHUP` in `main`. Everywhere,
//! including Windows where no such convention exists, [`FileSink`] can
//! rotate itself by size. Both can be enabled at once; they do not
//! conflict, because reopening a path is idempotent.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::engine::{Alert, Severity};
use crate::intel::Tags;

// =======================================================================
// Time formatting
// =======================================================================

/// Calendar breakdown of a Unix timestamp, UTC.
///
/// Hand-rolled rather than pulled from a date crate. EVE-JSON and
/// RFC5424 both require a real calendar timestamp, which is the only
/// thing ARGUS needs a calendar for; a dependency that exists to format
/// one field in one output mode is a poor trade, and the civil-date
/// algorithm is short and exactly testable.
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
    pub micros: u32,
}

impl Civil {
    /// Howard Hinnant's `civil_from_days`, which is exact for the whole
    /// proleptic Gregorian range and needs no table.
    pub fn from_unix(secs: i64, micros: u32) -> Civil {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        Civil {
            year: if m <= 2 { y + 1 } else { y },
            month: m as u32,
            day: d as u32,
            hour: (rem / 3600) as u32,
            min: ((rem % 3600) / 60) as u32,
            sec: (rem % 60) as u32,
            micros,
        }
    }

    pub fn from_system(t: SystemTime) -> Civil {
        let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
        Civil::from_unix(d.as_secs() as i64, d.subsec_micros())
    }

    /// `2026-09-18T14:21:07.123456+0000` — the shape Suricata's EVE
    /// output uses, which is what consumers of EVE expect to parse.
    pub fn write_eve(&self, out: &mut String) {
        use std::fmt::Write as _;
        let _ = write!(
            out,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+0000",
            self.year, self.month, self.day, self.hour, self.min, self.sec, self.micros
        );
    }

    /// RFC3339 with a `Z` zone, as RFC5424 syslog requires.
    pub fn write_rfc3339(&self, out: &mut String) {
        use std::fmt::Write as _;
        let _ = write!(
            out,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            self.year, self.month, self.day, self.hour, self.min, self.sec, self.micros
        );
    }
}

// =======================================================================
// Formats
// =======================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// Fixed-column text, for a human watching a terminal.
    Text,
    /// One JSON object per line — ARGUS's own field names.
    Json,
    /// Suricata-compatible EVE-JSON, for a SIEM that already ingests it.
    Eve,
}

impl Format {
    pub fn parse(s: &str) -> anyhow::Result<Format> {
        match s.to_ascii_lowercase().as_str() {
            "text" | "plain" => Ok(Format::Text),
            "json" | "ndjson" => Ok(Format::Json),
            "eve" | "eve-json" | "evejson" => Ok(Format::Eve),
            other => anyhow::bail!("unknown output format {:?} (text, json, eve)", other),
        }
    }

    fn index(self) -> usize {
        match self {
            Format::Text => 0,
            Format::Json => 1,
            Format::Eve => 2,
        }
    }
}

/// Escapes into an existing buffer, so a render does not allocate.
pub fn json_escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// EVE severity runs 1 (most severe) to 3, the inverse of the natural
/// reading, because that is what Suricata emits and what downstream
/// rules key on.
fn eve_severity(s: Severity) -> u8 {
    match s {
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

/// Renders one alert to a fresh `String`.
///
/// The writer path never uses this — it renders into reusable buffers —
/// but a caller holding a single alert, and every test that asserts on
/// output shape, wants exactly this.
pub fn render_alert(alert: &Alert, tags: &Tags, format: Format) -> String {
    let mut s = String::new();
    render(alert, tags, format, &mut s);
    s
}

fn render(alert: &Alert, tags: &Tags, format: Format, out: &mut String) {
    use std::fmt::Write as _;
    out.clear();
    match format {
        Format::Text => {
            let t = alert.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
            let secs_of_day = t.as_secs() % 86400;
            let _ = write!(
                out,
                "[{:02}:{:02}:{:02}] {:<6} {:<16} src={:<15} dst={:<15} proto={:<4} port={:<5} {}",
                secs_of_day / 3600,
                (secs_of_day % 3600) / 60,
                secs_of_day % 60,
                alert.severity.as_str(),
                alert.category,
                alert.src.to_string(),
                alert.dst.to_string(),
                alert.proto,
                alert.port,
                alert.message
            );
            tags.write_text(out);
        }
        Format::Json => {
            let _ = write!(out, "{{\"timestamp\":{},\"severity\":\"", alert.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());
            out.push_str(alert.severity.as_str());
            out.push_str("\",\"category\":\"");
            json_escape_into(alert.category, out);
            let _ = write!(out, "\",\"src\":\"{}\",\"dst\":\"{}\",\"proto\":\"{}\",\"port\":{},\"sid\":{},\"message\":\"", alert.src, alert.dst, alert.proto, alert.port, alert.sid);
            json_escape_into(&alert.message, out);
            out.push('"');
            tags.write_json(out);
            out.push('}');
        }
        Format::Eve => {
            out.push_str("{\"timestamp\":\"");
            Civil::from_system(alert.timestamp).write_eve(out);
            let _ = write!(
                out,
                "\",\"event_type\":\"alert\",\"src_ip\":\"{}\",\"dest_ip\":\"{}\",\"dest_port\":{},\"proto\":\"{}\",\"alert\":{{\"signature_id\":{},\"rev\":1,\"signature\":\"",
                alert.src, alert.dst, alert.port, alert.proto, alert.sid
            );
            json_escape_into(&alert.message, out);
            out.push_str("\",\"category\":\"");
            json_escape_into(alert.category, out);
            let _ = write!(out, "\",\"severity\":{}}}", eve_severity(alert.severity));
            tags.write_json(out);
            out.push('}');
        }
    }
}

// =======================================================================
// Sinks
// =======================================================================

/// One destination for rendered alert lines.
///
/// `emit` takes an already-rendered line so that several sinks sharing a
/// format share one rendering. Errors are reported rather than
/// propagated to the caller: a failing sink must not take down detection,
/// and the count is surfaced in the shutdown summary so a silently dead
/// destination is visible.
pub trait Sink: Send {
    fn format(&self) -> Format;
    fn emit(&mut self, line: &str) -> io::Result<()>;
    /// Close and reopen the underlying destination, for `logrotate`.
    fn reopen(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn describe(&self) -> String;
}

/// A sink wrapping any `Write`, used for stdout and in tests.
pub struct WriterSink {
    w: Box<dyn Write + Send>,
    format: Format,
    name: &'static str,
}

impl WriterSink {
    pub fn new(w: Box<dyn Write + Send>, format: Format, name: &'static str) -> WriterSink {
        WriterSink { w, format, name }
    }

    pub fn stdout(format: Format) -> WriterSink {
        WriterSink::new(Box::new(io::stdout()), format, "stdout")
    }
}

impl Sink for WriterSink {
    fn format(&self) -> Format {
        self.format
    }
    fn emit(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.w, "{}", line)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
    fn describe(&self) -> String {
        self.name.to_string()
    }
}

/// A file, optionally self-rotating by size.
///
/// Buffered, because an alert storm writing unbuffered is one syscall
/// per alert, and flushed on every rotation and at shutdown so a crash
/// loses at most the current buffer.
pub struct FileSink {
    path: PathBuf,
    w: BufWriter<File>,
    format: Format,
    /// Bytes written to the current file. Tracked rather than `stat`ed:
    /// asking the filesystem per alert is a syscall for a number we
    /// already know.
    written: u64,
    max_size: u64,
    keep: usize,
}

impl FileSink {
    pub fn open(path: &Path, format: Format, max_size: u64, keep: usize) -> io::Result<FileSink> {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        let written = f.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(FileSink { path: path.to_path_buf(), w: BufWriter::new(f), format, written, max_size, keep })
    }

    /// `x.log` -> `x.log.1`, `x.log.1` -> `x.log.2`, dropping the oldest.
    ///
    /// Renaming oldest-first is what makes this safe to interrupt: every
    /// intermediate state is a valid set of logs with at most one gap,
    /// rather than a state where two generations share a name.
    fn rotate(&mut self) -> io::Result<()> {
        self.w.flush()?;
        for i in (1..=self.keep).rev() {
            let from = if i == 1 { self.path.clone() } else { numbered(&self.path, i - 1) };
            let to = numbered(&self.path, i);
            if from.exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }
        let f = OpenOptions::new().create(true).truncate(true).write(true).open(&self.path)?;
        self.w = BufWriter::new(f);
        self.written = 0;
        Ok(())
    }
}

fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".{}", n));
    PathBuf::from(s)
}

impl Sink for FileSink {
    fn format(&self) -> Format {
        self.format
    }

    fn emit(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.w, "{}", line)?;
        self.written += line.len() as u64 + 1;
        if self.max_size > 0 && self.written >= self.max_size {
            self.rotate()?;
        }
        Ok(())
    }

    fn reopen(&mut self) -> io::Result<()> {
        self.w.flush()?;
        let f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        self.written = f.metadata().map(|m| m.len()).unwrap_or(0);
        self.w = BufWriter::new(f);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

/// RFC5424 syslog over UDP or TCP.
///
/// UDP is fire-and-forget, which suits a sensor: a collector that goes
/// away must not block detection. TCP reconnects lazily on the next
/// alert after a failure rather than retrying in a loop, for the same
/// reason — the alert path is not the place to wait on a network.
pub struct SyslogSink {
    transport: SyslogTransport,
    format: Format,
    facility: u8,
    hostname: String,
    target: String,
    /// Reused across alerts; the framing wraps the rendered line.
    frame: String,
}

enum SyslogTransport {
    Udp { sock: UdpSocket, addr: std::net::SocketAddr },
    Tcp { stream: Option<TcpStream>, addr: std::net::SocketAddr },
}

impl SyslogSink {
    /// `udp://host:port` or `tcp://host:port`; a bare `host:port` is UDP.
    pub fn connect(spec: &str, format: Format, facility: u8) -> anyhow::Result<SyslogSink> {
        let (is_tcp, rest) = match spec.split_once("://") {
            Some(("tcp", r)) => (true, r),
            Some(("udp", r)) => (false, r),
            Some((other, _)) => anyhow::bail!("unknown syslog transport {:?} (tcp, udp)", other),
            None => (false, spec),
        };
        let addr = rest
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("syslog target {:?}: {}", rest, e))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("syslog target {:?} resolved to nothing", rest))?;

        let transport = if is_tcp {
            SyslogTransport::Tcp { stream: TcpStream::connect(addr).ok(), addr }
        } else {
            let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            SyslogTransport::Udp { sock: UdpSocket::bind(bind)?, addr }
        };

        Ok(SyslogSink {
            transport,
            format,
            facility,
            hostname: hostname(),
            target: spec.to_string(),
            frame: String::with_capacity(512),
        })
    }
}

/// Best-effort local hostname, `-` when unavailable — which is exactly
/// what RFC5424 says to send for an unknown field.
fn hostname() -> String {
    for var in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(h) = std::env::var(var) {
            if !h.is_empty() {
                return h;
            }
        }
    }
    "-".to_string()
}

impl Sink for SyslogSink {
    fn format(&self) -> Format {
        self.format
    }

    fn emit(&mut self, line: &str) -> io::Result<()> {
        use std::fmt::Write as _;
        // Severity is carried in the rendered line already; PRI uses
        // "warning" uniformly so a collector's own severity filter
        // doesn't silently drop alerts it should have kept. Consumers
        // that care read the field.
        let pri = (self.facility as u16) * 8 + 4;
        self.frame.clear();
        let _ = write!(self.frame, "<{}>1 ", pri);
        Civil::from_system(SystemTime::now()).write_rfc3339(&mut self.frame);
        let _ = write!(self.frame, " {} argus {} - - {}", self.hostname, std::process::id(), line);

        match &mut self.transport {
            SyslogTransport::Udp { sock, addr } => {
                sock.send_to(self.frame.as_bytes(), *addr)?;
            }
            SyslogTransport::Tcp { stream, addr } => {
                if stream.is_none() {
                    *stream = TcpStream::connect(*addr).ok();
                }
                let Some(s) = stream.as_mut() else {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "syslog collector unreachable"));
                };
                // RFC6587 octet counting: the only framing that survives
                // a message containing a newline, which JSON payloads do
                // not but text messages might.
                let res = write!(s, "{} {}", self.frame.len(), self.frame);
                if res.is_err() {
                    *stream = None;
                }
                res?;
            }
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("syslog {}", self.target)
    }
}

// =======================================================================
// Output: the set of sinks
// =======================================================================

/// Every alert destination, plus the render cache they share.
pub struct Output {
    sinks: Vec<Box<dyn Sink>>,
    /// One reusable buffer per format, and a validity mask saying which
    /// hold a rendering of the alert currently being written.
    buffers: [String; 3],
    valid: u8,
    /// Sink write failures, by sink index. A destination that has gone
    /// away is reported once at shutdown rather than per alert, which
    /// would turn one broken collector into an unbounded log of its own.
    errors: Vec<u64>,
}

impl Output {
    pub fn new(sinks: Vec<Box<dyn Sink>>) -> Output {
        let errors = vec![0; sinks.len()];
        Output { sinks, buffers: [String::new(), String::new(), String::new()], valid: 0, errors }
    }

    /// A single writer in a single format — the shape tests want.
    pub fn single(w: Box<dyn Write + Send>, format: Format) -> Output {
        Output::new(vec![Box::new(WriterSink::new(w, format, "test"))])
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Renders once per distinct format and emits to every sink.
    pub fn write(&mut self, alert: &Alert, tags: &Tags) {
        self.valid = 0;
        for i in 0..self.sinks.len() {
            let f = self.sinks[i].format();
            let bit = 1u8 << f.index();
            if self.valid & bit == 0 {
                render(alert, tags, f, &mut self.buffers[f.index()]);
                self.valid |= bit;
            }
            // Split the borrow: the buffer and the sink live in different
            // fields, so this is the borrow checker's problem rather than
            // a real aliasing one.
            let (buffers, sinks) = (&self.buffers, &mut self.sinks);
            if sinks[i].emit(&buffers[f.index()]).is_err() {
                self.errors[i] += 1;
            }
        }
    }

    /// A pre-rendered line straight through, for the suppression notices
    /// that are not themselves alerts. Text sinks only — a structured
    /// consumer wants alerts, not commentary.
    pub fn write_note(&mut self, note: &str) {
        for (i, s) in self.sinks.iter_mut().enumerate() {
            if s.format() == Format::Text && s.emit(note).is_err() {
                self.errors[i] += 1;
            }
        }
    }

    pub fn reopen(&mut self) {
        for s in self.sinks.iter_mut() {
            let _ = s.reopen();
        }
    }

    pub fn flush(&mut self) {
        for s in self.sinks.iter_mut() {
            let _ = s.flush();
        }
    }

    /// `(description, failures)` for each sink, for the shutdown summary.
    pub fn failures(&self) -> Vec<(String, u64)> {
        self.sinks.iter().zip(self.errors.iter()).filter(|(_, &n)| n > 0).map(|(s, &n)| (s.describe(), n)).collect()
    }

    pub fn describe_all(&self) -> Vec<String> {
        self.sinks.iter().map(|s| format!("{} ({:?})", s.describe(), s.format())).collect()
    }
}

/// How long a sink may hold buffered output before it is flushed even
/// though nothing new has arrived.
///
/// Without this a quiet sensor's last few alerts can sit in a `BufWriter`
/// indefinitely, which is precisely backwards: the quieter the link, the
/// more each alert matters and the longer it would be invisible.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Alert;
    use crate::packet::IpAddr;
    use std::sync::{Arc, Mutex};

    fn alert() -> Alert {
        Alert {
            timestamp: UNIX_EPOCH + Duration::from_secs(1_789_746_085),
            severity: Severity::Medium,
            category: "PORT_SCAN",
            src: IpAddr::V4([192, 168, 0, 112]),
            dst: IpAddr::V4([192, 168, 0, 1]),
            proto: "TCP",
            port: 21,
            message: "21 distinct TCP ports".to_string(),
            sid: 1000001,
        }
    }

    /// A sink that keeps what it was given, so a test can read it back.
    #[derive(Clone)]
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture(format: Format) -> (Output, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Output::single(Box::new(Shared(buf.clone())), format), buf)
    }

    fn text_of(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn civil_date_matches_known_timestamps() {
        // Epoch, a leap day, and a date past 2038 to prove nothing is
        // silently 32-bit.
        let c = Civil::from_unix(0, 0);
        assert_eq!((c.year, c.month, c.day, c.hour, c.min, c.sec), (1970, 1, 1, 0, 0, 0));
        let c = Civil::from_unix(1_709_164_800, 0); // 2024-02-29T00:00:00Z
        assert_eq!((c.year, c.month, c.day), (2024, 2, 29));
        let c = Civil::from_unix(4_102_444_800, 0); // 2100-01-01T00:00:00Z
        assert_eq!((c.year, c.month, c.day), (2100, 1, 1));
        let c = Civil::from_unix(1_789_746_085, 0);
        assert_eq!((c.year, c.month, c.day, c.hour, c.min, c.sec), (2026, 9, 18, 15, 41, 25));
    }

    #[test]
    fn eve_output_carries_the_fields_a_siem_keys_on() {
        let (mut out, buf) = capture(Format::Eve);
        out.write(&alert(), &Tags::none());
        let s = text_of(&buf);
        for needle in ["\"event_type\":\"alert\"", "\"src_ip\":\"192.168.0.112\"", "\"dest_port\":21", "\"signature_id\":1000001", "\"severity\":2"] {
            assert!(s.contains(needle), "EVE output missing {}: {}", needle, s);
        }
        assert!(s.starts_with("{\"timestamp\":\"2026-09-18T"), "EVE needs a calendar timestamp: {}", s);
    }

    /// EVE severity is inverted relative to the human reading, because
    /// Suricata's is and consumers key on the number.
    #[test]
    fn eve_severity_is_inverted_like_suricatas() {
        assert_eq!(eve_severity(Severity::High), 1);
        assert_eq!(eve_severity(Severity::Low), 3);
    }

    #[test]
    fn json_output_escapes_control_characters_in_messages() {
        let (mut out, buf) = capture(Format::Json);
        let mut a = alert();
        a.message = "quote\" backslash\\ newline\n".to_string();
        out.write(&a, &Tags::none());
        let s = text_of(&buf);
        assert!(s.contains(r#"quote\" backslash\\ newline\n"#), "{}", s);
        assert_eq!(s.lines().count(), 1, "an escaped newline must not split the record");
    }

    #[test]
    fn one_alert_renders_once_per_format_not_once_per_sink() {
        // Three sinks, two of them sharing a format. Each must receive a
        // line, and the shared format is rendered once.
        let a = Arc::new(Mutex::new(Vec::new()));
        let b = Arc::new(Mutex::new(Vec::new()));
        let c = Arc::new(Mutex::new(Vec::new()));
        let mut out = Output::new(vec![
            Box::new(WriterSink::new(Box::new(Shared(a.clone())), Format::Json, "a")),
            Box::new(WriterSink::new(Box::new(Shared(b.clone())), Format::Json, "b")),
            Box::new(WriterSink::new(Box::new(Shared(c.clone())), Format::Text, "c")),
        ]);
        out.write(&alert(), &Tags::none());
        assert_eq!(text_of(&a), text_of(&b), "sinks sharing a format get identical lines");
        assert!(text_of(&a).starts_with('{'));
        assert!(text_of(&c).starts_with('['), "the text sink gets text: {}", text_of(&c));
    }

    #[test]
    fn a_file_sink_rotates_by_size_and_keeps_a_bounded_number_of_generations() {
        let dir = std::env::temp_dir().join(format!("argus-rot-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("alerts.log");
        let _ = std::fs::remove_file(&path);
        {
            let mut sink = FileSink::open(&path, Format::Json, 200, 2).unwrap();
            for _ in 0..40 {
                sink.emit("0123456789012345678901234567890123456789").unwrap();
            }
            sink.flush().unwrap();
        }
        assert!(path.exists(), "the live log must exist");
        assert!(numbered(&path, 1).exists(), "one generation back must exist");
        assert!(!numbered(&path, 3).exists(), "keep=2 must not leave a third generation");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `logrotate` renames the file and signals; reopening must land on
    /// the path, not on the renamed inode.
    #[test]
    fn reopening_follows_the_path_after_an_external_rename() {
        let dir = std::env::temp_dir().join(format!("argus-reopen-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("alerts.log");
        let _ = std::fs::remove_file(&path);

        let mut sink = FileSink::open(&path, Format::Text, 0, 0).unwrap();
        sink.emit("before").unwrap();
        sink.flush().unwrap();
        std::fs::rename(&path, dir.join("alerts.log.old")).unwrap();
        sink.reopen().unwrap();
        sink.emit("after").unwrap();
        sink.flush().unwrap();

        let live = std::fs::read_to_string(&path).unwrap();
        assert!(live.contains("after") && !live.contains("before"), "the reopened path holds only what came after: {:?}", live);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_names_round_trip() {
        for (s, f) in [("text", Format::Text), ("json", Format::Json), ("eve", Format::Eve)] {
            assert_eq!(Format::parse(s).unwrap(), f);
        }
        assert!(Format::parse("xml").is_err());
    }
}
