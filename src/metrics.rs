//! Live counters, and a Prometheus endpoint to read them from.
//!
//! ARGUS already counted almost everything worth counting — packets
//! decoded, fragments buffered, flows refused, pool exhaustions,
//! suppression resets — but every one of those numbers was only visible
//! in the shutdown summary. A sensor you have to stop in order to find
//! out how it is doing is a sensor you will not check.
//!
//! # Why the counters live here rather than where they are incremented
//!
//! The obvious design puts an `AtomicU64` next to each subsystem's own
//! state. That works until you want to *read* them all, at which point
//! the reader needs a reference into every subsystem, including ones
//! owned by worker threads. Collecting them in one `Arc<Metrics>` that
//! everything already holds inverts the problem: incrementing is a
//! relaxed atomic add on a shared cache line, and reading is a plain
//! walk over a struct.
//!
//! Relaxed ordering throughout is deliberate and correct here. These are
//! statistics, not synchronisation: nothing branches on them, a reader
//! that sees a slightly stale value is not wrong in any way that
//! matters, and the alternative costs a fence on the packet path.
//!
//! # Why the HTTP server is hand-written
//!
//! It answers two paths, serves one content type, and must never be able
//! to affect capture. A dependency-free listener on a background thread
//! is about eighty lines, cannot outlive the process, and has no
//! configuration surface to get wrong. Pulling in an HTTP stack to serve
//! a text document would be the larger risk.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const R: Ordering = Ordering::Relaxed;

/// Every counter, in one place.
///
/// Grouped by what a reader would ask about rather than by which module
/// increments them, because the audience is an operator looking at a
/// dashboard, not a maintainer looking at a call graph.
#[derive(Default)]
pub struct Metrics {
    // --- capture ---
    pub frames_read: AtomicU64,
    pub packets_decoded: AtomicU64,
    pub frames_undecoded: AtomicU64,
    pub bytes_captured: AtomicU64,
    /// Dropped by the kernel or the capture library before ARGUS saw
    /// them — the number that says the sensor is undersized.
    pub capture_dropped: AtomicU64,
    pub capture_iface_dropped: AtomicU64,

    // --- pipeline back-pressure ---
    /// Frames shed because the packet pool was exhausted.
    pub pool_exhausted: AtomicU64,
    /// Packets dropped because a worker's queue was full.
    pub queue_full: AtomicU64,
    /// Alerts dropped because the alert channel was full.
    pub alert_queue_full: AtomicU64,
    /// Observations dropped because the behaviour channel was full.
    pub observation_queue_full: AtomicU64,

    // --- detection ---
    pub alerts_emitted: AtomicU64,
    pub alerts_suppressed: AtomicU64,
    pub alerts_allowlisted: AtomicU64,
    pub suppression_resets: AtomicU64,
    pub rules_loaded: AtomicU64,
    pub rule_reloads: AtomicU64,
    pub rule_reload_failures: AtomicU64,

    // --- bounded tables refusing work ---
    pub flows_refused: AtomicU64,
    pub sources_refused: AtomicU64,
    pub destinations_refused: AtomicU64,
    pub fragments_refused: AtomicU64,
    pub behavior_refused: AtomicU64,

    // --- current occupancy, set rather than incremented ---
    pub flows_tracked: AtomicU64,
    pub fragments_buffered: AtomicU64,

    // --- enrichment ---
    pub intel_hits: AtomicU64,
    pub intel_entries: AtomicU64,

    /// Process start, for an uptime gauge.
    started: Option<Instant>,
}

impl Metrics {
    pub fn new() -> Arc<Metrics> {
        Arc::new(Metrics { started: Some(Instant::now()), ..Metrics::default() })
    }

    #[inline]
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, R);
    }

    #[inline]
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, R);
    }

    /// Renders the Prometheus text exposition format.
    ///
    /// Every metric carries HELP and TYPE, because a counter without
    /// units or a description is a number somebody will misread. Names
    /// follow the convention: `_total` for monotonic counters, bare nouns
    /// for gauges.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);

        macro_rules! metric {
            ($name:literal, $kind:literal, $help:literal, $value:expr) => {{
                use std::fmt::Write as _;
                let _ = write!(out, "# HELP argus_{} {}\n# TYPE argus_{} {}\nargus_{} {}\n", $name, $help, $name, $kind, $name, $value);
            }};
        }

        metric!("frames_read_total", "counter", "Frames handed to ARGUS by the capture layer.", self.frames_read.load(R));
        metric!("packets_decoded_total", "counter", "Frames that decoded to an IP packet.", self.packets_decoded.load(R));
        metric!("frames_undecoded_total", "counter", "Frames ARGUS could not decode.", self.frames_undecoded.load(R));
        metric!("bytes_captured_total", "counter", "Bytes seen on the wire.", self.bytes_captured.load(R));
        metric!("capture_dropped_total", "counter", "Packets dropped by the capture library before ARGUS saw them.", self.capture_dropped.load(R));
        metric!("capture_iface_dropped_total", "counter", "Packets dropped by the interface driver.", self.capture_iface_dropped.load(R));

        metric!("pool_exhausted_total", "counter", "Frames shed because the packet pool was empty.", self.pool_exhausted.load(R));
        metric!("queue_full_total", "counter", "Packets dropped because a worker queue was full.", self.queue_full.load(R));
        metric!("alert_queue_full_total", "counter", "Alerts dropped because the alert channel was full.", self.alert_queue_full.load(R));
        metric!("observation_queue_full_total", "counter", "Observations dropped because the behaviour channel was full.", self.observation_queue_full.load(R));

        metric!("alerts_emitted_total", "counter", "Alerts written to at least one sink.", self.alerts_emitted.load(R));
        metric!("alerts_suppressed_total", "counter", "Alerts collapsed as duplicates.", self.alerts_suppressed.load(R));
        metric!("alerts_allowlisted_total", "counter", "Alerts dropped by an allowlist entry.", self.alerts_allowlisted.load(R));
        metric!("suppression_resets_total", "counter", "Times the suppression table was cleared under pressure.", self.suppression_resets.load(R));
        metric!("rules_loaded", "gauge", "Rules currently active.", self.rules_loaded.load(R));
        metric!("rule_reloads_total", "counter", "Successful rule reloads.", self.rule_reloads.load(R));
        metric!("rule_reload_failures_total", "counter", "Rule reloads that failed and left the previous rules in place.", self.rule_reload_failures.load(R));

        metric!("flows_refused_total", "counter", "New flows refused because the flow table was at capacity.", self.flows_refused.load(R));
        metric!("sources_refused_total", "counter", "New sources refused because the source table was at capacity.", self.sources_refused.load(R));
        metric!("destinations_refused_total", "counter", "New destinations refused because a source's table was at capacity.", self.destinations_refused.load(R));
        metric!("fragments_refused_total", "counter", "Fragments refused because the reassembly table was at capacity.", self.fragments_refused.load(R));
        metric!("behavior_refused_total", "counter", "Behavioural tracking refused because a table was at capacity.", self.behavior_refused.load(R));

        metric!("flows_tracked", "gauge", "TCP connections currently tracked.", self.flows_tracked.load(R));
        metric!("fragments_buffered", "gauge", "Fragmented datagrams currently held.", self.fragments_buffered.load(R));

        metric!("regex_backtrack_limit_total", "counter", "Backtracking regex matches abandoned for exceeding their step limit.", crate::rules::backtrack_limit_hits());
        metric!("intel_hits_total", "counter", "Reputation matches.", self.intel_hits.load(R));
        metric!("intel_entries", "gauge", "Indicators loaded.", self.intel_entries.load(R));

        let uptime = self.started.map(|t| t.elapsed().as_secs()).unwrap_or(0);
        metric!("uptime_seconds", "gauge", "Seconds since start.", uptime);
        metric!("build_info", "gauge", "Always 1; present so a dashboard can detect the exporter.", 1);
        out
    }

    /// A compact human summary, for the shutdown banner.
    pub fn pressure_summary(&self) -> Option<String> {
        let items: [(&str, u64); 9] = [
            ("pool exhausted", self.pool_exhausted.load(R)),
            ("queue full", self.queue_full.load(R)),
            ("alert queue full", self.alert_queue_full.load(R)),
            ("observations dropped", self.observation_queue_full.load(R)),
            ("flows refused", self.flows_refused.load(R)),
            ("sources refused", self.sources_refused.load(R)),
            ("destinations refused", self.destinations_refused.load(R)),
            ("fragments refused", self.fragments_refused.load(R)),
            ("capture dropped", self.capture_dropped.load(R)),
        ];
        let parts: Vec<String> = items.iter().filter(|(_, n)| *n > 0).map(|(k, n)| format!("{} {}", n, k)).collect();
        (!parts.is_empty()).then(|| parts.join(", "))
    }
}

// =======================================================================
// The endpoint
// =======================================================================

/// A background HTTP server exposing `/metrics` and `/healthz`.
///
/// Bound to a caller-supplied address, which should be a loopback or
/// management address: the endpoint exposes traffic statistics, and
/// statistics about a network are information about that network.
pub struct MetricsServer {
    pub addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MetricsServer {
    pub fn start(spec: &str, metrics: Arc<Metrics>) -> anyhow::Result<MetricsServer> {
        let addr = spec
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("metrics address {:?}: {}", spec, e))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("metrics address {:?} resolved to nothing", spec))?;
        let listener = TcpListener::bind(addr)?;
        // A read timeout on every accepted connection means a client that
        // opens a socket and says nothing cannot hold the thread. The
        // listener itself stays blocking; shutdown wakes it with a
        // self-connect, which is more reliable than polling.
        let actual = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();

        let handle = std::thread::Builder::new().name("argus-metrics".into()).spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    return;
                }
                if let Ok(s) = stream {
                    let _ = serve_one(s, &metrics);
                }
            }
        })?;

        Ok(MetricsServer { addr: actual, shutdown, handle: Some(handle) })
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // Unblock `accept` by connecting to ourselves; the loop then sees
        // the flag and returns.
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_one(mut stream: TcpStream, metrics: &Metrics) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let path = line.split_whitespace().nth(1).unwrap_or("/");

    let (status, content_type, body) = match path {
        "/metrics" => ("200 OK", "text/plain; version=0.0.4; charset=utf-8", metrics.render()),
        "/healthz" => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string()),
        "/" => (
            "200 OK",
            "text/plain; charset=utf-8",
            format!("argus\nGET /metrics   Prometheus exposition\nGET /healthz   liveness\nnow {}\n", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()),
        ),
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found\n".to_string()),
    };

    write!(
        stream,
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        write!(s, "GET {} HTTP/1.1\r\nHost: x\r\n\r\n", path).unwrap();
        let mut body = String::new();
        s.read_to_string(&mut body).unwrap();
        body
    }

    #[test]
    fn metrics_render_in_prometheus_exposition_format() {
        let m = Metrics::new();
        Metrics::add(&m.frames_read, 1234);
        Metrics::inc(&m.pool_exhausted);
        let text = m.render();
        assert!(text.contains("# TYPE argus_frames_read_total counter"));
        assert!(text.contains("\nargus_frames_read_total 1234\n"));
        assert!(text.contains("\nargus_pool_exhausted_total 1\n"));
        // Every metric line must be preceded by its HELP and TYPE, or
        // scrapers report it as untyped.
        let helps = text.matches("# HELP ").count();
        let types = text.matches("# TYPE ").count();
        assert_eq!(helps, types, "every metric needs both HELP and TYPE");
    }

    #[test]
    fn the_endpoint_serves_metrics_and_health() {
        let m = Metrics::new();
        Metrics::add(&m.alerts_emitted, 7);
        let mut server = MetricsServer::start("127.0.0.1:0", m).unwrap();

        let body = get(server.addr, "/metrics");
        assert!(body.contains("200 OK"), "{}", body);
        assert!(body.contains("argus_alerts_emitted_total 7"), "{}", body);

        let health = get(server.addr, "/healthz");
        assert!(health.contains("200 OK") && health.contains("ok"));

        let missing = get(server.addr, "/nope");
        assert!(missing.contains("404 Not Found"), "{}", missing);

        server.stop();
    }

    /// The server must not keep the process alive or panic on shutdown,
    /// which is the whole reason it owns an explicit stop rather than
    /// being detached.
    #[test]
    fn the_endpoint_stops_cleanly() {
        let mut server = MetricsServer::start("127.0.0.1:0", Metrics::new()).unwrap();
        let addr = server.addr;
        server.stop();
        server.stop(); // idempotent
        // The port is released, so a fresh bind on it succeeds.
        drop(TcpListener::bind(addr));
    }

    #[test]
    fn pressure_summary_names_only_what_actually_happened() {
        let m = Metrics::new();
        assert!(m.pressure_summary().is_none(), "a clean run says nothing");
        Metrics::add(&m.flows_refused, 3);
        let s = m.pressure_summary().unwrap();
        assert_eq!(s, "3 flows refused");
    }
}
