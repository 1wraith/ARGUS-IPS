//! Plain std::time micro-benchmarks — no extra crates, so this always
//! builds regardless of toolchain version. Run with:
//!   cargo run --release --example bench

use argus::engine::{AnomalyConfig, AnomalyEngine, Buffer, Direction, FlowTable, SignatureEngine};
use argus::packet::{parse_ethernet_frame, Packet, TCP_ACK, TCP_PSH, TCP_SYN};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn build_tcp_frame(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut eth = vec![0u8; 14];
    eth[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let tcp_len = 20 + payload.len();
    let ip_len = 20 + tcp_len;
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[9] = 6;
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

fn bench(name: &str, min_dur: Duration, mut f: impl FnMut()) {
    for _ in 0..1000 {
        f();
    }
    let start = Instant::now();
    let mut iters: u64 = 0;
    while start.elapsed() < min_dur {
        for _ in 0..1000 {
            f();
        }
        iters += 1000;
    }
    let elapsed = start.elapsed();
    let ns_per_iter = elapsed.as_nanos() as f64 / iters as f64;
    println!("{name:<44} {iters:>12} iters   {ns_per_iter:>10.1} ns/iter");
}

fn main() {
    let dur = Duration::from_millis(500);
    let now = SystemTime::now();
    let now_sec = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

    // --- parse_ethernet_frame ---
    let frame = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, 80, 1, TCP_PSH, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let mut pkt = Packet::default();
    bench("parse_ethernet_frame", dur, || {
        parse_ethernet_frame(&frame, &mut pkt);
    });

    // --- literal (Aho-Corasick) matching against 51 loaded rules ---
    let mut rules_text = String::new();
    for i in 0..50 {
        rules_text.push_str(&format!("noise-{i}|payload|any|literal|pattern-does-not-appear-here-XYZ\n"));
    }
    rules_text.push_str("real|payload|any|literal|UNION SELECT\n");
    let rules_path = std::env::temp_dir().join("argus_bench_rules.txt");
    std::fs::write(&rules_path, &rules_text).unwrap();
    let sig_engine = SignatureEngine::load(None, Some(rules_path.to_str().unwrap())).unwrap();
    let payload = b"id=1 AND UNION SELECT password, credit_card FROM users WHERE id=1";
    // The allocating form, kept for comparison.
    bench("literal_match (51 rules, allocating)", dur, || {
        std::hint::black_box(sig_engine.check_buffer(&Packet::default(), Buffer::Payload, Direction::Any, payload));
    });
    // What the packet path actually does now: reuse the caller's buffers,
    // so matching costs no allocator traffic at all.
    let mut scratch = argus::engine::ScanScratch::default();
    let probe = Packet::default();
    bench("literal_match (51 rules, reused scratch)", dur, || {
        scratch.hits.clear();
        sig_engine.check_buffer_into(&probe, Buffer::Payload, Direction::Any, payload, &mut scratch.matcher, None, &mut scratch.hits);
        std::hint::black_box(scratch.hits.len());
    });
    std::fs::remove_file(&rules_path).ok();

    // --- regex matching, single rule ---
    let regex_rules_text = "path-trav|http.uri|any|regex|\\.\\./\\.\\./\n";
    let regex_path = std::env::temp_dir().join("argus_bench_regex_rules.txt");
    std::fs::write(&regex_path, regex_rules_text).unwrap();
    let regex_engine = SignatureEngine::load(None, Some(regex_path.to_str().unwrap())).unwrap();
    let uri = b"/files?path=../../etc/passwd&extra=stuff-to-pad-the-buffer-a-little";
    bench("regex_match (1 rule)", dur, || {
        std::hint::black_box(regex_engine.check_buffer(&Packet::default(), Buffer::HttpUri, Direction::ToServer, uri));
    });
    std::fs::remove_file(&regex_path).ok();

    // --- AnomalyEngine.observe, steady state (ACK traffic, not scan-shaped) ---
    let mut ae = AnomalyEngine::new(AnomalyConfig::default());
    let frame3 = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, 80, 1, TCP_ACK, &[]);
    let mut pkt3 = Packet::default();
    parse_ethernet_frame(&frame3, &mut pkt3);
    let mut alerts3 = Vec::new();
    bench("anomaly_observe (steady state)", dur, || {
        alerts3.clear();
        ae.observe(&pkt3, now, &mut alerts3);
    });

    // --- AnomalyEngine.observe cost vs. distinct ports already tracked (SYN traffic) ---
    // port_scan_limit is set high enough that no alert ever fires during
    // the growth loop below (so we're purely measuring tracking cost,
    // not alert-construction cost) — but deliberately NOT usize::MAX:
    // an earlier version of this benchmark used usize::MAX here, which
    // silently overflowed when the detection code computed
    // `port_scan_limit * 4` for its pruning threshold (release builds
    // wrap on overflow rather than panicking), producing a threshold
    // near usize::MAX that pruning could never cross — accidentally
    // disabling pruning entirely and reporting a flat ~36ns/iter that
    // didn't reflect real behavior under any config that actually prunes.
    println!();
    println!("anomaly_observe cost as distinct-ports-tracked grows (SYN-only, per-destination):");
    for &n in &[1_000u32, 10_000, 40_000] {
        let mut ae2 = AnomalyEngine::new(AnomalyConfig {
            window: Duration::from_secs(10),
            packet_rate_pps: u32::MAX,
            port_scan_limit: 1_000_000,
            // No alert gating, so the benchmark measures the observe
            // path itself rather than how often it declines to report.
            alert_min_interval_secs: 0,
            ..AnomalyConfig::default()
        });
        let mut pkt4 = Packet::default();
        let mut alerts4 = Vec::new();
        for port in 1..n as u16 {
            let f = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, port, 1, TCP_SYN, &[]);
            parse_ethernet_frame(&f, &mut pkt4);
            alerts4.clear();
            ae2.observe(&pkt4, now, &mut alerts4);
        }
        let f = build_tcp_frame([10, 0, 0, 5], [10, 0, 0, 1], 51234, n as u16, 1, TCP_SYN, &[]);
        parse_ethernet_frame(&f, &mut pkt4);
        bench(&format!("  after {n} distinct ports"), Duration::from_millis(200), || {
            alerts4.clear();
            ae2.observe(&pkt4, now, &mut alerts4);
        });
    }

    // --- FlowTable.observe: reassembly + HTTP parse + payload rule match ---
    println!();
    let flow_rules_text = "sqli|payload|any|literal|UNION SELECT\n";
    let flow_rules_path = std::env::temp_dir().join("argus_bench_flow_rules.txt");
    std::fs::write(&flow_rules_path, flow_rules_text).unwrap();
    let flow_sig = SignatureEngine::load(None, Some(flow_rules_path.to_str().unwrap())).unwrap();

    let client = [10, 0, 0, 5];
    let server = [10, 0, 0, 1];
    let http_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\n\r\n";

    bench("flow_observe (SYN + one HTTP-shaped segment, new flow each time)", dur, || {
        let mut table = FlowTable::new();
        let mut alerts = Vec::new();
        let syn = build_tcp_frame(client, server, 51234, 80, 1, TCP_SYN, &[]);
        let mut p = Packet::default();
        parse_ethernet_frame(&syn, &mut p);
        table.observe(&p, now, now_sec, &flow_sig, &mut alerts);

        let seg = build_tcp_frame(client, server, 51234, 80, 2, TCP_PSH | TCP_ACK, http_req);
        parse_ethernet_frame(&seg, &mut p);
        alerts.clear();
        table.observe(&p, now, now_sec, &flow_sig, &mut alerts);
    });
    std::fs::remove_file(&flow_rules_path).ok();
}