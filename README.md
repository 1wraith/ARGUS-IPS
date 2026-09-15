# ARGUS
ARGUS is a high-performance, Rust-based network intrusion detection engine designed to provide real-time packet inspection, flow tracking, protocol analysis, and rule-based threat detection with minimal overhead.

The system captures live network traffic through Npcap on Windows and processes packets through an optimized capture → parse → flow → detect → alert pipeline. Its architecture has been deliberately kept compact, with the implementation consolidated into four core Rust modules: lib.rs, packet.rs, engine.rs, and main.rs. Each module has a clearly defined responsibility while avoiding unnecessary abstraction or duplicated processing.

ARGUS supports TCP stream reassembly, allowing detection rules to identify malicious content even when a payload is fragmented across multiple packets or arrives out of order. TCP flows are consistently assigned to workers using canonical flow hashing so both directions of a connection can be reconstructed correctly.

The protocol layer provides structured inspection of common network data rather than relying exclusively on raw packet bytes. ARGUS can extract fields including HTTP hosts and URIs, DNS queries, TLS SNI values, and JA3 fingerprints. These fields can be targeted directly by detection rules.

The rule engine supports literal and regular-expression matching, negation, and traffic-direction scoping, providing substantially more expressive detection than simple substring signatures. Static indicators such as IP blacklists can be combined with behavioral detection including packet-rate floods and TCP SYN scanning.

Performance is a core design goal. The hot path minimizes allocations and synchronization, uses efficient flow state management, and is structured to remain predictable under sustained traffic. Comprehensive tests cover packet parsing, stream reassembly, protocol extraction, rule evaluation, and JA3 correctness, including independently verified reference fingerprints.

ARGUS is intentionally an IDS rather than an IPS: it observes and reports suspicious activity without attempting to modify or block network traffic. It is an actively developing project focused on building a compact, efficient, and technically rigorous foundation for deeper network security capabilities.
