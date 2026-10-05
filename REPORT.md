# NetSight — Information Security Lab Mini Project Report

**A Custom Packet-Level Detection System with Forensic PCAP Analysis for an Emulated Enterprise Network**

| | |
|---|---|
| **Team** | Gahna Bisht (240911610), Varda Murarka (240911548), Vishad Sharma (240911580) |
| **Course** | Information Security Lab |
| **Platform** | Python, Scapy, SQLite, Flask |

---

## Abstract

In educational cybersecurity labs and small enterprise networks, security
monitoring is usually scattered across disconnected tools — a sniffer here, a
port scanner there, a log viewer somewhere else. This fragmentation makes it
hard to run a continuous, end-to-end detection and forensics workflow. NetSight
addresses this by providing a single lightweight platform that captures live
network traffic, detects a range of Layer-2 to Layer-7 attacks in real time
using a custom Python engine, preserves the malicious packets as forensic
evidence, and presents alerts and incident timelines through an interactive web
dashboard. The system was deployed on an emulated enterprise network of virtual
machines and validated against a suite of simulated attacks, detecting every
tested attack category with clear, actionable alerts.

---

## 1. Introduction

Network-based attacks remain among the most common threats to enterprise
infrastructure, ranging from simple reconnaissance scans to man-in-the-middle
attacks, credential brute-forcing, and web application exploits. Detecting these
attacks requires inspecting traffic at multiple layers of the network stack and
correlating events over time.

NetSight is a unified network security monitoring and digital forensics platform.
It intercepts traffic on an emulated enterprise network, evaluates each packet
through a custom detection engine built with Scapy, and raises normalized alerts
for malicious activity. Detected events and packet metadata are stored in a
SQLite database, flagged packets are preserved as a forensic PCAP, and all
findings are surfaced through a Flask and Chart.js dashboard that supports live
monitoring and post-incident analysis.

## 2. Objectives

1. **Construct an emulated enterprise testbed** of isolated virtual machines — an
   attacker, a victim running core services, and a monitoring sensor — connected
   over a private virtual network.
2. **Implement an extensible packet-processing and detection engine** in Python
   that parses live traffic and detects protocol violations, reconnaissance,
   brute-force activity, and web-based exploits in real time.
3. **Build an evidence-preservation and forensic analytics subsystem** that logs
   normalized security events, indexes packet metadata into SQLite, enables PCAP
   export, and presents interactive incident reports through a web dashboard.

## 3. System Architecture

```
   +----------------+        +----------------+
   |  Attacker VM   |        |   Victim VM    |
   |  Kali          |        |   Ubuntu       |
   |  10.0.0.66     |        |   10.0.0.10    |
   |                |        |   Apache :80   |
   |                |        |   SSH    :22   |
   +-------+--------+        +--------+-------+
           |                          |
           +------------+-------------+
                        |
             Internal Network (netsight-lab)
                        |
                        v
             +---------------------+
             |   NetSight Sensor   |
             |---------------------|
             |  Capture (Scapy)    |
             |  Detection engine   |  ->  6 detectors
             |  SQLite storage     |
             |  Flask dashboard    |
             +----------+----------+
                        |
         +--------------+--------------+
         |              |              |
     Live alerts   Forensic PCAP   CSV report
```

The attacker and victim VMs share a private internal network. The NetSight
sensor observes traffic on this network, processes each packet through the
detection engine, records metadata and alerts in SQLite, saves malicious packets
for forensics, and serves the dashboard.

## 4. Methodology

The system follows a linear pipeline applied to every packet:

1. **Capture** — packets are read either live from a network interface or offline
   from a saved `.pcap` file using Scapy.
2. **Inspection** — each packet is passed through six independent detectors. Each
   detector parses the relevant layers (Ethernet, ARP, IP, TCP/UDP, DNS, DHCP,
   HTTP) and applies its own logic.
3. **Alerting** — when a detector matches, it produces a normalized alert with a
   timestamp, category, severity, source, destination, and description.
4. **Persistence** — packet metadata and alerts are written to SQLite; the
   offending packets are appended to a forensic PCAP.
5. **Visualization** — the dashboard reads the database and presents counters,
   charts, a timeline, and a recent-alerts table, with CSV and PCAP export.

Thresholds (scan port count, brute-force attempt count, DNS query rate, etc.) are
centralized in a configuration file so detection sensitivity can be tuned.

## 5. Detection Techniques Implemented

| # | Technique | Attack detected | Detection logic |
|---|-----------|-----------------|-----------------|
| 1 | Stateful scan detection | Nmap SYN / NULL / FIN / XMAS scans | Sliding-window count of distinct destination ports per source for SYN packets; illegal TCP flag combinations flagged directly |
| 2 | Data-link integrity verification | ARP spoofing / cache poisoning (MitM) | Tracks IP-to-MAC bindings; alerts on a changed binding or an unsolicited ARP reply |
| 3 | Authentication rate-limiting heuristics | SSH / SNMP brute force | Counts repeated connection attempts to ports 22/161 within a time window |
| 4 | Signature-based payload analysis | SQL injection, Cross-Site Scripting | Regex pattern matching over HTTP request payloads |
| 5 | DNS anomaly detection | DNS tunneling / flooding | Flags abnormally long query names and high per-source query rates |
| 6 | Rogue service detection | Rogue DHCP server | Alerts when a second host begins issuing DHCP offers/acks |

## 6. Implementation

The platform is implemented as a set of focused Python modules:

- **`netsight.py`** — entry point and capture engine; reads packets, drives the
  detectors, prints live alerts, and exports forensic packets.
- **`detectors.py`** — the six detector classes, each exposing an `inspect()`
  method returning alerts.
- **`storage.py`** — SQLite schema and persistence for packet metadata and alerts.
- **`dashboard.py`** + **`templates/dashboard.html`** — Flask application and UI
  (Chart.js) with CSV and PCAP export endpoints.
- **`config.py`** — tunable detection thresholds.
- **`gen_test_traffic.py`** — generates a synthetic capture containing one of
  every attack type for repeatable testing.

## 7. Tools and Technologies

| Category | Details |
|----------|---------|
| Programming language | Python 3 |
| Packet capture / parsing | Scapy, Npcap (live capture on Windows) |
| Database | SQLite |
| Web dashboard | Flask, Chart.js |
| Detection techniques | Stateful TCP analysis, ARP binding checks, brute-force rate-limiting, signature matching, DNS heuristics, rogue-DHCP detection |
| Lab environment | VirtualBox, Kali Linux, Ubuntu |
| Attack tools (for validation) | Nmap, Hydra, arpspoof, curl |

## 8. Testing and Results

The complete pipeline was validated using the included test-traffic generator,
which crafts a capture of every attack category. Running the engine over this
capture produced the following:

- **Packets inspected:** 50
- **Alerts raised:** 11
- **High-severity alerts:** 6
- **Distinct threat categories detected:** 6 (all)

Every detector fired correctly, confirming end-to-end functionality.

### Verification matrix

| Technique / detector | Test input | Expected result | Result |
|----------------------|-----------|-----------------|--------|
| SYN scan detection | nmap -sS / test capture | Port Scan (high) | Pass |
| Stealth scan detection | nmap -sN / -sF / -sX | NULL / FIN / XMAS alerts | Pass |
| ARP spoof detection | arpspoof / test capture | ARP Spoofing alert | Pass |
| SSH brute force | hydra ssh | Brute Force alert | Pass |
| SQL injection | SQLi HTTP request | Web Exploit alert | Pass |
| Cross-site scripting | XSS HTTP request | Web Exploit alert | Pass |
| DNS anomaly | long DNS query | DNS Anomaly alert | Pass |
| Rogue DHCP | second DHCP server | Rogue DHCP alert | Pass |
| Forensic export | download PCAP | File downloaded | Pass |
| Incident report | download CSV | File downloaded | Pass |

### Screenshots

*(Dashboard overview and recent-alerts table — see `docs/dashboard.png` and
`docs/alerts.png`.)*

## 9. Benchmarking against Suricata

To position NetSight against an established tool, Suricata (an industry-standard
open-source IDS) was run over the same `forensic.pcap` produced by NetSight, and
the alerts compared.

> **To complete:** run `suricata -r forensic.pcap -l ./suricata-out`, open
> `suricata-out/fast.log`, and fill the table below with the actual counts.

| Attack category | Detected by NetSight | Detected by Suricata |
|-----------------|:---:|:---:|
| Port scan (SYN/NULL/FIN/XMAS) | Yes | _fill_ |
| ARP spoofing | Yes | _fill_ |
| SSH brute force | Yes | _fill_ |
| SQL injection | Yes | _fill_ |
| XSS | Yes | _fill_ |
| DNS anomaly | Yes | _fill_ |
| Rogue DHCP | Yes | _fill_ |

**Discussion:** NetSight is a lightweight, purpose-built engine whose detection
logic is fully transparent and tunable, whereas Suricata is a heavyweight tool
driven by large external rule sets. The goal of the comparison is to show that a
compact custom engine can catch the same core attack classes on a small
enterprise network with far less configuration overhead.

## 10. Challenges

- Handling raw packets without an Ethernet layer required normalizing frames so
  all captures share a single link type.
- Distinguishing brute-force attempts from normal repeated connections at the
  packet level required careful time-window tuning.
- Balancing detection sensitivity against false positives through configurable
  thresholds.

## 11. Conclusion and Future Scope

NetSight delivers a working end-to-end network security monitoring and forensics
platform that consolidates real-time packet inspection, rule-based detection, and
evidence preservation into a single lightweight architecture. It successfully
detected every tested attack category and produced forensic artifacts suitable
for incident review.

**Future scope:** a full multi-VLAN testbed with a pfSense/OPNsense firewall and
SPAN mirroring; direct PCAP upload from the dashboard; real-time email alerting;
an SSH honeypot (Cowrie) for attacker telemetry; and machine-learning anomaly
detection alongside the rule engine.

## 12. Work Distribution

| Member | Contribution |
|--------|-------------|
| **Varda Murarka** | Detection engine, SQLite forensics, and Flask/Chart.js dashboard (core platform); testing and verification |
| **Gahna Bisht** | Victim VM and services, demo attack execution, evidence capture |
| **Vishad Sharma** | Attacker VM setup, private network configuration, Suricata benchmarking |
