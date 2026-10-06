import re
import time
from collections import defaultdict, deque

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP
from scapy.packet import Raw

import config


class Alert:
    def __init__(self, category, severity, src, dst, description,
                 sport=None, dport=None, proto=None, ts=None):
        self.ts = ts if ts is not None else time.time()
        self.category = category
        self.severity = severity
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.description = description

    def row(self):
        return (self.ts, self.category, self.severity, self.src, self.dst,
                self.sport, self.dport, self.proto, self.description)


class PortScanDetector:
    category = "Port Scan"

    def __init__(self):
        self.window = config.PORT_SCAN_WINDOW
        self.threshold = config.PORT_SCAN_PORT_THRESHOLD
        self.history = defaultdict(deque)
        self.last_report = {}

    def inspect(self, pkt, ts):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return []

        tcp = pkt[TCP]
        flags = int(tcp.flags)

        if flags == 0x00:
            return [self._stealth(pkt, ts, "NULL scan (no TCP flags set)")]
        if flags == 0x01:
            return [self._stealth(pkt, ts, "FIN scan (lone FIN flag)")]
        if flags == 0x29:
            return [self._stealth(pkt, ts, "XMAS scan (FIN+PSH+URG flags)")]

        syn = flags & 0x02
        ack = flags & 0x10
        if not (syn and not ack):
            return []

        src = pkt[IP].src
        seen = self.history[src]
        seen.append((ts, int(tcp.dport)))
        cutoff = ts - self.window
        while seen and seen[0][0] < cutoff:
            seen.popleft()

        ports = {port for _, port in seen}
        if len(ports) >= self.threshold and ts - self.last_report.get(src, 0) > self.window:
            self.last_report[src] = ts
            return [Alert(self.category, "high", src, pkt[IP].dst,
                          "SYN scan: %d distinct ports in %ds" % (len(ports), self.window),
                          dport=int(tcp.dport), proto="TCP", ts=ts)]
        return []

    def _stealth(self, pkt, ts, description):
        return Alert(self.category, "medium", pkt[IP].src, pkt[IP].dst, description,
                     dport=int(pkt[TCP].dport), proto="TCP", ts=ts)


class ArpSpoofDetector:
    category = "ARP Spoofing"

    def __init__(self):
        self.bindings = {}
        self.requested = set()

    def inspect(self, pkt, ts):
        if not pkt.haslayer(ARP):
            return []

        arp = pkt[ARP]
        alerts = []

        if arp.op == 1:
            self.requested.add(arp.pdst)
            return []

        if arp.op == 2:
            ip, mac = arp.psrc, arp.hwsrc
            known = self.bindings.get(ip)
            if known and known != mac:
                alerts.append(Alert(self.category, "high", mac, ip,
                                    "IP %s moved from MAC %s to %s (ARP cache poisoning)" % (ip, known, mac),
                                    proto="ARP", ts=ts))
            elif ip not in self.requested:
                alerts.append(Alert(self.category, "medium", mac, ip,
                                    "Unsolicited ARP reply: %s claims to be %s" % (mac, ip),
                                    proto="ARP", ts=ts))
            self.bindings[ip] = mac
            self.requested.discard(ip)
        return alerts


class BruteForceDetector:
    category = "Brute Force"

    def __init__(self):
        self.window = config.BRUTE_FORCE_WINDOW
        self.threshold = config.BRUTE_FORCE_THRESHOLD
        self.services = {22: "SSH", 161: "SNMP"}
        self.attempts = defaultdict(deque)
        self.last_report = {}

    def inspect(self, pkt, ts):
        if not pkt.haslayer(IP):
            return []

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            if int(tcp.dport) == 22 and (flags & 0x02) and not (flags & 0x10):
                return self._track(pkt[IP].src, pkt[IP].dst, 22, ts)

        if pkt.haslayer(UDP) and int(pkt[UDP].dport) == 161:
            return self._track(pkt[IP].src, pkt[IP].dst, 161, ts)

        return []

    def _track(self, src, dst, dport, ts):
        key = (src, dst, dport)
        hits = self.attempts[key]
        hits.append(ts)
        cutoff = ts - self.window
        while hits and hits[0] < cutoff:
            hits.popleft()

        if len(hits) >= self.threshold and ts - self.last_report.get(key, 0) > self.window:
            self.last_report[key] = ts
            service = self.services.get(dport, str(dport))
            return [Alert(self.category, "high", src, dst,
                          "%s brute force: %d attempts in %ds" % (service, len(hits), self.window),
                          dport=dport, proto="TCP/UDP", ts=ts)]
        return []


class WebExploitDetector:
    category = "Web Exploit"

    SQLI = re.compile(rb"(\bunion\b.{0,40}\bselect\b|\bor\b[\s+]+\d+\s*=\s*\d+|'[\s+]*or[\s+]|'[\s+]*--|--[\s+]|\bdrop\b[\s+]+\btable\b|information_schema)", re.I)
    XSS = re.compile(rb"(<script\b|onerror\s*=|onload\s*=|javascript:|<img[^>]+src\s*=\s*['\"]?javascript)", re.I)

    def inspect(self, pkt, ts):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
            return []
        if int(pkt[TCP].dport) not in (80, 8080):
            return []

        payload = bytes(pkt[Raw].load)
        src, dst = pkt[IP].src, pkt[IP].dst
        dport = int(pkt[TCP].dport)
        alerts = []

        if self.SQLI.search(payload):
            alerts.append(Alert(self.category, "high", src, dst,
                                "SQL injection signature in HTTP request",
                                dport=dport, proto="HTTP", ts=ts))
        if self.XSS.search(payload):
            alerts.append(Alert(self.category, "high", src, dst,
                                "Cross-site scripting signature in HTTP request",
                                dport=dport, proto="HTTP", ts=ts))
        return alerts


class DnsAnomalyDetector:
    category = "DNS Anomaly"

    def __init__(self):
        self.window = config.DNS_WINDOW
        self.rate_threshold = config.DNS_RATE_THRESHOLD
        self.qname_length = config.DNS_QNAME_LENGTH
        self.queries = defaultdict(deque)
        self.last_report = {}

    def inspect(self, pkt, ts):
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP)):
            return []
        if pkt[DNS].qr != 0:
            return []

        src = pkt[IP].src
        qname = pkt[DNSQR].qname.decode("utf-8", "ignore").rstrip(".")
        alerts = []

        if len(qname) >= self.qname_length:
            alerts.append(Alert(self.category, "medium", src, qname,
                                "Long DNS query (%d chars), possible DNS tunneling" % len(qname),
                                proto="DNS", ts=ts))

        recent = self.queries[src]
        recent.append(ts)
        cutoff = ts - self.window
        while recent and recent[0] < cutoff:
            recent.popleft()

        if len(recent) >= self.rate_threshold and ts - self.last_report.get(src, 0) > self.window:
            self.last_report[src] = ts
            alerts.append(Alert(self.category, "medium", src, "",
                                "High DNS query rate: %d queries in %ds" % (len(recent), self.window),
                                proto="DNS", ts=ts))
        return alerts


class RogueDhcpDetector:
    category = "Rogue DHCP"

    SERVER_TYPES = {2, 5, "offer", "ack"}

    def __init__(self):
        self.servers = set()

    def inspect(self, pkt, ts):
        if not (pkt.haslayer(DHCP) and pkt.haslayer(IP)):
            return []

        msg_type = None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                msg_type = opt[1]
                break
        if msg_type not in self.SERVER_TYPES:
            return []

        server = pkt[IP].src
        alerts = []
        if self.servers and server not in self.servers:
            alerts.append(Alert(self.category, "high", server, pkt[IP].dst,
                                "Second DHCP server %s detected (known: %s)" % (server, ", ".join(sorted(self.servers))),
                                proto="DHCP", ts=ts))
        self.servers.add(server)
        return alerts


def all_detectors():
    return [
        PortScanDetector(),
        ArpSpoofDetector(),
        BruteForceDetector(),
        WebExploitDetector(),
        DnsAnomalyDetector(),
        RogueDhcpDetector(),
    ]
