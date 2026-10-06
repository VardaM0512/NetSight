import sqlite3

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     REAL,
    src    TEXT,
    dst    TEXT,
    proto  TEXT,
    length INTEGER,
    info   TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL,
    category    TEXT,
    severity    TEXT,
    src         TEXT,
    dst         TEXT,
    sport       INTEGER,
    dport       INTEGER,
    proto       TEXT,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
"""


class Store:
    def __init__(self, path="netsight.db", reset=False):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        if reset:
            self.conn.execute("DELETE FROM packets")
            self.conn.execute("DELETE FROM alerts")
        self.conn.commit()

    def log_packet(self, pkt, ts):
        src = dst = info = ""
        proto = "OTHER"
        length = len(pkt)

        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
            if pkt.haslayer(TCP):
                proto = "TCP"
                info = "%d->%d" % (pkt[TCP].sport, pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                info = "%d->%d" % (pkt[UDP].sport, pkt[UDP].dport)
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
            else:
                proto = "IP"
        elif pkt.haslayer(ARP):
            proto = "ARP"
            src, dst = pkt[ARP].hwsrc, pkt[ARP].hwdst

        self.conn.execute(
            "INSERT INTO packets (ts, src, dst, proto, length, info) VALUES (?,?,?,?,?,?)",
            (ts, src, dst, proto, length, info))

    def log_alert(self, alert):
        self.conn.execute(
            "INSERT INTO alerts (ts, category, severity, src, dst, sport, dport, proto, description) "
            "VALUES (?,?,?,?,?,?,?,?,?)", alert.row())

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()
