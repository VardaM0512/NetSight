"""Generate a synthetic test capture for verifying the detectors.

This crafts packets in memory and writes them to test.pcap. Nothing is sent
onto any network. Run the engine on the resulting file to confirm every
detector fires:

    python gen_test_traffic.py
    python netsight.py capture --pcap test.pcap
"""

from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.packet import Raw
from scapy.utils import wrpcap

ATTACKER = "10.0.0.66"
VICTIM = "10.0.0.10"
GATEWAY = "10.0.0.1"


def build():
    packets = []

    # SYN scan across many ports
    for port in range(20, 45):
        packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000 + port, dport=port, flags="S"))

    # Stealth scans
    packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(dport=139, flags=0))       # NULL
    packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(dport=139, flags="F"))     # FIN
    packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(dport=139, flags="FPU"))   # XMAS

    # ARP cache poisoning: gateway IP suddenly on a new MAC
    packets.append(ARP(op=2, psrc=GATEWAY, hwsrc="00:11:22:33:44:55", pdst=VICTIM))
    packets.append(ARP(op=2, psrc=GATEWAY, hwsrc="66:66:66:66:66:66", pdst=VICTIM))

    # SSH brute force: many connection attempts to port 22
    for i in range(15):
        packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(sport=50000 + i, dport=22, flags="S"))

    # HTTP SQL injection
    sqli = b"GET /login?user=admin'+OR+1=1--+&pass=x HTTP/1.1\r\nHost: victim\r\n\r\n"
    packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(sport=51000, dport=80, flags="PA") / Raw(load=sqli))

    # HTTP XSS
    xss = b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: victim\r\n\r\n"
    packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(sport=51001, dport=80, flags="PA") / Raw(load=xss))

    # Rogue DHCP: two different servers both offering leases
    packets.append(IP(src=GATEWAY, dst="255.255.255.255") / UDP(sport=67, dport=68) /
                   BOOTP(op=2) / DHCP(options=[("message-type", "offer"), "end"]))
    packets.append(IP(src="10.0.0.200", dst="255.255.255.255") / UDP(sport=67, dport=68) /
                   BOOTP(op=2) / DHCP(options=[("message-type", "offer"), "end"]))

    # DNS tunneling: abnormally long query name
    long_name = ("x" * 60) + ".exfil.example.com"
    packets.append(IP(src=ATTACKER, dst=GATEWAY) / UDP(sport=33000, dport=53) /
                   DNS(rd=1, qd=DNSQR(qname=long_name)))

    # Wrap everything in an Ethernet frame so the whole capture shares one
    # link type, then assign increasing timestamps for the time-window logic.
    base = 1_700_000_000.0
    framed = []
    for i, pkt in enumerate(packets):
        frame = Ether() / pkt
        frame.time = base + i * 0.05
        framed.append(frame)

    return framed


if __name__ == "__main__":
    pkts = build()
    wrpcap("test.pcap", pkts)
    print("Wrote test.pcap with %d packets." % len(pkts))
