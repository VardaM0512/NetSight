import argparse
import sys
import time

from scapy.utils import PcapReader, wrpcap
from scapy.sendrecv import sniff

import detectors
from storage import Store


class Engine:
    def __init__(self, store, keep_flagged=True):
        self.store = store
        self.detectors = detectors.all_detectors()
        self.flagged = []
        self.keep_flagged = keep_flagged
        self.packets = 0
        self.alerts = 0

    def process(self, pkt):
        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        self.packets += 1
        self.store.log_packet(pkt, ts)

        matched = False
        for detector in self.detectors:
            for alert in detector.inspect(pkt, ts):
                self.store.log_alert(alert)
                self.alerts += 1
                matched = True
                print("[%-6s] %-14s %s  (%s -> %s)" % (
                    alert.severity.upper(), alert.category, alert.description,
                    alert.src, alert.dst))

        if matched and self.keep_flagged:
            self.flagged.append(pkt)
        if self.packets % 500 == 0:
            self.store.commit()

    def export_flagged(self, path):
        if self.flagged:
            wrpcap(path, self.flagged)
            print("Saved %d flagged packets to %s" % (len(self.flagged), path))


def run_capture(args):
    store = Store(args.db, reset=True)
    engine = Engine(store)

    if args.pcap:
        print("Analysing %s ..." % args.pcap)
        with PcapReader(args.pcap) as reader:
            for pkt in reader:
                engine.process(pkt)
    elif args.iface:
        print("Capturing on %s (Ctrl+C to stop) ..." % args.iface)
        try:
            sniff(iface=args.iface, prn=engine.process, store=False)
        except KeyboardInterrupt:
            print("\nStopping capture.")
    else:
        print("Give either --pcap <file> or --iface <name>.")
        sys.exit(1)

    engine.export_flagged(args.out_pcap)
    store.close()
    print("Done: %d packets, %d alerts. Database: %s" % (engine.packets, engine.alerts, args.db))

    if args.serve:
        serve(args.db, args.out_pcap, args.port)


def serve(db, pcap, port):
    from dashboard import create_app
    app = create_app(db, pcap)
    print("Dashboard running at http://127.0.0.1:%d" % port)
    app.run(host="127.0.0.1", port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(description="NetSight detection engine")
    sub = parser.add_subparsers(dest="command", required=True)

    cap = sub.add_parser("capture")
    cap.add_argument("--pcap")
    cap.add_argument("--iface")
    cap.add_argument("--db", default="netsight.db")
    cap.add_argument("--out-pcap", default="forensic.pcap")
    cap.add_argument("--serve", action="store_true")
    cap.add_argument("--port", type=int, default=5000)

    dash = sub.add_parser("dashboard")
    dash.add_argument("--db", default="netsight.db")
    dash.add_argument("--out-pcap", default="forensic.pcap")
    dash.add_argument("--port", type=int, default=5000)

    args = parser.parse_args()
    if args.command == "capture":
        run_capture(args)
    elif args.command == "dashboard":
        serve(args.db, args.out_pcap, args.port)


if __name__ == "__main__":
    main()
