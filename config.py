"""Tunable thresholds for the detection engine.

Lower the thresholds if detections do not fire during your demo;
raise them if you see false positives on a busy network.
"""

PORT_SCAN_WINDOW = 10.0
PORT_SCAN_PORT_THRESHOLD = 15

BRUTE_FORCE_WINDOW = 30.0
BRUTE_FORCE_THRESHOLD = 10

DNS_WINDOW = 10.0
DNS_RATE_THRESHOLD = 50
DNS_QNAME_LENGTH = 50
