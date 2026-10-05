# NetSight — Full Project Guide

Network security monitoring and forensics for ISL Mini Project.
Team: Gahna Bisht, Varda Murarka, Vishad Sharma.

This guide assumes you have **nothing installed** and know nothing about the
setup. Follow it top to bottom.

---

## 1. What the project actually is (in plain words)

NetSight watches network traffic, catches attacks as they happen, saves the
evidence, and shows everything on a web dashboard. Three pieces:

1. **A lab network** — a few virtual machines (VMs) on one laptop, pretending
   to be a small company network. One machine attacks, one is the victim, one
   watches.
2. **A detection engine** (Python) — reads every packet and raises an alert
   when it sees a scan, a spoof, a brute-force attempt, or a web attack.
3. **A dashboard + forensics** — stores alerts in a database, draws charts,
   and lets you download an incident report and the captured evidence file.

### How this maps to the 3 objectives in your synopsis

| Objective | What it means | Who owns it |
|-----------|---------------|-------------|
| **Obj 1** — Build the testbed | Set up the VMs and the virtual network | **Gahna** (victim VM + services) + **Vishad** (attacker VM + networking) |
| **Obj 2** — Detection engine | The Python code that detects attacks live | **Varda** (done) |
| **Obj 3** — Forensics + dashboard + benchmarking | Database, web dashboard, PCAP export, Suricata comparison | **Varda** (dashboard/forensics, done) + **Vishad** (Suricata benchmark) |

Report and diagram are split: **Gahna** writes the easy sections and draws the
diagram, **Vishad** writes the technical sections.

---

## 2. Work division (who does what)

### Varda — Detection engine + dashboard + forensics (core, already built)

This is the brain of the project and **it is already written and tested for
you** — it's in this folder. Your job is to:

1. Understand it well enough to explain it (section 4 explains every detector).
2. Run it on the lab and during the demo (section 5).
3. Verify it works (section 7) — already proven to catch all attack types.

### Gahna — easy mix (a little hands-on + easy writing)

A balance of light technical and documentation work — all of it copy-paste or
guided, no networking theory and no Python.

1. **Install VirtualBox** (section 3 step B) — just an installer with defaults.
2. **Build + set up the victim VM** (section 3 step C-victim and step D-victim):
   install Ubuntu, then run two copy-paste commands to start the web server and
   SSH server. Nothing to configure by hand.
3. **Run the demo attacks** (section 6) by copy-pasting the ready-made commands
   on the attacker VM while Varda's engine captures. No need to understand them.
4. **Collect screenshots** of the dashboard, the alerts, and the downloaded
   report.
5. **Draw the architecture diagram** in draw.io (free, in-browser) using the
   template in section 8.
6. **Write the easy report sections** — Introduction, Objectives, and Tools
   Used — mostly liftable from this guide and the synopsis.

### Vishad — networking + benchmarking + technical writeup (moderate)

The parts that need a bit more thought.

1. **Build + configure the attacker VM (Kali)** (section 3 step C-attacker).
2. **Set up the private network** (section 3 step D-network): put both VMs on
   the same internal network, give each a static IP, and confirm they can ping
   each other. This is the one genuinely fiddly step — it's yours.
3. **Suricata benchmarking** (section 9) — install Suricata, run it on the same
   `forensic.pcap` NetSight produces, and build the comparison table (what each
   tool caught/missed). This is the "benchmarking" in your title.
4. **Write the technical report sections** — Methodology, Detection Techniques
   (lift from section 4), and Results & Benchmark Analysis (from section 9).

---

## 3. Setup — download and install (Windows)

Ownership: **Varda** does A. **Gahna** does B, the victim VM in C, and the
victim services in D. **Vishad** does the attacker VM in C and the network
setup in D.

### A. Python + NetSight (Varda's machine)

1. **Install Python 3**
   - Go to https://www.python.org/downloads/
   - Download the latest Windows installer, run it.
   - **On the first screen, tick "Add python.exe to PATH"** before clicking
     Install. This matters.
2. **Get the project folder** — unzip `netsight.zip` somewhere easy, e.g.
   `C:\netsight`.
3. **Open a terminal in that folder**
   - Open the `netsight` folder in File Explorer.
   - Click the address bar, type `cmd`, press Enter. A black window opens
     already in the right place.
4. **Install the two libraries** — in that window, type:
   ```
   pip install -r requirements.txt
   ```
5. **(Only for live capture) install Npcap** — this lets Python sniff real
   traffic on Windows.
   - Go to https://npcap.com/#download, download the installer, run it.
   - Keep default options and **tick "Install Npcap in WinPcap API-compatible
     Mode"**.
   - You do **not** need this to test with a `.pcap` file (section 7).

You are now ready. Jump to section 7 to prove it works before touching VMs.

### B. VirtualBox — Gahna

1. Download VirtualBox from https://www.virtualbox.org/wiki/Downloads →
   "Windows hosts". Install with defaults. (Install this on whichever single
   laptop will host the two VMs for the demo.)

### C. The two VMs

**Victim — Ubuntu (Gahna)** — simple target
   - Download Ubuntu Desktop ISO: https://ubuntu.com/download/desktop
   - In VirtualBox: New → name it "Victim", type Linux / Ubuntu 64-bit, give it
     2 GB RAM, create a 15 GB disk, then start it and point it at the ISO to
     install. Create any username/password you like.

**Attacker — Kali Linux (Vishad)** — comes with all attack tools pre-installed
   - Go to https://www.kali.org/get-kali/#kali-virtual-machines
   - Download the **VirtualBox** image (a `.7z` file). Extract it with 7-Zip
     (https://www.7-zip.org/).
   - In VirtualBox: Machine → Add → pick the extracted `.vbox` file.
   - Default login: user `kali`, password `kali`.

### D. Network + services

**Network setup — Vishad.** This is what makes them a "network" NetSight can
watch, and it's the one fiddly step.

1. For **each** VM: select it → Settings → Network → Adapter 1 →
   "Attached to:" → choose **Internal Network**, name it `netsight-lab` for
   both. Click OK.
2. Start both VMs. Give each a static IP so they match this guide:
   - On **Victim** (Ubuntu terminal):
     ```
     sudo ip addr add 10.0.0.10/24 dev enp0s3
     sudo ip link set enp0s3 up
     ```
   - On **Kali** (attacker terminal):
     ```
     sudo ip addr add 10.0.0.66/24 dev eth0
     sudo ip link set eth0 up
     ```
   (If the interface name differs, run `ip a` to see the real name and use it.)
3. Test they can see each other — from Kali: `ping 10.0.0.10` should reply.

**Victim services — Gahna.** Once Vishad confirms the ping works, start the
services on the Ubuntu victim so there's something to attack (copy-paste):
   ```
   sudo apt update
   sudo apt install -y apache2 openssh-server
   ```
   Apache gives a web page on port 80; openssh gives SSH on port 22.

### Where does NetSight run?

Two easy options — pick one:

- **Simplest (recommended for the demo):** run NetSight **on the victim VM**.
  It sees all traffic aimed at the victim. Copy the `netsight` folder into the
  Ubuntu victim, install Python 3 + the libs there
  (`sudo apt install python3-pip -y` then `pip install -r requirements.txt`),
  and capture on its interface.
- **On your Windows laptop:** works if you capture a `.pcap` on a VM first,
  copy the file to Windows, and analyse the file. Good for building the report
  offline.

---

## 4. What the detection engine does (so Varda can explain it)

The engine reads packets one by one and runs each through six detectors. Each
file:

- **`netsight.py`** — the main program. Reads packets (live or from a file),
  feeds them to the detectors, prints alerts, saves flagged packets as evidence.
- **`detectors.py`** — the six detectors (the actual security logic).
- **`storage.py`** — saves packet metadata and alerts into a SQLite database.
- **`dashboard.py`** + **`templates/dashboard.html`** — the web dashboard.
- **`config.py`** — thresholds you can tune.
- **`gen_test_traffic.py`** — makes a test capture to prove detection works.

The six detectors and the technique each uses:

| Detector | Attack caught | How it decides |
|----------|---------------|----------------|
| **Port Scan** | Nmap SYN / NULL / FIN / XMAS scans | Counts distinct ports hit by SYN packets from one source in a time window; also flags illegal TCP flag combinations |
| **ARP Spoofing** | Man-in-the-middle / cache poisoning | Watches IP→MAC bindings; alerts when one IP suddenly changes MAC, or on unsolicited ARP replies |
| **Brute Force** | SSH / SNMP password guessing | Counts repeated connection attempts to port 22 / 161 in a window |
| **Web Exploit** | SQL injection, XSS | Signature/pattern matching on HTTP request payloads |
| **DNS Anomaly** | DNS tunneling / flooding | Flags very long query names and high query rates |
| **Rogue DHCP** | Fake DHCP server | Alerts when a second machine starts handing out DHCP leases |

This directly covers all five "Implemented Information Security Techniques" in
your synopsis.

---

## 5. How to run NetSight

All commands are run in the terminal, inside the `netsight` folder.

**Analyse a saved capture file:**
```
python netsight.py capture --pcap test.pcap
```

**Capture live traffic** (needs Npcap on Windows, or run on the Linux VM):
```
python netsight.py capture --iface "Ethernet"
```
Replace `"Ethernet"` with your interface name. On Windows, run
`python -c "from scapy.all import get_if_list; print(get_if_list())"` to list
them. On Linux the attacker-facing one is usually `eth0` or `enp0s3`.

**Capture live and open the dashboard automatically when you stop (Ctrl+C):**
```
python netsight.py capture --iface "Ethernet" --serve
```

**Just open the dashboard for a database you already made:**
```
python netsight.py dashboard
```
Then open **http://127.0.0.1:5000** in a browser.

### The demo flow (what you do on presentation day)

1. On the sensor (victim VM or your laptop), start capture:
   `python netsight.py capture --iface eth0 --serve`
2. Gahna runs the attacks from section 6 on the Kali VM, in order.
3. Watch alerts print live in the terminal.
4. Press **Ctrl+C** to stop. The dashboard opens.
5. Show the charts, the alert table, and click the two download buttons to show
   the incident report (CSV) and the forensic PCAP.

---

## 6. Attack commands for the demo (Gahna runs these on Kali)

> Vishad sets up the Kali VM and networking; Gahna runs these copy-paste
> commands during the demo while Varda's engine captures.

Run these on the **attacker (Kali)** VM, against the victim `10.0.0.10`, while
NetSight is capturing. These are standard tools that come pre-installed on
Kali, used here only against your own isolated lab VM.

```
# 1. Port scan (triggers Port Scan detector)
nmap -sS 10.0.0.10

# 2. Stealth scans (NULL / FIN / XMAS)
sudo nmap -sN 10.0.0.10
sudo nmap -sF 10.0.0.10
sudo nmap -sX 10.0.0.10

# 3. SSH brute force (triggers Brute Force detector)
hydra -l root -P /usr/share/wordlists/nmap.lst -t 4 ssh://10.0.0.10

# 4. Web attack - SQL injection style request (triggers Web Exploit detector)
curl "http://10.0.0.10/login?user=admin'+OR+1=1--+"

# 5. Web attack - XSS style request
curl "http://10.0.0.10/search?q=<script>alert(1)</script>"

# 6. ARP spoofing (triggers ARP Spoofing detector)
sudo arpspoof -i eth0 -t 10.0.0.10 10.0.0.1
```

If `arpspoof` is missing: `sudo apt install dsniff -y`.

Stop each long-running one (hydra, arpspoof) with Ctrl+C after a few seconds.

---

## 7. How to test and verify (do this FIRST, before the lab)

You can prove the whole engine works on your own laptop with **no VMs at all**,
using the included test-traffic generator. This is the fastest way to confirm
your part is done.

```
python gen_test_traffic.py
python netsight.py capture --pcap test.pcap --serve
```

`gen_test_traffic.py` builds a capture file containing one of every attack
(it does **not** send anything on a network — it just writes a file). When you
run the engine on it, you should see **all six categories** of alert. Expected
output:

```
[HIGH  ] Port Scan      SYN scan: 15 distinct ports in 10s
[MEDIUM] Port Scan      NULL scan (no TCP flags set)
[MEDIUM] Port Scan      FIN scan (lone FIN flag)
[MEDIUM] Port Scan      XMAS scan (FIN+PSH+URG flags)
[MEDIUM] ARP Spoofing   Unsolicited ARP reply...
[HIGH  ] ARP Spoofing   IP 10.0.0.1 moved from MAC ... (ARP cache poisoning)
[HIGH  ] Brute Force    SSH brute force: 10 attempts in 30s
[HIGH  ] Web Exploit    SQL injection signature in HTTP request
[HIGH  ] Web Exploit    Cross-site scripting signature in HTTP request
[HIGH  ] Rogue DHCP     Second DHCP server 10.0.0.200 detected...
[MEDIUM] DNS Anomaly    Long DNS query ... possible DNS tunneling
```

Then the dashboard opens at http://127.0.0.1:5000 showing the charts, the
counters, and the alert table. Click both download buttons to confirm the CSV
report and the forensic PCAP download. **If you see this, your part is 100%
done and working.**

### Verification checklist (put this table in the report)

| Technique / detector | Test input | Expected result | Pass? |
|----------------------|-----------|-----------------|-------|
| SYN scan detection | `nmap -sS` / test.pcap | Port Scan (high) alert | ☐ |
| Stealth scan detection | `nmap -sN/-sF/-sX` | NULL/FIN/XMAS alerts | ☐ |
| ARP spoof detection | `arpspoof` / test.pcap | ARP Spoofing alert | ☐ |
| SSH brute force | `hydra ssh` | Brute Force alert | ☐ |
| SQL injection | SQLi curl request | Web Exploit alert | ☐ |
| XSS | XSS curl request | Web Exploit alert | ☐ |
| DNS anomaly | long DNS query | DNS Anomaly alert | ☐ |
| Rogue DHCP | second DHCP server | Rogue DHCP alert | ☐ |
| Forensic export | click Download PCAP | file downloads | ☐ |
| Incident report | click Download CSV | file downloads | ☐ |

### Tuning (if a detector doesn't fire on the real lab)

Open `config.py` and lower a threshold. For example, if a real scan isn't
flagged, drop `PORT_SCAN_PORT_THRESHOLD` from 15 to 8. If SSH brute force is
missed, drop `BRUTE_FORCE_THRESHOLD`.

---

## 8. Architecture diagram (for Gahna to draw in draw.io)

Boxes and arrows:

```
 [ Attacker VM ]              [ Victim VM ]
   Kali 10.0.0.66   ----\    /---- Ubuntu 10.0.0.10
                         \  /       (Apache :80, SSH :22)
                    [ Internal Network: netsight-lab ]
                               |
                     [ NetSight sensor ]
                   Python engine -> SQLite -> Flask dashboard
                               |
                 Alerts | Forensic PCAP | CSV report
```

Label the three objectives next to the matching box.

---

## 9. Suricata benchmarking (Vishad)

This gives the "Suricata/Zeek benchmarking" part of the title.

1. On the victim VM (or any Linux): `sudo apt install suricata -y`
2. Run Suricata over the same evidence file NetSight produced:
   ```
   suricata -r forensic.pcap -l ./suricata-out
   ```
3. Open `./suricata-out/fast.log` to see Suricata's alerts.
4. **Compare in a small table** for the report: for each attack, did NetSight
   catch it? Did Suricata? This is the benchmark. NetSight is lightweight and
   custom; Suricata is a heavy industry tool — the point is to show your custom
   engine catches the same core attacks.

---

## 10. Quick checklist for the whole team

- [ ] Varda: Python installed, `pip install -r requirements.txt` done
- [ ] Varda: `gen_test_traffic.py` + engine shows all 6 alert types (section 7)
- [ ] Varda: dashboard opens and both downloads work
- [ ] Gahna: VirtualBox installed + Ubuntu victim VM built
- [ ] Vishad: Kali attacker VM built
- [ ] Vishad: both VMs on `netsight-lab`, static IPs set, can ping each other
- [ ] Gahna: Apache + SSH running on victim
- [ ] Gahna: demo attacks run cleanly on Kali, screenshots collected
- [ ] Gahna: architecture diagram drawn + Intro/Objectives/Tools report sections written
- [ ] Vishad: Suricata benchmark table done
- [ ] Vishad: Methodology/Detection/Results report sections written
