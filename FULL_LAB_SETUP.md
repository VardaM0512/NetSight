# NetSight — Full Lab Setup (run everything on one PC)

This sets up the complete live lab on your Windows machine: an attacker VM, a
victim VM running NetSight, a private network between them, real attacks, the
live dashboard, and the Suricata benchmark. Follow it top to bottom.

Plan at a glance:

```
 Kali (attacker)  10.0.0.66 ──┐
                              ├── Internal Network "netsight-lab"
 Ubuntu (victim) 10.0.0.10 ──┘   (NetSight captures here)
   - Apache :80, SSH :22
   - runs NetSight + dashboard
```

Each VM also has a second NAT adapter just for internet (apt / git).

Rough time: 1.5–2 hours, mostly downloads.

---

## PART A — Install VirtualBox + downloads (Windows host)

1. **VirtualBox:** https://www.virtualbox.org/wiki/Downloads → "Windows hosts" →
   install with defaults.
2. **7-Zip:** https://www.7-zip.org/ → install (needed to extract the Kali image).
3. **Kali VM image:** https://www.kali.org/get-kali/#kali-virtual-machines →
   the **VirtualBox** image (a `.7z`). Extract it with 7-Zip.
4. **Ubuntu ISO:** https://ubuntu.com/download/desktop → the Desktop `.iso`.

---

## PART B — Create the two VMs

### Victim — Ubuntu
1. VirtualBox → **New** → Name "Victim", Type Linux / Ubuntu 64-bit, 2–4 GB RAM,
   create a 20 GB disk.
2. Start it, select the Ubuntu ISO, and install Ubuntu (any username/password).
3. After install, shut it down for the network step.

### Attacker — Kali
1. VirtualBox → **Machine → Add** → pick the extracted Kali `.vbox` file.
2. Default login is `kali` / `kali`. Shut it down for the network step.

---

## PART C — Network (do this for BOTH VMs while they are powered off)

Give each VM two adapters:

1. Select the VM → **Settings → Network**.
2. **Adapter 1:** Enable, "Attached to:" = **NAT**. (This is internet.)
3. **Adapter 2:** Enable, "Attached to:" = **Internal Network**, name it
   `netsight-lab` (type it the same on both VMs).
4. OK. Repeat for the other VM.

Now start both VMs and set static IPs on the **internal** adapter.

On each VM, first find the interface names:
```
ip a
```
The NAT adapter usually has a `10.0.2.x` address already (leave it alone). The
second adapter has **no** IP yet — that is the lab interface.

- **Ubuntu victim** (second adapter is usually `enp0s8`):
  ```
  sudo ip addr add 10.0.0.10/24 dev enp0s8
  sudo ip link set enp0s8 up
  ```
- **Kali attacker** (second adapter is usually `eth1`):
  ```
  sudo ip addr add 10.0.0.66/24 dev eth1
  sudo ip link set eth1 up
  ```
  (Use the real name from `ip a` if it differs.)

Test connectivity — from Kali:
```
ping 10.0.0.10
```
If you get replies, the lab network is up.

---

## PART D — Prepare the victim VM (Ubuntu)

Run these on the **Ubuntu victim**:

1. Install the services to be attacked and the tools NetSight needs:
   ```
   sudo apt update
   sudo apt install -y apache2 openssh-server python3-pip git
   ```
2. Install the Python libraries:
   ```
   pip3 install scapy flask
   ```
   (If it complains about an "externally-managed environment", run:
   `pip3 install scapy flask --break-system-packages`.)
3. Get the NetSight code (after you've pushed it to GitHub):
   ```
   git clone https://github.com/VardaM0512/NetSight.git
   cd NetSight
   ```
   (Or copy the `netsight` folder in via a USB / shared folder.)

---

## PART E — Run NetSight (on the victim VM)

Start the live capture on the lab interface and launch the dashboard:
```
sudo python3 netsight.py capture --iface enp0s8 --serve
```
- Use the same interface name you set in Part C.
- `sudo` is required for live packet capture.
- Leave this running. Open **http://127.0.0.1:5000** in the victim VM's browser.

---

## PART F — Launch the attacks (on the Kali VM)

With NetSight capturing, run these on **Kali**, one at a time. Stop the
long-running ones (hydra, arpspoof) with **Ctrl+C** after a few seconds.

```
# Port scans
sudo nmap -sS 10.0.0.10
sudo nmap -sN 10.0.0.10
sudo nmap -sF 10.0.0.10
sudo nmap -sX 10.0.0.10

# SSH brute force
hydra -l root -P /usr/share/wordlists/nmap.lst -t 4 ssh://10.0.0.10

# Web attacks
curl "http://10.0.0.10/login?user=admin'+OR+1=1--+"
curl "http://10.0.0.10/search?q=<script>alert(1)</script>"

# ARP spoofing (install once: sudo apt install dsniff -y)
sudo arpspoof -i eth1 -t 10.0.0.10 10.0.0.1
```

Watch the alerts appear live in the NetSight terminal and on the dashboard.
Press **Ctrl+C** in the NetSight window to stop; it saves `forensic.pcap`.

---

## PART G — Suricata benchmark (on the victim VM)

```
sudo apt install -y suricata
suricata -r forensic.pcap -l ./suricata-out
cat suricata-out/fast.log
```
Compare Suricata's alerts against NetSight's and fill the table in `REPORT.md`
(Section 9).

---

## Troubleshooting

- **No alerts appearing:** confirm you're capturing on the **internal** interface
  (the one with the `10.0.0.x` IP), not the NAT one.
- **`ping` fails:** both VMs must have Adapter 2 on the *same* Internal Network
  name, and each needs its static `10.0.0.x` IP set (Part C).
- **Interface name wrong:** run `ip a` and use the real name of the adapter that
  has the `10.0.0.x` address.
- **Dashboard won't open from the host:** it binds to the VM's localhost — open
  it inside the victim VM's own browser.
- **Static IP lost after reboot:** the `ip addr add` commands reset on reboot;
  just re-run them, or ask if you want a permanent netplan config.
