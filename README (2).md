# Home Network Scanner

A beginner-friendly Python tool that scans your **own home network** to discover
connected devices, check which ports are open on them, and flag a few
well-known risky configurations.

Built using only Python's standard library — no external dependencies to install.

## ⚠️ Legal / ethical note

**Only run this against networks you own or have explicit permission to test**
(e.g. your own home Wi-Fi). Scanning devices or networks you don't own or
don't have permission for is illegal in most countries, regardless of intent.

## What it does

1. **Host discovery** — pings every address in your chosen network range to
   find which devices are currently online.
2. **Port scanning** — checks ~20 common ports (SSH, HTTP, Telnet, SMB, RDP,
   printer ports, etc.) on each live device.
3. **Banner grabbing** — for each open port, tries to read the service's
   greeting/banner (often reveals software name/version).
4. **Risk flagging** — compares open ports against a small set of
   "well-known risky configuration" rules (e.g. Telnet open, RDP exposed).
5. **Reporting** — prints a readable summary to your terminal and saves the
   full results as JSON.

## Requirements

- Python 3.7+
- `ping` command available on your system (already true on Windows/macOS/Linux)
- No pip installs needed

## Usage

Find your home network's IP range first. On most home routers this is:
```
192.168.1.0/24     (covers 192.168.1.1 – 192.168.1.254)
```
or
```
192.168.0.0/24
10.0.0.0/24
```
You can find your own range by checking your computer's IP address
(`ipconfig` on Windows, `ifconfig` or `ip a` on macOS/Linux) and using the
same first three numbers with `/24`.

Then run:
```bash
python3 network_scanner.py 192.168.1.0/24
```

Optional: choose where to save the JSON report:
```bash
python3 network_scanner.py 192.168.1.0/24 -o my_report.json
```

A full `/24` scan (254 addresses × ~20 ports) typically takes 1–3 minutes
depending on your network.

## Example output

```
[*] Discovering live hosts on 192.168.1.0/24 ...
    [+] Host up: 192.168.1.1
    [+] Host up: 192.168.1.23

[*] Scanning 2 live host(s)...

[*] Scanning 192.168.1.1 ...
[*] Scanning 192.168.1.23 ...

============================================================
SCAN REPORT
============================================================

Host: 192.168.1.1 (router.home)
   Open ports:
     - 80/tcp  HTTP | banner: HTTP/1.1 200 OK
     - 443/tcp  HTTPS

Host: 192.168.1.23
   Open ports:
     - 23/tcp  Telnet | banner: Welcome to BusyBox
   Risk findings:
     [HIGH] Port 23 (Telnet): Telnet sends everything (including passwords)
     in plain text. Prefer SSH instead.

============================================================
Summary: 2 host(s) scanned, 1 risk finding(s).
============================================================
```

## How it works (for learning)

- **Host discovery**: uses the system `ping` command via `subprocess`, run in
  parallel across many threads so a full subnet doesn't take forever.
- **Port scanning**: opens a raw TCP socket (`socket.connect_ex`) to each
  common port — if the connection succeeds, the port is open. This is a
  simplified version of what tools like `nmap` do under the hood.
- **Banner grabbing**: reads the first bytes a service sends after connecting
  (or sends a minimal HTTP request for web ports) to help identify what's
  running.
- **Risk flagging**: a small hardcoded rule table (`RISK_RULES`) — this is
  the same *pattern* real vulnerability scanners use, just at a much smaller
  scale (real ones check against CVE databases with thousands of entries).

## Ideas to extend this project

Once the basics work, these make great "v2" additions:

- **Service version detection**: parse banners more precisely (e.g. extract
  `OpenSSH_7.2` and flag it if it's below a known-safe version).
- **MAC address + vendor lookup**: use ARP (`arp -a` output, or the `scapy`
  library) to get device MAC addresses and look up the manufacturer via the
  IEEE OUI database — helps identify "what is this device" (e.g. a smart
  camera vs. a laptop).
- **Historical comparison**: save each scan's results with a timestamp and
  diff against the previous scan to alert on *new* devices or *newly opened*
  ports — this turns it into a simple intrusion-detection tool.
- **HTML report**: convert the JSON output into a styled HTML report using a
  template.
- **Scheduling**: run automatically every night via `cron` (Linux/macOS) or
  Task Scheduler (Windows) and email yourself if anything risky changes.
- **CVE lookup integration**: use a free vulnerability API (like the NVD API)
  to check discovered software versions against real CVE records instead of
  the hardcoded rule table.

## Troubleshooting

- **"No live hosts found"** — some routers/devices block ICMP ping by
  default. Try scanning a smaller known range, or temporarily disable your
  firewall's ping-blocking for testing.
- **Permission errors on Linux/macOS** — plain `ping` and TCP connect scans
  shouldn't need root, but if your OS restricts raw ping, you may need
  `sudo python3 network_scanner.py ...`.
- **Scan feels slow** — reduce `MAX_THREADS` if your machine/network
  struggles, or narrow your IP range (e.g. scan `.1-.50` instead of the full
  `/24`) by editing the script.
