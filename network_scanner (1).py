#!/usr/bin/env python3
"""
Home Network Scanner
=====================
A beginner-friendly cybersecurity project that:
  1. Discovers live devices on your local network (ping sweep)
  2. Scans common ports on each live device
  3. Grabs service banners to identify what's running
  4. Flags a few well-known risky configurations
  5. Prints a report and saves results to JSON

IMPORTANT / LEGAL NOTE:
Only run this against networks you own or have explicit permission to test
(e.g. your own home Wi-Fi). Scanning networks you don't own or don't have
permission for is illegal in most places, even if you're "just curious."

Usage:
    python3 network_scanner.py 192.168.1.0/24
    python3 network_scanner.py 192.168.1.1-192.168.1.50
"""

import socket
import threading
import subprocess
import platform
import ipaddress
import json
import sys
import argparse
from datetime import datetime
from queue import Queue

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Common ports worth checking on a home network. Feel free to add more.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP (camera/streaming)",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP/Custom",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9100: "Printer (JetDirect)",
}

# Very small, illustrative "risk rules". Real tools use huge CVE databases;
# this is meant to teach the *pattern*, not replace a real vuln scanner.
RISK_RULES = [
    {
        "port": 23,
        "service": "Telnet",
        "severity": "HIGH",
        "reason": "Telnet sends everything (including passwords) in plain text. "
                  "Prefer SSH instead.",
    },
    {
        "port": 21,
        "service": "FTP",
        "severity": "MEDIUM",
        "reason": "FTP is often misconfigured to allow anonymous login and sends "
                  "credentials unencrypted.",
    },
    {
        "port": 445,
        "service": "SMB",
        "severity": "MEDIUM",
        "reason": "SMB has a history of major exploits (e.g. EternalBlue/WannaCry). "
                  "Make sure it's not exposed beyond your LAN.",
    },
    {
        "port": 3389,
        "service": "RDP",
        "severity": "HIGH",
        "reason": "RDP exposed to the internet is a top target for brute-force and "
                  "ransomware attacks. Never expose it directly.",
    },
    {
        "port": 9100,
        "service": "Printer (JetDirect)",
        "severity": "LOW",
        "reason": "Raw printer protocol with no auth. Usually fine on a home LAN, "
                  "but shouldn't be exposed externally.",
    },
]

PORT_TIMEOUT = 0.6      # seconds per port connection attempt
PING_TIMEOUT_MS = 500   # ping timeout in ms
MAX_THREADS = 100

lock = threading.Lock()


# ---------------------------------------------------------------------------
# Step 1: Host discovery (ping sweep)
# ---------------------------------------------------------------------------

def ping_host(ip: str) -> bool:
    """Return True if the host responds to a single ping."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), str(ip)]
    else:
        # -W expects seconds on Linux, so convert; macOS uses -W in ms already
        timeout_sec = max(1, PING_TIMEOUT_MS // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), str(ip)]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False


def discover_hosts(network: str) -> list:
    """Ping-sweep every address in the given CIDR/range and return live IPs."""
    print(f"[*] Discovering live hosts on {network} ...")
    net = ipaddress.ip_network(network, strict=False)

    live_hosts = []
    q = Queue()
    for ip in net.hosts():
        q.put(str(ip))

    def worker():
        while not q.empty():
            try:
                ip = q.get_nowait()
            except Exception:
                return
            if ping_host(ip):
                with lock:
                    live_hosts.append(ip)
                    print(f"    [+] Host up: {ip}")
            q.task_done()

    threads = []
    thread_count = min(MAX_THREADS, q.qsize()) or 1
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    return sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))


# ---------------------------------------------------------------------------
# Step 2 & 3: Port scanning + banner grabbing
# ---------------------------------------------------------------------------

def grab_banner(ip: str, port: int) -> str:
    """Try to read a short banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(PORT_TIMEOUT)
            s.connect((ip, port))
            # Some services send a banner immediately (SSH, FTP, SMTP...)
            try:
                banner = s.recv(128).decode(errors="ignore").strip()
            except socket.timeout:
                banner = ""
            if not banner and port in (80, 8080, 443, 8443):
                # HTTP-like services usually need a request first
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode(errors="ignore").split("\r\n")[0]
                except Exception:
                    pass
            return banner
    except Exception:
        return ""


def scan_ports(ip: str) -> dict:
    """Scan COMMON_PORTS on a single host, return {port: {service, banner}}."""
    open_ports = {}

    def worker(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(PORT_TIMEOUT)
                result = s.connect_ex((ip, port))
                if result == 0:
                    banner = grab_banner(ip, port)
                    with lock:
                        open_ports[port] = {
                            "service": COMMON_PORTS.get(port, "Unknown"),
                            "banner": banner,
                        }
        except Exception:
            pass

    threads = []
    for port in COMMON_PORTS:
        t = threading.Thread(target=worker, args=(port,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    return dict(sorted(open_ports.items()))


# ---------------------------------------------------------------------------
# Step 4: Basic vuln / risk flagging
# ---------------------------------------------------------------------------

def flag_risks(open_ports: dict) -> list:
    """Compare open ports against RISK_RULES and return matching findings."""
    findings = []
    for port in open_ports:
        for rule in RISK_RULES:
            if rule["port"] == port:
                findings.append(rule)
    return findings


# ---------------------------------------------------------------------------
# Step 5: Orchestration + reporting
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def run_scan(network: str) -> dict:
    start = datetime.now()
    results = {"network": network, "scan_started": start.isoformat(), "hosts": []}

    live_hosts = discover_hosts(network)
    if not live_hosts:
        print("[!] No live hosts found. Check the network range and try again.")
        return results

    print(f"\n[*] Scanning ports on {len(live_hosts)} live host(s)...\n")

    for ip in live_hosts:
        print(f"[*] Scanning {ip} ...")
        open_ports = scan_ports(ip)
        findings = flag_risks(open_ports)
        host_entry = {
            "ip": ip,
            "hostname": resolve_hostname(ip),
            "open_ports": open_ports,
            "risk_findings": findings,
        }
        results["hosts"].append(host_entry)

    results["scan_finished"] = datetime.now().isoformat()
    return results


def print_report(results: dict):
    print("\n" + "=" * 60)
    print("SCAN REPORT")
    print("=" * 60)

    for host in results["hosts"]:
        name = f" ({host['hostname']})" if host["hostname"] else ""
        print(f"\nHost: {host['ip']}{name}")
        if not host["open_ports"]:
            print("   No common ports open.")
            continue

        print("   Open ports:")
        for port, info in host["open_ports"].items():
            banner_str = f" | banner: {info['banner']}" if info["banner"] else ""
            print(f"     - {port}/tcp  {info['service']}{banner_str}")

        if host["risk_findings"]:
            print("   Risk findings:")
            for finding in host["risk_findings"]:
                print(f"     [{finding['severity']}] Port {finding['port']} "
                      f"({finding['service']}): {finding['reason']}")

    print("\n" + "=" * 60)
    total_hosts = len(results["hosts"])
    total_findings = sum(len(h["risk_findings"]) for h in results["hosts"])
    print(f"Summary: {total_hosts} host(s) scanned, {total_findings} risk finding(s).")
    print("=" * 60 + "\n")


def save_report(results: dict, filename: str = "scan_report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[*] Full report saved to {filename}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Home Network Scanner — discover devices, open ports, and basic risks."
    )
    parser.add_argument(
        "network",
        help="Network range in CIDR notation, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "-o", "--output", default="scan_report.json",
        help="Output JSON filename (default: scan_report.json)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("HOME NETWORK SCANNER")
    print("Only scan networks you own or have permission to test.")
    print("=" * 60 + "\n")

    results = run_scan(args.network)
    print_report(results)
    save_report(results, args.output)


if __name__ == "__main__":
    main()
