# Orlantech Network Intelligence Suite

A small, Python-based toolkit for **authorized, defensive checks on networks you administer**. It provides private-LAN asset discovery, optional checks of a fixed set of common ports, and metadata-only monitoring of outbound IPv4 connections. The legacy `brutechecher.py` name is retained for compatibility, but the script no longer guesses passwords; it performs one loopback-only HTTP availability check.

## Tools

### `Wifi_scanner.py` — private-LAN discovery

Sends ARP discovery requests to an explicitly supplied RFC 1918 IPv4 network. Networks larger than 256 addresses and non-private ranges are rejected. Port checks are opt-in and limited to ports 80, 443, 554, 3702, and 8080. Vendor lookups are also opt-in because they send MAC addresses to the third-party macvendors.com service.

```bash
python Wifi_scanner.py 192.168.1.0/24
python Wifi_scanner.py 192.168.1.0/24 --probe-ports
python Wifi_scanner.py 192.168.1.0/24 --vendor-lookup
```

Run with the privileges required by your OS and Scapy/Npcap configuration. The target must be a network you own or have explicit permission to assess.

### `sniffer.py` — outbound connection metadata

Captures IPv4 packet headers on the selected interface and reports only packets from a private source address to a globally routable destination. It does not print or store packet payloads. Optional blocked destination IPs are highlighted; this is exact-IP matching, not a threat-intelligence feed.

```bash
python sniffer.py --interface "Wi-Fi" --exclude-ip 192.168.1.20
python sniffer.py --interface eth0 --duration 60 --forbidden-ip 203.0.113.10
```

The capture runs until interrupted unless `--duration` is set. Use only on interfaces and networks for which you have monitoring authorization. Packet capture may require Administrator/root privileges and a supported capture driver.

### `brutechecher.py` — local endpoint availability

The historical filename is preserved, but password guessing and credential submission have been removed. The script makes a single GET request to a loopback URL only, does not follow redirects, and does not send credentials.

```bash
python brutechecher.py
python brutechecher.py http://localhost:8000/login/
```

## Setup

Python 3.10 or later is recommended.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Safety and privacy

Use these utilities only on systems and networks you own or are explicitly authorized to assess. The scanner deliberately rejects public ranges and limits discovery scope. Port probing and external vendor lookups are disabled unless explicitly requested. Packet capture is limited to connection metadata in the program's output, but the operating system and capture driver may still have access to full packets. Review applicable laws, organizational policy, and consent requirements before use.
