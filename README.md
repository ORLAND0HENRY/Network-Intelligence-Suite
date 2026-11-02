# Orlantech Network Intelligence Suite

A small Python toolkit for **authorized defensive checks on networks you administer**. It supports private-LAN asset discovery, optional fixed-port checks, and metadata-only monitoring of outbound IPv4 traffic. It also includes a credential-free availability check limited to loopback URLs.

## Install

Python 3.10 or later is required. Install the project and its command-line tools in a virtual environment:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e ".[test]"
```

Scapy packet capture may additionally require Administrator/root privileges and Npcap (Windows) or libpcap (Linux/macOS).

## CLI commands

The unified `nis` command and the individual entry points are installed by the package:

```bash
nis scan 192.168.1.0/24
nis-scan 192.168.1.0/24 --probe-ports
nis-scan 192.168.1.0/24 --vendor-lookup
nis monitor --interface eth0 --duration 60 --forbidden-ip 203.0.113.10
nis-monitor --interface "Wi-Fi" --exclude-ip 192.168.1.20
nis health-check http://localhost:8000/health
nis-health-check
```

The scanner rejects non-RFC1918 ranges and networks larger than 256 addresses. Port checks are limited to a fixed documented list and are opt-in. Vendor lookups are opt-in and disclose MAC addresses to macvendors.com. The monitor prints only private-source to global-destination IPv4 addresses; packet payloads are not stored or displayed. Forbidden IPs are exact-match operator-supplied values, not threat intelligence. The health checker sends one credential-free request to localhost/loopback only and does not follow redirects.

The original root-level scripts remain as compatibility wrappers. Prefer the installed commands or `python -m network_intelligence ...`.

## Tests

```bash
python -m pytest
```

Tests exercise input validation and traffic classification without sending packets, scanning hosts, or making external requests.

## Safety and privacy

Use these utilities only on systems and networks you own or are explicitly authorized to assess. Follow applicable laws, organizational policy, and consent requirements. Even metadata-only packet capture can be sensitive; obtain appropriate authorization before monitoring.
