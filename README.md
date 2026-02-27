Orlantech Network Intelligence Suite
A dual-tool security kit for local network asset discovery and real-time egress monitoring. This suite enables a "Blue Team" operator to map the network surface and then immediately pivot to watching for policy violations or data exfiltration.

🛠️ The Toolkit
1. Net-Explorer (Wifi-scanner.py)
An advanced ARP-based network scanner that identifies active hosts, resolves manufacturer data via MAC OUI lookups, and probes for specific "at-risk" service ports.

Key Feature: Includes specialized logic to flag potential surveillance equipment (IP Cameras) by scanning for RTSP (554) and ONVIF (3702) protocols.

Protocol Layer: Operates at Layer 2 (Data Link) for discovery and Layer 4 (Transport) for port probing.

2. Sentry-Sniff (sniffer.py)
A real-time packet inspection engine that monitors outbound traffic from internal devices to the global web.

Key Feature: Implements a "State Policy" (Blacklist) to alert the operator when a device contacts forbidden external zones.

Intelligence: Filters out local "noise" (traffic destined for the monitoring station) to provide a high-signal view of network egress.

🚀 Deployment Guide
Prerequisites
Environment: Python 3.10+

Dependencies: scapy, requests, colorama

System Driver: Npcap (Windows) or Libpcap (Linux)

Privileges: Must be executed as Administrator/Root to utilize Raw Sockets.

Quick Start
Map the Terrain:
Update target_range in scanner.py (e.g., 192.168.1.0/24) and run:

Bash
python scanner.py
Monitor the Perimeter:
Identify your interface ID and exclude your own IP in sniffer.py, then run:

Bash
python sniffer.py


📊 Technical Specifications & Logic
Component	Method	Security Objective
Discovery	ARP Who-has Broadcast	Rapid asset identification without triggering OS firewalls.
Vendor ID	API-based MAC Lookup	Identifying rogue hardware or unauthorized device types.
Port Probing	TCP Three-way Handshake	Surface area mapping (Web, HTTPS, RTSP).
Packet Sniffing	Promiscuous Mode Hook	Detecting "Phone Home" behavior and C2 (Command & Control) traffic.



⚖️ Ethical & Legal Use
This suite is part of the Orlantech Innovations educational portfolio. It is designed for network administrators to audit their own infrastructure. Unauthorized scanning or sniffing on public or third-party networks is illegal and unethical.

