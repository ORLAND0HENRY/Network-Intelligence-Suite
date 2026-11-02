"""Private-LAN asset discovery and opt-in checks."""

from __future__ import annotations

import argparse
import ipaddress
import socket
from typing import Iterable

import requests
from scapy.all import ARP, Ether, srp

RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
PORTS_TO_CHECK = (80, 443, 554, 3702, 8080)


def parse_private_network(value: str) -> ipaddress.IPv4Network:
    """Validate an RFC 1918 IPv4 network containing at most 256 addresses."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid network: {exc}") from exc
    if not isinstance(network, ipaddress.IPv4Network) or not any(
        network.subnet_of(allowed) for allowed in RFC1918_NETWORKS
    ):
        raise argparse.ArgumentTypeError("target must be within an RFC 1918 IPv4 range")
    if network.num_addresses > 256:
        raise argparse.ArgumentTypeError("target network must contain at most 256 addresses")
    return network


def get_hostname(ip: str) -> str:
    """Resolve a host name when reverse DNS is available."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return "Unknown host"


def get_vendor(mac: str, session: requests.Session | None = None) -> str:
    """Optionally retrieve vendor metadata from the external macvendors.com API."""
    client = session or requests
    try:
        response = client.get(
            f"https://api.macvendors.com/{mac}",
            timeout=3,
            headers={"User-Agent": "Orlantech-Network-Intelligence-Suite/1.0"},
        )
        if response.ok and response.text.strip():
            return response.text.strip()
    except requests.RequestException:
        pass
    return "Unknown vendor"


def scan_network(network: ipaddress.IPv4Network) -> list[dict[str, str]]:
    """Discover responsive hosts by ARP on the explicitly selected LAN."""
    print(f"[*] Discovering authorized LAN hosts in {network}...")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(packet, timeout=2, retry=1, verbose=0)
    return [{"ip": received.psrc, "mac": received.hwsrc} for _, received in answered]


def probe_ports(ip: str, ports: Iterable[int] = PORTS_TO_CHECK) -> list[int]:
    """Check only the documented fixed TCP ports on one discovered LAN host."""
    found: list[int] = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.3)
                if connection.connect_ex((ip, port)) == 0:
                    found.append(port)
        except OSError:
            continue
    return found


def main(argv: list[str] | None = None) -> int:
    """Run the scanner command-line interface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("network", type=parse_private_network, help="authorized private IPv4 CIDR (up to 256 addresses)")
    parser.add_argument("--probe-ports", action="store_true", help="check a fixed list of common TCP ports")
    parser.add_argument("--vendor-lookup", action="store_true", help="send MAC addresses to macvendors.com")
    args = parser.parse_args(argv)
    try:
        devices = scan_network(args.network)
    except (OSError, RuntimeError) as exc:
        parser.error(f"scan failed; check interface and capture permissions: {exc}")

    print(f"\n{'IP ADDRESS':<16} {'HOSTNAME':<30} {'MAC ADDRESS':<18} {'VENDOR':<28} PORTS")
    print("-" * 112)
    for device in devices:
        hostname = get_hostname(device["ip"])
        vendor = get_vendor(device["mac"]) if args.vendor_lookup else "Not requested"
        ports = probe_ports(device["ip"]) if args.probe_ports else []
        hint = "  (RTSP/ONVIF service)" if any(port in ports for port in (554, 3702)) else ""
        display = ",".join(map(str, ports)) if ports else ("none found" if args.probe_ports else "not checked")
        print(f"{device['ip']:<16} {hostname[:29]:<30} {device['mac']:<18} {vendor[:27]:<28} {display}{hint}")
    print(f"\n[*] Found {len(devices)} host(s). A port check is not a vulnerability assessment.")
    return 0
