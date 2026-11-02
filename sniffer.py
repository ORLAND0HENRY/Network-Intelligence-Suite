"""Display metadata for outbound IPv4 packets on an authorized interface.

Only source/destination IP addresses are printed; packet payloads are not
stored or displayed. Use this monitor only with appropriate authorization.
"""

from __future__ import annotations

import argparse
import ipaddress

from colorama import Fore, Style, init
from scapy.all import IP, conf, sniff


init(autoreset=True)


def is_outbound_public_traffic(packet: object) -> tuple[str, str] | None:
    """Return private-source/public-destination IPv4 addresses, if applicable."""
    if not getattr(packet, "haslayer", lambda _layer: False)(IP):
        return None
    layer = packet[IP]
    try:
        source = ipaddress.ip_address(layer.src)
        destination = ipaddress.ip_address(layer.dst)
    except ValueError:
        return None
    if source.version != 4 or destination.version != 4:
        return None
    if not source.is_private or not destination.is_global:
        return None
    return str(source), str(destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", help="capture interface (defaults to Scapy's configured interface)")
    parser.add_argument("--exclude-ip", help="omit packets with this source IPv4 address")
    parser.add_argument("--forbidden-ip", action="append", default=[], help="highlight a destination IPv4 address; may be repeated")
    parser.add_argument("--duration", type=float, help="stop after this many seconds")
    args = parser.parse_args()

    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be greater than zero")

    forbidden: set[str] = set()
    for value in args.forbidden_ip:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            parser.error(f"invalid --forbidden-ip value: {value}")
        if address.version != 4:
            parser.error("--forbidden-ip must be an IPv4 address")
        forbidden.add(str(address))

    exclude_ip = None
    if args.exclude_ip:
        try:
            address = ipaddress.ip_address(args.exclude_ip)
        except ValueError:
            parser.error("--exclude-ip must be a valid IPv4 address")
        if address.version != 4:
            parser.error("--exclude-ip must be an IPv4 address")
        exclude_ip = str(address)

    interface = args.interface or conf.iface
    print(f"[*] Monitoring outbound IPv4 metadata on {interface}; press Ctrl+C to stop.")
    if not forbidden:
        print("[*] No forbidden destinations configured; all matching traffic is informational.")

    def packet_callback(packet: object) -> None:
        traffic = is_outbound_public_traffic(packet)
        if traffic is None:
            return
        source, destination = traffic
        if source == exclude_ip:
            return
        blocked = destination in forbidden
        color = Fore.RED if blocked else Fore.GREEN
        label = "[ALERT]" if blocked else "[OUTBOUND]"
        print(f"{color}{label}{Style.RESET_ALL} {source} -> {destination}")

    try:
        sniff(iface=interface, prn=packet_callback, store=False, timeout=args.duration)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped.")
    except (OSError, PermissionError) as exc:
        parser.error(f"capture failed; check interface and permissions: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
