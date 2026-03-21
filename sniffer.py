from scapy.all import sniff, IP, conf
import datetime
from colorama import Fore, Style

# Target the Wi-Fi interface
TARGET_IFACE = 24 #check wi-fi card interface and replace

# The "State Policy" (Blacklisted IPs)
# Example: 142.250.188.46 is a Google IP (test it by pinging google)
FORBIDDEN_ZONES = ["142.250.188.46", "31.13.71.36"]

EXCLUDE_IP = "192.x.x.x" # Enter ip to exclude from the scan e.g. your own device

import socket


def get_hostname(ip):
    try:
        # attempt to find the domain name associated with the IP
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Host"


def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if dst_ip == EXCLUDE_IP:
            return

        hostname = get_hostname(dst_ip)

        # Highlight if it hits a FORBIDDEN_ZONE
        color = Fore.RED if dst_ip in FORBIDDEN_ZONES else Fore.GREEN

        print(f"{color}[OUTBOUND]{Style.RESET_ALL} {src_ip} -> {dst_ip} ({Fore.CYAN}{hostname}{Style.RESET_ALL})")