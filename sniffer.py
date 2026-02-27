from scapy.all import sniff, IP, conf
import datetime
from colorama import Fore, Style

# Target the Wi-Fi interface
TARGET_IFACE = 24 #check wi-fi card interface and replace

# The "State Policy" (Blacklisted IPs)
# Example: 142.250.188.46 is a Google IP (test it by pinging google)
FORBIDDEN_ZONES = ["142.250.188.46", "31.13.71.36"]

EXCLUDE_IP = "192.x.x.x" # Enter ip to exclude from the scan e.g your own device


def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # IGNORE traffic coming TO your laptop/device
        if dst_ip == EXCLUDE_IP:
            return

            # Now you ONLY see where the devices on network is trying to go out in the world
        print(f"[OUTBOUND] {src_ip} is headed to -> {dst_ip}")

# We use the 'iface' parameter to lock onto your Intel Wireless card
sniff(iface=conf.ifaces.dev_from_index(TARGET_IFACE), filter="ip", prn=packet_callback, store=0)