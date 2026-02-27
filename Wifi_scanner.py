import socket
import requests
from scapy.all import ARP, Ether, srp


def get_vendor(mac):
    """Fetch manufacturer info using the MAC address."""
    try:
        # Using a free API for MAC lookup
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=2)
        return response.text if response.status_code == 200 else "Unknown Vendor"
    except:
        return "Lookup Failed"


def get_hostname(ip):
    """Try to resolve the network name of the device."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Host"


def scan_network(ip_range):
    print(f"[*] Initializing Advanced Scan on {ip_range}...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        print(f"[+] Found: {received.psrc}")  # Progress indicator
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients


def probe_ports(ip):
    # Expanded list for better identification
    # 554 (RTSP), 3702 (ONVIF), 80/8080 (Web), 443 (HTTPS)
    ports = [80, 443, 554, 3702, 8080]
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports


# RUNNING THE TOOL
target_range = "192.168.100.0/24" #enter target range based on your ip confirm with ifconfig on linux and ipconfig on windows
found_devices = scan_network(target_range)

print("\n" + "=" * 100)
print(f"{'IP ADDRESS':<15} | {'HOSTNAME':<20} | {'VENDOR':<25} | {'PORTS'}")
print("=" * 100)

for device in found_devices:
    hostname = get_hostname(device['ip'])
    vendor = get_vendor(device['mac'])
    ports = probe_ports(device['ip'])

    # Logic to flag suspicious devices
    alert = " [!] CAM?" if (554 in ports or 3702 in ports) else ""

    print(f"{device['ip']:<15} | {hostname[:20]:<20} | {vendor[:25]:<25} | {str(ports):<10} {alert}")