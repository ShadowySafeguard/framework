import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

'''
- network_scanner.py - Linux Targets
- scan.bat - Windows targets
'''

def scan_ip(ip):
    try:
        socket.gethostbyaddr(str(ip))
        print(f"Host up: {ip}")
    except socket.herror:
        pass

def network_scan(network):
    """
    Exploitablisecure
    """
    ips = ipaddress.ip_network(network)
    with ThreadPoolExecutor(max_workers=10) as executor:
        for ip in ips:
            executor.submit(scan_ip, ip)

if __name__ == "__main__":
    network = input("Enter the network to scan (e.g., 192.168.1.0/24): ")
    network_scan(network)
