import os
import re
import socket
import requests
from scapy.all import ARP, Ether, srp, sr1, TCP, IP

def fetch_local_ip_subnet():
    try:
        output = os.popen("ip -o -4 addr show").read()
        for line in output.splitlines():
            if "inet" in line and "scope global" in line:
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if match:
                    return match.group(1), match.group(2)
        return None, None
    except Exception as err:
        print(f"[!] Error retrieving IP/subnet: {err}")
        return None, None

def scan_network(ip, subnet):
    try:
        scan_range = f"{ip}/{subnet}"
        arp_req = ARP(pdst=scan_range)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        response = srp(ether_frame / arp_req, timeout=2, verbose=0)[0]
        return [recv.psrc for _, recv in response]
    except Exception as err:
        print(f"[!] Error during host scan: {err}")
        return []

def probe_ports(target, port_list):
    discovered_ports = []
    for port in port_list:
        try:
            syn_pkt = IP(dst=target) / TCP(dport=port, flags='S')
            response = sr1(syn_pkt, timeout=1, verbose=0)
            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                discovered_ports.append(port)
                sr1(IP(dst=target) / TCP(dport=port, flags='R'), timeout=1, verbose=0)
        except:
            continue
    return discovered_ports

def retrieve_banner(target, port):
    try:
        if port in [80, 443]:
            scheme = "http" if port == 80 else "https"
            resp = requests.get(f"{scheme}://{target}", timeout=2)
            return resp.headers.get("Server", "Unknown")
        else:
            with socket.create_connection((target, port), timeout=2) as conn:
                banner_data = conn.recv(1024).decode().strip()
                return banner_data
    except:
        return "No banner detected"

if __name__ == "__main__":
    local_ip, netmask = fetch_local_ip_subnet()
    if not local_ip or not netmask:
        print("[!] Unable to determine local network details.")
        exit()
    print(f"[+] Detected Network: {local_ip}/{netmask}")
    hosts = scan_network(local_ip, netmask)
    print(f"[+] Identified Hosts: {hosts}")
    target_ports = [21, 22, 80, 443, 8000, 8080, 3306, 3389, 445, 53, 161]
    
    for target_host in hosts:
        if target_host == local_ip:
            continue
        print(f"\n[+] Scanning {target_host}")
        open_ports = probe_ports(target_host, target_ports)
        print(f"Open Ports: {open_ports}")
        for open_port in open_ports:
            print(f"Port {open_port} Banner: {retrieve_banner(target_host, open_port)}")
