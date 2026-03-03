#!/usr/bin/env python3

import sys
import socket
import requests
import whois
import argparse
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]


# -----------------------------
# Resolve Domain
# -----------------------------
def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n[+] Target Domain : {domain}")
        print(f"[+] Resolved IP   : {ip}")
        return ip
    except socket.gaierror:
        print("[-] Error: Unable to resolve domain.")
        return None


# -----------------------------
# Reverse DNS Lookup
# -----------------------------
def reverse_lookup(ip):
    try:
        result = socket.gethostbyaddr(ip)
        print(f"[+] Reverse DNS   : {result[0]}")
    except socket.herror:
        print("[-] No PTR record found.")


# -----------------------------
# WHOIS Lookup
# -----------------------------
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(f"\n[+] WHOIS INFORMATION")
        print(f"    Registrar     : {w.registrar}")
        print(f"    Creation Date : {w.creation_date}")
        print(f"    Expiry Date   : {w.expiration_date}")
    except:
        print("[-] WHOIS lookup failed.")


# -----------------------------
# IP Information (ASN / ISP / Country)
# -----------------------------
def ip_info(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        print(f"\n[+] IP GEO INFORMATION")
        print(f"    Country       : {r.get('country')}")
        print(f"    Region        : {r.get('regionName')}")
        print(f"    ISP           : {r.get('isp')}")
        print(f"    ASN           : {r.get('as')}")
    except:
        print("[-] Failed to retrieve IP information.")


# -----------------------------
# Port Scanner
# -----------------------------
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except:
        pass
    return None


def port_scan(ip):
    print(f"\n[+] Scanning Common Ports...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: scan_port(ip, p), COMMON_PORTS)

    for port in results:
        if port:
            open_ports.append(port)

    if open_ports:
        print(f"    Open Ports    : {open_ports}")
    else:
        print("    No common open ports detected.")


# -----------------------------
# Main Function
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Hoot Recon Tool - Domain & IP Intelligence Scanner"
    )

    parser.add_argument("target", help="Target domain name")
    parser.add_argument("--full", action="store_true", help="Perform full reconnaissance scan")

    args = parser.parse_args()

    print("\n========================================")
    print("         HOOT RECON TOOL v1.0")
    print("========================================")

    ip = resolve_domain(args.target)

    if not ip:
        return

    reverse_lookup(ip)

    if args.full:
        whois_lookup(args.target)
        ip_info(ip)
        port_scan(ip)


if __name__ == "__main__":
    main()
