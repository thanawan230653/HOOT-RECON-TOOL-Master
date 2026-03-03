#!/usr/bin/env python3

import sys
import socket
import requests
import whois
import argparse
import ssl


def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n[+] Target Domain : {domain}")
        print(f"[+] Resolved IP   : {ip}")
        return ip
    except socket.gaierror:
        print("[-] Error: Unable to resolve domain.")
        return None


def reverse_lookup(ip):
    try:
        result = socket.gethostbyaddr(ip)
        print(f"[+] Reverse DNS   : {result[0]}")
    except socket.herror:
        print("[-] No PTR record found.")


def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(f"\n[+] WHOIS INFORMATION")
        print(f"    Registrar     : {w.registrar}")
        print(f"    Creation Date : {w.creation_date}")
        print(f"    Expiry Date   : {w.expiration_date}")
    except:
        print("[-] WHOIS lookup failed.")


def ip_info(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()

        lat = r.get("lat")
        lon = r.get("lon")

        print(f"\n[+] IP GEO INFORMATION")
        print(f"    Country       : {r.get('country')}")
        print(f"    Region        : {r.get('regionName')}")
        print(f"    City          : {r.get('city')}")
        print(f"    ISP           : {r.get('isp')}")
        print(f"    ASN           : {r.get('as')}")
        print(f"    Latitude      : {lat}")
        print(f"    Longitude     : {lon}")

        if lat and lon:
            print(f"\n    Google Maps   : https://www.google.com/maps?q={lat},{lon}")

    except:
        print("[-] Failed to retrieve IP information.")


def check_ssh(ip):
    print("\n[+] SSH Check (Port 22)")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 22))

        if result == 0:
            print("    Status        : OPEN")
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
                if banner:
                    print(f"    SSH Banner    : {banner}")
            except:
                pass
        else:
            print("    Status        : CLOSED or FILTERED")

        sock.close()
    except:
        print("    Status        : ERROR")


def detect_web_server(domain):
    print("\n[+] Web Server Detection")

    try:
        response = requests.get(f"http://{domain}", timeout=5)
        print(f"    HTTP Server   : {response.headers.get('Server', 'Unknown')}")
        print(f"    X-Powered-By  : {response.headers.get('X-Powered-By', 'Not disclosed')}")
    except:
        print("    HTTP          : Not accessible")

    try:
        response = requests.get(f"https://{domain}", timeout=5)
        print(f"    HTTPS Server  : {response.headers.get('Server', 'Unknown')}")

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                print(f"    SSL Issuer    : {issuer.get('organizationName', 'Unknown')}")
    except:
        print("    HTTPS         : Not accessible")


def main():
    parser = argparse.ArgumentParser(
        description="HootRecon - Full Domain Intelligence Scanner"
    )

    parser.add_argument("target", help="Target domain name")
    parser.add_argument("--full", action="store_true", help="Perform full scan")

    args = parser.parse_args()

    if not args.full:
        print("Usage: python hoot.py <domain> --full")
        return

    print("\n========================================")
    print("           HOOTRECON v6.0")
    print("========================================")

    ip = resolve_domain(args.target)

    if not ip:
        return

    reverse_lookup(ip)
    whois_lookup(args.target)
    ip_info(ip)
    check_ssh(ip)
    detect_web_server(args.target)


if __name__ == "__main__":
    main()
