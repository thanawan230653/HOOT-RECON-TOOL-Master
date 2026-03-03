#!/usr/bin/env python3

import sys
import socket
import requests
import whois
import argparse


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

        country = r.get("country")
        region = r.get("regionName")
        city = r.get("city")
        isp = r.get("isp")
        asn = r.get("as")
        lat = r.get("lat")
        lon = r.get("lon")

        print(f"\n[+] IP GEO INFORMATION")
        print(f"    Country       : {country}")
        print(f"    Region        : {region}")
        print(f"    City          : {city}")
        print(f"    ISP           : {isp}")
        print(f"    ASN           : {asn}")
        print(f"    Latitude      : {lat}")
        print(f"    Longitude     : {lon}")

        if lat and lon:
            print(f"\n    Google Maps   : https://www.google.com/maps?q={lat},{lon}")

    except:
        print("[-] Failed to retrieve IP information.")


def check_ssh(ip):
    print("\n[+] Checking SSH (Port 22)...")

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


def main():
    parser = argparse.ArgumentParser(
        description="HootRecon - Domain & IP Intelligence Scanner"
    )

    parser.add_argument("target", help="Target domain name")
    parser.add_argument("--full", action="store_true", help="Perform full reconnaissance scan")
    parser.add_argument("--ssh", action="store_true", help="Check SSH port (22)")

    args = parser.parse_args()

    print("\n========================================")
    print("           HOOTRECON v4.0")
    print("========================================")

    ip = resolve_domain(args.target)

    if not ip:
        return

    reverse_lookup(ip)

    if args.full:
        whois_lookup(args.target)
        ip_info(ip)

    if args.ssh:
        check_ssh(ip)


if __name__ == "__main__":
    main()
