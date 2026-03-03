# 🦉 HootRecon

**HootRecon** is a lightweight Domain & IP Intelligence Scanner written in Python.
It provides quick reconnaissance capabilities including DNS resolution, reverse lookup, WHOIS information, IP geolocation, ASN data, and basic port scanning.

---

## 🚀 Features

* ✅ Domain → IP resolution
* ✅ Reverse DNS (PTR) lookup
* ✅ WHOIS information
* ✅ IP Geo / ISP / ASN lookup
* ✅ Common port scanning
* ✅ Simple CLI interface
* ✅ Fast and lightweight

---

## 📦 Requirements

* Python 3.8+
* Internet connection

### Install Dependencies

```bash
pip install requests python-whois
```

On Windows (if pip is not recognized):

```bash
python -m pip install requests python-whois
```

---

## 📂 Installation

1. Download or clone the repository:

```bash
git clone https://github.com/yourusername/hootrecon.git
cd hootrecon
```

Or simply place `hoot.py` in any folder.

---

## 🖥 Usage

### 🔹 Basic Scan

Resolves domain and performs reverse DNS lookup.

```bash
python hoot.py example.com
```

---

### 🔹 Full Recon Scan

Performs complete reconnaissance including:

* WHOIS
* IP Geo / ASN / ISP
* Port scanning

```bash
python hoot.py example.com --full
```

---

## 📌 Example Output

```
========================================
         HOOT RECON TOOL v1.0
========================================

[+] Target Domain : example.com
[+] Resolved IP   : 93.184.216.34
[+] Reverse DNS   : edgecastcdn.net

[+] WHOIS INFORMATION
    Registrar     : IANA
    Creation Date : 1995-08-14
    Expiry Date   : 2025-08-13

[+] IP GEO INFORMATION
    Country       : United States
    Region        : California
    ISP           : EdgeCast Networks
    ASN           : AS15133

[+] Scanning Common Ports...
    Open Ports    : [80, 443]
```

---

## ⚠️ Legal Disclaimer

This tool is intended for:

* Educational purposes
* Security research
* Testing systems you own or have permission to assess

Unauthorized scanning of networks or systems may be illegal in your jurisdiction.
Use responsibly.

---

## 🔧 Future Improvements (Planned)

* Subdomain enumeration
* Banner grabbing
* JSON export support
* Colored terminal output
* Custom port range scanning
* Executable build version (.exe)

---

## 👨‍💻 Author

Created as a lightweight reconnaissance utility project.

---

## 📜 License

MIT License
