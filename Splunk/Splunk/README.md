# 🛡️ Cybersecurity Home Lab

A virtualised cybersecurity lab environment built to practice and demonstrate core network security concepts including firewall configuration, network segmentation, traffic analysis, and ethical hacking workflows.

---

## 📋 Overview

This lab simulates a real-world network environment using three virtual machines, each serving a distinct role. The setup is designed to demonstrate practical skills in network defence, traffic monitoring, and penetration testing.

| VM | OS | Role |
|---|---|---|
| Firewall/Router | pfSense | Network gateway, firewall rules, traffic filtering |
| Target Machine | Ubuntu | Internal host, web services, hardening practice |
| Attack Machine | Kali Linux | Penetration testing, vulnerability scanning, exploitation |

---

## 🏗️ Lab Architecture

```
[ Internet / Host Network ]
          |
     [ pfSense ]
     Firewall / Router
     WAN + LAN interfaces
          |
    [ Internal LAN ]
    192.168.1.0/24
     /           \
[ Ubuntu ]     [ Kali ]
Target Host    Attack Machine
```

> Network diagram available in `/diagrams/`

---

## ⚙️ Environment

| Component | Details |
|---|---|
| Hypervisor | VirtualBox / VMware (choose your platform) |
| pfSense Version | 2.7.x |
| Ubuntu Version | 22.04 LTS |
| Kali Linux Version | 2024.x (Rolling) |
| Host OS | Windows / macOS / Linux |

---

## 🚀 Setup Guide

### 1. pfSense (Firewall)
- **Network Adapters:** Adapter 1 → NAT (WAN) | Adapter 2 → Internal Network (LAN)
- Assign WAN/LAN interfaces on first boot
- Access web GUI at `192.168.1.1`
- Configure firewall rules to control traffic between LAN segments

→ See [`docs/pfsense-setup.md`](docs/pfsense-setup.md)

### 2. Ubuntu (Target)
- **Network Adapter:** Internal Network (same as pfSense LAN)
- Set static IP or use DHCP from pfSense
- Install services for practice (Apache, SSH, etc.)
- Apply OS hardening techniques

→ See [`docs/ubuntu-setup.md`](docs/ubuntu-setup.md)

### 3. Kali Linux (Attacker)
- **Network Adapter:** Internal Network (same LAN segment)
- Pre-loaded with tools: Nmap, Metasploit, Wireshark, Burp Suite
- Used for recon, scanning, and controlled exploitation

→ See [`docs/kali-setup.md`](docs/kali-setup.md)

---

## 🧪 Lab Exercises

| Exercise | Tools Used | Description |
|---|---|---|
| Network Recon | Nmap | Discover live hosts and open ports |
| Traffic Capture | Wireshark | Analyse packets between VMs |
| Firewall Rules | pfSense GUI | Block/allow traffic, test rules |
| Vulnerability Scan | OpenVAS / Nmap NSE | Identify weaknesses on Ubuntu host |
| Web App Testing | Burp Suite | Intercept and manipulate HTTP traffic |
| SSH Hardening | Ubuntu | Disable root login, key-based auth |

---

## 📁 Repository Structure

```
cybersecurity-home-lab/
├── README.md
├── docs/
│   ├── pfsense-setup.md       # pfSense installation & config guide
│   ├── ubuntu-setup.md        # Ubuntu setup & hardening steps
│   └── kali-setup.md          # Kali Linux setup & tool overview
├── configs/
│   ├── pfsense/               # Exported pfSense config backups
│   ├── ubuntu/                # Config files (sshd_config, ufw rules, etc.)
│   └── kali/                  # Custom tool configs
├── scripts/
│   └── recon.sh               # Example recon automation script
├── diagrams/                  # Network topology diagrams
└── screenshots/               # Lab evidence / results
```

---

## 🔐 Skills Demonstrated

- Network architecture and segmentation
- Firewall rule configuration and policy management
- Linux administration (Ubuntu + Kali)
- Basic penetration testing methodology
- Traffic analysis and packet inspection
- Security hardening techniques

---

## ⚠️ Disclaimer

This lab is built entirely within a **virtualised, isolated environment** for educational purposes only. All testing is performed on machines I own and control. Nothing in this repository should be used against systems without explicit written permission.

---

## 📬 Contact

Feel free to connect or ask questions via [LinkedIn](#) or open an issue in this repo.
