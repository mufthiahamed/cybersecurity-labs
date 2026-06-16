# Kali Linux Setup Guide

## Overview
Kali Linux is the **attack machine** in this lab. It comes pre-loaded with hundreds of security tools used for recon, scanning, exploitation, and analysis.

---

## VM Configuration

| Setting | Value |
|---|---|
| RAM | 2 GB minimum (4 GB recommended) |
| Storage | 30 GB |
| Adapter 1 | Internal Network: `lab-net` |

---

## Installation Steps

1. Download Kali Linux VM image from [kali.org](https://www.kali.org/get-kali/#kali-virtual-machines) (pre-built VMware/VirtualBox image available)
2. Import VM and set adapter to Internal Network: `lab-net`
3. Default credentials: `kali` / `kali` — change after first login

---

## Network Check

```bash
# Confirm IP assigned by pfSense
ip addr show

# Test reach to Ubuntu target
ping 192.168.1.x   # replace with Ubuntu's IP

# Test reach to pfSense
ping 192.168.1.1
```

---

## Key Tools & Usage

### Nmap — Network Scanning
```bash
# Discover live hosts on the LAN
nmap -sn 192.168.1.0/24

# Full port scan on Ubuntu target
nmap -sV -p- 192.168.1.x

# Run default scripts
nmap -sC -sV 192.168.1.x
```

### Wireshark — Traffic Analysis
```bash
# Launch GUI
wireshark

# Or capture via terminal
sudo tcpdump -i eth0 -w capture.pcap
```

### Metasploit — Exploitation Framework
```bash
msfconsole

# Example: search for SSH exploits
msf > search type:exploit name:ssh
```

### Netcat — Basic Connectivity Testing
```bash
# Listen on port
nc -lvnp 4444

# Connect to target
nc 192.168.1.x 80
```

---

## Example Recon Workflow

```bash
# Step 1: Discover hosts
nmap -sn 192.168.1.0/24

# Step 2: Identify services on target
nmap -sV -sC 192.168.1.x

# Step 3: Capture traffic during scan
sudo tcpdump -i eth0 host 192.168.1.x -w recon.pcap

# Step 4: Analyse in Wireshark
wireshark recon.pcap
```

> ⚠️ Only run these tools against the lab VMs. Never use on external networks.
