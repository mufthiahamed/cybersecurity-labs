# pfSense Setup Guide

## Overview
pfSense acts as the firewall and router for this lab. It sits between the host network (WAN) and the internal lab network (LAN), controlling all traffic flow.

---

## VM Configuration

| Setting | Value |
|---|---|
| RAM | 1 GB minimum |
| Storage | 8 GB |
| Adapter 1 | NAT (WAN — internet access) |
| Adapter 2 | Internal Network: `lab-net` (LAN) |

---

## Installation Steps

1. Download pfSense ISO from [pfsense.org](https://www.pfsense.org/download/)
2. Create VM with specs above and boot from ISO
3. Accept default install options → reboot
4. On first boot, assign interfaces:
   - WAN → `em0` (NAT adapter)
   - LAN → `em1` (Internal adapter)
5. LAN IP will default to `192.168.1.1`

---

## Web GUI Access

From the Ubuntu or Kali VM, open a browser and navigate to:
```
http://192.168.1.1
```
Default credentials: `admin` / `pfsense` (change immediately)

---

## Key Configuration Tasks

### Firewall Rules
- Navigate to **Firewall → Rules → LAN**
- Default: allow all LAN → WAN
- Practice: create rules to block specific ports or IPs between VMs

### DHCP Server
- Navigate to **Services → DHCP Server**
- Assign IP range for lab VMs (e.g. `192.168.1.100 – 192.168.1.200`)

### Traffic Monitoring
- Navigate to **Diagnostics → Packet Capture**
- Capture traffic on LAN interface to observe VM communication

---

## Config Backup
Export config via **Diagnostics → Backup & Restore** and store in `/configs/pfsense/`
