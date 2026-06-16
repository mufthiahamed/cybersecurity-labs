# Exercise 01 — Network Recon & Service Discovery

## Objective
Perform basic network reconnaissance from the Kali attack machine to discover live hosts and identify running services on the lab network. Document findings as a simulated penetration testing engagement.

---

## Environment

| VM | IP | Role |
|---|---|---|
| Kali Linux | 192.168.1.x | Attacker |
| pfSense | 192.168.1.1 | Firewall / Router |
| Ubuntu | 192.168.1.102 | Target Host |

---

## Phase 1 — Host Discovery

**Command run from Kali:**
```bash
nmap 192.168.1.1
nmap 192.168.1.102
```

**Findings:**

| Host | Status | Notes |
|---|---|---|
| 192.168.1.1 (pfSense) | Up | Latency 0.0019s |
| 192.168.1.102 (Ubuntu) | Up | Latency 0.00034s |

Both hosts confirmed live on the internal LAN (`192.168.1.0/24`).

**Initial Ubuntu scan result:** All 1000 ports closed (reset) — UFW active and blocking all traffic. This is expected behaviour on a freshly installed, hardened host.

---

## Phase 2 — pfSense Service Scan

**Command:**
```bash
nmap 192.168.1.1
```

**Open Ports:**

| Port | State | Service |
|---|---|---|
| 53/tcp | open | domain (DNS) |
| 80/tcp | open | http |
| 443/tcp | open | https |

**Analysis:** pfSense is exposing its web GUI on ports 80 and 443, and acting as the DNS resolver for the LAN on port 53. In a production environment, the web GUI should be restricted to a dedicated management interface or VPN — not accessible from the general LAN.

---

## Phase 3 — Ubuntu Service Scan

**Ubuntu was configured with:**
- Apache2 web server (port 80)
- OpenSSH server (port 22)
- UFW rules updated to allow ports 22 and 80

**Command:**
```bash
nmap -sV -sC 192.168.1.102
```

**Open Ports:**

| Port | State | Service | Version |
|---|---|---|---|
| 22/tcp | open | SSH | OpenSSH 9.6p1 Ubuntu |
| 80/tcp | open | HTTP | Apache httpd 2.4.58 |

**Script Results:**
- SSH host keys retrieved (ECDSA + ED25519)
- HTTP title: `Apache2 Ubuntu Default Page: It works`
- Server header exposed: `Apache/2.4.58 (Ubuntu)`

---

## Observations & Security Notes

| Finding | Risk | Recommendation |
|---|---|---|
| Apache default page visible | Low | Replace with custom page; remove default index |
| Server version header exposed | Medium | Disable `ServerTokens` in Apache config — reveals version to attackers |
| SSH on default port 22 | Medium | Consider moving to non-standard port; enforce key-based auth only |
| pfSense GUI on LAN | Medium | Restrict GUI access to management VLAN or specific IP only |

---

## Commands Reference

```bash
# Basic scan
nmap 192.168.1.1

# Service + script scan
nmap -sV -sC 192.168.1.102

# Subnet host discovery
nmap -sn 192.168.1.0/24
```

---

## Screenshots
- `screenshots/nmap-pfsense-scan.png` — pfSense port scan result
- `screenshots/nmap-ubuntu-pfsense.png` — both hosts confirmed live
- `screenshots/nmap-ubuntu-services.png` — Ubuntu service discovery result

---

## Tools Used
- Nmap 7.95
- Kali Linux 2024.x

---

## Outcome
Successfully mapped the lab network, identified all live hosts, and enumerated running services on the target Ubuntu machine. Identified four actionable security findings with recommendations — demonstrating a basic penetration testing methodology from recon through to reporting.
