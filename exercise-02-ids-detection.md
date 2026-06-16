# Exercise 02 — IDS Detection with Snort

## Objective
Verify that pfSense with Snort IDS can detect reconnaissance activity from the Kali attack machine. Run multiple Nmap scan types and analyse resulting Snort alerts to demonstrate detection capability.

---

## Environment

| VM | IP | Role |
|---|---|---|
| Kali Linux | 192.168.1.101 | Attacker |
| pfSense | 192.168.1.1 | Firewall / IDS (Snort on LAN em1) |

**IDS Configuration:**
- Snort installed via pfSense Package Manager
- Monitoring interface: LAN (em1)
- Ruleset: ET Open (Emerging Threats)

---

## Scans Performed

### Scan 1 — Aggressive Scan (`-A`)
```bash
nmap -A 192.168.1.1
```
Enables OS detection, version detection, script scanning, and traceroute.

**Results:**

| Port | Service | Version |
|---|---|---|
| 53/tcp | domain | Unbound DNS |
| 80/tcp | http | nginx |
| 443/tcp | ssl/http | nginx |

Additional intel gathered by Nmap:
- OS: FreeBSD 11.2 (97% confidence)
- SSL cert: pfSense self-signed, valid 2025–2027
- HTTP title: `pfSense – Login`
- Network distance: 1 hop, RTT 1.91ms

### Scan 2 — SYN Stealth Scan (`-sS`)
```bash
sudo nmap -sS 192.168.1.1
```
Sends SYN packets without completing the TCP handshake — a classic low-noise scan technique.

**Results:** Ports 53, 80, 443 confirmed open. Scan completed in 5.06 seconds.

---

## Snort Alert Analysis

**Interface monitored:** LAN (em1)
**Total alerts triggered:** 11 entries

### Alert Type 1 — Nmap HTTP Inspection (Your Scan Detected ✅)

| Field | Detail |
|---|---|
| Date | 2026-06-16 03:10 |
| GID:SID | 119:31 |
| Priority | 3 |
| Class | Unknown Traffic |
| Proto | TCP |
| Source | 192.168.1.101 (Kali) |
| Destination | 192.168.1.1:80 |
| Description | `http_inspect UNKNOWN METHOD` |

**Explanation:** Nmap's `-sC` and `-A` scripts send non-standard HTTP methods during web service probing. Snort's `http_inspect` preprocessor flagged these as anomalous — correctly identifying the scan originated from Kali (`192.168.1.101`).

### Alert Type 2 — External SSH Brute Force (Bonus Finding 🔍)

| Field | Detail |
|---|---|
| Date | 2025-12-09 (multiple) |
| GID:SID | 128:4 |
| Priority | 2 |
| Class | Detection of Non-Standard Protocol or Event |
| Proto | TCP |
| Source | Multiple external IPs (port 22) |
| Destination | 192.168.1.1:80 |
| Description | `spp_ssh Protocol mismatch` |

**Explanation:** Eight separate external IP addresses attempted SSH connections to pfSense on December 9, 2025. The `spp_ssh Protocol mismatch` rule fires when a connection to an SSH port doesn't follow the SSH protocol — a common indicator of automated brute-force scanning tools probing for open SSH services. This confirms real-world attack traffic reaching the WAN interface.

---

## Security Findings

| # | Finding | Risk | Recommendation |
|---|---|---|---|
| 1 | Snort detected Nmap HTTP probing from internal attacker | Low | Expected — IDS working correctly. Consider blocking Kali IP during non-testing periods |
| 2 | pfSense WAN SSH exposed to internet | High | Disable SSH on WAN interface or restrict to specific management IP only |
| 3 | pfSense OS fingerprint revealed (FreeBSD 11.2) | Medium | Not easily mitigated, but firewall rules should limit what can probe the device |
| 4 | nginx version exposed via Nmap | Low | Not configurable in pfSense GUI directly, but reduce attack surface by blocking WAN access to port 80 |

---

## Outcome

Snort **successfully detected** the Nmap aggressive scan from `192.168.1.101` via the `http_inspect UNKNOWN METHOD` alert. The IDS is functioning correctly on the LAN interface. An additional real-world finding was identified — external SSH brute-force attempts against the pfSense WAN interface — demonstrating that the lab environment is also exposed to genuine internet threat traffic.

---

## Screenshots
- `screenshots/nmap-aggressive-scan.png` — `nmap -A` results against pfSense
- `screenshots/nmap-syn-scan.png` — `nmap -sS` stealth scan results
- `screenshots/snort-alerts-nmap-detected.png` — Snort alert log showing Kali scan detected
- `screenshots/snort-alerts-ssh-bruteforce.png` — External SSH brute force alerts

---

## Tools Used
- Nmap 7.95
- Snort (via pfSense Package Manager)
- Kali Linux 2024.x
- pfSense Community Edition
