# Ubuntu Setup Guide

## Overview
Ubuntu serves as the **target machine** in this lab. It represents an internal host that can be configured with services, then hardened and tested against.

---

## VM Configuration

| Setting | Value |
|---|---|
| RAM | 2 GB recommended |
| Storage | 20 GB |
| Adapter 1 | Internal Network: `lab-net` |

---

## Installation Steps

1. Download Ubuntu 22.04 LTS ISO from [ubuntu.com](https://ubuntu.com/download/server)
2. Install with default options (Server or Desktop)
3. Set hostname: `ubuntu-target`
4. After install, configure network to use pfSense as gateway

---

## Network Configuration

```bash
# Check assigned IP (should be in 192.168.1.x range via pfSense DHCP)
ip addr show

# Test connectivity to pfSense
ping 192.168.1.1

# Test internet (via pfSense NAT)
ping 8.8.8.8
```

---

## Services to Install (for lab practice)

```bash
# Web server
sudo apt install apache2 -y
sudo systemctl enable apache2

# SSH server
sudo apt install openssh-server -y
sudo systemctl enable ssh
```

---

## Hardening Steps

### SSH Hardening
```bash
sudo nano /etc/ssh/sshd_config
```
Recommended changes:
```
PermitRootLogin no
PasswordAuthentication no
Port 2222
```

### UFW Firewall
```bash
sudo ufw enable
sudo ufw allow 2222/tcp   # SSH on custom port
sudo ufw allow 80/tcp     # HTTP
sudo ufw status
```

---

## Useful Commands for Lab Exercises

```bash
# View active connections
ss -tuln

# Monitor logs
sudo tail -f /var/log/auth.log

# Check open ports
sudo netstat -tulnp
```
