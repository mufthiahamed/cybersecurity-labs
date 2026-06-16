#!/bin/bash
# recon.sh — Basic recon script for lab use
# Run from Kali against the lab subnet

TARGET_SUBNET="192.168.1.0/24"
OUTPUT_DIR="./recon-output"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting host discovery on $TARGET_SUBNET"
nmap -sn "$TARGET_SUBNET" -oN "$OUTPUT_DIR/hosts_$TIMESTAMP.txt"
echo "[+] Host discovery complete. Results saved."

echo "[*] Enter target IP for service scan:"
read TARGET_IP

echo "[*] Running service scan on $TARGET_IP"
nmap -sV -sC -p- "$TARGET_IP" -oN "$OUTPUT_DIR/services_${TARGET_IP}_$TIMESTAMP.txt"
echo "[+] Service scan complete. Results saved to $OUTPUT_DIR/"
