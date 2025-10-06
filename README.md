# Cyberdash: Internal Cybersecurity Team Dashboard

**INTERNAL AUTHORIZED USE ONLY — ALL ACTIONS LOGGED**

## Features

- White, Red, Blue, Purple, Gray, and Black Hat tool panels (modular)
- Per-user auth, audit trail, and per-user result storage
- Strictly local/LAN-only, no cloud or telemetry

## Quickstart

1. **Install all dependencies:**
   ```bash
   sudo apt update
   sudo apt install nmap nikto hydra hashcat john sqlmap amass sublist3r whois dnsutils python3-pip tshark dnsrecon xsser theharvester gobuster metasploit-framework veil empire mythic sliver
   pip3 install -r requirements.txt
   ```

2. **Find your LAN IP:**
   ```bash
   ip a
   # e.g. 192.168.1.50
   ```

3. **Run:**
   ```bash
   python3 app.py
   # Open http://[LAN_IP]:3434 from your LAN
   ```

## Security

- App binds to 0.0.0.0:3434 (LAN only)
- No CDN, no telemetry, no cloud
- All subprocess input is sanitized
- All actions are logged
- Results and uploads stored per user

## Ethics

- For internal, authorized use only
- Compliant with OSCP, PTES, NIST, etc.
- For C2/Black Hat tools, use only in isolated, authorized labs

---